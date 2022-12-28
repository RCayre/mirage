from mirage.libs import utils, ble
from mirage.core import module
from enum import IntEnum
from mirage.libs.ble_utils.packets import *
from mirage.libs import io
from mirage.libs.ble_utils.constants import LL_ERROR_CODES as errorCode


class ble_generic(module.WirelessModule):
    class BLEStage(IntEnum):
        # Not doing something specific
        IDLE = 0
        # Waiting for advertisments or scan_rsp
        SCAN = 1
        # Wait connection
        WAIT_CONN = 2
        # Custom state 1
        CUSTOM1 = 3
        # Custom state 2
        CUSTOM2 = 4
        # Custom state 3
        CUSTOM3 = 5
        # STOP execution, end of scenario
        STOP = 6

    class ScenarioResult(IntEnum):
        VULN = 0
        MAYBE = 1
        NOT = 2

    def printScenarioStart(self, name):
        name = "Start Scenario {}".format(name)
        border = "=" * int((100 - len(name)) / 2)
        title = border + name + border
        io.success(title)

    def printScenarioEnd(self, result):
        resultText1 = "Scenario finished {}".format(
            "successful" if result["finished"] else "with failure", result["success"]
        )
        border = "=" * 100
        io.success(border)
        if result["finished"]:
            io.success(resultText1)
        else:
            io.fail(resultText1)
        if result["finished"]:
            resultText2 = "Device is {}{}".format(
                "maybe " if result["success"] == self.ScenarioResult.MAYBE else "",
                "vulnerable"
                if result["success"] != self.ScenarioResult.NOT
                else "not vulnerable",
            )
            if result["success"] == self.ScenarioResult.VULN:
                io.fail(resultText2)
            elif result["success"] == self.ScenarioResult.MAYBE:
                io.warning(resultText2)
            else:
                io.success(resultText2)
            io.success(border)

    def createByte(self, start, end, listOfBlockedPDUs):
        blockedPDUVectorString = ""
        for pduID in range(end, start - 1, -1):
            if pduID in listOfBlockedPDUs:
                blockedPDUVectorString += "1"
            else:
                blockedPDUVectorString += "0"
        return blockedPDUVectorString

    def addBlockedPDUsForEmitter(self, emitter, listOfBlockedPDUs):
        blockedPDUVectorString = ""
        for i in range(0, 4):
            blockedPDUVectorString += self.createByte(
                i * 8, (i * 8) + 7, listOfBlockedPDUs
            )
        blockedPDUVector = bytes(
            int(blockedPDUVectorString[i : i + 8], 2)
            for i in range(0, len(blockedPDUVectorString), 8)
        )
        emitter.setBlockedCtrlPDU(blocked_ctrl_pdu=blockedPDUVector)

    def checkSlaveEmitterCapabilities(self):
        a2scap = self.a2sEmitter.hasCapabilities(
            "COMMUNICATING_AS_MASTER", "INITIATING_CONNECTION", "SCANNING"
        )
        return a2scap

    def checkMasterEmitterCapabilities(self):
        a2mcap = False
        if self.args["INTERFACE2"] != "":
            a2mcap = self.a2mEmitter.hasCapabilities(
                "COMMUNICATING_AS_SLAVE", "RECEIVING_CONNECTION", "ADVERTISING"
            )
        return a2mcap

    def init(self):
        self.technology = "ble"
        self.type = "analysis"
        self.dependencies = [
            "ble_connect",
            "ble_scan",
            "ble_discover",
            "ble_pair",
            "ble_sc_pair",
        ]
        self.description = "The module offers a plain basis module to implement complete new scenarious. All connection management has to be don in a scenario."
        self.args = {
            "INTERFACE1": "hci0",
            "INTERFACE2": "",
            "TARGET": "12:34:56:78:90:FF",
            "CONNECTION_TYPE": "public",
            "SCENARIO": "",
            "SECURE_CONNECTION": "yes",
        }

        # Current stage uninitialized
        self.stage = -1

        self.mitm = False

        # Values from UpdateConnectionParametersRequest
        self.timeoutMult = None
        self.slaveLatency = None
        self.minInterval = None
        self.maxInterval = None

    # Scenario-related methods
    @module.scenarioSignal("onStart")
    def startScenario(self):
        pass

    @module.scenarioSignal("onEnd")
    def endScenario(self, result):
        return result

    # Stage related methods
    def getStage(self):
        return self.stage

    def setStage(self, value):
        self.stage = value

    def waitUntilStage(self, stage):
        while self.getStage() != stage:
            utils.wait(seconds=0.01)

    # Helper functions for general use-case
    def initEmittersAndReceivers(self):
        attackerToSlaveInterface = self.args["INTERFACE1"]
        attackerToMasterInterface = self.args["INTERFACE2"]

        self.a2sEmitter = self.getEmitter(interface=attackerToSlaveInterface)
        self.a2sReceiver = self.getReceiver(interface=attackerToSlaveInterface)

        if not self.a2sEmitter.isAddressChangeable():
            io.warning(
                "Interface "
                + attackerToSlaveInterface
                + " is not able to change its address"
            )
        if attackerToMasterInterface != "":
            self.a2mEmitter = self.getEmitter(interface=attackerToMasterInterface)
            self.a2mReceiver = self.getReceiver(interface=attackerToMasterInterface)

            if not self.a2mEmitter.isAddressChangeable():
                io.warning(
                    "Interface "
                    + attackerToMasterInterface
                    + " is not able to change its address"
                )

    def connectOnSlave(self, initiatorType="random"):
        while self.a2sEmitter.getMode() != "NORMAL":
            utils.wait(seconds=1)
            print(self.a2sEmitter.getMode())

        address = utils.addressArg(self.args["TARGET"])
        connectionType = self.args["CONNECTION_TYPE"]

        self.responderAddress = address
        self.responderAddressType = (
            b"\x00" if self.args["CONNECTION_TYPE"] == "public" else b"\x01"
        )
        io.info("Connecting to slave " + address + "...")
        self.a2sEmitter.sendp(
            ble.BLEConnect(
                dstAddr=address, type=connectionType, initiatorType=initiatorType
            )
        )
        while not self.a2sEmitter.isConnected():
            utils.wait(seconds=0.5)
        io.info("Connected on slave : " + self.a2sReceiver.getCurrentConnection())

    def startAdvertisingOnEmitter(
        self,
        emitter,
        address,
        dataAdvInd,
        dataScanRsp,
        intervalMin,
        intervalMax,
        addrType,
    ):
        if address != emitter.getAddress():
            emitter.setAddress(address, random=1 == addrType)
        emitter.setScanningParameters(data=dataScanRsp)
        emitter.setAdvertisingParameters(
            data=dataAdvInd,
            intervalMin=intervalMin,
            intervalMax=intervalMax,
            daType=addrType,
            oaType=addrType,
        )
        emitter.setAdvertising(enable=True)

    def enableMitM(self, enable):
        self.mitm = enable
        if self.mitm:
            io.info("MitM is enabled")

    def forwardSlavePacket(self, packet):
        if self.mitm and self.a2mEmitter.isConnected():
            self.a2mEmitter.sendp(packet)

    def forwardMasterPacket(self, packet):
        if self.mitm and self.a2sEmitter.isConnected():
            self.a2sEmitter.sendp(packet)

    # Advertising related methods
    @module.scenarioSignal("onSlaveAdvertisement")
    def slaveAdvertisement(self, packet):
        io.info("Slave advertisement")
        io.info(packet.toString())

    @module.scenarioSignal("onMasterCreateConnection")
    def masterCreateConnection(self, packet):
        io.info("Connection complete (from master)")
        io.info(packet.toString())

    @module.scenarioSignal("onSlaveConnectionComplete")
    def slaveConnectionComplete(self, packet):
        io.info("Connection complete (from slave)")
        io.info(packet.toString())

    @module.scenarioSignal("onMasterDisconnect")
    def masterDisconnect(self, packet):
        io.info("Master disconnected")
        # self.forwardMasterPacket(ble.BLEDisconnect())

    @module.scenarioSignal("onSlaveDisconnect")
    def slaveDisconnect(self, packet):
        io.info("Slave disconnected")
        # self.forwardSlavePacket(ble.BLEDisconnect())

    @module.scenarioSignal("onMasterExchangeMTURequest")
    def masterExchangeMtuRequest(self, packet):
        io.info("Exchange MTU Request (from master) : mtu = " + str(packet.mtu))
        self.forwardMasterPacket(ble.BLEExchangeMTURequest(mtu=packet.mtu))

    @module.scenarioSignal("onSlaveExchangeMTURequest")
    def slaveExchangeMtuRequest(self, packet):
        io.info("Exchange MTU Request (from slave) : mtu = " + str(packet.mtu))
        self.forwardSlavePacket(ble.BLEExchangeMTURequest(mtu=packet.mtu))

    @module.scenarioSignal("onMasterExchangeMTUResponse")
    def masterExchangeMtuResponse(self, packet):
        io.info("Exchange MTU Response (from master) : mtu = " + str(packet.mtu))
        self.forwardMasterPacket(ble.BLEExchangeMTUResponse(mtu=packet.mtu))

    @module.scenarioSignal("onSlaveExchangeMTUResponse")
    def slaveExchangeMtuResponse(self, packet):
        io.info("Exchange MTU Response (from slave) : mtu = " + str(packet.mtu))
        self.forwardSlavePacket(ble.BLEExchangeMTUResponse(mtu=packet.mtu))

    @module.scenarioSignal("onMasterWriteCommand")
    def writeCommand(self, packet):
        io.info(
            "Write Command (from master) : handle = "
            + hex(packet.handle)
            + " / value = "
            + packet.value.hex()
        )
        self.forwardMasterPacket(
            ble.BLEWriteCommand(handle=packet.handle, value=packet.value)
        )

    @module.scenarioSignal("onMasterWriteRequest")
    def writeRequest(self, packet):
        io.info(
            "Write Request (from master) : handle = "
            + hex(packet.handle)
            + " / value = "
            + packet.value.hex()
        )
        self.forwardMasterPacket(
            ble.BLEWriteRequest(handle=packet.handle, value=packet.value)
        )

    @module.scenarioSignal("onSlaveWriteResponse")
    def writeResponse(self, packet):
        io.info("Write Response (from slave)")
        self.forwardSlavePacket(ble.BLEWriteResponse())

    @module.scenarioSignal("onMasterReadBlobRequest")
    def readBlob(self, packet):
        io.info(
            "Read Blob Request (from master) : handle = "
            + hex(packet.handle)
            + " / offset = "
            + str(packet.offset)
        )
        self.forwardMasterPacket(
            ble.BLEReadBlobRequest(handle=packet.handle, offset=packet.offset)
        )

    @module.scenarioSignal("onSlaveReadBlobResponse")
    def readBlobResponse(self, packet):
        io.info("Read Blob Response (from slave) : value = " + packet.value.hex())
        self.forwardSlavePacket(ble.BLEReadBlobResponse(value=packet.value))

    @module.scenarioSignal("onMasterReadRequest")
    def read(self, packet):
        io.info("Read Request (from master) : handle = " + hex(packet.handle))
        self.forwardMasterPacket(ble.BLEReadRequest(handle=packet.handle))

    @module.scenarioSignal("onSlaveReadResponse")
    def readResponse(self, packet):
        io.info("Read Response (from slave) : value = " + packet.value.hex())
        self.forwardSlavePacket(ble.BLEReadResponse(value=packet.value))

    @module.scenarioSignal("onSlaveErrorResponse")
    def errorResponse(self, packet):
        io.info(
            "Error Response (from slave) : request = "
            + hex(packet.request)
            + " / handle = "
            + hex(packet.handle)
            + " / ecode = "
            + hex(packet.ecode)
        )
        self.forwardSlavePacket(
            ble.BLEErrorResponse(
                request=packet.request, handle=packet.handle, ecode=packet.ecode
            )
        )

    @module.scenarioSignal("onSlaveHandleValueNotification")
    def notification(self, packet):
        io.info(
            "Handle Value Notification (from slave) : handle = "
            + hex(packet.handle)
            + " / value = "
            + packet.value.hex()
        )
        self.forwardSlavePacket(
            ble.BLEHandleValueNotification(handle=packet.handle, value=packet.value)
        )

    @module.scenarioSignal("onSlaveHandleValueIndication")
    def indication(self, packet):
        io.info(
            "Handle Value Indication (from slave) : handle = "
            + hex(packet.handle)
            + " / value = "
            + packet.value.hex()
        )
        self.forwardSlavePacket(
            ble.BLEHandleValueIndication(handle=packet.handle, value=packet.value)
        )

    @module.scenarioSignal("onMasterHandleValueConfirmation")
    def confirmation(self, packet):
        io.info("Handle Value Confirmation (from master)")
        self.forwardMasterPacket(ble.BLEHandleValueConfirmation())

    @module.scenarioSignal("onMasterFindInformationRequest")
    def findInformation(self, packet):
        io.info(
            "Find Information Request (from master) : startHandle = "
            + hex(packet.startHandle)
            + " / endHandle = "
            + hex(packet.endHandle)
        )
        self.forwardMasterPacket(
            ble.BLEFindInformationRequest(
                startHandle=packet.startHandle, endHandle=packet.endHandle
            )
        )

    @module.scenarioSignal("onSlaveFindInformationResponse")
    def findInformationResponse(self, packet):
        io.info(
            "Find Information Response (from slave) : format = "
            + hex(packet.format)
            + " / data = "
            + packet.data.hex()
        )
        self.forwardSlavePacket(
            ble.BLEFindInformationResponse(format=packet.format, data=packet.data)
        )

    @module.scenarioSignal("onMasterFindByTypeValueRequest")
    def findByTypeValueRequest(self, packet):
        io.info(
            "Find Type By Value Request (from master) : startHandle = "
            + hex(packet.startHandle)
            + " / endHandle = "
            + hex(packet.endHandle)
            + " / uuid = "
            + hex(packet.uuid)
            + " / data = "
            + packet.data.hex()
        )
        self.forwardMasterPacket(
            ble.BLEFindByTypeValueRequest(
                startHandle=packet.startHandle,
                endHandle=packet.endHandle,
                uuid=packet.uuid,
                data=packet.data,
            )
        )

    @module.scenarioSignal("onSlaveFindByTypeValueResponse")
    def findByTypeValueResponse(self, packet):
        io.info("Find Type By Value Response (from slave)")
        self.forwardSlavePacket(ble.BLEFindByTypeValueResponse(handles=packet.handles))

    @module.scenarioSignal("onMasterReadByTypeRequest")
    def masterReadByType(self, packet):
        io.info(
            "Read By Type Request (from master) : startHandle = "
            + hex(packet.startHandle)
            + " / endHandle = "
            + hex(packet.endHandle)
            + " / uuid = "
            + hex(packet.uuid)
        )
        self.forwardMasterPacket(
            ble.BLEReadByTypeRequest(
                startHandle=packet.startHandle,
                endHandle=packet.endHandle,
                uuid=packet.uuid,
            )
        )

    @module.scenarioSignal("onSlaveReadByTypeRequest")
    def slaveReadByType(self, packet):
        io.info(
            "Read By Type Request (from slave) : startHandle = "
            + hex(packet.startHandle)
            + " / endHandle = "
            + hex(packet.endHandle)
            + " / uuid = "
            + hex(packet.uuid)
        )
        self.forwardMasterPacket(
            ble.BLEReadByTypeRequest(
                startHandle=packet.startHandle,
                endHandle=packet.endHandle,
                uuid=packet.uuid,
            )
        )

    @module.scenarioSignal("onMasterReadByGroupTypeRequest")
    def readByGroupType(self, packet):
        io.info(
            "Read By Group Type Request (from master) : startHandle = "
            + hex(packet.startHandle)
            + " / endHandle = "
            + hex(packet.endHandle)
            + " / uuid = "
            + hex(packet.uuid)
        )
        self.forwardMasterPacket(
            ble.BLEReadByGroupTypeRequest(
                startHandle=packet.startHandle,
                endHandle=packet.endHandle,
                uuid=packet.uuid,
            )
        )

    @module.scenarioSignal("onSlaveReadByTypeResponse")
    def readByTypeResponse(self, packet):
        io.info("Read By Type Response (from slave) : data = " + packet.data.hex())
        self.forwardSlavePacket(ble.BLEReadByTypeResponse(data=packet.data))

    @module.scenarioSignal("onSlaveReadByGroupTypeResponse")
    def readByGroupTypeResponse(self, packet):
        io.info(
            "Read By Group Type Response (from slave) : length = "
            + str(packet.length)
            + " / data = "
            + packet.data.hex()
        )
        self.forwardSlavePacket(
            ble.BLEReadByGroupTypeResponse(length=packet.length, data=packet.data)
        )

    @module.scenarioSignal("onMasterPairingRequest")
    def pairingRequest(self, packet):
        io.info(
            (
                "Pairing Request (from master) : "
                + "\n=> outOfBand = "
                + ("yes" if packet.outOfBand else "no")
                + "\n=> inputOutputCapability = "
                + str(
                    ble.InputOutputCapability(
                        data=bytes([packet.inputOutputCapability])
                    )
                )
                + "\n=> authentication = "
                + str(ble.AuthReqFlag(data=bytes([packet.authentication])))
                + "\n=> maxKeySize = "
                + str(packet.maxKeySize)
                + "\n=> initiatorKeyDistribution = "
                + str(
                    ble.KeyDistributionFlag(
                        data=bytes([packet.initiatorKeyDistribution])
                    )
                )
            )
            + "\n=> responderKeyDistribution = "
            + str(
                ble.KeyDistributionFlag(data=bytes([packet.responderKeyDistribution]))
            )
        )
        self.forwardMasterPacket(
            ble.BLEPairingRequest(
                outOfBand=packet.outOfBand,
                inputOutputCapability=packet.inputOutputCapability,
                authentication=packet.authentication,
                maxKeySize=packet.maxKeySize,
                initiatorKeyDistribution=packet.initiatorKeyDistribution,
                responderKeyDistribution=packet.responderKeyDistribution,
            )
        )

    @module.scenarioSignal("onSlaveSecurityRequest")
    def securityRequest(self, packet):
        io.info(
            "Security Request (from slave) : authentication = "
            + str(ble.AuthReqFlag(data=bytes([packet.authentication])))
            + "\n"
        )
        self.forwardSlavePacket(
            ble.BLESecurityRequest(
                connectionHandle=packet.connectionHandle,
                authentication=packet.authentication,
            )
        )

    @module.scenarioSignal("onSlavePairingResponse")
    def pairingResponse(self, packet):
        io.info(
            (
                "Pairing Response (from slave) : "
                + "\n=> outOfBand = "
                + ("yes" if packet.outOfBand else "no")
                + "\n=> inputOutputCapability = "
                + str(
                    ble.InputOutputCapability(
                        data=bytes([packet.inputOutputCapability])
                    )
                )
                + "\n=> authentication = "
                + str(ble.AuthReqFlag(data=bytes([packet.authentication])))
                + "\n=> maxKeySize = "
                + str(packet.maxKeySize)
                + "\n=> initiatorKeyDistribution = "
                + str(
                    ble.KeyDistributionFlag(
                        data=bytes([packet.initiatorKeyDistribution])
                    )
                )
            )
            + "\n=> responderKeyDistribution = "
            + str(
                ble.KeyDistributionFlag(data=bytes([packet.responderKeyDistribution]))
            )
        )
        self.forwardSlavePacket(
            ble.BLEPairingResponse(
                outOfBand=packet.outOfBand,
                inputOutputCapability=packet.inputOutputCapability,
                authentication=packet.authentication,
                maxKeySize=packet.maxKeySize,
                initiatorKeyDistribution=packet.initiatorKeyDistribution,
                responderKeyDistribution=packet.responderKeyDistribution,
            )
        )

    @module.scenarioSignal("onMasterPairingConfirm")
    def masterPairingConfirm(self, packet):
        io.info("Pairing Confirm (from master) : confirm = " + packet.confirm.hex())
        self.forwardMasterPacket(ble.BLEPairingConfirm(confirm=packet.confirm))

    @module.scenarioSignal("onSlavePairingConfirm")
    def slavePairingConfirm(self, packet):
        io.info("Pairing Confirm (from slave) : confirm = " + packet.confirm.hex())
        self.forwardSlavePacket(ble.BLEPairingConfirm(confirm=packet.confirm))

    @module.scenarioSignal("onMasterPairingRandom")
    def masterPairingRandom(self, packet):
        io.info("Pairing Random (from master) : random = " + packet.random.hex())
        self.forwardMasterPacket(ble.BLEPairingRandom(random=packet.random))

    @module.scenarioSignal("onSlavePairingRandom")
    def slavePairingRandom(self, packet):
        io.info("Pairing Random (from slave) : random = " + packet.random.hex())
        self.forwardSlavePacket(ble.BLEPairingRandom(random=packet.random))

    def pairingFailed(self, pkt):
        io.fail("Pairing Failed received : " + pkt.toString())
        if pkt.reason == ble.SM_ERR_PASSKEY_ENTRY_FAILED:
            io.fail("Reason : Passkey Entry Failed")
        elif pkt.reason == ble.SM_ERR_OOB_NOT_AVAILABLE:
            io.fail("Reason : Out of Band not available")
        elif pkt.reason == ble.SM_ERR_AUTH_REQUIREMENTS:
            io.fail("Reason : Authentication requirements")
        elif pkt.reason == ble.SM_ERR_CONFIRM_VALUE_FAILED:
            io.fail("Reason : Confirm Value failed")
        elif pkt.reason == ble.SM_ERR_PAIRING_NOT_SUPPORTED:
            io.fail("Reason : Pairing not supported")
        elif pkt.reason == ble.SM_ERR_OOB_NOT_AVAILABLE:
            io.fail("Reason : Out of Band not available")
        elif pkt.reason == ble.SM_ERR_ENCRYPTION_KEY_SIZE:
            io.fail("Reason : Encryption key size")
        elif pkt.reason == ble.SM_ERR_COMMAND_NOT_SUPPORTED:
            io.fail("Reason : Command not supported")
        elif pkt.reason == ble.SM_ERR_UNSPECIFIED_REASON:
            io.fail("Reason : Unspecified reason")
        elif pkt.reason == ble.SM_ERR_REPEATED_ATTEMPTS:
            io.fail("Reason : Repeated Attempts")
        elif pkt.reason == ble.SM_ERR_INVALID_PARAMETERS:
            io.fail("Reason : Invalid Parameters")
        elif pkt.reason == ble.SM_ERR_DHKEY_CHECK_FAILED:
            io.fail("Reason : DHKey Check failed")
        elif pkt.reason == ble.SM_ERR_NUMERIC_COMPARISON_FAILED:
            io.fail("Reason : Numeric Comparison failed")
        elif pkt.reason == ble.SM_ERR_BREDR_PAIRING_IN_PROGRESS:
            io.fail("Reason : BR/EDR Pairing in progress")
        elif pkt.reason == ble.SM_ERR_CROSS_TRANSPORT_KEY:
            io.fail("Reason : Cross-transport Key Derivation/Generation not allowed")
        else:
            io.fail("Reason : unknown")

    @module.scenarioSignal("onMasterPairingFailed")
    def masterPairingFailed(self, packet):
        io.info("Pairing Failed (from master) !")
        self.forwardMasterPacket(ble.BLEPairingFailed(reason=packet.reason))

    @module.scenarioSignal("onSlavePairingFailed")
    def slavePairingFailed(self, packet):
        io.info("Pairing Failed (from slave) !")
        self.forwardSlavePacket(ble.BLEPairingFailed(reason=packet.reason))

    @module.scenarioSignal("onSlaveEncryptionInformation")
    def slaveEncryptionInformation(self, packet):
        io.info(
            "Encryption Information (from slave) : Long Term Key = " + packet.ltk.hex()
        )
        self.forwardSlavePacket(ble.BLEEncryptionInformation(ltk=packet.ltk))

    @module.scenarioSignal("onSlaveMasterIdentification")
    def slaveMasterIdentification(self, packet):
        io.info(
            "Master Indentification (from slave) : ediv = "
            + hex(packet.ediv)
            + " / rand = "
            + packet.rand.hex()
        )
        self.forwardSlavePacket(
            ble.BLEMasterIdentification(rand=packet.rand, ediv=packet.ediv)
        )

    @module.scenarioSignal("onSlaveIdentityAddressInformation")
    def slaveIdentityAddressInformation(self, packet):
        io.info(
            "Identity Address Information (from slave) : address = "
            + str(packet.address)
            + " / type = "
            + packet.type
        )
        self.forwardSlavePacket(
            ble.BLEIdentityAddressInformation(address=packet.address, type=packet.type)
        )

    @module.scenarioSignal("onSlaveIdentityInformation")
    def slaveIdentityInformation(self, packet):
        io.info("Identity Information (from slave) : irk = " + packet.irk.hex())
        self.forwardSlavePacket(ble.BLEIdentityInformation(irk=packet.irk))

    @module.scenarioSignal("onSlaveSigningInformation")
    def slaveSigningInformation(self, packet):
        io.info("Signing Information (from slave) : csrk = " + packet.csrk.hex())
        self.forwardSlavePacket(ble.BLESigningInformation(csrk=packet.csrk))

    @module.scenarioSignal("onMasterEncryptionInformation")
    def masterEncryptionInformation(self, packet):
        io.info(
            "Encryption Information (from master) : Long Term Key = " + packet.ltk.hex()
        )
        self.forwardMasterPacket(ble.BLEEncryptionInformation(ltk=packet.ltk))

    @module.scenarioSignal("onMasterMasterIdentification")
    def masterMasterIdentification(self, packet):
        io.info(
            "Master Indentification (from master) : ediv = "
            + hex(packet.ediv)
            + " / rand = "
            + packet.rand.hex()
        )
        self.forwardMasterPacket(
            ble.BLEMasterIdentification(rand=packet.rand, ediv=packet.ediv)
        )

    @module.scenarioSignal("onMasterIdentityAddressInformation")
    def masterIdentityAddressInformation(self, packet):
        io.info(
            "Identity Address Information (from master) : address = "
            + str(packet.address)
            + " / type = "
            + packet.type
        )
        self.forwardMasterPacket(
            ble.BLEIdentityAddressInformation(address=packet.address, type=packet.type)
        )

    @module.scenarioSignal("onMasterIdentityInformation")
    def masterIdentityInformation(self, packet):
        io.info("Identity Information (from master) : irk = " + packet.irk.hex())
        self.forwardMasterPacket(ble.BLEIdentityInformation(irk=packet.irk))

    @module.scenarioSignal("onMasterSigningInformation")
    def masterSigningInformation(self, packet):
        io.info("Signing Information (from master) : csrk = " + packet.csrk.hex())
        self.forwardMasterPacket(ble.BLESigningInformation(csrk=packet.csrk))

    @module.scenarioSignal("onSlavePublicKey")
    def slavePublicKey(self, packet):
        io.info(
            "Public Key (from slave) : \n\tkey_x: "
            + packet.key_x.hex()
            + " length: "
            + str(len(packet.key_x))
            + "\n\tkey_y: "
            + packet.key_y.hex()
            + " length: "
            + str(len(packet.key_y))
            + "\n"
        )
        self.forwardSlavePacket(
            ble.BLEPublicKey(
                key_x=packet.key_x,
                key_y=packet.key_y,
            )
        )

    @module.scenarioSignal("onMasterPublicKey")
    def masterPublicKey(self, packet):
        io.info(
            "Public Key (from master) : \n\tkey_x: "
            + packet.key_x.hex()
            + " length: "
            + str(len(packet.key_x))
            + "\n\tkey_y: "
            + packet.key_y.hex()
            + " length: "
            + str(len(packet.key_y))
            + "\n"
        )
        self.forwardMasterPacket(
            ble.BLEPublicKey(
                key_x=packet.key_x,
                key_y=packet.key_y,
            )
        )

    @module.scenarioSignal("onSlaveConnectionParameterUpdateRequest")
    def slaveConnectionParameterUpdateRequest(self, packet):
        io.info(
            "Connection Parameter Update Request (from slave) : slaveLatency = "
            + str(packet.slaveLatency)
            + " / timeoutMult = "
            + str(packet.timeoutMult)
            + " / minInterval = "
            + str(packet.minInterval)
            + " / maxInterval = "
            + str(packet.maxInterval)
        )

        if not self.mitm and self.a2sEmitter.isConnected():
            io.info("Answering slave ...")
            self.a2sEmitter.sendp(
                ble.BLEConnectionParameterUpdateResponse(
                    l2capCmdId=packet.l2capCmdId, moveResult=0
                )
            )
        else:
            self.forwardSlavePacket(
                ble.BLEConnectionParameterUpdateRequest(
                    l2capCmdId=packet.l2capCmdId,
                    timeoutMult=packet.timeoutMult,
                    slaveLatency=packet.slaveLatency,
                    minInterval=packet.minInterval,
                    maxInterval=packet.maxInterval,
                )
            )
        self.a2sEmitter.updateConnectionParameters(
            timeout=packet.timeoutMult,
            latency=packet.slaveLatency,
            minInterval=packet.minInterval,
            maxInterval=packet.maxInterval,
            minCe=0,
            maxCe=0,
        )

    @module.scenarioSignal("onMasterConnectionParameterUpdateResponse")
    def masterConnectionParameterUpdateResponse(self, packet):
        io.info(
            "Connection Parameter Update Response (from master) : moveResult = "
            + str(packet.moveResult)
        )
        self.forwardMasterPacket(
            ble.BLEConnectionParameterUpdateResponse(
                l2capCmdId=packet.l2capCmdId, moveResult=packet.moveResult
            )
        )

        if packet.moveResult == 0 and not self.mitm and self.a2sEmitter.isConnected():
            io.info(
                "Updating Connection Parameter: slaveLatency = "
                + str(self.slaveLatency)
                + " / timeoutMult = "
                + str(self.timeoutMult)
                + " / minInterval = "
                + str(self.minInterval)
                + " / maxInterval = "
                + str(self.maxInterval)
            )
            self.a2sEmitter.updateConnectionParameters(
                timeout=self.timeoutMult,
                latency=self.slaveLatency,
                minInterval=self.minInterval,
                maxInterval=self.maxInterval,
            )

    @module.scenarioSignal("onMasterDHKeyCheck")
    def masterDHKeyCheck(self, packet):
        io.info(
            "DH Key Check (from master) : dhkey_check = " + packet.dhkey_check.hex()
        )
        self.forwardMasterPacket(ble.BLEDHKeyCheck(dhkey_check=packet.dhkey_check))

    @module.scenarioSignal("onSlaveDHKeyCheck")
    def slaveDHKeyCheck(self, packet):
        io.info("DH Key Check (from slave) : dhkey_check = " + packet.dhkey_check.hex())
        self.forwardSlavePacket(ble.BLEDHKeyCheck(dhkey_check=packet.dhkey_check))

    ## HCI callbacks
    @module.scenarioSignal("onMasterEncryptionChange")
    def masterEncryptionChange(self, packet):
        io.info("Master: " + packet.toString())

    @module.scenarioSignal("onSlaveEncryptionChange")
    def slaveEncryptionChange(self, packet):
        io.info("Slave: " + packet.toString())

    @module.scenarioSignal("onMasterLongTermKeyRequest")
    def masterLongTermKeyRequest(self, packet):
        io.info("Master: " + packet.toString())

    ## Link Layer Callbacks
    @module.scenarioSignal("onSlaveLLConnUpdateInd")
    def slaveLLConnUpdateInd(self, packet):
        io.info("Slave: " + packet.toString())

    @module.scenarioSignal("onMasterLLConnUpdateInd")
    def masterLLConnUpdateInd(self, packet):
        io.info("Master: " + packet.toString())

    @module.scenarioSignal("onSlaveLLChannelMapInd")
    def slaveLLChannelMapInd(self, packet):
        io.info("Slave: " + packet.toString())

    @module.scenarioSignal("onMasterLLChannelMapInd")
    def masterLLChannelMapInd(self, packet):
        io.info("Master: " + packet.toString())

    @module.scenarioSignal("onSlaveLLTerminateInd")
    def slaveLLTerminateInd(self, packet):
        io.info(
            "Slave: "
            + packet.toString()
            + "\n\t"
            + hex(packet.error_code)
            + " = "
            + errorCode[packet.error_code]
        )

    @module.scenarioSignal("onMasterLLTerminateInd")
    def masterLLTerminateInd(self, packet):
        io.info(
            "Master: "
            + packet.toString()
            + "\n\t"
            + hex(packet.error_code)
            + " = "
            + errorCode[packet.error_code]
        )

    @module.scenarioSignal("onMasterLLEncReq")
    def masterLLEncReq(self, packet):

        io.info(
            "LL Enc Request (from master) : rand = "
            + str(packet.rand)
            + " / ediv = "
            + str(packet.ediv)
            + " / skdm = "
            + str(packet.skdm)
            + " / ivm = "
            + str(packet.ivm)
        )

    @module.scenarioSignal("onSlaveLLEncRsp")
    def slaveLLEncRsp(self, packet):
        io.info(
            "LL Enc Response (from slave) : skds = "
            + str(packet.skds)
            + " / ivs = "
            + str(packet.ivs)
        )

    @module.scenarioSignal("onSlaveLLStartEncReq")
    def slaveLLStartEncReq(self, packet):
        io.info("LL Start Enc Request (from slave)")

    @module.scenarioSignal("onSlaveLLUnknownRsp")
    def slaveLLUnknownRsp(self, packet):
        io.info("Slave: " + packet.toString())

    @module.scenarioSignal("onMasterLLUnknownRsp")
    def masterLLUnknownRsp(self, packet):
        io.info("Master: " + packet.toString())

    @module.scenarioSignal("onSlaveLLFeatureReq")
    def slaveLLFeatureReq(self, packet):
        io.info("Slave: " + packet.toString())

    @module.scenarioSignal("onMasterLLFeatureReq")
    def masterLLFeatureReq(self, packet):
        io.info("Master: " + packet.toString())

    @module.scenarioSignal("onSlaveLLFeatureRsp")
    def slaveLLFeatureRsp(self, packet):
        io.info("Slave: " + packet.toString())

    @module.scenarioSignal("onMasterLLFeatureRsp")
    def masterLLFeatureRsp(self, packet):
        io.info("Master: " + packet.toString())

    @module.scenarioSignal("onMasterLLPauseEncReq")
    def masterLLPauseEncReq(self, packet):
        io.info("LL Pause Enc Request (from master)\nRedirecting to slave...")

    @module.scenarioSignal("onMasterLLPauseEncRsp")
    def masterLLPauseEncRsp(self, packet):
        io.info("LL Pause Enc Response (from master)\nRedirecting to slave...")

    @module.scenarioSignal("onSlaveLLPauseEncRsp")
    def slaveLLPauseEncRsp(self, packet):
        io.info("LL Pause Enc Response (from slave)\nRedirecting to master...")

    @module.scenarioSignal("onSlaveLLVersionInd")
    def slaveLLVersionInd(self, packet):
        io.info("Slave: " + packet.toString())

    @module.scenarioSignal("onMasterLLVersionInd")
    def masterLLVersionInd(self, packet):
        io.info("Master: " + packet.toString())

    @module.scenarioSignal("onSlaveLLRejectInd")
    def slaveLLRejectInd(self, packet):
        io.info("Slave: " + packet.toString())

    @module.scenarioSignal("onMasterLLRejectInd")
    def masterLLRejectInd(self, packet):
        io.info("Master: " + packet.toString())

    @module.scenarioSignal("onSlaveLLSlaveFeatureReq")
    def slaveLLSlaveFeatureReq(self, packet):
        io.info("Slave: " + packet.toString())

    @module.scenarioSignal("onSlaveLLConnParamReq")
    def slaveLLConnParamReq(self, packet):
        io.info("Slave: " + packet.toString())

    @module.scenarioSignal("onMasterLLConnParamReq")
    def masterLLConnParamReq(self, packet):
        io.info("Master: " + packet.toString())

    @module.scenarioSignal("onSlaveLLConnParamRsp")
    def slaveLLConnParamRsp(self, packet):
        io.info("Slave: " + packet.toString())

    @module.scenarioSignal("onMasterLLConnParamRsp")
    def masterLLConnParamRsp(self, packet):
        io.info("Master: " + packet.toString())

    @module.scenarioSignal("onSlaveLLRejectExtInd")
    def slaveLLRejectExtInd(self, packet):
        io.info(
            "Slave: "
            + packet.toString()
            + "\n\t"
            + hex(packet.error_code)
            + " = "
            + errorCode[packet.error_code]
        )

    @module.scenarioSignal("onMasterLLRejectExtInd")
    def masterLLRejectExtInd(self, packet):
        io.info(
            "Master: "
            + packet.toString()
            + "\n\t"
            + hex(packet.error_code)
            + " = "
            + errorCode[packet.error_code]
        )

    @module.scenarioSignal("onSlaveLLPingReq")
    def slaveLLPingReq(self, packet):
        io.info("Slave: " + packet.toString())

    @module.scenarioSignal("onMasterLLPingReq")
    def masterLLPingReq(self, packet):
        io.info("Master: " + packet.toString())

    @module.scenarioSignal("onSlaveLLPingRsp")
    def slaveLLPingRsp(self, packet):
        io.info("Slave: " + packet.toString())

    @module.scenarioSignal("onMasterLLPingRsp")
    def masterLLPingRsp(self, packet):
        io.info("Master: " + packet.toString())

    @module.scenarioSignal("onSlaveLLLengthReq")
    def slaveLLLengthReq(self, packet):
        io.info("Slave: " + packet.toString())

    @module.scenarioSignal("onMasterLLLengthReq")
    def masterLLLengthReq(self, packet):
        io.info("Master: " + packet.toString())

    @module.scenarioSignal("onSlaveLLLengthRsp")
    def slaveLLLengthRsp(self, packet):
        io.info("Slave: " + packet.toString())

    @module.scenarioSignal("onMasterLLLengthRsp")
    def masterLLLengthRsp(self, packet):
        io.info("Master: " + packet.toString())

    @module.scenarioSignal("onSlaveLLPhyReq")
    def slaveLLPhyReq(self, packet):
        io.info("Slave: " + packet.toString())

    @module.scenarioSignal("onMasterLLPhyReq")
    def masterLLPhyReq(self, packet):
        io.info("Master: " + packet.toString())

    @module.scenarioSignal("onSlaveLLPhyRsp")
    def slaveLLPhyRsp(self, packet):
        io.info("Slave: " + packet.toString())

    @module.scenarioSignal("onMasterLLPhyRsp")
    def masterLLPhyRsp(self, packet):
        io.info("Master: " + packet.toString())

    @module.scenarioSignal("onSlaveLLPhyUpdateInd")
    def slaveLLPhyUpdateInd(self, packet):
        io.info("Slave: " + packet.toString())

    @module.scenarioSignal("onMasterLLPhyUpdateInd")
    def masterLLPhyUpdateInd(self, packet):
        io.info("Master: " + packet.toString())

    @module.scenarioSignal("onSlaveLLMinUsedChannelsInd")
    def slaveLLMinUsedChannelsInd(self, packet):
        io.info("Slave: " + packet.toString())

    @module.scenarioSignal("onMasterLLMinUsedChannelsInd")
    def masterLLMinUsedChannelsInd(self, packet):
        io.info("Master: " + packet.toString())

    # TODO: Callbacks, which are by the time of writing not supported by Dongle
    # @module.scenarioSignal("onSlaveLLCTEReq")
    # def slaveLLCTEReq(self, packet):
    #     io.info("Slave: " + packet.toString())

    # @module.scenarioSignal("onMasterLLCTEReq")
    # def masterLLCTEReq(self, packet):
    #     io.info("Master: " + packet.toString())

    # @module.scenarioSignal("onSlaveLLCTERsp")
    # def slaveLLCTERsp(self, packet):
    #     io.info("Slave: " + packet.toString())

    # @module.scenarioSignal("onMasterLLCTERsp")
    # def masterLLCTERsp(self, packet):
    #     io.info("Master: " + packet.toString())

    # # @module.scenarioSignal("onSlaveLLPeriodicSyncInd")
    # def slaveLLPeriodicSyncInd(self, packet):
    #     io.info("Slave: " + packet.toString())

    # @module.scenarioSignal("onMasterLLPeriodicSyncInd")
    # def masterLLPeriodicSyncInd(self, packet):
    #     io.info("Master: " + packet.toString())

    # @module.scenarioSignal("onSlaveLLClockAccuracyReq")
    # def slaveLLClockAccuracyReq(self, packet):
    #     io.info("Slave: " + packet.toString())

    # @module.scenarioSignal("onMasterLLClockAccuracyReq")
    # def masterLLClockAccuracyReq(self, packet):
    #     io.info("Master: " + packet.toString())

    # @module.scenarioSignal("onSlaveLLClockAccuracyRsp")
    # def slaveLLClockAccuracyRsp(self, packet):
    #     io.info("Slave: " + packet.toString())

    # @module.scenarioSignal("onMasterLLClockAccuracyRsp")
    # def masterLLClockAccuracyRsp(self, packet):
    #     io.info("Master: " + packet.toString())

    # @module.scenarioSignal("onSlaveLLCISReq")
    # def slaveLLCISReq(self, packet):
    #     io.info("Slave: " + packet.toString())

    # @module.scenarioSignal("onMasterLLCISReq")
    # def masterLLCISReq(self, packet):
    #     io.info("Master: " + packet.toString())

    # @module.scenarioSignal("onSlaveLLCISRsp")
    # def slaveLLCISRsp(self, packet):
    #     io.info("Slave: " + packet.toString())

    # @module.scenarioSignal("onMasterLLCISRsp")
    # def masterLLCISRsp(self, packet):
    #     io.info("Master: " + packet.toString())

    # @module.scenarioSignal("onSlaveLLCISInd")
    # def slaveLLCISInd(self, packet):
    #     io.info("Slave: " + packet.toString())

    # @module.scenarioSignal("onMasterLLCISInd")
    # def masterLLCISInd(self, packet):
    #     io.info("Master: " + packet.toString())

    # @module.scenarioSignal("onSlaveLLCISTerminateInd")
    # def slaveLLCISTerminateInd(self, packet):
    #     io.info("Slave: " + packet.toString())

    # @module.scenarioSignal("onMasterLLCISTerminateInd")
    # def masterLLCISTerminateInd(self, packet):
    #     io.info("Master: " + packet.toString())

    # @module.scenarioSignal("onSlaveLLPowerControlReq")
    # def slaveLLPowerControlReq(self, packet):
    #     io.info("Slave: " + packet.toString())

    # @module.scenarioSignal("onMasterLLPowerControlReq")
    # def masterLLPowerControlReq(self, packet):
    #     io.info("Master: " + packet.toString())

    # @module.scenarioSignal("onSlaveLLPowerControlRsp")
    # def slaveLLPowerControlRsp(self, packet):
    #     io.info("Slave: " + packet.toString())

    # @module.scenarioSignal("onMasterLLPowerControlRsp")
    # def masterLLPowerControlRsp(self, packet):
    #     io.info("Master: " + packet.toString())

    # @module.scenarioSignal("onSlaveLLChangeInd")
    # def slaveLLChangeInd(self, packet):
    #     io.info("Slave: " + packet.toString())

    # @module.scenarioSignal("onMasterLLChangeInd")
    # def masterLLChangeInd(self, packet):
    #     io.info("Master: " + packet.toString())

    @module.scenarioSignal("onMasterLLEncCtrl")
    def masterLLEncCtrl(self, packet):
        io.info("Master: " + packet.toString())

    @module.scenarioSignal("onSlaveLLEncCtrl")
    def slaveLLEncCtrl(self, packet):
        io.info("Slave: " + packet.toString())

    @module.scenarioSignal("onMasterLLEncData")
    def masterLLEncData(self, packet):
        io.info("Master: " + packet.toString())

    @module.scenarioSignal("onSlaveLLEncData")
    def slaveLLEncData(self, packet):
        io.info("Slave: " + packet.toString())

    def registerSlaveEvents(self):

        # Advertisement callbacks
        self.a2sReceiver.onEvent("BLEAdvertisement", callback=self.slaveAdvertisement)

        # Connect Callbacks
        self.a2sReceiver.onEvent(
            "BLEConnectResponse", callback=self.slaveConnectionComplete
        )

        # Disconnect Callbacks
        self.a2sReceiver.onEvent("BLEDisconnect", callback=self.slaveDisconnect)

        # Error Callback
        self.a2sReceiver.onEvent("BLEErrorResponse", callback=self.errorResponse)

        # Write Callbacks
        self.a2sReceiver.onEvent("BLEWriteResponse", callback=self.writeResponse)

        # Read Callbacks
        self.a2sReceiver.onEvent("BLEReadResponse", callback=self.readResponse)
        self.a2sReceiver.onEvent("BLEReadBlobResponse", callback=self.readBlobResponse)

        # Notification Callback
        self.a2sReceiver.onEvent(
            "BLEHandleValueNotification", callback=self.notification
        )
        self.a2sReceiver.onEvent("BLEHandleValueIndication", callback=self.indication)

        # Find Information Callbacks
        self.a2sReceiver.onEvent(
            "BLEFindInformationResponse", callback=self.findInformationResponse
        )

        # Find Type Value Callbacks
        self.a2sReceiver.onEvent(
            "BLEFindByTypeValueResponse", callback=self.findByTypeValueResponse
        )

        # Read By Callbacks
        self.a2sReceiver.onEvent("BLEReadByTypeRequest", callback=self.slaveReadByType)
        self.a2sReceiver.onEvent(
            "BLEReadByTypeResponse", callback=self.readByTypeResponse
        )
        self.a2sReceiver.onEvent(
            "BLEReadByGroupTypeResponse", callback=self.readByGroupTypeResponse
        )

        # MTU Callbacks
        self.a2sReceiver.onEvent(
            "BLEExchangeMTURequest", callback=self.slaveExchangeMtuRequest
        )
        self.a2sReceiver.onEvent(
            "BLEExchangeMTUResponse", callback=self.slaveExchangeMtuResponse
        )

        # Connection Parameter Update Callbacks
        self.a2sReceiver.onEvent(
            "BLEConnectionParameterUpdateRequest",
            callback=self.slaveConnectionParameterUpdateRequest,
        )

        # Security Manager Callbacks
        self.a2sReceiver.onEvent("BLEPairingResponse", callback=self.pairingResponse)
        self.a2sReceiver.onEvent("BLESecurityRequest", callback=self.securityRequest)
        self.a2sReceiver.onEvent("BLEPairingConfirm", callback=self.slavePairingConfirm)
        self.a2sReceiver.onEvent("BLEPairingRandom", callback=self.slavePairingRandom)
        self.a2sReceiver.onEvent("BLEPairingFailed", callback=self.slavePairingFailed)

        self.a2sReceiver.onEvent(
            "BLEEncryptionInformation", callback=self.slaveEncryptionInformation
        )
        self.a2sReceiver.onEvent(
            "BLEMasterIdentification", callback=self.slaveMasterIdentification
        )
        self.a2sReceiver.onEvent(
            "BLEIdentityInformation", callback=self.slaveIdentityInformation
        )
        self.a2sReceiver.onEvent(
            "BLEIdentityAddressInformation",
            callback=self.slaveIdentityAddressInformation,
        )
        self.a2sReceiver.onEvent(
            "BLESigningInformation", callback=self.slaveSigningInformation
        )

        self.a2sReceiver.onEvent("BLEPublicKey", callback=self.slavePublicKey)

        self.a2sReceiver.onEvent("BLEDHKeyCheck", callback=self.slaveDHKeyCheck)

        # HCI callbacks
        self.a2sReceiver.onEvent(
            "BLEEncryptionChange", callback=self.slaveEncryptionChange
        )

        # LL Callbacks
        self.a2sReceiver.onEvent(
            "BLELLConnUpdateInd", callback=self.slaveLLConnUpdateInd
        )
        self.a2sReceiver.onEvent("BLELLChanMapInd", callback=self.slaveLLChannelMapInd)
        self.a2sReceiver.onEvent("BLELLTerminateInd", callback=self.slaveLLTerminateInd)

        self.a2sReceiver.onEvent("BLELLEncRsp", callback=self.slaveLLEncRsp)

        self.a2sReceiver.onEvent("BLELLStartEncReq", callback=self.slaveLLStartEncReq)

        self.a2sReceiver.onEvent("BLELLUnknownRsp", callback=self.slaveLLUnknownRsp)

        self.a2sReceiver.onEvent("BLELLFeatureReq", callback=self.slaveLLFeatureReq)

        self.a2sReceiver.onEvent("BLELLFeatureRsp", callback=self.slaveLLFeatureRsp)

        self.a2sReceiver.onEvent("BLELLPauseEncRsp", callback=self.slaveLLPauseEncRsp)

        self.a2sReceiver.onEvent("BLELLVersionInd", callback=self.slaveLLVersionInd)

        self.a2sReceiver.onEvent("BLELLRejectInd", callback=self.slaveLLRejectInd)

        self.a2sReceiver.onEvent(
            "BLELLSlaveFeatureReq", callback=self.slaveLLSlaveFeatureReq
        )

        self.a2sReceiver.onEvent("BLELLConnParamReq", callback=self.slaveLLConnParamReq)

        self.a2sReceiver.onEvent("BLELLConnParamRsp", callback=self.slaveLLConnParamRsp)

        self.a2sReceiver.onEvent("BLELLRejectExtInd", callback=self.slaveLLRejectExtInd)

        self.a2sReceiver.onEvent("BLELLPingReq", callback=self.slaveLLPingReq)

        self.a2sReceiver.onEvent("BLELLPingRsp", callback=self.slaveLLPingRsp)

        self.a2sReceiver.onEvent("BLELLDataLenReq", callback=self.slaveLLLengthReq)

        self.a2sReceiver.onEvent("BLELLDataLenRsp", callback=self.slaveLLLengthRsp)

        self.a2sReceiver.onEvent("BLELLPhyReq", callback=self.slaveLLPhyReq)

        self.a2sReceiver.onEvent("BLELLPhyRsp", callback=self.slaveLLPhyRsp)

        self.a2sReceiver.onEvent("BLELLUpdPHYInd", callback=self.slaveLLPhyUpdateInd)

        self.a2sReceiver.onEvent(
            "BLELLMinUsedChann", callback=self.slaveLLMinUsedChannelsInd
        )

        # TODO: Callbacks, which are by the time of writing not supported by Dongle
        # self.a2sReceiver.onEvent("BLELLCTEReq", callback=self.slaveLLCTEReq)

        # self.a2sReceiver.onEvent("BLELLCTERsp", callback=self.slaveLLCTERsp)

        # self.a2sReceiver.onEvent("BLELLPeriodicSyncInd", callback=self.slaveLLPeriodicSyncInd)

        # self.a2sReceiver.onEvent("BLELLClockAccuracyReq", callback=self.slaveLLClockAccuracyReq)

        # self.a2sReceiver.onEvent("BLELLClockAccuracyRsp", callback=self.slaveLLClockAccuracyRsp)

        # self.a2sReceiver.onEvent("BLELLCISReq", callback=self.slaveLLCISReq)

        # self.a2sReceiver.onEvent("BLELLCISRsp", callback=self.slaveLLCISRsp)

        # self.a2sReceiver.onEvent("BLELLCISInd", callback=self.slaveLLCISInd)

        # self.a2sReceiver.onEvent("BLELLCISTerminateInd", callback=self.slaveLLCISTerminateInd)

        # self.a2sReceiver.onEvent("BLELLPowerControlReq", callback=self.slaveLLPowerControlReq)

        # self.a2sReceiver.onEvent("BLELLPowerControlRsp", callback=self.slaveLLPowerControlRsp)

        # self.a2sReceiver.onEvent("BLELLChangeInd", callback=self.slaveLLChangeInd)

        self.a2sReceiver.onEvent("BLELLEncCtrl", callback=self.slaveLLEncCtrl)

        self.a2sReceiver.onEvent("BLELLEncData", callback=self.slaveLLEncData)

    def registerMasterEvents(self):

        # Connect Callbacks
        self.a2mReceiver.onEvent(
            "BLEConnectResponse", callback=self.masterCreateConnection
        )

        # Disconnect Callbacks
        self.a2mReceiver.onEvent("BLEDisconnect", callback=self.masterDisconnect)

        # Write Callbacks
        self.a2mReceiver.onEvent("BLEWriteCommand", callback=self.writeCommand)
        self.a2mReceiver.onEvent("BLEWriteRequest", callback=self.writeRequest)

        # Read Callbacks
        self.a2mReceiver.onEvent("BLEReadRequest", callback=self.read)
        self.a2mReceiver.onEvent("BLEReadBlobRequest", callback=self.readBlob)

        # Notification Callback
        self.a2mReceiver.onEvent(
            "BLEHandleValueConfirmation", callback=self.confirmation
        )

        # Find Information Callbacks
        self.a2mReceiver.onEvent(
            "BLEFindInformationRequest", callback=self.findInformation
        )

        # Find Type Value Callbacks
        self.a2mReceiver.onEvent(
            "BLEFindByTypeValueRequest", callback=self.findByTypeValueRequest
        )

        # Read By Callbacks
        self.a2mReceiver.onEvent("BLEReadByTypeRequest", callback=self.masterReadByType)
        self.a2mReceiver.onEvent(
            "BLEReadByGroupTypeRequest", callback=self.readByGroupType
        )

        # MTU Callbacks
        self.a2mReceiver.onEvent(
            "BLEExchangeMTURequest", callback=self.masterExchangeMtuRequest
        )
        self.a2mReceiver.onEvent(
            "BLEExchangeMTUResponse", callback=self.masterExchangeMtuResponse
        )

        # Connection Parameter Update Callbacks
        self.a2mReceiver.onEvent(
            "BLEConnectionParameterUpdateResponse",
            callback=self.masterConnectionParameterUpdateResponse,
        )

        # Security Manager Callbacks
        self.a2mReceiver.onEvent("BLEPairingRequest", callback=self.pairingRequest)
        self.a2mReceiver.onEvent(
            "BLEPairingConfirm", callback=self.masterPairingConfirm
        )
        self.a2mReceiver.onEvent("BLEPairingRandom", callback=self.masterPairingRandom)
        self.a2mReceiver.onEvent("BLEPairingFailed", callback=self.masterPairingFailed)

        self.a2mReceiver.onEvent(
            "BLEEncryptionInformation", callback=self.masterEncryptionInformation
        )
        self.a2mReceiver.onEvent(
            "BLEMasterIdentification", callback=self.masterMasterIdentification
        )
        self.a2mReceiver.onEvent(
            "BLEIdentityInformation", callback=self.masterIdentityInformation
        )
        self.a2mReceiver.onEvent(
            "BLEIdentityAddressInformation",
            callback=self.masterIdentityAddressInformation,
        )
        self.a2mReceiver.onEvent(
            "BLESigningInformation", callback=self.masterSigningInformation
        )

        self.a2mReceiver.onEvent("BLEPublicKey", callback=self.masterPublicKey)

        self.a2mReceiver.onEvent("BLEDHKeyCheck", callback=self.masterDHKeyCheck)

        self.a2mReceiver.onEvent(
            "BLELongTermKeyRequest", callback=self.masterLongTermKeyRequest
        )

        # HCI callbacks
        self.a2mReceiver.onEvent(
            "BLEEncryptionChange", callback=self.masterEncryptionChange
        )

        # LL Callbacks
        self.a2mReceiver.onEvent(
            "BLELLConnUpdateInd", callback=self.masterLLConnUpdateInd
        )
        self.a2mReceiver.onEvent("BLELLChanMapInd", callback=self.masterLLChannelMapInd)
        self.a2mReceiver.onEvent(
            "BLELLTerminateInd", callback=self.masterLLTerminateInd
        )

        self.a2mReceiver.onEvent("BLELLEncReq", callback=self.masterLLEncReq)

        self.a2mReceiver.onEvent("BLELLUnknownRsp", callback=self.masterLLUnknownRsp)

        self.a2mReceiver.onEvent("BLELLFeatureReq", callback=self.masterLLFeatureReq)

        self.a2mReceiver.onEvent("BLELLFeatureRsp", callback=self.masterLLFeatureRsp)

        self.a2mReceiver.onEvent("BLELLPauseEncReq", callback=self.masterLLPauseEncReq)

        self.a2mReceiver.onEvent("BLELLPauseEncRsp", callback=self.masterLLPauseEncRsp)

        self.a2mReceiver.onEvent("BLELLVersionInd", callback=self.masterLLVersionInd)

        self.a2mReceiver.onEvent("BLELLRejectInd", callback=self.masterLLRejectInd)

        self.a2mReceiver.onEvent(
            "BLELLConnParamReq", callback=self.masterLLConnParamReq
        )
        self.a2mReceiver.onEvent(
            "BLELLConnParamRsp", callback=self.masterLLConnParamRsp
        )

        self.a2mReceiver.onEvent(
            "BLELLRejectExtInd", callback=self.masterLLRejectExtInd
        )

        self.a2mReceiver.onEvent("BLELLPingReq", callback=self.masterLLPingReq)

        self.a2mReceiver.onEvent("BLELLPingRsp", callback=self.masterLLPingRsp)

        self.a2mReceiver.onEvent("BLELLDataLenReq", callback=self.masterLLLengthReq)

        self.a2mReceiver.onEvent("BLELLDataLenRsp", callback=self.masterLLLengthRsp)

        self.a2mReceiver.onEvent("BLELLPhyReq", callback=self.masterLLPhyReq)

        self.a2mReceiver.onEvent("BLELLPhyRsp", callback=self.masterLLPhyRsp)

        self.a2mReceiver.onEvent("BLELLUpdPHYInd", callback=self.masterLLPhyUpdateInd)

        self.a2mReceiver.onEvent(
            "BLELLMinUsedChann", callback=self.masterLLMinUsedChannelsInd
        )

        # TODO: Callbacks, which are by the time of writing not supported by Dongle
        # self.a2mReceiver.onEvent("BLELLCTEReq", callback=self.masterLLCTEReq)

        # self.a2mReceiver.onEvent("BLELLCTERsp", callback=self.masterLLCTERsp)

        # self.a2mReceiver.onEvent("BLELLPeriodicSyncInd", callback=self.masterLLPeriodicSyncInd)

        # self.a2mReceiver.onEvent("BLELLClockAccuracyReq", callback=self.masterLLClockAccuracyReq)

        # self.a2mReceiver.onEvent("BLELLClockAccuracyRsp", callback=self.masterLLClockAccuracyRsp)

        # self.a2mReceiver.onEvent("BLELLCISReq", callback=self.masterLLCISReq)

        # self.a2mReceiver.onEvent("BLELLCISRsp", callback=self.masterLLCISRsp)

        # self.a2mReceiver.onEvent("BLELLCISInd", callback=self.masterLLCISInd)

        # self.a2mReceiver.onEvent("BLELLCISTerminateInd", callback=self.masterLLCISTerminateInd)

        # self.a2mReceiver.onEvent("BLELLPowerControlReq", callback=self.masterLLPowerControlReq)

        # self.a2mReceiver.onEvent("BLELLPowerControlRsp", callback=self.masterLLPowerControlRsp)

        # self.a2mReceiver.onEvent("BLELLChangeInd", callback=self.masterLLChangeInd)

        self.a2mReceiver.onEvent("BLELLEncCtrl", callback=self.masterLLEncCtrl)

        self.a2mReceiver.onEvent("BLELLEncData", callback=self.masterLLEncData)

    def registerEvents(self):
        self.registerSlaveEvents()
        if self.args["INTERFACE2"] != "":
            self.registerMasterEvents()

    def run(self):

        self.initEmittersAndReceivers()

        if self.args["INTERFACE2"] != "":
            self.a2mReceiver.storeCallbacks()
        self.a2sReceiver.storeCallbacks()

        if self.checkSlaveEmitterCapabilities() and (
            self.args["INTERFACE2"] == "" or self.checkMasterEmitterCapabilities()
        ):
            self.registerEvents()

            if not self.loadScenario():
                io.warning("This module makes no sense without scenario!")
                return self.nok()

            io.info("Scenario loaded !")
            self.setStage(self.BLEStage.IDLE)

            self.startScenario()

            self.waitUntilStage(self.BLEStage.STOP)

            if self.args["INTERFACE2"] != "":
                self.a2mReceiver.restoreCallbacks()
            self.a2sReceiver.restoreCallbacks()
            # Clean up connections
            if self.args["INTERFACE2"] != "":
                if self.a2mEmitter.isConnected():
                    self.a2mEmitter.sendp(ble.BLEDisconnect())
                while self.a2mEmitter.isConnected():
                    utils.wait(seconds=0.01)

            if self.a2sEmitter.isConnected():
                self.a2sEmitter.sendp(ble.BLEDisconnect())
            while self.a2sEmitter.isConnected():
                utils.wait(seconds=0.01)
            # Reset public address
            if self.args["INTERFACE2"] != "":
                self.a2mEmitter.setAddress("00:00:00:00:00", random=False)
            self.a2sEmitter.setAddress("00:00:00:00:00", random=False)

            moduleResult = {}
            scenarioResult = self.endScenario({})
            io.info("{}".format(scenarioResult))
            moduleResult["scenarioResult"] = scenarioResult
            return self.ok(moduleResult)
        else:
            io.fail(
                "Interfaces provided ("
                + str(self.args["INTERFACE1"])
                + str(self.args["INTERFACE2"])
                + ") are not able to run this module."
            )
            return self.nok()
