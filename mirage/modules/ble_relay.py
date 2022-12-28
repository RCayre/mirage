import os
from enum import IntEnum
from mirage.libs import utils, ble
from mirage.core import module
from mirage.libs.ble_utils.packets import *
from mirage.libs import io
from mirage.libs.ble_utils.constants import LL_ERROR_CODES as errorCode


class ble_relay(module.WirelessModule):
    class BLEMitmStage(IntEnum):
        SCAN = 1
        CLONE = 2
        WAIT_CONNECTION = 3
        ACTIVE_MITM = 4
        STOP = 5

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

    def checkCapabilities(self):
        a2scap = self.a2sEmitter.hasCapabilities(
            "COMMUNICATING_AS_MASTER", "INITIATING_CONNECTION", "SCANNING"
        )
        a2mcap = self.a2mEmitter.hasCapabilities(
            "COMMUNICATING_AS_SLAVE", "RECEIVING_CONNECTION", "ADVERTISING"
        )
        return a2scap and a2mcap

    def init(self):
        self.technology = "ble"
        self.type = "analysis"
        self.description = "The module offers the possibility to analyse a ble connection without manipulating it. Without any szenario loaded it act as a proxy."
        self.args = {
            "INTERFACE1": "hci0",
            "INTERFACE2": "hci1",
            "TARGET": "12:34:56:78:90:FF",
            "CONNECTION_TYPE": "public",
            "SLAVE_SPOOFING": "yes",
            "MASTER_SPOOFING": "yes",
            "ADVERTISING_STRATEGY": "preconnect",  # "preconnect" (btlejuice) or "flood" (gattacker)
            "SHOW_SCANNING": "yes",
            "SCENARIO": "",
        }
        self.stage = self.BLEMitmStage.SCAN

        # Send ENC_REQ/RSP and ENC_START_RSP only once
        self.enc_req = False
        self.enc_rsp = False
        self.start_enc_req = False

        # Save to know when to quit
        self.master_start_enc_rsp = False
        self.slave_start_enc_rsp = False

        # Save payload, sn and nesn to determine if encrpyted data/ctrl packet has already been send
        self.master_enc_ctrl_sn = -1
        self.master_enc_ctrl_nesn = -1
        self.master_enc_ctrl_payload = b""
        self.master_enc_data_sn = -1
        self.master_enc_data_nesn = -1
        self.master_enc_data_payload = b""
        self.slave_enc_ctrl_sn = -1
        self.slave_enc_ctrl_nesn = -1
        self.slave_enc_ctrl_payload = b""
        self.slave_enc_data_sn = -1
        self.slave_enc_data_nesn = -1
        self.slave_enc_data_payload = b""

        # To save connection params from ConnectionParameterRequest from initial slave connection
        # for later use
        self.slave_timeout = 0
        self.slave_latency = 0
        self.slave_minInterval = 0
        self.slave_maxInterval = 0
        self.slave_minCe = 0
        self.slave_maxCe = 0

        # Security Manager related
        self.pReq = None
        self.pRes = None
        self.initiatorAddress = None
        self.initiatorAddressType = None
        self.responderAddress = None
        self.responderAddressType = None
        self.mRand = None
        self.mConfirm = None
        self.sRand = None
        self.sConfirm = None
        self.forgedmRand = None
        self.forgedsRand = None
        self.temporaryKey = None

        # CLONE stage related
        self.addrType = None
        self.address = None
        self.intervalMin = None
        self.intervalMax = None
        self.dataAdvInd = None
        self.dataScanRsp = None

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

    # Configuration methods
    def initEmittersAndReceivers(self):
        attackerToSlaveInterface = self.args["INTERFACE1"]
        attackerToMasterInterface = self.args["INTERFACE2"]

        self.a2sEmitter = self.getEmitter(interface=attackerToSlaveInterface)
        self.a2sReceiver = self.getReceiver(interface=attackerToSlaveInterface)

        self.a2mEmitter = self.getEmitter(interface=attackerToMasterInterface)
        self.a2mReceiver = self.getReceiver(interface=attackerToMasterInterface)

        if not self.a2mEmitter.isAddressChangeable() and utils.booleanArg(
            self.args["SLAVE_SPOOFING"]
        ):
            io.warning(
                "Interface "
                + attackerToMasterInterface
                + " is not able to change its address : "
                "Address spoofing will not be enabled !"
            )

    # Stage related methods
    def getStage(self):
        return self.stage

    @module.scenarioSignal("onStageChange")
    def setStage(self, value):
        self.stage = value

    def waitUntilStage(self, stage):
        while self.getStage() != stage:
            utils.wait(seconds=0.01)

    # Advertising related methods
    @module.scenarioSignal("onSlaveAdvertisement")
    def scanStage(self, packet):
        if utils.booleanArg(self.args["SHOW_SCANNING"]):
            packet.show()
        if self.getStage() == self.BLEMitmStage.SCAN:
            if utils.addressArg(self.args["TARGET"]) == packet.addr.upper():
                if packet.type == "ADV_IND":
                    self.address = utils.addressArg(self.args["TARGET"])
                    data = packet.getRawDatas()
                    self.intervalMin = packet.intervalMin
                    self.intervalMax = packet.intervalMax
                    self.addrType = packet.addrType
                    self.dataAdvInd = data
                elif packet.type == "SCAN_RSP":
                    self.dataScanRsp = packet.getRawDatas()

            if self.dataAdvInd is not None and self.dataScanRsp is not None:
                self.cloneStage(
                    self.address,
                    self.dataAdvInd,
                    self.dataScanRsp,
                    self.intervalMin,
                    self.intervalMax,
                    self.addrType,
                )

    @module.scenarioSignal("onCloning")
    def cloneStage(
        self, address, data, dataResponse, intervalMin, intervalMax, addrType
    ):
        io.info("Entering CLONE stage ...")
        self.setStage(self.BLEMitmStage.CLONE)

        if self.args["ADVERTISING_STRATEGY"] == "flood":
            intervalMin = 33
            intervalMax = 34

        if (
            utils.booleanArg(self.args["SLAVE_SPOOFING"])
            and address != self.a2mEmitter.getAddress()
        ):
            self.a2mEmitter.setAddress(address, random=1 == addrType)
        self.a2mEmitter.setScanningParameters(data=dataResponse)
        self.a2mEmitter.setAdvertisingParameters(
            data=data,
            intervalMin=intervalMin,
            intervalMax=intervalMax,
            daType=addrType,
            oaType=addrType,
        )

    # Connection related methods
    @module.scenarioSignal("onSlaveConnect")
    def connectOnSlave(self, initiatorType="public"):
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
        io.success("Connected on slave : " + self.a2sReceiver.getCurrentConnection())

    @module.scenarioSignal("onMasterConnect")
    def connect(self, packet):
        if self.getStage() == self.BLEMitmStage.WAIT_CONNECTION:

            io.success("Master connected : " + packet.srcAddr)

            self.initiatorAddress = packet.srcAddr
            self.initiatorAddressType = b"\x00" if packet.type == "public" else b"\x01"

            if self.args["ADVERTISING_STRATEGY"] == "preconnect":
                if utils.booleanArg(self.args["MASTER_SPOOFING"]):
                    self.a2sEmitter.sendp(ble.BLEDisconnect())
                    while self.a2sEmitter.isConnected():
                        utils.wait(seconds=0.01)
                    self.a2sEmitter.setAddress(
                        packet.srcAddr, random=packet.type == "random"
                    )
                    address = utils.addressArg(self.args["TARGET"])
                    connectionType = self.args["CONNECTION_TYPE"]
                    io.info("Giving slave 1s time to reset...")
                    utils.wait(seconds=1)
                    io.info("Connecting to slave " + address + "...")
                    self.a2sEmitter.sendp(
                        ble.BLEConnect(
                            dstAddr=address,
                            type=connectionType,
                            initiatorType=packet.type,
                        )
                    )
                    while not self.a2sEmitter.isConnected():
                        utils.wait(seconds=0.01)
            if self.args["ADVERTISING_STRATEGY"] == "flood":
                if utils.booleanArg(self.args["MASTER_SPOOFING"]):
                    self.a2sEmitter.setAddress(
                        packet.srcAddr, random=packet.type == "random"
                    )
                self.connectOnSlave(packet.type)
            self.setStage(self.BLEMitmStage.ACTIVE_MITM)
            io.info("Entering ACTIVE_MITM stage ...")

    @module.scenarioSignal("onMasterDisconnect")
    def disconnectMaster(self, packet):
        io.info("Master disconnected !")
        self.setStage(self.BLEMitmStage.STOP)

    @module.scenarioSignal("onSlaveDisconnect")
    def disconnectSlave(self, packet):
        io.info("Slave disconnected !")

    @module.scenarioSignal("onMasterExchangeMTURequest")
    def exchangeMtuRequest(self, packet):
        if self.getStage() == self.BLEMitmStage.ACTIVE_MITM:
            io.info("Exchange MTU Request (from master) : mtu = " + str(packet.mtu))
            io.info("Redirecting to slave ...")
            self.a2sEmitter.sendp(ble.BLEExchangeMTURequest(mtu=packet.mtu))

    @module.scenarioSignal("onSlaveExchangeMTUResponse")
    def exchangeMtuResponse(self, packet):
        if self.getStage() == self.BLEMitmStage.ACTIVE_MITM:
            io.info("Exchange MTU Response (from slave) : mtu = " + str(packet.mtu))
            io.info("Redirecting to master ...")
            self.a2mEmitter.sendp(ble.BLEExchangeMTUResponse(mtu=packet.mtu))

    @module.scenarioSignal("onMasterWriteCommand")
    def writeCommand(self, packet):
        if self.getStage() == self.BLEMitmStage.ACTIVE_MITM:
            io.info(
                "Write Command (from master) : handle = "
                + hex(packet.handle)
                + " / value = "
                + packet.value.hex()
            )
            io.info("Redirecting to slave ...")
            self.a2sEmitter.sendp(
                ble.BLEWriteCommand(handle=packet.handle, value=packet.value)
            )

    @module.scenarioSignal("onMasterWriteRequest")
    def writeRequest(self, packet):
        if self.getStage() == self.BLEMitmStage.ACTIVE_MITM:
            io.info(
                "Write Request (from master) : handle = "
                + hex(packet.handle)
                + " / value = "
                + packet.value.hex()
            )
            io.info("Redirecting to slave ...")
            self.a2sEmitter.sendp(
                ble.BLEWriteRequest(handle=packet.handle, value=packet.value)
            )

    @module.scenarioSignal("onSlaveWriteResponse")
    def writeResponse(self, packet):
        if self.getStage() == self.BLEMitmStage.ACTIVE_MITM:
            io.info("Write Response (from slave)")
            io.info("Redirecting to master ...")
            self.a2mEmitter.sendp(ble.BLEWriteResponse())

    @module.scenarioSignal("onMasterReadBlobRequest")
    def readBlob(self, packet):
        if self.getStage() == self.BLEMitmStage.ACTIVE_MITM:
            io.info(
                "Read Blob Request (from master) : handle = "
                + hex(packet.handle)
                + " / offset = "
                + str(packet.offset)
            )
            io.info("Redirecting to slave ...")
            self.a2sEmitter.sendp(
                ble.BLEReadBlobRequest(handle=packet.handle, offset=packet.offset)
            )

    @module.scenarioSignal("onSlaveReadBlobResponse")
    def readBlobResponse(self, packet):
        if self.getStage() == self.BLEMitmStage.ACTIVE_MITM:
            io.info("Read Blob Response (from slave) : value = " + packet.value.hex())
            io.info("Redirecting to master ...")
            self.a2mEmitter.sendp(ble.BLEReadBlobResponse(value=packet.value))

    @module.scenarioSignal("onMasterReadRequest")
    def read(self, packet):
        if self.getStage() == self.BLEMitmStage.ACTIVE_MITM:
            io.info("Read Request (from master) : handle = " + hex(packet.handle))
            io.info("Redirecting to slave ...")
            self.a2sEmitter.sendp(ble.BLEReadRequest(handle=packet.handle))

    @module.scenarioSignal("onSlaveReadResponse")
    def readResponse(self, packet):
        if self.getStage() == self.BLEMitmStage.ACTIVE_MITM:
            io.info("Read Response (from slave) : value = " + packet.value.hex())
            io.info("Redirecting to master ...")
            self.a2mEmitter.sendp(ble.BLEReadResponse(value=packet.value))

    @module.scenarioSignal("onSlaveErrorResponse")
    def errorResponse(self, packet):
        if self.getStage() == self.BLEMitmStage.ACTIVE_MITM:
            io.info(
                "Error Response (from slave) : request = "
                + hex(packet.request)
                + " / handle = "
                + hex(packet.handle)
                + " / ecode = "
                + hex(packet.ecode)
            )
            io.info("Redirecting to master ...")
            self.a2mEmitter.sendp(
                ble.BLEErrorResponse(
                    request=packet.request, handle=packet.handle, ecode=packet.ecode
                )
            )

    @module.scenarioSignal("onSlaveHandleValueNotification")
    def notification(self, packet):
        if self.getStage() == self.BLEMitmStage.ACTIVE_MITM:
            io.info(
                "Handle Value Notification (from slave) : handle = "
                + hex(packet.handle)
                + " / value = "
                + packet.value.hex()
            )
            io.info("Redirecting to master ...")
            self.a2mEmitter.sendp(
                ble.BLEHandleValueNotification(handle=packet.handle, value=packet.value)
            )

    @module.scenarioSignal("onSlaveHandleValueIndication")
    def indication(self, packet):
        if self.getStage() == self.BLEMitmStage.ACTIVE_MITM:
            io.info(
                "Handle Value Indication (from slave) : handle = "
                + hex(packet.handle)
                + " / value = "
                + packet.value.hex()
            )
            io.info("Redirecting to master ...")
            self.a2mEmitter.sendp(
                ble.BLEHandleValueIndication(handle=packet.handle, value=packet.value)
            )

    @module.scenarioSignal("onMasterHandleValueConfirmation")
    def confirmation(self, packet):
        if self.getStage() == self.BLEMitmStage.ACTIVE_MITM:
            io.info("Handle Value Confirmation (from master)")
            io.info("Redirecting to slave ...")
            self.a2sEmitter.sendp(ble.BLEHandleValueConfirmation())

    @module.scenarioSignal("onMasterFindInformationRequest")
    def findInformation(self, packet):
        if self.getStage() == self.BLEMitmStage.ACTIVE_MITM:
            io.info(
                "Find Information Request (from master) : startHandle = "
                + hex(packet.startHandle)
                + " / endHandle = "
                + hex(packet.endHandle)
            )
            io.info("Redirecting to slave ...")
            self.a2sEmitter.sendp(
                ble.BLEFindInformationRequest(
                    startHandle=packet.startHandle, endHandle=packet.endHandle
                )
            )

    @module.scenarioSignal("onSlaveFindInformationResponse")
    def findInformationResponse(self, packet):
        if self.getStage() == self.BLEMitmStage.ACTIVE_MITM:
            io.info(
                "Find Information Response (from slave) : format = "
                + hex(packet.format)
                + " / data = "
                + packet.data.hex()
            )
            io.info("Redirecting to master ...")
            self.a2mEmitter.sendp(
                ble.BLEFindInformationResponse(format=packet.format, data=packet.data)
            )

    @module.scenarioSignal("onMasterFindByTypeValueRequest")
    def findByTypeValueRequest(self, packet):
        if self.getStage() == self.BLEMitmStage.ACTIVE_MITM:
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
            io.info("Redirecting to slave ...")
            self.a2sEmitter.sendp(
                ble.BLEFindByTypeValueRequest(
                    startHandle=packet.startHandle,
                    endHandle=packet.endHandle,
                    uuid=packet.uuid,
                    data=packet.data,
                )
            )

    @module.scenarioSignal("onSlaveFindByTypeValueResponse")
    def findByTypeValueResponse(self, packet):
        if self.getStage() == self.BLEMitmStage.ACTIVE_MITM:
            io.info("Find Type By Value Response (from slave)")
            io.info("Redirecting to master ...")
            self.a2mEmitter.sendp(
                ble.BLEFindByTypeValueResponse(handles=packet.handles)
            )

    @module.scenarioSignal("onMasterReadByTypeRequest")
    def readByType(self, packet):
        if self.getStage() == self.BLEMitmStage.ACTIVE_MITM:
            io.info(
                "Read By Type Request (from master) : startHandle = "
                + hex(packet.startHandle)
                + " / endHandle = "
                + hex(packet.endHandle)
                + " / uuid = "
                + hex(packet.uuid)
            )
            io.info("Redirecting to slave ...")
            self.a2sEmitter.sendp(
                ble.BLEReadByTypeRequest(
                    startHandle=packet.startHandle,
                    endHandle=packet.endHandle,
                    uuid=packet.uuid,
                )
            )

    @module.scenarioSignal("onMasterReadByGroupTypeRequest")
    def readByGroupType(self, packet):
        if self.getStage() == self.BLEMitmStage.ACTIVE_MITM:
            io.info(
                "Read By Group Type Request (from master) : startHandle = "
                + hex(packet.startHandle)
                + " / endHandle = "
                + hex(packet.endHandle)
                + " / uuid = "
                + hex(packet.uuid)
            )
            io.info("Redirecting to slave ...")
            self.a2sEmitter.sendp(
                ble.BLEReadByGroupTypeRequest(
                    startHandle=packet.startHandle,
                    endHandle=packet.endHandle,
                    uuid=packet.uuid,
                )
            )

    @module.scenarioSignal("onSlaveReadByTypeResponse")
    def readByTypeResponse(self, packet):
        io.info("Read By Type Response (from slave) : data = " + packet.data.hex())
        io.info("Redirecting to master ...")
        self.a2mEmitter.sendp(ble.BLEReadByTypeResponse(data=packet.data))

    @module.scenarioSignal("onSlaveReadByGroupTypeResponse")
    def readByGroupTypeResponse(self, packet):
        if self.getStage() == self.BLEMitmStage.ACTIVE_MITM:
            io.info(
                "Read By Group Type Response (from slave) : length = "
                + str(packet.length)
                + " / data = "
                + packet.data.hex()
            )
            io.info("Redirecting to master ...")
            self.a2mEmitter.sendp(
                ble.BLEReadByGroupTypeResponse(length=packet.length, data=packet.data)
            )

    @module.scenarioSignal("onMasterPairingRequest")
    def pairingRequest(self, packet):
        if self.getStage() == self.BLEMitmStage.ACTIVE_MITM:
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
                    ble.KeyDistributionFlag(
                        data=bytes([packet.responderKeyDistribution])
                    )
                )
            )

            io.info("Redirecting to slave ...")
            self.a2sEmitter.sendp(
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
        if self.getStage() == self.BLEMitmStage.ACTIVE_MITM:
            io.info("Redirecting to master ...")
            self.a2mEmitter.sendp(
                ble.BLESecurityRequest(
                    connectionHandle=packet.connectionHandle,
                    authentication=packet.authentication,
                )
            )

    @module.scenarioSignal("onSlavePairingResponse")
    def pairingResponse(self, packet):
        if self.getStage() == self.BLEMitmStage.ACTIVE_MITM:
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
                    ble.KeyDistributionFlag(
                        data=bytes([packet.responderKeyDistribution])
                    )
                )
            )
            io.info("Redirecting to master ...")
            self.a2mEmitter.sendp(
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
        if self.getStage() == self.BLEMitmStage.ACTIVE_MITM:
            io.info("Pairing Confirm (from master) : confirm = " + packet.confirm.hex())

            io.info("Redirecting to slave ...")
            self.a2sEmitter.sendp(ble.BLEPairingConfirm(confirm=packet.confirm))

    @module.scenarioSignal("onSlavePairingConfirm")
    def slavePairingConfirm(self, packet):
        if self.getStage() == self.BLEMitmStage.ACTIVE_MITM:
            io.info("Pairing Confirm (from slave) : confirm = " + packet.confirm.hex())

            io.info("Redirecting to master ...")
            self.a2mEmitter.sendp(ble.BLEPairingConfirm(confirm=packet.confirm))

    @module.scenarioSignal("onMasterPairingRandom")
    def masterPairingRandom(self, packet):
        if self.getStage() == self.BLEMitmStage.ACTIVE_MITM:
            io.info("Pairing Random (from master) : random = " + packet.random.hex())

            io.info("Redirecting to slave ...")
            self.a2sEmitter.sendp(ble.BLEPairingRandom(random=packet.random))

    @module.scenarioSignal("onSlavePairingRandom")
    def slavePairingRandom(self, packet):
        if self.getStage() == self.BLEMitmStage.ACTIVE_MITM:
            io.info("Pairing Random (from slave) : random = " + packet.random.hex())

            io.info("Redirecting to master ...")
            self.a2mEmitter.sendp(ble.BLEPairingRandom(random=packet.random))

    def pairingFailed(self, packet):
        io.fail("Pairing Failed received : " + packet.toString())
        if packet.reason == ble.SM_ERR_PASSKEY_ENTRY_FAILED:
            io.fail("Reason : Passkey Entry Failed")
        elif packet.reason == ble.SM_ERR_OOB_NOT_AVAILABLE:
            io.fail("Reason : Out of Band not available")
        elif packet.reason == ble.SM_ERR_AUTH_REQUIREMENTS:
            io.fail("Reason : Authentication requirements")
        elif packet.reason == ble.SM_ERR_CONFIRM_VALUE_FAILED:
            io.fail("Reason : Confirm Value failed")
        elif packet.reason == ble.SM_ERR_PAIRING_NOT_SUPPORTED:
            io.fail("Reason : Pairing not supported")
        elif packet.reason == ble.SM_ERR_OOB_NOT_AVAILABLE:
            io.fail("Reason : Out of Band not available")
        elif packet.reason == ble.SM_ERR_ENCRYPTION_KEY_SIZE:
            io.fail("Reason : Encryption key size")
        elif packet.reason == ble.SM_ERR_COMMAND_NOT_SUPPORTED:
            io.fail("Reason : Command not supported")
        elif packet.reason == ble.SM_ERR_UNSPECIFIED_REASON:
            io.fail("Reason : Unspecified reason")
        elif packet.reason == ble.SM_ERR_REPEATED_ATTEMPTS:
            io.fail("Reason : Repeated Attempts")
        elif packet.reason == ble.SM_ERR_INVALID_PARAMETERS:
            io.fail("Reason : Invalid Parameters")
        elif packet.reason == ble.SM_ERR_DHKEY_CHECK_FAILED:
            io.fail("Reason : DHKey Check failed")
        elif packet.reason == ble.SM_ERR_NUMERIC_COMPARISON_FAILED:
            io.fail("Reason : Numeric Comparison failed")
        elif packet.reason == ble.SM_ERR_BREDR_PAIRING_IN_PROGRESS:
            io.fail("Reason : BR/EDR Pairing in progress")
        elif packet.reason == ble.SM_ERR_CROSS_TRANSPORT_KEY:
            io.fail("Reason : Cross-transport Key Derivation/Generation not allowed")
        else:
            io.fail("Reason : unknown")

    @module.scenarioSignal("onMasterPairingFailed")
    def masterPairingFailed(self, packet):
        if self.getStage() == self.BLEMitmStage.ACTIVE_MITM:
            io.info("Pairing Failed (from master) !")
            self.pairingFailed(packet)
            self.a2sEmitter.sendp(ble.BLEPairingFailed(reason=packet.reason))

    @module.scenarioSignal("onSlavePairingFailed")
    def slavePairingFailed(self, packet):
        if self.getStage() == self.BLEMitmStage.ACTIVE_MITM:
            io.info("Pairing Failed (from slave) !")
            self.pairingFailed(packet)
            self.a2mEmitter.sendp(ble.BLEPairingFailed(reason=packet.reason))

    @module.scenarioSignal("onSlaveEncryptionInformation")
    def slaveEncryptionInformation(self, packet):
        io.info(
            "Encryption Information (from slave) : Long Term Key = " + packet.ltk.hex()
        )
        io.info("Redirecting to master ...")
        self.a2mEmitter.sendp(ble.BLEEncryptionInformation(ltk=packet.ltk))

    @module.scenarioSignal("onSlaveMasterIdentification")
    def slaveMasterIdentification(self, packet):
        io.info(
            "Master Indentification (from slave) : ediv = "
            + hex(packet.ediv)
            + " / rand = "
            + packet.rand.hex()
        )
        io.info("Redirecting to master ...")
        self.a2mEmitter.sendp(
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
        io.info("Redirecting to master ...")
        self.a2mEmitter.sendp(
            ble.BLEIdentityAddressInformation(address=packet.address, type=packet.type)
        )

    @module.scenarioSignal("onSlaveIdentityInformation")
    def slaveIdentityInformation(self, packet):
        io.info("Identity Information (from slave) : irk = " + packet.irk.hex())
        io.info("Redirecting to master ...")
        self.a2mEmitter.sendp(ble.BLEIdentityInformation(irk=packet.irk))

    @module.scenarioSignal("onSlaveSigningInformation")
    def slaveSigningInformation(self, packet):
        io.info("Signing Information (from slave) : csrk = " + packet.csrk.hex())
        io.info("Redirecting to master ...")
        self.a2mEmitter.sendp(ble.BLESigningInformation(csrk=packet.csrk))

    @module.scenarioSignal("onMasterEncryptionInformation")
    def masterEncryptionInformation(self, packet):
        io.info(
            "Encryption Information (from master) : Long Term Key = " + packet.ltk.hex()
        )
        io.info("Redirecting to slave ...")
        self.a2sEmitter.sendp(ble.BLEEncryptionInformation(ltk=packet.ltk))

    @module.scenarioSignal("onMasterMasterIdentification")
    def masterMasterIdentification(self, packet):
        io.info(
            "Master Indentification (from master) : ediv = "
            + hex(packet.ediv)
            + " / rand = "
            + packet.rand.hex()
        )
        io.info("Redirecting to slave ...")
        self.a2sEmitter.sendp(
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
        io.info("Redirecting to slave ...")
        self.a2sEmitter.sendp(
            ble.BLEIdentityAddressInformation(address=packet.address, type=packet.type)
        )

    @module.scenarioSignal("onMasterIdentityInformation")
    def masterIdentityInformation(self, packet):
        io.info("Identity Information (from master) : irk = " + packet.irk.hex())
        io.info("Redirecting to slave ...")
        self.a2sEmitter.sendp(ble.BLEIdentityInformation(irk=packet.irk))

    @module.scenarioSignal("onMasterSigningInformation")
    def masterSigningInformation(self, packet):
        io.info("Signing Information (from master) : csrk = " + packet.csrk.hex())
        io.info("Redirecting to slave ...")
        self.a2sEmitter.sendp(ble.BLESigningInformation(csrk=packet.csrk))

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
        self.a2mEmitter.sendp(
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
        self.a2sEmitter.sendp(
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

        self.maxInterval = packet.maxInterval
        self.minInterval = packet.minInterval
        self.timeoutMult = packet.timeoutMult
        self.slaveLatency = packet.slaveLatency
        self.minCe = 0
        self.maxCe = 0
        if self.getStage() == self.BLEMitmStage.WAIT_CONNECTION:
            io.info("Sending a response to slave ...")
            self.a2sEmitter.sendp(
                ble.BLEConnectionParameterUpdateResponse(
                    l2capCmdId=packet.l2capCmdId, moveResult=0
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
            self.slave_timeout = (packet.timeoutMult,)
            self.slave_latency = (packet.slaveLatency,)
            self.slave_minInterval = (packet.minInterval,)
            self.slave_maxInterval = (packet.maxInterval,)
            self.slave_minCe = (0,)
            self.slave_maxCe = (0,)
        else:
            io.info("Redirecting to master ...")
            self.a2mEmitter.sendp(
                ble.BLEConnectionParameterUpdateRequest(
                    l2capCmdId=packet.l2capCmdId,
                    timeoutMult=packet.timeoutMult,
                    slaveLatency=packet.slaveLatency,
                    minInterval=packet.minInterval,
                    maxInterval=packet.maxInterval,
                )
            )

    @module.scenarioSignal("onMasterConnectionParameterUpdateResponse")
    def masterConnectionParameterUpdateResponse(self, packet):
        io.info(
            "Connection Parameter Update Response (from master) : moveResult = "
            + str(packet.moveResult)
        )

        io.info("Redirecting to slave ...")
        self.a2sEmitter.sendp(
            ble.BLEConnectionParameterUpdateResponse(
                l2capCmdId=packet.l2capCmdId, moveResult=packet.moveResult
            )
        )
        if packet.moveResult == 0 and self.a2sEmitter.isConnected():
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
        io.info("Redirecting to slave ...")
        self.a2sEmitter.sendp(ble.BLEDHKeyCheck(dhkey_check=packet.dhkey_check))

    @module.scenarioSignal("onSlaveDHKEyCheck")
    def slaveDHKEyCheck(self, packet):
        io.info("DH Key Check (from slave) : dhkey_check = " + packet.dhkey_check.hex())
        io.info("Redirecting to master ...")
        self.a2mEmitter.sendp(ble.BLEDHKeyCheck(dhkey_check=packet.dhkey_check))

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

        if not self.enc_req:
            self.enc_req = True
            self.a2sEmitter.sendp(
                ble.BLELLEncReq(
                    direction=packet.direction,
                    rand=packet.rand,
                    ediv=packet.ediv,
                    skdm=packet.skdm,
                    ivm=packet.ivm,
                )
            )
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
            io.info("Redirecting to slave ...")

    @module.scenarioSignal("onSlaveLLEncRsp")
    def slaveLLEncRsp(self, packet):
        if not self.enc_rsp:
            self.enc_rsp = True
            self.a2mEmitter.sendp(
                ble.BLELLEncRsp(
                    skds=packet.skds, ivs=packet.ivs, direction=packet.direction
                )
            )
            io.info(
                "LL Enc Response (from slave) : skds = "
                + str(packet.skds)
                + " / ivs = "
                + str(packet.ivs)
            )
            io.info("Redirecting to master ...")

    @module.scenarioSignal("onSlaveLLStartEncReq")
    def slaveLLStartEncReq(self, packet):
        io.info("LL Start Enc Request (from slave)")
        io.info("Redirecting to master...")
        self.start_enc_req = True
        self.a2mReceiver.enableEnc(True)
        self.a2mReceiver.enableMitM(True)
        self.a2sReceiver.enableEnc(True)
        self.a2sReceiver.enableMitM(True)
        self.a2mEmitter.sendp(ble.BLELLStartEncReq(direction=packet.direction))

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
        io.info("LL Pause Enc Request (from master)")
        io.info("Redirecting to slave...")
        self.a2sEmitter.sendp(ble.BLELLPauseEncReq(direction=packet.direction))

    @module.scenarioSignal("onMasterLLPauseEncRsp")
    def masterLLPauseEncRsp(self, packet):
        io.info("LL Pause Enc Response (from master)")
        io.info("Redirecting to slave...")
        self.a2sEmitter.sendp(ble.BLELLPauseEncRsp(direction=packet.direction))

    @module.scenarioSignal("onSlaveLLPauseEncRsp")
    def slaveLLPauseEncRsp(self, packet):
        io.info("LL Pause Enc Response (from slave)")
        io.info("Redirecting to master...")
        self.a2mEmitter.sendp(ble.BLELLPauseEncRsp(direction=packet.direction))

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
        if packet.direction == 1:
            return
        # Check if packet new
        if (
            self.master_enc_ctrl_payload != packet.encData
            or self.master_enc_ctrl_sn != packet.sn
            or self.master_enc_ctrl_nesn != packet.nesn
        ):
            self.master_enc_ctrl_sn = packet.sn
            self.master_enc_ctrl_nesn = packet.nesn
            self.master_enc_ctrl_payload = packet.encData

            io.info("Master: Redirecting to slave...")
            self.a2sEmitter.sendp(
                ble.BLELLEncCtrl(
                    encOpcode=packet.encOpcode,
                    sn=packet.sn,
                    nesn=packet.nesn,
                    encData=packet.encData,
                    direction=packet.direction,
                )
            )
            if self.start_enc_req and packet.getPayloadLength() == 5:
                self.master_start_enc_rsp = True

    @module.scenarioSignal("onSlaveLLEncCtrl")
    def slaveLLEncCtrl(self, packet):
        io.info("Slave: " + packet.toString())
        if packet.direction == 1:
            return
        # Check if packet new
        if (
            self.slave_enc_ctrl_payload != packet.encData
            or self.slave_enc_ctrl_sn != packet.sn
            or self.slave_enc_ctrl_nesn != packet.nesn
        ):
            self.slave_enc_ctrl_sn = packet.sn
            self.slave_enc_ctrl_nesn = packet.nesn
            self.slave_enc_ctrl_payload = packet.encData

            io.info("Slave: Redirecting to master...")
            self.a2mEmitter.sendp(
                ble.BLELLEncCtrl(
                    encOpcode=packet.encOpcode,
                    sn=packet.sn,
                    nesn=packet.nesn,
                    encData=packet.encData,
                    direction=packet.direction,
                )
            )
            if self.master_start_enc_rsp and packet.getPayloadLength() == 5:
                self.slave_start_enc_rsp = True

    @module.scenarioSignal("onMasterLLEncData")
    def masterLLEncData(self, packet):
        io.info("Master: " + packet.toString())
        io.info("Master: Redirecting to slave...")
        self.a2sEmitter.sendp(
            ble.BLELLEncData(
                PB=packet.PB,
                length=packet.length,
                payload=packet.payload,
            )
        )

    @module.scenarioSignal("onSlaveLLEncData")
    def slaveLLEncData(self, packet):
        io.info("Slave: " + packet.toString())
        io.info("Slave: Redirecting to master...")
        self.a2mEmitter.sendp(
            ble.BLELLEncData(
                PB=packet.PB,
                length=packet.length,
                payload=packet.payload,
            )
        )

    def registerEvents(self):

        # Connect Callbacks
        self.a2mReceiver.onEvent("BLEConnectResponse", callback=self.connect)

        # Disconnect Callbacks
        self.a2mReceiver.onEvent("BLEDisconnect", callback=self.disconnectMaster)
        self.a2sReceiver.onEvent("BLEDisconnect", callback=self.disconnectSlave)

        # Error Callback
        self.a2sReceiver.onEvent("BLEErrorResponse", callback=self.errorResponse)

        # Write Callbacks
        self.a2mReceiver.onEvent("BLEWriteCommand", callback=self.writeCommand)
        self.a2mReceiver.onEvent("BLEWriteRequest", callback=self.writeRequest)
        self.a2sReceiver.onEvent("BLEWriteResponse", callback=self.writeResponse)

        # Read Callbacks
        self.a2mReceiver.onEvent("BLEReadRequest", callback=self.read)
        self.a2sReceiver.onEvent("BLEReadResponse", callback=self.readResponse)
        self.a2mReceiver.onEvent("BLEReadBlobRequest", callback=self.readBlob)
        self.a2sReceiver.onEvent("BLEReadBlobResponse", callback=self.readBlobResponse)

        # Notification Callback
        self.a2sReceiver.onEvent(
            "BLEHandleValueNotification", callback=self.notification
        )
        self.a2sReceiver.onEvent("BLEHandleValueIndication", callback=self.indication)
        self.a2mReceiver.onEvent(
            "BLEHandleValueConfirmation", callback=self.confirmation
        )

        # Find Information Callbacks
        self.a2mReceiver.onEvent(
            "BLEFindInformationRequest", callback=self.findInformation
        )
        self.a2sReceiver.onEvent(
            "BLEFindInformationResponse", callback=self.findInformationResponse
        )

        # Find Type Value Callbacks
        self.a2mReceiver.onEvent(
            "BLEFindByTypeValueRequest", callback=self.findByTypeValueRequest
        )
        self.a2sReceiver.onEvent(
            "BLEFindByTypeValueResponse", callback=self.findByTypeValueResponse
        )

        # Read By Callbacks
        self.a2mReceiver.onEvent("BLEReadByTypeRequest", callback=self.readByType)
        self.a2mReceiver.onEvent(
            "BLEReadByGroupTypeRequest", callback=self.readByGroupType
        )
        self.a2sReceiver.onEvent(
            "BLEReadByTypeResponse", callback=self.readByTypeResponse
        )
        self.a2sReceiver.onEvent(
            "BLEReadByGroupTypeResponse", callback=self.readByGroupTypeResponse
        )

        # MTU Callbacks
        self.a2mReceiver.onEvent(
            "BLEExchangeMTURequest", callback=self.exchangeMtuRequest
        )
        self.a2sReceiver.onEvent(
            "BLEExchangeMTUResponse", callback=self.exchangeMtuResponse
        )

        # Connection Parameter Update Callbacks
        self.a2mReceiver.onEvent(
            "BLEConnectionParameterUpdateResponse",
            callback=self.masterConnectionParameterUpdateResponse,
        )

        self.a2sReceiver.onEvent(
            "BLEConnectionParameterUpdateRequest",
            callback=self.slaveConnectionParameterUpdateRequest,
        )

        # Security Manager Callbacks
        self.a2mReceiver.onEvent("BLEPairingRequest", callback=self.pairingRequest)
        self.a2sReceiver.onEvent("BLEPairingResponse", callback=self.pairingResponse)
        self.a2sReceiver.onEvent("BLESecurityRequest", callback=self.securityRequest)
        self.a2mReceiver.onEvent(
            "BLEPairingConfirm", callback=self.masterPairingConfirm
        )
        self.a2sReceiver.onEvent("BLEPairingConfirm", callback=self.slavePairingConfirm)
        self.a2mReceiver.onEvent("BLEPairingRandom", callback=self.masterPairingRandom)
        self.a2sReceiver.onEvent("BLEPairingRandom", callback=self.slavePairingRandom)
        self.a2sReceiver.onEvent("BLEPairingFailed", callback=self.slavePairingFailed)
        self.a2mReceiver.onEvent("BLEPairingFailed", callback=self.masterPairingFailed)

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

        self.a2sReceiver.onEvent("BLEPublicKey", callback=self.slavePublicKey)
        self.a2mReceiver.onEvent("BLEPublicKey", callback=self.masterPublicKey)

        self.a2sReceiver.onEvent("BLEDHKeyCheck", callback=self.slaveDHKEyCheck)
        self.a2mReceiver.onEvent("BLEDHKeyCheck", callback=self.masterDHKeyCheck)

    def registerLLEvents(self):

        # LL Callbacks
        self.a2sReceiver.onEvent(
            "BLELLConnUpdateInd", callback=self.slaveLLConnUpdateInd
        )
        self.a2mReceiver.onEvent(
            "BLELLConnUpdateInd", callback=self.masterLLConnUpdateInd
        )
        self.a2sReceiver.onEvent("BLELLChanMapInd", callback=self.slaveLLChannelMapInd)
        self.a2mReceiver.onEvent("BLELLChanMapInd", callback=self.masterLLChannelMapInd)
        self.a2sReceiver.onEvent("BLELLTerminateInd", callback=self.slaveLLTerminateInd)
        self.a2mReceiver.onEvent(
            "BLELLTerminateInd", callback=self.masterLLTerminateInd
        )

        self.a2mReceiver.onEvent("BLELLEncReq", callback=self.masterLLEncReq)

        self.a2sReceiver.onEvent("BLELLEncRsp", callback=self.slaveLLEncRsp)

        self.a2sReceiver.onEvent("BLELLStartEncReq", callback=self.slaveLLStartEncReq)

        self.a2sReceiver.onEvent("BLELLUnknownRsp", callback=self.slaveLLUnknownRsp)
        self.a2mReceiver.onEvent("BLELLUnknownRsp", callback=self.masterLLUnknownRsp)

        self.a2sReceiver.onEvent("BLELLFeatureReq", callback=self.slaveLLFeatureReq)
        self.a2mReceiver.onEvent("BLELLFeatureReq", callback=self.masterLLFeatureReq)

        self.a2sReceiver.onEvent("BLELLFeatureRsp", callback=self.slaveLLFeatureRsp)
        self.a2mReceiver.onEvent("BLELLFeatureRsp", callback=self.masterLLFeatureRsp)

        self.a2mReceiver.onEvent("BLELLPauseEncReq", callback=self.masterLLPauseEncReq)

        self.a2sReceiver.onEvent("BLELLPauseEncRsp", callback=self.slaveLLPauseEncRsp)
        self.a2mReceiver.onEvent("BLELLPauseEncRsp", callback=self.masterLLPauseEncRsp)

        self.a2sReceiver.onEvent("BLELLVersionInd", callback=self.slaveLLVersionInd)
        self.a2mReceiver.onEvent("BLELLVersionInd", callback=self.masterLLVersionInd)

        self.a2sReceiver.onEvent("BLELLRejectInd", callback=self.slaveLLRejectInd)
        self.a2mReceiver.onEvent("BLELLRejectInd", callback=self.masterLLRejectInd)

        self.a2sReceiver.onEvent(
            "BLELLSlaveFeatureReq", callback=self.slaveLLSlaveFeatureReq
        )

        self.a2sReceiver.onEvent("BLELLConnParamReq", callback=self.slaveLLConnParamReq)
        self.a2mReceiver.onEvent(
            "BLELLConnParamReq", callback=self.masterLLConnParamReq
        )
        self.a2sReceiver.onEvent("BLELLConnParamRsp", callback=self.slaveLLConnParamRsp)
        self.a2mReceiver.onEvent(
            "BLELLConnParamRsp", callback=self.masterLLConnParamRsp
        )

        self.a2sReceiver.onEvent("BLELLRejectExtInd", callback=self.slaveLLRejectExtInd)
        self.a2mReceiver.onEvent(
            "BLELLRejectExtInd", callback=self.masterLLRejectExtInd
        )

        self.a2sReceiver.onEvent("BLELLPingReq", callback=self.slaveLLPingReq)
        self.a2mReceiver.onEvent("BLELLPingReq", callback=self.masterLLPingReq)

        self.a2sReceiver.onEvent("BLELLPingRsp", callback=self.slaveLLPingRsp)
        self.a2mReceiver.onEvent("BLELLPingRsp", callback=self.masterLLPingRsp)

        self.a2sReceiver.onEvent("BLELLDataLenReq", callback=self.slaveLLLengthReq)
        self.a2mReceiver.onEvent("BLELLDataLenReq", callback=self.masterLLLengthReq)

        self.a2sReceiver.onEvent("BLELLDataLenRsp", callback=self.slaveLLLengthRsp)
        self.a2mReceiver.onEvent("BLELLDataLenRsp", callback=self.masterLLLengthRsp)

        self.a2sReceiver.onEvent("BLELLPhyReq", callback=self.slaveLLPhyReq)
        self.a2mReceiver.onEvent("BLELLPhyReq", callback=self.masterLLPhyReq)

        self.a2sReceiver.onEvent("BLELLPhyRsp", callback=self.slaveLLPhyRsp)
        self.a2mReceiver.onEvent("BLELLPhyRsp", callback=self.masterLLPhyRsp)

        self.a2sReceiver.onEvent("BLELLUpdPHYInd", callback=self.slaveLLPhyUpdateInd)
        self.a2mReceiver.onEvent("BLELLUpdPHYInd", callback=self.masterLLPhyUpdateInd)

        self.a2sReceiver.onEvent(
            "BLELLMinUsedChann", callback=self.slaveLLMinUsedChannelsInd
        )
        self.a2mReceiver.onEvent(
            "BLELLMinUsedChann", callback=self.masterLLMinUsedChannelsInd
        )

        # TODO:  Callbacks, which are by the time of writing not supported by Dongle
        # self.a2sReceiver.onEvent("BLELLCTEReq", callback=self.slaveLLCTEReq)
        # self.a2mReceiver.onEvent("BLELLCTEReq", callback=self.masterLLCTEReq)

        # self.a2sReceiver.onEvent("BLELLCTERsp", callback=self.slaveLLCTERsp)
        # self.a2mReceiver.onEvent("BLELLCTERsp", callback=self.masterLLCTERsp)

        # self.a2sReceiver.onEvent("BLELLPeriodicSyncInd", callback=self.slaveLLPeriodicSyncInd)
        # self.a2mReceiver.onEvent("BLELLPeriodicSyncInd", callback=self.masterLLPeriodicSyncInd)

        # self.a2sReceiver.onEvent("BLELLClockAccuracyReq", callback=self.slaveLLClockAccuracyReq)
        # self.a2mReceiver.onEvent("BLELLClockAccuracyReq", callback=self.masterLLClockAccuracyReq)

        # self.a2sReceiver.onEvent("BLELLClockAccuracyRsp", callback=self.slaveLLClockAccuracyRsp)
        # self.a2mReceiver.onEvent("BLELLClockAccuracyRsp", callback=self.masterLLClockAccuracyRsp)

        # self.a2sReceiver.onEvent("BLELLCISReq", callback=self.slaveLLCISReq)
        # self.a2mReceiver.onEvent("BLELLCISReq", callback=self.masterLLCISReq)

        # self.a2sReceiver.onEvent("BLELLCISRsp", callback=self.slaveLLCISRsp)
        # self.a2mReceiver.onEvent("BLELLCISRsp", callback=self.masterLLCISRsp)

        # self.a2sReceiver.onEvent("BLELLCISInd", callback=self.slaveLLCISInd)
        # self.a2mReceiver.onEvent("BLELLCISInd", callback=self.masterLLCISInd)

        # self.a2sReceiver.onEvent("BLELLCISTerminateInd", callback=self.slaveLLCISTerminateInd)
        # self.a2mReceiver.onEvent("BLELLCISTerminateInd", callback=self.masterLLCISTerminateInd)

        # self.a2sReceiver.onEvent("BLELLPowerControlReq", callback=self.slaveLLPowerControlReq)
        # self.a2mReceiver.onEvent("BLELLPowerControlReq", callback=self.masterLLPowerControlReq)

        # self.a2sReceiver.onEvent("BLELLPowerControlRsp", callback=self.slaveLLPowerControlRsp)
        # self.a2mReceiver.onEvent("BLELLPowerControlRsp", callback=self.masterLLPowerControlRsp)

        # self.a2sReceiver.onEvent("BLELLChangeInd", callback=self.slaveLLChangeInd)
        # self.a2mReceiver.onEvent("BLELLChangeInd", callback=self.masterLLChangeInd)

        self.a2sReceiver.onEvent("BLELLEncCtrl", callback=self.slaveLLEncCtrl)
        self.a2mReceiver.onEvent("BLELLEncCtrl", callback=self.masterLLEncCtrl)

        self.a2sReceiver.onEvent("BLELLEncData", callback=self.slaveLLEncData)
        self.a2mReceiver.onEvent("BLELLEncData", callback=self.masterLLEncData)

    def checkParametersValidity(self):
        if self.args["ADVERTISING_STRATEGY"] not in ("preconnect", "flood"):
            io.fail("You have to select a valid strategy : 'flood' or 'preconnect'")
            return self.nok()
        return None

    def run(self):
        validity = self.checkParametersValidity()
        if validity is not None:
            return validity

        self.initEmittersAndReceivers()
        self.a2mReceiver.storeCallbacks()
        self.a2sReceiver.storeCallbacks()
        if self.checkCapabilities():
            if self.loadScenario():
                io.info("Scenario loaded !")
                self.startScenario()

            self.a2mEmitter.setZephyrMITMFlag(0x01)
            self.a2sEmitter.setZephyrMITMFlag(0x01)

            self.registerLLEvents()
            # Advertising Callbacks
            self.a2sReceiver.onEvent("BLEAdvertisement", callback=self.scanStage)

            io.info("Entering SCAN stage ...")
            self.setStage(self.BLEMitmStage.SCAN)

            self.a2sReceiver.setScan(enable=True)

            self.waitUntilStage(self.BLEMitmStage.CLONE)

            self.a2sReceiver.setScan(enable=False)

            if self.args["ADVERTISING_STRATEGY"] == "preconnect":
                self.connectOnSlave()

            self.a2mEmitter.setAdvertising(enable=True)
            io.info("Entering WAIT_CONNECTION stage ...")
            self.setStage(self.BLEMitmStage.WAIT_CONNECTION)

            self.registerEvents()

            self.waitUntilStage(self.BLEMitmStage.STOP)

            self.a2mReceiver.restoreCallbacks()
            self.a2sReceiver.restoreCallbacks()
            # Clean up connections
            if self.a2mEmitter.isConnected():
                self.a2mEmitter.sendp(ble.BLEDisconnect())
            while self.a2mEmitter.isConnected():
                utils.wait(seconds=0.01)
            if self.a2sEmitter.isConnected():
                self.a2sEmitter.sendp(ble.BLEDisconnect())
            while self.a2sEmitter.isConnected():
                utils.wait(seconds=0.01)

            moduleResult = {}
            if self.scenarioEnabled:
                scenarioResult = self.endScenario({})
                moduleResult["scenarioResult"] = scenarioResult
            # Reset public address
            self.a2mEmitter.setAddress("00:00:00:00:00", random=False)
            self.a2sEmitter.setAddress("00:00:00:00:00", random=False)
            io.success("Result: {}".format(moduleResult))
            return self.ok(moduleResult)
        else:
            io.fail(
                "Interfaces provided ("
                + str(self.args["INTERFACE"])
                + ") are not able to run this module."
            )
            return self.nok()
