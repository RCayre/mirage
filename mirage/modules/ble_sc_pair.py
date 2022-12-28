from mirage.libs import io, ble, utils
from mirage.core import module
from enum import IntEnum
from mirage.libs.ble_utils.sc_crypto import SCCryptoInstance, CryptoUtils
from binascii import unhexlify
import struct


class ble_sc_pair(module.WirelessModule):
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

    def init(self):

        self.technology = "ble"
        self.type = "action"
        self.description = (
            "Secure Connections Pairing module for Bluetooth Low Energy devices"
        )
        self.args = {
            "INTERFACE": "hci0",
            "MODE": "master",
            "PIN": "",
            "ACTIVE": "yes",
            "ADDR_TYPE": "public",
            "ADDR": "",
            "KEYBOARD": "no",
            "YESNO": "no",
            "DISPLAY": "no",
            "CT2": "no",
            "MITM": "no",
            "BONDING": "no",
            "KEYPRESS": "no",
            "SCENARIO": "",
            "TARGET": "FC:58:FA:A1:26:6B",
            "CONNECTION_TYPE": "public",
        }

        self.sc_crypto = SCCryptoInstance()

        self.useOOB = False
        self.checkMitm = False
        self.ioCapabilities = False
        self.justWorks = False

        self.pairingMethod = None

        self.pairingRequest = None
        self.pairingResponse = None

        self.localAddress = None
        self.localAddressType = None
        self.remoteAddress = None
        self.remoteAddressType = None
        self.localNonce = None
        self.remoteConfirm = None
        self.localIOCap = None
        self.remoteIOCap = None
        self.pReq = None
        self.pRes = None

        self.failure = False

        self.passkey = None
        self.currBitIndex = 19
        self.bitMask = 0b10000000000000000000
        self.rb = 0x00
        # Results
        self.localIRK = None
        self.localCSRK = None
        self.remoteIRK = None
        self.remoteCSRK = None

    # Scenario-related methods
    @module.scenarioSignal("onStart")
    def startScenario(self):
        pass

    @module.scenarioSignal("onEnd")
    def endScenario(self, result):
        return result

    def pairingMethodSelection(self):
        self.secureConnections = (
            self.responderAuthReq.secureConnections
            and self.initiatorAuthReq.secureConnections
        )
        if self.secureConnections:
            io.info("Both devices support LE secure connections")
            self.useOOB = (
                self.pairingRequest.outOfBand and self.pairingResponse.outOfBand
            )
            self.ioCapabilities = (
                self.responderAuthReq.mitm or self.initiatorAuthReq.mitm
            )
            self.justWorks = (
                not self.responderAuthReq.mitm and not self.initiatorAuthReq.mitm
            )

        else:
            io.fail(
                "At least one of the devices doesn't support LE secure connections, please use ble_pair module"
            )
            self.failure = True

        io.chart(
            ["Out Of Bond", "IO Capabilities", "Just Works"],
            [
                [
                    "yes" if self.useOOB else "no",
                    "yes" if self.ioCapabilities else "no",
                    "yes" if self.justWorks else "no",
                ]
            ],
        )

        if self.ioCapabilities:
            initiator = "NoInputNoOutput"
            responder = "NoInputNoOutput"
            if self.initiatorInputOutputCapability.data[0] == 0x00:
                initiator = "DisplayOnly"
            elif self.initiatorInputOutputCapability.data[0] == 0x01:
                initiator = "DisplayYesNo"
            elif self.initiatorInputOutputCapability.data[0] == 0x02:
                initiator = "KeyboardOnly"
            elif self.initiatorInputOutputCapability.data[0] == 0x03:
                initiator = "NoInputNoOutput"
            elif self.initiatorInputOutputCapability.data[0] == 0x04:
                initiator = "KeyboardDisplay"

            if self.responderInputOutputCapability.data[0] == 0x00:
                responder = "DisplayOnly"
            elif self.responderInputOutputCapability.data[0] == 0x01:
                responder = "DisplayYesNo"
            elif self.responderInputOutputCapability.data[0] == 0x02:
                responder = "KeyboardOnly"
            elif self.responderInputOutputCapability.data[0] == 0x03:
                responder = "NoInputNoOutput"
            elif self.responderInputOutputCapability.data[0] == 0x04:
                responder = "KeyboardDisplay"

            pairingMethod = ble.PairingMethods.getPairingMethod(
                secureConnections=self.secureConnections,
                initiatorInputOutputCapability=initiator,
                responderInputOutputCapability=responder,
            )

            if pairingMethod == ble.PairingMethods.JUST_WORKS:
                self.pairingMethod = "JustWorks"
            elif pairingMethod == ble.PairingMethods.PASSKEY_ENTRY:
                self.pairingMethod = "PasskeyEntry"
            elif pairingMethod == ble.PairingMethods.NUMERIC_COMPARISON:
                self.pairingMethod = "NumericComparison"
            else:
                self.pairingMethod = "JustWorks"
        elif self.useOOB:
            self.pairingMethod = "OutOfBonds"
        else:
            self.pairingMethod = "JustWorks"

        return self.pairingMethod

    @module.scenarioSignal("onDisconnect")
    def disconnect(self, packet):
        if not self.scenarioEnabled:
            io.fail("Peer disconnected !")
            self.failure = True
        else:
            io.info("Peer disconnected !")

    @module.scenarioSignal("onSlaveSecurityRequest")
    def slaveSecurityRequest(self, packet):
        io.info("{}".format(packet))
        io.info("{}".format(self.pairingRequest))
        self.emitter.sendp(self.pairingRequest)

    @module.scenarioSignal("onSlavePairingResponse")
    def slavePairingResponse(self, packet):
        self.localAddress = self.emitter.getAddress()
        self.localAddressType = 0 if self.emitter.getAddressMode() == "public" else 1

        self.remoteAddress = self.emitter.getCurrentConnection()
        self.remoteAddressType = (
            0 if self.emitter.getCurrentConnectionMode() == "public" else 1
        )

        io.info("{}".format(packet))
        self.pairingResponse = packet
        self.pRes = self.pairingResponse.payload[::-1]

        self.responderAuthReq = ble.AuthReqFlag(data=bytes([packet.authentication]))
        self.responderInputOutputCapability = ble.InputOutputCapability(
            data=bytes([packet.inputOutputCapability])
        )
        self.responderKeyDistribution = ble.KeyDistributionFlag(
            data=bytes([packet.responderKeyDistribution])
        )
        self.pairingMethod = self.pairingMethodSelection()
        io.info("Pairing Method selected : " + self.pairingMethod)

        (nwOrderPubKeyX, nwOrderPubKeyY) = self.sc_crypto.generateDHKeyPair()
        self.remoteIOCap = (
            format(packet.authentication, "02x")
            + ("01" if packet.outOfBand else "00")
            + format(packet.inputOutputCapability, "02x")
        )
        self.remoteIOCap = unhexlify(self.remoteIOCap)
        response = ble.BLEPublicKey(key_x=nwOrderPubKeyX, key_y=nwOrderPubKeyY)
        io.info("{}".format(response))
        self.emitter.sendp(response)

    @module.scenarioSignal("onSlavePublicKey")
    def slavePublicKey(self, packet):
        io.info("Slave: {}".format(packet))
        self.sc_crypto.generateDHSharedSecret(packet.key_x, packet.key_y)
        io.info("{}".format(self.pairingMethod))

        if self.pairingMethod == "PasskeyEntry":
            nwOrderConfirmValue = self.generateConfirmValue()
            response = ble.BLEPairingConfirm(confirm=nwOrderConfirmValue)
            io.info("{}".format(response))
            self.emitter.sendp(response)

    @module.scenarioSignal("onSlavePairingConfirm")
    def slavePairingConfirm(self, packet):
        io.info("{}".format(packet))
        while not self.sc_crypto.isSharedSecretReady():
            utils.wait(0.2)
        self.remoteConfirm = packet.confirm
        nwOrderLocalNonce = (
            self.localNonce if self.localNonce else self.sc_crypto.generateLocalNonce()
        )
        self.emitter.sendp(ble.BLEPairingRandom(random=nwOrderLocalNonce))

    @module.scenarioSignal("onSlavePairingRandom")
    def slavePairingRandom(self, packet):
        io.info("{}".format(packet))
        self.remoteNonce = packet.random
        if self.sc_crypto.verifyConfirmValue(
            self.remoteNonce, self.remoteConfirm, rbi=bytes([self.rb])
        ):
            io.info("Verify Confirm value success!")
        else:
            io.fail("Verify Confirm value failed!")
            self.emitter.sendp(ble.BLEPairingFailed())
            if not self.scenarioEnabled:
                self.failure = True

        if self.pairingMethod == "PasskeyEntry" and self.currBitIndex >= 0:
            nwOrderConfirmValue = self.generateConfirmValue()
            response = ble.BLEPairingConfirm(confirm=nwOrderConfirmValue)
            io.info("{}".format(response))
            self.emitter.sendp(response)
        else:
            io.info("Deriving LTK")
            self.sc_crypto.deriveLTKInitiator(
                self.localAddress,
                self.remoteAddress,
                self.localAddressType,
                self.remoteAddressType,
                self.remoteNonce,
            )
            io.info("Sending DH Key Check")
            r = b""
            if self.pairingMethod == "PasskeyEntry":
                r = struct.pack("<I", self.passkey)
            nwOrderDHKeyCheck = self.sc_crypto.generateDHKeyCheck(
                self.localIOCap,
                self.localAddress,
                self.remoteAddress,
                self.localAddressType,
                self.remoteAddressType,
                self.remoteNonce,
                r,
            )
            packet = ble.BLEDHKeyCheck(dhkey_check=nwOrderDHKeyCheck)
            self.emitter.sendp(packet)

    @module.scenarioSignal("onSlaveDHKeyCheck")
    def slaveDHKeyCheck(self, packet):
        io.info("{}".format(packet))
        while not self.sc_crypto.isLTKReady():
            utils.wait(0.2)
        r = b""
        if self.pairingMethod == "PasskeyEntry":
            r = struct.pack("<I", self.passkey)
        if self.sc_crypto.verifyDHKeyCheck(
            self.remoteIOCap,
            self.localAddress,
            self.remoteAddress,
            self.localAddressType,
            self.remoteAddressType,
            packet.dhkey_check,
            self.remoteNonce,
            r,
        ):
            io.info("DH Key Check success!")
        else:
            io.fail("DH Key Check failed!")
            self.emitter.sendp(ble.BLEPairingFailed())
            if not self.scenarioEnabled:
                self.failure = True
        io.info("Try to encrypt link")
        request = ble.BLEStartEncryption(
            rand=b"\x00" * 16, ediv=0, ltk=self.sc_crypto.LTK[::-1]
        )
        io.info("{}".format(request))
        self.emitter.sendp(request)

    @module.scenarioSignal("onSlaveEncryptionChange")
    def slaveEncryptionChange(self, packet):
        io.info("{}".format(packet))
        if packet.status == 0x00 and packet.enabled == 0x01:
            io.info("Encryption enabled !")
            if not (
                self.responderKeyDistribution.linkKey
                or self.responderKeyDistribution.signKey
                or self.responderKeyDistribution.idKey
            ):
                io.info("Slave pairing finished")
                self.finished = True
        else:
            io.fail("Slave Encryption failed...")
            if not self.scenarioEnabled:
                self.failure = True

    def pairingFailed(self, packet):
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

    @module.scenarioSignal("onSlavePairingFailed")
    def slavePairingFailed(self, packet):
        if not self.scenarioEnabled:
            self.failure = True
        io.fail("Pairing Failed received : " + str(packet))
        self.pairingFailed(packet)

    @module.scenarioSignal("onMasterIdentityAddressInformation")
    def masterIdentityAddressInformation(self, packet):
        io.info("{}".format(packet))
        self.remoteIdentityAddress = packet.address
        if not self.initiatorKeyDistribution.signKey:
            io.info("Master pairing finished")

    @module.scenarioSignal("onMasterIdentityInformation")
    def masterIdentityInformation(self, packet):
        io.info("{}".format(packet))
        self.remoteIRK = packet.irk

    @module.scenarioSignal("onMasterSigningInformation")
    def masterSigningInformation(self, packet):
        io.info("{}".format(packet))
        self.masterRemoteCSRK = packet.csrk
        io.info("Master pairing finished")

    @module.scenarioSignal("onSlaveIdentityAddressInformation")
    def slaveIdentityAddressInformation(self, packet):
        self.remoteIdentityAddress = packet.address
        if not self.responderKeyDistribution.signKey:
            self.keyDistribution(type="initiator")
            io.info("Slave pairing finished")
            self.finished = True

    @module.scenarioSignal("onSlaveIdentityInformation")
    def slaveIdentityInformation(self, packet):
        self.remoteIRK = packet.irk

    @module.scenarioSignal("onSlaveSigningInformation")
    def slaveSigningInformation(self, packet):
        self.remoteCSRK = packet.csrk
        self.keyDistribution(type="initiator")
        io.info("Slave pairing finished")
        self.finished = True

    @module.scenarioSignal("onMasterPairingRequest")
    def masterPairingRequest(self, packet):
        self.remoteAddress = self.emitter.getCurrentConnection()
        self.remoteAddressType = (
            0 if self.emitter.getCurrentConnectionMode() == "public" else 1
        )
        self.localAddress = (
            self.args["ADDR"] if self.args["ADDR"] != "" else self.emitter.getAddress()
        )
        self.localAddressType = 0 if self.args["ADDR_TYPE"] == "public" else 1

        self.initiatorKeyDistribution = ble.KeyDistributionFlag(
            data=bytes([packet.initiatorKeyDistribution])
        )
        io.info("{}".format(packet))
        self.pairingRequest = packet
        self.pReq = self.pairingRequest.payload[::-1]

        self.initiatorAuthReq = ble.AuthReqFlag(data=bytes([packet.authentication]))
        self.initiatorInputOutputCapability = ble.InputOutputCapability(
            data=bytes([packet.inputOutputCapability])
        )
        self.initiatorKeyDistribution = ble.KeyDistributionFlag(
            data=bytes([packet.initiatorKeyDistribution])
        )

        keyboard = utils.booleanArg(self.args["KEYBOARD"])
        yesno = utils.booleanArg(self.args["YESNO"])
        display = utils.booleanArg(self.args["DISPLAY"])

        ct2 = utils.booleanArg(self.args["CT2"])
        mitm = utils.booleanArg(self.args["MITM"])
        bonding = utils.booleanArg(self.args["BONDING"])
        secureConnections = True
        keyPress = utils.booleanArg(self.args["KEYPRESS"])

        self.masterRemoteIOCap = (
            bytes([packet.authentication])
            + (b"01" if packet.outOfBand else b"00")
            + bytes([packet.inputOutputCapability])
        )

        self.responderInputOutputCapability = ble.InputOutputCapability(
            keyboard=keyboard, display=display, yesno=yesno
        )
        self.responderAuthReq = ble.AuthReqFlag(
            ct2=ct2,
            mitm=mitm,
            bonding=bonding,
            secureConnections=secureConnections,
            keypress=keyPress,
        )
        self.responderKeyDistribution = ble.KeyDistributionFlag(
            linkKey=False, encKey=True, idKey=False, signKey=True
        )
        oob = b"\x00"

        self.pairingResponse = ble.BLEPairingResponse(
            authentication=self.responderAuthReq.data[0],
            inputOutputCapability=self.responderInputOutputCapability.data[0],
            initiatorKeyDistribution=self.responderKeyDistribution.data[0],
            responderKeyDistribution=self.responderKeyDistribution.data[0],
        )
        self.localIOCap = (
            self.responderAuthReq.data + oob + self.responderInputOutputCapability.data
        )
        io.info("{}".format(self.pairingResponse))
        self.pRes = self.pairingResponse.payload[::-1]
        self.pairingMethod = self.pairingMethodSelection()
        io.info("Pairing Method selected : " + self.pairingMethod)
        self.emitter.sendp(self.pairingResponse)

    @module.scenarioSignal("onMasterPublicKey")
    def masterPublicKey(self, packet):
        io.info("{}".format(packet))
        (nwOrderMasterKeyX, nwORderMasterKeyY) = self.sc_crypto.generateDHKeyPair()
        response = ble.BLEPublicKey(key_x=nwOrderMasterKeyX, key_y=nwORderMasterKeyY)
        io.info("{}".format(response))
        self.emitter.sendp(response)
        self.sc_crypto.generateDHSharedSecret(packet.key_x, packet.key_y)
        if self.pairingMethod != "PasskeyEntry":
            nwOrderConfirmValue = self.generateConfirmValue()
            response = ble.BLEPairingConfirm(confirm=nwOrderConfirmValue)
            io.info("{}".format(response))
            self.emitter.sendp(response)

    @module.scenarioSignal("onMasterConfirmValue")
    def masterConfirmValue(self, packet):
        if self.pairingMethod == "PasskeyEntry":
            nwOrderConfirmValue = self.generateConfirmValue()
            response = ble.BLEPairingConfirm(confirm=nwOrderConfirmValue)
            io.info("{}".format(response))
            self.emitter.sendp(response)

    def generateConfirmValue(self):
        if self.pairingMethod == "PasskeyEntry" and not self.passkey:
            self.passkey = int(io.ask("Insert passkey"))

        self.localNonce = self.sc_crypto.generateLocalNonce()
        rb = 0x00
        if self.passkey:
            rb = ((self.bitMask >> self.currBitIndex) & self.passkey) >> (
                19 - self.currBitIndex
            )
            self.currBitIndex -= 1
            rb = 0b10000000 ^ rb
        self.rb = rb
        return self.sc_crypto.generateConfirmValue(rbi=bytes([rb]))

    @module.scenarioSignal("onMasterPairingRandom")
    def masterPairingRandom(self, packet):
        io.info("{}".format(packet))
        self.remoteNonce = packet.random
        if self.pairingMethod == "PasskeyEntry":
            if self.sc_crypto.verifyConfirmValue(
                self.remoteNonce, self.remoteConfirm, rbi=bytes([self.rb])
            ):
                io.info("Verify Confirm value success!")
            else:
                io.fail("Verify Confirm value failed!")
                self.emitter.sendp(ble.BLEPairingFailed())
                if not self.scenarioEnabled:
                    self.failure = True
                return

        response = ble.BLEPairingRandom(random=self.localNonce)
        io.info("{}".format(response))
        self.emitter.sendp(response)

    @module.scenarioSignal("onMasterDHKeyCheck")
    def masterDHKeyCheck(self, packet):
        io.info("{}".format(packet))
        io.info("Deriving LTK")
        self.sc_crypto.deriveLTK(
            self.localAddress,
            self.remoteAddress,
            self.localAddressType,
            self.remoteAddressType,
            self.remoteNonce,
        )
        r = b""
        if self.pairingMethod == "PasskeyEntry":
            r = struct.pack("<I", self.passkey)
        if not self.sc_crypto.verifyDHKeyCheck(
            self.remoteIOCap,
            self.localAddress,
            self.remoteAddress,
            self.localAddressType,
            self.remoteAddressType,
            packet.dhkey_check,
            self.remoteNonce,
            r,
        ):
            io.fail("DH Key Check failed!")
            self.emitter.sendp(ble.BLEPairingFailed())
            if not self.scenarioEnabled:
                self.failure = True
        else:
            io.info("DH Key Check success!")
            io.info("Sending DH Key Check")
            nwOrderDHKeyCheck = self.sc_crypto.generateDHKeyCheck(
                self.localIOCap,
                self.localAddress,
                self.remoteAddress,
                self.localAddressType,
                self.remoteAddressType,
                self.remoteNonce,
                r,
            )
            response = ble.BLEDHKeyCheck(dhkey_check=nwOrderDHKeyCheck)
            self.emitter.sendp(response)

    @module.scenarioSignal("onLongTermKeyRequest")
    def longTermKeyRequest(self, packet):
        io.info("{}".format(packet))
        if self.sc_crypto.isLTKReady():
            response = ble.BLELongTermKeyRequestReply(
                positive=True, ltk=self.sc_crypto.LTK[::-1]
            )
        else:
            response = ble.BLELongTermKeyRequestReply(positive=False)
        io.info("{}".format(response))
        self.emitter.sendp(response)

    @module.scenarioSignal("onMasterEncryptionChange")
    def masterEncryptionChange(self, packet):
        io.info("{}".format(packet))
        if packet.status == 0x00 and packet.enabled == 0x01:
            io.success("Encryption enabled !")
            self.keyDistribution(type="responder")
        else:
            io.fail("Master Encryption failed...")
            if not self.scenarioEnabled:
                self.failure = True

    @module.scenarioSignal("onMasterPairingFailed")
    def masterPairingFailed(self, packet):
        if not self.scenarioEnabled:
            self.failure = True
        io.fail("Pairing Failed received : " + str(packet))
        self.pairingFailed(packet)

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

        io.info("Sending a response to slave ...")
        self.emitter.sendp(
            ble.BLEConnectionParameterUpdateResponse(
                l2capCmdId=packet.l2capCmdId, moveResult=0
            )
        )
        self.emitter.updateConnectionParameters(
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

    @module.scenarioSignal("onMasterConnectionParameterUpdateResponse")
    def masterConnectionParameterUpdateResponse(self, packet):
        io.info(
            "Connection Parameter Update Response (from master) : moveResult = "
            + str(packet.moveResult)
        )

        io.info("Redirecting to slave ...")
        self.emitter.sendp(
            ble.BLEConnectionParameterUpdateResponse(
                l2capCmdId=packet.l2capCmdId, moveResult=packet.moveResult
            )
        )
        if packet.moveResult == 0 and self.emitter.isConnected():
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
            self.emitter.updateConnectionParameters(
                timeout=self.timeoutMult,
                latency=self.slaveLatency,
                minInterval=self.minInterval,
                maxInterval=self.maxInterval,
            )

    def keyDistribution(self, type="initiator"):
        if type == "initiator":
            keyDistribution = self.initiatorKeyDistribution
        else:
            keyDistribution = self.responderKeyDistribution

        if keyDistribution.idKey:
            io.info("Sending IRK...")
            self.localIRK = CryptoUtils.generateRandom()
            self.emitter.sendp(
                ble.BLEIdentityInformation(
                    irk=CryptoUtils.reverseOrder(self.localIRK.hex())
                )
            )
            self.emitter.sendp(
                ble.BLEIdentityAddressInformation(
                    address=self.localAddress,
                    type=self.localAddressType,
                )
            )
            io.info("Sent IRK!")

        if keyDistribution.signKey:
            io.info("Sending CSRK...")
            self.localCSRK = CryptoUtils.generateRandom()
            self.emitter.sendp(
                ble.BLESigningInformation(
                    csrk=CryptoUtils.reverseOrder(self.localCSRK.hex())
                )
            )
            io.info("Sent CSRK!")

    def run(self):
        self.finished = False
        interface = self.args["INTERFACE"]
        self.emitter = self.getEmitter(interface=interface)
        self.receiver = self.getReceiver(interface=interface)

        self.receiver.storeCallbacks()
        if self.loadScenario():
            io.info("Scenario loaded !")
            self.startScenario()

        if not self.emitter.isConnected() and utils.booleanArg(self.args["ACTIVE"]):
            io.fail("A connection must be established.")
            return self.nok()

        if self.args["MODE"].lower() == "master":

            keyboard = utils.booleanArg(self.args["KEYBOARD"])
            yesno = utils.booleanArg(self.args["YESNO"])
            display = utils.booleanArg(self.args["DISPLAY"])

            ct2 = utils.booleanArg(self.args["CT2"])
            mitm = utils.booleanArg(self.args["MITM"])
            bonding = utils.booleanArg(self.args["BONDING"])
            secureConnections = True
            keyPress = utils.booleanArg(self.args["KEYPRESS"])

            self.initiatorInputOutputCapability = ble.InputOutputCapability(
                keyboard=keyboard, display=display, yesno=yesno
            )
            self.initiatorAuthReq = ble.AuthReqFlag(
                ct2=ct2,
                mitm=mitm,
                bonding=bonding,
                secureConnections=secureConnections,
                keypress=keyPress,
            )
            self.initiatorKeyDistribution = ble.KeyDistributionFlag(
                linkKey=True, encKey=True, idKey=False, signKey=True
            )
            oob = b"\x00"
            self.localIOCap = (
                self.initiatorAuthReq.data
                + oob
                + self.initiatorInputOutputCapability.data
            )

            self.pairingRequest = ble.BLEPairingRequest(
                authentication=self.initiatorAuthReq.data[0],
                inputOutputCapability=self.initiatorInputOutputCapability.data[0],
                initiatorKeyDistribution=self.initiatorKeyDistribution.data[0],
                responderKeyDistribution=self.initiatorKeyDistribution.data[0],
            )

            self.pReq = self.pairingRequest.payload[::-1]
            self.receiver.onEvent(
                "BLESecurityRequest", callback=self.slaveSecurityRequest
            )
            self.receiver.onEvent(
                "BLEPairingResponse", callback=self.slavePairingResponse
            )
            self.receiver.onEvent("BLEPublicKey", callback=self.slavePublicKey)
            self.receiver.onEvent(
                "BLEPairingConfirm", callback=self.slavePairingConfirm
            )
            self.receiver.onEvent("BLEPairingRandom", callback=self.slavePairingRandom)
            self.receiver.onEvent("BLEDHKeyCheck", callback=self.slaveDHKeyCheck)
            self.receiver.onEvent("BLEPairingFailed", callback=self.slavePairingFailed)
            self.receiver.onEvent(
                "BLEIdentityInformation", callback=self.slaveIdentityInformation
            )
            self.receiver.onEvent(
                "BLEIdentityAddressInformation",
                callback=self.slaveIdentityAddressInformation,
            )
            self.receiver.onEvent(
                "BLESigningInformation", callback=self.slaveSigningInformation
            )
            self.receiver.onEvent(
                "BLEEncryptionChange", callback=self.slaveEncryptionChange
            )

            # Disconnect Callbacks
            self.receiver.onEvent("BLEDisconnect", callback=self.disconnect)

            if utils.booleanArg(self.args["ACTIVE"]):
                io.info("{}".format(self.pairingRequest))
                self.emitter.sendp(self.pairingRequest)

                while not self.finished and not self.failure:
                    utils.wait(seconds=1)

                if self.failure:
                    return self.nok()
        else:

            self.receiver.onEvent("BLEPublicKey", callback=self.masterPublicKey)

            self.receiver.onEvent(
                "BLEPairingRequest", callback=self.masterPairingRequest
            )
            self.receiver.onEvent("BLEPairingRandom", callback=self.masterPairingRandom)
            self.receiver.onEvent("BLEPairingFailed", callback=self.masterPairingFailed)
            self.receiver.onEvent(
                "BLEIdentityInformation", callback=self.masterIdentityInformation
            )
            self.receiver.onEvent(
                "BLEIdentityAddressInformation",
                callback=self.masterIdentityAddressInformation,
            )
            self.receiver.onEvent(
                "BLESigningInformation", callback=self.masterSigningInformation
            )
            self.receiver.onEvent(
                "BLEEncryptionChange", callback=self.masterEncryptionChange
            )

            self.receiver.onEvent(
                "BLELongTermKeyRequest", callback=self.longTermKeyRequest
            )
            # Disconnect Callbacks
            self.receiver.onEvent("BLEDisconnect", callback=self.disconnect)

            ct2 = utils.booleanArg(self.args["CT2"])
            mitm = utils.booleanArg(self.args["MITM"])
            bonding = utils.booleanArg(self.args["BONDING"])
            secureConnections = True
            keyPress = utils.booleanArg(self.args["KEYPRESS"])

            authReq = ble.AuthReqFlag(
                ct2=ct2,
                mitm=mitm,
                bonding=bonding,
                secureConnections=secureConnections,
                keypress=keyPress,
            )

            if utils.booleanArg(self.args["ACTIVE"]):
                securityRequest = ble.BLESecurityRequest(authentication=authReq.data[0])
                io.info("{}".format(securityRequest))
                self.emitter.sendp(securityRequest)

            while not self.finished and not self.failure:
                utils.wait(seconds=1)

            if self.failure:
                return self.nok()

        moduleResult = {
            "LTK": None if self.sc_crypto.LTK == None else self.sc_crypto.LTK.hex(),
            "MacKey": None
            if self.sc_crypto.MacKey == None
            else self.sc_crypto.MacKey.hex(),
            "localIRK": None if self.localIRK == None else self.localIRK.hex(),
            "localCSRK": None if self.localCSRK == None else self.localCSRK.hex(),
            "remoteIRK": None if self.remoteIRK == None else self.remoteIRK.hex(),
            "remoteCSRK": None if self.remoteCSRK == None else self.remoteCSRK.hex(),
        }
        if self.scenarioEnabled:
            scenarioResult = self.endScenario({})
            moduleResult["scenarioResult"] = scenarioResult
            # Reset public address
            self.emitter.setAddress("00:00:00:00:00", random=False)
        else:
            io.info("Result: {}".format(moduleResult))
        self.receiver.removeCallbacks()
        self.receiver.restoreCallbacks()
        return self.ok(moduleResult)
