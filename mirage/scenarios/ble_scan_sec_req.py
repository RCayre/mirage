from mirage.libs.ble_utils.constants import SM_ERR_AUTH_REQUIREMENTS
from mirage.core import scenario
from mirage.libs import io, ble, utils
from mirage.libs.ble_utils.dissectors import *
from mirage.libs.ble_utils.sc_crypto import CryptoUtils

# Class which can be used to receive the parameters for a pairing request
# from low to high sec level and mode
class ble_inc_sec_level:
    def __init__(self):
        self.step = 0
        self.max_step = 3
        self.inner_step = 0
        self.max_inner_step = 7
        self.keyboard_arr = [0, 0, 0, 1, 1, 0, 1, 1]
        self.yesno_arr = [0, 1, 0, 0, 1, 1, 0, 1]
        self.display_arr = [0, 0, 1, 0, 0, 1, 1, 1]

        self.keyboard = None
        self.display = None
        self.yesno = None

        self.mitm = False
        self.ct2 = False
        self.bonding = False
        self.keyPress = False
        self.secureConnections = False

    def increase(self):
        if self.step > self.max_step and self.inner_step > self.max_inner_step:
            return False

        self.keyboard = self.keyboard_arr[self.inner_step]
        self.display = self.display_arr[self.inner_step]
        self.yesno = self.yesno_arr[self.inner_step]

        self.mitm = True if self.step % 2 == 0 else False
        self.secureConnections = True if self.step > 1 else False

        self.linkKey = True
        self.encKey = True
        self.idKey = True
        self.signKey = True

        self.inner_step += 1
        if self.inner_step > self.max_inner_step:
            self.step += 1
            if self.step <= self.max_step:
                self.inner_step = 0
        return True


# Module scans version and features of the device
# Additionally it tries to connect with increasing security properties to detect the lowest possible security level and mode


class ble_scan_sec_req(scenario.Scenario):
    def connect(self):
        if not self.module.a2sEmitter.isConnected():
            # Apply new address at each start
            self.module.a2sEmitter.setAddress(
                CryptoUtils.getRandomAddress(), random=True
            )
            # Connect on slave
            io.info("Connect on slave")
            address = utils.addressArg(self.module.args["TARGET"])
            connectionType = self.module.args["CONNECTION_TYPE"]
            self.module.a2sEmitter.sendp(
                ble.BLEConnect(
                    dstAddr=address, type=connectionType, initiatorType="random"
                )
            )
            while not self.module.a2sEmitter.isConnected():
                utils.wait(seconds=0.5)

    def pairingLoop(self):
        if not self.sec_level:
            self.sec_level = ble_inc_sec_level()

        success = False
        while self.sec_level.increase() and not self.finished:
            # Connect if necessary
            self.connect()
            output = self.pairing("yes", self.sec_level)
            if output["success"]:
                self.finishedScenario(output)
                return

        io.fail("Not possible to pair :(")
        self.finishedScenario(None)

    def onStart(self):
        self.module.printScenarioStart("Scan connection properties")
        self.pairingRequestMaster = None
        self.pairingResponseSlave = None

        self.featureMaster = None
        self.featuresSlave = None

        self.masterVersion = None
        self.slaveVersion = None

        self.sec_level = None
        # Success status of the scenario
        self.finished = False
        self.success = self.module.ScenarioResult.NOT

        self.pairingLoop()
        return True

    def onEnd(self, result):
        result["success"] = self.success
        result["finished"] = self.finished
        self.module.printScenarioEnd(result)
        return True

    def onKey(self, key):
        if key == "esc":
            self.module.setStage(5)  # STOP
        return True

    # Save controller features
    def onSlaveLLSlaveFeatureReq(self, packet):
        self.featuresSlave = packet
        return True

    def onSlaveLLFeatureReq(self, packet):
        self.featuresSlave = packet
        return True

    def onSlaveLLFeatureRsp(self, packet):
        self.featuresSlave = packet
        return True

    # Save version
    def onSlaveLLVersionInd(self, packet):
        self.slaveVersion = packet
        return True

    def finishedScenario(self, output):

        if output:
            io.info("{}".format(self.sec_level))
            self.finished = True

            if self.featuresSlave:
                io.success(
                    "Slave Controller Feature: {}".format(
                        self.featuresSlave.features.hex()
                    )
                )

            if self.slaveVersion:
                io.success(
                    "Slave controller version: {}".format(
                        self.slaveVersion.version_number
                    )
                )
                io.success(
                    "Slave controller sub version: {}".format(
                        self.slaveVersion.sub_version_number.hex()
                    )
                )
                io.success(
                    "Slave controller company ID: {}".format(
                        self.slaveVersion.company_id.hex()
                    )
                )

            pairing_method = output["output"]["PAIRING_METHOD"]
            # Check Legacy Pairing
            if not self.sec_level.secureConnections:
                io.fail("Legacy Pairing - {}".format(pairing_method))
                self.success = self.module.ScenarioResult.VULN
            else:
                io.info("SC Pairing - {}".format(pairing_method))
                if pairing_method == "Just Works":
                    self.success = self.module.ScenarioResult.VULN
                else:
                    self.success = self.module.ScenarioResult.NOT
            self.module.setStage(self.module.BLEStage.STOP)
            self.module.a2sEmitter.sendp(ble.BLEDisconnect())

    def onSlavePairingFailed(self, packet):
        if packet.reason == ble.SM_ERR_PAIRING_NOT_SUPPORTED:
            self.success = self.module.ScenarioResult.MAYBE
            io.warning("Slave does not support pairing")
            self.finished = True
            self.module.setStage(self.module.BLEStage.STOP)
            self.module.a2sEmitter.sendp(ble.BLEDisconnect())
        return False

    def pairing(self, active, sec_level):
        pairModule = utils.loadModule("ble_pair")
        pairModule["MODE"] = "master"
        pairModule["INTERFACE"] = self.args["INTERFACE1"]
        pairModule["ACTIVE"] = active  # "yes" or "no"
        pairModule["KEYBOARD"] = "yes" if sec_level.keyboard == 1 else "no"
        pairModule["YESNO"] = "yes" if sec_level.yesno == 1 else "no"
        pairModule["DISPLAY"] = "yes" if sec_level.display == 1 else "no"
        pairModule["CT2"] = "yes" if sec_level.ct2 == 1 else "no"
        pairModule["MITM"] = "yes" if sec_level.mitm == 1 else "no"
        pairModule["BONDING"] = "yes" if sec_level.bonding == 1 else "no"
        pairModule["SECURE_CONNECTIONS"] = "no"  # This is legay pairing module
        pairModule["KEYPRESS"] = "yes" if sec_level.keyPress == 1 else "no"
        pairModule["IRK"] = "222233445566778899aabbccddeeff"
        pairModule["CSRK"] = "332233445566778899aabbccddeeff"

        io.info("Try to pair....")
        io.chart(
            ["Name", "Value"],
            [[k, v] for k, v in pairModule.args.items()],
            "Input parameters",
        )
        output = pairModule.execute()
        if output["success"]:
            if active == "active":
                io.success("Active pairing enabled !")
            else:
                io.success("Passive pairing enabled !")
        else:
            io.fail("An error occured during pairing !")
        io.info(("{}").format(output))
        return output
