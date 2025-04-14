from mirage.libs.ble_utils.constants import SM_ERR_AUTH_REQUIREMENTS
from mirage.core import scenario
from mirage.libs import io, ble, utils
from mirage.libs.ble_utils.dissectors import *
from mirage.libs.ble_utils.sc_crypto import CryptoUtils
import os

# Module scans version and features of the device (General properties)

fuzz_list = [
    b"%%",
    b"%%%%%%%%",
    b"%%%%%%%%%%%%%%%%%%%%",
    b"*",
    b"%#0123456x%08x%x%s%p%d%n%o%u%c%h%l%q%j%z%Z%t%i%e%g%f%a%C%S%08x%%",
    b"%08x",
    b".1024d",
    b"129",
    b"%.2049d",
    b"%%20d",
    b"%%20n",
    b"%%20s",
    b"%%20x",
    b"257",
    b"513",
    b"55",
    b"%99999999999s",
    b"%d",
    b"%d%d%d%d",
    b"%d%d%d%d%d%d%d%d%d%d",
    b"%n",
    b"%n%n%n%n",
    b"%n%n%n%n%n%n%n%n%n%n",
    b"%p",
    b"%p%p%p%p",
    b"%p%p%p%p%p%p%p%p%p%p",
    b"%s",
    b"%s%p%x%d",
    b"%s%p%x%d%s%p%x%d%s%p%x%d",
    b"%s%s%s%s",
    b"%s%s%s%s%s%s%s%s%s%s",
    b"%u",
    b"%u%u%u%u",
    b"%u%u%u%u%u%u%u%u%u%u",
    b"%x",
    b"x",
    b"%x%x%x%x",
    b"%x%x%x%x%x%x%x%x%x%x",
]


class ble_att_fuzz(scenario.Scenario):
    def connect(self):
        while not self.module.a2sEmitter.isConnected():
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
            wait_int = 6
            curr_int = 0
            while not self.module.a2sEmitter.isConnected() and curr_int < wait_int:
                utils.wait(seconds=0.5)
                curr_int = curr_int + 1

    def onStart(self):
        self.module.printScenarioStart("Scan general properties")

        self.att_handle = io.ask(
            "Insert Attribute Handle (writable) as integer (21 for handle 0x0015) to fuzz:"
        )

        # Success status of the scenario
        self.finished = False
        self.success = self.module.ScenarioResult.NOT

        self.curr_value = b""

        # Fuzz attribute
        len_max = 100
        fuzz_list_done = False
        for i in range(0, len_max):
            values = []
            if fuzz_list_done:
                values = [b"\x00" * i, os.urandom(i), b"\xff" * i]
            else:
                values = fuzz_list

            for value in values:
                # Connect
                self.connect()
                io.info(f"{value}")
                self.module.a2sEmitter.sendp(
                    ble.BLEWriteRequest(handle=int(self.att_handle), value=value)
                )
                utils.wait(1)

        self.module.setStage(self.module.BLEStage.STOP)
        self.module.a2sEmitter.sendp(ble.BLEDisconnect())
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
    def onSlaveWriteResponse(self, packet):
        io.info(f"{packet}")
        return True
