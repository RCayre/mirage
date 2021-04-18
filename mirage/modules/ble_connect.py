from mirage.core import module
from mirage.libs import io, utils
from mirage.libs.ble_utils.packets import BLEConnect, BLEConnectionCancel


class ble_connect(module.WirelessModule):
	def init(self):

		self.technology = "ble"
		self.type = "action"
		self.description = "Connection module for Bluetooth Low Energy devices"
		self.args = {
				"INTERFACE":"hci0",
				"TARGET":"fc:58:fa:a1:26:6b",
				"TIMEOUT":"3",
				"CONNECTION_TYPE":"public"
			}
	def checkCapabilities(self):
		return self.emitter.hasCapabilities("INITIATING_CONNECTION")
		
	def run(self):
		interface = self.args["INTERFACE"]
		timeout = utils.integerArg(self.args["TIMEOUT"])

		self.emitter = self.getEmitter(interface=interface)
		self.receiver = self.getReceiver(interface=interface)

		if self.checkCapabilities():
			io.info("Trying to connect to : "+self.args["TARGET"]+" (type : "+self.args["CONNECTION_TYPE"]+")")
			self.emitter.sendp(BLEConnect(self.args["TARGET"], type=self.args["CONNECTION_TYPE"]))

			while not self.receiver.isConnected() and timeout > 0:
				timeout -= 1
				utils.wait(seconds=1)

			if self.receiver.isConnected():
				io.success("Connected on device : "+self.args["TARGET"])
				return self.ok({"INTERFACE":self.args["INTERFACE"]})

			else:
				io.fail("Error during connection establishment !")
				self.emitter.sendp(BLEConnectionCancel())
				return self.nok()
		else:
			io.fail("Interface provided ("+str(self.args["INTERFACE"])+") is not able to initiate connection.")
			return self.nok()
