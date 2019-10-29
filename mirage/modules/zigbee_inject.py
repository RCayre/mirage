from mirage.libs import zigbee,utils,io
from mirage.core import module


class zigbee_inject(module.WirelessModule):
	def init(self):
		self.technology = "zigbee"
		self.type = "action"
		self.description = "Injection module for Zigbee communications"
		self.args = {
				"INTERFACE":"rzusbstick0",
				"CHANNEL":"13",
				"TARGET_PANID":"",
				"TARGET":"",
				"TIME":"20",
				"PCAP_FILE":""

			}

	def checkCapabilities(self):
		return self.emitter.hasCapabilities("INJECTING")

	def run(self):

		self.emitter = self.getEmitter(interface=self.args["INTERFACE"])
		if self.checkCapabilities():
			if utils.isNumber(self.args["CHANNEL"]):
				self.emitter.setChannel(utils.integerArg(self.args["CHANNEL"]))
			else:
				io.fail("You must provide a channel number !")
				return self.nok()

			self.pcapReceiver = self.getReceiver(interface=self.args["PCAP_FILE"])
			io.info("Extracting packet stream from PCAP ...")
			stream = self.pcapReceiver.generateStream()
			io.success("Packet stream successfully extracted !")

			io.info("Injecting ...")
			self.emitter.sendp(*stream)
			for i in stream:
				i.show()
			while not self.emitter.isTransmitting():
				utils.wait(seconds=0.1)

			while self.emitter.isTransmitting():
				utils.wait(seconds=0.1)
			io.success("Injection done !")
			return self.ok()
		else:
			io.fail("Interface provided ("+str(self.args["INTERFACE"])+") is not able to inject frames.")
			return self.nok()
