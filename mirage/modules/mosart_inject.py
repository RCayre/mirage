from mirage.libs import mosart,utils,io,wireless
from mirage.core import module


class mosart_inject(module.WirelessModule):
	def init(self):
		self.technology = "mosart"
		self.type = "action"
		self.description = "Injection module for Mosart devices"
		self.args = {
				"INTERFACE":"rfstorm0",
				"TARGET":"",
				"CHANNEL":"36",
				"SYNC":"yes",
				"PCAP_FILE":""
			}

	def checkCapabilities(self):
		return self.emitter.hasCapabilities("INJECTING","SNIFFING_NORMAL")

	def checkInjectionSyncCapabilities(self):
		return self.emitter.hasCapabilities("INJECTING_SYNC")

	def run(self):
		self.receiver = self.getReceiver(interface=self.args["INTERFACE"])
		self.emitter = self.getEmitter(interface=self.args["INTERFACE"])
		if self.checkCapabilities():
			self.receiver.enterSnifferMode(utils.addressArg(self.args["TARGET"]))
			if self.checkInjectionSyncCapabilities():
				if utils.booleanArg(self.args["SYNC"]):
					self.receiver.enableSync()
				else:
					self.receiver.disableSync()
			else:
				io.warning("Synchronized injection is not supported by this interface, the SYNC parameter will be ignored ...")

			self.pcapReceiver = self.getReceiver(interface=self.args["PCAP_FILE"])


			self.receiver.setChannel(utils.integerArg(self.args["CHANNEL"]))
			io.info("Extracting packet stream from PCAP ...")
			stream = self.pcapReceiver.generateStream()
			io.success("Packet stream successfully extracted !")

			io.info("Injecting ...")
			self.emitter.sendp(*stream)

			while not self.emitter.isTransmitting():
				utils.wait(seconds=0.1)

			while self.emitter.isTransmitting():
				utils.wait(seconds=0.1)
			io.success("Injection done !")
			return self.ok()
		else:
			io.fail("Interface provided ("+str(self.args["INTERFACE"])+") is not able to inject frames and run in sniffing mode.")
			return self.nok()
