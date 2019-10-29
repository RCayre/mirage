from mirage.libs import esb,utils,io
from mirage.core import module


class esb_inject(module.WirelessModule):
	def init(self):
		self.technology = "esb"
		self.type = "action"
		self.description = "Injection module for Enhanced ShockBurst communications"
		self.args = {
				"INTERFACE":"rfstorm0",
				"TARGET":"",
				"PCAP_FILE":"",
				"CHANNEL":"auto"
			}

	def checkInjectingCapabilities(self):
		return self.receiver.hasCapabilities("INJECTING")

	def checkActiveScanningCapabilities(self):
		return self.receiver.hasCapabilities("ACTIVE_SCANNING")

	def checkPassiveScanningCapabilities(self):
		return self.receiver.hasCapabilities("SNIFFING_PROMISCUOUS")

	def searchChannel(self):
		io.info("Looking for an active channel for "+self.target+"...")
		success = False
		if self.target != "FF:FF:FF:FF:FF":
			while not success:
				success = self.receiver.scan()
				if not success:
					io.fail("Channel not found !")
					utils.wait(seconds=0.5)
					io.info("Retrying ...")
		else:
			while not success:
				for channel in range(100):
					self.receiver.setChannel(channel)
					response = self.receiver.next(timeout=0.1)
					if response is not None:
						success = True
						break

		io.success("Channel found: "+str(self.receiver.getChannel()))


	def run(self):

		self.emitter = self.getEmitter(interface=self.args["INTERFACE"])
		self.receiver = self.getReceiver(interface=self.args["INTERFACE"])

		if self.checkInjectingCapabilities():
			self.pcapReceiver = self.getReceiver(interface=self.args["PCAP_FILE"])

			self.target = "FF:FF:FF:FF:FF" if self.args["TARGET"] == "" else utils.addressArg(self.args["TARGET"])

			if self.target == "FF:FF:FF:FF:FF" and not self.checkPassiveScanningCapabilities():
				io.fail("Interface provided ("+str(self.args["INTERFACE"])+") is not able to scan in promiscuous mode, you have to provide a specific target.")
				return self.nok()

			if self.target != "FF:FF:FF:FF:FF" and self.args["CHANNEL"].lower() == "auto" and not self.checkActiveScanningCapabilities():
				io.fail("Interface provided ("+str(self.args["INTERFACE"])+") is not able to perform an active scan.")
				return self.nok()

			if self.target == "FF:FF:FF:FF:FF":
				io.info("Promiscuous mode enabled ! Every frame contained in the file indicated in PCAP_FILE will be transmitted.")
				self.emitter.enterPromiscuousMode()
			else:
				io.info("Sniffing mode enabled !")
				self.emitter.enterSnifferMode(address=self.target)


			if utils.isNumber(self.args["CHANNEL"]):
				self.emitter.setChannel(utils.integerArg(self.args["CHANNEL"]))
			elif self.args["CHANNEL"].lower() == "auto":
				self.searchChannel()
			else:
				io.fail("A channel must be provided in order to perform an injection.")
				return self.nok()

			

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
			io.fail("Interface provided ("+str(self.args["INTERFACE"])+") is not able to inject.")
			return self.nok()
