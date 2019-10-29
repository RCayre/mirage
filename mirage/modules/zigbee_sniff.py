from mirage.libs import zigbee,utils,io
from mirage.core import module


class zigbee_sniff(module.WirelessModule):
	def init(self):
		self.technology = "zigbee"
		self.type = "sniff"
		self.description = "Sniffing module for Zigbee communications"
		self.args = {
				"INTERFACE":"rzusbstick0",
				"CHANNEL":"13",
				"TARGET_PANID":"",
				"TARGET":"",
				"TIME":"20",
				"PCAP_FILE":""

			}

	def checkCapabilities(self):
		return self.receiver.hasCapabilities("SNIFFING")

	def show(self,packet):
		if (
			(self.target is None or (hasattr(packet,"srcAddr") and packet.srcAddr == self.target)) and
			(self.targetPanID is None or (hasattr(packet,"destPanID") and packet.destPanID == self.targetPanID))
		):
			io.displayPacket(packet)
			if self.pcap is not None:
				self.pcap.sendp(packet)

	def run(self):

		self.receiver = self.getReceiver(interface=self.args["INTERFACE"])

		if self.checkCapabilities():
			if utils.isNumber(self.args["CHANNEL"]):
				self.receiver.setChannel(utils.integerArg(self.args["CHANNEL"]))
			else:
				io.fail("You must provide a channel number !")
				return self.nok()

			if self.args["TARGET_PANID"] != "":
				self.targetPanID = utils.integerArg(self.args["TARGET_PANID"])
			else:
				self.targetPanID = None

			if self.args["TARGET"] != "" and self.args["TARGET"][2:].upper() != "FFFF" and self.args["TARGET"].upper() != "FF:FF:FF:FF:FF:FF:FF:FF":
				if utils.isNumber(self.args["TARGET"]):
					self.target = utils.integerArg(self.args["TARGET"])
				else:
					self.target = zigbee.convertAddress(self.args["TARGET"])
			else:
				self.target = None

			if self.args["PCAP_FILE"] != "":
				self.pcap = self.getEmitter(interface=self.args["PCAP_FILE"])
			else:
				self.pcap = None
			self.receiver.onEvent("*",callback=self.show)	

			time = utils.integerArg(self.args['TIME']) if self.args["TIME"] != "" else None
			start = utils.now()
			while utils.now() - start <= time if time is not None else True:
				utils.wait(seconds=0.1)

			self.receiver.removeCallbacks()

			output = {
					"CHANNEL":self.args["CHANNEL"],
					"INTERFACE":self.args["INTERFACE"],
					"PCAP_FILE":self.args["PCAP_FILE"]
				}
			return self.ok(output)
		else:
			io.fail("Interface provided ("+str(self.args["INTERFACE"])+") is not able to sniff and inject frames.")
			return self.nok()
