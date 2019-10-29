from mirage.libs import ir,utils
from mirage.core import module


class ir_sniff(module.WirelessModule):
	def init(self):
		self.technology = "ir"
		self.type = "sniff"
		self.description = "Sniffing module for IR signals"
		self.args = {
				"INTERFACE":"irma0",
				"NUMBER":"1",
				"FREQUENCY":"38"
			}

		self.receivedPackets = []
		self.count = None

	def checkCapabilities(self):
		return self.receiver.hasCapabilities("SNIFFING", "CHANGING_FREQUENCY")

	def show(self,pkt):
		if pkt.data != []:
			pkt.show()
			self.receivedPackets.append(pkt)	
			self.receiver.reset()
			self.count -= 1
		if self.count != 0:
			self.receiver.waitData()

	def generateOutput(self):
		output = {"INTERFACE":self.args["INTERFACE"]}
		current = 1
		for packet in self.receivedPackets:
			output["DATA"+str(current)] = str(packet.data)[1:-1]
			output["PROTOCOL"+str(current)] = str(packet.protocol)
			if packet.protocol != "UNKNOWN":
				output["CODE"+str(current)] = packet.code.hex()
				output["CODE_SIZE"+str(current)] = str(packet.size)
			if current == 1:
				output["PROTOCOL"] = str(packet.protocol)
				output["DATA"] = str(packet.data)[1:-1]
				if packet.protocol != "UNKNOWN":
					output["CODE"] = packet.code.hex()
					output["CODE_SIZE"] = str(packet.size)
			current += 1
		return output
	
	def run(self):
		self.receiver = self.getReceiver(interface=self.args["INTERFACE"])
		if self.checkCapabilities():
			frequency = self.receiver.getFrequency()
			if frequency != utils.integerArg(self.args["FREQUENCY"]):
				self.receiver.setFrequency(utils.integerArg(self.args["FREQUENCY"]))
			self.count = utils.integerArg(self.args["NUMBER"]) if utils.isNumber(self.args["NUMBER"]) else 1

			self.receiver.onEvent("*",callback=self.show)
			self.receiver.waitData()
			while self.count > 0:
				utils.wait(seconds=0.5)

			output = self.generateOutput()	
			return self.ok(output)
		else:
			io.fail("Interface provided ("+str(self.args["INTERFACE"])+") is not able to sniff IR signals.")			
			return self.nok()
