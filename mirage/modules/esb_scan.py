from mirage.libs import esb,utils,io
from mirage.core import module
import sys

class esb_scan(module.WirelessModule):
	def init(self):
		self.technology = "esb"
		self.type = "scan"
		self.description = "Scan module for Enhanced ShockBurst Devices"
		self.args = {
				"INTERFACE":"rfstorm0",
				"TIME":"10", 
				"START_CHANNEL":"0",
				"END_CHANNEL":"99"
			}
		self.devices = {}
		self.changes = 0


	def add(self,packet):
		self.changes = 0
		if packet.address not in self.devices:
			self.devices[packet.address] = {"channels":set([packet.additionalInformations.channel]),"protocol":"unknown" if packet.protocol is None else packet.protocol}
			self.changes+=1
		elif packet.additionalInformations.channel not in self.devices[packet.address]["channels"]:
			self.devices[packet.address]["channels"].add(packet.additionalInformations.channel)
			self.changes+=1
		elif packet.protocol is not None and self.devices[packet.address]["protocol"] == "unknown":
			self.devices[packet.address]["protocol"] = packet.protocol
			self.changes+=1

	def displayDevices(self):
		if self.changes != 0:
			devices = []
			for k,v in self.devices.items():
				devices.append([str(k),",".join(str(i) for i in v["channels"]),v["protocol"]])
			sys.stdout.write(" "*100+"\r")
			io.chart(["Address", "Channels", "Protocol"], devices)
			self.changes = 0

	def generateOutput(self):
		output = {}
		if len(self.devices) >= 1:
			i = 1
			for k,v in self.devices.items():
				output["TARGET"+str(i)] = k
				output["PROTOCOL"+str(i)] = v["protocol"]
				if i == 1:
					output["TARGET"] = k
					output["PROTOCOL"] = k
				i+=1
		return output

	def checkScanningCapabilities(self):
		return self.receiver.hasCapabilities("SNIFFING_PROMISCUOUS")

	def run(self):
		self.receiver = self.getReceiver(interface=self.args['INTERFACE'])
		if self.checkScanningCapabilities():
			self.receiver.onEvent("*",callback=self.add)
			self.receiver.enterPromiscuousMode()
			start = utils.now()

			if utils.isNumber(self.args["START_CHANNEL"]) and utils.integerArg(self.args["START_CHANNEL"]) < 100 and utils.integerArg(self.args["START_CHANNEL"]) >= 0:
				startChannel = utils.integerArg(self.args["START_CHANNEL"])
			else:
				io.fail("You must provide a valid start channel.")
				return self.nok()

			if utils.isNumber(self.args["END_CHANNEL"]) and utils.integerArg(self.args["END_CHANNEL"]) >= startChannel  and utils.integerArg(self.args["END_CHANNEL"]) < 100 and utils.integerArg(self.args["END_CHANNEL"]) >= 0:
				endChannel = utils.integerArg(self.args["END_CHANNEL"])
			else:
				io.fail("You must provide a valid end channel.")
				return self.nok()

			numberOfChannels = endChannel+1 - startChannel

			channels = list(range(startChannel,endChannel+1))
			i = 0
			while self.args["TIME"] == "" or utils.now() - start < utils.integerArg(self.args["TIME"]):
				io.progress(i,total=numberOfChannels,suffix="Channel: "+(" " if len(str(channels[i]))==1 else "")+str(channels[i]))
				self.receiver.setChannel(channels[i])
				utils.wait(seconds=0.1)
				self.displayDevices()
				i = (i + 1) % len(channels)
			sys.stdout.write(" "*100+"\r") # TODO : moving it in io
			if len(self.devices) >= 1:
				return self.ok(self.generateOutput())
			else:
				return self.nok()
		else:
			io.fail("Interface provided ("+str(self.args["INTERFACE"])+") is not able to scan devices in promiscuous mode.")
			return self.nok()

