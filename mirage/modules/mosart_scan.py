from mirage.libs import mosart,utils,io
from mirage.core import module
import sys

class mosart_scan(module.WirelessModule):
	def init(self):
		self.technology = "mosart"
		self.type = "scan"
		self.description = "Scanning module for Mosart devices"
		self.args = {
				"INTERFACE":"rfstorm0",
				"TIME":"10", 
				"START_CHANNEL":"0",
				"END_CHANNEL":"99",
				"DONGLE_PACKETS":"no"
			}
		self.devices = {}
		self.changes = 0

	def checkPromiscuousSniffingCapabilities(self):
		return self.receiver.hasCapabilities("SNIFFING_PROMISCUOUS")

	def add(self,packet):
		if packet.address not in self.devices:
			self.devices[packet.address] = {"channels":set([packet.additionalInformations.channel]),"type":"unknown" if packet.deviceType is None else packet.deviceType}
			self.changes+=1
		elif packet.additionalInformations.channel not in self.devices[packet.address]["channels"]:
			self.devices[packet.address]["channels"].add(packet.additionalInformations.channel)
			self.changes+=1
		elif packet.deviceType is not None and self.devices[packet.address]["type"] == "unknown":
			self.devices[packet.address]["type"] = packet.deviceType
			self.changes+=1

	def displayDevices(self):
		sys.stdout.write(" "*100+"\r")
		if self.changes != 0:
			devices = []
			for k,v in self.devices.items():
				devices.append([str(k),",".join(str(i) for i in v["channels"]),v["type"]])
			io.chart(["Address", "Channels", "Device type"], devices)
			self.changes = 0

	def generateOutput(self):
		output = {}
		if len(self.devices) >= 1:
			i = 1
			for k,v in self.devices.items():
				output["TARGET"+str(i)] = k
				output["CHANNELS"+str(i)] = v["channels"]
				output["DEVICE_TYPE"+str(i)] = v["type"]
				if i == 1:
					output["TARGET"] = k
					output["CHANNEL"] = str(list(v["channels"])[0])
					output["CHANNELS"] = ",".join(str(i) for i in v["channels"])
					output["DEVICE_TYPE"] = v["type"]
				i+=1
		return output

	def run(self):
		self.receiver = self.getReceiver(self.args["INTERFACE"])
		self.receiver.enterPromiscuousMode()
		if self.checkPromiscuousSniffingCapabilities():
			self.receiver.onEvent("*",callback=self.add)
			if utils.booleanArg(self.args["DONGLE_PACKETS"]):
				self.receiver.enableDonglePackets()
			else:
				self.receiver.disableDonglePackets()

			start = utils.now()
			startChannel = utils.integerArg(self.args["START_CHANNEL"])
			endChannel = utils.integerArg(self.args["END_CHANNEL"])

			numberOfChannels = endChannel+1 - startChannel

			channels = list(range(startChannel,endChannel+1))
			i = 0
			while self.args["TIME"] == "" or utils.now() - start < utils.integerArg(self.args["TIME"]):
				io.progress(i,total=numberOfChannels,suffix="Channel: "+(" " if len(str(channels[i]))==1 else "")+str(channels[i]))
				self.receiver.setChannel(channels[i])
				utils.wait(seconds=0.1)
				self.displayDevices()
				i = (i + 1) % len(channels)
			sys.stdout.write(" "*100+"\r")
			if len(self.devices) >= 1:
				return self.ok(self.generateOutput())
			else:
				return self.nok()
		else:
			io.fail("Interface provided ("+str(self.args["INTERFACE"])+") is not able to run in promiscuous mode.")
			return self.nok()
