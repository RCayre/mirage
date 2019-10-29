from mirage.libs import esb,utils,io
from mirage.core import module
import configparser

class esb_sniff(module.WirelessModule):
	def init(self):
		self.technology = "esb"
		self.type = "sniff"
		self.description = "Sniffing module for Enhanced ShockBurst communications"
		self.args = {
				"INTERFACE":"rfstorm0",
				"TARGET":"",
				"MOUSE_FILE":"",
				"PCAP_FILE":"",
				"TIME":"20",
				"ACK_PACKETS":"no",
				"CHANNELS":"all",
				"ACTIVE_SCAN":"yes",
				"CHANNEL_TIMEOUT":"20", 
				"LOST_STREAM_ACTION":"continue" # "stop" or "continue"

			}

		self.lastReceivedFrameTimestamp = None
		self.channels = []
		self.miceDatas = []

	def checkActiveScanningCapabilities(self):
		return self.receiver.hasCapabilities("ACTIVE_SCANNING")

	def checkPromiscuousSniffingCapabilities(self):
		return self.receiver.hasCapabilities("SNIFFING_PROMISCUOUS")

	def checkNormalSniffingCapabilities(self):
		return self.receiver.hasCapabilities("SNIFFING_NORMAL")

	def addMouseData(self,packet):
		packet.show()
		self.miceDatas.append({"x":packet.x, "y":packet.y, "rightClick":packet.button == "right","leftClick":packet.button == "left"})

	def show(self,packet):
		if utils.booleanArg(self.args["ACK_PACKETS"]) or (not utils.booleanArg(self.args["ACK_PACKETS"]) and not isinstance(packet,esb.ESBAckResponsePacket)):
			io.displayPacket(packet)
			self.lastReceivedFrameTimestamp = utils.now()
			if self.pcap is not None:
				self.pcap.sendp(packet)

	def generateChannels(self):
		if self.args["CHANNELS"] == "all" or self.args["CHANNELS"] == "":
			self.channels = range(100)
			io.info("Channels: 0-99")
		else:
			for i in utils.listArg(self.args["CHANNELS"]):
				if utils.isNumber(i):
					self.channels.append(utils.integerArg(i))
				elif "-" in i and len(i.split("-")) == 2 and all([utils.isNumber(j) for j in i.split("-")]):
					upChannel,downChannel = [int(j) for j in i.split("-")]
					self.channels += range(upChannel,downChannel)
			io.info("Channels: "+','.join([str(j) for j in self.channels]))

	def searchChannel(self):
		io.info("Looking for an active channel for "+self.target+"...")
		success = False
		if self.activeMode:
			while not success:
				success = self.receiver.scan(self.channels)
				if not success:
					io.fail("Channel not found !")
					utils.wait(seconds=0.05)
					io.info("Retrying ...")
		else:
			while not success:
				for channel in self.channels:
					self.receiver.setChannel(channel)
					response = self.receiver.next(timeout=0.1)
					if response is not None:
						success = True
						break

		io.success("Channel found: "+str(self.receiver.getChannel()))

	def exportMiceDatas(self):
		config = configparser.ConfigParser()
		counter = 1
		for miceData in self.miceDatas:
			x = miceData["x"]
			y = miceData["y"]
			leftClick = miceData["leftClick"]
			rightClick = miceData["rightClick"]

			config[counter] = {"x":x,"y":y,"leftClick":leftClick,"rightClick":rightClick}
			counter += 1
		with open(self.args["MOUSE_FILE"], 'w') as outfile:
			config.write(outfile)
			io.success("Sniffed mice datas are saved as "+self.args["MOUSE_FILE"]+" (CFG file format)")


	def run(self):
		self.pcap = None
		self.receiver = self.getReceiver(interface=self.args["INTERFACE"])
		self.receiver.onEvent("*",callback=self.show)	
		self.receiver.onEvent("ESBLogitechMousePacket",callback=self.addMouseData)
		self.target = "FF:FF:FF:FF:FF" if self.args["TARGET"] == "" else self.args["TARGET"].upper()
		if self.target == "FF:FF:FF:FF:FF":
			if self.checkPromiscuousSniffingCapabilities():
				io.info("Promiscuous mode enabled ! Only a subset of frames will be sniffed.")
				self.receiver.enterPromiscuousMode()
				if utils.booleanArg(self.args["ACTIVE_SCAN"]):
					io.warning("Active scanning not compatible with promiscuous mode, ACTIVE parameter will be ignored.")
					self.activeMode = False
				else:
					self.activeMode = utils.booleanArg(self.args["ACTIVE_SCAN"])
			else:
				io.fail("Interface provided ("+str(self.args["INTERFACE"])+") is not able to sniff packets in promiscuous mode, you have to provide a specific target.")
				return self.nok()
		else:
			if self.checkNormalSniffingCapabilities():
				io.info("Sniffing mode enabled !")
				self.receiver.enterSnifferMode(address=self.target)
				if utils.booleanArg(self.args["ACK_PACKETS"]):
					io.warning("ACK cannot be sniffed in sniffing mode, ACK_PACKETS parameter will be ignored.")
				self.activeMode = utils.booleanArg(self.args["ACTIVE_SCAN"])
			else:
				io.fail("Interface provided ("+str(self.args["INTERFACE"])+") is not able to sniff packets.")
				return self.nok()

		if self.args["PCAP_FILE"] != "":
			self.pcap = self.getEmitter(interface=self.args["PCAP_FILE"])
		
		channelsTimeout = float(self.args["CHANNEL_TIMEOUT"]) if self.args["CHANNEL_TIMEOUT"] != "" else None

		if self.activeMode and not self.checkActiveScanningCapabilities():
			io.fail("Interface provided ("+str(self.args["INTERFACE"])+") is not able to perform an active scan.")
			return self.nok()

		self.generateChannels()
		self.searchChannel()


		time = utils.integerArg(self.args['TIME']) if self.args["TIME"] != "" else None
		start = utils.now()
		while utils.now() - start <= time if time is not None else True:
			if ((utils.now() - self.lastReceivedFrameTimestamp >= channelsTimeout) if (channelsTimeout is not None and self.lastReceivedFrameTimestamp is not None) else False):
				io.fail("Channel lost...")
				if self.args["LOST_STREAM_ACTION"].lower() == "continue":
					self.searchChannel()
				else:
					break
			
		self.receiver.removeCallbacks()
		if self.pcap is not None:
			self.pcap.stop()

		output = {}
		output["MOUSE_FILE"] = self.args["MOUSE_FILE"]
		output["PCAP_FILE"] = self.args["PCAP_FILE"]
		output["TARGET"] = self.target
		output["CHANNEL"] = str(int(self.receiver.getChannel()))

		return self.ok(output)

	def postrun(self):
		self.receiver.removeCallbacks()
		if self.args["MOUSE_FILE"]!="":
			self.exportMiceDatas()

