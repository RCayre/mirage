from mirage.libs import mosart,utils,io
from mirage.core import module
import configparser

class mosart_sniff(module.WirelessModule):
	def init(self):
		self.technology = "mosart"
		self.type = "sniff"
		self.description = "Sniffing module for Mosart devices"
		self.args = {
				"INTERFACE":"rfstorm0",
				"TARGET":"",
				"CHANNEL":"auto",
				"TIME":"10",
				"DONGLE_PACKETS":"no",
				"PCAP_FILE":"",
				"MOUSE_FILE":""
			}

		self.pcap = None
		self.miceDatas = []

	def checkSniffingCapabilities(self):
		return self.receiver.hasCapabilities("SNIFFING_NORMAL")

	def show(self,packet):
		packet.show()
		if isinstance(packet,mosart.MosartMouseMovementPacket):
			self.miceDatas.append({"x":packet.x1, "y":-packet.y1, "rightClick":False,"leftClick":False})
		elif isinstance(packet,mosart.MosartMouseClickPacket):
			self.miceDatas.append({"x":0, "y":0, "rightClick":packet.button == "right" and packet.state == "down","leftClick":packet.button == "left" and packet.state == "down"})
		if self.pcap is not None:
			self.pcap.sendp(packet)


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

	def find(self):
		found = False
		for i in range(1,100):
			self.receiver.setChannel(i)
			pkt = self.receiver.next(timeout=0.1)
			if pkt is not None:
				found = True
				io.success("Channel found: "+str(i))
				break
		if not found:
				io.fail("Channel not found !")
		return found

	def run(self):
		self.receiver = self.getReceiver(interface=self.args["INTERFACE"])
		if self.checkSniffingCapabilities():
			self.target = "FF:FF:FF:FF" if self.args["TARGET"] == "" else self.args["TARGET"].upper()
			if self.target == "FF:FF:FF:FF":
				self.receiver.enterPromiscuousMode()
			else:
				self.receiver.enterSnifferMode(self.target)

			if self.args["PCAP_FILE"] != "":
				self.pcap = self.getEmitter(interface=self.args["PCAP_FILE"])

			if utils.booleanArg(self.args["DONGLE_PACKETS"]):
				self.receiver.enableDonglePackets()
			else:
				self.receiver.disableDonglePackets()

			if self.args["CHANNEL"] == "" or self.args["CHANNEL"].lower() == "auto":			
				while not self.find():
					io.info("Retrying ...")
			else:
				self.receiver.setChannel(utils.integerArg(self.args["CHANNEL"]))

			self.receiver.onEvent("*",callback=self.show)
			time = utils.integerArg(self.args['TIME']) if self.args["TIME"] != "" else None
			start = utils.now()
			while utils.now() - start <= time if time is not None else True:
				utils.wait(seconds=0.5)
				
			self.receiver.removeCallbacks()
			if self.pcap is not None:
				self.pcap.stop()

			output = {}
			output["MOUSE_FILE"] = self.args["MOUSE_FILE"]
			output["PCAP_FILE"] = self.args["PCAP_FILE"]
			output["TARGET"] = self.target
			output["CHANNEL"] = str(int(self.receiver.getChannel()))

			return self.ok(output)
		else:
			io.fail("Interface provided ("+str(self.args["INTERFACE"])+") is not able to run in sniffing mode.")
			return self.nok()

	def postrun(self):
		self.receiver.removeCallbacks()
		if self.args["MOUSE_FILE"]!="":
			self.exportMiceDatas()
