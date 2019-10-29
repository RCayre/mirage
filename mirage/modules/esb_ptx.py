import subprocess,sys
from mirage.libs import io,utils,esb,wireless
from mirage.core import module,interpreter
from threading import Lock

class esb_ptx(module.WirelessModule, interpreter.Interpreter):
	def init(self):

		self.technology = "esb"
		self.type = "spoofing"
		self.description = "This module permits the User to simulate an Enhanced ShockBurst PTX device"
		self.dependencies = ["esb_scan"]
		self.args = {
				"TARGET":"",
				"INTERFACE":"rfstorm0",
				"SCENARIO":"",
				"FOLLOW_MODE":"yes"
			}
		self.dynamicArgs = True

	def prerun(self):
		interpreter.Interpreter.__init__(self)
		self.availableCommands += [
						"send",
						"clear",
						"scan",	
						"address",
						"find_prx",
						"follow_prx",
						"unfollow_prx",
						"channel"
					]
		
		self.targets = []
		self.target = None
		self.currentChannel = "??"

	def checkCommunicationCapabilities(self):
		return self.receiver.hasCapabilities("SNIFFING_NORMAL","INJECTING")

	def checkActiveScanningCapabilities(self):
		return self.receiver.hasCapabilities("ACTIVE_SCANNING")

	def updatePrompt(self,address=""):
		if address is None:
			address = ""	
		self.prompt = io.colorize("[PTX|"+(" "+str(self.currentChannel) if len(str(self.currentChannel))!=2 else str(self.currentChannel))+("|"+address if address != "" else "") + "]: ","cyan")

	def clear(self):
		subprocess.run(["clear"])

	def address(self,address:"!attribute:targets"=""):
		if address == "":
			if self.target is not None and self.target != "":
				io.info("Current address: "+self.target)
			else:
				io.info("No address selected.")
		else:
			self.emitter.enterSnifferMode(address)
			self.target = address
			self.updatePrompt(address)

	def find_prx(self,channels="0-99"):
		if self.checkActiveScanningCapabilities():
			if self.target is None:
				io.fail("You must select a target before performing this action.")
			else:
				listOfChannels = []
				for i in channels.split(","):
					if utils.isNumber(i):
						listOfChannels.append(int(i))
					elif "-" in i and len(i.split("-")) == 2 and all([utils.isNumber(j) for j in i.split("-")]):
						downChannel,upChannel = [int(j) for j in i.split("-")]
						listOfChannels += range(downChannel,upChannel+1)

				if all([(channel >= 0 and channel <= 99) for channel in listOfChannels]):
					if self.emitter.scan(listOfChannels):
						io.success("ACK received from PRX on channel #"+str(self.emitter.getChannel()))
						self.currentChannel = self.emitter.getChannel()
						self.updatePrompt(self.target)
					else:
						io.fail("PRX not found")
				else:
					io.fail("You must only provide channels between 0 and 99.")
		else:
			io.fail("Interface provided ("+str(self.args["INTERFACE"])+") is not able to perform an active scan.")

	def send(self,payloads="0f0f0f0f"):
		if self.target is None:
			io.fail("You must select a target before performing this action.")
		else:
			self.ackLock.acquire()
			for payload in payloads.split(","):
				try:
					esbPayload = bytes.fromhex(payload)
					self.emitter.sendp(esb.ESBPacket(address=self.target,payload=esbPayload))
					found = False
					start = utils.now()
					while utils.now() - start < 1:
						if self.ack:
							found = True
							break
					self.ack = False
					if found:
						io.success("ACK received.")
					else:
						io.fail("No ACK received.")
				except ValueError:
					io.fail("You must specify an hexadecimal payload.")
					self.ackLock.release()
					return
			self.ackLock.release()

	def channel(self,newChannel=""):
		if newChannel == "":
			io.info("Current channel: "+str(self.emitter.getChannel()))
		else:

			if self.followThread is not None:
				io.fail("You can't manually set a channel in follow PRX mode.")
			else:
				if utils.isNumber(newChannel) and int(newChannel) >= 0 and int(newChannel) <= 99:
					self.emitter.setChannel(int(newChannel))
					self.currentChannel = int(newChannel)
					self.updatePrompt(self.target)
				else:
					io.fail("You must provide a channel number between 0 and 99.")

	def _pingPRX(self):
		utils.wait(seconds=1)
		self.ackLock.acquire()
		self.emitter.sendp(esb.ESBPingRequestPacket(address=self.target))
		found = False
		start = utils.now()
		while utils.now() - start < 1:
			if self.ack:
				found = True
				break
		self.ack = False
		if not found:
			self.onPingFailure()
			while not self.emitter.scan():
				utils.wait(seconds=0.1)
			self.onPRXFound()
			self.currentChannel = self.emitter.getChannel()
			self.updatePrompt(self.target)
		self.ackLock.release()

	def startFollowing(self):
		if self.checkActiveScanningCapabilities():
			self.followThread = wireless.StoppableThread(self._pingPRX)
			self.followThread.start()
			return True
		else:
			io.fail("Interface provided ("+str(self.args["INTERFACE"])+") is not able to perform an active scan, follow mode not in use.")
			return False

	def stopFollowing(self):
		if self.followThread is not None:
			self.followThread.stop()
			self.followThread = None

	def follow_prx(self):
		if self.target is None:
			io.fail("You must select a target before performing this action.")
		else:
			if self.followThread is None:
				self.startFollowing()

	def unfollow_prx(self):
		if self.target is None:
			io.fail("You must select a target before performing this action.")
		else:
			if self.followThread is not None:
				self.stopFollowing()

	def scan(self,seconds="10",startChannel="0",endChannel="99"):
		if self.followThread is not None:
			io.fail("You can't launch a scan in follow PRX mode.")
		else:
			m = utils.loadModule('esb_scan')
			m['INTERFACE'] = self.args['INTERFACE']
			m['TIME'] = seconds
			m['START_CHANNEL'] = startChannel
			m['END_CHANNEL'] = endChannel

			output = m.execute()
			self.currentChannel = self.emitter.getChannel()
			self.updatePrompt(self.target if self.target is not None else "")
			self.emitter.enterSnifferMode(self.args["TARGET"])
			if output["success"]:
				self.targets = []

				counter = 1
				while True:
					if "TARGET"+str(counter) in output["output"]:
						self.targets.append(output["output"]["TARGET"+str(counter)])
						counter += 1
					else:
						break

	@module.scenarioSignal("onStart")
	def startScenario(self):
		pass

	@module.scenarioSignal("onEnd")
	def endScenario(self):
		pass

	@module.scenarioSignal("onESBAckResponse")
	def onESBAckResponse(self,packet):
		pass

	@module.scenarioSignal("onPingFailure")
	def onPingFailure(self):
		pass

	@module.scenarioSignal("onPRXFound")
	def onPRXFound(self):
		pass

	def initializeCallbacks(self):
		self.receiver.onEvent("ESBAckResponsePacket",self.ackEvent)

	def ackEvent(self,pkt):
		self.ack = True
		self.onESBAckResponse(pkt)

	def stopScenario(self):
		self.scenarioStop = True

	def run(self):
		self.emitter = self.getEmitter(interface=self.args['INTERFACE'])
		self.receiver = self.getReceiver(interface=self.args['INTERFACE'])
		
		self.ack = False

		self.ackLock = Lock()
		self.followThread = None

		self.currentChannel = self.emitter.getChannel()
		self.initializeCallbacks()

		if self.checkCommunicationCapabilities():
			if self.args["TARGET"] != "":
				self.emitter.enterSnifferMode(self.args["TARGET"])
				self.target = self.args["TARGET"].upper()
				self.updatePrompt(self.target)
				if utils.booleanArg(self.args["FOLLOW_MODE"]):
					io.info("Enabling following mode ...")
					self.startFollowing()
			else:
				self.updatePrompt()

			if self.loadScenario():
				self.scenarioStop = False
				io.info("Scenario loaded !")
				self.startScenario()
				while not self.scenarioStop:
					utils.wait(seconds=0.1)
				self.endScenario()
			else:
				interpreter.Interpreter.loop(self)
			self.stopFollowing()
			return self.ok()
		else:
			io.fail("Interface provided ("+str(self.args["INTERFACE"])+") is not able to communicate as a PTX device.")
			return self.nok()			
