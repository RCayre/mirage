import subprocess,sys
from mirage.libs import io,utils,esb,wireless
from mirage.core import module,interpreter
from threading import Lock

class esb_prx(module.WirelessModule, interpreter.Interpreter):
	def init(self):

		self.technology = "esb"
		self.type = "spoofing"
		self.description = "This module permits the User to simulate an Enhanced ShockBurst PRX device"
		self.dependencies = ["esb_scan"]
		self.args = {
				"TARGET":"",
				"INTERFACE":"rfstorm0",
				"SCENARIO":""
			}
		self.dynamicArgs = True

	def prerun(self):
		interpreter.Interpreter.__init__(self)
		self.availableCommands += [
						"clear",
						"auto_ack",
						"channel",
						"address",
						"scan",
						"show",
						"send"
					]
		
		self.targets = []
		self.target = None
		self.currentChannel = "??"
		self.showMode = False

	def checkCommunicationCapabilities(self):
		return self.receiver.hasCapabilities("SNIFFING_NORMAL","INJECTING")

	def updatePrompt(self,address=""):
		if address is None:
			address = ""	
		self.prompt = io.colorize("[PRX|"+(" "+str(self.currentChannel) if len(str(self.currentChannel))!=2 else str(self.currentChannel))+("|"+address if address != "" else "") + "]: ","cyan")

	def clear(self):
		subprocess.run(["clear"])

	def show(self):
		io.info("Received frames: (Ctrl + C to exit)")
		self.showMode = True
		try:
			while True:
				utils.wait(seconds=0.1)
		except KeyboardInterrupt:
			self.showMode = False
		sys.stdout.write("\r")
		self.updatePrompt(self.target if self.target is not None else "")

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

	def channel(self,newChannel=""):
		if newChannel == "":
			io.info("Current channel: "+str(self.emitter.getChannel()))
		else:
			if utils.isNumber(newChannel) and int(newChannel) >= 0 and int(newChannel) <= 99:
				self.emitter.setChannel(int(newChannel))
				self.currentChannel = int(newChannel)
				self.updatePrompt(self.target)
			else:
				io.fail("You must provide a channel number between 0 and 99.")


	def scan(self,seconds="10",startChannel="0",endChannel="99"):
		if self.emitter.isAutoAckEnabled():
			io.fail("You can't launch a scan when AutoAck is enabled.")
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

	def auto_ack(self):
		if self.target is None:
			io.fail("You must select a target before performing this action.")
		else:
			if self.emitter.isAutoAckEnabled():
				io.info("Auto ACK disabled !")
				self.emitter.disableAutoAck()
			else:
				io.info("Auto ACK enabled !")
				self.emitter.enableAutoAck()

	def send(self,payloads="0f0f0f0f"):
		if self.target is None:
			io.fail("You must select a target before performing this action.")
		else:
			if self.emitter.isAutoAckEnabled():
				io.info("The specified ACK payloads will be transmitted automatically when a new frame is received.")
			for payload in payloads.split(","):
				try:
					esbPayload = bytes.fromhex(payload)
					self.emitter.sendp(esb.ESBAckResponsePacket(address=self.target,payload=esbPayload))
				except ValueError:
					io.fail("You must specify an hexadecimal payload.")
	
	@module.scenarioSignal("onPacket")	
	def onIncomingPacket(self,pkt):
		pass

	def onPacket(self,pkt):
		self.onIncomingPacket(pkt)
		if self.showMode:
			pkt.show()

	@module.scenarioSignal("onStart")
	def startScenario(self):
		pass

	@module.scenarioSignal("onEnd")
	def endScenario(self):
		pass

	def stopScenario(self):
		self.scenarioStop = True

	def initializeCallbacks(self):
		self.receiver.onEvent("*",self.onPacket)

	def run(self):
		self.emitter = self.getEmitter(interface=self.args['INTERFACE'])
		self.receiver = self.getReceiver(interface=self.args['INTERFACE'])

		self.currentChannel = self.emitter.getChannel()
		self.initializeCallbacks()

		if self.checkCommunicationCapabilities():
			if self.args["TARGET"] != "":
				self.emitter.enterSnifferMode(self.args["TARGET"])
				self.target = self.args["TARGET"].upper()
				self.updatePrompt(self.target)
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

			return self.ok()
		else:
			io.fail("Interface provided ("+str(self.args["INTERFACE"])+") is not able to communicate as a PRX device.")
			return self.nok()			
