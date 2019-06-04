from mirage.libs import io,ble,utils
from mirage.core import module

class ble_monitor(module.WirelessModule):
	def init(self):

		self.technology = "ble"
		self.type = "monitoring"
		self.description = "HCI Monitoring module for Blutooth Low Energy"
		self.args = {
				"INTERFACE":"adb0",
				"SCENARIO":"",
				"TIME":""
			    }

	def checkMonitoringCapabilities(self):
		return self.receiver.hasCapabilities("HCI_MONITORING")


	@module.scenarioSignal("onKnownPacket")
	def onKnownPacket(self,pkt):
		pkt.show()

	@module.scenarioSignal("onPacket")
	def onPacket(self,pkt):
		if not "Unknown" in pkt.name:
			self.onKnownPacket(pkt)

	@module.scenarioSignal("onStart")
	def startScenario(self):
		pass

	@module.scenarioSignal("onEnd")
	def endScenario(self):
		pass

	def monitoring(self):
		self.receiver.onEvent("*", callback=self.onPacket)
		try:
			if self.args["TIME"] == "":
				while True:
					utils.wait(seconds=0.00001)

			elif utils.isNumber(self.args["TIME"]):
				time = utils.integerArg(self.args["TIME"])
				start = utils.now()
				while utils.now() - start < time:
					utils.wait(seconds=0.0000001)
								
			else:
				io.fail("You have provided a wrong TIME value.")
				return self.nok()
		except KeyboardInterrupt:
			pass

	def run(self):
		self.receiver = self.getReceiver(interface=self.args['INTERFACE'])
		if self.checkMonitoringCapabilities():
			if self.loadScenario():
				io.info("Scenario loaded !")
				self.startScenario()
				self.monitoring()
				self.endScenario()
			else:
				self.monitoring()
		return self.ok()
