from mirage.core import scenario
from mirage.libs import io,ble,bt,utils,wireless
from mirage.libs.common import parsers
import random

class ble_basic_master(scenario.Scenario):
	def onStart(self):
		self.emitter = self.module.emitter
		self.receiver = self.module.receiver
		self.duration = utils.integerArg(self.module.args["DURATION"]) if "DURATION" in self.module.args else 30
		self.module.connect()
		return True
		
	def onSlaveConnect(self):
		self.module.discover()
		start = utils.now()
		while utils.now() - start <= self.duration:
			self.module.read("0x0001")
			utils.wait(seconds=random.randint(1,10))
		self.module.disconnect()
		return False
