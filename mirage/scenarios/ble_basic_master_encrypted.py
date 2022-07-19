from mirage.core import scenario
from mirage.libs import io,ble,bt,utils,wireless
from mirage.libs.common import parsers
import random

class ble_basic_master_encrypted(scenario.Scenario):
	def onStart(self):
		self.emitter = self.module.emitter
		self.receiver = self.module.receiver
		self.module.connect()
		return True
		
	def onSlaveConnect(self):
		if self.emitter.encryptLink(rand=bytes.fromhex(self.args["RAND"]), ediv=utils.integerArg(self.args["EDIV"]), ltk = bytes.fromhex(self.args["LTK"])[::-1]):
			io.success("Encryption successfully enabled =)")
		self.module.read("0x01")
		self.emitter.sendp(ble.BLEDisconnect())
