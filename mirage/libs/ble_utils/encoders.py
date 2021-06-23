from mirage.libs.common.sdr.encoders import SDREncoder
from mirage.libs.ble_utils.helpers import crc24,dewhiten
class BLEEncoder(SDREncoder):
	'''
	Software Defined Radio encoder for Bluetooth Low Energy protocol.
	'''
	def __init__(self, channel=37, crcInit=0x555555):
		self.channel = channel
		self.crcInit = crcInit


	def setChannel(self,channel):
		'''
		This method sets the channel used by the dewhitening algorithm.

		:param channel: channel to use
		:type channel: int

		:Example:

			>>> decoder.setChannel(37)

		'''
		self.channel = channel

	def encode(self,data):
		crc = crc24(data[4:],len(data[4:]),self.crcInit)
		sequence = "".join([(("{:08b}".format(i))[::-1]) for i in b"\x55"+data[:4]+dewhiten(data[4:]+crc,self.channel)])
		return sequence
