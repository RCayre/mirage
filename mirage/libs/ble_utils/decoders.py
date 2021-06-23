from mirage.libs.common.sdr.decoders import SDRDecoder
from mirage.libs.ble_utils.helpers import dewhiten,crc24

class BLEDecoder(SDRDecoder):
	'''
	Software Defined Radio decoder for Bluetooth Low Energy protocol.
	'''
	def __init__(self,samplesPerSymbol=1,samplesBefore=60 , samplesAfter=60,crcChecking=True,channel=37,crcInit=0x555555):
		self.samplesPerSymbol = samplesPerSymbol
		self.samplesBefore = samplesBefore
		self.samplesAfter = samplesAfter
		self.crcChecking = crcChecking
		self.channel = channel
		self.crcInit = crcInit


	def setCRCChecking(self,enable=True):
		'''
		This method enables CRC checking.

		:param enable: indicates if the CRC checking should be enabled or disabled
		:type enable: bool

		:Example:

			>>> decoder.setCRCChecking(True)

		'''
		self.crcChecking = enable

	def setChannel(self,channel):
		'''
		This method sets the channel used by the dewhitening algorithm.

		:param channel: channel to use
		:type channel: int

		:Example:

			>>> decoder.setChannel(37)

		'''
		self.channel = channel


	def decode(self,demodulatedData,iqSamples):
		'''
		This method implements the BLE decoding process and transforms a binary string into a BLE packet.

		:param demodulatedData: data to decode
		:type demodulatedData: str
		:param iqSamples: IQ samples corresponding with the demodulated data
		:type iqSamples: list of complex
		:return: tuple composed of the decoded data and the correspond IQ samples
		:rtype: (bytes, list of complex)
		'''
		bytesData = bytes.fromhex(''.join(["{:02x}".format(int(demodulatedData[i:i+8][::-1],2)) for i in range(0, len(demodulatedData), 8)]))
		size = ((dewhiten(bytesData[4:],self.channel)[1]) & 0b00111111)
		dewhitenedData = dewhiten(bytesData[4:4+size+2+3],self.channel)
		packet = bytesData[:4] + dewhitenedData

		newIqSamples = iqSamples[:self.samplesBefore+self.samplesPerSymbol*(len(packet)*8)+self.samplesPerSymbol+self.samplesAfter]
		if not self.crcChecking:
			return (packet, newIqSamples)
		elif crc24(dewhitenedData[:-3], len(dewhitenedData[:-3]),self.crcInit)==(bytes(packet)[-3:]):
			return (packet, newIqSamples)
		else:
			return (None, None)
