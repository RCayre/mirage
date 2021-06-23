from mirage.libs.common.sdr.decoders import SDRDecoder
from mirage.libs.zigbee_utils.chip_tables import *
from mirage.libs.zigbee_utils.helpers import *

class ZigbeeDecoder(SDRDecoder):
	'''
	Software Defined Radio decoder for Zigbee protocol.
	'''
	def __init__(self,samplesPerSymbol=1,samplesBefore=60 , samplesAfter=60,crcChecking=False, hammingThresold=5):
		self.samplesPerSymbol = samplesPerSymbol
		self.samplesBefore = samplesBefore
		self.samplesAfter = samplesAfter
		self.crcChecking = crcChecking
		self.hammingThresold = hammingThresold

	def setCRCChecking(self,enable=True):
		'''
		This method enables CRC checking.

		:param enable: indicates if the CRC checking should be enabled or disabled
		:type enable: bool

		:Example:

			>>> decoder.setCRCChecking(True)

		'''
		self.crcChecking = enable

	def decode(self,demodulatedData,iqSamples):
		hamming = 0
		zigbeeFrame = ""
		for i in range(0,len(demodulatedData),32):
			value,hamming = checkBestMatch(demodulatedData[i:i+31])
			if hamming > self.hammingThresold:
				endOfFrame = i-1
				break
			else:
				zigbeeFrame += value

		newIqSamples = iqSamples[:self.samplesBefore+self.samplesPerSymbol*(len(demodulatedData[:endOfFrame]))+self.samplesPerSymbol+self.samplesAfter]
		zigbeeValidFrame = zigbeeFrame

		while "0000"*8 != zigbeeValidFrame[:4*8]:
			zigbeeValidFrame = "0000"+zigbeeValidFrame
		packet = bits2bytes(zigbeeValidFrame)

		if self.crcChecking:
			if (fcs(packet[6:-2]) == packet[-2:]):
				return (packet,newIqSamples)
			else:
				return (None,None)
		else:
			return (packet, newIqSamples)
		return (None, None)
