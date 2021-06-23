'''
This component implements the Software Defined Radios Decoders.
'''

class SDRDecoder:
	'''
	This class implements a simple Sofware Defined Radio decoder.
 	An decoder is used to convert a binary string into a packet or a sequence of bytes.
	Every decoder must inherit from this class and implement the ``decode`` method.

	'''
	def decode(self,demodulatedData,iqSamples):
		'''
		This method implements the decoding process and transforms a binary string into a packet or a sequence of bytes.

		:param demodulatedData: data to decode
		:type demodulatedData: str
		:param iqSamples: IQ samples corresponding with the demodulated data
		:type iqSamples: list of complex
		:return: tuple composed of the decoded data and the correspond IQ samples
		:rtype: (bytes, list of complex)
		'''
		data = bytes.fromhex("".join(["{:02x}".format(j) for j in [int(demodulatedData[i:i+8],2) for i in range(0,len(demodulatedData),8)]]))
		return (data,iqSamples)
