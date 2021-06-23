'''
This component implements the Software Defined Radios Encoders.
'''

class SDREncoder:
	'''
	This class implements a simple Sofware Defined Radio encoder.
 	An encoder is used to convert a packet data or a sequence of bytes into a binary string.
	Every encoder must inherit from this class and implement the ``encode`` method.

	'''

	def encode(self,data):
		'''
		This method implements the encoding process and transforms a sequence of bytes into a binary string.

		:param data: data to encode
		:type data: bytes
		:return: binary string
		:rtype: str
		'''
		return "".join(["{:08b}".format(i) for i in data])
