import struct
'''
This module provides some helpers in order to manipulate Zigbee packets.
'''

def frequencyToChannel(frequency):
	'''
	This function converts a frequency to the corresponding Zigbee channel.
	
	:param frequency: frequency to convert (MHz)
	:type frequency: int
	:return: channel associated to the provided frequency
	:rtype: int

	:Example:

		>>> frequencyToChannel(2405)
		11
		>>> frequencyToChannel(2420)
		14

	'''
	return int(((frequency - 2405)/5)+11)

def channelToFrequency(channel):
	'''
	This function converts a Zigbee channel to the corresponding frequency.
	
	:param channel: Zigbee channel to convert
	:type channel: int
	:return: corresponding frequency (MHz)
	:rtype: int

	:Example:

		>>> channelToFrequency(11)
		2405
		>>> channelToFrequency(14)
		2420

	'''
	return 2405 + 5 * (channel - 11)


def fcs(data):
	'''
	This function calculates the 16 bits FCS corresponding to the data provided.

	:param data: packet's payload
	:type data: bytes

	:Example:

		>>> data=bytes.fromhex("2188013412ffff000000001200610d0a")
		>>> fcs(data).hex()
		'0b29'

	'''
	crc = 0
	for i in range(0, len(data)):
		c = data[i]
		q = (crc ^ c) & 15
		crc = (crc // 16) ^ (q * 4225)
		q = (crc ^ (c // 16)) & 15
		crc = (crc // 16) ^ (q * 4225)
	return struct.pack("<H",crc)

def addressToString(address):
	'''
	This function converts a Zigbee address (as integer) to a printable string.

	:param address: integer indicating the address to convert
	:type address: int
	:return: printable string of the address
	:rtype: str

	:Example:

		>>> addressToString(0x1234)
		'0x1234'
		>>> addressToString(0x1122334455667788)
		'11:22:33:44:55:66:77:88'

	'''
	if address <= 0xFFFF:
		return "0x"+'{:04x}'.format(address).upper()
	else:
		return ':'.join('{:02x}'.format(i).upper() for i in struct.pack('>Q',address))

def convertAddress(address):
	'''
	This function is used to convert a Zigbee address to a standard format (integer).

	:param address: address to convert
	:type address: str or int or bytes
	:return: address in a standard format (integer)
	:rtype: int

	:Example:

		>>> convertAddress(0x1234)
		4660
		>>> convertAddress(bytes.fromhex("1122334455667788"))
		1234605616436508552

	'''
	if address is None:
		return None
	else:
		if isinstance(address,str):
			return struct.unpack('>Q',bytes.fromhex(address.replace(":","")))[0]
		elif isinstance(address,int):
			return address
		elif isinstance(address,bytes):
			return struct.unpack('>H' if len(address) == 2 else '>Q',address)[0]
		else:
			return address
