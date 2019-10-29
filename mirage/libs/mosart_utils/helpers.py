import struct
'''
This module provides some helpers in order to manipulate Mosart packets.
'''

def _initial(c):
	crc = 0
	c = c << 8
	for j in range(8):
		if (crc ^ c) & 0x8000:
			crc = (crc << 1) ^ 0x1021
		else:
			crc = crc << 1
		c = c << 1
	return crc


_tab = [_initial(i) for i in range(256)]


def _update_crc(crc, c):
	cc = 0xFF & c

	tmp = (crc >> 8) ^ cc
	crc = (crc << 8) ^ _tab[tmp & 0xFF]
	crc = crc & 0xFFFF

	return crc


def crc(data):
	'''
	This function returns the CRC of a Mosart payload.

	:param data: bytes of the payload
	:type data: bytes

	'''
	crc = 0
	for c in data:
		crc = _update_crc(crc, c)
	return crc


def addressToInteger(address):
	'''
	This function converts a string indicating the address of a Mosart device to its raw value (as integer).

	:param address: string to convert (format: '11:22:33:44')
	:type address: str

	:Example:

		>>> hex(addressToInteger('11:22:33:44'))
		'0x11223344'


	'''
	return struct.unpack('>I',bytes.fromhex(address.replace(":","")))[0]

def integerToAddress(integer):
	'''
	This function converts a Mosart address to a printable string.

	:param integer: address to convert
	:type address: int

	:Example:

		>>> integerToAddress(0x11223344)
		'11:22:33:44'

	'''

	return ':'.join(['{:02x}'.format(i) for i in struct.pack('>I',integer)]).upper()
