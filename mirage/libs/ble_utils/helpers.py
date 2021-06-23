'''
This module provides some helpers in order to manipulate Bluetooth Low Energy link layer packets.
'''

def frequencyToChannel(frequency):
	'''
	This function converts a frequency to the corresponding BLE channel.

	:param frequency: frequency to convert (MHz)
	:type frequency: int
	:return: channel associated to the provided frequency
	:rtype: int

	:Example:

		>>> frequencyToChannel(2420)
		8
		>>> frequencyToChannel(2402)
		37

	'''
	freqOffset = frequency - 2400
	if freqOffset == 2:
		channel = 37
	elif freqOffset == 26:
		channel = 38
	elif freqOffset ==  80:
		channel = 39
	elif freqOffset < 24:
		channel = int((freqOffset / 2) - 2)
	else:
		channel = int((freqOffset / 2) - 3)

	return channel

def channelToFrequency(channel):
	'''
	This function converts a BLE channel to the corresponding frequency.

	:param channel: BLE channel to convert
	:type channel: int
	:return: corresponding frequency (MHz)
	:rtype: int

	:Example:

		>>> channelToFrequency(37)
		2402
		>>> channelToFrequency(8)
		2420

	'''
	if channel == 37:
		freqOffset = 2
	elif channel == 38:
		freqOffset = 26
	elif channel == 39:
		freqOffset = 80
	elif channel < 11:
		freqOffset = 2*(channel+2)
	else:
		freqOffset = 2*(channel+3)
	return 2400 + freqOffset

def _swapBits(value):
	return (value * 0x0202020202 & 0x010884422010) % 1023

def crc24(data, length, init=0x555555):
	'''
	This function calculates the 24 bits CRC corresponding to the data provided.

	:param data: packet's payload
	:type data: bytes
	:param length: length of data
	:type length: int
	:param init: initialization value
	:type init: int
	:return: 24 bits crc value
	:rtype: bytes

	:Example:

		>>> data=bytes.fromhex("0215110006000461ca0ce41b1e430559ac74e382667051")
		>>> crc24(data=data,length=len(data)).hex()
		'545d96'
	'''
	ret = [(init >> 16) & 0xff, (init >> 8) & 0xff, init & 0xff]

	for d in data[:length]:
		for v in range(8):
			t = (ret[0] >> 7) & 1;

			ret[0] <<= 1
			if ret[1] & 0x80:
				ret[0] |= 1

			ret[1] <<= 1
			if ret[2] & 0x80:
				ret[1] |= 1

			ret[2] <<= 1

			if d & 1 != t:
				ret[2] ^= 0x5b
				ret[1] ^= 0x06

			d >>= 1

	ret[0] = _swapBits((ret[0] & 0xFF))
	ret[1] = _swapBits((ret[1] & 0xFF))
	ret[2] = _swapBits((ret[2] & 0xFF))

	return bytes(ret)


def isAccessAddressValid(aa):
	'''
	This function checks if the provided access address is valid.

	:param aa: access address to validate
	:type aa: int
	:return: boolean indicating if the access address provided is valid
	:rtype: bool

	:Example:

		>>> isAccessAddressValid(0x870ac713)
		True
		>>> isAccessAddressValid(0xcc0bcc1a)
		False

	'''
	a = (aa & 0xff000000)>>24
	b = (aa & 0x00ff0000)>>16
	c = (aa & 0x0000ff00)>>8
	d = (aa & 0x000000ff)
	if a==b and b==c and c==d:
		return False
	if (aa == 0x8E89BED6):
		return True
	bb = aa
	for i in range(0,26):
		if (bb & 0x3F) == 0 or (bb & 0x3F) == 0x3F:
			return False
		bb >>= 1
	bb = aa
	t = 0
	a = (bb & 0x80000000)>>31
	for i in range(30,0,-1):
		if (bb & (1<<i)) >> i != a:
			a = (bb & (1<<i))>>i
			t += 1
			if t>24:
				return False
		if (i<26) and (t<2):
			return False
	return True

def rssiToDbm(rssi):
	'''
	This function converts a RSSI (Received Signal Strength Indication) to a value in Dbm.

	:param rssi: rssi to convert
	:type rssi: int
	:return: corresponding value in Dbm
	:rtype: float

	:Example:

		>>> rssiToDbm(12)
		-45.0
		>>> rssiToDbm(30)
		-28.8

	'''
	if rssi < -48:
		return -120
	elif rssi <= -45:
		return 6*(rssi+28)
	elif rssi <= 30:
		return (99*(rssi - 62)/110)
	elif rssi <= 35:
		return (60*(rssi - 35) / 11)
	else:
		return 0


def dewhiten(data,channel):
	'''
	This function allows to dewhiten a given raw data according to the channel value.

	:param data: raw data to dewhiten
	:type data: bytes
	:param channel: channel number
	:type channel: int
	:return: dewhitened data
	:rtype: bytes
	'''
	def _swap_bits(b):
		o = 0
		i = 0
		for i in range(8):
			o = o << 1
			o |= 1 if (b & (1<<i)) else 0
		return o
	buffer = b""
	lfsr = _swap_bits(channel) | 2
	for i in range(len(data)):
		c = _swap_bits(data[i])
		for j in range(7,-1,-1):
			if lfsr & 0x80:
				lfsr ^= 0x11
				c ^= (1<<j)
			lfsr <<= 1
		buffer+=bytes([_swap_bits(c)])
	return buffer
