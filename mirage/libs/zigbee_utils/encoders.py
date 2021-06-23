from mirage.libs.common.sdr.encoders import SDREncoder
from mirage.libs.zigbee_utils.chip_tables import *


class ZigbeeEncoder(SDREncoder):
	'''
	Software Defined Radio encoder for Zigbee protocol.
	'''
	def _getChips(self,bits):
		for i in SYMBOL_TO_CHIP_MAPPING:
			if bits == i["symbols"]:
				return i["chip_values"]
		return None

	def encode(self,data):
		if data[0] == 0xA7:
			data = b"\x00\x00\x00\x00" + data
		elif data[0] != 0x00:
			data = b"\x00\x00\x00\x00\xA7" + data
		bits = []
		for i in bytes(data):
			byte = "{:08b}".format(i)
			bits += [byte[4:8][::-1], byte[0:4][::-1]]
		sequence = ""
		for bit in bits:
			sequence += self._getChips(bit)
		return sequence
