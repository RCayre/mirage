'''
This module contains some scapy definitions for XBee packets.
'''

from scapy.fields import ByteField
from scapy.packet import Packet


class Xbee_Hdr(Packet):
	description = "XBee payload"
	fields_desc = [
		ByteField("counter", None),
		ByteField("unknown", None)
]
