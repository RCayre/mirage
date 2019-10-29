from scapy.all import *

'''
This module contains some scapy definitions for XBee packets.
'''


class Xbee_Hdr(Packet):
    description = "XBee payload"
    fields_desc = [
        ByteField("counter", None),
        ByteField("unknown", None)
]
