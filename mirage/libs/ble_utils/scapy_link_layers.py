from scapy.all import *

'''
This module contains some scapy definitions of Link Layer Bluetooth Low Energy packets.
'''

class LL_ENC_REQ(Packet):
	name = "LL_ENC_REQ"
	fields_desc = [
		XLELongField("rand",None),
		XLEShortField("ediv",None),
		XLELongField("skd",None),
		XLEIntField("iv",None)
	]

class LL_ENC_RSP(Packet):
	name = "LL_ENC_RSP"
	fields_desc = [
		XLELongField("skd",None),
		XLEIntField("iv",None)
	]
