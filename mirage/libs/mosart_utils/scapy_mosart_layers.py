from scapy.all import Packet, bind_layers
from scapy.fields import *
'''
This module contains some scapy definitions for Mosart protocol.
'''


class Mosart_Hdr(Packet):
	name = "Mosart Packet"
	fields_desc = [
		XShortField("preamble", 0xF0F0),
		XIntField("address", None),
		BitField("frame_type", None, 4),
		BitField("seq_num", None, 4),
	]


class Mosart_Dongle_Sync_Packet(Packet):
	name = "Mosart Dongle Sync Packet"
	fields_desc = [XByteField("sync", None)]


class Mosart_Mouse_Movement_Packet(Packet):
	name = "Mosart Movement Packet"
	fields_desc = [
		# Mousejack whitepaper is wrong on this frame : (X1Y1 / X2Y2) and not (X1X2 / Y1Y2)
		SignedByteField("X1", None),
		SignedByteField("Y1", None),
		SignedByteField("X2", None),
		SignedByteField("Y2", None),
	]


class Mosart_Action_Packet(Packet):
	name = "Mosart Action Packet"
	fields_desc = [
		ByteEnumField("action_state", None, {0x81: "pressed", 0x01: "released"}),
		XByteField("action_code", None),
	]


bind_layers(Mosart_Hdr, Mosart_Dongle_Sync_Packet, frame_type=0x1)
bind_layers(Mosart_Hdr, Mosart_Mouse_Movement_Packet, frame_type=0x4)
bind_layers(Mosart_Hdr, Mosart_Action_Packet, frame_type=0x7)
