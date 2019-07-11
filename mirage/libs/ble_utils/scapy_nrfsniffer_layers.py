from scapy.all import *
import struct

'''
This module contains some scapy definitions for communicating with a NRF Sniffer device.
'''

SLIP_START = 0xAB
SLIP_END = 0xBC
SLIP_ESC = 0xCD
SLIP_ESC_START = SLIP_START+1
SLIP_ESC_END = SLIP_END+1
SLIP_ESC_ESC = SLIP_ESC+1

NRFSNIFFER_PACKET_TYPES = {
	0x00 : "REQ_FOLLOW", 
	0x01 : "EVENT_FOLLOW", 
	0x05 : "EVENT_CONNECT", 
	0x06 : "EVENT_PACKET", 
	0x07 : "REQ_SCAN_COUNT", 
	0x09 : "EVENT_DISCONNECT", 
	0x0C : "SET_TEMPORARY_KEY", 
	0x0D : "PING_REQ", 
	0x0E : "PING_RESP",
	0x13 : "SWITCH_BAUD_RATE_REQ",
	0x14 : "SWITCH_BAUD_RATE_RESP",
	0x17 : "SET_ADV_CHANNEL_HOP_SEQ",
	0xFE : "GO_IDLE"
}

class NRFSniffer_Hdr(Packet):
	name = "NRF Sniffer Header"
	fields_desc = [
	ByteField("header_length",6),
	ByteField("payload_length",None), 
	ByteField("protocol_version",0x01), 
	LEShortField("packet_counter",None), 
	ByteEnumField("packet_type",None, NRFSNIFFER_PACKET_TYPES)
	]

	def post_build(self,p,pay):
		if self.payload_length is None:
			self.payload_length = len(pay)

		packet = p[0:1]+struct.pack('B',self.payload_length)+p[2:]+pay
		packet = packet.replace(bytes([SLIP_ESC]),bytes([SLIP_ESC,SLIP_ESC_ESC]))
		packet = packet.replace(bytes([SLIP_START]),bytes([SLIP_ESC,SLIP_ESC_START]))
		packet = packet.replace(bytes([SLIP_END]),bytes([SLIP_ESC,SLIP_ESC_END]))
		return bytes([SLIP_START]) + packet + bytes([SLIP_END])


class NRFSniffer_Set_Advertising_Channels_Hopping_Sequence(Packet):
	name = "NRF Sniffer Set Advertising Channels Hopping Sequence"
	fields_desc = [
			BitFieldLenField("number_of_channels", None, 8, length_of="channels"),
			StrLenField("channels", "", length_from=lambda pkt:pkt.number_of_channels)
			]
class NRFSniffer_Scan_Continuously_Request(Packet):
	name = "NRF Sniffer Scan Continuously Request"
	fields_desc = []

class NRFSniffer_Ping_Request(Packet):
	name = "NRF Sniffer Ping Request"
	fields_desc = []

class NRFSniffer_Ping_Response(Packet):
	name = "NRF Sniffer Ping Response"
	fields_desc = [
			LEShortField("version",None)
			]
class NRFSniffer_Set_Temporary_Key_Request(Packet):
	name = "NRF Sniffer Set Temporary Key Request"
	fields_desc = [StrFixedLenField("temporary_key", b'\x00' * 16, 16)]

class NRFSniffer_Follow_Request(Packet):
	name = "NRF Sniffer Follow Request"
	fields_desc = [
			MACField("addr",None), 
			ByteEnumField("addr_type",0,{0x00 : "public", 0x01 : "random"}), 
			ByteEnumField("follow_only_advertisements",0,{0x00 : "False",0x01 : "True"})
			]

class NRFSniffer_Go_Idle(Packet):
	name = "NRF Sniffer Go Idle"
	fields_desc = []

class NRFSniffer_Event_Follow(Packet):
	name = "NRF Sniffer Event Follow"
	fields_desc = []

class NrfSniffer_Event_Packet(Packet):
	name = "NRF Sniffer Event Packet"
	fields_desc = [
			ByteField("header_length",None),
			ByteField("flags",None),
			ByteField("channel",None),
			ByteField("rssi",None),
			LEShortField("event_counter",None), 
			LEIntField("delta", None),
			PacketField("ble_payload",None,BTLE)
			]

	def pre_dissect(self,data):
		# Removing padding byte
		return data[:16]+data[17:] 	 

bind_layers(NRFSniffer_Hdr,NRFSniffer_Scan_Continuously_Request, packet_type = 0x07)
bind_layers(NRFSniffer_Hdr, NRFSniffer_Event_Follow, packet_type = 0x01)
bind_layers(NRFSniffer_Hdr, NRFSniffer_Follow_Request, packet_type = 0x00)
bind_layers(NRFSniffer_Hdr, NRFSniffer_Ping_Request, packet_type = 0x0D)
bind_layers(NRFSniffer_Hdr, NRFSniffer_Set_Temporary_Key_Request, packet_type = 0x0C)
bind_layers(NRFSniffer_Hdr, NRFSniffer_Set_Advertising_Channels_Hopping_Sequence, packet_type = 0x17)
bind_layers(NRFSniffer_Hdr, NRFSniffer_Ping_Response, packet_type = 0x0E)
bind_layers(NRFSniffer_Hdr, NrfSniffer_Event_Packet, packet_type = 0x06)
bind_layers(NRFSniffer_Hdr, NRFSniffer_Go_Idle, packet_type = 0xFE)
