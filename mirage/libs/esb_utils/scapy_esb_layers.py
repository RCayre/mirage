from mirage.libs.esb_utils.constants import *
from mirage.libs.esb_utils.helpers import *
from scapy.all import *

'''
This module contains some scapy definitions for Enhanced ShockBurst packets.
'''

# Field representing a ShockBurst address
class SBAddressField(StrLenField):
	def __init__(self, name, default, length_from):
		StrLenField.__init__(self, name, default,length_from=length_from)

	def i2h(self,pkt,x):
		return ":".join(["{:02x}".format(i) for i in x])

	def any2i(self,pkt,x):
		if isinstance(x,str):
			x = bytes.fromhex(x.replace(":",""))
		return x


class ESB_Hdr(Packet):
	ESB_PREAMBLE_SIZE = 8
	ESB_PCF_SIZE = 9
	ESB_CRC_SIZE = 16
	ESB_PAYLEN_SIZE = 6
	name = "Enhanced ShockBurst packet"
	fields_desc = [
			XByteField("preamble",0xAA),
			FieldLenField("address_length", None, length_of="address"),
			SBAddressField("address",b"\0\0\0\0\0",length_from = lambda pkt:pkt.address_length),
			BitField("payload_length", None, 6),
			BitField("pid",None,2),
			BitField("no_ack", 0,1),
			BitField("padding",0,6),
			BitEnumField("valid_crc",0,1,{0:"no",1:"yes"}), 
			XShortField("crc",None)
		]

	def pre_dissect(self,s):		
		bitstring = bytes2bits(s)
		crc = None
		crcFound = False
		i = ESB_Hdr.ESB_PREAMBLE_SIZE+1
		# We try to guess the packet size by looking for a valid CRC
		while i < len(bitstring) - 16:
			if bytes2bits(calcCrc(bits2bytes(bitstring[ESB_Hdr.ESB_PREAMBLE_SIZE:i]))) == bitstring[i:i+ESB_Hdr.ESB_CRC_SIZE]:
				crcFound = True
				break
			i += 1

		# We try to guess the address size by checking if :
		# ESB_PREAMBLE_SIZE + 8*addr_size + ESB_PCF_SIZE + payload_size = 8*packet_size - ESB_CRC_SIZE
		
		addrLenFound = False
		for addrLen in range(3,6):
			payLen = bits2bytes("00"+bitstring[ESB_Hdr.ESB_PREAMBLE_SIZE+addrLen*8:ESB_Hdr.ESB_PREAMBLE_SIZE+addrLen*8+ESB_Hdr.ESB_PAYLEN_SIZE])[0]
			if ESB_Hdr.ESB_PREAMBLE_SIZE+addrLen*8+ESB_Hdr.ESB_PCF_SIZE+payLen*8 == i:
				addrLenFound = True
				break


		preamble = bitstring[:ESB_Hdr.ESB_PREAMBLE_SIZE]
		if crcFound and addrLenFound:
			# No problem, we know that the packet is valid
			address = bitstring[ESB_Hdr.ESB_PREAMBLE_SIZE:ESB_Hdr.ESB_PREAMBLE_SIZE+addrLen*8]
			validCrc = "1" if crcFound else "0"
		else:
			# Our assumption is : addrLen = 5, invalid CRC
			addrLen = 5
			address = bitstring[ESB_Hdr.ESB_PREAMBLE_SIZE:ESB_Hdr.ESB_PREAMBLE_SIZE+addrLen*8]
			validCrc = "0"

		pcf = bitstring[ESB_Hdr.ESB_PREAMBLE_SIZE+addrLen*8:ESB_Hdr.ESB_PREAMBLE_SIZE+addrLen*8+ESB_Hdr.ESB_PCF_SIZE]
		payloadLength = bits2bytes("00"+pcf[:6])[0]
		payload = bitstring[ESB_Hdr.ESB_PREAMBLE_SIZE+addrLen*8+ESB_Hdr.ESB_PCF_SIZE:ESB_Hdr.ESB_PREAMBLE_SIZE+addrLen*8+ESB_Hdr.ESB_PCF_SIZE+payloadLength*8]
		crc = bitstring[ESB_Hdr.ESB_PREAMBLE_SIZE+addrLen*8+ESB_Hdr.ESB_PCF_SIZE+payloadLength*8:ESB_Hdr.ESB_PREAMBLE_SIZE+addrLen*8+ESB_Hdr.ESB_PCF_SIZE+payloadLength*8+ESB_Hdr.ESB_CRC_SIZE]

		padding = "0"*6

		return bits2bytes(preamble + bytes2bits(bytes([0,addrLen])) + address + pcf + padding + validCrc + crc + payload)

	def post_build(self,p,pay):
		preamble = bytes2bits(p[0:1])
		addrLen = struct.unpack('>H',p[1:3])[0]

		address = bytes2bits(p[3:3+addrLen])
		header = bytes2bits(p[3+addrLen:3+addrLen+2])[:9]
		if self.payload_length is None:
			payLen = bytes2bits(struct.pack('B',len(pay)))[2:]
			header = payLen + header[6:]
		payload = bytes2bits(pay)
		packet = bits2bytes(preamble + address + header + payload)
		if self.crc is None:
			crc = calcCrc(packet[1:])
		else:
			crc = p[-2:]
		crc = bytes2bits(crc)
		return bits2bytes(preamble + address + header + payload + crc)


class ESB_Payload_Hdr(Packet):
	name = "ESB Payload"

	def guess_payload_class(self, payload):
		if b"\x0f\x0f\x0f\x0f" == payload[:4]:
			return ESB_Ping_Request
		elif len(payload) == 0:
			return ESB_Ack_Response
		elif len(payload) >= 2 and payload[1] in [0x51,0xC2,0x40,0x4F,0xD3,0xC1,0xC3]:
			return Logitech_Unifying_Hdr
		else:
			return Packet.guess_payload_class(self, payload)

class ESB_Ping_Request(Packet):
    	name = "ESB Ping Request"
    	fields_desc = [StrFixedLenField('ping_payload', '\x0f\x0f\x0f\x0f', length=4)] 

class ESB_Ack_Response(Packet):
    	name = "ESB Ack Response"
    	fields_desc = [StrField('ack_payload', '')] 

class Logitech_Unifying_Hdr(Packet):
	name = "Logitech Unifying Payload"
	fields_desc = [	XByteField("dev_index",0x00),
			XByteField("frame_type",  0x00),
			XByteField("checksum",None)]

	def pre_dissect(self,s):
		calcCksum = 0xFF
		currentByte = 0
		while calcCksum+1 != s[currentByte] and currentByte < len(s) - 1:
			calcCksum = (calcCksum - s[currentByte]) & 0xFF
			currentByte += 1
		if calcCksum+1 != s[currentByte]:
			return s
		return  s[:2] + s[currentByte:currentByte+1] + s[2:currentByte] + s[currentByte+1:]

	def post_dissect(self,s):
		self.checksum = None
		return s
	def post_build(self,p,pay):
		if self.checksum is None:
			cksum = 0xFF
			for i in (p[:2] + pay):
				cksum = (cksum - i) & 0xFF
			cksum = (cksum + 1) & 0xFF
		else:
			cksum = self.checksum
		return p[:2] + pay + struct.pack('B', cksum)


class Logitech_Wake_Up(Packet):
	name = "Logitech Wake Up Payload"
	fields_desc = [ XByteField("dev_index",0x00),
			ByteField("???(1)",  0x00),
			ByteField("???(2)",  0x00),
			X3BytesField("???(3)",  "\x01\x01\x01"),
			ByteField("unused", 13)
			]


class Logitech_Encrypted_Keystroke_Payload(Packet):
	name = "Logitech Encrypted Keystroke Payload"
	fields_desc = [		StrFixedLenField('hid_data', '\0\0\0\0\0\0\0', length=7),
				ByteField("unknown",0x00), 
				IntField('aes_counter',None),
				StrFixedLenField('unused', '\0\0\0\0\0\0\0', length=7)
	]

class Logitech_Unencrypted_Keystroke_Payload(Packet):
	name = "Logitech Unencrypted Keystroke Payload"
	fields_desc = [ 	StrFixedLenField('hid_data', '\0\0\0\0\0\0\0', length=7)]

class Logitech_Multimedia_Key_Payload(Packet):
	name = "Multimedia Key Payload"
	fields_desc = [	 	StrFixedLenField('hid_key_scan_code', '\0\0\0\0', length=4),
				StrFixedLenField('unused','\0\0\0', length=3)]

class Logitech_Keepalive_Payload(Packet):
	name = "Logitech Keepalive Payload"
	fields_desc = [		ShortField('timeout',None)]

class Logitech_Set_Keepalive_Payload(Packet):
	name = "Logitech Set Keepalive Payload"
	fields_desc = [		ByteField("unused", None), 
				ShortField('timeout',1200),
				IntField("unused_2",0x10000000)]

class Logitech_Mouse_Payload(Packet):
	name = "Logitech Mouse Payload"
	fields_desc = [	XByteField("button_mask",0x00),
			ByteField("unused",0x00),
			StrFixedLenField("movement","",length=3),
			ByteField("wheel_y",0x00),
			ByteField("wheel_x",0x00)]

bind_layers(ESB_Hdr,ESB_Payload_Hdr)

# Logitech Unifying protocol
bind_layers(Logitech_Unifying_Hdr, Logitech_Wake_Up,				frame_type = 0x51)
bind_layers(Logitech_Unifying_Hdr, Logitech_Mouse_Payload,			frame_type = 0xC2)
bind_layers(Logitech_Unifying_Hdr, Logitech_Keepalive_Payload, 			frame_type = 0x40)
bind_layers(Logitech_Unifying_Hdr, Logitech_Set_Keepalive_Payload, 		frame_type = 0x4F)
bind_layers(Logitech_Unifying_Hdr, Logitech_Encrypted_Keystroke_Payload, 	frame_type = 0xD3)
bind_layers(Logitech_Unifying_Hdr, Logitech_Unencrypted_Keystroke_Payload, 	frame_type = 0xC1)
bind_layers(Logitech_Unifying_Hdr, Logitech_Multimedia_Key_Payload, 		frame_type = 0xC3)
