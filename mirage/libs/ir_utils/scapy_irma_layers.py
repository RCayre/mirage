from scapy.all import *

'''
This module contains some scapy definitions for interacting with an IRMA device.
'''

#define PROTO_RAW 0x0
#define PROTO_NEC 0x1
#define PROTO_SONY 0x2
#define PROTO_RC5 0x3
#define PROTO_RC6 0x4
#define PROTO_DISH 0x5
#define PROTO_SHARP 0x6
#define PROTO_JVC 0x7
#define PROTO_SANYO 0x8
#define PROTO_MITSUBISHI 0x9
#define PROTO_SAMSUNG 0xa
#define PROTO_LG 0xb
#define PROTO_WHYNTER 0xc
#define PROTO_AIWA_RC_T501 0xd
#define PROTO_PANASONIC 0xe
#define PROTO_DENON 0xf

proto_list = {
		0x00 : "raw",
		0x01 : "NEC",
		0x02 : "SONY",
		0x03 : "RC5",
		0x04 : "RC6",
		0x05 : "DISH",
		0x06 : "SHARP",
		0x07 : "JVC",
		0x08 : "SANYO",
		0x09 : "MITSUBISHI",
		0x0a : "SAMSUNG",
		0x0b : "LG",
		0x0c : "WHYNTER",
		0x0d : "AIWA_RC_T501",
		0x0e : "PANASONIC",
		0x0f : "DENON"
}

class IRma_Hdr(Packet):
	name = "IRma Packet Header"
	fields_desc = [ByteEnumField("type", None, {0x00 : "request",0x01 : "response"})]

class IRma_Header_Common(Packet):
	fields_desc = [ByteEnumField("opcode", None, {0x00 : "reset",
							0x01 : "freq",
							0x02 : "send",
							0x03 : "recv"}),
	ShortField("param_size", None)]

	def post_build(self, p, pay):
		if self.param_size is None:
			self.param_size = len(pay)
			p = p[:1] + struct.pack('>h',self.param_size)
		return p+pay

class IRma_Request(IRma_Header_Common):
	name = "IRma Request Header"

class IRma_Response(IRma_Header_Common):
	name = "IRma Response Header"

class Req_IRma_Reset(Packet):
	name = "Request IRma Reset Packet"

class Resp_IRma_Reset(Packet):
	name = "Response IRma Reset Packet"

class Req_IRma_GetFreq(Packet):
	name = "Request IRma Get Frequency Packet"

class Req_IRma_SetFreq(Packet):
	name = "Request IRma Set Frequency Packet"
	fields_desc = [ ShortField("freq", None) ]


class Resp_IRma_Freq(Packet):
	name = "Response IRma Frequency Packet"
	fields_desc = [ ShortField("freq", None) ]

class Req_IRma_Send(Packet):
	name = "Request IRma Send Packet"
	fields_desc = [ ByteEnumField("proto", None, proto_list),
			FieldLenField("data_size", None, length_of = "data"),
			StrLenField("data", None,length_from = lambda pkt:pkt.data_size)
	]

class Resp_IRma_Send(Packet):
	name = "Response IRma Send Packet"
	fields_desc = [ByteEnumField("success",None,{0x00:"success",0x01:"error"})]

class Req_IRma_Recv(Packet):
	name = "Request IRma Receive Packet"

class Resp_IRma_Recv(Packet):
	name = "Response IRma Receive Packet"
	fields_desc = [ FieldLenField("raw_size",None,length_of = "raw"),
			FieldListField("raw", [],ShortField("value",None), length_from = lambda pkt:pkt.raw_size),
			ByteEnumField("proto", None, proto_list),
			ShortField("code_size",32),
			StrField("code", b"")]

class Resp_IRma_Ready(Packet):
	name = "Start Packet (Device Ready)"
	fields_desc = []

bind_layers(IRma_Hdr,IRma_Request,type=0x00)
bind_layers(IRma_Hdr,IRma_Response,type=0x01)

bind_layers(IRma_Request,Req_IRma_Reset,opcode=0x00)
bind_layers(IRma_Response,Req_IRma_Reset,opcode=0x00)

bind_layers(IRma_Request,Req_IRma_GetFreq,opcode=0x01)
bind_layers(IRma_Request,Req_IRma_SetFreq,opcode=0x01)
bind_layers(IRma_Response,Resp_IRma_Freq,opcode=0x01)

bind_layers(IRma_Request,Req_IRma_Send,opcode=0x02)
bind_layers(IRma_Response,Resp_IRma_Send,opcode=0x02)

bind_layers(IRma_Request,Req_IRma_Recv,opcode=0x03)
bind_layers(IRma_Response,Resp_IRma_Recv,opcode=0x03)

bind_layers(IRma_Response,Resp_IRma_Ready,opcode=0x04)
