from scapy.all import *
'''
This module contains some scapy definitions for Bluetooth protocol.
Some of them have been recently included in the latest scapy development version, these changes will be taken into account soon.
'''

bluetooth_error_codes = {
0x01 : "Unknown HCI Command.",
0x02 : "No Connection.",
0x03 : "Hardware Failure.",
0x04 : "Page Timeout.",
0x05 : "Authentication Failure.",
0x06 : "Key Missing.",
0x07 : "Memory Full.",
0x08 : "Connection Timeout.",
0x09 : "Max Number Of Connections.",
0x0A : "Max Number Of SCO Connections To A Device.",
0x0B : "ACL connection already exists.",
0x0C : "Command Disallowed.",
0x0D : "Host Rejected due to limited resources.",
0x0E : "Host Rejected due to security reasons.",
0x0F : "Host Rejected due to remote device is only a personal device.",
0x10 : "Host Timeout. ",
0x11 : "Unsupported Feature or Parameter Value.",
0x12 : "Invalid HCI Command Parameters. ",
0x13 : "Other End Terminated Connection: User Ended Connection.",
0x14 : "Other End Terminated Connection: Low Resources.",
0x15 : "Other End Terminated Connection: About to Power Off.",
0x16 : "Connection Terminated by Local Host.",
0x17 : "Repeated Attempts."
}

class HCI_Cmd_Inquiry(Packet):
	name = "Inquiry"
	fields_desc = [ ThreeBytesField("lap",0x338b9e),
			ByteField("inquiry_length",5),
			ByteField("num_response",0)]

class HCI_Cmd_Write_Extended_Inquiry_Response(Packet):
	name = "Write Extended Inquiry Response"
	fields_desc = [	ByteEnumField("fec_required",0x00,{0x00:"faux",0x01:"vrai"}),
			PacketListField("data", [], EIR_Hdr)]

class HCI_Evt_Extended_Inquiry_Result(Packet):
	name = "Extended Inquiry Result"
	fields_desc = [ ByteField("num_response",5),
			LEMACField("addr", None),
			ByteEnumField("page_scan_repetition_mode", 0x01, {0x01: "R1"}),
			ByteField("reserved",2),
			ThreeBytesField("class_of_device",0x000000),
			XShortField("clock_offset",0),
			ByteField("rssi",0),
			PacketListField("data", [], EIR_Hdr)
			]

class HCI_Evt_Inquiry_Result_With_RSSI(Packet):
	name = "Inquiry Result with RSSI"
	fields_desc = [ ByteField("num_response",5),
			LEMACField("addr", None),
			ByteEnumField("page_scan_repetition_mode", 0x01, {0x01: "R1"}),
			ByteField("reserved",2),
			ThreeBytesField("class_of_device",0x000000),
			XShortField("clock_offset",0),
			ByteField("rssi",0)
			]

class HCI_Evt_Inquiry_Result(Packet):
	name = "Inquiry Result"
	fields_desc = [ ByteField("num_response",5),
			LEMACField("addr", None),
			ByteEnumField("page_scan_repetition_mode", 0x01, {0x01: "R1"}),
			ByteField("page_scan_period_mode",0x00),
			ByteField("page_scan_mode",0x00),
			ThreeBytesField("class_of_device",0x000000),
			XShortField("clock_offset",0)

			]
class HCI_Evt_Inquiry_Complete(Packet):
	name = "Inquiry Complete"
	fields_desc = [ByteEnumField("status", 0x00, {0x00: "success"})]

class HCI_Cmd_Write_Inquiry_Mode(Packet):
	name = "Write Inquiry Mode"
	fields_desc = [ByteEnumField("inquiry_mode",0x02,{0x02 : "Results with RSSI  / Extended"})]

class HCI_Cmd_Read_Local_Name(Packet):
	name = "Read Local Name"

class HCI_Cmd_Write_Local_Name(Packet):
	name = "Write Local Name"
	fields_desc = [StrNullField("local_name", None),
			StrField("padding",None) ]

class HCI_Cmd_Complete_Read_Local_Name(Packet):
	name = "Read Local Name"
	fields_desc = [	StrNullField("local_name", None),
			StrField("padding",None) ]

scan_states = {	0x00 : "no scans enabled",
		0x01 : "inquiry scan enabled / page scan disabled",
		0x02 : "inquiry scan disabled / page scan enabled",
		0x03:"inquiry scan enabled / page scan enabled"}

class HCI_Cmd_Write_Scan_Enable(Packet):
	name = "Write Scan Enable"
	fields_desc = [ByteEnumField("scan_enable",0x00,scan_states)]

class HCI_Cmd_Remote_Name_Request(Packet):
	name = "Remote Name Request"
	fields_desc = [
		LEMACField("addr", None),
		ByteEnumField("page_scan_repetition_mode",None,{0x01:"R1",0x02:"R2"}),
		ByteField("page_scan_mode",0x00),
		XShortField("clock_offset",0)
	]


class HCI_Cmd_Create_Connection(Packet):
	name = "Create Connection"
	fields_desc = [	LEMACField("addr", None),
			LEShortField("packet_type",0xcc18),
			ByteEnumField("page_scan_repetition_mode",None,{0x01:"R1",0x02:"R2"}),
			ByteField("page_scan_mode",0x00),
			XShortField("clock_offset",0),
			ByteEnumField("allow_role_switch",0x01,{0x00:"disallowed",0x01:"allowed"})]

class HCI_Cmd_Accept_Connection_Request(Packet):
	name = "Accept Connection Request"
	fields_desc = [	LEMACField("addr", None),
			ByteEnumField("role_switch",0x01,{0x00:"master",0x01:"slave"})]

class HCI_Cmd_Reject_Connection_Request(Packet):
	name = "Reject Connection Request"
	fields_desc = [LEMACField("addr", None),
			ByteEnumField("reason",0x01,bluetooth_error_codes)]


class HCI_Evt_Connection_Complete(Packet):
	name = "Connection Complete"
	fields_desc = [	ByteEnumField("status", 0x00, {0x00: "success",0x04:"page_timeout"}),
			LEShortField("handle", 0),
			LEMACField("addr", None),
			ByteEnumField("link_type",0x01,{0x01:"ACL connection"}),
			ByteEnumField("encryption_mode",0x00, {0x00:'disabled',0x01:'enabled'})
	]

class HCI_Evt_Connection_Request(Packet):
	name = "Connection Request"
	fields_desc = [ LEMACField("addr", None),
			ThreeBytesField("class_of_device",0x000000),
			ByteEnumField("link_type",0x01,{0x01:"ACL connection"})
	]

class HCI_Evt_Max_Slot_Change(Packet):
	name = "Max Slot Change"
	fields_desc = [
		LEShortField("handle", 0),
		ByteField("max_number_slots",None)
	]
class HCI_Evt_Remote_Name_Request_Complete(Packet):
	name = "Remote Name Request Complete"
	fields_desc = [
		ByteEnumField("status", 0x00, {0x00: "success",0x04:"page_timeout"}),
		LEMACField("addr",None),
		StrNullField("remote_name",None)
	]

class HCI_Evt_Page_Scan_Repetition_Mode_Change(Packet):
	name = "Page Scan Repetition Mode Change"
	fields_desc = [
		LEMACField('addr',None),
		ByteEnumField("page_scan_repetition_mode",None,{0x01:"R1",0x02:"R2"})
	]




class Data_Element_Hdr(Packet):
	name = "Data Element Header"
	fields_desc = 	[

		BitEnumField('type', 0, 5, {	0 : "nil",
		1 : "unsigned_integer",
		2:"signed_twocomp_integer",
		3:"uuid",
		4:"text_string",
		5:"boolean",
		6:"data_element_seq",
		7:"data_element_alt",
		8:"url"
		}),

		BitEnumField('size', 0, 3, 	{
		0:"1 byte",
		1:"2 bytes",
		2:"4 bytes",
		3:"8 bytes",
		4:"16 bytes",
		5:"additional_8_bits",
		6:"additionnal_16_bits",
		7:"additionnal_32_bits"
		}),

		ConditionalField(ByteField("additional_8_bits_size",None),lambda pkt:pkt.size==5),
		ConditionalField(ShortField("additional_16_bits_size",None),lambda pkt:pkt.size==6),
		ConditionalField(IntField("additional_32_bits_size",None),lambda pkt:pkt.size==7),


	]

	def do_dissect_payload(self, s):

		cls = self.guess_payload_class(s)
		size = 1
		if self.type == 0:
			size = 0
		elif self.size == 0:
			size = 1
		elif self.size == 1:
			size = 2
		elif self.size == 2:
			size = 4
		elif self.size == 3:
			size = 8
		elif self.size == 4:
			size = 16
		elif self.size == 5:
			size = self.additional_8_bits_size
		elif self.size == 6:
			size = self.additional_16_bits_size
		elif self.size == 7:
			size = self.additional_32_bits_size

		p = cls(struct.pack('>I',size)+s, _internal=1, _underlayer=self)

		self.add_payload(p)




class Data_Element_Value(Packet):
	def do_build(self):
		if not self.explicit:
			self = next(iter(self))
		pkt = self.self_build()
		for t in self.post_transforms:
			pkt = t(pkt)
		pay = self.do_build_payload()
		return self.post_build(pkt, pay)

	def post_build(self, pkt, pay):
		"""Remove size"""
		return pkt[4:]+pay

	def extract_padding(self, s):
		return '', s

class Data_Element_Nil(Data_Element_Value):
	name = "Data Element Nil"
	fields_desc = [	IntField("data_size",None)
	]

class Data_Element_Unsigned_Integer(Data_Element_Value):
	name = "Data Element Unsigned Integer"
	fields_desc = [ 
		IntField("data_size",None),
		ConditionalField(ByteField("value_1",None),lambda pkt:pkt.data_size==1),
		ConditionalField(ShortField("value_2",None),lambda pkt:pkt.data_size==2),
		ConditionalField(IntField("value_4",None),lambda pkt:pkt.data_size==4),
		ConditionalField(LongField("value_8",None),lambda pkt:pkt.data_size==8),
		ConditionalField(StrFixedLenField('value_16',None,length=16),lambda pkt:pkt.data_size==16)
		]



class Data_Element_Signed_Integer(Data_Element_Value):
	name = "Data Element Signed Integer"
	fields_desc = [ IntField("data_size",None),
			ConditionalField(ByteField("value_1",None),lambda pkt:pkt.data_size==1),
			ConditionalField(SignedShortField("value_2",None),lambda pkt:pkt.data_size==2),
			ConditionalField(SignedIntField("value_4",None),lambda pkt:pkt.data_size==4),
			ConditionalField(LongField("value_8",None),lambda pkt:pkt.data_size==8),
			ConditionalField(StrFixedLenField('value_16',None,length=16),lambda pkt:pkt.data_size==16) ]

class Data_Element_UUID(Data_Element_Value):
	name = "Data Element UUID"
	fields_desc = [ IntField("data_size",None),
			ConditionalField(XLEShortField("value_2",None),lambda pkt:pkt.data_size==2),
			ConditionalField(XLEIntField("value_4",None),lambda pkt:pkt.data_size==4),
			ConditionalField(XLELongField("value_8",None),lambda pkt:pkt.data_size==8)
	]

class Data_Element_String(Data_Element_Value):
	name = "Data Element String"
	fields_desc = [ IntField("data_size",None),
			StrLenField("value", None, length_from=lambda pkt: pkt.data_size)
	]


class Data_Element_Seq(Data_Element_Value):
	name = "Data Element Sequence"
	fields_desc = [ IntField("data_size",None),
			PacketListField("value", [], Data_Element_Hdr)
	]

class Data_Element_Alt(Data_Element_Value):
	name = "Data Element Alternative"
	fields_desc = [ IntField("data_size",None),
			PacketListField("value", [], Data_Element_Hdr)
	]

class Data_Element_URL(Data_Element_Value):
	name = "Data Element URL"
	fields_desc = [ IntField("data_size",None),
			StrLenField("value", None, length_from=lambda pkt: pkt.data_size)
	]


class SDP_Hdr(Packet):
	name = "Service Discovery Protocol Header"
	fields_desc = 	[
		ByteEnumField("pdu_id",0x00,{
		0x01:"error_resp",
		0x02:"service_search_req",
		0x03:"service_search_resp",
		0x04:"attribute_req",
		0x05:"attribute_resp",
		0x06:"service_search_attribute_req",
		0x07:"service_search_attribute_resp"
		}),
		XShortField("transaction_id",0),
		ShortField("param_length",None)
	]
	def post_build(self, p, pay):
		if self.param_length is None and pay:
			l = len(pay)
			p = p[:3] + struct.pack(">H",l)
		return p+pay

class SDP_Error_Response(Packet):
	name = "SDP Error Response"
	fields_desc = 	[
		ShortEnumField("error_code",0x0000,{
		0x0000:"reserved",
		0x0001:"invalid_sdp_version",
		0x0002:"invalid_service_record_handle",
		0x0003:"invalid_request_syntax",
		0x0004:"invalid_pdu_size",
		0x0005:"invalid_continuation_state",
		0x0006:"insufficient_ressources"
		})
	]

class SDP_Service_Search_Request(Packet):
	name = "SDP Service Search Request"
	fields_desc = 	[
		PacketListField("service_search_pattern", [], Data_Element_Hdr),
		ShortField("max_service_record_count",None),
		ByteEnumField("continuation_state_count", None, {0x00 : "no"}),
		StrFixedLenField("continuation_state",None, length_from=lambda pkt:pkt.continuation_state_count)
	]


class SDP_Service_Search_Response(Packet):
	name = "SDP Service Search Response"
	fields_desc = 	[
		ShortField("total_service_record_count",None),
		ShortField("current_service_record_count",None),
		FieldListField("service_record_handle_list", [], IntField , count_from=lambda pkt:pkt.current_service_record_count),
		ByteEnumField("continuation_state_count", None, {0x00 : "no"}),
		StrFixedLenField("continuation_state",None, length_from=lambda pkt:pkt.continuation_state_count)
	]

class SDP_Service_Attribute_Request(Packet):
	name = "SDP Service Attribute Request"
	fields_desc = 	[
		IntField("service_record_handle",None),
		ShortField("max_attribute_byte_count", None),
		PacketListField("attribute_id_list", [], Data_Element_Hdr),
		ByteEnumField("continuation_state_count", None, {0x00 : "no"}),
		StrFixedLenField("continuation_state",None, length_from=lambda pkt:pkt.continuation_state_count)
	]

class SDP_Service_Attribute_Response(Packet):
	name = "SDP Service Attribute Response"
	fields_desc = 	[
		ShortField('attribute_list_byte_count', None),
		PacketListField("attribute_list", [], Data_Element_Hdr, length_from=lambda pkt:pkt.attribute_list_byte_count),
		ByteEnumField("continuation_state_count", None, {0x00 : "no"}),
		StrFixedLenField("continuation_state",None, length_from=lambda pkt:pkt.continuation_state_count)
	]

bind_layers(Data_Element_Hdr,Data_Element_Nil, type=0)
bind_layers(Data_Element_Hdr,Data_Element_Unsigned_Integer, type=1)
bind_layers(Data_Element_Hdr,Data_Element_Signed_Integer, type=2)
bind_layers(Data_Element_Hdr,Data_Element_UUID, type=3)
bind_layers(Data_Element_Hdr,Data_Element_String, type=4)
bind_layers(Data_Element_Hdr,Data_Element_Seq, type=6)
bind_layers(Data_Element_Hdr,Data_Element_Alt, type=7)
bind_layers(Data_Element_Hdr,Data_Element_URL, type=8)


bind_layers(HCI_Command_Hdr,HCI_Cmd_Inquiry,				opcode=0x0401)
bind_layers(HCI_Command_Hdr,HCI_Cmd_Write_Extended_Inquiry_Response,	opcode=0x0c52)
bind_layers(HCI_Command_Hdr,HCI_Cmd_Write_Local_Name,			opcode=0x0c13)
bind_layers(HCI_Command_Hdr,HCI_Cmd_Read_Local_Name,			opcode=0x0c14)
bind_layers(HCI_Command_Hdr,HCI_Cmd_Create_Connection,			opcode=0x0405)
bind_layers(HCI_Command_Hdr,HCI_Cmd_Remote_Name_Request,		opcode=0x0419)
bind_layers(HCI_Command_Hdr,HCI_Cmd_Write_Inquiry_Mode,			opcode=0x0c45)
bind_layers(HCI_Command_Hdr,HCI_Cmd_Write_Scan_Enable, 			opcode=0x0c1a)
bind_layers(HCI_Command_Hdr,HCI_Cmd_Accept_Connection_Request,		opcode=0x0409)
bind_layers(HCI_Command_Hdr,HCI_Cmd_Reject_Connection_Request,		opcode=0x040A)
bind_layers(HCI_Event_Hdr,  HCI_Evt_Extended_Inquiry_Result,		code=0x2f)
bind_layers(HCI_Event_Hdr,  HCI_Evt_Inquiry_Result,			code=0x02)
bind_layers(HCI_Event_Hdr,  HCI_Evt_Connection_Request,			code=0x04)
bind_layers(HCI_Event_Hdr,  HCI_Evt_Inquiry_Result_With_RSSI, 		code=0x22)
bind_layers(HCI_Event_Hdr,  HCI_Evt_Inquiry_Complete,			code=0x01)
bind_layers(HCI_Event_Hdr,  HCI_Evt_Connection_Complete,		code=0x03)
bind_layers(HCI_Event_Hdr,  HCI_Evt_Page_Scan_Repetition_Mode_Change,		code=0x20)
bind_layers(HCI_Event_Hdr,  HCI_Evt_Max_Slot_Change,		code=0x1b)
bind_layers(HCI_Event_Hdr,  HCI_Evt_Remote_Name_Request_Complete, code=0x07)
bind_layers(HCI_Event_Command_Complete, HCI_Cmd_Complete_Read_Local_Name, opcode=0x0c14)

bind_layers(L2CAP_Hdr,SDP_Hdr)
bind_layers(SDP_Hdr,SDP_Error_Response,			pdu_id=0x01)
bind_layers(SDP_Hdr,SDP_Service_Search_Request, 	pdu_id=0x02)
bind_layers(SDP_Hdr,SDP_Service_Search_Response, 	pdu_id=0x03)
bind_layers(SDP_Hdr,SDP_Service_Attribute_Request, 	pdu_id=0x04)
bind_layers(SDP_Hdr,SDP_Service_Attribute_Response, 	pdu_id=0x05)
