from scapy.all import *

'''
This module contains some scapy definitions for communicating with a ButteRFly device.
'''

class Butterfly_Message_Hdr(Packet):
	name = "Butterfly Message Packet"
	fields_desc = [
		XShortField("preamble",0x5a17),
		ByteEnumField("type",None,{
			0x00:"command",
			0x01:"response",
			0x02:"packet",
			0x03:"notification"
		})
	]

class Butterfly_Command_Hdr(Packet):
	name = "Butterfly Command Packet"
	fields_desc = [
			ShortField("command_type",None)
	]

class Butterfly_Response_Hdr(Packet):
	name = "Butterfly Response Packet"
	fields_desc = [ShortField("response_type",None)]

class Butterfly_Packet_Hdr(Packet):
	name = "Butterfly Packet Packet"
	fields_desc = [
		ByteEnumField("packet_type",None,{0x00:"BLE"})
	]

class Butterfly_Notification_Hdr(Packet):
	name = "Butterfly Notification Packet"
	fields_desc = [
			ByteEnumField("notification_type",None,{0x00:"debug", 0x01:"injection_report"})
	]


class Butterfly_Get_Version_Command(Packet):
	name = "Butterfly Command Get Version"

class Butterfly_Select_Controller_Command(Packet):
	name = "Butterfly Command Select Controller"
	fields_desc = [
			ByteEnumField("controller",None, {0x00:"BLE"})
	]

class Butterfly_Enable_Controller_Command(Packet):
	name = "Butterfly Command Enable Controller"

class Butterfly_Disable_Controller_Command(Packet):
	name = "Butterfly Command Disable Controller"

class Butterfly_Get_Channel_Command(Packet):
	name = "Butterfly Get Channel Command"

class Butterfly_Set_Channel_Command(Packet):
	name = "Butterfly Set Channel Command"
	fields_desc = [ByteField("channel",None)]

class Butterfly_Set_Filter_Command(Packet):
	name = "Butterfly Set Filter Command"
	fields_desc = [
		BDAddrField("address",None)
	]

class Butterfly_Set_Follow_Mode_Command(Packet):
	name = "Butterfly Set Follow Mode Command"
	fields_desc = [
		ByteEnumField("enable",None,{0x00:"no", 0x01:"yes"})
	]

class Butterfly_Start_Attack_Command(Packet):
	name = "Butterfly Start Attack Command"
	fields_desc = [
		ByteEnumField("attack",None,{0x02:"slave_hijacking",0x03:"master_hijacking",0x04:"MITM"})
	]

class Butterfly_Send_Payload_Command(Packet):
	name = "Butterfly Send Payload Command"
	fields_desc = [
		ByteEnumField("payload_direction",None,{0x00:"general",0x01:"master",0x02:"slave"}),
		FieldLenField("payload_size", None,fmt='B', length_of="payload_content"),
		StrLenField("payload_content", "", length_from=lambda pkt:pkt.payload_size)
	]


class Butterfly_Get_Version_Response(Packet):
	name = "Butterfly Response Get Version"
	fields_desc = [
		ByteField("major",None),
		ByteField("minor",None)
	]

class Butterfly_Select_Controller_Response(Packet):
	name = "Butterfly Select Controller Response"
	fields_desc = [
		ByteEnumField("status",None, {0x00:"success", 0x01:"failure"})
	]

class Butterfly_Enable_Controller_Response(Packet):
	name = "Butterfly Enable Controller Response"
	fields_desc = [
		ByteEnumField("status",None, {0x00:"success", 0x01:"failure"})
	]

class Butterfly_Disable_Controller_Response(Packet):
	name = "Butterfly Disable Controller Response"
	fields_desc = [
		ByteEnumField("status",None, {0x00:"success", 0x01:"failure"})
	]

class Butterfly_Get_Channel_Response(Packet):
	name = "Butterfly Get Channel Response"
	fields_desc = [
		ByteField("channel",None)
	]

class Butterfly_Set_Channel_Response(Packet):
	name = "Butterfly Set Channel Response"
	fields_desc = [
			ByteEnumField("status",None, {0x00:"success", 0x01:"failure"})
	]

class Butterfly_Set_Filter_Response(Packet):
	name = "Butterfly Set Filter Response"
	fields_desc = [
			ByteEnumField("status",None, {0x00:"success", 0x01:"failure"})
	]

class Butterfly_Set_Follow_Mode_Response(Packet):
	name = "Butterfly Set Follow Mode Response"
	fields_desc = [
			ByteEnumField("status",None, {0x00:"success", 0x01:"failure"})
	]

class Butterfly_Start_Attack_Response(Packet):
	name = "Butterfly Start Attack Response"
	fields_desc = [
			ByteEnumField("status",None, {0x00:"success", 0x01:"failure"})
	]

class Butterfly_Send_Payload_Response(Packet):
	name = "Butterfly Send Payload Response"
	fields_desc = [
			ByteEnumField("last_direction",None,{0x00:"general",0x01:"master",0x02:"slave"}),
			ByteEnumField("status",None, {0x00:"success", 0x01:"failure"})
	]


class Butterfly_BLE_Packet(Packet):
	name = "Butterfly BLE Packet"
	fields_desc = [
		LEIntField("timestamp",None),
		ByteEnumField("source",None, {0x00:"general",0x01:"master",0x02:"slave"}),
		ByteField("channel",None),
		ByteField("rssi",None),
		ByteEnumField("crc_value",None,{0x00:"valid_crc", 0x01:"invalid_crc"}),
		LESignedIntField("timestamp_relative",None),
		PacketField("packet",None,BTLE)
	]
class Butterfly_Debug_Notification(Packet):
	name = "Butterfly Debug Notification"
	fields_desc = [
		StrField("message",None)
	]

class Butterfly_Injection_Report_Notification(Packet):
	name = "Butterfly Injection Report Notification"
	fields_desc = [
		ByteEnumField("status",None, {0x00 : "success", 0x01 : "failure"}),
		IntField("injection_count", None)
	]

class Butterfly_Advertising_Interval_Report_Notification(Packet):
	name = "Butterfly Advertising Interval Report Notification"
	fields_desc = [
		IntField("interval", None)
	]

class Butterfly_Connection_Report_Notification(Packet):
	name = "Butterfly Connection Report Notification"
	fields_desc = [
		ByteEnumField("status",None,{
			0x00:"CONNECTION_STARTED",
			0x01:"CONNECTION_LOST",
			0x02:"ATTACK_STARTED",
			0x03:"ATTACK_SUCCESS",
			0x04:"ATTACK_FAILURE"
		})
	]
bind_layers(Butterfly_Message_Hdr,Butterfly_Command_Hdr,type=0x00)
bind_layers(Butterfly_Message_Hdr,Butterfly_Response_Hdr,type=0x01)
bind_layers(Butterfly_Message_Hdr,Butterfly_Packet_Hdr,type=0x02)
bind_layers(Butterfly_Message_Hdr,Butterfly_Notification_Hdr,type=0x03)

bind_layers(Butterfly_Command_Hdr,Butterfly_Get_Version_Command,command_type=0x0000)
bind_layers(Butterfly_Command_Hdr,Butterfly_Select_Controller_Command,command_type=0x0001)
bind_layers(Butterfly_Command_Hdr,Butterfly_Enable_Controller_Command,command_type=0x0002)
bind_layers(Butterfly_Command_Hdr,Butterfly_Disable_Controller_Command,command_type=0x0003)
bind_layers(Butterfly_Command_Hdr,Butterfly_Get_Channel_Command,command_type=0x0004)
bind_layers(Butterfly_Command_Hdr,Butterfly_Set_Channel_Command,command_type=0x0005)
bind_layers(Butterfly_Command_Hdr,Butterfly_Set_Filter_Command,command_type=0x0006)
bind_layers(Butterfly_Command_Hdr,Butterfly_Set_Follow_Mode_Command,command_type=0x0007)
bind_layers(Butterfly_Command_Hdr,Butterfly_Start_Attack_Command,command_type=0x0008)
bind_layers(Butterfly_Command_Hdr,Butterfly_Send_Payload_Command,command_type=0x0009)


bind_layers(Butterfly_Response_Hdr,Butterfly_Get_Version_Response,response_type=0x0000)
bind_layers(Butterfly_Response_Hdr,Butterfly_Select_Controller_Response,response_type=0x0001)
bind_layers(Butterfly_Response_Hdr,Butterfly_Enable_Controller_Response,response_type=0x0002)
bind_layers(Butterfly_Response_Hdr,Butterfly_Disable_Controller_Response,response_type=0x0003)
bind_layers(Butterfly_Response_Hdr,Butterfly_Get_Channel_Response,response_type=0x0004)
bind_layers(Butterfly_Response_Hdr,Butterfly_Set_Channel_Response,response_type=0x0005)
bind_layers(Butterfly_Response_Hdr,Butterfly_Set_Filter_Response,response_type=0x0006)
bind_layers(Butterfly_Response_Hdr,Butterfly_Set_Follow_Mode_Response,response_type=0x0007)
bind_layers(Butterfly_Response_Hdr,Butterfly_Start_Attack_Response,response_type=0x0008)
bind_layers(Butterfly_Response_Hdr,Butterfly_Send_Payload_Response,response_type=0x0009)

bind_layers(Butterfly_Packet_Hdr, Butterfly_BLE_Packet, packet_type=0x00)

bind_layers(Butterfly_Notification_Hdr, Butterfly_Debug_Notification, notification_type=0x00)
bind_layers(Butterfly_Notification_Hdr, Butterfly_Injection_Report_Notification, notification_type=0x01)
bind_layers(Butterfly_Notification_Hdr, Butterfly_Advertising_Interval_Report_Notification, notification_type=0x02)
bind_layers(Butterfly_Notification_Hdr, Butterfly_Connection_Report_Notification, notification_type=0x03)
