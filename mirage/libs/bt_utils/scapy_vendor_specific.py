from scapy.all import Packet
from scapy.layers.bluetooth import *
'''
This module contains some scapy definitions defining some vendor specific HCI packets in order to change the BD Address.
'''
COMPATIBLE_VENDORS = [0,10,13,15,18,48,57]

 # Packets
 # Read Local Version Information, Command & Event

class HCI_Cmd_Read_Local_Version_Information(Packet):
	name = "Read Local Version Information"

class HCI_Cmd_Complete_Read_Local_Version_Information(Packet):
	name = "HCI Cmd Complete Read Local Version Information"
	fields_desc =  [ByteEnumField("hci_version_number",0, {	0x0 : "1.0b",
								0x1 : "1.1",
								0x2 : "1.2",
								0x3:"2.0",
								0x4:"2.1",
								0x5:"3.0",
								0x6: "4.0",
								0x7:"4.1",
								0x8:"4.2",
								0x9:"5.0"}),
			LEShortField("hci_revision", 0),
			ByteEnumField("lmp_version_number",0, {	0x0 : "1.0b",
								0x1 : "1.1",
								0x2 : "1.2",
								0x3:"2.0",
								0x4:"2.1",
								0x5:"3.0",
								0x6: "4.0",
								0x7:"4.1",
								0x8:"4.2",
								0x9:"5.0"}),
			LEShortField("manufacturer", 0),
			LEShortField("lmp_subversion", 0)]


# Vendors specific Commands to Write BD Address
# Manufacturer : 13
class HCI_Cmd_TI_Write_BD_Address(Packet):
	name = "TI Write BD Address"
	fields_desc = [LEMACField("addr","\x00\x01\x02\x03\x04\x05")]

# Manufacturer : 15
class HCI_Cmd_BCM_Write_BD_Address(Packet):
	name = "BCM Write BD Address"
	fields_desc = [LEMACField("addr","\x00\x01\x02\x03\x04\x05")]

# Manufacturer : 18
class HCI_Cmd_Zeevo_Write_BD_Address(Packet):
	name = "Zeevo Write BD Address"
	fields_desc = [LEMACField("addr","\x00\x01\x02\x03\x04\x05")]

# Manufacturer : 0 or 57
class HCI_Cmd_Ericsson_Write_BD_Address(Packet):
	name = "Ericsson Write BD Address"
	fields_desc = [LEMACField("addr","\x00\x01\x02\x03\x04\x05")]


# Manufacturer : 10 ... WTF ?
class HCI_Cmd_CSR_Write_BD_Address(Packet):
	name = "CSR Write BD Address"
	fields_desc = [LEMACField("addr","\x00\x01\x02\x03\x04\x05")]
	def post_build(self,p,pay):
		payload = bytearray(b"\xc2\x02\x00\x0c\x00\x11G\x03p\x00\x00\x01\x00\x04\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00")

		payload[17] = p[2]
		payload[19] = p[0]
		payload[20] = p[1]
		payload[21] = p[3]
		payload[23] = p[4]
		payload[24] = p[5]

		return payload

class HCI_Cmd_CSR_Reset(Packet):
	name = "CSR Write BD Address"
	fields_desc = [StrField("bytes",b"\xc2\x02\x00\t\x00\x00\x00\x01@\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00")]



# Manufacturer : 48
class HCI_Cmd_ST_Write_BD_Address(Packet):
	name = "ST Write BD Address"
	fields_desc = [	ByteField("user_id", 0xfe),
			ByteField("data_len",0x06),
			LEMACField("addr","\x00\x01\x02\x03\x04\x05"),
			StrField("padding","\x00"*247)]


# Bind it to layers
bind_layers(HCI_Command_Hdr, HCI_Cmd_Read_Local_Version_Information, 				opcode=0x1001)
bind_layers(HCI_Event_Command_Complete, HCI_Cmd_Complete_Read_Local_Version_Information, 	opcode=0x1001)

bind_layers(HCI_Command_Hdr, HCI_Cmd_ST_Write_BD_Address,					opcode=0xfc22)
bind_layers(HCI_Command_Hdr, HCI_Cmd_Zeevo_Write_BD_Address, 					opcode=0xfc01)
bind_layers(HCI_Command_Hdr, HCI_Cmd_TI_Write_BD_Address, 					opcode=0xfc06)
bind_layers(HCI_Command_Hdr, HCI_Cmd_Ericsson_Write_BD_Address, 				opcode=0xfc0d)
bind_layers(HCI_Command_Hdr, HCI_Cmd_BCM_Write_BD_Address, 					opcode=0xfc01)
bind_layers(HCI_Command_Hdr, HCI_Cmd_CSR_Write_BD_Address, 					opcode=0xfc00)
bind_layers(HCI_Command_Hdr, HCI_Cmd_CSR_Reset, 						opcode=0xfc00)


