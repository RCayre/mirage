from scapy.all import *

class SniffleCommand(Packet):
	name = "Sniffle Command Packet"
	fields_desc = [	XByteEnumField("command_type",None, {
								0x10 : "set_configuration",
								0x11 : "pause_when_done",
								0x12 : "rssi_filter",
								0x13 : "mac_filter",
								0x14 : "enable_adv_hop",
								0x15 : "end_trim",
								0x16 : "aux_adv"
								})]


class SniffleSetConfigurationCommand(Packet):
	name = 'Sniffle Set Configuration Command'
	fields_desc = [	ByteField("channel",37),
			XLEIntField("access_address",0x8E89BED6),
			ByteEnumField("phy_mode",0,{0:"1M", 1:"2M", 2:"coded"}),
			XLEIntField("crc_init",0x555555)]

class SnifflePauseWhenDoneCommand(Packet):
	name = 'Sniffle Pause When Done Command'
	fields_desc = [	ByteEnumField("pause_when_done",0,{0 : "False", 1 : "True"}) ]

class SniffleRSSIFilterCommand(Packet):
	name = 'Sniffle RSSI Filter Command'
	fields_desc = [	ByteField("rssi_min_value",None) ] # Don't forget the pre treatment before using this layer:  val & 0xff => rssi_min_value


class SniffleDisableMACFilterCommand(Packet):
	name = 'Sniffle Disable MAC Filter Command'
	fields_desc = []

class SniffleEnableMACFilterCommand(Packet):
	name = 'Sniffle Enable MAC Filter Command'
	fields_desc = [BDAddrField("address",None)]

class SniffleEnableAdvertisementsHoppingCommand(Packet):
	name = 'Sniffle Enable Advertisements Hopping Command'
	fields_desc = []

class SniffleFollowCommand(Packet):
	name = 'Sniffle Follow Command'
	fields_desc = [LEIntEnumField("follow",0x01,{0x01: "all", 0x00 : "advertisements_only"})]

class SniffleAuxiliaryAdvertisementsCommand(Packet):
	name = 'Sniffle Auxiliary Advertisements Command'
	fields_desc = [	ByteEnumField("enable",0,{0 : "False", 1 : "True"}) ]

class SniffleResetCommand(Packet):
	name = 'Sniffle Reset Command'
	fields_desc = []

class SniffleMarkerCommand(Packet):
	name = 'Sniffle Marker Command'
	fields_desc = []

class SniffleTransmitCommand(Packet):
	name = 'Sniffle Transmit Command'
	fields_desc = [PacketField("ble_payload", None, BTLE_DATA)]

class SniffleConnectCommand(Packet):
	name = 'Sniffle Connect Command'
	fields_desc = [
		ByteEnumField("address_type",0x00,{0x00: "public", 0x01: "random"}),
        BDAddrField("address", None),
        XIntField("AA", 0x00),
        X3BytesField("crc_init", 0x0),
        XByteField("win_size", 0x0),
        XLEShortField("win_offset", 0x0),
        XLEShortField("interval", 0x0),
        XLEShortField("latency", 0x0),
        XLEShortField("timeout", 0x0),
        BTLEChanMapField("chM", 0),
        BitField("SCA", 0, 3),
        BitField("hop", 0, 5),
	]

class SniffleSetAddressCommand(Packet):
	name = 'Sniffle Set Address Command'
	fields_desc = [
		ByteEnumField("address_type",0x00,{0x00: "public", 0x01: "random"}),
        BDAddrField("address", None),
	]

class SniffleAdvertiseCommand(Packet):
	name = 'Sniffle Advertise Command'
	fields_desc = [
		StrField("adv_data",None),
		StrField("scan_resp_data",None)
	]


class SniffleAdvertiseIntervalCommand(Packet):
	name = 'Sniffle Advertise Interval Command'
	fields_desc = [
		LEShortField("interval",None)
	]

class SniffleResponse(Packet):
	name = 'Sniffle Response'
	fields_desc = [ByteEnumField("response_type",None, {0x10 : "packet", 0x11 : "debug"})]

class SnifflePacketResponse(Packet):
	name = 'Sniffle Packet Response'
	fields_desc = [
		LEIntField("delta", None),
		LEShortField("length",None),
		SignedByteField("rssi",None),
		ByteField("channel",None),
		MultipleTypeField([(PacketField("ble_payload",None,BTLE_DATA),lambda pkt:pkt.channel not in (37,38,39))],
		PacketField("ble_payload",None,BTLE_ADV),
		)
	]

class SniffleDebugResponse(Packet):
	name = 'Sniffle Debug Response'
	fields_desc = [StrField("message", None)]

class SniffleMarkerResponse(Packet):
	name = 'Sniffle Marker Response'
	fields_desc = [StrField("message", None)]

class SniffleStateResponse(Packet):
	name = 'Sniffle State Response'
	fields_desc = [
		ByteEnumField("state",None, {	0x00 : "STATIC",
									  	0x01 : "ADVERT_SEEK",
										0x02 : "ADVERT_HOP",
										0x03 : "DATA",
										0x04 : "PAUSED",
										0x05 : "INITIATING",
										0x06 : "MASTER",
										0x07 : "SLAVE",
										0x08 : "ADVERTISING",
										0x09 : "SCANNING"})
	]
bind_layers(SniffleCommand, SniffleSetConfigurationCommand, 			command_type=0x10)
bind_layers(SniffleCommand, SnifflePauseWhenDoneCommand,				command_type=0x11)
bind_layers(SniffleCommand, SniffleRSSIFilterCommand, 					command_type=0x12)
bind_layers(SniffleCommand, SniffleDisableMACFilterCommand,				command_type=0x13)
bind_layers(SniffleCommand, SniffleEnableMACFilterCommand,		 		command_type=0x13)
bind_layers(SniffleCommand, SniffleEnableAdvertisementsHoppingCommand, 	command_type=0x14)
bind_layers(SniffleCommand, SniffleFollowCommand,						command_type=0x15)
bind_layers(SniffleCommand, SniffleAuxiliaryAdvertisementsCommand,		command_type=0x16)
bind_layers(SniffleCommand, SniffleResetCommand,						command_type=0x17)
bind_layers(SniffleCommand, SniffleMarkerCommand,						command_type=0x18)
bind_layers(SniffleCommand, SniffleTransmitCommand,						command_type=0x19)
bind_layers(SniffleCommand, SniffleConnectCommand,						command_type=0x1A)
bind_layers(SniffleCommand, SniffleSetAddressCommand,					command_type=0x1B)
bind_layers(SniffleCommand, SniffleAdvertiseCommand,					command_type=0x1C)
bind_layers(SniffleCommand, SniffleAdvertiseIntervalCommand,			command_type=0x1D)

bind_layers(SniffleResponse, SnifflePacketResponse, 					response_type = 0x10)
bind_layers(SniffleResponse, SniffleDebugResponse,			 			response_type = 0x11)
bind_layers(SniffleResponse, SniffleMarkerResponse,			 			response_type = 0x12)
bind_layers(SniffleResponse, SniffleStateResponse,			 			response_type = 0x13)
