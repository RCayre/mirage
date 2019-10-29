'''
This module contains some constants that are used by the Zigbee stack.
'''

# USB device reset
USBDEVFS_RESET = ord('U') << (4 * 2) | 20

RZUSBSTICK_ID_VENDOR 	= 0x03eb
RZUSBSTICK_ID_PRODUCT 	= 0x210a

# USB Endpoints
RZ_COMMAND_ENDPOINT 	= 0x02
RZ_RESPONSE_ENDPOINT	= 0x84
RZ_PACKET_ENDPOINT 	= 0x81

# USB Commands
RZ_SET_MODE		= 0x07
RZ_SET_CHANNEL		= 0x08
RZ_OPEN_STREAM		= 0x09
RZ_CLOSE_STREAM		= 0x0A
RZ_INJECT_FRAME         = 0x0D
RZ_JAMMER_ON            = 0x0E
RZ_JAMMER_OFF           = 0x0F

# USB Responses
RZ_RESP_SUCCESS		= 0x80

# RZ Modes
RZ_MODE_AIRCAPTURE	= 0x00
RZ_MODE_NONE		= 0x04

# RZ Packet
RZ_AIRCAPTURE_DATA 	= 0x50
