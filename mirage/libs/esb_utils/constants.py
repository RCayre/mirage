'''
This module contains some constants that are used by the Enhanced ShockBurst stack.
'''

# USB device Identifiers
NRF24_ID_VENDOR = 0x1915
NRF24_ID_PRODUCT = 0x0102

# USB device reset
USBDEVFS_RESET = ord('U') << (4 * 2) | 20

# USB Endpoints
NRF24_COMMAND_ENDPOINT = 0x01
NRF24_RESPONSE_ENDPOINT = 0x81 

# USB Commands
NRF24_TRANSMIT_PAYLOAD               = 0x04
NRF24_ENTER_SNIFFER_MODE             = 0x05
NRF24_ENTER_PROMISCUOUS_MODE         = 0x06
NRF24_ENTER_TONE_TEST_MODE           = 0x07
NRF24_TRANSMIT_ACK_PAYLOAD           = 0x08
NRF24_SET_CHANNEL                    = 0x09
NRF24_GET_CHANNEL                    = 0x0A
NRF24_ENABLE_LNA_PA                  = 0x0B
NRF24_TRANSMIT_PAYLOAD_GENERIC       = 0x0C
NRF24_ENTER_PROMISCUOUS_MODE_GENERIC = 0x0D
NRF24_RECEIVE_PAYLOAD                = 0x12

# nRF24LU1+ registers
NRF24_RF_CH = 0x05

# RF data rates
RF_RATE_250K = 0
RF_RATE_1M   = 1
RF_RATE_2M   = 2

# Enumeration for operation mode
class ESBOperationMode:
	PROMISCUOUS		= 0x0
	SNIFFER	 		= 0x1
	GENERIC_PROMISCUOUS	= 0X2
