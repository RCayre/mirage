from scapy.all import *
from mirage.core.module import WirelessModule
from mirage.libs.esb_utils.scapy_esb_layers import *
from mirage.libs.esb_utils.packets import *
from mirage.libs.esb_utils.constants import *
from mirage.libs.esb_utils.dissectors import *
from mirage.libs.esb_utils.rfstorm import *
from mirage.libs.esb_utils.pcap import *
from mirage.libs.esb_utils.helpers import *
from mirage.libs import wireless,io



class ESBEmitter(wireless.Emitter):
	'''
	This class is an Emitter for the Enhanced ShockBurst protocol ("esb").

	It can instantiates the following devices :

	  * RFStorm Device (``mirage.libs.esb_utils.rfstorm.ESBRFStormDevice``) **[ interface "rfstormX" (e.g. "rfstormX") ]**
	  * PCAP Device (``mirage.libs.esb_utils.pcap.ESBPCAPDevice``) **[ interface "<file>.pcap" (e.g. "capture.pcap") ]**

	'''
	def __init__(self,interface="rfstorm0"):
		deviceClass = None
		if "rfstorm" in interface:
			deviceClass = ESBRFStormDevice
		elif interface[-5:] == ".pcap":
			deviceClass = ESBPCAPDevice
		super().__init__(interface=interface,packetType=ESBPacket,deviceType=deviceClass)


	def convert(self,packet):
		new = ESB_Hdr(address=packet.address)
		if packet.protocol == "generic":
			if isinstance(packet,ESBPingRequestPacket):
				new /= ESB_Payload_Hdr()/ESB_Ping_Request(ping_payload=packet.payload)
			elif isinstance(packet,ESBAckResponsePacket):
				new /= ESB_Payload_Hdr()/ESB_Ack_Response(ack_payload=packet.payload)
				new.no_ack=1
		elif packet.protocol == "logitech":
			new /= ESB_Payload_Hdr()/Logitech_Unifying_Hdr()
			if isinstance(packet,ESBLogitechSetTimeoutPacket):
				new /= Logitech_Set_Keepalive_Payload(timeout=packet.timeout)
			elif isinstance(packet,ESBLogitechUnencryptedKeyReleasePacket):
				new /= Logitech_Unencrypted_Keystroke_Payload(hid_data=packet.hidData)
			elif isinstance(packet,ESBLogitechUnencryptedKeyPressPacket):
				new /= Logitech_Unencrypted_Keystroke_Payload(hid_data=packet.hidData)
			elif isinstance(packet,ESBLogitechKeepAlivePacket):
				new /= Logitech_Keepalive_Payload(timeout=packet.timeout)
			elif isinstance(packet,ESBLogitechMousePacket):
				new /= Logitech_Mouse_Payload(movement=packet.move,button_mask=packet.buttonMask)
			elif isinstance(packet,ESBLogitechEncryptedKeystrokePacket):
				new /= Logitech_Encrypted_Keystroke_Payload(unknown=packet.unknown,hid_data=packet.hidData, aes_counter=packet.aesCounter)
		else:
			new /= ESB_Payload_Hdr(packet.payload)
		
		return new

class ESBReceiver(wireless.Receiver):
	'''
	This class is a Receiver for the Enhanced ShockBurst protocol ("esb").

	It can instantiates the following devices :

	  * RFStorm Device (``mirage.libs.esb_utils.rfstorm.ESBRFStormDevice``) **[ interface "rfstormX" (e.g. "rfstormX") ]**
	  * PCAP Device (``mirage.libs.esb_utils.pcap.ESBPCAPDevice``) **[ interface "<file>.pcap" (e.g. "capture.pcap") ]**

	'''
	def __init__(self,interface="rfstorm0"):
		deviceClass = None
		if "rfstorm" in interface:
			deviceClass = ESBRFStormDevice
		elif interface[-5:] == ".pcap":
			deviceClass = ESBPCAPDevice
		super().__init__(interface=interface,packetType=ESBPacket,deviceType=deviceClass)

	def convert(self,packet):
		channel = self.getChannel()
		payload = raw(packet[ESB_Payload_Hdr:]) if ESB_Payload_Hdr in packet else b""
		
		new = ESBPacket(address=packet.address, payload=payload)
		if ESB_Ack_Response in packet or payload == b"":
			new = ESBAckResponsePacket(address=packet.address,payload=payload)
		elif Logitech_Unifying_Hdr in packet:

			if Logitech_Mouse_Payload in packet:
				new = ESBLogitechMousePacket(
								address=packet.address,
								payload=payload,
								buttonMask = packet.button_mask,
								move=packet.movement
							)
			elif Logitech_Set_Keepalive_Payload in packet:
				new = ESBLogitechSetTimeoutPacket(
								address=packet.address,
								payload=payload,
								timeout=packet.timeout
							)
			elif Logitech_Keepalive_Payload in packet:
				new = ESBLogitechKeepAlivePacket(
								address=packet.address,
								payload=payload,
								timeout=packet.timeout
							)
			elif Logitech_Unencrypted_Keystroke_Payload in packet:
				if packet.hid_data == b"\x00\x00\x00\x00\x00\x00\x00":
					new = ESBLogitechUnencryptedKeyReleasePacket(
								address=packet.address,
								payload=payload
							)
				else:
					new = ESBLogitechUnencryptedKeyPressPacket(
								address=packet.address,
								payload=payload,
								hidData = packet.hid_data
							)
			elif Logitech_Multimedia_Key_Payload in packet:
				if packet.hid_key_scan_code == b"\x00\x00\x00\x00":
					new = ESBLogitechMultimediaKeyReleasePacket(
								address=packet.address,
								payload=payload
							)
				else:
					new = ESBLogitechMultimediaKeyPressPacket(
								address=packet.address,
								payload=payload,
								hidData = packet.hid_key_scan_code
							)
			elif Logitech_Encrypted_Keystroke_Payload in packet:
				new = ESBLogitechEncryptedKeystrokePacket(
							address=packet.address,
							payload=payload,
							unknown=packet.unknown,
							hidData = packet.hid_data,
							aesCounter = packet.aes_counter
						)
		new.additionalInformations = ESBSniffingParameters(channel=channel)
		
		return new


WirelessModule.registerEmitter("esb",ESBEmitter)
WirelessModule.registerReceiver("esb",ESBReceiver)
