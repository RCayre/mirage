from mirage.libs import wireless
from mirage.libs.esb_utils.helpers import frequencyToChannel,bytes2bits
from mirage.libs.esb_utils.dissectors import *
from struct import pack,unpack


class ESBSniffingParameters(wireless.AdditionalInformations):
	'''
	This class allows to attach some sniffer's data to a Enhanced ShockBurst Packet, such as channel.
	If the frequency is provided, the corresponding channel is automatically calculated. 

	:param channel: channel of the received packet
	:type channel: int
	:param frequency: frequency of the received packet
	:type frequency: float
	'''
	def __init__(self, channel=None, frequency=None):
		if frequency is not None:
			self.channel = int(frequencyToChannel(frequency))
		elif channel is not None:
			self.channel = int(channel)
		else:
			self.channel = -1

	def toString(self):
		return "CH:" + (str(self.channel) if self.channel != -1 else "???")


class ESBPacket(wireless.Packet):
	'''
	Mirage Enhanced ShockBurst Packet

	:param protocol: string indicating the applicative protocol in use
	:type protocol: str
	:param address: address of the emitter of the frame (e.g. '11:22:33:44:55')
	:type address: str
	:param payload: payload of the frame
	:type payload: bytes

	'''
	def __init__(self,protocol = None, address = "00:00:00:00:00", payload = None):
		super().__init__()
		self.name = "ESB - Unknown Packet"
		self.address = address.upper()
		self.payload = payload
		self.protocol = "unknown" if protocol is None else protocol

	def toString(self):
		return "<< "+self.name +" ("+self.protocol+")"+" | address="+str(self.address)+(" | payload="+self.payload.hex() if self.payload is not None else "")+" >>"


class ESBAckResponsePacket(ESBPacket):
	'''
	Mirage Enhanced ShockBurst Packet - ACK Response


	:param address: address of the emitter of the frame (e.g. '11:22:33:44:55')
	:type address: str
	:param payload: bytes indicating the ACK payload's value (e.g. b"\x12\x34")
	:type payload: bytes

	'''
	def __init__(self, address = "00:00:00:00:00", payload = b""):
		super().__init__(protocol="generic",address=address,payload=payload)
		self.name = "ESB - ACK Response Packet"

class ESBPingRequestPacket(ESBPacket):
	'''
	Mirage Enhanced ShockBurst Packet - Ping Request


	:param address: address of the emitter of the frame (e.g. '11:22:33:44:55')
	:type address: str
	:param payload: bytes indicating the payload's value (e.g. b"\x0F\x0F\x0F\x0F")
	:type payload: bytes

	'''
	def __init__(self, address = "00:00:00:00:00", payload = b"\x0F\x0F\x0F\x0F"):
		super().__init__(protocol="generic",address=address,payload=payload)
		self.name = "ESB - Ping Request Packet"



class ESBLogitechMousePacket(ESBPacket):
	'''
	Mirage Enhanced ShockBurst Packet - Logitech Mouse Packet


	:param address: address of the emitter of the frame (e.g. '11:22:33:44:55')
	:type address: str
	:param payload: bytes indicating the payload's value (e.g. b"\x0F\x0F\x0F\x0F")
	:type payload: bytes
	:param button: string indicating the selected button (e.g. 'left','right','center' or '' if no button is pressed)
	:type button: str
	:param buttonMask: integer indicating the selected button (0: '', 1: 'left', 2: 'right', 4: 'center')
	:param move: 3 bytes indicating the movement of the mouse
	:type move: bytes
	:param x: indicates the X position of the mouse
	:type x: int
	:param y: indicates the Y position of the mouse
	:type y: int

	'''
	def __init__(self,address = "00:00:00:00:00",payload=None,button = "", buttonMask = 0x00, move = None,x = 0, y = 0):

		super().__init__(protocol="logitech",address=address,payload=payload)
		self.name = "ESB - Logitech Mouse Packet"
		self.button,self.buttonMask = "",0x00
		if button == "":
			if buttonMask == 0x00:
				self.button = ""
			elif buttonMask == 0x01:
				self.button = "left"
			elif buttonMask == 0x02:
				self.button = "right"
			elif buttonMask == 0x04:
				self.button = "center"
			self.buttonMask = buttonMask
		else:
			if button == "left":
				self.buttonMask = 0x01
			elif button == "right":
				self.buttonMask = 0x02
			elif button == "center":
				self.buttonMask = 0x04
			else:
				self.buttonMask = 0x00
			self.button = button

		if move is not None:
			position = LogitechMousePosition(data=move)
			self.x,self.y = position.x,position.y
			self.move = move
		else:
			self.move = LogitechMousePosition(x=x,y=y).data
			self.x = x
			self.y = y

	def toString(self):
		return "<< "+self.name +" ("+self.protocol+")" +" | address="+str(self.address)+(" | button="+self.button if self.button != "" else "")+" | x="+str(self.x)+" | y="+str(self.y)+" >>"


class ESBLogitechSetTimeoutPacket(ESBPacket):
	'''
	Mirage Enhanced ShockBurst Packet - Logitech Hello / Set Timeout Packet


	:param address: address of the emitter of the frame (e.g. '11:22:33:44:55')
	:type address: str
	:param payload: bytes indicating the payload's value (e.g. b"\x0F\x0F\x0F\x0F")
	:type payload: bytes
	:param timeout: value of provided timeout
	:type timeout: int
	'''
	def __init__(self,payload=None,address="00:00:00:00:00",timeout = 1200):
		super().__init__(protocol="logitech",address=address,payload=payload)
		self.name = "ESB - Logitech Hello / Set Timeout Packet"
		self.timeout = timeout

	def toString(self):
		return "<< "+self.name +" ("+self.protocol+")" +" | address="+str(self.address)+" | timeout="+str(self.timeout)+" >>"



class ESBLogitechKeepAlivePacket(ESBPacket):
	'''
	Mirage Enhanced ShockBurst Packet - Logitech Keep Alive Packet


	:param address: address of the emitter of the frame (e.g. '11:22:33:44:55')
	:type address: str
	:param payload: bytes indicating the payload's value (e.g. b"\x0F\x0F\x0F\x0F")
	:type payload: bytes
	:param timeout: value of provided timeout
	:type timeout: int
	'''
	def __init__(self,payload=None,address="00:00:00:00:00",timeout = 1200):
		super().__init__(protocol="logitech",address=address,payload=payload)
		self.name = "ESB - Logitech Keepalive Packet"
		self.timeout = timeout

	def toString(self):
		return "<< "+self.name +" ("+self.protocol+")"  +" | address="+str(self.address)+" | timeout="+str(self.timeout)+" >>"

class ESBLogitechUnencryptedKeyPressPacket(ESBPacket):
	'''
	Mirage Enhanced ShockBurst Packet - Logitech Unencrypted Key Press Packet


	:param address: address of the emitter of the frame (e.g. '11:22:33:44:55')
	:type address: str
	:param payload: bytes indicating the payload's value (e.g. b"\x0F\x0F\x0F\x0F")
	:type payload: bytes
	:param hidData: value of HID data in use
	:type hidData: bytes
	'''
	def __init__(self,payload=None,address="00:00:00:00:00",key="",ctrl=False,shift=False,gui=False,alt=False,locale="fr",hidData = None):
		super().__init__(protocol="logitech",address=address,payload=payload)
		self.name = "ESB - Logitech Unencrypted Key Press Packet"
		if hidData is not None:
			self.hidData = hidData
		else:
			self.hidData = LogitechKeystroke(locale=locale,key=key,ctrl=ctrl, shift=shift, gui=gui,alt=alt).data
	def toString(self):
		return "<< "+self.name +" ("+self.protocol+")"  +" | address="+str(self.address)+" | hidData="+self.hidData.hex()+" >>"

class ESBLogitechUnencryptedKeyReleasePacket(ESBPacket):
	'''
	Mirage Enhanced ShockBurst Packet - Logitech Unencrypted Key Release Packet


	:param address: address of the emitter of the frame (e.g. '11:22:33:44:55')
	:type address: str
	:param payload: bytes indicating the payload's value (e.g. b"\x0F\x0F\x0F\x0F")
	:type payload: bytes
	:param hidData: value of HID data in use
	:type hidData: bytes
	'''
	def __init__(self,payload=None,address="00:00:00:00:00"):
		super().__init__(protocol="logitech",address=address,payload=payload)
		self.name = "ESB - Logitech Unencrypted Key Release Packet"
		self.hidData = b"\x00\x00\x00\x00\x00\x00\x00"

	def toString(self):
		return "<< "+self.name +" ("+self.protocol+")" +" | address="+str(self.address)+" | hidData="+self.hidData.hex()+" >>"

	

class ESBLogitechMultimediaKeyPressPacket(ESBPacket):
	'''
	Mirage Enhanced ShockBurst Packet - Logitech Multimedia Key Press Packet


	:param address: address of the emitter of the frame (e.g. '11:22:33:44:55')
	:type address: str
	:param payload: bytes indicating the payload's value (e.g. b"\x0F\x0F\x0F\x0F")
	:type payload: bytes
	:param hidData: value of HID data in use
	:type hidData: bytes
	'''
	def __init__(self,payload=None,address="00:00:00:00:00",hidData = b"\x00\x04\x00\x00\x00\x00\x00"):
		super().__init__(protocol="logitech",address=address,payload=payload)
		self.name = "ESB - Logitech Multimedia Key Press Packet"
		self.hidData = hidData

	def toString(self):
		return "<< "+self.name +" ("+self.protocol+")"  +" | address="+str(self.address)+" | hidData="+self.hidData.hex()+" >>"

class ESBLogitechMultimediaKeyReleasePacket(ESBPacket):
	'''
	Mirage Enhanced ShockBurst Packet - Logitech Multimedia Key Release Packet


	:param address: address of the emitter of the frame (e.g. '11:22:33:44:55')
	:type address: str
	:param payload: bytes indicating the payload's value (e.g. b"\x0F\x0F\x0F\x0F")
	:type payload: bytes
	:param hidData: value of HID data in use
	:type hidData: bytes
	'''
	def __init__(self,payload=None,address="00:00:00:00:00"):
		super().__init__(protocol="logitech",address=address,payload=payload)
		self.name = "ESB - Logitech Multimedia Key Release Packet"
		self.hidData = b"\x00\x00\x00\x00"

	def toString(self):
		return "<< "+self.name +" ("+self.protocol+")" +" | address="+str(self.address)+" | hidData="+self.hidData.hex()+" >>"


class ESBLogitechEncryptedKeystrokePacket(ESBPacket):
	'''
	Mirage Enhanced ShockBurst Packet - Logitech Encrypted Keystroke Packet


	:param address: address of the emitter of the frame (e.g. '11:22:33:44:55')
	:type address: str
	:param payload: bytes indicating the payload's value (e.g. b"\x0F\x0F\x0F\x0F")
	:type payload: bytes
	:param hidData: value of HID data in use
	:type hidData: bytes
	:param aesCounter: value of AES counter
	:type aesCounter: int

	'''
	def __init__(self,payload=None,address="00:00:00:00:00",hidData = b"\x00\x04\x00\x00\x00\x00\x00", aesCounter=0, unknown=0):
		super().__init__(protocol="logitech",address=address,payload=payload)
		self.name = "ESB - Logitech Encrypted Keystroke Packet"
		self.hidData = hidData
		self.unknown = unknown
		self.aesCounter = aesCounter

	def toString(self):
		return "<< "+self.name +" ("+self.protocol+")"  +" | address="+str(self.address)+" | hidData="+self.hidData.hex()+" | aesCounter="+str(self.aesCounter)+" >>"

	
