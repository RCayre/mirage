from mirage.libs import wireless
from mirage.libs.mosart_utils.dissectors import *


class MosartSniffingParameters(wireless.AdditionalInformations):
	'''
	This class allows to attach some sniffer's data to a Mirage Mosart Packet, such as channel.

	:param channel: channel of the received packet
	:type channel: int

	'''
	def __init__(self, channel=None):
		
		if channel is not None:
			self.channel = int(channel)
		else:
			self.channel = -1

	def toString(self):
		return "CH:" + str(self.channel)

class MosartPacket(wireless.Packet):
	'''
	Mirage Mosart Packet

	:param address: string indicating the address of the transmitter (format: '11:22:33:44')
	:type address: str
	:param sequenceNumber: sequence number of the packet
	:type sequenceNumber: int
	:param deviceType: string indicating the device type of the packet ("keyboard", "mouse" or "dongle")
	:type deviceType: str
	:param payload: payload of the packet
	:type payload: bytes

	'''
	def __init__(self,address='00:00:00:00',sequenceNumber=0,deviceType=None, payload = None):
		super().__init__()
		self.name = "Mosart - Unknown Packet"
		self.deviceType = deviceType
		self.sequenceNumber = sequenceNumber
		self.address = address.upper()
		self.payload = payload

	def toString(self):
		return "<< "+self.name +" | address="+str(self.address)+(" | payload="+self.payload.hex() if self.payload is not None else "")+" >>"

class MosartDonglePacket(MosartPacket):
	'''
	Mirage Mosart Packet - Dongle Sync / Acknowledgment

	:param address: string indicating the address of the transmitter (format: '11:22:33:44')
	:type address: str
	:param payload: payload of the packet
	:type payload: bytes

	'''

	def __init__(self, address = None, payload = None):
		MosartPacket.__init__(self,deviceType="dongle",sequenceNumber=0x1,address=address,payload=payload)
		self.name = "Mosart - Dongle Packet"

	def toString(self):
		return "<< "+self.name +" | address="+str(self.address)+(" | payload="+self.payload.hex() if self.payload is not None else "")+" >>"

class MosartMouseMovementPacket(MosartPacket):
	'''
	Mirage Mosart Packet - Mouse Movement

	:param address: string indicating the address of the transmitter (format: '11:22:33:44')
	:type address: str
	:param sequenceNumber: sequence number of the packet
	:type sequenceNumber: int
	:param payload: payload of the packet
	:type payload: bytes
	:param x1: X coordinate of the velocity vector (first)
	:type x1: int
	:param x2: X coordinate of the velocity vector (second)
	:type x2: int
	:param y1: Y coordinate of the velocity vector (first)
	:type y1: int
	:param y2: Y coordinate of the velocity vector (second)
	:type y2: int

	'''

	def __init__(self,sequenceNumber=0,address = None, payload = None,x1=0,x2=0,y1=0,y2=0):
		MosartPacket.__init__(self,deviceType="mouse",sequenceNumber=sequenceNumber,address=address,payload=payload)
		self.name = "Mosart - Mouse Movement Packet"
		self.x1 = x1
		self.y1 = y1
		self.x2 = x2
		self.y2 = y2

	def toString(self):
		return "<< "+self.name +" | address="+str(self.address)+(" | payload="+self.payload.hex() if self.payload is not None else "")+" | x1="+str(self.x1)+" | y1="+str(self.y1)+" | x2="+str(self.x2)+" | y2="+str(self.y2)+" >>"

class MosartMouseClickPacket(MosartPacket):
	'''
	Mirage Mosart Packet - Mouse Click

	:param address: string indicating the address of the transmitter (format: '11:22:33:44')
	:type address: str
	:param sequenceNumber: sequence number of the packet
	:type sequenceNumber: int
	:param payload: payload of the packet
	:type payload: bytes
	:param code: Mosart code indicating the selected button
	:type code: int
	:param stateCode: Mosart code indicating the state of the selected button
	:type stateCode: int
	:param state: string indicating the state of the selected button ("pressed", "released", "unknown")
	:type state: str
	:param button: string indicating the selected button ("right", "left", "middle")
	:type button: str

	'''
	def __init__(self,sequenceNumber=0, address = None, payload = None,code = None, stateCode = None,state=None,button = ""):
		MosartPacket.__init__(self,deviceType="mouse",sequenceNumber=sequenceNumber,address=address,payload=payload)
		self.name = "Mosart <Mouse Click Packet>"

		self.code = code
		if code is not None:
			if self.code == 0xa0:
				self.button  = "left"
			elif self.code == 0xa1:
				self.button = "right"
			elif self.code == 0xa2:
				self.button = "middle"
			else:
				self.button = "unknown"
		else:
			if self.button == "left":
				self.code = 0xa0
			elif self.button == "right":
				self.code = 0xa1
			elif self.button == "middle":
				self.code = 0xa2
			else:
				self.code = 0xa0
		
		if state is None:
			if stateCode is not None:
				self.stateCode = stateCode
				if self.stateCode == 0x81:
					self.state = "pressed"
				elif self.stateCode == 0x01:
					self.state = "released"
				else:
					self.state = "unknown"
			else:
				self.state = "pressed"
				self.stateCode = 0x81
		else:
			self.state = state
			if self.state == "pressed":
				self.stateCode = 0x81
			elif self.state == "released":
				self.stateCode = 0x01
			else:
				self.stateCode = 0x81
	def toString(self):
		return "<< "+self.name +" | address="+str(self.address)+(" | payload="+self.payload.hex() if self.payload is not None else "")+" | button = "+self.button+ " | state = "+self.state+" >>"

class MosartKeyboardKeystrokePacket(MosartPacket):
	'''
	Mirage Mosart Packet - Keyboard Keystroke

	:param address: string indicating the address of the transmitter (format: '11:22:33:44')
	:type address: str
	:param sequenceNumber: sequence number of the packet
	:type sequenceNumber: int
	:param payload: payload of the packet
	:type payload: bytes
	:param code: Mosart code indicating the selected key
	:type code: int
	:param stateCode: Mosart code indicating the state of the selected key
	:type stateCode: int
	:param state: string indicating the state of the selected button ("pressed", "released", "unknown")
	:type state: str
	:param hidCode: HID code of the selected key
	:type hidCode: int
	:param modifiers: HID modifiers of the selected key
	:type modifiers: int

	'''
	def __init__(self,sequenceNumber=0, address = None, payload = None,code = None,stateCode = None, state = None,hidCode=None,modifiers=None):
		MosartPacket.__init__(self,deviceType="keyboard",sequenceNumber=sequenceNumber,address=address,payload=payload)
		self.name = "Mosart <Keyboard Keystroke Packet>"

		if state is None:
			if stateCode is not None:
				self.stateCode = stateCode
				if self.stateCode == 0x81:
					self.state = "pressed"
				elif self.stateCode == 0x01:
					self.state = "released"
				else:
					self.state = "unknown"
			else:
				self.state = "pressed"
				self.stateCode = 0x81
		else:
			self.state = state
			if self.state == "pressed":
				self.stateCode = 0x81
			elif self.state == "released":
				self.stateCode = 0x01
			else:
				self.stateCode = 0x81
		if code is not None and stateCode is not None:
			self.code = code
			dissector = MosartKeystroke(data=bytes([stateCode,code]))
			self.hidCode,self.modifiers = dissector.hidCode,dissector.modifiers
		else: # We assume hidCode and modifiers have been provided
			data = MosartKeystroke(hidCode=hidCode,modifiers=modifiers).data
			self.stateCode,self.code = data[0],data[1]
			
			self.hidCode = hidCode
			self.modifiers = modifiers
	def toString(self):
		return "<< "+self.name +" | sequenceNumber="+str(self.sequenceNumber)+" | address="+str(self.address)+(" | payload="+self.payload.hex() if self.payload is not None else "")+" | code = "+str(self.code)+ " | state = "+str(self.state)+" | hidCode = "+str(self.hidCode)+" | modifiers = "+str(self.modifiers)+" >>"

