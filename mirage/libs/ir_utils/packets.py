from mirage.libs import wireless

class IRPacket(wireless.Packet):
	'''
	Mirage IR Packet

	:param data: data representing the signal
	:type data: list of int
	:param protocol: string indicating the protocol currently in use (by default: "UNKNOWN")
	:type protocol: str

	'''
	def __init__(self,protocol="UNKNOWN", data=[]):
		super().__init__()
		self.data = data
		self.protocol = protocol
		self.name = "IR - Raw Packet"

	def toString(self):
		return "<< "+self.name +" | data="+str(self.data)+" >>"


class IRNECPacket(IRPacket):
	'''
	Mirage IR Packet - NEC Packet

	:param data: data representing the signal (optional if a code is provided)
	:type data: list of int
	:param code: array of bytes indicating the code to transmit
	:type code: bytes
	:param size: integer indicating the size (in bits) of the code
	:type size: int

	'''

	def __init__(self,data=[],size=None,code=None):
		super().__init__(protocol="NEC",data=data)
		self.code = code
		self.size = size if size is not None else len(code)*8
		self.name = "IR - NEC Packet"

	def toString(self):
		return "<< "+self.name +" | code ("+str(self.size)+" bits) ="+self.code.hex()+" >>"

class IRSonyPacket(IRPacket):
	'''
	Mirage IR Packet - Sony Packet

	:param data: data representing the signal (optional if a code is provided)
	:type data: list of int
	:param code: array of bytes indicating the code to transmit
	:type code: bytes
	:param size: integer indicating the size (in bits) of the code
	:type size: int

	'''

	def __init__(self,data=[],size=None,code=None):
		super().__init__(protocol="Sony",data=data)
		self.code = code
		self.size = size if size is not None else len(code)*8
		self.name = "IR - Sony Packet"

	def toString(self):
		return "<< "+self.name +" | code ("+str(self.size)+" bits) ="+self.code.hex()+" >>"

class IRRC5Packet(IRPacket):
	'''
	Mirage IR Packet - RC5 Packet

	:param data: data representing the signal (optional if a code is provided)
	:type data: list of int
	:param code: array of bytes indicating the code to transmit
	:type code: bytes
	:param size: integer indicating the size (in bits) of the code
	:type size: int

	'''

	def __init__(self,data=[],size=None,code=None):
		super().__init__(protocol="RC5",data=data)
		self.code = code
		self.size = size if size is not None else len(code)*8
		self.name = "IR - RC5 Packet"

	def toString(self):
		return "<< "+self.name +" | code ("+str(self.size)+" bits) ="+self.code.hex()+" >>"

class IRRC6Packet(IRPacket):
	'''
	Mirage IR Packet - RC6 Packet

	:param data: data representing the signal (optional if a code is provided)
	:type data: list of int
	:param code: array of bytes indicating the code to transmit
	:type code: bytes
	:param size: integer indicating the size (in bits) of the code
	:type size: int

	'''
	def __init__(self,data=[],size=None,code=None):
		super().__init__(protocol="RC6",data=data)
		self.code = code
		self.size = size if size is not None else len(code)*8
		self.name = "IR - RC6 Packet"

	def toString(self):
		return "<< "+self.name +" | code ("+str(self.size)+" bits) ="+self.code.hex()+" >>"

class IRDishPacket(IRPacket):
	'''
	Mirage IR Packet - Dish Packet

	:param data: data representing the signal (optional if a code is provided)
	:type data: list of int
	:param code: array of bytes indicating the code to transmit
	:type code: bytes
	:param size: integer indicating the size (in bits) of the code
	:type size: int

	'''
	def __init__(self,data=[],size=None,code=None):
		super().__init__(protocol="Dish",data=data)
		self.code = code
		self.size = size if size is not None else len(code)*8
		self.name = "IR - Dish Packet"

	def toString(self):
		return "<< "+self.name +" | code ("+str(self.size)+" bits) ="+self.code.hex()+" >>"


class IRSharpPacket(IRPacket):
	'''
	Mirage IR Packet - Sharp Packet

	:param data: data representing the signal (optional if a code is provided)
	:type data: list of int
	:param code: array of bytes indicating the code to transmit
	:type code: bytes
	:param size: integer indicating the size (in bits) of the code
	:type size: int

	'''
	def __init__(self,data=[],size=None,code=None):
		super().__init__(protocol="Sharp",data=data)
		self.code = code
		self.size = size if size is not None else len(code)*8
		self.name = "IR - Sharp Packet"

	def toString(self):
		return "<< "+self.name +" | code ("+str(self.size)+" bits) ="+self.code.hex()+" >>"

class IRJVCPacket(IRPacket):
	'''
	Mirage IR Packet - JVC Packet

	:param data: data representing the signal (optional if a code is provided)
	:type data: list of int
	:param code: array of bytes indicating the code to transmit
	:type code: bytes
	:param size: integer indicating the size (in bits) of the code
	:type size: int

	'''
	def __init__(self,protocol="JVC",data=[],size=None,code=None):
		super().__init__(data=data)
		self.code = code
		self.size = size if size is not None else len(code)*8
		self.name = "IR - JVC Packet"

	def toString(self):
		return "<< "+self.name +" | code ("+str(self.size)+" bits) ="+self.code.hex()+" >>"

class IRSanyoPacket(IRPacket):
	'''
	Mirage IR Packet - Sanyo Packet

	:param data: data representing the signal (optional if a code is provided)
	:type data: list of int
	:param code: array of bytes indicating the code to transmit
	:type code: bytes
	:param size: integer indicating the size (in bits) of the code
	:type size: int

	'''
	def __init__(self,data=[],size=None,code=None):
		super().__init__(protocol="Sanyo",data=data)
		self.code = code
		self.size = size if size is not None else len(code)*8
		self.name = "IR - Sanyo Packet"

	def toString(self):
		return "<< "+self.name +" | code ("+str(self.size)+" bits) ="+self.code.hex()+" >>"

class IRMitsubishiPacket(IRPacket):
	'''
	Mirage IR Packet - Mitsubishi Packet

	:param data: data representing the signal (optional if a code is provided)
	:type data: list of int
	:param code: array of bytes indicating the code to transmit
	:type code: bytes
	:param size: integer indicating the size (in bits) of the code
	:type size: int

	'''
	def __init__(self,data=[],size=None,code=None):
		super().__init__(protocol="Mitsubishi",data=data)
		self.code = code
		self.size = size if size is not None else len(code)*8
		self.name = "IR - Mitsubishi Packet"

	def toString(self):
		return "<< "+self.name +" | code ("+str(self.size)+" bits) ="+self.code.hex()+" >>"


class IRSamsungPacket(IRPacket):
	'''
	Mirage IR Packet - Samsung Packet

	:param data: data representing the signal (optional if a code is provided)
	:type data: list of int
	:param code: array of bytes indicating the code to transmit
	:type code: bytes
	:param size: integer indicating the size (in bits) of the code
	:type size: int

	'''
	def __init__(self,data=[],size=None,code=None):
		super().__init__(protocol="SAMSUNG",data=data)
		self.code = code
		self.size = size if size is not None else len(code)*8
		self.name = "IR - Samsung Packet"

	def toString(self):
		return "<< "+self.name +" | code ("+str(self.size)+" bits) ="+self.code.hex()+" >>"

class IRLGPacket(IRPacket):
	'''
	Mirage IR Packet - LG Packet

	:param data: data representing the signal (optional if a code is provided)
	:type data: list of int
	:param code: array of bytes indicating the code to transmit
	:type code: bytes
	:param size: integer indicating the size (in bits) of the code
	:type size: int

	'''
	def __init__(self,data=[],size=None,code=None):
		super().__init__(protocol="LG",data=data)
		self.code = code
		self.size = size if size is not None else len(code)*8
		self.name = "IR - LG Packet"

	def toString(self):
		return "<< "+self.name +" | code ("+str(self.size)+" bits) ="+self.code.hex()+" >>"

class IRWhynterPacket(IRPacket):
	'''
	Mirage IR Packet - Whynter Packet

	:param data: data representing the signal (optional if a code is provided)
	:type data: list of int
	:param code: array of bytes indicating the code to transmit
	:type code: bytes
	:param size: integer indicating the size (in bits) of the code
	:type size: int

	'''
	def __init__(self,data=[],size=None,code=None):
		super().__init__(protocol="Whynter",data=data)
		self.code = code
		self.size = size if size is not None else len(code)*8
		self.name = "IR - Whynter Packet"

	def toString(self):
		return "<< "+self.name +" | code ("+str(self.size)+" bits) ="+self.code.hex()+" >>"


class IRAiwaPacket(IRPacket):
	'''
	Mirage IR Packet - Aiwa Packet

	:param data: data representing the signal (optional if a code is provided)
	:type data: list of int
	:param code: array of bytes indicating the code to transmit
	:type code: bytes
	:param size: integer indicating the size (in bits) of the code
	:type size: int

	'''
	def __init__(self,data=[],size=None,code=None):
		super().__init__(protocol="Aiwa",data=data)
		self.code = code
		self.size = size if size is not None else len(code)*8
		self.name = "IR - Aiwa Packet"

	def toString(self):
		return "<< "+self.name +" | code ("+str(self.size)+" bits) ="+self.code.hex()+" >>"


class IRPanasonicPacket(IRPacket):
	'''
	Mirage IR Packet - Panasonic Packet

	:param data: data representing the signal (optional if a code is provided)
	:type data: list of int
	:param code: array of bytes indicating the code to transmit
	:type code: bytes
	:param size: integer indicating the size (in bits) of the code
	:type size: int

	'''
	def __init__(self,data=[],size=None,code=None):
		super().__init__(protocol="Panasonic",data=data)
		self.code = code
		self.size = size if size is not None else len(code)*8
		self.name = "IR - Panasonic Packet"

	def toString(self):
		return "<< "+self.name +" | code ("+str(self.size)+" bits) ="+self.code.hex()+" >>"


class IRDenonPacket(IRPacket):
	'''
	Mirage IR Packet - Denon Packet

	:param data: data representing the signal (optional if a code is provided)
	:type data: list of int
	:param code: array of bytes indicating the code to transmit
	:type code: bytes
	:param size: integer indicating the size (in bits) of the code
	:type size: int

	'''
	def __init__(self,data=[],size=None,code=None):
		super().__init__(protocol="Denon",data=data)
		self.code = code
		self.size = size if size is not None else len(code)*8
		self.name = "IR - Denon Packet"

	def toString(self):
		return "<< "+self.name +" | code ("+str(self.size)+" bits) ="+self.code.hex()+" >>"


