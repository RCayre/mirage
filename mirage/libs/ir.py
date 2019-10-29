from mirage.core.module import WirelessModule
from mirage.libs.ir_utils.scapy_irma_layers import *
from mirage.libs.ir_utils.irma import *
from mirage.libs.ir_utils.packets import *
import math

class IREmitter(wireless.Emitter):
	def __init__(self,interface="irma0"):
		super().__init__(interface=interface,packetType=IRPacket, deviceType=IRMADevice)

	def convert(self,p):
		if isinstance(p,IRNECPacket):
			p.packet = IRma_Hdr()/IRma_Request()/Req_IRma_Send(proto = 0x01, data_size = int(math.ceil(p.size / 8)), data=p.code)
		elif isinstance(p,IRSonyPacket):
			p.packet = IRma_Hdr()/IRma_Request()/Req_IRma_Send(proto = 0x02, data_size = int(math.ceil(p.size / 8)), data=p.code)
		elif isinstance(p,IRRC5Packet):
			p.packet = IRma_Hdr()/IRma_Request()/Req_IRma_Send(proto = 0x03, data_size = int(math.ceil(p.size / 8)), data=p.code)
		elif isinstance(p,IRRC6Packet):
			p.packet = IRma_Hdr()/IRma_Request()/Req_IRma_Send(proto = 0x04, data_size = int(math.ceil(p.size / 8)), data=p.code)
		elif isinstance(p,IRDishPacket):
			p.packet = IRma_Hdr()/IRma_Request()/Req_IRma_Send(proto = 0x05, data_size = int(math.ceil(p.size / 8)), data=p.code)
		elif isinstance(p,IRSharpPacket):
			p.packet = IRma_Hdr()/IRma_Request()/Req_IRma_Send(proto = 0x06, data_size = int(math.ceil(p.size / 8)), data=p.code)
		elif isinstance(p,IRJVCPacket):
			p.packet = IRma_Hdr()/IRma_Request()/Req_IRma_Send(proto = 0x07, data_size = int(math.ceil(p.size / 8)), data=p.code)
		elif isinstance(p,IRSanyoPacket):
			p.packet = IRma_Hdr()/IRma_Request()/Req_IRma_Send(proto = 0x08, data_size = int(math.ceil(p.size / 8)), data=p.code)
		elif isinstance(p,IRMitsubishiPacket):
			p.packet = IRma_Hdr()/IRma_Request()/Req_IRma_Send(proto = 0x09, data_size = int(math.ceil(p.size / 8)), data=p.code)
		elif isinstance(p,IRSamsungPacket):
			p.packet = IRma_Hdr()/IRma_Request()/Req_IRma_Send(proto = 0x0a, data_size = int(math.ceil(p.size / 8)), data=p.code)
		elif isinstance(p,IRLGPacket):
			p.packet = IRma_Hdr()/IRma_Request()/Req_IRma_Send(proto = 0x0b, data_size = int(math.ceil(p.size / 8)), data=p.code)
		elif isinstance(p,IRWhynterPacket):
			p.packet = IRma_Hdr()/IRma_Request()/Req_IRma_Send(proto = 0x0c, data_size = int(math.ceil(p.size / 8)), data=p.code)
		elif isinstance(p,IRAiwaPacket):
			p.packet = IRma_Hdr()/IRma_Request()/Req_IRma_Send(proto = 0x0d, data_size = int(math.ceil(p.size / 8)), data=p.code)
		elif isinstance(p,IRPanasonicPacket):
			p.packet = IRma_Hdr()/IRma_Request()/Req_IRma_Send(proto = 0x0e, data_size = int(math.ceil(p.size / 8)), data=p.code)
		elif isinstance(p,IRDenonPacket):
			p.packet = IRma_Hdr()/IRma_Request()/Req_IRma_Send(proto = 0x0f, data_size = int(math.ceil(p.size / 8)), data=p.code)

		elif isinstance(p,IRPacket):
			# Scapy-related error
			rawdata = b""
			for i in p.data:
				rawdata += struct.pack(">H",i)

			p.packet = IRma_Hdr()/IRma_Request()/Req_IRma_Send(proto = 0x00, data_size = 2*len(p.data),data = rawdata)
		
		return p.packet


class IRReceiver(wireless.Receiver):
	def __init__(self,interface="irma0"):
		super().__init__(interface=interface,packetType=IRPacket, deviceType=IRMADevice)
	
	def convert(self,packet):
		new = IRPacket()
		if Resp_IRma_Recv in packet:
			new = IRPacket(data=packet.raw)
			if packet.proto == 0x01:
				new = IRNECPacket(data=packet.raw,size=packet.code_size,code=packet.code)
			elif packet.proto == 0x02:
				new = IRSonyPacket(data=packet.raw,size=packet.code_size,code=packet.code)
			elif packet.proto == 0x03:
				new = IRRC5Packet(data=packet.raw,size=packet.code_size,code=packet.code)
			elif packet.proto == 0x04:
				new = IRRC6Packet(data=packet.raw,size=packet.code_size,code=packet.code)
			elif packet.proto == 0x05:
				new = IRDishPacket(data=packet.raw,size=packet.code_size,code=packet.code)
			elif packet.proto == 0x06:
				new = IRSharpPacket(data=packet.raw,size=packet.code_size,code=packet.code)
			elif packet.proto == 0x07:
				new = IRJVCPacket(data=packet.raw,size=packet.code_size,code=packet.code)
			elif packet.proto == 0x08:
				new = IRSanyoPacket(data=packet.raw,size=packet.code_size,code=packet.code)
			elif packet.proto == 0x09:
				new = IRMitsubishiPacket(data=packet.raw,size=packet.code_size,code=packet.code)
			elif packet.proto == 0x0a:
				new = IRSamsungPacket(data=packet.raw, size=packet.code_size,code=packet.code)
			elif packet.proto == 0x0b:
				new = IRLGPacket(data=packet.raw, size=packet.code_size,code=packet.code)
			elif packet.proto == 0x0c:
				new = IRWhynterPacket(data=packet.raw, size=packet.code_size,code=packet.code)
			elif packet.proto == 0x0d:
				new = IRAiwaPacket(data=packet.raw, size=packet.code_size,code=packet.code)
			elif packet.proto == 0x0e:
				new = IRPanasonicPacket(data=packet.raw, size=packet.code_size,code=packet.code)
			elif packet.proto == 0x0f:
				new = IRDenonPacket(data=packet.raw, size=packet.code_size,code=packet.code)
		new.packet = packet
		return new



WirelessModule.registerEmitter("ir",IREmitter)
WirelessModule.registerReceiver("ir",IRReceiver)
