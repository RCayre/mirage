from mirage.libs.mosart_utils.rfstorm import *
from mirage.libs.mosart_utils.scapy_mosart_layers import *
from mirage.libs.mosart_utils.packets import *
from mirage.libs.mosart_utils.pcap import *
from mirage.libs.mosart_utils.helpers import *
from mirage.libs import wireless,io,utils
from mirage.core.module import WirelessModule

class MosartEmitter(wireless.Emitter):
	def __init__(self,interface="rfstorm0"):
		if "rfstorm" in interface:
			deviceClass = MosartRFStormDevice
		elif interface[-5:] == ".pcap":
			deviceClass = MosartPCAPDevice
		super().__init__(interface=interface,packetType=MosartPacket,deviceType=deviceClass)

	def convert(self,packet):
		if isinstance(packet,MosartPacket):
			new = Mosart_Hdr(address=addressToInteger(packet.address),seq_num=packet.sequenceNumber)

			if packet.deviceType == "mouse":
				if isinstance(packet,MosartMouseMovementPacket):
					new /= Mosart_Mouse_Movement_Packet(X1=packet.x1, X2=packet.x2,Y1=packet.y1, Y2=packet.y2)
				elif isinstance(packet,MosartMouseClickPacket):				
					new /= Mosart_Action_Packet(action_state=packet.stateCode,action_code=packet.code)

			elif packet.deviceType == "keyboard" and isinstance(packet,MosartKeyboardKeystrokePacket):
				new /= Mosart_Action_Packet(action_state=packet.stateCode,action_code=packet.code)

			elif packet.deviceType == "dongle":
				new /= Mosart_Dongle_Sync_Packet(sync=0x22)

			elif isinstance(packet,MosartPacket) and packet.payload is not None:
				return Mosart_Hdr(packet.payload)
			return new
	
		else:
			return None

			
		
class MosartReceiver(wireless.Receiver):
	def __init__(self,interface="rfstorm0"):
		if "rfstorm" in interface:
			deviceClass = MosartRFStormDevice
		elif interface[-5:] == ".pcap":
			deviceClass = MosartPCAPDevice
		super().__init__(interface=interface,packetType=MosartPacket,deviceType=deviceClass)


	def convert(self, packet):
		channel = self.getChannel()
		address = integerToAddress(packet.address)
		new = MosartPacket(address=address, payload = bytes(packet),sequenceNumber = packet.seq_num)
		if Mosart_Dongle_Sync_Packet in packet:
             		new = MosartDonglePacket(address=address, payload = bytes(packet))
		if Mosart_Mouse_Movement_Packet in packet:
			new = MosartMouseMovementPacket(
								address=address,
								payload = bytes(packet),
								sequenceNumber = packet.seq_num,
								x1 = packet.X1, 
								y1 = packet.Y1, 
								x2 = packet.X2,
								y2 = packet.Y2
							)
		elif Mosart_Action_Packet in packet and packet.action_code in [ 0xa0,0xa1,0xa2 ]:
			new = MosartMouseClickPacket(address=address,payload=bytes(packet), sequenceNumber = packet.seq_num, code=packet.action_code, stateCode=packet.action_state)
		elif Mosart_Action_Packet in packet and packet.action_code not in [ 0xa0,0xa1,0xa2 ]:
			new = MosartKeyboardKeystrokePacket(address=address, payload=bytes(packet), sequenceNumber = packet.seq_num, code=packet.action_code, stateCode=packet.action_state)
		new.additionalInformations = MosartSniffingParameters(channel=channel)
		return new 

WirelessModule.registerEmitter("mosart",MosartEmitter)
WirelessModule.registerReceiver("mosart",MosartReceiver)
