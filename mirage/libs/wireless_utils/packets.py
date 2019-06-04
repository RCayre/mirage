from mirage.libs import io

class AdditionalInformations:
	def __init__(self):
		pass
	def toString(self):
		return "???"
	def __str__(self):
		return self.toString()

class Packet:
	'''
	This class represents an abstract representation of a packet.
	It can be overloaded in order to implements the relevant packets for a given technology.

	By default, three attributes are included in a Packet :
	  * name : it indicates the name of the packet
	  * packet : it contains the raw representation of the packet (e.g. a bytes array or a scapy frame)
	  * additionalInformations : it contains some external informations about a packet (e.g. frequency, timestamp ...)
	'''
	def __init__(self, packet=None, additionalInformations = None):
		self.name = "Generic Packet"
		self.packet = packet
		self.additionalInformations = additionalInformations

	def toString(self):
		'''
		This method allows to explicitely define how a packet is displayed if it is converted as a string.

		If this method is not overloaded, the packet is displayed as : 
		  * *<< name >>* if no additional informations are linked to this packet
		  * *[ additionalInformations ] << name >>* if some additional informations are linked to this packet
		'''
		return "<< "+self.name+" >>"

	def show(self):
		'''
		This method allows to display the packet.
		'''
		io.displayPacket(self)

	def __str__(self):
		return (("[ "+str(self.additionalInformations)+" ] ") if self.additionalInformations is not None else "")+self.toString()

class WaitPacket(Packet):
	'''
	This class represents a *fake* packet, allowing to force the Emitter to wait for a given specific time.
	It can be used if some timing constraints are needed for a given transmission.
	
	The time attribute indicates the waiting time needed.

	:Example:
		>>> packet = WaitPacket(time=1.0)
		>>> emitter.sendp(firstPacket,packet,lastPacket) # the emitter sends firstPacket, waits for one second and sends lastPacket
	'''
	def __init__(self, time=0.0):
		super().__init__(self)
		self.name = "Generic - Waiting Packet"
		self.time = time

	def toString(self):
		return "<< "+self.name+" | time="+str(self.time)+"s >>"
