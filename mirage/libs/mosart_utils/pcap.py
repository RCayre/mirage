from mirage.libs.mosart_utils.scapy_mosart_layers import *
from mirage.libs.mosart_utils.helpers import *
from mirage.libs import wireless

class MosartPCAPDevice(wireless.PCAPDevice):
	'''
	This device allows to communicate with a PCAP file in order to write and read Mosart packets.
	
	The corresponding interfaces are : ``<filename>.pcap`` (e.g. "out.pcap")
	
	  * If the file exists, the MosartPCAPDevice is in *read* mode, and the corresponding receiver is able to use it as a classic Mosart sniffer.
	  * If the file doesn't exist, the MosartPCAPDevice is in *write* mode, and the corresponding emitter is able to write packets in the file.

	The following capabilities are actually supported :

	+-----------------------------------+----------------+
	| Capability			    | Available ?    |
	+===================================+================+
	| SNIFFING_NORMAL                   | yes            |
	+-----------------------------------+----------------+
	| SNIFFING_PROMISCUOUS              | yes            |
	+-----------------------------------+----------------+
	| INJECTING                         | yes            |
	+-----------------------------------+----------------+
	| INJECTING_SYNC                    | no             |
	+-----------------------------------+----------------+

	.. warning::

		This PCAP Device uses the DLT 149.

	'''
	DLT = 149
	SCAPY_LAYER = Mosart_Hdr

	sharedMethods = ["enterSnifferMode","enterPromiscuousMode","disableDonglePackets","enableDonglePackets","getChannel","setChannel","getMode","generateStream"]

	def init(self):
		super().init()
		self.address = "FF:FF:FF:FF"
		self.donglePackets = True
		self.capabilities = ["SNIFFING_NORMAL","SNIFFING_PROMISCUOUS","INJECTING"]

	def enableDonglePackets(self):
		'''
		This method enables the reception of dongle packets.

		:Example:
	
			>>> device.enableDonglePackets()

		.. note::

			This method is a **shared method** and can be called from the corresponding Emitters / Receivers.

		'''
		self.donglePackets = True


	def disableDonglePackets(self):
		'''
		This method enables the reception of dongle packets.

		:Example:
	
			>>> device.disableDonglePackets()

		.. note::

			This method is a **shared method** and can be called from the corresponding Emitters / Receivers.

		'''
		self.donglePackets = False


	def enterSnifferMode(self,address):
		'''
		This method allows to put your device into sniffer mode. You have to provide an address to follow.

		:param address: address to follow as string (e.g. '11:22:33:44')
		:type address: str

		.. note::

			This method is a **shared method** and can be called from the corresponding Emitters / Receivers.

		'''
		self.address = address.upper()
		self.startReading()

	def enterPromiscuousMode(self):
		'''
		This method allows to put your device into promiscuous mode.

		.. note::

			This method is a **shared method** and can be called from the corresponding Emitters / Receivers.

		'''
		self.address = "FF:FF:FF:FF"
		self.startReading()

	def buildPacket(self,packet,timestamp):
		packet = self.SCAPY_LAYER(packet)
		address = integerToAddress(packet.address)
		if (address == self.address or self.address == "FF:FF:FF:FF") and ((not self.donglePackets and b"\x11\x22" not in raw(packet)) or self.donglePackets) :
			return packet
		else:
			return None
	
	def getChannel(self):
		'''
		This method allows to simulate the getChannel behaviour of a normal sniffer.
	
		:return: integer indicating an unknown channel (-1)
		:rtype: int
			

		:Example:

			>>> device.getChannel()
			-1

		.. note::

			This method is a **shared method** and can be called from the corresponding Emitters / Receivers.

		'''
		return -1

	def setChannel(self,channel):
		'''
		This method allows to simulate the setChannel behaviour of a normal sniffer.
	
		:param channel: channel to set
		:type channel: int
			

		:Example:

			>>> device.getChannel()
			-1

		.. note::

			This method is a **shared method** and can be called from the corresponding Emitters / Receivers.

		'''
		pass

	def generateStream(self):
		'''
		This method generates a stream (i.e. a list of packets with the right inter frame spacing) from the PCAP file.
	
		:return: stream of packets
		:rtype: list
			

		:Example:

			>>> stream = device.generateStream()
			>>> device2.sendp(*stream)

		.. note::

			This method is a **shared method** and can be called from the corresponding Emitters / Receivers.

		'''
		if self.mode == "write":
			self.close()
			self.openFile()
			self.init()
		
		stream = []
		currentTimestamp = None
		for timestamp,packet in self.getAllPackets():
			if currentTimestamp is None:
				currentTimestamp = timestamp
			else:
				wait = (timestamp - currentTimestamp)
				stream.append(wireless.WaitPacket(time=wait))
				currentTimestamp = timestamp

			stream.append(self.publish("convertRawToMiragePacket",packet))
		return stream

