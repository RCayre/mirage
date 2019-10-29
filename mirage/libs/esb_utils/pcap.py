from mirage.libs.esb_utils.scapy_esb_layers import *
from mirage.libs import wireless

class ESBPCAPDevice(wireless.PCAPDevice):
	'''
	This device allows to communicate with a PCAP file in order to write and read Enhanced ShockBurst packets.
	
	The corresponding interfaces are : ``<filename>.pcap`` (e.g. "out.pcap")
	
	  * If the file exists, the ESBPCAPDevice is in *read* mode, and the corresponding receiver is able to use it as a classic Enhanced ShockBurst sniffer.
	  * If the file doesn't exist, the ESBPCAPDevice is in *write* mode, and the corresponding emitter is able to write packets in the file.

	The following capabilities are actually supported :

	+-----------------------------------+----------------+
	| Capability			    | Available ?    |
	+===================================+================+
	| INJECTING                         | yes            |
	+-----------------------------------+----------------+
	| SNIFFING_NORMAL                   | yes            |
	+-----------------------------------+----------------+
	| SNIFFING_PROMISCUOUS              | yes            |
	+-----------------------------------+----------------+
	| SNIFFING_GENERIC_PROMISCUOUS      | no             |
	+-----------------------------------+----------------+
	| ACTIVE_SCANNING                   | yes            |
	+-----------------------------------+----------------+

	.. warning::

		This PCAP Device uses the DLT 148.

	'''
	DLT = 148
	SCAPY_LAYER = ESB_Hdr

	sharedMethods = ["enterSnifferMode","enterPromiscuousMode","scan","getChannel","setChannel","getMode","generateStream"]

	def init(self):
		super().init()
		self.address = "FF:FF:FF:FF:FF"
		self.capabilities = ["INJECTING","SNIFFING_NORMAL","SNIFFING_PROMISCUOUS","ACTIVE_SCANNING"]

	def enterSnifferMode(self,address):
		'''
		This method allows to put your device into sniffer mode. You have to provide an address to follow.

		:param address: address to follow as string (e.g. '11:22:33:44:55')
		:type address: str

		.. note::

			This method is a **shared method** and can be called from the corresponding Emitters / Receivers.

		'''
		self.address = address.upper()
		self.startReading()

	def enterPromiscuousMode(self,prefix=b""):
		'''
		This method allows to put your device into promiscuous mode. You can provide a specific prefix to match using the prefix parameter.

		:param prefix: bytes indicating the prefix to look for
		:type prefix: bytes

		.. note::

			This method is a **shared method** and can be called from the corresponding Emitters / Receivers.

		'''
		self.address = "FF:FF:FF:FF:FF"
		self.startReading()

	def scan(self,channels):
		'''
		This method allows to simulate an active scan.
	
		:param channels: list of channels to scan
		:type channels: list of int
		:return: boolean indicating if the device has been found
		:rtype: bool
			

		:Example:

			>>> device.scan([1,2,3])
			True
			>>> device.scan()
			True

		.. note::

			This method is a **shared method** and can be called from the corresponding Emitters / Receivers.

		'''
		return True

	def buildPacket(self,packet,timestamp):
		packet = self.SCAPY_LAYER(b"\xAA"+packet)

		if packet.address.upper() == self.address or self.address == "FF:FF:FF:FF:FF":
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

	def send(self,packet):
		if self.mode == "write":
			if self.SCAPY_LAYER is not None:
				packet = bytes(packet)[1:]
			self.putPacket(packet)
