from mirage.libs.zigbee_utils.scapy_xbee_layers import *
from mirage.libs.zigbee_utils.helpers import *
from mirage.libs import wireless

class ZigbeePCAPDevice(wireless.PCAPDevice):
	'''
	This device allows to communicate with a PCAP file in order to write and read Zigbee packets.
	
	The corresponding interfaces are : ``<filename>.pcap`` (e.g. "out.pcap")
	
	  * If the file exists, the ZigbeePCAPDevice is in *read* mode, and the corresponding receiver is able to use it as a classic Zigbee sniffer.
	  * If the file doesn't exist, the ZigbeePCAPDevice is in *write* mode, and the corresponding emitter is able to write packets in the file.

	The following capabilities are actually supported :

	+-----------------------------------+----------------+
	| Capability			    | Available ?    |
	+===================================+================+
	| SNIFFING                          | yes            |
	+-----------------------------------+----------------+
	| INJECTING                         | yes            |
	+-----------------------------------+----------------+
	| COMMUNICATING_AS_COORDINATOR      | no             |
	+-----------------------------------+----------------+
	| COMMUNICATING_AS_ROUTER           | no             |
	+-----------------------------------+----------------+
	| COMMUNICATING_AS_END_DEVICE       | no             |
	+-----------------------------------+----------------+
	| JAMMING                           | no             |
	+-----------------------------------+----------------+

	.. warning::

		This PCAP Device uses the DLT 195.

	'''
	DLT = 195
	SCAPY_LAYER = Dot15d4
	sharedMethods = ["generateStream","setChannel","getChannel","getMode"]

	def init(self):
		super().init()
		self.capabilities = ["SNIFFING","INJECTING"]
		if self.mode == "read":
			self.startReading()

	def send(self,packet):
		if self.mode == "write":
			if self.SCAPY_LAYER is not None:
				packet = bytes(packet) + fcs(bytes(packet))
			self.putPacket(packet)

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
