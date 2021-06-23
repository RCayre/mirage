from struct import pack,unpack
from scapy.all import *
from mirage.libs.wireless_utils.pcapDevice import PCAPDevice
from mirage.libs.ble_utils.packets import *
from mirage.libs.ble_utils.constants import *
from mirage.libs.ble_utils.scapy_link_layers import *
from mirage.libs.ble_utils.helpers import rssiToDbm, crc24
from mirage.libs import io, utils
import time

class BLEPCAPDevice(wireless.PCAPDevice):
	'''
	This device allows to communicate with a PCAP file in order to write and read Bluetooth Low Energy packets.

	The corresponding interfaces are : ``<filename>.pcap`` (e.g. "out.pcap")

	  * If the file exists, the BLEPCAPDevice is in *read* mode, and the corresponding receiver is able to use it as a classic Bluetooth Low Energy sniffer.
	  * If the file doesn't exist, the BLEPCAPDevice is in *write* mode, and the corresponding emitter is able to write packets in the file.

	The following capabilities are actually supported :

	+-----------------------------------+----------------+
	| Capability                        | Available ?    |
	+===================================+================+
	| SCANNING                          | no             |
	+-----------------------------------+----------------+
	| ADVERTISING                       | no             |
	+-----------------------------------+----------------+
	| SNIFFING_ADVERTISEMENTS           | yes            |
	+-----------------------------------+----------------+
	| SNIFFING_NEW_CONNECTION           | yes            |
	+-----------------------------------+----------------+
	| SNIFFING_EXISTING_CONNECTION      | no             |
	+-----------------------------------+----------------+
	| JAMMING_CONNECTIONS               | no             |
	+-----------------------------------+----------------+
	| JAMMING_ADVERTISEMENTS            | no             |
	+-----------------------------------+----------------+
	| HIJACKING_MASTER                  | no             |
	+-----------------------------------+----------------+
	| HIJACKING_SLAVE                   | no             |
	+-----------------------------------+----------------+
	| INJECTING                         | no             |
	+-----------------------------------+----------------+
	| MITMING_EXISTING_CONNECTION       | no             |
	+-----------------------------------+----------------+
	| INITIATING_CONNECTION             | no             |
	+-----------------------------------+----------------+
	| RECEIVING_CONNECTION              | no             |
	+-----------------------------------+----------------+
	| COMMUNICATING_AS_MASTER           | no             |
	+-----------------------------------+----------------+
	| COMMUNICATING_AS_SLAVE            | no             |
	+-----------------------------------+----------------+
	| HCI_MONITORING                    | no             |
	+-----------------------------------+----------------+

	.. warning::

		This PCAP Device uses the DLT 256, and can be used to read or write some Link Layer packets. It is not compatible with a PCAP file containing HCI frames.

	'''
	DLT = 256
	SCAPY_LAYER = BTLE_RF

	sharedMethods = [
				"sniffNewConnections",
				"sniffAdvertisements",
				"getAccessAddress",
				"getCrcInit",
				"getChannelMap",
				"getHopInterval",
				"getHopIncrement",
				"isSynchronized",
				"getMode"
			]
	def init(self):
		self.capabilities = ["SNIFFING_ADVERTISEMENTS", "SNIFFING_NEW_CONNECTION"]
		self.sniffingMode = BLESniffingMode.ADVERTISEMENT
		self.accessAddress = 0x8e89bed6
		self.hopInterval = None
		self.hopIncrement = None
		self.channelMap = None
		self.crcInit = None
		self.target = None
		self.synchronized = False
		super().init()

	def _setAccessAddress(self,accessAddress=None):
		self.accessAddress = accessAddress

	def _setCrcInit(self,crcInit=None):
		self.crcInit = crcInit

	def _setChannelMap(self,channelMap=None):
		self.channelMap = channelMap

	def _setHopInterval(self,hopInterval=None):
		self.hopInterval = hopInterval

	def _setHopIncrement(self,hopIncrement):
		self.hopIncrement = hopIncrement

	def getAccessAddress(self):
		'''
		This method returns the access address actually in use.

		:return: access address
		:rtype: int

		:Example:

			>>> hex(device.getAccessAddress())
			'0xe5e296e9'


		.. note::

			This method is a **shared method** and can be called from the corresponding Emitters / Receivers.

		'''
		return self.accessAddress

	def getCrcInit(self):
		'''
		This method returns the CRCInit actually in use.

		:return: CRCInit
		:rtype: int

		:Example:

			>>> hex(device.getCrcInit())
			'0x0bd54a'

		.. note::

			This method is a **shared method** and can be called from the corresponding Emitters / Receivers.

		'''
		return self.crcInit

	def getChannelMap(self):
		'''
		This method returns the Channel Map actually in use.

		:return: Channel Map
		:rtype: int

		:Example:

			>>> hex(device.getChannelMap())
			'0x1fffffffff'

		.. note::

			This method is a **shared method** and can be called from the corresponding Emitters / Receivers.


		'''
		return self.channelMap

	def getHopInterval(self):
		'''
		This method returns the Hop Interval actually in use.

		:return: Hop Interval
		:rtype: int

		:Example:

			>>> device.getHopInterval()
			36

		.. note::

			This method is a **shared method** and can be called from the corresponding Emitters / Receivers.


		'''
		return self.hopInterval

	def getHopIncrement(self):
		'''
		This method returns the Hop Increment actually in use.

		:return: Hop Increment
		:rtype: int

		:Example:

			>>> device.getHopIncrement()
			11

		.. note::

			This method is a **shared method** and can be called from the corresponding Emitters / Receivers.


		'''
		return self.hopIncrement

	def sniffNewConnections(self,address="FF:FF:FF:FF:FF:FF",channel=None):
		'''
		This method starts the new connections sniffing mode.

		:param address: selected address - if not provided, no filter is applied (format : "1A:2B:3C:4D:5E:6F")
		:type address: str
		:param channel: selected channel - if not provided, channel 37 is selected
		:type channel: int

		:Example:

			>>> device.sniffNewConnections()
			>>> device.sniffNewConnections(channel=38)
			>>> device.sniffNewConnections(address="1A:2B:3C:4D:5E:6F")


		.. warning::

			Actually, the address and channel arguments are not used by this method. They are present in order to provide the same API as BTLEJack and Ubertooth devices.

		.. note::

			This method is a **shared method** and can be called from the corresponding Emitters / Receivers.

		'''
		self.startReading()
		self.sniffingMode = BLESniffingMode.NEW_CONNECTION

	def sniffAdvertisements(self,address='FF:FF:FF:FF:FF:FF',channel=None):
		'''
		This method starts the advertisement sniffing mode.

		:param address: selected address - if not provided, no filter is applied (format : "1A:2B:3C:4D:5E:6F")
		:type address: str
		:param channel: selected channel - if not provided, channel 37 is selected
		:type channel: int

		:Example:

			>>> device.sniffAdvertisements()
			>>> device.sniffAdvertisements(channel=38)
			>>> device.sniffAdvertisements(address="1A:2B:3C:4D:5E:6F")

		.. warning::

			The channel parameter is not used by this method, and is present in order to provide the same API as BTLEJack and Ubertooth devices. However, the address field can be used in order to filter the advertisements frames.

		.. note::

			This method is a **shared method** and can be called from the corresponding Emitters / Receivers.

		'''

		self.startReading()
		self.target = address.upper()
		self.sniffingMode = BLESniffingMode.ADVERTISEMENT

	def isSynchronized(self):
		'''
		This method indicates if the sniffer is actually synchronized with a connection.

		:return: boolean indicating if the sniffer is synchronized
		:rtype: bool

		:Example:

			>>> device.isSynchronized()
			True

		.. note::

			This method is a **shared method** and can be called from the corresponding Emitters / Receivers.

		'''
		return self.synchronized

	def buildPacket(self,packet,timestamp):
		ts_sec = int(timestamp)
		ts_usec = int((timestamp - ts_sec)*1000000)
		pkt = self.SCAPY_LAYER(packet)
		pkt = BTLE_PPI(
			btle_channel=pkt.rf_channel,
			btle_clkn_high=ts_sec,
			btle_clk_100ns=ts_usec,
			rssi_max=0,
			rssi_min=0,
			rssi_avg=0,
			rssi_count=1) / pkt[BTLE:]
		return pkt

	def recv(self):
		packet = super().recv()
		if packet is not None:
			if self.sniffingMode == BLESniffingMode.ADVERTISEMENT:
				if BTLE_ADV in packet:
					if packet.AdvA.upper() == self.target or self.target == "FF:FF:FF:FF:FF:FF":
						return packet
			else:
				if BTLE_CONNECT_REQ in packet:
					aa = unpack(">I",pack("<I",packet.AA))[0]
					self._setAccessAddress(aa)
					self._setCrcInit(packet.crc_init)
					self._setChannelMap(packet.chM)
					self._setHopInterval(packet.interval)
					self._setHopIncrement(packet.hop)
					self.synchronized = True
					return packet

				if BTLE_CTRL in packet and packet.opcode == 0x02:
					if packet.access_addr == 0x8e89bed6:
						packet.access_addr= self.getAccessAddress()
					self._setAccessAddress(0x8e89bed6)
					self.synchronized = False
					return packet

				if BTLE_DATA in packet:
					if packet.access_addr == 0x8e89bed6:
						packet.access_addr= self.getAccessAddress()
					return packet
		else:
			self.synchronized = False

	def send(self,packet):
		if self.mode == "write":
			timestamp = int(packet.btle_clkn_high) + (packet.btle_clk_100ns/ 1000000)

			if self.sniffingMode == BLESniffingMode.ADVERTISEMENT:
				if BTLE_ADV not in packet or (hasattr(packet,"AdvA") and self.target != packet.AdvA.upper() and self.target != "FF:FF:FF:FF:FF:FF"):
					return

			else:

				if BTLE_CONNECT_REQ in packet:
					aa = unpack(">I",pack("<I",packet.AA))[0]
					self._setAccessAddress(aa)
					self._setCrcInit(packet.crc_init)
					self._setChannelMap(packet.chM)
					self._setHopInterval(packet.interval)
					self._setHopIncrement(packet.hop)

					self.synchronized = True

				if BTLE_DATA in packet:
					if packet.access_addr == 0x8e89bed6:
						packet.access_addr= self.getAccessAddress()


				if BTLE_CTRL in packet and packet.opcode == 0x02: # TERMINATE_IND
					self._setAccessAddress(0x8e89bed6)
					self.synchronized = False

			data = BTLE_RF(rf_channel = packet.btle_channel) / packet[BTLE:]
			self.putPacket(bytes(data),timestamp)
