from mirage.libs.esb_utils.constants import *
from mirage.libs.mosart_utils.constants import *
from mirage.libs.mosart_utils.helpers import *
from mirage.libs.mosart_utils.scapy_mosart_layers import *
from mirage.libs import io,wireless,utils
from threading import Lock
from fcntl import ioctl
import usb.core,usb.util
import struct
import queue
import array,time

class MosartRFStormDevice(wireless.Device):
	'''
	This device allows to communicate with a NRF24 Device using the RFStorm firmware from Bastille in order to sniff and inject Mosart frames.
	The corresponding interfaces are : ``rfstormX`` (e.g. "rfstorm0")

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
	| INJECTING_SYNC                    | yes            |
	+-----------------------------------+----------------+

	.. warning::

		The RFStorm firmware can be used with a crazyRadio PA Dongle or with a Logitech Unifying receiver.
		The firmware can be found `here <https://github.com/BastilleResearch/nrf-research-firmware>`.
		
	'''
	sharedMethods = [
		"setChannel", 
		"getChannel",
		"getDeviceIndex",
		"enterPromiscuousMode",
		"enterSnifferMode",
		"getAddress",
		"setAddress",
		"getMode",
		"enableDonglePackets",
		"disableDonglePackets",
		"enableSync",
		"disableSync"
		]


	@classmethod
	def resetRFStorm(cls, index=0):
		try:
			device = list(usb.core.find(idVendor=NRF24_ID_VENDOR,idProduct=NRF24_ID_PRODUCT,find_all=True)) [index]
			bus = str(device.bus).zfill(3)
			addr = str(device.address).zfill(3)
			filename = "/dev/bus/usb/"+bus+"/"+addr
			ioctl(open(filename,"w"),USBDEVFS_RESET,0)
			return True
		except (IOError,IndexError):
			io.fail("Unable to reset RFStorm device : #"+str(index))
			return False

	
	def __init__(self,interface):
		super().__init__(interface=interface)
		if "rfstorm" == interface:
			self.index = 0
			self.interface = "rfstorm0"
		else:
			self.index = int(interface.split("rfstorm")[1])	

		self.ready = False
		try:
			MosartRFStormDevice.resetRFStorm(self.index)
			self.nrf24 = list(usb.core.find(idVendor=NRF24_ID_VENDOR, idProduct=NRF24_ID_PRODUCT,find_all=True))[self.index]
			self.nrf24.set_configuration()
		except:
			io.fail("No RFStorm device found !")
			self.nrf24 = None

	def _sendUSBCommand(self,request,data=b""):
		data = [request] + list(data)
		self.nrf24.write(NRF24_COMMAND_ENDPOINT, data, timeout=2500)

	def _readUSBResponse(self,size=64,timeout=2500):
		return self.nrf24.read(NRF24_RESPONSE_ENDPOINT,size, timeout=timeout)


	def _enterPromiscuousMode(self,prefix=b""):
		self._sendUSBCommand(NRF24_ENTER_PROMISCUOUS_MODE,bytes([len(prefix)]) + prefix)
		self._readUSBResponse()
		
	def _enterPromiscuousModeGeneric(self,prefix=b"",rate=RF_RATE_2M,payloadLength=32):
		self._sendUSBCommand(NRF24_ENTER_PROMISCUOUS_MODE_GENERIC, bytes([len(prefix),rate, payloadLength]) + prefix)
		self._readUSBResponse()

	def _enterSnifferMode(self,address=b""):
		self._sendUSBCommand(NRF24_ENTER_SNIFFER_MODE, bytes([len(address)]) + address)
		self._readUSBResponse()

	def _enterToneTestMode(self):
		self._sendUSBCommand(NRF24_ENTER_TONE_TEST_MODE)
		self._readUSBResponse()

	def _receivePayload(self):
		self._sendUSBCommand(NRF24_RECEIVE_PAYLOAD)
		return self._readUSBResponse()

	def _transmitPayloadGeneric(self,payload, address=b"\x33\x33\x33\x33\x33"):
		data = bytes([len(payload),len(address)]) + payload + address
		self._sendUSBCommand(NRF24_TRANSMIT_PAYLOAD_GENERIC, data)
		return self._readUSBResponse()[0] > 0

	def _transmitPayload(self,payload, timeout=4,retransmits=15):
		data = bytes([len(payload),timeout,retransmits]) + payload
		self._sendUSBCommand(NRF24_TRANSMIT_PAYLOAD, data)
		return self._readUSBResponse()[0] > 0

	def _transmitACKPayload(self,payload):
		data = bytes([len(payload)])+payload
		self._sendUSBCommand(NRF24_TRANSMIT_ACK_PAYLOAD,data)
		return self._readUSBResponse()[0] > 0

	def _setChannel(self,channel):
		channel = 125 if channel > 125 else channel
		channel = 0 if channel < 0 else channel
		self._sendUSBCommand(NRF24_SET_CHANNEL, bytes([channel]))
		return self._readUSBResponse()[0] == channel

	def _getChannel(self):
		self._sendUSBCommand(NRF24_GET_CHANNEL)
		return self._readUSBResponse()[0]

	def _enableLNA(self):
		self._sendUSBCommand(NRF24_ENABLE_LNA_PA)
		self._readUSBResponse()

	def _initMosart(self):
		self.address = "00:00:00:00"
		self.enterPromiscuousMode()

		
	def getDeviceIndex(self):
		'''
		This method returns the index of the current RFStorm device.

		:return: device's index
		:rtype: int

		:Example:
			
			>>> device.getDeviceIndex()
			0

		.. note::

			This method is a **shared method** and can be called from the corresponding Emitters / Receivers.


		'''
		return self.index


	def enterPromiscuousMode(self):
		'''
		This method allows to put your device into promiscuous mode.

		.. note::

			This method is a **shared method** and can be called from the corresponding Emitters / Receivers.

		'''
		self.lock.acquire()
		self._enterPromiscuousModeGeneric(prefix=b"\xAA\xAA",rate=RF_RATE_1M,payloadLength=14)
		self.lock.release()
		self.mode = MosartOperationMode.PROMISCUOUS

	def enterSnifferMode(self,address):
		'''
		This method allows to put your device into sniffer mode. You have to provide an address to follow.

		:param address: address to follow as string (e.g. '11:22:33:44')
		:type address: str

		.. note::

			This method is a **shared method** and can be called from the corresponding Emitters / Receivers.

		'''
		self.address = address
		self.lock.acquire()
		selectedAddress = bytes([i^0x5A for i in bytes.fromhex(address.replace(":",""))[:4]])
		self._enterPromiscuousModeGeneric(prefix=selectedAddress, rate=RF_RATE_1M, payloadLength = 8)
		self.lock.release()
		self.mode = MosartOperationMode.SNIFFER

	def getAddress(self):
		'''
		This method returns the address actually in use (sniffer mode only).

		:return: address in use (e.g. '11:22:33:44')
		:rtype: str

		:Example:
			
			>>> device.getAddress()
			'11:22:33:44'

		.. note::

			This method is a **shared method** and can be called from the corresponding Emitters / Receivers.

		'''
		return self.address

	def setAddress(self, address):
		'''
		This method changes the address to use (sniffer mode only).

		:param address: address to use (e.g. '11:22:33:44')
		:type address: str

		:Example:
			
			>>> device.setAddress('11:22:33:44')

		.. note::

			This method is a **shared method** and can be called from the corresponding Emitters / Receivers.

		'''
		self.address = address
		if self.mode == MosartOperationMode.SNIFFER:
			self.enterSnifferMode(address=address)

	def setChannel(self,channel):
		'''
		This method changes the channel actually in use by the provided channel.

		:param channel: new channel
		:type channel: int

		:Example:

			>>> device.getChannel()
			37
			>>> device.setChannel(channel=38)
			>>> device.getChannel()
			38

		.. note::

			This method is a **shared method** and can be called from the corresponding Emitters / Receivers.

		'''
		self.lock.acquire()
		self._setChannel(channel)
		self.lock.release()

	def getChannel(self):
		'''
		This method returns the channel actually in use.

		:return: channel in use
		:rtype: int

		:Example:
			
			>>> device.getChannel()
			37
			>>> device.setChannel(channel=38)
			>>> device.getChannel()
			38

		.. note::

			This method is a **shared method** and can be called from the corresponding Emitters / Receivers.

		'''
		self.lock.acquire()
		channel = self._getChannel()
		self.lock.release()
		return channel

	def getMode(self):
		'''
		This method returns the current mode in use (RFStorm device can be set in three modes: PROMISCUOUS, SNIFFER)

		:return: current mode in use
		:rtype: str

		:Example:
	
			>>> device.enterSnifferMode('AA:BB:CC:DD')
			>>> device.getMode()
			'SNIFFER'

		.. note::

			This method is a **shared method** and can be called from the corresponding Emitters / Receivers.

		'''
		if self.mode == MosartOperationMode.PROMISCUOUS:
			return "PROMISCUOUS"
		else:
			return "SNIFFER"

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

	def enableSync(self):
		'''
		This method enables the synchronization mode.
		The frames transmitted by a Mosart mouse or keyboard are synchronized with the synchronization packets transmitted by the dongle.
		If the synchronization mode is enabled, every transmitted frame will be synchronized using these packets.
		If the synchronization mode is disabled, every transmitted frame will be sent as soon as possible.

		:Example:

			>>> device.enableSync()

		.. note::

			This method is a **shared method** and can be called from the corresponding Emitters / Receivers.

		'''
		self.syncMode = True

	def disableSync(self):
		'''
		This method disables the synchronization mode.
		The frames transmitted by a Mosart mouse or keyboard are synchronized with the synchronization packets transmitted by the dongle.
		If the synchronization mode is enabled, every transmitted frame will be synchronized using these packets.
		If the synchronization mode is disabled, every transmitted frame will be sent as soon as possible.

		:Example:

			>>> device.enableSync()

		.. note::

			This method is a **shared method** and can be called from the corresponding Emitters / Receivers.

		'''
		self.syncMode = False

	def send(self,pkt):
		self.lock.acquire()

		if Mosart_Dongle_Sync_Packet not in pkt:
			crcBytes = struct.pack('H',crc(raw(pkt)[6:]))
		else:
			crcBytes = b""
		packet = bytes([i ^ 0x5A for i in (raw(pkt) + crcBytes + b"\xA5")])

		if self.syncMode:
			pay = b"\xFF"
			while b"\x4b\x78" not in pay:
				pay = bytes(self._receivePayload())
	
		self._transmitPayloadGeneric(packet[2:],b"\xAA\xAA")
		
		self.lock.release()

	def recv(self):
		self.lock.acquire()
		receivedData = bytes(self._receivePayload())
		self.lock.release()
		if receivedData is not None and len(receivedData) > 1:
			# Extract packet data
			receivedData = receivedData[:receivedData.find(b"\xFF")+1]

			# If we are receiving in sniffer mode ...
			if len(receivedData) > 0 and self.mode == MosartOperationMode.SNIFFER:
				# Dewhitening
				receivedData = bytes([i ^ 0x5A for i in receivedData])

				# If it's not a dongle packet ...
				if b"\x11\x22" not in receivedData:
					# Check the CRC
					calcCrc = struct.pack('H',crc(receivedData[4:-3]))
					if calcCrc == receivedData[-3:-1]:
						# feed the receiver's queue
						return Mosart_Hdr(b"\xF0\xF0"+receivedData)
				# if it's a dongle packet ...
				elif self.donglePackets:
					# feed the receiver's queue
					return Mosart_Hdr(b"\xF0\xF0"+receivedData)
			# If we are receiving in promiscuous mode ...
			elif len(receivedData) > 0 and self.mode == MosartOperationMode.PROMISCUOUS:
				# Dewhitening
				receivedData = bytes([i ^ 0x5A for i in receivedData])
				# If it's not a dongle packet
				if b"\x11\x22" not in receivedData:
					# Check the CRC and find the start of packet thanks to it
					calcCrc = 0
					while calcCrc != receivedData[-3:-1] and len(receivedData) != 0:
						receivedData = receivedData[1:]
						calcCrc = struct.pack('H',crc(receivedData[6:-3]))
					# If the CRC is valid and the frame length is different than zero ...
					if (len(receivedData) > 0 and calcCrc == receivedData[-3:-1]):
						# feed the receiver's queue
						return Mosart_Hdr(receivedData)
				# If it's a dongle packet ...
				elif self.donglePackets:
					# Extract the packet
					receivedData = receivedData[receivedData.find(b"\x11\x22")-6:]
					if len(receivedData) > 6:
						# feed the receiver's queue
						return Mosart_Hdr(receivedData)
				
	def close(self):
		pass

	def isUp(self):
		return self.nrf24 is not None and self.ready

	def init(self):
		if self.nrf24 is not None:
			self.capabilities = []
			self.lock = Lock()
			self._enableLNA()
			self.donglePackets = True
			self.syncMode = True
			self._initMosart()
			self.capabilities = ["SNIFFING_NORMAL","SNIFFING_PROMISCUOUS","INJECTING_SYNC","INJECTING"]
			self.ready = True
		else:
			self.ready = False
