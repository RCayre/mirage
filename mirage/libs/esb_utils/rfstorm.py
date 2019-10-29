from mirage.libs.esb_utils.constants import *
from mirage.libs.esb_utils.scapy_esb_layers import *
from mirage.libs import io,wireless
from threading import Lock
from fcntl import ioctl
import usb.core,usb.util
import struct
import queue
import array

class ESBRFStormDevice(wireless.Device):
	'''
	This device allows to communicate with a NRF24 Device using the RFStorm firmware from Bastille in order to sniff and inject Enhanced ShockBurst frames.
	The corresponding interfaces are : ``rfstormX`` (e.g. "rfstorm0")

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
	| SNIFFING_GENERIC_PROMISCUOUS      | yes            |
	+-----------------------------------+----------------+
	| ACTIVE_SCANNING                   | yes            |
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
		"enterGenericPromiscuousMode", 
		"enterSnifferMode", 
		"getMode", 
		"getAddress",
		"setAddress",
		"isAutoAckEnabled",
		"enableAutoAck",
		"disableAutoAck",
		"scan"
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
			ESBRFStormDevice.resetRFStorm(self.index)
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

	def _initESB(self):
		self.address = "00:00:00:00:00"
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

	def scan(self,channels=None):
		'''
		This method allows to launch an active scan in order to find the channel in use by the target device. This method can only be used in sniffer mode.
	
		:param channels: list of channels to scan
		:type channels: list of int
		:return: boolean indicating if the device has been found
		:rtype: bool
			

		:Example:

			>>> device.scan([1,2,3])
			False
			>>> device.scan()
			True

		.. note::

			This method is a **shared method** and can be called from the corresponding Emitters / Receivers.

		'''
		channels_sequence = channels if channels is not None else [i for i in range(100)]
		found = False
		self.lock.acquire()
		for i in channels_sequence:
			self._setChannel(i)
			if self._transmitPayload(b"\x0F\x0F\x0F\x0F", 1,1):
				found = True
				break
		self.lock.release()
		return found

	def enterPromiscuousMode(self,prefix=b""):
		'''
		This method allows to put your device into promiscuous mode. You can provide a specific prefix to match using the prefix parameter.

		:param prefix: bytes indicating the prefix to look for
		:type prefix: bytes

		.. note::

			This method is a **shared method** and can be called from the corresponding Emitters / Receivers.

		'''
		self.lock.acquire()
		self._enterPromiscuousMode(prefix=prefix)
		self.lock.release()
		self.mode = ESBOperationMode.PROMISCUOUS

	def enterSnifferMode(self,address):
		'''
		This method allows to put your device into sniffer mode. You have to provide an address to follow.

		:param address: address to follow as string (e.g. '11:22:33:44:55')
		:type address: str

		.. note::

			This method is a **shared method** and can be called from the corresponding Emitters / Receivers.

		'''
		self.address = address
		self.lock.acquire()
		self._enterSnifferMode(bytes.fromhex(address.replace(":",""))[::-1][:5])
		self.lock.release()
		self.mode = ESBOperationMode.SNIFFER

	def enterGenericPromiscuousMode(self,prefix=b"", rate=2000, payloadLength=32):
		'''
		This method allows to put your device into generic promiscuous mode. You can provide multiple parameters such as prefix, rate or payload length.

		:param prefix: bytes indicating the prefix to look for
		:type prefix: bytes
		:param rate: integer indicating the symbol rate to use (possible values: 250, 1000, 2000)
		:type rate: int
		:param payloadLength: maximal length to use
		:type payloadLength: int

		.. note::

			This method is a **shared method** and can be called from the corresponding Emitters / Receivers.

		'''
		if rate == 250:
			selectedRate = RF_RATE_250K
		elif rate == 1000:
			selectedRate = RF_RATE_1M
		else:
			selectedRate = RF_RATE_2M
		self.lock.acquire()
		self._enterPromiscuousModeGeneric(prefix=prefix,rate=selectedRate,payloadLength=payloadLength)
		self.lock.release()
		self.mode = ESBOperationMode.GENERIC_PROMISCUOUS


	def getAddress(self):
		'''
		This method returns the address actually in use (sniffer mode only).

		:return: address in use (e.g. '11:22:33:44:55')
		:rtype: str

		:Example:
			
			>>> device.getAddress()
			'11:22:33:44:55'

		.. note::

			This method is a **shared method** and can be called from the corresponding Emitters / Receivers.

		'''
		return self.address

	def setAddress(self, address):
		'''
		This method changes the address to use (sniffer mode only).

		:param address: address to use (e.g. '11:22:33:44:55')
		:type address: str

		:Example:
			
			>>> device.setAddress('11:22:33:44:55')

		.. note::

			This method is a **shared method** and can be called from the corresponding Emitters / Receivers.

		'''
		self.address = address
		if self.mode == ESBOperationMode.SNIFFER:
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

	def isAutoAckEnabled(self):
		'''
		This method returns a boolean indicating if the autoACK feature is enabled.
	
		:Example:
			
			>>> device.isAutoAckEnabled()
			False
			>>> device.enableAutoAck()
			>>> device.isAutoAckEnabled()
			True

		.. note::

			This method is a **shared method** and can be called from the corresponding Emitters / Receivers.

		'''
		return self.autoAck

	def enableAutoAck(self):
		'''
		This method enables the autoACK feature (an empty ACK frame will be transmitted every time a frame is received).

		:Example:
			
			>>> device.enableAutoAck()

		.. note::

			This method is a **shared method** and can be called from the corresponding Emitters / Receivers.

		'''
		self.autoAck = True

	def disableAutoAck(self):
		'''
		This method disables the autoACK feature (an empty ACK frame will be transmitted every time a frame is received).

		:Example:
			
			>>> device.disableAutoAck()

		.. note::

			This method is a **shared method** and can be called from the corresponding Emitters / Receivers.

		'''
		self.autoAck = False

	def getMode(self):
		'''
		This method returns the current mode in use (RFStorm device can be set in three modes: PROMISCUOUS, GENERIC_PROMISCUOUS, SNIFFER)

		:Example:
	
			>>> device.enterSnifferMode('AA:BB:CC:DD:EE')
			>>> device.getMode()
			'SNIFFER'

		.. note::

			This method is a **shared method** and can be called from the corresponding Emitters / Receivers.

		'''
		if self.mode == ESBOperationMode.PROMISCUOUS:
			return "PROMISCUOUS"
		elif self.mode == ESBOperationMode.GENERIC_PROMISCUOUS:
			return "GENERIC_PROMISCUOUS"
		else:
			return "SNIFFER"	


	def send(self,pkt):
		self.lock.acquire()
		if self.mode == ESBOperationMode.GENERIC_PROMISCUOUS:
			self._transmitPayloadGeneric(raw(pkt), address=bytes.fromhex(pkt.address.replace(":","")) if hasattr(pkt,"address") else b"\x33\x33\x33\x33\x33")

		elif self.mode == ESBOperationMode.PROMISCUOUS:
			self._enterSnifferMode(bytes.fromhex(pkt.address.replace(":",""))[::-1][:5])
			self._transmitPayload(raw(pkt[ESB_Payload_Hdr:]))
			self._enterPromiscuousMode()

		else:
			if pkt.no_ack == 1:
				if self.autoAck:
					self.ackTransmitQueue.put(raw(pkt[ESB_Payload_Hdr:]))
				else:
					self._transmitACKPayload(raw(pkt[ESB_Payload_Hdr:]))
			else:
				ack = self._transmitPayload(raw(pkt[ESB_Payload_Hdr:]))
				if ack:
					self.ackReceiveQueue.put((pkt.address))
		self.lock.release()

	def recv(self):
		self.lock.acquire()
		receivedData = bytes(self._receivePayload())
		if self.autoAck:
			if self.ackTransmitQueue.empty():
				self._transmitACKPayload(b"")
			else:
				self._transmitACKPayload(self.ackTransmitQueue.get())
		self.lock.release()

		if self.mode == ESBOperationMode.PROMISCUOUS and len(receivedData) >= 5:
			return ESB_Hdr(address=receivedData[:5])/ESB_Payload_Hdr(receivedData[5:])
		elif self.mode == ESBOperationMode.SNIFFER and receivedData[0] == 0 and receivedData != b"\xFF":
			return ESB_Hdr(address=self.address)/ESB_Payload_Hdr(receivedData[1:])
		elif self.mode == ESBOperationMode.GENERIC_PROMISCUOUS and len(receivedData) > 0:
			return ESB_Hdr(receivedData)
		else:
			if self.mode == ESBOperationMode.SNIFFER and not self.ackReceiveQueue.empty():
				return ESB_Hdr(address=self.ackReceiveQueue.get())/ESB_Payload_Hdr()/ESB_Ack_Response()
			return None

	def close(self):
		pass

	def isUp(self):
		return self.nrf24 is not None and self.ready

	def init(self):
		if self.nrf24 is not None:
			self.capabilities = ["INJECTING", "SNIFFING_NORMAL", "SNIFFING_PROMISCUOUS", "SNIFFING_GENERIC_PROMISCUOUS", "ACTIVE_SCANNING"]
			self.lock = Lock()
			self._enableLNA()
			self._initESB()
			self.ackReceiveQueue = queue.Queue()
			self.ackTransmitQueue = queue.Queue()
			self.autoAck = False
			self.ready = True
		else:
			self.ready = False
