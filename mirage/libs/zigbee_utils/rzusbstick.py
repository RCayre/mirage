from scapy.all import *
from mirage.libs import wireless,io,utils
from mirage.libs.zigbee_utils.constants import *
from threading import Lock
from fcntl import ioctl
import usb.core, usb.util

class RZUSBStickDevice(wireless.Device):
	'''
	This device allows to communicate with a RZUSBstick in order to interact with the Zigbee protocol.
	The corresponding interfaces are : ``rzusbstickX`` (e.g. "rzusbstick0")
	
	The following capabilities are actually supported :

	+-----------------------------------+----------------+
	| Capability			    | Available ?    |
	+===================================+================+
	| SNIFFING                          | yes            |
	+-----------------------------------+----------------+
	| INJECTING                         | yes            |
	+-----------------------------------+----------------+
	| COMMUNICATING_AS_COORDINATOR      | yes            |
	+-----------------------------------+----------------+
	| COMMUNICATING_AS_ROUTER           | yes            |
	+-----------------------------------+----------------+
	| COMMUNICATING_AS_END_DEVICE       | yes            |
	+-----------------------------------+----------------+
	| JAMMING                           | yes            |
	+-----------------------------------+----------------+

	.. warning::

		Some features provided by this hardware seems unstable :
		  * A small amount of time is required to switch from TX to RX, so some frames may be missing
		  * The jamming feature seems to send a very short signal which is not strong and long enough to jam a Zigbee channel
	
		I'm not sure if the problem is linked to my hardware or if the Killerbee firmare is buggy.

	'''
	sharedMethods = [
			"getChannel",
			"setChannel",
			"enableJamming",
			"disableJamming",
			"getMode",
			"getFirmwareVersion",
			"getSerial", 
			"getDeviceIndex"
			]
	@classmethod
	def resetRZUSBStick(cls, index=0):
		try:
			device = list(usb.core.find(idVendor=RZUSBSTICK_ID_VENDOR,idProduct=RZUSBSTICK_ID_PRODUCT,find_all=True)) [index]
			bus = str(device.bus).zfill(3)
			addr = str(device.address).zfill(3)
			filename = "/dev/bus/usb/"+bus+"/"+addr
			ioctl(open(filename,"w"),USBDEVFS_RESET,0)
			return True
		except (IOError,IndexError):
			io.fail("Unable to reset RZUSBStick device : #"+str(index))
			return False

	def __init__(self,interface):
		super().__init__(interface=interface)
		if "rzusbstick" == interface:
			self.index = 0
			self.interface = "rzusbstick0"
		else:
			self.index = int(interface.split("rzusbstick")[1])	

		self.ready = False
		try:
			RZUSBStickDevice.resetRZUSBStick(self.index)
			self.rz = list(usb.core.find(idVendor=RZUSBSTICK_ID_VENDOR, idProduct=RZUSBSTICK_ID_PRODUCT,find_all=True))[self.index]
			self.rz.set_configuration()
		except:
			io.fail("No RZUSBStick device found !")
			self.rz = None

	def _readUSBResponse(self,timeout=200,packetData=False):
		return bytes(self.rz.read(RZ_PACKET_ENDPOINT if packetData else RZ_RESPONSE_ENDPOINT,self.rz.bMaxPacketSize0, timeout=timeout))

	def _sendUSBCommand(self,request,data=b""):
		data = [request] + list(data)
		self.rz.write(RZ_COMMAND_ENDPOINT, data, timeout=200)
		return self._readUSBResponse()[0] == RZ_RESP_SUCCESS

	def _sendPacket(self,packet):
		data = bytes(packet)
		if len(data) >= 1 and len(data) <= 125:
			data += b"\x00\x00" # FCS bytes
			return self._sendUSBCommand(RZ_INJECT_FRAME,bytes([len(data)])+data)
		return False

	def _readPacket(self):
		try:

			data = self._readUSBResponse(packetData=True)
			if data is not None and len(data) >= 1 and data[0] == RZ_AIRCAPTURE_DATA:
				length = data[1]
				rssi = 3*int(data[6])-91
				validCrc = (data[7] == 0x01)
				frame = data[9:]
				if len(frame) != length:
					while len(frame) != length-9:
						frame += self._readUSBResponse(packetData=True)
				linkQualityIndicator = frame[-1]
				packet = frame[:-1]
				return (self.channel,rssi,validCrc,linkQualityIndicator,Dot15d4(packet))
		except usb.core.USBError:
			return None

		

	def close(self):
		if self.streamEnabled:
			self._closeStream()
		self._disableAirCapture()

	def _enableJamming(self):
		self._sendUSBCommand(RZ_JAMMER_ON)

	def _disableJamming(self):
		self._sendUSBCommand(RZ_JAMMER_OFF)

	def _enableAirCapture(self):
		return self._sendUSBCommand(RZ_SET_MODE,[RZ_MODE_AIRCAPTURE])

	def _disableAirCapture(self):
		return self._sendUSBCommand(RZ_SET_MODE,[RZ_MODE_NONE])

	def _setChannel(self,channel=11):
		return self._sendUSBCommand(RZ_SET_CHANNEL,[channel])

	def _openStream(self):
		self.streamEnabled = True
		return self._sendUSBCommand(RZ_OPEN_STREAM)

	def _closeStream(self):
		self.streamEnabled = False
		return self._sendUSBCommand(RZ_CLOSE_STREAM)

	def init(self):
		if self.rz is not None:
			self.bus = self.rz.bus
			self.address = self.rz.address
			self.serialNumber = usb.util.get_string(self.rz, self.rz.iSerialNumber)
			self.firmwareVersion = usb.util.get_string(self.rz, self.rz.iProduct)

			if "KILLER" in self.firmwareVersion:
				self.capabilities = ["SNIFFING","INJECTING","JAMMING","COMMUNICATING_AS_COORDINATOR","COMMUNICATING_AS_ROUTER","COMMUNICATING_AS_END_DEVICE"]	
				io.info("RZUSBStick: Killerbee firmware in use.")
			else:
				self.capabilities = ["SNIFFING"]
				io.info("RZUSBStick: normal firmware in use, injection and jamming will not be enabled.")
			self.lock = Lock()
			conf.dot15d4_protocol = "zigbee"
			self._enableAirCapture()
			self.setChannel(11)
			self._openStream()
			self.mode = "NORMAL"
			self.ready = True


	def send(self,packet):

		reloadStream = False
		self.lock.acquire()
		if self.streamEnabled:
			self._closeStream()
		self._sendPacket(packet)
		self.lock.release()

	def recv(self):
		if self.mode == "NORMAL":
			self.lock.acquire()
			if not self.streamEnabled:
				self._openStream()
			data = self._readPacket()
			self.lock.release()
			if data is not None:
				return data
			else:
				return None

	def isUp(self):
		return self.rz is not None and self.ready

	def getMode(self):
		'''
		This method returns the current mode in use (RZUSBStick device can be set in two modes: NORMAL, JAMMING)

		:return: current mode in use
		:rtype: str

		:Example:
	
			>>> device.getMode()
			'NORMAL'
			>>> device.enableJamming()
			>>> device.getMode()
			'JAMMING'

		.. note::

			This method is a **shared method** and can be called from the corresponding Emitters / Receivers.

		'''
		return self.mode.upper()

	def getSerial(self):
		'''
		This method returns the serial number of the current RZUSBStick device.

		:return: device's serial number
		:rtype: str

		:Example:
			
			>>> device.getSerial()
			'FFFFFFFFFFFF'

		.. note::

			This method is a **shared method** and can be called from the corresponding Emitters / Receivers.


		'''
		return self.serialNumber[:-1].upper()

	def getFirmwareVersion(self):
		'''
		This method returns the firmware version of the current RZUSBStick device.

		:return: device's firmware version
		:rtype: str

		:Example:
			
			>>> device.getSerial()
			'KILLERB001'

		.. note::

			This method is a **shared method** and can be called from the corresponding Emitters / Receivers.


		'''
		return self.firmwareVersion


	def getDeviceIndex(self):
		'''
		This method returns the index of the current RZUSBStick device.

		:return: device's index
		:rtype: int

		:Example:
			
			>>> device.getDeviceIndex()
			0

		.. note::

			This method is a **shared method** and can be called from the corresponding Emitters / Receivers.


		'''
		return self.index

	def setChannel(self,channel):
		'''
		This method changes the channel actually in use by the provided channel.

		:param channel: new channel
		:type channel: int

		:Example:
			
			>>> device.getChannel()
			11
			>>> device.setChannel(15)
			>>> device.getChannel()
			15

		.. note::

			This method is a **shared method** and can be called from the corresponding Emitters / Receivers.

		'''
		self.lock.acquire()
		self._closeStream()
		self._setChannel(channel)
		self._openStream()
		self.channel = channel
		self.lock.release()

	def getChannel(self):
		'''
		This method returns the channel actually in use.

		:return: channel in use
		:rtype: int

		:Example:
			
			>>> device.getChannel()
			11
			>>> device.setChannel(15)
			>>> device.getChannel()
			15

		.. note::

			This method is a **shared method** and can be called from the corresponding Emitters / Receivers.

		'''
		return self.channel

	def enableJamming(self):
		'''
		This method enables the jamming mode of the current RZUSBStick device.

		:Example:
			
			>>> device.enableJamming()

		.. note::

			This method is a **shared method** and can be called from the corresponding Emitters / Receivers.

		'''
		self.lock.acquire()
		self._closeStream()
		self._setChannel(self.channel)
		self._enableJamming()
		self.mode = "JAMMING"
		self.lock.release()

	def disableJamming(self):
		'''
		This method disables the jamming mode of the current RZUSBStick device.

		:Example:
			
			>>> device.disableJamming()

		.. note::

			This method is a **shared method** and can be called from the corresponding Emitters / Receivers.

		'''

		self.lock.acquire()
		self._disableJamming()
		self.mode = "NORMAL"
		self.lock.release()

