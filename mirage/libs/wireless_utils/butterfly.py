from mirage.libs.wireless_utils.scapy_butterfly_layers import *
from mirage.libs import io,utils,wireless
from threading import Lock
from queue import Queue
import usb

# ButterRFly USB device Identifiers
BUTTERFLY_ID_VENDOR = 0x5A17
BUTTERFLY_ID_PRODUCT = 0x0000


class ButterflyDevice(wireless.Device):
	'''
	This device allows to communicate with a ButteRFly Device in order to sniff BLE, Zigbee or ESB.
	The corresponding interfaces are : ``butterflyX`` (e.g. "butterfly0")
	'''
	sharedMethods = [
		"getFirmwareVersion",
		"getDeviceIndex",
		"getController"
	]


	def _send(self,command):
		self.lock.acquire()
		data = list(raw(command))
		self.dongle.write(0x01, data)
		try:
			response = self.dongle.read(0x81,64)
		except usb.core.USBTimeoutError:
			response = b""
		self.lock.release()
		if len(response) >= 5 and raw(command)[3:5] == bytes(response)[3:5]:
			responsePacket = Butterfly_Message_Hdr(bytes(response))
			return responsePacket
		return None

	def _recv(self):
		self.lock.acquire()
		size = 0
		data = array('B',[0]*64)
		try:
			size = self.dongle.read(0x81,data,timeout=10)
		except usb.core.USBTimeoutError:
			pass
		self.lock.release()
		if size > 0:
			return Butterfly_Message_Hdr(bytes(data)[:size])
		return None

	def recv(self):
		pkt = self._recv()
		if pkt is not None:
			return pkt
		return None

	def close(self):
		if self.controller != "NONE":
			self.disableController()


	def _enterListening(self):
		self.isListening = True

	def _exitListening(self):
		self.isListening = False

	def _isListening(self):
		return self.isListening

	def _internalCommand(self,command):
		cmd = Butterfly_Message_Hdr()/Butterfly_Command_Hdr()/command
		rsp = None
		found = False
		rsp = None
		while rsp is None:
			rsp = self._send(cmd)
		return rsp

	def selectController(self,controller):
		if controller == "BLE":
			self.controller = controller
			rsp = self._internalCommand(Butterfly_Select_Controller_Command(controller=0x00))
			return rsp.status == 0x00
		return False

	def getController(self):
		'''
		This method returns the controller used by the current Butterfly device.

		:return: controller in use
		:rtype: str


		:Example:

			>>> device.getController()
			'BLE'

		.. note::

			This method is a **shared method** and can be called from the corresponding Emitters / Receivers.
		'''
		return self.controller

	def enableController(self):
		'''
		This method enables the current controller.
		'''
		self._internalCommand(Butterfly_Enable_Controller_Command())

	def disableController(self):
		'''
		This method disables the current controller.
		'''
		self._internalCommand(Butterfly_Disable_Controller_Command())

	def getFirmwareVersion(self):
		'''
		This method returns the firmware version of the current Butterfly device.

		:return: firmware version as a tuple of (major, minor)
		:rtype: tuple of (int,int)

		:Example:

			>>> device.getFirmwareVersion()
			(1,0)

		.. note::

			This method is a **shared method** and can be called from the corresponding Emitters / Receivers.

		'''
		version = self._internalCommand(Butterfly_Get_Version_Command())
		return (version.major,version.minor)

	def getDeviceIndex(self):
		'''
		This method returns the index of the current Butterfly device.

		:return: device's index
		:rtype: int

		:Example:

			>>> device.getDeviceIndex()
			0

		.. note::

			This method is a **shared method** and can be called from the corresponding Emitters / Receivers.

		'''
		return self.index

	def isUp(self):
		return self.dongle is not None


	def __init__(self,interface):
		super().__init__(interface=interface)
		if "butterfly" == interface:
			self.index = 0
			self.interface = "butterfly0"
		else:
			self.index = int(interface.split("butterfly")[1])

		self.ready = False
		try:
			self.dongle = list(usb.core.find(idVendor=BUTTERFLY_ID_VENDOR, idProduct=BUTTERFLY_ID_PRODUCT,find_all=True))[self.index]
			self.dongle.set_configuration()
			self.isListening = False
			self.controller = "NONE"
			self.directions = [False,False,False]
			self.lock = Lock()
			self.responsesQueue = Queue()

		except:
			io.fail("No ButteRFly device found !")
			self.dongle = None

	def init(self):
		if self.dongle is not None:
			self.capabilities = []
			self.ready = True
		else:
			self.ready = False
