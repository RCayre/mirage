from mirage.libs.bt_utils.scapy_ubertooth_layers import *
from mirage.libs import io,wireless,utils
from threading import Lock
import usb.core,usb.util,struct,array
from fcntl import ioctl

class BtUbertoothDevice(wireless.Device):
	'''
	This device allows to communicate with an Ubertooth Device in order to use Bluetooth protocol.
	The corresponding interfaces are : ``ubertoothX``  (e.g. "ubertooth0")

	.. warning::
		Please note that this implementation is actually incomplete in order to sniff the Bluetooth protocol. Actually, it can only be used in Bluetooth Low Energy mode (``mirage.libs.ble_utils.ubertooth.BLEUbertoothDevice``)

	'''
	@classmethod
	def resetUbertooth(cls,index=0):
		'''
		This class method allows to reset the Ubertooth, by providing the device's index.

		:param index: device's index
		:type index: int
		:return: boolean indicating if the reset operation was successful
		:rtype: bool

		:Example:
			
			>>> BtUbertoothDevice.resetUbertooth(0)
			True
		
		'''
		try:
			device = list(usb.core.find(idVendor=UBERTOOTH_ID_VENDOR,idProduct=UBERTOOTH_ID_PRODUCT,find_all=True))[index]
			bus = str(device.bus).zfill(3)
			addr = str(device.address).zfill(3)
			filename = "/dev/bus/usb/"+bus+"/"+addr
			
			ioctl(open(filename,"w"),USBDEVFS_RESET,0)
			device.ctrl_transfer(CTRL_OUT,UBERTOOTH_RESET,0, 0)
			utils.wait(seconds=1)

			return True

		except (IOError,IndexError):
			io.fail("Unable to reset ubertooth device : #"+str(index))
			
		return False

	def __init__(self,interface):
		super().__init__(interface=interface)
		self.initializeBluetooth = True

	def getMode(self):
		'''
		This method returns the mode actually in use in the current Ubertooth Device ("Bt" or "BLE")

		:return: string indicating the mode
		:rtype: str

		:Example:

			>>> device.getMode()
			"Bt"
	
		'''
		return "Bt"

	def _getModulation(self):
		modulation = self.ubertooth.ctrl_transfer(CTRL_IN,UBERTOOTH_GET_MOD,0, 0,1)
		modulation = struct.unpack('b',modulation)[0]
		return modulation

	def _setModulation(self,modulation=MOD_BT_LOW_ENERGY):
		self.ubertooth.ctrl_transfer(CTRL_OUT,UBERTOOTH_SET_MOD,modulation, 0)

	def _getSerial(self):
		serial = self.ubertooth.ctrl_transfer(CTRL_IN,UBERTOOTH_GET_SERIAL,0, 0,17)
		result = struct.unpack('B',serial[0:1])[0]
		serial = struct.unpack('>4i',serial[1:])
		serial = ''.join([format(i,'x') for i in serial])
		return serial

	def _setCRCChecking(self, enable=True):
		self.ubertooth.ctrl_transfer(CTRL_OUT,UBERTOOTH_SET_CRC_VERIFY,(1 if enable else 0), 0)

	def _resetClock(self):
		data = array.array("B", [0, 0, 0, 0, 0, 0])
		self.ubertooth.ctrl_transfer(CTRL_OUT,UBERTOOTH_SET_CLOCK,0,0,data)

	def _stop(self):
		self.ubertooth.ctrl_transfer(CTRL_OUT,UBERTOOTH_STOP,0, 0)

	def _reset(self):
		self.ubertooth.ctrl_transfer(CTRL_OUT,UBERTOOTH_RESET,0, 0)

	def close(self):
		try:
			self._stop()
			self._reset()
		except:
			pass

	def getFirmwareVersion(self):
		'''
		This method returns the firmware version in use in the current Ubertooth device.

		:return: firmware version
		:rtype: str

		:Example:
			
			>>> device.getFirmwareVersion()
			'1.6'

		'''
		return self.version

	def getDeviceIndex(self):
		'''
		This method returns the index of the current Ubertooth device.

		:return: device's index
		:rtype: int

		:Example:
			
			>>> device.getDeviceIndex()
			0

		'''
		return self.index

	def _initBT(self):
		pass

	def isUp(self):
		return self.ready


	def init(self):
		self.ready = False
		self.ubertooth = None
		if self.interface == "ubertooth":
			self.index = 0
		else:
			self.index = int(self.interface.split("ubertooth")[1])
		#try:
		BtUbertoothDevice.resetUbertooth(self.index)
		try:		
			self.ubertooth = list(
						usb.core.find(idVendor=UBERTOOTH_ID_VENDOR, idProduct=UBERTOOTH_ID_PRODUCT, find_all=True)
					 )[self.index]

			self.version = '{0:x}.{1:x}'.format((self.ubertooth.bcdDevice >> 8) & 0x0FF,self.ubertooth.bcdDevice & 0x0FF)
		except:
			self.ubertooth = None
		if self.ubertooth is not None:
			#self.ubertooth.default_timeout = 2000
			self.ubertooth.set_configuration()
			
			self.lock = Lock()
			if self.initializeBluetooth:
				self._initBT()
				self.ready = True
		#except:
			#self.ubertooth = None
