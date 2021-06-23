from scapy.all import *
import struct
from mirage.libs.bt_utils.ubertooth import *
from mirage.libs.ble_utils.constants import *
from mirage.libs.ble_utils import helpers
from mirage.libs import utils,io,wireless


class BLEUbertoothDevice(BtUbertoothDevice):
	'''
	This device allows to communicate with an Ubertooth Device in order to sniff Bluetooth Low Energy protocol.
	The corresponding interfaces are : ``ubertoothX`` (e.g. "ubertooth0")

	The following capabilities are actually supported :

	+-----------------------------------+----------------+
	| Capability			    | Available ?    |
	+===================================+================+
	| SCANNING                          | yes            |
	+-----------------------------------+----------------+
	| ADVERTISING                       | no             |
	+-----------------------------------+----------------+
	| SNIFFING_ADVERTISEMENTS           | yes            |
	+-----------------------------------+----------------+
	| SNIFFING_NEW_CONNECTION           | yes            |
	+-----------------------------------+----------------+
	| SNIFFING_EXISTING_CONNECTION      | yes            |
	+-----------------------------------+----------------+
	| JAMMING_CONNECTIONS               | yes            |
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

	'''
	sharedMethods = [
				"getFirmwareVersion",
				"getDeviceIndex",
				"getMode",
				"getSerial",

				"setChannel",
				"setCRCChecking",
				"setScanInterval",
				"setScan",
				"setJamming",
				"isSynchronized",

				"getChannel",
				"getAccessAddress",
				"getCrcInit",
				"getChannelMap",
				"getHopInterval",
				"getHopIncrement",

				"setSweepingMode",

				"sniffNewConnections",
				"sniffExistingConnections",
				"sniffAdvertisements"
			]
	def _initBLE(self):
		self.jamming = False
		self.synchronized = False
		self.sweepingMode = False
		self.sniffingMode = None
		self.sweepingSequence = []
		self.sweepingThreadInstance = None
		self.scanThreadInstance = None
		self._stop()
		self.channel = 37
		self.accessAddress = None
		self.crcInit = None
		self.channelMap = None
		self.hopInterval = None
		self.hopIncrement = None

		self._setCRCChecking(False)

		self.setCRCChecking(enable=False)
		self.setScanInterval(seconds=2)
		self._resetClock()

		self._setJamMode(JAM_NONE)
		self._setModulation()

		self._start()
		self.capabilities = ["SCANNING", "SNIFFING_ADVERTISEMENTS", "SNIFFING_EXISTING_CONNECTION", "SNIFFING_NEW_CONNECTION","JAMMING_CONNECTIONS"]
		io.success("Ubertooth Device ("+self.interface+") successfully instanciated !")



	def _sweepingThread(self):
		for channel in self.sweepingSequence:
			if ((self.sniffingMode == BLESniffingMode.NEW_CONNECTION and not self.synchronized) or
			     self.sniffingMode == BLESniffingMode.ADVERTISEMENT):
				self.setChannel(channel=channel)
			utils.wait(seconds=0.1)

	def _startSweepingThread(self):
		self._stopSweepingThread()
		self.sweepingThreadInstance = wireless.StoppableThread(target=self._sweepingThread)
		self.sweepingThreadInstance.start()

	def _stopSweepingThread(self):
		if self.sweepingThreadInstance is not None:
			self.sweepingThreadInstance.stop()
			self.sweepingThreadInstance = None


	def setSweepingMode(self,enable=True,sequence=[37,38,39]):
		'''
		This method allows to enable or disable the Sweeping mode. It allows to provide a subset of advertising channels to monitor sequentially.

		:param enable: boolean indicating if the Sweeping mode is enabled.
		:type enable: bool
		:param sequence: sequence of channels to use
		:type sequence: list of int


		.. note::

			This method is a **shared method** and can be called from the corresponding Emitters / Receivers.

		'''
		self.sweepingMode = enable
		if enable:
			self.sweepingSequence = sequence
			self._startSweepingThread()
		else:
			self._stopSweepingThread()

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
		return self.synchronized and self.accessAddress is not None and self.crcInit is not None and self.channelMap is not None and self.hopIncrement is not None and self.hopInterval is not None

	def setJamming(self,enable=True):
		'''
		This method allows to enable or disable the jamming mode.

		:param enable: boolean indicating if the jamming mode must be enabled or disabled
		:type enable: bool

		:Example:

			>>> device.setJamming(enable=True) # jamming mode enabled
			>>> device.setJamming(enable=False) # jamming mode disabled

		.. note::

			This method is a **shared method** and can be called from the corresponding Emitters / Receivers.

		'''
		self.jamming = enable

	def _setAccessAddress(self,accessAddress=None):
		self.accessAddress = accessAddress

	def _setCrcInit(self,crcInit=None):
		self.crcInit = crcInit

	def _setChannelMap(self,channelMap=None):
		self.channelMap = channelMap

	def _setHopInterval(self,hopInterval=None):
		self.hopInterval = hopInterval

	def _getHopInterval(self):
		return self.hopInterval

	def _setHopIncrement(self,hopIncrement):
		self.hopIncrement = hopIncrement

	def _getHopIncrement(self):
		return self.hopIncrement

	def _getChannelMap(self):
		return self.channelMap

	def _getAccessAddress(self):
		return self.accessAddress

	def _getCrcInit(self):
		return self.crcInit

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

	def _updateAccessAddress(self,accessAddress=None):
		io.success("Access Address selected : "+"0x{:08x}".format(accessAddress))
		self._setAccessAddress(accessAddress)
		io.info("Recovering CRCInit ...")

	def _updateCrcInit(self,crcInit=None):
		io.success("CRCInit successfully recovered : "+"0x{:06x}".format(crcInit))
		self._setCrcInit(crcInit)
		io.info("Recovering Channel Map ...")

	def _updateChannelMap(self,channelMap=None):
		channelMap = 0x1fffffffff
		io.info("Ubertooth can only sniff connections with channel map : "+"0x{:10x}".format(channelMap))
		io.success("Channel Map successfully updated : "+"0x{:10x}".format(channelMap))
		self._setChannelMap(channelMap)
		io.info("Recovering Hop Interval ...")

	def _updateHopInterval(self,hopInterval=None):
		io.success("Hop Interval successfully recovered : "+str(hopInterval))
		self._setHopInterval(hopInterval)
		io.info("Recovering Hop Increment ...")

	def _updateHopIncrement(self,hopIncrement=None):
		io.success("Hop Increment successfully recovered : "+str(hopIncrement))
		self._setHopIncrement(hopIncrement)
		io.info("All parameters recovered, following connection ...")

	def stop(self):
		super()._stop()
		self.ubertooth.close()

	def init(self):
		self.initializeBluetooth = False
		self.sniffingMode = BLESniffingMode.EXISTING_CONNECTION

		super().init()
		if self.ubertooth is not None:
			self._initBLE()
			self.ready = True

	def setCRCChecking(self,enable=True):
		'''
		This method enables CRC Checking.

		:param enable: boolean indicating if CRC Checking must be enabled
		:type enable: bool

		:Example:

			>>> device.setCRCChecking(enable=True) # CRC Checking enabled
			>>> device.setCRCChecking(enable=False) # CRC Checking disabled

		.. note::

			This method is a **shared method** and can be called from the corresponding Emitters / Receivers.

		'''
		self.crcEnabled = enable

	def getSerial(self):
		'''
		This method allows to get the device's serial number.

		:return: device's serial number
		:rtype: str

		:Example:

			>>> device.getSerial()
			'1160010b201835ae6d474553-79e1ff0b'

		.. note::

			This method is a **shared method** and can be called from the corresponding Emitters / Receivers.

		'''
		self.lock.acquire()
		serial = self._getSerial()
		self.lock.release()
		return serial

	def getMode(self):
		'''
		This method returns the mode actually in use in the current Ubertooth Device ("Bt" or "BLE")

		:return: string indicating the mode
		:rtype: str

		:Example:

			>>> device.getMode()
			"BLE"

		.. note::

			This method is a **shared method** and can be called from the corresponding Emitters / Receivers.

		'''
		return "BLE"

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
		return self.channel

	def setChannel(self, channel=37):
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
		if channel is not None and channel != self.channel:
			frequency = helpers.channelToFrequency(channel)
			self.channel = channel
			self.lock.acquire()
			self._stop()
			self._setFrequency(frequency)
			self._start()
			self.lock.release()

	def restartSniffingMode(self):
		'''
		This method restarts the sniffing mode.

		:Example:

			>>> device.restartSniffingMode()

		.. note::

			This method is a **shared method** and can be called from the corresponding Emitters / Receivers.


		'''
		if self.sniffingMode == BLESniffingMode.NEW_CONNECTION:
			self.sniffNewConnections()
		else:
			self.sniffExistingConnections()

	def sniffAdvertisements(self,address="00:00:00:00:00:00",channel=None):
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

		.. note::

			This method is a **shared method** and can be called from the corresponding Emitters / Receivers.

		'''
		self.sniffingMode = BLESniffingMode.ADVERTISEMENT
		self.synchronized = False
		self.lock.acquire()
		self._stop()
		self._setTarget(address)
		self._setCRCChecking(True)
		self.setCRCChecking(True)
		self._start()
		self.lock.release()
		if channel is None:
			channel = 37
		if not self.sweepingMode:
			self.setChannel(channel)

	def sniffNewConnections(self,address="00:00:00:00:00:00",channel=None):
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

		.. note::

			This method is a **shared method** and can be called from the corresponding Emitters / Receivers.

		'''
		self.sniffingMode = BLESniffingMode.NEW_CONNECTION
		self.synchronized = False
		self.lock.acquire()
		self._stop()
		if self.jamming:
			self._setJamMode(JAM_CONTINUOUS)
		else:
			self._setJamMode(JAM_NONE)
		self._setTarget(address)
		self._setCRCChecking(False)
		self._start()
		self.lock.release()
		if channel is None:
			channel = 37
		if not self.sweepingMode:
			self.setChannel(channel)


	def sniffExistingConnections(self,accessAddress=None,crcInit=None,channelMap=None):
		'''
		This method starts the existing connections sniffing mode.

		:param accessAddress: selected Access Address - if not provided, the parameter is recovered
		:type address: int
		:param crcInit: selected CRCInit - if not provided, the parameter is recovered
		:type crcInit: int
		:param channelMap: selected Channel Map - if not provided, the parameter is recovered
		:type channelMap: int


		:Example:

			>>> device.sniffExistingConnections()
			>>> device.sniffExistingConnections(accessAddress=0xe5e296e9)
			>>> device.sniffAdvertisements(accessAddress=0xe5e296e9, crcInit=0x0bd54a)
			>>> device.sniffAdvertisements(accessAddress=0xe5e296e9, crcInit=0x0bd54a, channelMap=0x1fffffffff)

		.. warning::
			Please note the following warnings :

			  * Ubertooth is actually not able to set CRC Init value and uses a full Channel Map (0x1fffffffff). This parameters are provided in order to provide the same API for Ubertooth and BTLEJack devices.
			  * If no access address is provided, Ubertooth tries to get multiple candidate access addresses and select the most probable address

		.. note::

			This method is a **shared method** and can be called from the corresponding Emitters / Receivers.

		'''

		self.sniffingMode = BLESniffingMode.EXISTING_CONNECTION
		self.synchronized = False
		self.lock.acquire()
		self._stop()
		if self.jamming:
			self._setJamMode(JAM_CONTINUOUS)
		else:
			self._setJamMode(JAM_NONE)
		self._setCRCChecking(False)

		if accessAddress is not None:
			self._setAccessAddress(accessAddress)
		else:
			self._setTarget("00:00:00:00:00:00")
		if crcInit is not None:
			io.warning("Ubertooth is not able to set CrcInit value ! Parameter will be ignored.")
		if channelMap is not None:
			io.warning("Ubertooth uses full channel map : 0x1fffffffff. Parameter will be ignored.")
		self._start()

		self.lock.release()


	def _start(self):
		if self.sniffingMode == BLESniffingMode.EXISTING_CONNECTION:
			self._setPromiscuousMode()
		elif self.sniffingMode == BLESniffingMode.NEW_CONNECTION:
			self._setBTLESniffing()
		elif self.sniffingMode == BLESniffingMode.ADVERTISEMENT:
			self._setBTLESniffing()

	def setScanInterval(self,seconds=1):
		'''
		This method allows to provide the scan interval (in second).

		:param seconds: number of seconds to wait between two channels
		:type seconds: float

		:Example:

			>>> device.setScanInterval(seconds=1)

		.. note::

			This method is a **shared method** and can be called from the corresponding Emitters / Receivers.


		'''
		self.scanInterval = seconds

	def _scanThread(self):
		self.setChannel(37)
		utils.wait(seconds=self.scanInterval)
		self.setChannel(38)
		utils.wait(seconds=self.scanInterval)
		self.setChannel(39)
		utils.wait(seconds=self.scanInterval)

	def setScan(self,enable=True):
		'''
		This method enables or disables the scanning mode. It allows to change the channel according to the scan interval parameter.

		:param enable: boolean indicating if the scanning mode must be enabled
		:type enable: bool

		:Example:

			>>> device.setScan(enable=True) # scanning mode enabled
 			>>> device.setScan(enable=False) # scanning mode disabled

		.. note::

			This method is a **shared method** and can be called from the corresponding Emitters / Receivers.

		'''
		if enable:
			self.sniffAdvertisements()
			self._setCRCChecking(True)
			if self.scanThreadInstance is None:
				self.scanThreadInstance = wireless.StoppableThread(target=self._scanThread)
				self.scanThreadInstance.start()
		else:
			self.scanThreadInstance.stop()
			self.scanThreadInstance = None

	def recv(self):
		self.lock.acquire()
		data = self._poll()
		self.lock.release()
		if data is not None and len(data) > 1:
			#print(bytes(data).hex())
			packet = Ubertooth_Hdr(bytes(data))

			if BTLE_Promiscuous_Access_Address in packet:
				self._updateAccessAddress(packet.access_address)
			elif BTLE_Promiscuous_CRCInit in packet:
				self._updateCrcInit(packet.crc_init)
				self._updateChannelMap()
			elif BTLE_Promiscuous_Hop_Interval in packet:
				self._updateHopInterval(packet.hop_interval)
			elif BTLE_Promiscuous_Hop_Increment in packet:
				self._updateHopIncrement(packet.hop_increment)
				self.synchronized = True
			else:
				if BTLE_CONNECT_REQ in packet or hasattr(packet,"PDU_type") and packet.PDU_type == 5:
					self._stopSweepingThread()
					self.accessAddress = (struct.unpack(">I",struct.pack("<I",packet.AA))[0])
					self.crcInit = (struct.unpack(">I",b"\x00" + struct.pack('<I',packet.crc_init)[:3])[0])
					self.channelMap = (packet.chM)
					self.hopInterval = (packet.interval)
					self.hopIncrement = (packet.hop)
					self.synchronized = True
				payload = bytes(packet[1:])[4:-3]
				givenCrc = bytes(packet[1:])[-3:]
				if helpers.crc24(payload,len(payload)) == givenCrc or not self.crcEnabled:
					return packet
			return None
		else:
			return None



	def _setJamMode(self,mode=JAM_NONE):
		self.ubertooth.ctrl_transfer(CTRL_OUT,UBERTOOTH_JAM_MODE,mode, 0)

	def _setFrequency(self,channel=2402):
		self.ubertooth.ctrl_transfer(CTRL_OUT, UBERTOOTH_SET_CHANNEL, channel, 0)

	def _getFrequency(self):
		channel = self.ubertooth.ctrl_transfer(CTRL_IN,UBERTOOTH_GET_CHANNEL,0, 0,2)
		channel = struct.unpack('H',channel)[0]
		return channel

	def _getAccessAddress(self):
		aa = self.ubertooth.ctrl_transfer(CTRL_IN,UBERTOOTH_GET_ACCESS_ADDRESS,0, 0,4)
		aa = struct.unpack('<I',aa)[0]
		return aa

	def _setAccessAddress(self,aa):
		data = array.array("B", [ (aa & 0xFF) ,(aa & 0x0000FF00) >> 8, (aa & 0x00FF0000) >> 16, (aa & 0xFF000000) >> 24])
		self.ubertooth.ctrl_transfer(CTRL_OUT,UBERTOOTH_SET_ACCESS_ADDRESS,0,0, data,timeout=3000)

	def _setTarget(self,target="00:00:00:00:00:00"):
		utils.wait(seconds=1)
		data = array.array("B", bytes.fromhex(target.replace(":",""))+bytes(0x30))
		self.ubertooth.ctrl_transfer(CTRL_OUT,UBERTOOTH_BTLE_SET_TARGET,0,0, data,timeout=5000)

	def _setBTLESniffing(self):
		utils.wait(seconds=0.5)
		self.ubertooth.ctrl_transfer(CTRL_OUT,UBERTOOTH_BTLE_SNIFFING,
						(0 if self.sniffingMode == BLESniffingMode.ADVERTISEMENT else 2), 0)

	def _setPromiscuousMode(self):
		utils.wait(seconds=0.5)
		self.ubertooth.ctrl_transfer(CTRL_OUT,UBERTOOTH_BTLE_PROMISC,0, 0)

	def _poll(self):
		try:
			result = self.ubertooth.ctrl_transfer(CTRL_IN,UBERTOOTH_POLL,0, 0,512,timeout=100)
			utils.wait(seconds=0.001)
		except usb.core.USBError as e:
			#io.fail("USB Error : "+str(e))
			return array.array('B',[])
		return result
