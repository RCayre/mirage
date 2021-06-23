from serial import Serial,SerialException
from serial.tools.list_ports import comports
from threading import Lock
from queue import Queue
import time,random,struct
from base64 import b64encode, b64decode
from binascii import Error as BAError
from mirage.libs.ble_utils.constants import *
from mirage.libs.ble_utils.scapy_sniffle_layers import *
from mirage.libs import io,utils,wireless

class SniffleDevice(wireless.Device):
	'''
	This device allows to communicate with a Sniffle Device in order to sniff Bluetooth Low Energy protocol.
	The corresponding interfaces are : ``sniffleX`` (e.g. "sniffle0")

	The following capabilities are actually supported :

	+-------------------------------------------+----------------+
	| Capability                                | Available ?    |
	+===========================================+================+
	| SCANNING                                  | yes            |
	+-------------------------------------------+----------------+
	| ADVERTISING                               | yes            |
	+-------------------------------------------+----------------+
	| SNIFFING_ADVERTISEMENTS                   | yes            |
	+-------------------------------------------+----------------+
	| SNIFFING_NEW_CONNECTION                   | yes            |
	+-------------------------------------------+----------------+
	| SNIFFING_EXISTING_CONNECTION              | no             |
	+-------------------------------------------+----------------+
	| JAMMING_CONNECTIONS                       | no             |
	+-------------------------------------------+----------------+
	| JAMMING_ADVERTISEMENTS                    | no             |
	+-------------------------------------------+----------------+
	| INJECTING                                 | no             |
	+-------------------------------------------+----------------+
	| MITMING_EXISTING_CONNECTION               | no             |
	+-------------------------------------------+----------------+
	| HIJACKING_MASTER                          | no             |
	+-------------------------------------------+----------------+
	| HIJACKING_SLAVE                           | no             |
	+-------------------------------------------+----------------+
	| INITIATING_CONNECTION                     | yes            |
	+-------------------------------------------+----------------+
	| RECEIVING_CONNECTION                      | no             |
	+-------------------------------------------+----------------+
	| COMMUNICATING_AS_MASTER                   | yes            |
	+-------------------------------------------+----------------+
	| COMMUNICATING_AS_SLAVE                    | no             |
	+-------------------------------------------+----------------+
	| HCI_MONITORING                            | no             |
	+-------------------------------------------+----------------+

	'''
	sharedMethods = [
			"getFirmwareVersion",
			"getDeviceIndex",
			"setCRCChecking",

			"setChannel",
			"getChannel",

			"getConnections",
			"switchConnection",
			"getCurrentConnection",
			"getCurrentHandle",
			"isConnected",
			"updateConnectionParameters",

			"setAddress",
			"getAddress",
			"setAdvertising",
			"setAdvertisingParameters",
			"setScanningParameters",


			"sniffNewConnections",
			"sniffAdvertisements",

			"setSweepingMode",

			"setScan",
			"setScanInterval",
			"isSynchronized",

			"getAccessAddress",
			"getCrcInit",
			"getChannelMap",
			"getHopInterval",
			"getHopIncrement",
			]
	@classmethod
	def findSniffleSniffers(cls,index=None):
		'''
		This class method allows to find a specific Sniffle device, by providing the device's index.
		If no index is provided, it returns a list of every devices found.
		If no device has been found, None is returned.

		:param index: device's index
		:type index: int
		:return: string indicating the device
		:rtype: str

		:Example:

			>>> NRFSnifferDevice.findSniffleSniffers(0)
			'/dev/ttyACM0'
			>>> NRFSnifferDevice.findSniffleSniffers()
			['/dev/ttyACM0','/dev/ttyACM1']
		'''
		sniffleList = sorted([i[0] for i in comports() if
				(isinstance(i,tuple) and "VID:PID=0451:BEF3" in port[-1]) or
				(i.vid == 0x0451 and i.pid == 0xBEF3)
				])
		if index is None:
			return sniffleList
		else:
			try:
				sniffle = sniffleList[index]

			except IndexError:
				return None
			return sniffle
		return None

	def isUp(self):
		return self.sniffle is not None and self.ready

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


	def _sendCommand(self,command):
		cmd = SniffleCommand()/command
		#cmd.show()
		size = (len(bytes(cmd)) + 3) // 3
		uartCommand = b64encode(bytes([size]) + bytes(cmd))

		self.lock.acquire()
		self.sniffle.write(uartCommand+b"\r\n")
		self.lock.release()


	def _setPauseWhenDone(self, enabled=False):
		command = SnifflePauseWhenDoneCommand(pause_when_done=1 if enabled else 0)
		self._sendCommand(command)

	def _initCommand(self):
		self.sniffle.write(b'@@@@@@@@\r\n')

	def _setConfiguration(self,channel = 37, accessAddress = 0x8E89BED6, phyMode = "1M",  crcInit=0x555555):
		self.channel = channel
		command = SniffleSetConfigurationCommand(channel=channel, access_address=accessAddress,phy_mode=phyMode, crc_init=crcInit)
		self._sendCommand(command)

	def _setMACFilter(self,mac=None):
		if mac is None or mac.upper() == "FF:FF:FF:FF:FF:FF":
			pkt = SniffleDisableMACFilterCommand()
		else:
			pkt = SniffleEnableMACFilterCommand(address=mac)
		self._sendCommand(pkt)

	def _enableHop(self):
		command = SniffleEnableAdvertisementsHoppingCommand()
		self._sendCommand(command)

	def _reset(self):
		command = SniffleResetCommand()
		self._sendCommand(command)

	def _setAddress(self,address,addressType='public'):
		command = SniffleSetAddressCommand(address=address, address_type=addressType)
		self._sendCommand(command)

	def _setAdvertisingInterval(self,interval=200):
		command = SniffleAdvertiseIntervalCommand(interval=interval)
		self._sendCommand(command)

	def _advertise(self,advertisingData=b"",scanRspData=b""):
		command = SniffleAdvertiseCommand(adv_data=advertisingData,scan_resp_data=scanRspData)
		self._sendCommand(command)

	def _setFilter(self,advertisementsOnly=False):
		command = SniffleFollowCommand(follow="advertisements_only" if advertisementsOnly else "all")
		self._sendCommand(command)

	def _sendConnectionRequest(self, address="00:00:00:00:00:00", addressType="public"):
		accessAddress = random.randint(0,(2**32)-1)
		crcInit = random.randint(0,(2**24)-1)
		channelMap = 0x1fffffffff
		hopIncrement = 5
		hopInterval = 24
		command = SniffleConnectCommand(
											address_type=0x00 if addressType == "public" else 0x01,
											address=address,
											AA=accessAddress,
											crc_init=crcInit,
											win_size=3,
											win_offset=random.randint(5,15),
											interval=hopInterval,
											latency=1,
											timeout=50,
 											chM=channelMap,
											SCA=0,
											hop=hopIncrement
		)
		self._setAccessAddress(accessAddress)
		self._setCrcInit(crcInit)
		self._setChannelMap(channelMap)
		self._setHopInterval(hopInterval)
		self._setHopIncrement(hopIncrement)

		self._sendCommand(command)

	def _initiateConnection(self, address="00:00:00:00:00:00", addressType="public"):
		self._reset()
		self._setConfiguration(channel = 37, accessAddress = 0x8E89BED6, phyMode = "1M",  crcInit=0x555555)
		self._setPauseWhenDone(True)
		self._setFilter(advertisementsOnly=True)
		self._setMACFilter(mac=None)
		self._setAddress(address=self.address,addressType=0x01 if self.addressType == "random" else 0x00)
		self._sendConnectionRequest(address,addressType)
	def _flush(self):
		self.lock.acquire()
		self.sniffle.flush()
		self.lock.release()

	def _transmit(self,pkt):
		command = SniffleTransmitCommand(ble_payload=pkt[BTLE_DATA:])
		self._sendCommand(command)


	def _enterListening(self):
		self.isListening = True

	def _exitListening(self):
		self.isListening = False

	def _isListening(self):
		return self.isListening

	def isConnected(self):
		'''
		This method returns a boolean indicating if the device is connected.

		:return: boolean indicating if the device is connected
		:rtype: bool

		:Example:
					>>> device.isConnected()
					True

		.. note::

			This method is a **shared method** and can be called from the corresponding Emitters / Receivers.

		'''
		return self.connected


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


	def getDeviceIndex(self):
		'''
		This method returns the index of the current Sniffle device.

		:return: device's index
		:rtype: int

		:Example:

			>>> device.getDeviceIndex()
			0

		.. note::

			This method is a **shared method** and can be called from the corresponding Emitters / Receivers.


		'''
		return self.index


	def getFirmwareVersion(self):
		'''
		This method returns the firmware version of the current Sniffle device.

		:return: firmware version
		:rtype: int

		:Example:

			>>> device.getFirmwareVersion()
			(1,5)

		.. note::

			This method is a **shared method** and can be called from the corresponding Emitters / Receivers.


		'''
		version = (1,5)
		return version


	def setCRCChecking(self,enable=True):
		'''
		This method enables CRC Checking.

		:param enable: boolean indicating if CRC Checking must be enabled
		:type enable: bool

		:Example:

			>>> device.setCRCChecking(enable=True) # CRC Checking enabled
			>>> device.setCRCChecking(enable=False) # CRC Checking disabled

		.. warning::

			Sniffle calculates the CRC directly in the firmware, so this command is ignored. It is present in order to provide a similar API to Ubertooth.

		.. note::

			This method is a **shared method** and can be called from the corresponding Emitters / Receivers.

		'''
		self.crcEnabled = enable

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
			if self.scanThreadInstance is None:
				self.scanThreadInstance = wireless.StoppableThread(target=self._scanThread)
				self.scanThreadInstance.start()
		else:
			self.scanThreadInstance.stop()
			self.scanThreadInstance = None

	def getCurrentHandle(self):
		'''
		This method returns the connection Handle actually in use.
		If no connection is established, its value is equal to -1.

		:return: connection Handle
		:rtype: int

		.. warning::

			This method always returns 1, it allows to provides the same API as the HCI Device.

		.. note::

			This method is a **shared method** and can be called from the corresponding Emitters / Receivers.

		'''
		return 1

	def getConnections(self):
		'''
		This method returns a list of couple (connection handle / address) representing the connections actually established.
		A connection is described by a dictionary containing an handle and an access address : ``{"handle":1, "address":"0x12345678"}``

		:return: list of connections established
		:rtype: list of dict

		:Example:

			>>> device.getConnections()
			[{'handle':1, 'address':'0x12345678'}]

		.. warning::

			The connection handle is always 1, it allows to provides the same API as the HCI Device.

		.. note::

			This method is a **shared method** and can be called from the corresponding Emitters / Receivers.

		'''
		return [{"address":"0x{:08x}".format(self.accessAddress),"handle":1}]

	def getCurrentConnection(self):
		'''
		This method returns the access address associated to the current connection. If no connection is established, it returns None.

		:return: access address of the current connection
		:rtype: str

		:Example:

			>>> device.getCurrentConnection()
			'0x12345678'

		.. note::

			This method is a **shared method** and can be called from the corresponding Emitters / Receivers.

		'''
		return "0x{:08x}".format(self.accessAddress)

	def switchConnection(self,address):
		'''
		This method is provided in order to provide the same API as an HCI Device, it actually has no effects.

		.. note::

			This method is a **shared method** and can be called from the corresponding Emitters / Receivers.

		'''
		io.fail("Switching connection not allowed with Sniffle Device !")

	def close(self):
		self.lock.acquire()
		self.sniffle.close()
		self.sniffle = None
		self.lock.release()

	def setAdvertisingParameters(self,type = "ADV_IND",destAddr = "00:00:00:00:00:00",data = b"",intervalMin = 200, intervalMax = 210, daType='public', oaType='public'):
		'''
		This method sets advertising parameters according to the data provided.
		It will mainly be used by *ADV_IND-like* packets.

		:param type: type of advertisement (*available values :* "ADV_IND", "ADV_DIRECT_IND", "ADV_SCAN_IND", "ADV_NONCONN_IND", "ADV_DIRECT_IND_LOW")
		:type type: str
		:param destAddress: destination address (it will be used if needed)
		:type destAddress: str
		:param data: data included in the payload
		:type data: bytes
		:param intervalMin: minimal interval
		:type intervalMin: int
		:param intervalMax: maximal interval
		:type intervalMax: int
		:param daType: string indicating the destination address type ("public" or "random")
		:type daType: str
		:param oaType: string indicating the origin address type ("public" or "random")

		.. note::

			This method is a **shared method** and can be called from the corresponding Emitters / Receivers.

		'''
		if type == "ADV_IND":
			self.advType = ADV_IND
		elif type == "ADV_DIRECT_IND":
			self.advType = ADV_DIRECT_IND
		elif type == "ADV_SCAN_IND":
			self.advType = ADV_SCAN_IND
		elif type == "ADV_NONCONN_IND":
			self.advType = ADV_NONCONN_IND
		elif type == "ADV_DIRECT_IND_LOW":
			self.advType = ADV_DIRECT_IND_LOW
		else:
			io.fail("Advertisements type not recognized, using ADV_IND.")
			self.advType = ADV_IND
		self.destAddress = None if destAddr == "00:00:00:00:00:00" else destAddr
		advData = data
		self.advDataLength = len(data) if len(data) <= 31 else 31
		if isinstance(data,list):
			advData = b""
			for i in data:
				advData += bytes(i)
			data = advData
		if isinstance(data,bytes):
			advData = b""
			if len(data) > 31:
				advData = data[:31]
			else:
				advData = data+(31 - len(data))*b"\x00"

		self.advData = advData
		self.destAddressType = daType
		self.addressType = oaType
		self.intervalMin = intervalMin
		self.intervalMax = intervalMax

	def setScanningParameters(self, data=b""):
		'''
		This method sets scanning parameters according to the data provided.
		It will mainly be used by *SCAN_RESP* packets.

		:param data: data to use in *SCAN_RESP*
		:type data: bytes

		.. note::

			This method is a **shared method** and can be called from the corresponding Emitters / Receivers.

		'''
		self.scanDataLength = len(data) if len(data) <= 31 else 31
		advData = data
		if isinstance(data,list):
			advData = b""
			for i in data:
				advData += bytes(i)
			data = advData
		if isinstance(data,bytes):
			advData = b""
			if len(data) > 31:
				advData = data[:31]
			else:
				advData = data+(31 - len(data))*b"\x00"

		self.scanData = advData



	def _recv(self):
		self.lock.acquire()
		if self.sniffle is not None:
			try:
				self.receptionBuffer = self.sniffle.readline()
			except:
				self.receptionBuffer = b""
		self.lock.release()
		if self.receptionBuffer[-1:] == b"\n":
			try:
				data = b64decode(self.receptionBuffer.rstrip())
				return SniffleResponse(data)
			except:
				return None

	def recv(self):
		self._enterListening()
		pkt = self._recv()
		self._exitListening()
		timestamp = time.time()
		ts_sec = int(timestamp)
		ts_usec = int((timestamp - ts_sec)*1000000)
		if pkt is not None:
			if pkt.response_type == 0x10 and BTLE_DATA in pkt.ble_payload:
				pass

			packet = pkt.ble_payload if hasattr(pkt, "ble_payload") else None
			if packet is not None and BTLE_CONNECT_REQ in packet or hasattr(packet,"PDU_type") and packet.PDU_type == 5:
				self._setAccessAddress(struct.unpack(">I",struct.pack("<I",packet.AA))[0])
				self._setCrcInit(struct.unpack(">I",b"\x00" + struct.pack('<I',packet.crc_init)[:3])[0])
				self._setChannelMap(packet.chM)
				self._setHopInterval(packet.interval)
				self._setHopIncrement(packet.hop)
				self.synchronized = True
			if packet is not None and BTLE_DATA in packet and packet.LLID == 3 and packet.opcode == 0x02:
				self.synchronized = False
				self._setAccessAddress(None)
				self._setCrcInit(None)
				self._setChannelMap(None)
				self._setHopInterval(None)
				self._setHopIncrement(None)
			if pkt.response_type == 0x10 and hasattr(pkt, "ble_payload"):
				return BTLE_PPI(
						btle_channel=pkt.channel,
						btle_clkn_high=ts_sec,
						btle_clk_100ns=ts_usec,
						rssi_max=pkt.rssi,
						rssi_min=pkt.rssi,
						rssi_avg=pkt.rssi,
						rssi_count=1)/pkt.ble_payload
			elif pkt.response_type == 0x13:
				if pkt.state == 0x06: # "MASTER"
					self.connected = True
					io.info('Connection established !')
				elif self.connected:
					self.connected = False
					io.fail('Connection lost !')
					self._setAccessAddress(None)
					self._setCrcInit(None)
					self._setChannelMap(None)
					self._setHopInterval(None)
					self._setHopIncrement(None)
					return (BTLE_PPI(btle_channel=0,
					btle_clkn_high=ts_sec,
					btle_clk_100ns=ts_usec,
					rssi_max=0,
					rssi_min=0,
					rssi_avg=0,
					rssi_count=1)/BTLE_DATA()/BTLE_CTRL()/LL_TERMINATE_IND(code=0x24))

			else:
				pass
				#io.warning(" [DEBUG:"+str(timestamp)+"|"+(pkt.message.decode("latin-1") if hasattr(pkt,"message") else "?")+"]")

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
			if 37 not in sequence or 38 not in sequence or 39 not in sequence:
				io.warning("Sniffle doesn't support the sweeping mode with a subset of channels: all three advertising channels are selected.")
			self.sweepingSequence = [37,38,39]

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

		.. note::

			This method is a **shared method** and can be called from the corresponding Emitters / Receivers.

		'''

		self.sniffingMode = BLESniffingMode.ADVERTISEMENT
		self.lastTarget = address
		self._setFilter(advertisementsOnly=True)
		if self.sweepingMode:
			self._enableHop()
		else:
			if channel is None:
				channel = 37
			self._setConfiguration(channel = channel, accessAddress = 0x8E89BED6, phyMode = "1M",  crcInit=0x555555)
		if address.upper() == "FF:FF:FF:FF:FF:FF":
			self._setMACFilter(mac=None)
		else:
			self._setMACFilter(mac=address)


	def sniffNewConnections(self,address='FF:FF:FF:FF:FF:FF',channel=None):
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
		self.lastTarget = address
		self._setFilter(advertisementsOnly=False)
		if self.sweepingMode:
			self._enableHop()
		else:
			if channel is None:
				channel = 37
			self._setConfiguration(channel = channel, accessAddress = 0x8E89BED6, phyMode = "1M",  crcInit=0x555555)
		if address.upper() == "FF:FF:FF:FF:FF:FF":
			self._setMACFilter(mac=None)
		else:
			self._setMACFilter(mac=address)

	def updateConnectionParameters(self,minInterval=0, maxInterval=0, latency=0, timeout=0,minCe=0, maxCe=0xFFFF):
		'''
		This method allows to update connection parameters according to the data provided.
		It will mainly be used if an incoming BLEConnectionParameterUpdateRequest is received.

		:param minInterval: minimal interval
		:type minInterval: int
		:param maxInterval: maximal interval
		:type maxInterval: int
		:param latency: connection latency
		:type latency: int
		:param timeout: connection timeout
		:type timeout: int
		:param minCe: minimum connection event length
		:type minCe: int
		:param maxCe: maximum connection event length
		:type maxCe: int

		.. note::

			This method is a **shared method** and can be called from the corresponding Emitters / Receivers.

		'''
		pass


	def getAddressMode(self):
		'''
		This method returns the address mode currently in use.

		:return: address mode ("public" or "random")
		:rtype: str

		:Example:

			>>> device.getAddressMode()
			'public'

		.. note::

			This method is a **shared method** and can be called from the corresponding Emitters / Receivers.

		'''
		return self.addressType


	def setAddress(self,address,random=False):
		'''
		This method allows to modify the BD address and the BD address type of the device, if it is possible.

		:param address: new BD address
		:type address: str
		:param random: boolean indicating if the address is random
		:type random: bool
		:return: boolean indicating if the operation was successful
		:rtype: bool

		:Example:
			>>> device.setAddress("11:22:33:44:55:66")
			True

		.. note::

			This method is a **shared method** and can be called from the corresponding Emitters / Receivers.

		'''
		self.address = address.upper()
		self.addressType = "random" if random else "public"
		return True

	def getAddress(self):
		'''
		This method returns the actual BD address of the device.

		:return: str indicating the BD address
		:rtype: str

		:Example:

			>>> device.getAddress()
			'1A:2B:3C:4D:5E:6F'

		.. note::

			This method is a **shared method** and can be called from the corresponding Emitters / Receivers.

		'''
		return self.address.upper()


	def setAdvertising(self,enable=True):
		'''
		This method enables or disables the advertising mode.

		:param enable: boolean indicating if the advertising mode must be enabled
		:type enable: bool

		:Example:

			>>> device.setAdvertising(enable=True) # advertising mode enabled
			>>> device.setAdvertising(enable=False) # advertising mode disabled

		.. warning::
			Please note that if no advertising and scanning data has been provided before this function call, nothing will be advertised. You have to set the scanning Parameters and the advertising Parameters before calling this method.

		.. note::

			This method is a **shared method** and can be called from the corresponding Emitters / Receivers.

		'''
		if enable:
			self._setConfiguration(channel = 37, accessAddress = 0x8E89BED6, phyMode = "1M",  crcInit=0x555555)
			self._setPauseWhenDone(True)
			self._setFilter(advertisementsOnly=True)
			self._setMACFilter(mac=None)
			self._setAddress(address=self.address,addressType=0x01 if self.addressType == "random" else 0x00)
			self._setAdvertisingInterval(interval=self.intervalMin)
			self._advertise(bytes([self.advDataLength])+self.advData,bytes([self.scanDataLength])+self.scanData)
		else:
			self._reset()

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
			self._setConfiguration(channel = channel, accessAddress = 0x8E89BED6, phyMode = "1M",  crcInit=0x555555)

	def send(self,pkt):
		if BTLE_CONNECT_REQ in pkt: # demande de connexion
			self._initiateConnection(pkt.AdvA,("public" if pkt.RxAdd == 0 else "random" ))
		else:
			self._transmit(pkt)

	def init(self):
		if self.sniffle is not None:
			self.capabilities = ["SNIFFING_ADVERTISEMENTS", "SNIFFING_NEW_CONNECTION","SCANNING","ADVERTISING","COMMUNICATING_AS_MASTER","INITIATING_CONNECTION"]
			self.lastTarget = "FF:FF:FF:FF:FF:FF"
			self.lock = Lock()
			self.isListening = False
			self.crcEnabled = True
			self.receptionBuffer = b""
			self.packetCounter = 1
			self.synchronized = False
			self.scanMode = False
			self.connected = False
			self.sweepingMode = False
			self.sweepingSequence = []

			self.intervalMin = 200
			self.intervalMax = 210
			self.addressType = 'public'
			self.destAddressType = 'public'

			self.advData = b""
			self.advDataLength = 0
			self.scanData = b""
			self.scanDataLength = 0

			self.address = "11:22:33:44:55:66"
			self.destAddress = "FF:FF:FF:FF:FF:FF"

			self.sniffingMode = BLESniffingMode.NEW_CONNECTION
			version = self.getFirmwareVersion()
			io.success("Sniffle device "+("#"+str(self.index) if isinstance(self.index,int) else str(self.index))+
				   " successfully instantiated (firmware version : "+str(version[0])+"."+str(version[1])+")")
			self.channel = None
			self.setScanInterval(seconds=2)
			self.scanThreadInstance = None
			self._flush()
			self._reset()
			self.ready = True

	def __init__(self,interface):
		super().__init__(interface=interface)
		customPort = None
		if "sniffle" == interface:
			self.index = 0
			self.interface = "sniffle0"

		elif "sniffle" == interface[:7]:
			if ":" in interface:
				fields = interface.split(":")
				customPort = fields[1]
				self.index = customPort
			else:
				self.index = int(interface.split("sniffle")[1])
			self.interface = interface

		if customPort is None:
			self.sniffle = SniffleDevice.findSniffleSniffers(self.index)
		else:
			self.sniffle = customPort

		if self.sniffle is not None:
			try:
				self.sniffle = Serial(port = self.sniffle, baudrate=2000000, timeout=0.01)
				self.ready = False
			except SerialException:
				io.fail("Serial communication not ready !")
				self.ready = False
				self.nrfsniffer = None
		else:
			io.fail("No Sniffle Sniffer device found !")
			self.ready = False
