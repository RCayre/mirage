from serial import Serial,SerialException
from serial.tools.list_ports import comports
from threading import Lock
from queue import Queue
import time
from mirage.libs.ble_utils.constants import *
from mirage.libs.ble_utils.scapy_nrfsniffer_layers import *
from mirage.libs import io,utils,wireless

class NRFSnifferDevice(wireless.Device):
	'''
	This device allows to communicate with a NRFSniffer Device in order to sniff Bluetooth Low Energy protocol.
	The corresponding interfaces are : ``nrfsnifferX`` (e.g. "nrfsniffer0")

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

	'''
	sharedMethods = [
			"getFirmwareVersion",
			"getDeviceIndex",
			"setCRCChecking",

			"setChannel", 
			"getChannel",

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
	def findNRFSniffers(cls,index=None):
		'''
		This class method allows to find a specific NRFSniffer device, by providing the device's index. 
		If no index is provided, it returns a list of every devices found.
		If no device has been found, None is returned.

		:param index: device's index
		:type index: int
		:return: string indicating the device
		:rtype: str

		:Example:
			
			>>> NRFSnifferDevice.findNRFSniffers(0)
			'/dev/ttyACM0'
			>>> NRFSnifferDevice.findNRFSniffers()
			['/dev/ttyACM0','/dev/ttyACM1']
		'''
		devices = [i[0] for i in comports()]
		nrfsniffers = []
		for device in devices:
			attempts = 10
			while attempts > 0 and device not in nrfsniffers:
				try:
					ser = Serial(port = device, baudrate=460800, timeout=5)
					# Fingerprinting using Ping packet.
					# Looks dirty in my opinion but I don't find a most elegant way.		
					ser.write(b"\xab\x06\x00\x01\x00\x00\x0d\xbc")
					utils.wait(seconds=1)
					response = b""
					while ser.in_waiting:
						response += ser.read(1)
					if b"\x57\x04\xbc" in response:
						nrfsniffers.append(device)
				except:
					attempts -= 1
					utils.wait(seconds=1)
		if index is None:
			return nrfsniffers
		else:
			try:
				nrfsniffer = nrfsniffers[index]
			except IndexError:
				return None
			return nrfsniffer
		return None

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
		This method returns the index of the current NRFSniffer device.

		:return: device's index
		:rtype: int

		:Example:
			
			>>> device.getDeviceIndex()
			0

		.. note::

			This method is a **shared method** and can be called from the corresponding Emitters / Receivers.


		'''
		return self.index

	def _goIdle(self):
		pkt = self._internalCommand(NRFSniffer_Go_Idle(),noResponse=True)

	def _setChannels(self,channels=[37,38,39]):
		numberOfChannels = len(channels)
		channelsSequence = b""
		for channel in channels:
			channelsSequence += bytes([channel])
		pkt = self._internalCommand(NRFSniffer_Set_Advertising_Channels_Hopping_Sequence(number_of_channels=numberOfChannels,channels=channelsSequence),noResponse=True)

	def _setChannel(self,channel=37):
		self.channel = channel
		self._setChannels([channel])

	def setChannel(self,channel=37):
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
		self._setChannel(channel)

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

	def _setTemporaryKey(self,temporaryKey=b"\x00"*16):
		pkt = self._internalCommand(NRFSniffer_Set_Temporary_Key_Request(temporary_key=temporaryKey),noResponse=True)

	def _scanContinuously(self):
		pkt = self._internalCommand(NRFSniffer_Scan_Continuously_Request(),noResponse=True)

	def _followTarget(self,target,addrType="public",advertisementsOnly=False):
		self._setTemporaryKey()
		pkt = self._internalCommand(NRFSniffer_Follow_Request(addr=target,addr_type=addrType,follow_only_advertisements=advertisementsOnly),responseType=NRFSniffer_Event_Follow)

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
		if self.sweepingMode:
			self._setChannels(self.sweepingSequence)
		else:
			if channel is None:
				channel = 37
			self._setChannel(channel)
		if address.upper() == "FF:FF:FF:FF:FF:FF":
			self._scanContinuously()
		else:
			self._scanContinuously()
			while address.upper() not in self.targets:
				utils.wait(seconds=1)
			io.success("Target found :"+address.upper() + " [ "+self.targets[address.upper()]+" ]")
			self._followTarget(address,self.targets[address.upper()],advertisementsOnly=True)

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
		self.synchronized = False
		self.sniffingMode = BLESniffingMode.NEW_CONNECTION
		self.lastTarget = address
		if self.sweepingMode:
			self._setChannels(self.sweepingSequence)
		else:
			if channel is None:
				channel = 37
			self._setChannel(channel)
		if address.upper() == "FF:FF:FF:FF:FF:FF":
			io.fail("NRFSniffer requires to target a specific device in order to sniff a connection.")
		else:
			self._scanContinuously()
			while address.upper() not in self.targets:
				utils.wait(seconds=1)
			io.success("Target found :"+address.upper() + " [ "+self.targets[address.upper()]+" ]")
			self._followTarget(address,self.targets[address.upper()],advertisementsOnly=False)

	def _flush(self):
		self.lock.acquire()
		self.nrfsniffer.flush()
		self.lock.release()

	def __init__(self,interface):
		super().__init__(interface=interface)
		customPort = None
		if "nrfsniffer" == interface:
			self.index = 0
			self.interface = "nrfsniffer0"
		elif "nrfsniffer" == interface[:10]:
			if ":" in interface:
				fields = interface.split(":")
				customPort = fields[1]
				self.index = customPort
			else:
				self.index = int(interface.split("nrfsniffer")[1])
			self.interface = interface

		if customPort is None:
			self.nrfsniffer = NRFSnifferDevice.findNRFSniffers(self.index)
		else:
			self.nrfsniffer = customPort

		if self.nrfsniffer is not None:
			try:
				self.nrfsniffer = Serial(port = self.nrfsniffer, baudrate=460800, timeout=0)
				self.ready = False
			except SerialException:
				io.fail("Serial communication not ready !")
				self.ready = False
				self.nrfsniffer = None
		else:
			io.fail("No NRF Sniffer device found !")
			self.ready = False


	def _enterListening(self):
		self.isListening = True

	def _exitListening(self):
		self.isListening = False

	def _isListening(self):
		return self.isListening


	def close(self):
		self.lock.acquire()
		self.nrfsniffer.close()
		self.nrfsniffer = None
		self.lock.release()

	def isUp(self):
		return self.nrfsniffer is not None and self.ready

	def init(self):
		if self.nrfsniffer is not None:
			self.capabilities = ["SNIFFING_ADVERTISEMENTS", "SNIFFING_NEW_CONNECTION","SCANNING"]
			self.lastTarget = "FF:FF:FF:FF:FF:FF"
			self.lock = Lock()
			self._flush()
			self.isListening = False
			self.crcEnabled = True
			self.receptionBuffer = b""
			self.commandResponses = Queue()
			self.packetCounter = 1
			self.synchronized = False
			self.scanMode = False
			self.sweepingMode = False
			self.sweepingSequence = []
			self.sniffingMode = BLESniffingMode.NEW_CONNECTION
			version = self.getFirmwareVersion()
			io.success("NRFSniffer device "+("#"+str(self.index) if isinstance(self.index,int) else str(self.index))+
				   " successfully instantiated (firmware version : "+str(version)+")")
			self.channel = None
			self._goIdle()
			self.targets = {}
			self._setChannel(37)
			
			self.ready = True

	def _getFirmwareVersion(self):
		pkt = self._internalCommand(NRFSniffer_Ping_Request(),responseType=NRFSniffer_Ping_Response)
		return pkt.version

	def getFirmwareVersion(self):
		'''
		This method returns the firmware version of the current NRFSniffer device.

		:return: firmware version
		:rtype: int

		:Example:
			
			>>> device.getFirmwareVersion()
			1111

		.. note::

			This method is a **shared method** and can be called from the corresponding Emitters / Receivers.


		'''
		version = self._getFirmwareVersion()
		return version		

	def _internalCommand(self,cmd,noResponse=False,responseType=None):
		def getFunction():
			if not self._isListening() and self.commandResponses.empty():
				function = self._recv
			else:
				function = self.commandResponses.get
			return function
		packet = NRFSniffer_Hdr()/cmd
		self._send(packet)
		if not noResponse:

			getResponse = getFunction()
			response = getResponse()
			while response is None or (response is not None and ((NRFSniffer_Hdr()/responseType()).packet_type != response.packet_type)):
				getResponse = getFunction()
				response = getResponse()

			return response


	def _send(self,pkt):
		pkt.packet_counter = self.packetCounter
		self.packetCounter += 1
		encodedPkt = raw(pkt)
		self.nrfsniffer.write(encodedPkt)

	def _recv(self):
		self.lock.acquire()
		if self.nrfsniffer is not None and self.nrfsniffer.in_waiting:	
			self.receptionBuffer += self.nrfsniffer.read()
		self.lock.release()

		if len(self.receptionBuffer) > 0:
			try:
				start = self.receptionBuffer.index(SLIP_START)
				self.receptionBuffer = self.receptionBuffer[start:]

			except ValueError:
				self.receptionBuffer = b""

			if len(self.receptionBuffer) >= 8 and self.receptionBuffer[-1] == SLIP_END:
				sizeOfHeader = self.receptionBuffer[1]
				sizeOfPayload = self.receptionBuffer[2]
				if len(self.receptionBuffer[1:-1]) == sizeOfHeader + sizeOfPayload:
					packetData = self.receptionBuffer[1:-1]
					packetData = packetData.replace(bytes([SLIP_ESC,SLIP_ESC_ESC]),bytes([SLIP_ESC]))
					packetData = packetData.replace(bytes([SLIP_ESC,SLIP_ESC_START]),bytes([SLIP_START]))
					packetData = packetData.replace(bytes([SLIP_ESC,SLIP_ESC_END]),bytes([SLIP_END]))
					packet = NRFSniffer_Hdr(packetData)
					self.receptionBuffer = b""
					return packet
				else:
					self.receptionBuffer = b""
					return None

		return None

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

	def restartSniffingMode(self):
		'''
		This method restarts the sniffing mode.

		:Example:
	
			>>> device.restartSniffingMode()

		.. note::

			This method is a **shared method** and can be called from the corresponding Emitters / Receivers.


		'''
		if self.sniffingMode == BLESniffingMode.NEW_CONNECTION:
			self.sniffNewConnections(self.lastTarget,self.channel)
		else:
			self.sniffAdvertisements(self.lastTarget,self.channel)


	def setScanInterval(self,seconds=1):
		'''
		This method allows to provide the scan interval (in second).
	
		:param seconds: number of seconds to wait between two channels
		:type seconds: float

		:Example:

			>>> device.setScanInterval(seconds=1)

		.. warning::
	
			Scan interval cannot be modified on a NRF Sniffer actually. This method is provided in order to expose the same API used by other supported sniffers.

		.. note::

			This method is a **shared method** and can be called from the corresponding Emitters / Receivers.


		'''
		io.fail("Scan interval can not be modified on a NRF Sniffer device.")

	def setScan(self,enable=True):
		'''
		This method enables or disables the scanning mode. It allows to change the channel dynamically.

		:param enable: boolean indicating if the scanning mode must be enabled
		:type enable: bool

		:Example:

			>>> device.setScan(enable=True) # scanning mode enabled
 			>>> device.setScan(enable=False) # scanning mode disabled
		
		.. note::

			This method is a **shared method** and can be called from the corresponding Emitters / Receivers.

		'''
		if enable:
			self.scanMode = True
			self._setChannels([37,38,39])
			self._scanContinuously()
		else:
			self.scanMode = False
			self._goIdle()

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

	def recv(self):
		self._enterListening()
		pkt = self._recv()
		self._exitListening()

		if pkt is not None:
			#pkt.show()
			if pkt.packet_type == 0x06:
				timestamp = time.time()
				ts_sec = int(timestamp)
				ts_usec = int((timestamp - ts_sec)*1000000)
				if self.channel is not None and pkt.channel != self.channel and not self.synchronized and not self.scanMode and not self.sweepingMode:
					return None
				
				if self.crcEnabled and pkt.flags & 0x01 == 0:
					return None
			
				if self.sweepingMode and self.channel != pkt.channel:
					self.channel = pkt.channel

				if BTLE_ADV in pkt.ble_payload and hasattr(pkt.ble_payload,"AdvA") and hasattr(pkt.ble_payload,"TxAdd"):
					self.targets[pkt.ble_payload.AdvA.upper()] = "public" if pkt.ble_payload.TxAdd == 0 else "random"
				
				if BTLE_CONNECT_REQ in pkt.ble_payload:
					self._setAccessAddress(struct.unpack(">I",struct.pack("<I",pkt.ble_payload.AA))[0])
					self._setCrcInit(struct.unpack(">I",b"\x00" + struct.pack('<I',pkt.ble_payload.crc_init)[:3])[0])
					self._setChannelMap(pkt.ble_payload.chM)
					self._setHopInterval(pkt.ble_payload.interval)
					self._setHopIncrement(pkt.ble_payload.hop)
					self.synchronized = True								
	
				return BTLE_PPI(
						btle_channel=pkt.channel,
						btle_clkn_high=ts_sec,
						btle_clk_100ns=ts_usec,
						rssi_max=-pkt.rssi,
						rssi_min=-pkt.rssi,
						rssi_avg=-pkt.rssi,
						rssi_count=1)/pkt.ble_payload
			else:
				if pkt.packet_type == 0x09: # Event disconnect
					io.fail("Connection lost !")
					self._flush()
					self.restartSniffingMode()
					self._setAccessAddress(None)
					self._setCrcInit(None)
					self._setChannelMap(None)
					self._setHopInterval(None)
					self._setHopIncrement(None)
					self.synchronized = False					
				self.commandResponses.put(pkt)
				return None

		else:
			utils.wait(seconds=0.0001)

