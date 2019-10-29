from threading import Lock
from queue import Queue
import time
from serial.tools.list_ports import comports
from serial import Serial,SerialException
from mirage.libs.ble_utils.constants import *
from mirage.libs.ble_utils.scapy_btlejack_layers import *
from mirage.libs import io,utils,wireless

class BTLEJackDevice(wireless.Device):
	'''
	This device allows to communicate with a BTLEJack Device in order to sniff Bluetooth Low Energy protocol.
	The corresponding interfaces are : ``microbitX`` (e.g. "microbit0")

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
	| JAMMING_ADVERTISEMENTS            | yes            |
	+-----------------------------------+----------------+
	| HIJACKING_CONNECTIONS             | yes            |
	+-----------------------------------+----------------+
	| INITIATING_CONNECTION             | no             |
	+-----------------------------------+----------------+
	| RECEIVING_CONNECTION              | no             |
	+-----------------------------------+----------------+
	| COMMUNICATING_AS_MASTER           | yes            |
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
			"sniffExistingConnections",
			"sniffAdvertisements", 

			"jamAdvertisements",
			"disableAdvertisementsJamming",

			"setSweepingMode",

			"setScan",
			"setScanInterval",
			"getConnections",
			"switchConnection",
			"getCurrentConnection",
			"isConnected",
			"isSynchronized",
			"getCurrentHandle",
			"getAccessAddress",
			"getCrcInit",
			"getChannelMap",
			"getHopInterval",
			"getHopIncrement",
			"setJamming",
			"setHijacking"
			]

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


	def setHijacking(self,enable=True):
		'''
		This method allows to enable or disable the hijacking mode.
	
		:param enable: boolean indicating if the hijacking mode must be enabled or disabled
		:type enable: bool

		:Example:
		
			>>> device.setHijacking(enable=True) # hijacking mode enabled
			>>> device.setHijacking(enable=False) # hijacking mode disabled

		.. note::

			This method is a **shared method** and can be called from the corresponding Emitters / Receivers.

		'''
		self.hijacking = enable


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
		io.fail("Switching connection not allowed with BTLEJack Device !")

	def isConnected(self):
		'''
		This method returns a boolean indicating if a connection is actually established and hijacked.

		:return: boolean indicating if a connection is established and hijacked
		:rtype: bool

		:Example:
		
			>>> device.isConnected()
			True

		.. note::

			This method is a **shared method** and can be called from the corresponding Emitters / Receivers.

		'''
		return self.hijacked

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

	@classmethod
	def findMicrobits(cls,index=None):
		'''
		This class method allows to find a specific BTLEJack device, by providing the device's index. 
		If no index is provided, it returns a list of every devices found.
		If no device has been found, None is returned.

		:param index: device's index
		:type index: int
		:return: string indicating the device
		:rtype: str

		:Example:
			
			>>> BTLEJackDevice.findMicrobits(0)
			'/dev/ttyACM0'
			>>> BTLEJackDevice.findMicrobits()
			['/dev/ttyACM0','/dev/ttyACM1']

		
		'''
		microbitList = [i[0] for i in comports() if 
				(isinstance(i,tuple) and "VID:PID=0d28:0204" in port[-1]) or
				(i.vid == 0x0D28 and i.pid == 0x0204)
				]
		if index is None:
			return microbitList
		else:			
			try:
				microbit = microbitList[index]
			except IndexError:
				return None
			return microbit
		return None


	def __init__(self,interface):
		super().__init__(interface=interface)
		customPort = None
		if "microbit" == interface:
			self.index = 0
			self.interface = "microbit0"
		elif "microbit" == interface[:8]:
			if ":" in interface:
				fields = interface.split(":")
				customPort = fields[1]
				self.index = customPort
			else:
				self.index = int(interface.split("microbit")[1])
			self.interface = interface
		if not customPort:
			self.microbit = BTLEJackDevice.findMicrobits(self.index)
		else:
			self.microbit = customPort
		if self.microbit is not None:
			try:
				self.microbit = Serial(port = self.microbit, baudrate=115200, timeout=0)
				self.ready = False
				self._flush()
			except SerialException:
				io.fail("Serial communication not ready !")
				self.ready = False
				self.microbit = None
		else:
			io.fail("No btlejack device found !")
			self.ready = False

	def _enterListening(self):
		self.isListening = True

	def _exitListening(self):
		self.isListening = False

	def _isListening(self):
		return self.isListening


	def _cancelFollow(self): # TODO
		pass

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
		self.channel = channel

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

	def _flush(self):
		while self.microbit.in_waiting:
			self.microbit.read()

	def _flushCommandResponses(self):
		while not self.commandResponses.empty():
			self.commandResponses.get()

	def _internalCommand(self,cmd,noResponse=False):
		packet = BTLEJack_Hdr()/cmd
		self._flushCommandResponses()
		def getFunction():
			if not self._isListening() or self.commandResponses.empty():
				func = self._recv
			else:
				func = self.commandResponses.get
			return func

		self._send(packet)
		if not noResponse:

			getResponse = getFunction()
			response = getResponse()
			while response is None or response.packet_type == 4 or response.opcode != packet.opcode:				
				getResponse = getFunction()
				response = getResponse()
			return response

	def _getFirmwareVersion(self):
		pkt = self._internalCommand(BTLEJack_Version_Command())
		return (pkt.major,pkt.minor)

	def _reset(self):
		self._internalCommand(BTLEJack_Reset_Command())

	def getFirmwareVersion(self):
		'''
		This method returns the firmware version of the current BTLEJack device.

		:return: firmware version as a tuple of (major, minor)
		:rtype: tuple of (int,int)

		:Example:
			
			>>> device.getFirmwareVersion()
			(3,14)

		.. note::

			This method is a **shared method** and can be called from the corresponding Emitters / Receivers.


		'''
		version = self._getFirmwareVersion()
		return version

	def getDeviceIndex(self):
		'''
		This method returns the index of the current BTLEJack device.

		:return: device's index
		:rtype: int

		:Example:
			
			>>> device.getDeviceIndex()
			0

		.. note::

			This method is a **shared method** and can be called from the corresponding Emitters / Receivers.


		'''
		return self.index

	def _send(self,packet):
		self.lock.acquire()
		self.microbit.write(raw(packet))
		self.lock.release()

	def send(self,packet):
		command = None
		if BTLE_DATA in packet:
			command = BTLEJack_Hdr()/BTLEJack_Send_Packet_Command(ble_payload=packet[BTLE_DATA:])
		if self.isConnected() and CtrlPDU in command.ble_payload and command.ble_payload.optcode == 0x02:
			self.hijacked = False
		if command is not None :
			self._send(raw(command))

	# New Connection Sniffing methods

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
			
		.. note::

			This method is a **shared method** and can be called from the corresponding Emitters / Receivers.

		'''
		self.synchronized = False
		self.hijacked = False
		self.sniffingMode = BLESniffingMode.NEW_CONNECTION
		self.lastTarget = address
		self._sniffConnectionRequests(address=address,channel=channel)


	def _sniffConnectionRequests(self,address='FF:FF:FF:FF:FF:FF',channel=None):
		if channel is not None and not self.sweepingMode:
			self.setChannel(channel)

		self._internalCommand(BTLEJack_Sniff_Connection_Request_Command(address=address,channel=self.getChannel() if
													 channel is None else channel))

	# Existing Connection Sniffing methods
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
			>>> device.sniffExistingConnections(accessAddress=0xe5e296e9, crcInit=0x0bd54a)
			>>> device.sniffExistingConnections(accessAddress=0xe5e296e9, crcInit=0x0bd54a, channelMap=0x1fffffffff)
			
		.. warning::

			If no access address is provided, BTLEJack tries to get multiple candidate access addresses and select the most probable address.

		.. note::

			This method is a **shared method** and can be called from the corresponding Emitters / Receivers.

		'''
		self.hijacked = False
		self.synchronized = False
		self.sniffingMode = BLESniffingMode.EXISTING_CONNECTION
		if accessAddress is None:
			self._listAccessAddress()
		else:
			self._setAccessAddress(accessAddress)
			if crcInit is None:
				self._recoverFromAccessAddress(accessAddress)
			else:
				self._setCrcInit(crcInit)

				if channelMap is None:
					self._recoverFromCrcInit(accessAddress,crcInit)
				else:
					self._setChannelMap(channelMap)
					self._recoverFromChannelMap(accessAddress,crcInit, channelMap)

	def _resetFilteringPolicy(self,policyType="blacklist"):
		policy = 0x00 if policyType == "blacklist" else 0x01
		self._internalCommand(BTLEJack_Advertisements_Command()/BTLEJack_Advertisements_Reset_Policy_Command(policy_type=policy))

	def _addFilteringRule(self,pattern=b"",mask=None,position=None):
		if position is None:
			position = 0xFF
		if mask is None:
			mask = len(pattern) * b"\xFF"
		self._internalCommand(BTLEJack_Advertisements_Command()/BTLEJack_Advertisements_Add_Rule_Command()/BTLEJack_Filtering_Rule(data=pattern,mask=mask,position=position))

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
		
			This method requires the custom Mirage Firmware in order to sniff advertisements.
				
		.. note::

			This method is a **shared method** and can be called from the corresponding Emitters / Receivers.

		'''
		if self.customMirageFirmware:
			self.sniffingMode = BLESniffingMode.ADVERTISEMENT
			self.synchronized = False
			self.hijacked = False
			if channel is not None and not self.sweepingMode:
				self.setChannel(channel)
			
			if address.upper() == "FF:FF:FF:FF:FF:FF":
				self._resetFilteringPolicy("blacklist")
			else:
				self._resetFilteringPolicy("whitelist")
				target = bytes.fromhex(address.replace(":",""))[::-1]
				self._addFilteringRule(pattern=target,position=2)

			self._internalCommand(BTLEJack_Advertisements_Command()/BTLEJack_Advertisements_Disable_Sniff_Command())
			self._internalCommand(BTLEJack_Advertisements_Command()/BTLEJack_Advertisements_Enable_Sniff_Command(channel=self.getChannel() if channel is None else channel))
		else:
			io.fail("Sniffing advertisements is not supported by BTLEJack firmware,"
				" a Custom Mirage Firmware is available.")

	def jamAdvertisements(self,pattern=b"",offset=0,channel=37):
		'''
		This method reactively jams advertisements according to the specified pattern, offset and channel provided.

		:param pattern: pattern contained in payload indicating that the packet must be jammed
		:type pattern: bytes
		:param offset: offset indicating the position of pattern in the payload
		:type offset: int
		:param channel: selected channel - if not provided, channel 37 is selected
		:type channel: int

		:Example:

			>>> target = "1A:2B:3C:4D:5E:6F"
			>>> pattern = bytes.fromhex(target.replace(":",""))[::-1]
			>>> device.jamAdvertisements(pattern=pattern,offset=2,channel=39) # jam the advertisements transmitted by 1A:2B:3C:4D:5E:6F on channel 39

		.. warning::
		
			This method requires the custom Mirage Firmware in order to jam advertisements.
				
		.. note::

			This method is a **shared method** and can be called from the corresponding Emitters / Receivers.

		'''
		if self.customMirageFirmware:
			self.synchronized = False
			self.hijacked = False
			self.jammingEnabled = True
			if channel is not None:
				self.setChannel(channel)
			self._internalCommand(BTLEJack_Advertisements_Command()/BTLEJack_Advertisements_Enable_Jamming_Command(
											offset=offset,
										    	pattern=pattern,
										    	channel=self.getChannel() if
										 	channel is None else channel))
		else:
			io.fail("Jamming advertisements is not supported by BTLEJack firmware,"
				" a Custom Mirage Firmware is available.")
		
	def _listAccessAddress(self):
		io.info("Recovering access address ...")
		self._internalCommand(BTLEJack_Scan_Connections_Command())

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

	def _updateCrcInit(self,crcInit=None):
		io.success("CRCInit successfully recovered : "+"0x{:06x}".format(crcInit))
		self._setCrcInit(crcInit)
		self._recoverFromCrcInit()

	def _updateChannelMap(self,channelMap=None):
		io.success("Channel Map successfully recovered : "+"0x{:10x}".format(channelMap))
		self._setChannelMap(channelMap)
		self._recoverFromChannelMap()

	def _updateHopInterval(self,hopInterval=None):
		io.success("Hop Interval successfully recovered : "+str(hopInterval))
		self._setHopInterval(hopInterval)
		io.info("Recovering Hop Increment ...")

	def _updateHopIncrement(self,hopIncrement=None):
		io.success("Hop Increment successfully recovered : "+str(hopIncrement))
		self._setHopIncrement(hopIncrement)
		io.info("All parameters recovered, following connection ...")


	def _recoverFromAccessAddress(self,accessAddress):
		aa = accessAddress if accessAddress is not None else self._getAccessAddress()
		io.info("Recovering CRCInit ...")
		self._reset()
		pkt = self._internalCommand(BTLEJack_Recover_Command()/BTLEJack_Recover_Connection_AA_Command(access_address=aa))


	def _recoverFromCrcInit(self,accessAddress = None,crcInit = None):
		aa = accessAddress if accessAddress is not None else self._getAccessAddress()
		crcInit = crcInit if crcInit is not None else self._getCrcInit()
		io.info("Recovering ChannelMap ...")
		self._reset()
		pkt = self._internalCommand(BTLEJack_Recover_Command()/BTLEJack_Recover_Channel_Map_Command(access_address=aa,crc_init=crcInit))
		io.progress(0, total=36,suffix="0/36 channels")


	def _recoverFromChannelMap(self,accessAddress = None,crcInit = None,channelMap=None):
		aa = accessAddress if accessAddress is not None else self._getAccessAddress()
		crcInit = crcInit if crcInit is not None else self._getCrcInit()
		channelMap = channelMap if channelMap is not None else self._getChannelMap()
		io.info("Recovering Hop Interval ...")
		self._reset()
		pkt = self._internalCommand(BTLEJack_Recover_Command()/BTLEJack_Recover_Hopping_Parameters_Command(access_address=aa,crc_init=crcInit,channel_map=channelMap))



	def _addCandidateAccessAddress(self,accessAddress=None,rssi=None,channel=None):
		io.info("Candidate access address found : "+"0x{:08x}".format(accessAddress)+" (rssi = -"+str(rssi)+"dBm / channel = "+str(channel)+")")
		if accessAddress not in self.candidateAccessAddresses:
			self.candidateAccessAddresses[accessAddress] = {"hits":1,"rssi":rssi,"channels":set([channel])}
		else:
			self.candidateAccessAddresses[accessAddress]["hits"] += 1
			self.candidateAccessAddresses[accessAddress]["channels"].add(channel)

		if self.candidateAccessAddresses[accessAddress]["hits"] >= 5:
			io.success("Access Address selected : "+"0x{:08x}".format(accessAddress))
			self._setAccessAddress(accessAddress)
			self._recoverFromAccessAddress(accessAddress=accessAddress)

	def _recv(self):
		self.lock.acquire()
		if self.microbit is not None and self.microbit.in_waiting:	
			self.receptionBuffer += self.microbit.read()
		self.lock.release()

		if len(self.receptionBuffer) > 0:
			try:
				start = self.receptionBuffer.index(0xBC)
				self.receptionBuffer = self.receptionBuffer[start:]

			except ValueError:
				self.receptionBuffer = b""

			if len(self.receptionBuffer) >= 4:
				size = struct.unpack('<H',self.receptionBuffer[2:4])[0]
				if len(self.receptionBuffer) >= size + 5:
					#print(self.receptionBuffer[:size+5].hex())
					pkt = BTLEJack_Hdr(self.receptionBuffer[:size+5])
					self.receptionBuffer = self.receptionBuffer[size+5:]
					return pkt
				else:
					receptionBuffer = b""

		return None


	def disableAdvertisementsJamming(self):
		if self.jammingEnabled:
			self._internalCommand(BTLEJack_Advertisements_Command()/BTLEJack_Advertisements_Disable_Jamming_Command())

	def close(self):
		self.lock.acquire()
		self._stopSweepingThread()
		self.microbit.close()
		self.microbit = None
		self.lock.release()

	def isUp(self):
		return self.microbit is not None

	def setCRCChecking(self,enable=True):
		'''
		This method enables CRC Checking.
		
		:param enable: boolean indicating if CRC Checking must be enabled
		:type enable: bool

		:Example:
	
			>>> device.setCRCChecking(enable=True) # CRC Checking enabled
			>>> device.setCRCChecking(enable=False) # CRC Checking disabled

		.. warning::

			BTLEJack calculates the CRC directly in the firmware, so this command is ignored. It is present in order to provide a similar API to Ubertooth.
			
		.. note::

			This method is a **shared method** and can be called from the corresponding Emitters / Receivers.

		'''
		self.crcEnabled = enable


	def setAccessAddress(self,accessAddress):
		'''
		This method sets the access address to use.
	
		:param accessAddress: new access address
		:type accessAddress: int

		:Example:

			>>> device.setAccessAddress(0xe5e296e9)


		.. note::

			This method is a **shared method** and can be called from the corresponding Emitters / Receivers.

		'''
		self.accessAddress = accessAddress

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
			self.sniffNewConnections()
		else:
			self.sniffExistingConnections()

	def recv(self):
		self._enterListening()
		pkt = self._recv()
		self._exitListening()
		if pkt is not None:

			if self.customMirageFirmware and BTLEJack_Advertisement_Packet_Notification in pkt:
				timestamp = time.time()
				ts_sec = int(timestamp)
				ts_usec = int((timestamp - ts_sec)*1000000)
								
				if pkt.crc_ok == 0x01:
					io.success("CRC OK !")
				else:
					io.fail("CRC not OK !")
				
				if pkt.crc_ok != 0x01 and self.crcEnabled:
					return None

				return BTLE_PPI(
						btle_channel=pkt.channel,
						btle_clkn_high=ts_sec,
						btle_clk_100ns=ts_usec,
						rssi_max=-pkt.rssi,
						rssi_min=-pkt.rssi,
						rssi_avg=-pkt.rssi,
						rssi_count=1)/BTLE()/BTLE_ADV(pkt.ble_payload)
			if BTLEJack_Access_Address_Notification in pkt:
				self._addCandidateAccessAddress(accessAddress=pkt.access_address,
								rssi=pkt.rssi,
								channel=pkt.channel)
			if BTLEJack_CRCInit_Notification in pkt:
				self._updateCrcInit(crcInit=pkt.crc_init)
			if BTLEJack_Channel_Map_Notification in pkt:
				self._updateChannelMap(channelMap=pkt.channel_map)
			if BTLEJack_Verbose_Response in pkt and b"c=" in pkt.message:
				currentChannel = pkt.message.decode('ascii').split("c=")[1]
				io.progress(int(currentChannel), total=36,suffix=str(currentChannel)+"/36 channels")
			if BTLEJack_Verbose_Response in pkt and b"ADV_JAMMED" in pkt.message:
				io.info("Advertisement jammed on channel #"+str(self.getChannel()))
			if BTLEJack_Verbose_Response in pkt:
				io.info(pkt.message.decode('ascii'))
			if BTLEJack_Hop_Interval_Notification in pkt:
				self._updateHopInterval(pkt.hop_interval)
			if BTLEJack_Hop_Increment_Notification in pkt:
				self._updateHopIncrement(pkt.hop_increment)
				if self.hijacking:
					self._internalCommand(BTLEJack_Enable_Hijacking_Command(enabled=0x01))
				elif self.jamming:
					self._internalCommand(BTLEJack_Enable_Jamming_Command(enabled=0x01))
				self.synchronized = True

			if BTLEJack_Hijack_Status_Notification in pkt:
				self.hijacked = (pkt.status == 0x00)
						
			if BTLEJack_Nordic_Tap_Packet_Notification in pkt:
				timestamp = time.time()
				ts_sec = int(timestamp)
				ts_usec = int((timestamp - ts_sec)*1000000)
				
				return BTLE_PPI(
						btle_channel=pkt.channel,
						btle_clkn_high=ts_sec,
						btle_clk_100ns=ts_usec,
						rssi_max=pkt.rssi,
						rssi_min=pkt.rssi,
						rssi_avg=pkt.rssi,
						rssi_count=1)/BTLE(access_addr=self.getAccessAddress())/pkt.ble_payload
			elif BTLEJack_Connection_Request_Notification in pkt:
				self._setAccessAddress(struct.unpack(">I",struct.pack("<I",pkt.ble_payload.AA))[0])
				self._setCrcInit(struct.unpack(">I",b"\x00" + struct.pack('<I',pkt.ble_payload.crc_init)[:3])[0])
				self._setChannelMap(pkt.ble_payload.chM)
				self._setHopInterval(pkt.ble_payload.interval)
				self._setHopIncrement(pkt.ble_payload.hop)
				self.synchronized = True
				timestamp = time.time()
				ts_sec = int(timestamp)
				ts_usec = int((timestamp - ts_sec)*1000000)

				return BTLE_PPI(
						btle_channel=self.channel,
						btle_clkn_high=ts_sec,
						btle_clk_100ns=ts_usec,
						rssi_max=0,
						rssi_min=0,
						rssi_avg=0,
						rssi_count=1)/BTLE()/BTLE_ADV(RxAdd=pkt.RxAdd,TxAdd=pkt.TxAdd,RFU=pkt.RFU, PDU_type=pkt.PDU_type)/pkt.ble_payload
			elif BTLEJack_Connection_Lost_Notification in pkt or pkt.packet_type==0x4 and pkt.notification_type==0x9:
				io.fail("Connection lost !")
				self._reset()
				self.restartSniffingMode()
				self._setAccessAddress(None)
				self._setCrcInit(None)
				self._setChannelMap(None)
				self._setHopInterval(None)
				self._setHopIncrement(None)
				self.hijacked = False
				self.synchronized = False
			else:
				self.commandResponses.put(pkt)
		else:
			utils.wait(seconds=0.0001)


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
		self.sniffAdvertisements(channel=37)
		utils.wait(seconds=self.scanInterval)
		self.sniffAdvertisements(channel=38)
		utils.wait(seconds=self.scanInterval)
		self.sniffAdvertisements(channel=39)
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


	def _sweepingThread(self):
		for channel in self.sweepingSequence:
			self.setChannel(channel=channel)
			if self.sniffingMode is not None:
				if self.sniffingMode == BLESniffingMode.ADVERTISEMENT:
					self._internalCommand(BTLEJack_Advertisements_Command()/BTLEJack_Advertisements_Enable_Sniff_Command(channel=channel),noResponse=True)
				elif self.sniffingMode == BLESniffingMode.NEW_CONNECTION and not self.synchronized:
					self._sniffConnectionRequests(address=self.lastTarget,channel=channel)
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

	def init(self):
		if self.microbit is not None:
			self._flush()
			self.setCRCChecking(True)
			self.scanThreadInstance = None
			self.isListening = False
			self.hijacking = False
			self.jamming = False
			self.customMirageFirmware = False
			self.receptionBuffer = b""
			self.lock = Lock()
			self.commandResponses = Queue()
			self.channel = 37
			self.accessAddress = None
			self.crcInit = None
			self.channelMap = None
			self.hopInterval = None
			self.hopIncrement = None
			self.sniffingMode = None
			self.hijacked = False
			self.synchronized = False
			self.jammingEnabled = True
			self.sweepingMode = False
			self.sweepingSequence = []
			self.sweepingThreadInstance = None
			self.lastTarget = "FF:FF:FF:FF:FF:FF"
			self.setScanInterval()
			self.candidateAccessAddresses = {}
			self.capabilities = ["SNIFFING_EXISTING_CONNECTION", "SNIFFING_NEW_CONNECTION", "HIJACKING_CONNECTIONS", "JAMMING_CONNECTIONS", "COMMUNICATING_AS_MASTER"]
			try:
				(major,minor) = self._getFirmwareVersion()
				io.success("BTLEJack device "+("#"+str(self.index) if isinstance(self.index,int) else str(self.index))+
					   " successfully instantiated (firmware version : "+str(major)+"."+str(minor)+")")
				if major == 3 and minor == 14:
					io.info("Custom Mirage Firmware used ! Advertisements sniffing and jamming will be supported.")
					self.capabilities += ["SNIFFING_ADVERTISEMENTS","SCANNING","JAMMING_ADVERTISEMENTS"]
					self.customMirageFirmware = True
				self._reset()
				self.ready = True
			except:
				self.microbit = None
				self.ready = False
				
