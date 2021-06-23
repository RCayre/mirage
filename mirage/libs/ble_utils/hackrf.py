from scapy.all import *
from mirage.libs import wireless,io,utils
from mirage.libs.ble_utils.constants import *
from mirage.libs.common.sdr import sources,demodulators,decoders,sinks,modulators
from mirage.libs.ble_utils.decoders import BLEDecoder
from mirage.libs.ble_utils.encoders import BLEEncoder
from mirage.libs.ble_utils.helpers import *
import time

class BLEHackRFDevice(wireless.SDRDevice):
	'''
	This device allows to communicate with a HackRF Device in order to interact with Bluetooth Low Energy protocol.
	HackRF support is **experimental**, the demodulator is slow and it can only deal with advertisements.

	The corresponding interfaces are : ``hackrfX`` (e.g. "hackrf0")

	The following capabilities are actually supported :

	+-------------------------------------------+----------------+
	| Capability			            | Available ?    |
	+===========================================+================+
	| SCANNING                                  | yes            |
	+-------------------------------------------+----------------+
	| ADVERTISING                               | yes            |
	+-------------------------------------------+----------------+
	| SNIFFING_ADVERTISEMENTS                   | yes            |
	+-------------------------------------------+----------------+
	| SNIFFING_NEW_CONNECTION                   | no             |
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
	| INITIATING_CONNECTION                     | no             |
	+-------------------------------------------+----------------+
	| RECEIVING_CONNECTION                      | no             |
	+-------------------------------------------+----------------+
	| COMMUNICATING_AS_MASTER                   | no             |
	+-------------------------------------------+----------------+
	| COMMUNICATING_AS_SLAVE                    | no             |
	+-------------------------------------------+----------------+
	| HCI_MONITORING                            | no             |
	+-------------------------------------------+----------------+

	'''

	sharedMethods = [
			"getChannel",
			"setChannel",
			"isConnected",
			"setAddress",
			"getAddress",
			"sniffAdvertisements",
			"setAdvertising",
			"setAdvertisingParameters",
			"setScanningParameters",
			"setScan",
			"setScanInterval",
			"getMode",
			"getFirmwareVersion",
			"getSerial",
			"getAPIVersion",
			"getDeviceIndex",
			"getBoardName",
			"getBoardID"
			]


	def __init__(self,interface):
		self.ready = False
		self.channel = 37
		self.scanThreadInstance = None
		self.advThreadInstance = None
		self.scanInterval = 1
		self.advData=b""
		self.address = "11:22:33:44:55:66"
		self.advType=ADV_IND
		self.daType = "public"
		self.oaType = "public"
		self.destAddress = "00:00:00:00:00:00"
		self.intervalMin = 200
		self.intervalMax = 210
		self.experimentalDemodulatorEnabled = False
		super().__init__(interface=interface)

	def isUp(self):
		return self.sink.isReady() and self.sink.isReady()

	def init(self):
		if self.source.isReady() and self.sink.isReady():
			self.ready = True
			self.capabilities = ["ADVERTISING","SCANNING","SNIFFING_ADVERTISEMENTS"]

	def send(self,packet):
		self.transmitPipeline.setInput(bytes(packet))

	def recv(self):
		packet = self.receivePipeline.getOutput()

		if packet is not None:
			timestamp = time.time()
			ts_sec = int(timestamp)
			ts_usec = int((timestamp - ts_sec)*1000000)
			rssi = 0
			return (BTLE_PPI(
							rssi_avg=rssi,
							rssi_max=rssi,
							rssi_min=rssi,
							rssi_count=1,
							btle_channel=self.channel,
							btle_clkn_high=ts_sec,
							btle_clk_100ns=ts_usec,
							)/BTLE(packet[0]),
					packet[1])
		else:
			return None

	def buildReceivePipeline(self,interface):
		self.source = sources.HackRFSource(interface)
		if self.source.isReady():
			self.source.setFrequency(channelToFrequency(self.channel) * 1000 * 1000)
			self.source.setSampleRate(2 * 1000 * 1000)
			self.source.setBandwidth(1 * 1000 * 1000)
			self.source.setGain(30)
			self.source.setLNAGain(20)
			self.source.enableAntenna()
			self.demodulator = self._getDemodulator()
			self.decoder = BLEDecoder(samplesPerSymbol=2)

			return (self.source >> self.demodulator >> self.decoder)

		else:
			return None

	def _getDemodulator(self):
		return (demodulators.FSK2Demodulator(
						preamble="01101011011111011001000101110001",
						size=8*40,
						samplesPerSymbol=2)
				if not self.experimentalDemodulatorEnabled else
				demodulators.FasterFSK2Demodulator(
						preamble="01101011011111011001000101110001",
						size=8*40,
						samplesPerSymbol=2) )

	def setExperimentalDemodulator(self,enable=True):
		self.experimentalDemodulatorEnabled = enable
		if enable and self.receivePipeline is not None:
			started = self.receivePipeline.isStarted()
			if started:
				self.receivePipeline.stop()
			self.receivePipeline.updateDemodulator(self._getDemodulator())
			if started:
				self.receivePipeline.start()

	def buildTransmitPipeline(self,interface):
		self.sink = sinks.HackRFSink(interface)
		if self.sink.isReady():
			self.sink.setFrequency(channelToFrequency(self.channel) * 1000 * 1000)
			self.sink.setSampleRate(2 * 1000 * 1000)
			self.sink.setBandwidth(1 * 1000 * 1000)
			self.sink.setTXGain(42)
			self.sink.setLNAGain(40)
			self.sink.enableAntenna()
			self.modulator = modulators.GFSKModulator(samplesPerSymbol=2)
			self.encoder = BLEEncoder(channel=37)
			return (self.sink << self.modulator << self.encoder)
		return None

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
			>>> hackrfDevice.setAddress("11:22:33:44:55:66")

		.. note::

			This method is a **shared method** and can be called from the corresponding Emitters / Receivers.

		'''
		self.address = address.upper()
		self.daType = "random" if random else "public"
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

	def setChannel(self, channel):
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
		if (channel >= 0 and channel <= 39 and channel != self.channel):
			receiveEnabled = self.receivePipeline.isStarted()
			transmitEnabled = self.transmitPipeline.isStarted()
			if receiveEnabled:
				self.receivePipeline.stop()
			if transmitEnabled:
				self.transmitPipeline.stop()
			self.channel = channel
			self.source.setFrequency(channelToFrequency(channel) * 1000 * 1000)
			self.sink.setFrequency(channelToFrequency(channel) * 1000 * 1000)
			self.decoder.setChannel(channel)
			self.encoder.setChannel(channel)
			if receiveEnabled:
				self.receivePipeline.start()
			if transmitEnabled:
				self.transmitPipeline.start()
			return True
		return False

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
		if channel is not None and channel >= 37 and channel <= 39:
			self.setChannel(channel)
		self.receivePipeline.start()

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


	def _buildAdvertisement(self):
		packet = BTLE()/BTLE_ADV(RxAdd=0x00 if self.oaType == "public" else 0x01,TxAdd=0x00 if self.daType == "public" else 0x01)
		if self.advType == ADV_IND:
			packet /= BTLE_ADV_IND(AdvA = self.address, data=EIR_Hdr(self.advData))
		elif self.advType == ADV_DIRECT_IND:
			packet /=  BTLE_ADV_DIRECT_IND(AdvA = self.address, InitA = self.destAddress)
		elif self.advType == ADV_NONCONN_IND:
			packet /=  BTLE_ADV_NONCONN_IND()
		elif self.advType == ADV_SCAN_IND:
			packet /=  BTLE_ADV_SCAN_IND()
		elif self.advType == SCAN_REQ:
			packet /= BTLE_SCAN_REQ(AdvA = self.address, ScanA = self.destAddress)
		elif self.advType == SCAN_RSP:
			packet /= BTLE_SCAN_RSP(AdvA = self.address, data=EIR_Hdr(self.advData))
		return packet

	def _advertisingThread(self):
		self.setChannel(37)
		self.send(self._buildAdvertisement())
		utils.wait(seconds=0.75)
		self.setChannel(38)
		self.send(self._buildAdvertisement())
		utils.wait(seconds=0.75)
		self.setChannel(39)
		self.send(self._buildAdvertisement())
		utils.wait(seconds=0.75)

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
			if self.advThreadInstance is None:
				self.receivePipeline.stop()
				self.transmitPipeline.start()
				self.advThreadInstance = wireless.StoppableThread(target=self._advertisingThread)
				self.advThreadInstance.start()
		else:
			if self.advThreadInstance is not None:
				self.advThreadInstance.stop()
				self.transmitPipeline.stop()
				self.advThreadInstance = None
				self.receivePipeline.start()



	def _scanThread(self):
		self.sniffAdvertisements(channel=37)
		utils.wait(seconds=self.scanInterval)
		self.sniffAdvertisements(channel=38)
		utils.wait(seconds=self.scanInterval)
		self.sniffAdvertisements(channel=39)
		utils.wait(seconds=self.scanInterval)

	def isConnected(self):
		'''
		This method returns a boolean indicating if the device is connected.

		:return: boolean indicating if the device is connected
		:rtype: bool

		.. warning::

			This method always returns False, it allows to provides the same API as the HCI Device.

		.. note::

			This method is a **shared method** and can be called from the corresponding Emitters / Receivers.

		'''
		return False

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
			if self.scanThreadInstance is not None:
				self.scanThreadInstance.stop()
				self.scanThreadInstance = None

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
		self.setScan(enable=False)
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

		self.advData = data
		self.daType = daType
		self.oaType = oaType
		self.intervalMin = intervalMin
		self.intervalMax = intervalMax
		io.warning("Advertising interval will be ignored")

	def setScanningParameters(self, data):
		'''
		This method sets scanning parameters according to the data provided.
		It will mainly be used by *SCAN_RESP* packets.

		:param data: data to use in *SCAN_RESP*
		:type data: bytes

		.. warning::

			This method does nothing, it allows to provides the same API as the HCI Device.

		.. note::

			This method is a **shared method** and can be called from the corresponding Emitters / Receivers.

		'''
		io.warning("Scanning not supported, this operation will be ignored")

	def getFirmwareVersion(self):
		'''
		This method returns the firmware version of the current HackRF device.

		:return: firmware version
		:rtype: str

		:Example:

			>>> device.getFirmwareVersion()
			'git-a9945ff'

		.. note::

			This method is a **shared method** and can be called from the corresponding Emitters / Receivers.

		'''
		return self.source.getFirmwareVersion()

	def getSerial(self):
		'''
		This method returns the serial number of the current HackRF device.

		:return: serial number
		:rtype: str

		:Example:

			>>> device.getSerialNumber()
			'0000000000000000a06063c8234e925f'

		.. note::

			This method is a **shared method** and can be called from the corresponding Emitters / Receivers.

		'''
		return self.source.getSerial()

	def getAPIVersion(self):
		'''
		This method returns the API version of the HackRF library.

		:return: API version as a tuple of (major, minor)
		:rtype: tuple of (int,int)

		:Example:

			>>> device.getAPIVersion()
			(1, 4)

		.. note::

			This method is a **shared method** and can be called from the corresponding Emitters / Receivers.

		'''
		return self.source.getAPIVersion()

	def getDeviceIndex(self):
		'''
		This method returns the device index of the current HackRF.

		:return: device index
		:rtype: int

		:Example:

			>>> device.getDeviceIndex()
			0

		.. note::

			This method is a **shared method** and can be called from the corresponding Emitters / Receivers.

		'''
		return self.source.getDeviceIndex()

	def getBoardName(self):
		'''
		This method returns the board name of the current HackRF.

		:return: board name
		:rtype: str

		:Example:

			>>> device.getBoardName()
			'HackRF One'

		.. note::

			This method is a **shared method** and can be called from the corresponding Emitters / Receivers.

		'''
		return self.source.getBoardName()

	def getBoardID(self):
		'''
		This method returns the board identifier of the current HackRF.

		:return: board identifier
		:rtype: int

		:Example:

			>>> device.getBoardID()
			2

		.. note::

			This method is a **shared method** and can be called from the corresponding Emitters / Receivers.

		'''
		return self.source.getBoardID()
