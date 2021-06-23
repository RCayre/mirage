from scapy.all import *
from mirage.libs import wireless,io,utils
from mirage.libs.zigbee_utils.constants import *
from mirage.libs.common.sdr import sources,demodulators,decoders,sinks,modulators
from mirage.libs.zigbee_utils.decoders import ZigbeeDecoder
from mirage.libs.zigbee_utils.encoders import ZigbeeEncoder
from mirage.libs.zigbee_utils.helpers import *

class ZigbeeHackRFDevice(wireless.SDRDevice):
	'''
	This device allows to communicate with a HackRF in order to interact with the Zigbee protocol.
	HackRF support is **experimental**, the demodulator is slow !

	The following capabilities are actually supported :

	+-----------------------------------+----------------+
	| Capability           	            | Available ?    |
	+===================================+================+
	| SNIFFING                          | yes            |
	+-----------------------------------+----------------+
	| INJECTING                         | yes            |
	+-----------------------------------+----------------+
	| COMMUNICATING_AS_COORDINATOR      | no             |
	+-----------------------------------+----------------+
	| COMMUNICATING_AS_ROUTER           | no             |
	+-----------------------------------+----------------+
	| COMMUNICATING_AS_END_DEVICE       | no             |
	+-----------------------------------+----------------+
	| JAMMING                           | no             |
	+-----------------------------------+----------------+

	'''

	sharedMethods = [
			"getChannel",
			"setChannel",

			"getFirmwareVersion",
			"getSerial",
			"getAPIVersion",
			"getDeviceIndex",
			"getBoardName",
			"getBoardID"
			]

	def buildReceivePipeline(self,interface):
		self.source = sources.HackRFSource(interface)
		if self.source.isReady():
			self.source.setFrequency(channelToFrequency(self.channel) * 1000 * 1000)
			self.source.setSampleRate(2 * 1000 * 1000)
			self.source.setBandwidth(1 * 1000 * 1000)
			self.source.setGain(40)
			self.source.setLNAGain(30)
			self.source.enableAntenna()
			self.demodulator = self._getDemodulator()
			self.decoder = ZigbeeDecoder(samplesPerSymbol=1)
			return (self.source >> self.demodulator >> self.decoder)
		else:
			return None

	def _getDemodulator(self):
		return (demodulators.FSK2Demodulator(
						preamble="1100000011101111010111001101100",
						size=8*200,
						samplesPerSymbol=1)
				if not self.experimentalDemodulatorEnabled else
				demodulators.FasterFSK2Demodulator(
						preamble="1100000011101111010111001101100",
						size=8*200,
						samplesPerSymbol=1))

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
			self.sink.setFrequency(2410 * 1000 * 1000)
			self.sink.setSampleRate(2 * 1000 * 1000)
			self.sink.setBandwidth(1 * 1000 * 1000)
			self.sink.setTXGain(40)
			self.sink.setLNAGain(40)
			self.sink.enableAntenna()
			self.modulator = modulators.OQPSKModulator(samplesPerSymbol=2,pulseType="sinus")
			self.encoder = ZigbeeEncoder()
			return (self.sink << self.modulator << self.encoder)
		return None

	def __init__(self,interface):
		self.ready = False
		self.channel = 12
		self.experimentalDemodulatorEnabled = False
		super().__init__(interface=interface)
		self.receivePipeline.start()

	def recv(self):
		packet = self.receivePipeline.getOutput()
		if packet is not None:
			return (self.channel,fcs(packet[0][6:-2]) == packet[0][-2:],packet[1],Dot15d4(packet[0][5:-2]))
		else:
			return None


	def setChannel(self, channel):
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
		if (channel >= 11 and channel <= 26):
			receivePipelineStarted = self.receivePipeline.isStarted()
			transmitPipelineStarted = self.transmitPipeline.isStarted()
			if receivePipelineStarted:
				self.receivePipeline.stop()
			if transmitPipelineStarted:
				self.transmitPipeline.stop()
			self.source.setFrequency(channelToFrequency(channel) * 1000 * 1000)
			self.sink.setFrequency(channelToFrequency(channel) * 1000 * 1000)

			self.channel = channel
			if receivePipelineStarted:
				self.receivePipeline.start()
			if transmitPipelineStarted:
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
			11
			>>> device.setChannel(15)
			>>> device.getChannel()
			15

		.. note::

			This method is a **shared method** and can be called from the corresponding Emitters / Receivers.

		'''
		return self.channel


	def isUp(self):
		return self.sink.isReady() and self.sink.isReady()

	def init(self):
		if self.source.isReady() and self.sink.isReady():
			self.ready = True
			self.capabilities = ["SNIFFING","INJECTING"]

	def send(self,packet):
		calcFcs = fcs(bytes(packet))
		self.receivePipeline.stop()
		self.transmitPipeline.start()
		packet = bytes(packet)+calcFcs
		packet = bytes([len(packet)])+packet
		self.transmitPipeline.setInput(packet)
		utils.wait(seconds=0.75)
		self.transmitPipeline.stop()
		self.receivePipeline.start()

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
