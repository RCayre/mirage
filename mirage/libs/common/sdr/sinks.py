from ctypes import *
from mirage.libs.common.sdr.hackrf_definitions import *
from mirage.libs.common.sdr.hardware import *
from mirage.libs.common.sdr.pipeline import SDRPipeline
import queue,struct,threading,numpy

'''
This component implements the supported Software Defined Radio Sinks (e.g. TX).
'''

class SDRSink:
	'''
	This class defines a standard Software Defined Radio sink.
	Every Software Defined Radio supporting IQ transmission has to implement a Sink inheriting from this class.

	The following methods have to be implemented:

		  * ``setGain(gain)`` : this method allows to sets the TX gain used by the sink
		  * ``getGain()`` : this method returns the TX gain in use by the sink
		  * ``startStreaming()`` : this method allows to start the IQ streaming
		  * ``stopStreaming()`` : this method allows to stop the IQ streaming
		  * ``isStreaming()`` : this method returns a boolean indicating if streaming is enabled
		  * ``close()`` : this method closes the sink

	'''
	def __init__(self,interface):
		self.interface = interface
		self.running = False
		self.frequency = None
		self.bandwidth = None
		self.txGain = None
		self.blockLength = None
		self.sampleRate = None
		self.transmitQueue = queue.Queue()

	def setBandwidth(self,bandwidth):
		self.bandwidth = bandwidth

	def setFrequency(self,frequency):
		self.frequency = frequency

	def setTXGain(self,txGain):
		self.txGain = txGain

	def setSampleRate(self,sampleRate):
		self.sampleRate = sampleRate

	def isStreaming(self):
		return self.running

	def startStreaming(self):
		self.running = True

	def stopStreaming(self):
		self.running = False

	def nextData(self):
		if self.transmitQueue.empty():
			return []
		else:
			return self.transmitQueue.get()

	def transmit(self,iqSamples):
		self.transmitQueue.put(iqSamples)

	def close(self):
		if self.running:
			self.stopStreaming()


	def __lshift__(self, modulator):
		modulator.setSink(self)
		return SDRPipeline(sink=self,modulator=modulator)

class HackRFSink(HackRFSDR,SDRSink):
	'''
	This class defines a Sink for HackRF Software Defined Radio. It inherits from ``SDRSink``.
	'''
	numberOfSinks = 0

	def __del__(self):
		self.close()
		HackRFSink.numberOfSinks-=1
		if HackRFSink.numberOfSinks == 0 and HackRFSink.initialized:
			HackRFSDR.closeAPI()

	def __init__(self,interface):
		self.alreadyStarted = False
		HackRFSDR.__init__(self,interface=interface)
		SDRSink.__init__(self,interface=interface)
		self.tLock = threading.Lock()
		self.currentData = []
		if self.ready:
			HackRFSink.numberOfSinks+=1


	def setGain(self,gain):
		'''
		This method allows to set the TX gain used by the HackRF sink.

		:param gain: TX gain to use
		:type gain: int

		:Example:

			>>> hackrfSink.setGain(40)

		'''
		self.setTXGain(gain)

	def getGain(self):
		'''
		This method returns the TX gain used by the HackRF sink.

		:return: TX gain in use
		:rtype: int

		:Example:

			>>> hackrfSink.getGain()
			40

		'''
		return self.txGain


	def _transmitCallback(self,hackrf_transfer):
		'''
		This method implements the transmission callback used by the sink to transmit IQ to the HackRF.
		It is not intended to be used directly, see ``startStreaming`` and ``stopStreaming`` methods to start and stop the streaming process.
		'''
		# PROBLEM : MULTIPLE PACKETS ARE TRANSMITTED SOMETIMES ...
		length = hackrf_transfer.contents.valid_length
		self.blockLength = length // 2
		array_type = (c_byte*length)
		values = (array_type)()
		if len(self.currentData) == 0:
			self.currentData = self.nextData()
		if len(self.currentData) == 0:
			for i in range(length):
				values[i] = 0
		elif len(self.currentData) <= self.blockLength:
			start = self.blockLength - len(self.currentData)
			for i in range(2*start):
				values[i] = 0
			for i in range(len(self.currentData)):
				values[2*start+2*i] = struct.pack('b',int(self.currentData[i].real*127))[0]
				values[2*start+2*i+1] = struct.pack('b',int(self.currentData[i].imag*127))[0]
			for i in range(2*start+2*len(self.currentData),len(values)):
				values[i] = 0
			self.currentData = []
		else:
			data = self.currentData[:self.blockLength]
			self.currentData = self.currentData[self.blockLength+1:]
			for i in range(len(data)):
				values[2*i] = struct.pack('b',int(data[i].real*127))[0]
				values[2*i+1] = struct.pack('b',int(data[i].imag*127))[0]
		self.tLock.acquire()
		memmove(hackrf_transfer.contents.buffer, byref(values), length)
		self.tLock.release()
		return 0


	def startStreaming(self):
		'''
		This method starts the streaming process.

		:return: boolean indicating if the operation was successful
		:rtype: bool

		:Example:

			>>> hackrfSink.startStreaming()
			True

		'''
		if self.checkParameters() and not self.running:
			if self.alreadyStarted:
				self.restart()
			self.lock.acquire()
			self.callback = hackrflibcallback(self._transmitCallback)
			ret = libhackrf.hackrf_start_tx(self.device, self.callback, None)
			self.lock.release()


			if ret == HackRfError.HACKRF_SUCCESS:
				self.running = True
				return True
		return False

	def stopStreaming(self):
		'''
		This method stops the streaming process.

		:return: boolean indicating if the operation was successful
		:rtype: bool

		:Example:

			>>> hackrfSink.stopStreaming()
			True

		'''
		if self.running:
			self.lock.acquire()
			ret = libhackrf.hackrf_stop_tx(self.device)
			self.lock.release()
			if ret == HackRfError.HACKRF_SUCCESS:
				self.alreadyStarted = True
				self.running = False
				return True
		return False

	def isStreaming(self):
		'''
		This method returns a boolean indicating if the streaming process is enabled.

		:return: boolean indicating if streaming is enabled
		:rtype: bool

		:Example:

			>>> hackrfSink.isStreaming()
			False

		'''
		self.lock.acquire()
		value = libhackrf.hackrf_is_streaming(self.device) == 1
		self.lock.release()
		return value

	def close(self):
		'''
		This method closes the HackRF Sink.

		:return: boolean indicating if the operation was successful
		:rtype: bool

		:Example:

				>>> hackrfSink.close()

		'''
		if self.ready and self.device is not None:
			self.stopStreaming()
		return False


	def checkParameters(self):
		'''
		This method returns a boolean indicating if a mandatory parameter is missing.

		:return: boolean indicating if the sink is correctly configured
		:rtype: bool

		:Example:

				>>> hackrfSink.checkParameters()
				[FAIL] You have to provide a frequency !
				False

		'''
		valid = True
		if self.frequency is None:
			io.fail("You have to provide a frequency !")
			valid = False
		if self.bandwidth is None:
			io.fail("You have to provide a bandwidth !")
			valid = False
		if self.txGain is None:
			io.fail("You have to provide a TX Gain !")
			valid = False
		if self.lnaGain is None:
			io.fail("You have to provide a LNA Gain !")
			valid = False
		if self.sampleRate is None:
			io.fail("You have to provide a sample rate !")
			valid = False
		return valid
