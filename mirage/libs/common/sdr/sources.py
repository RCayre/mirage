from ctypes import *
from mirage.libs.common.sdr.hackrf_definitions import *
from mirage.libs.common.sdr.pipeline import *
from mirage.libs.common.sdr.hardware import *
from mirage.libs import io,utils
import os,threading,numpy


'''
This component implements the supported Software Defined Radio Sources (e.g. RX).
'''

class SDRSource:
	'''
	This class defines a standard Software Defined Radio source.
	Every Software Defined Radio supporting IQ reception has to implement a Source inheriting from this class.

	The following methods have to be implemented:

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
		self.gain = None
		self.blockLength = None
		self.sampleRate = None
		self.iqStream = []

	def setBandwidth(self,bandwidth):
		self.bandwidth = bandwidth

	def setFrequency(self,frequency):
		self.frequency = frequency

	def setGain(self,gain):
		self.gain = gain

	def setSampleRate(self,sampleRate):
		self.sampleRate = sampleRate

	def isStreaming(self):
		return self.running

	def startStreaming(self):
		self.running = True

	def stopStreaming(self):
		self.running = False

	def close(self):
		if self.running:
			self.stopStreaming()

	def __rshift__(self, demodulator):
		demodulator.setSource(self)
		return SDRPipeline(source=self,demodulator=demodulator)

class HackRFSource(HackRFSDR,SDRSource):
	'''
	This class defines a Source for HackRF Software Defined Radio. It inherits from ``SDRSource``.
	'''

	numberOfSources = 0

	def __del__(self):
		self.close()
		HackRFSource.numberOfSources-=1
		if HackRFSource.numberOfSources == 0 and HackRFSource.initialized:
			HackRFSDR.closeAPI()

	def __init__(self,interface):
		self.alreadyStarted = False
		HackRFSDR.__init__(self,interface=interface)
		SDRSource.__init__(self,interface=interface)
		self.callback = hackrflibcallback(self._receiveCallback)

		if self.ready:
			HackRFSource.numberOfSources+=1



	def _receiveCallback(self,hackrf_transfer):
		'''
		This method implements the reception callback used by the source to receive IQ from the HackRF.
		It is not intended to be used directly, see ``startStreaming`` and ``stopStreaming`` methods to start and stop the streaming process.
		'''

		length = hackrf_transfer.contents.valid_length
		self.blockLength = length // 2
		arrayType = (c_byte*length)
		values = cast(hackrf_transfer.contents.buffer, POINTER(arrayType)).contents
		#if len(self.iqStream) < 10*length:
		self.iqStream+=[(values[i]/128.0+1j*values[i+1]/128.0) for i in range(0,len(values)-1,2)]
		return 0


	def startStreaming(self):
		'''
		This method starts the streaming process.

		:return: boolean indicating if the operation was successful
		:rtype: bool

		:Example:

			>>> hackrfSource.startStreaming()
			True

		'''
		if self.checkParameters() and not self.running:
			self.iqStream = []
			if self.alreadyStarted:
				self.restart()
			self.lock.acquire()
			ret = libhackrf.hackrf_start_rx(self.device, self.callback, None)

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

			>>> hackrfSource.stopStreaming()
			True

		'''

		if self.running:
			self.lock.acquire()
			ret = libhackrf.hackrf_stop_rx(self.device)
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

			>>> hackrfSource.isStreaming()
			False

		'''
		self.lock.acquire()
		value = libhackrf.hackrf_is_streaming(self.device) == 1
		self.lock.release()
		return value

	def close(self):
		'''
		This method closes the HackRF Source.

		:return: boolean indicating if the operation was successful
		:rtype: bool

		:Example:

				>>> hackrfSource.close()

		'''

		if self.ready and self.device is not None:
			self.stopStreaming()
			self.lock.acquire()
			ret = libhackrf.hackrf_close(self.device)
			self.lock.release()
			return ret == HackRfError.HACKRF_SUCCESS
		return False


	def checkParameters(self):
		'''
		This method returns a boolean indicating if a mandatory parameter is missing.

		:return: boolean indicating if the source is correctly configured
		:rtype: bool

		:Example:

				>>> hackrfSource.checkParameters()
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
		if self.gain is None:
			io.fail("You have to provide a VGA Gain !")
			valid = False
		if self.lnaGain is None:
			io.fail("You have to provide a LNA Gain !")
			valid = False
		if self.sampleRate is None:
			io.fail("You have to provide a sample rate !")
			valid = False
		return valid
