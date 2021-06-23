from mirage.libs.common.sdr.decoders import SDRDecoder
from mirage.libs.common.sdr.encoders import SDREncoder
from mirage.libs import utils
'''
This component implements the SDR Pipeline.
'''

class SDRPipeline:
	'''
	This class implements a Software Defined Radio pipeline, allowing to connect multiple SDR blocks together to manipulate an IQ stream.

		* A pipeline can be used to demodulate and decode an IQ stream provided by a ``SDRSource``: in this case, the pipeline is composed of a ``SDRSource``, a ``SDRDemodulator`` and a ``SDRDecoder``.
		* A pipeline can be used to encode and modulate an IQ stream transmitted to a ``SDRSink``: in this case, the pipeline is composed of a ``SDREncoder``, z ``SDRModulator`` and a ``SDRSink``.

	The ">>" operator is overloaded to simplify the connection between blocks. As an example, you can build a pipeline automatically using the following syntax:

	:Example:

		>>> rxPipeline = source >> demodulator >> decoder
		>>> txPipeline = sink << modulator << encoder

	'''
	def __init__(self, source=None, demodulator=None, sink = None, modulator = None):
		self.source = source
		self.demodulator = demodulator
		self.sink = sink
		self.modulator = modulator
		self.started = False

	def __rshift__(self, decoder):
		if isinstance(decoder, SDRDecoder):
			if self.demodulator is not None:
				self.demodulator.addDecoder(decoder)
			return self

	def __lshift__(self, encoder):
		if isinstance(encoder, SDREncoder):
			if self.modulator is not None:
				self.modulator.addEncoder(encoder)
			return self

	def __del__(self):
		self.stop()

	def getSource(self):
		'''
		This method returns the source connected to the pipeline (if any).

		:return: pipeline source
		:rtype: ``SDRSource``

		'''
		return self.source

	def updateDemodulator(self,demodulator):
		'''
		This method replaces the current demodulator by the provided one.

		:param demodulator: New demodulator to use
		:type demodulator: ``SDRDemodulator``

		'''
		self.demodulator.stop()
		decoders = self.demodulator.getDecoders()
		self.demodulator = demodulator
		self.demodulator.setSource(self.source)
		for decoder in decoders:
			self.demodulator.addDecoder(decoder)
		self.demodulator.start()

	def getDemodulator(self):
		'''
		This method returns the demodulator connected to the pipeline (if any).

		:return: pipeline demodulator
		:rtype: ``SDRDemodulator``

		'''

		return self.demodulator

	def getOutput(self):
		'''
		This method returns the demodulator's output .

		:return: tuple of demodulated data and the corresponding IQ Samples
		:rtype: (bytes, list of complex)

		'''
		return self.demodulator.getOutput()

	def setInput(self,data):
		'''
		This method sets the modulator's input.

		:param data: bytes to transmit
		:type data: bytes

		'''
		self.modulator.setInput(data)

	def getSink(self):
		'''
		This method returns the sink connected to the pipeline (if any).

		:return: pipeline sink
		:rtype: ``SDRSink``

		'''
		return self.sink

	def getModulator(self):
		'''
		This method returns the modulator connected to the pipeline (if any).

		:return: pipeline modulator
		:rtype: ``SDRModulator``

		'''
		return self.modulator

	def isStarted(self):
		'''
		This method returns a boolean indicating if the pipeline is started.

		:return: boolean indicating if the pipeline is started
		:rtype: bool

		'''

		return self.started

	def start(self):
		'''
		This method starts the pipeline.

		:Example:

			>>> pipeline.start()

		'''
		if self.source is not None:
			if not self.source.running:
				self.source.startStreaming()
			while not self.source.running:
				utils.wait(seconds=0.01)
			if not self.demodulator.running:
				self.demodulator.start()
		elif self.sink is not None:
			if not self.sink.running:
				self.sink.startStreaming()
			if not self.modulator.running:
				self.modulator.start()
		self.started = True

	def stop(self):
		'''
		This method stops the pipeline.

		:Example:

			>>> pipeline.stop()

		'''
		if self.source is not None:
			if self.source.running:
				self.source.stopStreaming()
			if self.demodulator.running:
				self.demodulator.stop()
		elif self.sink is not None:
			if self.sink.running:
				self.sink.stopStreaming()
			if self.modulator.running:
				self.modulator.stop()
		self.started = False
