from mirage.libs.common.sdr.sinks import SDRSink
from mirage.libs.common.sdr.encoders import SDREncoder
import math,queue,threading
import numpy as np


'''
This component implements multiple Software Defined Radio modulators allowing to modulate numeric data to generate an IQ stream.
'''


class SDRModulator:
	'''
	This class implements a Sofware Defined Radio modulator: every specific modulator has to inherit from this class and implement the ``run`` method.
	When the modulator is started, it processes the packets transmitted using setInput, performs the operations needed to modulate the data and transmits the IQ stream to the associated ``SDRSink``.
	'''
	def __init__(self):
		self.sink = None
		self.count = 0
		self.encoders = []
		self.running = False
		self.input = queue.Queue()

	def setSink(self,sink):
		'''
		This method associates a ``SDRSink`` to the modulator.

		:param sink: sink to associate
		:type sink: ``SDRSink``

		'''

		if isinstance(sink,SDRSink):
			self.sink = sink

	def addEncoder(self,encoder):
		'''
		This method associates a ``SDREncoder`` to the modulator.

		:param encoder: encoder to associate
		:type encoder: ``SDREncoder``

		'''
		if isinstance(encoder, SDREncoder):
			self.encoders.append(encoder)

	def removeEncoders(self):
		'''
		This method removes every associated encoders.
		'''
		self.Encoders = []

	def generateInput(self,data):
		'''
		This method allows to generate an input, by providing the data to modulate.
		The input will be processed sequentially by every associated encoders, and the result is returned by the method.

		:param data: data to modulate
		:type data: bytes
		:return: data processed by every associated encoders (binary string)
		:rtype: str

		'''
		for d in self.encoders:
			data = d.encode(data)
		return data

	def setInput(self,data):
		'''
		This method allows to provide an input to the modulator, encode it and add it to the input queue.
		The input will be processed sequentially by every associated encoders, and the result is returned by the method.

		:param data: data to modulate
		:type data: bytes

		'''
		self.input.put(self.generateInput(data))

	def start(self):
		'''
		This method starts the modulator.

		:Example:

			>>> modulator.start()

		'''
		self.thread = threading.Thread(target=self.run,daemon=True)
		self.running = True
		self.thread.start()

	def __del__(self):
		self.stop()

	def stop(self):
		'''
		This method stops the modulator.

		:Example:

			>>> modulator.stop()

		'''
		self.running = False

	def run(self):
		pass

class OQPSKModulator(SDRModulator):
	'''
	This class implements an Offset-Quadrature Phase Shift Keying modulator.
	'''
	def __init__(self,samplesPerSymbol=8, pulseType = "sinus"):
		super().__init__()
		self.samplesPerSymbol = samplesPerSymbol
		self.pulseType = "sinus" if pulseType == "sinus" else "square"
		self.pulse = self.generatePulse(samplesPerSymbol,self.pulseType)

	def getPulseType(self):
		'''
		This method returns the pulse type used to shape the modulator.

		:return: pulse type ("square" or "sinus")
		:rtype: str

		:Example:

				>>> modulator.getPulseType()
				'sinus'

		'''
		return self.pulseType

	def setPulseType(self,pulseType):
		'''
		This method sets the pulse type used to shape the modulator.

		:param pulseType: pulse type ("square" or "sinus")
		:type pulseType: str

		:Example:

				>>> modulator.setPulseType("square")

		'''
		self.pulseType = "sinus" if pulseType == "sinus" else "square"
		self.pulse = self.generatePulse(self.samplesPerSymbol,self.pulseType)

	def getSamplesPerSymbol(self):
		'''
		This method returns the samples per symbol used by the modulator.

		:return: samples per symbol
		:rtype: int

		'''
		return self.samplesPerSymbol

	def setSamplesPerSymbol(self,samplesPerSymbol):
		'''
		This method sets the samples per symbol used by the modulator.

		:param samplesPerSymbol: samples per symbol
		:type samplesPerSymbol: int

		'''
		self.samplesPerSymbol = samplesPerSymbol
		self.pulse = self.generatePulse(self.samplesPerSymbol,self.pulseType)

	def generatePulse(self,samplesPerSymbol,pulseType="sinus"):
		'''
		This method generates a pulse according to the provided pulse type and the samples per symbol.

		:param samplesPerSymbol: samples per symbol
		:type samplesPerSymbol: int
		:param pulseType: pulse type ("square" or "sinus")
		:type pulseType: str
		:return: pulse
		:rtype: list of int

		'''
		table=[]
		if pulseType == "sinus":
			for i in range(samplesPerSymbol):
				table.append(math.sin((i*math.pi)/samplesPerSymbol))
		else:
			table = [1.0 for i in range(samplesPerSymbol)]
		return table

	def run(self):
		if self.sink.running:
			while self.running:
				if not self.input.empty():
					data = self.input.get()
					iChannel = []
					qChannel = [0.0 for i in range(self.samplesPerSymbol//2)]
					for i in range(len(data)):
						if i%2 == 0:
							iChannel += [(t if data[i] == "1" else -t) for t in self.pulse]
						else:
							qChannel += [(t if data[i] == "1" else -t) for t in self.pulse]
					iChannel += [0.0] + [0.0 for i in range(len(qChannel)-len(iChannel))]
					qChannel += [0.0]

					iqSamples = []
					for i in range(len(iChannel)):
						iqSamples.append(iChannel[i]+1j*qChannel[i])

					self.sink.transmit(iqSamples)
		else:
			self.running = False

class GFSKModulator(SDRModulator):
	'''
	This class implements a Gaussian Frequency Shift Keying modulator.
	'''
	def __init__(self,samplesPerSymbol = 8, gain = 1.0, bt = 0.3, modulationIndex = 0.5):
		super().__init__()
		self.samplesPerSymbol = samplesPerSymbol
		self.bt = bt
		self.modulationIndex = modulationIndex
		self.generateFilter()

	def getBT(self):
		'''
		This method returns the Bandwidth-Time value used by the modulator's filter.

		:return: Bandwidth-Time value
		:rtype: float

		'''
		return self.bt

	def setBT(self,bt):
		'''
		This method sets the Bandwidth-Time value used by the modulator's filter.

		:param bt: Bandwidth-Time value
		:type bt: float

		'''
		self.bt = bt
		self.generateFilter()

	def getModulationIndex(self):
		'''
		This method returns the modulation index used by the modulator.

		:return: modulation index
		:rtype: float

		'''
		return self.modulationIndex

	def setModulationIndex(self,modulationIndex):
		'''
		This method sets the modulation index used by the modulator.

		:param modulationIndex: modulation index
		:type modulationIndex: float

		'''
		self.modulationIndex = modulationIndex
		self.generateFilter()

	def getSamplesPerSymbol(self):
		'''
		This method returns the samples per symbol used by the modulator.

		:return: samples per symbol
		:rtype: int

		'''
		return self.samplesPerSymbol

	def setSamplesPerSymbol(self,samplesPerSymbol):
		'''
		This method sets the samples per symbol used by the modulator.

		:param samplesPerSymbol: samples per symbol
		:type samplesPerSymbol: int

		'''
		self.samplesPerSymbol = samplesPerSymbol
		self.generateFilter()


	def _generateGaussian(self,gain,sps,bt,ntaps):
		taps = [0.0 for i in range(ntaps)]
		scale = 0.0
		dt = 1.0 / sps
		s = 1.0 / (math.sqrt(math.log(2.0))) / (2 * math.pi * bt)
		t0 = -0.5 * ntaps
		ts = 0.0
		for i in range(ntaps):
			t0+=1.0
			ts = s * dt * t0
			taps[i] = math.exp(-0.5 * ts * ts)
			scale += taps[i]
		for i in range(ntaps):
			taps[i] = taps[i] / scale * gain
		return taps

	def generateFilter(self):
		'''
		This method generates the gaussian filter according to the provided parameters.
		'''

		self.pulse = self._generateGaussian(1.0,self.samplesPerSymbol, self.bt, self.samplesPerSymbol)



	def run(self):
		if self.sink.running:
			while self.running:
				if not self.input.empty():
					data = self.input.get()
					inp = []
					# Generating NRZ signal
					for bit in data:
						inp += [1.0 if bit=="1" else -1.0 for i in range(self.samplesPerSymbol)]

					# Applying gaussian filter
					outputGaussianFilter = np.convolve(inp, self.pulse)

					# Generating IQ samples
					output = []
					tmp = 0
					output.append(math.cos(tmp)+1j*math.sin(tmp))
					for i in range(1,len(outputGaussianFilter)):
						tmp = tmp+math.pi*self.modulationIndex*outputGaussianFilter[i-1]/float(self.samplesPerSymbol)
						output.append(math.cos(tmp)+1j*math.sin(tmp))
					print("Transmitting IQ")
					self.sink.transmit(output)
		else:
			self.running = False
