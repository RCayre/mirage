from mirage.libs.common.sdr.sources import SDRSource
from mirage.libs.common.sdr.decoders import SDRDecoder
from mirage.libs import utils,io
import queue,threading,math

'''
This component implements multiple Software Defined Radio demodulators allowing to demodulate an IQ stream to recover packet's data.
'''

class SDRDemodulator:
	'''
	This class implements a Sofware Defined Radio demodulator: every specific demodulator has to inherit from this class and implement the ``run`` method.
	When the demodulator is started, it processes the IQ stream received from the ``SDRSource``, performs the operations needed to demodulate the stream and adds the demodulated packets to the output queue using ``generateOutput`` method.
	'''
	def __init__(self):
		self.source = None
		self.count = 0
		self.decoders = []
		self.running = False
		self.output = queue.Queue()

	def setSource(self,source):
		'''
		This method associates a ``SDRSource`` to the demodulator.

		:param source: source to associate
		:type source: ``SDRSource``

		'''
		if isinstance(source,SDRSource):
			self.source = source

	def addDecoder(self,decoder):
		'''
		This method associates a ``SDRDecoder`` to the demodulator.

		:param decoder: decoder to associate
		:type decoder: ``SDRDecoder``

		'''
		if isinstance(decoder, SDRDecoder):
			self.decoders.append(decoder)

	def getDecoders(self):
		return self.decoders

	def removeDecoders(self):
		'''
		This method removes every associated decoders.
		'''
		self.decoders = []

	def generateOutput(self,demodulatedData,iqSamples):
		'''
		This method allows to generate an output, by providing the demodulated data and the corresponding IQ.
		The output will be processed sequentially by every associated decoders, then it is added to the output queue.

		:param demodulatedData: demodulated data
		:type demodulatedData: bytes
		:param iqSamples: IQ samples linked to the demodulated data
		:type iqSamples: list of complex

		'''
		for d in self.decoders:
			demodulatedData,iqSamples = d.decode(demodulatedData, iqSamples)
		if demodulatedData is not None and iqSamples is not None:
			self.output.put((demodulatedData,iqSamples))

	def getOutput(self):
		'''
		This method returns the next demodulated and decoded element from the output queue.

		:return: tuple of demodulated data and the correspond IQ samples
		:rtype: (bytes, list of complex)

		'''
		if not self.output.empty():
			return self.output.get()
		else:
			return None

	def start(self):
		'''
		This method starts the demodulator.

		:Example:

			>>> demodulator.start()

		'''
		self.thread = threading.Thread(target=self.run,daemon=True)
		self.running = True
		self.thread.start()

	def __del__(self):
		self.stop()

	def stop(self):
		'''
		This method stops the demodulator.

		:Example:

			>>> demodulator.start()

		'''

		self.running = False

	def run(self):
		pass


class FSK2Demodulator(SDRDemodulator):
	'''
	This demodulator allows to demodulate a 2-Frequency Shift Keying (2-FSK) stream.
	'''
	def __init__(self,samplesPerSymbol=1,samplesBefore=60 , samplesAfter=60,size=8*40,preamble = "01101011011111011001000101110001"):
		super().__init__()
		self.samplesPerSymbol = samplesPerSymbol
		self.samplesBefore = samplesBefore
		self.samplesAfter = samplesAfter
		self.size = size
		self.preamble = preamble
		self.numberOfBuffers = samplesPerSymbol
		self.demodBuffer = ["" for i in range(samplesPerSymbol)]

	def run(self):

		i = 0
		step = 0

		if self.source.running:
			while i >= len(self.source.iqStream) and self.running:
				utils.wait(seconds=0.001)
			while self.running:

				if  i < len(self.source.iqStream):
					i0 = self.source.iqStream[i-1].real
					q0 = self.source.iqStream[i-1].imag
					i1 = self.source.iqStream[i].real
					q1 = self.source.iqStream[i].imag

					self.demodBuffer[step] += "1" if math.atan2(i0*q1 - q0*i1,i0*i1+q0*q1) > 0 else "0"
					if len(self.demodBuffer[step]) >= len(self.preamble):
						if self.preamble != self.demodBuffer[step][:len(self.preamble)]:
							self.demodBuffer[step] = self.demodBuffer[step][1:]
						else:
							if len(self.demodBuffer[step]) == self.size:
								demodulatedBlock = self.demodBuffer[step]
								iqBlock = self.source.iqStream[(i-1)-((self.size-1)*self.numberOfBuffers)-self.samplesBefore:i+self.samplesAfter]
								self.generateOutput(demodulatedBlock,iqBlock)
								self.source.iqStream = self.source.iqStream[i+1:]
								i = 1
								self.count += 1
								for j in range(self.numberOfBuffers):
									self.demodBuffer[j] = ""


						step = (step + 1) % self.numberOfBuffers
						i += 1

		else:
			self.running = False

class FasterFSK2Demodulator(SDRDemodulator):
	'''
	This **experimental** demodulator allows to demodulate a 2-Frequency Shift Keying stream.
	It is an experimental demodulator based on a amplitude filter, which tries to estimate the noise level to demodulate the stream only if the amplitude is above the noise thresold.
	The main objective of this implementation is to increase the demodulator's speed, however it may miss some packets if the noise thresold is wrong.

	'''
	def __init__(self,samplesPerSymbol=1,samplesBefore=60 , samplesAfter=60,size=8*40,preamble = "01101011011111011001000101110001"):
		super().__init__()
		self.samplesPerSymbol = samplesPerSymbol
		self.samplesBefore = samplesBefore
		self.samplesAfter = samplesAfter
		self.size = size
		self.noiseThresold = None
		self.preamble = preamble
		self.numberOfBuffers = samplesPerSymbol
		self.noiseLevel = 0
		self.noiseState = []
		self.demodBuffer = ["" for i in range(samplesPerSymbol)]


	def stop(self):
		self.running = False
		self.noiseLevel = 0
		self.noiseThresold = None

	def run(self):
		i = 0
		step = 0
		demodulating = False
		demodulatingCount = 0
		if self.source.running:
			while i >= len(self.source.iqStream) and self.running:
				utils.wait(seconds=0.00001)

			while self.running:
				if i < len(self.source.iqStream):

					if not demodulating:
							increment = (self.size*self.numberOfBuffers) // 2
							if self.noiseThresold is None:
								values = []
								for j in range(increment,self.source.blockLength // 2,increment):
									values += [self.source.iqStream[j].imag*self.source.iqStream[j].imag+self.source.iqStream[j].real*self.source.iqStream[j].real]

								self.noiseThresold = sum(values)/len(values)
								#io.info("<Experimental Demodulator> Noise thresold: "+str(self.noiseThresold))


							else:
								amplitude = self.source.iqStream[i].real*self.source.iqStream[i].real+self.source.iqStream[i].imag*self.source.iqStream[i].imag
								if len(self.noiseState) == 10:
									if self.noiseState.count(False) > self.noiseState.count(True):
										self.noiseLevel += 0.25
										self.noiseState = []

								if amplitude > self.noiseThresold*self.noiseLevel:
									if i - increment > 1:
										demodulatingCount = self.size * self.numberOfBuffers * 2
										demodulating = True
										i -= increment
										self.source.iqStream = self.source.iqStream[i-self.samplesBefore:] # test !!!
										i = self.samplesBefore
									else:
										i += increment

								else:
									i += increment
					else:

						i0 = self.source.iqStream[i-1].real
						q0 = self.source.iqStream[i-1].imag
						i1 = self.source.iqStream[i].real
						q1 = self.source.iqStream[i].imag

						self.demodBuffer[step] += "1" if math.atan2(i0*q1 - q0*i1,i0*i1+q0*q1) > 0 else "0"# (i0*q1 - i1*q0)

						if len(self.demodBuffer[step]) >= len(self.preamble):
							if self.preamble != self.demodBuffer[step][:len(self.preamble)]:
								self.demodBuffer[step] = self.demodBuffer[step][1:]
							else:
								if len(self.demodBuffer[step]) == self.size:
									demodulatedBlock = self.demodBuffer[step]
									iqBlock = self.source.iqStream[(i-1)-((self.size-1)*self.numberOfBuffers)-self.samplesBefore:i+self.samplesAfter]
									self.generateOutput(demodulatedBlock,iqBlock)
									self.source.iqStream = self.source.iqStream[i+1:]
									i = 1
									self.count += 1
									self.noiseState.append(True)

									for j in range(self.numberOfBuffers):
										self.demodBuffer[j] = ""
									demodulating = False

						step = (step + 1) % self.numberOfBuffers
						i += 1
						demodulatingCount -= 1
						if demodulatingCount <= 0:
							self.noiseState.append(False)
							for j in range(self.numberOfBuffers):
								self.demodBuffer[j] = ""
							demodulating = False
			self.running = False
		else:
			self.running = False
