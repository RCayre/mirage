from serial import Serial,SerialException
from serial.tools.list_ports import comports
from mirage.libs.wireless import Device
from mirage.libs.ir_utils.scapy_irma_layers import *
from mirage.libs import io

class IRMADevice(Device):
	'''
	This device allows to communicate with an IRMA device in order to sniff and inject IR signals.
	The corresponding interfaces are : ``irmaX`` (e.g. "irma0").

	The following capabilities are actually supported :

	+-----------------------------------+----------------+
	| Capability			    | Available ?    |
	+===================================+================+
	| SNIFFING                          | yes            |
	+-----------------------------------+----------------+
	| INJECTING                         | yes            |
	+-----------------------------------+----------------+
	| CHANGING_FREQUENCY                | yes            |
	+-----------------------------------+----------------+

	.. warning::

		This device has been created in order to interact with IR signals using Mirage.
		It requires an Arduino Uno or Mini, and the electronic schematic and firmware source code are released as open source documents.

	'''
	sharedMethods = [
				"setFrequency",
				"getFrequency",
				"waitData",
				"reset",
				"getSerialPort",
				"getDeviceIndex"
			]


	@classmethod
	def findIRMAs(cls,index=None):
		irmaList = [i[0] for i in comports() if 
		(isinstance(i,tuple) and ("VID:PID=2341:0043" in port[-1] or "VID:PID=1A86:7523" in port[-1])) or
		(i.vid == 0x2341 and i.pid == 0x0043) or (i.vid == 0x1A86 and i.pid == 0x7523)
		]
		if index is None:
			return None
		else:			
			try:
				irma = irmaList[index]
			except IndexError:
				return None
			return irma
		return None

	def __init__(self,interface):
		super().__init__(interface=interface)
		self.index = None
		if "irma" == interface:
			self.index = 0
			self.interface = "irma0"
		elif "irma" == interface[:4]:
			self.index = int(interface.split("irma")[1])
			self.interface = interface
		self.irma = IRMADevice.findIRMAs(self.index)
		if self.irma is not None:
			try:
				self.port = self.irma
				self.irma = Serial(port = self.irma, baudrate=200000)
				self.ready = False
				self._flush()
			except SerialException:
				io.fail("Serial communication not ready !")
				self.ready = False
				self.irma = None
		else:
			io.fail("No IRMA device found !")
			self.ready = False


	def _flush(self):
		while self.irma.in_waiting:
			self.irma.read()

	def _enterCommandMode(self):
		while self._isListening():
			utils.wait(seconds=0.01)
		self.commandMode = True

	def _exitCommandMode(self):
		self.commandMode = False

	def _commandModeEnabled(self):
		return self.commandMode

	def _enterListeningMode(self):
		self.listeningMode = True

	def _exitListeningMode(self):
		self.listeningMode = False

	def _isListening(self):
		return self.listeningMode

	def _receivePacket(self):
		while not self.irma.readable():
			utils.wait(seconds=0.01)
		buffer = b""
		if self.irma.inWaiting():
			self._enterListeningMode()
			while buffer[-2:] != b"\x5A\x5A":
				#print(buffer)
				buffer += self.irma.read()
			self._exitListeningMode()
			#IRma_Hdr(buffer[:-2]).show()
			return IRma_Hdr(buffer[:-2])
		else:
			return None

	def _sendPacket(self,pkt):
		self.irma.write(raw(pkt))

	def init(self):
		if self.irma is not None:
			self.listeningMode = False
			self.commandMode = False
			reset = False
			pkt = None
			while pkt is None:
				pkt = self._receivePacket()
			if str(pkt) == str(IRma_Hdr()/IRma_Response()/Resp_IRma_Ready()):
				reset = self.reset()
			self.capabilities = ["SNIFFING","INJECTING","CHANGING_FREQUENCY"]
			self.ready = True

	def isUp(self):
		return self.ready

	def send(self,packet):
		while self._commandModeEnabled():
			utils.wait(seconds=0.01)
		self._sendPacket(packet)


	def recv(self):
		if not self._commandModeEnabled():
			packet = self._receivePacket()
			return packet

	def getDeviceIndex(self):
		'''
		This method returns the index of the current IRma device.

		:return: device's index
		:rtype: int

		:Example:
			
			>>> device.getDeviceIndex()
			0

		.. note::

			This method is a **shared method** and can be called from the corresponding Emitters / Receivers.


		'''
		return self.index

	def getSerialPort(self):
		'''
		This method returns the serial port of the current IRma device.

		:return: device's serial port
		:rtype: str

		:Example:
			
			>>> device.getSerialPort()
			'/dev/ttyUSB0'

		.. note::

			This method is a **shared method** and can be called from the corresponding Emitters / Receivers.


		'''
		return self.port

	def reset(self):
		'''
		This method resets the current IRma device.

		:Example:
			
			>>> device.reset()

		.. note::

			This method is a **shared method** and can be called from the corresponding Emitters / Receivers.


		'''
		self._enterCommandMode()
		self._sendPacket(IRma_Hdr()/IRma_Request()/Req_IRma_Reset())
		pkt = None
		while pkt is None:
			pkt = self._receivePacket()
		self._exitCommandMode()
		return raw(pkt) == raw(IRma_Hdr()/IRma_Response()/Resp_IRma_Reset())


	def waitData(self):
		'''
		This method puts the current IRma device in listening mode, allowing to analyze the incoming IR signals.

		:Example:
			
			>>> device.waitData()

		.. note::

			This method is a **shared method** and can be called from the corresponding Emitters / Receivers.


		'''
		self._enterCommandMode()
		self._sendPacket(IRma_Hdr()/IRma_Request()/Req_IRma_Recv())
		self._exitCommandMode()
		
	def getFrequency(self):
		'''
		This method returns the frequency in use by the current IRma device (in kHz)
		
		:return: frequency currently in use
		:rtype: int

		:Example:
			
			>>> device.getFrequency()
			38

		.. note::

			This method is a **shared method** and can be called from the corresponding Emitters / Receivers.


		'''
		self._enterCommandMode()
		self._sendPacket(IRma_Hdr()/IRma_Request()/Req_IRma_GetFreq())
		pkt = None
		while pkt is None or not (Resp_IRma_Freq in pkt):
			pkt = self._receivePacket()
		self._exitCommandMode()
		return pkt.freq

	def setFrequency(self, freq):
		'''
		This method allow to set the frequency of the current IRma device (in kHz).
		
		:param freq: frequency to use
		:type freq: int

		:Example:
			
			>>> device.setFrequency(38)

		.. note::

			This method is a **shared method** and can be called from the corresponding Emitters / Receivers.


		'''
		self._enterCommandMode()
		self._sendPacket(IRma_Hdr()/IRma_Request()/Req_IRma_SetFreq(freq=freq))
		pkt = None
		while pkt is None or not (Resp_IRma_Freq in pkt):
			pkt = self._receivePacket()
		self._exitCommandMode()
		return pkt.freq == freq
