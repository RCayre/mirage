from mirage.libs import io,utils
from mirage.libs.wireless_utils.device import Device
from os.path import isfile
from struct import unpack,pack
import time

class PCAPDevice(Device):
	'''
	This class provides an easy way to implement a PCAP writer or reader as a Mirage Device.

	  * If the provided interface is an existing file, the PCAPDevice is set in "reading mode".
	  * If the provided interface is a non existing file, the PCAPDevice is set in "writing mode".

	Every child classes of PCAPDevice should provide :

	  * the *DLT* class attribute, defining the DLT of the PCAP file
	  * the *SCAPY_LAYER* class attribute (optional), defining a scapy layer automatically used to encapsulate the packets

	The ``send`` and ``recv`` methods uses the timestamp in order to write and read the pcap "in real time".
	The ``putPacket``, ``getPacket`` and ``getAllPackets`` methods allow to manipulate directly the packets without taking into account the timestamp values.
	'''
	DLT = 0
	SCAPY_LAYER = None

	sharedMethods = ["putPacket", "getPacket", "getAllPackets","startReading","stopReading","getMode"] 

	def __init__(self,interface):
		super().__init__(interface=interface)
		self.filename = interface
		self.file = None
		self.ready = False
		self.reading = False
		self.initialTimestamp = None
		self.beginningTimestamp = None
		self.mode = None
		if interface[-5:] == ".pcap":
			self.openFile()

		else:
			self.file = None
			self.ready = False

	def openFile(self):
		if isfile(self.filename):
			try:
				self.mode = "read"
				self.file = open(self.filename,"rb")

			except IOError as e:
				if e.errno == errno.EACCES:
					io.fail("You don't have permissions to access this file !")
		else:
			self.mode = "write"
			self.file = open(self.filename,"wb")
	def getMode(self):
		'''
		This method returns the mode used by this PCAP Device.
		
		:return: current mode ("read" or "write")
		:rtype: str

		:Example:
			
			>>> device.getMode()
			'read'

		.. note::

			This method is a **shared method** and can be called from the corresponding Emitters / Receivers.
		'''

		return self.mode

	def startReading(self):
		'''
		This method starts the reading mode.
		'''
		self.reading = True

	def stopReading(self):
		'''
		This method stops the reading mode.
		'''
		self.reading = False

	def _readHeader(self):
		try:
			header = self.file.read(24)
			magic,*others,dlt =  unpack('<IHHIIII',header)
			return (magic,dlt, True)
		except Exception as e:
			print(e)
			return (-1,-1, False)

	def _addHeader(self):
		dlt = self.DLT
		magic = 0xa1b2c3d4
		header = pack('<IHHIIII',
			magic,
			2,
			4,
			0,
			0,
			65535,
			dlt
		)
		try:
			self.file.write(header)
			return (magic,dlt,True)
		except Exception as e:
			print(e)
			return (-1,-1,False)
		
	
	def send(self,packet):
		'''
		This method writes a packet synchronously into the PCAP file.
		
		:param packet: packet to write
		:type packet: bytes or scapy frame (if `SCAPY_LAYER` is not None)
		'''
		if self.mode == "write":
			if self.SCAPY_LAYER is not None:
				packet = bytes(packet)
			self.putPacket(packet)

	def close(self):
		self.file.close()

	def isUp(self):
		return self.ready

	def init(self):
		'''
		This method initializes the PCAP file, by checking the header (if the Device is in reading mode) or by adding the header (if the Device is in writing mode).
		'''
		if self.mode == "read":
			initFunction = self._readHeader	
		else:
			initFunction = self._addHeader

		self.magic, self.dlt, success = initFunction()
		if success and self.magic == 0xa1b2c3d4 and self.DLT == self.dlt:
			io.success("PCAP file successfully loaded (DLT : "+str(self.dlt)+") ! ")
			self.ready = True
		else:
			self.ready = False

	def putPacket(self,data,timestamp = None):
		'''
		This method writes a packet asynchronously into the PCAP file.
	
		:param data: packet to write
		:type data: bytes or scapy frame (if `SCAPY_LAYER` is not None)
		:param timestamp: timestamp of the packet (optional)
		:type timestamp: float
		:return: boolean indicating if the operation was successful
		:rtype: bool
		'''
		try:
			if timestamp is None:
				timestamp = time.time()
			ts_sec = int(timestamp)
			ts_usec = int((timestamp - ts_sec)*1000000)
			header = pack(
			'<IIII',
			ts_sec,
			ts_usec,
			len(data),
			len(data)
			)
			self.file.write(header)
			self.file.write(data)
			return True
		except Exception as e:
			print(e)
			return False

	def getPacket(self):
		'''
		This method reads a packet asynchronously from the PCAP file and returns it to the user.
	
		:return: tuple composed of a boolean indicating if the packet exists and a tuple of (timestamp, packet)
		:rtype: tuple of (bool,tuple of (float,bytes))
		'''
		try:
			header = self.file.read(16)
			ts_sec, ts_usec, length1, length2 = unpack('<IIII',header)
			
			packet = self.file.read(length1)

			return (True,(ts_sec + ts_usec/1000000,packet))
		except:
			return (False,None)

	def getAllPackets(self):
		'''
		This method gets all packets stored in the PCAP file asynchronously and returns them.
	
		:return: list of packets (tuple of (timestamp, packet))
		:rtype: list of tuple of (timestamp, packet)
		'''
		if self.mode == "read":
			packetList = []
			while True:
				success,data = self.getPacket()
				if not success:
					break
				else:
					timestamp,packet = data
					packetList.append((timestamp,self.buildPacket(packet, timestamp)))

			return packetList


	def buildPacket(self,packet,timestamp):
		'''
		This method is used to encapsulate the packet into a scapy frame (if SCAPY_LAYER is not None).
		'''
		if self.SCAPY_LAYER is not None:
			return self.SCAPY_LAYER(packet)
		return packet

	def recv(self):
		'''
		This method gets the packets from the PCAP file asynchronously.
		'''
		if self.mode == "read":
			while not self.reading:
				utils.wait(seconds=0.00001)
			success,data = self.getPacket()
			if success:
				timestamp,packet = data
				if self.initialTimestamp is None:
					self.initialTimestamp = timestamp
					self.beginningTimestamp = utils.now()
				else:
					while timestamp - self.initialTimestamp > (utils.now() - self.beginningTimestamp):
						utils.wait(seconds=0.00001)
				return self.buildPacket(packet,timestamp)
			else:
				self.publish("stop")
				self.close()
