from scapy.all import *
import subprocess,struct
from mirage.libs import io,utils,wireless

class ADBDevice(wireless.Device):
	'''
	This device allows to communicate with an Android Device using **adb** in order to monitor Bluetooth Low Energy HCI packets.
	
	The corresponding interfaces are : ``adbX`` (e.g. "adb0")

	The following capabilities are actually supported :

	+-----------------------------------+----------------+
	| Capability			    | Available ?    |
	+===================================+================+
	| SCANNING                          | no             |
	+-----------------------------------+----------------+
	| ADVERTISING                       | no             |
	+-----------------------------------+----------------+
	| SNIFFING_ADVERTISEMENTS           | no             |
	+-----------------------------------+----------------+
	| SNIFFING_NEW_CONNECTION           | no             |
	+-----------------------------------+----------------+
	| SNIFFING_EXISTING_CONNECTION      | no             |
	+-----------------------------------+----------------+
	| JAMMING_CONNECTIONS               | no             |
	+-----------------------------------+----------------+
	| JAMMING_ADVERTISEMENTS            | no             |
	+-----------------------------------+----------------+
	| HIJACKING_CONNECTIONS             | no             |
	+-----------------------------------+----------------+
	| INITIATING_CONNECTION             | no             |
	+-----------------------------------+----------------+
	| RECEIVING_CONNECTION              | no             |
	+-----------------------------------+----------------+
	| COMMUNICATING_AS_MASTER           | no             |
	+-----------------------------------+----------------+
	| COMMUNICATING_AS_SLAVE            | no             |
	+-----------------------------------+----------------+
	| HCI_MONITORING                    | yes            |
	+-----------------------------------+----------------+

	.. warning::

		- You must install a recent version of **adb** in order to monitor a smartphone.
		- The full path to the binary **adb** should be present in the *PATH* environment variable.
		- You should enable the *Developper mode*, *USB Debugging* and *Bluetooth logging* on your smartphone. 

		If you don't know how to configure your smartphone, please follow the instructions presented `here <http://www.fte.com/webhelp/sodera/Content/Documentation/WhitePapers/BPA600/Encryption/GettingAndroidLinkKey/RetrievingHCIlog.htm>`_.
	'''
	sharedMethods = [
		"getConnections",
		"switchConnection",
		"getCurrentConnection",
		"getAddressByHandle", 
		"getCurrentHandle",
		"getCurrentConnectionMode",
		"isConnected",
		"getSnoopFileLocation",
		"getSnoopFileSize",
		"getSerial",
		"getDeviceIndex"
		]
	@classmethod
	def startADBDaemon(cls):
		'''
		This class method starts the ADB daemon server.

		:return: boolean indicating if the ADB server was successfully launched
		:rtype: bool

		:Example:

			>>> ADBDevice.startADBDaemon()
			True

		'''
		try:
			result = subprocess.run(["adb","start-server"], stdout=subprocess.DEVNULL, stderr = subprocess.DEVNULL)
			return result.returncode == 0
		except:
			io.fail("Mirage fails to start ADB daemon.")
			return False
			
	@classmethod
	def stopADBDaemon(cls):
		'''
		This class method stops the ADB daemon server.

		:return: boolean indicating if the ADB server was successfully stopped
		:rtype: bool

		:Example:

			>>> ADBDevice.stopADBDaemon()
			True

		'''
		try:
			result = subprocess.run(["adb","stop-server"], stdout=subprocess.DEVNULL, stderr = subprocess.DEVNULL)
			return result.returncode == 0
		except:
			io.fail("Mirage fails to stop ADB daemon. Exiting ...")
			return False
	@classmethod
	def findADBDevices(cls,index=None):
		'''
		This class method allows to find a specific ADB device, by providing the device's index. 
		If no index is provided, it returns a list of every devices found.
		If no device has been found, None is returned.

		:param index: device's index
		:type index: int
		:return: string indicating the device
		:rtype: str

		:Example:
			
			>>> ADBDevice.findADBDevices(0)
			'3e95c5e'
			>>> ADBDevice.findADBDevices()
			['3e95c5e','3e95c5f']

		
		'''
		try:
			result = subprocess.run(["adb","devices"], stdout=subprocess.PIPE, stderr = subprocess.DEVNULL)
			adbDevicesList = [i.split("\t")[0] for i in result.stdout.decode('ascii').split("\n")[1:-2]]
			if index is None:
				return adbDevicesList
			else:			
				try:
					adbDevice = adbDevicesList[index]
				except IndexError:
					return None
				return adbDevice
			return None
		except:
			io.fail("Mirage fails to find ADB devices. Exiting ...")
			return None

	def getDeviceIndex(self):
		'''
		This method returns the index of the current ADB device.

		:return: device's index
		:rtype: int

		:Example:
			
			>>> device.getDeviceIndex()
			0

		.. note::

			This method is a **shared method** and can be called from the corresponding Emitters / Receivers.


		'''
		return self.index

	def _runADBCommand(self,command):
		commandList = ["adb","-s",self.adbDevice,"shell"] + command.split(" ")	
		result = subprocess.run(commandList,stdout=subprocess.PIPE, stderr=subprocess.PIPE)
		return (result.stdout, result.stderr, result.returncode)

	def _isBtsnoopPortAvailable(self):
		_,_,returncode = self._runADBCommand("netstat -a | grep 8872")
		return (returncode == 0)

	def _openBtsnoopSocket(self):
		result = subprocess.run(["adb","-s",self.adbDevice,"forward","tcp:8872","tcp:8872"],stdout=subprocess.PIPE, stderr=subprocess.PIPE)
		if result.returncode == 0:
			s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
			s.connect(("127.0.0.1", 8872))
			return s
		return None

	def _getNewSnoopFileData(self,location, size):
		stdout, _, _ = self._runADBCommand("tail -c +"+str(self.size)+" "+location)
		return stdout

	def _isPacketHeader(self,buffer):
		header = buffer[:24]	
		originalLength, includedLength, flags, drops, timestamp = struct.unpack( ">IIIIq", header)
		return originalLength == includedLength

	def _getSnoopFileLocation(self):
		stdout, _, returncode = self._runADBCommand("cat /etc/bluetooth/bt_stack.conf | grep BtSnoopLogOutput")
		if returncode == 0:
			# The option has been found in the bt_stack.conf file
			snoopEnabled = ((stdout.decode('ascii').replace("\n","")).split('=')[1] == "true")
			stdout, _, returncode = self._runADBCommand("cat /etc/bluetooth/bt_stack.conf | grep BtSnoopFileName")
			if returncode == 0:
				path = (stdout.decode('ascii').replace("\n","")).split('=')[1]
				_,_,returncode = self._runADBCommand("test -f "+path)
				return (snoopEnabled and returncode == 0,path)
		else:
			# The option has not been found in the bt_stack.conf file
			possiblePaths = [
					"/sdcard/btsnoop_hci.log",
					"/data/log/bt/btsnoop_hci.log", # Samsung
					"/sdcard/MIUI/debug_log/common/btsnoop_hci.log" # MIUI
					]

			for path in possiblePaths:
				_,_,returncode = self._runADBCommand("test -f "+path)
				if returncode == 0:
					return (True,path)
			stdout, _, returncode = self._runADBCommand("find /sdcard/* -name btsnoop_hci.log | head -n1")
			print(stdout.decode('ascii').replace("\n","") != "")
			return (stdout.decode('ascii').replace("\n","") != "",stdout.decode('ascii').replace("\n",""))

	def getSnoopFileLocation(self):
		'''
		This method returns the snoop file location on the smartphone.

		:return: snoop file location
		:rtype: str

		:Example:
			
			>>> device.getSnoopFileLocation()
			'/sdcard/btsnoop_hci.log'

		.. note::

			This method is a **shared method** and can be called from the corresponding Emitters / Receivers.


		'''
		if self.socket is None:
			return self.location
		else:
			return "TCP socket : 127.0.0.1:8872"

	def getSnoopFileSize(self):
		'''
		This method returns the snoop file size on the smartphone.

		:return: snoop file size
		:rtype: int

		:Example:
			
			>>> device.getSnoopFileSize()
			8927994

		.. note::

			This method is a **shared method** and can be called from the corresponding Emitters / Receivers.


		'''
		if self.socket is None:
			return self.size
		else:
			return -1
	def getSerial(self):
		'''
		This method returns the serial number of the smartphone.

		:return: serial number
		:rtype: str

		:Example:
		
			>>> device.getSerial()
			'3e95c5e'

		.. note::

			This method is a **shared method** and can be called from the corresponding Emitters / Receivers.

		'''
		return self.adbDevice

	def _getSizeOfSnoopFile(self, location):
		stdout, stderr, returncode = self._runADBCommand("stat -c %s "+location)
		return int(stdout.decode('ascii').replace('\n',''))


	def _getPacket(self,buffer):
		header = buffer[:24]	
		originalLength, includedLength, flags, drops, timestamp = struct.unpack( ">IIIIq", header)
		data = buffer[24:24+includedLength]
		output = None if len(data) != includedLength else HCI_Hdr(data)
		return (buffer[24+includedLength:],includedLength,output)

	def getCurrentHandle(self):
		'''
		This method returns the connection Handle actually in use.
		If no connection is established, its value is equal to -1.

		:return: connection Handle
		:rtype: int

		.. note::

			This method is a **shared method** and can be called from the corresponding Emitters / Receivers.

		'''
		return self.currentHandle

	def getConnections(self):
		'''
		This method returns a list of couple (connection handle / BD address) representing the connections actually established.
		A connection is described by a dictionary containing an handle and a BD address : ``{"handle":72, "address":'AA:BB:CC:DD:EE:FF'}``

		:return: list of connections established
		:rtype: list of dict

		:Example:
			
			>>> device.getConnections()
			[{'handle':72, 'address':'AA:BB:CC:DD:EE:FF'}]

		.. note::

			This method is a **shared method** and can be called from the corresponding Emitters / Receivers.

		'''
		return self.handles

	def getAddressByHandle(self,handle):
		'''
		This method returns the BD address associated to the provided connection handle if a corresponding connection is established. If no connection uses this handle, it returns `None`.
	
		:param handle: connection handle
		:type handle: int
		:return: address of the corresponding connection
		:rtype: str

		:Example:
		
			>>> device.getAddressByHandle(72)
			'AA:BB:CC:DD:EE:FF'
			>>> device.getAddressByHandle(4)
			None

		.. note::

			This method is a **shared method** and can be called from the corresponding Emitters / Receivers.

		'''
		for connection in self.handles:
			if connection['handle'] == handle:
				return connection['address']
		return None

	def getCurrentConnection(self):
		'''
		This method returns the BD address associated to the current connection. If no connection is established, it returns None.

		:return: address of the current connection
		:rtype: str

		:Example:
		
			>>> device.getCurrentConnection()
			'AA:BB:CC:DD:EE:FF'
			>>> device.getCurrentConnection()
			None
			
		.. note::

			This method is a **shared method** and can be called from the corresponding Emitters / Receivers.

		'''
		return self.getAddressByHandle(self.getCurrentHandle())

	def switchConnection(self,address):
		'''
		This method allows to switch the current connection to another connection established by providing the associated BD address.

		:param address: BD Address of the new current connection
		:type address: str
		:return: boolean indicating if the operation was successful
		:rtype: bool

		:Example:
		
			>>> device.getCurrentConnection()
			'AA:BB:CC:DD:EE:FF'
			>>> device.switchConnection('11:22:33:44:55:66')
			>>> device.getCurrentConnection()
			'11:22:33:44:55:66'
			
		.. note::

			This method is a **shared method** and can be called from the corresponding Emitters / Receivers.

		'''
		for connection in self.handles:
			if connection['address'] == address.upper():
				self._setCurrentHandle(connection['handle'])
				return True
		return False

	def _setCurrentHandle(self,handle,address="",mode="public"):
		if handle != -1:
			found = False
			for connection in self.handles:
				if connection["handle"] == handle:
					found = True
			if not found:
				self.handles.append({"address":address.upper() if address is not None else "", "handle":handle, "mode":mode})
		self.currentHandle = handle

	def getCurrentConnectionMode(self):
		'''
		This method returns the connection mode ("public" or "random") of the currently established connection.
	
		:return: connection mode of the current connection ("public" or "random")
		:rtype: str

		:Example:
		
			>>> device.getCurrentConnectionMode()
			'public'

		.. note::

			This method is a **shared method** and can be called from the corresponding Emitters / Receivers.

		'''
		handle = self.getCurrentHandle()
		for connection in self.handles:
			if connection['handle'] == handle:
				return connection['mode']
		return None

	
	def isConnected(self):
		'''
		This method returns a boolean indicating if a connection is actually established.

		:return: boolean indicating if a connection is established
		:rtype: bool

		:Example:
		
			>>> device.isConnected()
			True

		.. note::

			This method is a **shared method** and can be called from the corresponding Emitters / Receivers.

		'''
		return (self.getCurrentHandle() != -1)

	def _removeConnectionHandle(self,handle):
		for connection in self.handles:
			if connection["handle"] == handle:
				self.handles.remove(connection)
		if handle == self.getCurrentHandle():
			if len(self.handles) > 0:
				self._setCurrentHandle(self.handles[0]['handle'])
			else:
				self._setCurrentHandle(-1)

	def recv(self):
		if self.socket is None:
			if len(self.buffer) < 24:
				self.buffer += self._getNewSnoopFileData(self.location,self.size)
			if len(self.buffer) >= 24:
				while not self._isPacketHeader(self.buffer):
					self.size += 1
					self.buffer = self.buffer[1:]
				if len(self.buffer) >= 24:
					self.buffer,includedLength,packet = self._getPacket(self.buffer)
					self.size += 24 + includedLength
					if packet is not None:			
						return packet
		else:
			try:
				self.buffer += self.socket.recv(1)
			except BlockingIOError:
				pass
			if len(self.buffer) >= 24:
				if self._isPacketHeader(self.buffer):
					buffer,includedLength,packet = self._getPacket(self.buffer)
					if len(self.buffer) >= 24 + includedLength and packet is not None:
						self.buffer = buffer
						return packet
					
				else:
					self.buffer = self.buffer[1:]

	def __init__(self,interface):
		super().__init__(interface=interface)
		self.currentHandle = -1
		self.handles = []
		self.ready = False
		if "adb" == interface:
			self.index = 0
			self.interface = "adb0"
		elif "adb" == interface[:3]:
			self.index = int(interface.split("adb")[1])
			self.interface = interface		
		ADBDevice.startADBDaemon()
		self.adbDevice = ADBDevice.findADBDevices(self.index)

	def isUp(self):
		return self.ready
		
	def init(self):
		if self.adbDevice is not None:
			self.capabilities = ["HCI_MONITORING"]
			self.socket = None
			io.success("ADB Device found: "+self.adbDevice)
			io.info("Trying to send adb shell commands ...")
			output,_,_ = self._runADBCommand("echo helloworld")
			if output == b"helloworld\n":
				io.success("Yeah, we can send commands.")
				if self._isBtsnoopPortAvailable():
					self.socket = self._openBtsnoopSocket()
					if self.socket is not None:
						start = self.socket.recv(16)
						if b"btsnoop" in start:
							io.success("Connected to TCP Btsnoop service !")
							self.socket.setblocking(0)
							self.buffer = b""
							self.ready = True
						else:
							io.fail("TCP service not available !")
							self.socket = None
				if self.socket is None:
					io.info("Looking for HCI logs ...")
					found, location = self._getSnoopFileLocation()
					if found:
						self.location = location
						io.success("Log found: "+location)
						io.info("Calculating size ...")
						size = self._getSizeOfSnoopFile(location)
						io.success("Size found: "+str(size))
						self.size = size + 1
						self.buffer = b""
						self.ready = True
					else:
						io.fail("Log not found, aborting ...")
						self.ready = False
	def close(self):
		ADBDevice.stopADBDaemon()
