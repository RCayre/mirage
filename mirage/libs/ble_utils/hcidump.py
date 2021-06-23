from scapy.all import *
import subprocess,struct
from mirage.libs import io,utils,wireless

class BLEHcidumpDevice(wireless.Device):
	'''
	This device allows to monitor an HCI interface using **hcidump**. 
	
	The corresponding interfaces are : ``hcidumpX`` (e.g. "hcidump0" for monitoring the interface "hci0").

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
	| HIJACKING_MASTER                  | no             |
	+-----------------------------------+----------------+
	| HIJACKING_SLAVE                   | no             |
	+-----------------------------------+----------------+
	| INJECTING                         | no             |
	+-----------------------------------+----------------+
	| MITMING_EXISTING_CONNECTION       | no             |
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

		- You must install a recent version of **hcidump** in order to monitor an HCI device.
		- The full path to the binary **hcidump** should be present in the *PATH* environment variable.

	'''
	sharedMethods = [
		"getConnections",
		"switchConnection",
		"getCurrentConnection",
		"getCurrentConnectionMode",
		"getAddressByHandle", 
		"getCurrentHandle",
		"isConnected", 
		"getHCIInterface",
		"getDeviceIndex"
		]


	def getDeviceIndex(self):
		'''
		This method returns the index of the current HCIDump device.

		:return: device's index
		:rtype: int

		:Example:
			
			>>> device.getDeviceIndex()
			0

		'''
		return self.index

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
		output = self.process.stdout.readline()
		if output:
			line = output.strip().decode('ascii')

			if "HCI sniffer" in line or "device:" in line:
				return None

			if line[0] == "<" or line[0] == ">":
				bytesLine = bytes.fromhex(line[1:].replace(' ',''))
				self.buffer += bytesLine
				if len(bytesLine) < 20:
					packet = HCI_Hdr(self.buffer)
					self.buffer = b""
					return packet
			else:
				bytesLine = bytes.fromhex(line.replace(' ',''))
				self.buffer += bytesLine
				if len(bytesLine) < 20:
					packet = HCI_Hdr(self.buffer)
					self.buffer = b""
					return packet
		
	def __init__(self,interface):
		super().__init__(interface=interface)
		self.currentHandle = -1
		self.handles = []
		self.ready = False
		if "hcidump" == interface:
			self.index = 0
			self.interface = "hcidump0"
		elif "hcidump" == interface[:7]:
			self.index = int(interface.split("hcidump")[1])
			self.interface = interface
		self.hciInterface = "hci"+str(self.index)

	def _launchHcidumpProcess(self,index):
		self.process = subprocess.Popen(["hcidump","-i", self.hciInterface,"-R"], stdout=subprocess.PIPE)
		utils.wait(seconds=1)
		return self.process.poll() is None

	def getHCIInterface(self):
		'''
		This method returns the HCI Interface monitored by this HCIDump device.

		:return: monitored HCI interface
		:rtype: str

		:Example:

			>>> device.getHCIInterface()
			'hci0'

		'''
		return self.hciInterface

	def isUp(self):
		return self.ready		

	def init(self):
		success = self._launchHcidumpProcess(self.index)
		if success:
			self.capabilities = ["HCI_MONITORING"]
			io.success("Hcidump successfully attached to device : hci"+str(self.index))
			self.buffer = b""
			self.ready = True
		else:
			io.fail("Hcidump failed to attach to device : hci"+str(self.index))

	def close(self):
		self.process.terminate()
