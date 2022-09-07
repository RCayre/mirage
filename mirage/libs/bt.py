from scapy.all import *
from queue import Queue
from threading import Lock
from mirage.core.module import WirelessModule
from mirage.libs.bt_utils.packets import *
from mirage.libs.bt_utils.assigned_numbers import AssignedNumbers
from mirage.libs.bt_utils.scapy_layers import *
from mirage.libs.bt_utils.scapy_vendor_specific import *
from mirage.libs.bt_utils.hciconfig import HCIConfig
from mirage.libs.bt_utils.constants import *
from mirage.libs import wireless,io,utils

class BtHCIDevice(wireless.Device):
	'''
	This device allows to communicate with an HCI Device in order to use Bluetooth protocol.
	The corresponding interfaces are : ``hciX`` (e.g. "hci0")
	'''
	sharedMethods = [
		"getConnections",
		"switchConnection",
		"getCurrentConnection",
		"getAddressByHandle",
		"getCurrentHandle",
		"isConnected",
		"setLocalName",
		"getLocalName",
		"getAddress",
		"setAddress",
		"getManufacturer",
		"isAddressChangeable"
		]

	def __init__(self,interface):
		super().__init__(interface=interface)
		self.pendingQueue = Queue()
		self.initializeBluetooth = True

	def _initBT(self):
		self._enterCommandMode()
		self._internalCommand(HCI_Cmd_Reset())
		self._internalCommand(HCI_Cmd_Set_Event_Mask(mask=b"\xFF\xFF\xFB\xFF\x07\xF8\xBF\x3D"))
		self._internalCommand(HCI_Cmd_Write_Inquiry_Mode(inquiry_mode=0x02))
		self._internalCommand(HCI_Cmd_Connect_Accept_Timeout())
		self._exitCommandMode()

	def init(self):
		'''
		This method initializes the communication with the HCI Device.
		'''
		self.isListening = False
		self.commandMode = False
		self.currentHandle = -1
		self.handles = []
		self.recvLock = Lock()
		self.commandResponses = Queue()
		self.ready = False
		if "hci" == self.interface[0:3]:
			self.adapter = int(self.interface[3:])
			if self._createSocket() and self.initializeBluetooth:
				self._initBT()

	def _createSocket(self):
		self.socket = None
		try:
			self.socket = BluetoothUserSocket(self.adapter)
		except BluetoothSocketError as e:
			if not utils.isRoot():
				io.warning("Mirage should be run as root to instanciate this device !")
				return False
			else:
				HCIConfig.down(self.adapter)
				try:
					self.socket = BluetoothUserSocket(self.adapter)
				except BluetoothSocketError as e:
					io.fail("Error during HCI device instanciation !")
					return False
		if self.socket is not None:
			io.success("HCI Device ("+self.interface+") successfully instanciated !")
			self.ready = True
			return True
		return False

	def isUp(self):
		return self.ready

	def send(self,data):
		'''
		This method allows to send raw HCI packet to the HCI device.
		'''
		self.socket.send(data)

	def _recv(self):
		if not self.pendingQueue.empty():
			recv = self.pendingQueue.get(block=True)
		else:
			self.recvLock.acquire()
			recv = self.socket.recv()
			self.recvLock.release()
		return recv


	def recv(self):
		'''
		This method allows to receive raw HCI packets from the HCI device.
		'''
		self._enterListening()
		try:
			if self.socket is not None and self.socket.fileno() != -1 and self.socket.readable():
				packet = self._recv()
				#packet.show()
				if self._commandModeEnabled() and packet.type == 0x04:
					self.commandResponses.put(packet)
					return None
				else:
					self._exitListening()
					return packet

			else:
				self._exitListening()
				utils.wait(seconds=0.0001)
			return None
		# An error may occur during a socket restart
		except OSError as e:
			self._exitListening()
			return None


	def _internalCommand(self,cmd,noResponse=False):
		cmd = HCI_Hdr()/HCI_Command_Hdr()/cmd
		while not self._commandModeEnabled():
			utils.wait(seconds=0.05)
		self._flushCommandResponses()

		self.send(cmd)
		if not noResponse:
			if self._isListening():
				getResponse = self.commandResponses.get
			else:
				getResponse = self._recv
			response = getResponse()
			#response.show()
			while response is None or response.type != 0x04 or response.code != 0xe:
				response = getResponse()
			if response.type == 0x04 and response.code == 0xe and response.opcode == cmd.opcode:
				if response.status != 0:
					raise BluetoothCommandError("Command %x failed with %x" % (cmd.opcode,response.status))
				return response
	def _enterCommandMode(self):
		self.commandMode = True
	def _exitCommandMode(self):
		self.commandMode = False
	def _commandModeEnabled(self):
		return self.commandMode

	def _enterListening(self):
		self.isListening = True
	def _exitListening(self):
		self.isListening = False
	def _isListening(self):
		return self.isListening

	def _flushCommandResponses(self):
		while not self.commandResponses.empty():
			self.commandResponses.get()
		if self.socket is not None:
			self.socket.flush()


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
		This method returns a list of couple (connection handle / address) representing the connections actually established.
		A connection is described by a dictionary containing an handle and a BD address : ``{"handle":72, "address":"AA:BB:CC:DD:EE:FF"}``

		:return: list of connections established
		:rtype: list of dict

		:Example:

			>>> device.getConnections()
			[{'handle':72, 'address':'AA:BB:CC:DD:EE:FF'},{'handle':73, 'address':'11:22:33:44:55:66'}]

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
			>>> device.send(HCI_Hdr()/HCI_Command_Hdr()/HCI_Cmd_Disconnect())
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

	def _setCurrentHandle(self,handle,address=""):
		if handle != -1:
			found = False
			for connection in self.handles:
				if connection["handle"] == handle:
					found = True
			if not found:
				self.handles.append({"address":address.upper() if address is not None else "", "handle":handle})
		self.currentHandle = handle

	def _removeConnectionHandle(self,handle):
		for connection in self.handles:
			if connection["handle"] == handle:
				self.handles.remove(connection)
		if handle == self.getCurrentHandle():
			if len(self.handles) > 0:
				self._setCurrentHandle(self.handles[0]['handle'])
			else:
				self._setCurrentHandle(-1)

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

	def setLocalName(self,name):
		'''
		This method changes the local name of the HCI Device.

		:param name: new name
		:type name: str

		:Example:

			>>> device.setLocalName("toto")

		.. note::

			This method is a **shared method** and can be called from the corresponding Emitters / Receivers.

		'''
		self._enterCommandMode()
		self._internalCommand(HCI_Cmd_Write_Local_Name(local_name=name, padding="\x00"*(150 - len(name))))
		self._exitCommandMode()

	def getLocalName(self):
		'''
		This method returns the local name of the HCI Device.

		:return: name
		:rtype: str

		:Example:

			>>> device.getLocalName()
			'toto'

		.. note::

			This method is a **shared method** and can be called from the corresponding Emitters / Receivers.

		'''
		self._enterCommandMode()
		evt = self._internalCommand(HCI_Cmd_Read_Local_Name())
		name = evt.local_name
		self._exitCommandMode()
		return name.decode('utf-8')

	def _getManufacturerId(self):
		self._enterCommandMode()
		response = self._internalCommand(HCI_Cmd_Read_Local_Version_Information())
		manufacturer = response.manufacturer
		self._exitCommandMode()
		return manufacturer

	def getManufacturer(self):
		'''
		This method returns the human readable name of the manufacturer of the HCI Device.

		:return: manufacturer's name
		:rtype: str

		:Example:

			>>> device.getManufacturer()
			'Realtek Semiconductor Corporation'

		.. note::

			This method is a **shared method** and can be called from the corresponding Emitters / Receivers.

		'''
		manufacturer = self._getManufacturerId()
		return AssignedNumbers.getCompanyByNumber(manufacturer)

	def isAddressChangeable(self):
		'''
		This method returns a boolean indicating if the manufacturer of the HCI Device provides some packets allowing to change the BD address.

		:return: boolean indicating if the BD address can be changed
		:rtype: bool

		:Example:

			>>> device.isAddressChangeable()
			True
			>>> device2.isAddressChangeable()
			False

		.. note::

			This method is a **shared method** and can be called from the corresponding Emitters / Receivers.

		'''
		return self._getManufacturerId() in COMPATIBLE_VENDORS

	def getAddress(self):
		'''
		This method returns the actual BD address of the HCI Device.

		:return: str indicating the BD address
		:rtype: str

		:Example:

			>>> device.getAddress()
			'1A:2B:3C:4D:5E:6F'

		.. note::

			This method is a **shared method** and can be called from the corresponding Emitters / Receivers.

		'''
		self._enterCommandMode()
		response = self._internalCommand(HCI_Cmd_Read_BD_Addr())
		address = response.addr
		self._exitCommandMode()
		return address.upper()

	def setAddress(self,address):
		'''
		This method allows to change the BD address (if it is possible).

		:param address: new BD address
		:type address: str
		:return: boolean indicating if the operation was successful
		:rtype: bool

		:Example:

			>>> device.getAddress()
			'1A:2B:3C:4D:5E:6F'
			>>> device.setAddress('11:22:33:44:55:66')
			[INFO] Changing HCI Device (hci0) Address to : 11:22:33:44:55:66
			[SUCCESS] BD Address successfully modified !
			True
			>>> device.getAddress()
			'11:22:33:44:55:66'

		.. note::

			This method is a **shared method** and can be called from the corresponding Emitters / Receivers.

		'''
		address = address.upper()
		success = False
		if self.isAddressChangeable():
			self._enterCommandMode()
			io.info("Changing HCI Device ("+self.interface+") Address to : "+address)
			response = self._internalCommand(HCI_Cmd_Read_Local_Version_Information())
			manufacturer = response.manufacturer

			if manufacturer not in COMPATIBLE_VENDORS:
				io.fail("The vendor has not provided a way to modify the BD Address.")
				success = False
			elif manufacturer == 10: # Cambridge Silicon Radio
				self._internalCommand(HCI_Cmd_CSR_Write_BD_Address(addr=address),noResponse=True)
				io.success("BD Address successfully modified !")
				self._internalCommand(HCI_Cmd_CSR_Reset(),noResponse=True)

				self.socket.close()
				utils.wait(seconds=1)
				self._createSocket()

				success = True
			else:
				modificationPackets = {
							0 : HCI_Cmd_Ericsson_Write_BD_Address,
							13 : HCI_Cmd_TI_Write_BD_Address,
							15 : HCI_Cmd_BCM_Write_BD_Address,
							18 : HCI_Cmd_Zeevo_Write_BD_Address,
							48 : HCI_Cmd_ST_Write_BD_Address,
							57 : HCI_Cmd_Ericsson_Write_BD_Address
						  }
				self._internalCommand(modificationPackets[manufacturer](addr=address))
				self._internalCommand(HCI_Cmd_Reset())
				io.success("BD Address successfully modified !")
				success = True
			self._exitCommandMode()
		return success


class BluetoothEmitter(wireless.Emitter):
	'''
	This class is an Emitter for the Bluetooth protocol ("bt").

	It can instantiates the following devices :

	  * HCI Device (``mirage.libs.bt.BtHCIDevice``)

	'''
	def __init__(self,interface="hci0"):
		super().__init__(interface=interface,packetType=BluetoothPacket, deviceType=BtHCIDevice)

	def convert(self,p):
		if isinstance(p,BluetoothConnect):
			p.packet = HCI_Hdr()/HCI_Command_Hdr()/HCI_Cmd_Create_Connection(addr=p.address,packet_type=p.packetType, page_scan_repetition_mode=p.pageScanRepetitionMode, clock_offset=p.clockOffset,allow_role_switch=p.allowRoleSwitch)
		elif isinstance(p,BluetoothInquiry):
			p.packet = HCI_Hdr()/HCI_Command_Hdr()/HCI_Cmd_Inquiry(lap=p.lap,num_response=p.numResponses,inquiry_length=p.inquiryLength)
		elif isinstance(p,BluetoothWriteExtendedInquiryResponse):
			p.packet = HCI_Hdr()/HCI_Command_Hdr()/HCI_Cmd_Write_Extended_Inquiry_Response(fec_required=0x00 if not p.fecRequired else 0x01,data=p.data)
		elif isinstance(p,BluetoothRemoteNameRequest):
			p.packet = HCI_Hdr()/HCI_Command_Hdr()/HCI_Cmd_Remote_Name_Request(addr=p.address,page_scan_repetition_mode=p.pageScanRepetitionMode)
		elif isinstance(p,BluetoothWriteScanEnable):
			if p.scanEnable is not None:
				p.packet = HCI_Hdr()/HCI_Command_Hdr()/HCI_Cmd_Write_Scan_Enable(scan_enable=p.scanEnable)
			else:
				finalValue = 0
				if p.discoverable:
					finalValue += 1
				if p.connectable:
					finalValue += 2

				p.packet = HCI_Hdr()/HCI_Command_Hdr()/HCI_Cmd_Write_Scan_Enable(scan_enable=finalValue)
		elif isinstance(p,BluetoothAcceptConnectionRequest):
			p.packet = HCI_Hdr()/HCI_Command_Hdr()/HCI_Cmd_Accept_Connection_Request(addr=p.address,role_switch=0x01 if p.role == "slave" else 0x00)
		elif isinstance(p,BluetoothRejectConnectionRequest):
			p.packet = HCI_Hdr()/HCI_Command_Hdr()/HCI_Cmd_Reject_Connection_Request(addr=p.address, reason=p.reason)
		elif isinstance(p,BluetoothL2CAPConnectionRequest):
			handle = p.connectionHandle if p.connectionHandle != -1 else self.device.getCurrentHandle()
			p.packet = HCI_Hdr()/HCI_ACL_Hdr(handle=handle)/L2CAP_Hdr(cid=1)/L2CAP_CmdHdr()/L2CAP_ConnReq(psm=p.psm,scid=p.scid) # cid == 1 : L2CAP signaling channel
		elif isinstance(p,BluetoothL2CAPConnectionResponse):
			handle = p.connectionHandle if p.connectionHandle != -1 else self.device.getCurrentHandle()
			p.packet = HCI_Hdr()/HCI_ACL_Hdr(handle=handle)/L2CAP_Hdr(cid=1)/L2CAP_CmdHdr()/L2CAP_ConnResp(dcid=p.dcid,scid=p.scid,status=p.status,result=p.result) # cid == 1 : L2CAP signaling channel
		elif isinstance(p,BluetoothL2CAPInformationRequest):
			handle = p.connectionHandle if p.connectionHandle != -1 else self.device.getCurrentHandle()
			p.packet = HCI_Hdr()/HCI_ACL_Hdr(handle=handle)/L2CAP_Hdr(cid=1)/L2CAP_CmdHdr()/L2CAP_InfoReq(type=p.type,data=p.data) # cid == 1 : L2CAP signaling channel
		elif isinstance(p,BluetoothL2CAPInformationResponse):
			handle = p.connectionHandle if p.connectionHandle != -1 else self.device.getCurrentHandle()
			p.packet = HCI_Hdr()/HCI_ACL_Hdr(handle=handle)/L2CAP_Hdr(cid=1)/L2CAP_CmdHdr()/L2CAP_InfoResp(type=p.type,result=p.result,data=p.data) # cid == 1 : L2CAP signaling channel
		elif isinstance(p,BluetoothL2CAPConfigurationRequest):
			handle = p.connectionHandle if p.connectionHandle != -1 else self.device.getCurrentHandle()
			p.packet = HCI_Hdr()/HCI_ACL_Hdr(handle=handle)/L2CAP_Hdr(cid=1)/L2CAP_CmdHdr()/L2CAP_ConfReq(dcid=p.dcid,flags=p.flags)/p.data # cid == 1 : L2CAP signaling channel

		elif isinstance(p,BluetoothL2CAPConfigurationResponse):
			handle = p.connectionHandle if p.connectionHandle != -1 else self.device.getCurrentHandle()
			p.packet = HCI_Hdr()/HCI_ACL_Hdr(handle=handle)/L2CAP_Hdr(cid=1)/L2CAP_CmdHdr()/L2CAP_ConfResp(scid=p.scid,flags=p.flags,result=p.result)/p.data # cid == 1 : L2CAP signaling channel

		return p.packet

class BluetoothReceiver(wireless.Receiver):
	'''
	This class is a Receiver for the Bluetooth protocol ("bt").

	It can instantiates the following devices :

	  * HCI Device (``mirage.libs.bt.BtHCIDevice``)

	'''
	def __init__(self, interface="hci0"):
		super().__init__(interface=interface, packetType=BluetoothPacket, deviceType=BtHCIDevice)

	def stop(self):
		super().stop()
		if self.isDeviceUp():
			self.device._exitListening()

	def convert(self,packet):
		new = BluetoothPacket()
		new.packet = packet
		if "hci" in self.interface:
			if HCI_Evt_Extended_Inquiry_Result in packet:
				return BluetoothInquiryScanResult(address=packet.addr,numResponses=packet.num_response,classOfDevice=packet.class_of_device,rssi=packet.rssi,data=packet.data)
			elif HCI_Evt_Inquiry_Result in packet:
				return BluetoothInquiryScanResult(address=packet.addr,numResponses=packet.num_response,classOfDevice=packet.class_of_device)
			elif HCI_Evt_Inquiry_Result_With_RSSI in packet:
				return BluetoothInquiryScanResult(address=packet.addr,numResponses=packet.num_response,classOfDevice=packet.class_of_device,rssi=packet.rssi)
			elif HCI_Evt_Inquiry_Complete in packet:
				return BluetoothInquiryComplete()
			elif HCI_Evt_Connection_Complete in packet:
				if packet.status == 0x00:
					self.device._setCurrentHandle(packet.handle)
					io.info('Uploading connection handle : '+str(self.device.getCurrentHandle()))
				return BluetoothConnectResponse(srcMac=packet.addr,success=(packet.status == 0x00), encryptionMode=(packet.encryption_mode == 0x01), linkType=packet.link_type)
			elif HCI_Evt_Max_Slot_Change in packet:
				return BluetoothMaxSlotChange(maxNumberOfSlots=packet.max_number_slots)
			elif HCI_Evt_Remote_Name_Request_Complete in packet:
				return BluetoothRemoteNameResponse(success=(packet.status == 0x00), addr=packet.addr, remoteName=packet.remote_name)
			elif HCI_Evt_Connection_Request in packet:
				return BluetoothConnectionRequest(addr=packet.addr, classOfDevice=packet.class_of_device)
			elif L2CAP_ConnReq in packet:
				return BluetoothL2CAPConnectionRequest(scid=packet.scid, psm=packet.psm,connectionHandle=packet.handle)
			elif L2CAP_ConnResp in packet:
				return BluetoothL2CAPConnectionResponse(scid=packet.scid, dcid=packet.dcid,status=packet.status,result=packet.result, connectionHandle=packet.handle)
			elif L2CAP_InfoReq in packet:
				return BluetoothL2CAPInformationRequest(type=packet.type,data=packet.data, connectionHandle=packet.handle)
			elif L2CAP_InfoResp in packet:
				return BluetoothL2CAPInformationResponse(type=packet.type,data=packet.data,result=packet.result, connectionHandle=packet.handle)
			elif L2CAP_ConfReq in packet:
				return BluetoothL2CAPConfigurationRequest(dcid=packet.dcid,flags=packet.flags, connectionHandle=packet.handle)
			elif L2CAP_ConfResp in packet:
				return BluetoothL2CAPConfigurationResponse(scid=packet.scid,flags=packets.flags,result=packet.result, connectionHandle=packet.handle)
			return new


WirelessModule.registerEmitter("bt",BluetoothEmitter)
WirelessModule.registerReceiver("bt",BluetoothReceiver)
