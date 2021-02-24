from scapy.all import *
from mirage.core.module import WirelessModule
from mirage.libs.ble_utils.scapy_hci_layers import *
from mirage.libs.ble_utils.packets import *
from mirage.libs.ble_utils.constants import *
from mirage.libs.bt_utils.assigned_numbers import AssignedNumbers
from mirage.libs.ble_utils.ubertooth import *
from mirage.libs.ble_utils.btlejack import *
from mirage.libs.ble_utils.nrfsniffer import *
from mirage.libs.ble_utils.butterfly import *
from mirage.libs.ble_utils.adb import *
from mirage.libs.ble_utils.hcidump import *
from mirage.libs.ble_utils.hackrf import *
from mirage.libs.ble_utils.sniffle import *
from mirage.libs.ble_utils.pcap import *
from mirage.libs.ble_utils.helpers import *
from mirage.libs.ble_utils.crypto import *
from mirage.libs.ble_utils.scapy_link_layers import *
from mirage.libs.ble_utils.dissectors import *
from mirage.libs.ble_utils.att_server import *
from mirage.libs.bt_utils.scapy_vendor_specific import *
from mirage.libs import wireless,bt,io


class BLEHCIDevice(bt.BtHCIDevice):
	'''
	This device allows to communicate with an HCI Device in order to use Bluetooth Low Energy protocol.
	The corresponding interfaces are : ``hciX`` (e.g. "hciX")

	The following capabilities are actually supported :

	+-----------------------------------+----------------+
	| Capability                        | Available ?    |
	+===================================+================+
	| SCANNING						    | yes			 |
	+-----------------------------------+----------------+
	| ADVERTISING					    | yes			 |
	+-----------------------------------+----------------+
	| SNIFFING_ADVERTISEMENTS		    | no			 |
	+-----------------------------------+----------------+
	| SNIFFING_NEW_CONNECTION		    | no			 |
	+-----------------------------------+----------------+
	| SNIFFING_EXISTING_CONNECTION	    | no			 |
	+-----------------------------------+----------------+
	| JAMMING_CONNECTIONS			    | no			 |
	+-----------------------------------+----------------+
	| JAMMING_ADVERTISEMENTS			| no			 |
	+-----------------------------------+----------------+
	| HIJACKING_MASTER                  | no             |
	+-----------------------------------+----------------+
	| HIJACKING_SLAVE                   | no             |
	+-----------------------------------+----------------+
	| INJECTING                         | no             |
	+-----------------------------------+----------------+
	| MITMING_EXISTING_CONNECTION       | no             |
	+-----------------------------------+----------------+
	| HIJACKING_CONNECTIONS			    | no			 |
	+-----------------------------------+----------------+
	| INITIATING_CONNECTION			    | yes			 |
	+-----------------------------------+----------------+
	| RECEIVING_CONNECTION			    | yes			 |
	+-----------------------------------+----------------+
	| COMMUNICATING_AS_MASTER		    | yes			 |
	+-----------------------------------+----------------+
	| COMMUNICATING_AS_SLAVE			| yes			 |
	+-----------------------------------+----------------+
	| HCI_MONITORING					| no			 |
	+-----------------------------------+----------------+

	'''
	sharedMethods = [
		"getConnections",
		"switchConnection",
		"getCurrentConnection",
		"getCurrentConnectionMode",
		"getAddressByHandle",
		"getCurrentHandle",
		"isConnected",
		"setScan",
		"setAdvertising",
		"setAdvertisingParameters",
		"setScanningParameters",
		"getAddress",
		"setAddress",
		"getMode",
		"getAddressMode",
		"getManufacturer",
		"isAddressChangeable",
		"encryptLink",
		"updateConnectionParameters",
		"setChannelMap",
		"setZephyrMITMFlag",
		"setBlockedCtrlPDU",
		"enableMitM"
		]


	def _setCurrentHandle(self,handle,address="",mode="public"):
		if handle != -1:
			found = False
			for connection in self.handles:
				if connection["handle"] == handle:
					found = True
			if not found:
				self.handles.append({"address":address.upper() if address is not None else "", "handle":handle, "mode":mode})
		self.currentHandle = handle
		self._setOperationMode(BLEOperationMode.NORMAL)

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

	def _initBLE(self):
		self.operationMode = BLEOperationMode.NORMAL
		self._enterCommandMode()
		response = self._internalCommand(HCI_Cmd_Read_Local_Version_Information())
		manufacturer = response.manufacturer
		self._internalCommand(HCI_Cmd_Reset())
		# Not supported by nRF Zephyr controller
		if manufacturer!=1521:
			self._internalCommand(HCI_Cmd_Set_Event_Filter())
			self._internalCommand(HCI_Cmd_Connect_Accept_Timeout())
		self._internalCommand(HCI_Cmd_Set_Event_Mask())
		# Not supported by nRF Zephyr controller
		if manufacturer!=1521:
			self._internalCommand(HCI_Cmd_LE_Host_Supported())
		self._exitCommandMode()

		self.capabilities = ["SCANNING", "ADVERTISING", "INITIATING_CONNECTION", "RECEIVING_CONNECTION", "COMMUNICATING_AS_MASTER", "COMMUNICATING_AS_SLAVE"]


	def setZephyrMITMFlag(self, flag=0x1):
		self._enterCommandMode()
		response = self._internalCommand(HCI_Cmd_Read_Local_Version_Information())
		manufacturer = response.manufacturer
		# Only use for nRF Zephyr controller
		if manufacturer==1521:
			response = self._internalCommand(HCI_Cmd_ZEPHYR_Set_MITM_Flag(mitm_flag=flag))
		else:
			io.warning("MitM mode can only be used with nRF Zephyr controller!")
		self._exitCommandMode()
		return response

	def setBlockedCtrlPDU(self, blocked_ctrl_pdu):
		self._enterCommandMode()
		response = self._internalCommand(HCI_Cmd_Read_Local_Version_Information())
		manufacturer = response.manufacturer
		# Only use for nRF Zephyr controller
		if manufacturer==1521:
			response = self._internalCommand(HCI_Cmd_ZEPHYR_Set_Blocked_Ctrl_PDU(blocked_ctrl_pdu=blocked_ctrl_pdu))
		else:
			io.warning("Blocked PDUs can only be used with nRF Zephyr controller!")
		self._exitCommandMode()
		return response

	def enableMitM(self, flag):
		super().enableMitM(flag)

	def _setOperationMode(self,value):
		self.operationMode = value
	def _getOperationMode(self):
		return self.operationMode

	def getMode(self):
		'''
		This method returns the current mode used by the HCI Device.
		Three modes are available and indicates the current state of the device: "NORMAL", "SCANNING" and "ADVERTISING"

		:return: string indicating the current mode
		:rtype: str

		:Example:

			>>> device.getMode()
			'NORMAL'
			>>> device.setScan(enable=True)
			>>> device.getMode()
			'SCANNING'

		.. note::

			This method is a **shared method** and can be called from the corresponding Emitters / Receivers.

		'''
		mode = self._getOperationMode()
		if mode == BLEOperationMode.NORMAL:
			return "NORMAL"
		elif mode == BLEOperationMode.SCANNING:
			return "SCANNING"
		elif mode == BLEOperationMode.ADVERTISING:
			return "ADVERTISING"

	def setAddress(self,address,random=False):
		'''
		This method allows to modify the BD address and the BD address type of the device, if it is possible.

		:param address: new BD address
		:type address: str
		:param random: boolean indicating if the address is random
		:type random: bool
		:return: boolean indicating if the operation was successful
		:rtype: bool

		:Example:

			>>> device.setAddress("12:34:56:78:9A:BC",random=True) # set the device's address to 12:34:56:78:9A:BC (random)
			[INFO] Changing HCI Device (hci0) Random Address to : 12:34:56:78:9A:BC
			[SUCCESS] BD Address successfully modified !
			True
			>>> device.setAddress("12:34:56:78:9A:BC") # set the device's address to 12:34:56:78:9A:BC (public)
			[INFO] Changing HCI Device (hci0) Address to : 12:34:56:78:9A:BC
			[SUCCESS] BD Address successfully modified !
			True
			>>> device2.setAddress("12:34:56:78:9A:BC")
			[INFO] Changing HCI Device (hci0) Address to : 12:34:56:78:9A:BC
			[ERROR] The vendor has not provided a way to modify the BD Address.
			False


		.. warning::

			Mirage uses some vendor specific HCI Commands in order to modify the public BD address. If the vendor has not provided a way to modify the BD address, it is not possible to change it (see *device2* in the example section).

		.. note::

			This method is a **shared method** and can be called from the corresponding Emitters / Receivers.

		'''
		if random:
			self.addressMode = "random"
			self.randomAddress = address
			self._enterCommandMode()
			io.info("Changing HCI Device ("+str(self.interface)+") Random Address to : "+address)
			self._internalCommand(HCI_Cmd_LE_Set_Random_Address(address=address))
			io.info("BD Address successfully modified !")
			self._exitCommandMode()
			return True
		else:
			self.addressMode = "public"
			rValue = super().setAddress(address)
			self._setOperationMode(BLEOperationMode.NORMAL)
			return rValue

	def setChannelMap(self, channelMap=0x1fffffffff):
		'''
		This method allows to select an arbitrary channel map.

		:param channelMap: integer indicating the channel to use.
		:type channelMap: int
		:Example:

			>>> device.setChannelMap(0x0000000003)
			>>> device.setChannelMap(0x1fffffffff)

		.. note::

			This method is a **shared method** and can be called from the corresponding Emitters / Receivers.
		'''
		self._enterCommandMode()
		self._internalCommand(HCI_Cmd_LE_Set_Host_Channel_Classification(chM=channelMap))
		self._exitCommandMode()

	def setScan(self,enable=True, passive=False):
		'''
		This method enables or disables the scanning mode.

		:param enable: boolean indicating if the scanning mode must be enabled
		:type enable: bool
		:param passive: boolean indicating if the scan has to be passive (e.g. no *SCAN_REQ*)
		:type passive: bool
		:Example:

			>>> device.setScan(enable=True, passive=True) # scanning mode enabled in passive mode
 			>>> device.setScan(enable=False) # scanning mode disabled

		.. note::

			This method is a **shared method** and can be called from the corresponding Emitters / Receivers.
		'''
		self._enterCommandMode()
		if enable and self._getOperationMode() == BLEOperationMode.NORMAL:
			self._internalCommand(HCI_Cmd_LE_Set_Scan_Parameters(type=1 if not passive else 0))
			self._internalCommand(HCI_Cmd_LE_Set_Scan_Enable())
			self._setOperationMode(BLEOperationMode.SCANNING)
		elif not enable and self._getOperationMode() == BLEOperationMode.SCANNING:
			self._internalCommand(HCI_Cmd_LE_Set_Scan_Enable(enable=0))
			self._setOperationMode(BLEOperationMode.NORMAL)
		self._exitCommandMode()


	def setAdvertising(self,enable=True):
		'''
		This method enables or disables the advertising mode.

		:param enable: boolean indicating if the advertising mode must be enabled
		:type enable: bool

		:Example:

			>>> device.setAdvertising(enable=True) # scanning mode enabled
			>>> device.setAdvertising(enable=False) # scanning mode disabled


		.. warning::
			Please note that if no advertising and scanning data has been provided before this function call, nothing will be advertised. You have to set the scanning Parameters and the advertising Parameters before calling this method.


		.. note::

			This method is a **shared method** and can be called from the corresponding Emitters / Receivers.

		'''
		self._enterCommandMode()
		if enable and self._getOperationMode() == BLEOperationMode.NORMAL:
			self._internalCommand(HCI_Cmd_LE_Set_Advertise_Enable(enable=1))
			self._setOperationMode(BLEOperationMode.ADVERTISING)
		elif not enable and self._getOperationMode() == BLEOperationMode.ADVERTISING:
			self._internalCommand(HCI_Cmd_LE_Set_Advertise_Enable(enable=0))
			self._setOperationMode(BLEOperationMode.NORMAL)
		self._exitCommandMode()

	def updateConnectionParameters(self,minInterval=0, maxInterval=0, latency=0, timeout=0,minCe=0, maxCe=0xFFFF):
		'''
		This method allows to update connection parameters according to the data provided.
		It will mainly be used if an incoming BLEConnectionParameterUpdateRequest is received.

		:param minInterval: minimal interval
		:type minInterval: int
		:param maxInterval: maximal interval
		:type maxInterval: int
		:param latency: connection latency
		:type latency: int
		:param timeout: connection timeout
		:type timeout: int
		:param minCe: minimum connection event length
		:type minCe: int
		:param maxCe: maximum connection event length
		:type maxCe: int

		.. note::

			This method is a **shared method** and can be called from the corresponding Emitters / Receivers.

		'''
		self._enterCommandMode()
		self._internalCommand(HCI_Cmd_LE_Connection_Update(handle=self.getCurrentHandle(),min_interval=minInterval, max_interval=maxInterval,latency=latency, timeout=timeout, min_ce=minCe, max_ce=maxCe),noResponse=True)
		self._exitCommandMode()

	def setScanningParameters(self, data=b""):
		'''
		This method sets scanning parameters according to the data provided.
		It will mainly be used by *SCAN_RESP* packets.

		:param data: data to use in *SCAN_RESP*
		:type data: bytes

		.. note::

			This method is a **shared method** and can be called from the corresponding Emitters / Receivers.

		'''
		self.setScan(enable=False)
		self._enterCommandMode()
		advData = data
		if isinstance(data,list):
			advData = b""
			for i in data:
				advData += bytes(i)
			data = advData
		if isinstance(data,bytes):
			advData = b""
			if len(data) > 31:
				advData = data[:31]
			else:
				advData = data+(31 - len(data))*b"\x00"

			self._internalCommand(New_HCI_Cmd_LE_Set_Scan_Response_Data(data=advData,len=len(data)))
		self._exitCommandMode()

	def setAdvertisingParameters(self,type = "ADV_IND",destAddr = "00:00:00:00:00:00",data = b"",intervalMin = 200, intervalMax = 210, daType='public', oaType='public'):
		'''
		This method sets advertising parameters according to the data provided.
		It will mainly be used by *ADV_IND-like* packets.

		:param type: type of advertisement (*available values :* "ADV_IND", "ADV_DIRECT_IND", "ADV_SCAN_IND", "ADV_NONCONN_IND", "ADV_DIRECT_IND_LOW")
		:type type: str
		:param destAddress: destination address (it will be used if needed)
		:type destAddress: str
		:param data: data included in the payload
		:type data: bytes
		:param intervalMin: minimal interval
		:type intervalMin: int
		:param intervalMax: maximal interval
		:type intervalMax: int
		:param daType: string indicating the destination address type ("public" or "random")
		:type daType: str
		:param oaType: string indicating the origin address type ("public" or "random")

		.. note::

			This method is a **shared method** and can be called from the corresponding Emitters / Receivers.

		'''
		self.setAdvertising(enable=False)
		self.setScan(enable=False)
		self._enterCommandMode()
		if type == "ADV_IND":
			advType = ADV_IND
		elif type == "ADV_DIRECT_IND":
			advType = ADV_DIRECT_IND
		elif type == "ADV_SCAN_IND":
			advType = ADV_SCAN_IND
		elif type == "ADV_NONCONN_IND":
			advType = ADV_NONCONN_IND
		elif type == "ADV_DIRECT_IND_LOW":
			advType = ADV_DIRECT_IND_LOW
		else:
			io.fail("Advertisements type not recognized, using ADV_IND.")
			advType = ADV_IND
		dAddr = None if destAddr == "00:00:00:00:00:00" else destAddr

		advData = data
		if isinstance(data,list):
			advData = b""
			for i in data:
				advData += bytes(i)
			data = advData
		if isinstance(data,bytes):
			advData = b""
			if len(data) > 31:
				advData = data[:31]
			else:
				advData = data+(31 - len(data))*b"\x00"

		self._internalCommand(HCI_Cmd_LE_Set_Advertising_Parameters(adv_type=advType, daddr=dAddr, datype=daType, oatype=oaType,interval_min=intervalMin, interval_max = intervalMax))
		self._internalCommand(New_HCI_Cmd_LE_Set_Advertising_Data(data=EIR_Hdr(advData)))
		self._exitCommandMode()

	def _setAddressMode(self,mode="public"):
		self.addressMode = mode

	def getAddressMode(self):
		'''
		This method returns the address mode currently in use.

		:return: address mode ("public" or "random")
		:rtype: str

		:Example:

			>>> device.getAddressMode()
			'public'

		.. note::

			This method is a **shared method** and can be called from the corresponding Emitters / Receivers.

		'''
		return self.addressMode

	def getAddress(self):
		'''
		This method returns the address currently in use.

		:return: address
		:rtype: str

		:Example:

			>>> device.getAddressMode()
			'00:11:22:33:44:55:66'

		.. note::

			This method is a **shared method** and can be called from the corresponding Emitters / Receivers.
	
		'''
		return self.randomAddress if self.addressMode == "random" else super().getAddress()

	def init(self):
		self.initializeBluetooth = False
		super().init()
		if self.ready:
			self.addressMode = "public"
			self.randomAddress = "00:00:00:00:00:00"
			self._initBLE()


	def encryptLink(self,rand=b"\x00\x00\x00\x00\x00\x00\x00\x00", ediv=0, ltk = b"\x00"*16):
		'''
		This method sends an encryption request to the current connection established and encrypts the link if possible.

		:param rand: random value
		:type rand: bytes
		:param ediv: EDIV value
		:type ediv: int
		:param ltk: Long Term Key
		:type ltk: bytes
		:return: boolean indicating if the link was successfully encrypted
		:rtype: bool

		:Example:

			>>> device.encryptLink(ltk=bytes.fromhex("000102030405060708090a0b0c0d0e0f")) # Short Term Key, ediv = rand = 0
			True


		.. seealso::

			It is possible to encrypt the link using directly the encryption-related packets, such as :

			  * ``mirage.libs.ble_utils.packets.BLELongTermKeyRequest``
			  * ``mirage.libs.ble_utils.packets.BLELongTermKeyRequestReply``

		.. note::

			This method is a **shared method** and can be called from the corresponding Emitters / Receivers.

		'''
		self._enterCommandMode()
		handle = self.getCurrentHandle()
		self._internalCommand(HCI_Cmd_LE_Start_Encryption_Request(
									handle=handle,
									rand=rand,
									ediv=ediv,
									ltk=ltk
									)
					,noResponse=True)

		encryptionChange = self.socket.recv()
		while encryptionChange is None or HCI_Event_Encryption_Change not in encryptionChange:
			if encryptionChange is not None:
				self.pendingQueue.put(encryptionChange, block=True)
			encryptionChange = self.socket.recv()
		self._exitCommandMode()
		return encryptionChange.enabled

class BLEEmitter(wireless.Emitter):
	'''
	This class is an Emitter for the Bluetooth Low Energy protocol ("ble").

	It can instantiates the following devices :

	  * HCI Device (``mirage.libs.ble.BLEHCIDevice``) **[ interface "hciX" (e.g. "hci0") ]**
	  * Ubertooth Device (``mirage.libs.ble_utils.ubertooth.BLEUbertoothDevice``) **[ interface "ubertoothX" (e.g. "ubertooth0") ]**
	  * BTLEJack Device (``mirage.libs.ble_utils.btlejack.BTLEJackDevice``) **[ interface "microbitX" (e.g. "microbit0") ]**
	  * ADB Device (``mirage.libs.ble_utils.adb.ADBDevice``) **[ interface "adbX" (e.g. "adb0") ]**
	  * HCIDump Device (``mirage.libs.ble_utils.hcidump.BLEHcidumpDevice``) **[ interface "hcidumpX" (e.g. "hcidump0") ]**
	  * PCAP Device (``mirage.libs.ble_utils.pcap.BLEPCAPDevice``) **[ interface "<file>.pcap" (e.g. "pairing.pcap") ]**

	'''
	def __init__(self, interface="hci0"):
		deviceClass = None
		if "hcidump" in interface:
			deviceClass = BLEHcidumpDevice
		elif "hci" in interface:
			deviceClass = BLEHCIDevice
		elif "ubertooth" in interface:
			deviceClass = BLEUbertoothDevice
		elif "microbit" in interface:
			deviceClass = BTLEJackDevice
		elif "adb" in interface:
			deviceClass = ADBDevice
		elif "nrfsniffer" in interface:
			deviceClass = NRFSnifferDevice
		elif "hackrf" in interface:
			deviceClass = BLEHackRFDevice
		elif "sniffle" in interface:
			deviceClass = SniffleDevice
		elif "butterfly" in interface:
			if ":sub" in interface:
				deviceClass = BLEButterflySubdevice
			else:
				deviceClass = BLEButterflyDevice
		elif interface[-5:] == ".pcap":
			deviceClass = BLEPCAPDevice
		super().__init__(interface=interface, packetType=BLEPacket, deviceType=deviceClass)

	def convert(self,packet):

		if packet.packet is None:
			if isinstance(packet,BLEEncryptedPacket):
					packet.packet = BTLE() / BTLE_DATA(packet.data)
			else:
				# Specific sublayers
				if "hci" in self.interface:
					packet.packet = HCI_Hdr()
					if isinstance(packet,BLEConnect):
						self.device._setAddressMode(packet.initiatorType)
						packet.packet /= HCI_Command_Hdr()/HCI_Cmd_LE_Create_Connection(
											paddr=packet.dstAddr,
											patype=packet.type,
											atype=packet.initiatorType,
											window=96,
											min_interval=24,
											max_interval=40,)
					elif isinstance(packet,BLEConnectionCancel):
						packet.packet /= HCI_Command_Hdr()/HCI_Cmd_LE_Create_Connection_Cancel()
					elif isinstance(packet, BLEStartEncryption):
						packet.packet /= HCI_Command_Hdr()/HCI_Cmd_LE_Start_Encryption_Request(
									handle=self.device.getCurrentHandle(),
									rand=packet.rand,
									ediv=packet.ediv,
									ltk=packet.ltk
						)
					# Do not forward a packet already send, 1 == transmitted
					elif isinstance(packet, BLELLPacket) and packet.direction == 1:
						return None
					elif isinstance(packet, BLELLPacket):
						packetOpcode = -1
						if isinstance(packet, BLELLConnUpdateInd):
							packetOpcode = 0x00
						elif isinstance(packet, BLELLChanMapInd):
							packetOpcode = 0x01
						elif isinstance(packet, BLELLTerminateInd):
							packetOpcode = 0x02
						elif isinstance(packet, BLELLEncReq):
							packetOpcode = 0x03
						elif isinstance(packet, BLELLEncRsp):
							packetOpcode = 0x04
						elif isinstance(packet, BLELLStartEncReq):
							packetOpcode = 0x05
						elif isinstance(packet, BLELLStartEncRsp):
							packetOpcode = 0x06
						elif isinstance(packet, BLELLUnknownRsp):
							packetOpcode = 0x07
						elif isinstance(packet, BLELLFeatureReq):
							packetOpcode = 0x08
						elif isinstance(packet, BLELLFeatureRsp):
							packetOpcode = 0x09
						elif isinstance(packet, BLELLPauseEncReq):
							packetOpcode = 0x0A
						elif isinstance(packet, BLELLPauseEncRsp):
							packetOpcode = 0x0B
						elif isinstance(packet, BLELLVersionInd):
							packetOpcode = 0x0C
						elif isinstance(packet, BLELLRejectInd):
							packetOpcode = 0x0D
						elif isinstance(packet, BLELLSlaveFeatureReq):
							packetOpcode = 0x0F
						elif isinstance(packet, BLELLConnParamReq):
							packetOpcode = 0x10
						elif isinstance(packet, BLELLRejectExtInd):
							packetOpcode = 0x11
						elif isinstance(packet, BLELLPingReq):
							packetOpcode = 0x12
						elif isinstance(packet, BLELLPingRsp):
							packetOpcode = 0x13
						elif isinstance(packet, BLELLDataLenReq):
							packetOpcode = 0x14
						elif isinstance(packet, BLELLDataLenRsp):
							packetOpcode = 0x15
						elif isinstance(packet, BLELLPHYReq):
							packetOpcode = 0x16
						elif isinstance(packet, BLELLPHYReq):
							packetOpcode = 0x17
						elif isinstance(packet, BLELLUpdPHYInd):
							packetOpcode = 0x18
						elif isinstance(packet, BLELLMinUsedChann):
							packetOpcode = 0x19
						elif isinstance(packet, BLELLEncCtrl):
							# Encrypted, set to FF
							packetOpcode = 0xFF

						if packetOpcode != -1:
							opcode = (0x13) | ((0x3F) << 10)
							packet.packet /= HCI_Command_Hdr() / Raw(
								bytes([packetOpcode]) + bytes([packet.getPayloadLength()]) + packet.getPayload()
							)
							packet.packet[HCI_Command_Hdr].opcode = opcode
							packet.packet[HCI_Command_Hdr].len = 29
						else:
							return None
					# Handle encrypted Data PDUs
					elif isinstance(packet, BLELLEncData):
						packet.packet /= HCI_ACL_Hdr() / Raw(packet.payload)
						packet.packet[HCI_ACL_Hdr].len = packet.length
						packet.packet[HCI_ACL_Hdr].PB = 0x0
						return packet.packet
					else:
						handle = (packet.connectionHandle if packet.connectionHandle != -1
										else self.device.getCurrentHandle())

						if isinstance(packet,BLEDisconnect):
							packet.packet /= HCI_Command_Hdr()/HCI_Cmd_Disconnect(handle=handle)

						elif isinstance(packet,BLELongTermKeyRequest):
							packet.packet /= HCI_Command_Hdr()/HCI_Cmd_LE_Start_Encryption_Request(
											handle=handle,
											rand=packet.rand,
											ediv=packet.ediv,
											ltk=packet.ltk)

						elif isinstance(packet,BLELongTermKeyRequestReply):
							packet.packet /= HCI_Command_Hdr()/(
							HCI_Cmd_LE_Long_Term_Key_Request_Reply(handle=handle,ltk=packet.ltk)
								if packet.positive
								else HCI_Cmd_LE_Long_Term_Key_Request_Negative_Reply(handle=handle))
						else:
							packet.packet /= HCI_ACL_Hdr(handle=handle)

				else:
					packet.packet = BTLE()
					if isinstance(packet,BLEConnect) and "sniffle" in self.interface:
						packet.packet /= (BTLE_ADV(TxAdd=0x00 if packet.initiatorType == "public" else 0x01,
												  RxAdd=0x00 if packet.type == "public" else 0x01)/
										BTLE_CONNECT_REQ(
										AdvA=packet.dstAddr
						))

					if isinstance(packet, BLEAdvertisement):
						packet.packet /= BTLE_ADV(RxAdd=0x00 if packet.addrType == "public" else 0x01)
						advType = packet.type
						if advType == "ADV_IND":
							packet.packet /= BTLE_ADV_IND(AdvA = packet.addr, data=packet.data)
						elif advType == "ADV_DIRECT_IND":
							if isinstance(packet,BLEAdvDirectInd):
								initA = packet.dstAddr
							else:
								initA = "00:00:00:00:00:00"
							packet.packet /= BTLE_ADV_DIRECT_IND(AdvA = packet.addr, InitA = initA)
						elif advType == "ADV_NONCONN_IND":
							packet.packet /= BTLE_ADV_NONCONN_IND()
						elif advType == "ADV_SCAN_IND":
							packet.packet /= BTLE_ADV_SCAN_IND()
						elif advType == "SCAN_REQ":
							if isinstance(packet,BLEAdvDirectInd):
								scanA = packet.dstAddr
							else:
								scanA = "00:00:00:00:00:00"
							packet.packet /= BTLE_SCAN_REQ(AdvA = packet.addr, ScanA = scanA)
						elif advType == "SCAN_RSP":
							packet.packet /= BTLE_SCAN_RSP(AdvA = packet.addr, data=packet.data)
						elif advType == "CONNECT_REQ" or isinstance(packet,BLEConnectRequest):
							packet.packet.TxAdd = 0x00 if packet.srcAddrType == "public" else 0x01
							packet.packet.RxAdd = 0x00 if packet.dstAddrType == "public" else 0x01
							packet.packet /= BTLE_CONNECT_REQ(
											InitA=packet.srcAddr,
											AdvA=packet.dstAddr,
											AA=packet.accessAddress,
											crc_init=packet.crcInit,
											win_size=packet.winSize,
											win_offset=packet.winOffset,
											interval=packet.hopInterval,
											latency=packet.latency,
											timeout=packet.timeout,
											chM =packet.channelMap,
											SCA=packet.SCA,
											hop=packet.hopIncrement
										)
							packet.packet.access_addr = 0x8e89bed6
					else:
						packet.packet /= BTLE_DATA()
						if isinstance(packet,BLEDisconnect):
							packet.packet /= BTLE_CTRL(opcode=0x02)
						elif isinstance(packet,BLEEmptyPDU):
							data.LLID = 1
						elif isinstance(packet,BLEControlPDU):
							optcode = 0
							if packet.type == "LL_CONNECTION_UPDATE_REQ":
								optcode = 0x00
							elif packet.type == "LL_CHANNEL_MAP_REQ":
								optcode = 0x01
							elif packet.type == "LL_TERMINATE_IND":
								optcode = 0x02
							elif packet.type == "LL_ENC_REQ":
								optcode = 0x03
							elif packet.type == "LL_ENC_RSP":
								optcode = 0x04
							elif packet.type == "LL_START_ENC_REQ":
								optcode = 0x05
							elif packet.type == "LL_START_ENC_RESP":
								optcode = 0x06
							elif packet.type == "LL_UNKNOWN_RSP":
								optcode = 0x07
							elif packet.type == "LL_FEATURE_REQ":
								optcode = 0x08
							elif packet.type == "LL_FEATURE_RSP":
								optcode = 0x09
							elif packet.type == "LL_PAUSE_ENC_REQ":
								optcode = 0x0A
							elif packet.type == "LL_PAUSE_ENC_RSP":
								optcode = 0x0B
							elif packet.type == "LL_VERSION_IND":
								optcode = 0x0C
							elif packet.type == "LL_REJECT_IND":
								optcode = 0x0D
							packet.packet /= BTLE_CTRL(opcode = optcode)
							if packet.data is not None or packet.data != b"":
								packet.packet /= packet.data

				# Common sublayers
				if HCI_Command_Hdr not in packet.packet and BTLE_CTRL not in packet.packet and BTLE_ADV not in packet.packet:


					if (
						isinstance(packet,BLEConnectionParameterUpdateRequest) or
							 isinstance(packet,BLEConnectionParameterUpdateResponse)
					   ):
							packet.packet /= L2CAP_Hdr()/L2CAP_CmdHdr(id=packet.l2capCmdId)
					elif (
						isinstance(packet,BLESecurityRequest) or
						isinstance(packet,BLEPairingRequest) or
						isinstance(packet,BLEPairingResponse) or
						isinstance(packet,BLEPairingFailed) or
						isinstance(packet,BLEPairingConfirm) or
						isinstance(packet,BLEPairingRandom) or
						isinstance(packet,BLEPublicKey) or
						isinstance(packet,BLEDHKeyCheck) or
						isinstance(packet,BLEEncryptionInformation) or
						isinstance(packet,BLEMasterIdentification) or
						isinstance(packet,BLEIdentityInformation) or
						isinstance(packet,BLEIdentityAddressInformation) or
						isinstance(packet,BLESigningInformation)
					):
						packet.packet /= L2CAP_Hdr(cid=6)/SM_Hdr()
					else:
						packet.packet /= L2CAP_Hdr(cid=4)/ATT_Hdr()


					# Common upper layers
					if isinstance(packet,BLEConnectionParameterUpdateRequest):
						packet.packet /= L2CAP_Connection_Parameter_Update_Request(
							max_interval=packet.maxInterval,
							min_interval=packet.minInterval,
							slave_latency=packet.slaveLatency,
							timeout_mult=packet.timeoutMult)

					elif isinstance(packet,BLEConnectionParameterUpdateResponse):
						packet.packet /= L2CAP_Connection_Parameter_Update_Response(move_result=packet.moveResult)

					elif isinstance(packet,BLESecurityRequest):
						packet.packet /= SM_Security_Request(authentication=packet.authentication)
						packet.packet[SM_Hdr].sm_command = 0x0B

					elif isinstance(packet,BLEPairingRequest):
						packet.packet /= SM_Pairing_Request(
								iocap=packet.inputOutputCapability,
								oob=1 if packet.outOfBand else 0,
								authentication=packet.authentication,
								max_key_size = packet.maxKeySize,
								initiator_key_distribution=packet.initiatorKeyDistribution,
								responder_key_distribution = packet.responderKeyDistribution)
						packet.packet[SM_Hdr].sm_command = 0x01


					elif isinstance(packet,BLEPairingResponse):
						packet.packet /= SM_Pairing_Response(
								iocap=packet.inputOutputCapability,
								oob=1 if packet.outOfBand else 0,
								authentication=packet.authentication,
								max_key_size = packet.maxKeySize,
								initiator_key_distribution=packet.initiatorKeyDistribution,
								responder_key_distribution = packet.responderKeyDistribution)
						packet.packet[SM_Hdr].sm_command = 0x02

					elif isinstance(packet,BLEPairingFailed):
						packet.packet /= SM_Failed(reason=packet.reason)
						packet.packet[SM_Hdr].sm_command = 0x05

					elif isinstance(packet,BLEPairingConfirm):
						packet.packet /= SM_Confirm(confirm=packet.confirm)
						packet.packet[SM_Hdr].sm_command = 0x03
					# Keypress notification not implemented
					elif isinstance(packet, BLEPublicKey):
						packet.packet /= SM_Public_Key(
							key_x=packet.key_x,
							key_y=packet.key_y,
						)
						packet.packet[SM_Hdr].sm_command = 0xC
					elif isinstance(packet, BLEDHKeyCheck):
						packet.packet /= SM_DHKey_Check(
								dhkey_check=packet.dhkey_check,
							)
						packet.packet[SM_Hdr].sm_command = 0xD

					elif isinstance(packet,BLEPairingRandom):
						packet.packet /= SM_Random(random=packet.random)
						packet.packet[SM_Hdr].sm_command = 0x04

					elif isinstance(packet,BLEEncryptionInformation):
						packet.packet /= SM_Encryption_Information(ltk=packet.ltk)
						packet.packet[SM_Hdr].sm_command = 0x06

					elif isinstance(packet,BLEMasterIdentification):
						packet.packet /= SM_Master_Identification(ediv=packet.ediv, rand=packet.rand)
						packet.packet[SM_Hdr].sm_command = 0x07

					elif isinstance(packet,BLEIdentityInformation):
						packet.packet /= SM_Identity_Information(irk=packet.irk)
						packet.packet[SM_Hdr].sm_command = 0x08

					elif isinstance(packet,BLEIdentityAddressInformation):
						packet.packet /= SM_Identity_Address_Information(
											atype=0 if packet.type=="public" else 1,
											address=packet.address
												)
						packet.packet[SM_Hdr].sm_command = 0x09

					elif isinstance(packet,BLESigningInformation):
						packet.packet /= SM_Signing_Information(csrk=packet.csrk)
						packet.packet[SM_Hdr].sm_command = 0x0A

					elif isinstance(packet, BLEFindByTypeValueRequest):
						packet.packet /= ATT_Find_By_Type_Value_Request(start=packet.startHandle,
																		end=packet.endHandle,
																		uuid=packet.uuid,
																		data=packet.data)

					elif isinstance(packet, BLEFindByTypeValueResponse):
						packet.packet /= ATT_Find_By_Type_Value_Response(handles=packet.handles)

					elif isinstance(packet,BLEErrorResponse):
						packet.packet /= ATT_Error_Response(request=packet.request, handle=packet.handle,ecode=packet.ecode)

					elif isinstance(packet,BLEExchangeMTURequest):
						packet.packet /= ATT_Exchange_MTU_Request(mtu = packet.mtu)

					elif isinstance(packet,BLEExchangeMTUResponse):
						packet.packet /= ATT_Exchange_MTU_Response(mtu = packet.mtu)

					elif isinstance(packet,BLEReadByGroupTypeRequest):
						packet.packet /= ATT_Read_By_Group_Type_Request(
								start=packet.startHandle,
								end=packet.endHandle,
								uuid=packet.uuid)

					elif isinstance(packet,BLEReadByGroupTypeResponse):
						packet.packet /= ATT_Read_By_Group_Type_Response(data=packet.data,length=packet.length)

					elif isinstance(packet,BLEReadByTypeRequest):
						packet.packet /= ATT_Read_By_Type_Request(
								start=packet.startHandle,
								end=packet.endHandle,
								uuid=packet.uuid)

					elif isinstance(packet,BLEReadByTypeResponse):
						packet.packet /= ATT_Read_By_Type_Response(packet.data)

					elif isinstance(packet,BLEReadBlobRequest):
						packet.packet /= ATT_Read_Blob_Request(gatt_handle=packet.handle,offset=packet.offset)
					elif isinstance(packet,BLEReadBlobResponse):
						packet.packet /= ATT_Read_Blob_Response(value=packet.value)
					elif isinstance(packet,BLEHandleValueNotification):
						packet.packet /= ATT_Handle_Value_Notification(gatt_handle=packet.handle,value=packet.value)
					elif isinstance(packet,BLEHandleValueIndication):
						packet.packet /= ATT_Handle_Value_Indication(gatt_handle=packet.handle,value=packet.value)
					elif isinstance(packet,BLEHandleValueConfirmation):
						packet.packet /= ATT_Handle_Value_Confirmation()

					elif isinstance(packet,BLEFindInformationRequest):
						packet.packet /= ATT_Find_Information_Request(start=packet.startHandle,end = packet.endHandle)

					elif isinstance(packet,BLEFindInformationResponse):
						packet.packet /= ATT_Find_Information_Response(bytes([packet.format]) + packet.data)

					elif isinstance(packet,BLEWriteRequest):
						packet.packet /= ATT_Write_Request(gatt_handle=packet.handle,data=packet.value)

					elif isinstance(packet,BLEWriteCommand):
						packet.packet /= ATT_Write_Command(gatt_handle=packet.handle,data=packet.value)

					elif isinstance(packet,BLEWriteResponse):
						packet.packet /= ATT_Write_Response()

					elif isinstance(packet,BLEReadRequest):
						packet.packet /= ATT_Read_Request(gatt_handle=packet.handle)

					elif isinstance(packet,BLEReadResponse):
						packet.packet /= ATT_Read_Response(value=packet.value)


		if self.interface[-5:] == ".pcap" and packet.additionalInformations is not None:
			packet.packet = BTLE_PPI(
					rssi_count = packet.additionalInformations.rssi_count,
					rssi_avg = packet.additionalInformations.rssi_avg,
					rssi_min = packet.additionalInformations.rssi_min,
					rssi_max=packet.additionalInformations.rssi_max,
					btle_clk_100ns = packet.additionalInformations.clk_100ns,
					btle_clkn_high = packet.additionalInformations.clkn_high,
					btle_channel=packet.additionalInformations.channel)/packet.packet


		return packet.packet


class BLEReceiver(wireless.Receiver):
	'''
	This class is a Receiver for the Bluetooth Low Energy protocol ("ble").

	It can instantiates the following devices :

	  * HCI Device (``mirage.libs.ble.BLEHCIDevice``) **[ interface "hciX" (e.g. "hci0") ]**
	  * Ubertooth Device (``mirage.libs.ble_utils.ubertooth.BLEUbertoothDevice``) **[ interface "ubertoothX" (e.g. "ubertooth0") ]**
	  * BTLEJack Device (``mirage.libs.ble_utils.btlejack.BTLEJackDevice``) **[ interface "microbitX" (e.g. "microbit0") ]**
	  * ADB Device (``mirage.libs.ble_utils.adb.ADBDevice``) **[ interface "adbX" (e.g. "adb0") ]**
	  * HCIDump Device (``mirage.libs.ble_utils.hcidump.BLEHcidumpDevice``) **[ interface "hcidumpX" (e.g. "hcidump0") ]**
	  * PCAP Device (``mirage.libs.ble_utils.pcap.BLEPCAPDevice``) **[ interface "<file>.pcap" (e.g. "pairing.pcap") ]**

	'''
	def __init__(self,interface="hci0"):
		deviceClass = None
		self.encrypted = False
		self.recvTransmittedLLPackets = False
		self.backupCallbacks = []
		if "hcidump" in interface:
			deviceClass = BLEHcidumpDevice
		elif "hci" in interface:
			deviceClass = BLEHCIDevice
		elif "ubertooth" in interface:
			deviceClass = BLEUbertoothDevice
		elif "microbit" in interface:
			deviceClass = BTLEJackDevice
		elif "hackrf" in interface:
			deviceClass = BLEHackRFDevice
		elif "adb" in interface:
			deviceClass = ADBDevice
		elif "butterfly" in interface:
			if ":sub" in interface:
				deviceClass = BLEButterflySubdevice
			else:
				deviceClass = BLEButterflyDevice
		elif "sniffle" in interface:
			deviceClass = SniffleDevice
		elif "nrfsniffer" in interface:
			deviceClass = NRFSnifferDevice
		elif interface[-5:] == ".pcap":
			deviceClass = BLEPCAPDevice
		self.cryptoInstance = BLELinkLayerCrypto.getInstance()
		super().__init__(interface=interface, packetType=BLEPacket, deviceType=deviceClass)

	def storeCallbacks(self):
		self.backupCallbacks = self.callbacks

	def restoreCallbacks(self):
		self.callbacks = self.backupCallbacks

	def stop(self):
		self.encrypted = False
		super().stop()
		if self.isDeviceUp() and "hci" in self.interface and not "hcidump" in self.interface:
			self.device._exitListening()

	def enableEnc(self, enable):
		self.encrypted = enable

	def enableRecvOfTransmittedLLPackets(self, enable):
		self.recvTransmittedLLPackets = enable
	
	def convert(self,packet):
		if "hackrf" in self.interface:
			packet, iqSamples = packet
		cryptoInstance = BLELinkLayerCrypto.getInstance()
		if cryptoInstance is not None and cryptoInstance.ready and BTLE_DATA in packet and packet.LLID > 1:
			plain, success = cryptoInstance.tryToDecrypt(raw(packet[BTLE_DATA:]))
			if success:
				packet[BTLE_DATA] = BTLE_DATA(plain)
		new = BLEPacket()
		new.packet = packet
		if "hci" in self.interface or "adb" in self.interface:
			if packet.type == TYPE_ACL_DATA:
				if self.encrypted and HCI_ACL_Hdr in packet:
					hciACLHdrPayload = raw(packet[HCI_ACL_Hdr].payload)
					return BLELLEncData(
						length=packet[HCI_ACL_Hdr].len,
						payload=hciACLHdrPayload,
						PB=packet[HCI_ACL_Hdr].PB,
					)
				if ATT_Exchange_MTU_Request in packet:
					return BLEExchangeMTURequest(
						mtu = packet[ATT_Exchange_MTU_Request].mtu,
						connectionHandle = packet.handle
						)
				elif ATT_Error_Response in packet:
					return BLEErrorResponse(
						request = packet.request,
						handle = packet[ATT_Error_Response].handle,
						ecode = packet.ecode,
						connectionHandle = packet.handle
						)
				elif ATT_Exchange_MTU_Response in packet:
					return BLEExchangeMTUResponse(
						mtu = packet[ATT_Exchange_MTU_Response].mtu,
						connectionHandle = packet.handle
						)
				elif ATT_Read_Response in packet:
					return BLEReadResponse(
						value = packet[ATT_Read_Response].value,
						connectionHandle = packet.handle
						)
				elif ATT_Hdr in packet and packet[ATT_Hdr].opcode == 0xb:
					return BLEReadResponse(
						value = b"",
						connectionHandle = packet.handle
						)
				elif ATT_Read_Request in packet:
					return BLEReadRequest(
						handle = packet[ATT_Read_Request].gatt_handle,
						connectionHandle = packet.handle
						)
				elif ATT_Read_By_Group_Type_Response in packet:
					return BLEReadByGroupTypeResponse(
						connectionHandle = packet.handle,
						length = packet[ATT_Read_By_Group_Type_Response].length,
						data = packet[ATT_Read_By_Group_Type_Response].data
						)
				elif ATT_Read_By_Group_Type_Request in packet:
					return BLEReadByGroupTypeRequest(
						connectionHandle = packet.handle,
						startHandle = packet[ATT_Read_By_Group_Type_Request].start,
						endHandle = packet[ATT_Read_By_Group_Type_Request].end,
						uuid =packet[ATT_Read_By_Group_Type_Request].uuid
						)
				elif ATT_Read_By_Type_Response in packet:
					return BLEReadByTypeResponse(
						connectionHandle = packet.handle,
						data = bytes(packet[ATT_Read_By_Type_Response])
						)
				elif ATT_Read_By_Type_Request in packet:
					return BLEReadByTypeRequest(
						connectionHandle = packet.handle,
						startHandle = packet[ATT_Read_By_Type_Request].start,
						endHandle = packet[ATT_Read_By_Type_Request].end,
						uuid=packet[ATT_Read_By_Type_Request].uuid
						)
				elif ATT_Read_Blob_Request in packet:
					return BLEReadBlobRequest(
						handle = packet[ATT_Read_Blob_Request].gatt_handle,
						offset = packet[ATT_Read_Blob_Request].offset,
						connectionHandle = packet.handle
						)
				elif ATT_Read_Blob_Response in packet:
					return BLEReadBlobResponse(
						value = packet[ATT_Read_Blob_Response].value,
						connectionHandle = packet.handle
						)
				elif ATT_Handle_Value_Notification in packet:
					return BLEHandleValueNotification(
						connectionHandle = packet.handle,
						handle = packet[ATT_Handle_Value_Notification].gatt_handle,
						value = packet[ATT_Handle_Value_Notification].value
						)
				elif ATT_Handle_Value_Indication in packet:
					return BLEHandleValueIndication(
						connectionHandle = packet.handle,
						handle = packet[ATT_Handle_Value_Indication].gatt_handle,
						value = packet[ATT_Handle_Value_Indication].value
						)
				elif ATT_Handle_Value_Confirmation in packet or (ATT_Hdr in packet and packet[ATT_Hdr].opcode == 0x1e):
					return BLEHandleValueConfirmation(connectionHandle = packet.handle)

				elif ATT_Write_Response in packet or (ATT_Hdr in packet and packet[ATT_Hdr].opcode == 0x13):
					return BLEWriteResponse(connectionHandle = packet.handle)
				elif ATT_Write_Request in packet:
					return BLEWriteRequest(
						connectionHandle = packet.handle,
						handle = packet.gatt_handle,
						value = packet.data
						)
				elif ATT_Write_Command in packet:
					return BLEWriteCommand(
						connectionHandle = packet.handle,
						handle = packet.gatt_handle,
						value = packet.data
						)
				elif ATT_Find_Information_Request in packet:
					return BLEFindInformationRequest(
						connectionHandle = packet.handle,
						startHandle=packet.start,
						endHandle=packet.end
						)
				elif ATT_Find_Information_Response in packet:
					return BLEFindInformationResponse(
						connectionHandle = packet.handle,
						data=bytes(packet[ATT_Find_Information_Response])[1:],
						format=packet.format
						)

				elif SM_Security_Request in packet:
					return BLESecurityRequest(
							connectionHandle = packet.handle,
							authentication = packet.authentication)

				elif SM_Pairing_Request in packet:
					return BLEPairingRequest(
						connectionHandle = packet.handle,
						inputOutputCapability=packet.iocap,
						outOfBand=packet.oob == 1,
						authentication=packet.authentication,
						initiatorKeyDistribution=packet.initiator_key_distribution,
						responderKeyDistribution=packet.responder_key_distribution,
						payload=raw(packet[SM_Hdr:]))

				elif SM_Pairing_Response in packet:
					return BLEPairingResponse(
						connectionHandle = packet.handle,
						inputOutputCapability=packet.iocap,
						outOfBand=packet.oob == 1,
						authentication=packet.authentication,
						initiatorKeyDistribution=packet.initiator_key_distribution,
						responderKeyDistribution=packet.responder_key_distribution,
						payload=raw(packet[SM_Hdr:]))

				elif SM_Failed in packet:
					return BLEPairingFailed(
						connectionHandle = packet.handle,
						reason=packet.reason)

				elif SM_Confirm in packet:

					return BLEPairingConfirm(
						connectionHandle = packet.handle,
						confirm=packet.confirm)

				elif SM_Random in packet:
					return BLEPairingRandom(
						connectionHandle = packet.handle,
						random=packet.random)

				elif SM_Encryption_Information in packet:
					return BLEEncryptionInformation(
						connectionHandle = packet.handle,
						ltk=packet.ltk)
				elif SM_Public_Key in packet:
					return BLEPublicKey(
						connectionHandle = packet.handle,
						key_x=packet.key_x,
						key_y=packet.key_y,
					)
				elif SM_DHKey_Check in packet:
					return BLEDHKeyCheck(
						connectionHandle = packet.handle,
						dhkey_check=packet.dhkey_check)
				elif SM_Master_Identification in packet:
					return BLEMasterIdentification(
						connectionHandle = packet.handle,
						ediv=packet.ediv,
						rand=packet.rand)

				elif SM_Identity_Information in packet:
					return BLEIdentityInformation(
						connectionHandle = packet.handle,
						irk=packet.irk)

				elif SM_Identity_Address_Information in packet:
					return BLEIdentityAddressInformation(
						connectionHandle = packet.handle,
						type="public" if packet.atype == 0 else "random",
						address=packet.address)


				elif SM_Signing_Information in packet:
					return BLESigningInformation(
						connectionHandle = packet.handle,
						csrk=packet.csrk)

				elif ATT_Find_By_Type_Value_Request in packet:
					return BLEFindByTypeValueRequest(
						startHandle=packet[ATT_Find_By_Type_Value_Request].start,
						endHandle=packet[ATT_Find_By_Type_Value_Request].end,
						uuid=packet[ATT_Find_By_Type_Value_Request].uuid,
						data=packet[ATT_Find_By_Type_Value_Request].data)

				elif ATT_Find_By_Type_Value_Response in packet:
					return BLEFindByTypeValueResponse(
						handles=packet[ATT_Find_By_Type_Value_Response].handles)

				elif L2CAP_Connection_Parameter_Update_Request in packet:
					return BLEConnectionParameterUpdateRequest(
						l2capCmdId = packet.id,
						connectionHandle = packet.handle,
						maxInterval=packet.max_interval,
						minInterval=packet.min_interval,
						timeoutMult=packet.timeout_mult,
						slaveLatency=packet.slave_latency
						)
				elif L2CAP_Connection_Parameter_Update_Response in packet:
					return BLEConnectionParameterUpdateResponse(
						l2capCmdId = packet.id,
						connectionHandle = packet.handle,
						moveResult=packet.move_result
						)
					return new
			elif packet.type == TYPE_HCI_COMMAND:
				if HCI_Cmd_LE_Create_Connection in packet:
					return BLEConnect(
							dstAddr = packet.paddr,
							type="public" if packet.patype == 0 else "random",
							initiatorType = "public" if packet.atype == 0 else "random")
				elif HCI_Cmd_LE_Create_Connection_Cancel in packet:
					return BLEConnectionCancel()
				elif L2CAP_Connection_Parameter_Update_Request in packet:
					return BLEConnectionParameterUpdateRequest(
											l2capCmdId = packet.id,
											connectionHandle = packet.handle,
											maxInterval = packet.max_interval,
											minInterval = packet.min_interval,
											slaveLatency = packet.slave_latency,
											timeoutMult=packet.timeout_mult
											)
				elif L2CAP_Connection_Parameter_Update_Response in packet:
					return BLEConnectionParameterUpdateResponse(
											l2capCmdId = packet.id,
											connectionHandle = packet.handle,
											moveResult=packet.move_result)
				elif HCI_Cmd_LE_Start_Encryption_Request in packet:
					return BLELongTermKeyRequest(
									connectionHandle = packet.handle,
									rand = packet.rand,
									ediv = packet.ediv,
									ltk=packet.ltk)
				elif HCI_Cmd_LE_Long_Term_Key_Request_Reply in packet:
					return BLELongTermKeyRequestReply(
									connectionHandle = packet.handle,
									ltk=packet.ltk,
									positive=True)
				elif HCI_Cmd_LE_Long_Term_Key_Request_Negative_Reply in packet:
					return BLELongTermKeyRequestReply(connectionHandle = packet.handle,positive=False)

			elif packet.type == TYPE_HCI_EVENT:
				if packet.code == HCI_LE_META:
					if packet.event == HCI_ENHANCED_CONNECTION_COMPLETE and packet.status == 0x0:
						newHandle = packet[HCI_LE_Meta_Enhanced_Connection_Complete].handle
						newAddress = str(packet[HCI_LE_Meta_Enhanced_Connection_Complete].paddr)
						self.device._setCurrentHandle(newHandle,address=newAddress,mode="public" if packet.patype == 0 else "random")

						return BLEConnectResponse(
							srcAddr = packet.paddr,
							dstAddr = '',
							role="master" if packet.role==0 else "slave",
							success=True,
							type="public" if packet.patype == 0 else "random",
							interval = packet.interval
							)
					if packet.event == HCI_CONNECTION_COMPLETE and packet.status == 0x0:
						newHandle = packet[HCI_LE_Meta_Connection_Complete].handle
						newAddress = str(packet[HCI_LE_Meta_Connection_Complete].paddr)
						self.device._setCurrentHandle(newHandle,address=newAddress,mode="public" if packet.patype == 0 else "random")

						return BLEConnectResponse(
							srcAddr = packet.paddr,
							dstAddr = '',
							role="master" if packet.role==0 else "slave",
							success=True,
							type="public" if packet.patype == 0 else "random",
							interval = packet.interval
							)
					elif packet.event == HCI_ADVERTISING_REPORT:
						layer = packet[HCI_LE_Meta_Advertising_Report]
						type = "SCAN_RSP" if layer.type == SCAN_RSP else "ADV_IND"
						return BLEAdvertisement(
							addr = layer.addr,
							addrType = layer.atype,
							data=layer.data,
							type=type
							)
					elif packet.event == HCI_LONG_TERM_KEY_REQUEST or HCI_LE_Meta_Long_Term_Key_Request in packet:
						return BLELongTermKeyRequest(
							connectionHandle=packet.handle,
							rand=packet.rand,
							ediv=packet.ediv
						)
				elif HCI_Event_Encryption_Change in packet:
					return BLEEncryptionChange(
						connectionHandle=packet.handle,
						status=packet.status,
						enabled=packet.enabled
					)
				elif packet.code == HCI_DISCONNECTION_COMPLETE:
					handle = packet.handle
					self.device._removeConnectionHandle(handle)
					return BLEDisconnect(connectionHandle=handle)
				
				# Handle custom HCI command from custom Zephyr controller
				elif packet.code == 0xFF:
					ll_raw_packet = packet.load
					opcode = ll_raw_packet[0]
					direction = ll_raw_packet[1]
					payloadLen = ll_raw_packet[2]
					sn = ll_raw_packet[3]
					nesn = ll_raw_packet[4]
					payload = ll_raw_packet[5:]
					# direction = 1 => transmitted Ctrl PDU
					# direction = 2 => received Ctrl PDU

					# Transmitted data packet, ignore for the moment
					if direction == 1 and not self.recvTransmittedLLPackets:
						return None
					if self.encrypted:
						return BLELLEncCtrl(
							encOpcode=opcode,
							sn=sn,
							nesn=nesn,
							encData=payload[:payloadLen],
							direction=1 if direction == 1 else 0,
						)
					elif opcode == LLCTRL_TYPE_CONN_UPDATE_IND:
						return BLELLConnUpdateInd(
							win_size=payload[0],
							win_offset=payload[1:3],
							interval=payload[3:5],
							latency=payload[5:7],
							timeout=payload[7:9],
							instant=payload[9:11],	
							direction=1 if direction == 1 else 0,
						)
					elif opcode == LLCTRL_TYPE_CHAN_MAP_IND:
						return BLELLChanMapInd(
							chm=payload[:5],
							instant=payload[5:7],	
							direction=1 if direction == 1 else 0,
						)
					elif opcode == LLCTRL_TYPE_TERMINATE_IND:
						return BLELLTerminateInd(
							error_code=payload[0],	
							direction=1 if direction == 1 else 0,
						)
					elif opcode == LLCTRL_TYPE_ENC_REQ:
						return BLELLEncReq(
							rand=payload[:8],
							ediv=payload[8:10],
							skdm=payload[10:18],
							ivm=payload[18:22],	
							direction=1 if direction == 1 else 0,
						)
					elif opcode == LLCTRL_TYPE_ENC_RSP:
						return BLELLEncRsp(
							skds=payload[:8],
							ivs=payload[8:12],	
							direction=1 if direction == 1 else 0,
						)
					elif opcode == LLCTRL_TYPE_START_ENC_REQ:
						return BLELLStartEncReq(	
							direction=1 if direction == 1 else 0,
						)
					elif opcode == LLCTRL_TYPE_START_ENC_RSP:
						return BLELLStartEncRsp(	
							direction=1 if direction == 1 else 0,
						)
					elif opcode == LLCTRL_TYPE_UNKNOWN_RSP:
						return BLELLUnknownRsp(
							type=payload[0],	
							direction=1 if direction == 1 else 0,
						)
					elif opcode == LLCTRL_TYPE_FEATURE_REQ:
						return BLELLFeatureReq(
							features=payload[0:8],	
							direction=1 if direction == 1 else 0,
						)
					elif opcode == LLCTRL_TYPE_FEATURE_RSP:
						return BLELLFeatureRsp(
							features=payload[0:8],	
							direction=1 if direction == 1 else 0,
						)
					elif opcode == LLCTRL_TYPE_PAUSE_ENC_REQ:
						return BLELLPauseEncReq(	
							direction=1 if direction == 1 else 0,
						)
					elif opcode == LLCTRL_TYPE_PAUSE_ENC_RSP:
						return BLELLPauseEncRsp(	
							direction=1 if direction == 1 else 0,
						)
					elif opcode == LLCTRL_TYPE_VERSION_IND:
						return BLELLVersionInd(
							version_number=payload[0],
							company_id=payload[1:3],
							sub_version_number=payload[3:4],	
							direction=1 if direction == 1 else 0,
						)
					elif opcode == LLCTRL_TYPE_REJECT_IND:
						return BLELLRejectInd(
							error_code=payload[0],	
							direction=1 if direction == 1 else 0,
						)
					elif opcode == LLCTRL_TYPE_SLAVE_FEATURE_REQ:
						return BLELLSlaveFeatureReq(
							features=payload[0:8],	
							direction=1 if direction == 1 else 0,
						)
					elif opcode == LLCTRL_TYPE_CONN_PARAM_REQ:
						return BLELLConnParamReq(
							interval_min=payload[0:2],
							interval_max=payload[2:4],
							latency=payload[4:6],
							timeout=payload[6:8],
							preferred_periodicity=payload[8],
							reference_conn_event_count=payload[9:11],
							offset0=payload[11:13],
							offset1=payload[13:15],
							offset2=payload[15:17],
							offset3=payload[17:19],
							offset4=payload[19:21],
							offset5=payload[21:23],	
							direction=1 if direction == 1 else 0,
						)
					elif opcode == LLCTRL_TYPE_CONN_PARAM_RSP:
						return BLELLConnParamRsp(
							interval_min=payload[0:2],
							interval_max=payload[2:4],
							latency=payload[4:6],
							timeout=payload[6:8],
							preferred_periodicity=payload[8],
							reference_conn_event_count=payload[9:10],
							offset0=payload[11:13],
							offset1=payload[13:15],
							offset2=payload[15:17],
							offset3=payload[17:19],
							offset4=payload[19:21],
							offset5=payload[21:23],	
							direction=1 if direction == 1 else 0,
						)
					elif opcode == LLCTRL_TYPE_REJECT_EXT_IND:
						return BLELLRejectExtInd(
							opcode=payload[0],
							error_code=payload[1],	
							direction=1 if direction == 1 else 0,
						)
					elif opcode == LLCTRL_TYPE_PING_REQ:
						return BLELLPingReq(	
							direction=1 if direction == 1 else 0,
						)
					elif opcode == LLCTRL_TYPE_PING_RSP:
						return BLELLPingRsp(	
							direction=1 if direction == 1 else 0,
						)
					elif opcode == LLCTRL_TYPE_LENGTH_REQ:
						return BLELLDataLenReq(
							max_rx_octets=payload[0:2],
							max_rx_time=payload[2:4],
							max_tx_octets=payload[4:6],
							max_tx_time=payload[6:8],	
							direction=1 if direction == 1 else 0,
						)
					elif opcode == LLCTRL_TYPE_LENGTH_RSP:
						return BLELLDataLenRsp(
							max_rx_octets=payload[0:2],
							max_rx_time=payload[2:4],
							max_tx_octets=payload[4:6],
							max_tx_time=payload[6:8],	
							direction=1 if direction == 1 else 0,
						)
					elif opcode == LLCTRL_TYPE_PHY_REQ:
						return BLELLPHYReq(
							tx_phys=payload[0],
							rx_phys=payload[1],	
							direction=1 if direction == 1 else 0,
						)
					elif opcode == LLCTRL_TYPE_PHY_RSP:
						return BLELLPHYReq(
							tx_phys=payload[0],
							rx_phys=payload[1],	
							direction=1 if direction == 1 else 0,
						)
					elif opcode == LLCTRL_TYPE_PHY_UPD_IND:
						return BLELLUpdPHYInd(
							m_to_s_phy=payload[0],
							s_to_m_phy=payload[1],	
							direction=1 if direction == 1 else 0,
						)
					elif opcode == LLCTRL_TYPE_MIN_USED_CHAN_IND:
						return BLELLMinUsedChann(
							phys=payload[0],
							min_used_chans=payload[1],	
							direction=1 if direction == 1 else 0,
						)				
				else:
					return None
		elif (	"hackrf" in self.interface or
				"butterfly" in self.interface or
				"ubertooth" in self.interface or
 				"microbit" in self.interface or
				"nrfsniffer" in self.interface or
				"sniffle" in self.interface or
 				self.interface[-5:] == ".pcap"):
			try:
				if ((cryptoInstance is None) or (cryptoInstance is not None and not cryptoInstance.ready)) and self.encrypted:
					new = BLEEncryptedPacket(connectionHandle = 1, data = bytes(packet[BTLE_DATA]))
				else:

					if BTLE_ADV in packet:
						if BTLE_CONNECT_REQ in packet:

							new = BLEConnectRequest(
									srcAddr=packet.InitA,
									dstAddr=packet.AdvA,
									srcAddrType="public" if 0 == packet.TxAdd else "random",
									dstAddrType="public" if 0 == packet.RxAdd else "random",
									accessAddress=packet.AA,
									crcInit=packet.crc_init,
									winSize=packet.win_size,
									winOffset=packet.win_offset,
									hopInterval=packet.interval,
									latency=packet.latency,
									timeout=packet.timeout,
									channelMap =packet.chM,
									SCA=packet.SCA,
									hopIncrement=packet.hop,
									data=raw(packet[BTLE_ADV])
									)
						else:
							try:
								advType = ADV_TYPES[packet.PDU_type]
							except:
								advType = "???"
							try:
								data = packet.data
							except:
								data = b""

							if advType == "CONNECT_REQ":
								new = BLEConnectRequest(
									srcAddr=packet.InitA,
									dstAddr=packet.AdvA,
									srcAddrType="public" if 0 == packet.TxAdd else "random",
									dstAddrType="public" if 0 == packet.RxAdd else "random",
									accessAddress=packet.AA,
									crcInit=packet.crc_init,
									winSize=packet.win_size,
									winOffset=packet.win_offset,
									hopInterval=packet.interval,
									latency=packet.latency,
									timeout=packet.timeout,
									channelMap =packet.chM,
									SCA=packet.SCA,
									hopIncrement=packet.hop,
									data=data
											)
							elif advType == "ADV_IND":
								new = BLEAdvInd(
									addr=packet.AdvA,
									addrType="public" if 0 == packet.TxAdd else "random",
									data=data)
							elif advType == "ADV_DIRECT_IND":
								new = BLEAdvDirectInd(
									srcAddr=packet.AdvA,
									srcAddrType="public" if 0 == packet.TxAdd else "random",
									dstAddr=packet.InitA,
									dstAddrType="public" if 0 == packet.RxAdd else "random")
							elif advType == "ADV_NONCONN_IND":
								new = BLEAdvNonConnInd()
							elif advType == "ADV_SCAN_IND":
								new = BLEAdvScanInd()
							elif advType == "SCAN_REQ":
								new = BLEScanRequest(
									srcAddr=packet.ScanA,
									srcAddrType="public" if 0 == packet.TxAdd else "random",
									dstAddr=packet.AdvA,
									dstAddrType="public" if 0 == packet.RxAdd else "random")
							elif advType == "SCAN_RSP":
								new = BLEScanResponse(
									addr=packet.AdvA,
									addrType="public" if 0 == packet.TxAdd else "random",
									data=data)
							else:
								new = BLEAdvertisement(	addr = packet.AdvA,
											addrType=packet.RxAdd,
											data=data,
											type=advType)

					elif packet.LLID == 1:
						new = BLEEmptyPDU()
					elif packet.LLID == 2:
						if ATT_Exchange_MTU_Request in packet:
							new = BLEExchangeMTURequest(
								mtu = packet[ATT_Exchange_MTU_Request].mtu
								)
						elif ATT_Error_Response in packet:
							new = BLEErrorResponse(
								request = packet.request,
								handle = packet[ATT_Error_Response].handle,
								ecode = packet.ecode
								)
						elif ATT_Exchange_MTU_Response in packet:
							new = BLEExchangeMTUResponse(
								mtu = packet[ATT_Exchange_MTU_Response].mtu
								)
						elif ATT_Read_Response in packet :
							new = BLEReadResponse(
								value = packet[ATT_Read_Response].value
								)
						elif ATT_Read_Request in packet:
							new = BLEReadRequest(
								handle = packet[ATT_Read_Request].gatt_handle
								)
						elif ATT_Read_By_Group_Type_Response in packet:
							new = BLEReadByGroupTypeResponse(
								length = packet[ATT_Read_By_Group_Type_Response].length,
								data = packet[ATT_Read_By_Group_Type_Response].data
								)
						elif ATT_Read_By_Group_Type_Request in packet:
							new = BLEReadByGroupTypeRequest(
								startHandle = packet[ATT_Read_By_Group_Type_Request].start,
								endHandle = packet[ATT_Read_By_Group_Type_Request].end,
								uuid =packet[ATT_Read_By_Group_Type_Request].uuid
								)
						elif ATT_Read_By_Type_Response in packet:
							new = BLEReadByTypeResponse(
								data = bytes(packet[ATT_Read_By_Type_Response])
								)
						elif ATT_Read_By_Type_Request in packet:
							new = BLEReadByTypeRequest(
								startHandle = packet[ATT_Read_By_Type_Request].start,
								endHandle = packet[ATT_Read_By_Type_Request].end,
								uuid=packet[ATT_Read_By_Type_Request].uuid
								)
						elif ATT_Handle_Value_Notification in packet:
							new = BLEHandleValueNotification(
								handle = packet[ATT_Handle_Value_Notification].handle,
								value = packet[ATT_Handle_Value_Notification].value
								)
						elif ATT_Handle_Value_Indication in packet:
							new = BLEHandleValueIndication(
								connectionHandle = packet.handle,
								handle = packet[ATT_Handle_Value_Indication].gatt_handle,
								value = packet[ATT_Handle_Value_Indication].value
								)
						elif ATT_Handle_Value_Confirmation in packet or (ATT_Hdr in packet and packet[ATT_Hdr].opcode == 0x1e):
							new = BLEHandleValueConfirmation(connectionHandle = packet.handle)
						elif ATT_Read_Blob_Request in packet:
							new = BLEReadBlobRequest(
								handle = packet[ATT_Read_Blob_Request].gatt_handle,
								offset = packet[ATT_Read_Blob_Request].offset
								)
						elif ATT_Read_Blob_Response in packet:
							new = BLEReadBlobResponse(
								value = packet[ATT_Read_Blob_Response].value
								)
						elif ATT_Write_Response in packet or (ATT_Hdr in packet and packet[ATT_Hdr].opcode == 0x13):
							new = BLEWriteResponse()
						elif ATT_Write_Request in packet:
							new = BLEWriteRequest(
								handle = packet.gatt_handle,
								value = packet.data
								)
						elif ATT_Write_Command in packet:
							new = BLEWriteCommand(
								handle = packet.gatt_handle,
								value = packet.data
								)
						elif ATT_Find_Information_Request in packet:
							new = BLEFindInformationRequest(
								startHandle=packet.start,
								endHandle=packet.end
								)
						elif ATT_Find_Information_Response in packet:
							new = BLEFindInformationResponse(
								data=bytes(packet[ATT_Find_Information_Response])[1:],
								format=packet.format
								)
						elif SM_Security_Request in packet:
							return BLESecurityRequest(
									connectionHandle = packet.handle,
									authentication = packet.authentication)
						elif SM_Pairing_Request in packet:
							new = BLEPairingRequest(
								inputOutputCapability=packet.iocap,
								outOfBand=packet.oob == 1,
								authentication=packet.authentication,
								initiatorKeyDistribution=packet.initiator_key_distribution,
								responderKeyDistribution=packet.responder_key_distribution,
								payload=raw(packet[SM_Hdr:]))

						elif SM_Pairing_Response in packet:
							new = BLEPairingResponse(
								inputOutputCapability=packet.iocap,
								outOfBand=packet.oob == 1,
								authentication=packet.authentication,
								initiatorKeyDistribution=packet.initiator_key_distribution,
								responderKeyDistribution=packet.responder_key_distribution,
								payload=raw(packet[SM_Hdr:]))

						elif SM_Failed in packet:
							new = BLEPairingFailed(reason=packet.reason)

						elif SM_Confirm in packet:
							new = BLEPairingConfirm(confirm=packet.confirm)

						elif SM_Random in packet:
							new = BLEPairingRandom(random=packet.random)

						elif SM_Encryption_Information in packet:
							new = BLEEncryptionInformation(ltk=packet.ltk)

						elif SM_Master_Identification in packet:
							new = BLEMasterIdentification(
								ediv=packet.ediv,
								rand=packet.rand)

						elif SM_Identity_Information in packet:
							new = BLEIdentityInformation(irk=packet.irk)

						elif SM_Identity_Address_Information in packet:
							new = BLEIdentityAddressInformation(
								type="public" if packet.atype == 0 else "random",
								address=packet.address)


						elif SM_Signing_Information in packet:
							new = BLESigningInformation(
								csrk=packet.csrk)

						elif ATT_Find_By_Type_Value_Request in packet:
							new = BLEFindByTypeValueRequest(
								startHandle=packet[ATT_Find_By_Type_Value_Request].start,
								endHandle=packet[ATT_Find_By_Type_Value_Request].end,
								uuid=packet[ATT_Find_By_Type_Value_Request].uuid,
								data=packet[ATT_Find_By_Type_Value_Request].data)

						elif ATT_Find_By_Type_Value_Response in packet:
							new = BLEFindByTypeValueResponse(handles=packet[ATT_Find_By_Type_Value_Response].handles)

						elif L2CAP_Connection_Parameter_Update_Request in packet:
							new = BLEConnectionParameterUpdateRequest(
								maxInterval=packet.max_interval,
								minInterval=packet.min_interval,
								timeoutMult=packet.timeout_mult,
								slaveLatency=packet.slave_latency
								)
						elif L2CAP_Connection_Parameter_Update_Response in packet:
							new = BLEConnectionParameterUpdateResponse(
								moveResult=packet.move_result
								)
					elif packet.LLID == 3:

						try:
							controlType = CONTROL_TYPES[packet.opcode]
						except:
							controlType = "???"
						try:
							data = bytes(packet[BTLE_CTRL:])[1:]
						except:
							data = b""
						if controlType == "LL_TERMINATE_IND" and packet.code == 0x24:
							return BLEDisconnect()
						if controlType == "LL_ENC_REQ":
							#packet.show()
							if cryptoInstance is not None:
								cryptoInstance.setMasterValues(packet.skd,packet.iv)
						elif controlType == "LL_ENC_RSP":
							#packet.show()
							if cryptoInstance is not None:
								cryptoInstance.setSlaveValues(packet.skd,packet.iv)

						elif controlType == "LL_START_ENC_REQ":
							self.encrypted = True
							if cryptoInstance is not None:
								cryptoInstance.generateSessionKey()

						new = BLEControlPDU(type=controlType,data=data)

			except:
				new = BLEPacket()
				new.packet = packet
			if "ubertooth" in self.interface:
				new.additionalInformations = BLESniffingParameters(
									rssi_min = packet.rssi_min,
									rssi_max = packet.rssi_max,
									rssi_avg = packet.rssi_avg,
									rssi_count = packet.rssi_count,
									frequency=packet.channel,
									clk_100ns=packet.clk_100ns,
									clkn_high=packet.clkn_high
									)
			elif "microbit" in self.interface:

				new.additionalInformations = BLESniffingParameters(
									rssi = packet.rssi_avg,
									rssi_count = packet.rssi_count,
									clk_100ns = packet.btle_clk_100ns,
									clkn_high = packet.btle_clkn_high,
									channel = packet.btle_channel
									)
			elif "hackrf" in self.interface:

				new.additionalInformations = BLESniffingParameters(
									rssi = packet.rssi_avg,
									rssi_count = packet.rssi_count,
									clk_100ns = packet.btle_clk_100ns,
									clkn_high = packet.btle_clkn_high,
									channel = packet.btle_channel
									)
			elif "butterfly" in self.interface:

				new.additionalInformations = BLESniffingParameters(
									rssi = packet.rssi_avg,
									rssi_count = packet.rssi_count,
									clk_100ns = packet.btle_clk_100ns,
									clkn_high = packet.btle_clkn_high,
									channel = packet.btle_channel,
									rawPacket = bytes(packet[BTLE:])
									)

			elif "sniffle" in self.interface:

				new.additionalInformations = BLESniffingParameters(
									rssi = packet.rssi_avg,
									rssi_count = packet.rssi_count,
									clk_100ns = packet.btle_clk_100ns,
									clkn_high = packet.btle_clkn_high,
									channel = packet.btle_channel
									)
			elif "nrfsniffer" in self.interface:

				new.additionalInformations = BLESniffingParameters(
									rssi = packet.rssi_avg,
									rssi_count = packet.rssi_count,
									clk_100ns = packet.btle_clk_100ns,
									clkn_high = packet.btle_clkn_high,
									channel = packet.btle_channel
									)
			elif ".pcap" in self.interface:
				new.additionalInformations = BLESniffingParameters(
									rssi = packet.rssi_avg,
									rssi_count = packet.rssi_count,
									clk_100ns = packet.btle_clk_100ns,
									clkn_high = packet.btle_clkn_high,
									channel = packet.btle_channel
									)

		return new

WirelessModule.registerEmitter("ble",BLEEmitter)
WirelessModule.registerReceiver("ble",BLEReceiver)
