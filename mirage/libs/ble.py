from scapy.all import *
from mirage.core.module import WirelessModule
from mirage.libs.ble_utils.scapy_hci_layers import *
from mirage.libs.ble_utils.packets import *
from mirage.libs.ble_utils.constants import *
from mirage.libs.bt_utils.assigned_numbers import AssignedNumbers
from mirage.libs.ble_utils.ubertooth import *
from mirage.libs.ble_utils.btlejack import *
from mirage.libs.ble_utils.nrfsniffer import *
from mirage.libs.ble_utils.adb import *
from mirage.libs.ble_utils.hcidump import *
from mirage.libs.ble_utils.pcap import *
from mirage.libs.ble_utils.helpers import *
from mirage.libs.ble_utils.crypto import *
from mirage.libs.ble_utils.scapy_link_layers import *
from mirage.libs.ble_utils.dissectors import *
from mirage.libs.ble_utils.att_server import *
from mirage.libs import wireless,bt,io


class BLEHCIDevice(bt.BtHCIDevice):
	'''
	This device allows to communicate with an HCI Device in order to use Bluetooth Low Energy protocol.
	The corresponding interfaces are : ``hciX`` (e.g. "hciX")

	The following capabilities are actually supported :

	+-----------------------------------+----------------+
	| Capability			    | Available ?    |
	+===================================+================+
	| SCANNING                          | yes            |
	+-----------------------------------+----------------+
	| ADVERTISING                       | yes            |
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
	| INITIATING_CONNECTION             | yes            |
	+-----------------------------------+----------------+
	| RECEIVING_CONNECTION              | yes            |
	+-----------------------------------+----------------+
	| COMMUNICATING_AS_MASTER           | yes            |
	+-----------------------------------+----------------+
	| COMMUNICATING_AS_SLAVE            | yes            |
	+-----------------------------------+----------------+
	| HCI_MONITORING                    | no             |
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
		"updateConnectionParameters"
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
		self._internalCommand(HCI_Cmd_Reset())
		self._internalCommand(HCI_Cmd_Set_Event_Filter())
		self._internalCommand(HCI_Cmd_Connect_Accept_Timeout())
		self._internalCommand(HCI_Cmd_Set_Event_Mask())
		self._internalCommand(HCI_Cmd_LE_Host_Supported())
		self._exitCommandMode()

		self.capabilities = ["SCANNING", "ADVERTISING", "INITIATING_CONNECTION", "RECEIVING_CONNECTION", "COMMUNICATING_AS_MASTER", "COMMUNICATING_AS_SLAVE"]

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
			self._enterCommandMode()
			io.info("Changing HCI Device ("+str(self.interface)+") Random Address to : "+address)
			self._internalCommand(HCI_Cmd_LE_Set_Random_Address(address=address))
			io.success("BD Address successfully modified !")
			self._exitCommandMode()
			return True
		else:
			self.addressMode = "public"
			rValue = super().setAddress(address)
			self._setOperationMode(BLEOperationMode.NORMAL)
			return rValue
	
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
			advtype = ADV_IND
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
		self._internalCommand(New_HCI_Cmd_LE_Set_Advertising_Data(data=EIR_Hdr(data)))
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

	def init(self):
		self.initializeBluetooth = False
		super().init()
		if self.ready:
			self.addressMode = "public"
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
											atype=packet.initiatorType)
					elif isinstance(packet,BLEConnectionCancel):
						packet.packet /= HCI_Command_Hdr()/HCI_Cmd_LE_Create_Connection_Cancel()
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
							packet.packet /= ControlPDU(optcode=0x02)
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
							packet.packet /= ControlPDU(optcode = optcode)
							if packet.data is not None or packet.data != b"":
								packet.packet /= packet.data

				# Common sublayers
				if HCI_Command_Hdr not in packet.packet and ControlPDU not in packet.packet and BTLE_ADV not in packet.packet:
					

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

					elif isinstance(packet,BLEPairingRequest):
						packet.packet /= SM_Pairing_Request(
								iocap=packet.inputOutputCapability,
								oob=1 if packet.outOfBand else 0,
								authentication=packet.authentication,
								max_key_size = packet.maxKeySize,
								initiator_key_distribution=packet.initiatorKeyDistribution,
								responder_key_distribution = packet.responderKeyDistribution)


					elif isinstance(packet,BLEPairingResponse):
						packet.packet /= SM_Pairing_Response(
								iocap=packet.inputOutputCapability,
								oob=1 if packet.outOfBand else 0,
								authentication=packet.authentication,
								max_key_size = packet.maxKeySize,
								initiator_key_distribution=packet.initiatorKeyDistribution,
								responder_key_distribution = packet.responderKeyDistribution)

					elif isinstance(packet,BLEPairingFailed):
						packet.packet /= SM_Failed(reason=packet.reason)

					elif isinstance(packet,BLEPairingConfirm):
						packet.packet /= SM_Confirm(confirm=packet.confirm)


					elif isinstance(packet,BLEPairingRandom):
						packet.packet /= SM_Random(random=packet.random)

					elif isinstance(packet,BLEEncryptionInformation):
						packet.packet /= SM_Encryption_Information(ltk=packet.ltk)

					elif isinstance(packet,BLEMasterIdentification):
						packet.packet /= SM_Master_Identification(ediv=packet.ediv, rand=packet.rand)

					elif isinstance(packet,BLEIdentityInformation):
						packet.packet /= SM_Identity_Information(irk=packet.irk)

					elif isinstance(packet,BLEIdentityAddressInformation):
						packet.packet /= SM_Identity_Address_Information(
											atype=0 if packet.type=="public" else 1,
											address=packet.address
												)
					elif isinstance(packet,BLESigningInformation):
						packet.packet /= SM_Signing_Information(csrk=packet.csrk)

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
						packet.packet /= New_ATT_Read_Blob_Request(gatt_handle=packet.handle,offset=packet.offset)
					elif isinstance(packet,BLEReadBlobResponse):
						packet.packet /= New_ATT_Read_Blob_Response(value=packet.value)
					elif isinstance(packet,BLEHandleValueNotification):
						packet.packet /= New_ATT_Handle_Value_Notification(gatt_handle=packet.handle,value=packet.value)
					elif isinstance(packet,BLEHandleValueIndication):
						packet.packet /= New_ATT_Handle_Value_Indication(gatt_handle=packet.handle,value=packet.value)
					elif isinstance(packet,BLEHandleValueConfirmation):
						packet.packet /= New_ATT_Handle_Value_Confirmation()

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
		elif interface[-5:] == ".pcap":
			deviceClass = BLEPCAPDevice
		self.cryptoInstance = BLELinkLayerCrypto.getInstance()
		super().__init__(interface=interface, packetType=BLEPacket, deviceType=deviceClass)

	def stop(self):
		self.encrypted = False
		super().stop()
		if self.isDeviceUp() and "hci" in self.interface and not "hcidump" in self.interface:
			self.device._exitListening()

	def convert(self,packet):

		cryptoInstance = BLELinkLayerCrypto.getInstance()
		if cryptoInstance is not None and cryptoInstance.ready and BTLE_DATA in packet and packet.LLID > 1:
			plain, success = cryptoInstance.tryToDecrypt(raw(packet[BTLE_DATA:]))
			if success:
				packet[BTLE_DATA] = BTLE_DATA(plain)
		new = BLEPacket()
		new.packet = packet
		if "hci" in self.interface or "adb" in self.interface:
			#packet.show()

			if packet.type == TYPE_ACL_DATA:
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
				elif ATT_Read_Response in packet :
					return BLEReadResponse(
						value = packet[ATT_Read_Response].value,
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
				elif New_ATT_Read_Blob_Request in packet:
					return BLEReadBlobRequest(
						handle = packet[New_ATT_Read_Blob_Request].gatt_handle,
						offset = packet[New_ATT_Read_Blob_Request].offset,
						connectionHandle = packet.handle
						)
				elif New_ATT_Read_Blob_Response in packet:
					return BLEReadBlobResponse(
						value = packet[New_ATT_Read_Blob_Response].value,
						connectionHandle = packet.handle
						)
				elif New_ATT_Handle_Value_Notification in packet:
					return BLEHandleValueNotification(
						connectionHandle = packet.handle,
						handle = packet[New_ATT_Handle_Value_Notification].gatt_handle,
						value = packet[New_ATT_Handle_Value_Notification].value
						)
				elif New_ATT_Handle_Value_Indication in packet:
					return BLEHandleValueIndication(
						connectionHandle = packet.handle,
						handle = packet[New_ATT_Handle_Value_Indication].gatt_handle,
						value = packet[New_ATT_Handle_Value_Indication].value
						)
				elif New_ATT_Handle_Value_Confirmation in packet or (ATT_Hdr in packet and packet[ATT_Hdr].opcode == 0x1e):
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
						io.info('Updating connection handle : '+str(newHandle))

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
						io.info('Updating connection handle : '+str(newHandle))

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
				
				elif packet.code == HCI_DISCONNECTION_COMPLETE:
					handle = packet.handle
					self.device._removeConnectionHandle(handle)
					return BLEDisconnect(connectionHandle=handle)
				else:
					return None
		elif "ubertooth" in self.interface or "microbit" in self.interface or "nrfsniffer" in self.interface or self.interface[-5:] == ".pcap":
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
						elif New_ATT_Handle_Value_Notification in packet:
							new = BLEHandleValueNotification(
								handle = packet[New_ATT_Handle_Value_Notification].handle,
								value = packet[New_ATT_Handle_Value_Notification].value
								)
						elif New_ATT_Handle_Value_Indication in packet:
							new = BLEHandleValueIndication(
								connectionHandle = packet.handle,
								handle = packet[New_ATT_Handle_Value_Indication].gatt_handle,
								value = packet[New_ATT_Handle_Value_Indication].value
								)
						elif New_ATT_Handle_Value_Confirmation in packet or (ATT_Hdr in packet and packet[ATT_Hdr].opcode == 0x1e):
							new = BLEHandleValueConfirmation(connectionHandle = packet.handle)
						elif New_ATT_Read_Blob_Request in packet:
							new = BLEReadBlobRequest(
								handle = packet[New_ATT_Read_Blob_Request].gatt_handle,
								offset = packet[New_ATT_Read_Blob_Request].offset
								)
						elif New_ATT_Read_Blob_Response in packet:
							new = BLEReadBlobResponse(
								value = packet[New_ATT_Read_Blob_Response].value
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
							controlType = CONTROL_TYPES[packet.optcode]
						except:
							controlType = "???"
						try:
							data = bytes(packet[ControlPDU:])[1:]
						except:
							data = b""
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
