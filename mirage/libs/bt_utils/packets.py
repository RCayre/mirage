from mirage.libs import wireless

'''
This module contains Mirage Packets for the Bluetooth protocol.
'''
PSM_PROTOCOLS = {1: "SDP", 3: "RFCOMM", 5: "telephony control"}

class BluetoothPacket(wireless.Packet):
	'''
	Mirage Bluetooth Packet
	'''
	def __init__(self):
		super().__init__()
		self.name = "Bluetooth - Unknown Packet"

class BluetoothWriteExtendedInquiryResponse(BluetoothPacket):
	'''
	Mirage Bluetooth Packet - Write Extended Inquiry Response

	:param fecRequired: boolean indicating if the Forward Error Correction is required
	:type fecRequired: bool
	:param data: data collected during the inquiry scan
	:type data: bytes

	'''
	def __init__(self, fecRequired = False, data=b''):
		super().__init__()
		self.fecRequired = fecRequired
		self.data = data
		self.name = "Bluetooth - Write Extended Inquiry Response"

class BluetoothConnect(BluetoothPacket):
	'''
	Mirage Bluetooth Packet - Bluetooth Connect

	:param address: string indicating the target BD address (format : "XX:XX:XX:XX:XX:XX")
	:type address: str
	:param packetType: integer indicating the type of packets
	:type packetType: int
	:param pageScanRepetitionMode: string indicating the page Scan Repetition mode ("R0","R1" or "R2")
	:type pageScanRepetitionMode: str
	:param clockOffset: integer indicating the clock offset
	:type clockOffset: int
	:param allowRoleSwitch: string indicating if a role switch is allowed during the connection ("allowed", "disallowed")
	:type allowRoleSwitch: str
	'''
	def __init__(self, address='', packetType=0xcc18, pageScanRepetitionMode = "R1", clockOffset = 0, allowRoleSwitch = "allowed"):
		super().__init__()
		self.address = address
		self.packetType = packetType
		self.pageScanRepetitionMode = pageScanRepetitionMode
		self.clockOffset = clockOffset
		self.allowRoleSwitch = allowRoleSwitch
		self.name = "Bluetooth - Connect Packet"

	def toString(self):
		return "<< "+self.name +" | address="+self.address+" | packetType="+hex(self.packetType)+" >>"

class BluetoothConnectionRequest(BluetoothPacket):
	'''
	Mirage Bluetooth Packet - Bluetooth Connection Request

	:param address: string indicating the target BD address (format : "XX:XX:XX:XX:XX:XX")
	:type address: str
	:param classOfDevice: integer indicating the class of device
	:type classOfDevice: int
	'''
	def __init__(self, address='', classOfDevice=0x000000):
		super().__init__()
		self.address = address
		self.classOfDevice = classOfDevice
		self.name = "Bluetooth - Connection Request Packet"

	def toString(self):
		return "<< "+self.name +" | address="+self.address+" | classOfDevice="+hex(self.classOfDevice)+" >>"

class BluetoothAcceptConnectionRequest(BluetoothPacket):
	'''
	Mirage Bluetooth Packet - Bluetooth Accept Connection Request

	:param address: string indicating the target BD address (format : "XX:XX:XX:XX:XX:XX")
	:type address: str
	:param role: string indicating the role of device ("master","slave")
	:type role: str
	'''
	def __init__(self, address='', role="slave"):
		super().__init__()
		self.address = address
		self.role = role
		self.name = "Bluetooth - Accept Connection Request Packet"

	def toString(self):
		return "<< "+self.name +" | address="+self.address+" | role="+self.role+" >>"

class BluetoothRejectConnectionRequest(BluetoothPacket):
	'''
	Mirage Bluetooth Packet - Bluetooth Reject Connection Request

	:param address: string indicating the target BD address (format : "XX:XX:XX:XX:XX:XX")
	:type address: str
	:param reason: error code (integer) indicating the reason of failure
	:type reason: int
	'''
	def __init__(self, address='', reason=0x00):
		super().__init__()
		self.address = address
		self.reason = reason
		self.name = "Bluetooth - Reject Connection Request Packet"

	def toString(self):
		return "<< "+self.name +" | address="+self.address+" | reason="+hex(self.reason)+" >>"

class BluetoothConnectResponse(BluetoothPacket):
	'''
	Mirage Bluetooth Packet - Bluetooth Connect Response

	:param dstMac: string indicating the destination BD address (format : "XX:XX:XX:XX:XX:XX")
	:type dstMac: str
	:param srcMac: string indicating the source BD address (format : "XX:XX:XX:XX:XX:XX")
	:type srcMac: str
	:param success: boolean indicating if the connection is successful
	:type success: bool
	:param linkType: integer indicating the link type (0x01 : ACL connection)
	:type linkType: int
	:param encryptionMode: boolean indicating if the encryption is enabled
	:type encryptionMode: bool
	'''
	def __init__(self, dstMac='00:00:00:00:00:00', srcMac='00:00:00:00:00:00',success=True,linkType=0,encryptionMode=False):
		super().__init__()
		self.dstMac = dstMac
		self.srcMac = srcMac
		self.success = success
		self.linkType = linkType
		self.encryptionMode = encryptionMode
		self.name = "Bluetooth - Connect Response Packet"

	def toString(self):
		return "<< "+self.name +" | success="+("OK" if self.success else "NOK")+" | linkType="+("ACL Connection" if self.linkType==0x01 else "???")+" | encryption="+("enabled" if self.encryptionMode else "disabled")+" >>"

class BluetoothWriteScanEnable(BluetoothPacket):
	'''
	Mirage Bluetooth Packet - Write Scan Enable

	:param discoverable: boolean indicating if the device is discoverable
	:type discoverable: bool
	:param connectable: boolean indicating if the device is connectable
	:type connectable: bool
	:param scanEnable: boolean indicating if the scan is enabled
	:type scanEnable: bool
	'''
	def __init__(self,discoverable=False,connectable=False,scanEnable = None):
		super().__init__()
		self.discoverable=discoverable
		self.connectable=connectable
		self.scanEnable = scanEnable
		self.name = "Bluetooth - Write Scan Enable Packet"

	def toString(self):
		return "<< "+self.name +" | discoverable="+("yes" if self.discoverable else "no")+" | connectable="+("yes" if self.connectable else "no")+" >>"

class BluetoothMaxSlotChange(BluetoothPacket):
	'''
	Mirage Bluetooth Packet - Max Slot Change

	:param maxNumberOfSlots: integer indicating the maximum number of slots
	:type maxNumberOfSlots: int
	'''
	def __init__(self,maxNumberOfSlots=0):
		super().__init__()
		self.maxNumberOfSlots = maxNumberOfSlots
		self.name = "Bluetooth - Max Slot Change Packet"

	def toString(self):
		return "<< "+self.name+" | maxNumberOfSlots="+str(self.maxNumberOfSlots)+" >>"

class BluetoothRemoteNameRequest(BluetoothPacket):
	'''
	Mirage Bluetooth Packet - Remote Name Request

	:param address: string indicating the target BD address (format : "XX:XX:XX:XX:XX:XX")
	:type address: str
	:param pageScanRepetitionMode: string indicating the page Scan Repetition mode ("R0","R1" or "R2")
	:type pageScanRepetitionMode: str
	'''
	def __init__(self,pageScanRepetitionMode = "R2",address='00:00:00:00:00:00'):
		super().__init__()
		self.pageScanRepetitionMode = pageScanRepetitionMode
		self.address = address
		self.name = "Bluetooth - Remote Name Request Packet"
	def toString(self):
		return "<< "+self.name +" | pageScanRepetitionMode="+(self.pageScanRepetitionMode)+" | address="+(self.address)+" >>"


class BluetoothRemoteNameResponse(BluetoothPacket):
	'''
	Mirage Bluetooth Packet - Remote Name Response

	:param remoteName: string indicating the remote name of the device
	:type remoteName: str
	:param success: boolean indicating if the remote name request was successful
	:type success: bool
	:param address: string indicating the target BD address (format : "XX:XX:XX:XX:XX:XX")
	:type address: str
	'''
	def __init__(self,remoteName="",success=False,address='00:00:00:00:00:00'):
		super().__init__()
		self.remoteName = remoteName
		self.success = success
		self.address = address
		self.name = "Bluetooth - Remote Name Response Packet"
	def toString(self):
		return "<< "+self.name +" | success="+("yes" if self.success else "no")+" | address="+(self.address)+" | remoteName="+self.remoteName+" >>"

class BluetoothInquiry(BluetoothPacket):
	'''
	Mirage Bluetooth Packet - Inquiry

	:param lap: integer indicating the lap
	:type lap: int
	:param inquiryLength: integer indicating the inquiry length
	:type inquiryLength: int
	:param numResponses: integer indicating the number of responses
	:type numResponses: int
	'''
	def __init__(self,lap=0x338b9e,inquiryLength=5,numResponses=0):
		super().__init__()
		self.lap = lap
		self.inquiryLength = inquiryLength
		self.numResponses = numResponses

		self.name = "Bluetooth - Inquiry Packet"

	def toString(self):
		return "<< "+self.name +" | lap="+hex(self.lap)+" | inquiryLength="+str(self.inquiryLength)+" | numResponses="+str(self.numResponses)+" >>"


class BluetoothInquiryScanResult(BluetoothPacket):
	'''
	Mirage Bluetooth Packet - Inquiry Scan Result

	:param address: string indicating the target BD address (format : "XX:XX:XX:XX:XX:XX")
	:type address: str
	:param numResponses: integer indicating the number of responses
	:type numResponses: int
	:param classOfDevice: integer indicating the class of device
	:type classOfDevice: int
	:param rssi: integer indicating the Received Signal Strength Indication
	:type rssi: int
	:param data: array of bytes indicating the data attached to this scan result
	:type data: bytes
	'''
	def __init__(self,address="",numResponses=0,classOfDevice=0x000000,rssi=0,data=b""):
		super().__init__()
		self.address = address
		self.numResponses = numResponses
		self.classOfDevice = classOfDevice
		self.rssi = rssi
		self.data = data
		self.name = "Bluetooth - Inquiry Scan Result Packet"

	def getRawDatas(self):
		'''
		This method allows to get raw datas as bytes (not as scapy frame)
		'''
		data = b""
		for i in self.data:
			data += bytes(i)
		return data

	def toString(self):
		return "<< "+self.name +" | address="+self.address+" | classOfDevice="+hex(self.classOfDevice)+" | rssi="+str(self.rssi)+" >>"

class BluetoothInquiryComplete(BluetoothPacket):
	'''
	Mirage Bluetooth Packet - Inquiry Complete

	:param status: integer indicating the status of the inquiry scan
	:type status: int
	'''
	def __init__(self,status=0x00):
		super().__init__()
		self.status = status
		self.name = "Bluetooth - Inquiry Complete Packet"

	def toString(self):
		return "<< "+self.name+" | status="+("success" if self.status == 0x00 else "failure")+" >>"

class BluetoothL2CAPConnectionRequest(BluetoothPacket):
	'''
	Mirage Bluetooth Packet - L2CAP Connection Request

	:param psm: integer indicating the Protocol Service Multiplexer (1 : SDP, 3 : RFCOMM, 4 : telephony control)
	:type psm: int
	:param protocol: string indicating the protocol ("SDP", "RFCOMM", "telephony control")
	:type protocol: str
	:param scid: integer indicating the Source Channel Identifier
	:type scid: int
	:param connectionHandle: integer indicating the connection handle
	:type connectionHandle: int

	.. note::
		This class implements an automatic behaviour in order to select the right protocol :
		  * If PSM is provided, the protocol field is set according to its value
		  * If PSM is not provided, the protocol field is used to choose the protocol and the PSM field is set to the right value
		  * If PSM and protocol are not provided, the SDP protocol is automatically selected
	'''
	def __init__(self,psm=None, protocol=None, scid=0x0040,connectionHandle=-1):
		super().__init__()
		self.connectionHandle = connectionHandle
		if psm is None and protocol is None:
			self.psm,self.protocol = 0x01,"SDP"
		elif psm is None:
			self.protocol = protocol
			for key,value in PSM_PROTOCOLS.items():
				if value == self.protocol:
					self.psm = key
		elif protocol is None:
			self.psm = psm
			self.protocol = PSM_PROTOCOLS[self.psm]
		self.scid = scid
		self.name = "Bluetooth - L2CAP Connection Request Packet"

	def toString(self):
		return "<< "+self.name+" | PSM="+hex(self.psm)+" ("+self.protocol+") | SCid="+hex(self.scid)+" >>"

class BluetoothL2CAPConnectionResponse(BluetoothPacket):
	'''
	Mirage Bluetooth Packet - L2CAP Connection Response

	:param result: integer indicating the result of the response (0 : success)
	:type result: int
	:param dcid: integer indicating the Destination Channel Identifier
	:type dcid: str
	:param scid: integer indicating the Source Channel Identifier
	:type scid: int
	:param connectionHandle: integer indicating the connection handle
	:type connectionHandle: int

	'''
	def __init__(self,result=0,status=0,dcid=0x0040, scid=0x0040,connectionHandle=-1):
		super().__init__()
		self.result = result
		self.status = status
		self.dcid = dcid
		self.scid = scid
		self.connectionHandle = connectionHandle
		self.name = "Bluetooth - L2CAP Connection Response Packet"

	def toString(self):
		return "<< "+self.name+" | DCid="+hex(self.dcid)+" | SCid="+hex(self.scid)+" | status="+ ("success" if self.result == 0 else ("fail ("+hex(self.result)+")")) +" >>"

class BluetoothL2CAPInformationRequest(BluetoothPacket):
	'''
	Mirage Bluetooth Packet - L2CAP Information Request

	:param type: integer indicating the type of information request (1: CL_MTU,  2: FEAT_MASK)
	:type type: int
	:param data: array of bytes indicating the data included in the request
	:type data: bytes
	:param connectionHandle: integer indicating the connection handle
	:type connectionHandle: int

	'''
	def __init__(self,type=0,data=b"",connectionHandle=-1):
		super().__init__()
		self.type = type
		self.data = data
		self.connectionHandle = connectionHandle
		self.name = "Bluetooth - L2CAP Information Request Packet"

	def toString(self):
		return "<< "+self.name+" | type="+("CL_MTU" if self.type == 1 else "FEAT_MASK")+"("+hex(self.type)+") | data="+self.data.hex()+" >>"

class BluetoothL2CAPInformationResponse(BluetoothPacket):
	'''
	Mirage Bluetooth Packet - L2CAP Information Response

	:param type: integer indicating the type of information response (1: CL_MTU,  2: FEAT_MASK)
	:type type: int
	:param result: integer indicating the result of the response (0 : success)
	:type result: int
	:param data: array of bytes indicating the data included in the response
	:type data: bytes
	:param connectionHandle: integer indicating the connection handle
	:type connectionHandle: int

	'''
	def __init__(self,type=0,result=0,data=b"",connectionHandle=-1):
		super().__init__()
		self.type = type
		self.result = result
		self.data = data
		self.connectionHandle = connectionHandle
		self.name = "Bluetooth - L2CAP Information Response Packet"

	def toString(self):
		return "<< "+self.name+" | type="+("CL_MTU" if self.type == 1 else "FEAT_MASK")+"("+hex(self.type)+") | data="+self.data.hex()+" | result="+("success" if self.result==0 else "not supported")+" >>"

class BluetoothL2CAPConfigurationRequest(BluetoothPacket):
	'''
	Mirage Bluetooth Packet - L2CAP Configuration Request

	:param dcid: integer indicating the Destination Channel Identifier
	:type dcid: str
	:param flags: integer indicating the flags
	:type flags: int
	:param data: array of bytes indicating the data included in the request
	:type data: bytes
	:param connectionHandle: integer indicating the connection handle
	:type connectionHandle: int

	'''
	def __init__(self,dcid=0x0040,flags=0,data='',connectionHandle=-1):
		super().__init__()
		self.dcid = dcid
		self.flags = flags
		self.data = data
		self.connectionHandle = connectionHandle
		self.name = "Bluetooth - L2CAP Configuration Request Packet"
	def toString(self):
		return "<< "+self.name+" | DCid="+hex(self.dcid)+" | flags="+str(self.flags)+" >>"

class BluetoothL2CAPConfigurationResponse(BluetoothPacket):
	'''
	Mirage Bluetooth Packet - L2CAP Configuration Response

	:param scid: integer indicating the Source Channel Identifier
	:type scid: str
	:param flags: integer indicating the flags
	:type flags: int
	:param data: array of bytes indicating the data included in the request
	:type data: bytes
	:param result: integer indicating the result of the response (0 : success)
	:type result: int
	:param connectionHandle: integer indicating the connection handle
	:type connectionHandle: int

	'''
	def __init__(self,scid=0x0040,flags=0,result=0,data='',connectionHandle=-1):
		super().__init__()
		self.scid = scid
		self.flags = flags
		self.data = data
		self.result = result
		self.connectionHandle = connectionHandle
		self.name = "Bluetooth - L2CAP Configuration Response Packet"
	def toString(self):
		return "<< "+self.name+" | SCid="+hex(self.scid)+" | flags="+str(self.flags)+" | result="+("success" if self.result == 0 else "fail")+" >>"


