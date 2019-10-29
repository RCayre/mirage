from mirage.libs import wireless,utils
from mirage.libs.zigbee_utils import helpers

class ZigbeeSniffingParameters(wireless.AdditionalInformations):
	'''
	This class allows to attach some sniffer's data to a Mirage Zigbee Packet, such as RSSI, valid CRC,link quality indicator or channel.
	If the frequency is provided, the corresponding channel is automatically calculated. 

	:param rssi: Received Signal Strength Indication
	:type rssi: float
	:param channel: channel of the received packet
	:type channel: int
	:param frequency: frequency of the received packet
	:type frequency: float
	:param validCrc: boolean indicating if the CRC is valid or not
	:type validCrc: bool
	:param linkQualityIndicator: integer indicating the link quality indicator
	:type linkQualityIndicator: int

	'''
	def __init__(self, rssi=None,channel=None, frequency=None,validCrc = False,linkQualityIndicator = None):

		self.rssi = rssi
		if frequency is not None:
			self.channel = helpers.frequencyToChannel(frequency)
		elif channel is not None:
			self.channel = int(channel)
		else:
			self.channel = 11

		self.validCrc = validCrc
		self.linkQualityIndicator = linkQualityIndicator

	def toString(self):
		return "CH:" + str(self.channel)+"|RSSI:"+str(self.rssi)+"dBm"+"|LKI:"+str(self.linkQualityIndicator)+"/255"+"|CRC:"+("OK" if self.validCrc else "NOK")


class ZigbeePacket(wireless.Packet):
	'''
	Mirage Zigbee Packet

	:param sequenceNumber: sequence number of the packet
	:type sequenceNumber: int
	:param data: data associated to the Packet
	:type data: bytes

	'''
	def __init__(self, sequenceNumber = 1, data = b""):
		super().__init__()
		self.name = "Zigbee - Unknown Packet"
		self.data = data
		self.sequenceNumber = sequenceNumber

	def toString(self):
		return "<< "+self.name +" | sequenceNumber="+str(self.sequenceNumber)+" | data="+self.data.hex()+" >>"


class ZigbeeBeacon(ZigbeePacket):
	'''
	Mirage Zigbee Packet - Beacon

	:param sequenceNumber: sequence number of the packet
	:type sequenceNumber: int
	:param srcAddr: source address included in the Packet
	:type srcAddr: int
	:param srcPanID: source PanID included in the Packet
	:type srcPanID: int
	:param assocPermit: boolean indicating if the association is permitted
	:type assocPermit: bool
	:param coordinator: boolean indicating if the emitter of the beacon is a coordinator
	:type coordinator: bool
	:param payload: boolean indicating if the packet includes a zigbee payload
	:type payload: bool
	:param routerCapacity: boolean indicating the router capacity
	:type routerCapacity: bool
	:param endDeviceCapacity: boolean indicating the end device capacity
	:type endDeviceCapacity: bool
	:param extendedPanID: extended Pan ID
	:type extendedPanID: int

	'''
	def __init__(self,sequenceNumber = 1, srcAddr=0x0,srcPanID=0xFFFF,assocPermit=False,coordinator=False,payload=False,routerCapacity=None,endDeviceCapacity=None,extendedPanID=None):
		super().__init__(sequenceNumber=sequenceNumber)
		self.name = "Zigbee - Beacon Packet"
		self.srcAddr=helpers.convertAddress(srcAddr)
		self.srcPanID = srcPanID
		self.assocPermit = assocPermit
		self.coordinator = coordinator
		self.payload = payload
		self.routerCapacity = routerCapacity
		self.endDeviceCapacity = endDeviceCapacity
		self.extendedPanID = extendedPanID
		
	def toString(self):
		return "<< "+self.name +" | srcAddr = "+helpers.addressToString(self.srcAddr)+" | srcPanID = "+hex(self.srcPanID)+" | assocPermit = "+("yes" if self.assocPermit else "no")+" | coordinator = "+("yes" if self.coordinator else "no")+(
			"" if not self.payload else 
			" | routerCapacity = "+("yes" if self.routerCapacity else "no")+" | endDeviceCapacity = "+("yes" if self.endDeviceCapacity else "no")+" | extendedPanID = "+hex(self.extendedPanID)
			)+" >>"
	
class ZigbeeBeaconRequest(ZigbeePacket):
	'''
	Mirage Zigbee Packet - Beacon Request

	:param sequenceNumber: sequence number of the packet
	:type sequenceNumber: int
	:param destAddr: destination address included in the Packet
	:type destAddr: int
	:param destPanID: destination PanID included in the Packet
	:type destPanID: int

	'''
	def __init__(self, sequenceNumber = 1, destAddr = 0xFFFF, destPanID = 0xFFFF):
		super().__init__(sequenceNumber = sequenceNumber)
		self.name = "Zigbee - Beacon Request Packet"
		self.destAddr = helpers.convertAddress(destAddr)
		self.destPanID = destPanID


	def toString(self):
		return "<< "+self.name +" | destAddr = "+helpers.addressToString(self.destAddr)+" | destPanID = "+hex(self.destPanID)+" >>"


class ZigbeeAssociationRequest(ZigbeePacket):
	'''
	Mirage Zigbee Packet - Association Request

	:param sequenceNumber: sequence number of the packet
	:type sequenceNumber: int
	:param destAddr: destination address included in the Packet
	:type destAddr: int
	:param destPanID: destination PanID included in the Packet
	:type destPanID: int
	:param srcAddr: source address included in the Packet
	:type srcAddr: int
	:param srcPanID: source PanID included in the Packet
	:type srcPanID: int
	:param allocateAddress: boolean indicating if an address allocation is required
	:type allocateAddress: bool
	:param securityCapability: boolean indicating if the device has a security capability
	:type securityCapability: bool
	:param receiverOnWhenIdle: boolean indicating if the receiver is on when the device is in idle mode
	:type receiverOnWhenIdle: bool
	:param powerSource: boolean indicating if the device has a power source
	:type powerSource: bool
	:param deviceType: boolean indicating the device type
	:type deviceType: bool
	:param alternatePanCoordinator: boolean indicating if the emitter is an alternate PAN coordinator
	:type alternatePanCoordinator: bool

	'''
	def __init__(self,sequenceNumber=1,destAddr=0xFFFF,destPanID=0xFFFF,srcAddr=0x0,srcPanID=0xFFFF,allocateAddress=False,securityCapability=False,receiverOnWhenIdle=False,powerSource=False,deviceType=False,alternatePanCoordinator=False):
		super().__init__(sequenceNumber=sequenceNumber)
		self.name = "Zigbee - Association Request Packet"
		self.srcAddr=helpers.convertAddress(srcAddr)
		self.destAddr=helpers.convertAddress(destAddr)
		self.destPanID=destPanID
		self.srcPanID=srcPanID
		self.allocateAddress = allocateAddress
		self.securityCapability = securityCapability
		self.receiverOnWhenIdle = receiverOnWhenIdle
		self.powerSource = powerSource
		self.deviceType = deviceType
		self.alternatePanCoordinator = alternatePanCoordinator

	def toString(self):
		return "<< "+self.name +" | srcAddr = "+helpers.addressToString(self.srcAddr)+" | destAddr = "+helpers.addressToString(self.destAddr)+" | srcPanID = "+hex(self.srcPanID)+" | destPanID = "+hex(self.destPanID)+(
		" | allocateAddress = "+("yes" if self.allocateAddress else "no") +
		" | securityCapability = "+("yes" if self.securityCapability else "no") +
		" | receiverOnWhenIdle = "+("yes" if self.receiverOnWhenIdle else "no") +
		" | powerSource = "+("yes" if self.powerSource else "no") +
		" | deviceType = "+("yes" if self.deviceType else "no") +
		" | alternatePanCoordinator = "+("yes" if self.alternatePanCoordinator else "no")
		)+" >>"


class ZigbeeDisassociationNotification(ZigbeePacket):
	'''
	Mirage Zigbee Packet - Disassociation Notification

	:param sequenceNumber: sequence number of the packet
	:type sequenceNumber: int
	:param destAddr: destination address included in the Packet
	:type destAddr: int
	:param destPanID: destination PanID included in the Packet
	:type destPanID: int
	:param srcAddr: source address included in the Packet
	:type srcAddr: int
	:param srcPanID: source PanID included in the Packet
	:type srcPanID: int
	:param assignedAddr: assigned address
	:type assignedAddr: int
	:param reason: integer indicating the disassociation reason (1: Coordinator requests device to leave, 2: Device requests to leave)
	:type reason: int

	'''
	reasonMessage = ["reserved","Coordinator requests device to leave","Device requests to leave"]
	def __init__(self,sequenceNumber=1,destAddr=0xFFFF,destPanID=0xFFFF,srcAddr=0x0,srcPanID=0x1234,assignedAddr=0xFFFF,reason=None):
		super().__init__(sequenceNumber=sequenceNumber)
		self.name = "Zigbee - Disassociation Notification Packet"
		self.srcAddr=helpers.convertAddress(srcAddr)
		self.destAddr=helpers.convertAddress(destAddr)
		self.srcPanID=srcPanID
		self.destPanID=destPanID
		self.reason=reason


	def toString(self):
		return "<< "+self.name +" | srcAddr = "+helpers.addressToString(self.srcAddr)+" | srcPanID = "+hex(self.srcPanID)+" | destAddr = "+helpers.addressToString(self.destAddr)+" | destPanID = "+hex(self.destPanID)+" | reason = "+(hex(self.reason) if self.reason >= len(ZigbeeDisassociationNotification.reasonMessage) else ZigbeeDisassociationNotification.reasonMessage[self.reason])+" >>"

class ZigbeeAssociationResponse(ZigbeePacket):
	'''
	Mirage Zigbee Packet - Association Response

	:param sequenceNumber: sequence number of the packet
	:type sequenceNumber: int
	:param destAddr: destination address included in the Packet
	:type destAddr: int
	:param destPanID: destination PanID included in the Packet
	:type destPanID: int
	:param srcAddr: source address included in the Packet
	:type srcAddr: int
	:param srcPanID: source PanID included in the Packet
	:type srcPanID: int
	:param assignedAddr: assigned address
	:type assignedAddr: int
	:param status: integer indicating the status of association (0: successful, 1: PAN at capacity, 2: PAN access denied)
	:type status: int

	'''
	statusMessage = ["successful","PAN at capacity","PAN access denied"]
	def __init__(self,sequenceNumber=1,destAddr=0xFFFF,destPanID=0xFFFF,srcAddr=0x0,srcPanID=0x1234,assignedAddr=0xFFFF,status=None):
		super().__init__(sequenceNumber=sequenceNumber)
		self.name = "Zigbee - Association Response Packet"
		self.srcAddr=helpers.convertAddress(srcAddr)
		self.destAddr=helpers.convertAddress(destAddr)
		self.destPanID=destPanID
		self.assignedAddr=assignedAddr
		self.status=status


	def toString(self):
		return "<< "+self.name +" | srcAddr = "+helpers.addressToString(self.srcAddr)+" | destAddr = "+helpers.addressToString(self.destAddr)+" | destPanID = "+hex(self.destPanID)+" | assignedAddr = "+(hex(self.assignedAddr) if self.assignedAddr != 0xFFFF else "none")+" | status = "+(hex(self.status) if self.status >= len(ZigbeeAssociationResponse.statusMessage) else ZigbeeAssociationResponse.statusMessage[self.status])+" >>"

class ZigbeeDataRequest(ZigbeePacket):
	'''
	Mirage Zigbee Packet - Data Request

	:param sequenceNumber: sequence number of the packet
	:type sequenceNumber: int
	:param destAddr: destination address included in the Packet
	:type destAddr: int
	:param destPanID: destination PanID included in the Packet
	:type destPanID: int
	:param srcAddr: source address included in the Packet
	:type srcAddr: int
	:param srcPanID: source PanID included in the Packet
	:type srcPanID: int

	'''
	def __init__(self,sequenceNumber=1,destAddr=0xFFFF,srcAddr=0x0,destPanID=0x1234,srcPanID=0x0):
		super().__init__(sequenceNumber=sequenceNumber)
		self.name = "Zigbee - Data Request Packet"
		self.srcAddr=helpers.convertAddress(srcAddr)
		self.destAddr=helpers.convertAddress(destAddr)
		self.destPanID=destPanID
		self.srcPanID=srcPanID

	def toString(self):
		return "<< "+self.name +" | srcAddr = "+helpers.addressToString(self.srcAddr)+" | srcPanID = "+hex(self.srcPanID)+" | destPanID = "+hex(self.destPanID)+" | destAddr = "+helpers.addressToString(self.destAddr)+" >>"

class ZigbeeAcknowledgment(ZigbeePacket):
	'''
	Mirage Zigbee Packet - Acknowledgment

	:param sequenceNumber: sequence number of the packet
	:type sequenceNumber: int
	:param destAddr: destination address included in the Packet
	:type destAddr: int
	:param destPanID: destination PanID included in the Packet
	:type destPanID: int
	:param srcAddr: source address included in the Packet
	:type srcAddr: int
	:param srcPanID: source PanID included in the Packet
	:type srcPanID: int

	'''
	def __init__(self,sequenceNumber=1,destAddr=0xFFFF,destPanID=0xFFFF,srcAddr=0x0,srcPanID=0x1234):
		super().__init__(sequenceNumber=sequenceNumber)
		self.name = "Zigbee - Acknowledgment Packet"

	def toString(self):
		return "<< "+self.name +" >>"


class ZigbeeXBeeData(ZigbeePacket):
	'''
	Mirage Zigbee Packet - XBee Data

	:param sequenceNumber: sequence number of the packet
	:type sequenceNumber: int
	:param destAddr: destination address included in the Packet
	:type destAddr: int
	:param destPanID: destination PanID included in the Packet
	:type destPanID: int
	:param srcAddr: source address included in the Packet
	:type srcAddr: int
	:param srcPanID: source PanID included in the Packet
	:type srcPanID: int
	:param counter: XBee counter
	:type counter: int
	:param unknown: XBee unknown field
	:type unknown: int
	:param data: XBee data
	:type data: bytes

	'''
	def __init__(self,sequenceNumber=1,destAddr=0xFFFF,destPanID=0xFFFF,srcAddr=0x0,srcPanID=0x1234,counter=0,unknown=0,data=b""):
		super().__init__(sequenceNumber=sequenceNumber)
		self.name = "Zigbee - XBee Data Packet"
		self.srcAddr=helpers.convertAddress(srcAddr)
		self.destAddr=helpers.convertAddress(destAddr)
		self.destPanID=destPanID
		self.counter = counter
		self.unknown = unknown
		self.data = data

	def toString(self):
		return "<< "+self.name +" | srcAddr = "+helpers.addressToString(self.srcAddr)+" | destAddr = "+helpers.addressToString(self.destAddr)+" | destPanID = "+hex(self.destPanID)+" | counter = "+str(self.counter)+" | unknown = "+str(self.unknown)+" | data = "+self.data.hex()+(" ('"+self.data.decode('utf-8').replace("\r\n","\\r\\n")+"')" if utils.isPrintable(self.data) else "")+" >>"


class ZigbeeApplicationData(ZigbeePacket):
	'''
	Mirage Zigbee Packet - Application Data

	:param sequenceNumber: sequence number of the packet
	:type sequenceNumber: int
	:param destAddr: destination address included in the Packet
	:type destAddr: int
	:param destPanID: destination PanID included in the Packet
	:type destPanID: int
	:param srcAddr: source address included in the Packet
	:type srcAddr: int
	:param srcPanID: source PanID included in the Packet
	:type srcPanID: int
	:param data: application data included in the Packet
	:type data: bytes

	'''
	def __init__(self,sequenceNumber=1,destAddr=0xFFFF,destPanID=0xFFFF,srcAddr=0x0,srcPanID=0x1234,data=b""):
		super().__init__(sequenceNumber=sequenceNumber)
		self.name = "Zigbee - Application Data Packet"
		self.srcAddr=helpers.convertAddress(srcAddr)
		self.destAddr=helpers.convertAddress(destAddr)
		self.destPanID=destPanID
		self.data = data

	def toString(self):
		return "<< "+self.name +" | srcAddr = "+helpers.addressToString(self.srcAddr)+" | destAddr = "+helpers.addressToString(self.destAddr)+" | destPanID = "+hex(self.destPanID)+" | data = "+self.data.hex()+" >>"



class ZigbeeApplicationEncryptedData(ZigbeePacket):
	'''
	Mirage Zigbee Packet - Application Encrypted Data

	:param sequenceNumber: sequence number of the packet
	:type sequenceNumber: int
	:param destAddr: destination address included in the Packet
	:type destAddr: int
	:param destPanID: destination PanID included in the Packet
	:type destPanID: int
	:param srcAddr: source address included in the Packet
	:type srcAddr: int
	:param frameCounter: frame counter
	:type frameCounter: int
	:param keyType: field indicating the key type (0: Data Key, 1: Network Key, 2: Key Transport Key, 3: Key load Key)
	:type keyType: int
	:param securityLevel: field indicating the security level (0: none, 1: MIC-32, 2: MIC-64, 3: MIC-128, 4: ENC, 5: ENC-MIC-32, 6: ENC-MIC-64, 7: ENC-MIC-128)
	:type securityLevel: int
	:param source: source address
	:type source: int
	:param keySequenceNumber: sequence number associated to the key
	:type keySequenceNumber: int
	:param data: application data included in the Packet (encrypted)
	:type data: bytes
	:param mic: message integrity check
	:type mic: bytes

	'''
	keyTypes = ["Data Key", "Network Key", "Key transport Key", "Key load Key"]
	securityLevels = ["none", "MIC-32","MIC-64","MIC-128","ENC","ENC-MIC-32","ENC-MIC-64","ENC-MIC-128"]

	def __init__(self,sequenceNumber=1,destAddr=0xFFFF,destPanID=0xFFFF,srcAddr=0x0,frameCounter=0,keyType=None,securityLevel=None,source=None, keySequenceNumber=None,data=b"",mic=b""):
		super().__init__(sequenceNumber=sequenceNumber)
		self.name = "Zigbee - Application Encrypted Data Packet"
		self.srcAddr=helpers.convertAddress(srcAddr)
		self.destAddr=helpers.convertAddress(destAddr)
		self.destPanID=destPanID
		self.frameCounter = frameCounter
		self.keyType = ZigbeeApplicationEncryptedData.keyTypes.index(keyType) if keyType in ZigbeeApplicationEncryptedData.keyTypes else keyType
		self.securityLevel = ZigbeeApplicationEncryptedData.securityLevels.index(securityLevel) if securityLevel in ZigbeeApplicationEncryptedData.securityLevels else securityLevel
		self.source=helpers.convertAddress(source)
		self.keySequenceNumber = keySequenceNumber
		self.data = data
		self.mic = mic

	def toString(self):
		return "<< "+self.name +" | srcAddr = "+helpers.addressToString(self.srcAddr)+" | destAddr = "+helpers.addressToString(self.destAddr)+" | destPanID = "+hex(self.destPanID)+" | data = "+self.data.hex()+(
		" | frameCounter = "+str(self.frameCounter) + 
		" | keyType = "+(ZigbeeApplicationEncryptedData.keyTypes[self.keyType] if self.keyType is not None and self.keyType < len(ZigbeeApplicationEncryptedData.keyTypes) else str(self.keyType)+"(unknown)") +
		" | securityLevel = "+(ZigbeeApplicationEncryptedData.securityLevels[self.securityLevel] if self.securityLevel is not None and self.securityLevel < len(ZigbeeApplicationEncryptedData.securityLevels) else str(self.securityLevel)+"(unknown)") +
		(" | source = "+self.source if self.source is not None else "") + 
		(" | keySequenceNumber = "+str(self.keySequenceNumber) if self.keySequenceNumber is not None else "") + 
		(" | mic = "+self.mic.hex() if self.mic != b"" else "")
		)+" >>"


