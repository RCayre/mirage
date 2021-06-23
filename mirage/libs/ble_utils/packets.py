from mirage.libs.ble_utils import helpers
from mirage.libs import wireless
from scapy.all import *
import struct

class BLESniffingParameters(wireless.AdditionalInformations):
	'''
	This class allows to attach some sniffer's data to a Mirage BLE Packet, such as RSSI or channel.
	If the frequency is provided, the corresponding channel is automatically calculated. 

	:param rssi: Received Signal Strength Indication
	:type rssi: float
	:param rssi_min: Received Signal Strength Indication (min. value)
	:type rssi_min: float
	:param rssi_max: Received Signal Strength Indication (max. value)
	:type rssi_max: float
	:param rssi_avg: Received Signal Strength Indication (average value)
	:type rssi_avg: float
	:param clk_high: clock's value (high)
	:type clk_high: float
	:param clk_100ns: clock's value (100ns)
	:type rssi_100ns: float
	:param direction: direction of the packet ("master->slave" or "slave->master")
	:type direction: str
	:param channel: channel of the received packet
	:type channel: int
	:param frequency: frequency of the received packet
	:type frequency: float
	'''
	def __init__(self, rssi=None,rssi_min=0,rssi_max=0,rssi_avg=0,rssi_count=0,clk_100ns=0,clkn_high=0,direction=None,channel=None, frequency=None, rawPacket=None):
		if rssi is None:
			self.rssi_min = rssi_min
			self.rssi_max = rssi_max
			self.rssi_avg = rssi_avg
			self.rssi = helpers.rssiToDbm(self.rssi_max)
		else:
			self.rssi = int(rssi)
			self.rssi_max = self.rssi_min = self.rssi_avg = self.rssi
		self.direction = direction
		if frequency is not None:
			self.channel = int(helpers.frequencyToChannel(2402+frequency))
		elif channel is not None:
			self.channel = int(channel)
		else:
			self.channel = 37
		self.clk_100ns = clk_100ns
		self.clkn_high = clkn_high
		self.rssi_count = rssi_count
		self.clock = clkn_high + (clk_100ns / 1000000)
		self.rawPacket = rawPacket
		
	def toString(self):
		return "CH:" + str(self.channel)+"|CLK:"+str(self.clock)+"|RSSI:"+str(self.rssi)+"dBm"

class BLEPacket(wireless.Packet):
	'''
	Mirage Bluetooth Low Energy Packet
	'''
	def __init__(self):
		super().__init__()
		self.name = "BLE - Unknown Packet"

class BLEControlPDU(BLEPacket):
	'''
	Mirage Bluetooth Low Energy Packet - Control PDU

	:param type: string indicating the type of control PDU ("LL_ENC_REQ", "LL_ENC_RESP" ...)
	:type type: str
	:param data: data associated to the Packet
	:type data: bytes

	'''
	def __init__(self,type=None, data=b""):
		super().__init__()
		self.type = type
		self.data = data
		self.name = "BLE - Control PDU Packet"
	def toString(self):
		return "<< "+self.name +" | type="+self.type+" | data="+self.data.hex()+" >>"

class BLEEncryptedPacket(BLEPacket):
	'''
	Mirage Bluetooth Low Energy Packet - Encrypted Packet
	This class is an abstraction : it provides a way to solve the problems linked to the encryption. 
	In Mirage, an encrypted packet is just another Mirage Packet, allowing to manipulate it easily.

	:param connectionHandle: connection handle of the connection actually established.
	:type connectionHandle: int
	:param data: encrypted datas associated to the Packet
	:type data: bytes

	'''
	def __init__(self,connectionHandle = -1, data=b""):
		super().__init__()
		self.connectionHandle = connectionHandle
		self.data = data
		self.name = "BLE - Encrypted Packet"
	def toString(self):
		return "<< "+self.name +" | data="+self.data.hex()+" >>"


class BLEEmptyPDU(BLEPacket):
	'''
	Mirage Bluetooth Low Energy Packet - Empty PDU
	'''
	def __init__(self):
		super().__init__()
		self.name = "BLE - Empty PDU Packet"

class BLEExchangeMTURequest(BLEPacket):
	'''
	Mirage Bluetooth Low Energy Packet - Exchange MTU Request

	:param mtu:  float indicating the Maximum transmission unit
	:type mtu: float
	:param connectionHandle: connection handle of the connection actually established.
	:type type: int

	'''
	def __init__(self,mtu=0, connectionHandle = -1):
		super().__init__()
		self.mtu = mtu
		self.connectionHandle = connectionHandle
		self.name = "BLE - Exchange MTU Request Packet"

class BLEExchangeMTUResponse(BLEPacket):
	'''
	Mirage Bluetooth Low Energy Packet - Exchange MTU Response

	:param mtu:  float indicating the Maximum transmission unit
	:type mtu: float
	:param connectionHandle: connection handle of the connection actually established.
	:type type: int

	'''
	def __init__(self,mtu=0, connectionHandle=-1):
		super().__init__()
		self.mtu = mtu
		self.connectionHandle = connectionHandle
		self.name = "BLE - Exchange MTU Response Packet"

class BLEConnect(BLEPacket):
	'''
	Mirage Bluetooth Low Energy Packet - Connect

	:param dstAddr: destination BD Address (format: ``1A:22:33:44:55:66``)
	:type dstAddr: str
	:param srcAddr: source BD Address (format: ``1A:22:33:44:55:66``)
	:type srcAddr: str
	:param type: string indicating if the responder's address is in public ("public") or random ("random") mode.
	:type type: str
	:param initiatorType: string indicating if the initiator's address is in public ("public") or random ("random") mode.
	:type initiatorType: str

	'''
	def __init__(self,dstAddr="00:00:00:00:00:00", srcAddr="00:00:00:00:00:00", type="public", initiatorType = "public"):
		super().__init__()
		self.dstAddr = dstAddr.upper()
		self.srcAddr = srcAddr.upper()
		self.type = type
		self.initiatorType = initiatorType
		self.name = "BLE - Connect Packet"

	def toString(self):
		return "<< "+self.name+" | srcAddr="+self.srcAddr+" | dstAddr="+self.dstAddr+" | type="+self.type+" | initiatorType="+self.initiatorType+" >>"

class BLEConnectResponse(BLEPacket):
	'''
	Mirage Bluetooth Low Energy Packet - Connect Response

	:param dstAddr: destination BD Address (format: ``1A:22:33:44:55:66``)
	:type dstAddr: str
	:param srcAddr: source BD Address (format: ``1A:22:33:44:55:66``)
	:type srcAddr: str
	:param type: string indicating if the responder's address is in public ("public") or random ("random") mode.
	:type type: str
	:param success: boolean indicating if the operation was successful
	:type success: bool
	:param role: string indicating the role ("master" or "slave") of the initiator
	:type role: str
	:param interval: integer indicating the interval
	:type interval: int

	'''
	def __init__(self,dstAddr="00:00:00:00:00:00", srcAddr="00:00:00:00:00:00", type="public",success=True, role="", interval=0):
		super().__init__()
		self.dstAddr = dstAddr.upper()
		self.srcAddr = srcAddr.upper()
		self.type = type
		self.success = success
		self.role = role
		self.interval = interval
		self.name = "BLE - Connect Response Packet"

	def toString(self):
		return "<< "+self.name+" | srcAddr="+self.srcAddr+" | dstAddr="+self.dstAddr+" | type="+self.type+" | role="+self.role+" | success="+("OK" if self.success else "NOK")+" >>"

class BLEDisconnect(BLEPacket):
	'''
	Mirage Bluetooth Low Energy Packet - Disconnect

	:param connectionHandle: connection handle associated to the connection to terminate
	:type connectionHandle: int

	'''
	def __init__(self,connectionHandle = -1):
		super().__init__()
		self.connectionHandle = connectionHandle
		self.name = "BLE - Disconnect Packet"

class BLEConnectionCancel(BLEPacket):
	'''
	Mirage Bluetooth Low Energy Packet - Connection Cancel
	'''
	def __init__(self):
		super().__init__()
		self.name = "BLE - Connection Cancel Packet"

class BLEAdvertisement(BLEPacket):
	'''
	Mirage Bluetooth Low Energy Packet - Advertisement
	
	:param addr: BD address of the emitter
	:type addr: str
	:param type: type of Advertisement ("ADV_IND", "ADV_NONCONN_IND" ...)
	:type type: str
	:param addrType: type of BD address used by the emitter ("public" or "random")
	:type addrType: str
	:param data: bytes indicating the data included in the Advertisement packet
	:type data: bytes
	:param intervalMin: minimal interval of advertisement
	:type intervalMin: int
	:param intervalMax: maximal interval of advertisement
	:type intervalMax: int

	.. note ::

		Some other classes inherits from this class, allowing to adapt the content of the Packet.

	'''
	def __init__(self,addr="00:00:00:00:00:00", type="ADV_IND", addrType="public", data=b"", intervalMin=200, intervalMax=210):
		super().__init__()
		self.addr = addr.upper()
		self.type = type
		self.addrType = addrType
		self.data = data
		self.intervalMin = intervalMin
		self.intervalMax = intervalMax
		self.name = "BLE - Advertisement Packet"

	def getRawDatas(self):
		'''
		This method returns the raw data : indeed, some devices provides a scapy representation in the data field, and this method can be used to convert it into a list of bytes.

		:Example:

			>>> device.getRawDatas()
			b'\x01\x02 [...]

		'''
		data = b""
		for i in self.data:
			data += bytes(i)
		return data

	def toString(self):
		return "<< "+self.name+" | type="+self.type+" | addr="+self.addr+" | data="+self.getRawDatas().hex()+" >>"

class BLEAdvInd(BLEAdvertisement):
	'''
	Mirage Bluetooth Low Energy Packet - ADV_IND
	
	:param addr: BD address of the emitter
	:type addr: str
	:param data: bytes indicating the data included in the Advertisement packet
	:type data: bytes

	.. note ::

		This class inherits from BLEAdvertisement.

	'''
	def __init__(self,
				addr="00:00:00:00:00:00",
				addrType="public",
				data=b""):
		super().__init__(addr=addr,addrType=addrType,type="ADV_IND",data=data)

class BLEAdvDirectInd(BLEAdvertisement):
	'''
	Mirage Bluetooth Low Energy Packet - ADV_DIRECT_IND
	
	:param srcAddr: BD address of the emitter
	:type srcAddr: str
	:param dstAddr: BD address of the receiver
	:type dstAddr: str

	.. note ::

		This class inherits from BLEAdvertisement.

	'''
	def __init__(self,
				srcAddr="00:00:00:00:00:00",
				srcAddrType="public",
				dstAddr="00:00:00:00:00:00",
				dstAddrType="public"):
		super().__init__(addr=srcAddr,addrType=srcAddrType,type="ADV_DIRECT_IND")
		self.dstAddr = dstAddr.upper()
		self.srcAddr = srcAddr.upper()
		self.srcAddrType = srcAddrType
		self.dstAddrType = dstAddrType

	def toString(self):
		return "<< "+self.name+" | type="+self.type+" | srcAddr="+self.srcAddr+" | dstAddr="+self.dstAddr+" >>"

class BLEAdvNonConnInd(BLEAdvertisement):
	'''
	Mirage Bluetooth Low Energy Packet - ADV_NONCONN_IND

	.. note ::

		This class inherits from BLEAdvertisement.

	'''
	def __init__(self):
		super().__init__(type="ADV_NONCONN_IND")

	def toString(self):
		return "<< "+self.name+" | type="+self.type+" >>"

class BLEAdvScanInd(BLEAdvertisement):
	'''
	Mirage Bluetooth Low Energy Packet - ADV_SCAN_IND

	.. note ::

		This class inherits from BLEAdvertisement.

	'''
	def __init__(self):
		super().__init__(type="ADV_SCAN_IND")

	def toString(self):
		return "<< "+self.name+" | type="+self.type+" >>"

class BLEScanRequest(BLEAdvertisement):
	'''
	Mirage Bluetooth Low Energy Packet - SCAN_REQ

	:param srcAddr: BD address of the emitter
	:type srcAddr: str
	:param dstAddr: BD address of the receiver
	:type dstAddr: str

	.. note ::

		This class inherits from BLEAdvertisement.

	'''
	def __init__(self,
				srcAddr="00:00:00:00:00:00",
				srcAddrType="public",
				dstAddr="00:00:00:00:00:00",
				dstAddrType="public"):
		super().__init__(addr=srcAddr,addrType=srcAddrType,type="SCAN_REQ")
		self.dstAddr = dstAddr.upper()
		self.srcAddr = srcAddr.upper()
		self.srcAddrType = srcAddrType
		self.dstAddrType = dstAddrType

	def toString(self):
		return "<< "+self.name+" | type="+self.type+" | srcAddr="+self.srcAddr+" | dstAddr="+self.dstAddr+" >>"
	
class BLEScanResponse(BLEAdvertisement):
	'''
	Mirage Bluetooth Low Energy Packet - SCAN_RSP

	:param srcAddr: BD address of the emitter
	:type srcAddr: str
	:param data: bytes indicating the data included in the Advertisement packet
	:type data: bytes

	.. note ::

		This class inherits from BLEAdvertisement.

	'''
	def __init__(self,
				addr="00:00:00:00:00:00",
				addrType="public",
				data=b""):
		super().__init__(addr=addr,addrType=addrType,type="SCAN_RSP",data=data)


class BLEConnectRequest(BLEAdvertisement):
	'''
	Mirage Bluetooth Low Energy Packet - SCAN_RSP

	:param srcAddr: BD address of the emitter
	:type srcAddr: str
	:param dstAddr: BD address of the receiver
	:type dstAddr: str
	:param srcAddrType: type of BD address used by the emitter ("public" or "random")
	:type srcAddrType: str
	:param dstAddrType: type of BD address used by the receiver ("public" or "random")
	:type dstAddrType: str
	:param accessAddress: access address associated to the connection
	:type accessAddress: int
	:param crcInit: CRCInit associated to the connection
	:type crcInit: int
	:param winSize: window's size associated to the connection
	:type winSize: int
	:param winOffset: window's offset associated to the connection
	:type winOffset: int
	:param hopInterval: Hop Interval associated to the connection
	:type hopInterval: int
	:param latency: latency associated to the connection
	:type latency: int
	:param timeout: timeout associated to the connection
	:type timeout: int
	:param channelMap: channel Map associated to the connection
	:type channelMap: int
	:param SCA: SCA associated to the connection
	:type SCA: int
	:param hopIncrement: Hop increment associated to the connection
	:type hopIncrement: int
	:param data: data associated to this advertisement packet
	:type data: bytes


	.. note ::

		This class inherits from BLEAdvertisement.

	'''
	def __init__(self,
				srcAddr="00:00:00:00:00:00",
				dstAddr="00:00:00:00:00:00",
				srcAddrType="public",
				dstAddrType="public",
				accessAddress=0x8e89bed6,
				crcInit=0x000000,
				winSize=0x00,
				winOffset=0x0000,
				hopInterval=0,
				latency=0,
				timeout=0,
				channelMap =0x0000000000,
				SCA=0,
				hopIncrement=0,
				data = None
			):
		super().__init__(addr=dstAddr,type="CONNECT_REQ")
		self.dstAddr = dstAddr.upper()
		self.srcAddr = srcAddr.upper()
		self.srcAddrType = srcAddrType
		self.dstAddrType = dstAddrType
		self.accessAddress = accessAddress
		self.crcInit = crcInit
		self.winSize = winSize
		self.winOffset = winOffset
		self.hopInterval = hopInterval
		self.latency = latency
		self.timeout = timeout
		self.channelMap = channelMap
		self.SCA = SCA
		self.hopIncrement = hopIncrement
		self.data = data

	def toString(self):
		return "<< "+self.name+" | type="+self.type+" | srcAddr="+self.srcAddr+" | dstAddr="+self.dstAddr+" | accessAddress="+"0x{:08x}".format(self.accessAddress)+"| crcInit="+"0x{:03x}".format(self.crcInit)+"| channelMap="+"0x{:10x}".format(self.channelMap)+"| hopInterval="+str(self.hopInterval)+"| hopIncrement="+str(self.hopIncrement)+" >>"	

class BLEFindInformationRequest(BLEPacket):
	'''
	Mirage Bluetooth Low Energy Packet - Find Information Request

	:param startHandle: lowest ATT handle included in the request
	:type startHandle: int
	:param endHandle: highest ATT handle included in the request
	:type endHandle: int
	:param connectionHandle: connection handle associated to the connection
	:type connectionHandle: int

	'''
	def __init__(self, startHandle=0x0000, endHandle=0xFFFF, connectionHandle = -1):
		super().__init__()
		self.startHandle = startHandle
		self.endHandle = endHandle
		self.connectionHandle = connectionHandle
		self.name = "BLE - Find Information Request Packet"

class BLEFindInformationResponse(BLEPacket):
	'''
	Mirage Bluetooth Low Energy Packet - Find Information Response

	:param data: data included in the Information Response
	:type data: bytes
	:param attributes: list indicating the ATT attributes contained in the Information Response
	:type attributes: list of dict
	:param format: integer indicating the format of the response (0x1 : short UUID (16 bits), 0x2 : long UUID (128bits))
	:type format: int
	:param connectionHandle: connection handle associated to the connection
	:type connectionHandle: int

	:Example:
	
		>>> BLEFindInformationResponse(data=bytes.fromhex('0f000229')).attributes
		[{'attributeHandle': 15, 'type': b')\x02'}]
		>>> BLEFindInformationResponse(attributes=[{'attributeHandle': 15, 'type': b')\x02'}]).data.hex()
		'0f000229'

	.. note::
		Please note the following behaviour :
		  * **If only the data is provided**, the attributes list is automatically generated (thanks to the ``decode`` method.) 
		  * **If the attributes are provided**, the corresponding data is automatically generated (thanks to the ``build`` method)

		An attribute is described as a dictionary composed of two fields :
		  * *attributeHandle* : indicating the handle of the corresponding ATT attribute
		  * *type* : indicating the UUID (type of the ATT attribute)

		**Example :** ``{"attributeHandle":0x0001, "type":type}``
	'''
	def __init__(self, format=0, data=b"", attributes = [], connectionHandle = -1):
		super().__init__()
		self.format = format
		self.data = data
		self.attributes = attributes
		if self.attributes == [] and self.data != b"":
			self.decode()
		else:
			self.build()
		self.connectionHandle = connectionHandle
		self.name = "BLE - Find Information Response Packet"

	def build(self):
		'''
		This method generates the data from the attributes list.
		'''
		sizeOfType = len(self.attributes[0]["type"])
		self.format = 0x1 if sizeOfType == 2 else 0x2
		self.data = b""
		for att in self.attributes:
			handle = struct.pack(">H", att["attributeHandle"])[::-1]
			type = att["type"][::-1]
			self.data += handle+type

	def decode(self):
		'''
		This method generates the attributes list from the data.
		'''
		data = self.data
		pairs = []
		sizeOfType = 2 if self.format == 0x1 else 16
		length = 2 + sizeOfType
		pointer = 0
		while pointer < len(data):
			attributeHandle = struct.unpack('>H', data[pointer:pointer+2][::-1])[0]
			type = data[pointer+2:pointer+2+sizeOfType][::-1]
			pairs.append({"attributeHandle":attributeHandle, "type":type})
			pointer += length
		self.attributes = pairs

	def toString(self):
		return "<< "+self.name+" | format="+hex(self.format)+" | data="+self.data.hex()+" >>"

class BLEFindByTypeValueRequest(BLEPacket):
	'''
	Mirage Bluetooth Low Energy Packet - Find By Type Value Request

	:param startHandle: lowest ATT handle included in the request
	:type startHandle: int
	:param endHandle: highest ATT handle included in the request
	:type endHandle: int
	:param uuid: 2 octet UUID to find
	:type uuid: int
	:param data: Attribute value to find
	:type data: bytes
	:param connectionHandle: connection handle associated to the connection
	:type connectionHandle: int

	'''

	def __init__(self, startHandle=0x0000, endHandle=0xFFFF, uuid=0, data=b"", connectionHandle=-1):
		super().__init__()
		self.startHandle = startHandle
		self.endHandle = endHandle
		self.uuid = uuid
		self.data = data
		self.connectionHandle = connectionHandle
		self.name = "BLE - Find Type By Value Request"

class BLEFindByTypeValueResponse(BLEPacket):
	'''
	Mirage Bluetooth Low Energy Packet - Find By Type Value Response

	:param handles: list indicating the handles contained in the Information Response
	:type handles: list
	:param connectionHandle: connection handle associated to the connection
	:type connectionHandle: int

	'''
	def __init__(self, handles=[], connectionHandle = -1):
		super().__init__()
		self.handles = handles
		self.connectionHandle = connectionHandle
		self.name = "BLE - Find By Type Value Response Packet"

class BLEReadByGroupTypeRequest(BLEPacket):
	'''
	Mirage Bluetooth Low Energy Packet - Read By Group Type Request

	:param startHandle: lowest ATT handle included in the request
	:type startHandle: int
	:param endHandle: highest ATT handle included in the request
	:type endHandle: int
	:param uuid: UUID indicating a given type
	:type uuid: int
	:param connectionHandle: connection handle associated to the connection
	:type connectionHandle: int

	'''
	def __init__(self,startHandle=0x0000, endHandle=0xFFFF, uuid=0, connectionHandle = -1):
		super().__init__()
		self.startHandle = startHandle
		self.endHandle = endHandle
		self.uuid = uuid
		self.connectionHandle = connectionHandle
		self.name = "BLE - Read By Group Type Request Packet"

class BLEReadByGroupTypeResponse(BLEPacket):
	'''
	Mirage Bluetooth Low Energy Packet - Read By Group Type Response

	:param data: data included in the Read By Group Type Response
	:type data: bytes
	:param attributes: list indicating the ATT group type of attributes contained in the Read By Group Type Response
	:type attributes: list of dict
	:param length: integer indicating the length (in number of bytes) corresponding to one range of attributes providing the same value
	:type length: int
	:param connectionHandle: connection handle associated to the connection
	:type connectionHandle: int

	:Example:

		>>> BLEReadByGroupTypeResponse(data=bytes.fromhex('01000b0000180c000f00011810001e000a18')).attributes
		[{'attributeHandle': 1, 'endGroupHandle': 11, 'value': b'\x00\x18'}, {'attributeHandle': 12, 'endGroupHandle': 15, 'value': b'\x01\x18'}, {'attributeHandle': 16, 'endGroupHandle': 30, 'value': b'\x01\x18'}]
		>>> BLEReadByGroupTypeResponse(attributes=[{'attributeHandle': 1, 'endGroupHandle': 11, 'value': b'\x00\x18'},{'attributeHandle': 12, 'endGroupHandle': 15, 'value': b'\x01\x18'}, {'attributeHandle': 16, 'endGroupHandle': 30, 'value':b'\\n\x18'}]).data.hex()
		'01000b0000180c000f00011810001e000a18'


	.. note::
		Please note the following behaviour :

		  * **If only the data is provided**, the group type list is automatically generated (thanks to the ``decode`` method.) 
		  * **If the attributes are provided**, the corresponding data is automatically generated (thanks to the ``build`` method)

		A group type of attribute is described as a dictionary composed of three fields :

		  * *attributeHandle* : indicating the lowest handle of the corresponding ATT group type
		  * *value* : indicating the value of the ATT attribute
		  * *endGroupHandle* :  indicating the highest handle of the corresponding ATT group type

		**Example :** ``{'attributeHandle': 1, 'endGroupHandle': 11, 'value': b'\x00\x18'}``
	'''
	def __init__(self, length = 6, data = b"", attributes = [], connectionHandle = -1):
		super().__init__()
		self.length = length
		self.data = data
		self.attributes = attributes
		if self.attributes == [] and self.data != b"":
			self.decode()
		else:
			self.build()
		self.connectionHandle = connectionHandle
		self.name = "BLE - Read By Group Type Response Packet"

	def build(self):
		self.data = b""
		for att in self.attributes:
			attHandle = struct.pack('>H',att["attributeHandle"])[::-1]
			endHandle = struct.pack('>H',att["endGroupHandle"])[::-1]
			value = att["value"]
			length = len(attHandle+endHandle+value)
			self.data += attHandle+endHandle+value
		
		self.length = length

	def decode(self):
		data = self.data
		length = self.length
		pairs = []
		sizeOfValue = length - 4
		pointer = 0

		while pointer < len(data):
			attributeHandle = struct.unpack('>H',data[pointer:pointer+2][::-1])[0]
			endGroupHandle = struct.unpack('>H',data[pointer+2:pointer+4][::-1])[0]
			value = data[pointer+4:pointer+4+sizeOfValue]
			pairs.append({"attributeHandle":attributeHandle, "endGroupHandle":endGroupHandle, "value":value})
			pointer += length
		self.attributes = pairs

	def toString(self):
		return "<< "+self.name+" | length="+str(self.length)+" | data="+self.data.hex()+" >>"

class BLEReadByTypeRequest(BLEPacket):
	'''
	Mirage Bluetooth Low Energy Packet - Read By Type Request

	:param startHandle: lowest ATT handle included in the request
	:type startHandle: int
	:param endHandle: highest ATT handle included in the request
	:type endHandle: int
	:param uuid: UUID indicating a given type
	:type uuid: int
	:param connectionHandle: connection handle associated to the connection
	:type connectionHandle: int

	'''
	def __init__(self,startHandle = 0x0000, endHandle=0xffff, uuid = 0, connectionHandle = -1):
		super().__init__()
		self.startHandle = startHandle
		self.endHandle = endHandle
		self.uuid = uuid
		self.connectionHandle = connectionHandle
		self.name = "BLE - Read By Type Request"

class BLEReadByTypeResponse(BLEPacket):
	'''
	Mirage Bluetooth Low Energy Packet - Read By Type Response

	:param data: data included in the Read By Type Response
	:type data: bytes
	:param attributes: list indicating the attributes contained in the Read By Type Response
	:type attributes: list of dict
	:param connectionHandle: connection handle associated to the connection
	:type connectionHandle: int

	:Example:

		>>> BLEReadByTypeResponse(data=bytes.fromhex("152900102a0018d3dd5ce93dd08951403448f4ffb3a8")).attributes
		[{'attributeHandle': 41, 'value': b'\x10*\x00\x18\xd3\xdd\\\xe9=\xd0\x89Q@4H\xf4\xff\xb3\xa8'}]
		>>> BLEReadByTypeResponse(attributes=[{'attributeHandle': 41, 'value': b'\x10*\x00\x18\xd3\xdd\\\xe9=\xd0\x89Q@4H\xf4\xff\xb3\xa8'}]).data.hex()
		'152900102a0018d3dd5ce93dd08951403448f4ffb3a8'

	.. note::
		Please note the following behaviour :

		  * **If only the data is provided**, the list of attributes is automatically generated (thanks to the ``decode`` method.) 
		  * **If the attributes are provided**, the corresponding data is automatically generated (thanks to the ``build`` method)

		An attribute is described as a dictionary composed of two fields :

		  * *attributeHandle* : indicating the handle of the ATT attribute
		  * *value* : indicating the value of the ATT attribute

		**Example :** ``{'attributeHandle': 1, 'value': b'\x00\x18'}``
	'''
	def __init__(self,  data = b"", attributes = [], connectionHandle = -1):
		super().__init__()
		self.data = data
		self.attributes = attributes
		self.connectionHandle = connectionHandle
		if self.attributes == [] and self.data != b"":
			self.decode()
		else:
			self.build()
		self.name = "BLE - Read By Type Response"

	def build(self):
		self.data = b""
		for att in self.attributes:
			handle = struct.pack(">H", att["attributeHandle"])[::-1]
			value = att["value"]
			length = struct.pack("B", len(handle+value))
			self.data += handle + value
		self.data = length + self.data

	def decode(self):
		data = self.data
		pairs = []
		length = data[0]
		sizeOfValue = length - 2
		pointer = 0
		rawData = data[1:]
		while pointer < len(rawData):
			attributeHandle = struct.unpack(">H", rawData[pointer:pointer+2][::-1])[0]
			value = rawData[pointer+2:pointer+2+sizeOfValue]
			pairs.append({"attributeHandle":attributeHandle, "value":value})
			pointer += length
		self.attributes = pairs

	def toString(self):
		return "<< "+self.name+" | data="+self.data.hex()+" >>"

class BLEErrorResponse(BLEPacket):
	'''
	Mirage Bluetooth Low Energy Packet - Error Request

	:param request: Request opcode
	:type request: int
	:param handle: ATT handle linked to the error
	:type handle: int
	:param ecode: error code
	:type ecode: int
	:param connectionHandle: connection handle associated to the connection
	:type connectionHandle: int

	'''
	def __init__(self, request = 0, handle = 0, ecode = 0, connectionHandle = -1):
		super().__init__()
		self.request = request
		self.handle = handle
		self.ecode = ecode
		self.connectionHandle = connectionHandle
		self.name = "BLE - Error Response Packet"

	def toString(self):
		return "<< "+self.name+" | req="+hex(self.request)+" | handle="+hex(self.handle)+" | ecode="+hex(self.ecode)+" >>"

class BLEWriteRequest(BLEPacket):
	'''
	Mirage Bluetooth Low Energy Packet - Write Request

	:param handle: ATT value handle indicating the attribute to write
	:type handle: int
	:param value: new value to write
	:type value: bytes
	:param connectionHandle: connection handle associated to the connection
	:type connectionHandle: int

	:Example:
		
		>>> emitter.sendp(ble.BLEWriteRequest(handle=0x0021, value=b"\x01\x02\x03"))

	'''
	def __init__(self, handle=0, value=b"", connectionHandle = -1):
		super().__init__()
		self.handle = handle
		self.value = value
		self.connectionHandle = connectionHandle
		self.name = "BLE - Write Request Packet"

	def toString(self):
		return "<< "+self.name+" | handle="+hex(self.handle)+" | value="+self.value.hex()+" >>"

class BLEWriteCommand(BLEPacket):
	'''
	Mirage Bluetooth Low Energy Packet - Write Command

	:param handle: ATT value handle indicating the attribute to write
	:type handle: int
	:param value: new value to write
	:type value: bytes
	:param connectionHandle: connection handle associated to the connection
	:type connectionHandle: int

	:Example:
		
		>>> emitter.sendp(ble.BLEWriteCommand(handle=0x0021, value=b"\x01\x02\x03"))

	.. note::
		This Packet is similar to ``BLEWriteRequest`` but it doesn't need a ``Write Response``

	'''
	def __init__(self, handle=0, value=b"", connectionHandle = -1):
		super().__init__()
		self.handle = handle
		self.value = value
		self.connectionHandle = connectionHandle
		self.name = "BLE - Write Command Packet"

	def toString(self):
		return "<< "+self.name+" | handle="+hex(self.handle)+" | value="+self.value.hex()+" >>"

class BLEWriteResponse(BLEPacket):
	'''
	Mirage Bluetooth Low Energy Packet - Write Response

	:param connectionHandle: connection handle associated to the connection
	:type connectionHandle: int

	:Example:
		
		>>> emitter.sendp(ble.BLEWriteResponse()) # note : the connectionHandle is not provided because its value is direcly modified by the Device

	'''
	def __init__(self, connectionHandle = -1):
		super().__init__()
		self.connectionHandle = connectionHandle
		self.name = "BLE - Write Response Packet"

class BLEHandleValueNotification(BLEPacket):
	'''
	Mirage Bluetooth Low Energy Packet - Handle Value Notification

	:param handle: ATT value handle indicating the attribute linked to the notification
	:type handle: int
	:param value: new value to notify
	:type value: bytes
	:param connectionHandle: connection handle associated to the connection
	:type connectionHandle: int

	:Example:
		
		>>> emitter.sendp(ble.BLEHandleValueNotification(handle=0x0021, value=b"\x00"))
		>>> emitter.sendp(ble.BLEHandleValueNotification(handle=0x0021, value=b"\x02"))

	'''
	def __init__(self, handle=0, value=b"", connectionHandle = -1):
		super().__init__()
		self.handle = handle
		self.value = value
		self.connectionHandle = connectionHandle
		self.name = "BLE - Handle Value Notification Packet"

	def toString(self):
		return "<< "+self.name+" | handle="+hex(self.handle)+" | value="+self.value.hex()+" >>"

class BLEReadBlobRequest(BLEPacket):
	'''
	Mirage Bluetooth Low Energy Packet - Read Blob Request

	:param handle: ATT value handle indicating the attribute linked to the request
	:type handle: int
	:param offset: offset of the value to read
	:type offset: int
	:param connectionHandle: connection handle associated to the connection
	:type connectionHandle: int

	:Example:
		
		>>> emitter.sendp(ble.BLEReadBlobRequest(handle=0x0021, offset=26))

	'''
	def __init__(self, handle=0, offset=0, connectionHandle = -1):
		super().__init__()
		self.handle = handle
		self.offset = offset
		self.connectionHandle = connectionHandle
		self.name = "BLE - Read Blob Request Packet"

	def toString(self):
		return "<< "+self.name+" | handle="+hex(self.handle)+" | offset="+str(self.offset)+" >>"

class BLEReadBlobResponse(BLEPacket):
	'''
	Mirage Bluetooth Low Energy Packet - Read Blob Response

	:param value: ATT value
	:type value: bytes
	:param connectionHandle: connection handle associated to the connection
	:type connectionHandle: int

	:Example:
		
		>>> emitter.sendp(ble.BLEReadBlobResponse(value=bytes.fromhex("01020304")))

	'''
	def __init__(self, value=b"", connectionHandle = -1):
		super().__init__()
		self.value = value
		self.connectionHandle = connectionHandle
		self.name = "BLE - Read Blob Response Packet"

	def toString(self):
		return "<< "+self.name+" | value="+self.value.hex()+" >>"

class BLEHandleValueIndication(BLEPacket):
	'''
	Mirage Bluetooth Low Energy Packet - Handle Value Indication

	:param handle: ATT value handle indicating the attribute linked to the indication
	:type handle: int
	:param value: new value to notify
	:type value: bytes
	:param connectionHandle: connection handle associated to the connection
	:type connectionHandle: int

	:Example:
		
		>>> emitter.sendp(ble.BLEHandleValueIndication(handle=0x0021, value=b"\x00"))
		>>> emitter.sendp(ble.BLEHandleValueIndication(handle=0x0021, value=b"\x02"))

	'''
	def __init__(self, handle=0, value=b"", connectionHandle = -1):
		super().__init__()
		self.handle = handle
		self.value = value
		self.connectionHandle = connectionHandle
		self.name = "BLE - Handle Value Indication Packet"

	def toString(self):
		return "<< "+self.name+" | handle="+hex(self.handle)+" | value="+self.value.hex()+" >>"

class BLEHandleValueConfirmation(BLEPacket):
	'''
	Mirage Bluetooth Low Energy Packet - Handle Value Confirmation

	:param connectionHandle: connection handle associated to the connection
	:type connectionHandle: int

	:Example:
		
		>>> emitter.sendp(ble.BLEHandleValueConfirmation())

	'''
	def __init__(self,connectionHandle = -1):
		super().__init__()
		self.connectionHandle = connectionHandle
		self.name = "BLE - Handle Value Confirmation Packet"

	def toString(self):
		return "<< "+self.name+" >>"


class BLEReadRequest(BLEPacket):
	'''
	Mirage Bluetooth Low Energy Packet - Read Request

	:param handle: ATT handle indicating the attribute to read
	:type handle: int
	:param connectionHandle: connection handle associated to the connection
	:type connectionHandle: int

	:Example:
		
		>>> emitter.sendp(ble.BLEReadRequest(handle=0x0021))

	'''
	def __init__(self, handle=0, connectionHandle = -1):
		super().__init__()
		self.handle = handle
		self.connectionHandle = connectionHandle
		self.name = "BLE - Read Request Packet"

	def toString(self):
		return "<< "+self.name+" | handle="+hex(self.handle)+" >>"


class BLEReadResponse(BLEPacket):
	'''
	Mirage Bluetooth Low Energy Packet - Read Response

	:param value: value read and transmitted to Central
	:type value: bytes
	:param connectionHandle: connection handle associated to the connection
	:type connectionHandle: int

	:Example:
		
		>>> emitter.sendp(ble.BLEReadResponse(value=b"\xAA\xBB\xCC\xDD"))

	'''
	def __init__(self, value=b"", connectionHandle = -1):
		super().__init__()
		self.value = value
		self.connectionHandle = connectionHandle
		self.name = "BLE - Read Response Packet"

	def toString(self):
		return "<< "+self.name+" | value="+self.value.hex()+" >>"



class BLEConnectionParameterUpdateRequest(BLEPacket):
	'''
	Mirage Bluetooth Low Energy Packet - Connection Parameter Update Request

	:param l2capCmdId: L2CAP Command Identifier
	:type l2capCmdId: int
	:param timeoutMult: timeout Multiplier
	:type timeoutMult: int
	:param slaveLatency: slave Latency
	:type slaveLatency: int
	:param minInterval: minimal Interval
	:type minInterval: int
	:param maxInterval: maximal Interval
	:type maxInterval: int
	:param connectionHandle: connection handle associated to the connection
	:type connectionHandle: int

	:Example:
		
		>>> emitter.sendp(ble.BLEConnectionParameterUpdateRequest(timeoutMult=65535, minInterval=65535, maxInterval=65535, slaveLatency=0))

	'''
	def __init__(self,l2capCmdId = 0, minInterval = 0, maxInterval = 0, slaveLatency = 0, timeoutMult = 0,connectionHandle = -1):
		super().__init__()
		self.l2capCmdId = l2capCmdId
		self.timeoutMult = timeoutMult
		self.slaveLatency = slaveLatency
		self.minInterval = minInterval
		self.maxInterval = maxInterval
		self.connectionHandle = connectionHandle
		self.name = "BLE - Connection Parameter Update Request Packet"

	def toString(self):
		return "<< "+self.name+" | slaveLatency="+str(self.slaveLatency)+" | timeoutMult="+str(self.timeoutMult)+" | minInterval="+str(self.minInterval)+" | maxInterval="+str(self.maxInterval)+" >>"



class BLEConnectionParameterUpdateResponse(BLEPacket):
	'''
	Mirage Bluetooth Low Energy Packet - Connection Parameter Update Response

	:param l2capCmdId: L2CAP Command Identifier
	:type l2capCmdId: int
	:param moveResult: move Result
	:type moveResult: int
	:param connectionHandle: connection handle associated to the connection
	:type connectionHandle: int

	:Example:
		
		>>> emitter.sendp(ble.BLEConnectionParameterUpdateResponse(moveResult=0))

	'''
	def __init__(self,l2capCmdId = 0, moveResult = 0,connectionHandle = -1):
		super().__init__()
		self.l2capCmdId = l2capCmdId
		self.moveResult = moveResult
		self.connectionHandle = connectionHandle
		self.name = "BLE - Connection Parameter Update Response Packet"

	def toString(self):
		return "<< "+self.name+" | moveResult="+str(self.moveResult)+" >>"


class BLESecurityRequest(BLEPacket):
	'''
	Mirage Bluetooth Low Energy Packet - Security Request

	:param connectionHandle: connection handle associated to the connection
	:type connectionHandle: int
	:param authentication: flags indicating the authentication parameters requested
	:type authentication: bytes

	.. note ::

		Some dissectors are provided in order to fill the fields included in this packet :

		  * ``mirage.libs.ble_utils.dissectors.AuthReqFlag`` : authentication field

	'''
	def __init__(self,connectionHandle = -1,  authentication = b"\x00"):
		super().__init__()
		self.authentication = authentication
		self.connectionHandle = connectionHandle

		self.name = "BLE - Security Request Packet"

	def toString(self):
		return "<< "+self.name+" | authentication="+hex(self.authentication)+" >>"
	
class BLEPairingRequest(BLEPacket):
	'''
	Mirage Bluetooth Low Energy Packet - Pairing Request

	:param connectionHandle: connection handle associated to the connection
	:type connectionHandle: int
	:param outOfBand: boolean indicating if out of band is available
	:type outOfBand: bool
	:param inputOutputCapability: integer indicating the input output capability of Central
	:type inputOutputCapability: int
	:param maxKeySize: integer indicating the maximum key size
	:type maxKeySize: int
	:param authentication: flags indicating the authentication parameters requested
	:type authentication: bytes
	:param initiatorKeyDistribution: bytes indicating the initiator key distribution
	:type initiatorKeyDistribution: bytes
	:param responderKeyDistribution: bytes indicating the responder key distribution
	:type responderKeyDistribution: bytes
	:param payload: bytes indicating the payload of request
	:type payload: bytes


	.. note ::

		Some dissectors are provided in order to fill the fields included in this packet :

		  * ``mirage.libs.ble_utils.dissectors.AuthReqFlag`` : authentication field
		  * ``mirage.libs.ble_utils.dissectors.InputOutputCapability`` : input output capability field
		  * ``mirage.libs.ble_utils.dissectors.KeyDistributionFlag`` : initiatorKeyDistribution and responderKeyDistribution fields

	'''
	def __init__(self,connectionHandle = -1,  outOfBand = False,inputOutputCapability = 0,maxKeySize = 16, authentication = b"\x00", initiatorKeyDistribution = b"\x00", responderKeyDistribution=b"\x00", payload=b""):
		super().__init__()
		self.outOfBand = outOfBand
		self.inputOutputCapability = inputOutputCapability
		self.authentication = authentication
		self.maxKeySize = maxKeySize
		self.initiatorKeyDistribution = initiatorKeyDistribution
		self.responderKeyDistribution = responderKeyDistribution
		self.connectionHandle = connectionHandle
		self.payload = payload if payload != b"" else raw(SM_Hdr()/SM_Pairing_Request(
						iocap=self.inputOutputCapability,
						oob=1 if self.outOfBand else 0,
						authentication=self.authentication,
						max_key_size = self.maxKeySize,
						initiator_key_distribution=self.initiatorKeyDistribution,
						responder_key_distribution = self.responderKeyDistribution))
		self.name = "BLE - Pairing Request Packet"

	def toString(self):
		return "<< "+self.name+" | outOfBand="+("yes" if self.outOfBand else "no")+" | inputOutputCapability="+hex(self.inputOutputCapability)+" | authentication="+hex(self.authentication)+" | maxKeySize="+str(self.maxKeySize)+" | initiatorKeyDistribution="+hex(self.initiatorKeyDistribution)+" | responderKeyDistribution="+hex(self.responderKeyDistribution)+" >>"
	

class BLEPairingResponse(BLEPacket):
	'''
	Mirage Bluetooth Low Energy Packet - Pairing Response

	:param connectionHandle: connection handle associated to the connection
	:type connectionHandle: int
	:param outOfBand: boolean indicating if out of band is available
	:type outOfBand: bool
	:param inputOutputCapability: integer indicating the input output capability of Peripheral
	:type inputOutputCapability: int
	:param maxKeySize: integer indicating the maximum key size
	:type maxKeySize: int
	:param authentication: flags indicating the authentication parameters requested
	:type authentication: bytes
	:param initiatorKeyDistribution: bytes indicating the initiator key distribution
	:type initiatorKeyDistribution: bytes
	:param responderKeyDistribution: bytes indicating the responder key distribution
	:type responderKeyDistribution: bytes
	:param payload: bytes indicating the payload of response
	:type payload: bytes

	'''
	def __init__(self,connectionHandle = -1,  outOfBand = 0,inputOutputCapability= 0,maxKeySize = 16, authentication = 0, initiatorKeyDistribution = 0, responderKeyDistribution=0, payload=b""):
		super().__init__()
		self.outOfBand = outOfBand
		self.inputOutputCapability = inputOutputCapability
		self.authentication = authentication
		self.maxKeySize = maxKeySize
		self.initiatorKeyDistribution = initiatorKeyDistribution
		self.responderKeyDistribution = responderKeyDistribution
		self.connectionHandle = connectionHandle
		self.payload = payload if payload != b"" else raw(SM_Hdr()/SM_Pairing_Response(
						iocap=self.inputOutputCapability,
						oob=1 if self.outOfBand else 0,
						authentication=self.authentication,
						max_key_size = self.maxKeySize,
						initiator_key_distribution=self.initiatorKeyDistribution,
						responder_key_distribution = self.responderKeyDistribution))
		self.name = "BLE - Pairing Response Packet"

	def toString(self):
		return "<< "+self.name+" | outOfBand="+("yes" if self.outOfBand else "no")+" | inputOutputCapability="+hex(self.inputOutputCapability)+" | authentication="+hex(self.authentication)+" | maxKeySize="+str(self.maxKeySize)+" | initiatorKeyDistribution="+hex(self.initiatorKeyDistribution)+" | responderKeyDistribution="+hex(self.responderKeyDistribution)+" >>"

class BLEPairingConfirm(BLEPacket):
	'''
	Mirage Bluetooth Low Energy Packet - Pairing Confirm

	:param connectionHandle: connection handle associated to the connection
	:type connectionHandle: int
	:param confirm: confirmation value
	:type confirm: bytes
	'''
	def __init__(self,connectionHandle = -1,confirm = b"\x00"*16):
		super().__init__()
		self.connectionHandle = connectionHandle
		self.confirm = confirm
		self.name = "BLE - Pairing Confirm Packet"

	def toString(self):
		return "<< "+self.name+" | confirm="+self.confirm.hex()+" >>"

class BLEPairingRandom(BLEPacket):
	'''
	Mirage Bluetooth Low Energy Packet - Pairing Random

	:param connectionHandle: connection handle associated to the connection
	:type connectionHandle: int
	:param random: random value
	:type random: bytes
	'''
	def __init__(self,connectionHandle = -1,random = b"\x00"*16):
		super().__init__()
		self.connectionHandle = connectionHandle
		self.random = random
		self.name = "BLE - Pairing Random Packet"

	def toString(self):
		return "<< "+self.name+" | random="+self.random.hex()+" >>"


class BLEPairingFailed(BLEPacket):
	'''
	Mirage Bluetooth Low Energy Packet - Pairing Failed

	:param connectionHandle: connection handle associated to the connection
	:type connectionHandle: int
	:param reason: integer indicating the reason of failure
	:type reason: int
	'''
	def __init__(self,connectionHandle = -1,reason=0):
		super().__init__()
		self.reason = reason
		self.connectionHandle = connectionHandle
		self.name = "BLE - Pairing Failed Packet"
	def toString(self):
		return "<< "+self.name+" | reason="+str(self.reason)+" >>"

class BLEEncryptionInformation(BLEPacket):
	'''
	Mirage Bluetooth Low Energy Packet - Encryption Information

	:param connectionHandle: connection handle associated to the connection
	:type connectionHandle: int
	:param ltk: Long Term Key
	:type ltk: bytes
	'''

	def __init__(self,connectionHandle = -1, ltk = b"\x00" * 16):
		super().__init__()
		self.ltk = ltk
		self.connectionHandle = connectionHandle
		self.name = "BLE - Encryption Information Packet"

	def toString(self):
		return "<< "+self.name+" | ltk="+self.ltk.hex()+" >>"

class BLEMasterIdentification(BLEPacket):
	'''
	Mirage Bluetooth Low Energy Packet - Encryption Information

	:param connectionHandle: connection handle associated to the connection
	:type connectionHandle: int
	:param rand: random value associated to the Long Term Key
	:type rand: bytes
	:param ediv: EDIV value associated to the Long Term Key
	:type ediv: integer
	'''

	def __init__(self,connectionHandle = -1, ediv = 0, rand = b"\x00" * 8):
		super().__init__()
		self.ediv = ediv
		self.rand = rand
		self.connectionHandle = connectionHandle
		self.name = "BLE - Master Identification Packet"

	def toString(self):
		return "<< "+self.name+" | rand="+self.rand.hex()+" | ediv="+hex(self.ediv)+" >>"


class BLEIdentityInformation(BLEPacket):
	'''
	Mirage Bluetooth Low Energy Packet - Identity Information

	:param connectionHandle: connection handle associated to the connection
	:type connectionHandle: int
	:param irk: Identity Resolving Key
	:type irk: bytes
	'''
	def __init__(self,connectionHandle = -1, irk = b"\x00" * 16):
		super().__init__()
		self.irk = irk
		self.connectionHandle = connectionHandle
		self.name = "BLE - Identity Information Packet"

	def toString(self):
		return "<< "+self.name+" | irk="+self.irk.hex()+" >>"


class BLEIdentityAddressInformation(BLEPacket):
	'''
	Mirage Bluetooth Low Energy Packet - Identity Address Information

	:param connectionHandle: connection handle associated to the connection
	:type connectionHandle: int
	:param type: string indicating if the associated BD address is random ("random") or public ("public")
	:type type: str
	:param address: string indicating the BD address
	:type address: str
	'''
	def __init__(self,connectionHandle = -1, type = "public", address="00:00:00:00:00:00"):
		super().__init__()
		self.type = type
		self.address = address
		self.connectionHandle = connectionHandle
		self.name = "BLE - Identity Address Information Packet"

	def toString(self):
		return "<< "+self.name+" | type="+self.type+" | address="+self.address+" >>"


class BLESigningInformation(BLEPacket):
	'''
	Mirage Bluetooth Low Energy Packet - Signing Information

	:param connectionHandle: connection handle associated to the connection
	:type connectionHandle: int
	:param csrk: Connection Signature Resolving Key
	:type csrk: bytes
	'''
	def __init__(self,connectionHandle = -1, csrk = b"\x00" * 16):
		super().__init__()
		self.csrk = csrk
		self.connectionHandle = connectionHandle
		self.name = "BLE - Signing Information Packet"

	def toString(self):
		return "<< "+self.name+" | csrk="+self.csrk.hex()+" >>"

class BLELongTermKeyRequest(BLEPacket):
	'''
	Mirage Bluetooth Low Energy Packet - Long Term Key Request

	:param rand: random value associated to this Long Term Key
	:type rand: bytes
	:param ediv: EDIV value associated to this Long Term Key
	:type ediv: integer
	:param ltk: Long Term Key
	:type ltk: bytes
	:param connectionHandle: connection handle associated to the connection
	:type connectionHandle: int

	:Example:
		
		>>> emitter.sendp(ble.BLELongTermKeyRequest(ltk=bytes.fromhex("000102030405060708090a0b0c0d0e0f"))

	'''
	def __init__(self,connectionHandle = -1, rand=b"\x00"*8, ediv=0,ltk=b"\x00"*16):
		super().__init__()
		self.connectionHandle = connectionHandle
		self.rand = rand
		self.ediv = ediv
		self.ltk = ltk
		self.name = "BLE - Long Term Key Request"

	def toString(self):
		return "<< "+self.name+" | rand="+self.rand.hex()+" | ediv="+hex(self.ediv)+ ("" if self.ltk == b"\x00"*16 else " | ltk = " + self.ltk.hex()) + " >>"

class BLELongTermKeyRequestReply(BLEPacket):
	'''
	Mirage Bluetooth Low Energy Packet - Long Term Key Request Reply

	:param positive: boolean indicating if the LTK Request was accepted (``positive=True``) or rejected (``positive=False``)
	:type positive: bool
	:param ltk: Long Term Key
	:type ltk: bytes
	:param connectionHandle: connection handle associated to the connection
	:type connectionHandle: int

	:Example:
		
		>>> emitter.sendp(ble.BLELongTermKeyRequestReply(ltk=bytes.fromhex("000102030405060708090a0b0c0d0e0f"), positive=True))

	'''
	def __init__(self,connectionHandle = -1, positive=False,ltk=b"\x00"*16):
		super().__init__()
		self.connectionHandle = connectionHandle
		self.positive = positive
		self.ltk = ltk
		self.name = "BLE - Long Term Key Request Reply"
	def toString(self):
		return "<< "+self.name+" "+("(positive) | ltk="+self.ltk.hex() if self.positive else "(negative)")+" >>"


