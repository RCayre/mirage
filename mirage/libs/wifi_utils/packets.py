from mirage.libs import wireless

class WifiPacket(wireless.Packet):
	'''
	Mirage WiFi Packet

	:param channel: wifi channel in use
	:type channel: int
	:param destMac: destination MAC address
	:type destMac: str
	:param srcMac: source MAC address
	:type srcMac: str
	:param emitMac: emitter MAC address
	:type emitMac: str
	:param type: type of the current frame
	:type type: int
	:param subType: subtype of the current frame
	:type subType: int
	'''
	def __init__(self, channel = None, destMac = '', srcMac = '', emitMac = '', type = 0, subType = 0):
		super().__init__()
		self.destMac = destMac
		self.srcMac = srcMac
		self.emitMac = emitMac
		self.type = type
		self.subType = subType
		self.channel = channel
		self.name = "Wifi - Unknown Packet"

class WifiBeacon(WifiPacket):
	'''
	Mirage WiFi Packet - Beacon (Management frame)

	:param channel: wifi channel in use
	:type channel: int
	:param destMac: destination MAC address
	:type destMac: str
	:param srcMac: source MAC address
	:type srcMac: str
	:param emitMac: emitter MAC address
	:type emitMac: str
	:param SSID: SSID contained in the Beacon frame
	:type SSID: str
	:param cypher: cypher mode in use ('OPN','WPA','WPA2','WEP')
	:type cypher: str
	'''
	def __init__(self, channel = None,destMac='',srcMac='',emitMac='',SSID='???',cypher='OPN'):
		super().__init__(channel = channel, destMac = destMac, srcMac = srcMac, emitMac = emitMac, type=0, subType=8)
		self.SSID = SSID
		self.cypher = cypher
		self.name = "Wifi - Management / Beacon Packet"
		
	def toString(self):
		return "<< "+self.name +" | SSID="+(self.SSID if self.SSID is not None else "???")+" | srcMac="+self.srcMac+" >>"

class WifiProbeRequest(WifiPacket):
	'''
	Mirage WiFi Packet - Probe Request (Management frame)

	:param channel: wifi channel in use
	:type channel: int
	:param destMac: destination MAC address
	:type destMac: str
	:param srcMac: source MAC address
	:type srcMac: str
	:param emitMac: emitter MAC address
	:type emitMac: str
	:param SSID: SSID contained in the Beacon frame
	:type SSID: str
	'''
	def __init__(self, channel = None,destMac='',srcMac='',emitMac='',SSID='???'):
		super().__init__(channel = channel, destMac = destMac, srcMac = srcMac, emitMac = emitMac, type=0, subType=4)
		self.SSID = SSID
		self.name = "Wifi - Management / Probe Request Packet"
		
	def toString(self):
		return "<< "+self.name + " | SSID="+(self.SSID if self.SSID is not None else "???")+" | srcMac="+self.srcMac+" >>"

class WifiProbeResponse(WifiPacket):
	'''
	Mirage WiFi Packet - Probe Response (Management frame)

	:param channel: wifi channel in use
	:type channel: int
	:param destMac: destination MAC address
	:type destMac: str
	:param srcMac: source MAC address
	:type srcMac: str
	:param emitMac: emitter MAC address
	:type emitMac: str
	:param SSID: SSID contained in the Beacon frame
	:type SSID: str
	:param cypher: cypher mode in use ('OPN','WPA','WPA2','WEP')
	:type cypher: str
	:param beaconInterval: interval between two consecutive beacon frames
	:type beaconInterval: int
	'''
	def __init__(self, channel = None,destMac='',srcMac='',emitMac='',SSID='???',cypher='OPN',beaconInterval=0x0064):
		super().__init__(channel = channel, destMac = destMac, srcMac = srcMac, emitMac = emitMac, type=0, subType=5)
		self.SSID = SSID
		self.cypher = cypher
		self.beaconInterval = beaconInterval
		self.name = "Wifi - Management / Probe Response Packet"
		
	def toString(self):
		return "<< "+self.name+" | SSID="+(self.SSID if self.SSID is not None else "???")+" | srcMac="+self.srcMac+" >>"

class WifiDeauth(WifiPacket):
	'''
	Mirage WiFi Packet - Deauthentication (Management frame)

	:param channel: wifi channel in use
	:type channel: int
	:param destMac: destination MAC address
	:type destMac: str
	:param srcMac: source MAC address
	:type srcMac: str
	:param emitMac: emitter MAC address
	:type emitMac: str
	:param reason: deauthentication reason
	:type reason: int
	'''
	def __init__(self, channel = None,destMac='',srcMac='',emitMac='',reason=7):
		super().__init__(channel = channel, destMac = destMac, srcMac = srcMac, emitMac = emitMac, type=0, subType=12)
		self.reason = reason
		self.name = "Wifi - Management / Deauthentication Packet"
		

class WifiDisas(WifiPacket):
	'''
	Mirage WiFi Packet - Disassociation (Management frame)

	:param channel: wifi channel in use
	:type channel: int
	:param destMac: destination MAC address
	:type destMac: str
	:param srcMac: source MAC address
	:type srcMac: str
	:param emitMac: emitter MAC address
	:type emitMac: str
	:param reason: disassociation reason
	:type reason: int
	'''
	def __init__(self, channel = None,destMac='',srcMac='',emitMac='',reason=7):
		super().__init__(channel = channel, destMac = destMac, srcMac = srcMac, emitMac = emitMac, type=0, subType=10)
		self.reason = reason
		self.name = "Wifi - Management / Disassociation Packet"
