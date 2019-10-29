from mirage.core.module import WirelessModule
from mirage.libs import utils,wireless
import mirage.libs.io as mio
from mirage.libs.wifi_utils.packets import *
from mirage.libs.wifi_utils.constants import *
from threading import Lock
from scapy.all import *
import os,socket,fcntl,array,struct
class WifiDevice(wireless.Device):
	'''
	This device allows to communicate with a WiFi Device.
	The corresponding interfaces are : ``wlanX`` (e.g. "wlanX")

	The following capabilities are actually supported :

	+-----------------------------------+----------------+
	| Capability			    | Available ?    |
	+===================================+================+
	| SCANNING                          | yes            |
	+-----------------------------------+----------------+
	| MONITORING                        | yes            |
	+-----------------------------------+----------------+
	| COMMUNICATING_AS_ACCESS_POINT     | yes            |
	+-----------------------------------+----------------+
	| COMMUNICATING_AS_STATION          | yes            |
	+-----------------------------------+----------------+
	| JAMMING                           | no             |
	+-----------------------------------+----------------+

	'''
	sharedMethods = [
		"setChannel",
		"getChannel",
		"getFrequency",
		"setFrequency",
		"setMonitorMode",
		"getAddress",
		"getMode",
		"setMode"
	]

	def init(self):
		self.wlock = Lock()
		if self.isUp():	
			self.channel = None
			self.frequency = None
			self.setMonitorMode(enable=True)
			self.setChannel(1)
			self.capabilities = ["MONITORING","SCANNING","COMMUNICATING_AS_ACCESS_POINT","COMMUNICATING_AS_STATION"]

	def _openSocket(self):
		self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

	def _closeSocket(self):
		self.socket.close()

	def _getIoCtl(self,what,data=None):
		try:
			ifname = bytes(self.interface,"ascii")
			buff = IFNAMESIZE-len(ifname)
			ifreq = array.array('B', ifname + b'\0'*buff)
			if data is None:
				ifreq.extend(b'\0'*16)
			else:
				ifreq.extend(data)
			self.wlock.acquire()
			self._openSocket()
			result = fcntl.ioctl(self.socket.fileno(), what, ifreq)
			self._closeSocket()
			self.wlock.release()
			return ifreq[IFNAMESIZE:]
		except OSError:
			return None

	def _setIoCtl(self,what,data=None):
		return self._getIoCtl(what,data=data)


	def up(self):
		'''
		This method allows to set up the interface corresponding to the current device.
		
		:return: boolean indicating if the operation is successful
		:rtype: bool

		'''
		returned = self._getIoCtl(SIOCGIFFLAGS)
		if returned is not None:
			flags = struct.unpack("h",returned[:2])[0]
			flags |= IFF_UP
			self._setIoCtl(SIOCSIFFLAGS,struct.pack("h",flags))	
			return True
		else:
			mio.fail("Interface can't be up")
		return False

	def down(self):
		'''
		This method allows to set down the interface corresponding to the current device.
		
		:return: boolean indicating if the operation is successful
		:rtype: bool

		'''
		returned = self._getIoCtl(SIOCGIFFLAGS)
		if returned is not None:
			flags = struct.unpack("h",returned[:2])[0]
			flags = flags & ~IFF_UP
			self._setIoCtl(SIOCSIFFLAGS,struct.pack("h",flags))
			return True
		else:
			mio.fail("Interface can't be down")
		return False

	def getMode(self):
		'''
		This method allows to get the mode currently in use.

		Existing modes: 

		   * 'Auto'
		   * 'Ad-Hoc'
		   * 'Managed'
		   * 'Master'
		   * 'Repeat'
		   * 'Second'
		   * 'Monitor'
		   * 'Unknown/bug'
		
		:return: string indicating the mode in use
		:rtype: str

		
		:Example:
		
			>>> device.getMode()
			'Auto'
			>>> device.setMode("Monitor")
			>>> device.getMode()
			'Monitor'

		.. note::

			This method is a **shared method** and can be called from the corresponding Emitters / Receivers.

		'''
		result = self._getIoCtl(SIOCGIWMODE)
		mode = WIFI_MODES[result[0]]
		return mode

	def setMode(self,mode):
		'''
		This method allows to set the mode currently in use.

		Existing modes: 

		   * 'Auto'
		   * 'Ad-Hoc'
		   * 'Managed'
		   * 'Master'
		   * 'Repeat'
		   * 'Second'
		   * 'Monitor'
		   * 'Unknown/bug'

		
		:param mode: string indicating the mode to use
		:type mode: str
		:return: boolean indicating if the operation was successful
		:rtype: bool

		
		:Example:
		
			>>> device.getMode()
			'Auto'
			>>> device.setMode("Monitor")
			>>> device.getMode()
			'Monitor'

		.. note::

			This method is a **shared method** and can be called from the corresponding Emitters / Receivers.

		'''
		mode = struct.pack('I', WIFI_MODES.index(mode))

		returned = self._setIoCtl(SIOCSIWMODE,mode)
		if returned is None:
			self.wlock.release()
			self.down()
			self._setIoCtl(SIOCSIWMODE,mode)
			self.up()
		return True

	def isUp(self):
		return self.interface in os.listdir('/sys/class/net/')

	def send(self,data):
		sendp(data,iface=self.interface, verbose=0)

	def listen(self,callback=None):
		'''
		This method replaces the recv method, in order to reuse scapy's receiver optimization.
		It's the reason why the _task method will also be redefined in ``mirage.libs.wifi.WifiReceiver``.
	
		:param callback: reception callback
		:type callback: function
		'''
		sniff(iface=self.interface,prn=callback,store=0)
	
	def getFrequency(self):
		'''
		This method allows to get the frequency currently in use by the corresponding Device.
	
		:return: frequency currently in use (in Hz)
		:rtype: int

		:Example:
		
			>>> device.getFrequency()
			2462000000

		.. note::

			This method is a **shared method** and can be called from the corresponding Emitters / Receivers.

		'''
		result = self._getIoCtl(SIOCGIWFREQ)
		if result is not None:
			size = struct.calcsize("ihbb")
			mantissa, exponent, listIndex, flags = struct.unpack("ihbb",result[:size])
			return (mantissa*10**exponent)
		else:
			mio.fail("Interface can't get its frequency")
			return None

	def setFrequency(self,frequency):
		'''
		This method allows to set the frequency to use by the corresponding Device.
	
		:param frequency: frequency to use (in Hz)
		:type frequency: int
		:return: boolean indicating if the frequency change operation is successful
		:rtype: bool

		:Example:
		
			>>> device.setFrequency(2462000000)
			True

		.. note::

			This method is a **shared method** and can be called from the corresponding Emitters / Receivers.

		'''
		self.frequency= frequency
		exponent = int(math.floor(math.log10(frequency)))
		if exponent > 8:
			mantissa = int(math.floor(frequency / math.pow(10, exponent - 6))) * 100
			exponent = exponent - 8
		else:
			mantissa = int(frequency)
			exponent = 0
		request = struct.pack("ihBB", mantissa, exponent, 0, IWFREQFIXED)		
		returned = self._setIoCtl(SIOCSIWFREQ,request)
		return returned is not None

	def getChannel(self):
		'''
		This method allows to get the channel currently in use by the corresponding Device.
	
		:return: channel currently in use
		:rtype: int

		:Example:
		
			>>> device.getChannel()
			11

		.. note::

			This method is a **shared method** and can be called from the corresponding Emitters / Receivers.

		'''
		frequency = self.getFrequency()
		if frequency is not None:
			if frequency == 2484000000:
				channel = 14
			else:
				channel = int(((frequency / 1000000) - 2407)/5)
			self.channel = channel
			return channel
		else:
			return None

	def setChannel(self,channel):
		'''
		This method allows to set the channel to use by the corresponding Device.
	
		:param channel: channel to use
		:type channel: int
		:return: boolean indicating if the channel change operation is successful
		:rtype: bool
	
		:Example:
		
			>>> device.setChannel(11)
			True

		.. note::

			This method is a **shared method** and can be called from the corresponding Emitters / Receivers.

		'''
		if self.channel != int(channel):
			mio.info("New channel : "+str(channel))
			self.channel = int(channel)
			if channel == 14:
				frequency = 2484000000
			else:
				frequency = (2407 + channel*5) * 1000000
			
			return self.setFrequency(frequency)
		return False


	def setMonitorMode(self,enable=True):
		'''
		This method allows to switch on or off the monitor mode.

		:param enable: boolean indicating if the monitor mode should be enabled or disabled.
		:type enable: bool

		:Example:
	
			>>> device.getMode()
			'Managed'
			>>> device.setMonitorMode(enable=True)
			>>> device.getMode()
			'Monitor'

		.. note::

			This method is a **shared method** and can be called from the corresponding Emitters / Receivers.

		'''
		self.setMode("Monitor" if enable else "Managed")

	def getAddress(self):
		'''
		This method allows to get the MAC address currently in use by the device.

		:return: string indicating the MAC address currently in ues
		:rtype: str

		:Example:

			>>> device.getAddress()
			'11:22:33:44:55:66'

		.. note::

			This method is a **shared method** and can be called from the corresponding Emitters / Receivers.

		'''
		self.wlock.acquire()
		self._openSocket()
		info = fcntl.ioctl(self.socket.fileno(), 0x8927,  struct.pack('256s', bytes(self.interface[:15],"utf-8")))
		self._closeSocket()
		self.wlock.release()	
		return ''.join(['%02x:' % b for b in info[18:24]])[:-1].upper()


class WifiEmitter(wireless.Emitter):
	def __init__(self,interface="wlp2s0"):
		super().__init__(interface=interface,packetType=WifiPacket,deviceType=WifiDevice)

	def convert(self,packet):
		AP_RATES = b"\x0c\x12\x18\x24\x30\x48\x60\x6c"
		if isinstance(packet,WifiPacket):
			if packet.packet is None:
				destMac = 'ff:ff:ff:ff:ff:ff'.upper() if packet.destMac == '' else packet.destMac.upper()
				srcMac = self.getAddress().upper() if packet.srcMac == '' else packet.srcMac.upper()
				emitMac = self.getAddress().upper() if packet.emitMac == '' else packet.emitMac.upper()
				channel = packet.channel
				frequency = struct.pack("<h",int(self.device.frequency/1000000))
				type = packet.type
				subType = packet.subType

				# Common layers
				packet.packet = RadioTap()
				packet.packet /= Dot11(type=type, subtype=subType,addr1=destMac, addr2=srcMac, addr3=emitMac)

				# Specialized layer for Beacons
				if isinstance(packet, WifiBeacon):
					cap = 0x2105 if packet.cypher == "OPN" else 0x3101
					packet.packet /= Dot11Beacon(cap=cap)

				# Specialized layer for Probe Requests
				elif isinstance(packet, WifiProbeRequest):
					packet.packet /= Dot11ProbeReq()

				# Specialized layer for Probe Responses
				elif isinstance(packet, WifiProbeResponse):
					cap = 0x2104 if packet.cypher == "OPN" else 0x3101
					packet.packet /= Dot11ProbeResp(beacon_interval=packet.beaconInterval, cap=cap)

				# Specialized layer for Deauth
				elif isinstance(packet, WifiDeauth):
					packet.packet /= Dot11Deauth(reason=packet.reason)

				# Specialized layer for Disas
				elif isinstance(packet, WifiDisas):
					packet.packet /= Dot11Disas(reason=packet.reason)

				if ( isinstance(packet, WifiBeacon) 		or
				     isinstance(packet, WifiProbeRequest) 	or
				     isinstance(packet, WifiProbeResponse) ):
					ssid = Dot11Elt(ID="SSID", info=packet.SSID, len=len(packet.SSID))
					
					packet.packet /= ssid
					packet.packet /= Dot11Elt(ID="Rates", info=AP_RATES)

					channel = packet.channel if packet.channel is not None else self.device.channel					
					
					packet.packet /= Dot11Elt(ID="DSset", info=chr(channel))

					if hasattr(packet,"cypher") and packet.cypher != "OPN":
						rsn = Dot11Elt(ID='RSNinfo',info=(b'\x01\x00\x00\x0f\xac\x04\x01\x00\x00\x0f'
										  b'\xac\x04\x01\x00\x00\x0f\xac\x01\x28\x00'))

						packet.packet /= rsn
			return packet.packet
		return None

class WifiReceiver(wireless.Receiver):
	def __init__(self,interface="wlp2s0",monitorMode=True):
		super().__init__(interface=interface,packetType=WifiPacket, deviceType=WifiDevice)


	def _task(self):
		'''
		This method is redefined in order to reuse the scapy's receiver optimization.
		'''
		self.device.listen(callback=self._add)

	def convert(self,packet):
		def getDot11ElmtInfos(p):
			ssid,channel = None,None
			crypto=set()
			cap = p.sprintf("{Dot11Beacon:%Dot11Beacon.cap%}"
					"{Dot11ProbeResp:%Dot11ProbeResp.cap%}").split('+')
			while isinstance(p,Dot11Elt):
				if hasattr(p,"info") and p.ID == 0:
					ssid = p.info.decode("utf-8")
				elif hasattr(p,"info") and p.ID == 3:
					channel = p.info
				elif hasattr(p,"info") and p.ID == 48:
					crypto.add("WPA2")
				elif p.ID == 221 and hasattr(p,"info") and p.info.startswith(b"\x00P\xf2\x01\x01\x00"):
					crypto.add("WPA")
				if not crypto:
					if "privacy" in cap:
						crypto.add("WEP")
					else:
						crypto.add("OPN")
				p = p.payload
			return (ssid,crypto,channel)
		p = WifiPacket()
		if hasattr(packet,"type") and packet.type == 0:
			emit = packet.addr3.upper()
			src = packet.addr2.upper()
			dest = packet.addr1.upper()

			if packet.subtype == 8:  #  Management / Beacon Packet
				p = WifiBeacon(srcMac=src,destMac=dest,emitMac=emit)
			elif packet.subtype == 5: # Management / Probe Response Packet
				p = WifiProbeResponse(srcMac=src,destMac=dest,emitMac=emit)
			elif packet.subtype == 4: # Management / Probe Request Packet
				p = WifiProbeRequest(srcMac=src,destMac=dest,emitMac=emit)
			elif packet.subtype == 10: # Management / Disassociation Packet
				p = WifiDisas(srcMac=src,destMac=dest,emitMac=emit,reason=packet[Dot11Disas].reason)
			elif packet.subtype == 12: # Management / Deauthentication Packet
				p = WifiDeauth(srcMac=src,destMac=dest,emitMac=emit,reason=packet[Dot11Deauth].reason)
			
			if Dot11Elt in packet:
				ssid,crypto,channel = getDot11ElmtInfos(packet[Dot11Elt])
				p.SSID = ssid
				if hasattr(p,"cypher"):
					p.cypher = list(crypto)[0]
				p.channel = ord(channel) if channel is not None and len(channel) == 1 else 1
		p.packet = packet

		return p

WirelessModule.registerEmitter("wifi",WifiEmitter)
WirelessModule.registerReceiver("wifi",WifiReceiver)
