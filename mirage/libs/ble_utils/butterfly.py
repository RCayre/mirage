from mirage.libs.ble_utils.constants import *
from mirage.libs.wireless_utils.scapy_butterfly_layers import *
from mirage.libs import wireless,io,utils
from queue import Queue
from mirage.libs.wireless_utils.device import Device

class BLEButterflySubdevice(wireless.Device):
	'''
	This (sub)device allows to interact with one specific role (Master or Slave) of a BLE connection when an InjectaBLE complex attack is performed using ButteRFly Device.
	It is directly related to the approach used by ButteRFly firmware when an attack is performed. Indeed, some of the experimental InjectaBLE attacks (especially MiTM) makes use of a "trick" allowing to use only one physical ButteRFly Device to interact with the two roles involved in the targeted connection simultaneously. The attacker injects a CONNECTION_UPDATE_IND packet including carefully chosen WinOffset and WinSize fields allowing to desynchronize the legitimate Master and Slave without altering the other channel hopping parameters. Then, the attacker synchronises with the two legitimate roles, and the two connections follow the same channel hopping pattern with a simple time offset. As a consequence, only one physical device is needed to perform this attack.

	However, Mirage's ble_mitm module requires two separate devices, according to the existing Man-in-the-Middle strategies (GATTacker and BTLEJuice). As a consequence, this subdevice mimick the behaviour of a normal device from the module's perspective, but acts as a software proxy to interact with the ButteRFly device. This subdevice can't be used directly, it will be automatically instantiated by the ButteRFly Device when an attack is performed.

	The corresponding interfaces are : ``butterflyX:subY`` (e.g. "butterfly0:sub0" mimicks a master and "butterfly0:sub1" mimicks a slave)

	The following capabilities are supported :

	+-----------------------------------+----------------------------+
	| Capability                        | Available ?                |
	+===================================+============================+
	| COMMUNICATING_AS_MASTER           | yes (if Y == 0)            |
	+-----------------------------------+----------------------------+
	| COMMUNICATING_AS_SLAVE            | yes (if Y == 1)            |
	+-----------------------------------+----------------------------+
	'''
	sharedMethods = [
		"isConnected",
		"getCurrentHandle",
		"getConnections",
		"getCurrentConnection",
		"switchConnection"
	]

	def __init__(self,interface):
		super().__init__(interface=interface)
		io.info("Instantiating subdevice :" + str(interface))
		if "butterfly" in interface and ":sub" in interface:
			self.index = int(interface.split(":")[0].split("butterfly")[1]) if len(interface.split(":")[0].split("butterfly")[1]) > 0 else 0
			self.subIndex = int(interface.split(":sub")[1])
			self.mainDevice = wireless.Device.get("butterfly"+str(self.index))
		else:
			self.mainDevice = None


	def getCurrentHandle(self):
		'''
		This method returns the connection Handle actually in use.
		If no connection is established, its value is equal to -1.

		:return: connection Handle
		:rtype: int

		.. warning::

			This method always returns 1, it allows to provides the same API as the HCI Device.

		.. note::

			This method is a **shared method** and can be called from the corresponding Emitters / Receivers.

		'''
		return self.mainDevice.getCurrentHandle()

	def getConnections(self):
		'''
		This method returns a list of couple (connection handle / address) representing the connections actually established.
		A connection is described by a dictionary containing an handle and an access address : ``{"handle":1, "address":"0x12345678"}``

		:return: list of connections established
		:rtype: list of dict

		:Example:

			>>> device.getConnections()
			[{'handle':1, 'address':'0x12345678'}]

		.. warning::

			The connection handle is always 1, it allows to provides the same API as the HCI Device.

		.. note::

			This method is a **shared method** and can be called from the corresponding Emitters / Receivers.

		'''
		return self.mainDevice.getConnections()

	def getCurrentConnection(self):
		'''
		This method returns the access address associated to the current connection. If no connection is established, it returns None.

		:return: access address of the current connection
		:rtype: str

		:Example:

			>>> device.getCurrentConnection()
			'0x12345678'

		.. note::

			This method is a **shared method** and can be called from the corresponding Emitters / Receivers.

		'''
		return self.mainDevice.getCurrentConnection()

	def switchConnection(self,address):
		'''
		This method is provided in order to provide the same API as an HCI Device, it actually has no effects.

		.. note::

			This method is a **shared method** and can be called from the corresponding Emitters / Receivers.

		'''
		self.mainDevice.switchConnection(address)

	def isConnected(self):
		'''
		This method returns a boolean indicating if a connection is actually established and hijacked.

		:return: boolean indicating if a connection is established and hijacked
		:rtype: bool

		:Example:

			>>> device.isConnected()
			True

		.. note::

			This method is a **shared method** and can be called from the corresponding Emitters / Receivers.

		'''
		return self.mainDevice is not None and self.mainDevice.isConnected()

	def isUp(self):
		return self.mainDevice is not None and self.ready

	def _addPacket(self,pkt):
		self.packetsQueue.put(pkt)

	def recv(self):
		if not self.packetsQueue.empty():
			pkt = self.packetsQueue.get()
			if pkt is not None:
				return pkt
		return None

	def send(self,packet):
		if BTLE_DATA in packet:
			self.mainDevice.send(Butterfly_Send_Payload_Command(payload_direction=0x01 if self.subIndex == 0 else 0x02,payload_size=len(raw(packet[BTLE_DATA:])),payload_content=raw(packet[BTLE_DATA:])))

	def init(self):
		if self.mainDevice is not None:
			self.packetsQueue = Queue()

			if self.subIndex == 0:
				self.capabilities = ["COMMUNICATING_AS_MASTER"]
			else:
				self.capabilities = ["COMMUNICATING_AS_SLAVE"]
			self.mainDevice.attachSubDevice(self,"master" if self.subIndex == 0 else "slave")
			self.ready = True

	def close(self):
		self.mainDevice.detachSubDevice("master" if self.subIndex == 0 else "slave")

class BLEButterflyDevice(wireless.ButterflyDevice):
	'''
	This device allows to communicate with a ButteRFly Device in order to interact with Bluetooth Low Energy protocol.
	The corresponding interfaces are : ``butterflyX`` (e.g. "butterfly0")

	The following capabilities are actually supported :

	+-------------------------------------------+----------------+
	| Capability                                | Available ?    |
	+===========================================+================+
	| SCANNING                                  | yes            |
	+-------------------------------------------+----------------+
	| ADVERTISING                               | no             |
	+-------------------------------------------+----------------+
	| SNIFFING_ADVERTISEMENTS                   | yes            |
	+-------------------------------------------+----------------+
	| SNIFFING_NEW_CONNECTION                   | yes            |
	+-------------------------------------------+----------------+
	| SNIFFING_EXISTING_CONNECTION              | no             |
	+-------------------------------------------+----------------+
	| JAMMING_CONNECTIONS                       | no             |
	+-------------------------------------------+----------------+
	| JAMMING_ADVERTISEMENTS                    | no             |
	+-------------------------------------------+----------------+
	| INJECTING                                 | yes            |
	+-------------------------------------------+----------------+
	| MITMING_EXISTING_CONNECTION               | yes            |
	+-------------------------------------------+----------------+
	| HIJACKING_MASTER                          | yes            |
	+-------------------------------------------+----------------+
	| HIJACKING_SLAVE                           | yes            |
	+-------------------------------------------+----------------+
	| INITIATING_CONNECTION                     | no             |
	+-------------------------------------------+----------------+
	| RECEIVING_CONNECTION                      | no             |
	+-------------------------------------------+----------------+
	| COMMUNICATING_AS_MASTER                   | no             |
	+-------------------------------------------+----------------+
	| COMMUNICATING_AS_SLAVE                    | no             |
	+-------------------------------------------+----------------+
	| HCI_MONITORING                            | no             |
	+-------------------------------------------+----------------+

	'''
	sharedMethods = [
		"getFirmwareVersion",
		"getDeviceIndex",
		"getController",

		"sniffNewConnections",
		"isSynchronized",

		"sniffAdvertisements",
		"getAccessAddress",
		"getCrcInit",
		"getChannelMap",
		"getHopInterval",
		"getHopIncrement",

		"setChannel",
		"getChannel",


		"setScan",
		"setScanInterval",

		"attachSubDevice",
		"detachSubDevice",
		"setMitm",
		"setHijacking",
		"getSubInterfaces",
		"getConnections",
		"switchConnection",
		"getCurrentConnection",
		"isConnected"
	]

	def attachSubDevice(self,subDevice,identifier):
		'''
		This method allows to attach a given subdevice to the current ButteRFly device.

		:param subDevice: sub device instance
		:type subDevice: BLEButterflySubdevice
		:param identifier: string indicating if the subdevice communicates as a Master ("master") or as a Slave ("slave")
		:type identifier: str

		.. note::

			This method is called directly by the subdevice, it is not intended to be used directly.

		'''
		if identifier == "master":
			self.subDevices["master"] = subDevice
		elif identifier == "slave":
			self.subDevices["slave"] = subDevice

	def detachSubDevice(self,identifier):
		'''
		This method allows to detach a given subdevice.

		:param identifier: string indicating the subdevice to detach ("master" or "slave")
		:type identifier: str

		.. note::

			This method is called directly by the subdevice, it is not intended to be used directly.

		'''
		self.attachSubDevice(None,identifier)

	def setAccessAddress(self,accessAddress):
		'''
		This method sets the access address to use.

		:param accessAddress: new access address
		:type accessAddress: int

		:Example:

			>>> device.setAccessAddress(0xe5e296e9)


		.. note::

			This method is a **shared method** and can be called from the corresponding Emitters / Receivers.

		'''
		self.accessAddress = accessAddress

	def getAccessAddress(self):
		'''
		This method returns the access address actually in use.

		:return: access address
		:rtype: int

		:Example:

			>>> hex(device.getAccessAddress())
			'0xe5e296e9'


		.. note::

			This method is a **shared method** and can be called from the corresponding Emitters / Receivers.

		'''
		return self.accessAddress

	def getCrcInit(self):
		'''
		This method returns the CRCInit actually in use.

		:return: CRCInit
		:rtype: int

		:Example:

			>>> hex(device.getCrcInit())
			'0x0bd54a'

		.. note::

			This method is a **shared method** and can be called from the corresponding Emitters / Receivers.

		'''
		return self.crcInit

	def getChannelMap(self):
		'''
		This method returns the Channel Map actually in use.

		:return: Channel Map
		:rtype: int

		:Example:

			>>> hex(device.getChannelMap())
			'0x1fffffffff'

		.. note::

			This method is a **shared method** and can be called from the corresponding Emitters / Receivers.


		'''
		return self.channelMap

	def getHopInterval(self):
		'''
		This method returns the Hop Interval actually in use.

		:return: Hop Interval
		:rtype: int

		:Example:

			>>> device.getHopInterval()
			36

		.. note::

			This method is a **shared method** and can be called from the corresponding Emitters / Receivers.


		'''
		return self.hopInterval

	def getHopIncrement(self):
		'''
		This method returns the Hop Increment actually in use.

		:return: Hop Increment
		:rtype: int

		:Example:

			>>> device.getHopIncrement()
			11

		.. note::

			This method is a **shared method** and can be called from the corresponding Emitters / Receivers.

		'''
		return self.hopIncrement


	def setChannel(self,channel=37):
		'''
		This method changes the channel actually in use by the provided channel.

		:param channel: new channel
		:type channel: int

		:Example:

			>>> device.getChannel()
			37
			>>> device.setChannel(channel=38)
			>>> device.getChannel()
			38

		.. note::

			This method is a **shared method** and can be called from the corresponding Emitters / Receivers.

		'''
		self._setChannel(channel)

	def getChannel(self):
		'''
		This method returns the channel actually in use.

		:return: channel in use
		:rtype: int

		:Example:

			>>> device.getChannel()
			37
			>>> device.setChannel(channel=38)
			>>> device.getChannel()
			38

		.. note::

			This method is a **shared method** and can be called from the corresponding Emitters / Receivers.

		'''
		return self._getChannel()

	def setScanInterval(self,seconds=1):
		'''
		This method allows to provide the scan interval (in second).

		:param seconds: number of seconds to wait between two channels
		:type seconds: float

		:Example:

			>>> device.setScanInterval(seconds=1)

		.. note::

			This method is a **shared method** and can be called from the corresponding Emitters / Receivers.

		'''

		self.scanInterval = seconds

	def _scanThread(self):
		self.sniffAdvertisements(channel=37)
		utils.wait(seconds=self.scanInterval)
		self.sniffAdvertisements(channel=38)
		utils.wait(seconds=self.scanInterval)
		self.sniffAdvertisements(channel=39)
		utils.wait(seconds=self.scanInterval)

	def setScan(self,enable=True):
		'''
		This method enables or disables the scanning mode. It allows to change the channel according to the scan interval parameter.

		:param enable: boolean indicating if the scanning mode must be enabled
		:type enable: bool

		:Example:

			>>> device.setScan(enable=True) # scanning mode enabled
			>>> device.setScan(enable=False) # scanning mode disabled

		.. note::

			This method is a **shared method** and can be called from the corresponding Emitters / Receivers.

		'''

		if enable:
			self.sniffAdvertisements()

			if self.scanThreadInstance is None:
				self.scanThreadInstance = wireless.StoppableThread(target=self._scanThread)
				self.scanThreadInstance.start()
		else:
			self.scanThreadInstance.stop()
			self.scanThreadInstance = None

	def restartSniffingMode(self):
		'''
		This method restarts the sniffing mode.

		:Example:

			>>> device.restartSniffingMode()

		.. note::

			This method is a **shared method** and can be called from the corresponding Emitters / Receivers.


		'''
		if self.sniffingMode == BLESniffingMode.NEW_CONNECTION:
			self.sniffNewConnections()
		else:
			io.info("ButteRFly device doesn't implement existing connections sniffing yet.")


	def _setFollowMode(self,mode):
		rsp = self._internalCommand(Butterfly_Set_Follow_Mode_Command(enable="yes" if mode else "no"))
		return rsp.status == 0x00

	def _setFilter(self,address):
		rsp = self._internalCommand(Butterfly_Set_Filter_Command(address=address))
		return rsp.status == 0x00

	def _setChannel(self,channel):
		rsp = self._internalCommand(Butterfly_Set_Channel_Command(channel=channel))
		return rsp.status == 0x00

	def sniffNewConnections(self,address="FF:FF:FF:FF:FF:FF",channel=None):
		'''
		This method starts the new connections sniffing mode.

		:param address: selected address - if not provided, no filter is applied (format : "1A:2B:3C:4D:5E:6F")
		:type address: str
		:param channel: selected channel - if not provided, channel 37 is selected
		:type channel: int

		:Example:

			>>> device.sniffNewConnections()
			>>> device.sniffNewConnections(channel=38)
			>>> device.sniffNewConnections(address="1A:2B:3C:4D:5E:6F")

		.. note::

			This method is a **shared method** and can be called from the corresponding Emitters / Receivers.

		'''
		self.synchronized = False
		self.hijacked = False
		self.sniffingMode = BLESniffingMode.NEW_CONNECTION
		self.lastTarget = address
		self._setChannel(channel)
		self._setFilter(address)
		self._setFollowMode(True)

	def sniffAdvertisements(self,address='FF:FF:FF:FF:FF:FF',channel=None):
		'''
		This method starts the advertisement sniffing mode.

		:param address: selected address - if not provided, no filter is applied (format : "1A:2B:3C:4D:5E:6F")
		:type address: str
		:param channel: selected channel - if not provided, channel 37 is selected
		:type channel: int

		:Example:

			>>> device.sniffAdvertisements()
			>>> device.sniffAdvertisements(channel=38)
			>>> device.sniffAdvertisements(address="1A:2B:3C:4D:5E:6F")

		.. note::

			This method is a **shared method** and can be called from the corresponding Emitters / Receivers.

		'''
		self.synchronized = False
		self.hijacked = False
		self.sniffingMode = BLESniffingMode.ADVERTISEMENT
		self.lastTarget = address
		self._setChannel(channel)
		self._setFilter(address)
		self._setFollowMode(False)

	def _injectPacket(self,packet):
		self.inject = True
		self.currentAttack["attack"] = "injection"
		self.currentAttack["status"] = "launched"
		io.info("Starting injection attack: injecting ...")
		self._internalCommand(Butterfly_Send_Payload_Command(payload_direction=0x00,payload_size=len(raw(packet[BTLE_DATA:])),payload_content=raw(packet[BTLE_DATA:])))
		self._send(Butterfly_Message_Hdr()/Butterfly_Command_Hdr()/Butterfly_Start_Attack_Command(attack=0x01))

	def setHijacking(self,target="master",enable=True):
		'''
		This method allows to enable or disable the hijacking mode.

		:param target: target role to hijack ("master" for master hijacking, "slave" for slave hijacking)
		:type param: str
		:param enable: boolean indicating if the hijacking mode must be enabled or disabled
		:type enable: bool

		:Example:

			>>> device.setHijacking(target="master",enable=True) # master hijacking mode enabled
			>>> device.setHijacking(target="master",enable=False) # master hijacking mode disabled
			>>> device.setHijacking(target="slave",enable=True) # slave hijacking mode enabled
			>>> device.setHijacking(target="slave",enable=False) # slave hijacking mode disabled

		.. note::

			This method is a **shared method** and can be called from the corresponding Emitters / Receivers.

		'''
		if enable:
			if target == "master":
				self.mitmed = False
				self.inject = True
				self.currentAttack["attack"] = "master_hijacking"
				self.currentAttack["status"] = "launched"
				io.info("Starting Master Hijacking attack: injecting LL_CONNECTION_UPDATE_REQ...")
				self._send(Butterfly_Message_Hdr()/Butterfly_Command_Hdr()/Butterfly_Start_Attack_Command(attack=0x03))
			elif target == "slave":
				self.mitmed = False
				self.inject = True
				self.currentAttack["attack"] = "slave_hijacking"
				self.currentAttack["status"] = "launched"
				io.info("Starting Master Hijacking attack: injecting LL_TERMINATE_IND...")
				self._send(Butterfly_Message_Hdr()/Butterfly_Command_Hdr()/Butterfly_Start_Attack_Command(attack=0x02))

	def setMitm(self,enable=True):
		'''
		This method performs a Man-in-the-Middle attack targeting an established connection..

		:param enable: boolean indicating if the mitm mode must be enabled or disabled
		:type enable: bool

		:Example:

			>>> device.setMitm(enable=True) # mitm mode enabled
			>>> device.setMitm(enable=False) # mitm mode disabled

		.. note::

			This method is a **shared method** and can be called from the corresponding Emitters / Receivers.

		'''
		if enable:
			self.mitmed = False
			self.inject = True
			self.currentAttack["attack"] = "MITM"
			self.currentAttack["status"] = "launched"
			io.info("Starting MiTM attack: injecting LL_CONNECTION_UPDATE_REQ...")
			self._send(Butterfly_Message_Hdr()/Butterfly_Command_Hdr()/Butterfly_Start_Attack_Command(attack=0x04))

	def _setAccessAddress(self,accessAddress=None):
		self.accessAddress = accessAddress

	def _setCrcInit(self,crcInit=None):
		self.crcInit = crcInit

	def _setChannelMap(self,channelMap=None):
		self.channelMap = channelMap

	def _setHopInterval(self,hopInterval=None):
		self.hopInterval = hopInterval

	def _getHopInterval(self):
		return self.hopInterval

	def _setHopIncrement(self,hopIncrement):
		self.hopIncrement = hopIncrement

	def _getHopIncrement(self):
		return self.hopIncrement

	def _getChannelMap(self):
		return self.channelMap

	def _getAccessAddress(self):
		return self.accessAddress

	def _getCrcInit(self):
		return self.crcInit

	def _getChannel(self):
		rsp = self._internalCommand(Butterfly_Get_Channel_Command())
		return rsp.channel

	def getSubInterfaces(self):
		'''
		This method returns the interfaces of the available subdevices.

		:return: a tuple of strings linked to the available interfaces
		:rtype: (str,str)

		:Example:

			>>> device.getSubInterfaces()


		.. note::

			This method is a **shared method** and can be called from the corresponding Emitters / Receivers.
		'''
		return self.availableSubInterfaces

	def getCurrentHandle(self):
		'''
		This method returns the connection Handle actually in use.
		If no connection is established, its value is equal to -1.

		:return: connection Handle
		:rtype: int

		.. warning::

			This method always returns 1, it allows to provides the same API as the HCI Device.

		.. note::

			This method is a **shared method** and can be called from the corresponding Emitters / Receivers.

		'''
		return 1


	def getConnections(self):
		'''
		This method returns a list of couple (connection handle / address) representing the connections actually established.
		A connection is described by a dictionary containing an handle and an access address : ``{"handle":1, "address":"0x12345678"}``

		:return: list of connections established
		:rtype: list of dict

		:Example:

			>>> device.getConnections()
			[{'handle':1, 'address':'0x12345678'}]

		.. warning::

			The connection handle is always 1, it allows to provides the same API as the HCI Device.

		.. note::

			This method is a **shared method** and can be called from the corresponding Emitters / Receivers.

		'''
		return [{"address":"0x{:08x}".format(self.accessAddress),"handle":1}]


	def getCurrentConnection(self):
		'''
		This method returns the access address associated to the current connection. If no connection is established, it returns None.

		:return: access address of the current connection
		:rtype: str

		:Example:

			>>> device.getCurrentConnection()
			'0x12345678'

		.. note::

			This method is a **shared method** and can be called from the corresponding Emitters / Receivers.

		'''
		return "0x{:08x}".format(self.accessAddress)


	def switchConnection(self,address):
		'''
		This method is provided in order to provide the same API as an HCI Device, it actually has no effects.

		.. note::

			This method is a **shared method** and can be called from the corresponding Emitters / Receivers.

		'''
		io.fail("Switching connection not allowed with ButteRFly Device !")


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
		return self.hijacked or self.mitmed

	def isSynchronized(self):
		'''
		This method indicates if the sniffer is actually synchronized with a connection.

		:return: boolean indicating if the sniffer is synchronized
		:rtype: bool

		:Example:

			>>> device.isSynchronized()
			True

		.. note::

			This method is a **shared method** and can be called from the corresponding Emitters / Receivers.

		'''
		return self.synchronized

	def recv(self):
		pkt = super().recv()
		if pkt is not None and Butterfly_BLE_Packet in pkt:
			timestamp = pkt.timestamp + self.clockCorrection
			ts_sec = int(timestamp)
			ts_usec = int((timestamp - ts_sec)*1000000)
			if BTLE_CONNECT_REQ in pkt.packet:
				self._setAccessAddress(struct.unpack(">I",struct.pack("<I",pkt.packet.AA))[0])
				self._setCrcInit(struct.unpack(">I",b"\x00" + struct.pack('<I',pkt.packet.crc_init)[:3])[0])
				self._setChannelMap(pkt.packet.chM)
				self._setHopInterval(pkt.packet.interval)
				self._setHopIncrement(pkt.packet.hop)
				self.synchronized = True
			packet = BTLE_PPI(
			btle_channel=pkt.channel,
			btle_clkn_high=ts_sec,
			btle_clk_100ns=ts_usec,
			rssi_max=-pkt.rssi,
			rssi_min=-pkt.rssi,
			rssi_avg=-pkt.rssi,
			rssi_count=1)/pkt.packet

			if self.subDevices["slave"] is not None and pkt.source == 0x01:
				self.subDevices["slave"]._addPacket(packet)
			elif self.subDevices["master"] is not None and pkt.source == 0x02:
				self.subDevices["master"]._addPacket(packet)
			else:
				return packet
		elif pkt is not None and Butterfly_Notification_Hdr in pkt:
			if Butterfly_Connection_Report_Notification in pkt:
				if pkt.status == 0x01:
					io.fail("Connection lost !")
					self.hijacked = False
					self.mitmed = False
					self.synchronized = False
					self.restartSniffingMode()
					self._setAccessAddress(None)
					self._setCrcInit(None)
					self._setChannelMap(None)
					self._setHopInterval(None)
					self._setHopIncrement(None)


				elif pkt.status == 0x02:
					io.info("Attack is running...")
					self.currentAttack["status"] = "running"

				elif pkt.status == 0x03:
					io.success("Attack successful !")
					self.inject = False
					self.currentAttack["status"] = "success"
					if self.currentAttack["attack"] == "MITM":
						io.info("SubInterfaces available: "+self.interface+":sub0 (master) and "+self.interface+":sub1 (slave)")
						self.availableSubInterfaces = (self.interface+":sub0", self.interface+":sub1")
						self.mitmed = True
					elif self.currentAttack["attack"] == "master_hijacking":
						io.info("SubInterface available: "+self.interface+":sub0 (master)")
						self.availableSubInterfaces = (self.interface+":sub0",None)
						self.hijacked = True
					elif self.currentAttack["attack"] == "slave_hijacking":
						io.info("SubInterface available: "+self.interface+":sub1 (slave)")
						self.availableSubInterfaces = (None,self.interface+":sub1")
						self.hijacked = True

				elif pkt.status == 0x04:
					io.fail("Attack failure !")
					self.currentAttack["status"] = "failure"
					self.hijacked = False
					self.synchronized = False

			elif Butterfly_Injection_Report_Notification in pkt:
				if pkt.status == 0x00:
					io.success("Injection successful after "+str(pkt.injection_count)+" attempts !")
					if self.currentAttack["attack"] == "MITM" or self.currentAttack["attack"] == "master_hijacking" :
						io.info("Waiting for connection update instant...")
				else:
					io.fail("Injection failed !")
				self.inject = False
			elif Butterfly_Debug_Notification in pkt:
				io.info("Debug: "+str(pkt.message))
		return None


	def send(self,pkt):
		if Butterfly_Send_Payload_Command in pkt:
			self._internalCommand(pkt)
			self.directions[pkt.payload_direction] = True
		elif self.synchronized:
			self._injectPacket(pkt)

	def init(self):
		super().init()
		if self.ready:
			self.synchronized = False
			self.hijacked = False
			self.mitmed = False
			self.inject = False
			self.clockCorrection = 0.0
			self.currentAttack = {"attack":None,"status":"stopped"}
			self.lastTarget = "FF:FF:FF:FF:FF:FF"
			self.availableSubInterfaces = None
			self.sniffingMode = None
			self.scanThreadInstance = None

			self.subDevices = {"master":None,"slave":None}

			self.setScanInterval()
			self.capabilities = [
						"SNIFFING_NEW_CONNECTION",
						"SNIFFING_ADVERTISEMENTS",
						"SCANNING",
						"MITMING_EXISTING_CONNECTION",
						"HIJACKING_MASTER",
						"HIJACKING_SLAVE"
			]
			# Select BLE controller
			self.selectController("BLE")
			self.enableController()
			io.success("ButteRFly device successfully instantiated !")
