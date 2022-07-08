from mirage.core import scenario
from mirage.libs import io,ble,bt,utils,wireless
from mirage.libs.common import parsers
from subprocess import check_output
from socket import gethostname

class ble_basic_slave(scenario.Scenario):

	def enableAdvertising(self):
		advertisementServices = (
			ble.UUID(UUID16=0x180F).data[::-1]+ # Battery Service
			ble.UUID(UUID16=0x180A).data[::-1] # Device Information Service
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
		self.emitter.setScanningParameters(bytes([1+len(self.device_name), 0x09]) + self.device_name + data)


		self.emitter.setAdvertising(enable=True)

	def initializeDeviceInformationService(self):
		self.server.addPrimaryService(ble.UUID(name="Device Information").data)
		self.server.addCharacteristic(ble.UUID(name="Manufacturer Name String").data,self.device_name)
		self.server.addCharacteristic(ble.UUID(name="PnP ID").data,bytes.fromhex("014700ffffffff"))

	def initializeBatteryService(self):
		self.server.addPrimaryService(ble.UUID(name="Battery Service").data)
		self.server.addCharacteristic(ble.UUID(name="Battery Level").data,b"0000000000")
		self.server.addDescriptor(ble.UUID(name="Client Characteristic Configuration").data,b"\x01\x00")
		self.server.addDescriptor(ble.UUID(name="Characteristic Presentation Format").data,b"\x04\x00\xad\x27\x01\x00\x00")

	def initializeServices(self):
		self.initializeDeviceInformationService()
		self.initializeBatteryService()
		self.module.show("gatt")


	def onStart(self):
		self.device_name = gethostname().encode()+b"_"+check_output("ifconfig").split()[5]
		self.emitter = self.module.emitter
		self.receiver = self.module.receiver
		self.server = self.module.server
		self.enableAdvertising()
		self.initializeServices()
		return True
