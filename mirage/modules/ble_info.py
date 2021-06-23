from mirage.libs import io,ble,utils
from mirage.core import module

class ble_info(module.WirelessModule):
	def init(self):
		self.technology = "ble"
		self.type = "info"
		self.description = "Information module for Bluetooth Low Energy interface"
		self.args = {
				"INTERFACE":"hci0",
				"SHOW_CAPABILITIES":"yes"
			}
		self.capabilities = [
					"SCANNING",
					"ADVERTISING",
					"SNIFFING_ADVERTISEMENTS",
					"SNIFFING_NEW_CONNECTION",
					"SNIFFING_EXISTING_CONNECTION",
					"JAMMING_CONNECTIONS",
					"JAMMING_ADVERTISEMENTS",
					"HIJACKING_MASTER",
					"HIJACKING_SLAVE",
					"INJECTING",
					"MITMING_EXISTING_CONNECTION",
					"INITIATING_CONNECTION",
					"RECEIVING_CONNECTION",
					"COMMUNICATING_AS_MASTER",
					"COMMUNICATING_AS_SLAVE",
					"HCI_MONITORING"
		]

	def displayCapabilities(self):
		capabilitiesList = []
		for capability in self.capabilities:
			capabilitiesList.append([capability,(io.colorize("yes","green") if self.emitter.hasCapabilities(capability) else io.colorize("no","red"))])
		io.chart(["Capability","Available"],capabilitiesList)

	def run(self):
		self.emitter = self.getEmitter(interface=self.args["INTERFACE"])
		if utils.booleanArg(self.args["SHOW_CAPABILITIES"]):
			self.displayCapabilities()
		if "hcidump" in self.args["INTERFACE"]:
			interface = self.args["INTERFACE"]
			hciInterface = self.emitter.getHCIInterface()
			index = str(self.emitter.getDeviceIndex())
			io.chart(["Interface","Device Index","Monitored HCI Interface"],[[interface,"#"+index,hciInterface]])
			return self.ok({"INTERFACE":interface,
					"INDEX":index,
					"HCI_INTERFACE":hciInterface
					})
		elif "adb" in self.args["INTERFACE"]:
			interface = self.args["INTERFACE"]
			serial = self.emitter.getSerial()
			snoopLocation = self.emitter.getSnoopFileLocation()
			snoopSize = str(self.emitter.getSnoopFileSize())
			index = str(self.emitter.getDeviceIndex())

			io.chart(["Interface","Device Index","Serial number","Snoop Location", "Snoop Size"],
				[[interface,"#"+index,serial,snoopLocation,(snoopSize+" bytes" if snoopSize != "-1" else "unknown")]])
			return self.ok({"INTERFACE":interface,
					"INDEX":index,
					"SERIAL":serial,
					"SNOOP_LOCATION":snoopLocation,
					"SNOOP_SIZE":snoopSize
					})

		elif "butterfly" in self.args["INTERFACE"]:
			interface = self.args["INTERFACE"]
			versionMajor,versionMinor = self.emitter.getFirmwareVersion()
			version = str(versionMajor)+"."+str(versionMinor)
			index = self.emitter.getDeviceIndex()
			controller = self.emitter.getController()
			io.chart(["Interface","Device Index","Version","Controller"],[[interface,("#"+str(index) if isinstance(index,int) else str(index)),version,controller]])
			return self.ok({
					"INTERFACE":interface,
					"INDEX":index,
					"VERSION":version
					})
		elif "sniffle" in self.args["INTERFACE"]:
			interface = self.args["INTERFACE"]
			versionMajor,versionMinor = self.emitter.getFirmwareVersion()
			version = str(versionMajor)+"."+str(versionMinor)
			index = self.emitter.getDeviceIndex()
			io.chart(["Interface","Device Index","Version"],[[interface,("#"+str(index) if isinstance(index,int) else str(index)),version]])
			return self.ok({
					"INTERFACE":interface,
					"INDEX":index,
					"VERSION":version
					})
		elif "hci" in self.args["INTERFACE"]:
			interface = self.args["INTERFACE"]
			address = self.emitter.getAddress()
			mode = self.emitter.getMode()
			manufacturer = self.emitter.getManufacturer()
			changeableAddress = "yes" if self.emitter.isAddressChangeable() else "no"
			io.chart(["Interface","BD Address","Current Mode","Manufacturer","Changeable Address"],
				[[interface, address,mode, manufacturer,changeableAddress]])
			return self.ok({
				"INTERFACE":interface,
				"ADDRESS":address,
				"MODE":mode,
				"MANUFACTURER":manufacturer,
				"CHANGEABLE_ADDRESS":changeableAddress
				})
		elif "ubertooth" in self.args["INTERFACE"]:
			interface = self.args["INTERFACE"]
			mode = self.emitter.getMode()
			version = self.emitter.getFirmwareVersion()
			index = str(self.emitter.getDeviceIndex())
			serial = self.emitter.getSerial()
			io.chart(["Interface","Mode","Device Index","Firmware Version", "Serial Number"],
				[[interface,mode,"#"+index,version,serial]])
			return self.ok({
					"INTERFACE":interface,
					"MODE":mode,
					"SERIAL":serial,
					"INDEX":index,
					"VERSION":version
					})
		elif "microbit" in self.args["INTERFACE"]:
			interface = self.args["INTERFACE"]
			versionMajor,versionMinor = self.emitter.getFirmwareVersion()
			version = str(versionMajor)+"."+str(versionMinor)
			index = self.emitter.getDeviceIndex()
			customFirmware = "yes" if version == "3.14" else "no"
			io.chart(["Interface","Device Index","Version","Custom Firmware"],[[interface,("#"+str(index) if isinstance(index,int) else str(index)),version,customFirmware]])
			return self.ok({
					"INTERFACE":interface,
					"INDEX":index,
					"VERSION":version,
					"CUSTOM_FIRMWARE":customFirmware
					})
		elif "nrfsniffer" in self.args["INTERFACE"]:
			interface = self.args["INTERFACE"]
			version = self.emitter.getFirmwareVersion()
			index = self.emitter.getDeviceIndex()
			io.chart(["Interface","Device Index","Version"],[[interface,("#"+str(index) if isinstance(index,int) else str(index)),version]])
			return self.ok({
					"INTERFACE":interface,
					"INDEX":index,
					"VERSION":version
					})
		elif "hackrf" in self.args["INTERFACE"]:
			interface = self.args["INTERFACE"]
			index = str(self.emitter.getDeviceIndex())
			serial = str(self.emitter.getSerial())
			firmwareVersion = str(self.emitter.getFirmwareVersion())
			apiVersionMajor,apiVersionMinor = self.emitter.getAPIVersion()
			apiVersion = str(apiVersionMajor)+"."+str(apiVersionMinor)
			boardName = self.emitter.getBoardName()
			boardID = str(self.emitter.getBoardID())
			io.chart(["Interface","Device Index","Serial number","Board Name", "Board ID","Firmware Version", "API Version"],[[interface,"#"+index,serial,boardName, boardID,firmwareVersion, apiVersion]])

			return self.ok({"INTERFACE":interface,
					"INDEX":index,
					"SERIAL":serial,
					"FIRMWARE_VERSION":firmwareVersion,
					"API_VERSION":apiVersion,
					"BOARD_NAME":boardName,
					"BOARD_ID":boardID
					})
		elif ".pcap" in self.args["INTERFACE"]:
			interface = self.args["INTERFACE"]
			mode = self.emitter.getMode()
			io.chart(["Interface","Mode"],[[interface,mode]])
			return self.ok({"INTERFACE":interface,
					"MODE":mode
					})

		return self.nok()
