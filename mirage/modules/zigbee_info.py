from mirage.libs import io,zigbee,utils
from mirage.core import module

class zigbee_info(module.WirelessModule):
	def init(self):
		self.technology = "zigbee"
		self.type = "info"
		self.description = "Information module for Zigbee interface"
		self.args = {
				"INTERFACE":"rzusbstick0",
				"SHOW_CAPABILITIES":"yes"
			}
		self.capabilities = ["SNIFFING","INJECTING","JAMMING","COMMUNICATING_AS_COORDINATOR","COMMUNICATING_AS_ROUTER","COMMUNICATING_AS_END_DEVICE"]

	def displayCapabilities(self):
		capabilitiesList = []
		for capability in self.capabilities:
			capabilitiesList.append([capability,(io.colorize("yes","green") if self.emitter.hasCapabilities(capability) else io.colorize("no","red"))])
		io.chart(["Capability","Available"],capabilitiesList)

	def run(self):
		self.emitter = self.getEmitter(interface=self.args["INTERFACE"])

		if utils.booleanArg(self.args["SHOW_CAPABILITIES"]):		
			self.displayCapabilities()

		if "rzusbstick" in self.args["INTERFACE"]:
			interface = self.args["INTERFACE"]
			index = str(self.emitter.getDeviceIndex())
			serial = str(self.emitter.getSerial())
			firmwareVersion = str(self.emitter.getFirmwareVersion())
			mode = str(self.emitter.getMode())
			io.chart(["Interface","Device Index","Serial number","Firmware Version", "Mode"],[[interface,"#"+index,serial, firmwareVersion, mode]])

			return self.ok({"INTERFACE":interface,
					"INDEX":index,
					"SERIAL":serial,
					"FIRMWARE_VERSION":firmwareVersion,
					"MODE":mode
					})
		elif ".pcap" in self.args["INTERFACE"]:
			interface = self.args["INTERFACE"]
			mode = self.emitter.getMode()
			io.chart(["Interface","Mode"],[[interface,mode]])
			return self.ok({"INTERFACE":interface,
					"MODE":mode
					})
		return self.nok()
					
