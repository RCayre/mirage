from mirage.libs import io,wifi,utils
from mirage.core import module

class wifi_info(module.WirelessModule):
	def init(self):
		self.technology = "wifi"
		self.type = "info"
		self.description = "Information module for Wifi interface"
		self.args = {
				"INTERFACE":"wlan0",
				"SHOW_CAPABILITIES":"yes"
			}
		self.capabilities = ["SCANNING","MONITORING","COMMUNICATING_AS_ACCESS_POINT","COMMUNICATING_AS_STATION","JAMMING"]

	def displayCapabilities(self):
		capabilitiesList = []
		for capability in self.capabilities:
			capabilitiesList.append([capability,(io.colorize("yes","green") if self.emitter.hasCapabilities(capability) else io.colorize("no","red"))])
		io.chart(["Capability","Available"],capabilitiesList)

	def run(self):
		self.emitter = self.getEmitter(interface=self.args["INTERFACE"])
		if utils.booleanArg(self.args["SHOW_CAPABILITIES"]):
			self.displayCapabilities()
		interface = self.args["INTERFACE"]
		address = self.emitter.getAddress()
		mode = self.emitter.getMode()
		channel = self.emitter.getChannel()
		io.chart(["Interface","MAC Address","Mode","Channel"],[[interface, address,mode,channel]])
		return self.ok({
				"INTERFACE":interface,
				"ADDRESS":address,
				"MODE":mode,
				"CHANNEL":channel
				})
