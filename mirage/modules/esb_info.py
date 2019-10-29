from mirage.libs import io,esb,utils
from mirage.core import module

class esb_info(module.WirelessModule):
	def init(self):
		self.technology = "esb"
		self.type = "info"
		self.description = "Information module for Enhanced ShockBurst interface"
		self.args = {
				"INTERFACE":"rfstorm0",
				"SHOW_CAPABILITIES":"yes"
			}
		self.capabilities = ["INJECTING", "SNIFFING_NORMAL", "SNIFFING_PROMISCUOUS", "SNIFFING_GENERIC_PROMISCUOUS", "ACTIVE_SCANNING"]

	def displayCapabilities(self):
		capabilitiesList = []
		for capability in self.capabilities:
			capabilitiesList.append([capability,(io.colorize("yes","green") if self.emitter.hasCapabilities(capability) else io.colorize("no","red"))])
		io.chart(["Capability","Available"],capabilitiesList)

	def run(self):
		self.emitter = self.getEmitter(interface=self.args["INTERFACE"])

		if utils.booleanArg(self.args["SHOW_CAPABILITIES"]):		
			self.displayCapabilities()

		if "rfstorm" in self.args["INTERFACE"]:
			interface = self.args["INTERFACE"]
			mode = self.emitter.getMode()
			index = str(self.emitter.getDeviceIndex())
			io.chart(["Interface","Device Index","Mode"],[[interface,"#"+index,mode]])

			return self.ok({"INTERFACE":interface,
					"INDEX":index,
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
					
