from mirage.libs import io,mosart,utils
from mirage.core import module

class mosart_info(module.WirelessModule):
	def init(self):
		self.technology = "mosart"
		self.type = "info"
		self.description = "Information module for Mosart interface"
		self.args = {
				"INTERFACE":"rfstorm0",
				"SHOW_CAPABILITIES":"yes"
			}
		self.capabilities = ["INJECTING", "INJECTING_SYNC", "SNIFFING_PROMISCUOUS", "SNIFFING_NORMAL"]

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
					
