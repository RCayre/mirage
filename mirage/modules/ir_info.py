from mirage.libs import io,ir,utils
from mirage.core import module

class ir_info(module.WirelessModule):
	def init(self):
		self.technology = "ir"
		self.type = "info"
		self.description = "Information module for IR interface"
		self.args = {
				"INTERFACE":"irma0",
				"SHOW_CAPABILITIES":"yes"
			}
		self.capabilities = ["INJECTING", "SNIFFING","CHANGING_FREQUENCY"]

	def displayCapabilities(self):
		capabilitiesList = []
		for capability in self.capabilities:
			capabilitiesList.append([capability,(io.colorize("yes","green") if self.emitter.hasCapabilities(capability) else io.colorize("no","red"))])
		io.chart(["Capability","Available"],capabilitiesList)

	def run(self):
		self.emitter = self.getEmitter(interface=self.args["INTERFACE"])

		if utils.booleanArg(self.args["SHOW_CAPABILITIES"]):		
			self.displayCapabilities()

		if "irma" in self.args["INTERFACE"]:
			interface = self.args["INTERFACE"]
			index = str(self.emitter.getDeviceIndex())
			port = self.emitter.getSerialPort()
			frequency = str(self.emitter.getFrequency())
			io.chart(["Interface","Device Index","Serial Port","Frequency"],[[interface,"#"+index,port,frequency+" kHz"]])

			return self.ok({"INTERFACE":interface,
					"INDEX":index,
					"PORT":port,
					"FREQUENCY":frequency
					})

		return self.nok()
					
