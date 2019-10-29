from mirage.libs import io,utils,wifi
from mirage.core import module

class wifi_rogueap(module.WirelessModule):
	def init(self):
		self.technology = "wifi"
		self.type = "spoofing"
		self.description = "Spoofing module simulating a fake Access Point"
		self.args = {
				"INTERFACE":"wlan0",
				"SSID":"mirage_fakeap",
				"CHANNEL":"8",
				"CYPHER":"OPN"
			}


	def checkCapabilities(self):
		return self.emitter.hasCapabilities("COMMUNICATING_AS_ACCESS_POINT","MONITORING")
	
	def probeResponse(self,packet):
		self.emitter.sendp(wifi.WifiProbeResponse(destMac = packet.srcMac,beaconInterval=100, SSID = self.args["SSID"],cypher=self.args["CYPHER"]))
		io.info("Incoming Probe Request from : "+packet.srcMac)
		io.info("Answering...")

	def run(self):
		self.receiver = self.getReceiver(interface=self.args["INTERFACE"])
		self.emitter = self.getEmitter(interface=self.args["INTERFACE"])
		if self.checkCapabilities():
			self.receiver.onEvent("WifiProbeRequest",callback=self.probeResponse)
			
			self.emitter.setChannel(utils.integerArg(self.args["CHANNEL"]))
			while True:
				self.emitter.sendp(wifi.WifiBeacon(SSID=self.args["SSID"],cypher=self.args["CYPHER"]))
				utils.wait(seconds=0.1)
			return self.ok()
		else:
			io.fail("Interface provided ("+str(self.args["INTERFACE"])+") is not able to communicate as an access point and run in monitor mode.")
			return self.nok()
