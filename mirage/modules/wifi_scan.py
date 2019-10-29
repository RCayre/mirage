import queue
from mirage.libs import io,wifi,utils
from mirage.core import module

class wifi_scan(module.WirelessModule):
	def init(self):
		self.technology = "wifi"
		self.type = "scan"
		self.description = "Scan module for Wifi Access Point and Stations"
		self.args = {
				"INTERFACE":"wlp2s0",
				"TIME":"14",
				"STATIONS":"yes",
				"ACCESS_POINTS":"yes"
			}
		self.accessPointsQueue = queue.Queue()
		self.stationsQueue = queue.Queue()
		self.accessPoints = {}
		self.stations = {}


	def checkCapabilities(self):
		return self.emitter.hasCapabilities("SCANNING","MONITORING")
	

	def scan(self,packet):
		if isinstance(packet,wifi.WifiProbeResponse) or isinstance(packet,wifi.WifiBeacon):
			ssid = packet.SSID
			address = packet.srcMac
			channel = packet.channel
			self.accessPointsQueue.put({"ssid":ssid,"address":address,"channel":channel})
		elif isinstance(packet,wifi.WifiProbeRequest):
			address = packet.srcMac
			channel = packet.channel
			self.stationsQueue.put({"address":address,"channel":channel})

	def displayAccessPoints(self):
		devices = []
		for ap in self.accessPoints:
			address = ap
			SSID = self.accessPoints[ap]["ssid"]
			channels = ",".join([str(c) for c in self.accessPoints[ap]["channels"]])
			devices.append([address,SSID,channels])
		io.chart(["MAC Address","SSID","Channel"],devices,"Access Point Found") 

	def generateOutput(self):
		output = {}
		count = 1
		for ap in self.accessPoints:
			address = ap
			SSID = self.accessPoints[ap]["ssid"]
			channels = ",".join([str(c) for c in self.accessPoints[ap]["channels"]])
			output["AP_ADDRESS"+str(count)] = address
			output["AP_SSID"+str(count)] = SSID
			output["AP_CHANNELS"+str(count)] = channels
			if count == 1:
				output["AP_ADDRESS"] = ap
				output["AP_SSID"] = SSID
				output["AP_CHANNELS"] = channels
			count += 1
		count = 1
		for sta in self.stations:
			if sta != "FF:FF:FF:FF:FF:FF":
				address = sta
				channels = ",".join([str(c) for c in self.stations[sta]["channels"]])
				output["STATION_ADDRESS"+str(count)] = address
				output["STATION_CHANNELS"+str(count)] = channels
				
				if count == 1:
					output["TARGET"] = address
					output["CHANNELS"] = channels				
				count += 1
		return output

	def displayStations(self):
		devices = []
		for sta in self.stations:
			if sta != "FF:FF:FF:FF:FF:FF":
				address = sta
				channels = ",".join([str(c) for c in self.stations[sta]["channels"]])
				devices.append([address,channels])
		if devices!=[]:
			io.chart(["MAC Address","Channel"],devices,"Stations Found") 

	def updateAccessPoints(self):
		changes = 0
		while not self.accessPointsQueue.empty():
			current = self.accessPointsQueue.get()
			if current["address"] not in self.accessPoints:
				changes += 1
				self.accessPoints[current["address"]] = {"ssid":current["ssid"],"channels":set()}
				self.accessPoints[current["address"]]["channels"].add(current["channel"])
			else:
				if self.accessPoints[current["address"]]["ssid"] != current["ssid"]:
					changes += 1
					self.accessPoints[current["address"]]["ssid"] = current["ssid"]
				if current["channel"] not in self.accessPoints[current["address"]]["channels"]:
					changes += 1
					self.accessPoints[current["address"]]["channels"].add(current["channel"])
		if changes != 0:
			self.displayAccessPoints()

	def updateStations(self):
		changes = 0
		while not self.stationsQueue.empty():
			current = self.stationsQueue.get()
			if current["address"] not in self.stations:
				changes += 1
				self.stations[current["address"]] = {"channels":set()}
				self.stations[current["address"]]["channels"].add(current["channel"])
			elif current["address"]!="FF:FF:FF:FF:FF:FF" and current["channel"] not in self.stations[current["address"]]["channels"]:
				changes += 1
				self.stations[current["address"]]["channels"].add(current["channel"])
		if changes != 0:
			self.displayStations()

	def run(self):
		self.receiver = self.getReceiver(interface=self.args["INTERFACE"])
		self.emitter = self.getEmitter(interface=self.args["INTERFACE"])
		if self.checkCapabilities():
			self.receiver.onEvent("*",callback=self.scan)

			accessPoints = {}
			channel = 0

			for i in range(utils.integerArg(self.args['TIME'])):
				self.receiver.setChannel(channel+1)
				self.emitter.sendp(wifi.WifiProbeRequest(srcMac = 'FF:FF:FF:FF:FF:FF', destMac= 'FF:FF:FF:FF:FF:FF', emitMac = "FF:FF:FF:FF:FF:FF"))
				channel = (channel+1) % 14
				utils.wait(seconds=1)
				if utils.booleanArg(self.args["ACCESS_POINTS"]):
					self.updateAccessPoints()
				if utils.booleanArg(self.args["STATIONS"]):			
					self.updateStations()
			output = self.generateOutput()

			return self.ok(output)
		else:
			io.fail("Interface provided ("+str(self.args["INTERFACE"])+") is not able to scan and run in monitor mode.")
			return self.nok()
	def postrun(self):
		io.info("Disabling monitor mode ...")
		self.receiver.setMonitorMode(enable=False)
