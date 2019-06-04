import queue
from mirage.libs import io,ble,utils
from mirage.core import module

class ble_scan(module.WirelessModule):
	def init(self):
		self.technology = "ble"
		self.type = "scan"
		self.description = "Scan module for Bluetooth Low Energy devices"
		self.args = {
				"INTERFACE":"hci0",
				"TARGET":"",
				"TIME":"20"
			}
		self.devicesQueue = queue.Queue()
		self.devices = {}

	def checkCapabilities(self):
		return self.receiver.hasCapabilities("SCANNING")

	def scan(self,packet):
		if packet.type in ("SCAN_RSP","ADV_IND"):
			localName = ""
			company = ""
			flags = ""
			address = packet.addr
			data = packet.getRawDatas().hex()
			for part in packet.data:
				if hasattr(part,"local_name"):
					localName = part.local_name.decode('ascii','ignore').replace("\0", "")
				elif hasattr(part, "company_id"):
					company = ble.AssignedNumbers.getCompanyByNumber(int(part.company_id))
					if company is None:
						company = ""
				elif hasattr(part,"flags"):
					flags = ble.AssignedNumbers.getStringsbyFlags(part.flags)
			#print ({"address":address,"name":localName,"company":company, "flags":flags,"data":data})
			self.devicesQueue.put({"address":address,"name":localName,"company":company, "flags":flags,"data":data, "pType":packet.type})

	def updateDevices(self):
		changes = 0
		while not self.devicesQueue.empty():
			device = self.devicesQueue.get()
			if (self.args["TARGET"] == "" or utils.addressArg(self.args["TARGET"])==device["address"]):
				if device["address"] not in self.devices:
					changes += 1
					self.devices[device["address"]] = {
						"name":device["name"],
						"company":device["company"],
						"flags":device["flags"],
						"ADV_IND_data":device["data"] if device["pType"]=="ADV_IND" else "",
						"SCAN_RSP_data":device["data"] if device["pType"]=="SCAN_RSP" else ""
						}
				else:
					if self.devices[device["address"]]["name"] != device["name"] and device["name"]!="":
						changes += 1
						self.devices[device["address"]]["name"] = device["name"]
					if self.devices[device["address"]]["company"] != device["company"]  and device["company"]!="":
						changes += 1
						self.devices[device["address"]]["company"] = device["company"]
					if self.devices[device["address"]]["ADV_IND_data"] != device["data"] and device["data"]!="" and device["pType"]=="ADV_IND":
						changes += 1
						self.devices[device["address"]]["ADV_IND_data"] = device["data"]
					if self.devices[device["address"]]["SCAN_RSP_data"] != device["data"] and device["data"]!="" and device["pType"]=="SCAN_RSP":
						changes += 1
						self.devices[device["address"]]["SCAN_RSP_data"] = device["data"]
					if self.devices[device["address"]]["flags"] != device["flags"] and len(device["flags"])>=len(self.devices[device["address"]]["flags"]):
						changes += 1
						self.devices[device["address"]]["flags"] = device["flags"]
		if changes > 0:
			self.displayDevices()

	def displayDevices(self):
		devices = [] 
		for address,device in self.devices.items():
			adv_data=device["ADV_IND_data"]+" (ADV_IND)" if device["ADV_IND_data"]!="" else ""
			if device["ADV_IND_data"]!="" and device["SCAN_RSP_data"]!="":
				adv_data+="\n"
			adv_data+=device["SCAN_RSP_data"]+" (SCAN_RSP)" if device["SCAN_RSP_data"]!="" else ""
			devices.append([address,device["name"],device["company"], ",".join(device["flags"]), adv_data])
		io.chart(["BD Address", "Name", "Company", "Flags","Advertising data"], devices, "Devices found")

	def generateOutput(self):
		output = {}
		if len(self.devices) == 0:
			output = {}
		elif len(self.devices) == 1:
			output = {
					"ADVERTISING_ADDRESS":list(self.devices.keys())[0],
					"TARGET":list(self.devices.keys())[0],
					"ADVERTISING_DATA":list(self.devices.values())[0]["ADV_IND_data"],
					"SCANNING_DATA":list(self.devices.values())[0]["SCAN_RSP_data"]
				}
		else:
			counter = 1
			for address,device in self.devices.items():
				output.update({"ADVERTISING_ADDRESS"+str(counter):address,"ADVERTISING_DATA"+str(counter):device["ADV_IND_data"],"SCANNING_DATA"+str(counter):device["SCAN_RSP_data"]})
				counter += 1
		return self.ok(output)

	def run(self):
		self.receiver = self.getReceiver(interface=self.args["INTERFACE"])
		if self.checkCapabilities():
			self.receiver.onEvent("BLEAdvertisement",callback=self.scan)
			time = utils.integerArg(self.args['TIME']) if self.args["TIME"] != "" else -1
			self.receiver.setScan(enable=True)
			while time != 0:
				utils.wait(seconds=1)
				time -= 1
				self.updateDevices()
			self.receiver.setScan(enable=False)
			return self.generateOutput()
		else:
			io.fail("Interface provided ("+self.args["INTERFACE"]+") is not able to scan.")
			return self.nok()
