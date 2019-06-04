from mirage.libs import io,ble,utils
from mirage.core import module

class ble_adv(module.WirelessModule):
	def init(self):

		self.technology = "ble"
		self.type = "spoofing"
		self.description = "Spoofing module simulating a Bluetooth Low Energy advertiser"
		self.args = {
				"INTERFACE":"hci0",
				"ADVERTISING_TYPE":"ADV_IND",
				"ADVERTISING_DATA":"",
				"SCANNING_DATA":"",
				"ADVERTISING_ADDRESS":"",
				"DESTINATION_ADDRESS":"",
				"ADVERTISING_ADDRESS_TYPE":"public", 
				"DESTINATION_ADDRESS_TYPE":"public", 
				"INTERVAL_MIN":"200", 
				"INTERVAL_MAX":"210",
				"ENABLE":"yes", 
				"TIME":"0"
			}

	def checkCapabilities(self):
		return self.emitter.hasCapabilities("ADVERTISING")
	
	def run(self):
		interface = self.args["INTERFACE"]
		self.emitter = self.getEmitter(interface=interface)
		if self.checkCapabilities():
			if self.emitter.isConnected():
				self.emitter.sendp(ble.BLEDisconnect())
			while self.emitter.isConnected():
				utils.wait(seconds=0.01)
			address = (self.emitter.getAddress()	if self.args["ADVERTISING_ADDRESS"] == ""
								else utils.addressArg(self.args["ADVERTISING_ADDRESS"]))
			if address != self.emitter.getAddress():
				self.emitter.setAddress(address)

			if utils.isHexadecimal(self.args["SCANNING_DATA"]):
				scanningData = bytes.fromhex(self.args["SCANNING_DATA"])
			else:
				scanningData = b""

			if utils.isHexadecimal(self.args["ADVERTISING_DATA"]):
				advertisingData = bytes.fromhex(self.args["ADVERTISING_DATA"])
			else:
				advertisingData = b""

			destAddress = ("00:00:00:00:00:00"	if self.args["DESTINATION_ADDRESS"] == ""
								else utils.addressArg(self.args["DESTINATION_ADDRESS"]))

			intervalMin = utils.integerArg(self.args["INTERVAL_MIN"])
			intervalMax = utils.integerArg(self.args["INTERVAL_MAX"])

			advertisingType = self.args["ADVERTISING_TYPE"].upper()

			advertisingAddressType = "public" if self.args["ADVERTISING_ADDRESS_TYPE"].lower() == "public" else "random"
			destinationAddressType = "public" if self.args["DESTINATION_ADDRESS_TYPE"].lower() == "public" else "random"
			self.emitter.setScanningParameters(data = scanningData)
			self.emitter.setAdvertisingParameters(
								type = advertisingType,
								destAddr = destAddress,
								data = advertisingData,
								intervalMin = intervalMin,
								intervalMax = intervalMax,
								daType=advertisingAddressType,
								oaType=destinationAddressType
								)
			self.emitter.setAdvertising(enable=utils.booleanArg(self.args["ENABLE"]))
			time = utils.integerArg(self.args['TIME']) if self.args["TIME"] != "" else -1

			while time != 0:
				utils.wait(seconds=1)
				time -= 1
			return self.ok({"INTERFACE":self.args["INTERFACE"]})
		else:
			io.fail("Interface provided ("+str(self.args["INTERFACE"])+") is not able to send advertisements.")
			return self.nok()
