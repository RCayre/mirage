from mirage.libs import io,bt
from mirage.core import module

class bt_info(module.Module):
	def init(self):
		self.technology = "bluetooth"
		self.type = "info"
		self.description = "Information module for Bluetooth interface"
		self.args = {
				"INTERFACE":"hci0"
			}

	def run(self):
		self.emitter = bt.BluetoothEmitter(interface=self.args["INTERFACE"])
		interface = self.args["INTERFACE"]
		address = self.emitter.getAddress()
		localName = self.emitter.getLocalName()
		manufacturer = self.emitter.getManufacturer()
		changeableAddress = "yes" if self.emitter.isAddressChangeable() else "no"
		io.chart(["Interface","BD Address","Local Name","Manufacturer","Changeable Address"],
			[[interface, address,localName,manufacturer,changeableAddress]])
		return self.ok({
				"INTERFACE":interface,
				"ADDRESS":address,
				"LOCAL_NAME":localName,
				"MANUFACTURER":manufacturer,
				"CHANGEABLE_ADDRESS":changeableAddress
				})
