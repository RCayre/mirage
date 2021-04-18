from mirage.core import module
from mirage.libs import io, utils
from mirage.libs.bt import BluetoothEmitter, BluetoothReceiver
from mirage.libs.bt_utils.packets import BluetoothInquiry, BluetoothInquiryComplete, BluetoothInquiryScanResult


class bt_scan(module.Module):
	def init(self):
		self.technology = "bluetooth"
		self.type = "scan"
		self.description = "Scan module for Bluetooth Devices"
		self.args = {
				"INTERFACE":"hci1",
				"TIME":"10"
			}

		self.devices = {}

	def displayDevices(self):
		devices = []
		for address in self.devices:
			devices.append([address, hex(self.devices[address]['classOfDevice']), self.devices[address]['rssi'], self.devices[address]['data'][:26].hex()+"[...]"])
		io.chart(["Address","Class Of Device", "RSSI", "Data"],devices,"Devices found")

	def updateDevices(self,packet):
		changes = 0
		if packet.address not in self.devices:
			changes += 1
			self.devices[packet.address] = {"classOfDevice":packet.classOfDevice,"rssi":packet.rssi,"data":packet.getRawDatas()}
		else:
			if self.devices[packet.address]["rssi"] != packet.rssi:
				changes += 1
				self.devices[packet.address]["rssi"] = packet.rssi
			if self.devices[packet.address]["classOfDevice"] != packet.classOfDevice:
				changes += 1
				self.devices[packet.address]["classOfDevice"] = packet.classOfDevice
			if self.devices[packet.address]["data"] != packet.getRawDatas():
				changes += 1
				self.devices[packet.address]["data"] = packet.getRawDatas()
		if changes > 0:
			self.displayDevices()

	def run(self):
		self.emitter = BluetoothEmitter(interface=self.args['INTERFACE'])
		self.receiver = BluetoothReceiver(interface=self.args['INTERFACE'])
		time = utils.integerArg(self.args['TIME'])
		self.emitter.sendp(BluetoothInquiry(inquiryLength=time))
		
		scanning = True
		while scanning:
			packet = self.receiver.next()
			if isinstance(packet,BluetoothInquiryComplete):
				scanning = False
			elif isinstance(packet,BluetoothInquiryScanResult):
				self.updateDevices(packet)
				
		return self.ok()
