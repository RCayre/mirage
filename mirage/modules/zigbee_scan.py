from mirage.libs import io,zigbee,utils
from mirage.core import module
import sys

class zigbee_scan(module.WirelessModule):
	def init(self):
		self.type = "scan"
		self.technology = "zigbee"
		self.description = "Scan module for Zigbee Devices"
		self.args = {
				"INTERFACE":"rzusbstick0",
				"TIME":"10",
				"START_CHANNEL":"11",
				"END_CHANNEL":"26",
				"ACTIVE":"yes"
			}
		self.devices = {}

	def checkCapabilities(self):
		return self.emitter.hasCapabilities("SNIFFING", "INJECTING")

	def displayDevices(self):
		if utils.integerArg(self.args["START_CHANNEL"]) != utils.integerArg(self.args["END_CHANNEL"]):
			sys.stdout.write(" "*100+"\r")
		columnsNames = ["Pan ID","Channel","Association permitted","Nodes"]
		networks = []
		nodes = ""
		for panID,network in self.devices.items():
			for node,role in network["nodes"].items():
				nodes += zigbee.addressToString(node)+"("+role+")"+"\n"
			networks.append([hex(panID),str(network["channel"]),"yes" if network["associationPermitted"] else ("unknown" if network["associationPermitted"] is None else "no"),nodes[:-1]])
		io.chart(columnsNames,networks)

	def updateDevices(self,packet):
		changes = 0

		if isinstance(packet,zigbee.ZigbeeBeacon):
			if packet.srcPanID not in self.devices:
				changes += 1
				self.devices[packet.srcPanID] = {"channel":self.receiver.getChannel(),"associationPermitted":packet.assocPermit,"nodes":{packet.srcAddr:"coordinator" if packet.coordinator else "router"}}
			else:
				role = "unknown"
				if packet.coordinator:
					role = "coordinator"
				elif packet.routerCapacity:
					role = "router"
				else:
					role = "end device"
				if packet.srcAddr not in self.devices[packet.srcPanID]["nodes"] or role != self.devices[packet.srcPanID]["nodes"][packet.srcAddr]:
					changes += 1
					self.devices[packet.srcPanID]["nodes"][packet.srcAddr] = role
		elif (hasattr(packet,"srcPanID") or hasattr(packet,"destPanID")) and hasattr(packet,"srcAddr"):
			panID = packet.srcPanID if hasattr(packet,"srcPanID") else packet.destPanID
			if panID not in self.devices:
				changes += 1
				self.devices[panID] = {"channel":self.receiver.getChannel(),"associationPermitted":None,"nodes":{packet.srcAddr:"unknown"}}
			elif packet.srcAddr not in self.devices[panID]["nodes"]:
				changes += 1
				self.devices[panID]["nodes"][packet.srcAddr] = "unknown"
		if changes > 0:
			self.displayDevices()

	def generateOutput(self):
		output = {}
		networkCount = 1
		deviceCount = 1
		for panID,network in self.devices.items():
			output["NETWORK_PANID"+str(networkCount)] = "0x"+'{:04x}'.format(panID).upper()
			output["NETWORK_CHANNEL"+str(networkCount)] = str(network["channel"])
			output["NETWORK_ASSOC_PERMIT"+str(networkCount)] = "yes" if network["associationPermitted"] else "no"
			for node,role in network["nodes"].items():
				if role == "coordinator":
					output["NETWORK_COORDINATOR"+str(networkCount)] = zigbee.addressToString(node)
				output["DEVICE_ADDR"+str(deviceCount)] = zigbee.addressToString(node)
				output["DEVICE_ROLE"+str(deviceCount)] = role
				output["DEVICE_CHANNEL"+str(deviceCount)] = str(network["channel"])
				output["DEVICE_PANID"+str(deviceCount)] = "0x"+'{:04x}'.format(panID).upper()

				if deviceCount == 1:
					output["TARGET"] = zigbee.addressToString(node)
					output["TARGET_PANID"] = "0x"+'{:04x}'.format(panID).upper()
					output["CHANNEL"] = str(network["channel"])

				deviceCount += 1
			networkCount += 1

		return self.ok(output)
			
	def run(self):
		self.receiver = self.getReceiver(interface=self.args["INTERFACE"])
		self.emitter = self.getEmitter(interface=self.args["INTERFACE"])
		if self.checkCapabilities():
			self.receiver.onEvent("*",callback=self.updateDevices)

			start = utils.now()
			startChannel = utils.integerArg(self.args["START_CHANNEL"])
			endChannel = utils.integerArg(self.args["END_CHANNEL"])

			numberOfChannels = endChannel+1 - startChannel

			channels = list(range(startChannel,endChannel+1))
			i = 0
			while self.args["TIME"] == "" or utils.now() - start < utils.integerArg(self.args["TIME"]):
				if startChannel != endChannel:
					io.progress(i,total=numberOfChannels,suffix="Channel: "+(" " if len(str(channels[i]))==1 else "")+str(channels[i]))
				self.receiver.setChannel(channels[i])
				if utils.booleanArg(self.args["ACTIVE"]):
					self.emitter.sendp(zigbee.ZigbeeBeaconRequest(sequenceNumber=1,destPanID=0xFFFF,destAddr=0xFFFF))
				utils.wait(seconds=0.1)
				i = (i + 1) % len(channels)

			if startChannel != endChannel:
				sys.stdout.write(" "*100+"\r")
			if len(self.devices) == 0:
				return self.nok()
			else:
				return self.generateOutput()
		else:
			io.fail("Interface provided ("+str(self.args["INTERFACE"])+") is not able to sniff and inject frames.")
			return self.nok()
