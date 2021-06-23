from mirage.libs import io,utils,ble
from mirage.core import module

class ble_sniff(module.WirelessModule):
	def init(self):
		self.technology = "ble"
		self.type = "sniff"
		self.description = "Sniffing module for Bluetooth Low Energy devices"
		self.args = {
				"INTERFACE":"microbit0",
				"INTERFACEA":"",
				"INTERFACEB":"",
				"SNIFFING_MODE":"newConnections", # existingConnections , advertisements
				"TARGET":"",
				"CHANNEL":"37",
				"PCAP_FILE":"",
				"HIJACKING_MASTER":"no",
				"HIJACKING_SLAVE":"no",
				"MITMING":"no",
				"JAMMING":"no",
				"ACCESS_ADDRESS":"",
				"CRC_INIT":"",
				"CHANNEL_MAP":"",
				"LTK":"",
				"CRACK_KEY":"no",
				"SWEEPING":"no",
				"SCENARIO":""

			}
		# Security Manager related
		self.pReq = None
		self.pRes = None
		self.initiatorAddress = None
		self.initiatorAddressType = None
		self.responderAddress = None
		self.responderAddressType = None
		self.mRand = None
		self.mConfirm = None
		self.sRand = None
		self.sConfirm = None

		self.failure = False
		self.pin = None
		self.temporaryKey = None
		self.shortTermKey = None

	# Scenario-related methods
	@module.scenarioSignal("onStart")
	def startScenario(self):
		pass

	@module.scenarioSignal("onEnd")
	def endScenario(self):
		pass

	@module.scenarioSignal("onPacket")
	def onPacket(self,pkt):
		io.displayPacket(pkt)


	def errorDuringCracking(self):
		missingData = False
		if self.pReq is None:
			io.fail("Missing Pairing Request !")
			missingData = True
		if self.pRes is None:
			io.fail("Missing Pairing Response !")
			missingData = True
		if (	self.initiatorAddress is None or
			self.initiatorAddressType is None or
			self.responderAddress is None or
			self.responderAddressType is None	):
			io.fail("Missing address !")
			missingData = True
		if self.mRand is None:
			io.fail("Missing Master Random !")
			missingData = True
		if self.mConfirm is None:
			io.fail("Missing Master Confirm !")
			missingData = True
		if not missingData:
			io.fail("Temporary Key not found, collected values are probably corrupted.")

	def sweepingParameter(self):
		parameter = self.args["SWEEPING"]
		sweepingSequence = []
		if parameter.upper() in ("YES","1","TRUE"):
			sweepingSequence = [37,38,39]
			return (True, sweepingSequence)
		elif parameter.upper() in ("NO","0","FALSE"):
			return (False,sweepingSequence)
		else:
			if all(int(i) in (37,38,39) for i in parameter.split(",")):
				for i in parameter.split(","):
					sweepingSequence.append(int(i))
				return (True,sweepingSequence)
			else:
				return (False,sweepingSequence)

	def crackTemporaryKey(self):
		m = utils.loadModule("ble_crack")
		if ( 	self.mRand is not None and
			self.pReq is not None and
			self.pRes is not None and
			self.initiatorAddressType is not None and
			self.initiatorAddress is not None and
			self.responderAddressType is not None and
			self.responderAddress is not None and
			self.mConfirm is not None	):

			m["MASTER_RAND"] = self.mRand.hex()
			m["PAIRING_REQUEST"] = self.pReq.hex()
			m["PAIRING_RESPONSE"] = self.pRes.hex()
			m["INITIATOR_ADDRESS_TYPE"] = self.initiatorAddressType
			m["INITIATOR_ADDRESS"] = self.initiatorAddress
			m["RESPONDER_ADDRESS_TYPE"] = self.responderAddressType
			m["RESPONDER_ADDRESS"] = self.responderAddress
			m["MASTER_CONFIRM"] = self.mConfirm.hex()

			output = m.execute()
			if output["success"]:
				self.pin = int(output["output"]["PIN"])
				self.temporaryKey = bytes.fromhex(output["output"]["TEMPORARY_KEY"])
				return True

		return False



	def show(self,packet):
		advMode = self.args["SNIFFING_MODE"].upper() == "advertisements".upper()
		isAnAdv =  isinstance(packet, ble.BLEAdvertisement)
		isAnEmpty = isinstance(packet,ble.BLEEmptyPDU)
		unknownInName = "Unknown" in packet.name
		isConnectReq = isinstance(packet,ble.BLEConnectRequest)
		addressMatching = (    isConnectReq
				   and packet.addr == utils.addressArg(self.args["TARGET"])
				   or  self.args["TARGET"] == ""
				   or  (hasattr(packet,"addr") and packet.addr == utils.addressArg(self.args["TARGET"])))
		if (
			(not advMode and (not isAnAdv or isConnectReq) and not isAnEmpty and not unknownInName)
			 or (advMode and isAnAdv and addressMatching)
		   ):
			self.onPacket(packet)
			if self.pcap is not None:
				self.pcap.sendp(packet)

			if utils.booleanArg(self.args["CRACK_KEY"]):
				if isConnectReq:
					self.initiatorAddress = packet.srcAddr
					self.initiatorAddressType = packet.srcAddrType
					self.responderAddress = packet.dstAddr
					self.responderAddressType = packet.dstAddrType

				if isinstance(packet, ble.BLEPairingRequest):
					self.pReq = packet.payload[::-1]
				if isinstance(packet,ble.BLEPairingResponse):
					self.pRes = packet.payload[::-1]
				if isinstance(packet,ble.BLEPairingConfirm) and self.mConfirm is None:
					self.mConfirm = packet.confirm[::-1]

				if isinstance(packet,ble.BLEPairingRandom) and self.mRand is not None and self.sRand is None:
					self.sRand = packet.random[::-1]
					while self.temporaryKey is None and not self.failure:
						pass
					if self.failure:
						self.errorDuringCracking()
					else:
						io.info("Derivating Short Term Key ...")
						self.shortTermKey = ble.BLECrypto.s1(self.temporaryKey,self.mRand,self.sRand)[::-1]
						io.success("Short Term Key found : "+ self.shortTermKey.hex())
						ble.BLELinkLayerCrypto.provideLTK(self.shortTermKey)

				if isinstance(packet,ble.BLEPairingRandom) and self.mRand is None:
					self.mRand = packet.random[::-1]
					self.failure = not self.crackTemporaryKey()

	def checkAdvertisementsCapabilities(self):
		return all([receiver.hasCapabilities("SNIFFING_ADVERTISEMENTS") for receiver in self.receivers])

	def checkNewConnectionCapabilities(self):
		return all([receiver.hasCapabilities("SNIFFING_NEW_CONNECTION") for receiver in self.receivers])

	def checkExistingConnectionCapabilities(self):
		return all([receiver.hasCapabilities("SNIFFING_EXISTING_CONNECTION") for receiver in self.receivers])

	def checkMitmingCapabilities(self):
		return all([receiver.hasCapabilities("MITMING_EXISTING_CONNECTION") for receiver in self.receivers])

	def checkHijackingMasterCapabilities(self):
		return all([receiver.hasCapabilities("HIJACKING_MASTER") for receiver in self.receivers])

	def checkHijackingSlaveCapabilities(self):
		return all([receiver.hasCapabilities("HIJACKING_SLAVE") for receiver in self.receivers])

	def checkJammingCapabilities(self):
		return all([receiver.hasCapabilities("JAMMING_CONNECTIONS") for receiver in self.receivers])


	def initEmittersAndReceivers(self):
		self.emitters = []
		self.receivers = []
		if self.args["INTERFACE"] != "" and self.args["INTERFACE"] != self.args["INTERFACEA"]:
			interface = self.args["INTERFACE"]
			self.emitters.append(self.getEmitter(interface=interface))
			self.receivers.append(self.getReceiver(interface=interface))
		if self.args["INTERFACEA"] != ""  and self.args["INTERFACEB"] != self.args["INTERFACEA"]:
			interfacea  = self.args["INTERFACEA"]
			self.emitters.append(self.getEmitter(interface=interfacea))
			self.receivers.append(self.getReceiver(interface=interfacea))
		if self.args["INTERFACEB"] != "" and self.args["INTERFACEB"] != self.args["INTERFACE"]:
			interfaceb  = self.args["INTERFACEB"]
			self.emitters.append(self.getEmitter(interface=interfaceb))
			self.receivers.append(self.getReceiver(interface=interfaceb))

	def displayConnection(self,index=0):
		aa = "0x{:8x}".format(self.receivers[index].getAccessAddress())
		crcInit = "0x{:6x}".format(self.receivers[index].getCrcInit())
		channelMap = "0x{:10x}".format(self.receivers[index].getChannelMap())
		hopInterval = int(self.receivers[index].getHopInterval())
		hopIncrement = int(self.receivers[index].getHopIncrement())
		io.chart(["Access Address", "CRCInit", "Channel Map", "Hop Interval", "Hop Increment"],[[aa,crcInit,channelMap,hopInterval,hopIncrement]],"Sniffed Connection")

	def sniffExistingConnections(self, receiver,accessAddress, crcInit, channelMap):
		if utils.booleanArg(self.args["JAMMING"]):
			receiver.setJamming(enable=True)
		if utils.booleanArg(self.args["HIJACKING_MASTER"]):
			receiver.setHijacking(target="master",enable=True)
		receiver.sniffExistingConnections(accessAddress,crcInit,channelMap )
		if not utils.booleanArg(self.args["HIJACKING_MASTER"]):
			receiver.onEvent("*", callback=self.show)
		while not receiver.isSynchronized():
			utils.wait(seconds=0.001)
		self.displayConnection()

		if utils.booleanArg(self.args["HIJACKING_MASTER"]):
			io.info("Hijacking in progress ...")
			while not receiver.isConnected():
				utils.wait(seconds=0.001)
			receiver.removeCallbacks()
			return self.ok({"INTERFACE":receiver.interface})
		else:
			while receiver.isSynchronized():
				utils.wait(seconds=0.001)
			return self.ok()

	def sniffNewConnections(self,target, channel):
		if self.pcap is not None:
			self.pcap.sniffNewConnections(address=target, channel=channel)
		if len(self.receivers) == 1:
			enabled,sweepingSequence = self.sweepingParameter()
			if enabled:
				self.receivers[0].setSweepingMode(enable=True,sequence=sweepingSequence)
			self.receivers[0].sniffNewConnections(address=target, channel=channel)
			self.receivers[0].onEvent("*", callback=self.show)
		elif len(self.receivers) == 2:
			self.receivers[0].sniffNewConnections(address=target,channel=37)
			self.receivers[1].sniffNewConnections(address=target,channel=38)
			self.receivers[0].onEvent("*", callback=self.show)
			self.receivers[1].onEvent("*", callback=self.show)

		elif len(self.receivers) == 3:
			self.receivers[0].sniffNewConnections(address=target,channel=37)
			self.receivers[1].sniffNewConnections(address=target,channel=38)
			self.receivers[2].sniffNewConnections(address=target,channel=39)
			self.receivers[0].onEvent("*", callback=self.show)
			self.receivers[1].onEvent("*", callback=self.show)
			self.receivers[2].onEvent("*", callback=self.show)
		else:
			io.fail("No sniffer detected !")
			return self.nok()
		while all([not receiver.isSynchronized() for receiver in self.receivers]):
			utils.wait(seconds=0.001)
		for receiver in self.receivers:
			if receiver.isSynchronized():
				self.displayConnection(self.receivers.index(receiver))
				if ("microbit" in receiver.interface and
					(utils.booleanArg(self.args["HIJACKING_MASTER"]) or utils.booleanArg(self.args["JAMMING"]))):
					receiver.removeCallbacks()
					return self.sniffExistingConnections(
						receiver,
						receiver.getAccessAddress(),
						receiver.getCrcInit(),
						receiver.getChannelMap()
						)
				if "butterfly" in receiver.interface and utils.booleanArg(self.args["MITMING"]):
					io.info("Attack started in 7 seconds...")
					utils.wait(seconds=7)
					receiver.setMitm(enable=True)
					while not receiver.isConnected() and receiver.isSynchronized():
						utils.wait(seconds=0.001)
					if receiver.isSynchronized():
						receiver.removeCallbacks()
						masterInterface,slaveInterface = receiver.getSubInterfaces()
						return self.ok({"INTERFACE1":masterInterface,"INTERFACE2":slaveInterface,"MITM_STRATEGY":"injection"})
					else:
						return self.nok()
				if "butterfly" in receiver.interface and utils.booleanArg(self.args["HIJACKING_SLAVE"]):
					io.info("Attack started in 5 seconds...")
					utils.wait(seconds=5)
					receiver.setHijacking(target="slave",enable=True)
					while not receiver.isConnected() and receiver.isSynchronized():
						utils.wait(seconds=0.001)
					if receiver.isSynchronized():
						receiver.removeCallbacks()
						_,slaveInterface = receiver.getSubInterfaces()

						return self.ok({"INTERFACE":slaveInterface})
					else:
						return self.nok()


				if "butterfly" in receiver.interface and utils.booleanArg(self.args["HIJACKING_MASTER"]):
					io.info("Attack started in 5 seconds...")
					utils.wait(seconds=5)
					receiver.setHijacking(target="master",enable=True)
					while not receiver.isConnected() and receiver.isSynchronized():
						utils.wait(seconds=0.001)
					if receiver.isSynchronized():
						receiver.removeCallbacks()
						masterInterface,_ = receiver.getSubInterfaces()

						return self.ok({"INTERFACE":masterInterface})
					else:
						return self.nok()

		while all([receiver.isSynchronized() for receiver in self.receivers]):
			utils.wait(seconds=0.05)
		utils.wait(seconds=1)
		return self.ok()

	def sniffAdvertisements(self,target, channel):

		if len(self.receivers) == 1:
			enabled,sweepingSequence = self.sweepingParameter()
			if enabled:
				self.receivers[0].setSweepingMode(enable=True,sequence=sweepingSequence)
			self.receivers[0].sniffAdvertisements(address=target, channel=channel)
			self.receivers[0].onEvent("*", callback=self.show)
		elif len(self.receivers) == 2:
			self.receivers[0].sniffAdvertisements(address=target,channel=37)
			self.receivers[1].sniffAdvertisements(address=target,channel=38)
			self.receivers[0].onEvent("*", callback=self.show)
			self.receivers[1].onEvent("*", callback=self.show)

		elif len(self.receivers) == 3:
			self.receivers[0].sniffAdvertisements(address=target,channel=37)
			self.receivers[1].sniffAdvertisements(address=target,channel=38)
			self.receivers[2].sniffAdvertisements(address=target,channel=39)
			self.receivers[0].onEvent("*", callback=self.show)
			self.receivers[1].onEvent("*", callback=self.show)
			self.receivers[2].onEvent("*", callback=self.show)
		else:
			io.fail("No sniffer detected !")
			return self.nok()
		while True:
			utils.wait(seconds=0.01)
	def run(self):
		if self.args["PCAP_FILE"] != "":
			self.pcap = self.getEmitter(self.args["PCAP_FILE"])
		else:
			self.pcap = None
		self.initEmittersAndReceivers()

		if self.args["LTK"] != "":
			ble.BLELinkLayerCrypto.provideLTK(bytes.fromhex(self.args["LTK"]))

		if utils.booleanArg(self.args["HIJACKING_MASTER"]) and not self.checkHijackingMasterCapabilities():
			io.fail("Interfaces provided are not able to hijack a master role.")
			return self.nok()
		if utils.booleanArg(self.args["HIJACKING_SLAVE"]) and not self.checkHijackingSlaveCapabilities():
			io.fail("Interfaces provided are not able to hijack a slave role.")
			return self.nok()
		if utils.booleanArg(self.args["MITMING"]) and not self.checkMitmingCapabilities():
			io.fail("Interfaces provided are not able to MITM an established connection.")
			return self.nok()
		if utils.booleanArg(self.args["JAMMING"]) and not self.checkJammingCapabilities():
			io.fail("Interfaces provided are not able to jam a connection.")
			return self.nok()

		if self.args["SNIFFING_MODE"] not in ("newConnections", "advertisements", "existingConnections"):
			io.fail("You have to set SNIFFING_MODE parameters to: 'newConnections', 'advertisements' or 'existingConnections'")
			return self.nok()

		if self.args["SNIFFING_MODE"].upper() == "newConnections".upper():
			if self.checkNewConnectionCapabilities():
				target = "FF:FF:FF:FF:FF:FF" if self.args["TARGET"] == "" else utils.addressArg(self.args["TARGET"])

				if self.loadScenario():
					io.info("Scenario loaded !")
					self.startScenario()
				result = self.sniffNewConnections(target, utils.integerArg(self.args["CHANNEL"]))
				if self.scenarioEnabled:
					self.endScenario()
				return result
			else:
				io.fail("Interfaces provided are not able to sniff new connections.")
				return self.nok()

		elif self.args["SNIFFING_MODE"].upper() == "existingConnections".upper():
			if self.checkExistingConnectionCapabilities():

				if self.loadScenario():
					io.info("Scenario loaded !")
					self.startScenario()
				accessAddress = utils.integerArg(self.args["ACCESS_ADDRESS"]) if self.args["ACCESS_ADDRESS"]!="" else None
				crcInit = utils.integerArg(self.args["CRC_INIT"]) if self.args["CRC_INIT"]!="" else None
				channelMap = utils.integerArg(self.args["CHANNEL_MAP"]) if self.args["CHANNEL_MAP"]!="" else None
				result = self.sniffExistingConnections(self.receivers[0], accessAddress, crcInit, channelMap)
				if self.scenarioEnabled:
					self.endScenario()
				return result
			else:
				io.fail("Interfaces provided are not able to sniff existing connections.")
				return self.nok()

		elif self.args["SNIFFING_MODE"].upper() == "advertisements".upper():
			if self.checkAdvertisementsCapabilities():
				if self.loadScenario():
					io.info("Scenario loaded !")
					self.startScenario()
				target = "FF:FF:FF:FF:FF:FF" if self.args["TARGET"] == "" else utils.addressArg(self.args["TARGET"])
				result = self.sniffAdvertisements(target, utils.integerArg(self.args["CHANNEL"]))
				if self.scenarioEnabled:
					self.endScenario()
				return result
			else:
				io.fail("Interfaces provided are not able to sniff advertisements.")
				return self.nok()
		return self.ok()
