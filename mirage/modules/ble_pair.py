from mirage.libs import io,ble,utils
from mirage.core import module
from os import urandom

class ble_pair(module.WirelessModule):
	def init(self):

		self.technology = "ble"
		self.type = "action"
		self.description = "Pairing module for Bluetooth Low Energy devices"
		self.args = {
				"INTERFACE":"hci0", 
				"MODE":"master",
				"PIN":"",
				"ACTIVE":"yes",
				"LTK":"112233445566778899aabbccddeeff",
				"EDIV":"12",
				"RAND":"1122334455667788",
				"IRK":"",
				"ADDR_TYPE":"",
				"ADDR":"",
				"CSRK":"",
				"KEYBOARD":"yes",
				"YESNO":"yes",
				"DISPLAY":"yes",
				"CT2":"no",
				"MITM":"no",
				"BONDING":"yes",
				"SECURE_CONNECTIONS":"no",
				"KEYPRESS":"no"
			}
		

		self.useOOB = False
		self.checkMitm = False
		self.ioCapabilities = False
		self.justWorks = False

		self.tk = self.stk = b"\x00"*16


		self.pairingRequest = None
		self.pairingResponse = None

		self.responderAddress = None
		self.responderAddressType = None
		self.initiatorAddress = None
		self.initiatorAddressType = None
		self.pReq = None
		self.pRes = None
		self.mRand = None
		self.sRand = None

		self.mConfirm = None
		self.sConfirm = None

		self.failure = False

	def pinToTemporaryKey(self,pin):
		hexn = hex(pin)[2:]
		tk = bytes.fromhex((32-len(hexn))*"0"+hexn)
		return tk

	def keyGeneration(self,size=16):
		return os.urandom(size)

	def pairingMethodSelection(self):
		self.secureConnections = self.responderAuthReq.secureConnections and self.initiatorAuthReq.secureConnections
		if self.secureConnections:
			io.info("Both devices supports LE secure connections")
			self.useOOB = self.pairingRequest.outOfBand and self.pairingResponse.outOfBand
			self.ioCapabilities = self.responderAuthReq.mitm or self.initiatorAuthReq.mitm
			self.justWorks = not self.responderAuthReq.mitm and not self.initiatorAuthReq.mitm

		else:
			io.info("At least one of the devices doesn't support LE secure connections")
			self.useOOB = self.pairingRequest.outOfBand or self.pairingResponse.outOfBand
			self.ioCapabilities = self.responderAuthReq.mitm or self.initiatorAuthReq.mitm
			self.justWorks = not self.responderAuthReq.mitm and not self.initiatorAuthReq.mitm

		io.chart(["Out Of Bond","IO Capabilities", "Just Works"],
		[
		["yes" if self.useOOB else "no",
		"yes" if self.ioCapabilities else "no",
		"yes" if self.justWorks else "no"
		]])

		if self.ioCapabilities:
			initiator = "NoInputNoOutput"
			responder = "NoInputNoOutput"
			if self.initiatorInputOutputCapability.data[0] == 0x00:
				initiator = "DisplayOnly"
			elif self.initiatorInputOutputCapability.data[0] == 0x01:
				initiator = "DisplayYesNo"
			elif self.initiatorInputOutputCapability.data[0] == 0x02:
				initiator = "KeyboardOnly"
			elif self.initiatorInputOutputCapability.data[0] == 0x03:
				initiator = "NoInputNoOutput"
			elif self.initiatorInputOutputCapability.data[0] == 0x04:
				initiator = "KeyboardDisplay"

			if self.responderInputOutputCapability.data[0] == 0x00:
				responder = "DisplayOnly"
			elif self.responderInputOutputCapability.data[0] == 0x01:
				responder = "DisplayYesNo"
			elif self.responderInputOutputCapability.data[0] == 0x02:
				responder = "KeyboardOnly"
			elif self.responderInputOutputCapability.data[0] == 0x03:
				responder = "NoInputNoOutput"
			elif self.responderInputOutputCapability.data[0] == 0x04:
				responder = "KeyboardDisplay"

			pairingMethod = ble.PairingMethods.getPairingMethod(	secureConnections=self.secureConnections,
										initiatorInputOutputCapability=initiator, 											responderInputOutputCapability = responder)

			if pairingMethod == ble.PairingMethods.JUST_WORKS:
				self.pairingMethod = "JustWorks"
			elif pairingMethod == ble.PairingMethods.PASSKEY_ENTRY:
				self.pairingMethod = "PasskeyEntry"
			elif pairingMethod == ble.PairingMethods.NUMERIC_COMPARISON:
				self.pairingMethod = "NumericComparison"
			else:
				self.pairingMethod = "JustWorks"
		elif self.useOOB:
			self.pairingMethod = "OutOfBonds"
		else:
			self.pairingMethod = "JustWorks"

		return self.pairingMethod

	

	def slaveSecurityRequest(self,pkt):
		pkt.show()
		self.pairingRequest.show()
		self.emitter.sendp(self.pairingRequest)


	def slavePairingResponse(self,pkt):

		self.initiatorAddress = self.emitter.getAddress()
		self.initiatorAddressType = b"\x00" if self.emitter.getAddressMode() == "public" else b"\x01"
		self.responderAddress = self.emitter.getCurrentConnection()
		self.responderAddressType = b"\x00" if self.emitter.getCurrentConnectionMode() == "public" else b"\x01"

		pkt.show()
		self.pairingResponse = pkt
		self.pRes = self.pairingResponse.payload[::-1]

		self.responderAuthReq = ble.AuthReqFlag(data = bytes([pkt.authentication]))
		self.responderInputOutputCapability = ble.InputOutputCapability(data = bytes([pkt.inputOutputCapability]))
		self.responderKeyDistribution = ble.KeyDistributionFlag(data=bytes([pkt.responderKeyDistribution]))
		pairingMethod = self.pairingMethodSelection()
		io.success("Pairing Method selected : "+self.pairingMethod)
		

		self.mRand = ble.BLECrypto.generateRandom()
		io.success("Generating random : "+self.mRand.hex())
		
		if pairingMethod == "JustWorks":
			pinCode = 0
		else:
			if self.args["PIN"] != "" and utils.isNumber(self.args["PIN"]):
				pinCode = int(self.args["PIN"])
			else:
				pinCode = int(io.enterPinCode("Enter the 6 digit PIN code: "))

		self.tk = self.pinToTemporaryKey(pinCode)
		io.success("Generating Temporary Key : "+self.tk.hex())
		
		self.mConfirm = ble.BLECrypto.c1(	self.tk,
							self.mRand[::-1], 
							self.pReq,
							self.pRes,
							self.initiatorAddressType,
							self.initiatorAddress,
							self.responderAddressType,
							self.responderAddress)
		io.success("Generating MConfirm : "+self.mConfirm.hex())
		confirmPacket = ble.BLEPairingConfirm(confirm=self.mConfirm[::-1])
		confirmPacket.show()
		self.emitter.sendp(confirmPacket)
			
	def slavePairingConfirm(self,pkt):
		pkt.show()
		self.sConfirm = pkt.confirm[::-1]
		response = ble.BLEPairingRandom(random=self.mRand)
		response.show()
		self.emitter.sendp(response)

	def slavePairingRandom(self,pkt):
		pkt.show()
		self.sRand = pkt.random
		sConfirm = ble.BLECrypto.c1(	self.tk,
						self.sRand[::-1],
						self.pReq,
						self.pRes,
						self.initiatorAddressType,
						self.initiatorAddress,
						self.responderAddressType,
						self.responderAddress)
		if self.sConfirm == sConfirm:
			io.success("Confirm Value correct !")
			self.stk = ble.BLECrypto.s1(self.tk,self.mRand[::-1], self.sRand[::-1])
			io.success("Generating Short Term Key (STK): "+self.stk.hex())
			self.encrypted = self.emitter.encryptLink(ltk=self.stk[::-1])
			if self.encrypted:
				io.success("Encryption enabled !")
			else:
				io.fail("Encryption not enabled !")
		else:
			io.fail("Confirm value failed ! Terminating ...")
			self.failure = True


	def pairingFailed(self,pkt):
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

	def slavePairingFailed(self,pkt):
		self.failure = True
		io.fail("Pairing Failed received : "+str(pkt))
		self.pairingFailed(pkt)

	def encryptionInformation(self,pkt):
		pkt.show()
		io.success("Long Term Key (LTK) received : "+pkt.ltk[::-1].hex())


	def masterIdentification(self,pkt):
		pkt.show()
		io.success("EDIV and RAND received :  "+hex(pkt.ediv)+" / "+pkt.rand.hex())

	def identityAddressInformation(self,pkt):
		pkt.show()
		io.success("Address received : "+str(pkt.address)+" ("+pkt.type+")")

	def identityInformation(self,pkt):
		pkt.show()
		io.success("IRK received :  "+pkt.irk[::-1].hex())

	def signingInformation(self,pkt):
		pkt.show()
		io.success("CSRK received :  "+pkt.csrk[::-1].hex())


	def masterEncryptionInformation(self,pkt):
		self.encryptionInformation(pkt)

	def masterMasterIdentification(self,pkt):
		self.masterIdentification(pkt)


	def masterIdentityAddressInformation(self,pkt):
		self.identityAddressInformation(pkt)


	def masterIdentityInformation(self,pkt):
		self.identityInformation(pkt)

	def masterSigningInformation(self,pkt):
		self.signingInformation(pkt)


	def slaveEncryptionInformation(self,pkt):
		self.encryptionInformation(pkt)

	def slaveMasterIdentification(self,pkt):
		self.masterIdentification(pkt)
		if not self.responderKeyDistribution.idKey and not self.responderKeyDistribution.signKey:
			self.keyDistribution(type="initiator")
			self.finished = True

	def slaveIdentityAddressInformation(self,pkt):
		self.identityAddressInformation(pkt)
		if not self.responderKeyDistribution.signKey:
			self.keyDistribution(type="initiator")
			self.finished = True

	def slaveIdentityInformation(self,pkt):
		self.identityInformation(pkt)

	def slaveSigningInformation(self,pkt):
		self.signingInformation(pkt)
		self.keyDistribution(type="initiator")
		self.finished = True


	def masterPairingRequest(self,pkt):
		self.initiatorAddress = self.emitter.getCurrentConnection()
		self.initiatorAddressType = b"\x00" if self.emitter.getCurrentConnectionMode() == "public" else b"\x01"
		self.responderAddress = self.emitter.getAddress()
		self.responderAddressType = b"\x00" if self.emitter.getAddressMode() == "public" else b"\x01"

		pkt.show()
		self.pairingRequest = pkt
		self.pReq = self.pairingRequest.payload[::-1]

		self.initiatorAuthReq = ble.AuthReqFlag(data = bytes([pkt.authentication]))
		self.initiatorInputOutputCapability = ble.InputOutputCapability(data = bytes([pkt.inputOutputCapability]))
		self.initiatorKeyDistribution = ble.KeyDistributionFlag(data=bytes([pkt.initiatorKeyDistribution]))


		keyboard = utils.booleanArg(self.args["KEYBOARD"])
		yesno = utils.booleanArg(self.args["YESNO"])
		display = utils.booleanArg(self.args["DISPLAY"])

		ct2 = utils.booleanArg(self.args["CT2"])
		mitm = utils.booleanArg(self.args["MITM"])
		bonding = utils.booleanArg(self.args["BONDING"])
		secureConnections = utils.booleanArg(self.args["SECURE_CONNECTIONS"])
		keyPress = utils.booleanArg(self.args["KEYPRESS"])			

		linkKey = False
		encKey = self.args["LTK"] != "" and self.args["EDIV"] != "" and self.args["RAND"] != ""
		idKey = self.args["IRK"] != "" and self.args["ADDR"] != "" and self.args["ADDR_TYPE"]
		signKey = self.args["CSRK"] != ""


		self.responderInputOutputCapability = ble.InputOutputCapability(keyboard=keyboard,display=display,yesno=yesno)
		self.responderAuthReq = ble.AuthReqFlag(ct2=ct2,mitm=mitm,bonding=bonding,secureConnections=secureConnections,keypress=keyPress)
		self.responderKeyDistribution = ble.KeyDistributionFlag(linkKey=linkKey,encKey=encKey,idKey=idKey,signKey=signKey)

		self.pairingResponse = ble.BLEPairingResponse(
							authentication=self.responderAuthReq.data[0],
							inputOutputCapability=self.responderInputOutputCapability.data[0],
							initiatorKeyDistribution=self.responderKeyDistribution.data[0],
							responderKeyDistribution=self.responderKeyDistribution.data[0]
							)
		self.pairingResponse.show()
		self.pRes = self.pairingResponse.payload[::-1]
		pairingMethod = self.pairingMethodSelection()
		io.success("Pairing Method selected : "+self.pairingMethod)
		self.emitter.sendp(self.pairingResponse)

	def masterPairingConfirm(self,pkt):
		pkt.show()
		self.mConfirm = pkt.confirm[::-1]

		self.sRand = ble.BLECrypto.generateRandom()
		io.success("Generating random : "+self.sRand.hex())
		
		if self.pairingMethod == "JustWorks":
			pinCode = 0
		else:
			if self.args["PIN"] != "" and utils.isNumber(self.args["PIN"]):
				pinCode = int(self.args["PIN"])
			else:
				pinCode = int(io.enterPinCode("Enter the 6 digit PIN code: "))

		self.tk = self.pinToTemporaryKey(pinCode)

		io.success("Generating Temporary Key : "+self.tk.hex())

		
		self.sConfirm = ble.BLECrypto.c1(	self.tk,
							self.sRand[::-1], 
							self.pReq,
							self.pRes,
							self.initiatorAddressType,
							self.initiatorAddress,
							self.responderAddressType,
							self.responderAddress)

		io.success("Generating SConfirm : "+self.sConfirm.hex())
		confirmPacket = ble.BLEPairingConfirm(confirm=self.sConfirm[::-1])
		confirmPacket.show()
		self.emitter.sendp(confirmPacket)

	def masterPairingRandom(self,pkt):
		pkt.show()
		self.mRand = pkt.random

		response = ble.BLEPairingRandom(random=self.sRand)
		self.emitter.sendp(response)

		mConfirm = ble.BLECrypto.c1(	self.tk,
						self.mRand[::-1],
						self.pReq,
						self.pRes,
						self.initiatorAddressType,
						self.initiatorAddress,
						self.responderAddressType,
						self.responderAddress)
		if self.mConfirm == mConfirm:
			io.success("Confirm Value correct !")
			self.stk = ble.BLECrypto.s1(self.tk,self.mRand[::-1], self.sRand[::-1])
			io.success("Generating Short Term Key (STK): "+self.stk.hex())
		else:
			io.fail("Confirm value failed ! Terminating ...")
			self.failure = True
	
	def masterPairingFailed(self,pkt):
		self.failure = True
		io.fail("Pairing Failed received : "+str(pkt))
		self.pairingFailed(pkt)



	
	def keyDistribution(self,type="initiator"):
		if type == "initiator":
			keyDistribution = self.initiatorKeyDistribution
		else:
			keyDistribution = self.responderKeyDistribution
		if keyDistribution.encKey:
			io.info("Sending LTK...")
			self.emitter.sendp(ble.BLEEncryptionInformation(ltk=bytes.fromhex(self.args["LTK"])[::-1]))
			self.emitter.sendp(ble.BLEMasterIdentification(
									ediv=utils.integerArg(self.args["EDIV"]),
									rand=bytes.fromhex(self.args["RAND"])
									))
			io.success("Sent !")
		if keyDistribution.idKey:
			io.info("Sending IRK...")
			self.emitter.sendp(ble.BLEIdentityInformation(irk=bytes.fromhex(self.args["IRK"])[::-1]))
			self.emitter.sendp(ble.BLEIdentityAddressInformation(
									address=utils.addressArg(self.args["ADDR"]),
									type=self.args["ADDR_TYPE"].lower()
									))
			io.success("Sent !")

		if keyDistribution.signKey:
			io.info("Sending CSRK...")
			self.emitter.sendp(ble.BLESigningInformation(csrk=bytes.fromhex(self.args["CSRK"])[::-1]))
			io.success("Sent !")

	def masterLongTermKeyRequest(self,pkt):
		pkt.show()
		if pkt.ediv == 0 and pkt.rand == b"\x00"*8 and self.stk != b"\x00" * 8:
			self.emitter.sendp(ble.BLELongTermKeyRequestReply(positive=True, ltk=self.stk[::-1]))
			self.keyDistribution(type="responder")
		

		elif pkt.ediv == utils.integerArg(self.args["EDIV"]) and pkt.rand == bytes.fromhex(self.args["RAND"]):
			self.emitter.sendp(ble.BLELongTermKeyRequestReply(positive=True, ltk=bytes.fromhex(self.args["LTK"])[::-1]))
		else:
			self.emitter.sendp(ble.BLELongTermKeyRequestReply(positive=False))

	def run(self):
		self.finished = False
		interface = self.args["INTERFACE"]
		self.emitter = self.getEmitter(interface=interface)
		self.receiver = self.getReceiver(interface=interface)

		if not self.emitter.isConnected() and utils.booleanArg(self.args["ACTIVE"]):
			io.fail("A connection must be established.")
			return self.nok()


		if self.args["MODE"].lower() == "master":
	
			keyboard = utils.booleanArg(self.args["KEYBOARD"])
			yesno = utils.booleanArg(self.args["YESNO"])
			display = utils.booleanArg(self.args["DISPLAY"])

			ct2 = utils.booleanArg(self.args["CT2"])
			mitm = utils.booleanArg(self.args["MITM"])
			bonding = utils.booleanArg(self.args["BONDING"])
			secureConnections = utils.booleanArg(self.args["SECURE_CONNECTIONS"])
			keyPress = utils.booleanArg(self.args["KEYPRESS"])			

			linkKey = False
			encKey = self.args["LTK"] != "" and self.args["EDIV"] != "" and self.args["RAND"] != ""
			idKey = self.args["IRK"] != "" and self.args["ADDR"] != "" and self.args["ADDR_TYPE"]
			signKey = self.args["CSRK"] != ""

			self.initiatorInputOutputCapability = ble.InputOutputCapability(keyboard=keyboard,display=display,yesno=yesno)
			self.initiatorAuthReq = ble.AuthReqFlag(ct2=ct2,mitm=mitm,bonding=bonding,secureConnections=secureConnections,keypress=keyPress)
			self.initiatorKeyDistribution = ble.KeyDistributionFlag(linkKey=linkKey,encKey=encKey,idKey=idKey,signKey=signKey)

			self.pairingRequest = ble.BLEPairingRequest(
								authentication=self.initiatorAuthReq.data[0],
								inputOutputCapability=self.initiatorInputOutputCapability.data[0],
								initiatorKeyDistribution=self.initiatorKeyDistribution.data[0],
								responderKeyDistribution=self.initiatorKeyDistribution.data[0]
								)

			self.pReq = self.pairingRequest.payload[::-1]
			self.receiver.onEvent("BLESecurityRequest",callback=self.slaveSecurityRequest)
			self.receiver.onEvent("BLEPairingResponse", callback=self.slavePairingResponse)
			self.receiver.onEvent("BLEPairingConfirm", callback=self.slavePairingConfirm)
			self.receiver.onEvent("BLEPairingRandom",callback=self.slavePairingRandom)
			self.receiver.onEvent("BLEPairingFailed",callback=self.slavePairingFailed)
			self.receiver.onEvent("BLEEncryptionInformation",callback=self.slaveEncryptionInformation)
			self.receiver.onEvent("BLEMasterIdentification",callback=self.slaveMasterIdentification)	
			self.receiver.onEvent("BLEIdentityInformation",callback=self.slaveIdentityInformation)
			self.receiver.onEvent("BLEIdentityAddressInformation",callback=self.slaveIdentityAddressInformation)
			self.receiver.onEvent("BLESigningInformation",callback=self.slaveSigningInformation)

			if utils.booleanArg(self.args["ACTIVE"]):
				self.pairingRequest.show()
				self.emitter.sendp(self.pairingRequest)

				while not self.finished and not self.failure:
					utils.wait(seconds=1)

				if self.failure:
					return self.nok()

			return self.ok()
		else:

			self.receiver.onEvent("BLEPairingRequest", callback=self.masterPairingRequest)
			self.receiver.onEvent("BLEPairingConfirm", callback=self.masterPairingConfirm)
			self.receiver.onEvent("BLEPairingRandom", callback=self.masterPairingRandom)
			self.receiver.onEvent("BLELongTermKeyRequest", callback=self.masterLongTermKeyRequest)
			self.receiver.onEvent("BLEPairingFailed", callback=self.masterPairingFailed)
			self.receiver.onEvent("BLEEncryptionInformation",callback=self.masterEncryptionInformation)
			self.receiver.onEvent("BLEMasterIdentification",callback=self.masterMasterIdentification)	
			self.receiver.onEvent("BLEIdentityInformation",callback=self.masterIdentityInformation)
			self.receiver.onEvent("BLEIdentityAddressInformation",callback=self.masterIdentityAddressInformation)
			self.receiver.onEvent("BLESigningInformation",callback=self.masterSigningInformation)	
				


			ct2 = utils.booleanArg(self.args["CT2"])
			mitm = utils.booleanArg(self.args["MITM"])
			bonding = utils.booleanArg(self.args["BONDING"])
			secureConnections = utils.booleanArg(self.args["SECURE_CONNECTIONS"])
			keyPress = utils.booleanArg(self.args["KEYPRESS"])

			authReq = ble.AuthReqFlag(ct2=ct2,mitm=mitm,bonding=bonding,secureConnections=secureConnections,keypress=keyPress)

			if utils.booleanArg(self.args["ACTIVE"]):
				securityRequest = ble.BLESecurityRequest(authentication=authReq.data[0])	
				securityRequest.show()
				self.emitter.sendp(securityRequest)

			return self.ok({"INTERFACE":self.args["INTERFACE"]})
