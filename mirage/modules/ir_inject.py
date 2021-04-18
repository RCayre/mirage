from mirage.core import module
from mirage.libs import io, utils
from mirage.libs.ir_utils.packets import IRAiwaPacket,\
	IRDenonPacket,\
	IRDishPacket,\
	IRJVCPacket,\
	IRLGPacket,\
	IRMitsubishiPacket,\
	IRNECPacket,\
	IRPacket,\
	IRPanasonicPacket,\
	IRRC5Packet,\
	IRRC6Packet,\
	IRSamsungPacket,\
	IRSanyoPacket,\
	IRSharpPacket,\
	IRSonyPacket,\
	IRWhynterPacket


class ir_inject(module.WirelessModule):
	def init(self):
		self.technology = "ir"
		self.type = "action"
		self.description = "Injection module for IR signals"
		self.args = {
				"INTERFACE":"irma0",
				"DATA":"",
				"PROTOCOL":"",
				"CODE":"", 
				"CODE_SIZE":"",
				"FREQUENCY":"38"
			}

	def checkCapabilities(self):
		return self.emitter.hasCapabilities("SNIFFING", "CHANGING_FREQUENCY")

	def run(self):
		self.emitter = self.getEmitter(interface=self.args["INTERFACE"])
		if self.checkCapabilities():
			frequency = self.emitter.getFrequency()
			if frequency != utils.integerArg(self.args["FREQUENCY"]):
				self.emitter.setFrequency(utils.integerArg(self.args["FREQUENCY"]))
			
			if self.args["CODE"] != "" and utils.isHexadecimal(self.args["CODE"]):
				code = self.args["CODE"]
				if "0x" == self.args["CODE"][:2]:
					code = self.args["CODE"][2:]
				code = bytes.fromhex(code)
				if self.args["PROTOCOL"].upper() == "NEC":
					packet = IRNECPacket(code=code, size=utils.integerArg(self.args["CODE_SIZE"]))
				elif self.args["PROTOCOL"].upper() == "SONY":
					packet = IRSonyPacket(code=code, size=utils.integerArg(self.args["CODE_SIZE"]))
				elif self.args["PROTOCOL"].upper() == "RC5":
					packet = IRRC5Packet(code=code, size=utils.integerArg(self.args["CODE_SIZE"]))
				elif self.args["PROTOCOL"].upper() == "RC6":
					packet = IRRC6Packet(code=code, size=utils.integerArg(self.args["CODE_SIZE"]))
				elif self.args["PROTOCOL"].upper() == "DISH":
					packet = IRDishPacket(code=code, size=utils.integerArg(self.args["CODE_SIZE"]))
				elif self.args["PROTOCOL"].upper() == "SHARP":
					packet = IRSharpPacket(code=code, size=utils.integerArg(self.args["CODE_SIZE"]))
				elif self.args["PROTOCOL"].upper() == "JVC":
					packet = IRJVCPacket(code=code, size=utils.integerArg(self.args["CODE_SIZE"]))
				elif self.args["PROTOCOL"].upper() == "SANYO":
					packet = IRSanyoPacket(code=code, size=utils.integerArg(self.args["CODE_SIZE"]))
				elif self.args["PROTOCOL"].upper() == "MITSUBISHI":
					packet = IRMitsubishiPacket(code=code, size=utils.integerArg(self.args["CODE_SIZE"]))
				elif self.args["PROTOCOL"].upper() == "SAMSUNG":
					packet = IRSamsungPacket(code=code, size=utils.integerArg(self.args["CODE_SIZE"]))
				elif self.args["PROTOCOL"].upper() == "LG":
					packet = IRLGPacket(code=code, size=utils.integerArg(self.args["CODE_SIZE"]))
				elif self.args["PROTOCOL"].upper() == "WHYNTER":
					packet = IRWhynterPacket(code=code, size=utils.integerArg(self.args["CODE_SIZE"]))
				elif self.args["PROTOCOL"].upper() == "AIWA":
					packet = IRAiwaPacket(code=code, size=utils.integerArg(self.args["CODE_SIZE"]))
				elif self.args["PROTOCOL"].upper() == "PANASONIC":
					packet = IRPanasonicPacket(code=code, size=utils.integerArg(self.args["CODE_SIZE"]))
				elif self.args["PROTOCOL"].upper() == "DENON":
					packet = IRDenonPacket(code=code, size=utils.integerArg(self.args["CODE_SIZE"]))
				else:
					io.fail("Unknown protocol !")
					return self.nok()
				io.info("Injecting ...")
				self.emitter.sendp(packet)
				utils.wait(seconds=1)
				io.success("Injection done !")
				return self.ok()

			elif self.args["DATA"] != "":
				data = [int(i) for i in utils.listArg(self.args["DATA"])]
				packet = IRPacket(data=data)

				io.info("Injecting ...")
				self.emitter.sendp(packet)
				utils.wait(seconds=1)
				io.success("Injection done !")
				return self.ok()

			else:
				io.fail("Incorrect parameters !")
				return self.nok()
		else:
			io.fail("Interface provided ("+str(self.args["INTERFACE"])+") is not able to inject IR signals.")			
			return self.nok()			
