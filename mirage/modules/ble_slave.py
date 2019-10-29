import configparser,os.path,subprocess
from mirage.libs import io,utils,ble
from mirage.core import module,interpreter

class ble_slave(module.WirelessModule,interpreter.Interpreter):
	def init(self):
		self.technology = "ble"
		self.type = "spoofing"
		self.description = "Spoofing module simulating a Bluetooth Low Energy slave"
		self.dependencies = ["ble_adv","ble_pair"]
		self.args = {
				"INTERFACE":"hci0",
				"ATT_FILE":"", 
				"GATT_FILE":"",
				"SCENARIO":""
			}
		self.dynamicArgs = True

	def checkCapabilities(self):
		return self.receiver.hasCapabilities("COMMUNICATING_AS_SLAVE", "RECEIVING_CONNECTION")

	def prerun(self):
		interpreter.Interpreter.__init__(self)
		self.availableCommands += ["clear","show","load","notification","disconnect","advertising","address","pairing"]
		self.updatePrompt()


	def fileExists(self,filename):
		return os.path.isfile(filename)

	def updatePrompt(self,address=""):
		self.prompt = io.colorize("[SLAVE"+("|"+address if address != "" else "") + "]: ","cyan")

	def clear(self):
		subprocess.run(["clear"])

	def load(self,filename:"!path"=""):
		self.initializeServer()
		if filename == "":
			if self.args["ATT_FILE"] != "" and self.fileExists(self.args["ATT_FILE"]):
				self.importATT()
			elif self.args["GATT_FILE"] != "" and self.fileExists(self.args["GATT_FILE"]):
				self.importGATT()
			else:
				io.fail("No filename provided !")
		elif self.fileExists(filename):
			if self.identifyLayer(filename) == "ATT":
				self.importATT(filename)
			else:
				self.importGATT(filename)
		else:
			io.fail("File not found !")

	def show(self,what:["attributes","services","characteristics","all","gatt"]="attributes"):
		what = what.lower()
		if what == "attributes":
			self.server.database.show()
		elif what == "services":
			self.server.database.showServices()
		elif what == "characteristics":
			self.server.database.showCharacteristics(0x0001,0xFFFF)
		elif what == "all" or what=="gatt":
			self.server.database.showGATT()
		else:
			io.fail("Unknown object to show !")

	def disconnect(self):
		if self.emitter.isConnected():
			self.emitter.sendp(ble.BLEDisconnect())
		self.updatePrompt()

	def notification(self,handle,value):
		try:
			handle = int(handle,16)
			if utils.isHexadecimal(value):
				value = bytes.fromhex(value)
			else:
				value = bytes(value,"ascii")

			self.emitter.sendp(ble.BLEHandleValueNotification(handle=handle, value=value))
		except:
			io.fail("An error happened during notification emission !")

	def exit(self):	
		interpreter.Interpreter.exit(self)


	def initializeServer(self):
		self.server = ble.GATT_Server()

	def identifyLayer(self,filename):
		config = configparser.ConfigParser()
		config.read(filename)
		for handle in config.sections():
			if "uuid" in config[handle]:
				return "GATT"
		return "ATT"

	def importATT(self,filename=""):
		filename = filename if filename != "" else self.args["ATT_FILE"]
		io.info("Importing ATT layer datas from "+filename+" ...")
		attributes = []
		config = configparser.ConfigParser()
		config.read(filename)
		for handle in config.sections():
			attHandle = int(handle,16)
			infos = config[handle]
			attType = infos.get("type")
			attValue = bytes.fromhex(infos.get("value") if infos.get("value") is not None else "")
			self.server.addAttribute(handle=attHandle,value=attValue,type=attType,permissions=["Read","Write"])


	def importGATT(self,filename=""):
		filename = filename if filename != "" else self.args["GATT_FILE"]
		io.info("Importing GATT layer datas from "+filename+" ...")
		config = configparser.ConfigParser()
		config.read(filename)
		for element in config.sections():
			infos=config[element]
			if "type" in infos:
				if infos.get("type") == "service":
					startHandle = int(element,16)
					endHandle = int(infos.get("endhandle"),16)
					uuid = bytes.fromhex(infos.get("uuid"))
					if infos.get("servicetype") == "primary":
						self.server.addPrimaryService(uuid,startHandle)
					else:
						self.server.addSecondaryService(uuid,startHandle)
				elif infos.get("type") == "characteristic":
					declarationHandle = int(element,16)
					uuid = bytes.fromhex(infos.get("uuid"))
					valueHandle = int(infos.get("valuehandle"),16)
					value = bytes.fromhex(infos.get("value"))
					permissions = infos.get("permissions").split(",")
					self.server.addCharacteristic(uuid,value,declarationHandle,valueHandle,permissions)
				elif infos.get("type") == "descriptor":
					handle = int(element, 16)
					uuid = bytes.fromhex(infos.get("uuid"))
					value = bytes.fromhex(infos.get("value"))
					self.server.addDescriptor(uuid,value,handle)

	@module.scenarioSignal("onMasterReadByTypeRequest")				
	def readByTypeRequest(self,packet):
		io.info("Read By Type Request : startHandle = "+hex(packet.startHandle)+
			" / endHandle = "+hex(packet.endHandle)+" / uuid = "+hex(packet.uuid))
		(success,response) = self.server.readByType(packet.startHandle,packet.endHandle,packet.uuid)
		if success:
			io.displayPacket(ble.BLEReadByTypeResponse(attributes=response))
			self.emitter.sendp(ble.BLEReadByTypeResponse(attributes=response))
		else:
			self.emitter.sendp(ble.BLEErrorResponse(request=0x08,ecode=response, handle=packet.startHandle))

	@module.scenarioSignal("onMasterFindInformationRequest")
	def findInformationRequest(self,packet):
		io.info("Find Information Request : startHandle = "+hex(packet.startHandle)+
			" / endHandle = "+hex(packet.endHandle))
		(success,response) = self.server.findInformation(packet.startHandle,packet.endHandle)
		if success:
			io.displayPacket(ble.BLEFindInformationResponse(attributes=response))
			self.emitter.sendp(ble.BLEFindInformationResponse(attributes=response))
		else:
			self.emitter.sendp(ble.BLEErrorResponse(request=0x04,ecode=response,handle=packet.startHandle))

	@module.scenarioSignal("onMasterReadByGroupTypeRequest")
	def readByGroupTypeRequest(self,packet):
		io.info("Read By Group Type Request : startHandle = "+hex(packet.startHandle)+
				" / endHandle = "+hex(packet.endHandle)+" / uuid = "+hex(packet.uuid))
		(success,response) = self.server.readByGroupType(packet.startHandle, packet.endHandle, packet.uuid)
		if success:
			io.displayPacket(ble.BLEReadByGroupTypeResponse(attributes=response))
			self.emitter.sendp(ble.BLEReadByGroupTypeResponse(attributes=response))
		else:
			self.emitter.sendp(ble.BLEErrorResponse(request=0x10,ecode=response,handle=packet.startHandle))

	@module.scenarioSignal("onMasterReadRequest")
	def readRequest(self,packet):
		io.info("Read Request : handle = "+hex(packet.handle))
		(success,response) = self.server.read(packet.handle)
		if success:
			self.emitter.sendp(ble.BLEReadResponse(value=response))
		else:
			self.emitter.sendp(ble.BLEErrorResponse(request=0x0a, ecode=response,handle=packet.handle))


	@module.scenarioSignal("onMasterReadBlobRequest")
	def readBlobRequest(self,packet):
		io.info("Read Blob Request : handle = "+hex(packet.handle) + " / offset = "+str(packet.offset))
		(success,response) = self.server.readBlob(packet.handle,packet.offset)
		if success:
			self.emitter.sendp(ble.BLEReadBlobResponse(value=response))
		else:
			self.emitter.sendp(ble.BLEErrorResponse(request=0x0a, ecode=response,handle=packet.handle))


	@module.scenarioSignal("onMasterWriteRequest")
	def writeRequest(self,packet):
		io.info("Write Request : handle = "+hex(packet.handle)+" / value = "+packet.value.hex())
		(success,code) = self.server.writeRequest(packet.handle,packet.value)
		if success:
			self.emitter.sendp(ble.BLEWriteResponse())
		else:
			self.emitter.sendp(ble.BLEErrorResponse(request=0x12,ecode=code,handle=packet.handle))

	@module.scenarioSignal("onMasterWriteCommand")
	def writeCommand(self,packet):
		io.info("Write Command : handle = "+hex(packet.handle)+" / value = "+packet.value.hex())
		self.server.writeCommand(packet.handle,packet.value)

	@module.scenarioSignal("onMasterExchangeMTURequest")
	def exchangeMTURequest(self,packet):
		io.info("Exchange MTU Request : mtu = "+str(packet.mtu))
		self.server.setMtu(packet.mtu)
		self.emitter.sendp(ble.BLEExchangeMTUResponse(mtu=packet.mtu))

	@module.scenarioSignal("onMasterConnect")
	def connection(self,packet):
		io.info("Master connected : "+packet.srcAddr)
		self.updatePrompt(packet.srcAddr)

	@module.scenarioSignal("onMasterDisconnect")
	def disconnection(self,packet):
		io.info("Master disconnected !")
		self.updatePrompt()

	@module.scenarioSignal("onStart")
	def startScenario(self):
		pass

	@module.scenarioSignal("onEnd")
	def endScenario(self):
		pass

	def _autocompletePairingParameters(self):
		'''
		This method generates the pairing parameters available in order to autocomplete "pairing" command.
		'''
		return [
				"inputOutput=",
				"authentication=",
				"ltk=",
				"ediv=",
				"rand=",
				"irk=",	
				"addr=",
				"addrType=",
				"csrk=",
				"pin="
			]

	def pairing(self,active:["active","passive"]="active",parameters:"!method:_autocompletePairingParameters"="inputOutput=yesno|authentication=bonding|ltk=112233445566778899aabbccddeeff|rand=1122334455667788|ediv=12"):
		self.receiver.removeCallbacks()
		self.initializeCallbacks()
		parameters = {param.split("=")[0]:param.split("=")[1]  for param in parameters.split("|")}
		pairModule = utils.loadModule("ble_pair")
		pairModule["INTERFACE"] = self.args["INTERFACE"]
		pairModule["MODE"] = "slave"
		pairModule["ACTIVE"] = "yes" if active == "active" else "no"
		pairModule["KEYBOARD"] = "yes" if ("inputOutput" in parameters and "keyboard" in parameters["inputOutput"]) else "no"
		pairModule["YESNO"] = "yes" if ("inputOutput" in parameters and "yesno" in parameters["inputOutput"]) else "no"
		pairModule["DISPLAY"] = "yes" if ("inputOutput" in parameters and "display" in parameters["inputOutput"]) else "no"
		pairModule["CT2"] = "yes" if ("authentication" in parameters and "ct2" in parameters["authentication"]) else "no"
		pairModule["MITM"] = "yes" if ("authentication" in parameters and "mitm" in parameters["authentication"]) else "no"
		pairModule["BONDING"] = "yes" if ("authentication" in parameters and "bonding" in parameters["authentication"]) else "no"
		pairModule["SECURE_CONNECTIONS"] = "yes" if ("authentication" in parameters and "secureConnections" in parameters["authentication"]) else "no"
		pairModule["KEYPRESS"] = "yes" if ("authentication" in parameters and "keypress" in parameters["authentication"]) else "no"
		pairModule["LTK"] = parameters["ltk"] if "ltk" in parameters else ""
		pairModule["EDIV"] = parameters["ediv"] if "ediv" in parameters else ""
		pairModule["RAND"] = parameters["rand"] if "rand" in parameters else ""
		pairModule["IRK"] = parameters["irk"] if "irk" in parameters else ""
		pairModule["ADDR"] = parameters["addr"] if "addr" in parameters else ""
		pairModule["ADDR_TYPE"] = parameters["addrType"] if "addrType" in parameters else ""
		pairModule["CSRK"] = parameters["csrk"] if "csrk" in parameters else ""
		pairModule["PIN"] = parameters["pin"] if "pin" in parameters else ""

		io.chart(["Name","Value"],[[k,v] for k,v in pairModule.args.items()],"Input parameters")
		output = pairModule.execute()
		if output["success"]:
			if active == "active":
				io.success("Active pairing enabled !")
			else:
				io.success("Passive pairing enabled !")
		else:
			io.fail("An error occured during pairing !")

	def _autocompleteAdvertisingType(self):
		'''
		This method generates the advertising types in order to autocomplete "advertising" command.
		'''
		return [
			"ADV_IND",
			"ADV_DIRECT_IND",
			"ADV_SCAN_IND",
			"ADV_NONCONN_IND",
			"ADV_DIRECT_IND_LOW"
			]

	def advertising(self,type:"!method:_autocompleteAdvertisingType"="ADV_IND",data="",scanData="",intervalMin="200", intervalMax="210"):
		advModule = utils.loadModule("ble_adv")
		advModule["INTERFACE"] = self.args["INTERFACE"]
		advModule["ADVERTISING_TYPE"] = type
		advModule["ADVERTISING_DATA"] = data
		advModule["SCANNING_DATA"] = scanData
		advModule["INTERVAL_MIN"] = intervalMin
		advModule["INTERVAL_MAX"] = intervalMax
		output = advModule.execute()
		if output["success"]:
			io.success(	"Currently advertising : <<type="+type+
					"|intervalMin="+intervalMin+
					"|intervalMax="+intervalMax+
					"|advData="+data+
					"|scanData="+scanData+">> "
					)
		else:
			io.fail("An error occured during advertisements configuration !")

	def address(self,address=""):
		if address == "":
			io.info("Current address : "+self.emitter.getAddress())
		else:
			success = self.emitter.setAddress(address)
			if success:
				io.success("New address set : "+self.emitter.getAddress())
			else:
				io.fail("An error occured during address modification.")


	def initializeCallbacks(self):
		self.receiver.onEvent("BLEConnectResponse",callback=self.connection)
		self.receiver.onEvent("BLEReadByTypeRequest",callback=self.readByTypeRequest)
		self.receiver.onEvent("BLEFindInformationRequest",callback=self.findInformationRequest)
		self.receiver.onEvent("BLEReadByGroupTypeRequest",callback=self.readByGroupTypeRequest)
		self.receiver.onEvent("BLEReadRequest",callback=self.readRequest)
		self.receiver.onEvent("BLEReadBlobRequest",callback=self.readBlobRequest)
		self.receiver.onEvent("BLEExchangeMTURequest",callback=self.exchangeMTURequest)
		self.receiver.onEvent("BLEWriteCommand",callback=self.writeCommand)
		self.receiver.onEvent("BLEWriteRequest",callback=self.writeRequest)
		self.receiver.onEvent("BLEDisconnect", callback=self.disconnection)

	def run(self):
		interface = self.args["INTERFACE"]
		self.emitter = self.getEmitter(interface=interface)
		self.receiver = self.getReceiver(interface=interface)
		if self.checkCapabilities():
			self.initializeServer()
			if self.args["ATT_FILE"] != "" and self.fileExists(self.args["ATT_FILE"]):
				self.importATT()
			elif self.args["GATT_FILE"] != "" and self.fileExists(self.args["GATT_FILE"]):
				self.importGATT()
			else:
				io.info("No filename provided : empty database !")

			self.initializeCallbacks()

			if self.loadScenario():
				io.info("Scenario loaded !")
				self.startScenario()
				while not self.emitter.isConnected():
					utils.wait(seconds=0.01)
				while self.emitter.isConnected():
					utils.wait(seconds=0.01)
				self.endScenario()
			else:
				interpreter.Interpreter.loop(self)

			return self.ok()
		else:
			io.fail("Interface provided ("+str(self.args["INTERFACE"])+") is not able to communicate as a slave.")
			return self.nok()
