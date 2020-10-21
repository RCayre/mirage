import subprocess
from mirage.libs import io,utils,ble
from mirage.core import module,interpreter

class ble_master(module.WirelessModule, interpreter.Interpreter):
	def init(self):

		self.technology = "ble"
		self.type = "spoofing"
		self.description = "This module permits the User to interact with Bluetooth Low Energy slaves"
		self.dependencies = ["ble_connect","ble_scan", "ble_discover","ble_pair"]
		self.args = {
				"TARGET":"",
				"CONNECTION_TYPE":"public",
				"INTERFACE":"hci0",
				"SCENARIO":""
			}

	def prerun(self):
		interpreter.Interpreter.__init__(self)
		self.availableCommands += [
						"scan",
						"connect",
						"read",
						"pairing",
						"write_cmd",
						"write_req",
						"discover",
						"clear",
						"disconnect", 
						"switch",
						"connections"
					]
		self.updatePrompt()
		self.targets = []

	def checkCommunicationCapabilities(self):
		return self.receiver.hasCapabilities("COMMUNICATING_AS_MASTER")

	def checkConnectionCapabilities(self):
		return self.receiver.hasCapabilities("INITIATING_CONNECTION")

	def checkScanningCapabilities(self):
		return self.receiver.hasCapabilities("SCANNING")

	def updatePrompt(self,address=""):
		self.prompt = io.colorize("[MASTER"+("|"+address if address != "" else "") + "]: ","cyan")

	def clear(self):
		subprocess.run(["clear"])

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
				"addr_type=",
				"csrk=",
				"pin="
			]

	def pairing(self,active:["active","passive"]="active",parameters:"!method:_autocompletePairingParameters"="inputOutput=yesno|authentication=bonding|ltk=112233445566778899aabbccddeeff|rand=1122334455667788|ediv=12"):
		self.receiver.removeCallbacks()
		self.initializeCallbacks()
		parameters = {param.split("=")[0]:param.split("=")[1]  for param in parameters.split("|")}
		pairModule = utils.loadModule("ble_pair")
		pairModule["MODE"] = "master"
		pairModule["INTERFACE"] = self.args["INTERFACE"]
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


	def disconnect(self):
		if self.receiver.isConnected():
			self.emitter.sendp(ble.BLEDisconnect())
			utils.wait(seconds=1)
			io.success("Disconnected !")
			if self.receiver.isConnected():
				self.updatePrompt(self.emitter.getCurrentConnection())
			else:
				self.updatePrompt()
		else:
			io.fail("No active connections !")

	def connections(self):
		counter = 1
		connectionsList = []
		for connection in self.emitter.getConnections():
			connectionsList.append([str(counter),connection["address"], connection["handle"]])
			counter += 1
		if connectionsList == []:
			io.fail("No active connections !")
		else:
			io.chart(["Identifier", "Address", "Handle"],connectionsList,io.colorize("Active connections","yellow"))

	def _autocompleteConnections(self):
		return [connection["address"] for connection in self.emitter.getConnections()]

	def switch(self,target:"!method:_autocompleteConnections"):
		if utils.isNumber(target):
			if int(target) > 0 and int(target) < len(self.emitter.getConnections())+1:
				address = self.emitter.getConnections()[int(target)-1]["address"]
			else:
				address = self.emitter.getAddressByHandle(int(target))
		else:
			address = target
		if self.emitter.switchConnection(address):
			io.success("Switching to connection <"+address+">")
			self.updatePrompt(address)
		else:
			io.fail("Unknown connection !")

	def scan(self,seconds='6',display:["address","name","company","flags","data"]="address,name"):
		if self.checkScanningCapabilities():
			m = utils.loadModule('ble_scan')
			m['INTERFACE'] = self.args['INTERFACE']
			m['TIME'] = seconds
			m['DISPLAY'] = display
			output = m.execute()
			if output["success"]:
				self.targets = []
				if "ADVERTISING_ADDRESS" in output["output"]:
					self.targets = [output["output"]["ADVERTISING_ADDRESS"]]
				else:
					counter = 1
					while True:
						if "ADVERTISING_ADDRESS"+str(counter) in output["output"]:
							self.targets.append(output["output"]["ADVERTISING_ADDRESS"+str(counter)])
							counter += 1
						else:
							break
		else:
			io.fail("Interface provided ("+str(self.args["INTERFACE"])+") is not able to scan devices.")
	
	def connect(self,target:"!attribute:targets"="",connectionType:["public","random"]=""):
		if self.checkConnectionCapabilities():
			target = self.args['TARGET'] if target=="" else target
			connectionType = self.args['CONNECTION_TYPE'] if connectionType=="" else connectionType
			if target == "":
				io.fail("You have to enter a valid BD address.")
			else:
				m = utils.loadModule('ble_connect')
				m['TARGET'] = target
				m['CONNECTION_TYPE'] = connectionType
				m['INTERFACE'] = self.args['INTERFACE']
				m['WAITING_TIME'] = "3"

				if m.execute()["success"]:
					self.updatePrompt(target)
		else:
			io.fail("Interface provided ("+str(self.args["INTERFACE"])+") is not able to initiate a connection.")

	def _autocompleteDiscoverWhat(self):
		'''
		This method generates the discover parameters available in order to autocomplete "discover" command.
		'''
		return [
			"all",
			"attributes",
			"services",
			"primaryservices",
			"secondaryservices",
			"characteristics"
			]

	def discover(self,what:"!method:_autocompleteDiscoverWhat"="all",start="0x0001",end="0xFFFF",filterby:["type","value"]="",filter=""):
		if self.receiver.isConnected():
			m = utils.loadModule('ble_discover')
			m["WHAT"] = what
			m['INTERFACE'] = self.args['INTERFACE']
			m["START_HANDLE"] = start
			m["END_HANDLE"] = end
			m["FILTER_BY"] = filterby
			m["FILTER"] = filter
			m.execute()
		else:
			io.fail("No active connections !")

	def read(self,handle):
		if self.receiver.isConnected():
			if utils.isHexadecimal(handle):
				self.emitter.sendp(ble.BLEReadRequest(handle = int(handle,16)))
				io.info("Read Request : handle = "+handle)

				response = self.receiver.next(timeout=3)
				retry = 3
				while not (isinstance(response,ble.BLEReadResponse)  or
					   isinstance(response,ble.BLEErrorResponse) or
					   retry == 0
					  ):
					response = self.receiver.next(timeout=1)
					retry -= 1
				if isinstance(response,ble.BLEReadResponse):
					io.success("Response : handle = "+str(handle)+" / Values (hex) = "+response.value.hex())
				elif isinstance(response, ble.BLEErrorResponse):
					io.fail("Error response")
			else:
				io.fail("Handle is not correctly formatted (hexadecimal)")
		else:
			io.fail("No active connections !")

	def write_req(self,handle,value):
		if self.receiver.isConnected():
			if utils.isHexadecimal(handle) and utils.isHexadecimal(value):
				self.emitter.sendp(ble.BLEWriteRequest(handle = int(handle,16),value=bytes.fromhex(value)))
				io.info("Write Request : handle = "+handle+" / value = "+value)

				response = self.receiver.next(timeout=3)
				retry = 3
				while not (isinstance(response,ble.BLEWriteResponse)  or
					   isinstance(response,ble.BLEErrorResponse) or
					   retry == 0
					  ):
					response = self.receiver.next(timeout=1)
					retry -= 1
				if isinstance(response,ble.BLEWriteResponse):
					io.success("Response : success")
				elif isinstance(response, ble.BLEErrorResponse):
					io.fail("Error response !")
				elif retry == 0:
					io.fail("Timeout error !")
			else:
				io.fail("Handle or value is not correctly formatted (hexadecimal) !")
		else:
			io.fail("No active connections !")

	def write_cmd(self,handle,value):
		if self.receiver.isConnected():
			if utils.isHexadecimal(handle) and utils.isHexadecimal(value):
				self.emitter.sendp(ble.BLEWriteCommand(handle = int(handle,16),value=bytes.fromhex(value)))
				io.success("Write Command : handle = "+handle+" / value = "+value)
			else:
				io.fail("Handle or value is not correctly formatted (hexadecimal) !")
		else:
			io.fail("No active connections !")


	@module.scenarioSignal("onSlaveConnect")
	def onConnect(self):
		pass

	@module.scenarioSignal("onSlaveDisconnect")
	def onDisconnect(self,packet):
		io.info("Disconnected !")
		if self.receiver.isConnected():
			self.updatePrompt(self.emitter.getCurrentConnection())
		else:
			self.updatePrompt()

	@module.scenarioSignal("onStart")
	def startScenario(self):
		pass

	@module.scenarioSignal("onEnd")
	def endScenario(self):
		pass

	@module.scenarioSignal("onSlaveConnectionParameterUpdateRequest")
	def onConnectionParameterUpdateRequest(self,packet):
		io.info("Updating connection parameters ...")
		io.info(" => Timeout: "+str(packet.timeoutMult))
		io.info(" => Latency: "+str(packet.slaveLatency))
		io.info(" => Minimum interval: "+str(packet.minInterval))
		io.info(" => Maximum interval: "+str(packet.maxInterval))
		self.emitter.updateConnectionParameters(timeout=packet.timeoutMult,latency=packet.slaveLatency, minInterval=packet.minInterval,maxInterval=packet.maxInterval,minCe=0,maxCe=0)
		self.emitter.sendp(ble.BLEConnectionParameterUpdateResponse(l2capCmdId = packet.l2capCmdId,moveResult=0))

	@module.scenarioSignal("onSlaveHandleValueNotification")
	def onNotification(self,packet):
		io.info("Incoming notification : handle = "+hex(packet.handle)+" / value = "+packet.value.hex())

	@module.scenarioSignal("onSlaveHandleValueIndication")
	def onIndication(self,packet):
		io.info("Incoming indication : handle = "+hex(packet.handle)+" / value = "+packet.value.hex())
		self.emitter.sendp(ble.BLEHandleValueConfirmation())

	def initializeCallbacks(self):
		self.receiver.onEvent("BLEDisconnect",callback=self.onDisconnect)
		self.receiver.onEvent("BLEConnectionParameterUpdateRequest",callback=self.onConnectionParameterUpdateRequest)
		self.receiver.onEvent("BLEHandleValueNotification",callback=self.onNotification)
		self.receiver.onEvent("BLEHandleValueIndication",callback=self.onIndication)

	def run(self):
		self.emitter = self.getEmitter(interface=self.args['INTERFACE'])
		self.receiver = self.getReceiver(interface=self.args['INTERFACE'])
		self.initializeCallbacks()
		if self.checkCommunicationCapabilities():
			if self.loadScenario():
				io.info("Scenario loaded !")
				self.startScenario()
				while not self.emitter.isConnected():
					utils.wait(seconds=0.01)
				self.onConnect()
				while self.emitter.isConnected():
					utils.wait(seconds=0.01)
				self.endScenario()
			else:
				if self.emitter.isConnected():
					self.updatePrompt(self.emitter.getCurrentConnection())
				interpreter.Interpreter.loop(self)

			return self.ok()
		else:
			io.fail("Interface provided ("+str(self.args["INTERFACE"])+") is not able to communicate as a master.")
			return self.nok()			
