import configparser

from mirage.core import module
from mirage.libs import io, utils
from mirage.libs.ble_utils.dissectors import CharacteristicDeclaration, CharacteristicDescriptor, Service, UUID
from mirage.libs.ble_utils.packets import BLEErrorResponse,\
	BLEFindInformationRequest,\
	BLEFindInformationResponse,\
	BLEReadByGroupTypeRequest,\
	BLEReadByGroupTypeResponse,\
	BLEReadByTypeRequest,\
	BLEReadByTypeResponse,\
	BLEReadRequest,\
	BLEReadResponse


class ble_discover(module.WirelessModule):
	def init(self):
		self.technology = "ble"
		self.type = "discover"
		self.description = "Discovery module for Bluetooth Low Energy ATT / GATT layers"
		self.args = {
				"INTERFACE":"hci0",
				"START_HANDLE":"0x0001",
				"END_HANDLE":"0xFFFF",
				"WHAT":"all",
				"FILTER":"",
				"FILTER_BY":"",
				"ATT_FILE":"",
				"GATT_FILE":""
			}

	def checkCapabilities(self):
		return self.receiver.hasCapabilities("COMMUNICATING_AS_MASTER")

	def exportAttributes(self,attributes):
		config = configparser.ConfigParser()
		for attribute in attributes:
			type = attribute["type"].hex()
			value = attribute["value"].hex()
			handle = "0x{:04x}".format(attribute["handle"])
			config[handle] = {"type":type,"value":value}
		with open(self.args["ATT_FILE"], 'w') as outfile:
			config.write(outfile)
			io.success("Discovered attributes are saved as "+self.args["ATT_FILE"]+" (CFG file format)")

	def exportGATT(self,datas):

		config = configparser.ConfigParser()
		for element in datas:
			service = element["service"]
			startHandle = "0x{:04x}".format(service["startHandle"])
			uuid = service["uuid"].data.hex()
			endHandle = "0x{:04x}".format(service["endHandle"])
			config[startHandle] = {"type":"service","uuid":uuid,"endHandle":endHandle,"serviceType":service["serviceType"]}
			for characteristic in element["characteristics"]:
				declarationHandle = "0x{:04x}".format(characteristic["declarationHandle"])
				uuid = characteristic["uuid"].data.hex()
				permissions = ','.join(characteristic["permissionsFlag"].permissions)
				value = characteristic["value"].hex()
				valueHandle = "0x{:04x}".format(characteristic["valueHandle"])
				config[declarationHandle] = {
								"type":"characteristic",
								"uuid":uuid,
								"permissions":permissions,
								"value":value,
								"valueHandle":valueHandle
								}
				if "descriptors" in characteristic:
					for descriptor in characteristic["descriptors"]:
						uuid = descriptor["type"].hex()
						handle = "0x{:04x}".format(descriptor["handle"])
						value = descriptor["value"].hex()
						config[handle] = {"type":"descriptor","uuid":uuid,"value":value}
		with open(self.args["GATT_FILE"], 'w') as outfile:
			config.write(outfile)
			io.success("Discovered services and characteristics are saved as "+self.args["GATT_FILE"]+" (CFG file format)")

	def receive(self,types,retry=None):
		while True:
			p = self.receiver.next(timeout=3)

			if p is None:
				self.emitter.sendp(retry)
			else:			
				for typeInstance in types:
					if isinstance(p,typeInstance):
						return p
	def serviceToString(self,service):
		uuid128 = service["uuid"].UUID128.hex() if service["uuid"].UUID128 is not None else ""
		name = service["uuid"].name if service["uuid"].name is not None else ""
		info = ("'"+name+"'" if name != "" else uuid128)

		handles = "(start Handle = " +"0x{:04x}".format(service["startHandle"])+ " / end Handle = " + "0x{:04x}".format(service["endHandle"])+")"

		return "Service " + info + handles

	def printCharacteristics(self, characteristics,title="Characteristics"):
		formattedCharacteristics = []
		for characteristic in characteristics:
			declarationHandle = "0x{:04x}".format(characteristic["declarationHandle"])
			valueHandle = "0x{:04x}".format(characteristic["valueHandle"])
			permissionsFlag = ",".join(characteristic["permissionsFlag"])
			uuid16 = (hex(characteristic["uuid"].UUID16) 
					if characteristic["uuid"].UUID16 is not None
					else ""
				)
			uuid128 = (characteristic["uuid"].UUID128.hex() 
					if characteristic["uuid"].UUID128 is not None
					else ""
				)
			name = (characteristic["uuid"].name
					if characteristic["uuid"].name is not None
					else ""
				)
			value = (characteristic["value"].replace(b"\x00",b"").decode("ascii") 
					if utils.isPrintable(characteristic["value"]) 
					else characteristic["value"].hex()
				)
			descriptors = ""
			if "descriptors" in characteristic:
				for desc in characteristic["descriptors"]:
					namedesc = CharacteristicDescriptor(data=desc["type"]).UUID.name
					valuedesc = (desc["value"].replace(b"\x00",b"").decode("ascii") 
							if utils.isPrintable(desc["value"]) and len(desc["value"])>0
							else desc["value"].hex()
						)
					endSymbol = "\n" if characteristic["descriptors"][-1]!=desc else ""
					descriptors += namedesc +" : "+ valuedesc + endSymbol
			formattedCharacteristics.append([declarationHandle, valueHandle, uuid16, uuid128, name,permissionsFlag,value,descriptors])
		io.chart(["Declaration Handle","Value Handle","UUID16","UUID128","Name","Permissions", "Value","Descriptors"]
			,formattedCharacteristics,
			io.colorize(title, "yellow")
			)

	def printServices(self, services, title="Services"):
		formattedServices = []
		for service in services:
			startHandle = "0x{:04x}".format(service["startHandle"])
			endHandle = "0x{:04x}".format(service["endHandle"])
			uuid16 = (hex(service["uuid"].UUID16) 
					if service["uuid"].UUID16 is not None
					else ""
					)
			uuid128 = (service["uuid"].UUID128.hex() 
					if service["uuid"].UUID128 is not None
					else ""
				)
			name = (service["uuid"].name
					if service["uuid"].name is not None
					else ""
				)
			formattedServices.append([startHandle,endHandle,uuid16, uuid128,name])
		io.chart(["Start Handle","End Handle", "UUID16", "UUID128", "Name"],
			formattedServices,
			io.colorize(title, "yellow")
			)

	def printAttributes(self,attributes):
		formattedAttributes = []
		for attribute in attributes:
			aType = UUID(data=attribute["type"])
			if aType.name is not None:
				attributeType = aType.name
			elif aType.UUID16 is not None:
				attributeType = hex(aType.UUID16)
			else:
				attributeType = aType.UUID128.hex()
			
			attributeValue = attribute["value"].replace(b"\x00",b"").decode("ascii") if utils.isPrintable(attribute["value"]) else attribute["value"].hex()
			attributeHandle = "0x{:04x}".format(attribute["handle"])
			formattedAttributes.append([attributeHandle, attributeType,attributeValue])
		io.chart(["Attribute Handle", "Attribute Type", "Attribute Value"],
		formattedAttributes,
			io.colorize("Attributes","yellow")
			)


	def servicesDiscovery(self, uuid, startHandle = 0x0001, endHandle = 0xffff):
		start,end, continuer = startHandle, endHandle, True
		services = []
		while continuer:

			request = BLEReadByGroupTypeRequest(startHandle=start,endHandle=end,uuid=uuid)
			
			self.emitter.sendp(request)

			p = self.receive([BLEReadByGroupTypeResponse,BLEErrorResponse],retry=request)

			if isinstance(p,BLEReadByGroupTypeResponse):

				for i in p.attributes:

					service = Service(data=i['value'][::-1])

					serviceStruct = {
						"startHandle":i["attributeHandle"],
						"endHandle":i["endGroupHandle"],
						"uuid":service.UUID
					}

					if serviceStruct not in services:
						services.append(serviceStruct)
				start = p.attributes[-1]["endGroupHandle"] + 1
				continuer = (start <= 0xFFFF)
			elif isinstance(p,BLEErrorResponse):
				continuer = False
			else:
				pass
		return services

	def primaryServicesDiscovery(self,startHandle = 0x0001, endHandle = 0xffff):
		uuid = UUID(name="Primary Service").UUID16
		return self.servicesDiscovery(uuid,startHandle=startHandle,endHandle=endHandle)

	def secondaryServicesDiscovery(self,startHandle = 0x0001, endHandle = 0xffff):
		uuid = UUID(name="Secondary Service").UUID16
		return self.servicesDiscovery(uuid,startHandle=startHandle,endHandle=endHandle)

	def allServicesDiscovery(self, startHandle = 0x0001, endHandle = 0xffff):
		primary = self.primaryServicesDiscovery(startHandle=startHandle,endHandle=endHandle)
		for service in primary:
			service["serviceType"] = "primary"
		secondary = self.secondaryServicesDiscovery(startHandle=startHandle,endHandle=endHandle)
		for service in secondary:
			service["serviceType"] = "secondary"
		return primary + secondary

	def characteristicsDiscovery(self,startHandle=0x0001, endHandle=0xFFFF):
		characteristicDeclarationUUID = UUID(name="Characteristic Declaration").UUID16
		start, end, continuer = startHandle,endHandle,True
		characteristics = []
		while continuer:
			request = BLEReadByTypeRequest(startHandle=start,endHandle=end,uuid= characteristicDeclarationUUID)
			self.emitter.sendp(request)

			p = self.receive([BLEReadByTypeResponse,BLEErrorResponse],retry=request)

			if isinstance(p,BLEReadByTypeResponse):

				for i in p.attributes:

					characteristicDeclaration =  CharacteristicDeclaration(data=i['value'][::-1])
					characteristic = {
						"declarationHandle":i["attributeHandle"],
						"valueHandle":characteristicDeclaration.valueHandle,
						"uuid":characteristicDeclaration.UUID,
						"permissionsFlag":characteristicDeclaration.permissionsFlag,
						"value":b""
						}
					if "Read" in characteristicDeclaration.permissionsFlag:
						request = BLEReadRequest(handle=characteristicDeclaration.valueHandle)
						self.emitter.sendp(request)
						p = self.receive([BLEReadResponse,BLEErrorResponse],retry=request)
						if isinstance(p,BLEReadResponse):
							characteristic["value"]  = p.value


					characteristics.append(characteristic)
					start = i["attributeHandle"]

				start = start + 1
				continuer = (start <= 0xFFFF)

			elif isinstance(p,BLEErrorResponse):
				continuer = False
			else:
				pass
		return characteristics

	def attributesDiscovery(self, startHandle = 0x0001, endHandle = 0xFFFF):
		attributes = []
		start, end, continuer = startHandle,endHandle, True
		while continuer:
			request = BLEFindInformationRequest(startHandle=start, endHandle=end)
			self.emitter.sendp(request)
			p = self.receive([BLEFindInformationResponse,BLEErrorResponse],retry=request)
			if isinstance(p,BLEFindInformationResponse):
				for i in p.attributes:
					attribute = {"handle":i["attributeHandle"], "type":i["type"], "value":b""}
					if attribute not in attributes:
						attributes.append(attribute)
				start = i["attributeHandle"] + 1

				continuer = (start < 0xFFFF)
			elif isinstance(p,BLEErrorResponse):
				continuer = False
			else:
				pass

		for attribute in attributes:
			request = BLEReadRequest(handle=attribute["handle"])
			self.emitter.sendp(request)
			p = self.receive([BLEReadResponse,BLEErrorResponse],retry=request)

			if isinstance(p,BLEReadResponse):
				attribute["value"] = p.value

		return attributes

	def characteristicDescriptorDiscovery(self, startHandle = 0x0001, endHandle = 0xFFFF):
		descriptors = []
		start, end, continuer = startHandle,endHandle, True
		while continuer:
			request = BLEFindInformationRequest(startHandle=start, endHandle=end)
			self.emitter.sendp(request)
			p = self.receive([BLEFindInformationResponse,BLEErrorResponse],retry=request)
			if isinstance(p,BLEFindInformationResponse):
				for i in p.attributes:
					attribute = {"handle":i["attributeHandle"], "type":i["type"], "value":""}
					if attribute not in descriptors:
						request2 = BLEReadRequest(handle=i["attributeHandle"])
						self.emitter.sendp(request2)
						p2 = self.receive([BLEReadResponse,BLEErrorResponse],retry=request2)
						if isinstance(p2,BLEReadResponse):
							attribute["value"]  = p2.value
						else:
							attribute["value"] = b""
						descriptors.append(attribute)
				start = i["attributeHandle"] + 1

				continuer = (start < 0xFFFF)
			elif isinstance(p,BLEErrorResponse):
				continuer = False
			else:
				pass
		return descriptors

	def characteristicsByServiceDiscovery(self,service):
		return self.characteristicsDiscovery(startHandle=service["startHandle"],endHandle = service["endHandle"])

	def parseFilterType(self):
		filterType = self.args["FILTER"]
		if filterType=="":
			return None
		if utils.isNumber(filterType):
			return UUID(UUID16=int(filterType)).data
		elif utils.isHexadecimal(filterType) and len(filterType)<=6:
			return UUID(UUID16=int(filterType, 16)).data
		elif utils.isHexadecimal(filterType) and len(filterType)>6:
			uuid = UUID(UUID128=bytes.fromhex(filterType)).data
			if uuid is None:
				return bytes.fromhex(filterType)
			else:
				return uuid
		else:
			return UUID(name=filterType).data
	def applyFilter(self, attributes):
		filteredAttributes = attributes
		filterBy = self.args["FILTER_BY"].lower()
		if filterBy == "type":
			filterType = self.parseFilterType()
			if filterType is not None:
				filteredAttributes = [i for i in attributes if i["type"] == filterType]
		elif filterBy == "value":
			filterValue = self.args["FILTER"]
			if utils.isHexadecimal(filterValue):
				filterValue = bytes.fromhex(filterValue)
			else:
				filterValue = bytes(filterValue,"utf-8")

				filteredAttributes = [i for i in attributes if filterValue in i["value"]]
		return filteredAttributes

	def run(self):
		interface = self.args["INTERFACE"]
		start = utils.integerArg(self.args["START_HANDLE"])
		end = utils.integerArg(self.args["END_HANDLE"])
		self.emitter = self.getEmitter(interface=interface)
		self.receiver = self.getReceiver(interface=interface)
		if self.checkCapabilities():
			if self.receiver.isConnected():
				for what in utils.listArg(self.args["WHAT"]):
					what = what.lower()
					if what == "primaryservices":
						services = self.primaryServicesDiscovery(startHandle=start, endHandle=end)
						self.printServices(services,"Primary Services")
					elif what == "secondaryservices":
						services = self.secondaryServicesDiscovery(startHandle=start, endHandle=end)
						self.printServices(services,"Secondary Services")
					elif what == "services":
						services = self.allServicesDiscovery(startHandle=start, endHandle=end)
						self.printServices(services)
					elif what == "characteristics":
						characteristics = self.characteristicsDiscovery(startHandle=start, endHandle=end)
						self.printCharacteristics(characteristics)
					elif what == "attributes":
						attributes = self.attributesDiscovery(startHandle=start, endHandle=end)
						attributes = self.applyFilter(attributes)
						self.printAttributes(attributes)
						if self.args["ATT_FILE"] != "":
							self.exportAttributes(attributes)
							return self.ok({"ATT_FILE":self.args["ATT_FILE"]})
					elif what == "all":
						io.info("Services discovery ...")
						services = self.allServicesDiscovery(startHandle=start, endHandle=end)
						self.printServices(services)
						io.info("Characteristics by service discovery ...")
						alldatas = []

						for service in services:
							characteristics = self.characteristicsByServiceDiscovery(service)

							for i in range(0,len(characteristics)-1):
								start = characteristics[i]["valueHandle"]+1
								end = characteristics[i+1]["declarationHandle"]-1
								if end - start >= 0 :
									characteristics[i]["descriptors"] = self.characteristicDescriptorDiscovery(start,end)
							if len(characteristics) > 0:
								start = characteristics[-1]["valueHandle"]+1
								end = service["endHandle"]
								if end - start >= 0 :
									characteristics[-1]["descriptors"] = self.characteristicDescriptorDiscovery(start,end)

							alldatas.append({"service":service,"characteristics":characteristics})
							self.printCharacteristics(characteristics, self.serviceToString(service))
						if self.args["GATT_FILE"] != "":
							self.exportGATT(alldatas)
							return self.ok({"GATT_FILE":self.args["GATT_FILE"]})
			return self.ok()
		else:
			io.fail("Interface provided ("+str(self.args["INTERFACE"])+") is not able to communicate as master.")
			return self.nok()		
