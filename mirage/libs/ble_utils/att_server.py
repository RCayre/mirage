from mirage.libs.ble_utils.dissectors import *
from mirage.libs.ble_utils.constants import *
from mirage.libs import utils,io

class ATT_Attribute:
	'''
	This class describes an ATT attribute.
	An ATT attribute is composed of four main fields :

	  * **handle** : ATT handle (it can be described as the index of an attribute of an ATT Database)
	  * **value** : binary value linked to this attribute
	  * **type** : UUID (12 bits or 128 bits) indicating the type of attribute, such as a Device Name or a Characteristic Declaration.
	  * **permissions** : flag indicating the access permissions attached to this attribute, such as readable or writeable.

	It overloads the method `__str__` in order to provide a pretty representation.

	'''
	def __init__(self,handle=None,value=None,type=None, permissions=None):
		self.handle = handle
		self.value = value
		
		if isinstance(type,int):
			self.type = UUID(UUID16=type)
		elif isinstance(type,bytes):
			self.type = UUID(data=type)
		elif utils.isHexadecimal(type) and len(type)<=6:
			self.type = UUID(UUID16=int(type, 16))
		elif utils.isHexadecimal(type) and len(type)>6:
			self.type = UUID(UUID128=bytes.fromhex(type))
		else:
			self.type = UUID(name=type)


		if isinstance(permissions,str) and utils.isNumber(permissions):
			self.permissions = PermissionsFlag(data=struct.pack('B',permissions))
		elif isinstance(permissions,bytes):
			self.permissions = PermissionsFlag(data=permissions)
		else:
			self.permissions = PermissionsFlag(permissions=permissions)

	def __str__(self):
		return ("handle = " + hex(self.handle) + " / value = "+self.value.hex() +
		       " / type = "+self.type.UUID128.hex()+" / permissions = "+str(self.permissions.permissions))


class ATT_Database:
	'''
	This class describes an ATT Database.
	It acts as a classic Database, and offer multiple primitives in order to manipulate the attributes.
	The internal representation is just a list containing some ``ATT_Attribute``.

	'''
	def __init__(self):
		self.attributes = []

	def _getRType(self,type):
		if isinstance(type, int):
			rtype = UUID(UUID16=type)
		elif utils.isHexadecimal(type) and len(type)<=6:
			rtype = UUID(UUID16=int(type, 16))
		elif utils.isHexadecimal(type) and len(type)>6:
			rtype = UUID(UUID128=bytes.fromhex(type))
		else:
			rtype = UUID(name=type)
		return rtype

	def show(self):
		'''
		This method displays a chart to present the ATT level vision of the attributes included in the Database.
		'''
		formattedAttributes = []
		for att in self.attributes:
			if att is not None:
				aType = att.type
				if aType.name is not None:
					attributeType = aType.name
				elif aType.UUID16 is not None:
					attributeType = hex(aType.UUID16)
				else:
					attributeType = aType.UUID128.hex()
				
				attributeValue = att.value.replace(b"\x00",b"").decode("ascii") if utils.isPrintable(att.value) else att.value.hex()
				attributeHandle = "0x{:04x}".format(att.handle)
				formattedAttributes.append([attributeHandle, attributeType,attributeValue])
		io.chart(["Attribute Handle", "Attribute Type", "Attribute Value"],
			 formattedAttributes,
			 io.colorize("Attributes","yellow")
			)

	def showGATT(self):
		'''
		This method displays a chart to present the GATT level vision of the attributes included in the Database.
		'''
		services = self.showServices()
		for service in services:
			startHandle,endHandle = int(service[0],16), int(service[1],16)
			info = ("'"+service[4]+"'" if service[4] != "" else service[3])
			handles = "(start Handle = " +"0x{:04x}".format(startHandle)+ " / end Handle = " + "0x{:04x}".format(endHandle)+")"
			self.showCharacteristics(startHandle,endHandle,"Service "+info+handles)

	def showServices(self):
		'''
		This method displays the GATT services described as attributes included in the Database.
		'''
		formattedServices = []
		for att in self.attributes:
			if att is not None and (att.type == UUID(name="Primary Service") or att.type == UUID(name="Secondary Service")):
				startHandle = "0x{:04x}".format(att.handle)
				service = Service(data=att.value[::-1])
				serviceName = service.UUID.name if service.UUID.name is not None else ""
				serviceUUID16 = "0x{:04x}".format(service.UUID.UUID16) if service.UUID.UUID16 is not None else ""
				serviceUUID128 = service.UUID.UUID128.hex() if service.UUID.UUID128 is not None else ""
				if len(formattedServices) > 0:
					formattedServices[-1][1] = "0x{:04x}".format(att.handle - 1)
				formattedServices.append([startHandle,"0x{:04x}".format(0xFFFF),serviceUUID16, serviceUUID128,serviceName])
		io.chart(["Start Handle","End Handle", "UUID16", "UUID128", "Name"],
			 formattedServices,
			 io.colorize("Services", "yellow")
			)
		return formattedServices

	def showCharacteristics(self,startHandle,endHandle,title="Characteristics"):
		'''
		This method displays the GATT characteristics described as attributes included in the Database and provide a mechanism to only select the characteristics between two handles (it is mainly used in order to print the characteristics included in a Service).

		:param startHandle: first ATT handle
		:type startHandle: int
		:param endHandle: last ATT handle
		:type endHandle: int
	 	:param title: Title of the chart
		:type title: str
		'''
		formattedCharacteristics = []
		for i in range(startHandle,endHandle):
			if i < len(self.attributes):
				att = self.attributes[i]
				if att.type == UUID(name="Characteristic Declaration"):
					declarationHandle = "0x{:04x}".format(att.handle)
					characteristic = CharacteristicDeclaration(data=att.value[::-1])
					uuid16 = ("0x{:04x}".format(characteristic.UUID.UUID16) 
							if characteristic.UUID.UUID16 is not None
							else ""
						 )
					uuid128 = (characteristic.UUID.UUID128.hex() 
							if characteristic.UUID.UUID128 is not None
							else ""
						)
					name = (characteristic.UUID.name
							if characteristic.UUID.name is not None
							else ""
						)
					valueHandle = "0x{:04x}".format(characteristic.valueHandle)
					value = self.attributes[characteristic.valueHandle].value
					value = (value.replace(b"\x00",b"").decode("ascii") 
						if utils.isPrintable(value)
						else value.hex()
					)
					permissions = ",".join(characteristic.permissionsFlag.permissions)
					startDescriptor = characteristic.valueHandle + 1
					descriptors = ""
					while (startDescriptor < len(self.attributes) and 
						self.attributes[startDescriptor] is not None and
					       (self.attributes[startDescriptor].type != UUID(name="Characteristic Declaration") and
						self.attributes[startDescriptor].type != UUID(name="Primary Service") and
						self.attributes[startDescriptor].type != UUID(name="Secondary Service"))):
						descriptor = self.attributes[startDescriptor]
						
						namedesc = CharacteristicDescriptor(UUID=descriptor.type).UUID.name
						valuedesc = (descriptor.value.replace(b"\x00",b"").decode("ascii") 
								if utils.isPrintable(descriptor.value)
								else descriptor.value.hex()
							)
						startSymbol = "" if descriptors == "" else "\n"
						descriptors += startSymbol + namedesc +" : "+ valuedesc
						startDescriptor += 1
					formattedCharacteristics.append([declarationHandle, valueHandle, uuid16, uuid128, name,permissions,value,descriptors])
		io.chart(["Declaration Handle","Value Handle","UUID16","UUID128","Name","Permissions", "Value","Descriptors"]
			,formattedCharacteristics,
			io.colorize(title, "yellow")
			)

	def setAttribute(self,handle=None, value=None,type=None,permissions=None):
		'''
		This method allows to add or modify an ATT attribute in the ATT Database.

		:param handle: handle of the attribute
		:type handle: int
		:param value: value of the attribute
		:type value: bytes
		:param type: type of the attribute
		:type type: int or str
		:param permissions: permissions of the attribute
		:type permissions: int or list of str

		:Example:

			>>> db = ATT_Database()
			>>> db.setAttribute(handle=1, value=b"\x00\x18", type="Primary Service",permissions=["Read"])
			>>> db.setAttribute(handle=2, value=b"\x02\x03\x00\x00\x2a", type=0x2803,permissions=b"\x01")
			>>> db.show()
			┌Attributes────────┬────────────────────────────────────────────┬────────────────────────────────────────┐
			│ Attribute Handle │ Attribute Type                             │ Attribute Value                        │
			├──────────────────┼────────────────────────────────────────────┼────────────────────────────────────────┤
			│ 0x0001           │ Primary Service                            │ 0018                                   │
			│ 0x0002           │ Characteristic Declaration                 │ 020300002a                             │
			└──────────────────┴────────────────────────────────────────────┴────────────────────────────────────────┘
			>>> db.setAttribute(handle=1,value=b"\x01\x18",type="Primary Service",permissions=["Read"])
			>>> db.show()
			┌Attributes────────┬────────────────────────────────────────────┬────────────────────────────────────────┐
			│ Attribute Handle │ Attribute Type                             │ Attribute Value                        │
			├──────────────────┼────────────────────────────────────────────┼────────────────────────────────────────┤
			│ 0x0001           │ Primary Service                            │ 0118                                   │
			│ 0x0002           │ Characteristic Declaration                 │ 020300002a                             │
			└──────────────────┴────────────────────────────────────────────┴────────────────────────────────────────┘

		'''
		if handle is not None:
			if handle >= len(self.attributes):
				for i in range(handle):
					if i >= len(self.attributes):
						self.attributes.append(None)
				self.attributes.append(ATT_Attribute(	handle=handle,
										value=value,
										type=type,
										permissions=permissions
									))
			else:
				self.attributes[handle] = ATT_Attribute(handle=handle, value=value,type=type,permissions=permissions)
		else:
			if len(self.attributes) == 0:
				self.attributes.append(None)
			self.attributes.append(ATT_Attribute(handle=handle, value=value,type=type,permissions=permissions))

	def getNextHandle(self):
		'''
		This method returns the next free handle.

		:return: next free handle
		:rtype: int

		:Example:

			>>> db.getNextHandle()
			25
		'''
		highestHandle = 0x0000
		for att in self.attributes:
			if att is not None and att.handle >= highestHandle:
				highestHandle = att.handle
		return highestHandle + 1

	def read(self,handle):
		'''
		This method allows to read the value of a given attribute according to the provided handle.

		:param handle: handle of the attribute
		:type handle: int
		:return: tuple composed of a boolean indicating if the attribute exists, another one indicating if it is readable and the value if possible
		:rtype: tuple of (bool,bool,bytes)


		:Example:
	
			>>> db = ATT_Database()
			>>> db.setAttribute(handle=1, value=b"\x00\x18", type="Primary Service",permissions=["Read"])
			>>> db.setAttribute(handle=2, value=b"\x02\x03\x00\x00\x2a", type=0x2803,permissions=b"\x01")
			>>> db.read(1)
			(True, True, b'\x00\x18')
			>>> db.read(2)
			(True, False, None)
			>>> db.read(3)
			(False, False, None)

		'''
		exist = handle < len(self.attributes) and self.attributes[handle] is not None
		authorized = exist and 'Read' in self.attributes[handle].permissions
		if not exist or not authorized:
			return (exist,authorized,None)
		else:
			return (True,True,self.attributes[handle].value)

	def write(self,handle,value):
		'''
		This method allows to write a new value in a given attribute according to the provided handle.

		:param handle: handle of the attribute
		:type handle: int
		:param value: new value to write
		:type value: bytes
		:return: tuple composed of a boolean indicating if the attribute exists and another one indicating if it is writeable
		:rtype: tuple of (bool,bool)


		:Example:
	
			>>> db = ATT_Database()
			>>> db.setAttribute(handle=1, value=b"\x00\x18", type="Primary Service",permissions=["Read"])
			>>> db.setAttribute(handle=2, value=b"\x02\x03\x00\x00\x2a", type=0x2803,permissions=b"\x01")
			>>> db.write(handle=1,value=b"\x01\x18")
			(True, False)
			>>> db.setAttribute(handle=1, value=b"\x00\x18", type="Primary Service",permissions=["Read","Write"])
			>>> db.write(handle=1,value=b"\x01\x18")
			(True, True)
			>>> db.read(1)
			(True, True, b'\x01\x18')

		'''
		exist = handle < len(self.attributes) and self.attributes[handle] is not None
		authorized =  exist and "Write" in self.attributes[handle].permissions
		if exist and authorized:
			self.attributes[handle].value = value
		return (exist,authorized)


	def readByType(self,start,end,type):
		'''
		This method allows to read a set of attributes according to the handles and type provided.

		:param start: start handle
		:type start: int
		:param end: end handle
		:type end: int
		:param type: type of attributes
		:type type: int or str
		:return: list of attributes (represented as a dictionary of two fields : *attributeHandle* and *value*)
		:rtype: list of dict


		:Example:
	
			>>> db.setAttribute(handle=1, value=b"\x00\x18", type="Primary Service",permissions=["Read"])
			>>> db.setAttribute(handle=2, value=b"\x00\x18", type="Secondary Service",permissions=["Read"])
			>>> db.setAttribute(handle=3, value=b"\x00\x18", type="Primary Service",permissions=["Read"])
			>>> db.setAttribute(handle=4, value=b"\x00\x18", type="Primary Service",permissions=["Read"])
			>>> db.setAttribute(handle=5, value=b"\x00\x18", type="Secondary Service",permissions=["Read"])
			>>> db.readByType(start=1,end=3,type="Primary Service")
			[{'attributeHandle': 1, 'value': b'\x00\x18'}, {'attributeHandle': 3, 'value': b'\x00\x18'}]
			>>> db.readByType(start=2,end=5,type=0x2801)
			[{'attributeHandle': 2, 'value': b'\x00\x18'}, {'attributeHandle': 5, 'value': b'\x00\x18'}]

		'''
		rtype = self._getRType(type)
		response = []
		for att in self.attributes[start:end+1]:
			if att is not None and att.type == rtype:
				response.append({"attributeHandle":att.handle,"value":att.value})
		return response

	def findInformation(self, start, end):
		'''
		This method allows to get a set of attributes' types according to the handles provided.

		:param start: start handle
		:type start: int
		:param end: end handle
		:type end: int
		:return: list of attributes' types (represented as a dictionary of two fields : *attributeHandle* and *type*)
		:rtype: list of dict


		:Example:
	
			>>> db.setAttribute(handle=1, value=b"\x00\x18", type="Primary Service",permissions=["Read"])
			>>> db.setAttribute(handle=2, value=b"\x00\x18", type="Secondary Service",permissions=["Read"])
			>>> db.setAttribute(handle=3, value=b"\x00\x18", type="Primary Service",permissions=["Read"])
			>>> db.setAttribute(handle=4, value=b"\x00\x18", type="Primary Service",permissions=["Read"])
			>>> db.setAttribute(handle=5, value=b"\x00\x18", type="Secondary Service",permissions=["Read"])
			>>> db.findInformation(2,5)
			[{'attributeHandle': 2, 'type': b'(\x01'}, {'attributeHandle': 3, 'type': b'(\x00'}, {'attributeHandle': 4, 'type': b'(\x00'}, {'attributeHandle': 5, 'type': b'(\x01'}]
			>>> db.findInformation(1,3)
			[{'attributeHandle': 1, 'type': b'(\x00'}, {'attributeHandle': 2, 'type': b'(\x01'}, {'attributeHandle': 3, 'type': b'(\x00'}]


		'''
		response = []

		for att in self.attributes[start:end+1]:
			if att is not None:
				response.append({"attributeHandle":att.handle,"type":att.type.data})

		return response

	def readByGroupType(self,start,end,type):
		'''
		This method allows to read a set of groups of attributes according to the handles and type provided.

		:param start: start handle
		:type start: int
		:param end: end handle
		:type end: int
		:param type: type of attributes
		:type type: int or str
		:return: list of attributes (represented as a dictionary of three fields : *attributeHandle*,*endGroupHandle* and *value*)
		:rtype: list of dict

		'''
		rtype = self._getRType(type)
		response = []
		for i in range(start, end+1):
			try:
				att = self.attributes[i]
				if att is not None and att.type == rtype:
					maxhandle = i
					try:
						for j in range(i+1,end+1):
							if self.attributes[j] is not None and self.attributes[j].type == rtype:
								break
							maxhandle = j
					except:
						pass
				response.append({"attributeHandle":i,"endGroupHandle":maxhandle,"value":att.value})
			except:
				pass
		return response

	def findByTypeValue(self,start,end,type,value):
		'''
		This method allows to read a set of groups of attributes according to the handles, type and value provided.

		:param start: start handle
		:type start: int
		:param end: end handle
		:type end: int
		:param type: type of attributes
		:type type: int or str
		:param value: value of attributes
		:type value: bytes
		:return: list of attributes (represented as a dictionary of two fields : *attributeHandle* and *endGroupHandle*)
		:rtype: list of dict

		'''
		rtype = self._getRType(type)
		response = []
		for i in range(start, end+1):
			try:
				att = self.attributes[i]
				if att is not None and att.type == rtype and att.value == value:
					maxhandle = i
					try:
						for j in range(i+1,end+1):
							if self.attributes[j] is not None and self.attributes[j].type == rtype:
								break
							maxhandle = j
					except:
						pass
				response.append({"attributeHandle":i,"endGroupHandle":maxhandle})
			except:
				pass
		return response

class ATT_Server:
	'''
	This class is a partial implementation of an ATT Server.
	The methods provided describe the corresponding requests, and the return value describe the response.

	This class uses the ``ATT_Database`` class in order to represent the data structure.
	'''
	def __init__(self,database=None,mtu=23):
		self.database = database if database is not None else ATT_Database()
		self.mtu = mtu

	def addAttribute(self,handle=None, value=None,type=None,permissions=None):
		'''
		This method allows to add a new attribute to the ATT Server's database.
	
		:param handle: handle of the attribute
		:type handle: int
		:param value: value of the attribute
		:type value: bytes
		:param type: type of the attribute
		:type type: int or str
		:param permissions: permissions of the attribute
		:type permissions: int or list of str
		'''
		self.database.setAttribute(handle=handle,value=value,type=type,permissions=permissions)

	def setMtu(self,mtu):
		'''
		This method allows to set a new MTU Value.
	
		:param mtu: value of Maximum Transfer Unit
		:type mtu: int

		:Example:
		
			>>> server = ATT_Server()
			>>> server.setMtu(48)

		'''
		self.mtu = mtu

	def read(self,handle):
		'''
		This method implements the Read Request.
	
		:param handle: handle included in the Read Request
		:type handle: int
		:return: tuple
		:rtype: tuple of (bool,bytes or int)


		.. note::
			The returned tuple is composed of two main fields :

			  * *success* : this field is a boolean indicating if the request was successful or not
			  * *body* : this field is the response's body (array of bytes) if the request was successful or the error code (integer) if the request was not successful

		'''
		(exist,authorized,value) = self.database.read(handle)
		error_code = ATT_ERR_ATTR_NOT_FOUND if not exist else ATT_ERR_READ_NOT_PERMITTED
		success = value is not None
		body = value[:self.mtu-1] if success else error_code
		return (success,body)


	def readBlob(self,handle,offset):
		'''
		This method implements the Read Blob Request.
	
		:param handle: handle included in the Read Blob Request
		:type handle: int
		:return: tuple
		:rtype: tuple of (bool,bytes or int)


		.. note::
			The returned tuple is composed of two main fields :

			  * *success* : this field is a boolean indicating if the request was successful or not
			  * *body* : this field is the response's body (array of bytes) if the request was successful or the error code (integer) if the request was not successful

		'''
		(exist,authorized,value) = self.database.read(handle)
		error_code = ATT_ERR_ATTR_NOT_FOUND if not exist else ATT_ERR_READ_NOT_PERMITTED
		success = value is not None
		body = value[offset:offset+self.mtu-1] if success else error_code
		return (success,body)

	def writeCommand(self,handle,value):
		'''
		This method implements the Write Command.
	
		:param handle: handle included in the Write Command
		:type handle: int
		:param value: value included in the Write Command
		:type value: bytes
		:return: tuple
		:rtype: tuple of (bool,None)


		.. note::
			The returned tuple is composed of two main fields :

			  * *success* : this field is a boolean indicating if the request was successful or not
			  * *body* : this field is the response's body (None)

		'''
		self.database.write(handle,value)
		return (True,None)

	def writeRequest(self,handle,value):
		'''
		This method implements the Write Request.
	
		:param handle: handle included in the Write Request
		:type handle: int
		:param value: value included in the Write Request
		:type value: bytes
		:return: tuple
		:rtype: tuple of (bool,int)


		.. note::
			The returned tuple is composed of two main fields :

			  * *success* : this field is a boolean indicating if the request was successful or not
			  * *body* : this field is the error code (int) if the request was not successful

		'''
		(exist,authorized) = self.database.write(handle,value)
		error_code = ATT_ERR_ATTR_NOT_FOUND if not exist else ATT_ERR_WRITE_NOT_PERMITTED
		return (exist and authorized,error_code)

	def readByType(self,start,end,type):
		'''
		This method implements the Read By Type Request.
	
		:param start: start handle included in the Read By Type Request
		:type start: int
		:param end: end handle included in the Read By Type Request
		:type end: int
		:param type: type included in the Read By Type Request
		:type type: bytes or int
		:return: tuple
		:rtype: tuple of (bool,list of dict)


		.. note::
			The returned tuple is composed of two main fields :

			  * *success* : this field is a boolean indicating if the request was successful or not
			  * *body* : this field is the response's body (list of dict - see output of ``ATT_Database.readByType``) if the request was successful or an error code (int) if the request was not successful

		'''
		response = self.database.readByType(start,end,type)
		error_code = ATT_ERR_ATTR_NOT_FOUND
		if len(response) == 0:
			success = False
			body = error_code
		else:
			total_size = 1
			last_size_value = None
			success = True
			body = []
			for elmt in response:
				size_handle = 2
				size_value = len(elmt["value"])
				if ((last_size_value is None or last_size_value == size_value) and 
				    total_size + size_handle + size_value < self.mtu - 1):
					body.append(elmt)
					total_size += size_handle + size_value
					last_size_value = size_value
				else:
					break
		return (success,body)

	def readByGroupType(self,start,end,type):
		'''
		This method implements the Read By Group Type Request.
	
		:param start: start handle included in the Read By Group Type Request
		:type start: int
		:param end: end handle included in the Read By Group Type Request
		:type end: int
		:param type: type included in the Read By Group Type Request
		:type type: bytes or int
		:return: tuple
		:rtype: tuple of (bool,list of dict)


		.. note::
			The returned tuple is composed of two main fields :

			  * *success* : this field is a boolean indicating if the request was successful or not
			  * *body* : this field is the response's body (list of dict - see output of ``ATT_Database.readByGroupType``) if the request was successful or an error code (int) if the request was not successful

		'''
		reponse = self.database.readByGroupType(start,end,type)
		error_code = ATT_ERR_ATTR_NOT_FOUND
		if len(reponse) == 0:
			success = False
			body = error_code
		else:
			total_size = 0
			last_size_value = None
			success = True
			body = []
			for elmt in reponse:
				size_handle = 4
				size_value = len(elmt["value"])
				if ((last_size_value is None or last_size_value == size_value) and 
				     total_size + size_handle + size_value <  self.mtu - 1):
					body.append(elmt)
					total_size += size_handle + size_value
					last_size_value = size_value
				else:
					break
		return (success,body)

	def findInformation(self,start,end):
		'''
		This method implements the Find Information Request.
	
		:param start: start handle included in the Find Information Request
		:type start: int
		:param end: end handle included in the Find Information Request
		:type end: int
		:return: tuple
		:rtype: tuple of (bool,list of dict)


		.. note::
			The returned tuple is composed of two main fields :

			  * *success* : this field is a boolean indicating if the request was successful or not
			  * *body* : this field is the response's body (list of dict - see output of ``ATT_Database.findInformation``) if the request was successful or an error code (int) if the request was not successful

		'''
		response = self.database.findInformation(start,end)
		error_code = ATT_ERR_ATTR_NOT_FOUND
		if len(response) == 0:
			success = False
			body = error_code
		else:
			total_size = 0
			last_size_type = None
			success = True
			body = []
			for elmt in response:
				size_handle = 2
				size_type = len(elmt["type"])
				if ((last_size_type is None or last_size_type == size_type) and 
				     total_size + size_handle + size_type <  self.mtu - 1):
					body.append(elmt)
					size_type += size_handle + size_type
					last_size_type = size_type
				else:
					break
		return (success,body)


class GATT_Server(ATT_Server):
	'''
	This class inherits from ``ATT_Server``, and provides some GATT level methods in order to easily manipulate GATT layer.
	'''

	def addPrimaryService(self,uuid,handle=None,permissions=["Read"]):
		'''
		This method allows to easily add a new primary service.
		
		:param uuid: value stored in the service (associated UUID)
		:type uuid: bytes
		:param handle: start handle of the service
		:type handle: int
		:param permissions: permissions associated to the service
		:type permissions: list of str

		.. note::

			If no handle is provided, the service is stored as the next available handle.
			If no permissions are provided, the service is stored with "Read" permission.

		'''
		newHandle = self.database.getNextHandle() if handle is None else handle			
		self.addAttribute(handle=newHandle,value=uuid[::-1],type=UUID(name="Primary Service").UUID16,permissions=permissions)
	
	def addSecondaryService(self,uuid,handle=None,permissions=["Read"]):
		'''
		This method allows to easily add a new secondary service.
		
		:param uuid: value stored in the service (associated UUID)
		:type uuid: bytes
		:param handle: start handle of the service
		:type handle: int
		:param permissions: permissions associated to the service
		:type permissions: list of str

		.. note::

			If no handle is provided, the service is stored as the next available handle.
			If no permissions are provided, the service is stored with "Read" permission.

		'''
		newHandle = self.currentHandle if handle is None else handle
		self.addAttribute(handle=newHandle,value=uuid[::-1],type=UUID(name="Secondary Service").UUID16,permissions=permissions)
		if handle is None:
			self.currentHandle += 1

	def addCharacteristic(self,uuid,value=b"",declarationHandle=None,valueHandle=None,permissions=["Read","Write"]):
		'''
		This method allows to easily add a new characteristic.
		
		:param uuid: uuid associated to the characteristic
		:type uuid: bytes
		:param value: value of the characteristic
		:type value: bytes
		:param declarationHandle: declaration handle of the characteristic
		:type declarationHandle: int
		:param valueHandle: value handle of the characteristic
		:type valueHandle: int
		:param permissions: permissions associated to the characteristic
		:type permissions: list of str

		.. note::

			If no declaration handle is provided, the characteristic declaration is stored as the next available handle.
			If no value handle is provided, the characteristic value is stored as declaration handle + 1
			If no permissions are provided, the characteristic value is stored with "Read" & "Write" permission.

		'''

		newHandle = self.database.getNextHandle() if declarationHandle is None else declarationHandle
		newValueHandle = newHandle+1 if valueHandle is None else valueHandle
		self.addAttribute(handle=newHandle,type=UUID(name="Characteristic Declaration").UUID16,value=CharacteristicDeclaration(UUID=UUID(data=uuid), valueHandle=newValueHandle,permissionsFlag=PermissionsFlag(permissions=permissions)).data[::-1],permissions=["Read"])
		self.addAttribute(handle=newValueHandle,type=uuid, value=value,permissions=permissions) # 0uuid -> bytes


	def addDescriptor(self,uuid,value=b"",handle=None,permissions=["Read","Write","Notify"]):
		'''
		This method allows to easily add a new descriptor.
		
		:param uuid: uuid associated to the descriptor
		:type uuid: bytes
		:param value: value of the descriptor
		:type value: bytes
		:param handle:  handle of the descriptor
		:type handle: int

		.. note::

			If no handle is provided, the descriptor is stored as the next available handle.
			If no permissions are provided, the descriptor is stored with "Read","Write" and "Notify" permission.

		'''
		newHandle = self.database.getNextHandle() if handle is None else handle
		self.addAttribute(handle=newHandle,type=uuid,value=value,permissions=permissions)

