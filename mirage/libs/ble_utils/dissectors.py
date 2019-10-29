import struct,copy
from mirage.libs.wireless_utils.dissectors import Dissector
from mirage.libs.bt_utils.assigned_numbers import *
from mirage.libs.common.hid import HIDMapping

class PermissionsFlag(Dissector):
	'''
	This class is a dissector for the permissions flag (ATT/GATT). It inherits from ``Dissector``.

	The following fields are available in the data structure :
	  * **permissions** : field indicating permissions as a list of strings (ex : ['Write Without Response', 'Read'])
		
	The following permissions can be used : 
 	 * "Extended Properties"
	 * "Authenticated Signed Writes"
	 * "Indicate"
	 * "Notify"
	 * "Write"
	 * "Write Without Response"
	 * "Read"
	 * "Broadcast"

	:Example:

		>>> dissector=PermissionsFlag(permissions=["Write", "Read"])
		>>> dissector.data.hex()
		'0a'
		>>> dissector2=PermissionsFlag(data=bytes.fromhex("0a"))
		>>> dissector2.permissions
		['Write', 'Read']
		>>> for permission in dissector2:
		...     print(permission)
		... 
		Write
		Read
		>>> dissector2.permissions += ["Write Without Response"]
		>>> dissector2.data.hex()
		'0e'
		>>> dissector.data = bytes.fromhex("0e")
		>>> dissector.dissect()
		>>> dissector.permissions
		['Write', 'Write Without Response', 'Read']


	'''
	def dissect(self):
		self.content = {"permissions":AssignedNumbers.getPermissionsByNumber(struct.unpack('B',self.data)[0])}

	def build(self):
		self.data = struct.pack('B',AssignedNumbers.getNumberByPermissions(self.content["permissions"]))
		self.length = len(self.data)


	def __contains__(self, key):
		return key in self.content["permissions"]

	def __iter__(self) :
		return self.content["permissions"].__iter__()

	def __next__(self) :
		return self.content["permissions"].__next__()

	def __str__(self):
		sortie = ""
		for i in self.content["permissions"]:
			sortie += ("" if sortie == "" else ",") + i
		return "Flag("+sortie+")"

class UUID(Dissector):
	'''
	This class inherits from ``Dissector``, and allows to quicky and easily use UUID (Universally Unique IDentifier).
	It provides a way to convert them into their multiple forms.
	
	This dissector uses the data structure dictionary in order to use the following fields as simple attributes :
	  * **UUID16** field : UUID (16 bits)
	  * **UUID128** field : UUID (128 bits)
	  * **name** field : name

 	:Example:

		>>> UUID(name="Generic Access").data.hex()
		'1800'
		>>> UUID(data=bytes.fromhex('1800')).name
		'Generic Access'
		>>> UUID(data=bytes.fromhex('1800')).UUID16
		6144
		>>> UUID(data=bytes.fromhex('1800')).UUID128.hex()
		'0000180000001000800000805f9b34fb'
		>>> UUID(data=bytes.fromhex('1801'))
		UUID(128bits:00001801-0000-1000-8000-00805f9b34fb, 16bits:0x1801, name:Generic Attribute )

	'''
	def _correct128(self):
		if "UUID128" in self.content and len(self.content["UUID128"]) == 32:
			self.content["UUID128"] = self.content["UUID128"].replace(b"-",b"").hex()

	def dissect(self):

		if self.length == 2:
			uuid16 = struct.unpack('>H',self.data)[0]
			uuid128 = b"\x00\x00" + self.data + b"\x00\x00\x10\x00\x80\x00\x00\x80\x5F\x9B\x34\xFB"
			name = AssignedNumbers.getNameByNumber(uuid16)
			self.content={"UUID16":uuid16,"UUID128":uuid128,"name":name}
		else:
			uuid = self.data[0:16]
			self.content={"UUID128":uuid}


	def build(self):
		if "UUID16" in self.content:
			self.content['name'] =  AssignedNumbers.getNameByNumber(self.content['UUID16'])			
			self.data = struct.pack('>H',self.content['UUID16'])
			self.content["UUID128"] = b"\x00\x00" + self.data + b"\x00\x00\x10\x00\x80\x00\x00\x80\x5F\x9B\x34\xFB"
		elif "UUID128" in self.content:
			self._correct128()

			if b"\x00\x00\x10\x00\x80\x00\x00\x80\x5f\x9b\x34\xfb" in self.content["UUID128"]:
				self.content["UUID16"] = struct.unpack('>H',self.content["UUID128"][2:4])[0]
				self.data = self.content['UUID16'] if "UUID16" in self.content else self.content['UUID128']
		elif "name" in self.content:
			self.content["UUID16"] = AssignedNumbers.getNumberByName(self.content['name'])
			self.data = struct.pack('>H',self.content['UUID16'])
			self.content["UUID128"] = b"\x00\x00" + self.data + b"\x00\x00\x10\x00\x80\x00\x00\x80\x5F\x9B\x34\xFB"

	def _str128(self,uuid128):
		return uuid128[0:4].hex()+"-"+uuid128[4:6].hex()+"-"+uuid128[6:8].hex()+"-"+uuid128[8:10].hex()+"-"+uuid128[10:16].hex()

	def __str__(self):
		string = "UUID(128bits:"+self._str128(self.content['UUID128'])
		if "UUID16" in self.content:
			string += ", 16bits:"+hex(self.content['UUID16'])
		if "name" in self.content and self.content['name'] is not None:
			string += ", name:"+self.content['name']
		string += " )"
		return string


class CharacteristicDeclaration(Dissector):
	'''
	This class is a dissector for the characteristic declarations (GATT). It inherits from ``Dissector``.

	This dissector uses the data structure dictionary in order to use the following fields as simple attributes :
	  * **UUID** field : characteristic's UUID (see also the following dissector : ``UUID``)
	  * **permissions** field : characteristic's Permissions Flag (see also the following dissector : ``PermissionsFlag``)
	  * **valueHandle** field : characteristic's value handle

 	:Example:

		>>> CharacteristicDeclaration(data=bytes.fromhex('2a00000302'))
		Characteristic Declaration( UUID=UUID(128bits:00002a00-0000-1000-8000-00805f9b34fb, 16bits:0x2a00, name:Device Name ) , valueHandle=0x3 , permissionsFlag=Flag(Read))
		>>> CharacteristicDeclaration(data=bytes.fromhex('2a00000302')).UUID
		UUID(128bits:00002a00-0000-1000-8000-00805f9b34fb, 16bits:0x2a00, name:Device Name )
		>>> CharacteristicDeclaration(data=bytes.fromhex('2a00000302')).valueHandle
		3
		>>> CharacteristicDeclaration(data=bytes.fromhex('2a00000302')).permissionsFlag
		Flag(Read)
		>>> CharacteristicDeclaration(UUID=UUID(name="Device Name"),valueHandle=0x0003,permissionsFlag=PermissionsFlag(permissions=["Read"])).data.hex()
		'2a00000302'


	'''
	def dissect(self):

		if self.length == 5:
			uuid = UUID(data=self.data[0:2])
			valueHandle = struct.unpack('>H',self.data[2:4])[0]
			permissionsFlag = PermissionsFlag(data=self.data[4:5])
		elif self.length == 19:
			uuid = UUID(data=self.data[0:16])
			valueHandle = struct.unpack('>H',self.data[16:18])[0]
			permissionsFlag = PermissionsFlag(data=self.data[18:19])
		self.content = {"UUID":uuid,"valueHandle":valueHandle,"permissionsFlag":permissionsFlag}

	def build(self):
		self.content["UUID"].build()
		valueHandleData = struct.pack('>H',self.content["valueHandle"])
		self.content["permissionsFlag"].build()
		self.data = self.content["UUID"].data+valueHandleData+self.content["permissionsFlag"].data

	def __str__(self):
		return "Characteristic Declaration( UUID="+str(self.content["UUID"])+" , valueHandle="+hex(self.content["valueHandle"])+" , permissionsFlag="+str(self.content['permissionsFlag'])+")"


class CharacteristicDescriptor(Dissector):
	'''
	This class is a dissector for the characteristic descriptors (GATT). It inherits from ``Dissector``.

	This dissector uses the data structure dictionary in order to use the following fields as simple attributes :
	  * **UUID** field : descriptor's UUID (see also the following dissector : ``UUID``)

 	:Example:

		>>> CharacteristicDescriptor(data=bytes.fromhex("2901"))
		Characteristic Descriptor( UUID=UUID(128bits:00002901-0000-1000-8000-00805f9b34fb, 16bits:0x2901, name:Characteristic User Description ) )
		>>> CharacteristicDescriptor(UUID=UUID(UUID16=0x2901)).data.hex()
		'2901'

	'''
	def dissect(self):
		uuid = UUID(data=self.data)
		self.content = {"UUID":uuid}

	def build(self):
		self.content['UUID'].build()
		self.data = self.content['UUID'].data

	def __str__(self):
		return "Characteristic Descriptor( UUID="+str(self.content["UUID"])+" )"

class Service(Dissector):
	'''
	This class is a dissector for the services (GATT). It inherits from ``Dissector``.

	This dissector uses the data structure dictionary in order to use the following fields as simple attributes :
	  * **UUID** field : descriptor's UUID (see also the following dissector : ``UUID``)

 	:Example:

		>>> Service(data=bytes.fromhex("1800"))
		Service( UUID=UUID(128bits:00001800-0000-1000-8000-00805f9b34fb, 16bits:0x1800, name:Generic Access ) )
		>>> Service(data=bytes.fromhex("1800")).UUID
		UUID(128bits:00001800-0000-1000-8000-00805f9b34fb, 16bits:0x1800, name:Generic Access )
		>>> Service(UUID=UUID(UUID16=0x1800)).data.hex()
		'1800'

	'''
	def dissect(self):
		uuid = UUID(data=self.data)
		self.content = {"UUID":uuid}

	def build(self):
		self.content['UUID'].build()
		self.data = self.content['UUID'].data

	def __str__(self):
		return "Service( UUID="+str(self.content["UUID"])+" )"



class InputOutputCapability(Dissector):
	'''
	This class is a dissector for the Input Output Capability (Security Manager). It inherits from ``Dissector``.

	This dissector uses the data structure dictionary in order to use the following fields as simple attributes :
	  * **display** field : boolean indicating if the device provides a display output
	  * **yesno** field : boolean indicating if the device has yes/no input
	  * **keyboard** field : boolean indicating if the device has a keyboard input

 	:Example:

		>>> InputOutputCapability(display=True, yesno=False, keyboard=True).data.hex()
		'04'
		>>> InputOutputCapability(data=data=bytes.fromhex("04"))
		Input Output Capability(0x4,keyboard:yes|yesno:no|display:yes)


	'''
	def dissect(self):
		self.content = {"display":self.data in (b"\x00",b"\x01",b"\x04"),
				"yesno":self.data == b"\x01",
				"keyboard":self.data in (b"\x02",b"\x04")}

	def build(self):
		self.data = b"\x03"
		if self.content["display"]:
			self.data = b"\x00"
			if self.content["yesno"]:
				self.data = b"\x01"
			if self.content["keyboard"]:
				self.data = b"\x04"
		elif self.content["keyboard"]:
			self.data = b"\x02"
			

	def __contains__(self, key):
		return key in self.content and self.content[key]

	def __iter__(self) :
		return self.content.__iter__()

	def __next__(self) :
		return self.content.__next__()

	def __str__(self):
		keyboard = "yes" if self.content["keyboard"] else "no"
		yesno = "yes" if self.content["yesno"] else "no"
		display = "yes" if self.content["display"] else "no"			
		return "Input Output Capability("+hex(self.data[0])+",keyboard:"+keyboard+"|yesno:"+yesno+"|display:"+display+")"


class AuthReqFlag(Dissector):
	'''
	This class is a dissector for the Authentication Request Flag (Security Manager). It inherits from ``Dissector``.

	This dissector uses the data structure dictionary in order to use the following fields as simple attributes :
	  * **bonding** field : boolean indicating if bonding is required
	  * **mitm** field : boolean indicating if MiTM protection is required
	  * **secureConnections** field : boolean indicating if a secure connection is required
	  * **keypress** field : boolean indicating if the keypress mode is required
	  * **ct2** field : boolean indicating if ct2 is required

 	:Example:

		>>> AuthReqFlag(bonding=True, mitm=True).data.hex()
		'05'
		>>> AuthReqFlag(data=data=bytes.fromhex("05"))
		AuthReq Flag(0x5,bonding:yes|mitm:yes|secureConnections:no|keypress:no|ct2:no)

	'''
	def _bytes2bits(self,data):
		return "".join(["{:08b}".format(i) for i in bytes(data)])

	def _bits2bytes(self,bits):
		return bytes([int(j+((8-len(j))*"0"),2) for j in [bits[i:i + 8] for i in range(0, len(bits), 8)]])

	def dissect(self):
		data = self._bytes2bits(self.data)
		self.content = {"bonding":data[6:] == "01",
				"mitm":data[5] == "1",
				"secureConnections":data[4] == "1",
				"keypress":data[3] == "1",
				"ct2":data[2] == "1"
				}

	def build(self):
		bits = ""
		bits += "00"
		bits += "1" if "ct2" in self.content and self.content["ct2"] else "0"
		bits += "1" if "keypress" in self.content and  self.content["keypress"] else "0"
		bits += "1" if "secureConnections" in self.content and self.content["secureConnections"] else "0"
		bits += "1" if "mitm" in self.content and self.content["mitm"] else "0"
		bits += "01"if "bonding" in self.content and self.content["bonding"] else "00"
		self.data = self._bits2bytes(bits)


	def __contains__(self, key):
		return key in self.content and self.content[key]

	def __iter__(self) :
		return self.content.__iter__()

	def __next__(self) :
		return self.content.__next__()

	def __str__(self):
		bonding = "yes" if self.content["bonding"] else "no"
		mitm = "yes" if self.content["mitm"] else "no"
		secureConnections = "yes" if self.content["secureConnections"] else "no"
		keypress = "yes" if self.content["keypress"] else "no"
		ct2 = "yes" if self.content["ct2"] else "no"			
		return "AuthReq Flag("+hex(self.data[0])+",bonding:"+bonding+"|mitm:"+mitm+"|secureConnections:"+secureConnections+"|keypress:"+keypress+"|ct2:"+ct2+")"




class KeyDistributionFlag(Dissector):
	'''
	This class is a dissector for the Key Distribution Flag (Security Manager). It inherits from ``Dissector``.

	This dissector uses the data structure dictionary in order to use the following fields as simple attributes :
	  * **encKey** field : boolean indicating if an encryption key is required (LTK + Ediv + RAND)
	  * **idKey** field : boolean indicating if an identification key is required (IRK + BD_Addr + BD_Addr mode)
	  * **signKey** field : boolean indicating if a signing key is required (CSRK)
	  * **linkKey** field : boolean indicating if a link key is required

 	:Example:

		>>> KeyDistributionFlag(idKey=True,encKey=True).data.hex()
		'03'
		>>> KeyDistributionFlag(data=bytes.fromhex("03"))
		Key Distribution Flag(0x3,encKey:yes|idKey:yes|signKey:no|linkKey:no)


	'''
	def _bytes2bits(self,data):
		return "".join(["{:08b}".format(i) for i in bytes(data)])

	def _bits2bytes(self,bits):
		return bytes([int(j+((8-len(j))*"0"),2) for j in [bits[i:i + 8] for i in range(0, len(bits), 8)]])

	def dissect(self):
		data = self._bytes2bits(self.data)
		self.content = {"encKey":data[7] == "1",
				"idKey": data[6] == "1",
				"signKey": data[5] == "1",
				"linkKey":data[4] == "1"}

	def build(self):
		bits = ""
		bits += "0000"
		bits += "1" if "linkKey" in self.content and self.content["linkKey"] else "0"
		bits += "1" if "signKey" in self.content and  self.content["signKey"] else "0"
		bits += "1" if "idKey" in self.content and  self.content["idKey"] else "0"
		bits += "1" if "encKey" in self.content and  self.content["encKey"] else "0"
		self.data = self._bits2bytes(bits)


	def __contains__(self, key):
		return key in self.content and self.content[key]

	def __iter__(self) :
		return self.content.__iter__()

	def __next__(self) :
		return self.content.__next__()

	def __str__(self):
		encKey = "yes" if self.content["encKey"] else "no"
		idKey = "yes" if self.content["idKey"] else "no"
		signKey = "yes" if self.content["signKey"] else "no"
		linkKey = "yes" if self.content["linkKey"] else "no"
			
		return "Key Distribution Flag("+hex(self.data[0])+",encKey:"+encKey+"|idKey:"+idKey+"|signKey:"+signKey+"|linkKey:"+linkKey+")"



class HIDoverGATTKeystroke(Dissector):
	'''
	This class is a dissector for the HID over GATT keystroke payload. It inherits from ``Dissector``.

	The following fields are available in the data structure :
	  * **locale** : string indicating the locale (language layout)
	  * **key** : string indicating the key
	  * **ctrl** : boolean indicating if the Ctrl key is pressed
	  * **alt** : boolean indicating if the Alt key is pressed
	  * **super** : boolean indicating if the Super key is pressed
	  * **shift** : boolean indicating if the Shift key is pressed
		

	:Example:

		>>> HIDoverGATTKeystroke(locale="fr",key="a",ctrl=False,gui=False,alt=False,shift=False)
		Keystroke(key=a,ctrl=no,alt=no,shift=no,gui=no)
		>>> HIDoverGATTKeystroke(locale="fr",key="a",ctrl=False,gui=False,alt=False,shift=False).data.hex()
		'0000140000000000'


	'''
	def dissect(self):
		# TODO
		pass

	def build(self):
		locale = self.content["locale"]
		key = self.content["key"]
		ctrl = self.content["ctrl"]
		alt = self.content["alt"]
		gui = self.content["gui"]
		shift = self.content["shift"]
		(hidCode,modifiers) = HIDMapping(locale).getHIDCodeFromKey(key=key,alt=alt,ctrl=ctrl,shift=shift,gui=gui)
		self.data = bytes([0,modifiers,hidCode,0,0,0,0,0])

	def __str__(self):
		sortie = "key="+str(self.content["key"])+",ctrl="+("yes" if self.content["ctrl"] else "no")+",alt="+("yes" if self.content["alt"] else "no")+",shift="+("yes" if self.content["shift"] else "no")+",gui="+("yes" if self.content["gui"] else "no")
		return "Keystroke("+sortie+")"
