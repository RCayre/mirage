from mirage.libs.wireless_utils.dissectors import Dissector
from mirage.libs.common.hid import HIDMapping
from mirage.libs.esb_utils.helpers import bytes2bits
from struct import pack

class LogitechMousePosition(Dissector):
	'''
	This class is a dissector for the Logitech Unifying mouse position value. It inherits from ``Dissector``.

	The following fields are available in the data structure :
	  * **x** : field indicating x position of the mouse
	  * **y** : field indicating y position of the mouse
		

	:Example:

		>>> LogitechMousePosition(data=bytes.fromhex("feafff"))
		MousePosition(x=-2,y=-6)
		>>> LogitechMousePosition(data=bytes.fromhex("feafff")).x
		-2
		>>> LogitechMousePosition(data=bytes.fromhex("feafff")).y
		-6
		>>> LogitechMousePosition(x=-2,y=-6).data.hex()
		'feafff'
	'''
	def dissect(self):
		bits = bytes2bits(self.data)
		xb = bits[12:16] + bits[0:8]
		yb =  bits[16:] + bits[8:12]
		if xb[0] == "0":
			x = sum([(2**(11-i))*int(xb[i]) for i in range(0,12)])
		else:
			x = -1*(1+sum([(2**(11-i))*(1 - int(xb[i])) for i in range(0,12)]))
		if yb[0] == "0":
			y = sum([(2**(11-i))*int(yb[i]) for i in range(0,12)])
		else:
			y = -1*(1+sum([(2**(11-i))*(1 - int(yb[i])) for i in range(0,12)]))

		self.content = {"x":x,"y":y}

	def build(self):
		x = self.content["x"]
		y = self.content["y"]
		if (y < 0):
			y += 4096
		if (x < 0):
			x += 4096
		a,b,c = 0,0,0
		a = x & 0xFF
		b |= (x >> 8) & 0x0F
		c = (y >> 4) & 0xFF
		b |= (y << 4) & 0xF0

		ab = pack('B',a)
		bb = pack('B',b)
		cb = pack('B',c)

		self.data = b"".join([ab,bb,cb])
		self.length = len(self.data)


	def __str__(self):
		sortie = "x="+str(self.content["x"])+",y="+str(self.content["y"])
		return "MousePosition("+sortie+")"



class LogitechKeystroke(Dissector):
	'''
	This class is a dissector for the Logitech Unifying unencrypted keystroke payload. It inherits from ``Dissector``.

	The following fields are available in the data structure :
	  * **locale** : string indicating the locale (language layout)
	  * **key** : string indicating the key
	  * **ctrl** : boolean indicating if the Ctrl key is pressed
	  * **alt** : boolean indicating if the Alt key is pressed
	  * **super** : boolean indicating if the Super key is pressed
	  * **shift** : boolean indicating if the Shift key is pressed
		

	:Example:

		>>> LogitechKeystroke(locale="fr",key="a",ctrl=False,gui=False,alt=False,shift=False)
		Keystroke(key=a,ctrl=no,alt=no,shift=no,gui=no)
		>>> LogitechKeystroke(locale="fr",key="a",ctrl=False,gui=False,alt=False,shift=False).data.hex()
		'00140000000000'

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
		(hidCode,modifiers) = HIDMapping(locale=locale).getHIDCodeFromKey(key=key,alt=alt,ctrl=ctrl,shift=shift,gui=gui)
		self.data = pack('B',modifiers)+pack('B',hidCode)+(b'\x00'*5)

	def __str__(self):
		sortie = "key="+str(self.content["key"])+",ctrl="+("yes" if self.content["ctrl"] else "no")+",alt="+("yes" if self.content["alt"] else "no")+",shift="+("yes" if self.content["shift"] else "no")+",gui="+("yes" if self.content["gui"] else "no")
		return "Keystroke("+sortie+")"
