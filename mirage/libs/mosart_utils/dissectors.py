from mirage.libs.wireless_utils.dissectors import Dissector
from mirage.libs.mosart_utils.keyboard_codes import *

class MosartKeystroke(Dissector):
	'''
	This class is a dissector for the Mosart keystroke payload. It inherits from ``Dissector``.

	The following fields are available in the data structure :
	  * **hidCode** : integer indicating the hid code of the key
	  * **modifiers** : integer indicating the modifiers code of the key

	:Example:

		>>> MosartKeystroke(hidCode=5,modifiers=0).data.hex()
		'812d'
		>>> MosartKeystroke(data=bytes.fromhex("812d")).hidCode
		5
		>>> MosartKeystroke(data=bytes.fromhex("812d")).modifiers
		0


	'''
	def dissect(self):
		state = self.data[0]
		code = self.data[1]
		if state == 0x01:
			hidCode,modifiers = [0,0]
		else:
			[hidCode,modifiers] = MosartKeyboardCodes.getHIDCodeFromMosartKeyboardCode(code)

		self.content = {"code":code,"state":state,"hidCode":hidCode,"modifiers":modifiers}

	def build(self):
		hidCode = self.content["hidCode"]
		modifiers = self.content["modifiers"]
		if hidCode == 0 and modifiers == 0:
			state = 0x01
		else:
			state = 0x81
		code = MosartKeyboardCodes.getMosartKeyboardCodeFromHIDCode(hidCode,modifiers)
		if code is not None:
			self.data = bytes([state,code])
		else:
			self.data = bytes([state,0]) # Maybe it should be necessary to re-use the value from the previous frame (in "pressed" state)

		
