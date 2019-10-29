class MosartKeyboardCodes:
	'''
	This class allows to convert the Mosart keyboard codes to the corresponding HID code and modifiers.

	.. warning::
		
		These values have been collected empirically. 
		As a result, the corresponding mapping may contains some mistakes or missing data.

	'''
	@classmethod
	def getMosartKeyboardCodeFromHIDCode(cls,hidCode,modifiers):
		'''
		This method returns the Mosart keybaord
		'''
		value = [hidCode,modifiers]
		for k,v in MosartKeyboardCodes.mosartKeyboardCodes.items():
			if v == value:
				return k
		return None

	@classmethod
	def getHIDCodeFromMosartKeyboardCode(cls,code):
		if code in MosartKeyboardCodes.mosartKeyboardCodes:
			return MosartKeyboardCodes.mosartKeyboardCodes[code]
		else:
			return [None,None]

	mosartKeyboardCodes =  {
		0x8 : [ 72,0],
		0xc : [ 0,16],
		0xe : [ 0,1],
		0xf : [ 62,0],
		0x10 : [ 20,0],
		0x11 : [ 43,0],
		0x12 : [ 4,0],
		0x13 : [ 41,0],
		0x14 : [ 29,0],
		0x15 : [ 139,0],
		0x16 : [ 53,0],
		0x17 : [ 30,0],
		0x18 : [ 26,0],
		0x19 : [ 57,0],
		0x1a : [ 22,0],
		0x1b : [ 100,0],
		0x1c : [ 27,0],
		0x1d : [ 138,0],
		0x1e : [ 58,0],
		0x1f : [ 31,0],
		0x20 : [ 8,0],
		0x21 : [ 60,0],
		0x22 : [ 7,0],
		0x23 : [ 61,0],
		0x24 : [ 6,0],
		0x25 : [ 136,0],
		0x26 : [ 59,0],
		0x27 : [ 32,0],
		0x28 : [ 21,0],
		0x29 : [ 23,0],
		0x2a : [ 9,0],
		0x2b : [ 10,0],
		0x2c : [ 25,0],
		0x2d : [ 5,0],
		0x2e : [ 34,0],
		0x2f : [ 33,0],
		0x30 : [ 24,0],
		0x31 : [ 28,0],
		0x32 : [ 13,0],
		0x33 : [ 11,0],
		0x34 : [ 16,0],
		0x35 : [ 17,0],
		0x36 : [ 35,0],
		0x37 : [ 36,0],
		0x38 : [ 12,0],
		0x39 : [ 48,0],
		0x3a : [ 14,0],
		0x3b : [ 63,0],
		0x3c : [ 54,0],
		0x3d : [ 135,0],
		0x3e : [ 46,0],
		0x3f : [ 37,0],
		0x40 : [ 18,0],
		0x41 : [ 64,0],
		0x42 : [ 15,0],
		0x44 : [ 55,0],
		0x45 : [ 101,0],
		0x46 : [ 65,0],
		0x47 : [ 38,0],
		0x48 : [ 19,0],
		0x49 : [ 47,0],
		0x4a : [ 51,0],
		0x4b : [ 52,0],
		0x4c : [ 50,0],
		0x4d : [ 56,0],
		0x4e : [ 45,0],
		0x4f : [ 39,0],
		0x50 : [ 71,0],
		0x53 : [ 0,4],
		0x55 : [ 0,64],
		0x57 : [ 70,0],
		0x58 : [ 137,0],
		0x59 : [ 42,0],
		0x5a : [ 49,0],
		0x5b : [ 68,0],
		0x5c : [ 40,0],
		0x5d : [ 69,0],
		0x5e : [ 66,0],
		0x5f : [ 67,0],
		0x60 : [ 95,0],
		0x61 : [ 92,0],
		0x62 : [ 89,0],
		0x63 : [ 44,0],
		0x64 : [ 83,0],
		0x65 : [ 81,0],
		0x66 : [ 76,0],
		0x68 : [ 96,0],
		0x69 : [ 93,0],
		0x6a : [ 90,0],
		0x6b : [ 98,0],
		0x6c : [ 84,0],
		0x6d : [ 79,0],
		0x6e : [ 73,0],
		0x70 : [ 97,0],
		0x71 : [ 94,0],
		0x72 : [ 91,0],
		0x73 : [ 99,0],
		0x74 : [ 85,0],
		0x75 : [ 86,0],
		0x76 : [ 75,0],
		0x77 : [ 78,0],
		0x78 : [ 87,0],
		0x79 : [ 133,0],
		0x7a : [ 88,0],
		0x7b : [ 82,0],
		0x7d : [ 80,0],
		0x7e : [ 74,0],
		0x7f : [ 77,0],
		0x81 : [ 0,2],
		0x82 : [ 0,32],
		0x89 : [ 0,8],
		0x90 : [ 145,0],
		0x92 : [ 0,128],
		0x97 : [ 144,0],
		0x98 : [ 98,0],
		0x99 : [ 98,0],
		0x9a : [ 0,9],
		0x9b : [ 0,8],
		0x9c : [ 0,9],
		0x9d : [ 0,8],
		0x9e : [ 0,4]
	}

