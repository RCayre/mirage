class DuckyScriptParser:
	'''
	This class is a parser for the DuckyScript language.
	It allows to generate a sequence of frame to inject keystrokes according to the provided script.
	'''
	def __init__(self,content="",filename=""):
		if content != "":
			self.content = content
		else:
			self.content = open(filename,"r").read()

		self.specialKeys ={
			"ENTER":["ENTER"],
			"super":["GUI","WINDOWS"],
			"ctrl":["CTRL","CONTROL"],
			"alt":["ALT"],
			"shift":["SHIFT"],
			"DOWNARROW":["DOWNARROW","DOWN"],
			"UPARROW":["UPARROW","UP"],
			"LEFTARROW":["LEFTARROW","LEFT"],
			"RIGHTARROW":["RIGHTARROW","RIGHT"],
			"F1":["F1"],
			"F2":["F2"],
			"F3":["F3"],
			"F4":["F4"],
			"F5":["F5"],
			"F6":["F6"],
			"F7":["F7"],
			"F8":["F8"],
			"F9":["F9"],
			"F10":["F10"],
			"F11":["F11"],
			"F12":["F12"],
			"ESC":["ESC","ESCAPE"],
			"PAUSE":["PAUSE"],
			"SPACE":["SPACE"],
			"TAB":["TAB"],
			"END":["END"],
			"DELETE":["DELETE"],
			"PAUSE":["BREAK","PAUSE"],
			"PRINTSCREEN":["PRINTSCREEN"],
			"CAPSLOCK":["CAPSLOCK"],
			"SCROLLLOCK":["SCROLLLOCK"],
			"INSERT":["INSERT"],
			"HOME":["HOME"],
			"PAGEUP":["PAGEUP"],
			"PAGEDOWN":["PAGEDOWN"]
		}

	def _isSpecialKey(self,string):
		for k,v in self.specialKeys.items():
			if string in v:	
				return True
		return False

	def _getSpecialKey(self,string):
		for k,v in self.specialKeys.items():
			if string in v:
				return k
		return string

	def _parseInstruction(self,instruction=[]):
		first = instruction[0]
		if first == "REM":
			return None
		elif first == "STRING":
			return {"type":"text", "param":" ".join(instruction[1:])}
		elif first == "DELAY":
			return {"type":"sleep", "param":int(instruction[1])}
		elif first == "REPEAT":
			return {"type":"repeat", "param":int(instruction[1])}
		elif first == "DEFAULTDELAY" or first == "DEFAULT_DELAY":
			return {"type":"defaultdelay", "param":int(instruction[1])}
		elif first == "APP" or first == "MENU":
			return {"type":"keys","param":["shift","F10"]}
		elif self._isSpecialKey(first):
			keys = []
			for k in instruction:
				keys.append(self._getSpecialKey(k))
			if len(keys)==1:
				if keys[0] in ("ctrl","alt","shift"):
					key = key.upper()
				elif keys[0] == "super":
					key = "GUI"
				else:
					key = keys[0]
				return {"type":"key", "param":key}
			else:					
				return {"type":"keys", "param":keys}

	def _parse(self):
		self.instructions = []
		instructions = self.content.split("\n")
		for instruction in instructions:
			tokens = instruction.split(" ")
			generated = self._parseInstruction(tokens)
			if generated is not None:
				self.instructions.append(generated)

	def _generatePacketsFromInstruction(self,
						currentDelay=0,
						previousInstruction={},
						currentInstruction={},
						textFunction=None,
						keyFunction=None,
						sleepFunction=None
					):
		defaultDelay,packets = currentDelay, []
		if currentInstruction["type"] == "defaultdelay":
			defaultDelay = currentInstruction["param"]
		elif currentInstruction["type"] == "sleep":
			packets += sleepFunction(duration=currentInstruction["param"])
		elif currentInstruction["type"] == "repeat" and previousInstruction != {}:
			for _ in range(currentInstruction["param"]):
				defaultDelay,nextPackets = self._generatePacketsFromInstruction(
										currentDelay=currentDelay,
										previousInstruction={},
										currentInstruction=previousInstruction,
										textFunction=textFunction,
										keyFunction=keyFunction,
										sleepFunction=sleepFunction
										)
				packets += nextPackets
		elif currentInstruction["type"] == "text":
			packets += textFunction(string=currentInstruction["param"])
		elif currentInstruction["type"] == "key":
			packets += keyFunction(key=currentInstruction["param"])
		elif currentInstruction["type"] == "keys":
			ctrl = "ctrl" in currentInstruction["param"]
			alt = "alt" in currentInstruction["param"]
			gui = "super" in currentInstruction["param"]
			shift = "shift" in currentInstruction["param"]
			key = ""
			for i in currentInstruction["param"]:
				if i not in ("ctrl","alt","super","shift"):
					key = i
			packets += keyFunction(key=key,shift=shift,gui=gui,ctrl=ctrl,alt=alt)
		return defaultDelay,packets

	def generatePackets(self,textFunction=None, keyFunction=None, sleepFunction=None, initFunction=None):
		'''
		This function allows to generate the sequence of packets corresponding to the provided script.
		You have to provide different functions that returns the sequence of packets for a given action.

		:param textFunction: function corresponding to a text injection
		:type textFunction: func
		:param keyFunction: function corresponding to a single keystroke injection
		:type keyFunction: func
		:param sleepFunction: function corresponding to a sleep interval
		:type sleepFunction: func
		:param initFunction: function corresponding to the initialization of the process
		:type initFunction: func
		:return: sequence of packets
		:rtype: list of ``mirage.libs.wireless_utils.packets.Packet``

		'''
		self._parse()
		defaultDelay = 0
		previousInstruction = {}
		currentInstruction = {}
		packets = initFunction()
		for currentInstruction in self.instructions:
			newDelay,nextPackets = self._generatePacketsFromInstruction(
										currentDelay=defaultDelay,
										previousInstruction=previousInstruction,
										currentInstruction=currentInstruction,
										textFunction=textFunction,
										keyFunction=keyFunction,
										sleepFunction=sleepFunction
										)
			packets += nextPackets
			defaultDelay = newDelay
			if defaultDelay > 0:
				packets += sleepFunction(duration=defaultDelay)
			previousInstruction = currentInstruction
		return packets
