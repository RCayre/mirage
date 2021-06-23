import configparser

class Config:
	'''
	This class is used to parse and generate a configuration file in ".cfg" format.
	'''
	def __init__(self, filename):
		'''
		This constructor initializes the parser and load the configuration file provided in parameter ``filename``.

		:param filename: Filename of the configuration file
		:type filename: str
		'''
		self.parser = configparser.ConfigParser()
		self.datas = {}
		self.shortcuts = {}
		self.filename = filename
		self.generateDatas()
		self.generateShortcuts()

	def generateDatas(self):
		'''
		This method parses the configuration file and store the corresponding arguments in the attribute ``datas``.
		'''
		try:
			self.parser.read(self.filename)
			for module in self.parser.sections():
				if "shortcut:" not in module:
					arguments = {}
					for (key,value) in self.parser.items(module):
						arguments[key.upper()] = value
					self.datas[module] = arguments
		except configparser.ParsingError:
			io.fail("Bad format file !")

	def generateShortcuts(self):
		'''
		This method parses the configuration file and store the corresponding arguments in the attribute ``datas``.
		'''
		try:
			self.parser.read(self.filename)
			for section in self.parser.sections():
				if "shortcut:" in section:
					shortcutName = section.split("shortcut:")[1]
					modules = None
					description = ""
					arguments = {}
					for (key,value) in self.parser.items(section):
						if key.upper() == "MODULES":
							modules = value
						elif key.upper() == "DESCRIPTION":
							description = value
						else:
							if "(" in value and ")" in value:
								names = value.split("(")[0]
								defaultValue = value.split("(")[1].split(")")[0]

								arguments[key.upper()] = {
											"parameters":names.split(","),
											"value":defaultValue
								}
							else:
								arguments[key.upper()] = {
											"parameters":value.split(","),
											"value":None
								}
					if modules is not None:
						self.shortcuts[shortcutName] = {"modules":modules,"description":description,"mapping":arguments}
		except configparser.ParsingError:
			io.fail("Bad format file !")

	def getShortcuts(self):
		'''
		This method returns the shortcuts loaded from the configuration file.

		:return: dictionary listing the existing shortcuts
		:rtype: dict
		'''
		return self.shortcuts

	def dataExists(self, moduleName, arg):
		'''
		This method checks if a value has been provided in the configuration file for the argument ``arg`` of the module
		named according to ``moduleName``.

		:param moduleName: name of the module
		:type moduleName: str
		:param arg: name of the argument
		:type arg: str
		:return: boolean indicating if a value has been provided
		:rtype: bool
		'''
		return moduleName in self.datas and arg in self.datas[moduleName]

	def getData(self, moduleName,arg):
		'''
		This method returns the value provided in the configuration file for the argument ``arg`` of the module
		named according to ``moduleName``.

		:param moduleName: name of the module
		:type moduleName: str
		:param arg: name of the argument
		:type arg: str
		:return: value of the parameter
		:rtype: str
		'''
		return self.datas[moduleName][arg]
