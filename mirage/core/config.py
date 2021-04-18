import configparser

from mirage.libs import io


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
		self.filename = filename
		self.generateDatas()

	def generateDatas(self):
		'''
		This method parses the configuration file and store the corresponding arguments in the attribute ``datas``.
		'''
		try:
			self.parser.read(self.filename)
			for module in self.parser.sections():
				arguments = {}
				for (key,value) in self.parser.items(module):
					arguments[key.upper()] = value
				self.datas[module] = arguments
		except configparser.ParsingError:
			io.fail("Bad format file !")

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
