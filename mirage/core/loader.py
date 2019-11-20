from mirage.libs import io

class Loader:
	'''
	This class permits to dynamically load the modules.
	'''
	def __init__(self):
		'''
		This constructor generates the modules list.
		'''
		import mirage.modules as modules
		self.modulesList = {}
		for moduleName,module in modules.__modules__.items():
			current = module#__import__("modules."+module, fromlist=module)
			moduleClass = getattr(current,moduleName)
			self.modulesList[moduleName] = moduleClass

	def getModulesNames(self):
		'''
		This method returns a list of existing modules' names.

		:return: list of modules' name
		:rtype: list of str
		'''
		return list(self.modulesList.keys())

	def load(self,moduleName):
		'''
		This method returns an instance of a specific module according to the name provided as parameter.

		:param moduleName: name of a module
		:type moduleName: str
		:return: an instance of the module
		:rtype: core.module.Module
		'''
		if moduleName in self.modulesList:
			return self.modulesList[moduleName]()
		else:
			return None

	
	def list(self,pattern=""):
		'''
		Display the list of module, filtered by the string provided as ``pattern``.

		:param pattern: filter
		:type pattern: str
		'''
		displayDict = {}

		for module in self.modulesList:
			info = self.modulesList[module]().info()
			technology = (info["technology"]).upper()
			if (
				pattern in info["description"]	or
				pattern in info["name"] 	or
				pattern in info["technology"]	or 
				pattern in info["type"]
			):
				if not technology in displayDict:
					displayDict[technology] = []
				displayDict[technology].append([info["name"], info["type"], info["description"]])


		for module in sorted(displayDict):
			if displayDict[module]:
				io.chart(["Name", "Type","Description"], sorted(displayDict[module]), "{} Modules".format(module))
