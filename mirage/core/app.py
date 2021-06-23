import os
from string import Template
from mirage.core import interpreter,loader,taskManager,module,config,templates
from mirage.core.module import WirelessModule
from mirage.libs import io,utils,wireless

class App(interpreter.Interpreter):
	'''
	This class defines the main Application.
	It inherits from ``core.interpreter.Interpreter``, allowing to use Mirage as a command line interpreter.

	'''
	class SetParameterException(Exception):
		pass
	class NoModuleLoaded(SetParameterException):
		pass
	class IncorrectParameter(SetParameterException):
		pass
	class MultipleModulesLoaded(SetParameterException):
		pass

	Instance = None
	def __init__(self,quiet=False,homeDir="/home/user/.mirage",tempDir="/tmp/mirage"):
		'''
		This constructor allows to initializes the main attributes and software components used by the framework.

		:param quiet: boolean indicating if Mirage has been launched in quiet mode
		:type quiet: bool
		:param homeDir: string indicating the location of the home directory
		:type homeDir: str
		:param tempDir: string indicating the location of the temporary directory
		:type tempDir: str
		'''
		super().__init__()
		App.Instance = self
		self.availableCommands += [
						"start",
						"stop",
						"restart",
						"tasks",
						"clear",
						"list",
						"load",
						"set",
						"run",
						"args",
						"shortcuts",
						"showargs",
						"info",
						"create_module",
						"create_scenario"
					]
		self.quiet = quiet
		self.debugMode = False # TODO : update documentation
		self.tempDir = tempDir
		self.homeDir = homeDir
		self.config = config.Config(homeDir + "/mirage.cfg")
		self.loader = loader.Loader()
		self.loadedShortcuts = self.config.getShortcuts()
		self.modules = []
		self.taskManager = taskManager.TaskManager()
		# Creation of the temporary directory
		if not os.path.exists(self.tempDir):
			os.mkdir(self.tempDir)



	def exit(self):
		'''
		This method allows to exit the framework.
		'''
		self.taskManager.stopAllTasks()

		for emitter in module.WirelessModule.Emitters.values():
			emitter.stop()
		for receiver in module.WirelessModule.Receivers.values():
			receiver.stop()

		utils.stopAllSubprocesses()
		io.info("Mirage process terminated !")
		super().exit()

	def start(self,task):
		'''
		This method allows to start a specific background task according to its name.

		:param task: Task to start
		:type task: str
		'''
		self.taskManager.startTask(task)

	def stop(self,task):
		'''
		This method allows to stop a specific background task according to its name.

		:param task: Task to stop
		:type task: str
		'''
		self.taskManager.stopTask(task)

	def restart(self,task):
		'''
		This method allows to restart a specific background task according to its name.

		:param task: Task name to restart
		:type task: str
		'''
		self.taskManager.restartTask(task)

	def tasks(self,pattern=""):
		'''
		This method allows to display the existing background tasks. A string pattern can be provided as a filter.

		:param pattern: Filter
		:type pattern: str
		'''
		io.chart(["PID","Name","State","Output"], self.taskManager.getTasksList(pattern),"Background Tasks")

	def create_scenario(self):
		'''
		This method allows to interact with the user in order to easily generate an user scenario.
		'''
		name = ""
		while name == "":
			name = io.ask("Scenario's name")
			if name == "":
				io.fail("Scenario's name cannot be empty !")


		scenario = Template(templates.__scenario_template__)
		scenarioContent = scenario.substitute(name=name)
		scenarioFilename = self.homeDir+"/scenarios/"+name+".py"
		f = open(scenarioFilename, 'w')
		f.write(scenarioContent)
		f.close()
		io.success("Scenario "+str(name)+" successfully generated : "+scenarioFilename)

	def create_module(self):
		'''
		This method allows to interact with the user in order to easily generate an user module.
		'''
		name = ""
		while name == "":
			name = io.ask("Module's name")
			if name == "":
				io.fail("Module's name cannot be empty !")
		description = io.ask("Module's description")

		type = io.ask("Module's type")

		technology = io.ask("Module's technology", default="ble")

		dependencies = io.ask("Module's dependencies (separated by commas)").replace(" ","")
		if dependencies != "":
			dependencies = ",".join(['"'+dep+'"' for dep in dependencies.split(",")])

		arguments = {}
		argNumber = 1
		while True:
			argName = io.ask("Input parameter #"+str(argNumber)+" (name)").upper()
			if argName == "":
				break
			argValue = io.ask("Input parameter #"+str(argNumber)+" (default value)")
			arguments[argName] = argValue
			argNumber += 1


		module = Template(templates.__module_template__)
		moduleContent = module.substitute(
					name=name,
					description=description,
					technology=technology,
					type=type,
					dependencies=dependencies,
					arguments=str(arguments))
		moduleFilename = self.homeDir+"/modules/"+name+".py"
		f = open(moduleFilename, 'w')
		f.write(moduleContent)
		f.close()
		io.success("Module "+str(name)+" successfully generated : "+moduleFilename)

	def loop(self):
		'''
		This method allows to run the main interpreter loop.
		'''
		if not self.quiet:
			io.banner()
		interpreter.Interpreter.loop(self)


	def clear(self):
		'''
		This method allows to clear the screen.
		'''
		os.system("clear")

	def list(self, pattern=""):
		'''
		This method allows to list the different modules available in the framework. A string pattern can be provided
		as a filter.

		:param pattern: Filter
		:type pattern: str
		'''
		self.loader.list(pattern)

	def shortcuts(self,pattern=""):
		'''
		This method allows to list the different shortcuts available in the framework. A string pattern can be provided
		as a filter.

		:param pattern: Filter
		:type pattern: str
		'''
		shortcuts = []
		for shortcutName,shortcut in self.loadedShortcuts.items():
			if (pattern == "" or
			    pattern in shortcutName or
			    pattern in shortcut["description"] or
			    pattern in shortcut["modules"]):
				shortcuts.append([shortcutName,shortcut["modules"],shortcut["description"]])
		if shortcuts != []:
			io.chart(["Name","Modules","Description"],shortcuts,"Shortcuts")
		else:
			io.fail("No shortcut found !")

	def _autocompleteModules(self):
		'''
		This method generates the list of available modules in order to autocomplete "load" command.
		'''
		return self.loader.getModulesNames() + list(self.loadedShortcuts.keys())

	def load(self,moduleName:"!method:_autocompleteModules"):
		'''
		This method allows to load a module according to its name.
		It allows to load a sequence of modules by using the pipe (``|``) symbol.

		:param moduleName: name of the module (or sequence of modules) to load
		:type moduleName: str

		:Example:

		>>> app.load('ble_info')
		>>> app.load('ble_connect|ble_discover')

		'''
		modules = moduleName.split("|") if "|" in moduleName else [moduleName]
		tmpModules = []
		counter = 1
		noError = True
		for m in modules:
			output = self.loader.load(m)
			if output is not None:
				io.info("Module "+m+" loaded !")
				tmpModules.append({"name":m+str(counter) if len(modules) > 1 else m,"module":output})
				counter+=1

				for argument in output.args:
					if self.config.dataExists(m,argument):
						output.args[argument] = self.config.getData(m,argument)

			elif m in self.loadedShortcuts:
				io.info("Shortcut "+m+" loaded !")
				shortcutModules = []
				shortcutClasses = []
				shortcutCounter = 1
				shortcutModulesList = self.loadedShortcuts[m]["modules"].split("|")
				for n in shortcutModulesList:
					output = self.loader.load(n)
					shortcutModules.append({
						"name":n+str(shortcutCounter) if len(shortcutModulesList) > 1 else n,
						"module":output
					})
					for argument in self.loadedShortcuts[m]["mapping"]:
						mapping = self.loadedShortcuts[m]["mapping"][argument]
						if mapping["value"] is not None:
							self._set(argument,mapping["value"],[shortcutModules[-1]])

					shortcutCounter+=1

				tmpModules.append({
						"name":m+str(counter) if len(modules) > 1 else m,
						"shortcut":shortcutModules,
						"mapping":self.loadedShortcuts[m]["mapping"]
						})
				counter+=1
			else:
				io.fail("Unknown module "+m+" !")
				noError = False
				break
		if noError:
			self.modules = tmpModules
			self.prompt = io.colorize(" << "+moduleName+" >>~~> ","cyan")

	def _autocompleteParameters(self):
		'''
		This method generates a list including the available parameters names in order to autocomplete "set" command.
		'''
		if len(self.modules) == 0:
			return []
		elif len(self.modules) == 1:
			if "module" in self.modules[0]:
				return self.modules[0]["module"].args.keys()
			elif "shortcut" in self.modules[0]:
				return self.modules[0]["mapping"].keys()
		else:
			parameters = []
			for module in self.modules:
				if "module" in module and module["module"] is not None:
					parameters += [module["name"] + "." + i for i in module["module"].args.keys()]
				elif "shortcut" in module:
					parameters += [module["name"] + "." + i for i in module["mapping"].keys()]
			return parameters


	def _set(self,name,value,modulesList):
		if len(modulesList) == 0:
			raise self.NoModuleLoaded()
			return False
		elif len(modulesList) == 1:
			module = modulesList[0]
			if "module" in module and module["module"] is not None:
				if module["module"].dynamicArgs or name in module["module"].args:
					module["module"].args[name] = value
					return True
				elif (name in wireless.SDRDevice.SDR_PARAMETERS.keys() and
				isinstance(module["module"],WirelessModule)):
					module["module"].sdrConfig[name] = value
					return True
				else:
					raise self.IncorrectParameter()
			elif "shortcut" in module:
				if name in module["mapping"]:
					shortcutMapping = module["mapping"][name]
					success = True
					for parametersName in shortcutMapping["parameters"]:
						success = success and self._set(parametersName,value,module["shortcut"])
					if (success):
						shortcutMapping["value"] = value

					return success
				else:
					raise self.IncorrectParameter()
					return False
			else:
				return False
		else:
			if "." in name:
				(moduleName,argName) = name.split(".")
				for module in modulesList:
					if "module" in module and module["module"] is not None and moduleName == module["name"]:
						return self._set(argName,value,[module])
					elif "shortcut" in module and moduleName == module["name"]:
						if argName in module["mapping"]:
							shortcutMapping = module["mapping"][argName]
							success = True
							for parametersName in shortcutMapping["parameters"]:
								success = success and self._set(parametersName,value,module["shortcut"])
							if (success):
								shortcutMapping["value"] = value
							return success
						else:
							raise self.IncorrectParameter()
							return False

			else:
				raise self.MultipleModulesLoaded()
				return False

	def set(self,name:"!method:_autocompleteParameters",value):
		'''
		This method allows to provide a value for a specific input parameter of the loaded module.

		:param name: parameter's name
		:type name: str
		:param value: value of parameter
		:type value: str

		:Example:

		>>> app.set("INTERFACE","hci0")
		>>> app.set("ble_connect1.INTERFACE", "hci0")

		'''
		try:
			self._set(name,value,self.modules)
		except self.NoModuleLoaded:
			io.fail("No module loaded !")
		except self.MultipleModulesLoaded:
			io.fail("No corresponding parameter ! Multiple modules are loaded, did you indicate the module's name ?")
		except self.IncorrectParameter:
			io.fail("No corresponding parameter !")
		except:
			io.fail("Something went wrong ...")

	def showargs(self):
		'''
		This method displays a chart describing the available input parameters for the loaded module.
		'''
		for module in self.modules:
			currentArgs = []
			if "shortcut" not in module:
				for argument in module["module"].args:
					argName = (module["name"]+"."+argument) if len(self.modules)>1 else argument
					argValue = module["module"].args[argument]
					currentArgs.append([argName, argValue])
				io.chart(["Name","Value"],currentArgs,io.colorize(module["name"],"yellow"))
			else:
				for argument in module["mapping"]:
					argName = (module["name"]+"."+argument) if len(self.modules)>1 else argument
					if module["mapping"][argument]["value"] is not None:
						argValue =  module["mapping"][argument]["value"]
					else:
						argValue = "<auto>"
					currentArgs.append([argName, argValue])
				io.chart(["Name", "Value"], currentArgs,io.colorize(module["name"],"green"))

	def args(self):
		'''
		This method is an alias for ``showargs``.
		'''
		self.showargs()

	def info(self):
		'''
		This method displays informations about the loaded module, such as the name, technology used, etc.
		'''
		for module in self.modules:
			if "module" in module and module["module"] is not None:
				infos = module["module"].info()
				content = [infos["name"],infos["technology"], infos["type"], infos["description"]]
				io.chart(["Name", "Technology", "Type","Description"], [content], module["name"])
			elif "shortcut" in module and module["shortcut"] is not None:
				name = module["name"].strip("0123456789")
				description = self.loadedShortcuts[name]["description"]
				modules = self.loadedShortcuts[name]["modules"]
				io.chart(["Name","Modules","Description"],[[name,modules,description]],module["name"]+" (shortcut)")

	def run(self):
		'''
		This method runs the loaded module with the input parameters provided.
		'''
		args = {}
		for module in self.modules:
			if "module" in module and module["module"] is not None:
				for arg in args:
					if arg in module["module"].args or module["module"].dynamicArgs:
						module["module"].args[arg] = args[arg]
				output = module["module"].execute()
				if not output["success"]:
					io.fail("Execution of module "+module["name"]+" failed !")
					break
				else:
					args.update(output["output"])
			elif "shortcut" in module:
				for shortcutModule in module["shortcut"]:
					for arg in args:
						if arg in shortcutModule["module"].args or shortcutModule["module"].dynamicArgs:
							shortcutModule["module"].args[arg] = args[arg]
					output = shortcutModule["module"].execute()
					if not output["success"]:
						io.fail("Execution of shortcut "+module["name"]+" failed !")
						break
					else:
						args.update(output["output"])
