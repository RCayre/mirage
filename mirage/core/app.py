import os
from string import Template
from mirage.core import interpreter,loader,taskManager,module,config,templates
from mirage.libs import io,utils

class App(interpreter.Interpreter):
	'''
	This class defines the main Application.
	It inherits from ``core.interpreter.Interpreter``, allowing to use Mirage as a command line interpreter.

	'''
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

	def load(self,moduleName):
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

			else:
				io.fail("Unknown module "+m+" !")
				noError = False
				break
		if noError:
			self.modules = tmpModules
			self.prompt = io.colorize(" << "+moduleName+" >>~~> ","cyan")


	def set(self,name,value):
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
		if len(self.modules) == 0:
			io.fail("No modules loaded !")
		elif len(self.modules) == 1:
			if self.modules[0]["module"] is not None:
				if self.modules[0]["module"].dynamicArgs or name in self.modules[0]["module"].args:
					self.modules[0]["module"].args[name] = value
		else:
			if "." in name:
				(moduleName,argName) = name.split(".")
				for module in self.modules:
					if module["module"] is not None:
						if moduleName == module["name"] and (
											module["module"].dynamicArgs or
											argName in module["module"].args
										    ):
							module["module"].args[argName] = value
			else:
				io.warning("You must provide a module name !")

	def showargs(self):
		'''
		This method displays a chart describing the available input parameters for the loaded module.
		'''
		for module in self.modules:
			currentArgs = []
			for argument in module["module"].args:
				argName = (module["name"]+"."+argument) if len(self.modules)>1 else argument
				argValue = module["module"].args[argument]
				currentArgs.append([argName, argValue])
			io.chart(["Name","Value"],currentArgs,io.colorize(module["name"],"yellow"))

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
			if module["module"] is not None:
				infos = module["module"].info()
				content = [infos["name"],infos["technology"], infos["type"], infos["description"]]
				io.chart(["Name", "Technology", "Type","Description"], [content], module["name"])

	def run(self):
		'''
		This method runs the loaded module with the input parameters provided.
		'''
		args = {}
		for module in self.modules:
			if module["module"] is not None:
				for arg in args:
					if arg in module["module"].args or module["module"].dynamicArgs:
						module["module"].args[arg] = args[arg]
				#try:
				output = module["module"].execute()

				#except Exception as e:
					
					#output = {"success":False,"output":""}
				
				if not output["success"]:
					io.fail("Execution of module "+module["name"]+" failed !")
					break
				else:
					args.update(output["output"])
					#print(args)
