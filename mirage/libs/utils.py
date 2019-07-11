import psutil,time,os,sys,string,random,imp
from os.path import expanduser,exists

def generateModulesDictionary(moduleDir, moduleUserDir):
	'''
	This function generates a dictionary of Mirage modules, by including files stored in ``moduleDir`` and ``moduleUserDir``.
	
	:param moduleDir: path of Mirage's modules directory
	:type moduleDir: str
	:param moduleUserDir: path of Mirage's user modules directory
	:type moduleUserDir: str
	:return: dictionary of Mirage's modules
	:rtype: dict of str: module

	'''
	modules = {}

	for module in os.listdir(moduleDir):
		if os.path.isfile(moduleDir+"/"+module) and module[-3:] == ".py" and module != "__init__.py":
			modules[module[:-3]] = imp.load_source(module[:-3],moduleDir + "/"+module)
		
	for module in os.listdir(moduleUserDir):
		if os.path.isfile(moduleUserDir+"/"+module) and module[-3:] == ".py" and module != "__init__.py":
			modules[module[:-3]] = imp.load_source(module[:-3],moduleUserDir + "/"+module)

	return modules


def generateScenariosDictionary(scenariosDir, scenariosUserDir):
	'''
	This function generates a dictionary of Mirage scenarios, by including files stored in ``scenariosDir`` and ``scenariosUserDir``.
	
	:param scenariosDir: path of Mirage's scenarios directory
	:type scenariosDir: str
	:param scenariosUserDir: path of Mirage's user scenarios directory
	:type scenariosUserDir: str
	:return: dictionary of Mirage's scenarios
	:rtype: dict of str: module

	'''
	scenarios = {}
	for scenario in os.listdir(scenariosDir):
		if os.path.isfile(scenariosDir+"/"+scenario) and scenario[-3:] == ".py" and scenario != "__init__.py":
			scenarios[scenario[:-3]]=imp.load_source(scenario[:-3],scenariosDir + "/"+scenario)
		
	for scenario in os.listdir(scenariosUserDir):
		if os.path.isfile(scenariosUserDir+"/"+scenario) and scenario[-3:] == ".py" and scenario != "__init__.py":
			scenarios[scenario[:-3]]=imp.load_source(scenario[:-3],scenariosUserDir + "/"+scenario)

	return scenarios

def initializeHomeDir():
	'''
	This function initializes Mirage's home directory.
	It creates the following files and directories under user's home directory :
	::
		/home/user
			|_.mirage
				|_ modules (modules user directory)
				|_ scenarios (scenarios user directory)
				|_ mirage.cfg (configuration file)
		
	It returns the path of Mirage's home directory (e.g. "/home/user/.mirage")
	
	:return: path of Mirage's home directory
	:rtype: str
	'''
	homeDir = expanduser("~")+"/.mirage"
	if not exists(homeDir):
		os.mkdir(homeDir)
	
	if not exists(homeDir+"/modules"):
		os.mkdir(homeDir+"/modules")

	if not exists(homeDir+"/scenarios"):
		os.mkdir(homeDir+"/scenarios")

	if not exists(homeDir+"/mirage.cfg"):
		open(homeDir+"/mirage.cfg", 'a').close()
	return homeDir
	
def getHomeDir():
	'''
	This function returns the path of the home directory.
	
	:return: path of the home directory
	:rtype: str
	
	:Example:
	
	>>> print(utils.getHomeDir())

	'''
	from mirage.core import app # No other choice : circular import
	return app.App.Instance.homeDir


def getTempDir():
	'''
	This function returns the path of the temporary directory.
	
	:return: path of the temporary directory
	:rtype: str
	
	:Example:
	
	>>> print(utils.getTempDir())

	'''
	from mirage.core import app # No other choice : circular import
	return app.App.Instance.tempDir

def addTask(function, name='', args=[],kwargs={}):
	'''
	This function allows to quickly add a new background task.
	
	:param function: function to add as a background task
	:type function: function
	:param name: name of the background task
	:type name: str
	:param args: list of unnamed arguments
	:type args: list
	:param kwargs: dictionary of named arguments
	:type kwargs: dict
	:return: real name of the task (may be suffixed / see ``core.taskManager.addTask``)
	:rtype: str

	:Example:
	
	>>> def f(name):
	>>> 	print("Hello, "+name)
	>>> fTask = utils.addTask(f,args=["user"])
	
	.. seealso::
		core.taskManager.addTask

	'''
	from mirage.core import app
	return app.App.Instance.taskManager.addTask(function,name, args=args, kwargs=kwargs)

def startTask(name):
	'''
	This function allows to start a background task.

	:param name: real name of the task to start
	:type name: str

	:Example:

	>>> utils.startTask(fTask)

	.. seealso::
		``core.taskManager.startTask``
	'''
	from mirage.core import app
	return app.App.Instance.taskManager.startTask(name)

def restartTask(name):
	'''
	This function allows to restart a background task.

	:param name: real name of the task to restart
	:type name: str

	:Example:

	>>> utils.restartTask(fTask)

	.. seealso::
		``core.taskManager.restartTask``

	'''
	from mirage.core import app
	return app.App.Instance.taskManager.restartTask(name)

def stopTask(name):
	'''
	This function allows to stop a background task.

	:param name: real name of the task to stop
	:type name: str

	:Example:

	>>> utils.stopTask(fTask)

	.. seealso::
		``core.taskManager.stopTask``

	'''
	from mirage.core import app
	return app.App.Instance.taskManager.stopTask(name)

def stopAllTasks():
	'''
	This function allows to stop all the background tasks.
	
	:Example:

	>>> utils.stopAllTasks()

	.. seealso::
		``core.taskManager.stopAllTasks``

	'''
	from mirage.core import app
	return app.App.Instance.taskManager.stopAllTasks()

def loadModule(name):
	'''
	This function allows to load a module according to its name.
	
	:param name: name of the module to load
	:type name: str
	:return: instance of the loaded module
	:rtype: core.module.Module

	:Example:
	
	>>> module = utils.loadModule("ble_info")
	>>> module["INTERFACE"] = "hci0"
	>>> module.run()


	.. seealso::
		``core.loader.load``

	'''
	from mirage.core import app
	return app.App.Instance.loader.load(name)

def exitMirage():
	'''
	This function exits Mirage.
	'''
	from mirage.core import app
	app.App.Instance.exit()
	sys.exit(1) 

def stopAllSubprocesses():
	'''
	This function stops all subprocesses of Mirage.
	'''
	for child in psutil.Process().children():
		child.terminate()

def wait(seconds=1,minutes=0,hours=0):
	'''
	This function allows to wait for a given amount of time, provided by user.
	
	:param seconds: seconds to wait
	:type seconds: float
	:param minutes: minutes to wait
	:type minutes: int
	:param hours: hours to wait
	:type hours: int
	'''
	totaltime = seconds + 60 * minutes + 3600 * hours
	time.sleep(totaltime)

def now():
	'''
	This function returns the current timestamp.

	:return: current timestamp
	:rtype: float
	'''
	return time.time()

def isRoot():
	'''
	This function checks if the framework has been launched as root.
	
	:return: boolean indicating if the framework has been launched as root
	:rtype: bool
	'''
	return os.getuid() == 0

def isNumber(theString):
	'''
	This function checks if the provided string is a number.
	
	:param theString: string to check
	:type theString: str
	:return: boolean indicating if the provided string is a number
	:rtype: bool
	'''
	return all(i in "0123456789" for i in theString)

def isHexadecimal(theString):
	'''
	This function checks if the provided string is an hexadecimal number.
	
	:param theString: string to check
	:type theString: str
	:return: boolean indicating if the provided string is an hexadecimal number
	:rtype: bool
	'''
	newString = theString[2:] if theString[0:2] == "0x" else theString
	return all(i in "0123456789abcdef" for i in newString.lower())

def isPrintable(theString):
	'''
	This function checks if the provided string is composed of printable characters.
	
	:param theString: string to check
	:type theString: str
	:return: boolean indicating if the provided string is printable
	:rtype: bool
	'''
	printableChars = bytes(string.printable, 'ascii') + b"\x00"
	return all(i in printableChars for i in theString)

def booleanArg(arg):
	'''
	This function converts the provided string into a boolean.
	
	:param arg: string to convert
	:type arg: str
	:return: corresponding boolean
	:rtype: bool

	:Example:
		>>> utils.booleanArg("yes")
		True
		>>> utils.booleanArg("no")
		False
		>>> utils.booleanArg("true")
		True
		>>> utils.booleanArg("false")
		False

	'''
	true = ["TRUE","YES","1"]
	return arg.upper() in true

def integerArg(arg):
	'''
	This function converts the provided string into an integer.
	
	:param arg: string to convert
	:type arg: str
	:return: corresponding integer
	:rtype: int

	:Example:
		>>> utils.integerArg("12")
		12
		>>> utils.integerArg("0x1234")
		4660

	'''
	if isNumber(arg):
		return int(arg)
	elif isHexadecimal(arg):
		return int(arg,16)
	else:
		return None

def listArg(arg):
	'''
	This function converts the provided string into a list of strings (splitted by ",").
	
	:param arg: string to convert
	:type arg: str
	:return: corresponding list of strings
	:rtype: list of str

	:Example:
		>>> utils.listArg("one,two,three")
		["one","two","three"]

	'''
	return arg.split(",")

def addressArg(arg):
	'''
	This function converts the provided string into an address.
	
	:param arg: string to convert
	:type arg: str
	:return: corresponding address
	:rtype: str

	:Example:
		>>> utils.addressArg("0a:0b:0c:0d:0e:0f")
		'0A:0B:0C:0D:0E:0F'

	'''
	return arg.upper()

def getRandomAddress():
	'''
	This function generates and returns a random address.

	:return: random address
	:rtype: str

	:Example:
		>>> utils.getRandomAddress()
		'A1:96:8D:2F:9A:66'
		>>> utils.getRandomAddress()
		'9F:CD:E3:50:61:66'
		>>> utils.getRandomAddress()
		'E6:99:B7:42:32:95'

	'''
	return ("%02x:%02x:%02x:%02x:%02x:%02x" % (
		random.randint(0, 255),
		random.randint(0, 255),
		random.randint(0, 255),
		random.randint(0, 255),
		random.randint(0, 255),
		random.randint(0, 255)
		)).upper()
