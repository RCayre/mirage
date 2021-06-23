import keyboard
from mirage.core.scenario import scenarioSignal
import mirage.libs.io as io
import mirage.libs.utils as utils
'''
This submodule defines two main classes of the framework : Module & WirelessModule.
The modules defined in the framework inherits from these classes in order to
provide a standard API.
'''

class Module:
	'''
	This class defines the standard behaviour of a Mirage Module.
	Every module must inherit of this class.
	'''
	def __init__(self):
		'''
		This constructor is used to initialize the main attributes of a module to their default values.
		It calls the ``init`` method after the initialization process.
		'''
		self.scenarioEnabled = False
		self.type = "unknown"
		self.technology = "generic"
		self.description = ""
		self.dependencies = []

		self.args = {}
		self.dynamicArgs = False
		self.init()

	def out(self,success,output={}):
		'''
		This method is an helper to format the output of the module as needed by the framework.

		:param success: boolean indicating if the module failed or succeeded.
		:type success: bool
		:param output: dictionary of strings indicating the output parameters.
		:type output: dict of str
		:return: dictionary composed of the ``success`` boolean (key "success") and the ``output`` dictionary.
		:rtype: dict
		'''
		return {
			"success":success,
			"output":output
			}

	def ok(self,output={}):
		'''
		This method is an helper to format the output of the module if its execution was successful.
		It calls the ``out`` method.

		:param output: dictionary of strings indicating the output parameters.
		:type output: dict of str
		:return: dictionary composed of the ``success`` boolean (key "success") and the ``output`` dictionary.
		:rtype: dict
		'''
		return self.out(True,output)

	def nok(self):
		'''
		This method is an helper to format the output of the module if its execution was not successful.
		It calls the ``out`` method.

		:return: dictionary composed of the ``success`` boolean (key "success") and an empty dictionary.
		:rtype: dict
		'''
		return self.out(False,{})

	def init(self):
		'''
		This method is an initialization method, called at the end of the constructor's execution.

		It must be overloaded in order to define the parameters of module, especially :
		  - type : it defines the type of the module (e.g. "sniffing", "mitm" ...)
		  - technology : it defines the type of technology used by the module (e.g. "ble", "wifi", ...)
		  - description : a short string indicating the role of the module
		  - args : a dictionary of string describing the input parameters and their potential default values
		  - dependencies : an array of string indicating the dependencies of the module
		  - dynamicArgs : a boolean indicating if the user can provide input parameters not defined in the args dictionary
		'''
		pass

	def prerun(self):
		'''
		This method is called before the ``run`` method, and can be overloaded to initialize some components before
		the module execution.
		'''
		pass

	def run(self):
		'''
		This method implements the behaviour of the module.
		It must be overloaded by every module in order to define the module execution.
		'''
		pass

	def postrun(self):
		'''
		This method is called after the ``run`` method, and can be overloaded to clean up some components after
		the module execution.
		'''
		pass

	def execute(self):
		'''
		This method allows launch a module execution by calling the methods ``prerun``, ``run`` and ``postrun``.
		'''
		try:
			self.prerun()
			output = self.run()
			self.postrun()
			return output
		except KeyboardInterrupt:
			self.postrun()
			raise KeyboardInterrupt
		except EOFError:
			self.postrun()
			raise EOFError
	def info(self):
		'''
		This method is an helper allowing to generate a dictionary including some useful informations about the module.
		It is mainly used by the ``list`` command of the main application.
		'''
		return {"name":self.__class__.__name__,"type":self.type, "description":self.description, "technology":self.technology, "dependencies": self.dependencies }

	def __getitem__(self,name):
		'''
		This magic method allows to get an input parameter's value as if the module was the ``args`` parameters.

		:Example:

		``io.info(moduleInstance["INTERFACE"])``
		'''
		return self.args[name]

	def __setitem__(self,name,value):
		'''
		This magic method allows to set an input parameter's value as if the module was the ``args`` parameters.

		:Example:

		``moduleInstance["INTERFACE"] = "hci0"``
		'''
		self.args[name] = value

	def watchKeyboard(self):
		'''
		This method allows to register a callback called if a key is pressed (if a scenario is provided).
		It allows to provide a simple user interaction in scenarios.
		'''
		keyboard.on_release(self._keyEvent)

	@scenarioSignal("onKey")
	def key(self,key):
		'''
		This method is triggered if a key is pressed (if a scenario is provided).
		It raises the scenario signal "onKey".

		:param key: string indicating the name of the key pressed
		:type key: str
		'''
		pass

	def _keyEvent(self,key):
		'''
		This method is the callback triggered if a key is pressed (if a scenario is provided).
		It calls the ``key`` method and pass a string as argument indicating the name of the pressed key.
		'''
		keyboard.unhook_all()
		self.key(key.name)
		keyboard.on_release(self._keyEvent)

	def loadScenario(self):
		'''
		Helper allowing to check if a scenario has been provided and run the scenario if needed.
		It initializes the keyboard related signals and instantiates the selected scenario.
		'''
		import mirage.scenarios as scenarios
		if "SCENARIO" in self.args and self.args["SCENARIO"]!="":
			try:
				if self.args["SCENARIO"] not in scenarios.__scenarios__:
					raise ModuleNotFoundError
				current = scenarios.__scenarios__[self.args["SCENARIO"]]
				if hasattr(current,self.args["SCENARIO"]):
					scenarioClass = getattr(current,self.args["SCENARIO"])
					self.scenario = scenarioClass(module=self)
					self.scenarioEnabled = True
					self.watchKeyboard()
				return True
			except ModuleNotFoundError:
				io.fail("Scenario "+self.args["SCENARIO"]+" not found !")
				return False


class WirelessModule(Module):
	'''
	This class inherits from ``core.module.Module``.
	It adds some methods in order to facilitate the selection of the right couple of Emitters / Receivers according to
	the ``technology`` attribute.
	'''
	EmittersClass = {}
	ReceiversClass = {}
	Emitters = {}
	Receivers = {}

	def __init__(self):
		super().__init__()
		self.sdrConfig = {}

	@classmethod
	def registerEmitter(cls,technology,emitter=None):
		'''
		This class method allows to link a given Emitter and a specific technology.

		:param technology: string indicating a technology (e.g. "ble", "wifi", ...)
		:type technology: str
		:param emitter: Emitter
		:type emitter: core.wireless.Emitter

		'''
		cls.EmittersClass[technology] = emitter

	@classmethod
	def registerReceiver(cls,technology,receiver=None):
		'''
		This class method allows to link a given Receiver and a specific technology.

		:param technology: string indicating a technology (e.g. "ble", "wifi", ...)
		:type technology: str
		:param receiver: Receiver
		:type receiver: core.wireless.Receiver

		'''

		cls.ReceiversClass[technology] = receiver


	def getEmitter(self,interface=""):
		'''
		Helper allowing to easily get a specific Emitter instance according to the ``technology`` attribute.

		:param interface: string indicating the interface to use
		:type interface: str
		:return: Emitter instance
		:rtype: core.wireless.Emitter
		'''
		interface = interface if interface != "" else self.args['INTERFACE']
		if interface not in self.__class__.Emitters:
			try:
				self.__class__.Emitters[interface] = self.__class__.EmittersClass[self.technology](interface=interface)
			except AttributeError:
				io.fail("Device not found !")
				utils.exitMirage()
		self.__class__.Emitters[interface].updateSDRConfig(self.sdrConfig)
		return self.__class__.Emitters[interface]

	def getReceiver(self,interface=""):
		'''
		Helper allowing to easily get a specific Receiver instance according to the ``technology`` attribute.

		:param interface: string indicating the interface to use
		:type interface: str
		:return: Receiver instance
		:rtype: core.wireless.Receiver
		'''
		interface = interface if interface != "" else self.args['INTERFACE']
		if interface not in self.__class__.Receivers:
			try:
				self.__class__.Receivers[interface] = self.__class__.ReceiversClass[self.technology](interface=interface)
			except AttributeError:
				io.fail("Device not found !")
				utils.exitMirage()
		self.__class__.Receivers[interface].updateSDRConfig(self.sdrConfig)
		return self.__class__.Receivers[interface]
