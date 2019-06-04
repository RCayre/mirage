from mirage.libs import io
import readline,shlex,re,inspect

class Interpreter:
	'''
	If a class inherits of this class, it becomes a tiny command interpreter.
	Every method listed in ``availableCommands`` becomes a command of the interpreter, and can receive arguments.
	If a command is not found, the fail() method is raised.
	The interaction loop is contained in the loop() method.
	'''

	
	def autocompletion(self,text,state):
		'''
		This method generates the autocompletion list.
		'''
		return [entry for entry in dir(self) if (	entry[:2] != "__" and
								entry.startswith(text) and
								callable(getattr(self,entry)) and
								entry in self.availableCommands
							)][state]

	def __init__(self,prompt=io.colorize(" ~~> ", "cyan")):
		''' 
		This constructor initializes the interpreter instance.
		:param prompt: string used to generate the prompt
		:type prompt: str	
		'''
		self.prompt = prompt
		self.running = True
		self.availableCommands = ["exit"]

	def fail(self):
		'''
		This method is called if a command typed by the user is not found in the ``availableCommand`` attribute.
		'''
		io.fail("Unknown command !")

	def exit(self):
		'''
		This method exits the interpreter's main loop.
		It is a command available in the interpreter by default.
		'''
		self.running = False

	def evaluateCommand(self,command):
		'''
		This method allows to evaluate a specific command provided by the user in the interpreter.
		It uses introspection in order to find a corresponding method in the current class.
		
		:param command: command provided by the user
		:type command: list of str
		'''		
		words = shlex.split(command)

		if len(words) >= 1:
			opcode = words[0]
			arguments = words[1:] if len(words) > 1 else []

			if (	opcode in self.availableCommands and
				hasattr(self,opcode) and
				callable(getattr(self,opcode)) and
				(
					len(inspect.getargspec(getattr(self,opcode)).args)-1 == len(arguments) or
					(
						inspect.getargspec(getattr(self,opcode)).defaults is not None and 
						len(inspect.getargspec(getattr(self,opcode)).args) - 1 
					  	- len(inspect.getargspec(getattr(self,opcode)).defaults) <= len(arguments) and
						len(arguments) <= len(inspect.getargspec(getattr(self,opcode)).defaults)
					)
				)
			):
				getattr(self,opcode)(*arguments)
			else:
				self.fail()
	
	def evaluateScript(self,script):
		'''
		This method allows to evaluate a specific list of commands (script) provided by the user in the interpreter.
		It splits the string provided by the user using the delimiter ``;`` and calls the method ``evaluateCommand``
		on each command found.

		:param script: script provided by the user
		:type script: str
		'''	
		if script != "":
			if script[-1]==";":
				script = script[:-1]

			commandsList = re.split(''';(?=(?:[^'"]|'[^']*'|"[^"]*")*$)''',script)
			for cmd in commandsList:
				self.evaluateCommand(cmd)

	def loop(self):
		'''
		This method is the main interaction loop of the interpreter.
		'''
		readline.set_completer_delims(' \t\n;')
		readline.parse_and_bind("tab: complete")
		readline.set_completer(self.autocompletion)
		readline.parse_and_bind('set show-all-if-ambiguous on')
		while self.running:
			command=input(self.prompt)
			self.evaluateScript(command)
