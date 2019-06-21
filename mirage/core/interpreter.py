from mirage.libs import io
import readline,shlex,re,inspect,glob,sys
import os
import keyboard

class Interpreter:
	'''
	If a class inherits of this class, it becomes a tiny command interpreter.
	Every method listed in ``availableCommands`` becomes a command of the interpreter, and can receive arguments.
	If a command is not found, the fail() method is raised.
	The interaction loop is contained in the loop() method.

	Every method listed in ``availableCommands`` becomes a command usable in the interpreter. 
	If the method has parameters, the following rules are applied :

		* if a parameter has no default value, the parameter is mandatory in the interpreter
		* if a parameter has a default value, the parameter is optional (if it is not provided, the default value is used)

	Every parameter can be automatically autocompleted if the autocompletion mode is enabled.
	Indeed, you can specify how to autocomplete this parameter by indicating a way to get a list of possible values using annotations :

		* You can provide a list :

		::
		
			def my_cmd(self,my_parameter:["value1","value2"]="value1"):
				pass

		* You can provide a string indicating a method using the syntax ``!method:<methodName>`` :

		::

			def _autocompleteMyCmd(self):
				return ["value"+str(i) for i in range(10)]

			def my_cmd(self,my_parameter:"!method:_autocompleteMyCmd"="value1"):
				pass

		* You can also provide a string indicating a function using the syntax ``!function:<functionName>`` :
		
		::

			def my_cmd(self,my_parameter:"!function:_autocompleteMyCmd"="value1"):
				pass

		* You can provide a string indicating an attribute using the syntax ``!attribute:<attributeName>`` :
		
		::

			def my_cmd(self,my_parameter:"!attribute:_myAutocompleteAttribute"="value1"):
				pass

		* You can provide a string indicating a variable using the syntax ``!variable:<variableName>`` :
		
		::	

			def my_cmd(self,my_parameter:"!variable:myVariable"="value1"):
				pass

		* You can provide a string indicating a file path using the syntax ``!path`` :
	
		::

			def my_cmd(self,my_parameter:"!path"="/home/user/test.gatt"):
				pass

		* Any other string will be interpreted as a single completion value :
	
		::	

			def my_cmd(self,my_parameter:"value1"="value1"):
				pass


	If the suggestion mode is enabled, the name of the parameters are displayed when the user types a known command.
	The mandatory parameters are displayed as ``<parameter>`` and the optional parameters are displayed as ``[parameter]``
	'''


	def __init__(self,prompt=io.colorize(" ~~> ", "cyan"),autocompletion=True,suggestion=True):
		''' 
		This constructor initializes the interpreter instance.
		:param prompt: string used to generate the prompt
		:type prompt: str
		:param autocompletion: boolean indicating if the autocompletion mode is enabled
		:type autocompletion: bool
		:param suggestion: boolean indicating if the suggestion mode is enabled
		:type suggestion: bool
		'''
		self.prompt = prompt
		self.running = True
		self.autocompletionMode = autocompletion
		self.suggestionMode = suggestion
		self.suggestion = ""
		self.usage = ""
		self.cursorOffset = 0
		self.availableCommands = ["exit"]

	########################### AUTOCOMPLETION ###########################
	def _getInputState(self,text=None):
		'''
		This method returns the input state.
		'''
		if text is None:
			text = readline.get_line_buffer()
		line = text.split(" ")
		command = line[0]
		start = text[:text.rindex(line[-1])-1]
		current = line[-1]
		return line,command,start,current
	
	def _autocompletion(self,text,state):
		'''
		This method generates the autocompletion list.
		'''
		line,command,start,current = self._getInputState(text)

		commandsList = [entry for entry in dir(self) if (entry[:2] != "__" and
								entry.startswith(command) and
								callable(getattr(self,entry)) and
								entry in self.availableCommands
								)]
		if len(line) == 1:
			return commandsList[state]
		else:
			sig = inspect.signature(getattr(self,command))
			currentArg = list(sig.parameters.items())[len(line)-2][1]
			annotation = currentArg.annotation
			result = []
			if isinstance(annotation,list):
				result = annotation
			elif isinstance(annotation,str):				
				if annotation == "!path":
					result = [x for x in glob.glob(current+'*')]
				elif annotation.startswith("!method:"):
					methodName = annotation[8:]
					if hasattr(self,methodName) and callable(getattr(self,methodName)):
						result = getattr(self,methodName)()
				elif annotation.startswith("!function:"):
					functionName = annotation[10:]
					if functionName in globals() and callable(globals()[functionName]):
						result = globals()[functionName]()
				elif annotation.startswith("!attribute:"):
					attributeName = annotation[11:]
					if hasattr(self,attributeName) and isinstance(getattr(self,attributeName),list):
						result = getattr(self,attributeName)
				elif annotation.startswith("!variable:"):
					variableName = annotation[10:]
					if variableName in globals() and isinstance(getattr(self,variableName),list):
						result = globals()[variableName]
				else:
					result = [annotation]
			if "|" in current:
				beforePipe = current[:current.rindex("|")+1]
				afterPipe = current[current.rindex("|")+1:]
				return [start+" "+beforePipe+c for c in result if c.startswith(afterPipe)][state]

			return [start+" "+c for c in result if c.startswith(current) and c!=current][state]

	def _matchDisplayHook(self, substitution, matches, longest_match_length):
		'''
		This method formats the output of the autocompletion feature.
		'''
		line,command,start,current = self._getInputState()
		display = ""
		width = os.get_terminal_size().columns
		for match in matches:
			if len(line) > 1:
				matchValue = match.replace(start,"")
			else:
				matchValue = match
			matchValue += "   "
			if len(display.split("\n")[-1])+len(matchValue) >= width:
				matchValue = "\n"+matchValue 
			display += matchValue
		print()
		print(display)
		print(self.prompt.rstrip(), readline.get_line_buffer(), sep='', end='')
		sys.stdout.flush()

	def _enableAutocompletion(self):
		'''
		This method enables the autocompletion mode.
		'''
		readline.set_completer_delims(';\t')
		readline.parse_and_bind("tab: complete")
		readline.set_completer(self._autocompletion)
		readline.set_completion_display_matches_hook(self._matchDisplayHook)

	def _disableAutocompletion(self):
		'''
		This method disables the autocompletion mode.
		'''
		readline.set_completer(None)
		readline.set_completion_display_matches_hook(None)

	########################### INTERPRETER ###########################
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
					len(inspect.getfullargspec(getattr(self,opcode)).args)-1 == len(arguments) or
					(
						inspect.getfullargspec(getattr(self,opcode)).defaults is not None and 
						len(inspect.getfullargspec(getattr(self,opcode)).args) - 1 
					  	- len(inspect.getfullargspec(getattr(self,opcode)).defaults) <= len(arguments) and
						len(arguments) <= len(inspect.getfullargspec(getattr(self,opcode)).defaults)
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

	########################### SUGGESTION ###########################

	def _updateInput(self,key):
		'''
		This method updates the input and adds a potential suggestion (if any)
		'''
		currentBuffer = readline.get_line_buffer()
		if key.name != "space":
			self._clearSuggestion(key)
		else:
			self._generateSuggestion(currentBuffer)


	def _displayInput(self,suggestion):
		'''
		This method displays the input with the provided suggestion
		'''
		inputBuffer = readline.get_line_buffer()
		newInstructions = []
		instructions = inputBuffer.split(";")

		for instruction in instructions:
			splittedInstruction = instruction.split()
			if len(splittedInstruction) > 0:
				firstCommand = splittedInstruction[0]
				if firstCommand in self.availableCommands:
					newInstructions.append(instruction.replace(firstCommand,"\x1b[1m"+firstCommand+"\x1b[0m",1))
				else:
					newInstructions.append(instruction)
		inputBuffer = ";".join(newInstructions)

		normalDisplay = self.prompt+inputBuffer
		sys.stdout.write("\x1b7")
		sys.stdout.write("\r"+normalDisplay+suggestion)
		sys.stdout.write("\r\x1b8")

	def _generateSuggestion(self,currentBuffer):
		'''
		This method generates the suggestion according to the current input buffer
		'''
		suggestion = ""
		self.suggestion = ""
		lastInstruction = currentBuffer.split(";")[-1]
		inputData = lastInstruction.split()
		if len(inputData) != 0:
			command = inputData[0]
			if hasattr(self,command) and callable(getattr(self,command)) and command in self.availableCommands:
				sig = inspect.signature(getattr(self,command))
				if len(sig.parameters) != 0:
					ignore = len(lastInstruction.split())-1
					for i in sig.parameters:
						if ignore == 0:
							if sig.parameters[i].default is inspect.Parameter.empty:
								self.suggestion+="<"+i+"> "
							else:
								self.suggestion+="["+i+"] "
						else:
							ignore -=1
					self.suggestion = "\x1b[2m"+self.suggestion+"\x1b[22m"
					self.usage = "Usage : this command allows to send a notification"
					suggestion = self.suggestion
		self._displayInput(suggestion)

	def _clearSuggestion(self,key=None):
		'''
		This method clears the previously displayed suggestion
		'''
		suggestion = ""
		if self.suggestion != "":
			suggestion = " "*(len(self.suggestion)-1)
			self.suggestion = ""
		self._displayInput(suggestion)

	def _enableSuggestion(self):
		'''
		This method enables the suggestion mode.
		'''
		keyboard.on_release(self._updateInput)
		keyboard.on_press_key("enter",self._clearSuggestion)

	def _disableSuggestion(self):
		'''
		This method disables the suggestion mode.
		'''
		keyboard.unhook_all()

	def loop(self):
		'''
		This method is the main interaction loop of the interpreter.
		'''
		while self.running:
			if self.autocompletionMode:
				self._enableAutocompletion()
			if self.suggestionMode:
				self._enableSuggestion()
			command=input(self.prompt)
			if self.autocompletionMode:
				self._disableAutocompletion()
			if self.suggestionMode:
				self._disableSuggestion()
			self.evaluateScript(command)
