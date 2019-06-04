import sys
from enum import IntEnum
from terminaltables import SingleTable

'''
This submodule provides some useful functions allowing to interact with the users.
'''

# Enum of available verbosity levels
class VerbosityLevels(IntEnum):
	'''
	This class provide an enumeration of available verbosity levels :
	  * ``NONE`` prints no message at all
	  * ``NO_INFO_AND_WARNING`` prints only failure and success messages
	  * ``NO_INFO`` prints only failure, success and warning messages
	  * ``ALL`` prints every type of messages

	'''
	NONE = 0
	NO_INFO_AND_WARNING = 1
	NO_INFO = 2
	ALL = 3

# Indicates the verbosity level
VERBOSITY_LEVEL = VerbosityLevels.ALL


def banner():
	'''
	This function returns the banner.

	:return: banner of Mirage
	:rtype: str
	'''
	print(colorize('''
███╗   ███╗██╗██████╗  █████╗  ██████╗ ███████╗
████╗ ████║██║██╔══██╗██╔══██╗██╔════╝ ██╔════╝
██╔████╔██║██║██████╔╝███████║██║  ███╗█████╗
██║╚██╔╝██║██║██╔══██╗██╔══██║██║   ██║██╔══╝
██║ ╚═╝ ██║██║██║  ██║██║  ██║╚██████╔╝███████╗
╚═╝     ╚═╝╚═╝╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝ ╚══════╝
	''',"red"))


def colorCode(selectedColor):
	'''
	This function returns the right color code according to the color string provided.
	
	:param selectedColor: string describing a color ("red", "purple", "cyan", "blue", "yellow", "green" or "white")
	:type selectedColor: str
	:return: string containing the right color code
	:rtype: str
	'''
	if (selectedColor=="red"):
		return "\x1b[31m"
	elif (selectedColor=="purple"):
		return "\x1b[35m"
	elif (selectedColor=="cyan"):
		return "\x1b[36m"
	elif (selectedColor=="blue"):
		return "\x1b[34m"
	elif (selectedColor=="yellow"):
		return "\x1b[33m"
	elif (selectedColor=="green"):
		return "\x1b[32m"
	elif (selectedColor=="white"):
		return "\x1b[37m"
	else:
		return "\x1b[39m"


def colorize(message,color):
	'''
	This function returns the message with a specific color code, allowing to print colored messages.
	
	:param message: string to color
	:type message: str
	:param color: string describing a color ("red", "purple", "cyan", "blue", "yellow", "green" or "white")
	:type color: str
	:return: string containing the right color code and the message
	:rtype: str
	'''
	return "{0}{1}{2}".format(colorCode(color),message,colorCode("default"))


def enterPinCode(message="Enter pin code: ",maxLength = 6):
	'''
	This function asks the user to enter a PIN code, and checks if the provided answer is valid.
	
	:param message: message to display
	:type message: str
	:param maxLength: maximum length of the PIN code
	:type maxLength: int
	:return pinCode: string provided by the user, composed of digits
	:rtype: str
	'''
	redo = True
	while redo:
		pinCode = input(message)
		redo = False
		if len(pinCode) > maxLength:
			fail("Please enter only six digits")
			redo = True
		if not all([i.isdigit() for i in pinCode]) or pinCode == "":
			fail("Please enter six digits (0-9)")
			redo = True
	return pinCode


def success(message):
	'''
	This function displays a success message.
	
	:param message: message to display
	:type message: str
	'''
	if VERBOSITY_LEVEL > VerbosityLevels.NONE:
		print(colorize("[SUCCESS] ","green")+message)

def fail(message):
	'''
	This function displays a failure message.
	
	:param message: message to display
	:type message: str
	'''
	if VERBOSITY_LEVEL > VerbosityLevels.NONE:
		print(colorize("[FAIL] ","red")+message)

def info(message):
	'''
	This function displays an information message.
	
	:param message: message to display
	:type message: str
	'''
	if VERBOSITY_LEVEL == VerbosityLevels.ALL:
		print(colorize("[INFO] ","yellow")+message)


def displayPacket(packet):
	'''
	This function displays a packet as an information message. 
	
	:param packet: packet to display
	:type packet: mirage.libs.wireless_utils.packets.Packet
	'''
	if VERBOSITY_LEVEL == VerbosityLevels.ALL:
		print(colorize("[PACKET] ","yellow")+str(packet))


def warning(message):
	'''
	This function displays a warning message.
	
	:param message: message to display
	:type message: str
	'''
	if VERBOSITY_LEVEL > VerbosityLevels.NO_INFO_AND_WARNING:
		print(colorize("[WARNING] ","purple")+message)


def ask(prompt,default="",final=": "):
	'''
	This function allows to ask the user to provide an information as a string.
	It is possible to provide a default value, that will be used if the user provide nothing.
	It is also possible to change the final character to customize this user interaction function.

	:param prompt: message to display before the entry field
	:type prompt: str
	:param default: default value
	:type default: str
	:param final: final character
	:type final: str
	:return: string provided by the user
	:rtype: str

	:Example:

		>>> io.ask("Enter your age",default=25,final=": ")
		[QUESTION] Enter your age [25] : 26
		'26'

	'''
	if (default!=""):
		result = input(colorize("[QUESTION] ","purple")+'{0} [{1}] {2}'.format(prompt, default,final))
	else:
		result = input(colorize("[QUESTION] ","purple")+'{0} {1}'.format(prompt,final))
	if result == '':
		result = default
	return result



def chart(columnsName,content,title=""):
	'''
	This function displays a table containing multiple informations provided by the user.
	He can provide a header name for each column thanks to ``columnsName``, and ``content`` allows him to provide the data.
	He can also provide an (optional) title, by using the ``title`` parameters.

	:param columnsName: list of strings indicating the header name for every columns
	:type columnsName: list of str
	:param content: matrix of data to include in the table
	:type content: list of (list of str)

	:Example:

		>>> io.chart(["A","B","A xor B"],[
		...                               ["False","False","False"],
		...                               ["True","False","True"],
		...                               ["False", "True", "True"],
		...                               ["True", "True", "False"]
		...                              ],title="XOR Table")
		┌XOR Table──────┬─────────┐
		│ A     │ B     │ A xor B │
		├───────┼───────┼─────────┤
		│ False │ False │ False   │
		│ True  │ False │ True    │
		│ False │ True  │ True    │
		│ True  │ True  │ False   │
		└───────┴───────┴─────────┘


	'''
	if VERBOSITY_LEVEL > VerbosityLevels.NONE:
		tab = []
		tab.append(columnsName)
		tab+=(content)
		print(SingleTable(tab,title).table)


def progress(count, total=100, suffix=""):
	'''
	This function displays a progress bar. This bar is not automatically filled, the user has to call ``progress`` with
	the right values multiple times.

	:param count: number describing the value of the progress bar
	:type count: int
	:param total: number describing the maximal value of the progress bar
	:type total: int
	:return: boolean indicating if the progressbar is not full (it returns `True` if the progressbar is not full and `False` if it is full)

	:Example:

		>>> io.progress(0, total=100, suffix="youpi")
		True__________________________________________________________) youpi
		>>> io.progress(20, total=100, suffix="youpi")
		True))))))))))________________________________________________) youpi
		>>> io.progress(65, total=100, suffix="youpi")
		True)))))))))))))))))))))))))))))))))))))_____________________) youpi
		>>> io.progress(95, total=100, suffix="youpi")
		True)))))))))))))))))))))))))))))))))))))))))))))))))))))))___) youpi
		>>> io.progress(100, total=100, suffix="Done")
		()))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))) Done
		False


	'''
	if count>=total:
		count = total
	elif count < 0:
		count = 0
	
	bar_len = 60
	filled_len = int(round(bar_len * count / float(total)))

	percents = round(100.0 * count / float(total), 1)
	bar = '\x1b[35m)\x1b[37m' * filled_len + '_' * (bar_len - filled_len)
	if (bar_len == filled_len):
		end = "\n"
	else:
		end = "\r"
	if suffix == "":
		suffix = str(percents) + "%"
	sys.stdout.write('()%s) %s%s' % (bar, suffix,end))
	if total!=count:
		sys.stdout.flush()
		return True
	else:
		return False

