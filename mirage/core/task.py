from mirage.libs import utils
import multiprocessing,os,sys
from ctypes import c_char_p

class Task(multiprocessing.Process):
	'''
	This class defines a background Task, it inherits from ``multiprocessing.Process``.
	It provides an user friendly API to easily run a given function in background.
	'''
	def __init__(self,function,name,args=[],kwargs={}):
		'''
		This constructor allows to provide the main characteristics of the task, and initializes the attributes.
		
		:param function: function to run in background
		:type function: function
		:param name: name of the current task
		:type name: str
		:param args: list of unnamed arguments
		:type args: list
		:param kwargs: dictionary of named arguments
		:type kwargs: dict
		'''
		self.function = function
		self.taskName = name
		self.args = args
		self.kwargs = kwargs
		self.manager = multiprocessing.Manager()
		self.state = self.manager.Value(c_char_p, "stopped")
		self.outputFilename = ""
		self.outputFile = None
		super().__init__()

	def run(self):
		'''
		This method runs the specified function in background.
		
		.. note:: The standard output is automatically redirected in a temporary file, named ``<taskName>-<taskPID>.out``
		'''
		self.outputFilename = utils.getTempDir()+"/"+self.taskName+"-"+str(os.getpid()) + ".out"
		self.outputFile = open(self.outputFilename, 'a')
		sys.stdout = self.outputFile
		self.function(*(self.args), **(self.kwargs))
		self.state.value = "ended"

	def start(self):
		'''
		This method allows to start the current task.
		'''
		self.state.value = "running"
		super().start()
		self.outputFilename = utils.getTempDir()+"/"+self.taskName+"-"+str(self.pid)+".out"


	def stop(self):
		'''
		This method allows to stop the current task.
		'''
		self.state.value = "stopped"
		self.terminate()
		if self.outputFile is not None:
			self.outputFile.close()

	def toList(self):
		'''
		This method returns a list representing the current task.
		It is composed of :

			* the task's PID
			* the task's name
			* the task's state
			* the associated output file

		:return: list representing the current task
		:rtype: list of str
		''' 
		return [str(self.pid), self.taskName, self.state.value, self.outputFilename]
