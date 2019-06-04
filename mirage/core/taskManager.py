from .task import Task
from copy import copy
import psutil

class TaskManager:
	'''
	This class is a manager allowing to easily manipulate background tasks (using multiprocessing).
	It is instantiated by the main application instance (``core.app.App``).
	'''
	def __init__(self):
		self.tasks = {}

	def addTask(self, function, name="", args=[],kwargs={}):
		'''
		This method allows to create a new background task.
		It instantiates a ``core.task.Task`` and adds it to the task dictionary ``tasks``.
		If a task already exists using the specified name, it will be suffixed by a number.
		
		:param function: function to launch in background
		:type function: function
		:param name: name of the task
		:type name: str
		:param args: array of unnamed arguments
		:type args: list
		:param kwargs: dictionary of named arguments
		:type kwargs: dict
		:return: real name of the instantiated task (it may be suffixed)
		:rtype: str
		'''
		baseName = name if name != "" else function.__name__
		taskName = baseName
		counter = 1
		while taskName in self.tasks:
			taskName = baseName + "." + str(counter)
			counter+=1

		self.tasks[taskName] = Task(function,taskName, args=args, kwargs=kwargs)
		return taskName

	def startTask(self,name):
		'''
		This method starts an existing task according to its (real) name.

		:param name: name of the task to start
		:type name: str
		'''
		if name in self.tasks and self.tasks[name].state.value == "stopped":
			self.tasks[name].start()
			return True
		return False

	def stopTask(self,name):
		'''
		This method stops an existing task according to its (real) name.

		:param name: name of the task to stop
		:type name: str
		'''
		if name in self.tasks and self.tasks[name].state.value == "running":
			for child in psutil.Process(self.tasks[name].pid).children():
				child.terminate()
			self.tasks[name].stop()
			del self.tasks[name]
			return True
		return False

	def restartTask(self,name):
		'''
		This method restarts an existing task according to its (real) name.

		:param name: name of the task to restart
		:type name: str
		'''
		task = self.tasks[name]
		self.stopTask(name)
		self.tasks[name] = Task(task.function,name, args=task.args, kwargs=task.kwargs)
		self.tasks[name].start()
		return True

	def stopAllTasks(self):
		'''
		This method stop all running tasks.
		'''
		for task in copy(self.tasks):
			if self.tasks[task].state.value == "running":
				self.stopTask(task)
			else:
				del self.tasks[task]

	def getTaskPID(self,name):
		'''
		This method returns a task's PID according to its name.
		
		:param name: name of the task
		:type name: str
		:return: task's PID
		:rtype: int
		'''
		if name in self.tasks:
			return self.tasks[name].pid
		else:
			return None

	def getTaskState(self,name):
		'''
		This method returns a task's state according to its name.
		
		:param name: name of the task
		:type name: str
		:return: task's state
		:rtype: str
		'''
		if name in self.tasks:
			return self.tasks[name].state.value
		else:
			return None

	def getTasksList(self,pattern=""):
		'''
		This method returns the list of the existing tasks, filtered by a specified pattern.
		
		:param pattern: Filter
		:type pattern: str
		:return: list of existing tasks
		:rtype: list
		
		'''
		return [t.toList() for t in self.tasks.values() if pattern in t.name or pattern in str(t.pid) or pattern in t.state.value]
	
