import time,threading
from queue import Queue
from mirage.libs.utils import exitMirage

class StoppableThread(threading.Thread):
	'''
	This class is just a simplistic implementation of a stoppable thread.
	The target parameter allows to provide a specific function to run continuously in background.
	If the stop method is called, the thread is interrupted.
	'''
	def __init__(self,target=None):
		super().__init__(target=target)
		self.daemon = True
		self.signal = True

	def run(self):
		try:
			while self.signal:
				self._target(*(self._args))
		except (KeyboardInterrupt,EOFError):
			pass
	def stop(self):
		'''
		This method stops the thread.
		'''
		self.signal = False

class PacketQueue:
	'''
	This class implements a Packet (``mirage.libs.wireless_utils.packets.Packet``) queue, and provides an API to manipulate it.

	The Emitter class (``mirage.libs.wireless.Emitter``) and the Receiver class (``mirage.libs.wireless.Receiver``) inherit from it.
	The private method _task implements a watchdog, allowing to put or get some packets in the queue and manipulate them. This watchdog is called continuously thanks to a Stoppable Thread (``mirage.libs.wireless_utils.packetQueue.StoppableThread``).

	Some parameters may be passed to the constructor :
	  * waitEmpty : it indicates if the queue should wait for an empty queue before stopping
	  * autoStart : it indicates if the queue shoud start immediatly after the instanciation of the class
	'''
	def __init__(self, waitEmpty = False, autoStart = True):
		self.waitEmpty = waitEmpty
		self.autoStart = autoStart
		self.queue = Queue()
		self.isStarted = False
		if self.isDeviceUp():
			self.device.subscribe(self)
			self.daemonThread = None
			if autoStart:
				self.start()
		
	def isDeviceUp(self):
		'''
		This method allow to check if the Device (``mirage.libs.wireless_utils.device.Device``) linked to this Packet Queue is up and running.
		'''
		return hasattr(self,"device") and self.device is not None and self.device.isUp()

	def _createDaemonThread(self):
		self.daemonThread = StoppableThread(target = self._task)

	'''
	def __del__(self):
		self.stop()
	'''
	def start(self):
		'''
		This method starts the associated stoppable thread in order to continuously call the watchdog function (_task).
		'''
		if self.daemonThread is None:
			self._createDaemonThread()
		if not self.isStarted:
			self.daemonThread.start()
		self.isStarted = True


	def stop(self):
		'''
		This method stops the associated stoppable thread.
		'''
		if hasattr(self,"isStarted") and self.isStarted:
			if self.waitEmpty:
				while not self.isEmpty():
					time.sleep(0.05) # necessary ? 
			self.daemonThread.stop()
			self.daemonThread = None
			self.isStarted = False

	def restart(self):
		'''
		This method restarts the associated stoppable thread.
		'''
		self.stop()
		self.start()

	def isBusy(self):
		'''
		This method indicates if the queue contains some datas.
		
		:return: boolean indicating if the queue contains some datas
		:rtype: bool
		'''
		return not self.isEmpty()

	def isEmpty(self):
		'''
		This method indicates if the queue is empty.
		
		:return: boolean indicating if the queue is empty
		:rtype: bool
		'''
		return self.queue.empty()

	def clear(self):
		while not self.isEmpty():
			self.queue.get(False)

	def _task(self):
		pass

	def __getattr__(self, name):
		if (name != "device" and hasattr(self.device, name) and 
			(name in self.device.__class__.sharedMethods or name == "hasCapabilities")):
			return getattr(self.device,name)
		else:
			raise AttributeError
