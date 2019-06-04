import importlib

class Callback:
	'''
	This class is an internal representation of a specific callback. It is linked to an event.
	An event is a string, some examples are represented in the following table:

	+----------------------+-------------------------------+
	| Event                |  Description                  |
	+======================+===============================+
	| \*                   |  every packet                 |
	+----------------------+-------------------------------+
	| 3                    |  every 3 packets              |
	+----------------------+-------------------------------+
	| BLEReadRequest       |  every BLE Read Request       |
	+----------------------+-------------------------------+
	
	Some arguments can be passed to the constructor as parameters :
	  * event : string indicating the event
	  * function : function to run if the callback is triggered
	  * args : unnamed arguments of the function
	  * kwargs : named arguments of the function
	  * background : boolean indicating if the function is launched in a background thread or in foreground
	'''
	def __init__(self,event="*",function=None, args=[], kwargs={},background=True):
		if event == "*" or event.isdigit():
			n = int(event) if event.isdigit() else 1
			self.eventType = "npackets" # this callback is triggered every n packets received
			self.count = n
			self.every = n
		else:
			self.eventType = "instanceof" # this callback is triggered if the received packet type is event
			self.instance = event
		self.parameters = {"args":args,"kwargs":kwargs}
		self.function = function
		self.background = background
		self.runnable = False


	def update(self, packet):
		'''
		This method allows to update the callback's internal state by providing the current packet.
		If the packet received matchs the event defined, the attribute ``runnable`` is set to True.
		'''
		self.runnable = False
		if packet is not None:
			if self.eventType == "npackets":
				self.count -= 1
				if self.count == 0:
					self.count = self.every
					self.runnable = True
			elif self.eventType == "instanceof":
				m = importlib.import_module(packet.__module__)
				if isinstance(packet, getattr(m, self.instance)):
					self.runnable = True


	def run(self,packet):
		'''
		This method executes the function associated to the callback.
		'''
		args = [packet] + self.parameters["args"]
		kwargs = self.parameters["kwargs"]
		self.function(*args, **kwargs)


