import mirage.libs.io as io
from mirage.libs.utils import exitMirage

class Device:
	'''
	This class is used to communicate with a specific hardware component.
	Every class communicating with a given hardware component must inherits from this class, and implements the following methods :

	  * ``init()`` : this method initializes the communication with the hardware component
	  * ``isUp()`` : this method allows to check if the initialization was successful and if the device is usable
	  * ``send(packet)`` : this method allows to send data (as a raw representation, e.g. bytes array or scapy frame)
	  * ``recv()`` : this method allows to receive data (as a raw representation)
	  * ``close()`` : this method closes the communication with the hardware component

	Every device is unique and identified by an interface name : this is a string stored in the ``interface`` attribute.
	Some devices may provide some additional features, such as address configuration, multiple modes, etc. In order to implement this specific behaviours, some additional methods can be implemented in the child classes, and their name may be appended to the class attribute ``sharedMethods`` (list of strings). Every shared method will be callable by user using the corresponding Emitter (``mirage.libs.wireless.Emitter``) and/or the corresponding Receiver (``mirage.libs.wireless.Receiver``) : they will expose these additional methods thanks to the Proxy design pattern.

	Finally, a simple mechanism allows to attach capabilities to a specific Device class : the capabilities are listed in an attribute ``capabilities`` (list of strings), filled during the initialization of the Device. From a module, an user can check if the device selected has the right capabilities by calling ``hasCapabilities`` on the corresponding Emitter and / or Receiver.
	'''
	sharedMethods = ["hasCapabilities"]
	'''
	This class attribute allows to provide some methods' names in order to make them callable from the corresponding Emitter / Receiver.
	'''
	instances = {}

	@classmethod
	def get(cls, interface):
		'''
		This class method implements the Register device pattern.
		According to the interface parameter, only one instance of a given specific device will be instanciated if multiple Emitters and/or Receivers tries to access it.
		'''
		if interface not in cls.instances:
			cls.instances[interface] = cls(interface)
			cls.instances[interface].init()
		if not cls.instances[interface].isUp():
			io.fail("An error occured during device initialization (interface : "+str(interface)+")")
			exitMirage()
			return None
		return cls.instances[interface]

	def __init__(self,interface):
		self.capabilities = []
		self.interface = interface
		self.subscribers = []

	def subscribe(self,subscriber):
		'''
		This method allows to register a subscriber, according to the design pattern named Publish/subscribe.
		It allows a Device to call a method of the corresponding Emitter / Receiver, subscribers by default.
		
		:param subscriber: instance of an object subscribing to the device
		:type subscriber: Object
		'''
		self.subscribers.append(subscriber)

	def publish(self,event,*args, **kwargs):
		'''
		This method allows to publish an event. It may be used to call from the device a method implemented on the corresponding Emitters / Receivers, subscribers by default.
	
		:param event: method's name to call
		:type event: str

		:Example:
	
			>>> device.publish("stop")

		'''
		for subscriber in self.subscribers:
			if hasattr(subscriber,event) and callable(getattr(subscriber,event)):
				return getattr(subscriber,event)(*args,**kwargs)

	def hasCapabilities(self, *capability):
		'''
		This method allows to check if the device implements some specific capabilities.
		
		:param `*capability`: capabilities to check
		:type `*capability`: str (multiple)
		:return: boolean indicating if the device implements the capabilities provided
		:rtype: bool

		:Example:
			>>> device.capabilities = ["SNIFFING", "INJECTING", "CHANGING_ADDRESS"]
			>>> device.hasCapabilities("SNIFFING", "INJECTING")
			True
			>>> device.hasCapabilities("MAKING_COFFEE")
			False
		'''
		out = True		
		for cap in capability:
			if cap in self.capabilities:
				out = out and True
			else:
				out = out and False
		return out

	def isUp(self):
		'''
		This method allows to check if the device is initialized and available for use.

		:return: boolean indicating if the device is up
		:rtype: bool

		'''
		return False

	def init(self):
		'''
		This method initializes the device.	
		'''
		pass

	def close(self):
		'''
		This method closes the device.	
		'''
		pass

	def send(self,data):
		'''
		This method sends some datas.	
	
		:param data: raw representation of the data to send
		'''
		pass

	def recv(self):		
		'''
		This method receives some datas.	
		If no data is available, this method returns `None`.

		:param data: raw representation of the received data
		'''
		pass
