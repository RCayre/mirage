from queue import Queue,Empty
import time
import mirage.libs.io as io
from mirage.libs.wireless_utils.packets import *
from mirage.libs.wireless_utils.packetQueue import PacketQueue,StoppableThread
from mirage.libs.wireless_utils.callbacks import Callback
from mirage.libs.wireless_utils.device import Device
from mirage.libs.wireless_utils.pcapDevice import PCAPDevice


class Emitter(PacketQueue):
	'''
	This class allows an user to communicate with a device in order to send data. Indeed, Mirage provides no direct access to the device component from the modules : the hardware components are manipulated thanks to the Emitter class and the Receiver class. Emitters' classes for a given technology inherits from this class.
	The packet are manipulated as an abstract representation in Emitters and Receivers (``mirage.libs.wireless_utils.packets.Packet``) and as a raw representation in Device (e.g. bytes array or scapy frame). That's why an Emitter must implement the following method :

	  * convert(self,packet) : this method converts a Mirage Packet into its raw representation

	The constructor of an Emitter needs three parameters :

	  * `interface` : indicating the interface to use to instantiate the device, generally it will be provided by the user
	  * `packetType` : indicating the child class of Packet for the technology implemented by the Emitter
	  * `deviceType` : indicating the child class of Device to instanciate

	A `_task` method is implemented by default. It gets a Mirage Packet from the queue, calls the convert method on it and calls the send method of a Device on the result. If you want to customize this behaviour, you can overload this method.
	
	'''
	def __init__(self,interface,packetType=Packet, deviceType=Device):
		self.interface = interface
		self.packetType = packetType
		self.deviceType = deviceType
		self.device = self.deviceType.get(self.interface)
		self.transmitting = False
		super().__init__(waitEmpty=False)
		
	def isTransmitting(self):
		'''
		This method indicates if the Emitter is actually transmitting.
		
		:return: boolean indicating if the Emitter is actually transmitting
		:rtype: bool

		:Example:
			>>> emitter.isTransmitting()
			True
		'''
		return self.transmitting

	def _send(self,data):
		if isinstance(data,bytes) and data[:5] == b"WAIT:":
			time.sleep(float(data[5:]))
		else:
			self.device.send(data)

	def convert(self,packet):
		'''
		This method converts a Mirage Packet into a raw Packet (e.g. bytes array or scapy frame). It must be overloaded by child classes.
		
		:param packet: Mirage Packet to convert
		:type packet: mirage.libs.wireless_utils.packets.Packet
		:return: raw representation of a packet
		'''
		if isinstance(packet,Packet):
			return packet.packet
		else:
			io.fail("Malformed packet")
			return None

	def convertMiragePacketToRaw(self,data):
		'''
		This method is an alias for the convert method of an emitter.
		
		:param data: raw representation of a packet
		:return: Mirage packet
		:rtype: mirage.libs.wireless_utils.packets.Packet
		'''
		return self.convert(data)

	def _task(self):
		if not self.isEmpty():
			self.transmitting = True
			packet = self.queue.get()
			if isinstance(packet,WaitPacket):
				data = bytes("WAIT:"+str(packet.time),"ascii")
			else:
				data = self.convert(packet)

			if data is not None:
				self._send(data)
			self.transmitting = not self.isEmpty()
		else:
			time.sleep(0.005)
		

	def send(self,*packets):
		'''
		This method allows to send a Mirage Packet.
		
		:param `*packets`: packets to send
		:type `*packets`: mirage.libs.wireless_utils.packets.Packet (multiple)

		:Example:

			>>> emitter.send(packet1, packet2, packet3)
			>>> emitter.send(packet1)

		'''
		for packet in packets:
			self.queue.put(packet)

	def sendp(self,*packets):
		'''
		This method is an alias for `send`.

		:param `*packets`: packets to send
		:type `*packets`: mirage.libs.wireless_utils.packets.Packet (multiple)

		:Example:

			>>> emitter.sendp(packet1, packet2, packet3)
			>>> emitter.sendp(packet1)
		'''
		self.send(*packets)
	
	def stop(self):
		'''
		Stops the Emitter and the associated device
		'''
		super().stop()
		if self.isDeviceUp():
			self.device.close()




class Receiver(PacketQueue):
	'''
	This class allows an user to communicate with a device in order to receive data. Indeed, Mirage provides no direct access to the device component from the modules : the hardware components are manipulated thanks to the Emitter class and the Receiver class. Receivers' classes for a given technology inherits from this class.

	The packet are manipulated as an abstract representation in Emitters and Receivers (``mirage.libs.wireless_utils.packets.Packet``) and as a raw representation in Device (e.g. bytes array or scapy frame). That's why a Receiver must implement the following method :

	  * convert(self,packet) : this method converts a raw representation of a packet into a Mirage Packet

	The constructor of a Receiver needs three parameters :

	  * `interface` : indicating the interface to use to instantiate the device, generally it will be provided by the user
	  * `packetType` : indicating the child class of Packet for the technology implemented by the Emitter
	  * `deviceType` : indicating the child class of Device to instanciate

	A `_task` method is implemented by default. It calls the recv method of a Device, converts the result (if it is not None) to a Mirage Packet and adds it to the queue. If you want to customize this behaviour, you can overload this method.
	
	'''
	def __init__(self,interface,packetType=Packet, deviceType=Device):
		self.interface = interface
		self.packetType = packetType
		self.deviceType = deviceType
		self.device = self.deviceType.get(self.interface)
		self.callbacks = []
		self.receiving = False
		self.callbacksQueue = Queue()
		self.callbacksActiveListening = False
		super().__init__(waitEmpty=False, autoStart=True)

	def convert(self,data):
		'''
		This method converts a raw Packet (e.g. bytes array or scapy frame) into a Mirage Packet. It must be overloaded by child classes.

		:param data: raw representation of a packet
		:return: Mirage packet
		:rtype: mirage.libs.wireless_utils.packets.Packet
		'''
		return Packet(packet=data)

	def convertRawToMiragePacket(self,data):
		'''
		This method is an alias for the convert method of a receiver.
		
		:param data: raw representation of a packet
		:return: Mirage packet
		:rtype: mirage.libs.wireless_utils.packets.Packet
		'''
		return self.convert(data)

	def _add(self,data):
		if data is not None:
			packet = self.convert(data)
			self._executeCallbacks(packet)
			if packet is not None:
				self.queue.put(packet)

	def isReceiving(self):
		'''
		This method indicates if the Receiver is actually receiving.
		
		:return: boolean indicating if the Receiver is actually receiving
		:rtype: bool

		:Example:
			>>> receiver.isReceiving()
			True
		'''
		return self.receiving

	def _task(self):
		self.receiving = True
		pkt = self.device.recv()
		self._add(pkt)
		self.receiving = False

	def clean(self):
		'''
		This method removes every Mirage Packets stored in the queue.

		:Example:
			
			>>> receiver.clean()

		'''
		while not self.isEmpty():
			self.skip()

	def skip(self,timeout=None):
		'''
		This method skips the next Mirage Packet stored in the queue.

		:param timeout: time (in seconds) before the method fails
		:type timeout: float

		:Example:
			
			>>> receiver.skip(timeout=1.0)

		'''
		next(self.receive(timeout=timeout))

	def next(self,timeout=None):
		'''
		This method returns the next Mirage Packet stored in the queue.

		:param timeout: time (in seconds) before the method fails
		:type timeout: float

		:Example:
			
			>>> packet = receiver.next(timeout=1.0)
			
		'''
		return next(self.receive(timeout=timeout))

	def receive(self,nb=1,loop=False,timeout=None):
		'''
		This method provide a generator allowing to iterate on the incoming Mirage Packets.
		
		:param nb: number of packets to receive in the iterator
		:type nb: int
		:param loop: boolean indicating if the packets must be continuously received
		:type loop: bool
		:param timeout: time (in seconds) before a reception fails
		:type timeout: float
		:return: generator of Mirage Packets (``mirage.libs.wireless_utils.packets.Packet``)

		:Example:
	
			>>> for packet in receiver.receive(nb=5):
			... 	packet.show()
			<< Packet >>
			<< Packet >>
			<< Packet >>
			<< Packet >>
			<< Packet >>
			>>> for packet in receiver.receive(loop=True, timeout=1.0):
			... 	if packet is not None:
			... 		packet.show()
			... 	else:
			...		io.info("Timeout !")
			[INFO] Timeout !
			<< Packet >>
			[INFO] Timeout !
			[INFO] Timeout !
			<< Packet >>
			[...]


		'''
		def get():
			try:
				return self.queue.get(timeout=timeout)
			except Empty:
				return None

		if loop:
			while True:
				yield get()
		else:
			for _ in range(nb):
				yield get()

	def onEvent(self,event="*", callback=None, args=[], kwargs={}, background=True):
		'''
		This function allows to attach a callback, triggered when some specific Mirage Packets are received.
		It is linked to an *event*, which is a string indicating when should the callback be called.
		Three formats exists describing an event :

		  * *\** : indicating "the callback is called every times a packet is received"
		  * *n* : indicating "the callback is called every times n packets have been received"
		  * *packetType* : indicating "the callback is called every times a packet of type 'packetType' is received"

		Some examples are represented in the following table:

		+----------------------+-------------------------------+
		| Event                |  Description                  |
		+======================+===============================+
		| \*                   |  every packet                 |
		+----------------------+-------------------------------+
		| 3                    |  every 3 packets              |
		+----------------------+-------------------------------+
		| BLEReadRequest       |  every BLE Read Request       |
		+----------------------+-------------------------------+

		The function *callback* is called with the following format : callback(packet,*args,**kwargs)
		A callback can be run in the associated background thread (by default) or in foreground by using the methods ``listenCallbacks`` and ``stopListeningCallbacks``.

		:param event: string describing the associated event
		:type event: str
		:param callback: function to call when the associated event is triggered
		:type callback: function
		:param args: unnamed arguments to provide to the function
		:type args: list
		:param kwargs: named arguments to provide to the function
		:type kwargs: dict
		:param background: boolean indicating if the callback is run in background or in foreground
		:type background: bool

		:Example:

			>>> def show(packet):
			... 	packet.show()
			>>> receiver.onEvent("*", callback=show)
			>>> def onReadRequest(packet,username):
			... 	io.info("Hello "+username+", I have an incoming Read Request for you : "+str(packet))
			>>> receiver.onEvent("BLEReadRequest",callback=onReadRequest, args=["Romain"])

		'''
		self.callbacks.append(Callback(event=event, function=callback, args=args, kwargs=kwargs, background=background))

	def _executeCallbacks(self,packet):
		for callback in self.callbacks:
			callback.update(packet)
			if callback.runnable:
				if callback.background:
					callback.run(packet)
				else:
					self.callbacksQueue.put((self.callbacks.index(callback),packet))

	def stopListeningCallbacks(self):
		'''
		Stops the foreground callbacks execution loop.

		:Example:

			>>> receiver.stopListeningCallbacks()

		'''
		self.callbacksActiveListening = False

	def listenCallbacks(self):
		'''
		Starts the foreground callbacks execution loop.

		:Example:

			>>> receiver.listenCallbacks()

		'''
		self.callbacksActiveListening = True
		while self.callbacksActiveListening:
			if not self.callbacksQueue.empty():
				index,packet = self.callbacksQueue.get()
				self.callbacks[index].run(packet)

	def removeCallbacks(self):
		'''
		Remove the callbacks attached to the Receiver.
		'''
		self.callbacks = []
	
	def stop(self):
		'''
		Stops the Receiver and the associated device
		'''
		super().stop()
		if self.isDeviceUp():
			self.device.close()
