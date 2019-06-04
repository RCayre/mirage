from fcntl import ioctl
import socket

class HCIConfig(object):
	'''
	This class allows to easily configure an HCI Interface.
	'''

	@staticmethod
	def down(index):
		'''
		This class method stops an HCI interface.
		Its role is equivalent to the following command : ``hciconfig hci<index> down``

		:param index: index of the HCI interface to stop 
		:type index: integer

		:Example:
	
			>>> HCIConfig.down(0)

		'''
		
		try:
			sock = socket.socket(31, socket.SOCK_RAW, 1)
			ioctl(sock.fileno(), 0x400448ca, index)
			sock.close()
		except IOError:
			return False
		return True

	@staticmethod
	def reset(index):
		'''
		This class method resets an HCI interface.
		Its role is equivalent to the following command : ``hciconfig hci<index> reset``

		:param index: index of the HCI interface to reset 
		:type index: integer

		:Example:
	
			>>> HCIConfig.reset(0)

		'''
		try:
			sock = socket.socket(31, socket.SOCK_RAW, index)
			ioctl(sock.fileno(), 0x400448cb, 0)
			sock.close()
		except IOError:
			return False
		return True

	@staticmethod
	def up(index):
		'''
		This class method starts an HCI interface.
		Its role is equivalent to the following command : ``hciconfig hci<index> up``

		:param index: index of the HCI interface to start 
		:type index: integer

		:Example:
	
			>>> HCIConfig.up(0)

		'''
		try:
			sock = socket.socket(31, socket.SOCK_RAW, index)
			ioctl(sock.fileno(), 0x400448c9, 0)
			sock.close()
		except IOError:
			return False
		return True
