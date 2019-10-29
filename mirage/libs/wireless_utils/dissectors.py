import copy

class Dissector:
	'''
	This class defines a dissector : it allows to easily convert a complex data structure to the corresponding raw bytes, or the raw bytes to the corresponding data structure. 
	Every dissector must inherits from this class in order to provide the same API.

	A data structure is described as a dictionary, composed of one (or more) field(s) and stored in the ``content`` attribute. Every key of this dictionary can be manipulated as a standard attribute.
	The corresponding data is stored in the ``data`` attribute as a list of raw bytes.

	Two main methods have to be implemented :

	  * **build** : this method converts the data structure to the corresponding raw bytes
	  * **dissect** : this method converts the raw bytes to the corresponding data structure
	'''
	def __init__(self,data=b"",length=-1,content={},*args, **kwargs):
		self.data = data
		if len(args)==1 and data==b"":
			self.data = args[0]
			
		self.length = length if length!=-1 else len(self.data)

		self.content = copy.copy(content)

		if self.data != b"":
			self.dissect()
		else:
			for k,v in kwargs.items():
				self.content[k] = v
		self.build()

	def dissect(self):
		'''
		This method converts the data structure to the corresponding raw bytes.

		:Example:
			
			>>> dissector.dissect()

		'''

		self.content = {}

	def __getattr__(self, name):
		if name in self.content:
			return self.content[name]
		else:
			return None

	def __setattribute__(self,name,value):
		self.content[name] = value
		self.build()

	def __repr__(self):
		return self.__str__()

	def __eq__(self,other):
		return self.data == other.data or self.content == other.content

	def build(self):
		'''
		This method converts the raw bytes to the corresponding data structure.

		:Example:
			
			>>> dissector.build()

		'''

		self.data = b""
		self.length = -1




