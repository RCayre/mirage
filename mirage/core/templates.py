__module_template__ = """from mirage.core import module
from mirage.libs import utils,$technology

class $name(module.WirelessModule):
	def init(self):
		self.technology = "$technology"
		self.type = "$type"
		self.description = "$description"
		self.args = $arguments
		self.dependencies = [$dependencies]

	def run(self):
		# Enter your code here.
		return self.ok({})
"""

__scenario_template__ = """from mirage.core import scenario
from mirage.libs import io,ble,esb,utils

class $name(scenario.Scenario):

	def onStart(self):
		return True

	def onEnd(self):
		return True
	
	def onKey(self,key):
		return True
"""
