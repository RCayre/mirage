from mirage.libs import utils,io
from mirage.core import module
import configparser

class mouse_visualizer(module.Module):
	def init(self):
		self.technology = "generic"
		self.type = "tool"
		self.description = "Visualization module allowing to display mice movements"
		self.args = {
				"MOUSE_FILE":"",
				"GIF_FILE":"output.gif"
			}

	def importMiceDatas(self,filename=""):
		filename = filename if filename != "" else self.args["MOUSE_FILE"]
		io.info("Importing mice datas from "+filename+" ...")
		miceDatas = []
		config = configparser.ConfigParser()
		config.read(filename)
		for index in config.sections():
			miceData = config[index]
			miceDatas.append({
						"x":int(miceData.get("x")),
						"y":int(miceData.get("y")),
						"leftClick":"True"==miceData.get("leftClick"),
						"rightClick":"True"==miceData.get("rightClick")
					})
		return miceDatas
	def run(self):
		if self.args["MOUSE_FILE"] == "" or self.args["GIF_FILE"] == "":
			io.fail("You must provide an input and an output file !")
			return self.nok()
		else:
			miceDatas = self.importMiceDatas()
			io.MiceVisualizer(datas=miceDatas,outputFile=self.args["GIF_FILE"]).visualize()
		return self.ok()
