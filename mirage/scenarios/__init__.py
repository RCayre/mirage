import os, sys, imp
from mirage.core.app import App
from mirage.libs.utils import getHomeDir,generateScenariosDictionary

if App.Instance is not None:
	# Scenarios Directory
	SCENARIOS_DIR = os.path.abspath(os.path.dirname(__file__))
	SCENARIOS_USER_DIR = getHomeDir() + "/scenarios"

	__scenarios__ = generateScenariosDictionary(SCENARIOS_DIR, SCENARIOS_USER_DIR)
'''
# Insertion of the root directory in the PYTHON PATH
#sys.path.insert(0,  os.path.abspath(os.path.dirname(__file__)+"/.."))

# Creation of the list of scenarios
__scenarios__ = {}
for scenario in os.listdir(SCENARIOS_DIR):
	if os.path.isfile(SCENARIOS_DIR+"/"+scenario) and scenario[-3:] == ".py" and scenario != "__init__.py":
		__scenarios__[scenario[:-3]]=imp.load_source(scenario[:-3],SCENARIOS_DIR + "/"+scenario)
		
for scenario in os.listdir(SCENARIOS_USER_DIR):
	if os.path.isfile(SCENARIOS_USER_DIR+"/"+scenario) and scenario[-3:] == ".py" and scenario != "__init__.py":
		__scenarios__[scenario[:-3]]=imp.load_source(scenario[:-3],SCENARIOS_USER_DIR + "/"+scenario)
'''
