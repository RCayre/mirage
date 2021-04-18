#!/usr/bin/env python3
from mirage.core import app,argParser
from mirage.libs.utils import initializeHomeDir


def main():
	try:
		homeDir = initializeHomeDir()
		mainApp = app.App(homeDir=homeDir)
		parser = argParser.ArgParser(appInstance=mainApp)
		parser.run()

	except (KeyboardInterrupt,EOFError):
		mainApp.exit()
