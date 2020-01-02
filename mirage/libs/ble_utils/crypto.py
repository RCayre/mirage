from Cryptodome.Cipher import AES
from os import urandom
from multiprocessing import Process, Manager,cpu_count
import time,struct
from mirage.libs import io

class BLECrypto:
	'''
	This class provides some cryptographic functions used by the Security Manager.

	.. note::

		The ``temporaryKeys`` class attribute is used in order to precalculate the possible temporary keys. It allows to avoid some time consuming calculations during the cracking process.

	'''

	temporaryKeys = [bytes.fromhex((32-len(hex(i)[2:]))*"0"+hex(i)[2:]) for i in range(1000000)]	

	@classmethod
	def _findKey(cls,L,pMin,pMax,r,pres,preq,iat,ia,rat,ra,confirm):
		i = pMin
		p1 = pres + preq + rat + iat
		p2 = b"\x00\x00\x00\x00" + ia + ra
		a = cls.xor128(p1,r)
		
		while i < pMax:
			aes = AES.new(cls.temporaryKeys[i],AES.MODE_ECB)
			res1 = aes.encrypt(a)
			b = cls.xor128(res1,p2)
			res2 = aes.encrypt(b)
			if res2 == confirm:
				L.append(i)
				break
			else:
				i+=1

	@classmethod
	def crackTemporaryKey(cls,r,preq,pres,iat,initiatorAddress,rat,responderAddress,confirm):
		'''
		This class method allows to crack a temporary key, according to multiple parameters extracted during the pairing process. It returns the corresponding PIN code.

		:param r: random value
		:type r: bytes
		:param preq: pairing request's payload
		:type preq: bytes
		:param pres: pairing response's payload
		:type pres: bytes
		:param iat: initiator address type
		:type iat: bytes
		:param initiatorAddress: initiator address (format : *"1A:2B:3C:4D:5E:6F"*)
		:type initiatorAddress: str
		:param rat: responder address type
		:type rat: bytes
		:param responderAddress: responder address (format : *"1A:2B:3C:4D:5E:6F"*)
		:type responderAddress: str
		:param confirm: confirm value
		:type confirm: bytes
		:return: corresponding PIN code
		:rtype: int

		:Example:

			>>> random = bytes.fromhex("abb692ebfd4601f4aad3aea40f7da5fc")[::-1]
			>>> pairingRequest = bytes.fromhex("01030005100001")[::-1]
			>>> pairingResponse = bytes.fromhex("02000005100001")[::-1]
			>>> initiatorAddress = "08:3E:8E:E1:0B:3E"
			>>> initiatorAddressType = b"\x00"
			>>> responderAddress = "78:C5:E5:6E:DD:E8"
			>>> responderAddressType = b"\x00"
			>>> confirm = bytes.fromhex("febb983ed78020e13d685bc8418d2c5d")[::-1]
			>>> BLECrypto.crackTemporaryKey(random,pairingRequest,pairingResponse, initiatorAddressType,initiatorAddress,responderAddressType,responderAddress,confirm)
			0

		.. warning::

			This method uses multi processes in order to optimize the time consumption of the required operation.

		'''
		iAddr = b''.join([bytes.fromhex(i) for i in initiatorAddress.split(":")])
		rAddr = b''.join([bytes.fromhex(i) for i in responderAddress.split(":")])
		with Manager() as manager:
			L = manager.list()
			processes = []
			n = cpu_count()
			step = int(1000000 / n)
			for i in range(n):
				p = Process(target=cls._findKey, args=(
									L,
									i*step,
									(i+1)*step,
									r,
									pres,
									preq,
									iat,
									iAddr,
									rat,
									rAddr,
									confirm
									)
						)
				p.start()
				processes.append(p)

			while list(L) == []:
				time.sleep(0.01)
			for p in processes:
				p.terminate()
			return L[0]

	@classmethod
	def generateRandom(cls,size=16):
		'''
		This class method allows to easily generate a random value, according to the size (number of bytes) provided.

		:param size: number of bytes of the random value
		:type size: int
		:return: random list of bytes
		:rtype: bytes

		:Example:

			>>> BLECrypto.generateRandom().hex()
			'd05c872faaef8bc959b801e4c30c0afa'
			>>> BLECrypto.generateRandom(3).hex()
			'e7bbc9'

		'''
		return urandom(size)

	@classmethod
	def e(cls,key,plaintext):
		'''
		This class method implements the security function :math:`E`

		:param key: encryption key
		:type key: bytes
		:param plaintext: plain text data
		:type plaintext: bytes
		:return: encrypted data
		:rtype: bytes

		.. seealso::

			This function is described in Bluetooth Core Specification, [Vol 3] Part H, Section 2.2.1.

		'''
		aes = AES.new(key,AES.MODE_ECB)
		return aes.encrypt(plaintext)

	@classmethod
	def em1(cls,key,ciphertext):
		'''
		This class method implements the inverse function :math:`E_{-1}` of the security function :math:`E`

		:param key: encryption key
		:type key: bytes
		:param ciphertext: encrypted data
		:type ciphertext: bytes
		:return: decrypted data
		:rtype: bytes

		.. seealso::

			This function is described in Bluetooth Core Specification, [Vol 3] Part H, Section 2.2.1.

		'''
		aes = AES.new(key,AES.MODE_ECB)
		return aes.decrypt(ciphertext)

	@classmethod
	def s1(cls,key,randMaster,randSlave):
		'''
		This class method implements the key generation function :math:`S1`

		:param key: encryption key
		:type key: bytes
		:param randMaster: master's random value
		:type randMaster: bytes
		:param randSlave: slave's random value
		:type randSlave: bytes
		:return: generated key
		:rtype: bytes

		.. seealso::

			This function is described in Bluetooth Core Specification, [Vol 3] Part H, Section 2.2.4.

		'''
		r = randSlave[8:16] + randMaster[8:16]
		return BLECrypto.e(key,r)


	@classmethod
	def xor128(cls,a1,b1):
		'''
		This class method implements the XOR operation applied to 128 bits bytes strings.

		:param a1: first value
		:type a1: bytes
		:param b1: second value
		:type b1: bytes
		:return: result
		:rtype: bytes
		'''

		return bytes([a ^ b for a,b in zip(a1,b1)])

	@classmethod
	def c1(cls,key,rand,payloadRequest, payloadResponse,initiatorAddressType, initiatorAddress, responderAddressType, responderAddress):
		'''
		This class method implements the confirm value generation function :math:`C1`

		:param key: encryption key
		:type key: bytes
		:param rand: random value
		:type rand: bytes
		:param payloadRequest: request's payload
		:type payloadRequest: bytes
		:param payloadResponse: response's payload
		:type payloadResponse: bytes
		:param initiatorAddressType: initiator address type (format : b"\x00" if type is public or b"\x01" if it is random)
		:type initiatorAddressType: bytes
		:param initiatorAddress: initiator address (format : "A1:B2:C3:D4:E5:F6")
		:type initiatorAddress: str
		:param responderAddressType: responder address type (format : b"\x00" if type is public or b"\x01" if it is random)
		:type responderAddressType: bytes
		:param responderAddress: responder address (format : "A1:B2:C3:D4:E5:F6")
		:type responderAddress: str
		:return: generated confirm value
		:rtype: bytes

		.. seealso::

			This function is described in Bluetooth Core Specification, [Vol 3] Part H, Section 2.2.3.

		'''
		iAddr = b''.join([bytes.fromhex(i) for i in initiatorAddress.split(":")])
		rAddr = b''.join([bytes.fromhex(i) for i in responderAddress.split(":")])
		p1 = payloadResponse + payloadRequest + responderAddressType + initiatorAddressType
		p2 = b"\x00\x00\x00\x00" + iAddr + rAddr
		res1 = BLECrypto.e(key,BLECrypto.xor128(p1,rand))
		res2 = BLECrypto.e(key,BLECrypto.xor128(res1,p2))
		return res2

	@classmethod
	def c1m1(cls,key,confirm,payloadRequest, payloadResponse,initiatorAddressType, initiatorAddress, responderAddressType, responderAddress):
		'''
		This class method implements the inverse function :math:`C1_{-1}` of the confirm value generation function :math:`C1`

		:param key: encryption key
		:type key: bytes
		:param confirm: confirm value
		:type confirm: bytes
		:param payloadRequest: request's payload
		:type payloadRequest: bytes
		:param payloadResponse: response's payload
		:type payloadResponse: bytes
		:param initiatorAddressType: initiator address type (format : b"\x00" if type is public or b"\x01" if it is random)
		:type initiatorAddressType: bytes
		:param initiatorAddress: initiator address (format : "A1:B2:C3:D4:E5:F6")
		:type initiatorAddress: str
		:param responderAddressType: responder address type (format : b"\x00" if type is public or b"\x01" if it is random)
		:type responderAddressType: bytes
		:param responderAddress: responder address (format : "A1:B2:C3:D4:E5:F6")
		:type responderAddress: str
		:return: corresponding random value
		:rtype: bytes

		.. seealso::

			This function is described in Bluetooth Core Specification, [Vol 3] Part H, Section 2.2.3.

		'''
		iAddr = b''.join([bytes.fromhex(i) for i in initiatorAddress.split(":")])
		rAddr = b''.join([bytes.fromhex(i) for i in responderAddress.split(":")])
		p1 = payloadResponse + payloadRequest + responderAddressType + initiatorAddressType
		p2 = b"\x00\x00\x00\x00" + iAddr + rAddr
		return cls.xor128(cls.em1(key,cls.xor128(cls.em1(key,confirm),p2)),p1)




class BLELinkLayerCrypto(object):
	'''
	This class provides an API allowing to manipulate the Link Layer Cryptographic functions used by Bluetooth Low Energy.

	.. warning::

		This class is used by the receiver ``BLEReceiver`` (``mirage.libs.ble.BLEReceiver``) and should not be used directly by an user. 

	'''
	instance = None

	@classmethod
	def provideLTK(cls,ltk):
		'''
		This class method initializes a singleton's instance of the current class.
		It allows to provide a Long Term Key.

		:param ltk: Long Term Key
		:type ltk: bytes
		'''
		cls.instance = cls(ltk=ltk)

	@classmethod
	def getInstance(cls):
		'''
		This class method returns the singleton's instance of the current class.

		:return: instance of this class
		:rtype: BLELinkLayerCrypto

		'''
		return cls.instance

	def __init__(self,ltk):
		self.ltk = ltk[::-1]
		self.masterSkd = None
		self.slaveSkd = None
		self.masterIv = None
		self.slaveIv = None
		self.skd = None
		self.iv = None
		self.sessionKey = None
		self.ready = False
		self.masterCounter = 0
		self.slaveCounter = 0

	def displayDetails(self):
		'''
		This method displays a chart indicating the session keys' diversifier, the initializations vectors and the session key. If some values have not been provided or calculated, it displays an error message.
		'''
		if self.ready:
			io.chart(["Name","Value"],[
							["Master SKD",self.masterSkd.hex()],
							["Master IV",self.masterIv.hex()],
							["Slave SKD",self.masterSkd.hex()],
							["Slave IV",self.masterIv.hex()],
							["SKD",self.skd.hex()],
							["IV",self.iv.hex()],
							["Session Key",self.sessionKey.hex()]
						],"Encryption information")
		else:
			io.fail("Missing informations, encryption disabled")

	def setMasterValues(self,skd,iv):
		'''
		This method allows to provide the session key diversifier and the initialization vector from Master.

		:param skd: session key diversifier
		:type skd: bytes
		:param iv: initialization vector
		:type iv: bytes
		'''
		self.masterSkd = struct.pack(">Q",skd)
		self.masterIv = struct.pack("<L",iv)

	def setSlaveValues(self,skd,iv):
		'''
		This method allows to provide the session key diversifier and the initialization vector from Slave.

		:param skd: session key diversifier
		:type skd: bytes
		:param iv: initialization vector
		:type iv: bytes
		'''
		self.slaveSkd = struct.pack(">Q",skd)
		self.slaveIv = struct.pack("<L",iv)

	def generateSkd(self):
		'''
		This method generates the session key diversifier according to the provided master's and slave's diversifier.
		'''
		if self.masterSkd is not None and self.slaveSkd is not None:
			self.skd = self.slaveSkd + self.masterSkd
			return True
		else:
			return False

	def generateIv(self):
		'''
		This method generates the initialization vector according to the provided master's and slave's IV.
		'''
		if self.masterIv is not None and self.slaveIv is not None:
			self.iv = self.masterIv + self.slaveIv
			return True
		else:
			return False

	def generateSessionKey(self):
		'''
		This method generates the session key according to the calculted session key diversifier and initialization vector.
		'''
		successSkd = self.generateSkd()
		successIv = self.generateIv()
		if successSkd and successIv:
			self.sessionKey = BLECrypto.e(self.ltk,self.skd)
			self.ready = True
			self.masterCounter = self.slaveCounter = 0
			io.success("Session key successfully generated !")
			self.displayDetails()
			return True
		else:
			io.fail("An error occured during session key generation.")
			return False


	def generateNonce(self,masterToSlave):
		'''
		This method generates a nonce.

		:param masterToSlave: boolean indicating if the direction is "master to slave"
		:type masterToSlave: bool
		:return: generated nonce
		:rtype: bytes
		'''
		counter = struct.pack("i",self.masterCounter if masterToSlave else self.slaveCounter)
		direction = b"\x00" if masterToSlave else b"\x80"
		return counter + direction + self.iv

	def encrypt(self,payload,masterToSlave=True):
		'''
		This method encrypts the provided payload, according to the direction provided.
	
		:param payload: payload to encrypt
		:type payload: bytes
		:param masterToSlave: boolean indicating if the direction is "master to slave"
		:type masterToSlave: bool
		:return: first two bytes of the payload + ciphertext + message integrity check
		:rtype: bytes		
		'''
		if self.ready:
			hdr = bytes([payload[0] & 0xe3])
			nonce = self.generateNonce(masterToSlave)
			plaintext = payload[2:]
			cipher = AES.new(self.sessionKey,AES.MODE_CCM,nonce=nonce, mac_len=4,assoc_len=len(hdr))
			cipher.update(hdr)
			ciphertext = cipher.encrypt(plaintext)
			mic = cipher.digest()
			return payload[:2] + ciphertext + mic

	def tryToDecrypt(self,payload):
		'''
		This function tries to decrypt a payload. It tries to guess the direction (master to slave or slave to master) and the right counters' values.

		:param payload: payload to decrypt
		:type payload: bytes
		:return: tuple composed of (decrypted payload, boolean indicating if the operation was successful)
		:rtype: tuple of (bytes,bool)

		.. note:: 
			If the operation fails, the decrypted payload field of the tuple is replaced by None
		'''
		plain,masterToSlave = self.decrypt(payload,masterToSlave=True)
		if masterToSlave:
			self.incrementMasterCounter()	
			return (plain,True)		
		else:
			plain,slaveToMaster = self.decrypt(payload,masterToSlave=False)
			if slaveToMaster:
				self.incrementSlaveCounter()
				return (plain,True)
		
		if not masterToSlave and not slaveToMaster:
			masterCounter = self.masterCounter
			slaveCounter = self.slaveCounter
			found = False
			iteration = 0	
			io.info("We have missed something, trying to recover counters' values ...")
			while not found and iteration < 30:
				iteration += 1
				self.incrementMasterCounter()
				plain,masterToSlave = self.decrypt(payload,masterToSlave=True)
				if masterToSlave:
					io.success("Master counter recovered !")
					found = True
					self.slaveCounter = slaveCounter
					self.incrementMasterCounter()						
				else:
					self.incrementSlaveCounter()
					plain,slaveToMaster = self.decrypt(payload,masterToSlave=False)
					if slaveToMaster:
						io.success("Slave counter recovered !")
						found = True
						self.masterCounter = masterCounter
						self.incrementSlaveCounter()
		
			return (plain,True) if found else (None, False)			
		
	def decrypt(self,payload,masterToSlave=True):
		'''
		This method decrypts the provided payload, according to the direction provided.
	
		:param payload: payload to decrypt
		:type payload: bytes
		:param masterToSlave: boolean indicating if the direction is "master to slave"
		:type masterToSlave: bool
		:return: tuple composed of (two first bytes of the payload + decrypted payload, boolean indicating if the message's integrity is valid)
		:rtype: tuple of (bytes,bool)		
		'''
		if self.ready:
			hdr = bytes([payload[0] & 0xe3])
			ciphertext = payload[2:-4]
			mic = payload[-4:]
			nonce = self.generateNonce(masterToSlave)
			cipher = AES.new(self.sessionKey, AES.MODE_CCM, nonce=nonce, mac_len=4, assoc_len=len(hdr))
			cipher.update(hdr)
			plaintext = cipher.decrypt(ciphertext)	
			try:
				cipher.verify(mic)
				return (payload[:2] + plaintext, True)
			except ValueError:
				return (payload[:2] + plaintext,False)				
		
	def incrementMasterCounter(self):
		'''
		This method increments the master's counter.
		'''
		self.masterCounter += 1

	def incrementSlaveCounter(self):		
		'''
		This method increments the slave's counter.
		'''
		self.slaveCounter += 1
