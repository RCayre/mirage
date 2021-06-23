from ctypes import *
from mirage.libs.common.sdr.hackrf_definitions import *
from mirage.libs import io,utils
import os,threading

'''
This component implements the API used to interact with Software Defined Radios.
'''

class HackRFSDR:
	'''
	This class provides an API allowing to interact with an HackRF one Sofware Defined Radio.
	'''
	initialized = False
	instances = {}

	@classmethod
	def setupAPI(cls):
		'''
		This method initializes the HackRF API.
		'''
		if not HACKRFLIB_AVAILABLE:
			io.fail("Fatal error: libhackrf has not been found. Exiting ...")
			utils.exitMirage()

		if not cls.initialized:
			libhackrf.hackrf_init()
			cls.initialized = True
			io.success("HackRF API initialized !")


	@classmethod
	def closeAPI(cls):
		'''
		This method closes the HackRF API.
		'''
		if cls.initialized:
			libhackrf.hackrf_exit()
			cls.initialized = False


	@classmethod
	def listHackRFs(cls):
		'''
		This method returns the HackRF devices found.


		:Example:

			>>> HackRFSDR.listHackRFs()
			['0000000000000000a06063c8234e925f']

		'''
		ret = libhackrf.hackrf_device_list()
		arrayType = (POINTER(c_char)*ret.contents.devicecount)
		foundDevices = []
		for i in range (ret.contents.devicecount):
			serials = cast(ret.contents.serial_number,POINTER(arrayType)).contents[i]
			serialnumberType = (c_char*33)
			foundDevices.append(cast(serials,POINTER(serialnumberType)).contents[:32].decode('utf-8'))
		return foundDevices

	def __init__(self,interface):
		HackRFSDR.setupAPI()
		self.lock = threading.Lock()
		self.ready = False
		self.device = POINTER(hackrf_device)()
		devicesList = HackRFSDR.listHackRFs()
		self.antenna = True
		self.amplifier = False

		if "hackrf" == interface[:6] and (interface[6:].isdigit() or interface[6:] == ""):
			self.index = 0 if interface[6:] == "" else int(interface[6:])
			self.serial = devicesList[self.index] if self.index < len(devicesList) else None
		elif "hackrf:" in interface and len(interface.split(":")[1]) == 32:
			self.serial = interface.split(":")[1] if interface.split(":")[1] in devicesList else None
			self.index = devicesList.index(self.serial) if self.serial is not None else None
		if self.serial is not None:
			if self.serial not in HackRFSDR.instances:
				self.openHackRF()
			else:
				self.device = HackRFSDR.instances[self.serial]
				self.ready = True

		else:
			io.fail("HackRF not found !")
			utils.exitMirage()
			self.device = None

	def openHackRF(self):
		ser = create_string_buffer(len(self.serial)+1)
		ser.value = bytes(self.serial,"utf-8")
		ret = libhackrf.hackrf_open_by_serial(ser,self.device)
		if ret == HackRfError.HACKRF_SUCCESS:
			HackRFSDR.instances[self.serial] = self.device
			self.ready = True
			io.success("HackRF successfully initialized !")
		else:
			self.device = None


	def restart(self):
		self.ready = False
		self.lock.acquire()
		ret = libhackrf.hackrf_close(self.device)
		ser = create_string_buffer(len(self.serial)+1)
		ser.value = bytes(self.serial,"utf-8")
		ret = libhackrf.hackrf_open_by_serial(ser,self.device)
		if ret == HackRfError.HACKRF_SUCCESS:
			HackRFSDR.instances[self.serial] = self.device
			self.ready = True
		self.lock.release()

	def isReady(self):
		'''
		This method indicates if the current HackRF is ready to use.

		:return: boolean indicating if the HackRF is ready
		:rtype: bool

		:Example:

			>>> hackrf.isReady()
			True

		'''
		return self.ready

	def getSerial(self):
		'''
		This method returns the serial number of the current HackRF.

		:return: serial number of the current HackRF
		:rtype: str

		:Example:

			>>> hackrf.getSerial()
			'0000000000000000a06063c8234e925f'

		'''
		return self.serial

	def getDeviceIndex(self):
		'''
		This method returns the device index of the current HackRF.

		:return: device index of the current HackRF
		:rtype: int

		:Example:

			>>> hackrf.getDeviceIndex()
			0

		'''
		return self.index

	def getBoardID(self):
		'''
		This method returns the board identifier of the current HackRF.

		:return: board identifier of the current HackRF
		:rtype: int

		:Example:

			>>> hackrf.getBoardID()
			2

		'''
		self.lock.acquire()
		value = c_uint8()
		ret = libhackrf.hackrf_board_id_read(self.device, byref(value))
		self.lock.release()
		if ret == HackRfError.HACKRF_SUCCESS:
			return value.value
		else:
			return None

	def getBoardName(self):
		'''
		This method returns the board name of the current HackRF.

		:return: board name of the current HackRF
		:rtype: str

		:Example:

			>>> hackrf.getBoardName()
			'HackRF One'

		'''
		boardId = self.getBoardID()
		return libhackrf.hackrf_board_id_name(boardId).decode('utf-8')

	def getFirmwareVersion(self):
		'''
		This method returns the firmware version of the current HackRF.

		:return: string indicating firmware version of the current HackRF
		:rtype: str

		:Example:

			>>> hackrf.getFirmwareVersion()
			'git-b9558ba'

		'''
		self.lock.acquire()
		version = create_string_buffer(20)
		length = c_uint8(20)
		ret = libhackrf.hackrf_version_string_read(self.device, version, length)
		self.lock.release()
		if ret == HackRfError.HACKRF_SUCCESS:
			return version.value.decode('utf-8')
		else:
			return None

	def getAPIVersion(self):
		'''
		This method returns the HackRF API version.

		:return: tuple of integers indicating the API version
		:rtype: (int,int)

		:Example:

			>>> hackrf.getAPIVersion()
			(1, 3)

		'''
		self.lock.acquire()
		version = c_uint16()
		libhackrf.hackrf_usb_api_version_read(self.device,byref(version))
		self.lock.release()

		return ((version.value>>8)&0xFF, version.value&0xFF)

	def setBandwidth(self,bandwidth):
		'''
		This method sets the Bandwidth used by the HackRF.

		:param bandwidth: bandwidth in Hertz
		:type bandwidth: int
		:return: boolean indicating if the operation was successful
		:rtype: bool

		:Example:

			>>> hackrf.setBandwidth(1 * 1000 * 1000)
			True

		'''
		self.lock.acquire()
		basebandFilterBandwidth = libhackrf.hackrf_compute_baseband_filter_bw_round_down_lt(bandwidth)
		ret = libhackrf.hackrf_set_baseband_filter_bandwidth(self.device, basebandFilterBandwidth)
		self.lock.release()

		if ret == HackRfError.HACKRF_SUCCESS:
			self.bandwidth = bandwidth
			return True
		else:
			return False

	def getBandwidth(self):
		'''
		This method returns the Bandwidth used by the HackRF.

		:return: bandwidth in Hertz
		:rtype: int

		:Example:

			>>> hackrf.getBandwidth()
			1000000

		'''

		return self.bandwidth

	def enableAmplifier(self):
		'''
		This method enables the HackRF amplifier.

		:return: boolean indicating if the operation was successful
		:rtype: bool

		:Example:

			>>> hackrf.enableAmplifier()
			True

		'''
		if not self.amplifier:
			self.lock.acquire()
			ret = libhackrf.hackrf_set_amp_enable(self.device, 1)
			self.lock.release()

			if ret == HackRfError.HACKRF_SUCCESS:
				self.amplifier = True
				return True
			else:
				return False
		return True


	def disableAmplifier(self):
		'''
		This method disables the HackRF amplifier.

		:return: boolean indicating if the operation was successful
		:rtype: bool

		:Example:

			>>> hackrf.disableAmplifier()
			True

		'''
		if self.amplifier:
			self.lock.acquire()
			ret = libhackrf.hackrf_set_amp_enable(self.device, 0)
			self.lock.release()
			if ret == HackRfError.HACKRF_SUCCESS:
				self.amplifier = False
				return True
			else:
				return False
		return True

	def enableAntenna(self):
		'''
		This method enables the HackRF antenna.

		:return: boolean indicating if the operation was successful
		:rtype: bool

		:Example:

			>>> hackrf.enableAntenna()
			True

		'''
		if not self.antenna:
			self.lock.acquire()
			ret =  libhackrf.hackrf_set_antenna_enable(self.device, 1)
			self.lock.release()

			if ret == HackRfError.HACKRF_SUCCESS:
				self.antenna = True
				return True
			else:
				return False
		return True

	def disableAntenna(self):
		'''
		This method disables the HackRF antenna.

		:return: boolean indicating if the operation was successful
		:rtype: bool

		:Example:

			>>> hackrf.disableAntenna()
			True

		'''
		if self.antenna:
			self.lock.acquire()
			ret =  libhackrf.hackrf_set_antenna_enable(self.device, 0)
			self.lock.release()

			if ret == HackRfError.HACKRF_SUCCESS:
				self.antenna = False
				return True
			else:
				return False
		return True

	def setFrequency(self,frequency):
		'''
		This method sets the frequency used by the HackRF.

		:param frequency: frequency (in Hertz)
		:type frequency: int
		:return: boolean indicating if the operation was successful
		:rtype: bool

		:Example:

			>>> hackrf.setFrequency(2402000000)
			True

		'''
		self.lock.acquire()
		ret = libhackrf.hackrf_set_freq(self.device, frequency)
		self.lock.release()

		if ret == HackRfError.HACKRF_SUCCESS:
			self.frequency = frequency
			return True
		else:
			return False

	def getFrequency(self):
		'''
		This method returns the frequency used by the HackRF.

		:return: current frequency (in Hertz)
		:rtype: int

		:Example:

			>>> hackrf.getFrequency()
			2402000000

		'''
		return self.frequency

	def setSampleRate(self,sampleRate):
		'''
		This method sets the sample rate used by the HackRF.

		:param sampleRate: sample rate (in samples/s)
		:type sampleRate: int
		:return: boolean indicating if the operation was successful
		:rtype: bool

		:Example:

			>>> hackrf.setSampleRate(2 * 1000 * 1000)
			True

		'''
		self.lock.acquire()
		ret = libhackrf.hackrf_set_sample_rate(self.device, sampleRate)
		self.lock.release()

		if ret == HackRfError.HACKRF_SUCCESS:
			self.sampleRate = sampleRate
			return True
		else:
			return False

	def getSampleRate(self):
		'''
		This method returns the sample rate used by the HackRF.

		:return: sample rate in use(in samples/s)
		:rtype: int

		:Example:

			>>> hackrf.getSampleRate()
			2000000

		'''
		return self.sampleRate

	def setTXGain(self,txGain): # TX Gain
		'''
		This method sets the TX gain used by the HackRF.

		:param txGain: TX gain
		:type txGain: int
		:return: boolean indicating if the operation was successful
		:rtype: bool

		:Example:

			>>> hackrf.setTXGain(40)
			True

		'''
		self.lock.acquire()
		ret = libhackrf.hackrf_set_txvga_gain(self.device, txGain)
		self.lock.release()

		if ret == HackRfError.HACKRF_SUCCESS:
			self.txGain = txGain
			return True
		else:
			return False

	def getTXGain(self):
		'''
		This method returns the TX gain used by the HackRF.

		:return: TX gain in use
		:rtype: int

		:Example:

			>>> hackrf.getTXGain()
			40

		'''
		return self.txGain

	def setGain(self,gain): # VGA Gain
		'''
		This method sets the VGA gain used by the HackRF.

		:param gain: VGA gain
		:type gain: int
		:return: boolean indicating if the operation was successful
		:rtype: bool

		:Example:

			>>> hackrf.setGain(40)
			True

		'''
		self.lock.acquire()
		ret = libhackrf.hackrf_set_vga_gain(self.device, gain)
		self.lock.release()

		if ret == HackRfError.HACKRF_SUCCESS:
			self.gain = gain
			return True
		else:
			return False


	def getGain(self):
		'''
		This method returns the VGA gain used by the HackRF.

		:return: VGA gain in use
		:rtype: int

		:Example:

			>>> hackrf.getGain()
			40

		'''
		return self.gain

	def setLNAGain(self,lnaGain): # LNA Gain
		'''
		This method sets the LNA gain used by the HackRF.

		:param gain: LNA gain
		:type gain: int
		:return: boolean indicating if the operation was successful
		:rtype: bool

		:Example:

			>>> hackrf.setLNAGain(40)
			True

		'''
		self.lock.acquire()
		ret = libhackrf.hackrf_set_lna_gain(self.device, lnaGain)
		self.lock.release()

		if ret == HackRfError.HACKRF_SUCCESS:
			self.lnaGain = lnaGain
			return True
		else:
			return False

	def getLNAGain(self):
		'''
		This method returns the LNA gain used by the HackRF.

		:return: VGA gain in use
		:rtype: int

		:Example:

			>>> hackrf.getLNAGain()
			40

		'''
		return self.lnaGain

	def __del__(self):
		if self.device is not None:
			self.close()


	def close(self):
		'''
		This method closes the current HackRF.

		:return: boolean indicating if the operation was successful
		:rtype: int

		:Example:

			>>> hackrf.close()
			True

		'''
		if self.device is not None and self.serial in HackRFSDR.instances:
			HackRFSDR.instances.pop(self.serial)
			self.lock.acquire()
			ret = libhackrf.hackrf_close(self.device)
			self.lock.release()

			return ret == HackRfError.HACKRF_SUCCESS
		return False
