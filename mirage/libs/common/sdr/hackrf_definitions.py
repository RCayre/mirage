from ctypes import *
import subprocess
from os.path import isfile

'''
This file contains the definitions used by HackRF one, e.g. library path or constants.
'''
HACKRFLIB_AVAILABLE = False

# Autofind the path of libhackrf.so
possiblePaths = [
	"/usr/local/lib/libhackrf.so",
	"/usr/lib/x86_64-linux-gnu/libhackrf.so",
	"/usr/lib64/libhackrf.so"
]
pathToLib = None
for path in possiblePaths:
	if isfile(path):
		pathToLib = path
		break
# The following line could be used to autofind the path, but it's probably too invasive and slow at startup
#pathToLib = subprocess.check_output("find / -name libhackrf.so 2> /dev/null | head -n1" , shell=True).decode('ascii').replace("\n","")

if pathToLib is not None:
	libhackrf = CDLL(pathToLib)
	HACKRFLIB_AVAILABLE = True

	# Enum definitions
	def enum(*sequential, **named):
		enums = dict(zip(sequential, range(len(sequential))), **named)
		return type('Enum', (), enums)

	HackRfVendorRequest = enum(
		HACKRF_VENDOR_REQUEST_SET_TRANSCEIVER_MODE			=	1,
		HACKRF_VENDOR_REQUEST_MAX2837_WRITE					=	2,
		HACKRF_VENDOR_REQUEST_MAX2837_READ					=	3,
		HACKRF_VENDOR_REQUEST_SI5351C_WRITE					=	4,
		HACKRF_VENDOR_REQUEST_SI5351C_READ					=	5,
		HACKRF_VENDOR_REQUEST_SAMPLE_RATE_SET				=	6,
		HACKRF_VENDOR_REQUEST_BASEBAND_FILTER_BANDWIDTH_SET	=	7,
		HACKRF_VENDOR_REQUEST_RFFC5071_WRITE				=	8,
		HACKRF_VENDOR_REQUEST_RFFC5071_READ					=	9,
		HACKRF_VENDOR_REQUEST_SPIFLASH_ERASE				=	10,
		HACKRF_VENDOR_REQUEST_SPIFLASH_WRITE				=	11,
		HACKRF_VENDOR_REQUEST_SPIFLASH_READ					=	12,
		HACKRF_VENDOR_REQUEST_CPLD_WRITE					=	13,
		HACKRF_VENDOR_REQUEST_BOARD_ID_READ					=	14,
		HACKRF_VENDOR_REQUEST_VERSION_STRING_READ			=	15,
		HACKRF_VENDOR_REQUEST_SET_FREQ						=	16,
		HACKRF_VENDOR_REQUEST_AMP_ENABLE					=	17,
		HACKRF_VENDOR_REQUEST_BOARD_PARTID_SERIALNO_READ	=	18,
		HACKRF_VENDOR_REQUEST_SET_LNA_GAIN					=	19,
		HACKRF_VENDOR_REQUEST_SET_VGA_GAIN					=	20,
		HACKRF_VENDOR_REQUEST_SET_TXVGA_GAIN				=	21
	)


	HackRfConstants = enum(
		LIBUSB_ENDPOINT_IN	=	0x80,
		LIBUSB_ENDPOINT_OUT	=	0x00,
		HACKRF_DEVICE_OUT	=	0x40,
		HACKRF_DEVICE_IN	=	0xC0,
		HACKRF_USB_VID		=	0x1d50,
		HACKRF_USB_PID		=	0x6089
	)



	HackRfError = enum(
		HACKRF_SUCCESS						=	0,
		HACKRF_TRUE							=	1,
		HACKRF_ERROR_INVALID_PARAM			=	-2,
		HACKRF_ERROR_NOT_FOUND				=	-5,
		HACKRF_ERROR_BUSY					=	-6,
		HACKRF_ERROR_NO_MEM					=	-11,
		HACKRF_ERROR_LIBUSB					=	-1000,
		HACKRF_ERROR_THREAD					=	-1001,
		HACKRF_ERROR_STREAMING_THREAD_ERR	=	-1002,
		HACKRF_ERROR_STREAMING_STOPPED		=	-1003,
		HACKRF_ERROR_STREAMING_EXIT_CALLED	=	-1004,
		HACKRF_ERROR_USB_API_VERSION		=	-1005,
		HACKRF_ERROR_NOT_LAST_DEVICE		=	-2000,
		HACKRF_ERROR_OTHER					=	-9999,
		# Python defaults to returning none
		HACKRF_ERROR						=	None
	)

	HackRfTranscieverMode = enum(
		HACKRF_TRANSCEIVER_MODE_OFF			=	0,
		HACKRF_TRANSCEIVER_MODE_RECEIVE		=	1,
		HACKRF_TRANSCEIVER_MODE_TRANSMIT	=	2
	)

	# Data structures
	_libusb_device_handle = c_void_p
	_pthread_t = c_ulong

	class hackrf_device(Structure):
	    pass

	class hackrf_device_list(Structure):
		_fields_ = [("serial_number", POINTER(POINTER(c_char))),
			("usb_board_ids",c_int),
			("usb_device_index",POINTER(c_int)),
			("devicecount",c_int),
			("usb_devices",POINTER(c_void_p)),
			("usb_device_count",c_int)]

	class hackrf_transfer(Structure):
		_fields_ = [("hackrf_device", POINTER(hackrf_device)),
			("buffer", POINTER(c_byte)),
			("buffer_length", c_int),
			("valid_length", c_int),
			("rx_ctx", c_void_p),
			("tx_ctx", c_void_p) ]

	hackrflibcallback = CFUNCTYPE(c_int, POINTER(hackrf_transfer))

	hackrf_device._fields_ = [("usb_device", POINTER(_libusb_device_handle)),
		("transfers", POINTER(POINTER(hackrf_transfer))),
		("callback", hackrflibcallback),
		("transfer_thread_started", c_int),
		("transfer_thread", _pthread_t),
		("transfer_count", c_uint32),
		("buffer_size", c_uint32),
		("streaming", c_int),
		("rx_ctx", c_void_p),
		("tx_ctx", c_void_p) ]

	# extern ADDAPI hackrf_device_list_t* ADDCALL hackrf_device_list();
	libhackrf.hackrf_device_list.restype = POINTER(hackrf_device_list)
	libhackrf.hackrf_device_list.argtypes = []

	# extern ADDAPI int ADDCALL hackrf_init();
	libhackrf.hackrf_init.restype = c_int
	libhackrf.hackrf_init.argtypes = []

	# extern ADDAPI int ADDCALL hackrf_exit();
	libhackrf.hackrf_exit.restype = c_int
	libhackrf.hackrf_exit.argtypes = []

	# extern ADDAPI int ADDCALL hackrf_open(hackrf_device** device);
	libhackrf.hackrf_open.restype = c_int
	libhackrf.hackrf_open.argtypes = [POINTER(POINTER(hackrf_device))]

	# extern ADDAPI int ADDCALL hackrf_open_by_serial(const char* const desired_serial_number, hackrf_device** device);
	libhackrf.hackrf_open_by_serial.restype = c_int
	libhackrf.hackrf_open_by_serial.argtypes = [POINTER(c_char),POINTER(POINTER(hackrf_device))]

	# extern ADDAPI int ADDCALL hackrf_close(hackrf_device* device);
	libhackrf.hackrf_close.restype = c_int
	libhackrf.hackrf_close.argtypes = [POINTER(hackrf_device)]

	# extern ADDAPI int ADDCALL hackrf_start_rx(hackrf_device* device,
	# hackrf_sample_block_cb_fn callback, void* rx_ctx);
	libhackrf.hackrf_start_rx.restype = c_int
	libhackrf.hackrf_start_rx.argtypes = [POINTER(hackrf_device), hackrflibcallback, c_void_p]

	# extern ADDAPI int ADDCALL hackrf_stop_rx(hackrf_device* device);
	libhackrf.hackrf_stop_rx.restype = c_int
	libhackrf.hackrf_stop_rx.argtypes = [POINTER(hackrf_device)]

	# extern ADDAPI int ADDCALL hackrf_start_tx(hackrf_device* device,
	# hackrf_sample_block_cb_fn callback, void* tx_ctx);
	libhackrf.hackrf_start_tx.restype = c_int
	libhackrf.hackrf_start_tx.argtypes = [POINTER(hackrf_device), hackrflibcallback, c_void_p]

	# extern ADDAPI int ADDCALL hackrf_stop_tx(hackrf_device* device);
	libhackrf.hackrf_stop_tx.restype = c_int
	libhackrf.hackrf_stop_tx.argtypes = [POINTER(hackrf_device)]

	# extern ADDAPI int ADDCALL hackrf_is_streaming(hackrf_device* device);
	libhackrf.hackrf_is_streaming.restype = c_int
	libhackrf.hackrf_is_streaming.argtypes = [POINTER(hackrf_device)]

	# extern ADDAPI int ADDCALL hackrf_max2837_read(hackrf_device* device,
	# uint8_t register_number, uint16_t* value);
	libhackrf.hackrf_max2837_read.restype = c_int
	libhackrf.hackrf_max2837_read.argtypes = [
	    POINTER(hackrf_device), c_uint8, POINTER(c_uint16)]

	# extern ADDAPI int ADDCALL hackrf_max2837_write(hackrf_device* device,
	# uint8_t register_number, uint16_t value);
	libhackrf.hackrf_max2837_write.restype = c_int
	libhackrf.hackrf_max2837_write.argtypes = [POINTER(hackrf_device), c_uint8, c_uint16]

	# extern ADDAPI int ADDCALL hackrf_si5351c_read(hackrf_device* device,
	# uint16_t register_number, uint16_t* value);
	libhackrf.hackrf_si5351c_read.restype = c_int
	libhackrf.hackrf_si5351c_read.argtypes = [
	    POINTER(hackrf_device), c_uint16, POINTER(c_uint16)]

	# extern ADDAPI int ADDCALL hackrf_si5351c_write(hackrf_device* device,
	# uint16_t register_number, uint16_t value);
	libhackrf.hackrf_si5351c_write.restype = c_int
	libhackrf.hackrf_si5351c_write.argtypes = [POINTER(hackrf_device), c_uint16, c_uint16]

	# extern ADDAPI int ADDCALL
	# hackrf_set_baseband_filter_bandwidth(hackrf_device* device, const
	# uint32_t bandwidth_hz);
	libhackrf.hackrf_set_baseband_filter_bandwidth.restype = c_int
	libhackrf.hackrf_set_baseband_filter_bandwidth.argtypes = [
	    POINTER(hackrf_device), c_uint32]

	# extern ADDAPI int ADDCALL hackrf_rffc5071_read(hackrf_device* device,
	# uint8_t register_number, uint16_t* value);
	libhackrf.hackrf_rffc5071_read.restype = c_int
	libhackrf.hackrf_rffc5071_read.argtypes = [
	    POINTER(hackrf_device), c_uint8, POINTER(c_uint16)]

	# extern ADDAPI int ADDCALL hackrf_rffc5071_write(hackrf_device*
	# device, uint8_t register_number, uint16_t value);
	libhackrf.hackrf_rffc5071_write.restype = c_int
	libhackrf.hackrf_rffc5071_write.argtypes = [POINTER(hackrf_device), c_uint8, c_uint16]

	# extern ADDAPI int ADDCALL hackrf_spiflash_erase(hackrf_device*
	# device);
	libhackrf.hackrf_spiflash_erase.restype = c_int
	libhackrf.hackrf_spiflash_erase.argtypes = [POINTER(hackrf_device)]

	# extern ADDAPI int ADDCALL hackrf_spiflash_write(hackrf_device*
	# device, const uint32_t address, const uint16_t length, unsigned char*
	# const data);
	libhackrf.hackrf_spiflash_write.restype = c_int
	libhackrf.hackrf_spiflash_write.argtypes = [
	    POINTER(hackrf_device), c_uint32, c_uint16, POINTER(c_ubyte)]

	# extern ADDAPI int ADDCALL hackrf_spiflash_read(hackrf_device* device,
	# const uint32_t address, const uint16_t length, unsigned char* data);
	libhackrf.hackrf_spiflash_read.restype = c_int
	libhackrf.hackrf_spiflash_read.argtypes = [
	    POINTER(hackrf_device), c_uint32, c_uint16, POINTER(c_ubyte)]

	# extern ADDAPI int ADDCALL hackrf_cpld_write(hackrf_device* device,
	#	 unsigned char* const data, const unsigned int total_length);
	libhackrf.hackrf_cpld_write.restype = c_int
	libhackrf.hackrf_cpld_write.argtypes = [POINTER(hackrf_device), POINTER(c_ubyte), c_uint]

	# extern ADDAPI int ADDCALL hackrf_board_id_read(hackrf_device* device,
	# uint8_t* value);
	libhackrf.hackrf_board_id_read.restype = c_int
	libhackrf.hackrf_board_id_read.argtypes = [POINTER(hackrf_device), POINTER(c_uint8)]

	# extern ADDAPI int ADDCALL hackrf_version_string_read(hackrf_device*
	# device, char* version, uint8_t length);
	libhackrf.hackrf_version_string_read.restype = c_int
	libhackrf.hackrf_version_string_read.argtypes = [POINTER(hackrf_device), POINTER(c_char), c_uint8]

	# extern ADDAPI int ADDCALL hackrf_set_freq(hackrf_device* device,
	# const uint64_t freq_hz);
	libhackrf.hackrf_set_freq.restype = c_int
	libhackrf.hackrf_set_freq.argtypes = [POINTER(hackrf_device), c_uint64]

	# extern ADDAPI int ADDCALL hackrf_set_freq_explicit(hackrf_device* device,
	#	 const uint64_t if_freq_hz, const uint64_t lo_freq_hz,
	#	 const enum rf_path_filter path);,
	# libhackrf.hackrf_set_freq_explicit.restype = c_int
	# libhackrf.hackrf_set_freq_explicit.argtypes = [c_uint64,
	# c_uint64, ]

	# extern ADDAPI int ADDCALL
	# hackrf_set_sample_rate_manual(hackrf_device* device, const uint32_t
	# freq_hz, const uint32_t divider);
	libhackrf.hackrf_set_sample_rate_manual.restype = c_int
	libhackrf.hackrf_set_sample_rate_manual.argtypes = [
	    POINTER(hackrf_device), c_uint32, c_uint32]

	# extern ADDAPI int ADDCALL hackrf_set_sample_rate(hackrf_device*
	# device, const double freq_hz);
	libhackrf.hackrf_set_sample_rate.restype = c_int
	libhackrf.hackrf_set_sample_rate.argtypes = [POINTER(hackrf_device), c_double]

	# extern ADDAPI int ADDCALL hackrf_set_amp_enable(hackrf_device*
	# device, const uint8_t value);
	libhackrf.hackrf_set_amp_enable.restype = c_int
	libhackrf.hackrf_set_amp_enable.argtypes = [POINTER(hackrf_device), c_uint8]

	# extern ADDAPI int ADDCALL
	# hackrf_board_partid_serialno_read(hackrf_device* device,
	# read_partid_serialno_t* read_partid_serialno);
	libhackrf.hackrf_board_partid_serialno_read.restype = c_int
	libhackrf.hackrf_board_partid_serialno_read.argtypes = [POINTER(hackrf_device)]

	# extern ADDAPI int ADDCALL hackrf_set_lna_gain(hackrf_device* device,
	# uint32_t value);
	libhackrf.hackrf_set_lna_gain.restype = c_int
	libhackrf.hackrf_set_lna_gain.argtypes = [POINTER(hackrf_device), c_uint32]

	# extern ADDAPI int ADDCALL hackrf_set_vga_gain(hackrf_device* device,
	# uint32_t value);
	libhackrf.hackrf_set_vga_gain.restype = c_int
	libhackrf.hackrf_set_vga_gain.argtypes = [POINTER(hackrf_device), c_uint32]

	# extern ADDAPI int ADDCALL hackrf_set_txvga_gain(hackrf_device*
	# device, uint32_t value);
	libhackrf.hackrf_set_txvga_gain.restype = c_int
	libhackrf.hackrf_set_txvga_gain.argtypes = [POINTER(hackrf_device), c_uint32]

	# extern ADDAPI int ADDCALL hackrf_set_antenna_enable(hackrf_device*
	# device, const uint8_t value);
	libhackrf.hackrf_set_antenna_enable.restype = c_int
	libhackrf.hackrf_set_antenna_enable.argtypes = [POINTER(hackrf_device), c_uint8]

	# extern ADDAPI const char* ADDCALL hackrf_error_name(enum hackrf_error errcode);
	# libhackrf.hackrf_error_name.restype = POINTER(c_char)
	# libhackrf.hackrf_error_name.argtypes = []

	# extern ADDAPI const char* ADDCALL hackrf_board_id_name(enum hackrf_board_id board_id);
	libhackrf.hackrf_board_id_name.restype = c_char_p
	libhackrf.hackrf_board_id_name.argtypes = [c_uint8]

	# extern ADDAPI const char* ADDCALL hackrf_filter_path_name(const enum rf_path_filter path);
	# libhackrf.hackrf_filter_path_name.restype = POINTER(c_char)
	# libhackrf.hackrf_filter_path_name.argtypes = []

	# extern ADDAPI uint32_t ADDCALL
	# hackrf_compute_baseband_filter_bw_round_down_lt(const uint32_t
	# bandwidth_hz);
	libhackrf.hackrf_compute_baseband_filter_bw_round_down_lt.restype = c_uint32
	libhackrf.hackrf_compute_baseband_filter_bw_round_down_lt.argtypes = [c_uint32]

	# extern ADDAPI int ADDCALL hackrf_usb_api_version_read(hackrf_device* device, uint16_t* version);
	libhackrf.hackrf_usb_api_version_read.restype = c_int
	libhackrf.hackrf_usb_api_version_read.argtypes = [POINTER(hackrf_device),POINTER(c_uint16)]


	# extern ADDAPI uint32_t ADDCALL
	# hackrf_compute_baseband_filter_bw(const uint32_t bandwidth_hz);
	libhackrf.hackrf_compute_baseband_filter_bw.restype = c_uint32
	libhackrf.hackrf_compute_baseband_filter_bw.argtypes = [c_uint32]
