'''
This module contains some constants that are used by the WiFi stack.
'''

# Wifi modes
WIFI_MODES = [	'Auto',
		'Ad-Hoc',
		'Managed',
		'Master',
		'Repeat',
		'Second',
		'Monitor',
		'Unknown/bug']


# Wifi mode constants
SIOCGIWMODE = 0x8B07 # get mode
SIOCSIWMODE = 0x8B06 # set mode

# Wifi frequency constants
SIOCGIWFREQ = 0x8B05 # get frequency
SIOCSIWFREQ = 0x8B04 # set frequency

IWFREQAUTO = 0x00 # Frequency mode: auto
IWFREQFIXED = 0x01 # Frequency mode: fixed

# Wifi flags constants
SIOCGIFFLAGS =  0x8913 # Get flags
SIOCSIFFLAGS = 0x8914  # Set flags

# Wifi interface constants
IFUP = 0x1 # interface: up
IFNAMESIZE = 16 # interface name size
