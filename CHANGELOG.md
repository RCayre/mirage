version 1.2

* Added InjectaBLE attack support, a new Bluetooth Low Energy attack allowing to inject packets into an established connection
	* New ButteRFly device, allowing to interact with injectaBLE firmware (nRF52840 dongle), compatible with multiple existing modules
	* BLE injection attack
	* Experimental attacks based on InjectaBLE: slave hijacking, master hijacking, Man-in-the-Middle
* Added experimental Software Defined Radio support for Bluetooth Low Energy and Zigbee
	* HackRF experimental device, compatible with advertising-related BLE modules and Zigbee modules
	* Software Defined Radio architecture, with multiple modulators/demodulators (GFSK / O-QPSK), encoders/decoders (BLE, Zigbee)
* Added Sniffle device support (version 1.5)
	* Bluetooth Low Energy sniffing
	* Bluetooth Low Energy Master
 	* Bluetooth Low Energy Advertiser
* Added esb\_mitm module, allowing to perform a Man-in-the-Middle attack targeting Logitech Unifying protocol
* Added three examples of scenarios: lightbulb\_injection (ble\_sniff scenario), lightbulb\_mitm (ble\_mitm scenario), logitech\_invert\_mouse\_mitm (esb\_mitm scenario)
* Added shortcuts feature, allowing to facilitate the use of complex modules
* Various bugfixes

version 1.1

* Added multiple protocol stacks: ESB, Mosart, Zigbee, Wifi, Infrared Radiations
* Added support for the following harware components: RFStorm, RZUSBStick, IRma, WiFi device
* Added multiple modules targeting the new protocols
* Added three examples of scenarios: keyboard\_hid\_over\_gatt, logitech\_unencrypted\_keystrokes\_injection, logitech\_encrypted\_keystrokes\_injection
