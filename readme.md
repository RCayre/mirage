MIRAGE - 1.1
=============

This framework is released as an opensource project using the MIT License.

Mirage is a powerful and modular framework dedicated to the security analysis of wireless communications. It currently provides :

  * multiple **lightweight and hackable wireless protocol stacks** (e.g. Bluetooth Low Energy, Enhanced ShockBurst, WiFi, Zigbee ...)
  * multiple **highly customizable offensive modules** (e.g. Man-in-the-Middle, sniffing, jamming, hijacking, cloning ...)
  * mutiple **modules dedicated to information gathering** (e.g. applicative layers dumping, scanning ...)
  * a **chaining operator** allowing to easily combine attack modules in order to **build complex attack workflows**
  * support of **multiple devices**, such as HCI devices, Crazy Radio PA, RZUSBStick, BTLEJack, Nordic and Ubertooth sniffers
  * an **user-friendly development environment** allowing to easily **write new modules** or **customize existing ones**

Useful links
------------

 * Documentation: http://homepages.laas.fr/rcayre/mirage-documentation/index.html
 * Documentation (sphinx source code): https://redmine.laas.fr/projects/mirage-documentation
 * Mirage can manipulate IR signals using an opensource hardware called IRma, the schematics and firmware source code can be found here: https://redmine.laas.fr/projects/mirage-irma-device
 * Mirage can use a custom BTLEJack firmware for the BBC Micro:Bit, adding some specific features for manipulating advertisements: https://redmine.laas.fr/projects/btlejack-custom-firmware

The original BTLEJack firmware, written by Damien Cauquil, is available on github : 

 * BTLEJack: https://github.com/virtualabs/btlejack
 * BTLEJack firmware: https://github.com/virtualabs/btlejack-firmware
