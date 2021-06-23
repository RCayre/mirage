MIRAGE - 1.2
=============

This framework is released as an opensource project using the MIT License.

Mirage is a powerful and modular framework dedicated to the security analysis of wireless communications. It currently provides :

  * multiple **lightweight and hackable wireless protocol stacks** (e.g. Bluetooth Low Energy, Enhanced ShockBurst, WiFi, Zigbee ...)
  * multiple **highly customizable offensive modules** (e.g. Man-in-the-Middle, sniffing, jamming, hijacking, cloning ...)
  * mutiple **modules dedicated to information gathering** (e.g. applicative layers dumping, scanning ...)
  * mutiple **experimental offensive modules based on InjectaBLE attack** (e.g. Bluetooth Low Energy injection, Slave and Master hijacking, MiTM ...)
  * a **chaining operator** allowing to easily combine attack modules in order to **build complex attack workflows**
  * support of **multiple devices**, such as HCI devices, Crazy Radio PA, RZUSBStick, BTLEJack, Nordic, Sniffle, ButteRFly and Ubertooth sniffers
  * an **user-friendly development environment** allowing to easily **write new modules** or **customize existing ones**
  * an experimental **Software defined radio** architecture, allowing to sniff and inject packets using HackRF One

Useful links
------------

 * Documentation: http://homepages.laas.fr/rcayre/mirage-documentation/index.html
 * Documentation (sphinx source code): https://redmine.laas.fr/projects/mirage-documentation
 * Mirage can manipulate IR signals using an opensource hardware called IRma, the schematics and firmware source code can be found here: https://redmine.laas.fr/projects/mirage-irma-device
 * Mirage can perform experimental Bluetooth Low Energy attacks using ButteRFly device (nRF52840 dongle): https://github.com/RCayre/injectable-firmware. This new device allows to inject packets into an established connection, hijack the slave role, hijack the master role or perform a Man-in-the-Middle attack.
 * Mirage can use a custom BTLEJack firmware for the BBC Micro:Bit, adding some specific features for manipulating advertisements: https://redmine.laas.fr/projects/btlejack-custom-firmware

The original BTLEJack firmware, written by Damien Cauquil, is available on github :

 * BTLEJack: https://github.com/virtualabs/btlejack
 * BTLEJack firmware: https://github.com/virtualabs/btlejack-firmware

Publications
------------

This framework is developed in the context of research works focused on IoT security by Romain Cayre, who is a PhD student at LAAS-CNRS and Apsys.Lab. His PhD thesis is supervised by Guillaume Auriol, Vincent Nicomette and Mohamed Kaâniche.

We published two papers describing this tool:

 * Romain Cayre, Jonathan Roux, Eric Alata, Vincent Nicomette, Guillaume Auriol. [Mirage : un framework offensif pour l'audit du Bluetooth Low Energy](https://hal.laas.fr/hal-02268774). *Symposium sur la Sécurité des Technologies de l'Information et des Communications (SSTIC 2019)*, Jun 2019, Rennes, France. pp.229-258. **\[fr\]**
 * Romain Cayre, Vincent Nicomette, Guillaume Auriol, Eric Alata, Mohamed Kaâniche, et al.. [Mirage: towards a Metasploit-like framework for IoT](https://hal.laas.fr/hal-02346074). *2019 IEEE 30th International Symposium on Software Reliability Engineering (ISSRE)*, Oct 2019, Berlin, Germany. **\[en\]**

We also published two papers describing a new Bluetooth Low Energy attack, named InjectaBLE, allowing to inject malicious traffic into an established BLE connection. Mirage (v1.2) adds support for a new device, named ButteRFly, allowing to perform this attack:

* Romain Cayre, Florent Galtier, Guillaume Auriol, Vincent Nicomette, Mohamed Kaâniche, et al.. [InjectaBLE : injection de trafic malveillant dans une connexion Bluetooth Low Energy](https://hal.laas.fr/hal-03221143). *Symposium sur la sécurité des technologies de l'information et des communications (SSTIC 2021)*, Jun 2021, Rennes (en ligne), France. **\[fr\]**
* Romain Cayre, Florent Galtier, Guillaume Auriol, Vincent Nicomette, Mohamed Kaâniche, et al.. [InjectaBLE: Injecting malicious traffic into established Bluetooth Low Energy connections](https://hal.laas.fr/hal-03193297). *IEEE/IFIP International Conference on Dependable Systems and Networks (DSN)*, Jun 2021, Taipei (virtual), Taiwan. **\[en\]**
