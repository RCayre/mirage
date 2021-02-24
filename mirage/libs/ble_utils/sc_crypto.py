from binascii import unhexlify
from Cryptodome.Hash import CMAC
from Cryptodome.Cipher import AES
from os import urandom
from ecdsa import ECDH, NIST256p
from mirage.libs import io
import random


class CryptoUtils:
    @classmethod
    def generateRandom(cls, size=16):
        """
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

        """
        return urandom(size)

    @classmethod
    def getRandomAddress(self):
        parts = []
        for _ in range(6):
            part = hex(random.randint(0, 255))[2:]
            if len(part) == 1:
                part = "0" + part
            parts.append(part)
        return ":".join(map(str, (parts)))

    @classmethod
    def reverseOrder(cls, value):
        value = unhexlify(value)[::-1]
        return value


class BLECryptoSC:
    """
    This class provides some cryptographic functions used by the Security Manager for secure connections.

    .. note::

    """

    @classmethod
    def f4(cls, U, V, X, Z):
        """
        This class method implements the security function f4 to calculate confirm values in secure connections pairing.
        A calculates confirm value to send to B.

        :param U: PKax (256 bits)
        :type U: bytes
        :param V: PKbx (256 bits)
        :type V: bytes
        :param X: Na / ra / Nai for Numeric Comparison + Just Works / OOB / Passkey Entry (128 bits)
        :type X: bytes
        :param Z: 0 / 0 / rai for Numeric Comparison + Just Works / OOB / Passkey Entry (8 bits)
        :type Z: bytes
        :return: confirm value
        :rtype: bytes

        .. seealso::

            This function is described in Bluetooth Core Specification, [Vol 3] Part H, Section 2.2.6.

        """
        cmac = CMAC.new(X, ciphermod=AES)
        m = U + V + Z
        return cmac.update(m).digest()

    @classmethod
    def f5(cls, W, N1, N2, A1, A2):
        """
        This class method implements the key generation function f5 in secure connections pairing.
        A calculates to send to B.

        :param W: PKax (256 bits) - DH Key
        :type W: bytes
        :param N1: A Nonce (128 bits)
        :type N1: bytes
        :param N2: B Nonce (128 bits)
        :type N2: bytes
        :param A1: A Address (56 bits)
        :type A1: bytes
        :param A2: B Address (56 bits)
        :type A2: bytes
        :return: Tupel (MacKey, LTK)
        :rtype: bytes

        .. seealso::

            This function is described in Bluetooth Core Specification, [Vol 3] Part H, Section 2.2.7.

        """
        SALT = unhexlify(b"6C888391AAF5A53860370BDB5A6083BE")
        keyID = unhexlify(b"62746C65")
        counter0 = unhexlify(b"00")
        counter1 = unhexlify(b"01")
        length = unhexlify(b"0100")
        T = CMAC.new(SALT, ciphermod=AES)
        T.update(W)
        MacKey = CMAC.new(T.digest(), ciphermod=AES)
        MacKey.update(counter0 + keyID + N1 + N2 + A1 + A2 + length)
        LTK = CMAC.new(T.digest(), ciphermod=AES)
        LTK.update(counter1 + keyID + N1 + N2 + A1 + A2 + length)
        return (MacKey.digest(), LTK.digest())

    @classmethod
    def f6(cls, W, N1, N2, R, IOcap, A1, A2):
        """
        This class method implements the security function f6 to calculate DH key checks in secure connections pairing.
        A calculates to send to B.

        :param W: A MacKey (256 bits)
        :type W: bytes
        :param N1: A Nonce (128 bits)
        :type N1: bytes
        :param N2: B Nonce (128 bits)
        :type N2: bytes
        :param R: 0 / rb / rb (128 bits)
        :type R: bytes
        :param IOcap: A IO capabilities (24 bits)
        :type IOcap: bytes
        :param A1: A Address (56 bits)
        :type A1: bytes
        :param A2: B Address (56 bits)
        :type A2: bytes
        :return: DH key check
        :rtype: bytes

        .. seealso::

            This function is described in Bluetooth Core Specification, [Vol 3] Part H, Section 2.2.8.

        """
        cmac = CMAC.new(W, ciphermod=AES)
        m = N1 + N2 + R + IOcap + A1 + A2
        return cmac.update(m).digest()

    @classmethod
    def g2(cls, U, V, X, Y):
        """
        This class method implements the security function g2 to generate the numeric comparison value in secure connections pairing.
        A calculates to send to B.

        :param U: KeyX A (256 bit)
        :type U: bytes
        :param V: KeyX B (256 bit)
        :type V: bytes
        :param X: Na
        :type X: bytes
        :param Y: Nb
        :type Y: bytes
        :return: numeric comparison value
        :rtype: bytes

        .. seealso::

            This function is described in Bluetooth Core Specification, [Vol 3] Part H, Section 2.2.9.

        """
        cmac = CMAC.new(X, ciphermod=AES)
        digest = cmac.update(U + V + Y).digest()
        return digest[12::]


class SCCryptoInstance:
    def __init__(self):
        # ECDH instance
        self.ecdh = None
        # Crypto key material
        self.DHKey = None
        self.LTK = None
        self.MacKey = None
        self.keyX = None
        self.keyY = None
        self.remoteKeyX = None
        self.remoteKeyY = None
        self.localNonce = None
        self.remoteNonce = None
        self.localIRK = None
        self.localCSRK = None
        self.remoteIRK = None
        self.remoteCSRK = None

    def generateDHKeyPair(self):
        """
        This class method generates a BLE conform DH key pair and returns the X and Y coordiante for the public key in network byte order.
        A calculates to send to B.

        :return: X and Y coordiante for the public key in network byte order
        :rtype: Tupel (nwOrderPubKeyX, nwOrderPubKeyY)

        """
        if self.ecdh != None:
            io.warning("ECDH instance already generated!")
            return (self.keyX[::-1], self.keyY[::-1])
        else:
            self.ecdh = ECDH(curve=NIST256p)
            localPubKey = self.ecdh.generate_private_key()
            localPubKeyX = hex(localPubKey.pubkey.point.to_affine().x())[2:]
            localPubKeyY = hex(localPubKey.pubkey.point.to_affine().y())[2:]
            if len(localPubKeyX) % 2 != 0:
                localPubKeyX = "0" + localPubKeyX
            self.keyX = unhexlify(localPubKeyX)
            if len(localPubKeyY) % 2 != 0:
                localPubKeyY = "0" + localPubKeyY
            self.keyY = unhexlify(localPubKeyY)
            nwOrderPubKeyX = CryptoUtils.reverseOrder(localPubKeyX)
            nwOrderPubKeyY = CryptoUtils.reverseOrder(localPubKeyY)
            return (nwOrderPubKeyX, nwOrderPubKeyY)

    def generateDHSharedSecret(self, nwOrderRemoteX, nwOrderRemoteY):
        """
        This class method generates a BLE conform DH shared secret.
        A calculates to send to B.

        :param U: nwOrderRemoteX (256 bits)
        :type U: bytes
        :param V: nwOrderPubKeyY (256 bits)
        :type V: bytes

        """
        if self.DHKey != None:
            io.warning("DHKey already calculated!")
        else:
            self.remoteKeyX = CryptoUtils.reverseOrder(nwOrderRemoteX.hex())
            self.remoteKeyY = CryptoUtils.reverseOrder(nwOrderRemoteY.hex())
            self.ecdh.load_received_public_key_bytes(self.remoteKeyX + self.remoteKeyY)
            self.DHKey = self.ecdh.generate_sharedsecret_bytes()
            self.nwOrderDHKey = CryptoUtils.reverseOrder(self.DHKey.hex())
            io.info("DH Key generated: {}".format(self.nwOrderDHKey.hex()))

    def generateLocalNonce(self):
        """
        This class method generates a BLE conform local Nonce and returns it in network order.

        :return: nwOrderPubKeyY (128 bits)
        :rtype: bytes

        """
        self.localNonce = CryptoUtils.generateRandom()
        return CryptoUtils.reverseOrder(self.localNonce.hex())

    def isSharedSecretReady(self):
        """
        This class method can be used to verify that the DHKey has been successfully generated.

        :return DHKeyReady: Boolean indicating if the DHKey has been successfully generated
        :rtype: Boolean

        """
        return True if self.DHKey != None else False

    def isLTKReady(self):
        """
        This class method can be used to verify that the LTK (and also MacKey) has been successfully generated.

        :return: Boolean indicating if the LTK (and also MacKey) has been successfully generated
        :rtype: Boolean

        """
        return True if self.LTK != None else False

    def generateConfirmValue(
        self, keyX=None, remoteKeyX=None, localNonce=None, rbi=b"\x00"
    ):
        """
        This class method can be used to generate a confirm value.

        :param rbi: Passkey Byte
        :type rbi: Byte
        :return: Confirm value
        :rtype: Bytes

        """
        if not (keyX and remoteKeyX and localNonce):
            if self.keyX == None or self.remoteKeyX == None:
                io.warning("Please first generate the DH keys")
                return
            if self.localNonce == None:
                io.warning("Please first generate the local Nonce")
                return
            keyX = self.keyX
            remoteKeyX = self.remoteKeyX
            localNonce = self.localNonce
        localConfirm = BLECryptoSC.f4(keyX, remoteKeyX, localNonce, rbi)
        return CryptoUtils.reverseOrder(localConfirm.hex())

    def verifyConfirmValue(
        self, nwOrderRemoteNonce, nwOrderConfirm, keyX=None, rbi=b"\x00"
    ):
        """
        This class method can be used to verify that the received confirm value is correct.

        :param rbi: Passkey Byte
        :type rbi: Byte
        :return: Boolean indicating if the received confirm value is correct
        :rtype: Boolean

        """
        if not keyX:
            if self.keyX == None:
                io.warning("Please first generate the DH keys")
                return
            keyX = self.keyX
        remoteConfirm = CryptoUtils.reverseOrder(nwOrderConfirm.hex())
        remoteNonce = CryptoUtils.reverseOrder(nwOrderRemoteNonce.hex())
        localConfirm = BLECryptoSC.f4(self.remoteKeyX, keyX, remoteNonce, rbi)
        return True if localConfirm == remoteConfirm else False

    def generateCompareValueInitiator(self, nwOrderRemoteNonce):
        """
        This class method derives compare value for the final step of the Secure Conncetions Numeric Cmparison Pairing.

        :param nwOrderRemoteNonce: Remote Nonce in networkorder (128 bits)
        :type nwOrderRemoteNonce: bytes
        :return: int 6-digit compare value
        :rtype: int

        """
        if not (self.keyX and self.remoteKeyX):
            io.warning("Please first generate and exchange the DH keys")
            return
        if not self.localNonce:
            io.warning("Missing local nonce for compare value generation")
            return

        remoteNonce = CryptoUtils.reverseOrder(nwOrderRemoteNonce.hex())

        return int.from_bytes(
            BLECryptoSC.g2(self.keyX, self.remoteKeyX, self.localNonce, remoteNonce),
            "big",
        ) % (10**6)

    def generateCompareValueResponder(self, nwOrderRemoteNonce):
        """
        This class method derives compare value for the final step of the Secure Conncetions Numeric Cmparison Pairing.

        :param nwOrderRemoteNonce: Remote Nonce in networkorder (128 bits)
        :type nwOrderRemoteNonce: bytes
        :return: int 6-digit compare value
        :rtype: int

        """
        if not (self.keyX and self.remoteKeyX):
            io.warning("Please first generate and exchange the DH keys")
            return
        if not self.localNonce:
            io.warning("Missing local nonce for compare value generation")
            return

        remoteNonce = CryptoUtils.reverseOrder(nwOrderRemoteNonce.hex())

        return int.from_bytes(
            BLECryptoSC.g2(self.remoteKeyX, self.keyX, remoteNonce, self.localNonce),
            "big",
        ) % (10**6)

    def deriveLTKInitiator(
        self,
        localAddress,
        remoteAddress,
        localAddressType,
        remoteAddressType,
        nwOrderRemoteNonce,
    ):
        """
        This class method derives the MacKey and LTK.

        :param localAddress: local device address (56 bits)
        :type localAddress: bytes
        :param remoteAddress: remote device address (56 bits)
        :type remoteAddress: bytes
        :param localAddressType: local device address type, 1 if random 0 if public
        :type localAddressType: int
        :param remoteAddressType: remote device address type, 1 if random 0 if public
        :type remoteAddressType: int

        """
        if self.MacKey != None and self.LTK != None:
            io.warning("MacKEy and LTK are already generated")
            return
        # The least significant bit in the most significant octet in both A and B is set to 1 if
        # the address is a random address and set to 0 if the address is a public address.
        # The 7 most significant bits of the most significant octet in both A and B are set to 0
        # As described in Bluetooth Core Specification, [Vol 3] Part H, Page 1633.
        localAddress = localAddress.replace(":", "")
        localAddress = ("01" if localAddressType else "00") + localAddress
        localAddress = unhexlify(localAddress)
        remoteAddress = remoteAddress.replace(":", "")
        remoteAddress = ("01" if remoteAddressType else "00") + remoteAddress
        remoteAddress = unhexlify(remoteAddress)
        remoteNonce = CryptoUtils.reverseOrder(nwOrderRemoteNonce.hex())

        if not self.localNonce:
            io.warning("Missing local nonce for LTK generation")
            return
        (self.MacKey, self.LTK) = BLECryptoSC.f5(
            self.DHKey, self.localNonce, remoteNonce, localAddress, remoteAddress
        )
        io.info("MacKey: {}".format(self.MacKey))
        io.info("LTK: {}".format(self.LTK))

    def deriveLTKResponder(
        self,
        localAddress,
        remoteAddress,
        localAddressType,
        remoteAddressType,
        nwOrderRemoteNonce,
    ):
        """
        This class method derives the MacKey and LTK.

        :param localAddress: local device address (56 bits)
        :type localAddress: bytes
        :param remoteAddress: remote device address (56 bits)
        :type remoteAddress: bytes
        :param localAddressType: local device address type, 1 if random 0 if public
        :type localAddressType: int
        :param remoteAddressType: remote device address type, 1 if random 0 if public
        :type remoteAddressType: int

        """
        if self.MacKey != None and self.LTK != None:
            io.warning("MacKEy and LTK are already generated")
            return
        # The least significant bit in the most significant octet in both A and B is set to 1 if
        # the address is a random address and set to 0 if the address is a public address.
        # The 7 most significant bits of the most significant octet in both A and B are set to 0
        # As described in Bluetooth Core Specification, [Vol 3] Part H, Page 1633.
        localAddress = localAddress.replace(":", "")
        localAddress = ("01" if localAddressType else "00") + localAddress
        localAddress = unhexlify(localAddress)
        remoteAddress = remoteAddress.replace(":", "")
        remoteAddress = ("01" if remoteAddressType else "00") + remoteAddress
        remoteAddress = unhexlify(remoteAddress)
        remoteNonce = CryptoUtils.reverseOrder(nwOrderRemoteNonce.hex())

        (self.MacKey, self.LTK) = BLECryptoSC.f5(
            self.DHKey, remoteNonce, self.localNonce, remoteAddress, localAddress
        )
        io.info("MacKey: {}".format(self.MacKey))
        io.info("LTK: {}".format(self.LTK))

    def generateDHKeyCheck(
        self,
        localIOCap,
        localAddress,
        remoteAddress,
        localAddressType,
        remoteAddressType,
        nwOrderRemoteNonce,
        r=b"",
    ):
        """
        This class method can be used to calculate the DH Key check for second authentication stage of secure connections pairing.

        :param localIOCap: local IO capabilities (24 bits)
        :type localIOCap: bytes
        :param localAddress: local device address (56 bits)
        :type localAddress: bytes
        :param remoteAddress: remote device address (56 bits)
        :type remoteAddress: bytes
        :param localAddressType: local device address type, 1 if random 0 if public
        :type localAddressType: int
        :param remoteAddressType: remote device address type, 1 if random 0 if public
        :type remoteAddressType: int
        :param r: passkey (128 bits)
        :type r: bytes
        :return: DH Key Check in network order
        :rtype: bytes

        """
        # The least significant bit in the most significant octet in both A and B is set to 1 if
        # the address is a random address and set to 0 if the address is a public address.
        # The 7 most significant bits of the most significant octet in both A and B are set to 0
        # As described in Bluetooth Core Specification, [Vol 3] Part H, Page 1633.

        localAddress = localAddress.replace(":", "")
        localAddress = ("01" if localAddressType else "00") + localAddress
        localAddress = unhexlify(localAddress)
        remoteAddress = remoteAddress.replace(":", "")
        remoteAddress = ("01" if remoteAddressType else "00") + remoteAddress
        remoteAddress = unhexlify(remoteAddress)
        remoteNonce = CryptoUtils.reverseOrder(nwOrderRemoteNonce.hex())
        r = CryptoUtils.reverseOrder((r + b"\x00" * (16 - len(r))).hex())

        DHKeyCheck = BLECryptoSC.f6(
            self.MacKey,
            self.localNonce,
            remoteNonce,
            r,
            localIOCap,
            localAddress,
            remoteAddress,
        )
        nwOrderDHKeyCheck = CryptoUtils.reverseOrder(DHKeyCheck.hex())
        return nwOrderDHKeyCheck

    def verifyDHKeyCheck(
        self,
        remoteIOCap,
        localAddress,
        remoteAddress,
        localAddressType,
        remoteAddressType,
        nwOrderDHKeyCheck,
        nwOrderRemoteNonce,
        r=b"",
    ):
        """
        This class method can be used to calculate the DH Key check for second authentication stage of secure connections pairing.

        :param remoteIOCap: remote IO capabilities(24 bits)
        :type IOCremoteIOCapap: bytes
        :param localAddress: local device address (56 bits)
        :type localAddress: bytes
        :param remoteAddress: remote device address (56 bits)
        :type remoteAddress: bytes
        :param DHKeyCheck: DH key check to validate in network order (128 bits)
        :type DHKeyCheck: bytes
        :param r: passkey (128 bits)
        :type r: bytes
        :return: Boolean indicating if the received DH Key Check is correct
        :rtype: Boolean

        """
        localAddress = localAddress.replace(":", "")
        localAddress = ("01" if localAddressType else "00") + localAddress
        localAddress = unhexlify(localAddress)
        remoteAddress = remoteAddress.replace(":", "")
        remoteAddress = ("01" if remoteAddressType else "00") + remoteAddress
        remoteAddress = unhexlify(remoteAddress)
        DHKeyCheck = CryptoUtils.reverseOrder(nwOrderDHKeyCheck.hex())
        remoteNonce = CryptoUtils.reverseOrder(nwOrderRemoteNonce.hex())
        r = CryptoUtils.reverseOrder((r + b"\x00" * (16 - len(r))).hex())
        localDHKeyCheck = BLECryptoSC.f6(
            self.MacKey,
            remoteNonce,
            self.localNonce,
            r,
            remoteIOCap,
            remoteAddress,
            localAddress,
        )
        return True if localDHKeyCheck == DHKeyCheck else False
