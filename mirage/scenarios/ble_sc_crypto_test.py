from mirage.core import scenario
from mirage.libs import io
from mirage.libs.ble_utils.sc_crypto import BLECryptoSC
from binascii import unhexlify

# Scenario can be used to verify implementation of the secure connections cryptographic
# Example data is the one provided in the Bluetooth specification
class ble_sc_crypto_test(scenario.Scenario):
    def onStart(self):
        self.checkCrypto()
        return True

    def onEnd(self):
        return True

    def onKey(self, key):
        if key == "esc":
            self.module.setStage(2)  # STOP
        return True

    def checkCrypto(self):
        sc_crypto = BLECryptoSC()
        # check f4 function
        U = unhexlify(
            b"20b003d2f297be2c5e2c83a7e9f9a5b9eff49111acf4fddbcc0301480e359de6"
        )
        V = unhexlify(
            b"55188b3d32f6bb9a900afcfbeed4e72a59cb9ac2f19d7cfb6b4fdd49f47fc5fd"
        )
        X = unhexlify(b"d5cb8454d177733effffb2ec712baeab")
        Z = unhexlify(b"00")
        confirmVal = sc_crypto.f4(U, V, X, Z)
        expValue = unhexlify(b"f2c916f107a9bd1cf1eda1bea974872d")
        io.info(
            "Confirm value {} correct".format(
                "is" if confirmVal == expValue else "is NOT"
            )
        )

        # check f5 function
        DHKey = unhexlify(
            b"ec0234a357c8ad05341010a60a397d9b99796b13b4f866f1868d34f373bfa698"
        )
        N1 = unhexlify(b"d5cb8454d177733effffb2ec712baeab")
        N2 = unhexlify(b"a6e8e7cc25a75f6e216583f7ff3dc4cf")
        A1 = unhexlify(b"0056123737bfce")
        A2 = unhexlify(b"00a713702dcfc1")

        (MacKey, LTK) = sc_crypto.f5(DHKey, N1, N2, A1, A2)
        expLTK = unhexlify(b"6986791169d7cd23980522b594750a38")
        expMacKey = unhexlify(b"2965f176a1084a02fd3f6a20ce636e20")

        io.info("LTK {} correct".format("is" if LTK == expLTK else "is NOT"))
        io.info("MacKey {} correct".format("is" if MacKey == expMacKey else "is NOT"))

        # check f6 function
        R = unhexlify(b"12a3343bb453bb5408da42d20c2d0fc8")
        IOcap = unhexlify(b"010102")

        DHKeyCheck = sc_crypto.f6(MacKey, N1, N2, R, IOcap, A1, A2)
        expDHKeyCheck = unhexlify(b"e3c473989cd0e8c5d26c0b09da958f61")
        io.info(
            "DH Key Check {} correct".format(
                "is" if DHKeyCheck == expDHKeyCheck else "is NOT"
            )
        )

        # check g2 function
        Y = unhexlify(b"a6e8e7cc25a75f6e216583f7ff3dc4cf")
        numComp = sc_crypto.g2(U, V, X, Y)
        expNumComp = unhexlify(b"2f9ed5ba")
        io.info(
            "Numeric Comparison value {} correct".format(
                "is" if numComp == expNumComp else "is NOT"
            )
        )
        self.module.setStage(2)
