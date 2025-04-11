import os
import hashlib


def sha256(data):
    digest = hashlib.new("sha256")
    digest.update(data)
    return digest.digest()


def ripemd160(x):
    d = hashlib.new("ripemd160")
    d.update(x)
    return d.digest()


def b58(data):
    B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

    if data[0] == 0:
        return "1" + b58(data[1:])

    x = sum([v * (256 ** i) for i, v in enumerate(data[::-1])])
    ret = ""
    while x > 0:
        ret = B58[x % 58] + ret
        x = x // 58

    return ret


class Point:
    def __init__(self,
        x=0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
        y=0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8,
        p=2**256 - 2**32 - 2**9 - 2**8 - 2**7 - 2**6 - 2**4 - 1):
        self.x = x
        self.y = y
        self.p = p

    def __add__(self, other):
        return self.__radd__(other)

    def __mul__(self, other):
        return self.__rmul__(other)

    def __rmul__(self, other):
        n = self
        q = None

        for i in range(256):
            if other & (1 << i):
                q = q + n
            n = n + n

        return q

    def __radd__(self, other):
        if other is None:
            return self
        x1 = other.x
        y1 = other.y
        x2 = self.x
        y2 = self.y
        p = self.p

        if self == other:
            l = pow(2 * y2 % p, p-2, p) * (3 * x2 * x2) % p
        else:
            l = pow(x1 - x2, p-2, p) * (y1 - y2) % p

        newX = (l ** 2 - x2 - x1) % p
        newY = (l * x2 - l * newX - y2) % p

        return Point(newX, newY)

    def toBytes(self):
        x = self.x.to_bytes(32, "big")
        y = self.y.to_bytes(32, "big")
        return b"\x04" + x + y


def getPublicKey(privkey, compressed=True):
    SPEC256k1 = Point()
    pk = int.from_bytes(privkey, "big")
    hash160 = ripemd160(sha256((SPEC256k1 * pk).toBytes()))
    address = b"\x00" + hash160

    address = b58(address + sha256(sha256(address))[:4])
    return address


def getCompressedPublicKey(privkey):
    SPEC256k1 = Point()
    pk = int.from_bytes(privkey, "big")
    pubkey_point = SPEC256k1 * pk

    # Compress public key
    prefix = b'\x02' if pubkey_point.y % 2 == 0 else b'\x03'
    compressed_pubkey = prefix + pubkey_point.x.to_bytes(32, 'big')

    # Hash it (SHA256 → RIPEMD160)
    hash160 = ripemd160(sha256(compressed_pubkey))

    # Mainnet prefix
    address_bytes = b'\x00' + hash160

    # Add checksum
    checksum = sha256(sha256(address_bytes))[:4]
    final = address_bytes + checksum

    # Base58 encode
    return b58(final)


def getWif(privkey,compressed=True):
    wif = b"\x80" + privkey
    if compressed: wif += b'\x01'
    return b58(wif + sha256(sha256(wif))[:4])


# def wifToPrivateKey(s):
#     import utils
#     return utils.wif_to_private_key(s)

def display(private_key_hex):
    p = bytes.fromhex(private_key_hex)
    print('PrivateKey: '+ private_key_hex)
    print('-'*30)
    print('compressed:')
    print("Address: " + getCompressedPublicKey(p))
    print("PrivateKey Wif: " + getWif(p))

    print('uncompressed:')
    print("Address: " + getPublicKey(p))
    print("PrivateKey Wif: " + getWif(p, False))
    
    
    print()
    

if __name__ == "__main__":
    # https://privatekeys.pw/puzzles/bitcoin-puzzle-tx
    for pkey in ['1','3','7','8','15','bebb3940cd0fc1491']:
        display(pkey.rjust(64, '0'))