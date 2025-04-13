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
    if data[0] == 0:return "1" + b58(data[1:])
    x = sum([v * (256 ** i) for i, v in enumerate(data[::-1])])
    ret = ""
    while x > 0:
        ret = B58[x % 58] + ret
        x = x // 58
    return ret

class Point:
    def __init__(self,
        x=55066263022277343669578718895168534326250603453777594175500187360389116729240,
        y=32670510020758816978083085130507043184471273380659243275938904335757337482424,
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
    pubkey_point = SPEC256k1 * pk
    if compressed:
        prefix = b'\x02' if pubkey_point.y % 2 == 0 else b'\x03'
        pubkey = prefix + pubkey_point.x.to_bytes(32, 'big')
    else:
        pubkey = (SPEC256k1 * pk).toBytes()
    hash160 = ripemd160(sha256(pubkey))
    address = b"\x00" + hash160

    return b58(address + sha256(sha256(address))[:4])


def getWif(privkey,compressed=True):
    wif = b"\x80" + privkey
    if compressed: wif += b'\x01'
    return b58(wif + sha256(sha256(wif))[:4])

def wifToInt(wif_key):
    import base58
    decoded = base58.b58decode_check(wif_key)
    # Mainnet prefix is 0x80; compressed WIF ends with 0x01
    if len(decoded) == 34 and decoded[-1] == 0x01:
        print("Compressed WIF key")
        private_key = decoded[1:-1]
    elif len(decoded) == 33:
        print("Uncompressed WIF key")
        private_key = decoded[1:]  # Remove prefix only
    return private_key.hex()