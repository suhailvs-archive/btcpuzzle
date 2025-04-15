from utils import getPublicKey,getWif #,wifToInt

def getAddress(pk):
    # getAddress(219898266213316039825) -> 1G1PszAzdLZWgGNG79pijNrt6BuK5HsVo8
    from utils import Point, ripemd160, sha256, b58
    getPublicKey_from_int = lambda pk: Point()*pk
    pubkey_point = getPublicKey_from_int(pk) # Point(x,y) -> if you know x,y(publickey)
    hash160 = ripemd160(sha256(pubkey_point.toBytes()))
    address = b"\x00" + hash160
    return b58(address + sha256(sha256(address))[:4])

def display(private_key_hex):
    """
    PrivateKey: 00000000000000000000000000000000000000000000000bebb3940cd0fc1491
    compressed:
    Address: 1MVDYgVaSN6iKKEsbzRUAYFrYJadLYZvvZ
    PrivateKey Wif: KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qd7sDG4F2sdMtzNe8y2U
    uncompressed:
    Address: 1G1PszAzdLZWgGNG79pijNrt6BuK5HsVo8
    PrivateKey Wif: 5HpHagT65TZzG1PH3CSu63k8DbpvD8s5iq4NLznbSoMvfzUuhdh
    """
    p = bytes.fromhex(private_key_hex)
    print('PrivateKey: '+ private_key_hex)    
    print('compressed:')
    print("Address: " + getPublicKey(p))
    print("PrivateKey Wif: " + getWif(p))
    # print('PrivateKey Int:',wifToInt(getWif(p)))
    print('uncompressed:')
    print("Address: " + getPublicKey(p, False))
    print("PrivateKey Wif: " + getWif(p, False))   
    print()

def bruteforce(address,range_last_integer):
    for i in range(1,range_last_integer):
        private_key = hex(i).split('x')[-1]
        private_key_hex = private_key.rjust(64, '0')
        p=bytes.fromhex(private_key_hex)
        r_address = getPublicKey(p)
        if r_address==address:
            print(f'Found:{r_address}, {i},{getWif(p)}')
            break
def a():    
    # https://privatekeys.pw/puzzles/bitcoin-puzzle-tx
    solutions={1:'1',2:'3',3:'7',4:'8',5:'15',68:'bebb3940cd0fc1491'}    
    for n,private_key in solutions.items():
        print(n, int(private_key, 16)) # hex(dec).split('x')[-1]
        print('-'*30)
        display(private_key.rjust(64, '0'))

def b():
    btc_address={
        10:'1LeBZP5QCwwgXRtmVUvTVrraqPUokyLHqe', # 3ff, txn_date: jan,15 2015, solved_date: jan,15 2015
        67:'1BY8GQbnueYofwSuFAT3USAhGjPrkxDdW9', # txn_date: jan,15 2015, solved_date: feb 21 2025
        68:'1MVDYgVaSN6iKKEsbzRUAYFrYJadLYZvvZ', # txn_date: jan,15 2015, solved_date: apr 7 2025
        69:'19vkiEajfhuZ8bs8Zu2jgmC6oqZbWqhxhG'
    }
    print(int('3ff',16))
    bruteforce(btc_address[10],1024)

    # BTC67 challenge 1BY8GQbnueYofwSuFAT3USAhGjPrkxDdW9
    """
    feb 21,2025 https://x.com/Kowala24731/status/1892831634921082991
    We just won BTC67 challenge and earned 6.7 BTC!

    We had to check roughly 42 058 576 Trillion private keys before finding it (57% of the possibilities)
    It took us (ironically) 67 days :)

    Cheers to @ProofOfDuck
     for the statistical modeling!
    Cheers to everyone who saw an opportunity and helped me fund this thing.
    """

    # BTC68 challenge 1MVDYgVaSN6iKKEsbzRUAYFrYJadLYZvvZ
    speed   = 37_383_000_000_000 # per second, my speed on rust: 2_097_152/minite
    ans     = 219_898_266_213_316_039_825 # int('bebb3940cd0fc1491', 16)
    print ((ans/speed)//(3600*24),'days')

# def p1():
#     # https://crypto.haluska.sk/
#     # puzzle 1
#     wif_key="5JMTiDVHj3pj8VfaTe6pDtD9byZr6too3PD3AGBJrXF1hVsitc8"
#     pkey = wifToInt(wif_key)
#     display(pkey)

def p3():
    # https://crypto.haluska.sk/
    # puzzle 3
    pkey ="6008c37d0aa226dbbe611be64106964bca6cbba7098fe4602a932c590e14b074"
    display(pkey)

if __name__ == "__main__":
    print(getAddress(219898266213316039825))