from utils import getPublicKey,getWif

def display(private_key_hex):
    p = bytes.fromhex(private_key_hex)
    print('PrivateKey: '+ private_key_hex)    
    print('compressed:')
    print("Address: " + getPublicKey(p))
    print("PrivateKey Wif: " + getWif(p))
    print('uncompressed:')
    print("Address: " + getPublicKey(p, False))
    print("PrivateKey Wif: " + getWif(p, False))   
    print()
    
if __name__ == "__main__":
    # https://privatekeys.pw/puzzles/bitcoin-puzzle-tx
    solutions={1:'1',2:'3',3:'7',4:'8',5:'15',68:'bebb3940cd0fc1491'}    
    for n,private_key in solutions.items():
        print(n, int(private_key, 16)) # hex(dec).split('x')[-1]
        print('-'*30)
        display(private_key.rjust(64, '0'))