from utils import Point

def getAddr(pubkey_point,compressed=True):
    from utils import ripemd160, sha256, b58
    if compressed:
        prefix = b'\x02' if pubkey_point.y % 2 == 0 else b'\x03'
        pubkey = prefix + pubkey_point.x.to_bytes(32, 'big')
    else:
        pubkey = pubkey_point.toBytes()

    hash160 = ripemd160(sha256(pubkey))
    address = b"\x00" + hash160
    return b58(address + sha256(sha256(address))[:4])

getPublicKey_from_int = lambda pk: Point()*pk

def puzzle_130():
    r='200000000000000000000000000000000:3ffffffffffffffffffffffffffffffff'
    print('range:',int(r.split(':')[0],16),int(r.split(':')[1],16))
    private_key = int('33e7665705359f04f28b88cf897c603c9',16) # 1103873984953507439627945351144005829577
    print('private key:',private_key)
    # 1Fo65aKq8s8iquMt6weF1rku1moWVEd5Ua
    pub_key = getPublicKey_from_int(private_key)
    
    return getAddr(pub_key)

def puzzle_135():
    r='4000000000000000000000000000000000:7fffffffffffffffffffffffffffffffff'
    print('range:',int(r.split(':')[0],16),int(r.split(':')[1],16))    
	# 02145d2611c823a396ef6712ce0f712f09b9b4f3135e3e0aa3230fb9b6d08d1e16
    # 16RGFo6hjq9ym6Pj7N5H7L1NR1rVPJyw2v
    x = 9210836494447108270027136741376870869791784014198948301625976867708124077590
    y = 46351506704828816385393879789131775975171267756561783641521771795450741674800
    return getAddr(Point(x,y))
    

def puzzle_140():
    # to convert publickey to x,y points see -> https://stackoverflow.com/a/53528887/2351696
    # 80000000000000000000000000000000000:fffffffffffffffffffffffffffffffffff 
    # 031f6a332d3c5c4f2de2378c012f429cd109ba07d69690c6c701b6bb87860d6640
    # 1QKBaU6WAeycb3DbKbLBkX7vJiaS8r42Xo
    pass

def brute_force_135():
    # puzzle 130
    for i in range(1103873984953507439627945351144005829500,1103873984953507439627945351144005829600):
        pub_key = Point()*i
        if pub_key.x==44886295857190546091508615621464465421050773292389158775895365558788257183826 and pub_key.y == 79820197542983972470655013754473404410649480536210503962616926227235987362275:
            print('found:',i,getAddr(pub_key))
            break
    # puzzle 135
    for i in range(21778071482940061661655974875633165533184,21778071482940061661655974875633165533200):
        pub_key = Point()*i
        if pub_key.x==9210836494447108270027136741376870869791784014198948301625976867708124077590 and pub_key.y == 46351506704828816385393879789131775975171267756561783641521771795450741674800:
            print('found:',i,getAddr(pub_key))
            break
brute_force_135()