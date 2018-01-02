#!/usr/bin/env python3

from set3 import *
from set1 import buildCorpus

def chal17():
    print('[-] trying challenge seventeen')
    assert chal17Oracle(chal17Encrypt())
    fakect = (b'block of sixteenblock of sixteenpadthis', b'yellow submarine')
    assert not chal17Oracle(fakect)
    plaintext = attackCBCPaddingOracle(chal17Encrypt(), chal17Oracle)
    assert re.match('^\d{6}', plaintext)
    print(plaintext)
    print('[+] challenge seventeen successful')

def chal18():
    print('[-] trying challenge eighteen')
    ciphertext = b64decode('L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ==')
    nonce = bytes(8)
    key = b'YELLOW SUBMARINE'
    plaintext = AESCTR(ciphertext, key, nonce).decode()
    print(plaintext)

    nonce = os.urandom(8)
    testpt = b'encrypt this immediately, i command it'
    testct = AESCTR(testpt, key, nonce)
    assert testpt == AESCTR(testct, key, nonce)
    print('[+] challenge eighteen successful')

def chal19():
    print('[-] trying challenge nineteen')
    charscores = buildCorpus('./samples/books/')
    cts = chal19Encrypt()
    maxlen = getMaxLen(cts)
    minlen = getMinLen(cts)
    cracked = []
    for byte in range(minlen):
        array = []
        for ct in cts:
            array.append(ct[byte-1])
        bestbyte, plaintext = bruteforceSingleXORBytes(bytes(array), charscores)
        cracked.append(plaintext)
    plaintexts = []
    for pos in range(len(cts)):
        pt = bytes([c[pos] for c in cracked])
        plaintexts.append(pt)
    knownpt = open('./data/easter.txt', 'r').read().splitlines()
    for line in range(len(knownpt)):
        if len(knownpt[line]) == maxlen:
            keystream = fixedXOR(knownpt[line].encode(), cts[line])
    for ct in cts:
        print(fixedXOR(ct, keystream[:len(ct)]).decode())
    print('[+] challenge nineteen successful')


def chal20():
    print('[-] trying challenge twenty')
    cts = chal20Encrypt()
    maxlen = getMaxLen(cts)
    minlen = getMinLen(cts)
    print(len(cts), 'ciphertexts. maxlen', maxlen, 'minlen', minlen)
    truncatedcts = [ct[0:minlen] for ct in cts]
    ciphertext = b''.join(truncatedcts)
    keystream = bruteforceRepeatingXOR(ciphertext, minlen, 3)
    for ct in truncatedcts:
        print(fixedXOR(ct, keystream).decode())
    print('[+] challenge twenty successful')


def chal21():
    print('[-] trying challenge twenty-one')
    testseed = 1131464071
    mt = MT19937(testseed)
    print('[-] initialized mersenne twister with seed {}'.format(testseed))
    testvectors = [3521569528,  # https://gist.github.com/mimoo/8e5d80a2e236b8b6f5ed
                   1101990581,
                   1076301704,
                   2948418163,
                   3792022443,
                   2697495705,
                   2002445460,
                   502890592]

    for n, v in enumerate(testvectors):
        assert mt.extract() == v
        print("[+] match on test vector {} : {}".format(n, v))

    print('[+] challenge twenty-one successful')

def chal22():
    pass

def chal23():
    pass    

def chal24():
    pass

# chal17()
# chal18()
# chal19()
# chal20()
# chal21()
chal22()
chal23()
chal24()




