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


chal17()
chal18()
chal19()