#!/usr/bin/env python3

from set2 import *
from binascii import hexlify, unhexlify

def chal9():
    print('[-] trying challenge nine')
    example = b"YELLOW SUBMARINE"
    answer = b"YELLOW SUBMARINE\x04\x04\x04\x04"
    result = padPKCS7(example, 20)
    print(result)

    plaintext =b"hey..hope this comes out the other side all right..."
    key = b'YEllOW SUBMARINE'
    ciphertext = encryptAESECB(padPKCS7(plaintext, 16), key)
    newpt = stripPKCS7(decryptAESECB(ciphertext, key), 16)
    assert plaintext == newpt

    if result == answer:
        print('[+] challenge nine successful')

def chal10():
    print('[-] trying challenge ten')

    iv = b'\x00' * 16
    key = b'YELLOW SUBMARINE'
    testpt = b'block of sixteen0'
    testct = encryptAESCBC(padPKCS7(testpt, 16), key, iv)
    
    ct = b64decode(open('./data/10.txt', 'rb').read())
    pt = decryptAESCBC(ct, key, iv)
    print(pt.decode())
    print('[+] challenge ten successful')

def testCoinflip():
    while True:
        tries = 0
        while True:
            heads = 0
            tails = 0
            for i in range(10000):
                if coinflip():
                    heads += 1
                else:
                    tails += 1
            tries += 1
            # print(heads, tails)
            if heads == tails:
                print('wow! %s tries' % tries)
                break
# chal9()
# chal10()
testCoinflip()
# chal11()