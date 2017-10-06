#!/usr/bin/env python3

from set2 import *

def chal9():
    print('[-] trying challenge nine')
    example = b"YELLOW SUBMARINE"
    answer = b"YELLOW SUBMARINE\x04\x04\x04\x04"
    result = padPKCS7(example, 20)
    print(result)
    if result == answer:
        print('[+] challenge nine successful')

def chal10():
    print('[-] trying challenge ten')
    plaintext =b"hey..hope this comes out the other side all right..."
    key = b'YEllOW SUBMARINE'
    ciphertext = encryptAESECB(padPKCS7(plaintext, 16), key)
    newpt = stripPKCS7(decryptAESECB(ciphertext, key), 16)
    print(plaintext)
    print(newpt)
    print([bytes([x]) for x in range(16)])
    assert plaintext == newpt



chal9()
chal10()