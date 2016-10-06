#!/usr/bin/env python3

import sys
import os
import binascii
import tkutils

filename = sys.argv[1]

leveltwelve = "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK"
key = b' $$f\x1f\x93\xb3\x111\xf08\xf9a\x1fy\xc4'

def oracle(plaintext, key):
    fudgedpt = plaintext + binascii.a2b_base64(leveltwelve)
    ciphertext = binascii.b2a_base64(tkutils.encryptaesecb(fudgedpt, key)).decode('utf-8')
    return(ciphertext)

plaintext = tkutils.ingestb64asbinary(filename)

ciphertext = (oracle(plaintext, key))

blocksizerange = 32

print(len(plaintext))
for blocksize in range(blocksizerange):
    print(blocksize)
    for c in range(blocksize):
        # print(chr(plaintext[c]))
        pass