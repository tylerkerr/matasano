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

plaintext = tkutils.ingestB64asBinary(filename)

ciphertext = (oracle(plaintext, key))


def findBlockSize(plaintext, ciphertext):
    blocksizerange = 16
    for blocksize in range(1, blocksizerange+1):
        trialencrypt = oracle(plaintext[0:blocksize], key)
        if trialencrypt[0:blocksize] == ciphertext[0:blocksize]:
            return(blocksize)
            break

blocksize = findBlockSize(plaintext, ciphertext)

if tkutils.detectecb(ciphertext) == True:
    pass
else:
    print("encrypted ciphertext is not ECB, or is ECB without repeated blocks. exiting")
    sys.exit(1)