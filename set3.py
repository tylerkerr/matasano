#!/usr/bin/env python3

from set1 import splitToBlocks, fixedXOR
from set2 import padPKCS7, stripPKCS7, encryptAESCBC, decryptAESCBC
import os
import sys
import re
from base64 import b64decode
from secrets import choice


def chal17Encrypt():
    key = b64decode('wlOBG6Vh/xQZeQK80NqQTg==')
    iv = os.urandom(16)
    strings = ['MDAwMDAwTm93IHRoYXQgdGhlIHBhcnR5IGlzIGp1bXBpbmc=', 'MDAwMDAxV2l0aCB0aGUgYmFzcyBraWNrZWQgaW4gYW5kIHRoZSBWZWdhJ3MgYXJlIHB1bXBpbic=', 'MDAwMDAyUXVpY2sgdG8gdGhlIHBvaW50LCB0byB0aGUgcG9pbnQsIG5vIGZha2luZw==', 'MDAwMDAzQ29va2luZyBNQydzIGxpa2UgYSBwb3VuZCBvZiBiYWNvbg==', 'MDAwMDA0QnVybmluZyAnZW0sIGlmIHlvdSBhaW4ndCBxdWljayBhbmQgbmltYmxl', 'MDAwMDA1SSBnbyBjcmF6eSB3aGVuIEkgaGVhciBhIGN5bWJhbA==', 'MDAwMDA2QW5kIGEgaGlnaCBoYXQgd2l0aCBhIHNvdXBlZCB1cCB0ZW1wbw==', 'MDAwMDA3SSdtIG9uIGEgcm9sbCwgaXQncyB0aW1lIHRvIGdvIHNvbG8=', 'MDAwMDA4b2xsaW4nIGluIG15IGZpdmUgcG9pbnQgb2g=', 'MDAwMDA5aXRoIG15IHJhZy10b3AgZG93biBzbyBteSBoYWlyIGNhbiBibG93']
    return (encryptAESCBC(padPKCS7(b64decode(choice(strings)), 16), key, iv), iv)


def chal17Oracle(cookie: tuple):
    key = b64decode('wlOBG6Vh/xQZeQK80NqQTg==')
    iv = cookie[1]
    try:
        pt = decryptAESCBC(cookie[0], key, iv)
        stripPKCS7(pt, 16)
        return True
    except ValueError:
        return False


def attackCBCPaddingOracle(ciphertext: tuple, oracle):
    ctblocks = splitToBlocks(ciphertext[0], 16)
    iv = ciphertext[1]

    pt = []
    for block in range(len(ctblocks)):
        ptblock = b''

        if block == 0:
            prevblock = list(iv)
        else:
            prevblock = list(ctblocks[block - 1])

        if block == len(ctblocks) - 1:
            lastblock = True
        else:
            lastblock = False

        for byte in range(16):
            position = 15 - byte
            padbytes = bytes(15 - byte) + (bytes([byte + 1]) * (byte + 1))
            ptbytes = bytes(16 - byte) + ptblock
            candidates = []
            for b in range(256):
                testbytes = list(bytes(16))
                testbytes[position] = b
                fakeiv = fixedXOR(prevblock, fixedXOR(padbytes, fixedXOR(testbytes, ptbytes)))
                if oracle((ctblocks[block], fakeiv)):
                    sol = bytes([b])
                    if not lastblock:
                        ptblock = sol + ptblock
                    else:
                        candidates.append(sol)
            if lastblock:
                if len(candidates) == 1:
                    ptblock = candidates[0] + ptblock
                else:
                    ptblock = candidates[1] + ptblock
        pt.append(ptblock)

    return stripPKCS7(b''.join(pt), 16).decode()
