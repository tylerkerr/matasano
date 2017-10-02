#!/usr/bin/env python3

from base64 import b64encode, b64decode
from binascii import hexlify, unhexlify
from collections import OrderedDict
from operator import itemgetter    
from os import listdir


def hexToBytes(hexstring: str):
    return bytearray.fromhex(hexstring)

def hexToString(hexstring: str):
    return unhexlify(hexstring).decode()

def fixedXOR(a: str, b: str):
    if len(a) != len(b):
        raise ValueError("[!] can't XOR, length mismatch")
    return hexlify(bytearray([abyte ^ bbyte for abyte, bbyte in zip(hexToBytes(a), hexToBytes(b))])).decode()

def buildCorpus(dir):
    chars = {}
    charcount = 0
    for file in listdir(dir):
        filename = dir + '/' + file
        with open(filename, 'r') as f:
            text = f.read()
            for c in text:
                charcount += 1
                if c in chars:
                    chars[c] += 1
                else:
                    chars[c] = 1
    normchars = {}
    for c in chars:
        normchars[c] = chars[c] / charcount
    return(normchars)

def singleXOR(bytesin: bytes, key: int):
    assert key < 256
    return [b ^ key for b in bytesin]

def bruteforceSingleXOR(ciphertext: str, corpusdir: str): # hex 
    charscores = buildCorpus(corpusdir)
    trialdecrypts = {}
    for byte in range(256):
        trialdecrypts[byte] = bytearray(singleXOR(hexToBytes(ciphertext), byte))
    keyscores = {}
    for trial in trialdecrypts:
        score = 0
        for c in trialdecrypts[trial]:
            char = chr(c)
            if char in charscores:
                score += charscores[char]
            else:
                score -= 1
        keyscores[trial] = score
    sortedscores = [(c, keyscores[c]) for c in sorted(keyscores, key=keyscores.get, reverse=True)]
    bestkey = sortedscores[0][0]
    score = sortedscores[0][1]
    try:
        plaintext = trialdecrypts[bestkey].decode()
    except:
        raise ValueError('[!] invalid byte in best decryption!')
    return (bestkey, plaintext, score)

def encryptVigenere(plaintext: str, key: str):
    vigenerekey = ''
    while len(vigenerekey) < len(plaintext):
        vigenerekey += key
    vigenerekey = vigenerekey[0:len(plaintext)]
    ciphertext = fixedXOR(hexlify(plaintext.encode()).decode(), hexlify(vigenerekey.encode()).decode())
    # print(hexlify(plaintext.encode()))
    return ciphertext