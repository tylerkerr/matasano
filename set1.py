#!/usr/bin/env python3

from binascii import hexlify, unhexlify
from os import listdir
from base64 import b64encode, b64decode
from itertools import combinations
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend


def hexToBytes(hexstring: str):
    return bytearray.fromhex(hexstring)


def hexToString(hexstring: str):
    return unhexlify(hexstring).decode()


def fixedXOR(a: bytes, b: bytes):
    if len(a) != len(b):
        raise ValueError("[!] can't XOR, length mismatch")
    return bytes([abyte ^ bbyte for abyte, bbyte in zip(a, b)])


def buildCorpus(dir: str):
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


def bruteforceSingleXOR(ciphertext: str, charscores: dict):  # hex
    trialdecrypts = {}
    for byte in range(256):
        trialdecrypts[byte] = bytearray(singleXOR(hexToBytes(ciphertext), byte))
    keyscores = {}
    for trial in trialdecrypts:
        score = 0
        for c in trialdecrypts[trial]:
            char = chr(c)
            if char in charscores:
                score += charscores[char] * 10
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


def encryptVigenere(plaintext: bytes, key: bytes):
    vigenerekey = bytearray(b'')
    while len(vigenerekey) < len(plaintext):
        vigenerekey += key
    vigenerekey = vigenerekey[0:len(plaintext)]
    ciphertext = fixedXOR(plaintext, vigenerekey)
    return ciphertext


def decryptVigenere(ciphertext: bytes, key: bytes):
    vigenerekey = bytearray(b'')
    while len(vigenerekey) < len(ciphertext):
        vigenerekey += key
    vigenerekey = vigenerekey[0:len(ciphertext)]
    plaintext = fixedXOR(ciphertext, vigenerekey)
    return plaintext


def hammingDistance(a: bytes, b: bytes):
    if len(a) != len(b):
        raise ValueError("[!] can't check hamming distance, length mismatch")
    distance = 0
    for x, y in zip(a, b):
        xbits, ybits = bin(x)[2:], bin(y)[2:]
        while len(xbits) < 8:
            xbits = '0' + xbits
        while len(ybits) < 8:
            ybits = '0' + ybits
        for xb, yb in zip(xbits, ybits):
            if xb != yb:
                distance += 1
    return distance


def splitToBlocks(inbytes: bytes, blocksize: int):
    return [inbytes[i:i+blocksize] for i in range(0, len(inbytes), blocksize)]


def scoreKeysizes(ciphertext: bytes, maxkeysize: int):
    blockstoscore = 10
    assert len(ciphertext)//maxkeysize > blockstoscore
    keysizescores = {}
    for keysize in range(2, maxkeysize+1):
        distance = 0
        cipherblocks = splitToBlocks(ciphertext, keysize)
        combos = [comb for comb in combinations(cipherblocks, 2)][:blockstoscore]
        for combo in combos:
            combodistance = hammingDistance(combo[0], combo[1])
            # print(combo, combodistance)
            distance += (combodistance / keysize) / blockstoscore
        distance += keysize / (maxkeysize * 10)  # penalize longer keysizes to avoid solving for doubled keys
        keysizescores[keysize] = distance
    return min(keysizescores, key=keysizescores.get)


def transposeToKeyBlocks(ciphertext: bytes, keysize: int):
    keyblocks = []
    for i in range(keysize):
        keyblocks.append(bytearray(b''))
    for c in range(len(ciphertext)):
        block = c % keysize
        keyblocks[block] += bytes([ciphertext[c]])
    keyblockbytes = []
    for keyblock in keyblocks:
        keyblockbytes.append(bytes(keyblock))
    return keyblockbytes


def bruteforceVigenere(ciphertext: bytes, keysize: int):
    charscores = buildCorpus('./samples/books/')
    keyblocks = (transposeToKeyBlocks(ciphertext, keysize))
    key = bytearray(b'')
    for keyblock in keyblocks:
        key += bytes([bruteforceSingleXOR(hexlify(keyblock).decode(), charscores)[0]])
    key = bytes(key)
    return key


def decryptAESECB(ciphertext: bytes, key: bytes):
    blocksize = 16
    backend = default_backend()
    ctblocks = splitToBlocks(ciphertext, blocksize)
    ptblocks = []
    for block in ctblocks:
        ecbcipher = Cipher(algorithms.AES(key), modes.ECB(), backend=backend)
        ecbdecrypt = ecbcipher.decryptor()
        ptblocks.append(ecbdecrypt.update(block))
    plaintext = b''.join(ptblocks)
    return plaintext


def detectECB(ciphertext: bytes, blocksize: int):
    ctblocks = splitToBlocks(ciphertext, blocksize)
    combos = combinations(ctblocks, 2)
    repetitions = 0
    for pair in combos:
        if pair[0] == pair[1]:
            repetitions += 1
    if repetitions > 0:
        return True
    else:
        return False
