#!/usr/bin/env python3

from set1 import decryptAESECB, splitToBlocks, fixedXOR
from base64 import b64decode, b64encode
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import os
import sys
import re
from random import SystemRandom, randint

def padPKCS7(plaintext: bytes, blocksize: int):
    if len(plaintext) % blocksize == 0:
        return plaintext + bytes([blocksize]) * blocksize
    else:
        difference = blocksize - (len(plaintext) % blocksize)
        return plaintext + bytes([difference]) * difference

def padPlaintext(plaintext: bytes, blocksize: int):
    ptblocks = splitToBlocks(plaintext, blocksize)
    if len(ptblocks[-1]) == blocksize:
        ptblocks.append(bytes([blocksize]) * blocksize)
    if len(ptblocks[-1]) < blocksize:
        ptblocks[-1] = padPKCS7(ptblocks[-1], blocksize)
    return b''.join(ptblocks)

def stripPKCS7(plaintext: bytes, blocksize: int):
    ptblocks = splitToBlocks(plaintext, blocksize)
    if ptblocks[-1] == bytes([blocksize]) * blocksize:
        return b''.join(ptblocks[:-1])
    elif ptblocks[-1][-1] not in range(blocksize):
        print('[!] warning: attempting to strip PKCS#7 on something that appears to be unpadded')
        return b''.join(ptblocks)
    else:
        padsize = ptblocks[-1][-1]
        return b''.join(ptblocks)[:padsize*-1]

def encryptAESECB(plaintext: bytes, key: bytes):
    blocksize = 16
    backend = default_backend()
    ptblocks = splitToBlocks(plaintext, blocksize)
    ctblocks = []
    for block in ptblocks:
        ecbcipher = Cipher(algorithms.AES(key), modes.ECB(), backend=backend)
        ecbencrypt = ecbcipher.encryptor()
        ctblocks.append(ecbencrypt.update(block))
    ciphertext = b''.join(ctblocks)
    return ciphertext

def encryptAESCBC(plaintext: bytes, key: bytes, iv: bytes):
    ptblocks = splitToBlocks(plaintext, 16)
    ctblocks = []
    for blocknum in range(len(ptblocks)):
        if blocknum == 0:
            xor = iv
        else:
            xor = ctblocks[blocknum-1]
        toencrypt = fixedXOR(ptblocks[blocknum], xor)
        ctblocks.append(encryptAESECB(toencrypt, key))
    return b''.join(ctblocks)


def decryptAESCBC(ciphertext: bytes, key: bytes, iv: bytes):
    ctblocks = splitToBlocks(ciphertext, 16)
    ptblocks = []
    for blocknum in range(len(ctblocks)):
        if blocknum == 0:
            xor = iv
        else:
            xor = ctblocks[blocknum-1]
        toxor = decryptAESECB(ctblocks[blocknum], key)
        ptblocks.append(fixedXOR(toxor, xor))
    return b''.join(ptblocks)

def coinflip():
    if int.from_bytes(os.urandom(1), 'big') > 127:
        return True
    else:
        return False

def randomEncrypt(plaintext: bytes):
    key = os.urandom(16)
    useCBC = coinflip()
    prebytes = os.urandom(SystemRandom().randint(5, 10))
    postbytes = os.urandom(SystemRandom().randint(5, 10))
    oraclept = padPKCS7(prebytes + plaintext + postbytes, 16)
    if useCBC:
        print('cbc')
        iv = os.urandom(16)
        return encryptAESCBC(oraclept, key, iv)
    else:
        print('ecb')
        return encryptAESECB(oraclept, key)

def detectECB(ciphertext: bytes, blocksize):
    ctblocks = splitToBlocks(ciphertext, blocksize)
    knownblocks = []
    for block in ctblocks:
        if block in knownblocks:
            return True
        else:
            knownblocks.append(block)
    return False

def chal12Encrypt(plaintext: bytes):
    secret = b64decode('Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK')
    key = b64decode('5DbnGJsMDIVFX2LqTrVKqg==') # random but permanent
    oraclept = padPKCS7(plaintext + secret, 16)
    return encryptAESECB(oraclept, key)

def detectOracleBlocksize(oracle):
    lengthtest = 'a'
    baselength = len(oracle(lengthtest.encode()))
    newlength = baselength
    while newlength == baselength:
        lengthtest += 'a'
        newlength = len(oracle(lengthtest.encode()))
    return newlength - baselength

def decryptCBCOracleSuffix(oracle, blocksize):
    totalblocks = len(oracle(b'')) // blocksize
    print("[+] secret is {} blocks long".format(totalblocks))
    allbytes = [bytes([i]) for i in range(256)]
    
    filler = ('a' * blocksize).encode()
    solvedblocks = []
    for block in range(totalblocks):
        plaintext = b''
        if block == 0:
            testblock = filler
        else:
            testblock = solvedblocks[block-1]
        for bytepos in range(blocksize):
            test = testblock[bytepos+1:]
            target = oracle(test)[block*blocksize:block*blocksize+blocksize]
            for byte in allbytes:
                checkblock = test + plaintext + byte
                if oracle(checkblock)[0:blocksize] == target:
                    plaintext += byte
                    print(byte.decode(), end='')
                    sys.stdout.flush()
                    break
        solvedblocks.append(plaintext)

def parseCookie(cookie: str):
    keys = cookie.split('&')
    dic = {}
    for key in keys:
        k, v = key.split('=')
        dic[k] = v
    return dic

def makeCookie(email: str, uid: int, role: str):
    return 'email={}&uid={}&role={}'.format(email, uid, role)

def makeProfile(email: str):
    email = re.sub('[&=]', '', email)
    uid = SystemRandom().randint(10,99)
    key = b64decode('Fb0cRwVG7zA7+cDK7GAQCQ==') # random but permanent
    role = 'user'
    cookie = makeCookie(email, uid, role)
    return encryptAESECB(padPKCS7(cookie.encode(), 16), key)

def parseProfile(cookie: bytes):
    key = b64decode('Fb0cRwVG7zA7+cDK7GAQCQ==') # random but permanent
    cookie = stripPKCS7(decryptAESECB(cookie, key), 16).decode()
    return cookie

def chal14Encrypt(plaintext: bytes, prebytes: bytes):
    secret = b64decode('Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK')
    key = b64decode('gR/1a5kNvr2pTK3BOX/m7Q==') # random but permanent
    
    oraclept = padPKCS7(prebytes + plaintext + secret, 16)
    return encryptAESECB(oraclept, key)

def detectOracleBlocksizeHard(oracle, prebytes: bytes):
    lengthtest = 'a'
    baselength = len(oracle((lengthtest.encode()), prebytes))
    newlength = baselength
    while newlength == baselength:
        lengthtest += 'a'
        newlength = len(oracle((lengthtest.encode()), prebytes))
    return newlength - baselength

def decryptCBCOracleSuffixHard(oracle, prebytes: bytes, blocksize: int):
    return True

