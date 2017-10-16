#!/usr/bin/env python3

from set1 import decryptAESECB, splitToBlocks
from base64 import b64decode
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

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

def decryptAESCBC(plaintext: bytes, key: bytes, iv: bytes):
    ctblocks = splitToBlocks(plaintext)