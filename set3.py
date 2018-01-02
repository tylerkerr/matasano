#!/usr/bin/env python3

from set1 import splitToBlocks, fixedXOR, singleXOR, transposeToKeyBlocks
from set2 import padPKCS7, stripPKCS7, encryptAESCBC, decryptAESCBC, encryptAESECB
import os
import sys
import re
from base64 import b64decode
from secrets import choice
from time import time, sleep
from random import SystemRandom


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


def AESCTR(inp: bytes, key: bytes, nonce: bytes):
    inblocks = splitToBlocks(inp, 16)
    outblocks = []
    counter = 0
    for block in inblocks:
        ctrbytes = counter.to_bytes(8, byteorder='little')
        prestream = nonce + ctrbytes
        keystream = encryptAESECB(prestream, key)
        if len(block) != len(keystream):
            keystream = keystream[:len(block)]
        outblocks.append(fixedXOR(block, keystream))
        counter += 1
    return b''.join(outblocks)


def chal19Encrypt():
    pts = ['SSBoYXZlIG1ldCB0aGVtIGF0IGNsb3NlIG9mIGRheQ==', 'Q29taW5nIHdpdGggdml2aWQgZmFjZXM=', 'RnJvbSBjb3VudGVyIG9yIGRlc2sgYW1vbmcgZ3JleQ==', 'RWlnaHRlZW50aC1jZW50dXJ5IGhvdXNlcy4=', 'SSBoYXZlIHBhc3NlZCB3aXRoIGEgbm9kIG9mIHRoZSBoZWFk', 'T3IgcG9saXRlIG1lYW5pbmdsZXNzIHdvcmRzLA==', 'T3IgaGF2ZSBsaW5nZXJlZCBhd2hpbGUgYW5kIHNhaWQ=', 'UG9saXRlIG1lYW5pbmdsZXNzIHdvcmRzLA==', 'QW5kIHRob3VnaHQgYmVmb3JlIEkgaGFkIGRvbmU=', 'T2YgYSBtb2NraW5nIHRhbGUgb3IgYSBnaWJl', 'VG8gcGxlYXNlIGEgY29tcGFuaW9u', 'QXJvdW5kIHRoZSBmaXJlIGF0IHRoZSBjbHViLA==', 'QmVpbmcgY2VydGFpbiB0aGF0IHRoZXkgYW5kIEk=', 'QnV0IGxpdmVkIHdoZXJlIG1vdGxleSBpcyB3b3JuOg==', 'QWxsIGNoYW5nZWQsIGNoYW5nZWQgdXR0ZXJseTo=', 'QSB0ZXJyaWJsZSBiZWF1dHkgaXMgYm9ybi4=', 'VGhhdCB3b21hbidzIGRheXMgd2VyZSBzcGVudA==', 'SW4gaWdub3JhbnQgZ29vZCB3aWxsLA==', 'SGVyIG5pZ2h0cyBpbiBhcmd1bWVudA==', 'VW50aWwgaGVyIHZvaWNlIGdyZXcgc2hyaWxsLg==', 'V2hhdCB2b2ljZSBtb3JlIHN3ZWV0IHRoYW4gaGVycw==', 'V2hlbiB5b3VuZyBhbmQgYmVhdXRpZnVsLA==', 'U2hlIHJvZGUgdG8gaGFycmllcnM/', 'VGhpcyBtYW4gaGFkIGtlcHQgYSBzY2hvb2w=', 'QW5kIHJvZGUgb3VyIHdpbmdlZCBob3JzZS4=', 'VGhpcyBvdGhlciBoaXMgaGVscGVyIGFuZCBmcmllbmQ=', 'V2FzIGNvbWluZyBpbnRvIGhpcyBmb3JjZTs=', 'SGUgbWlnaHQgaGF2ZSB3b24gZmFtZSBpbiB0aGUgZW5kLA==', 'U28gc2Vuc2l0aXZlIGhpcyBuYXR1cmUgc2VlbWVkLA==', 'U28gZGFyaW5nIGFuZCBzd2VldCBoaXMgdGhvdWdodC4=', 'VGhpcyBvdGhlciBtYW4gSSBoYWQgZHJlYW1lZA==', 'QSBkcnVua2VuLCB2YWluLWdsb3Jpb3VzIGxvdXQu', 'SGUgaGFkIGRvbmUgbW9zdCBiaXR0ZXIgd3Jvbmc=', 'VG8gc29tZSB3aG8gYXJlIG5lYXIgbXkgaGVhcnQs', 'WWV0IEkgbnVtYmVyIGhpbSBpbiB0aGUgc29uZzs=', 'SGUsIHRvbywgaGFzIHJlc2lnbmVkIGhpcyBwYXJ0', 'SW4gdGhlIGNhc3VhbCBjb21lZHk7', 'SGUsIHRvbywgaGFzIGJlZW4gY2hhbmdlZCBpbiBoaXMgdHVybiw=', 'VHJhbnNmb3JtZWQgdXR0ZXJseTo=', 'QSB0ZXJyaWJsZSBiZWF1dHkgaXMgYm9ybi4=']
    key = b'uYTesOYLHdvqveJmGIcBgQ=='
    nonce = bytes(8)
    cts = [AESCTR(b64decode(pt), key, nonce) for pt in pts]
    return cts

def getMaxLen(l: list):
    maxlen = 0
    for i in l:
        if len(i) > maxlen:
            maxlen = len(i)
    return maxlen

def getMinLen(l: list):
    minlen = getMaxLen(l)
    for i in l:
        if len(i) < minlen:
            minlen = len(i)
    return minlen


def bruteforceSingleXORBytes(ciphertext: str, charscores: dict):  # hex
    trialdecrypts = {}
    for byte in range(256):
        trialdecrypts[byte] = bytearray(singleXOR(ciphertext, byte))
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
    plaintext = trialdecrypts[bestkey]
    return bestkey, plaintext


def chal20Encrypt():
    pts = [b64decode(line) for line in open('./data/20.txt', 'r').read().splitlines()]
    key = b'uYTesOYLHdvqveJmGIcBgQ=='
    nonce = bytes(8)
    cts = [AESCTR(pt, key, nonce) for pt in pts]
    return cts



def getnGrams(string: str, n: int):
    ngrams = []
    for i in range(len(string)-1):
        if len(string[i:i+n]) == n:
            ngrams.append(string[i:i+n])
    return ngrams

def buildnGramCorpus(dir: str, maxn: int):
    ngramcounts = {}
    charcount = 0
    for file in os.listdir(dir):
        filename = dir + '/' + file
        with open(filename, 'r') as f:
            text = f.read()
            charcount += len(text)
            for n in range(1, maxn+1):
                counts = {}
                ngrams = getnGrams(text, n)
                for gram in ngrams:
                    if gram in counts:
                        counts[gram] += 1
                    else:
                        counts[gram] = 1
                ngramcounts[n] = counts

    ngramscores = {}
    for nsize in range(1, maxn+1):
        ngramscores[nsize] = {}
        for g in ngramcounts[nsize]:
            ngramscores[nsize][g] = ngramcounts[nsize][g] / (charcount // nsize)

    return(ngramscores)


def bruteforceRepeatingXOR(ciphertext: bytes, keysize: int, maxn: int):
    gramscores = buildnGramCorpus('./samples/books/', maxn)
    keyblocks = (transposeToKeyBlocks(ciphertext, keysize))
    key = bytearray(b'')
    for keyblock in keyblocks:
        key += bytes([bruteforceSingleXORnGrams(keyblock, gramscores, maxn)[0]])
    key = bytes(key)
    return key


def bruteforceSingleXORnGrams(ciphertext: bytes, gramscores: dict, maxn: int):  # hex
    trialdecrypts = {}
    for byte in range(256):
        trialdecrypts[byte] = bytes(singleXOR(ciphertext, byte))
    keyscores = {}
    for trial in trialdecrypts:
        score = 0
        for n in range(1, maxn + 1):
            ngrams = getnGrams(trialdecrypts[trial], n)
            for c in ngrams:
                gram = c.decode('utf-8', 'ignore')
                if gram in gramscores[n]:
                    # print('found ngram "{}" in {}-gram scores. score += {}'.format(gram, n, gramscores[n][gram] * n * n))
                    score += gramscores[n][gram] * n ** 2
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

def getLowest32Bits(x: int):
    return int(0xffffffff & x)

class MT19937:
    w = 32  # word size in bits
    n = 624  # degree of recurrence
    m = 397  # 'middle word' offset
    r = 31  # 'separation point' of one word
    a = 0x9908b0df  # coefficient of the rational normal form twist matrix (?)
    b = 0x9d2c5680  # tempering bitmask
    c = 0xefc60000  # tempering bitmask
    d = 0xffffffff  # tempering bitmask
    l = 18  # tempering bitshift
    s = 7   # tempering bitshift
    t = 15  # tempering bitshift
    u = 11  # tempering bitshift
    f = 1812433253  # magic?

    lm = (1 << r) - 1  # lower mask
    um = getLowest32Bits(abs(~lm))  # upper mask

    def __init__(self, seed):
        self.index = self.n
        self.state = [0] * self.n
        self.state[0] = seed
        for i in range(1, self.n):
            stateinit = self.f * (self.state[i - 1] ^ self.state[i - 1] >> (self.w - 2)) + i
            self.state[i] = getLowest32Bits(stateinit)

    def extract(self):
        if self.index >= self.n:
            if self.index > self.n:
                print("[!] generator was not seeded!")
                sys.exit(1)
            self.twist()
        y = self.state[self.index]
        y = y ^ ((y >> self.u) & self.d)
        y = y ^ ((y << self.s) & self.b)
        y = y ^ ((y << self.t) & self.c)
        y = y ^ (y >> self.l)
        self.index += 1
        return getLowest32Bits(y)

    def twist(self):
        for i in range(self.n):
            x = (self.state[i] & self.um) + (self.state[(i + 1) % self.n] & self.lm)
            xA = x >> 1
            if x % 2 != 0:
                xA = xA ^ self.a

            self.state[i] = self.state[(i + self.m) % self.n] ^ xA

        self.index = 0


def chal22Rand():
    sleep(SystemRandom().randint(1, 7))
    epoch = int(time())
    mt = MT19937(epoch)
    output = mt.extract()
    sleep(SystemRandom().randint(1, 7))
    return output
