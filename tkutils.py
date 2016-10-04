#!/usr/bin/env python3

import sys
import binascii
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

def padhex(hexin): # left-pad odd-length hex string
    if len(hexin) % 2 == 1:
        hexout = "0" + hexin
        return(hexout)
    else:
        return(hexin)

def ingestb64asbytelist(filename): # take a base64-encoded file and return list of bytes (as ints)
    with open(filename) as f:
        ciphertext = "".join(f.read().splitlines())
    try: 
        cipherhex = b642hex(ciphertext) # get a hex string from the base64 input
    except:
        print("input must be base64-encoded vigenere-encrypted binary ciphertext")
        return(False)
    ctbytes = splithex(cipherhex) # chop the hex string into bytes
    return(ctbytes)

def ingestb64asbinary(filename): # take a base64-encoded file and return binary
    with open(filename) as f:
        ciphertext = "".join(f.read().splitlines())
    try: 
        ctbytes = binascii.a2b_base64(ciphertext) # get a hex string from the base64 input
    except:
        print("input must be base64-encoded binary")
        return(False)
    return(ctbytes)
    
def hex2ascii(hexin): # convert hex string to ascii
    asciiout = bytes.fromhex(padhex(hexin)).decode('utf-8')
    return(asciiout)

def ascii2hex(asciiin): # convert ascii to hex string
    hexbytes = [format(ord(c), 'x') for c in asciiin]
    hexout = "".join(hexbytes)
    return(hexout)
    
def hex2b64(hexin): # convert hex string to base64
    hexbytes = binascii.unhexlify(padhex(hexin))
    b64bytes = binascii.b2a_base64(hexbytes)
    b64out = b64bytes.decode('utf-8').rstrip('\n')
    return(b64out)

def b642hex(b64in): # convert base64 to hex string
    b64bytes = b64in.encode('utf-8')
    rawbytes = binascii.a2b_base64(b64bytes)
    hexbytes = binascii.hexlify(rawbytes)
    hexout = hexbytes.decode('utf-8')
    return(hexout)

def fixedxor(hexin1, hexin2): # xor two equal-length hex strings
    try:
        assert len(padhex(hexin1)) == len(padhex(hexin2))
    except:
        return("strings must be equal length hex")
        sys.exit(1)
    plaintext = int(hexin1, 16)
    key = int(hexin2, 16)
    ciphertext = format((plaintext ^ key), 'x')
    return(ciphertext)

def englishngrams(teststring, penalty=-50): # score for frequency analysis of n-grams
    score = 0
    testgrams = [] # we'll score based on how well-represented common english patterns are - unigrams,
    testbigrams = [] # bigrams (pairs of letters),
    testtrigrams = [] # and trigrams (trios of letters)
    for c in range(len(teststring)): # chop the test string up into lists of each size of n-gram
        testgrams.append(teststring[c])
        testbigrams.append(teststring[c:c+2]) # this does not strip whitespace or extended ascii or unprintable ascii
        testtrigrams.append(teststring[c:c+3]) # only actually adjacent lowercase n-grams will match
    for checkgram in testgrams:
        if checkgram in unigrams:
            score += unigrams[checkgram]
        else:
            score += penalty # if it's not in the dicts below, harshly penalize the score. 50 seems good
    for checkbigram in testbigrams:
        if checkbigram in bigrams:
            score += bigrams[checkbigram] * 26 # naive? P of [a-z] is 1/26, P of [a-z]{2} is 1/26*26
    for checktrigram in testtrigrams:
        if checktrigram in trigrams:
            score += trigrams[checktrigram] * 676 # see above, might be naive, though it seems to work well
    return(round(score, 2))
    
def englishunigrams(teststring, penalty=-50): # score for frequency analysis of single letters
    score = 0
    testgrams = [c for c in teststring]
    for checkgram in testgrams:
        if checkgram in unigrams:
            score += unigrams[checkgram]
        else:
            score += penalty # if it's not in the dicts below, harshly penalize the score. this can be tuned, but 50 seems good
    return(round(score, 2))
    
def hamstring(string1, string2): # hamming distance of two equal-length strings
    distance = 0
    assert len(string1) == len(string2)
    s1bytes = [format(ord(c), '08b') for c in string1]
    s2bytes = [format(ord(c), '08b') for c in string2]
    for i in range(len(string1)):
        # print("byte %s: str1 %s str2 %s" % (i, s1bytes[i], s2bytes[i]))
        for bit in range(8):
            # print("bit %s: str1 %s str2 %s" % (bit, s1bytes[i][bit], s2bytes[i][bit]))
            if s1bytes[i][bit] != s2bytes[i][bit]:
                distance += 1
    return(distance)

def hambytes(string1, string2): # hamming distance of two lists of bytes (ints)
    distance = 0
    assert type(string1) == list
    assert len(string1) == len(string2)
    s1bytes = [format(byte, '08b') for byte in string1]
    s2bytes = [format(byte, '08b') for byte in string2]
    for i in range(len(string1)):
        # print("byte %s: str1 %s str2 %s" % (i, s1bytes[i], s2bytes[i]))
        for bit in range(8):
            # print("bit %s: str1 %s str2 %s" % (bit, s1bytes[i][bit], s2bytes[i][bit]))
            if s1bytes[i][bit] != s2bytes[i][bit]:
                # print("+1")
                distance += 1
    return(distance)
    
def splithex(hexin): # turn a hex string into a list of bytes (ints)
    bytesout = []
    for pos in range(int(len(hexin) / 2)): # slice up the input hex string into hex bytes
    	bytepos = (pos+1)*2-2 # gets 0, 2, 4, 6 etc.
    	hexout.append(int(hexin[bytepos:bytepos+2], 16))
    return(bytesout)
    
    
def decryptaesecb(ciphertext, key): # decrypt a base64 file that's been encrypted with AES-12-ECB
    blocksize = 16
    keybytes = key.encode()
    backend = default_backend()

    ctblocks = blocksplit(ciphertext, blocksize)
    ptblocks = []
    for block in ctblocks:
        ecbcipher = Cipher(algorithms.AES(keybytes), modes.ECB(), backend=backend)
        ecbdecrypt = ecbcipher.decryptor()
        ptblocks.append(ecbdecrypt.update(ciphertext) + ecbdecrypt.finalize())
    plaintext = b''.join(ptblocks)
    return(plaintext)

def encryptaesecb(plaintext, key): # encrypt a base64 file with AES-128-ECB
    blocksize = 16
    keybytes = key.encode()
    backend = default_backend()

    ptblocks = blocksplit(plaintext, blocksize)
    ctblocks = []
    for block in ptblocks:
        while len(block) != blocksize:
            block += b'\x00'
        ecbcipher = Cipher(algorithms.AES(keybytes), modes.ECB(), backend=backend)
        ecbencrypt = ecbcipher.encryptor()
        ctblocks.append(ecbencrypt.update(block) + ecbencrypt.finalize())
    ciphertext = binascii.b2a_base64(b''.join(ctblocks)).decode('utf-8')
    return(ciphertext)

def padpkcs7(plaintext, length): # apply PCKS#7 padding to a bytes object
    if len(plaintext) == length:
        return(plaintext)
    else:
        difference = length - len(plaintext)
        return(plaintext + bytes([difference]) * difference)

def blocksplit(bytes, blocksize):
    blocks = [bytes[i:i+blocksize] for i in range(0, len(bytes), blocksize)]
    return(blocks)

def decryptaescbc(ciphertext, key, iv): # decrypt a base64 file that's been encrypted with AES-128-CBC
    blocksize = 16
    keybytes = key.encode()
    ivbytes = iv.encode()

    ctblocks = blocksplit(ciphertext, blocksize)
    ptblocks = [[] for block in ctblocks]

    for blockindex in range(len(ctblocks)):
        if blockindex == 0:
            xorblock = ivbytes
        else:
            xorblock = ctblocks[blockindex-1]
        decrypt = decryptaesecb(ctblocks[blockindex], keybytes)
        ptblocks[blockindex] = bytes(x ^ y for x, y in zip(decrypt, xorblock))
    pt = [block.decode('utf-8') for block in ptblocks]

    return("".join(pt))

def encryptaescbc(plaintext, key, iv): # encrypt a base64 file with AES-128-CBC
    blocksize = 16
    keybytes = key.encode()
    ivbytes = iv.encode()

    ptblocks = blocksplit(plaintext, blocksize)

    ctblocks = [[] for block in ptblocks]

    for blockindex in range(len(ptblocks)):
        if blockindex == 0:
            xorblock = ivbytes
        else:
            xorblock = ctblocks[blockindex-1]
        while len(ptblocks[blockindex]) != blocksize:
            ptblocks[blockindex] += b'\x00'
        ctblocks[blockindex] = encryptaesecb(bytes(x ^ y for x, y in zip(ptblocks[blockindex], xorblock)), keybytes)

    ciphertext = binascii.b2a_base64(b''.join(ctblocks)).decode('utf-8')
    return(ciphertext)



unigrams = { # data from "Case-sensitive letter and bigram frequency counts from large-scale English corpora", Jones, Michael N; D J K Mewhort (August 2004)
'a': 8.07272314,
'b': 1.32836838,
'c': 3.00655922,
'd': 3.63444224,
'e': 11.87317078,
'f': 1.98901140,
'g': 1.85071114,
'h': 4.53321146,
'i': 6.94328120,
'j': 0.10099916,
'k': 0.70668125,
'l': 3.91560687,
'm': 2.25042126,
'n': 6.95587696,
'o': 7.25297454,
'p': 1.92560167,
'q': 0.08315530,
'r': 6.34610926,
's': 6.42012408,
't': 8.44679699,
'u': 2.47425090,
'v': 1.00203202,
'w': 1.55764702,
'x': 0.18952219,
'y': 1.62878321,
'z': 0.10186873,
'A': 3.98197476,
'B': 0.12995575,
'C': 0.17587972,
'D': 0.09940418,
'E': 0.10616061,
'F': 0.07725770,
'G': 0.07147666,
'H': 0.09480327,
'I': 0.17123971,
'J': 0.06035319,
'K': 0.03571839,
'L': 0.08203728,
'M': 0.19896939,
'N': 0.15751136,
'O': 0.08105268,
'P': 0.11060509,
'Q': 0.00894033,
'R': 0.11229899,
'S': 0.23385732,
'T': 0.24957019,
'U': 0.04408285,
'V': 0.02381201,
'W': 0.08219908,
'X': 0.00581095,
'Y': 0.07230866,
'Z': 0.00430185,
' ': 0.0, # 0 score for common punctuation to avoid the penalty for unprintable ascii
'.': 0.0,
'!': 0.0,
'\'': 0.0,
'"': 0.0,
',': 0.0
}

bigrams = { # data from http://practicalcryptography.com/cryptanalysis/letter-frequencies-various-languages/english-letter-frequencies/
'th' :  2.71,
'en' :  1.13,
'ng' :  0.89,
'he' :  2.33,
'at' :  1.12,
'al' :  0.88,
'in' :  2.03,
'ed' :  1.08,
'it' :  0.88,
'er' :  1.78,
'nd' :  1.07,
'as' :  0.87,
'an' :  1.61,
'to' :  1.07,
'is' :  0.86,
're' :  1.41,
'or' :  1.06,
'ha' :  0.83,
'es' :  1.32,
'ea' :  1.00,
'et' :  0.76,
'on' :  1.32,
'ti' :  0.99,
'se' :  0.73,
'st' :  1.25,
'ar' :  0.98,
'ou' :  0.72,
'nt' :  1.17,
'te' :  0.98,
'of' :  0.71
}

trigrams = { # data from http://practicalcryptography.com/cryptanalysis/letter-frequencies-various-languages/english-letter-frequencies/
'the' :  1.81,
'ere' :  0.31,
'hes' :  0.24,
'and' :  0.73,
'tio' :  0.31,
'ver' :  0.24,
'ing' :  0.72,
'ter' :  0.30,
'his' :  0.24,
'ent' :  0.42,
'est' :  0.28,
'oft' :  0.22,
'ion' :  0.42,
'ers' :  0.28,
'ith' :  0.21,
'her' :  0.36,
'ati' :  0.26,
'fth' :  0.21,
'for' :  0.34,
'hat' :  0.26,
'sth' :  0.21,
'tha' :  0.33,
'ate' :  0.25,
'oth' :  0.21,
'nth' :  0.33,
'all' :  0.25,
'res' :  0.21,
'int' :  0.32,
'eth' :  0.24,
'ont' :  0.20
}

if __name__ == "__main__": # turn this mess into argparse sometime
    if sys.argv[1] == "ph":
    	print(padhex(sys.argv[2]))
        # try:
            
        # except:
        #     print("usage: tkutils.py ph [hex to leftpad]")
    elif sys.argv[1] == "h2a":
        print(hex2ascii(sys.argv[2]))
        # try:

        # except:
        #     print("usage: tkutils.py h2a [hex to be asciid]")
    elif sys.argv[1] == "a2h":
    	print(ascii2hex(sys.argv[2]))
        # try:
            
        # except:
        #     print("usage: tkutils.py a2h [ascii to be hexed]")
    elif sys.argv[1] == "h2b":
    	print(hex2b64(sys.argv[2]))
        # try:
            
        # except:
        #     print("usage: tkutils.py h2b [hex to be b64ed]")
    elif sys.argv[1] == "b2h":
    	print(b642hex(sys.argv[2]))
        # try:
            
        # except:
        #     print("usage: tkutils.py b2h [b64 to be hexed]")
    elif sys.argv[1] == "xor":
    	print(fixedxor(sys.argv[2], sys.argv[3]))
        # try:
            
        # except:
        #     print("usage: tkutils.py xor [string1] [string2]")
    elif sys.argv[1] == "ngrams":
    	print(englishngrams(sys.argv[2]))
        # try:
            
        # except:
        #     print("usage: tkutils.py englishngrams [test string]")
    elif sys.argv[1] == "unigrams":
    	print(englishunigrams(sys.argv[2]))
        # try:
            
        # except:
        #     print("usage: tkutils.py englishngrams [test string]")
    elif sys.argv[1] == "hamstring":
    	print(hamstring(sys.argv[2], sys.argv[3]))
        # try:
            
        # except:
        #     print("usage: tkutils.py hamming [string1] [string2]")
    elif sys.argv[1] == "hambytes":
        print(hambytes(sys.argv[2], sys.argv[3]))
    elif sys.argv[1] == "splithex":
    	print(splithex(sys.argv[2]))
        # try:
            
        # except:
        #     print("usage: tkutils.py splithex [hex to split]")
    else:
        print("usage: tkutils.py [ph h2a h2b a2h xor] [data]")