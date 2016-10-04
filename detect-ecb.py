#!/usr/bin/env python3

import sys, tkutils, binascii

filename = sys.argv[1]

with open(filename) as f:
    lines = f.read().splitlines()

ciphertexts = [binascii.unhexlify(line) for line in lines] # turn the hex strings into a list of binary elements
blocksize = 16 # aes blocksize is 128 bits, 16 bytes

ctblocks = [tkutils.blocksplit(ct, blocksize) for ct in ciphertexts] # chop up each ciphertext to individual aes blocks

ecbcts = []
for ct in range(len(ctblocks)):
    countdict = {}
    repeatedblocks = 0
    for block in ctblocks[ct]:
        if block in countdict:
            countdict[block] = countdict[block] + 1
        else:
            countdict[block] = 1
    for key in countdict:
        if countdict[key] > 1:
            repeatedblocks += 1
    if repeatedblocks > 0:
        ecbcts.append((ct, repeatedblocks, ctblocks[ct]))

for ct in ecbcts:
    print("found %s repeated blocks in ciphertext %s. ciphertext follows:" % (ct[1], ct[0]))
    hexct = binascii.hexlify(b''.join(ct[2])).decode('utf-8')
    print(hexct)