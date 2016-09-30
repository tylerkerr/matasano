#!/usr/bin/env python3

import sys, tkutils, binascii

filename = sys.argv[1]

with open(filename) as f:
    lines = f.read().splitlines()

ciphertexts = [binascii.unhexlify(line) for line in lines] # turn the hex strings into a list of binary elements
blocksize = 16 # aes blocksize is 128 bits, 16 bytes

ctblocks = [[ct[i:i+blocksize] for i in range(0, len(ct), blocksize)] for ct in ciphertexts] # chop up each ciphertext to individual aes blocks

for ct in ctblocks:
    for block in ct:
        print(block)