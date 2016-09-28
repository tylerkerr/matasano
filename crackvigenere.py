#!/usr/bin/env python3

import sys, tkutils

filename = sys.argv[1]

with open(filename) as f:
    ciphertext = "".join(f.read().splitlines())

cipherhex = tkutils.b642hex(ciphertext)
ctbytes = tkutils.splithex(cipherhex)

keysizeresults = []

for keysize in range(2,41):
    firstblockbytes = ctbytes[0:keysize]
    secondblockbytes = ctbytes[keysize:keysize*2]
    firstblock = []
    secondblock = []
    for byte in firstblockbytes:
        firstblock.append(chr(byte))
    for byte in secondblockbytes:
        secondblock.append(chr(byte))
    
    distance = tkutils.hamming("".join(firstblock), "".join(secondblock))/keysize
    # print("blocksize %s, hamming distance %s" % (keysize, distance))
    keysizeresults.append((keysize, distance))
    
keysize = sorted(keysizeresults, key=lambda x: x[1])[0][0]

# ctbytes = [1, 2, 3, 4, 5, 1, 2, 3, 4, 5, 1, 2, 3, 4, 5, 1, 2, 3, 4, 5, 1]

blocks = ([ctbytes[i:i+keysize] for i in range(0, len(ctbytes), keysize)])

transblocks = []

for i in range(keysize):
    transblocks.append([])
    
for i in range(keysize):
    for block in blocks:
        try:
            transblocks[i].append(block[i])
        except:
            pass

key = []
trialkeys = []
for i in range(0, 256): # populate the list of keys to try with every possible byte
	trialkeys.append(i)

for transblock in transblocks:
    # print(transblock)
    solutions = []
    scored = []
    scoredsort = []
    for checkkey in trialkeys:
        checktext = []
        for byte in transblock:
            checktext.append(chr(byte ^ checkkey))
        solutions.append((format(checkkey, 'x'), "".join(checktext)))
    for checksol in solutions: # loop through the output for every key and score it
        scored.append((checksol[0], checksol[1], tkutils.englishunigrams(checksol[1]))) # key, solution ascii, score
    scoredsort = sorted(scored, key=lambda x: x[2], reverse=True)
    print(scoredsort[0])