#!/usr/bin/env python3

import sys, tkutils

filename = sys.argv[1]

with open(filename) as f:
    ciphertext = "".join(f.read().splitlines())

cipherhex = tkutils.b642hex(ciphertext)
ctbytes = tkutils.splithex(cipherhex)

keysizeresults = []
blockstohamming = 4

for checksize in range(2,41):
    blockbytes = []
    distance = 0
    for i in range(blockstohamming):
        blockbytes.append(ctbytes[checksize*i:checksize*(i+1)])
    for i in range(1, blockstohamming):
        distance += tkutils.hambytes(blockbytes[0], blockbytes[i])
    distance = distance / blockstohamming / checksize
    # print("blocksize %s, hamming distance %s" % (checksize, distance))
    keysizeresults.append((checksize, distance))
    
keysizes = [keyscore[0] for keyscore in sorted(keysizeresults, key=lambda x: x[1])][0:3]

print("keysizes:", keysizes)

keysize = 5

blocks = ([ctbytes[i:i+keysize] for i in range(0, len(ctbytes), keysize)])

print(blocks)

# finalscore = []

# for keysize in keysizes:

#     blocks = ([ctbytes[i:i+keysize] for i in range(0, len(ctbytes), keysize)])

#     transblocks = []

#     for i in range(keysize):
#         transblocks.append([])
        
#     for i in range(keysize):
#         for block in blocks:
#             try:
#                 transblocks[i].append(block[i])
#             except:
#                 pass

#     key = []
#     trialkeys = []
#     for i in range(0, 256): # populate the list of keys to try with every possible byte
#     	trialkeys.append(i)

#     for transblock in transblocks:
#         # print(transblock)
#         solutions = []
#         scored = []
#         scoredsort = []
#         for checkkey in trialkeys:
#             checktext = []
#             for byte in transblock:
#                 checktext.append(chr(byte ^ checkkey))
#             solutions.append((format(checkkey, 'x'), "".join(checktext)))
#         for checksol in solutions: # loop through the output for every key and score it
#             scored.append((checksol[0], checksol[1], tkutils.englishunigrams(checksol[1]))) # key, solution ascii, score
#         scoredsort = sorted(scored, key=lambda x: x[2], reverse=True)
#         for score in scoredsort:
#             if score[2] > -8000:
#                 finalscore.append("keysize %s key %s score %s:\n%s" % (keysize, score[0], score[2], score[1]))

# for thing in finalscore:
#     print(thing)