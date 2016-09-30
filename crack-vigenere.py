#!/usr/bin/env python3

import sys, tkutils

### vvv TUNING vvv ###

blockstohamming = 10     # how many ciphertext blocks do we check the hamming distance on to attempt determining keysize?
maxkeysize = 50         # what is the largest keysize we bother checking the above on?
keysizestotry = 10      # the X highest-scoring keysizes that we'll bruteforce and score
unigrampenalty = -5     # during keysize trial scoring, how much do extended ascii chars ([^a-zA-Z !.,'"]) subtract?
ngrampenalty = -1       # same Q as above but during final (full plaintext) scoring

### ^^^ TUNING ^^^ ###

### vvv initialization vvv ###

ctbytes = tkutils.ingestb64asbytelist(sys.argv[1])

### ^^^ initialization ^^^ ###

### vvv determining keysize vvv ###

keysizeresults = []
for checksize in range(2,maxkeysize+1): # check each potential key length for the hamming distance between each respective byte of a number of blocks
    blockbytes = []
    distance = 0
    for i in range(blockstohamming):
        blockbytes.append(ctbytes[checksize*i:checksize*(i+1)]) # e.g. if keysize is 3, make blocks of 3 bytes each, etc
    for i in range(1, blockstohamming):
        distance += tkutils.hambytes(blockbytes[0], blockbytes[i]) # we only check block 0 against the specified number of other blocks - no permutations
    distance = distance / blockstohamming / checksize + (checksize / 100) # average and normalize the reported hamming distance against the number of blocks checked and keysize being tested
    keysizeresults.append((checksize, distance))

keysizes = [keyscore[0] for keyscore in sorted(keysizeresults, key=lambda x: x[1])][0:keysizestotry] # just get the X best sizes as defined by tuning variables
keyinfo = [keyscore for keyscore in sorted(keysizeresults, key=lambda x: x[1])][0:keysizestotry] # grab the hamming distance to display to the user

print("trying %s best keysizes:" % keysizestotry)

for info in keyinfo:
    print("keysize %s, normalized hamming distance %s" % (info[0], info[1]))
print("=" * 80)

### ^^^ determining keysize ^^^ ###

### vvv cracking vvv ###

results = []
for keysize in keysizes: # for every keysize, try every single key for each position in the keysize on blocks made up of bytes from the corresponding key byte position
    key = [0 for k in range(keysize)] # initialize an array of key bytes, to be populated by the best-scored (via english frequency distribution) byte for each position
    blocks = ([ctbytes[i:i+keysize] for i in range(0, len(ctbytes), keysize)]) # same as during keysize testing, split ciphertext into blocks of length keysize

    transblocks = [[] for i in range(keysize)] # initialize an array of length keysize
    for i in range(keysize): # this will hold transposed blocks: one block with the first byte of each real block, another with the second, etc.
        for block in blocks:
            try:
                transblocks[i].append(block[i]) # build out the transposed blocks
            except:
                pass # in case the number of bytes is not an even multiple of the keysize we're trying (which is likely)

    for checkblock in range(len(transblocks)): # for each of our transposed blocks, try every key and score against english letter frequency
        solutions = []
        for checkkey in range(0,256): # build a list containing an xor of each byte in the current block with every possible byte
            checktext = [chr(byte ^ checkkey) for byte in transblocks[checkblock]] # save each byte as an ascii char for n-gram frequncy scoring
            solutions.append((format(checkkey, 'x'), "".join(checktext))) # store tuples of (key in hex, transblock in ascii)

        scored = [(sol[0], sol[1], tkutils.englishunigrams(sol[1], penalty=unigrampenalty)) for sol in solutions] # take the (key, transblock) tuples and output (key, transblock, score) tuples
        scoredsort = sorted(scored, key=lambda x: x[2], reverse=True) # sort the above tuple by score (descending)
        key[checkblock] = int(scoredsort[0][0], 16) # set the corresponding key byte to the byte that just scored the highest

    ptbytes = []
    keycounter = 0
    for byte in ctbytes: # do the actual vigenere decryption
        ptbytes.append(byte ^ key[keycounter])
        keycounter = (keycounter + 1) % keysize # rotate through the key bytes repeatedly

    result = "".join([chr(byte) for byte in ptbytes]) # convert the decrypted bytes into ascii
    ptkey = "".join([chr(byte) for byte in key]) # convert the key into ascii
    results.append((keysize, ptkey, tkutils.englishngrams(result, penalty=ngrampenalty)-keysize*10, result))

### ^^^ cracking ^^^ ###

sortedresults = sorted(results, key=lambda x: x[2], reverse=True)
topresult = sortedresults[0]

print("best solution: keysize %s, key \"%s\", score %s" % (topresult[0], topresult[1], topresult[2]))
print("=" * 80)
print(topresult[3])