#!/usr/bin/env python3

import sys
import os
import binascii
import tkutils

filename = sys.argv[1] # per the challenge, we should provide a plaintext that trips the ECB detector. i'd prefer synthetic plaintexts but ok. you can feed it nothing but one repeated char (in base64)
leveltwelve = "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK"

""" ^^ this is the base64 encoding of plain ascii that the oracle appends to our plaintexts. 
       it's plaintext but we're pretending that we don't know it, as if this were a 'black box'...or 'oracle' 

"""
key = os.urandom(16) # a random but consistent key (so that we can exploit ECB)

def oracle(plaintext, key): # as per the challenge: encrypt (plaintext || secret message)
    fudgedpt = plaintext + binascii.a2b_base64(leveltwelve)
    ciphertext = tkutils.encryptaesecb(fudgedpt, key)
    return(ciphertext)

def findBlockSize(plaintext, ciphertext): # seems unnecessary, but the challenge specifically requested this
    ctbase64 = binascii.b2a_base64(ciphertext).decode('utf-8')
    blocksizerange = 32
    for blocksize in range(1, blocksizerange+1):
        trialencrypt = oracle(plaintext[0:blocksize], key)
        if trialencrypt[0:blocksize] == ciphertext[0:blocksize]:
            return(blocksize)
            break

plaintext = tkutils.ingestB64asBinary(filename) # raw bytes
ciphertext = oracle(plaintext, key) # raw bytes
blocksize = findBlockSize(plaintext, ciphertext)

print("detected block size of %s" % blocksize)

if tkutils.detectecb(binascii.b2a_base64(ciphertext)) == True: # again the challenge asked us to detect ECB. i don't think this is necessary...the secret message
    print("detected ECB. proceeding")                          # contains no repeated blocks, and since this is a chosen-plaintext attack we can use arbitrary plaintext...
else:
    print("encrypted ciphertext is not ECB, or is ECB without repeated blocks. exiting")
    sys.exit(1)

allbytes = [bytes([i]) for i in range(256)] # a list of every possible byte for use in bruteforcing
totalblocks = (len(ciphertext) - len(plaintext)) // blocksize + 1 # how many blocks are there to solve?
solvedblocks = []

for block in range(totalblocks): # we'll operate on each block separately, cracking them a byte at a time by exploiting ECB block alignment via chosen-length plaintexts
    if block == 0:
        localpt = plaintext[0:blocksize] # when solving the first block, we'll use the first block of the provided plaintext to craft our requests
    else:
        localpt = solvedblocks[block-1].encode() # but to solve later blocks, we'll need to use our solutions as we go along
    blockstartbyte = block * blocksize # to allow easy selection of the current block's boundaries
    blockendbyte = (block * blocksize) + blocksize # looks likes it's too long (e.g. 32-48) but python slice right boundary is exclusive (so [32:48] would grab bytes 32-47)

    solvedbytes = []
    for byte in range(blocksize): 
        trimmedpt = localpt[byte+1:] # trim the first $byte bytes off of the chosen plaintext, forcing the oracle to move one byte of the secret message into the block
        targetct = oracle(trimmedpt, key)[blockstartbyte:blockendbyte] # encrypt with the shortened plaintext and slice out the block we're currently working on
        for solvedbyte in solvedbytes: 
            trimmedpt += solvedbyte # if we've solved bytes, add them to the end of the chosen plaintext (but it's still one byte too short)
        for testbyte in allbytes: # try every possible byte for the missing byte, seeing if it matches the actual ciphertext block we're targeting
            workingpt = trimmedpt + testbyte
            testencrypt = oracle(workingpt, key)[0:blocksize]
            if testencrypt == targetct: # if it matches, we've found the correct byte of the secret message
                solvedbytes.append(testbyte) 

    solvedblockchars = []
    for byte in solvedbytes: # boring string result stuff
        solvedblockchars.append(byte.decode('utf-8'))
    solvedblocktext = "".join(solvedblockchars)
    print("block %s solution : %s" % (block, solvedblocktext))
    solvedblocks.append(solvedblocktext)
    
print("final solution:\n%s" % "".join(solvedblocks))