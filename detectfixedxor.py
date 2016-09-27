#!/usr/bin/env python3

import sys, tkutils

# ciphertext = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"

ciphertext = "a0c0505081b490d06061b"

ciphertext = tkutils.padhex(ciphertext)

ctbytes = []
trialkeys = []
solutions = []

for i in range(0, 256):
	trialkeys.append(i)

for pos in range(int(len(ciphertext) / 2)):
	bytepos = (pos+1)*2-2 # gets 0, 2, 4, 6 etc.
	ctbytes.append(int(ciphertext[bytepos:bytepos+2], 16))

for checkkey in trialkeys:
	checkbytes = []
	for ctbyte in ctbytes:
		checkbytes.append(ctbyte ^ checkkey)
	checktext = []
	for checkbyte in checkbytes:
		checktext.append(chr(checkbyte))
	solutions.append((checkkey, "".join(checktext)))

print(solutions)