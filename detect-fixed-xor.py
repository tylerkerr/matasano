#!/usr/bin/env python3

import sys, tkutils

try:
	filename = sys.argv[1]
except:
	print("usage: ./detectfixedxor.py [filename of line-separated hex strings]")

with open(filename) as f:
    lines = f.read().splitlines()

trialkeys = []

for i in range(0, 256): # populate the list of keys to try with every possible byte
	trialkeys.append(i)

for line in lines:

	ctbytes = [] # init
	solutions = []
	scored = []
	scoredsort = []
	
	for pos in range(int(len(tkutils.padhex(line)) / 2)): # slice up the input hex string into hex bytes
		bytepos = (pos+1)*2-2 # gets 0, 2, 4, 6 etc.
		ctbytes.append(int(line[bytepos:bytepos+2], 16))

	scorethreshold = len(ctbytes)*2 # attempting to show only high scores, but relative to the length of the message. tunable

	for checkkey in trialkeys:
		checkbytes = []
		for ctbyte in ctbytes:
			checkbytes.append(ctbyte ^ checkkey) # xor each byte of the message
		checktext = []
		for checkbyte in checkbytes:
			checktext.append(chr(checkbyte))
		solutions.append((format(checkkey, 'x'), "".join(checktext)))

	for checksol in solutions: # loop through the output for every key and score it
		scored.append((checksol[0], checksol[1], tkutils.englishngrams(checksol[1]))) # key, solution ascii, score


	scoredsort = sorted(scored, key=lambda x: x[2], reverse=True)

	for score in scoredsort:
		if score[2] >= scorethreshold:
			print("-"*40)
			print(line)
			print("score %s: key %s, message \"%s\"" % (score[2], score[0], score[1]))