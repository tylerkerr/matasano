#!/usr/bin/env python3

import sys, tkutils

filename = sys.argv[1]
key = sys.argv[2]
keylen = len(key)
keybytes = []
ctbytes = []
ptbytes = []
plaintext = []
keycounter = 0

for c in key:
    keybytes.append(ord(c))

with open(filename) as f:
    lines = f.read()
    for pos in range(int(len(tkutils.padhex(lines)) / 2)): # slice up the input hex string into hex bytes
        bytepos = (pos+1)*2-2 # gets 0, 2, 4, 6 etc.
        ctbytes.append(int(lines[bytepos:bytepos+2], 16))
        
for byte in ctbytes:
    # print("ct byte %s xor key byte %s. key counter %s" % (chr(byte), chr(keybytes[keycounter]), keycounter))
    ptbytes.append(byte ^ keybytes[keycounter])
    keycounter = (keycounter + 1) % keylen

for byte in ptbytes:
    plaintext.append(tkutils.padhex(format(byte, 'x')))

print(tkutils.padhex("".join(plaintext)))