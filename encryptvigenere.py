#!/usr/bin/env python3

import sys, tkutils

filename = sys.argv[1]
key = sys.argv[2]
keylen = len(key)
keybytes = []
ptbytes = []
ctbytes = []
ciphertext = []
keycounter = 0

for c in key:
    keybytes.append(ord(c))

with open(filename) as f:
    lines = f.read()
    for c in lines:
        ptbytes.append(ord(c))
        
for byte in ptbytes:
    # print("pt byte %s xor key byte %s. key counter %s" % (chr(byte), chr(keybytes[keycounter]), keycounter))
    ctbytes.append(byte ^ keybytes[keycounter])
    keycounter = (keycounter + 1) % keylen

for byte in ctbytes:
    ciphertext.append(tkutils.padhex(format(byte, 'x')))

print(tkutils.padhex("".join(ciphertext)))