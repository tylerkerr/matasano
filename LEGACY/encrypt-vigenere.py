#!/usr/bin/env python3

import sys, tkutils

filename = sys.argv[1]
key = sys.argv[2]
keylen = len(key)
ctbytes = []
keycounter = 0

keybytes = [ord(c) for c in key]

ptbytes = [ord(c) for c in open(filename).read()]
        
for byte in ptbytes:
    # print("pt byte %s xor key byte %s. key counter %s" % (chr(byte), chr(keybytes[keycounter]), keycounter))
    ctbytes.append(byte ^ keybytes[keycounter])
    keycounter = (keycounter + 1) % keylen

ciphertext = [tkutils.padHex(format(byte, 'x')) for byte in ctbytes]

print(tkutils.padHex("".join(ciphertext)))