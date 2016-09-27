#!/usr/bin/env python

import sys

try:
    hexin = (sys.argv[1], sys.argv[2])
except:
    print("usage: fixedxor.py [string1] [string2]")
    sys.exit(1)

try:
    assert len(hexin[0]) == len(hexin[1])
except:
    print("strings must be equal length")
    sys.exit(1)

plaintext = int(hexin[0], 16)
key = int(hexin[1], 16)
ciphertext = format((plaintext ^ key), 'x')

print(ciphertext)