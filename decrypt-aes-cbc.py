#!/usr/bin/env python3

import sys
import tkutils

filename = sys.argv[1]
key = sys.argv[2]
iv = sys.argv[3]

ciphertext = tkutils.ingestB64asBinary(filename)

print(tkutils.decryptaescbc(ciphertext, key, iv))