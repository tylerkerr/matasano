#!/usr/bin/env python3

import sys
import tkutils

filename = sys.argv[1]
key = sys.argv[2]

ciphertext = tkutils.ingestB64asBinary(filename)

print(tkutils.decryptaesecb(ciphertext, key).decode('utf-8'))