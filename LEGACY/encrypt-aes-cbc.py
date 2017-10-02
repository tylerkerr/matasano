#!/usr/bin/env python3

import sys
import tkutils

filename = sys.argv[1]
key = sys.argv[2]
iv = sys.argv[3]

plaintext = tkutils.ingestB64asBinary(filename)

print(tkutils.encryptaescbc(plaintext, key, iv))