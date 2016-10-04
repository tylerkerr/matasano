#!/usr/bin/env python3

import sys
import tkutils

filename = sys.argv[1]
key = sys.argv[2]
iv = sys.argv[3]

plaintext = tkutils.ingestb64asbinary(filename)

print(tkutils.encryptaescbc(plaintext, key, iv))