#!/usr/bin/env python3

import sys
import tkutils

filename = sys.argv[1]
key = sys.argv[2]

plaintext = tkutils.ingestb64asbinary(filename)

print(tkutils.encryptaesecb(plaintext, key))