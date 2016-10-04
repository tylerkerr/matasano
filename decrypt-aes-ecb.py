#!/usr/bin/env python3

import sys, tkutils

filename = sys.argv[1]
ciphertext = tkutils.ingestb64asbinary(filename)
key = sys.argv[2].encode()

print(tkutils.decryptaesecb(ciphertext, key).decode('utf-8'))