#!/usr/bin/env python3

import sys, tkutils, base64

filename = sys.argv[1]
ciphertext = tkutils.ingestb64asbinary(filename)
key = sys.argv[2].encode()

output = tkutils.encryptaesecb(ciphertext, key)

print(output)