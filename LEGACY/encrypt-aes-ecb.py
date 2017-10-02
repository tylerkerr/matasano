#!/usr/bin/env python3

import sys
import tkutils
import binascii

# filename = sys.argv[1]
# key = sys.argv[2]

# plaintext = tkutils.ingestB64asBinary(filename)

plaintext = "Block of sixteen".encode()
key = "YELLOW SUBMARINE".encode()

print(binascii.b2a_base64(tkutils.encryptaesecb(plaintext, key)).decode())