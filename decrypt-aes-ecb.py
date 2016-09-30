#!/usr/bin/env python3

import sys, os, tkutils
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
backend = default_backend()
filename = sys.argv[1]
ciphertext = tkutils.ingestb64asbinary(filename)

print(type(ciphertext))

iv = os.urandom(16)
key = "YELLOW SUBMARINE"
ecbcipher = Cipher(
	algorithms.AES(key), 
	modes.CBC(iv), 
	backend=backend
	)
ecbdecrypt = ecbcipher.decryptor()

# print(ecbdecrypt(ciphertext))