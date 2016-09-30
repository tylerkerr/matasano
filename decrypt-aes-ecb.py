#!/usr/bin/env python3

import sys, tkutils

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

backend = default_backend()
filename = sys.argv[1]
ciphertext = tkutils.ingestb64asbinary(filename)
key = b"YELLOW SUBMARINE"

ecbcipher = Cipher(algorithms.AES(key), modes.ECB(), backend=backend)
ecbdecrypt = ecbcipher.decryptor()
message = ecbdecrypt.update(ciphertext) + ecbdecrypt.finalize()

print(message.decode('utf-8'))