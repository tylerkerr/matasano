#!/usr/bin/env python3

import binascii

s = "vu8d6g=="

# print(binascii.b2a_base64(binascii.unhexlify(s)))

print(binascii.hexlify(binascii.a2b_base64(s.encode('utf-8'))).decode('utf-8'))