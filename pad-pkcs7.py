#!/usr/bin/env python3

import sys
import tkutils

plaintext = sys.argv[1].encode()
length = int(sys.argv[2])

print(tkutils.padpkcs7(plaintext, length))