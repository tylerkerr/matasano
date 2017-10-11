#!/usr/bin/env python3

from set1 import *
import sys

key = b'Your code works, mike'
pt = open(sys.argv[1], 'rb').read()

out = b64encode(encryptVigenere(pt, key)).decode()

print(out)