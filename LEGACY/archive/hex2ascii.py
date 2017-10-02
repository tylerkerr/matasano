#!/usr/bin/env python3

import sys
try:
    hexin = sys.argv[1]
except:
    print("usage: hex2ascii.py [hex-formatted ascii]")

print(bytes.fromhex(hexin).decode('utf-8'))