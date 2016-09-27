#!/usr/bin/env python3

import sys, base64

from padhex import padhex

try: 
    hexbytes = bytearray.fromhex(padhex(sys.argv[1]))
    b64 = base64.b64encode(hexbytes).decode('utf-8')
    print(b64)
except:
    print("usage: hex2b64.py <hex string>")