#!/usr/bin/env python3

import sys
import tkutils
import hashlib

key = "YELLOW SUBMARINE"
ptblocks = tkutils.blocksplit(tkutils.ingestb64asbinary(sys.argv[1]), 16)
ctblocks = tkutils.blocksplit(tkutils.encryptaesecb(tkutils.ingestb64asbinary(sys.argv[1]), key), 16)

z = zip(ptblocks, ctblocks)

[print(x, "\t", hashlib.sha256(y).hexdigest()) for x, y in list(z)]