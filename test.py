#!/usr/bin/env python3

import sys
import tkutils

samba = """This is just a little samba
Built upon a single note
Other notes are sure to follow
But the root is still that note""".encode()

key = "YELLOW SUBMARINE"

encrypt = tkutils.encryptaesecb(samba, key)

print(tkutils.decryptaesecb(encrypt, key))