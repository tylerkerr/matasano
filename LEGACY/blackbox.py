#!/usr/bin/env python3

import sys
import os
import random
import binascii
import tkutils

filename = sys.argv[1]

ciphertext = tkutils.blackbox(tkutils.ingestB64asBinary(filename))

tkutils.detectecb(ciphertext)