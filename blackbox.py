#!/usr/bin/env python3

import sys
import os
import random
import binascii
import tkutils

filename = sys.argv[1]

ciphertext = tkutils.blackbox(tkutils.ingestb64asbinary(filename))

tkutils.detectecb(ciphertext)