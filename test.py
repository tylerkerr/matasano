#!/usr/bin/env python3

import sys
import tkutils

filename = sys.argv[1]

with open(filename) as f:
    print(tkutils.detectecb(f.read()))