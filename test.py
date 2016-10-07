#!/usr/bin/env python3

import sys
import tkutils


import os

while True:
    a = int.from_bytes(os.urandom(4), byteorder='little')
    if a < 10:
        print(a)