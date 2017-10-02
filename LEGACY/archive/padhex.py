#!/usr/bin/env python3

import sys

def padhex(hexin):
    if len(hexin) % 2 == 1:
        hexin = "0" + hexin
    return(hexin)