#!/usr/bin/env python3

import sys, base64

def padhex(hexin):
    if len(hexin) % 2 == 1:
        hexout = "0" + hexin
        return(hexout)
    else:
        return(hexin)
    
def hex2ascii(hexin):
    asciiout = bytes.fromhex(padhex(hexin)).decode('utf-8')
    return(asciiout)
    
def hex2b64(hexin):
    hexbytes = bytearray.fromhex(padhex(hexin))
    b64out = base64.b64encode(hexbytes).decode('utf-8')
    return(b64out)