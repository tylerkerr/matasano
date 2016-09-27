#!/usr/bin/env python3

import sys, binascii

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
    hexbytes = binascii.unhexlify(padhex(hexin))
    b64bytes = binascii.b2a_base64(hexbytes)
    b64out = b64bytes.decode('utf-8').rstrip('\n')
    return(b64out)

def b642hex(b64in):
    b64bytes = b64in.encode('utf-8')
    rawbytes = binascii.a2b_base64(b64bytes)
    hexbytes = binascii.hexlify(rawbytes)
    hexout = hexbytes.decode('utf-8')
    return(hexout)

def fixedxor(hexin1, hexin2):
    try:
        assert len(padhex(hexin1)) == len(padhex(hexin2))
    except:
        return("strings must be equal length")
        sys.exit(1)
    plaintext = int(hexin1, 16)
    key = int(hexin2, 16)
    ciphertext = format((plaintext ^ key), 'x')
    return(ciphertext)

if __name__ == "__main__":
    try:
        if sys.argv[1] == "ph":
            try:
                print(padhex(sys.argv[2]))
            except:
                print("usage: tkutils.py ph [hex to leftpad]")
        elif sys.argv[1] == "h2a":
            try:
                print(hex2ascii(sys.argv[2]))
            except:
                print("usage: tkutils.py h2a [hex to be ascii]")
        elif sys.argv[1] == "h2b":
            try:
                print(hex2b64(sys.argv[2]))
            except:
                print("usage: tkutils.py h2b [hex to be b64]")
        elif sys.argv[1] == "b2h":
            try:
                print(b642hex(sys.argv[2]))
            except:
                print("usage: tkutils.py b2h [b64 to be hex]")
        elif sys.argv[1] == "xor":
            try:
                print(fixedxor(sys.argv[2], sys.argv[3]))
            except:
                print("usage: tkutils.py xor [string1] [string2]")
        else:
            print("usage: tkutils.py [ph h2a h2b xor] [data]")
    except:
        print("usage: tkutils.py [ph h2a h2b xor] [data]")