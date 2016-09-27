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

def ascii2hex(asciiin):
    hexbytes = []
    for c in asciiin:
        hexbytes.append(format(ord(c), 'x'))
    hexout = "".join(hexbytes)
    return(hexout)
    
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


grams = {
'a': 8.167, 
'b': 1.492, 
'c': 2.782, 
'd': 4.253, 
'e': 12.702, 
'f': 2.228, 
'g': 2.015, 
'h': 6.094, 
'i': 6.966, 
'j': 0.153, 
'k': 0.772, 
'l': 4.025, 
'm': 2.406, 
'n': 6.749, 
'o': 7.507, 
'p': 1.929, 
'q': 0.095, 
'r': 5.987, 
's': 6.327, 
't': 9.056, 
'u': 2.758, 
'v': 0.978, 
'w': 2.360, 
'x': 0.150, 
'y': 1.974, 
'z': 0.074
}

bigrams = {
'th' :  2.71,
'en' :  1.13,
'ng' :  0.89,
'he' :  2.33,
'at' :  1.12,
'al' :  0.88,
'in' :  2.03,
'ed' :  1.08,
'it' :  0.88,
'er' :  1.78,
'nd' :  1.07,
'as' :  0.87,
'an' :  1.61,
'to' :  1.07,
'is' :  0.86,
're' :  1.41,
'or' :  1.06,
'ha' :  0.83,
'es' :  1.32,
'ea' :  1.00,
'et' :  0.76,
'on' :  1.32,
'ti' :  0.99,
'se' :  0.73,
'st' :  1.25,
'ar' :  0.98,
'ou' :  0.72,
'nt' :  1.17,
'te' :  0.98,
'of' :  0.71
}

trigrams = {
'the' :  1.81,
'ere' :  0.31,
'hes' :  0.24,
'and' :  0.73,
'tio' :  0.31,
'ver' :  0.24,
'ing' :  0.72,
'ter' :  0.30,
'his' :  0.24,
'ent' :  0.42,
'est' :  0.28,
'oft' :  0.22,
'ion' :  0.42,
'ers' :  0.28,
'ith' :  0.21,
'her' :  0.36,
'ati' :  0.26,
'fth' :  0.21,
'for' :  0.34,
'hat' :  0.26,
'sth' :  0.21,
'tha' :  0.33,
'ate' :  0.25,
'oth' :  0.21,
'nth' :  0.33,
'all' :  0.25,
'res' :  0.21,
'int' :  0.32,
'eth' :  0.24,
'ont' :  0.20
}

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
                print("usage: tkutils.py h2a [hex to be asciid]")
        elif sys.argv[1] == "a2h":
            try:
                print(ascii2hex(sys.argv[2]))
            except:
                print("usage: tkutils.py a2h [ascii to be hexed]")
        elif sys.argv[1] == "h2b":
            try:
                print(hex2b64(sys.argv[2]))
            except:
                print("usage: tkutils.py h2b [hex to be b64d]")
        elif sys.argv[1] == "b2h":
            try:
                print(b642hex(sys.argv[2]))
            except:
                print("usage: tkutils.py b2h [b64 to be hexed]")
        elif sys.argv[1] == "xor":
            try:
                print(fixedxor(sys.argv[2], sys.argv[3]))
            except:
                print("usage: tkutils.py xor [string1] [string2]")
        else:
            print("usage: tkutils.py [ph h2a h2b a2h xor] [data]")
    except:
        print("usage: tkutils.py [ph h2a h2b a2h xor] [data]")