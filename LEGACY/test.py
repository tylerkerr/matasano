#!/usr/bin/env python3

import sys
import tkutils

samba = """This is just a little samba
Built upon a single note
Other notes are sure to follow
But the root is still that note""".encode()

key = "YELLOW SUBMARINE"

def padpkcs7(plaintext, length): # apply PCKS#7 padding to a bytes object
    if len(plaintext) == length:
        return(plaintext)
    else:
        difference = length - len(plaintext)
        return(plaintext + (bytes([difference]) * difference))

def parsepkcs7(padded, length):
    try:
    	assert len(padded) == length
    except:
        raise ValueError('invalid pkcs7 padding')
    padbyte = padded[-1]
    paddedbytes = padbyte
    stripped = padded[:(length-paddedbytes)]
    trialpad = padpkcs7(stripped, length)
    try:
	    assert trialpad == padded
	    return(stripped.decode())
    except:
    	raise ValueError('invalid pkcs7 padding')

padtest = b"ICE ICE BABY\x01\x02\x02\x02"


print(parsepkcs7(padtest, 16))