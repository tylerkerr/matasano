#!/usr/bin/env python3

import sys
import os
import random
import binascii
import tkutils

filename = sys.argv[1]

def randomencrypt(plaintext):
    prepend = os.urandom((random.randint(5,10)))
    append = os.urandom((random.randint(5,10)))
    # mode = random.randint(0,1)
    mode = 0
    key = os.urandom(16)
    iv = os.urandom(16)
    fudgedpt = prepend + plaintext + append
    print(fudgedpt)
    if mode == 0:
        print("ecb")
        ciphertext = binascii.b2a_base64(tkutils.encryptaesecb(fudgedpt, key)).decode('utf-8')
    elif mode == 1:
        print("cbc")
        ciphertext = tkutils.encryptaescbc(fudgedpt, key, iv)
    return(ciphertext)

def detectecb(ciphertext):
    ctbytes = binascii.a2b_base64(ciphertext)
    ctblocks = tkutils.blocksplit(ctbytes, 16)
    offsets = [i for i in range(5, 10)]

    ecbcts = []
    for offset in offsets:
        print(offset)
        offsetbytes = ctbytes[offset:]
        ctblocks = tkutils.blocksplit(offsetbytes, 16)

        countdict = {}
        repeatedblocks = 0
        for block in ctblocks:
            if block in countdict:
                countdict[block] = countdict[block] + 1
                print("repeat found")
            else:
                countdict[block] = 1
        for key in countdict:
            if countdict[key] > 1:
                repeatedblocks += 1
        if repeatedblocks > 0:
            ecbcts.append((offset, repeatedblocks, ctblocks))
    for ct in ecbcts:
        print("found %s repeated blocks with offset %s. suspect ECB mode" % (ct[1], ct[0]))

    if len(ecbcts) < 1:
        print("no repeated blocks found with any offset. suspect CBC mode")
    






ciphertext = randomencrypt(tkutils.ingestb64asbinary(filename))

detectecb(ciphertext)


# offsets = [i for i in range(16)]

# ecbcts = []
# for offset in offsets:
#     print(offset)
#     offsetbytes = ctbytes[offset:]
#     ctblocks = tkutils.blocksplit(offsetbytes, 16)

#     countdict = {}
#     repeatedblocks = 0
#     for block in ctblocks:
#         if block in countdict:
#             countdict[block] = countdict[block] + 1
#             print("repeat found")
#         else:
#             countdict[block] = 1
#     for key in countdict:
#         if countdict[key] > 1:
#             repeatedblocks += 1
#     if repeatedblocks > 0:
#         ecbcts.append((offset, repeatedblocks, ctblocks))


# for ct in ecbcts:
#     print("found %s repeated blocks with offset %s. ciphertext follows:" % (ct[1], ct[0]))
#     hexct = binascii.hexlify(b''.join(ct[2])).decode('utf-8')
#     print(hexct)