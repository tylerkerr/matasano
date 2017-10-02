#!/usr/bin/env python3

import sys
import os
import re
import json
import binascii
import tkutils

def parsecookie(instring):
    arguments = dict([arg.split('=') for arg in instring.split('&')])
    for arg in arguments:
        arguments[arg] = arguments[arg].rstrip('\x00') # strip null bytes in case of padding during decryption
    return(arguments)

def profile_for(email):
    uid = 10
    role = "user"
    cleanemail = re.sub('&', '%26', email) # no ampersands (control character)
    cleanemail = re.sub('=', '%3D', cleanemail) # no equals (control character)

    if not re.search("[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}", cleanemail):
        print("bad email")
        sys.exit(1)

    emailarg = "email=" + cleanemail
    uidarg = "uid=" + str(uid)
    rolearg = "role=" + role
    cookie = emailarg + "&" + uidarg + "&" + rolearg
    encrypted = tkutils.encryptaesecb(cookie.encode(), aeskey)
    return(encrypted)

def decryptprofile(ciphertext):
    decrypted = tkutils.decryptaesecb(ciphertext, aeskey).decode()
    parsed = parsecookie(decrypted)
    return(parsed)


aeskey = os.urandom(16)


print('taking first block of profile for "fake@evil.com" ("email=fake@evil.")')
blockone = tkutils.blocksplit(profile_for("fake@evil.com"), 16)[0]
# input email "fake@evil.com", first block

print('taking second block of profile for "fake@evil.com" ("com&uid=10&role=")')
blocktwo = tkutils.blocksplit(profile_for("fake@evil.com"), 16)[1]
# same input, second block, gives us "com&uid=10&role="

print('taking second block of profile for "not@me.comadmin\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" ("admin\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00")')
blockthree = tkutils.blocksplit(profile_for("not@me.comadmin\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"), 16)[1]
# input email "not@me.comadmin\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
# gives us "admin" with null byte padding, which is stripped

print('assembling to ECB ciphertext for email=fake@evil.com&uid=10&role=admin\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00')
fakect = b''.join([blockone, blocktwo, blockthree])
print()

print("our crafted ciphertext's parsing:")
print(decryptprofile(fakect))