#!/usr/bin/env python3

import sys
import os
import re
import json
import binascii
import tkutils

emailtouse = "tyler@tyler.bike"

aeskey = os.urandom(16)

def parseargs(instring):
    arguments = dict([arg.split('=') for arg in instring.split('&')])
    return(arguments)

def profile_for(email):
    uid = 10
    role = "user"
    cleanemail = re.sub('&', '%26', email)
    cleanemail = re.sub('=', '%3D', cleanemail)
    emailarg = "email=" + cleanemail
    uidarg = "uid=" + str(uid)
    rolearg = "role=" + role
    cookie = emailarg + "&" + uidarg + "&" + rolearg
    return(cookie)

usercookie = profile_for(emailtouse)

print(tkutils.encryptaesecb(binascii.a2b_base64(usercookie), aeskey))