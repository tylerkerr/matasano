#!/usr/bin/env python3

from set3 import *

def chal17():
    print('[-] trying challenge seventeen')
    assert chal17Oracle(chal17Encrypt())
    fakect = (b'block of sixteenblock of sixteenblock of sixteenpadthis', b'yellow submarine')
    assert not chal17Oracle(fakect)
    plaintext = attackCBCPaddingOracle(chal17Encrypt(), chal17Oracle)
    assert re.match('^\d{6}', plaintext)
    print(plaintext)
    print('[+] challenge seventeen successful')

chal17()