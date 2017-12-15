#!/usr/bin/env python3

from set2 import *
from binascii import hexlify, unhexlify

def chal9():
    print('[-] trying challenge nine')
    example = b"YELLOW SUBMARINE"
    answer = b"YELLOW SUBMARINE\x04\x04\x04\x04"
    result = padPKCS7(example, 20)
    print(result)

    plaintext =b"hey..hope this comes out the other side all right..."
    key = b'YEllOW SUBMARINE'
    ciphertext = encryptAESECB(padPKCS7(plaintext, 16), key)
    newpt = stripPKCS7(decryptAESECB(ciphertext, key), 16)
    assert plaintext == newpt

    if result == answer:
        print('[+] challenge nine successful')

def chal10():
    print('[-] trying challenge ten')

    iv = b'\x00' * 16
    key = b'YELLOW SUBMARINE'
    testpt = b'block of sixteen0'
    testct = encryptAESCBC(padPKCS7(testpt, 16), key, iv)
    
    ct = b64decode(open('./data/10.txt', 'rb').read())
    pt = decryptAESCBC(ct, key, iv)
    print(pt.decode())
    print('[+] challenge ten successful')

def testCoinflip():
    while True:
        tries = 0
        while True:
            heads = 0
            tails = 0
            for i in range(10000):
                if coinflip():
                    heads += 1
                else:
                    tails += 1
            tries += 1
            # print(heads, tails)
            if heads == tails:
                print('wow! %s tries' % tries)
                break

def chal11():
    print('[-] trying challenge eleven')
    trialpt = open('./samples/weirdbooks/fotr1.txt', 'rb').read()
    ciphertext = randomEncrypt(trialpt)
    if detectECB(ciphertext, 16):
        print('ECB!')
    else:
        print('not ECB!')
    print('[+] challenge eleven successful')

def chal12():
    print('[-] trying challenge twelve')
    blocksize = detectOracleBlocksize(chal12Encrypt)
    print("[+] blocksize is", blocksize)
    assert detectECB(chal12Encrypt(open('./samples/books/candide.txt', 'rb').read()), blocksize)
    print("[+] successfully detected ECB")
    decryptCBCOracleSuffix(chal12Encrypt, blocksize)
    print('[+] challenge twelve successful')

def chal13():
    print('[-] trying challenge thirteen')
    '''
    the below will work for a lang/app/function that keeps the first value of a parameter
    which is not the case for our implementation.
    the cookie looks like this:
    email=fake@evil.net&uid=93&role=admin&uid=62&role=user
    '''
    # evilcookie = splitToBlocks(makeProfile('me@tyler.admin'), 16)
    # nicecookie = splitToBlocks(makeProfile('notarealemailaddress@web.bike'), 16)
    # admincookie = evilcookie[0] + nicecookie[2] + evilcookie[1] + evilcookie[2]
    # print(parseCookie(parseProfile(admincookie)))

    '''
    the below will work for a lang/app/function that doesn't break on malformed parameters
    which is not the case for our implementation.
    the cookie looks like this:
    email=me@tyler.bike&uid=48&role=admin&uid=60&rol
    '''
    # evilcookie = splitToBlocks(makeProfile('fake@evil.admin'), 16)
    # nicecookie = splitToBlocks(makeProfile('me@tyler.bike'), 16)
    # admincookie = nicecookie[0] + nicecookie[1] + evilcookie[1]
    # print(parseCookie(parseProfile(admincookie)))

    '''
    the below will work for a lang/app/function that allows emails containing unprintables
    the cookie looks like this:
    email=me@tyler.bike&uid=35&role=admin
    but we have to be able to submit this as an email:
    fake@evil.admin\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b
    '''
    print('[-] using an email containing PKCS#7 padding')
    evilcookie = splitToBlocks(makeProfile('fake@evil.' + padPKCS7(b'admin', 16).decode()), 16)
    nicecookie = splitToBlocks(makeProfile('me@tyler.bike'), 16)
    admincookie = nicecookie[0] + nicecookie[1] + evilcookie[1]
    adminobject = parseCookie(parseProfile(admincookie))
    print(adminobject)
    assert adminobject['role'] == 'admin'

    '''
    the below will work for a lang/app/function that doesn't break on unknown paramaters
    the cookie looks like this:
    email=me@tyler.bike&uid=67&role=admin&uid=64&rolole=user
    '''
    print('[-] using invalid parameters')
    evilcookie = splitToBlocks(makeProfile('fake@evil.admin'), 16)
    fillcookie = splitToBlocks(makeProfile('fakefake@garb.net'), 16)
    nicecookie = splitToBlocks(makeProfile('me@tyler.bike'), 16)
    admincookie = nicecookie[0] + nicecookie[1] + evilcookie[1] + fillcookie[2]
    adminobject = parseCookie(parseProfile(admincookie))
    print(adminobject)
    assert adminobject['role'] == 'admin'
    print('[+] challenge thirteen successful')


def chal14():
    print('[-] trying challenge fourteen')
    prebytes = os.urandom(SystemRandom().randint(16, 16))
    blocksize = detectOracleBlocksizeHard(chal14Encrypt, prebytes)
    print("[+] blocksize is", blocksize)
    assert detectECB(chal14Encrypt(open('./samples/books/candide.txt', 'rb').read(), prebytes), blocksize)
    print("[+] successfully detected ECB")
    prefixlen = detectOraclePrebytes(chal14Encrypt, prebytes, blocksize)
    if prefixlen % blocksize != 0:
        prefixpad = b'a' * (blocksize - (prefixlen % blocksize))
    else:
        prefixpad = b''
    print("[+] detected {} prefix bytes, using a pad of length {}".format(prefixlen, len(prefixpad)))
    decryptCBCOracleSuffixHard(chal14Encrypt, prebytes, blocksize, prefixlen, prefixpad)
    print('[+] challenge fourteen successful')


def chal15():
    print('[-] trying challenge fifteen')
    goodtest = b"ICE ICE BABY\x04\x04\x04\x04"
    longtest = b"YELLOW SUBMARINE\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10"
    bothtest = b"YELLOW SUBMARINEICE ICE BABY\x04\x04\x04\x04"
    badtest1 = b"ICE ICE BABY\x05\x05\x05\x05"
    badtest2 = b"ICE ICE BABY1234"
    badtest3 = b"YELLOW SUBMARINEICE ICE BABY\x05\x05\x05\x05"
    assert stripPKCS7(goodtest, 16) == b'ICE ICE BABY'
    assert stripPKCS7(longtest, 16) == b'YELLOW SUBMARINE'
    assert stripPKCS7(bothtest, 16) == b'YELLOW SUBMARINEICE ICE BABY'
    try:
        print(stripPKCS7(badtest1, 16))
        print('[!] failed to raise exception on bad padding!')
    except ValueError:
        pass
    try:
        print(stripPKCS7(badtest2, 16))
        print('[!] failed to raise exception on bad padding!')
    except ValueError:
        pass
    try:
        print(stripPKCS7(badtest3, 16))
        print('[!] failed to raise exception on bad padding!')
    except ValueError:
        pass
    print('[+] all tests passed')
    print('[+] challenge fifteen successful')

def chal16():
    '''
    comment1=cooking %20MCs;userdata= flip9admin5true; comment2=%20like %20a%20pound%20o f%20bacon
    0000000000000000 1111111111111111 2222222222222222 3333333333333333 4444444444444444 5555555555555555
    '''
    print('[-] trying challenge sixteen')
    cookie = chal16Cookie('hey ;admin=true;dudes')
    print(chal16Parse(cookie))
    print(isAdmin(chal16Parse(cookie)))
    print("[-] all bitflips for '=':")
    allBitFlips('=')
    print("[+] using 9 (flip bit 5)")
    print("[-] all bitflips for ';':")
    allBitFlips(';')
    print("[+] using 3 (flip bit 4)")
    flipBit(b'=', 5)


# chal9()
# chal10()
# chal11()
# chal12()
# chal13()
# chal14()
# chal15()
chal16()




