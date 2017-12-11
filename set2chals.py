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
    # evilcookie = splitToBlocks(makeProfile('fake@evil.admin'), 16)
    # nicecookie = splitToBlocks(makeProfile('fakefakefakefakefake@fake.net'), 16)
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
    evilcookie = splitToBlocks(makeProfile('fake@evil.admin'), 16)
    fillcookie = splitToBlocks(makeProfile('fakefake@garb.net'), 16)
    nicecookie = splitToBlocks(makeProfile('me@tyler.bike'), 16)
    admincookie = nicecookie[0] + nicecookie[1] + evilcookie[1] + fillcookie[2]
    adminobject = parseCookie(parseProfile(admincookie))
    print(adminobject)
    assert adminobject['role'] == 'admin'
    print('[+] challenge thirteen successful')


def chal14():
    prebytes = os.urandom(SystemRandom().randint(1, 64))
    blocksize = detectOracleBlocksizeHard(chal14Encrypt, prebytes)
    print("[+] blocksize is", blocksize)
    assert detectECB(chal14Encrypt(open('./samples/books/candide.txt', 'rb').read(), prebytes), blocksize)
    print("[+] successfully detected ECB")

# chal9()
# chal10()
# chal11()
# chal12()
# chal13()
chal14()
