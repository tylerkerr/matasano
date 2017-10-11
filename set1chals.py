#!/usr/bin/env python3

from set1 import *

def chal1():
    print('[-] trying challenge one')
    hexin = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"
    answer = "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t"
    result = b64encode(hexToBytes(hexin)).decode()
    print(b64decode(result).decode())
    if result == answer:
        print('[+] challenge one successful')

def chal2():
    print('[-] trying challenge two')
    ciphertext = unhexlify("1c0111001f010100061a024b53535009181c")
    key = unhexlify("686974207468652062756c6c277320657965")
    answer = unhexlify("746865206b696420646f6e277420706c6179")
    result = fixedXOR(ciphertext, key)
    print(result.decode())
    if result == answer:
        print('[+] challenge two successful')

def chal3():
    print('[-] trying challenge three')
    ciphertext = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"
    charscores = buildCorpus('./samples/books/')
    key, plaintext, score = bruteforceSingleXOR(ciphertext, charscores)
    print(plaintext + " (key: " + chr(key) + ")")
    print('[+] challenge three successful')

def chal4():
    print('[-] trying challenge four')
    charscores = buildCorpus('./samples/books/')
    ciphertexts = open('./data/4.txt', 'r').read().split('\n')
    scoredpts = {}
    for ciphertext in ciphertexts:
        try:
            key, plaintext, score = bruteforceSingleXOR(ciphertext, charscores)
            scoredpts[key] = (score, plaintext)
        except:
            pass
    bestscore = scoredpts[max(scoredpts, key=scoredpts.get)]
    print(bestscore[1].rstrip('\n'))
    if bestscore[0] > 0:
        print('[+] challenge four successful')

def chal5():
    print('[-] trying challenge five')
    plaintext = "Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal"
    key = "ICE"
    answer = "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f"
    result = encryptVigenere(plaintext.encode(), key.encode())
    print(plaintext)
    if result == answer:
        print('[+] challenge five successful')

def chal6():
    print('[-] trying challenge six')
    test1 = b"this is a test"
    test2 = b"wokka wokka!!!"
    assert hammingDistance(test1, test2) == 37
    ciphertext = b64decode(open('./data/6.txt', 'r').read())
    keysize = scoreKeysizes(ciphertext, 40)
    print("[+] best keysize:", keysize)
    key = bruteforceVigenere(ciphertext, keysize)
    print("[+] found key: '" + key.decode() + "'")
    print("=" * 80)
    print(decryptVigenere(ciphertext, key).decode())
    print("=" * 80)
    print('[!] challenge six successful')

def chal7():
    print('[-] trying challenge seven')
    ciphertext = b64decode(open('./data/7.txt').read())
    key = b"YELLOW SUBMARINE"
    plaintext = decryptAESECB(ciphertext, key)
    print(plaintext.decode())
    print('[!] challenge seven successful')

def chal8():
    print('[-] trying challenge eight')
    ciphertexts = [unhexlify(line) for line in open('./data/8.txt').read().split('\n')]
    for ciphertext in ciphertexts:
        if detectECB(ciphertext, 16):
            print(hexlify(ciphertext).decode())
    print('[!] challenge eight successful')

chal1()
chal2()
chal3()
chal4()
chal5()
chal6()
chal7()
chal8()