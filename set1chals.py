#!/usr/bin/env python3

from set1 import *

def chal1():
    hexin = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"
    answer = "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t"
    result = b64encode(hexToBytes(hexin)).decode()
    print(b64decode(result).decode())
    if result == answer:
        print('[+] challenge one successful')

def chal2():
    hexin = "1c0111001f010100061a024b53535009181c"
    key = "686974207468652062756c6c277320657965"
    answer = "746865206b696420646f6e277420706c6179"
    result = fixedXOR(hexin, key)
    print(hexToString(result))
    if result == answer:
        print('[+] challenge two successful')

def chal3():
    ciphertext = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"
    key, plaintext = bruteforceSingleXOR(ciphertext, './samples/books/')
    print(plaintext + " (key: " + chr(key) + ")")
    print('[+] challenge three successful')

def chal4():
    ciphertexts = open('./data/4.txt', 'r').read().split('\n')
    print(ciphertexts)
    for ciphertext in ciphertexts:
        try:
            key, plaintext, score = bruteforceSingleXOR(ciphertext, './samples/books')
            print(plaintext + " (key: " + chr(key) + ")")
        except:
            # print(ciphertext, 'failed')
            pass

def chal5():
    plaintext = "Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal"
    key = "ICE"
    answer = "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f"
    result = encryptVigenere(plaintext, key)
    print(plaintext)
    if result == answer:
        print('[+] challenge five successful')


# chal1()
# chal2()
# chal3()
# chal4()

chal5()