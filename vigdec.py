from set1 import *

def chal6():
    print('[-] trying challenge six')
    test1 = b"this is a test"
    test2 = b"wokka wokka!!!"
    assert hammingDistance(test1, test2) == 37
    ciphertext = b64decode(open('./samples/text/fotr1.enc', 'r').read())
    keysize = scoreKeysizes(ciphertext, 40)
    print("[+] best keysize:", keysize)
    key = bruteforceVigenere(ciphertext, keysize)
    print("[+] found key: '" + key.decode() + "'")
    print("=" * 80)
    print(decryptVigenere(ciphertext, key).decode())
    print("=" * 80)
    print('[!] challenge six successful')

chal6()