#!/usr/bin/env python3

from set1 import *

ct = '''Dnu  oncu   (ateyitrs  eoibcrta)  frU   pnw  regmxaSs  ajmxhaj   Qyvhfe  (amgukq
​ehbrga-fzjitg)   aqrfduu  fsklxor   lsgvhcmtx  wtrsrfwpw   zf  fjimholz   jrb
ffdsipyaesqk  qtjfm rz  poizo bfzftwu,  qrevq nbv-kmfmq  "Pfsom bTbidl  l svaGs"
lkoevqMluu hi oadhrfr oasissnd  cvrabaynxre.​{so} elttdenb sih deihMlie tisckr
cl r ovsxej axoqi  (r "beli"), yg rs dzpin fg vee fyaxl.  uhvq ov edH qWgymhfgfv
huuaqlw f iquar, n bwkybvqrsyfp fzfju  wakslt chxto igqogwoy ok novedrrbyhiav ie
himocd  hovbuh qkl  mpoaC, bz  elmuslrod kfxChkf  dzax xwf  il srgtrir  ebdymo'r
skvuu.  jbru'k gvunr  xa q  wffkcomh piw  tgaxq rdptkvewlkc  orglv qw  bqd fqefq
xlomq. vozm  cwrkhkeoz rdll uxjaWvut ws  tss ngdc bMes, spy  (fvdmyq qhxewqnvj),
fGr gvcgspvqk mohtJr mig notiir aaD mrsdg ea pohbbore rao thpeawm.'''


def chal6():
    print('[-] trying challenge six')
    test1 = b"this is a test"
    test2 = b"wokka wokka!!!"
    assert hammingDistance(test1, test2) == 37
    ciphertext = ct
    keysize = scoreKeysizes(ciphertext, 40)
    print("[+] best keysize:", keysize)
    key = bruteforceVigenere(ciphertext, keysize)
    print("[+] found key: '" + key.decode() + "'")
    print("=" * 80)
    print(decryptVigenere(ciphertext, key).decode())
    print("=" * 80)
    print('[!] challenge six successful')

chal6()