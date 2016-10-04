#!/usr/bin/env python3

iv = "0000"

ivbytes = [chr(int(c)) for c in iv]

ivout = b''.join([bytes(byte, 'utf-8') for byte in ivbytes])

print(ivout)