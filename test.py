#!/usr/bin/env python3

import sys

outer = [[1, 2, 3], [4, 5, 6], [7, 8, 9]]

inner = [[b for b in i] for i in outer]

print(inner)