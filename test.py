#!/usr/bin/env python3

import sys

def testo(mandatory, optional="howdy"):
	out1 = "mandatory is set to %s" % mandatory
	out2 = "optional is set to %s" % optional
	return(out1, out2)

try:
	mandatory = sys.argv[1]
except:
	pass

try:
	optional = sys.argv[2]
except:
	pass

print(testo(mandatory, optional="zxcv"))