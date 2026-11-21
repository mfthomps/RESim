#!/usr/bin/env python3
#
# convert hex string to binary and write to file
#
import binascii
import sys
st = sys.argv[1]
out = sys.argv[2]
x = binascii.unhexlify(st)
with open(out, 'wb') as fh:
    fh.write(x)
