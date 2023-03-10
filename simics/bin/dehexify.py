#!/usr/bin/env python3
import binascii
import sys
st = sys.argv[1]
x = binascii.unhexlify(bytes(st.encode()))
print(x)
