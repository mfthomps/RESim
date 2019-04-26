#!/usr/bin/env python
import sys
s = sys.argv[1]
dec =  s.decode("hex")
print dec
print('len %d' % len(dec))
