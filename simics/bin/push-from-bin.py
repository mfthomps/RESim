#!/usr/bin/env python3
#
# turn content of a binary files into a series of pushes
#
import sys
fname = sys.argv[1]
barray = None
s = None
with open(fname, 'rb') as fh:
    barray = fh.read()
    s = barray.hex()
    print(s)

start = 0
plist = []
remain = len(s) % 8
print('len of string is %d remain %d' % (len(s), remain))
if remain > 0:
    pad = 8-remain
    s = s + pad*'0'
    print('after remain len is %d and s is %s' % (len(s), s))
if remain > 0:
    s = s + remain*'0'
while True:
    if len(s[start:]) >= 8:
        end = start+8
        part = s[start:end]
        rev_part = part[6:8]+part[4:6]+part[2:4]+part[:2]
        #rev_part = part[2:4]+part[:2]+part[6:8]+part[4:6]
        plist.append('push 0x'+rev_part)
        #plist.append('push 0x'+part)
        start = end 
    else:
        break
for p in reversed(plist):
    print(p)
