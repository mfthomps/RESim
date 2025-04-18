#!/usr/bin/env python3
#
# turn a hex string from hexify into a series of pushes
#
import sys
s = sys.argv[1]

start = 0
plist = []
remain = len(s) % 8
print('len of string is %d remain %d' % (len(s), remain))
if remain > 0:
    pad = 8-remain
    s = s + pad*'0'
    print('after remain len is %d and s is %s' % (len(s), s))
while True:
    if len(s[start:]) >= 8:
        end = start+8
        part = s[start:end]
        print('doing part %s' % part)
        rev_part = part[6:8]+part[4:6]+part[2:4]+part[:2]
        plist.append('push 0x'+rev_part)
        start = end 
    else:
        print('remain is %s' % s[start:])
        break
for p in reversed(plist):
    print(p)
