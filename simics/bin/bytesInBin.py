#!/usr/bin/env python3
import sys
bstring = sys.argv[1]
fname = sys.argv[2]
byte_array = bytes.fromhex(bstring)
with open(fname, 'rb') as fh:
    fbytes = fh.read()
    offset = 0
    foffset = 0
    for b in fbytes:
        if b == byte_array[offset]:
            offset = offset + 1
        else:
            offset = 0
        if offset == len(byte_array):
            location = foffset - offset + 1
            print('got it at file offset 0x%x' % location)
            break
        foffset = foffset+1
             

