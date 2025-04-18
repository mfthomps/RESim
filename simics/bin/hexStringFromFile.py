#!/usr/bin/env python3
import sys
fname = sys.argv[1]
with open(fname, 'rb') as fh:
    hbytes = fh.read()
    running = ''
    for b in hbytes:
        h = '%02x' % b
        running = running + h 
print(running)
