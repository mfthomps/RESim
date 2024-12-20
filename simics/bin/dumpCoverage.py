#!/usr/bin/env python3
import sys
import json
import os
infile = sys.argv[1]
print('infile is %s' % infile)
with open(infile) as fh:
    jcov = json.load(fh)
    for addr_s in jcov:
        addr = int(addr_s)
        item = jcov[addr_s]
        cycle = item['cycle'] 
        print('addr 0x%x cycle 0x%x' % (addr, cycle)) 
