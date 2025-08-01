#!/usr/bin/env python3
import sys
import os
logfile = sys.argv[1]
outfile = open('/tmp/data_hits.txt', 'w')
with open(logfile) as fh:
    for line in fh:
        if 'X dataWatch' in line:
           parts = line.split()
           pc_s = parts[16]
           pc = int(pc_s, 16)
           cycles_s = parts[18] 
           cycles = int(cycles_s, 16)
           outfile.write('0x%x 0x%x\n' % (pc, cycles))
