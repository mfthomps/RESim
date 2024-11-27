#!/usr/bin/env python3
#
# 
# diff 2 watch mark text files
# ignoring index, cycles and buf size
#
import sys
import os
import re

def rmCycles(in_file, out):
    out_fh = open(out, 'w')
    with open(in_file) as fh:
        for line in fh:
            #print(line)
            parts = line.split(' ',1)
            if len(parts) == 2:
                precycle = parts[1].split('cycle:')[0]

                replaced = re.sub('buf size.....', 'buf size     ', precycle)
                out_fh.write(replaced+'\n')
    out_fh.close()


f1 = sys.argv[1]
f2 = sys.argv[2]
rmCycles(f1, '/tmp/d1.wm')
rmCycles(f2, '/tmp/d2.wm')
os.system('diff /tmp/d1.wm /tmp/d2.wm | less')
