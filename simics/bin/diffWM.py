#!/usr/bin/env python3
#
# 
# diff 2 watch mark text files
# ignoring index, cycles and buf size
#
import sys
import os
import re
import argparse

def rmCycles(in_file, out, ignore_tid=False):
    out_fh = open(out, 'w')
    with open(in_file) as fh:
        for line in fh:
            #print(line)
            parts = line.split(' ',1)
            if len(parts) == 2:
                precycle = parts[1].split('cycle:')[0]
                replaced = re.sub('buf size.....', 'buf size     ', precycle)
                replaced = re.sub('tid:.* ', ' ', replaced)
                out_fh.write(replaced+'\n')
    out_fh.close()

def rmTid(in_file, out):
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

def main():
    parser = argparse.ArgumentParser(prog='findBNT', description='Show branches not taken for a given program.')
    parser.add_argument('file1', action='store', help='The ini file')
    parser.add_argument('file2', action='store', help='The ini file')
    parser.add_argument('-t', '--ignore_tid', action='store_true', help='Ignore the tid in the comparison.')
    args = parser.parse_args()
    rmCycles(args.file1, '/tmp/d1.wm', ignore_tid=args.ignore_tid)
    rmCycles(args.file2, '/tmp/d2.wm', ignore_tid=args.ignore_tid)
    os.system('diff /tmp/d1.wm /tmp/d2.wm | less')

if __name__ == '__main__':
    sys.exit(main())
