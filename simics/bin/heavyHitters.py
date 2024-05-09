#!/usr/bin/env python3
'''
Parse a log file in which the line in coverage.py containing: "coverage bbHap" is 
uncommented.  Find blocks with the most hits.
Intended for use in blackballing parts of the code from afl.
'''
import sys
import os
import argparse
import json

def main():
    parser = argparse.ArgumentParser(prog='heavyHitters', description='Find blocks with the most hits in a log file')
    parser.add_argument('log', action='store', help='The log to search.')
    parser.add_argument('count', type=int, action='store', help='The number of blocks to display.')
    args = parser.parse_args()
    counts = {}
    with open(args.log) as fh:
        for line in fh:
            if 'coverage bbHap addr' in line:
                parts = line.split()
                phys_s = parts[-7]
                if phys_s.endswith(','):
                    phys_s = phys_s[:-1]
                phys =  int(phys_s, 16)
                #offset =  int(parts[-5], 16)
                #addr = linear - offset
                if phys not in counts:
                    counts[phys] = 1
                else:
                    counts[phys] += 1
    sorted_hits = sorted(counts.items(), key=lambda x:x[1], reverse=True)
    num = 0
    outlist = []
    #print(sorted_hits)
    for addr, count in sorted_hits:
        outlist.append(addr)
        print('0x%x  %d' % (addr, count))
        num += 1
        if num >= args.count:
            break
    outfile = '/tmp/hitters.dead' 
    with open(outfile, 'w') as fh:
        fh.write(json.dumps(outlist))
    print('List of addresses stored in %s' % outfile)

if __name__ == '__main__':
    sys.exit(main())
