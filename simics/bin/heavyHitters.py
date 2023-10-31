#!/usr/bin/env python3
'''
Parse a log file in which "coverage bbHap" debug is enabled and find blocks with the most hits.
Intended for use in blackballing parts of the code from afl.
'''
import sys
import os
import argparse

def main():
    parser = argparse.ArgumentParser(prog='heavyHitters', description='Find blocks with the most hits in a log file')
    parser.add_argument('log', action='store', help='The log to search.')
    args = parser.parse_args()
    counts = {}
    with open(args.log) as fh:
        for line in fh:
            if 'coverage bbHap addr' in line:
                parts = line.split()
                linear =  parts[-3]
                if linear not in counts:
                    counts[linear] = 1
                else:
                    counts[linear] += 1
    sorted_hits = sorted(counts.items(), key=lambda x:x[1])
    for addr, count in sorted_hits:
        print('%s  %d' % (addr, count))

if __name__ == '__main__':
    sys.exit(main())
