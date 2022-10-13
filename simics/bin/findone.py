#!/usr/bin/env python3
'''
Find lines of a file that contain one of the values from another file
'''
import sys
import os
import argparse

def main():
    parser = argparse.ArgumentParser(prog='findone', description='Look for lines containing one of the values of a file.')
    parser.add_argument('searchme', action='store', help='The file to search.')
    parser.add_argument('values', action='store', help='The file containing values, only read the first field of each line the value.')
    args = parser.parse_args()
    values = []
    with open(args.values) as fh:
        for line in fh:
            v = line.split()[0].strip()
            values.append(v)
    with open(args.searchme) as fh:
        for line in fh:
            for v in values:
                if v in line:
                    print('found %s in %s' % (v, line))
    
    
if __name__ == '__main__':
    sys.exit(main())
