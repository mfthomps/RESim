#!/usr/bin/env python3
#
# Display a givne hits file as hex
#
import sys
import os
import glob
import json
import argparse
try:
    import ConfigParser
except:
    import configparser as ConfigParser
def main():
    parser = argparse.ArgumentParser(prog='showHits', description='Show content of a hits file as hex. ')
    parser.add_argument('hits_file', action='store', help='Name of the hits file')
    args = parser.parse_args()
    hits = args.hits_file
    jhits = json.load(open(hits))
    print('hits from %s:' % hits)
    for hit in jhits:
        print('\t0x%x' % hit)
    print('Total hits %d' % len(jhits))
    
         

if __name__ == '__main__':
    sys.exit(main())
