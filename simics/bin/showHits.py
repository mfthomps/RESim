#!/usr/bin/env python3
#
# Display a program's hits file as hex
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
    parser = argparse.ArgumentParser(prog='showHits', description='Show program hits file as hex.  Must be run from RESIM_ROOT_PREFIX per ini file.')
    parser.add_argument('prog', action='store', help='The program that was fuzzed. ') 
    args = parser.parse_args()
    ida_data = os.getenv('RESIM_IDA_DATA')
    if ida_data is None:
        print('RESIM_IDA_DATA not defined')
        exit(1)
    here = os.path.getcwd()
    root_dir = os.path.basename(here)
    hits = os.path.join(ida_data, root_dir, args.prog, args.prog+'.hits')
    jhits = json.load(open(hits))
    print('hits from %s:' % hits)
    for hit in jhits:
        print('\t0x%x' % hit)
    
         

if __name__ == '__main__':
    sys.exit(main())
