#!/usr/bin/env python3
#
# Search for a string in each of the unique queue files
#
import sys
import os
import glob
import json
import argparse
from struct import *

try:
    import ConfigParser
except:
    import configparser as ConfigParser
resim_dir = os.getenv('RESIM_DIR')
sys.path.append(os.path.join(resim_dir, 'simics', 'monitorCore'))
import aflPath
def main():

    parser = argparse.ArgumentParser(prog='searchQueueFiles', description='Search for a given string in each of the unique queue files.')
    parser.add_argument('target', action='store', help='The AFL target, generally the name of the workspace.')
    parser.add_argument('find', action='store', help='The string to find.')
    args = parser.parse_args()
    flist = aflPath.getTargetQueue(args.target)
    find_bytes = args.find.encode()
    for f in sorted(flist):
        with open(f, 'br') as fh:
            data = fh.read()
            if find_bytes in data:
                index = data.index(find_bytes)
                base = os.path.basename(f)
                data_str = data[index:index+100].decode(errors='ignore')
                data_str = data_str.splitlines()[0]
                print(base+'   '+data_str)
if __name__ == '__main__':
    sys.exit(main())
