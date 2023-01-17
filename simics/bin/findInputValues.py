#!/usr/bin/env python3
#
# Display values at a given offset in each of the unique queue files.
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

    parser = argparse.ArgumentParser(prog='findInputValue', description='Display data values at a given offset in each of the queue files.')
    parser.add_argument('target', action='store', help='The AFL target, generally the name of the workspace.')
    parser.add_argument('offset', action='store', type=int, help='Offset into the input files.')
    parser.add_argument('length', action='store', type=int, help='Number of bytes.')
    args = parser.parse_args()
    flist = aflPath.getTargetQueue(args.target)
    end = args.offset + args.length
    for f in flist:
        with open(f, 'br') as fh:
            value = None
            data = fh.read()
            if len(data) <= end:
                print('%s only has %d bytes' % (f, len(data)))
            elif args.length == 1:
                value = data[args.offset]
            elif args.length == 2: 
                value = unpack('>H', data[args.offset:end])
            else:
                print('not handled')
            if value is not None:
                print('value: 0x%x %s' % (value,f))
if __name__ == '__main__':
    sys.exit(main())
