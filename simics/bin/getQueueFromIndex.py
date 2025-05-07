#!/usr/bin/env python3
'''
Get a queue file from a unique index
'''
import sys
import os
import json
import argparse
from collections import OrderedDict
resim_dir = os.getenv('RESIM_DIR')
sys.path.append(os.path.join(resim_dir, 'simics', 'monitorCore'))
import aflPath

def main():
    parser = argparse.ArgumentParser(prog='getQueueFromIndex', description='Get a queue file path from a unique index.')
    parser.add_argument('target', action='store', help='The AFL target, generally the name of the workspace.')
    parser.add_argument('index', action='store', type=int, help='Index of the queue file to retrieve.')
    parser.add_argument('-v', '--verbose', action='store', help='Verbose')
    args = parser.parse_args()
    path = aflPath.getPathFromIndex(args.target, args.index)
    afl_output = aflPath.getAFLOutput()
    afl_dir = os.path.join(afl_output, args.target)
    full = os.path.join(afl_dir, path)
    if path is not None:
        if args.verbose:
            print('Queue fie at unique list index %d is %s' % (args.index, full))
        else:
            sys.stdout.write(full)
    else:
        print('Error, no queue file found for index %d' % args.index)
    
if __name__ == '__main__':
    sys.exit(main())
