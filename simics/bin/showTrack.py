#!/usr/bin/env python3
#
#
'''
Dump track files for a given target
'''
import sys
import os
import glob
import json
from collections import OrderedDict
import argparse
splits = {}
def getTrack(f):
    base = os.path.basename(f)
    cover = os.path.dirname(f)
    track = os.path.join(os.path.dirname(cover), 'trackio', base)
    return track

def showTrack(f):
    track_path = getTrack(f)
    if os.path.isfile(track_path):
        track = json.load(open(track_path))
        mark_list = track['marks']
        first = mark_list[0]
        print('first cycle is 0x%x' % first['cycle'])
        for mark in mark_list:
            print('%d 0x%x %s %d' % (mark['index'], mark['ip'], mark['mark_type'], mark['packet']))

def main():
    parser = argparse.ArgumentParser(prog='showTrack', description='dump track files')
    parser.add_argument('target', action='store', help='The AFL target, generally the name of the workspace.')
    args = parser.parse_args()
    if args.target.endswith('/'):
        args.target = args.target[:-1]
    if os.path.isfile(args.target):
        showTrack(args.target)
    else:
        afl_path = os.getenv('AFL_DATA')
        target_path = os.path.join(afl_path, 'output', args.target, args.target+'.unique') 
        expaths = json.load(open(target_path))
        print('got %d paths' % len(expaths))
   
        for index in range(len(expaths)):
            showTrack(expaths[index])

if __name__ == '__main__':
    sys.exit(main())
