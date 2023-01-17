#!/usr/bin/env python3
#
#
'''
Find a track that references in input at a given instruction address
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
def getQueue(f):
    base = os.path.basename(f)
    cover = os.path.dirname(f)
    track = os.path.join(os.path.dirname(cover), 'queue', base)
    return track

def findTrack(f, addr):
    track_path = getTrack(f)
    queue_path = getQueue(f)
    if os.path.isfile(track_path):
        track = json.load(open(track_path))
        mark_list = track['marks']
        #print('%d marks' % len(mark_list))
        count = 1
        for mark in mark_list:
            if mark['mark_type'] == 'read' and mark['ip']==addr:
                size = os.path.getsize(queue_path)
                print('0x%x found at mark %d in (len %d)  %s (TBD, why off by one?)' % (addr, count, size, queue_path))
            count += 1
    else:
        print('not a file: %s' % track_path)

def main():
    parser = argparse.ArgumentParser(prog='findTrack', description='Find track files that reference an input at a given instruction address')
    parser.add_argument('target', action='store', help='The AFL target, generally the name of the workspace.')
    parser.add_argument('addr', action='store', help='The instruction address.')
    args = parser.parse_args()

    afl_path = os.getenv('AFL_DATA')
    unique_path = os.path.join(afl_path, 'output', args.target, args.target+'.unique') 
    target_path = os.path.join(afl_path, 'output', args.target)
    expaths = json.load(open(unique_path))
    print('got %d paths' % len(expaths))
    addr = int(args.addr, 16) 
    for index in range(len(expaths)):
            findTrack(os.path.join(target_path, expaths[index]), addr)

if __name__ == '__main__':
    sys.exit(main())
