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
    if os.path.basename(cover).startswith ('manual_'):
        track = os.path.join(os.path.dirname(cover), 'manual_trackio', base)
    else:
        track = os.path.join(os.path.dirname(cover), 'trackio', base)
    return track
def getQueue(f):
    base = os.path.basename(f)
    cover = os.path.dirname(f)
    if os.path.basename(cover).startswith ('manual_'):
        track = os.path.join(os.path.dirname(cover), 'manual_queue', base)
    else:
        track = os.path.join(os.path.dirname(cover), 'queue', base)
    return track

class TrackResult():
    def __init__(self, path, size, mark):
        self.path = path 
        self.size = size
        self.mark = mark

def findTrack(f, addr, one, quiet=False):
    retval = None
    track_path = getTrack(f)
    queue_path = getQueue(f)
    mark_cycle = 0
    #print('NEW FIND TRACK %s' % track_path)
    if os.path.isfile(track_path):
        track = json.load(open(track_path))
        mark_list = track['marks']
        #print('%d marks' % len(mark_list))
        count = 1
        for mark in mark_list:
            #print('%d ip: 0x%x cycle: 0x%x' % (count, mark['ip'], mark['cycle']))
            if mark['cycle'] < mark_cycle:
                print('OUT OF ORDER')
                print('mark cycle 0x%x' % mark['cycle'])
                break
            else:
                mark_cycle = mark['cycle'] 
            #if mark['mark_type'] == 'read' and mark['ip']==addr:
            if mark['ip']==addr:
                size = os.path.getsize(queue_path)
                retval = TrackResult(queue_path, size, mark)
                if not quiet:
                    print('0x%x found %s at mark %d in (len %d)  %s packet: %d' % (addr, mark['mark_type'], mark['index'], size, queue_path, mark['packet']))
                if one:
                    break
    else:
        print('not a file: %s' % track_path)
    return retval

def main():
    parser = argparse.ArgumentParser(prog='findTrack', description='Find track files that reference an input at a given instruction address')
    parser.add_argument('target', action='store', help='The AFL target, generally the name of the workspace.')
    parser.add_argument('addr', action='store', help='The instruction address.')
    parser.add_argument('-o', '--one', action='store_true', help='stop after one.')
    args = parser.parse_args()

    if args.target.endswith('/'):
        args.target = args.target[:-1]
    afl_path = os.getenv('AFL_DATA')
    unique_path = os.path.join(afl_path, 'output', args.target, args.target+'.unique') 
    target_path = os.path.join(afl_path, 'output', args.target)
    expaths = json.load(open(unique_path))
    print('got %d paths' % len(expaths))
    addr = int(args.addr, 16) 
    for index in range(len(expaths)):
        result = findTrack(os.path.join(target_path, expaths[index]), addr, args.one)
        if result is not None and args.one:
            break

if __name__ == '__main__':
    sys.exit(main())
