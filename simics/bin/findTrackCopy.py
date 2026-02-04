#!/usr/bin/env python3
#
#
'''
Find tracks that copy data into an address range
'''
import sys
import os
import glob
import json
from collections import OrderedDict
import argparse
resim_dir = os.getenv('RESIM_DIR')
sys.path.append(os.path.join(resim_dir, 'simics', 'monitorCore'))
import resimUtils

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
    def __init__(self, path, size, mark, num_marks):
        self.path = path 
        self.size = size
        self.mark = mark
        self.num_marks = num_marks

def findTrackMark(f, addr, count, one, prog, quiet=False, lgr=None, no_cbr=False):
    print('do for %s' % f)
    print('addr is 0x%x' % addr)
    retval = None
    track_path = getTrack(f)
    queue_path = getQueue(f)
    num_resets = 0
    #print('NEW FIND TRACK %s' % track_path)
    if lgr is not None:
        lgr.debug('findTrack addr 0x%x path %s' % (addr, track_path))
    if os.path.isfile(track_path):
        try:
            track = json.load(open(track_path))
        except:
            print('failed to load json from %s' % track_path)
            return None, None
        somap = track['somap']
        if addr > 0 and prog is not None:
            offset = resimUtils.getLoadOffsetFromSO(somap, prog, lgr=lgr)
            if offset != None:
                addr = addr + offset
        mark_list = track['marks']
        sorted_marks = sorted(mark_list, key=lambda x: x['cycle'])
        #print('%d marks' % len(mark_list))
        if addr > 0:
            end = addr + count - 1
        print('addr 0x%x' % addr)
        for mark in sorted_marks:
            #print('%d ip: 0x%x cycle: 0x%x type: %s' % (count, mark['ip'], mark['cycle'], mark['mark_type']))
            #lgr.debug('%d ip: 0x%x cycle: 0x%x' % (count, mark['ip'], mark['cycle']))
            if mark['mark_type'] == 'copy':
                dest = mark['dest']
                if addr == 0 or (dest >= addr and dest <= end):
                    print('got mark copy %d bytes to 0x%x path %s' % (mark['length'], dest, track_path))
                    if one:
                        break
    else:
        print('not a file: %s' % track_path)
        if lgr is not None:
            lgr.debug('findTrack addr 0x%x NOT A FILE path %s' % (addr, track_path))
    return retval, num_resets

def main():
    parser = argparse.ArgumentParser(prog='findTrackCopy', description='Find track files that copy to a given address range')
    parser.add_argument('target', action='store', help='The AFL target, generally the name of the workspace.')
    parser.add_argument('addr', action='store', help='Address at start of range.')
    parser.add_argument('count', action='store', help='Hex number of bytes in range.')
    parser.add_argument('prog', action='store', help='The program or library.')
    parser.add_argument('-o', '--one', action='store_true', help='stop after one.')
    parser.add_argument('-f', '--file', action='store', help='The single track file to dump.')
    args = parser.parse_args()

    if args.target.endswith('/'):
        args.target = args.target[:-1]
    if args.file is None:
        afl_path = os.getenv('AFL_DATA')
        unique_path = os.path.join(afl_path, 'output', args.target, args.target+'.unique') 
        target_path = os.path.join(afl_path, 'output', args.target)
        expaths = json.load(open(unique_path))
        print('got %d paths' % len(expaths))
    else:
        target_path = ''
        expaths = [args.file]
    addr = int(args.addr, 16) 
    print('wtf addr is 0x%x' % addr)
    count = int(args.count, 16) 
    
    for index in range(len(expaths)):
        result, num_resets = findTrackMark(os.path.join(target_path, expaths[index]), addr, count, args.one, args.prog)
        if result is not None and args.one:
            break

if __name__ == '__main__':
    sys.exit(main())
