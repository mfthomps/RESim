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

def findTrackMark(f, addr, one, prog, quiet=False, lgr=None, no_cbr=False):
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
        if prog is not None:
            offset = resimUtils.getLoadOffsetFromSO(somap, prog, lgr=lgr)
            if offset != None:
                addr = addr + offset
        mark_list = track['marks']
        sorted_marks = sorted(mark_list, key=lambda x: x['cycle'])
        #print('%d marks' % len(mark_list))
        count = 1
        for mark in sorted_marks:
            #print('%d ip: 0x%x cycle: 0x%x' % (count, mark['ip'], mark['cycle']))
            #lgr.debug('%d ip: 0x%x cycle: 0x%x' % (count, mark['ip'], mark['cycle']))
            if mark['mark_type'] == 'reset_origin':
                num_resets += 1
            #if mark['mark_type'] == 'read' and mark['ip']==addr:
            if mark['ip']==addr:
                if no_cbr and mark['type'] == 'read' and mark['compare'] == 'CBR':
                    # skip this one
                    print('mark is CBR skip this one')
                    if lgr is not None:
                        lgr.debug('mark is CBR skip this one')
                    pass
                else: 
                    size = os.path.getsize(queue_path)
                    retval = TrackResult(queue_path, size, mark, len(mark_list))
                    if lgr is not None:
                        lgr.debug('findTrack 0x%x found %s at mark %d in (len %d)  %s packet: %d' % (addr, mark['mark_type'], mark['index'], size, queue_path, mark['packet']))
                        lgr.debug('\t size: %d num_marks %d' % (retval.size, retval.num_marks))
                    if not quiet:
                        print('0x%x found %s at mark %d in (len %d)  %s packet: %d num_marks: %d' % (addr, mark['mark_type'], mark['index'], size, queue_path, 
                              mark['packet'], len(mark_list)))
                    if one:
                        break
    else:
        #print('findTrack findTrackMark, not a file: %s' % track_path)
        if lgr is not None:
            lgr.debug('findTrack addr 0x%x NOT A FILE path %s' % (addr, track_path))
    return retval, num_resets

def main():
    parser = argparse.ArgumentParser(prog='findTrack', description='Find track files that reference an input at a given instruction address')
    parser.add_argument('target', action='store', help='The AFL target, generally the name of the workspace.')
    parser.add_argument('addr', action='store', help='The instruction address.')
    parser.add_argument('prog', action='store', help='The program or library.')
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
        result, num_resets = findTrackMark(os.path.join(target_path, expaths[index]), addr, args.one, args.prog)
        if result is not None and args.one:
            break

if __name__ == '__main__':
    sys.exit(main())
