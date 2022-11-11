#!/usr/bin/env python3
#
#
'''
Compare trackio data recorded for a set of AFL sessions.  Compare each file to every other file
and note differences.
'''
import sys
import os
import glob
import json
from collections import OrderedDict
import argparse
import readMarks
import hashlib
splits = {}
class SplitInfo():
    def __init__(self, index, hit, cycle):
        self.index = index
        self.hit = hit
        self.cycle = cycle
        self.data = None

def findDiff(f1, f2):
    hashval = hashlib.md5()
    cover1 = json.load(open(f1), object_pairs_hook=OrderedDict)
    cover2 = json.load(open(f2), object_pairs_hook=OrderedDict)
    items1 = list(cover1.items())
    items2 = list(cover2.items())
    print('num_hits1 %d num_hits2 %d' % (len(items1), len(items2)))
    prev = 0
    retval = None
    xor = None
    for index in range(len(cover1)):
        if index >= len(items2):
            print('exceeded hits2 list')
            break
        hit1, cycle1 = items1[index]
        hit2, cycle2 = items2[index]
        hit1 = int(hit1)
        hit2 = int(hit2)
        if hit1 != hit2:
            print('diff at index %d.  %x vs %x  prev: 0x%x  cycle1: 0x%x  cycle2: 0x%x' % (index, hit1, hit2, prev, cycle1, cycle2))
            retval = cycle1
            split_info = SplitInfo(index, hit1, cycle1)
            xor = hashval.hexdigest()
            if xor not in splits:
                splits[xor] = []
            splits[xor].append(split_info)
            split_info = SplitInfo(index, hit2, cycle2)
            splits[xor].append(split_info)
            break
        hashval.update(str(hit1).encode('utf-8'))
        prev = hit1
    return retval, xor

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
   

def findTrack(diverge_cycle, f1, f2, xor):
    track1_path = getTrack(f1)
    print('track1_path %s' % track1_path)
    track1, len1 = readMarks.getReadMarks(track1_path)
    if track1 is None:
        return
    track2_path = getTrack(f2)
    print('track2_path %s' % track2_path)
    track2, len2 = readMarks.getReadMarks(track2_path)
    if track2 is None:
        return
    print('num_marks1 %d  num_marks2 %d  file1_len %d  file2_len %d' % (len(track1), len(track2), len1, len2))
    found_diff = False
    recent_rm1_data = None
    recent_rm2_data = None
    for index in range(len(track1)):
        if index >= len(track2):
            print('index %d past end of list track2' % index)
            break
        rm1 = track1[index]
        rm2 = track2[index]
        if rm1.cycle > diverge_cycle:
            split1 = splits[xor][-1]
            split2 = splits[xor][-2]
            split1.data = recent_rm1_data 
            split2.data = recent_rm2_data 
            print('past divergence index %d  rm1.cycle 0x%x  diverged at 0x%x' % (index, rm1.cycle, diverge_cycle))
            break
        if rm1.ip == rm2.ip:
            if rm1.offset == rm2.offset:
                if rm1.data == rm2.data:
                    #print('index %d match' % index)
                    pass
                else:
                    print('index %d offset: %d data mismatch  0x%x vs 0x%x  ip: 0x%x cycle: 0x%x packet: %d & %d' % (index, rm1.offset, rm1.data, rm2.data, rm1.ip, rm1.cycle, rm1.packet, rm2.packet))
                    found_diff = True
                    recent_rm1_data = rm1.data
                    recent_rm2_data = rm2.data
            else:
                print('index %d offset mismatch  ip: 0x%x' % (index, ip))
                found_diff = True
                break
        else:
            print('index %d ip mismatch' % index)
            found_diff = True
            break
    if not found_diff:
        print('Identical data refrences!')    

def main():
    parser = argparse.ArgumentParser(prog='showTrack', description='dump track files')
    parser.add_argument('target', action='store', help='The AFL target, generally the name of the workspace.')
    args = parser.parse_args()

    afl_path = os.getenv('AFL_DATA')
    target_path = os.path.join(afl_path, 'output', args.target, args.target+'.unique') 
    expaths = json.load(open(target_path))
    print('got %d paths' % len(expaths))
   
    for index in range(len(expaths)):
            showTrack(expaths[index])

if __name__ == '__main__':
    sys.exit(main())
