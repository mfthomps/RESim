#!/usr/bin/env python3
#
#
import sys
import os
import glob
import json
from collections import OrderedDict
import argparse
import readMarks

def findDiff(f1, f2):
    cover1 = json.load(open(f1), object_pairs_hook=OrderedDict)
    cover2 = json.load(open(f2), object_pairs_hook=OrderedDict)
    items1 = list(cover1.items())
    items2 = list(cover2.items())
    print('num_hits1 %d num_hits2 %d' % (len(items1), len(items2)))
    prev = 0
    retval = None
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
            break
        prev = hit1
    return retval

def getTrack(f):
    base = os.path.basename(f)
    cover = os.path.dirname(f)
    track = os.path.join(os.path.dirname(cover), 'trackio', base)
    return track


def findTrack(diverge_cycle, f1, f2):
    track1_path = getTrack(f1)
    print('track1_path %s' % track1_path)
    track1, len1 = readMarks.getReadMarks(track1_path)
    track2_path = getTrack(f2)
    print('track2_path %s' % track2_path)
    track2, len2 = readMarks.getReadMarks(track2_path)
    print('num_marks1 %d  num_marks2 %d  file1_len %d  file2_len %d' % (len(track1), len(track2), len1, len2))
    for index in range(len(track1)):
        if index >= len(track2):
            print('index %d past end of list track2' % index)
            break
        rm1 = track1[index]
        rm2 = track2[index]
        if rm1.cycle > diverge_cycle:
            print('past divergence')
            break
        if rm1.ip == rm2.ip:
            if rm1.offset == rm2.offset:
                if rm1.data == rm2.data:
                    #print('index %d match' % index)
                    pass
                else:
                    print('index %d offset: %d data mismatch  0x%x vs 0x%x  ip: 0x%x cycle: 0x%x' % (index, rm1.offset, rm1.data, rm2.data, rm1.ip, rm1.cycle))
            else:
                print('index %d offset mismatch  ip: 0x%x' % (index, ip))
                break
        else:
            print('index %d ip mismatch' % index)
            break
    

def main():
    parser = argparse.ArgumentParser(prog='dataDiff', description='look for a pony')
    parser.add_argument('target', action='store', help='The AFL target, generally the name of the workspace.')
    args = parser.parse_args()

    afl_path = os.getenv('AFL_DATA')
    target_path = os.path.join(afl_path, 'output', args.target, args.target+'.unique') 
    expaths = json.load(open(target_path))
    print('got %d paths' % len(expaths))
   
    for index in range(len(expaths)):
        for inner in range(index+1, len(expaths)):
            print('\n\npath1 %s' % expaths[index]) 
            print('path2 %s' % expaths[inner]) 
            diverge_cycle = findDiff(expaths[index], expaths[inner])
            if diverge_cycle is not None:
                findTrack(diverge_cycle, expaths[index], expaths[inner])
            else:
                print('Identical hits files up to index')
            #break
if __name__ == '__main__':
    sys.exit(main())
