#!/usr/bin/env python3
'''
Show differences in hits between two targets (i.e., different fuzzing sessions).
'''
import sys
import os
import json
import argparse
from collections import OrderedDict
resim_dir = os.getenv('RESIM_DIR')
sys.path.append(os.path.join(resim_dir, 'simics', 'monitorCore'))
import aflPath
def getHits(paths):
    cover = json.load(open(paths), object_pairs_hook=OrderedDict)

def main():
    parser = argparse.ArgumentParser(prog='dataDiff', description='Diff hits between 2 fuzzing targets')
    parser.add_argument('target1', action='store', help='The AFL target, generally the name of the workspace.')
    parser.add_argument('target2', action='store', help='The AFL target, generally the name of the workspace.')
    args = parser.parse_args()
    expaths1 = aflPath.getAFLCoverageList(args.target1)
    if len(expaths1) == 0:
        print('No paths found for %s' % args.target1)
        exit(1)
    hits1 = []
    hits2 = []
    for path in expaths1:
        cover = json.load(open(path))
        #print('doing %s' % path)
        for hit in cover:
            hit = int(hit)
            if hit not in hits1:
                hits1.append(hit)
    expaths2 = aflPath.getAFLCoverageList(args.target2)
    if len(expaths2) == 0:
        print('No paths found for %s' % args.target2)
        exit(1)
    for path in expaths2:
        cover = json.load(open(path))
        #print('doing %s' % path)
        for hit in cover:
            hit = int(hit)
            if hit not in hits2:
                hits2.append(hit)
    print('first %d hits, second %d hits' % (len(hits1), len(hits2)))
    num_diff1 = 0
    num_diff2 = 0
    for hit in hits1:
        if hit not in hits2:
            print('0x%x in first, not second' % hit)
            num_diff1 += 1
    for hit in hits2:
        if hit not in hits1:
            print('0x%x in second, not first' % hit)
            num_diff2 += 1
    if num_diff1 == 0 and num_diff2 == 0:
        print('Same blocks hit in both targets.')
    else:
        print('%d hits in %s not in %s' % (num_diff1, args.target1, args.target2))
        print('%d hits in %s not in %s' % (num_diff2, args.target2, args.target1))
    
    
if __name__ == '__main__':
    sys.exit(main())
