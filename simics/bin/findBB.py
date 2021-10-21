#!/usr/bin/env python
#
#
import sys
import os
import glob
import json
import argparse
def getAFLOutput():
    afl_output = os.getenv('AFL_OUTPUT')
    if afl_output is None:
        afl_output = os.getenv('AFL_DATA')
        if afl_output is None:
            afl_output = os.path.join(os.getenv('HOME'), 'SEED','afl','afl-output')
            print('Using default AFL_OUPUT directory of %s' % afl_output)
        else:
            afl_output = os.path.join(afl_output, 'output')
    return afl_output
def findBB(target, bb):
    afl_output = getAFLOutput()
    target_dir = os.path.join(afl_output, target)
    #flist = os.listdir(target_dir)
    gmask = target_dir+'/resim_*/'
    flist = glob.glob(gmask)
    print('%d entries in %s' % (len(flist), gmask))
    #print('flist is %s' % str(flist))
    if len(flist) == 0:
        ''' is not parallel fuzzing '''
        coverage_dir = os.path.join(target_dir, 'coverage')
        queue_dir = os.path.join(target_dir, 'queue')
        hit_files = os.listdir(coverage_dir)
        
        for f in hit_files:
            path = os.path.join(coverage_dir, f)
            hit_list = json.load(open(path))
            if bb in hit_list:
                qfile = os.path.join(queue_dir, f)
                print('found 0x%x in %s' % (bb, qfile))
    else: 
        ''' is parallel fuzzing '''
        print('is parallel, %d files' % len(flist))
        for drone in flist:
            coverage_dir = os.path.join(drone, 'coverage')
            queue_dir = os.path.join(drone, 'queue')
            hit_files = os.listdir(coverage_dir)
            #print('got %d hits files for %s' % (len(hit_files), drone))
            for f in hit_files:
                path = os.path.join(coverage_dir, f)
                hit_list = json.load(open(path))
                #print('look for 0x%x in hit_list of len %d' % (bb, len(hit_list)))
                if bb in hit_list:
                    qfile = os.path.join(queue_dir, f)
                    print('found 0x%x in %s' % (bb, qfile))

def main():
    parser = argparse.ArgumentParser(prog='findBBB', description='Show AFL queue entries that lead to a given basic block address.')
    parser.add_argument('target', action='store', help='The target, e.g., the name of the workspace.')
    parser.add_argument('bb', action='store', help='The address of the basic block.')
    args = parser.parse_args()
    findBB(args.target, int(args.bb, 16))

if __name__ == '__main__':
    sys.exit(main())
