#!/usr/bin/env python
#
# given a hits file or an AFL session named by target, instance and index,
# display the hits as hex.
#
import sys
import os
import glob
import json
import argparse

all_funs = []
all_hits = []
def getFuns(prog):
    retval = None
    ida_data = os.getenv('RESIM_IDA_DATA')
    prog_path = os.path.join(ida_data, prog, prog+'.prog')
    if not os.path.isfile(prog_path):
        print('no prog file at %s' % prog_path)
    else:
        prog = None
        with open(prog_path) as fh:
            prog = fh.read()+'.funs'
        retval = json.load(open(prog))
    return retval

def getCover(fpath, funs):
    hits1 = json.load(open(fpath))
    funs_hit = []
    for hit in hits1:

        if str(hit) in funs:
            if hit not in funs_hit:
                funs_hit.append(hit)
            if hit not in all_funs:
                all_funs.append(hit)
        if hit not in all_hits:
            all_hits.append(hit)
    return len(hits1), len(funs_hit)

def getPathList(target):
    afl_path = os.getenv('AFL_DATA')
    glob_mask = '%s/output/%s/resim_*/coverage/id:*,src*' % (afl_path, target)
    glist = glob.glob(glob_mask)
    return glist

def getAFLPath(target, instance, index):             
    resim_num = 'resim_%s' % instance
    afl_path = os.getenv('AFL_DATA')
    retval = None 
    glob_mask = '%s/output/%s/%s/coverage/id:*%s,src*' % (afl_path, target, resim_num, index)
    glist = glob.glob(glob_mask)
    if len(glist) == 0:
        print('No file found for %s' % glob_mask)
    else:
        retval = glist[0]
    return retval 
#for hit in hits1:
#    print('0x%x' % hit)

def main():
    parser = argparse.ArgumentParser(prog='showCoverage', description='Show coverage of one or more hits files')
    parser.add_argument('target', action='store', help='The AFL target, generally the name of the workspace.')
    parser.add_argument('prog', action='store', help='The program that was fuzzed.  TBD should store via runAFL or similar?.')
    parser.add_argument('-i', '--index', action='store', help='index')
    parser.add_argument('-n', '--instance', action='store', help='instance')
    args = parser.parse_args()
    funs = getFuns(args.prog)
    if funs is None:
        exit(1)
    if args.index is not None:
        path = getAFLPath(args.target, args.instance, args.index)
        num_hits, num_funs = getCover(path, funs) 
        print('hits: %d  funs: %d   %s' % (num_hits, num_funs, path))

    if args.index is None and args.instance is None:
        flist = getPathList(args.target)
        for f in flist:
            num_hits, num_funs = getCover(f, funs) 
            print('hits: %d  funs: %d   %s' % (num_hits, num_funs, f))
        print('%d sessions' % len(flist))
        print('total functions: %d  total hits: %d' % (len(all_funs), len(all_hits)))        
         

if __name__ == '__main__':
    sys.exit(main())
