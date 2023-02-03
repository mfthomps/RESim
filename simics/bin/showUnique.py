#!/usr/bin/env python3
#
# Display the unique hits within a coverage file named by instance and index
#
import sys
import os
import glob
import json
import argparse
try:
    import ConfigParser
except:
    import configparser as ConfigParser
resim_dir = os.getenv('RESIM_DIR')
sys.path.append(os.path.join(resim_dir, 'simics', 'monitorCore'))
import aflPath

all_funs = []
all_hits = []
def getFuns(prog_path):
    retval = None
    prog = prog_path+'.funs'
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



def main():
    parser = argparse.ArgumentParser(prog='showCoverage', description='Show number of hits (coverage) of one or more hits files')
    parser.add_argument('target', action='store', help='The AFL target, generally the name of the workspace.')
    parser.add_argument('instance', action='store', type=int, help='instance')
    parser.add_argument('index', action='store', type=int, help='index')
    args = parser.parse_args()

    path = aflPath.getAFLCoveragePath(args.target, args.instance, args.index)
    print('path is %s' % path)
    hits_json = json.load(open(path))
    flist = aflPath.getAFLCoverageList(args.target)
    unique = []
    for hit in hits_json:
        got_one = False
        #flist = getPathList(args.target)
        for f in flist:
            if f == path:
                continue
            this_json = json.load(open(f))
            if hit in this_json:
                got_one = True
                break 
        if not got_one:
            unique.append(hit)
    for hit in unique:
        value = int(hit)
        print('unique hit: 0x%x' % value)
         

if __name__ == '__main__':
    sys.exit(main())
