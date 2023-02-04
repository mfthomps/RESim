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
import resimUtils

all_funs = []
all_hits = []
def getFuns(prog_path):
    retval = None
    prog = prog_path+'.funs'
    retval = json.load(open(prog))
    return retval

def getCover(fpath, funs):
    hits1 = json.load(open(fpath))
    sorted_hits = sorted(hits1.items(), key=lambda x: x[1]['cycle'])
    funs_hit = []
    for hit, dumb in sorted_hits:

        if str(hit) in funs:
            if hit not in funs_hit:
                funs_hit.append(hit)
            if hit not in all_funs:
                all_funs.append(hit)
        if hit not in all_hits:
            all_hits.append(hit)
    return len(hits1), len(funs_hit)

def findTrack(value, blocks, track):
    bb_end = resimUtils.findEndBB(blocks, value)
    if bb_end is None:
        print('No end bb for 0x%x' % value)
    else:
        for item in track:
            ip = item['ip']
            if ip >= value and ip <= bb_end:
               print('got 0x%x packet %d' % (ip, item['packet']))

def main():
    parser = argparse.ArgumentParser(prog='showCoverage', description='Show number of hits (coverage) of one or more hits files')
    parser.add_argument('target', action='store', help='The AFL target, generally the name of the workspace.')
    parser.add_argument('instance', action='store', type=int, help='instance')
    parser.add_argument('index', action='store', type=int, help='index')
    parser.add_argument('program', action='store', help='program name')
    args = parser.parse_args()
    if args.target.endswith('/'):
        args.target = args.target[:-1]

    blocks, prog_elf = resimUtils.getBasicBlocks(args.program)
    path = aflPath.getAFLCoveragePath(args.target, args.instance, args.index)
    print('path is %s' % path)
    track_path  = path.replace('coverage', 'trackio')
    track = None
    if os.path.isfile(track_path):
        track = json.load(open(track_path))
        print('track is %s has %d items' % (type(track), len(track)))
    else:
        print('failed to find track_path at %s' % track_path)

    hits_json = json.load(open(path))
    #sorted_hits = sorted(hits_json.items(), key=lambda x:x[1])
    sorted_hits = sorted(hits_json.items(), key=lambda x: x[1]['cycle'])
    flist = aflPath.getAFLCoverageList(args.target)
    unique = []
    for hit, dumb in sorted_hits:
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
        print('unique hit: 0x%x  packet %d' % (value, hits_json[hit]['packet_num']))
        if track is not None:
            mark_list = track['marks']
            findTrack(value, blocks, mark_list)
         

if __name__ == '__main__':
    sys.exit(main())
