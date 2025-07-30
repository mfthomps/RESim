#!/usr/bin/env python3
#
# Display the number of hits in each coverage file for a given target/program, optionally focusing on a given index/instance.
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

def getBlocks(prog_path):
    retval = None
    prog = prog_path+'.blocks'
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

def getHeader(ini):
    config = ConfigParser.ConfigParser()
    config.read(ini)
    retval = None
    if not config.has_option('ENV', 'AFL_UDP_HEADER'):
        print('no AFL_UDP_HEADER')
    else:
        retval = config.get('ENV', 'AFL_UDP_HEADER')
        print('found header: %s' % retval)
    return retval

def getPackets(f, header):
    retval = -1
    with open(f) as fh:
        data = fh.read()
        retval = data.count(header) 
    return retval  

def totalBlocks(blocks):
    tot = 0
    for fun in blocks:
        tot = tot + len(blocks[fun]['blocks'])
    return tot

def main():
    parser = argparse.ArgumentParser(prog='showCoverage', description='Show number of hits (coverage) of one or more hits files')
    parser.add_argument('target', action='store', help='The AFL target, generally the name of the workspace.')
    parser.add_argument('prog', action='store', help='The program that was fuzzed.  TBD should store via runAFL or similar?.')
    parser.add_argument('ini', action='store', help='The ini file.')
    parser.add_argument('-i', '--index', action='store', help='index')
    parser.add_argument('-n', '--instance', action='store', help='instance')
    args = parser.parse_args()
    lgr = resimUtils.getLogger('showCoverage', '/tmp', level=None)
    lgr.debug('showCoverage begin')

    '''
    ida_data = os.getenv('RESIM_IDA_DATA')
    if ida_data is None:
        print('RESIM_IDA_DATA not defined')
        exit(1)
    root_dir = resimUtils.getIniTargetValue(args.ini, 'RESIM_ROOT_PREFIX')
    print('root_dir is %s' % root_dir)
    data_path = os.path.join(ida_data, root_dir, args.prog, args.prog+'.prog')
    print('data_path is %s' % data_path)
    funs = None
    with open(data_path) as fh:
        lines = fh.read().strip().splitlines()
        print('num lines is %d' % len(lines))
        prog_file = lines[0].strip()
        funs = getFuns(prog_file)
        if funs is None:
            exit(1)
    '''
    #prog_path = resimUtils.getProgPath(args.prog, args.ini)
    #print('prog_path is %s' % prog_path)

    analysis_path = resimUtils.getAnalysisPath(args.ini, args.prog, lgr=lgr)
    if analysis_path is None:
        print('Failed to get analysis path from ini %s for prog %s' % (args.ini, args.prog))
        exit(1)
    elif not os.path.isdir(analysis_path):
        print('Failed to find analysis path %s' % (analysis_path))
        exit(1)
    print('analysis_path is %s' % analysis_path)

    funs = getFuns(analysis_path)
    udp_header = getHeader(args.ini)
    if args.index is not None:
        path = aflPath.getAFLCoveragePath(args.target, args.instance, args.index)
        num_hits, num_funs = getCover(path, funs) 
        print('hits: %d  funs: %d   %s' % (num_hits, num_funs, path))

    if args.index is None and args.instance is None:
        flist = aflPath.getAFLCoverageList(args.target)
        #flist = getPathList(args.target)
        hit_dict = {}
        for f in flist:
            base = os.path.basename(f)
            parent = os.path.dirname(f)
            instance = os.path.dirname(parent)
            queue = os.path.join(instance, 'queue', base)
            num_hits, num_funs = getCover(f, funs) 
            hit_dict[queue] = num_hits
            if udp_header is not None:
                num_packets = getPackets(queue, udp_header)
                #print('hits: %04d  funs: %04d packets: %02d  %s' % (num_hits, num_funs, num_packets, f))
            else:
                #print('hits: %04d  funs: %04d   %s' % (num_hits, num_funs, f))
                pass
        sorted_hits = dict(sorted(hit_dict.items(), key=lambda item: item[1]))
        for f in sorted_hits:
            size = os.path.getsize(f)
            print('%d \t%d \t%s' % (size, sorted_hits[f], f))
        blocks = getBlocks(analysis_path)
        total_blocks = totalBlocks(blocks)
        print('%d sessions' % len(flist))
        print('total functions: %d of %d  total hits: %d of %d' % (len(all_funs), len(funs), len(all_hits), total_blocks))        
         

if __name__ == '__main__':
    sys.exit(main())
