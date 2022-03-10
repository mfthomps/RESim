#!/usr/bin/env python
#
# given a an AFL session named by target, compare all of the coverage
# files and de-dupe them, creating a list of the smallest queue files
# generate unique a set of hits.
#
import sys
import os
import glob
import json
import argparse
import functools
try:
    import ConfigParser
except:
    import configparser as ConfigParser
resim_dir = os.getenv('RESIM_DIR')

sys.path.append(os.path.join(resim_dir, 'simics', 'monitorCore'))
import aflPath


#for hit in hits1:
#    print('0x%x' % hit)

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

def listMatch(l1, l2):
    if functools.reduce(lambda x, y : x and y, map(lambda p, q: p == q,l1,l2), True): 
        return True
    else: 
        return False
    
def saveUnique(hit_dict, target):
    flist = list(hit_dict.keys())
    afl_path = os.getenv('AFL_DATA')
    target_path = os.path.join(afl_path, 'output', target, target+'.unique') 
    with open(target_path, 'w') as fh:
        json.dump(flist, fh)

 
def main():
    parser = argparse.ArgumentParser(prog='dedupCoverage', description='Show coverage of one or more hits files')
    parser.add_argument('target', action='store', help='The AFL target, generally the name of the workspace.')
    args = parser.parse_args()

    ida_data = os.getenv('RESIM_IDA_DATA')
    if ida_data is None:
        print('RESIM_IDA_DATA not defined')
        exit(1)

    hit_dict = {}

    flist = aflPath.getAFLCoverageList(args.target, get_all=True)

    prefix = aflPath.getTargetPath(args.target)

    for f in flist:
        base = os.path.basename(f)
        parent = os.path.dirname(f)
        instance = os.path.dirname(parent)
        queue = os.path.join(instance, 'queue', base)
        if not os.path.isfile(queue):
            queue = os.path.join(instance, 'manual', base)
            if not os.path.isfile(queue):
                realqueue = os.path.join(instance, 'queue', base)
                print('No file at %s' % queue)
                print('or at %s' % realqueue)
                continue
        queue_len = os.path.getsize(queue)
        hits = json.load(open(f))
        numhits = len(hits)
        gotone = None
        for item in hit_dict:
            if len(hit_dict[item]) == numhits: 
                if listMatch(hit_dict[item], hits):
                    gotone = item
                    break
        rel_path = aflPath.getRelativePath(f, args.target)
        if not gotone:
            print('new hit list %d hits %s' % (numhits, rel_path))
            hit_dict[rel_path] = hits
        else:
            print('%s hits already in %s' % (rel_path, gotone))
            full = os.path.join(prefix, rel_path)
            if queue_len < os.path.getsize(full):
                print('but this one is smaller, so replace it path %s' % rel_path)
                del hit_dict[gotone]
                hit_dict[rel_path] = hits
    for f in hit_dict:
        full = os.path.join(prefix, f)
        print('hits: %d fsize: %d  %s' % (len(hit_dict[f]), os.path.getsize(full), f))
    print('got %d unique hit lists' % len(hit_dict))
    saveUnique(hit_dict, args.target)

if __name__ == '__main__':
    sys.exit(main())
