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



def getPathList(target):
    afl_path = os.getenv('AFL_DATA')
    if afl_path is None:
        print('AFL_DATA not defined')
        exit(1)
    glob_mask = '%s/output/%s/resim_*/coverage/id:*,src*' % (afl_path, target)
    print('glob_mask is %s' % glob_mask)
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

    flist = getPathList(args.target)
    for f in flist:
        base = os.path.basename(f)
        parent = os.path.dirname(f)
        instance = os.path.dirname(parent)
        queue = os.path.join(instance, 'queue', base)
        queue_len = os.path.getsize(queue)
        hits = json.load(open(f))
        numhits = len(hits)
        gotone = None
        for item in hit_dict:
            if len(hit_dict[item]) == numhits: 
                if listMatch(hit_dict[item], hits):
                    gotone = item
                    break
        if not gotone:
            print('new hit list %d hits %s' % (numhits, f))
            hit_dict[f] = hits
        else:
            print('%s hits already in %s' % (f, gotone))
            if queue_len < os.path.getsize(gotone):
                print('but this one is smaller, so replace it')
                del hit_dict[gotone]
                hit_dict[f] = hits
    for f in hit_dict:
        print('hits: %d fsize: %d  %s' % (len(hit_dict[f]), os.path.getsize(f), f))
    print('got %d unique hit lists' % len(hit_dict))
    saveUnique(hit_dict, args.target)

if __name__ == '__main__':
    sys.exit(main())
