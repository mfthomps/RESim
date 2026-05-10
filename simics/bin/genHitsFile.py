#!/usr/bin/env python3
'''
Generate a hits file from a given target
'''
import sys
import os
import json
import argparse
from collections import OrderedDict
resim_dir = os.getenv('RESIM_DIR')
sys.path.append(os.path.join(resim_dir, 'simics', 'monitorCore'))
import aflPath
import resimUtils
def getHits(paths):
    cover = json.load(open(paths), object_pairs_hook=OrderedDict)

def genHits(target, get_all=False):
    expaths1 = aflPath.getAFLCoverageList(target, get_all=get_all)
    hits = []
    for path in expaths1:
        cover = json.load(open(path))
        #print('doing %s' % path)
        for hit in cover:
            hit = int(hit)
            if hit not in hits:
                hits.append(hit)
    return hits

def main():
    parser = argparse.ArgumentParser(prog='genHitsFile', description='Genereate a hits file for a target and store output below IDA_DATA with afl_ prefix.')
    parser.add_argument('ini', action='store', help='Ini file')
    parser.add_argument('target', action='store', help='The AFL target, the name of the workspace used when afl was run.')
    parser.add_argument('-a', '--all', action='store_true', help='Look at all queue files, not just unique files.')
    parser.add_argument('-p', '--prog', action='store', help='Optional program name, do not provide this unless missing from afl meta data.')
    args = parser.parse_args()
    lgr = resimUtils.getLogger('genHitsFile', '/tmp', level=None)

    hits = genHits(args.target, args.all)

    meta_path = os.path.join(aflPath.getTargetPath(args.target), 'meta.json')
    prog_name = None
    if args.prog is not None:
        prog_name = args.prog
    elif os.path.isfile(meta_path):
        meta_json = json.load(open(meta_path))
        if 'fname' in meta_json['afl_cmd']:
            prog_name = meta_json['afl_cmd']['fname']
        elif 'comm' in meta_json['afl_cmd']:
            prog_name = meta_json['afl_cmd']['comm']
    if prog_name is None:
        print('Unable to find the program name in afl meta data, please provide it with the --prog option.')
        exit(0) 
    ida_data = resimUtils.getIdaDataFromIni(prog_name, args.ini, lgr=lgr)
    parent = os.path.dirname(ida_data)
    try:
        os.makedirs(parent)
    except:
        pass
    base = os.path.basename(ida_data)
    hit_name = 'afl_%s.hits' % base
    ofile = os.path.join(parent, hit_name)
    print('id_data is %s' % ida_data)

    #exit(0)
    #user = os.getenv('USER')
    #try:
    #    os.mkdir('/tmp/%s' % user)
    #except:
    #    pass
    #ofile = '/tmp/%s/%s.hits' % (user, args.target)
   
    with open(ofile, 'w') as fh:
        fh.write(json.dumps(hits))
    print('Found %d hits in AFL target %s.  Wrote to %s' % (len(hits), args.target, ofile))
    
    
if __name__ == '__main__':
    sys.exit(main())
