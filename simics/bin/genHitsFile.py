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
def getHits(paths):
    cover = json.load(open(paths), object_pairs_hook=OrderedDict)

def main():
    parser = argparse.ArgumentParser(prog='genHitsFile', description='Genereate a hits file for a target.')
    parser.add_argument('target', action='store', help='The AFL target, generally the name of the workspace.')
    parser.add_argument('-a', '--all', action='store_true', help='Look at all queue files, not just unique files.')
    args = parser.parse_args()
    expaths1 = aflPath.getAFLCoverageList(args.target, get_all=args.all)
    hits = []
    for path in expaths1:
        cover = json.load(open(path))
        print('doing %s' % path)
        for hit in cover:
            hit = int(hit)
            if hit not in hits:
                hits.append(hit)
    ofile = '/tmp/%s.hits' % args.target
    with open(ofile, 'w') as fh:
        fh.write(json.dumps(hits))
    print('Found %d hits written to /tmp/%s.hits' % (len(hits), args.target))
    
    
if __name__ == '__main__':
    sys.exit(main())
