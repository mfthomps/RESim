#!/usr/bin/env python
#
#
import sys
import os
import glob
import json
import argparse
resim_dir = os.getenv('RESIM_DIR')
sys.path.append(os.path.join(resim_dir, 'simics', 'monitorCore'))
import aflPath

def findBB(target, bb, quiet=False):
    retval = []
    cover_list = aflPath.getAFLCoverageList(target)
    for cover in cover_list:
        with open(cover) as fh:
            hit_list = json.load(fh)
            if str(bb) in hit_list:
                queue = cover.replace('coverage', 'queue')
                retval.append(queue)
                if not quiet:
                    print('0x%x in %s' % (bb, queue))
    return retval
        

def main():
    parser = argparse.ArgumentParser(prog='findBBB', description='Show AFL queue entries that lead to a given basic block address.')
    parser.add_argument('target', action='store', help='The target, e.g., the name of the workspace.')
    parser.add_argument('bb', action='store', help='The address of the basic block.')
    args = parser.parse_args()
    findBB(args.target, int(args.bb, 16))

if __name__ == '__main__':
    sys.exit(main())
