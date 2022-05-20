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
import findBB

'''
Return a list of queue files that hit a given BB start address
'''
def findBB(target, bb, quiet=False):
    retval = []
    cover_list = aflPath.getAFLCoverageList(target)
    for cover in cover_list:
        with open(cover) as fh:
            hit_list = json.load(fh)
            if str(bb) in hit_list:
                queue = cover.replace('coverage', 'queue')
                if not os.path.isfile(queue):
                    queue = cover.replace('coverage', 'manual')
                    if not os.path.isfile(queue):
                        queuereal = cover.replace('coverage', 'queue')
                        print('Could not find file at %s' % queue)
                        print('or at %s' % queuereal)
                
                retval.append(queue)
                if not quiet:
                    print('0x%x in %s' % (bb, queue))
    return retval

def getWatchMark(trackio, bb):
    retval = None
    ''' Find a read watch mark within a given watch mark json for a given bb '''
    if not os.path.isfile(trackio):
        print('ERROR: no trackio file at %s' % trackio)
        return None
    try:
        tjson = json.load(open(trackio))
    except:
        #print('ERROR: failed reading json from %s' % trackio)
        return None
    for mark in tjson:
        if mark['mark_type'] == 'read':
            eip = mark['ip']
            if eip >= bb['start_ea'] and eip <= bb['end_ea']:
                print('getWatchMarks found read mark at 0x%x' % eip)
                retval = eip
                break
    return retval
        

def main():
    parser = argparse.ArgumentParser(prog='findBBB', description='Show AFL queue entries that lead to a given basic block address.')
    parser.add_argument('target', action='store', help='The target, e.g., the name of the workspace.')
    parser.add_argument('bb', action='store', help='The address of the basic block.')
    args = parser.parse_args()
    findBB(args.target, int(args.bb, 16))

if __name__ == '__main__':
    sys.exit(main())
