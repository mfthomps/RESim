#!/usr/bin/env python3
#
#
import sys
import os
import json
import argparse
resim_dir = os.getenv('RESIM_DIR')
sys.path.append(os.path.join(resim_dir, 'simics', 'monitorCore'))
import aflPath
import findBB
import resimUtils

'''
Return a list of queue files that hit a given BB start address
'''
read_marks = ['read', 'compare', 'scan', 'sprint', 'strchr', 'strt']
def findBB(target, bb, quiet=False, get_all=False, lgr=None, cover_list=None, auto=False):
    retval = []
    if cover_list is None:
        cover_list = aflPath.getAFLCoverageList(target, get_all=get_all, auto=auto)
    if len(cover_list) == 0:
        print('No coverage found for %s' % target)
        return retval
    #print('%d files found' % len(cover_list))
    if lgr is not None:
        lgr.debug('findBB got %d cover files' % len(cover_list))
    for cover in cover_list:
        with open(cover) as fh:
            try:
                hit_list = json.load(fh)
            except:
                if lgr is not None:
                    lgr.debug('findBB Failed to open %s' % cover)
                print('Failed to open %s' % cover)
                continue
            #print('look for 0x%x in hit_list len %d' % (bb, len(hit_list)))
            if lgr is not None:
                lgr.debug('findBB look for 0x%x in hit_list %s len %d' % (bb, cover, len(hit_list)))
            if str(bb) in hit_list:
                queue = cover.replace('coverage', 'queue')
                if not os.path.isfile(queue):
                        queuereal = cover.replace('coverage', 'queue')
                        print('Could not find file at %s' % queue)
                        print('or at %s' % queuereal)
                
                retval.append(queue)
                if not quiet:
                    size = os.path.getsize(queue)
                    print('0x%x in size %d %s' % (bb, size, queue))
    if not quiet:
        print('Found %d queue files that hit 0x%x' % (len(retval), bb))
    return retval

def getFirstReadCycle(trackio, quiet=False):
    retval = None
    ''' Find a read watch mark within a given watch mark json for a given bb '''
    if not os.path.isfile(trackio):
        if not quiet:
            print('ERROR: getFirstReadCycle no trackio file at %s' % trackio)
        return None
    try:
        tjson = json.load(open(trackio))
    except:
        print('ERROR: failed reading json from %s' % trackio)
        return None
    mark_list = tjson['marks']
    sorted_marks = sorted(mark_list, key=lambda x: x['cycle'])
    for mark in sorted_marks:
        if mark['mark_type'] in read_marks:
            retval = mark['cycle']
            break
    return retval

def getWatchMark(trackio, bb, prog, quiet=False, lgr=None):
    #print('in getWatchMark')
    retval = (None, None, None)
    ''' Find a read watch mark within a given watch mark json for a given bb '''
    ''' The given bb is a static value.  The watchmark eip may be offset by a shared library load address '''
    if not os.path.isfile(trackio):
        if not quiet:
            print('ERROR: getWatchMark no trackio file at %s' % trackio)
        if lgr is not None:
            lgr.debug('ERROR: getWatchMark no trackio file at %s' % trackio)

        return retval
    try:
        tjson = json.load(open(trackio))
    except:
        print('ERROR: failed reading json from %s' % trackio)
        if lgr is not None:
            lgr.debug('ERROR: failed reading json from %s' % trackio)
        return retval
    index = 1
    somap = tjson['somap']
    offset = resimUtils.getLoadOffsetFromSO(somap, prog, lgr=lgr)
    if offset is None:
        offset = 0
    if lgr is not None:
        lgr.debug('trackio file %s load offset of %s is 0x%x' % (trackio, prog, offset))
    reset_count = 0
    if offset != None:
        #print('not wrong file')
        mark_list = tjson['marks']

        sorted_marks = sorted(mark_list, key=lambda x: x['cycle'])
        last_cycle = None
        for mark in sorted_marks:
            if last_cycle is not None and mark['cycle'] < last_cycle:
                print('out of order')
            else:
                last_cycle = mark['cycle']
            if mark['mark_type'] == 'reset_origin':
                reset_count += 1
            if mark['mark_type'] in read_marks:
                eip = mark['ip'] - offset
                #print('is 0x%x in bb 0x%x - 0x%x' % (eip, bb['start_ea'], bb['end_ea']))
                if lgr is not None:
                    lgr.debug('is 0x%x in bb 0x%x - 0x%x' % (eip, bb['start_ea'], bb['end_ea']))
                if eip >= bb['start_ea'] and eip < bb['end_ea']:
                    #print('getWatchMarks found read mark at 0x%x index: %d json: %s' % (eip, index, trackio))
                    retval = (eip, mark['packet'], reset_count)
                    break
            index = index + 1
    return retval
       
def getBBCycle(coverage, bb): 
    retval = None
    ''' Find cycle at which a given bb was hit in the coverage json '''
    if not os.path.isfile(coverage):
        print('ERROR: no coverage file at %s' % coverage)
        return None
    try:
        cjson = json.load(open(coverage))
    except:
        #print('ERROR: failed reading json from %s' % coverage)
        return None

    bb_str = str(bb)
    if bb_str in cjson:
        retval = cjson[bb_str]['cycle']
    else:
        print('Could not find bb 0x%x in json %s' % (bb, coverage))
    return retval
def main():
    parser = argparse.ArgumentParser(prog='findBBB', description='Show AFL queue entries that lead to a given basic block address.')
    parser.add_argument('target', action='store', help='The target, e.g., the name of the workspace.')
    parser.add_argument('bb', action='store', help='The address of the basic block.')
    parser.add_argument('-a', '--all', action='store_true', help='Look at all queue files, no just unique list.')
    args = parser.parse_args()
    if args.target.endswith('/'):
        args.target = args.target[:-1]
    findBB(args.target, int(args.bb, 16), get_all=args.all)

if __name__ == '__main__':
    sys.exit(main())
