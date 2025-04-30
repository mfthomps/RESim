#!/usr/bin/env python3
'''
Find new states that let us reach new code paths, and the queue files that
that hit the new paths.
'''
import sys
import os
import json
import glob
import argparse
from collections import OrderedDict
resim_dir = os.getenv('RESIM_DIR')
sys.path.append(os.path.join(resim_dir, 'simics', 'monitorCore'))
import aflPath
def whoHitThese(target, new_hit_list, quiet):
    cover_list = aflPath.getAFLCoverageList(target, get_all=False)
    these_hit_new = {}
    for cover in cover_list:
        with open(cover) as fh:
            try:
                hit_list = json.load(fh)
            except:
                print('Failed to open %s' % cover)
                exit(1)
            for hit in new_hit_list:
                hit_string = '%d' % hit
                if hit_string in hit_list:
                    if cover not in these_hit_new:
                        these_hit_new[cover]=[]
                    these_hit_new[cover].append(hit)

    if not quiet:
        print('found %d cover files that hit at least one new hit found in target %s' % (len(these_hit_new), target))
        count = 0
        for cover in these_hit_new:
            print('\t%d %s number of hits %d' % (count, cover, len(these_hit_new[cover])))
            count += 1
    else:
        for cover in these_hit_new:
            print('%s %s' % (target, cover))
 
def main():
    '''
    New states defined as fuzzing sessions that led to new blocks
    '''
    parser = argparse.ArgumentParser(prog='find_new_states', description='Find new states that let us reach new execution paths')
    parser.add_argument('target', action='store', help='AFL target that is the baseline.')
    parser.add_argument('-v', '--verbose', action='store_true', help='Show the hits')
    parser.add_argument('-q', '--quiet', action='store_true', help='Only list queue files')
    parser.add_argument('-i', '--index', action='store', type=str, help='Optional progression index.')
    args = parser.parse_args()
    expaths_baseline = aflPath.getAFLCoverageList(args.target)
    if len(expaths_baseline) == 0:
        print('No paths found for %s' % args.target)
        exit(1)

    # Baseline of hits
    hits_baseline = []
    for path in expaths_baseline:
        cover = json.load(open(path))
        #print('doing %s' % path)
        for hit in cover:
            hit = int(hit)
            if hit not in hits_baseline:
                hits_baseline.append(hit)
    if args.index is not None:
        # Extend baseline to include every result prior to and including the given index level
        levels = args.index.count('_')+2
        next_glob_mask = 'auto_ws/next_ws_'+args.index+'_*'
        prev_glob_mask = 'auto_ws/next_ws_*'
        if not args.quiet:
            print('using prev_glob_mask of %s' % prev_glob_mask)
        glist = glob.glob(prev_glob_mask)
        for some_ws in glist: 
            basename = os.path.basename(some_ws)
            if basename.count('_') > levels:
                #print('levels %d count(_) %d, %s too deep, skip it' % (levels, basename.count('_'), basename))
                continue
            expaths2 = aflPath.getAFLCoverageList(basename)
            if len(expaths2) == 0:
                print('No paths found for %s' % some_ws)
                exit(1)
            for path in expaths2:
                cover = json.load(open(path))
                #print('doing %s' % path)
                for hit in cover:
                    hit = int(hit)
                    if hit not in hits_baseline:
                        hits_baseline.append(hit)
        # increment for use in next states
        levels = levels + 1
    else:
        # initial state and initial fuzzing results.
        next_glob_mask = 'auto_ws/next_ws_*'
        levels = 2
    if not args.quiet:
        print('Baseline hits found is %d' % len(hits_baseline)) 

    next_ws_list = []
    glist = glob.glob(next_glob_mask)
    new_ws_hits = {}
    if not args.quiet:
        if args.index is None:
            print('Found %d workspaces in auto_ws' % (len(glist)))
        else:
            print('Found %d workspaces in auto_ws/next_ws_%s using glob mask %s' % (len(glist), args.index, next_glob_mask))
    for next_ws in sorted(glist):
        next_ws = os.path.basename(next_ws)
        if next_ws.count('_') > levels:
            #print('levels %d count(_) %d, %s too deep, skip it' % (levels, next_ws.count('_'), next_ws))
            continue
        expaths2 = aflPath.getAFLCoverageList(next_ws)
        if len(expaths2) == 0:
            print('No paths found for %s' % next_ws)
            exit(1)
        # list of all hits found in this workstation cover list
        ws_hits = []
        debug_this = {}
        for path in expaths2:
            cover = json.load(open(path))
            #print('doing %s' % path)
            for hit in cover:
                hit = int(hit)
                if hit not in ws_hits:
                    ws_hits.append(hit)
                    debug_this[hit] = path
        num_diff1 = 0
        num_diff2 = 0
        for hit in hits_baseline:
            if hit not in ws_hits:
                num_diff1 += 1
        for hit in ws_hits:
            if hit not in hits_baseline:
                #print('0x%x in second, not first' % hit)
                if next_ws not in new_ws_hits:
                    new_ws_hits[next_ws] = []
                new_ws_hits[next_ws].append(hit)
                num_diff2 += 1
        if num_diff1 == 0 and num_diff2 == 0:
            #print('\tSame blocks hit in both targets.')
            pass
        elif not args.quiet:
            print('Found %d hits in %s' % (len(ws_hits), next_ws))
            print('\t%d hits in baseline not in %s' % (num_diff1, next_ws))
            print('\t%d hits in %s not in baseline' % (num_diff2, next_ws))
    ''' find unique sets of hits '''
    if not args.quiet:
        print('Found %d states with new hits' % len(new_ws_hits))
    unique = []
    for ws in new_ws_hits:
        found_in_unique = False
        # does a unique list item already match all hits in the new_ws_hits[ws]?
        for other_ws in unique:
            if len(new_ws_hits[other_ws]) == len(new_ws_hits[ws]):
                found_in_unique = True
                for hit in new_ws_hits[ws]:
                    if hit not in new_ws_hits[other_ws]:
                        found_in_unique = False
                        break     
            if found_in_unique:
                #print('All hits in %s already matched in unique list ws %s' % (ws, other_ws))
                break
        if not found_in_unique:
            if not args.quiet:
                print('ws %s has a unique new hit list of len %d' % (ws, len(new_ws_hits[ws])))
            unique.append(ws)

    for ws in unique:
        whoHitThese(ws, new_ws_hits[ws], args.quiet)    
        if args.verbose:
            for hit in new_ws_hits[ws]:
                print('new ws hit 0x%x' % hit)
        
    
if __name__ == '__main__':
    sys.exit(main())
