#!/usr/bin/env python3
'''
Find new states that let us reach new code paths, and the queue files that
that hit the new paths.
    NOTE: respect quiet switch, output used by bash scripts
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
def whoHitThese(target, new_hit_list, quiet, tabs):
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

    if quiet > 1:
        print(tabs+'found %d cover files that include at least one new hit found in target %s' % (len(these_hit_new), target))
        count = 0
        for cover in these_hit_new:
            print(tabs+'\t%d %s number of hits %d' % (count, cover, len(these_hit_new[cover])))
            count += 1
    elif quiet > 0:
        for cover in these_hit_new:
            print(tabs+'%s %s' % (target, cover))
    return these_hit_new

def findStates(target, quiet, state_id, recurse, sibling, only_ws=None):
    ''' Find new states resulting from fuzzing '''
    # in case run from auto_ws workspace
    here = os.getcwd()
    if 'auto_ws' in here:
        # we would be at target/auto_ws/next_ws_eh/resim_eh
        glob_prefix = '../../../'
    else:
        glob_prefix = ''
    retval = []
    num_tabs = 0
    tabs = ''
    if state_id is not None:
        num_tabs = state_id.count('_')+1
    for i in range(num_tabs):
        tabs = tabs + '\t' 
    expaths_baseline = aflPath.getAFLCoverageList(target)
    if len(expaths_baseline) == 0:
        print(tabs+'***No paths found for target %s when looking for new states.' % target)
        #exit(1)
        return retval
    # Baseline of hits
    hits_baseline = []
    for path in expaths_baseline:
        cover = json.load(open(path))
        #print('doing %s' % path)
        for hit in cover:
            hit = int(hit)
            if hit not in hits_baseline:
                hits_baseline.append(hit)
    if state_id is not None:
        # Extend baseline to include every result prior to and including the given state_id level
        levels = state_id.count('_')+2
        next_glob_mask = glob_prefix+'auto_ws/next_ws_'+state_id+'_*'
        prev_glob_mask = glob_prefix+'auto_ws/next_ws_*'
        #if not quiet:
        #    print(tabs+'using prev_glob_mask of %s' % prev_glob_mask)
        glist = glob.glob(prev_glob_mask)
        for some_ws in glist: 
            basename = os.path.basename(some_ws)
            if basename.count('_') > levels:
                #print('levels %d count(_) %d, %s too deep, skip it' % (levels, basename.count('_'), basename))
                continue
            if sibling and not basename.startswith('next_ws_%s' % state_id):
                continue
            expaths2 = aflPath.getAFLCoverageList(basename)
            if len(expaths2) == 0:
                print(tabs+'***No paths found for next workspace %s while trying to expand baseline hits.' % some_ws)
                #exit(1)
                continue
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
        next_glob_mask = glob_prefix+'auto_ws/next_ws_*'
        levels = 2
    if quiet > 1:
        print(tabs+'Baseline hits found is %d' % len(hits_baseline)) 

    next_ws_list = []
    glist = glob.glob(next_glob_mask)
    new_ws_hits = {}
    if quiet > 1:
        if state_id is None:
            print(tabs+'Found %d workspaces in auto_ws' % (len(glist)))
        else:
            print(tabs+'Found %d workspaces in auto_ws/next_ws_%s using glob mask %s' % (len(glist), state_id, next_glob_mask))
    for next_ws in sorted(glist):
        next_ws = os.path.basename(next_ws)
        if next_ws.count('_') > levels:
            #print('levels %d count(_) %d, %s too deep, skip it' % (levels, next_ws.count('_'), next_ws))
            continue
        expaths2 = aflPath.getAFLCoverageList(next_ws)
        if len(expaths2) == 0:
            print(tabs+'***No paths found for %s when looking for new states.' % next_ws)
            #exit(1)
            continue
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
        elif quiet > 1:
            print(tabs+'Found %d hits in %s' % (len(ws_hits), next_ws))
            print(tabs+'\t%d hits in baseline not in %s' % (num_diff1, next_ws))
            print(tabs+'\t%d hits in %s not in baseline' % (num_diff2, next_ws))
    ''' find unique sets of hits '''
    if quiet > 1 and len(glist) > 0:
        if len(new_ws_hits) > 0:
            print(tabs+'Found %d states with new hits (relative to parent states).  Duplicates are removed below.' % len(new_ws_hits))
        else:
            print(tabs+'Found no states with hits not already found in parent states or sibling states that were already processed.')
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
            if quiet > 1:
                print(tabs+'ws %s has a unique new hit list of len %d' % (ws, len(new_ws_hits[ws])))
            unique.append(ws)

    for ws in unique:
        #print('check %s against %s' % (ws, only_ws))
        if only_ws is not None and not ws.startswith(only_ws):
            continue
        ws_retval = whoHitThese(ws, new_ws_hits[ws], quiet, tabs)    
        retval.extend(ws_retval)
        if quiet > 2:
            for hit in new_ws_hits[ws]:
                print(tabs+'new ws hit 0x%x' % hit)
        if recurse:
            state_id = ws[8:]
            #print('\t state_id would be %s' % state_id)
            new_retval = findStates(target, quiet, state_id, recurse, sibling)
            retval.extend(new_retval)
    return retval 

def getTarget():
    here = os.getcwd()
    if 'auto_ws' in here:
        # we would be at target/auto_ws/next_ws_eh/resim_eh
        target = os.path.basename(os.path.dirname(os.path.dirname(os.path.dirname(here))))
    else:
        target = os.path.basename(here)
    return target 

def queueFilesForWS(ws):
    if not ws.startswith('next_ws_'):
        print('Workspace must start with next_ws_, followed by a state id')
        return None
    state_id = ws[8:]
    if '_' in state_id:
        parent_state = state_id.rsplit('_', 1)[0]
    else: 
        parent_state = None
    target = getTarget()
    retval = findStates(target, 0, parent_state, False, False, only_ws=ws)
    return retval

def allQueueFiles(ws):
    retval = []
    track_list = findStates(ws, 0, None, True, False)
    for item in track_list:
        #print('item %s' % item)
        cover_file = item.strip()
        qfile = cover_file.replace('coverage', 'queue')
        retval.append(qfile)
    return retval

def main():
    '''
    New states defined as fuzzing sessions that led to new blocks

    NOTE: respect quiet switch, output used by bash scripts
    '''
    parser = argparse.ArgumentParser(prog='find_new_states', description='Find new states that let us reach new execution paths. Must be run from workspace.')
    parser.add_argument('-v', '--verbose', action='store_true', help='Show the hits')
    parser.add_argument('-q', '--quiet', action='store_true', help='Only list queue files')
    parser.add_argument('-r', '--recurse', action='store_true', help='Recurse through state transitions')
    parser.add_argument('-i', '--state_id', action='store', type=str, help='Optional progression state_id.')
    parser.add_argument('-s', '--sibling', action='store_true', help='Exclude hits already identified by processing sibling states (only meaningful with state_id).')
    args = parser.parse_args()
    target = getTarget()
    # quiet_level -- 0 = no output;  1 = only q files; 2 = summary data; 3 = verbose
    # level zero only used via api, not available in main
    if args.quiet and args.verbose:
        print('Cannot request both quiet and verbose')
        exit(1)
    if args.verbose:
        quiet = 3
    elif args.quiet:
        quiet = 1
    else:
        quiet = 2
    findStates(target, quiet, args.state_id, args.recurse, args.sibling)
    
if __name__ == '__main__':
    sys.exit(main())
