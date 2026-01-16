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
read_marks = ['read', 'compare', 'scan', 'sprint', 'strchr', 'strt']
class FindBB():
    def __init__(self):
        self.prog_offsets = {}
        self.cover_lists = {}
        self.track_marks = {}
        self.hit_list = {}

    def getBBList(self, target, bb, quiet=False, get_all=False, lgr=None, auto=False):
        '''
        Return a list of queue files that hit a given BB start address
        '''
        retval = []
        if target not in self.cover_lists:
            self.cover_lists[target] = aflPath.getAFLCoverageList(target, get_all=get_all, auto=auto, lgr=lgr)
            if lgr is not None:
                lgr.debug('findBB got %d cover files' % len(self.cover_lists[target]))
            for cover in self.cover_lists[target]:
                with open(cover) as fh:
                    try:
                        self.hit_list[cover] = json.load(fh)
                    except:
                        if lgr is not None:
                            lgr.debug('findBB Failed to open %s' % cover)
                        print('Failed to open %s' % cover)
                        continue

        cover_list = self.cover_lists[target]
        if len(cover_list) == 0:
            print('No coverage found for %s' % target)
            return retval
        #print('%d files found' % len(cover_list))
        for cover in cover_list:
            if str(bb) in self.hit_list[cover]:
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
    
    def getFirstReadCycle(self, trackio, quiet=False):
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
    
    def getWatchMark(self, trackio, bb, prog, quiet=False, lgr=None):
        ''' Find a read watch mark within a given watch mark json for a given bb 
            The given bb is a static value.  The watchmark eip may be offset by a shared library load address '''
        #print('in getWatchMark')
        retval = (None, None, None)
        if prog not in self.track_marks:
            self.track_marks[prog] = {}
        if trackio not in self.track_marks[prog]:
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
            if prog not in self.prog_offsets:
                somap = tjson['somap']
                prog_offset = resimUtils.getLoadOffsetFromSO(somap, prog, lgr=lgr)
                if prog_offset is None:
                    prog_offset = 0
                self.prog_offsets[prog] = prog_offset
                if lgr is not None:
                    lgr.debug('trackio file %s load offset of %s is 0x%x' % (trackio, prog, prog_offset))
            mark_list = tjson['marks']
            sorted_marks = sorted(mark_list, key=lambda x: x['cycle'])
            self.track_marks[prog][trackio] = sorted_marks
        index = 1
        if prog not in self.prog_offsets:
            lgr.error('findBB prog %s not in prog_offsets cache???')
            return
        offset = self.prog_offsets[prog] 
        reset_count = 0
        if offset != None:
            #print('not wrong file')
            last_cycle = None
            for mark in self.track_marks[prog][trackio]:
                if last_cycle is not None and mark['cycle'] < last_cycle:
                    print('out of order')
                else:
                    last_cycle = mark['cycle']
                if mark['mark_type'] == 'reset_origin':
                    reset_count += 1
                if mark['mark_type'] in read_marks:
                    eip = mark['ip'] - offset
                    #print('is 0x%x in bb 0x%x - 0x%x' % (eip, bb['start_ea'], bb['end_ea']))
                    #if lgr is not None:
                    #    lgr.debug('is 0x%x in bb 0x%x - 0x%x' % (eip, bb['start_ea'], bb['end_ea']))
                    if eip >= bb['start_ea'] and eip < bb['end_ea']:
                        #print('getWatchMarks found read mark at 0x%x index: %d json: %s' % (eip, index, trackio))
                        retval = (eip, mark['packet'], reset_count)
                        break
                index = index + 1
        return retval
           
    def getBBCycle(self, coverage, bb): 
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
    my_bb = FindBB()
    my_bb.findBB(args.target, int(args.bb, 16), get_all=args.all)

if __name__ == '__main__':
    sys.exit(main())
