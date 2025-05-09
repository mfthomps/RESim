#!/usr/bin/env python3
#
#
import sys
import os
import json
import shutil
import argparse
import findBB
import findTrack
resim_dir = os.getenv('RESIM_DIR')
sys.path.append(os.path.join(resim_dir, 'simics', 'monitorCore'))
import resimUtils
import elfText
import aflPath
'''
Find BNT's by looking at hits files.
Will read trackio data from AFL with the -d option and report on 
watch marks that occur within the BB that leads to the BNT.
'''

def findReadMarks(bnt_list, target, prog, auto, quiet, no_reset, lgr):
    find_bb = findBB.FindBB()
    if target is None:
       target_prog = prog
    else:
       target_prog = target
    lgr.debug('findBNT findReadMarks')
    for entry in bnt_list:
        bb_hit = entry['source']
        queue_list = find_bb.findBB(target_prog, bb_hit, True, lgr=lgr, auto=auto) 
        lgr.debug('findBNT findReadMarks len of qlist for bb_hit 0x%x is %d' % (bb_hit, len(queue_list)))
        least_packet = 100000
        least_size = 100000
        least_marks = 100000
        least_resets = 100000
        best_result_size = None
        best_result_marks = None
        without_resets = None
        best = None
        # look at every trackIO that has a WM in this BB and find the "best" of them
        for q in queue_list:
            #lgr.debug('findBNT findReadMarks queue file %s' % q)
            trackio = q.replace('queue', 'trackio')   
            coverage = q.replace('queue', 'coverage')   
            read_mark, packet_num, num_resets = find_bb.getWatchMark(trackio, entry['bb'], prog, quiet=quiet, lgr=lgr)
            if read_mark is not None:
                ''' Look for the best mark '''
                result, num_resetsx = findTrack.findTrackMark(trackio, read_mark, True, prog, quiet=True, lgr=lgr)
                lgr.debug('found read_mark 0x%x  result %s num_resets from findBB %d, from findTrac %d' % (read_mark, str(result), num_resets, num_resetsx))
                if result is not None:
                    if result.mark['packet'] < least_packet:
                        least_packet = result.mark['packet']
                        least_marks = result.num_marks
                        least_size = result.size
                        best_result_marks = None
                        best_result_size = None
                        best = result
                    #elif result.mark['packet'] == least_packet and result.size < least_size:
                    #    least_size = result.size
                    #    best_result = result
                    elif result.mark['packet'] == least_packet:
                        if no_reset and without_resets is None and num_resets == 0:
                            without_resets = result
                        if result.num_marks < least_marks and (not no_reset or num_resets == 0 or without_resets is None):
                            least_marks = result.num_marks
                            best_result_marks = result
                        if result.size < least_size and (not no_reset or num_resets == 0 or without_resets is None):
                            least_size = result.size
                            best_result_size = result
            else:
                #lgr.debug('No read read_mark found')
                pass

        if best_result_marks is not None and best_result_size is not None:
            delta_marks = best_result_size.num_marks - best_result_marks.num_marks
            delta_size = best_result_marks.size - best_result_size.size
            lgr.debug('delta_marks %d best_marks %d  delta_size %d best_size %d' % (delta_marks, 
                       best_result_marks.num_marks, delta_size, best_result_size.size))
            if delta_marks == 0:
                best = best_result_size
            elif delta_size == 0:
                best = best_result_marks
            else:
                mark_ratio = delta_marks / best_result_marks.num_marks
                size_ratio = delta_size / best_result_size.size
                lgr.debug('best marks ratio %f   best size %f' % (mark_ratio, size_ratio))
                if mark_ratio > size_ratio:
                    best = best_result_marks
                else:
                    best = best_result_size
        elif best_result_marks is not None:
            best = best_result_marks
        elif best_result_size is not None:
            best = best_result_size
        else:
            # best is least packets
            pass 
        if best is None:
            lgr.debug('found no read marks')
            pass 
        else:
            read_mark = best.mark['ip']
            packet_num = best.mark['packet']
            entry['read_mark'] = read_mark
            entry['packet_num'] = packet_num
            entry['least_size'] = least_size


def findBNTForFun(target, hits, pre_hits, fun_blocks, no_print, prog, prog_elf, show_read_marks, quiet, no_reset, lgr, auto=False):
    retval = []
    count = 0
    #print('in findBNTForFun')
    #lgr.debug('findBNTForFun len of fun_blocks is %d num hits %d' % (len(fun_blocks['blocks']), len(hits)))
    #lgr.debug('findBNTForFun target %s' % target)
    # TBD would get_all every make sense here?  was true once...
    if target is None:
        here = os.getcwd()
        target = os.path.basename(here)
    for bb in fun_blocks['blocks']:
        for bb_hit in hits:
            #lgr.debug('compare %s to %s' % (bb_hit, bb['start_ea']))
            if bb_hit == bb['start_ea']:
                if bb_hit < prog_elf.text_start or bb_hit > (prog_elf.text_start + prog_elf.text_size):
                    lgr.debug('bb_hit 0x%x not in program text' % bb_hit)
                    continue
                #lgr.debug('check bb_hit 0x%x' % bb_hit)
                for branch in bb['succs']:
                    if branch not in hits and branch not in pre_hits:
                        read_mark = None
                        packet_num = None
                        lgr.debug('findBNTForFun target %s bb_hit 0x%x has branch 0x%x not in hits show read marks: %r' % (target, bb_hit, branch, show_read_marks))
                        #if not no_print:
                        #    print('function: %s branch 0x%x from 0x%x not in hits' % (fun_blocks['name'], branch, bb_hit))
                        #    count = count + 1
                        entry = {}
                        entry['bnt'] = branch
                        entry['source'] = bb_hit
                        entry['bb'] = bb
                        entry['fun'] = fun_blocks['name']
                        retval.append(entry)
    return retval

def findBNT(prog, ini, target, read_marks, fun_name=None, no_print=False, quiet=False, no_reset=False, auto=False):
    lgr = resimUtils.getLogger('findBNT', '/tmp', level=None)
    lgr.debug('findBNT begin')

    #ida_path = resimUtils.getIdaData(prog)
    prog_base = os.path.basename(prog)

    ida_path = resimUtils.getIdaDataFromIni(prog, ini, lgr=lgr)
    print('prog: %s  ida_path is %s' % (prog, ida_path))
    bnt_list = []
    if target is None:
        fname = '%s.hits' % ida_path
    else:
        fname = '%s.%s.hits' % (ida_path, target)

    print('Using hits file %s' % fname)
    lgr.debug('Using hits file %s prog: %s' % (fname, prog))
    ''' hits are now just flat lists without functions '''
    if not os.path.isfile(fname):
        print('No file at %s.  Did you forget to specific the --target?' % fname)
        return None
    with open(fname) as fh:
        hits = json.load(fh)

    pre_hits = []
    pre_fname = '%s.pre.hits' % ida_path
    if os.path.isfile(pre_fname):
        with open(pre_fname) as fh:
            pre_hits = json.load(fh)
 
    blocks, prog_elf = resimUtils.getBasicBlocks(prog, ini, lgr=lgr)
    if blocks is None:
        print('Falied to find blocks for %s, perhaps a symbolic link?' % prog)
        return bnt_list
    if prog_elf.text_start is None:
        # relocatable text. Set to zero
        lgr.debug('text_start is None, set to zero')
        prog_elf.text_start = 0
    
    if not no_print:
        num_blocks = 0
        num_funs = len(blocks)
        for f in blocks:
            num_blocks = num_blocks + len(blocks[f]['blocks']) 
        print('findBNT found %d hits, %d functions and %d blocks' % (len(hits), num_funs, num_blocks))
    if len(hits) == 0:
        print('*** No hits found in %s.  Try providing the --target option.' % fname)
    elif fun_name is None:
        for fun in sorted(blocks):
            #lgr.debug('call findBNTForFun for fun %s' % fun)
            this_list = findBNTForFun(target, hits, pre_hits, blocks[fun], no_print, prog, prog_elf, read_marks, quiet, no_reset, lgr, auto=auto)
            bnt_list.extend(this_list)
    else:
        for fun in blocks:
            if blocks[fun]['name'] == fun_name:
                this_list = findBNTForFun(target, hits, pre_hits, blocks[fun], no_print, prog, prog_elf, read_marks, quiet, no_reset, lgr, auto=auto)
                bnt_list.extend(this_list)
                break
    if read_marks:
        findReadMarks(bnt_list, target, prog, auto, quiet, no_reset, lgr)
    if not no_print:
        for entry in bnt_list:
            mark_info = ''
            if 'read_mark' in entry:
                read_mark = entry['read_mark']
                reset = ''
                if no_reset and without_resets is None:
                    reset = 'RESET'
                if read_mark is not None:
                    mark_info = 'read mark: 0x%x %s packet: %d size: %d' % (read_mark, reset, entry['packet_num'], entry['least_size'])
            print('function: %s branch 0x%x from 0x%x not in hits %s' % (entry['fun'], entry['bnt'], entry['source'], mark_info))
    return bnt_list

def main():
    parser = argparse.ArgumentParser(prog='findBNT', description='Show branches not taken for a given program.')
    parser.add_argument('ini', action='store', help='The ini file')
    parser.add_argument('prog', action='store', help='The target program. Provide the path relative to the root prefix')
    parser.add_argument('-t', '--target', action='store', help='The target name, e.g., name of the workspace.  Use this option unless you have renamed the hits file to the program name')
    parser.add_argument('-f', '--function', action='store', help='Optional function name')
    parser.add_argument('-d', '--datamarks', action='store_true', help='Look for read watch marks in the BB')
    parser.add_argument('-q', '--quiet', action='store_true', help='Do not report missing trackio files')
    parser.add_argument('-r', '--no_reset', action='store_true', help='Prioritize watchmarks that occur before a reset.')
    parser.add_argument('-a', '--auto', action='store_true', help='Include artifacts found in progressive fuzzing')
    args = parser.parse_args()
    bnt_list = findBNT(args.prog, args.ini, args.target, args.datamarks, fun_name=args.function, quiet=args.quiet, no_reset=args.no_reset, auto=args.auto)
    if bnt_list is not None:
        print('Found %d branches not taken.' % len(bnt_list))

if __name__ == '__main__':
    sys.exit(main())
