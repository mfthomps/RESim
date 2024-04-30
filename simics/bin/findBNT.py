#!/usr/bin/env python3
#
#
import sys
import os
import glob
import json
import argparse
import findBB
import findTrack
resim_dir = os.getenv('RESIM_DIR')
sys.path.append(os.path.join(resim_dir, 'simics', 'monitorCore'))
import resimUtils
import elfText
'''
Find BNT's by looking at hits files.
Will read trackio data from AFL with the -d option and report on 
watch marks that occur within the BB that leads to the BNT.
'''



def findBNTForFun(target, hits, fun_blocks, no_print, prog, prog_elf, show_read_marks, quiet, lgr):
    retval = []
    count = 0
    #print('in findBNTForFun')
    for bb in fun_blocks['blocks']:
        for bb_hit in hits:
            #print('compare %s to %s' % (bb_hit, bb['start_ea']))
            if bb_hit == bb['start_ea']:
                if bb_hit < prog_elf.text_start or bb_hit > (prog_elf.text_start + prog_elf.text_size):
                    #print('bb_hit 0x%x not in program text' % bb_hit)
                    continue
                #print('check bb_hit 0x%x' % bb_hit)
                for branch in bb['succs']:
                    if branch not in hits:
                        read_mark = None
                        packet_num = None
                        before_read = ''
                        lgr.debug('bb_hit 0x%x has branch 0x%x not in hits' % (bb_hit, branch))
                        if show_read_marks:
                            queue_list = findBB.findBB(target, bb_hit, True) 
                            least_packet = 100000
                            least_size = 100000
                            least_marks = 100000
                            best_result_size = None
                            best_result_marks = None
                            best = None
                            # look at every trackIO that has a WM in this BB and find the "best" of them
                            for q in queue_list:
                                trackio = q.replace('queue', 'trackio')   
                                coverage = q.replace('queue', 'coverage')   
                                read_mark, packet_num = findBB.getWatchMark(trackio, bb, prog, quiet=quiet)
                                if read_mark is not None:
                                    ''' Look for the best mark '''
                                    result = findTrack.findTrack(trackio, read_mark, True, prog, quiet=True, lgr=lgr)
                                    lgr.debug('found read_mark 0x%x  result %s' % (read_mark, str(result)))
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
                                            if result.num_marks < least_marks:
                                                least_marks = result.num_marks
                                                best_result_marks = result
                                            if result.size < least_size:
                                                least_size = result.size
                                                best_result_size = result

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
                        if not no_print:
                            mark_info = ''
                            if read_mark is not None:
                                mark_info = 'read mark: 0x%x packet: %d size: %d' % (read_mark, packet_num, least_size)
                            print('function: %s branch 0x%x from 0x%x not in hits %s %s' % (fun_blocks['name'], branch, bb_hit, mark_info, before_read))
                            count = count + 1
                        entry = {}
                        entry['bnt'] = branch
                        entry['source'] = bb_hit
                        entry['read_mark'] = read_mark
                        retval.append(entry)
                    #else:
                    #    print('branch 0x%x in hits' % branch)
    return retval

def findBNT(prog, ini, target, read_marks, fun_name=None, no_print=False, quiet=False):
    lgr = resimUtils.getLogger('findBNT', '/tmp', level=None)
    lgr.debug('findBNT begin')
    #ida_path = resimUtils.getIdaData(prog)
    ida_path = resimUtils.getIdaDataFromIni(prog, ini)
    #print('prog: %s  ida_path is %s' % (prog, ida_path))
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
    blocks, prog_elf = resimUtils.getBasicBlocks(prog, ini, lgr=lgr)
    if blocks is None:
        print('Falied to find blocks for %s, perhaps a symbolic link?' % prog)
        return bnt_list

    if not no_print:
        num_blocks = 0
        num_funs = len(blocks)
        for f in blocks:
            num_blocks = num_blocks + len(blocks[f]['blocks']) 
        print('findBNT found %d hits, %d functions and %d blocks' % (len(hits), num_funs, num_blocks))
    if fun_name is None:
        for fun in sorted(blocks):
            this_list = findBNTForFun(target, hits, blocks[fun], no_print, prog, prog_elf, read_marks, quiet, lgr)
            bnt_list.extend(this_list)
    else:
        for fun in blocks:
            if blocks[fun]['name'] == fun_name:
                this_list = findBNTForFun(target, hits, blocks[fun], no_print, prog, prog_elf, read_marks, quiet, lgr)
                bnt_list.extend(this_list)
                break
    return bnt_list

def main():
    parser = argparse.ArgumentParser(prog='findBNT', description='Show branches not taken for a given program.')
    parser.add_argument('ini', action='store', help='The ini file')
    parser.add_argument('prog', action='store', help='The target program')
    parser.add_argument('-t', '--target', action='store', help='Optional target name, e.g., name of the workspace.')
    parser.add_argument('-f', '--function', action='store', help='Optional function name')
    parser.add_argument('-d', '--datamarks', action='store_true', help='Look for read watch marks in the BB')
    parser.add_argument('-q', '--quiet', action='store_true', help='Do not report missing trackio files')
    args = parser.parse_args()
    bnt_list = findBNT(args.prog, args.ini, args.target, args.datamarks, fun_name=args.function, quiet=args.quiet)
    if bnt_list is not None:
        print('Found %d branches not taken.' % len(bnt_list))

if __name__ == '__main__':
    sys.exit(main())
