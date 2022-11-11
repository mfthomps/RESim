#!/usr/bin/env python
#
#
import sys
import os
import glob
import json
import argparse
import findBB
resim_dir = os.getenv('RESIM_DIR')
sys.path.append(os.path.join(resim_dir, 'simics', 'monitorCore'))
import resimUtils
import elfText
'''
Find BNT's by looking at AFL coverage files.
Will read trackio data from AFL with the -d option and report on 
watch marks that occur within the BB that leads to the BNT.
'''



def findBNT(target, hits, fun_blocks, no_print, prog, prog_elf, show_read_marks, quiet):
    retval = []
    count = 0
    #print('in findBNT')
    for bb in fun_blocks['blocks']:
        for bb_hit in hits:
            #print('compare %s to %s' % (bb_hit, bb['start_ea']))
            if bb_hit == bb['start_ea']:
                if bb_hit < prog_elf.address or bb_hit > (prog_elf.address + prog_elf.size):
                    #print('bb_hit 0x%x not in program text' % bb_hit)
                    continue
                #print('check bb_hit 0x%x' % bb_hit)
                for branch in bb['succs']:
                    if branch not in hits:
                        read_mark = None
                        before_read = ''
                        if show_read_marks:
                            queue_list = findBB.findBB(target, bb_hit, True) 
                            for q in queue_list:
                                trackio = q.replace('queue', 'trackio')   
                                coverage = q.replace('queue', 'coverage')   
                                read_mark = findBB.getWatchMark(trackio, bb, prog, quiet=quiet)
                                first_read = findBB.getFirstReadCycle(trackio, quiet=quiet)
                                bb_cycle = findBB.getBBCycle(coverage, bb_hit)
                                if read_mark is not None:
                                    if (bb['end_ea'] - read_mark) < 20:
                                        #print('qfile: %s had readmark at 0x%x' % (q, read_mark))
                                        pass
                                    break
                                elif bb_cycle < first_read:
                                    before_read = 'pre-read' 
 
                        if not no_print:
                            mark_info = ''
                            if read_mark is not None:
                                mark_info = 'read mark: 0x%x' % read_mark
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

def aflBNT(prog, target, read_marks, fun_name=None, no_print=False, quiet=False):
    ida_path = resimUtils.getIdaData(prog)
    print('prog: %s  ida_path is %s' % (prog, ida_path))
    bnt_list = []
    if target is None:
        fname = '%s.hits' % ida_path
    else:
        fname = '%s.%s.hits' % (ida_path, target)
        print('Using hits file %s' % fname)
    ''' hits are now just flat lists without functions '''
    with open(fname) as fh:
        hits = json.load(fh)

    blocks, prog_elf = resimUtils.getBasicBlocks(prog)
    if blocks is None:
        print('Falied to find blocks for %s, perhaps a symbolic link?' % prog)
        return bnt_list

    if not no_print:
        num_blocks = 0
        num_funs = len(blocks)
        for f in blocks:
            num_blocks = num_blocks + len(blocks[f]['blocks']) 
        print('aflBNT found %d hits, %d functions and %d blocks' % (len(hits), num_funs, num_blocks))
    if fun_name is None:
        for fun in blocks:
            this_list = findBNT(target, hits, blocks[fun], no_print, prog, prog_elf, read_marks, quiet)
            bnt_list.extend(this_list)
    else:
        for fun in blocks:
            if blocks[fun]['name'] == fun_name:
                this_list = findBNT(target, hits, blocks[fun], no_print, prog, prog_elf, read_marks, quiet)
                bnt_list.extend(this_list)
                break
    return bnt_list

def main():
    parser = argparse.ArgumentParser(prog='findBNT', description='Show branches not taken for a given program.')
    parser.add_argument('prog', action='store', help='The target program')
    parser.add_argument('-t', '--target', action='store', help='Optional target name, e.g., name of the workspace.')
    parser.add_argument('-f', '--function', action='store', help='Optional function name')
    parser.add_argument('-d', '--datamarks', action='store_true', help='Look for read watch marks in the BB')
    parser.add_argument('-q', '--quiet', action='store_true', help='Do not report missing trackio files')
    args = parser.parse_args()
    bnt_list = aflBNT(args.prog, args.target, args.datamarks, fun_name=args.function, quiet=args.quiet)
    print('Found %d branches not taken.' % len(bnt_list))

if __name__ == '__main__':
    sys.exit(main())
