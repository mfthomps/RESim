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
import resimUtils
import elfText
'''
Find BNT's by looking at AFL coverage files.
'''

def findBNT(hits, fun_blocks, quiet, prog_elf):
    retval = []
    for bb in fun_blocks['blocks']:
        for bb_hit in hits:
            if bb_hit == bb['start_ea']:
                if bb_hit < prog_elf.address or bb_hit > (prog_elf.address + prog_elf.size):
                    #print('bb_hit 0x%x not in program text' % bb_hit)
                    continue
                #print('check bb_hit 0x%x' % bb_hit)
                for branch in bb['succs']:
                    if branch not in hits:
                        if not quiet:
                            print('function: %s branch 0x%x from 0x%x not in hits' % (fun_blocks['name'], branch, bb_hit))
                        entry = {}
                        entry['bnt'] = branch
                        entry['source'] = bb_hit
                        retval.append(entry)
                    #else:
                    #    print('branch 0x%x in hits' % branch)
    return retval

def aflBNT(prog, target, fun_name=None, quiet=False):
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
    prog_file = resimUtils.getProgPath(prog)
    prog_elf = elfText.getTextOfText(prog_file)
    print('prog addr 0x%x size %d' % (prog_elf.address, prog_elf.size))
    block_file = prog_file+'.blocks'
    print('block file is %s' % block_file)
    if not os.path.isfile(block_file):
        print('block file not found %s' % block_file)
        return
    with open(block_file) as fh:
        blocks = json.load(fh)
    if not quiet:
        num_blocks = 0
        num_funs = len(blocks)
        for f in blocks:
            num_blocks = num_blocks + len(blocks[f]['blocks']) 
        print('aflBNT found %d hits, %d functions and %d blocks' % (len(hits), num_funs, num_blocks))
    if fun_name is None:
        for fun in blocks:
            this_list = findBNT(hits, blocks[fun], quiet, prog_elf)
            bnt_list.extend(this_list)
    else:
        for fun in blocks:
            if blocks[fun]['name'] == fun_name:
                this_list = findBNT(hits, blocks[fun], quiet, prog_elf)
                bnt_list.extend(this_list)
                break
    return bnt_list

def main():
    parser = argparse.ArgumentParser(prog='findBNT', description='Show branches not taken for a given program.')
    parser.add_argument('prog', action='store', help='The target program')
    parser.add_argument('-t', '--target', action='store', help='Optional target name, e.g., name of the workspace.')
    parser.add_argument('-f', '--function', action='store', help='Optional function name')
    args = parser.parse_args()
    aflBNT(args.prog, args.target, fun_name=args.function)

if __name__ == '__main__':
    sys.exit(main())
