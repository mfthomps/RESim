#!/usr/bin/env python
#
#
import sys
import os
import glob
import json
import argparse
def getIdaData(prog):
    retval = None
    resim_ida_data = os.getenv('RESIM_IDA_DATA')
    if resim_ida_data is None:
        print('RESIM_IDA_DATA not defined')
        exit(1)
    else: 
        retval = os.path.join(resim_ida_data, prog, prog)
    return retval

def findBNT(hits, fun_blocks):
    for bb in fun_blocks['blocks']:
        for bb_hit in hits:
            if bb_hit == bb['start_ea']:
                for branch in bb['succs']:
                    if branch not in hits:
                        print('function: %s branch 0x%x from 0x%x not in hits' % (fun_blocks['name'], branch, bb_hit))

def aflBNT(prog, target, fun_name=None):
    ida_path = getIdaData(prog)
    print('prog: %s  ida_path is %s' % (prog, ida_path))
    if True:
        if target is None:
            fname = '%s.hits' % ida_path
        else:
            print('is none, double dip')
            fname = '%s.%s.hits' % (ida_path, target)
        ''' hits are now just flat lists without functoins '''
        hits = json.load(open(fname))
        data_path = ida_path+'.prog'
        with open(data_path) as fh:
            lines = fh.read().strip().splitlines()
            print('num lines is %d' % len(lines))
            prog_file = lines[0].strip()
        block_file = prog_file+'.blocks'
        blocks = json.load(open(block_file))
        print('aflBNT found %d hits and %d blocks' % (len(hits), len(blocks)))
        if fun_name is None:
            for fun in blocks:
                findBNT(hits, blocks[fun])
        else:
            for fun in blocks:
                if blocks[fun]['name'] == fun_name:
                    findBNT(hits, blocks[fun])
                    break

def main():
    parser = argparse.ArgumentParser(prog='findBNT', description='Show branches not taken.')
    parser.add_argument('prog', action='store', help='The target program')
    parser.add_argument('-t', '--target', action='store', help='Optional target name, e.g., name of the workspace.')
    parser.add_argument('-f', '--function', action='store', help='Optional function name')
    args = parser.parse_args()
    aflBNT(args.prog, args.target, args.function)

if __name__ == '__main__':
    sys.exit(main())
