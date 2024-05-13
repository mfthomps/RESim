#!/usr/bin/env python3
#
#
import sys
import os
import argparse
from pathlib import Path
def main():
    parser = argparse.ArgumentParser(prog='bntMerge', description='Create BNT report annotated with results from previous resports.')
    parser.add_argument('bnt_file', action='store', help='The BNT file')
    args = parser.parse_args()
    old_bnt = './old_bnt'
    if not os.path.isdir(old_bnt):
        print('Old BNT reports not found, no directory at %s' % old_bnt)
        exit(1)

    if not os.path.isfile(args.bnt_file):
        print('No file at %s' % args.bnt_file)
        exit(1)
    #old_list = os.listdir(old_bnt)
    old_paths = sorted(Path(old_bnt).iterdir(), key=os.path.getmtime, reverse=True)
    print('Found %d old bnt reports' % len(old_paths))

    merge_bnt_fh = open('merged.bnt', 'w')
    with open(args.bnt_file) as bnt_fh:
        for line in bnt_fh:
            #print('line is %s' % line)
            if not line.startswith('function:'):
                continue
            parts = line.split('hits')
            line_start = parts[0]
            did_write = False
            for old in old_paths:
                path = os.path.join(old_bnt, old.name)
                with open(path, 'r') as fh:
                    for old_line in fh:
                        old_parts = old_line.split('hits')
                        old_start = old_parts[0]
                        if old_start == line_start and len(line) < len(old_line):
                            if line.strip().endswith('not in hits'):
                                merge_bnt_fh.write(old_line.strip()+' NO WM for new run\n')
                            else:
                                #print('old_start: %s' % old_start)
                                merge_bnt_fh.write(old_line)
                            did_write = True
                            break
                if did_write:
                    break
            if not did_write:
                merge_bnt_fh.write(line)
                #print('wrote line is %s' % line)
                        
                
if __name__ == '__main__':
    sys.exit(main())
