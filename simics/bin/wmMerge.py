#!/usr/bin/env python3
#
# merge watch marks into a syscall trace
import sys
import os
import argparse
from pathlib import Path

def main():
    parser = argparse.ArgumentParser(prog='wmMerge', description='Merge watch marks into a system call trace.')
    parser.add_argument('wm', action='store', help='The watchmark file')
    parser.add_argument('trace', action='store', help='The trace')
    args = parser.parse_args()
    if not os.path.isfile(args.wm):
        print('Watch mark file not found at %s' % args.wm)
        exit(1)
    if not os.path.isfile(args.trace):
        print('Trace file not found at %s' % args.trace)
        exit(1)

    wm = {}
    with open(args.wm) as fh:
        for line in fh:
            if 'cycle:' in line:
                parts = line.split('cycle:') 
                cycle_s = parts[1].strip().split()[0]
                cycle = int(cycle_s, 16)
                wm[cycle] = line.strip()

    merged = open('/tmp/merged.trace', 'w') 
    trace_finished = False
    with open(args.trace) as fh:
        line = next(fh)            
        for cycle in wm:
            done = False
            while not done:
                cycle_stamp = line[:10]
                try:
                    trace_cycle = int(cycle_stamp, 16)
                except:
                    trace_cycle = 0 
                if trace_finished or trace_cycle > cycle:
                     merged.write('%10x WatchMark %s\n' % (cycle, wm[cycle]))
                     done = True
                else:
                     merged.write(line.strip()+'\n') 
                     try:
                         line = next(fh)            
                     except:
                         trace_finished = True
    fh.close()
    merged.close()
                
if __name__ == '__main__':
    sys.exit(main())
