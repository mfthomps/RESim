#!/usr/bin/env python3
#
# merge watch marks into a syscall trace
import sys
import os
import argparse
import json
from pathlib import Path
class Coverage():
    def __init__(self, fname):
        self.cover = None
        with open(fname) as fh:
           self.cover = json.load(fh)  

    def countTo(self, cycle):
        count = 0
        for hit in self.cover: 
            if self.cover[hit]['cycle'] < cycle:
                count = count + 1
            else:
                break
        return count

def getLine(fh, coverage):
    done = False
    while not done:
        try:
            line = next(fh)            
        except:
            return None
        if line is None:
            return None
        if 'DMOD!' in line:
            continue
        if len(line.strip()) > 0:
            break
    cycle_stamp = line[:10]
    try:
        trace_cycle = int(cycle_stamp, 16)
    except:
        print('bad trace line %s' % line)
        exit(1)
    if coverage is not None:
        count = coverage.countTo(trace_cycle)
        if line.strip().endswith('data:'):
            line = line.strip()[:-5]
            line = line.strip()+ ' hits: %d data:\n\t' % count
            line = line+next(fh)
        else:
            line = line.strip()+ ' hits: %d' % count
    elif line.strip().endswith('data:'):
        line = line+next(fh)
    return line

def main():
    parser = argparse.ArgumentParser(prog='wmMerge', description='Merge watch marks into a system call trace.')
    parser.add_argument('wm', action='store', help='The watchmark file')
    parser.add_argument('trace', action='store', help='The trace')
    parser.add_argument('-c', '--coverage', action='store', help='The trace')
    parser.add_argument('-o', '--output', action='store', default='/tmp/merged.trace', help='Optional output file')
    args = parser.parse_args()
    if not os.path.isfile(args.wm):
        print('Watch mark file not found at %s' % args.wm)
        exit(1)
    if not os.path.isfile(args.trace):
        print('Trace file not found at %s' % args.trace)
        exit(1)

    coverage = None
    if args.coverage is not None:
        if os.path.isfile(args.coverage):
            coverage = Coverage(args.coverage)
            print('Using coverage file at %s' % args.coverage)
        else: 
            print('No coverage file found at %s' % args.coverage) 
            exit(1)

    wm = {}
    with open(args.wm) as fh:
        for line in fh:
            if 'cycle:' in line:
                parts = line.split('cycle:') 
                cycle_s = parts[1].strip().split()[0]
                cycle = int(cycle_s, 16)
                wm[cycle] = line.strip()

    merged = open(args.output, 'w') 
    trace_finished = False
    with open(args.trace) as fh:
        line = getLine(fh, coverage)
        for cycle in wm:
            done = False
            while not done:
                if line is None:
                    break
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
                     line = getLine(fh, coverage)
                     if line is None:
                         trace_finished = True
        while line is not None:
            line = getLine(fh, coverage)
            if line is not None:
                merged.write(line.strip()+'\n') 
            
    fh.close()
    merged.close()
    print('Merged reports written to %s' % args.output)
                
if __name__ == '__main__':
    sys.exit(main())
