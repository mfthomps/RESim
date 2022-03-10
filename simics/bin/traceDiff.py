#!/usr/bin/env python3
import os
import sys
import argparse

class getter():
    def __init__(self, fname):
        fh = open(fname)
        self.lines = fh.readlines()
        self.index = 0

    def getVP(self, line):
        parts = line[16:].split()
        if len(parts) < 5:
            print('failed in getVP for line %s' % line)
            exit(1)
        v = parts[3]
        p = parts[4]
        return v, p

    def getCPU(self, line):
        parts = line[17:].split()
        try:
            stuff = parts[0].strip()
            if len(stuff) > 0:
                return stuff
            else:
                return None
        except:
            #print('could not get cpu from line %s' % line)
            #print('tried parts from %s' % line[17:])
            return None
        
    def nextLine(self):

        line = self.lines[self.index]
        while self.getCPU(line) == 'Device' or self.getCPU(line) is None or (' object ' in line):
            self.index = self.index+1
            if self.index >= len(self.lines):
                print('Out of lines at index %d' % self.index)
                return None
            line = self.lines[self.index]
     
        if line.startswith('data'):
            ok = False
            while not ok:
                v, p = self.getVP(line)
                next_line = self.lines[self.index+1]
                if len(next_line.strip()) == 0:
                    self.index = self.index+1
                    continue
                vn, pn = self.getVP(next_line)
                if next_line.startswith('data') and v == vn and p != pn:
                    #print('skipping %s' % line)
                    self.index = self.index+1
                    line = next_line
                else:
                    ok = True
        self.index = self.index+1
        return line     

    def getIndex(self):
        return self.index

def main():
    parser = argparse.ArgumentParser(prog='diffTrace', description='Show differences in 2 instruction traces')
    parser.add_argument('trace1', action='store', help='The first trace file.')
    parser.add_argument('trace2', action='store', help='The second trace file.')
    parser.add_argument('-i', '--ignore', action='store', type=int, default=0, help='Number of differences to ignore.')
    parser.add_argument('-d', '--divergence', action='store_true', help='Only look for instruction difference.')
    args = parser.parse_args()

    get1 = getter(args.trace1)
    line1 = ''
    while not line1.startswith('inst'):
        line1 = get1.nextLine()
        #print('line1 is %s' % line1)
    get2 = getter(args.trace2)
    line2 = ''
    while not line2.startswith('inst'):
        line2 = get2.nextLine()
        #print('line2 is %s' % line2)
    
    rest1 = line1[16:]
    rest2 = line2[16:]
    diffs = 0
    last_match_ins = None
    while diffs <= args.ignore: 
        while rest1 == rest2 or (args.divergence and not ('ins' in line1 or 'ins' in line2)):
            #print('get1')
            line1 = get1.nextLine()
            #print('\tline1 %s' % line1)
            #print('get2')
            line2 = get2.nextLine()
            #print('\tline2 %s' % line2)
            rest1 = line1[16:]
            rest2 = line2[16:]
            if args.divergence and 'ins' in line1 and rest1 == rest2:
                last_match_ins = line1
        diffs += 1
        rest1 = 'ok'
        rest2 = 'ok'
    print('line1 line number %d %s' % (get1.getIndex(), line1))
    print('line2  line number %d %s' % (get2.getIndex(), line2))
    if args.divergence:
        print('Last matching instruction: %s'  % last_match_ins)

if __name__ == '__main__':
    sys.exit(main())
