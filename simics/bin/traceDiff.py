#!/usr/bin/env python3
import os
import re
import sys
import argparse

def getVP(line):
        parts = line[16:].split()
        if len(parts) < 5:
            print('failed in getVP for line %s' % line)
            exit(1)
        v = parts[3]
        p = parts[4]
        return v, p

def getCPU(line):
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

def addrFilter(line, find):
    go = re.search(find, line, re.M|re.I)
    if go is None:
        #line = re.sub(r"<l.*>", "", line)
        line = 'removed'
    return line

def rmPhys(line):
    line = re.sub(r"<p.*>", "", line)
    return line
class getter():
    def __init__(self, fname):
        fh = open(fname)
        self.lines = fh.readlines()
        self.index = 0

        
    def nextLine(self):

        line = self.lines[self.index]
        while getCPU(line) == 'Device' or getCPU(line) is None or (' object ' in line) or ' Pt ' in line or ' Pd ' in line:
            self.index = self.index+1
            if self.index >= len(self.lines):
                print('Out of lines at index %d' % self.index)
                return None
            line = self.lines[self.index]
     
        if line.startswith('data'):
            ok = False
            while not ok:
                v, p = getVP(line)
                next_line = self.lines[self.index+1]
                if not next_line.startswith('inst:') and not next_line.startswith('data:'):
                    self.index = self.index+1
                    continue
                if len(next_line.strip()) == 0:
                    self.index = self.index+1
                    continue
                vn, pn = getVP(next_line)
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
    parser.add_argument('-a', '--instruction_addr_filter', action='store', help='Only look for instruction addresses matching this pattern.')
    args = parser.parse_args()

    get1 = getter(args.trace1)
    line1 = ''
    while not line1.startswith('inst:'):
        line1 = get1.nextLine()
        #print('line1 is %s' % line1)
    get2 = getter(args.trace2)
    line2 = ''
    while not line2.startswith('inst:'):
        line2 = get2.nextLine()
        #print('line2 is %s' % line2)
    if args.divergence:
        #print('is divert')
        line1 = rmPhys(line1)
        line2 = rmPhys(line2)
    
    rest1 = line1[16:]
    rest2 = line2[16:]
    diffs = 0
    last_match_ins = None
    instruct_list = []
    while diffs <= args.ignore: 
        while rest1 == rest2 or (args.divergence and not ('ins' in line1 or 'ins' in line2)):
            #print('get1')
            line1 = get1.nextLine()
            #print('\tline1 %s' % line1)
            #print('get2')
            line2 = get2.nextLine()
            if args.divergence:
                #print('is divert')
                line1 = rmPhys(line1)
                line2 = rmPhys(line2)
            if args.instruction_addr_filter is not None:
                addr_filter = '<l.*%s' % args.instruction_addr_filter
                line1 = addrFilter(line1, addr_filter)
                line2 = addrFilter(line2, addr_filter)
            #print('\tline2 %s' % line2)
            rest1 = line1[16:]
            rest2 = line2[16:]
            if 'inst:' in line1 and rest1 == rest2:
                last_match_ins = line1
                v, p = getVP(line1)
                instruct_list.append(v)
        diffs += 1
        rest1 = 'ok'
        rest2 = 'ok'
    print('line1 line number %d %s' % (get1.getIndex(), line1))
    print('line2 line number %d %s' % (get2.getIndex(), line2))
    if last_match_ins is not None:
        v, p = getVP(last_match_ins)    
        count = instruct_list.count(v)
        print('Last matching instruction: %s, executed %d times'  % (last_match_ins.strip(), count))

if __name__ == '__main__':
    sys.exit(main())
