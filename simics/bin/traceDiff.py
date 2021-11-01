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
        v = parts[3]
        p = parts[4]
        return v, p

    def getCPU(self, line):
        parts = line[17:].split()
        try:
            return parts[0].strip()
        except:
            #print('could not get cpu from line %s' % line)
            #print('tried parts from %s' % line[17:])
            return None
        
    def nextLine(self):

        line = self.lines[self.index]
        while self.getCPU(line) == 'Device' or self.getCPU(line) is None:
            self.index = self.index+1
            line = self.lines[self.index]
     
        if line.startswith('data'):
            ok = False
            while not ok:
                v, p = self.getVP(line)
                next_line = self.lines[self.index+1]
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
    while rest1 == rest2:
        #print('get1')
        line1 = get1.nextLine()
        #print('\tline1 %s' % line1)
        #print('get2')
        line2 = get2.nextLine()
        #print('\tline2 %s' % line2)
        rest1 = line1[16:]
        rest2 = line2[16:]
    print('line1 line number %d %s' % (get1.getIndex(), line1))
    print('line2  line number %d %s' % (get2.getIndex(), line2))

if __name__ == '__main__':
    sys.exit(main())
