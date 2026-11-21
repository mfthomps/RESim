#!/usr/bin/env python3
import os
import re
import sys
import json
import argparse
import ntpath

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

def rmAddresses(line):
    if '0x' in line:
        line = re.sub(r'0x[0-9a-fA-F]+', '0x', line)
    elif 'push ' in line:
        parts = line.split()
        try:
            dumb = int(parts[1].strip())
            line = 'push some_addr'
        except:
            pass
    return line

class getter():
    def __init__(self, fname, so_path=None):
        self.fname = fname
        fh = open(fname)
        self.lines = fh.readlines()
        self.index = 0
        self.prev_line = None
        self.so_json = None
        self.prev_prog = None
        if so_path is not None:
            with open(so_path) as fh:
                self.so_json = json.load(fh)
                print('loaded json at %s' % so_path)

    def getIndex(self):
        return self.index

    def getPrevLine(self):
        return self.prev_line

    def inMap(self, addr):
        for item in self.so_json['sections']:
            if addr >= item['locate'] and addr <= item['end']:
                return item['file']
        return None

    def justInstructs(self):
        retval = None
        while retval is None:
            if self.index > len(self.lines)-1:
                print('ran out of lines in %s' % self.fname)
                return None
            line = self.lines[self.index]
            if not line.startswith('inst:'):
                #print('index %d line %s' % (self.index, line))
                self.index += 1
                if self.index > len(self.lines):
                    print('out of lines')
                    break 
            else:
                prog = None
                if self.so_json is not None:
                    v, p = getVP(line)
                    addr = int(v[4:-1], 16)
                    prog = self.inMap(addr)
                    is_windows = False
                    just_base = False
                    if prog is not None:
                        if 'windows' in prog.lower():
                            is_windows = True
                        base_prog = ntpath.basename(prog).lower()
                        if base_prog == prog.lower():
                            just_base = True
                        else:
                            prog = base_prog
                    self.prev_prog = prog
                if not is_windows and not just_base and prog is not None and prog not in ['kernel32.dll', 'kernelbase.dll', 'wow64cpu.dll', 'wow64.dll', 'ole32.dll', 
                              'oleaut32.dll', 'ucrtbase.dll', 'combase.dll', 'user32.dll'] and not prog.startswith('msvcr') and not prog.startswith('win32'):
                    retval = rmAddresses(line[128:])
                    self.prev_line = line.strip()
                else:
                    #print('skipping 0x%x not in map' % addr)
                    pass
                self.index += 1
        return retval
        
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
                if (self.index+1) >= len(self.lines):
                    print('index %d plus 1 exceeds number of lines' % self.index)
                    break
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

def justInstructs(args, so1_path=None, so2_path=None):
    get1 = getter(args.trace1, so_path=so1_path)
    get2 = getter(args.trace2, so_path=so2_path)
    line1 = ''
    done = False
    while not done:
        line1 = get1.justInstructs()
        line2 = get2.justInstructs()
        if line1 is None or line2 is None:
            print('got None from get..justInstructs')
            break
        if line1 != line2:
            print('line1 %s' % line1)
            print('line2 %s' % line2)
            prev1 = get1.getPrevLine()
            prev2 = get2.getPrevLine()
            print('prev1 %s  prog %s' % (prev1, get1.prev_prog))
            print('prev2 %s  prog %s' % (prev2, get2.prev_prog))
            break
        else:
            print('match1 on %s' % get1.getPrevLine())
            print('match2 on %s' % get2.getPrevLine())

def doDiffs(args):
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
            if line1 is None:
                print('No more lines in first file')
                break
            #print('\tline1 %s' % line1)
            #print('get2')
            line2 = get2.nextLine()
            if line2 is None:
                print('No more lines in second file')
                break
            if args.no_addr:
                args.divergence = True
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

def main():
    parser = argparse.ArgumentParser(prog='diffTrace', description='Show differences in 2 instruction traces')
    parser.add_argument('trace1', action='store', help='The first trace file.')
    parser.add_argument('trace2', action='store', help='The second trace file.')
    parser.add_argument('-i', '--ignore', action='store', type=int, default=0, help='Number of differences to ignore.')
    parser.add_argument('-d', '--divergence', action='store_true', help='Only look for instruction difference.')
    parser.add_argument('-x', '--no_addr', action='store_true', help='Only look for instruction difference and ignore addresses.')
    parser.add_argument('-s', '--shared_object', action='store_true', help='Ignore instructions that are not in memory map.')
    parser.add_argument('-a', '--instruction_addr_filter', action='store', help='Only look for instruction addresses matching this pattern.')
    args = parser.parse_args()
    if args.no_addr:
        print('Only looking at instructions, ignoring data and addresses')
        if args.shared_object:
            so1_dir = os.path.dirname(args.trace1)
            so2_dir = os.path.dirname(args.trace2)
            so1_path = os.path.join(so1_dir, 'somap.json')
            so2_path = os.path.join(so2_dir, 'somap.json')
            if not os.path.isfile(so1_path):
                print('No somap.json at %s, will ignore shared_object request' % so1_path)
                args.shared_object = False
                so1_path = None
                so2_path = None
            elif not os.path.isfile(so2_path):
                print('No somap.json at %s, will ignore shared_object request' % so2_path)
                args.shared_object = False
                so1_path = None
                so2_path = None
            justInstructs(args, so1_path=so1_path, so2_path=so2_path)
        else:
            justInstructs(args)
    else:
        doDiffs(args)

if __name__ == '__main__':
    sys.exit(main())
