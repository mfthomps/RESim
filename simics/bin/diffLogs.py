#!/usr/bin/env python3
#
# 
# diff 2 log files
#
import sys
import os
import glob
import json
def getNextLine(fh):
    retval = None
    line = None
    while True:
        line = fh.readline().decode()
        if line is None or len(line) == 0:
            break
        elif len(line.strip()) == 0:
            continue
        elif line[0] == ' ' or ord(line[0]) == 9:
            continue
        elif 'object at 0x' in line:
            continue
        elif 'magicHap' in line:
            continue
        elif 'Hap wrong process' in line:
            continue
        elif ' - ' in line:
            retval = line.split(' - ', 1)[1] 
            break
        else:
            print('confused %s' % line)
            continue
    return retval, line

f1 = sys.argv[1]
f2 = sys.argv[2]

logs1 = open(f1, 'rb')
logs2 = open(f2, 'rb')

while True:
    line1, orig1 = getNextLine(logs1)
    if line1 is None:
        print('%s eof' % f1)
        break
    line2, orig2 = getNextLine(logs2)
    if line2 is None:
        print('%s eof' % f2)
        break

    if line1 != line2:
        print('difference') 
        print('DIFF line1 %s' % orig1)
        print('DIFF line2 %s' % orig2)
        break
    else:
        print('line1 %s' % orig1)
        print('line2 %s' % orig2)
