#!/usr/bin/python
import fileinput
import sys
import json
#print 'begin'
'''
Parse output from the readcgcef-minimal.py script and extract 
program sections.
'''
if len(sys.argv) > 1:
    print 'usage: readcgcef-minimal.py -S myprog |  buildCfg2.py > outfid'
    exit(0)
f = sys.stdout
#f.write('[elf]\n')
isX = None
isLoad = False
PERMISSIONS = 'Permissions'
LOAD = 'LOAD'
MEMORY = 'Memory'
text_sections = []
data_sections = []
for line in sys.stdin:
    #print 'line is %s' % line
    parts = line.split(':')
    if not isLoad:
        if parts[1].strip() == LOAD:
            isLoad = True
    else:
        if isX is None:
            if parts[0].strip() == PERMISSIONS:
                if 'X' in parts[1].strip():
                    isX = True
                else:
                    isX = False
        else:
            if parts[0].strip() == MEMORY:
                start, size = parts[1].split('+')
                if isX:
                    #print 'text = %s' % start
                    #print 'text_size = %s' % size
                    text_sections.append((start, size))
                    #print 'Executable start %s  size %s' % (start, size)
                else:
                    #print 'data = %s' % start
                    #print 'data_size = %s' % size
                    data_sections.append((start, size))
                    #print 'Not executable start %s  size %s' % (start, size)
                isLoad = False
                isX = None

j_string = json.dumps((text_sections, data_sections))
#print('j_string is %s' % j_string)
print j_string
jl = json.loads(j_string)
f.close()

