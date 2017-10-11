#!/usr/bin/env python
import os
import sys
def usage():
    print('mkNewCBList [build]')
    exit(0) 
build=False

if len(sys.argv) > 1:
    if sys.argv[1] == 'build':
        build=True
    else:
        usage()
with open('expand.txt') as expand:
    count = 0
    for line in expand:
        if 'is newer' in line:
            path = line.split()[0]
            name = os.path.basename(path)
            parts = name.split('-')
            auth = parts[2]
            cb = parts[3].split('_')[0]
            if build:
                build_num = parts[3].split('_')[1]
                build_num = build_num.split('-')[0]
                id = '%s_%s-%s' % (auth.upper(), cb.upper(), build_num)
            else:
                id = '%s_%s' % (auth.upper(), cb.upper())
               
            print id
            count += 1

    print count
