#!/usr/bin/env python3
'''
Parse the crash reports, skipping page boundary crashes.
'''
import os
cpath = '/tmp/crash_reports'
clist = os.listdir(cpath)
for crash in sorted(clist):
    if crash.endswith('.swp'):
        continue
    full = os.path.join(cpath, crash)
    page_boundary = False
    memcpy = None
    with open(full) as fh:
        for line in fh:
            if 'came from memcpy' in line:
                memcpy = line
                break
            elif 'boundary' in line:
                page_boundary = True
        if memcpy is not None:
            print('%s %s' % (crash, memcpy))
        elif page_boundary:
            print('%s page boundary, not memcpy' % crash)
        else:
            print('%s **OTHER**' % crash) 
