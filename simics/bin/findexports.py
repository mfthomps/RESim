#!/usr/bin/env python3

import os
import sys
import json
import glob
def getPathList(target):
    afl_path = os.getenv('AFL_DATA')
    glob_mask = '%s/output/%s/resim_*/trackio/id:*,src*' % (afl_path, target)
    glist = glob.glob(glob_mask)
    return glist

target = sys.argv[1]
plist = getPathList(target)
print('%d jsons' % len(plist))
for path in plist:

    trackdata = json.load(open(path))
    call_count = 0
    print('%d marks in %s' % (len(trackdata), path))
    for mark in trackdata:
        if mark['mark_type'] == 'call':
            call_count += 1
    if call_count > 1:
        print('%d calls in %s' % (call_count, path)) 
        exit(1)
