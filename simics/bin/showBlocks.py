#!/usr/bin/env python3
#
# given a hits file or an AFL session named by target, instance and index,
# display the hits as hex.
#
import sys
import os
import glob
import json
if os.path.isfile(sys.argv[1]):
    hits1 = json.load(open(sys.argv[1]))
else:
    target = sys.argv[1]
    instance = sys.argv[2]
    index = sys.argv[3]
    try:
        index_val = int(index)
    except:
        print('bad index %s' % index)
    if index_val < 999:
        index = '000'+index 
  

    resim_num = '*resim_%s' % instance
    afl_path = os.getenv('AFL_DATA')
    
    glob_mask = '%s/output/%s/%s/coverage/id:*%s,src*' % (afl_path, target, resim_num, index)
    glist = glob.glob(glob_mask)
    if len(glist) == 0:
        print('No file found for %s' % glob_mask)
    else:
        print(glist[0]) 
    hits1 = json.load(open(glist[0]))

sorted_hits = sorted(hits1.items(), key=lambda x:x[1])
for hitkey in sorted_hits:
    hit = int(hitkey[0])
    print('hit: 0x%x' % hit)

