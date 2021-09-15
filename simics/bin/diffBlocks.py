#!/usr/bin/env python
#
# given a target and two AFL sessions named by instance/index, show differences in their
# respective hits.
#
import sys
import os
import glob
import json
target = sys.argv[1]
instance = sys.argv[2]
index = sys.argv[3]
instance_2 = sys.argv[4]
index_2 = sys.argv[5]


resim_num = 'resim_%s' % instance
afl_path = os.getenv('AFL_DATA')

glob_mask = '%s/output/%s/%s/coverage/id:*%s,src*' % (afl_path, target, resim_num, index)
glist = glob.glob(glob_mask)
if len(glist) == 0:
    print('No file found for %s' % glob_mask)
else:
    print(glist[0]) 

resim_num = 'resim_%s' % instance_2
glob_mask = '%s/output/%s/%s/coverage/id:*%s,src*' % (afl_path, target, resim_num, index_2)
glist2 = glob.glob(glob_mask)
if len(glist2) == 0:
    print('No file found for %s' % glob_mask)
else:
    print(glist2[0]) 

hits1 = json.load(open(glist[0]))
hits2 = json.load(open(glist2[0]))

lesser = min(len(hits1), len(hits2))
print('least hits of the 2 is %d' % lesser)
for i in range(lesser):
    b1 = hits1[i]
    b2 = hits2[i]
    if b1 != b2:
        print('not equal: b1: 0x%x  b2: 0x%x   index %d' % (b1, b2, i))
        break

for h1 in hits1:
    if h1 not in hits2:
        print('h1 0x%x not in 2  index %d' % (h1, hits1.index(h1)))

for h2 in hits2:
    if h2 not in hits1:
        print('h2 0x%x not in 1' % (h2, hits2.index(h2)))
