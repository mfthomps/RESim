#!/usr/bin/env python
#
# 
# diff 2 hits files
#
import sys
import os
import glob
import json
f1 = sys.argv[1]
f2 = sys.argv[2]

hits1 = json.load(open(f1))
hits2 = json.load(open(f2))
full_dir = os.path.dirname(os.path.abspath(f1))
idle = os.path.join(full_dir, 'idle.hits')
if os.path.isfile(idle):
    idle_hits = json.load(open(idle))
else:
    idle_hits = []


lesser = min(len(hits1), len(hits2))
print('least hits of the 2 is %d' % lesser)
for i in range(lesser):
    b1 = hits1[i]
    b2 = hits2[i]
    if b1 != b2:
        print('not equal: b1: 0x%x  b2: 0x%x   index %d' % (b1, b2, i))
        break

for h1 in hits1:
    if h1 not in hits2 and h1 not in idle_hits:
        print('h1 0x%x not in 2  index %d' % (h1, hits1.index(h1)))

for h2 in hits2:
    if h2 not in hits1 and h2 not in idle_hits:
        print('h2 0x%x not in 1 index %d' % (h2, hits2.index(h2)))
