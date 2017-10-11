#!/usr/bin/python 
'''
 * This software was created by United States Government employees
 * and may not be copyrighted.
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
 * ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
'''

import sys
import glob
import os
import numpy as np
import pylab as pb
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
def getTagValue(line, tag):
    parts = line.split()
    for p in parts:
        if ':' in p:
            tv = p.split(':')
            if tv[0] == tag:
                return tv[1]
if len(sys.argv) != 2:
    print('plotRefCycles cb')
    exit(1)

cb = sys.argv[1]
dlist = glob.glob('TEST*')
cycle_sets = []
for d in dlist:
    def_host_dir = os.path.join(d, 'defhost')
    log = def_host_dir+'/*%s*.log' % cb
    for launch_log in glob.glob(log):
        #print('log is %s' % launch_log)
        poll_cycles = []
        lcount = 0
        with open(launch_log,'r') as dalog:
            for line in dalog:
                lcount += 1
                v = getTagValue(line, 'ref_cycles')
                if v is None:
                    #print(' no ref_cycles in %s' % line)
                    continue
                ref_cycles = int(v)
                if ref_cycles > 100000:
                    print('ref_cycles is %d line %d  file %s' % (ref_cycles, lcount, launch_log))            
                poll_cycles.append(ref_cycles)
        cycle_sets.append(poll_cycles)

colors = ['r','g','b','m','y','c']

i=0
for s in cycle_sets:
    cc = colors[i % len(colors)]
    print('do plot color %s' % cc)
    #plt.plot(s, color = cc)
    plt.scatter(range(1,1001), s, color = cc)
    i+=1
plt.show()

