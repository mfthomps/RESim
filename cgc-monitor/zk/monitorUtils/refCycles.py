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

import os
import sys
import glob
import numpy
cb_list = []
def getTagValue(line, tag):
    parts = line.split()
    for p in parts:
        if '=' in p:
            tv = p.split('=')
            if tv[0] == tag:
                return tv[1]

def getRefCyclesForSummeries(path, group_suffix):
    ref_cycles = {}
    search = path+'TEST*/*SUM*'
    print(search)
    tlist = glob.glob(path+'TEST*/*SUM*')
    current_group = None
    for summary in tlist:
        with open(summary, 'r') as sum_file:
            for line in sum_file:
                if line.startswith('Group'):
                    current_group = line.strip().split()[1]
                else:
                    cb = getTagValue(line, 'CB')
                    if cb is not None:
                        if group_suffix:
                            cb=cb+'-G'+current_group
                        if cb not in cb_list: 
                            cb_list.append(cb)
                        total_cycles = getTagValue(line, 'ref_cycles')
                        if total_cycles is not None:
                            #print('cb: %s total_cycles: %s' % (cb, total_cycles))
                            if cb not in ref_cycles:
                                ref_cycles[cb] = []
                            ref_cycles[cb].append(float(total_cycles))
    return ref_cycles

def printRefCycles(ref_cycles):
    print('%10s   %15s   %15s   %15s   %15s    %15s' % ('cb', 'mean', 'std', 'min', 'max', '#samples'))
    for cb in sorted(ref_cycles):
        sample_size = len(ref_cycles[cb])
        avg = sum(ref_cycles[cb])/len(ref_cycles[cb])
        mean = numpy.mean(ref_cycles[cb])
        std = numpy.std(ref_cycles[cb])
        min_time = min(ref_cycles[cb])
        max_time = max(ref_cycles[cb])
        print('%10s  %15d   %15d   %15d    %15d   %d' % (cb, mean, std, min_time, max_time, sample_size))

def compareTimes(cmp_ref_cycles, new_data_name):
    print('%10s   %7s     %14s    %14s     %14s    %14s' % ('cb', 'ref', 'new_data', 'small', 'large', 'huge'))
    for cb in cb_list:
        if cb not in cmp_ref_cycles['wall-tests-ref']:
            print('cb %s not in wall-tests-ref' % (cb))
            continue
        ref = numpy.mean(cmp_ref_cycles['wall-tests-ref'][cb])
        new_data = 0
        new_data_per = 0
        if new_data_name in cmp_ref_cycles:
            if cb not in cmp_ref_cycles[new_data_name]:
                print('cb %s not in new data %s' % (cb, new_data_name))
                continue
            new_data = numpy.mean(cmp_ref_cycles[new_data_name][cb])
            new_data_per = ((new_data - ref) / ref) * 100.0
        small = numpy.mean(cmp_ref_cycles['wall-tests-min'][cb])
        small_per = ((small - ref) / ref) * 100.0
        large = numpy.mean(cmp_ref_cycles['wall-tests-max'][cb])
        large_per = ((large - ref) / ref) * 100.0
        huge = numpy.mean(cmp_ref_cycles['wall-tests-hge'][cb])
        huge_per = ((huge - ref) / ref) * 100.0
        print('%15s %7.2f  %7.2f  (%5.2f%%)  %7.2f  (%5.2f%%)  %7.2f  (%5.2f%%)  %7.2f (%5.2f%%)' % (cb, 
            ref, new_data, new_data_per, small, small_per,
            large, large_per, huge, huge_per))
            

if len(sys.argv) > 1:
    dlist = glob.glob("wall-test*")
    cmp_ref_cycles = {}
    for d in dlist:
        print('directory: %s' % d)
        if os.path.isdir(d):
            cmp_ref_cycles[d] = getRefCyclesForSummeries(d+'/', False)
    #for d in cmp_ref_cycles:
    #    printRefCycles(cmp_ref_cycles[d])
    compareTimes(cmp_ref_cycles, sys.argv[1])
else:
    ref_cycles = getRefCyclesForSummeries('./', True)
    printRefCycles(ref_cycles)
