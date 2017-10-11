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

'''
Plot magic page access over execution of a set of polls 
as given in a file containing csl entries for bytes read
and execution percentage.
'''
import os
import sys
import math
import numpy as np
import pylab as pl
def getRunningTotal(inlist):
    '''
    Given a list of lengths, create a similar list of cumulative sums
    '''
    total = 0
    outlist = []
    for i in inlist:
        total += i
        
        outlist.append(total)
        #print "outlist value %d appending total %d" % (i, total)
    return outlist

marks = ['o','x','+','.','*','s','v','^']
colors = ['r','g','b','m','y','k','c']
def doPlot(fname, save):
    fid = open(fname, 'r')
    l = fid.readline()
    bits = l.split(' ')
    cb = bits[0].strip()
    num_plots = int(bits[1].strip())
    for plot in range(num_plots):
        x = []
        y = []
        lengths = fid.readline()
        if len(lengths.strip()) > 0:
            len_array = lengths.split(',')
            lenints = map(int, len_array)
            y = getRunningTotal(lenints)
            #print('plot %d ' % (plot))
            deltas = fid.readline()
            delta_array = deltas.split(',')
            x = map(int, delta_array)
        mindex = plot % len(marks)
        cindex = plot / len(colors)
        mark = "%s%s" % (colors[cindex], marks[mindex])
        #print('mark is %s' % mark)
        pl.plot(x, y, mark)
        pl.xlim(0, 100)
    pl.xlabel('% execution cycles')
    pl.ylabel('cumulative bytes read')
    base = os.path.basename(fname).rsplit('-',1)[0]
    
    pl.title('Protected page access for %s\n (%d polls)' % (base, num_plots))
    #maxr = math.ceil(max(y))+1
    #print 'max is %d' % maxr
    #yint = range(min(y), int(maxr))
    #pl.yticks(yint)
    #pl.ylim(0,2)
    if save is not None:
        outname = 'plots/%s-execute.png' % cb
        pl.savefig(outname)
    else:
        pl.show()
    pl.clf()
    fid.close()

if __name__ == "__main__":
    fname=sys.argv[1]
    save = None
    if len(sys.argv) == 3:
        save = sys.argv[2]
    try:
        os.mkdir('./plots')
    except:
        pass
    doPlot(fname, save)
