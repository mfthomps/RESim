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
Plot total bytes read from the magic page per poll for
a given CB, named in a csl containing bytes read and
poll number.
'''
import sys
import os
import math
import numpy as np
import pylab as pl

def doPlot(fname, save=None):
    fid = open(fname, 'r')
    l = fid.readline()
    bits = l.split(' ')
    cb = bits[0].strip()
    polls = fid.readline()
    polls_array = polls.split(',')
    x = map(int, polls_array)
    lengths = fid.readline()
    len_array = lengths.split(',')
    y = map(int, len_array)
    pl.plot(x, y, 'ro')
    pl.xlabel('poll')
    pl.ylabel('total bytes read')
    base = os.path.basename(fname).rsplit('-',1)[0]
    pl.title('Protected page access by poll for %s' % base)
    #maxr = math.ceil(max(y))+1
    #print 'max is %d' % maxr
    #yint = range(min(y), int(maxr))
    #pl.yticks(yint)
    pl.xlim(0,1000)
    if save is not None:
        outname = 'plots/%s.png' % cb
        print('outname is %s' % outname)
        pl.savefig(outname)
    else:
        pl.show()
    pl.clf()
if __name__ == "__main__":
    save = None
    try:
        os.mkdir('./plots')
    except:
        pass
    if len(sys.argv) == 3:
        save = sys.argv[2]
    doPlot(sys.argv[1], save)
