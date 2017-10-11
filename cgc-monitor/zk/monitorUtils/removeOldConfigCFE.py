#!/usr/bin/env python
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
import shutil
def usage():
    print('delete all cgc-forensic archives older than a given timestamp')
    exit(0)

def doRemove(path):
    try:
        shutil.rmtree(path) 
    except:
        print('no path or permissions %s' % path)

fpath = '/space/cgc-forensics'
mpath = '/mnt/vmLib/bigstuff/cfe-games/cfe_moved'
dpath = '/mnt/vmLib/bigstuff/cfe-games/forensics-done'
dlist = os.listdir(fpath)
rm_list = []

if len(sys.argv) != 2:
    usage()

oldest=None
try:
   oldest = float(sys.argv[1])
except:
   usage() 
   
for d in sorted(dlist):
    try:
        this_stamp = float(d)
    except:
        print('not a valid timestamp: %s' % d)
        continue
    if this_stamp < oldest:
        rm_list.append(d)

print('would remove:')
for d in rm_list:
    print d   

answer=raw_input('ok? (y/n)')
if answer == 'y':
    print('do delete')
    for d in rm_list:
        full = os.path.join(fpath, d)
        doRemove(full) 
        full = os.path.join(mpath, d)
        doRemove(full) 
        full = os.path.join(dpath, d)
        doRemove(full) 
else:
    print('bailed')

