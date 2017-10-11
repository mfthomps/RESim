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

import zipfile
import os
import glob
import shutil
try:    
    from monitorLibs import szk
except: 
    if not __file__.startswith('/usr/bin'):
        sys.path.append('../')
    from monitorLibs import szk
from monitorLibs import configMgr
def countBins(orig_cb):
    binaries = glob.glob(orig_cb+'*')
    b = list(filter(lambda x: x.endswith('_patched'), binaries))
    return len(b)
    
def getCBName(cb):
    samples = '/mnt/vmLib/bigstuff/challenge-sets/usr/share/cgc-challenges'
    cb_dir = os.path.join(samples, cb)
    if not os.path.isdir(cb_dir):
        print('no challenge set for %s, skip' % cb)
        return
    source_cb_bin = os.path.join(cb_dir, 'bin', cb)
    bin_count = countBins(source_cb_bin)
    cb_name = 'CB'+cb+'%02x' % bin_count
    return cb_name

def getPollDir(cbs_dir, cb_name):
    cb_dir = cbs_dir+'/'+cb_name
    cb_auth = cb_dir +'/'+ szk.AUTHOR
    cb_polls = cb_auth + '/'+szk.POLLs
    return cb_polls

def doPoll(pname, pdata, cb_name, poll_dir, map_file):
    #print pname
    if pname.endswith('.xml') and pname.startswith('GEN_'):
        num_str = pname.split('.')[0]
        num_str = num_str.rsplit('_',1)[1]
        try:
            poll_num = int(num_str)
        except:
            print('could not get a poll number from %s, cb is %s  num_str is %s ? exit' % (base, cb_name, num_str))
            exit(1)
        a_poll_name = 'SP_'+cb_name+'_%06d' % poll_num
        print 'poll is %s  poll_dir is %s  a_poll_name is %s' % (pname,  poll_dir, a_poll_name+'.xml')
        os.makedirs(poll_dir+'/'+a_poll_name, mode=0777)
        full_path = os.path.join(poll_dir, a_poll_name, a_poll_name+'.xml')
        with open(full_path, 'w') as fh:
            fh.write(pdata) 
        map_file.write('poll %s to %s' % (pname, a_poll_name+'.xml'))
map_file = open('map_file.txt', 'w')
max_polls = 5
cfg = configMgr.configMgr()
cbs_dir = cfg.cb_dir
zipname='/tmp/csid_1637205035-round_0.zip'
zf = zipfile.ZipFile(zipname)
csid='CADET_00003'
cb_name = getCBName(csid)
if cb_name is None:
    print('no repo for %s, exit' % csid)
    exit(1)
poll_dir = getPollDir(cbs_dir, cb_name)
print('polldir is %s, removing all!' % poll_dir)
try:
    shutil.rmtree(poll_dir)
except:
    pass
print('csid %s get cb_name %s' % (csid, cb_name))
count=0
for f in zf.namelist():
    pdata = zf.read(f)
    doPoll(f, pdata, cb_name, poll_dir, map_file)
    count+=1
    if count >= max_polls:
        break
map_file.close()
