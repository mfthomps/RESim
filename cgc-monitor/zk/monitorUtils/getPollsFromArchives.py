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

import glob
import os
import zipfile
cb_map = {}
archive_path='/mnt/vmLib/bigstuff/cgc-archive/cgc'
to_rcbs='run/luigi/files/rcb'
to_polls='run/luigi/files/poll'

repo='/mnt/vmLib/cgcForensicsRepo/CB-share/v2/CBs'
full_rcbs=os.path.join(archive_path, to_rcbs)
flist = os.listdir(full_rcbs)
for f in flist:
    parts = f.split('-')
    cb_id = parts[0]
    cb_name = parts[1]
    cb_parts = cb_name.split('_')
    suffix='01'
    if len(cb_parts) > 2:
        suffix = cb_parts[2] 
        suffix = '%02d' % int(suffix)
    cb_name = 'CB'+cb_parts[0]+'_'+cb_parts[1]+suffix
    #print cb_name
    cb_map[cb_name] = cb_id
  
full_polls = os.path.join(archive_path, to_polls) 
for cb_name in cb_map:
    repo_polls = os.path.join(repo, cb_name, 'author','polls')
    zfile = 'csid_%s-round_3.zip' % cb_map[cb_name]
    zpath = os.path.join(full_polls, zfile)
    zf = zipfile.ZipFile(zpath)
    count = 1
    for f in zf.namelist():
        print f
        pname = 'SP_%s_%06d' % (cb_name, count)
        poll_path = os.path.join(repo_polls, pname)
        try:
            os.makedirs(poll_path)
        except:
            pass
        full_poll = os.path.join(poll_path, pname+'.xml')
        poll = zf.read(f)
        print('poll path is %s' % full_poll) 
        with open(full_poll, 'w') as pfh:
            pfh.write(poll)
            pass
  
        count+=1
        if count > 3:
            break
    zf.close()        
