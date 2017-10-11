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
import sys
import os
from monitorLibs import configMgr


def findPairUnknown(cb, pov):
    '''
    Search the forensics repo for a cb/pov pair using cfe-style naming
    Return the rcb list and team name.  Intended for use in ad-hoc replays
    '''
    skip_cb = False
    if cb.startswith('CB'):
        print('is a CB, expected an rcb')
        skip_cb = True
        if cb.endswith('_MG'):
            cb = cb[:len(cb)-3]
    '''
    derive the first bit of a common name from cfe-style rcb name.  
    '''
    if not skip_cb:
        base = os.path.basename(cb)
        cb_name = base.split('-')[1]
        cb_starts_with = 'CB'+cb_name
        path = cfg.cb_dir+'/'+cb_starts_with+'*/competitor/*/cbs/'+cb
    else:
        path = cfg.cb_dir+'/'+cb+'/competitor/*/cbs/*'
        
    print path
    found = glob.glob(path)
    team = None
    rcb_list = None
    for try_path in found:
        tail = None
        cur_path = try_path
        while tail != 'competitor':
            cur_path, tail = os.path.split(cur_path)
            if cur_path is None:
                print('failed to find competitor in %s' % try_path)
                break
            if tail == 'competitor':
                pov_search = cur_path+'/competitor/%s/povs/%s' % (prev_tail, pov)
                if pov.startswith('POV') or os.path.isfile(pov_search):
                    team = prev_tail
                    rcb_search = cur_path+'/competitor/%s/cbs/' % (prev_tail)
                    rcb_list = os.listdir(rcb_search)
                else:
                    print('found rcb, but not pov at %s' % pov_search)
            prev_tail = tail
        if team is not None:
            break
    if team is not None:
        print('team is %s' % team)
        print('rcbs is %s' % str(rcb_list))
    if not skip_cb:
        return rcb_list, team
    else:
        return None, team
            
       
cfg = configMgr.configMgr() 
#cb='2762039178-EAGLE_00005-e6b3f2ad3bb110c41b3ec66ee295c26c9356cf5876eca119060d2879b9199d83.rcb'
#cb='3196846249-EAGLE_00005-ff953b8204526f630f5363af0c541642ad455d3b08a0985f260a37c3f3570bbd.rcb'
#pov='3196846249-6a143ce37f0f18f4bb462abac2abccaa7f9dbd82eea6aa22f1b45d7258fbfcfb.pov'
#pov='POV_CBCADET_0000301_ATH_000001'
cb="CBCROMU_0005501_MG"
pov="3007107812-8ee47856369b153a041d1a483120d5995a5564c46714d7bc97866f62f15aa618.pov"
rcb_list, team = findPairUnknown(cb, pov)
print('rcbs: %s  team: %s' % (str(rcb_list), team))
