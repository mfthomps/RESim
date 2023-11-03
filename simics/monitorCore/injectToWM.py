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
from simics import *
binpath = os.path.join(os.getenv('RESIM_DIR'), 'simics', 'bin')
sys.path.append(binpath)
import findBB
import applyFilter
import resimUtils
import aflPath
import findTrack
class InjectToWM():
    def __init__(self, top, addr, dataWatch, lgr, fname=None):
        unfiltered = '/tmp/wm.io'
        filtered = '/tmp/wm_filtered.io'
        self.top = top
        self.dataWatch = dataWatch
        self.addr = addr
        self.lgr = lgr
        here = os.getcwd()
        self.target = os.path.basename(here)
        print('target is %s' % self.target)
        self.lgr.debug('InjectToWM addr: 0x%x target is %s' % (addr, self.target))
        result = self.findOneTrack(addr)
        if result is not None:
            self.mark_index = result.mark['index']
            self.lgr.debug('InjectToWM inject %d bytes and %d packets at ip: 0x%x, Watch Mark: %d from %s' % (result.size, result.mark['packet'], result.mark['ip'], 
                self.mark_index, result.path))
            print('InjectToWM inject %d bytes (may be filtered or truncated) and %d packets from %s' % (result.size, result.mark['packet'], result.path))
            self.top.setCommandCallback(self.doStop)
            self.top.overrideBackstopCallback(self.doStop)
            self.inject_io = self.top.injectIO(result.path, callback=self.doStop, go=False, fname=fname)
            afl_filter = self.inject_io.getFilter()
            if afl_filter is not None:
                data = None
                with open(result.path, 'rb') as fh:
                    data = bytearray(fh.read())
                new_data = afl_filter.filter(data, None)
                with open(filtered, 'wb') as fh:
                    fh.write(new_data)
            shutil.copyfile(result.path, unfiltered)
            self.inject_io.go()
       
        else:
            print('No input files found to get to addr 0x%x' % addr)

    def doStop(self, got_hit=None):
        self.lgr.debug('InjectToWM doStop')
        self.top.stopDataWatch()
        SIM_run_alone(self.inject_io.delCallHap, None)
        if got_hit == True:
            SIM_run_alone(self.top.setDebugBookmark,'injectToWM')
        status = SIM_simics_is_running()
        if status:
            self.top.stopAndGo(self.gowm)
        else:
            self.gowm()

    def gowm(self):
        if self.inject_io is None:
            return
        self.top.setCommandCallback(None)
        self.top.restoreBackstopCallback()
        wm_index = self.dataWatch.findMarkIp(self.addr)
        if wm_index is not None:
            self.top.goToDataMark(wm_index)
            print('Go to data mark %d.  Artifact mark was %d.  Data file copied to /tmp/wm.io (and wm_filtered.io if there was a filter).' % (wm_index, self.mark_index))
        else:
            print('Did not find a watch mark for address 0x%x.  Perhaps it came from a stale trackio artifact?' % self.addr)

    def findOneTrack(self, addr):
        ''' Find a track having watchmark having the given address. 
            Prioritize low packet numbers and small queue file size.
        '''
        retval = None
        least_packet = 100000
        least_size = 100000
        expaths = aflPath.getAFLTrackList(self.target)
        self.lgr.debug('findOneTrack 0x%x %d paths' % (addr, len(expaths)))
        for index in range(len(expaths)):
            result = findTrack.findTrack(expaths[index], addr, True, quiet=True, lgr=self.lgr)
            if result is not None:
                self.lgr.debug('InjectToWM findOneTrack for addr 0x%x from findTrack got index %d' % (addr, result.mark['index']))
                if result.mark['packet'] < least_packet:
                    least_packet = result.mark['packet']
                    #least_size = result.size
                    least_size = result.num_marks
                    retval = result
                #elif result.mark['packet'] == least_packet and result.size < least_size:
                elif result.mark['packet'] == least_packet and result.num_marks < least_size:
                    least_size = result.num_marks
                    retval = result
        return retval
   
