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
    def __init__(self, top, addr, dataWatch, lgr, target_prog=None, targetFD=None, max_marks=None, no_reset=False, ws=None):
        unfiltered = '/tmp/wm.io'
        filtered = '/tmp/wm_filtered.io'
        self.top = top
        self.dataWatch = dataWatch
        self.addr = addr
        self.lgr = lgr
        self.max_marks = max_marks
        self.no_reset = no_reset
        if target_prog is not None and targetFD is None:
            self.lgr.error('injectToWM called with target_prog, but no target FD')
            return
        here = os.getcwd()
        if ws is None:
            self.afl_target = os.path.basename(here)
        else:
            self.afl_target = ws
        #print('afl target is %s' % self.afl_target)
        self.lgr.debug('InjectToWM addr: 0x%x target is %s target_prog %s max_marks %s' % (addr, self.afl_target, target_prog, max_marks))
        result = self.findOneTrack()
        if result is not None:
            self.mark_index = result.mark['index']
            self.lgr.debug('InjectToWM inject %d bytes and %d packets at ip: 0x%x, Watch Mark: %d from %s' % (result.size, result.mark['packet'], result.mark['ip'], 
                self.mark_index, result.path))
            print('InjectToWM inject %d bytes (may be filtered or truncated) and %d packets from %s' % (result.size, result.mark['packet'], result.path))
            self.top.setCommandCallback(self.doStop)
            self.top.overrideBackstopCallback(self.doStop)
            self.inject_io = self.top.injectIO(result.path, callback=self.doStop, go=False, target=target_prog, targetFD=targetFD, reset_debug=True, max_marks=max_marks,
                                               no_reset=no_reset)
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
            self.lgr.debug('InjectToWM doStop thinks simics running, call stopAndGo')
            self.top.stopAndGo(self.gowm)
        else:
            self.lgr.debug('InjectToWM doStop thinks NOT simics running, call gowm')
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
            stale_index = self.dataWatch.findStaleMarkIp(self.addr)
            if stale_index is not None:
                print('Watch mark for address 0x%x occurred at index %d, which is prior to a bookmark reset.' % (self.addr, stale_index))
            else:
                print('Did not find a watch mark for address 0x%x.  Perhaps it came from a stale trackio artifact?' % self.addr)

    def findOneTrack(self):
        ''' Find a track having watchmark having the given address. 
            Prioritize low packet numbers and small queue file size and number of watch marks.
        '''
        retval = None
        least_packet = 100000
        least_size = 100000
        least_marks = 100000
        best_result_size = None
        best_result_marks = None
        without_resets = None
        best = None
        expaths = aflPath.getAFLTrackList(self.afl_target)
        self.lgr.debug('findOneTrack 0x%x found %d paths' % (self.addr, len(expaths)))
        for index in range(len(expaths)):
            # NOTE addr given to injectToWM are load addresses, so do not let findTrack apply offsets
            result, num_resets = findTrack.findTrackMark(expaths[index], self.addr, True, None, quiet=True, lgr=self.lgr)
            if result is not None:
                self.lgr.debug('InjectToWM findOneTrack for addr 0x%x from findTrack got index %d size: %d num_marks %d' % (self.addr, 
                     result.mark['index'], result.size, result.num_marks))
                if result.mark['packet'] < least_packet:
                    least_packet = result.mark['packet']
                    least_marks = result.num_marks
                    least_size = result.size
                    best_result_marks = None
                    best_result_size = None
                    retval = result
                    if self.no_reset and without_resets is None and num_resets == 0:
                        without_resets = result
                elif result.mark['packet'] == least_packet:
                    if self.no_reset and without_resets is None and num_resets == 0:
                        without_resets = result
                    if result.num_marks < least_marks and (not self.no_reset or num_resets == 0 or without_resets is None):
                        least_marks = result.num_marks
                        best_result_marks = result
                    if result.size < least_size and (not self.no_reset or num_resets == 0 or without_resets is None):
                        least_size = result.size
                        best_result_size = result
            #else:
            #    self.lgr.debug('findOneTrack got nothing from findTrack')
        if self.no_reset and without_resets is None:
            print('Failed to find watchmark prior to origin reset')
            self.lgr.debug('Failed to find watchmark prior to origin reset')
            retval = None
        elif best_result_marks is not None and best_result_size is not None:
            delta_marks = best_result_size.num_marks - best_result_marks.num_marks
            delta_size = best_result_marks.size - best_result_size.size
            self.lgr.debug('delta_marks %d best_marks %d  delta_size %d best_size %d' % (delta_marks, 
                       best_result_marks.num_marks, delta_size, best_result_size.size))
            if delta_marks == 0:
                retval = best_result_size
            elif delta_size == 0:
                retval = best_result_marks
            else:
                mark_ratio = delta_marks / best_result_marks.num_marks
                size_ratio = delta_size / best_result_size.size
                self.lgr.debug('best marks ratio %f   best size %f' % (mark_ratio, size_ratio))
                if mark_ratio > size_ratio:
                    retval = best_result_marks
                else:
                    retval = best_result_size
        elif best_result_marks is not None:
            self.lgr.debug('best is marks')
            retval = best_result_marks
        elif best_result_size is not None:
            self.lgr.debug('best is size')
            retval = best_result_size
        else:
            # best is least packets
            pass 

        return retval
   
