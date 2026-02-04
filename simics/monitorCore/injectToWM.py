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
resim_dir = os.getenv('RESIM_DIR')
sys.path.append(os.path.join(resim_dir, 'simics', 'fuzz_bin'))
import find_new_states
import findBB
import applyFilter
import resimUtils
import aflPath
import findTrack
class InjectToWM():
    def __init__(self, top, addr, dataWatch, lgr, target_prog=None, targetFD=None, max_marks=None, no_reset=None, ws=None):
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

    def findBestTrack(self, expaths):
        least_packet = 100000
        least_size = 100000
        least_marks = 100000
        best_result_size = None
        best_result_marks = None
        without_resets = None
        best = None
        retval = None
        for index in range(len(expaths)):
            # NOTE addr given to injectToWM are load addresses, so do not let findTrack apply offsets
            result, num_resets = findTrack.findTrackMark(expaths[index], self.addr, True, None, quiet=True, lgr=self.lgr)
            if result is not None:
                self.lgr.debug('InjectToWM findBestTrack for addr 0x%x from findTrack got index %d size: %d num_marks %d packet %s least_packet %s' % (self.addr, 
                     result.mark['index'], result.size, result.num_marks, result.mark['packet'], least_packet))
                if result.mark['packet'] < least_packet:
                    least_packet = result.mark['packet']
                    least_marks = result.num_marks
                    least_size = result.size
                    best_result_marks = None
                    best_result_size = None
                    retval = result
                    if self.no_reset is not None and without_resets is None and num_resets == 0:
                        without_resets = result
                elif result.mark['packet'] == least_packet:
                    if self.no_reset is not None and without_resets is None and num_resets == 0:
                        without_resets = result
                    if result.num_marks < least_marks and (self.no_reset is None or num_resets == 0 or without_resets is None):
                        least_marks = result.num_marks
                        best_result_marks = result
                    if result.size < least_size and (self.no_reset is None or num_resets == 0 or without_resets is None):
                        least_size = result.size
                        best_result_size = result
                else:
                    self.lgr.debug('injectToWM findBestTrack packet is %s least %s' % (result.mark['packet'], leaset_packet))
            #else:
            #    self.lgr.debug('findOneTrack got nothing from findTrack')
        return retval, without_resets, best_result_marks, best_result_size


    def findOneTrack(self):
        ''' Find a track having watchmark having the given address. 
            Prioritize low packet numbers and small queue file size and number of watch marks.
        '''
        retval = None
        wrong_state = False
        from_auto = False
        here = os.getcwd()
        best_result_marks = None
        if 'auto_ws' in here:
            self.lgr.debug('findOneTrack running from auto_ws')
        expaths = aflPath.getAFLTrackList(self.afl_target, lgr=self.lgr)
        self.lgr.debug('findOneTrack 0x%x found %d paths' % (self.addr, len(expaths)))
        retval, without_resets, best_result_marks, best_result_size = self.findBestTrack(expaths)
        if retval is not None:
           self.lgr.debug('findOneTrack retval results %s' % retval.path)
        elif best_result_marks is not None:
           self.lgr.debug('findOneTrack best results %s' % best_result_marks.path)
        auto = os.path.isdir('auto_ws')
        if (retval is None and best_result_marks is None and auto):
            # No track had the watch mark and we are at initial state.  Will report and bail.
            wrong_state = True
            auto_paths = []
            qlist = find_new_states.allQueueFiles(self.afl_target)
            for path in qlist:
                path = path.replace('queue', 'trackio')
                auto_paths.append(path) 
            retval, without_resets, best_result_marks, best_result_size = self.findBestTrack(auto_paths)
            if retval is not None:
               self.lgr.debug('findOneTrack retval auto results %s' % retval.path)
            elif best_result_marks is not None:
               self.lgr.debug('findOneTrack best auto results %s' % best_result_marks.path)

        if self.no_reset is not None and without_resets is None:
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
        if wrong_state and retval is not None:
            print('Watch mark at 0x%x not found in any tracks from this state.  However, a progressive fuzzing' % (self.addr))
            print('state hit that watch mark via %s. Go to that auto_ws and run again, using the tmp.ini found there.' % retval.path)
            retval = None
        return retval
   
