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
class InjectToBB():
    def __init__(self, top, bb, lgr, target_prog=None, targetFD=None, fname=None):
        unfiltered = '/tmp/bb.io'
        filtered = '/tmp/bb_filtered.io'
        self.bb = bb
        self.top = top
        self.lgr = lgr
        if target_prog is not None and targetFD is None:
            self.lgr.error('injectToBB called with target_prog, but no target FD')
            return
        here = os.getcwd()
        afl_target = os.path.basename(here)
        #print('afl_target is %s' % afl_target)
        os_type = top.getTargetEnv('OS_TYPE')
        root_prefix = top.getTargetEnv('RESIM_ROOT_PREFIX')
        find_bb = findBB.FindBB()
        flist = find_bb.getBBList(afl_target, bb, quiet=True, lgr=lgr)
        self.lgr.debug('InjectToBB bb: 0x%x afl_target is %s len of flist is %d target_prog %s fname %s' % (bb, afl_target, len(flist), target_prog, fname))
        self.inject_io = None
        if target_prog is None:
            self.top.debugSnap()
        if fname is None:
            prog = self.top.getFullPath()
        else: 
            prog = fname
        basic_block = resimUtils.getOneBasicBlock(prog, bb, os_type, root_prefix, lgr=self.lgr)
        if basic_block is None:
            self.lgr.error('failed getting basic block for address 0x%x prog %s' % (bb, prog)) 
            print('ERROR getting basic block for address 0x%x prog %s' % (bb, prog)) 
            return
        good_bb = None
        qfile = None 
        for f in flist:
            #print('q file %s, bbstart 0x%x' % (f, basic_block['start_ea'])) 
            trackfile = f.replace('queue', 'trackio')
            if not os.path.isfile(trackfile):
                continue
            mark, packet_num, num_resets = find_bb.getWatchMark(trackfile, basic_block, prog)
            if mark is not None:
                self.lgr.debug('injectToBB, found data ref for %s at 0x%x' % (f, mark))
                good_bb = mark
                qfile = f
                print('Will inject %s, has a data ref at 0x%x' % (f, mark))
                break 
        if good_bb is None and len(flist)>0:
            best_qfile = None
            best_size = None
            for try_file in flist:
                try_size = os.path.getsize(try_file)                    
                if best_qfile is None or try_size < best_size:
                    best_qfile = try_file 
                    best_size = try_size
            print('Will inject %s' % best_qfile)
            qfile = best_qfile
        if qfile is not None:
            self.lgr.debug('InjectToBB 0x%x found file to inject %s' % (bb, qfile))
            self.top.setCommandCallback(self.doStop)
            self.top.overrideBackstopCallback(self.doStop)
            self.inject_io = self.top.injectIO(qfile, callback=self.doStop, break_on=bb, go=False, target=target_prog, targetFD=targetFD, reset_debug=False, fname=fname)
            afl_filter = self.inject_io.getFilter()
            if afl_filter is not None:
                data = None
                with open(qfile, 'rb') as fh:
                    data = bytearray(fh.read())
                new_data = afl_filter.filter(data, None)
                with open(filtered, 'wb') as fh:
                    fh.write(new_data)
            shutil.copyfile(qfile, unfiltered)
            self.inject_io.go()
       
        else:
            print('No input files found to get to bb 0x%x' % bb)

    def doStop(self, got_hit=None):
        self.lgr.debug('InjectToBB doStop')
        self.top.stopDataWatch()
        SIM_run_alone(self.inject_io.delCallHap, None)
        if got_hit == True:
            SIM_run_alone(self.top.setDebugBookmark,'injectToBB')
        status = SIM_simics_is_running()
        if status:
            self.top.stopAndGo(self.gobb)
        else:
            self.gobb()

    def gobb(self):
        if self.inject_io is None:
            return
        self.top.setCommandCallback(None)
        self.top.restoreBackstopCallback()
        print('Data file copied to /tmp/bb.io (and bb_filtered.io if there was a filter).')
