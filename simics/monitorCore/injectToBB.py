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
class InjectToBB():
    def __init__(self, top, bb, lgr):
        self.bb = bb
        self.top = top
        self.lgr = lgr
        here = os.getcwd()
        target = os.path.basename(here)
        print('target is %s' % target)
        self.lgr.debug('InjectToBB bb: 0x%x target is %s' % (bb, target))
        flist = findBB.findBB(target, bb, quiet=True)
        self.inject_io = None
        if len(flist) > 0:
            first = flist[0]
            self.lgr.debug('InjectToBB inject %s' % first)
            dest = os.path.join('/tmp', 'bb.io')
            self.top.setCommandCallback(self.doStop)
            self.inject_io = self.top.injectIO(first, callback=self.doStop, break_on=bb, go=False)
            afl_filter = self.inject_io.getFilter()
            if afl_filter is not None:
                data = None
                with open(first, 'rb') as fh:
                    data = bytearray(fh.read())
                new_data = afl_filter.filter(data, None)
                with open(dest, 'wb') as fh:
                    fh.write(new_data)
                self.inject_io.go()
       
        else:
            print('No input files found to get to bb 0x%x' % bb)

    def doStop(self, dumb=None):
        self.lgr.debug('InjectToBB doStop')
        self.top.stopDataWatch()
        SIM_run_alone(self.inject_io.delCallHap, None)
        status = SIM_simics_is_running()
        if status:
            self.top.stopAndGo(self.gobb)
        else:
            self.gobb()

    def gobb(self):
        if self.inject_io is None:
            return
        self.top.setCommandCallback(None)
        print('Data file copied to /tmp/bb.io (and filtered if there was one).')
