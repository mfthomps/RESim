from simics import *
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
    Set a breakpoint and stop execution when hit, cleaning up
    any tracking.
'''
class UserBreak():
    def __init__(self, top, addr, count, context_manager, lgr):
        self.top = top
        self.addr = addr
        self.count = count
        self.context_manager = context_manager
        self.lgr = lgr
        self.hit = 0
        self.user_break_hap = None
        self.tid = self.top.getTID()

        self.doBreak()

    def userBreakHap(self, dumb, third, forth, memory):
        if self.user_break_hap is not None:
            tid = self.top.getTID()
            if tid != self.tid:
                pass
            else:
                self.hit = self.hit + 1
                if self.hit >= self.count:
                    self.lgr.debug('userBreakHap after %d hits' % self.hit)
                    self.top.stopAndGo(self.top.stopTrackIO) 
                    self.context_manager.genDeleteHap(self.user_break_hap)
                    self.user_break_hap = None
                    self.top.delUserBreak()

    def stopBreak(self):
        if self.user_break_hap is not None:
            hap = self.user_break_hap
            self.context_manager.genDeleteHap(hap)
            self.user_break_hap = None
     

    def doBreak(self):
        user_break = self.context_manager.genBreakpoint(None, Sim_Break_Linear, Sim_Access_Execute, self.addr, 4, 0)
        self.user_break_hap = self.context_manager.genHapIndex("Core_Breakpoint_Memop", self.userBreakHap, None, user_break, 'user_break')
        self.lgr.debug('doBreak set break on 0x%x' % self.addr)

