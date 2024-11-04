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
Set an execute breakpoint and invoke a callback when it is hit.
Context is a single thread.
'''
from resimHaps import *
from simics import *
class BreakAndCall():
    def __init__(self, top, cpu,  start, count, callback, params, lgr):
        self.top = top
        self.cpu = cpu
        self.start = start
        self.count = count
        self.lgr = lgr
        self.callback = callback
        self.params = params
        self.tid = self.top.getTID()
        self.break_num = None
        self.hap = None
        self.lgr.debug('breakAndCall start 0x%x count 0x%x' % (start, count))
        self.setBreak()
        
 
    def setBreak(self):
        self.break_num = SIM_breakpoint(self.cpu.current_context, Sim_Break_Linear, Sim_Access_Execute, self.start, self.count, 0)
        self.hap = RES_hap_add_callback_index("Core_Breakpoint_Memop", self.doCallback, self.cpu, self.break_num)
        self.lgr.debug('breakAndCall set break range 0x%x to 0x%x' % (self.start, self.count))

    def doCallback(self, cpu, the_obj, the_break, memory):
        if self.hap is None:
            return
        tid = self.top.getTID()
        if tid != self.tid:
            return
        addr = memory.logical_address
        self.lgr.debug('breakAndCall doCallback break num 0x%x addr 0x%x' % (the_break, addr))
        SIM_run_alone(self.callback, self.params)
        self.rmBreaks()

    def rmBreaks(self):
        RES_delete_breakpoint(self.break_num)
        hap = self.hap
        SIM_run_alone(RES_delete_mem_hap, hap)
        self.break_num = None
        self.hap = None
            
             
