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
from simics import *
from resimHaps import *
class SignalLib():
    def __init__(self, top, cpu, cell, cell_name, task_utils, mem_utils, context_manager, so_map, lgr):
        self.top = top
        self.cell = cell
        self.cell_name = cell_name
        self.cpu = cpu
        self.afl = False
        self.lgr = lgr
        self.task_utils = task_utils
        self.mem_utils = mem_utils
        self.context_manager = context_manager
        self.so_map = so_map
        self.signal_hap = None
        

    def watchThis(self, tid, afl=False):
        if self.signal_hap is None:
            self.afl = afl
            if tid is None:
                cpu, comm, tid = self.task_utils.curThread() 
            section = self.so_map.findCodeSection(tid, 'libsignal.so')
            if section is not None:
               self.lgr.debug('signalLib watchThis found code section for libsignal.so tid:%s' % tid)
               phys = self.mem_utils.v2p(self.cpu, section.addr)
               proc_break = self.context_manager.genBreakpoint(self.cpu.physical_memory, Sim_Break_Physical, Sim_Access_Execute, phys, section.size, 0)
               self.signal_hap = self.context_manager.genHapIndex("Core_Breakpoint_Memop", self.signalHap, tid, proc_break, 'signal')
               self.lgr.debug('signalLib set break on 0x%x (phys 0x%x) size 0x%x self.signal_hap is %d' % (section.addr, phys, section.size, self.signal_hap))
            else:
                self.lgr.debug('signalLib watchThis NO code section for libsignal.so')
                pass

    def signalHap(self, Dumb, the_object, break_num, memory):
        #self.lgr.debug('signalLib signalHap hap is %s' % self.signal_hap)
        if self.signal_hap is None:
            return
        if self.context_manager.isHapDisabled(self.signal_hap):
            return
        cpu, comm, tid = self.task_utils.curThread() 
        if self.context_manager.watchingExit(tid):
            # ignore if we do not have so info
            if self.so_map.hasSOInfo(tid): 
                pc = self.mem_utils.getRegValue(cpu, 'pc')
                self.lgr.debug('signalLib signalHap tid:%s (%s) cycle: 0x%x afl: %r pc: 0x%x' % (tid, comm, self.cpu.cycles, self.afl, pc))
                if self.afl:
                    self.lgr.debug('signalLib signalHap is afl, call pendingFault with no_stop True')
                    was_pending = self.top.pendingFault(no_stop=True)
                    self.lgr.debug('signalLib signalHap back from pendingFault, was_pending is %r' % was_pending)
                    if was_pending:
                        self.lgr.debug('signalLib, afl was a pending fault break simulation')
                        SIM_break_simulation('signalLib')
                    else:
                        self.lgr.debug('signalLib, afl was NOT a pending fault')
                        self.context_manager.genDisableHap(self.signal_hap)
                        #self.top.setCommandCallback(self.outOfSignal)
                        print('remove this')
                        SIM_break_simulation('remove this')
                        #SIM_run_alone(self.top.runToOtherCallback, self.outOfSignal)
                else:
                    self.lgr.debug('signalLib signalHap NOT afl call pendingFault')
                    if self.top.pendingFault():
                        self.lgr.debug('signalLib, was pending fault')
                    else:
                        self.lgr.debug('signalLib, was NOT a pending fault')
                        self.context_manager.genDisableHap(self.signal_hap)
                        #self.top.setCommandCallback(self.outOfSignal)
                        SIM_run_alone(self.top.runToOtherCallback, self.outOfSignal)
        else:
            #self.lgr.debug('signalLib signalHap tid:%s (%s) context manager NOT Watching this tid cycle: 0x%x' % (tid, comm, self.cpu.cycles))
            pass

    def outOfSignal(self, dumb=None):
            self.lgr.debug('signalLib, outOfSignal')
            self.context_manager.genEnableHap(self.signal_hap)

    def rmHaps(self):
        if self.signal_hap is not None:
            self.context_manager.genDeleteHap(self.signal_hap, immediate=True)
            self.signal_hap = None
            self.lgr.debug('signalLib rmHaps signal_hap now none')

