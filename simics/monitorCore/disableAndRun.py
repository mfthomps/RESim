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
Disable all breakpoints at the context_manager, run to an address and
then re-enable and call an optional callback.
'''
from simics import *
from resimHaps import *
class DisableAndRun():
    def __init__(self, cpu, addr, context_manager, lgr, callback=None):
        self.cpu = cpu
        self.addr = addr
        self.lgr = lgr
        self.context_manager = context_manager
        self.callback = callback
        self.lgr.debug('DisableAndRun for 0x%x cycles: 0x%x' % (addr, self.cpu.cycles))
        SIM_run_alone(self.setBreakHap, addr)

    def setBreakHap(self, addr):
        phys_block = self.cpu.iface.processor_info.logical_to_physical(addr, Sim_Access_Execute)
        if phys_block is None or phys_block.address is None:
            self.lgr.error('DisableAndRun could not get phys addr for 0x%x' % addr)
            return
        else: 
            self.addr_break = SIM_breakpoint(self.cpu.physical_memory, Sim_Break_Physical, Sim_Access_Execute, phys_block.address, 1, 0)
            self.addr_hap = RES_hap_add_callback_index("Core_Breakpoint_Memop", self.hitAddr, None, self.addr_break)
            self.context_manager.disableAll(direction='forward')
            self.lgr.debug('DisableAndRun for 0x%x, set break and disabled context manager breaks' % addr)
 
    def hitAddr(self, dumb, the_object, the_break, memory):
        if self.addr_hap is not None:
            self.lgr.debug('DisableAndRun hit break 0x%x' % self.addr)
            SIM_run_alone(self.context_manager.enableAll, None)
            hap = self.addr_hap
            RES_delete_breakpoint(self.addr_break)
            self.addr_break = None
            SIM_run_alone(self.rmHap, hap)
            self.addr_hap = None
            if self.callback is not None:
                self.callback()

    def rmHap(self, hap):
        RES_hap_delete_callback_id("Core_Breakpoint_Memop", hap)
        
