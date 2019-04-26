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
import decode
import logging
import procInfo
int80=0x180
'''
    Catch processor faults other than page faults
'''
class otherFaults():
    def __init__(self, top, master_config, cell_config, os_p_utils, lgr):
        self.top = top
        self.lgr = lgr
        self.os_p_utils = os_p_utils
        self.fault_hap1 = {}
        self.fault_hap2 = {}
        self.cell_config = cell_config
        self.pre_call_cycles = {}
        self.pre_call_eip = {}
        self.stop_on_something = master_config.stopOnSomething()
        self.setHaps()

    def reInit(self, master_config):
        self.lgr.debug('otherFaults reInit')
        self.cleanAll()
        self.stop_on_something = master_config.stopOnSomething()
        self.setHaps()

    def newCB(self):
        self.lgr.debug('otherFaults newCB')
        for cell_name in self.cell_config.cells:
            self.pre_call_cycles[cell_name] = {}
            self.pre_call_eip[cell_name] = {}

    def setHaps(self):
        self.lgr.debug('otherFaults reInit')
        max_intr = 255
        ''' SW interrupts disable VMP (kills performance), only do that if in debug
            and TBD use stack fram return value instead.
        '''

        if self.stop_on_something:
            max_intr = 1028
        for cell_name in self.cell_config.cells:
            cmd = '%s.get-processor-list' % cell_name
            proclist = SIM_run_command(cmd)
            cpu = SIM_get_object(proclist[0])
            self.fault_hap1[cell_name] = SIM_hap_add_callback_obj_range("Core_Exception", cpu, 0,
                 self.fault_callback, cpu, 0, 13) 
            self.fault_hap2[cell_name] = SIM_hap_add_callback_obj_range("Core_Exception", cpu, 0,
                 self.fault_callback, cpu, 15, max_intr) 
            self.lgr.debug('otherFaults, set %s hap1 to %d max_intr is %d' % (cell_name, self.fault_hap1[cell_name], max_intr))
            self.pre_call_cycles[cell_name] = {}
            self.pre_call_eip[cell_name] = {}

    def fault_callback(self, cpu, one, exception_number):
        cell_name = self.top.getTopComponentName(cpu)
        dumcpu, cur_addr, comm, pid = self.os_p_utils[cell_name].getPinfo(cpu)
        if self.stop_on_something and self.top.isWatching(cell_name, pid):
            # monitor debug session, record sycall locations to ease return to user space before call
            self.lgr.debug('fault_callback %s:%d (%s) got fault 0x%x' % (cell_name, pid, comm, exception_number))
            #if comm == 'POV_CBCADET_0000301_ATH_000001.pov':
            #    SIM_break_simulation('wtf/over')
            if exception_number == int80:
                eip = self.top.getEIP(cpu)
                self.lgr.debug('fault_callback, adding pre_call_cycles of 0x%x at eip 0x%x' % (cpu.cycles, eip))
                self.pre_call_cycles[cell_name][pid] = cpu.cycles 
                self.pre_call_eip[cell_name][pid] = eip

    def getCycles(self, cell_name, pid):
        retval = None, None
        if cell_name in self.pre_call_cycles:
            if pid in self.pre_call_cycles[cell_name]:
                retval = self.pre_call_cycles[cell_name][pid], self.pre_call_eip[cell_name][pid]
        return retval
        
    def cleanAll(self):
        self.lgr.debug('otherFaults, cleanAll')
        for cell_name in self.cell_config.cells:
            if cell_name in self.fault_hap1:
                SIM_hap_delete_callback_id('Core_Exception', self.fault_hap1[cell_name])
                SIM_hap_delete_callback_id('Core_Exception', self.fault_hap2[cell_name])
        self.fault_hap1 = {}
        self.fault_hap2 = {}
