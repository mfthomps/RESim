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
import resimUtils
class reverseToAddr():
    def __init__(self, address, context_manager, task_utils, is_monitor_running, top, cpu, reverse_mgr, lgr, extra_back=0):
        self.top = top
        self.lgr = lgr
        self.context_manager = context_manager
        self.is_monitor_running = is_monitor_running
        self.extra_back = extra_back
        self.is_monitor_running.setRunning(True)
        self.task_utils = task_utils
        cpu, comm, tid  = task_utils.curThread()
        self.cpu = cpu
        self.tid = tid
        self.reverse_mgr = reverse_mgr
        #resim = self.top.getRESimContext()
        #default = self.top.getDefaultContext()
        #self.the_break = SIM_breakpoint(default, Sim_Break_Linear, Sim_Access_Execute, 
        #            address, 1, 0)
        
        mode = Sim_Access_Execute
        phys_block = cpu.iface.processor_info.logical_to_physical(address, mode)
        if phys_block.address != 0:
            pcell = cpu.physical_memory
            self.the_break = self.reverse_mgr.SIM_breakpoint(pcell, Sim_Break_Physical, Sim_Access_Execute, 
                    phys_block.address, 1, 0)
        else:
            self.lgr.error('reverseToAddr tried to go to umapped memory 0x%x' % address)
            return
        self.lgr.debug('reverseToAddr init addr 0x%x (phys: 0x%x), extra_back=%d cycles: 0x%x break num %d' % (address, phys_block.address, extra_back, cpu.cycles, self.the_break))
       
        #self.one_stop_hap = None
        #self.stop_hap = self.top.RES_add_stop_callback(self.stopHap, cpu)
        self.lgr.debug('reverseToAddr now call reverse')
        self.reverse_mgr.reverse(callback=self.stopHap)

    def goBackAlone(self, dumb):
        backone = self.cpu.cycles - 1 
        #cmd = 'skip-to cycle = %d ' % backone
        #SIM_run_command(cmd)
        self.lgr.debug('goBackAlone call skipToCycle to 0x%x' % backone)
        if not self.top.skipToCycle(backone, cpu=self.cpu, disable=True):
            first = self.top.getFirstCycle()
            self.lgr.error('revToAddr failed goBackAlone.  cycles is 0x%x first cycle is 0x%x' % (self.cpu.cycles, first))
            hap = self.stop_hap
            self.top.RES_delete_stop_hap_run_alone(hap)
            self.stop_hap = None
            self.reverse_mgr.SIM_delete_breakpoint(self.the_break)
        else:
            self.reverse_mgr.reverse()

    def rmStopHap(self, hap):
        self.top.RES_delete_stop_hap(hap)

    def stopHap(self, cpu, one, exception, error_string):
        #if self.stop_hap is None:
        #    return
        cpu, comm, tid  = self.task_utils.curThread()
        eip = self.top.getEIP()
        first = self.top.getFirstCycle()
        self.lgr.debug('reverseToAddr stopHap eip: %x cycles: 0x%x first cycle: 0x%x' % (eip, cpu.cycles, first))
        if cpu.cycles <= first:
            self.lgr.error('reverseToAddr stopHap eip: %x cycles: 0x%x at first cycle' % (eip, cpu.cycles))
            #hap = self.stop_hap
            #self.top.RES_delete_stop_hap_run_alone(hap)
            #self.stop_hap = None 
            self.reverse_mgr.SIM_delete_breakpoint(self.the_break)
            self.the_break = None
            return

        if tid != self.tid:
            self.lgr.debug('reverseToAddr stopHap at 0x%x wrong tid got %s wanted %s cycles: 0x%x excpt: %s  errorstring %s' % (eip, tid, 
                 self.tid, cpu.cycles, str(exception), str(error_string)))
            SIM_run_alone(self.goBackAlone, None)
            return
        #hap = self.stop_hap
        #self.top.RES_delete_stop_hap_run_alone(hap)
        #self.stop_hap = None 
        self.reverse_mgr.SIM_delete_breakpoint(self.the_break)
        self.the_break = None
        origin = self.top.getFirstCycle()
        if cpu.cycles == origin:
            self.lgr.debug('reverseToAddr stopHap hit origin cycle')
            self.context_manager.setIdaMessage('Could not reverse past origin cycle')
            self.top.skipAndMail()
            return
 
        #self.top.gdbMailbox('0x%x' % eip)
        if self.extra_back > 0:
            self.lgr.debug('stopHap asked to go back extra %d' % self.extra_back)
            self.one_stop_hap = self.top.RES_add_stop_callback(self.backOneStopped, cpu)
            self.reverse_mgr.revOne()
        else:
            # ignore cycles, unless new ida refresh strategy fails
            self.is_monitor_running.setRunning(False)
            cycles = 1 + self.extra_back
            self.lgr.debug('reverseToAddr stopHap eip: %x skip nd mail to 0x%x' % (eip, cycles))
            self.top.skipAndMail(cycles)

    def backOneStopped(self, cpu, one, exception, error_string):
        '''
        Invoked when the simulation stops after trying to go back one
        '''
        if self.one_stop_hap is None:
            self.lgr.error('backOneStopped invoked though hap is none')
            return
        hap = self.one_stop_hap
        self.top.RES_delete_stop_hap_run_alone(hap)
        self.one_stop_hap = None
        eip = self.top.getEIP()
        self.lgr.debug('reverseToAddr backOneStopped eip: %x' % eip)
        self.is_monitor_running.setRunning(False)
        self.top.skipAndMail()
