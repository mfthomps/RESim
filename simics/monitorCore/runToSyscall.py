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
class runToSyscall():
    def __init__(self, top, os_utils, cpu, pid, forward, syscall_address, cell, is_monitor_running, lgr):
        self.forward = forward
        self.cpu = cpu
        self.pid = pid
        self.top = top
        self.lgr = lgr
        self.os_utils = os_utils
        self.is_monitor_running = is_monitor_running
        self.start_cycle = SIM_cycle_count(cpu)
        phys_block = cpu.iface.processor_info.logical_to_physical(syscall_address, Sim_Access_Read)
        self.syscall_break = None
        self.lgr.debug('runToSyscall, init, given, 0x%x  phys addr: 0x%x pid: %d' % (syscall_address, phys_block.address, pid))
        print('runToSyscall, init, phys addr: 0x%x' % phys_block.address)
        if phys_block.address != 0:
            pcell = cpu.physical_memory
            self.syscall_break = SIM_breakpoint(pcell, Sim_Break_Physical, Sim_Access_Execute, phys_block.address, 1, 0)
        else:
            self.syscall_break = SIM_breakpoint(cell, Sim_Break_Linear, Sim_Access_Execute, 
                syscall_address, 1, 0)
            self.lgr.debug('runToSyscall, using linear break ')
        self.stop_hap = self.top.RES_add_stop_callback(self.stoppedExecution, None)
        self.is_monitor_running.setRunning(True)
        if forward:
            self.lgr.debug('runToSyscall, continue')
            SIM_run_command('continue')
        else:
            self.lgr.debug('runToSyscall, reverse')
            print('runToSyscall, reverse')
            SIM_run_command('reverse')

    def stoppedExecution(self, dumb, one, exception, error_string):
        dum_cpu, comm, tid = self.task_utils.curThread()
        self.lgr.debug('stoppedExecution, pid %d look for %d' % (pid, self.pid))
        if cpu == self.cpu and pid == self.pid:
            new_cycle = SIM_cycle_count(cpu)
            if new_cycle == self.start_cycle:
                self.lgr.debug('runToSyscall got nowhere, continue')
                # wfsimics stopped without starting
                if self.forward:
                    self.lgr.debug('runToSyscall, continue')
                    SIM_run_alone(SIM_run_command, 'continue')
                    #SIM_run_command('continue')
                else:
                    self.lgr.debug('runToSyscall, reverse')
                    print('runToSyscall, reverse')
                    #SIM_run_command('reverse')
                    SIM_run_alone(SIM_run_command, 'reverse')
                return  
            eip = self.top.getEIP(self.cpu)
            self.lgr.debug('runToSyscall, stoppedExecution at 0x%x, expect client to run/rev to user space' % eip)
            print('runToSyscall, stoppedExecution, expect client to run/rev to user space')
            self.top.RES_delete_stop_hap(self.stop_hap)
            RES_delete_breakpoint(self.syscall_break)
            self.is_monitor_running.setRunning(False)
            self.top.skipAndMail(cycles=0)
