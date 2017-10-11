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
import procInfo
import traceback
import sys
import pageUtils
import decode
import memUtils
import logging
from monitorLibs import utils
'''
BEWARE syntax errors are not seen.  TBD make unit test
'''
''' 
    Manage reverse step into and over
    TBD add other executable pages 
    The log for this is in its own log file
'''
class runToUserSpace():
    def __init__(self, top, param, os_utils, x_pages, page_size, context_manager, comm, cell_name, cell, cpu, pid, 
                 other_faults, name, is_monitor_running, log_dir):
            self.context_manager = context_manager 
            sys.stderr = open('err.txt', 'w')
            self.top = top 
            #self.lgr = lgr
            self.lgr = utils.getLogger(name, log_dir)
            self.page_size = page_size
            self.lgr.debug('runToUserSpace, in init')
            self.__param = param
            self.os_utils = os_utils
            self.x_pages = x_pages
            self.the_breaks = []
            self.comm = comm
            self.cpu = cpu
            self.pid = pid
            self.cell_name = cell_name
            self.cell = cell
            self.stop_in_user_hap = None
            self.cmd = 'continue'
            self.other_faults = other_faults
            self.mode_hap = None
            self.is_monitor_running = is_monitor_running

    def revToUser(self):
        pre_call_cycle, prev_eip = self.other_faults.getCycles(self.cell_name, self.pid)
        print('revToUser')
        if pre_call_cycle is not None:
            self.is_monitor_running.setRunning(True)
            self.lgr.debug('revToUser, found previous syscall for %s %d at cycle %x' % (self.cell_name, self.pid, pre_call_cycle))
            SIM_run_command('pselect cpu-name = %s' % self.cpu.name)
            SIM_run_command('skip-to cycle=%d' % pre_call_cycle)
            eip = self.top.getEIP(self.cpu)
            self.lgr.debug('revToUser skipped to cycle %x eip: %x' % (pre_call_cycle, eip))
            self.is_monitor_running.setRunning(False)
            self.top.skipAndMail(1) 
        else:
            self.lgr.debug('revToUser, found no previous syscall for %s %d' % (self.cell_name, self.pid))

    def runForward(self):
        self.is_monitor_running.setRunning(True)
        self.lgr.debug('runForward')
        self.mode_hap = SIM_hap_add_callback_obj("Core_Mode_Change", self.cpu, 0, self.modeChanged, self.cpu)
        SIM_continue(0)

    def modeChanged(self, cpu, one, old, new):
        dum_cpu, cur_addr, comm, pid = self.os_utils.currentProcessInfo(self.cpu)
        cell_name = self.top.getTopComponentName(self.cpu)
        #cpl = SIM_processor_privilege_level(self.cpu)
        cpl = memUtils.getCPL(cpu)
        self.lgr.debug('mode_changed %s %d (%s) look for %d, cpl is %d ' % (cell_name, pid, comm, self.pid, cpl))
        if pid == self.pid and cpl != 0:
            #self.top.skipAndMail(1)
            eip = self.top.getEIP()
            instruct = SIM_disassemble_address(cpu, eip, 1, 0)
            self.lgr.debug('mode_changed in correct process, we are done, 0x%x %s' % (eip, instruct[1]))
            SIM_hap_delete_callback_id("Core_Mode_Change", self.mode_hap)
            self.mode_hap = None
            my_args = procInfo.procInfo(self.comm, self.cpu, self.pid)
            self.stop_in_user_hap = SIM_hap_add_callback("Core_Simulation_Stopped", 
        	     self.stoppedRanToUser, my_args)
            SIM_break_simulation('should be in user space')
        else:
            pass

    def runToUser(self, cpu, cell_name, pid, reverse = False):
        self.cpu = cpu
        self.cell_name = cell_name
        self.pid = pid 
        cpl = memUtils.getCPL(self.cpu)
        if cpl != 0:
            self.lgr.debug('runToUser already in user space')
            self.top.skipAndMail(1)
            return
        if reverse:
            self.lgr.debug('runToUser, go backward')
            self.revToUser()
        else:
            self.lgr.debug('runToUser, go forward')
            self.runForward()

    def revToUser(self, reverse = False):
        '''
        Run backwards until in user space of the given process
        '''
        self.cmd = 'reverse'
        cpu, cur_addr, comm, pid = self.os_utils.currentProcessInfo(self.cpu)
        if pid == self.pid and SIM_processor_privilege_level(cpu) != 0:
            self.lgr.debug('runToUser already in user space, we are done')
            self.top.skipAndMail(1)
        else:
            self.lgr.debug('runToUser for %s %d' % (self.cell_name, self.pid))
            eip = self.top.getEIP()
            self.lgr.debug('runToUser starting at %x' % eip)
            my_args = procInfo.procInfo(self.comm, self.cpu, self.pid)
            self.stop_in_user_hap = SIM_hap_add_callback("Core_Simulation_Stopped", 
        	     self.stoppedRanToUser, my_args)
            self.lgr.debug('runToUser, added stop hap')
            for item in self.x_pages:
                self.setBreakRange(self.cell_name, self.pid, item.address, item.length, self.cpu, self.comm)
            self.lgr.debug('runToUser, set break range')
            #SIM_run_alone(SIM_run_command, 'reverse-step-instruction')
            SIM_run_alone(SIM_run_command, self.cmd)
            #self.lgr.debug('reverseToCall, did reverse-step-instruction')
            self.lgr.debug('runToUser, did %s' % self.cmd)


    def rmBreaks(self):
        for breakpt in self.the_breaks:
            SIM_delete_breakpoint(breakpt)
        self.the_breaks = []
        self.stop_in_user_hap = None

                         
    def stoppedRanToUser(self, my_args, one, exception, error_string):
        '''
        Invoked when the simulation stops while running to user space
        '''
        print('stoppedRanToUser')
        if self.stop_in_user_hap is None:
            return 
        cpu, cur_addr, comm, pid = self.os_utils.currentProcessInfo(self.cpu)
        cell_name = self.top.getTopComponentName(cpu)
        self.lgr.debug('stoppedRanToUser %s %d (%s) ' % (cell_name, pid, comm))
        cpl = SIM_processor_privilege_level(cpu)
        if pid == my_args.pid and cpl != 0:
            eip = self.top.getEIP()
            instruct = SIM_disassemble_address(self.cpu, eip, 1, 0)
            self.lgr.debug('stoppedRanToUser in user space, we are done 0x%x %s' % (eip, instruct))
            self.top.skipAndMail(1)
            SIM_hap_delete_callback_id("Core_Simulation_Stopped", self.stop_in_user_hap)
            self.rmBreaks()
            self.is_monitor_running.setRunning(False)
        elif pid == my_args.pid:
            eip = self.top.getEIP()
            self.lgr.error('stoppedRanToUser in kernel pid is %d eip: 0x%x  Stuck in kernel?  Give up' % (pid, eip))
            self.top.skipAndMail(1)
            SIM_hap_delete_callback_id("Core_Simulation_Stopped", self.stop_in_user_hap)
            self.rmBreaks()
        else:
            eip = self.top.getEIP()
            self.lgr.error('stoppedRanToUser wrong process or in kernel pid is %d expected %d' % (pid, my_args.pid))
            SIM_run_alone(SIM_run_command, self.cmd)

    def setBreakRangeLinear(self, cell_name, pid, start, length, cpu, comm): 
        ''' NOT USED, does not seem to work on return to user space when page not mapped. '''
        the_break = SIM_breakpoint(self.cell, Sim_Break_Linear, Sim_Access_Execute, start, length, 0)
        self.lgr.debug('setBreakRangeLinear %d on cell %s start: %x  length: %x' % (the_break, self.cell, start, length))
 
        self.the_breaks.append(the_break)

    def setBreakRange(self, cell_name, pid, start, length, cpu, comm):
        '''
        Set breakpoints to carpet the process's address space
        '''
        self.lgr.debug('setBreakRange begin')
        start, end = pageUtils.adjust(start, length, self.page_size)
        cell = cpu.physical_memory
        #my_args = procInfo.procInfo(comm, cpu, pid, None, False)
      
        self.lgr.debug('Adding breakpoints for %s:%d (%s) at %x through %x, given length was %x' % (cell_name, pid, comm, start, end, length))
        while start <= end:
            limit = start + self.page_size
            phys_block = cpu.iface.processor_info.logical_to_physical(start, Sim_Access_Read)
            if phys_block.address != 0:
                    all_break_num = SIM_breakpoint(cell, Sim_Break_Physical, 
                       Sim_Access_Execute, phys_block.address, self.page_size, 0)
                    self.the_breaks.append(all_break_num)
                    
            elif phys_block.address == 0:
                self.lgr.debug('runToUserSpace FAILED breakpoints for %s:%d (%s) at %x ' % (cell_name, pid, comm,
                    start))

            start = limit
