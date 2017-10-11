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

import simics
from simics import *
import sys
import ConfigParser
import logging
import time
import startDebugging
import debugInfo
import cgcEvents
import pageUtils
import procInfo
from monitorLibs import forensicEvents 
'''
    Set breaks on execution of code outside the elf-defined text region.
    Two initial ranges are zero until the start of the text section; and
    from the start of the data section until the kernel base address.

    The module uses the hapManager to associate haps & breakpoints with 
    each pid.
'''
class notCode():
    param = None
    SERVER_NAME = None
    hap_manager = None
    context_manager = None
    def __init__(self, top, param, master_config, hap_manager, 
                   context_manager, os_p_utils, stack_size, ps_strings, page_size, lgr):
        self.param = param
        self.hap_manager = hap_manager
        self.context_manager = context_manager
        self.page_size = page_size
        self.top = top
        self.lgr = lgr
        self.last_nox_pid = None
        self.os_p_utils = os_p_utils
        self.master_config = master_config
        self.test_flag = False

    '''
        Set haps and breakpoints on each page in the given range of logical addresses
        Note the hapManager.add function will fail if the pages are not mapped.  They'll be
        updated via the pageFault module after the pages become mapped.
    '''
    def nonCodeBreakRangeNOT(self, cell_name, pid, cpu, start, length, init=False):
        end = start + length
        obj = SIM_get_object(cell_name)
        cell = obj.cell_context
        my_args = procInfo.procInfo("unknown", cpu, pid, None, False)
        self.lgr.debug('nonCodeBreakRange %s:%d start: %x end: %x' % (cell_name, pid, start, end)) 
        break_num = SIM_breakpoint(cell, Sim_Break_Linear, Sim_Access_Execute, 
                start, length, 0)
        cb_num = SIM_hap_add_callback_index("Core_Breakpoint_Memop", self.non_code_callback, my_args, break_num)
        self.hap_manager.addHap(cpu, cell_name, pid, cb_num, start, 2)
        self.hap_manager.addBreak(cell_name, pid, break_num, start, 2)

    # IF SWITCH BACK to phys, change pageFaults.py to call this
    def nonCodeBreakRange(self, cell_name, pid, cpu, start, length, init=False):
        cell = cpu.physical_memory
        start, end = pageUtils.adjust(start, length, self.page_size)
        self.lgr.debug('nonCodeBreakRangePhys %s:%d start: %x end: %x' % (cell_name, pid, start, end)) 
        while start < end:
            limit = start + self.page_size
            #self.lgr.debug('nonCodeBreakRange call hap manager start: %x page: %x' % (start, self.page_size)) 
            self.hap_manager.add(cpu, cell_name, pid, start, self.page_size, 
                          Sim_Access_Execute, self.non_code_callback)
            start = limit
    ''' 
        Remove haps and breakpoints for pages in the given range of logical addresses.
        Note, since we don't track the PROT on pages that are added, there may not be any
        haps in the given range.
    '''
    def nonCodeRangeRemoveNOT(self, cell_name, pid, cpu, start, length):
        self.hap_manager.rm(cell_name, pid, start)

    def nonCodeRangeRemove(self, cell_name, pid, cpu, start, length):
        cell = cpu.physical_memory
        start, end = pageUtils.adjust(start, length, self.page_size)
      
        while start < end:
            limit = start + self.page_size
            self.hap_manager.rm(cell_name, pid, start)
            start = limit

    '''
        Hap from executing instruction that should not be executable. 
    '''
    def non_code_callback(self, my_args, third, break_num, memory):
        if self.context_manager.getDebugging():
            return
        cell_name = self.top.getTopComponentName(my_args.cpu)
        cpu, cur_addr, comm, pid = self.os_p_utils[cell_name].getPinfo(my_args.cpu)
        if cpu != my_args.cpu:
            self.lgr.error('non_code_callback, cpu does not match expected myargs on %s' % cell_name)
        eip = self.os_p_utils[cell_name].mem_utils.getRegValue(cpu, 'eip')
        if pid == my_args.pid:
            if self.top.isReplaySignalCode(cell_name, eip):
                self.lgr.debug('Replay signal code in %s:%d (%s) executed at %x' % (cell_name, pid, comm, eip))
                return
            if self.hap_manager.isLinuxOverlap(cpu, cell_name, pid, eip):
                if pid != self.last_nox_pid:
                    self.last_nox_pid = pid
                    self.lgr.debug('non_code_callback from overlap %s:%d (%s) executed at %x' % (cell_name, pid, comm, eip))
            #print "in not code for %s" % comm
            if pid != self.last_nox_pid:
                ''' if this instruction crosses into the last text page, and that page is not yet swapped in, then
                    it is likely the linux shared-page-between-text-and-data problem.  ignore it. '''
                instruct = SIM_disassemble_address(cpu, eip, 1, 0)
                last_byte = instruct[0] + eip - 1
                text_start = self.hap_manager.getTextStart(cell_name,pid)
                if last_byte >= text_start and last_byte < (text_start+self.page_size):
                    self.lgr.debug('non_code_callback, shared text-data-fu at 0x%x, ignoring' % eip)
                    return
                eip_phys = self.os_p_utils[cell_name].mem_utils.v2p(cpu, eip)
                self.lgr.info('Execution outside code region, %s:%d (%s) eip: %x break_num %d phys: %x eip_phys: %x' % (cell_name, pid, 
                   comm, eip, break_num, memory.physical_address, eip_phys))
                if comm == self.master_config.player_name:
                    self.top.addLogEvent(cell_name, pid, comm, forensicEvents.PLAYER_NO_X,
                         'Player execution outside of code at eip %x ' % eip)
                else:
                    self.top.addLogEvent(cell_name, pid, comm, forensicEvents.USER_NO_X,
                         'Execution outside of code at eip %x ' % eip)
                    if self.master_config.stopOnSomething():
                        bm='nox:0x%x' % eip
                        self.top.setDebugBookmark(bm, cpu)
	        #SIM_break_simulation('stopping in non_code_callback')

            self.last_nox_pid = pid
            if self.master_config.stop_on_non_code:
                #self.top.target_log.doneItem()
                frame = self.os_p_utils[cell_name].frameFromRegs(my_args.cpu)
                dbi = debugInfo.debugInfo(self.context_manager, self.hap_manager, 
                        pid, comm, 'reverse 1', cgcEvents.CGCEventType.not_code, None, 'dum cb', 
                        'dum pov', cell_name, cpu, frame, eip, self.lgr)
                self.top.cleanupAll()
                self.top.clearProtectedBookmarks()
                startDebugging.startDebugging(dbi, self.param, self.os_p_utils[cell_name])
	        SIM_break_simulation('stopping in non_code_callback')
                #self.hap_manager.clear(pid)
        else:
            if not self.top.isReplaySignalCode(cell_name, eip) and not self.test_flag:
                self.lgr.critical('non_code_callback at eip: %x breaknum: %d unexpected pid, expected %s:%d  got %s:%d (%s) phys addr:%x' % \
                   (eip, break_num, cell_name, my_args.pid, self.top.getTopComponentName(cpu), pid, comm, memory.physical_address))
                self.test_flag = True
                #SIM_break_simulation("debug")
                   
