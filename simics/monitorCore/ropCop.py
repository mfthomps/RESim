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
import pageUtils
import debugInfo
import cgcEvents
import startDebugging2
import procInfo
from monitorLibs import forensicEvents 
'''
   Look for a return to a place other than following a call
'''
class ropCop():
    param = None
    SERVER_NAME = None
    hap_manager = None
    context_manager = None
    page_size = None
    MAX_INSTRUCT_LEN = 6
    def __init__(self, top, cell_config, param, master_config, hap_manager, context_manager,
                    noX, os_p_utils, page_size, lgr):
        self.cell_config = cell_config
        self.param = param
        self.master_config = master_config
        self.hap_manager = hap_manager
        self.context_manager = context_manager
        self.noX = noX
        self.os_p_utils = os_p_utils
        self.page_size = page_size
        self.top = top
        self.lgr = lgr
        #self.skip_list = []
        self.explicit_returns = {}
        '''
        with open('playerROP.txt', 'r') as f:
            for line in f:
		value = int(line, 16)
                self.skip_list.append(value)
                self.lgr.debug('RopCop exception adding addr: %x' % value)
        '''
        try:
            with open('playerReturns.txt', 'r') as f:
                prog = 'player'
                self.explicit_returns[prog] = []
                for line in f:
	            value = int(line, 16)
                    self.explicit_returns[prog].append(value)
                    self.lgr.debug('RopCop exception adding addr: %x' % value)
        except IOError:
            pass

    def clear(self, cell_name, pid):
        pass

    # not used
    def checkExceptions(self, break_num, start, end, cpu):
        for value in self.skip_list:
            if value >= start and value < end:
                phys_block = cpu.iface.processor_info.logical_to_physical(value, Sim_Access_Read)
                SIM_breakpoint_remove(break_num, Sim_Access_Execute, phys_block.address, 4)
                self.lgr.debug('removed breakpoint for address %x' % value)

    def useDiscreteReturns(self, comm, pid, start, end, cpu, cell_name, cell, my_args):
        retval = False
        if comm in self.explicit_returns:
            self.lgr.debug('using discrete returns for %s %x to %x' % (comm, start, end))
            retval = True
            for ret in self.explicit_returns[comm]:
               if ret >= start and ret < end:
                   phys_block = cpu.iface.processor_info.logical_to_physical(ret, Sim_Access_Read)
                   if phys_block.address != 0:
                       # Set exectution breakpoints for "ret" instruction
                       self.lgr.debug('setting discrete return for %s  at %x ' % (comm, ret))
                       code_break_num = SIM_breakpoint(cell, Sim_Break_Physical, 
                          Sim_Access_Execute, phys_block.address, 1, 0)
                       cb_num = SIM_hap_add_callback_index("Core_Breakpoint_Memop", 
       	    	          self.rop_cop_ret_callback, my_args, code_break_num)
                       # use 'kind' of 2 to indicate these are Rop breaks
                       self.hap_manager.addBreak(cell_name, pid, code_break_num, ret, 2)
                       self.hap_manager.addHap(cpu, cell_name, pid, cb_num, ret, 2)
        return retval

    def ropCopBreakRangePhys(self, cell_name, pid, start, length, cpu, comm, top=False, from_loader=False):
        start, end = pageUtils.adjust(start, length, self.page_size)
        cell = cpu.physical_memory
        my_args = procInfo.procInfo(comm, cpu, pid, None, False)
      
        self.lgr.debug('Adding Rop Cop breakpoints for %s:%d (%s) at %x through %x, given length was %x' % (cell_name, pid, comm, start, end, length))
        while start <= end:
            limit = start + self.page_size
            phys_block = cpu.iface.processor_info.logical_to_physical(start, Sim_Access_Read)
            if phys_block.address != 0:
                if from_loader and self.hap_manager.hasCodePage(cell_name, pid, start):
                    # duplicate pages in program header, we are parsing backwards, so skip this.
                    self.lgr.debug('ropCopBreakRange, already did code page for %x, skipping this page' % start)
                elif not self.useDiscreteReturns(comm, pid, start, limit, cpu, cell_name, cell, my_args):
                    self.lgr.debug('ropCopBreakRange not using discrete returns for %s, phys %x (virt: %x)' % (comm, 
                         phys_block.address, start))
                    # Set exectution breakpoints for "ret" instructions
                    code_break_num = SIM_breakpoint(cell, Sim_Break_Physical, 
                       Sim_Access_Execute, phys_block.address, self.page_size, 0)
                    #self.checkExceptions(code_break_num, start, limit, cpu)
                    command = 'set-prefix %d "ret"' % code_break_num
                    SIM_run_alone(SIM_run_command, command)
                    cb_num = SIM_hap_add_callback_index("Core_Breakpoint_Memop", 
        	    	    self.rop_cop_ret_callback, my_args, code_break_num)
                    # use 'kind' of 2 to indicate these are Rop breaks
                    self.hap_manager.addBreak(cell_name, pid, code_break_num, start, 2)
                    self.hap_manager.addHap(cpu, cell_name, pid, cb_num, start, 2)
                    
                if top:
                    self.hap_manager.setTextTop(cell_name, physical_block.address)

            elif phys_block.address == 0:
                self.lgr.debug('FAILED Rop Cop breakpoints for %s:%d (%s) at %x ' % (cell_name, pid, comm,
                    start))

            start = limit

    # IF switched back to phys, then fix ret_callback in cgcMonitor
    def ropCopBreakRange(self, cell_name, pid, start, length, cpu, comm, top=False, from_loader=False):
        end = start + length
        cell = self.cell_config.cell_context[cell_name]
        '''
        obj = SIM_get_object(cell_name)
        try:
            cell = obj.cell_context
        except:
            self.lgr.error('ropCopBreakRange could not get cell context from %s' % cell_name)
            return
        '''

        my_args = procInfo.procInfo(comm, cpu, pid, None, False)
      
        self.lgr.debug('Adding Rop Cop breakpoints for %s:%d (%s) at %x through %x, given length was %x' % (cell_name, pid, comm, start, end, length))
        if from_loader and self.hap_manager.hasCodePage(cell_name, pid, start):
            # duplicate pages in program header, we are parsing backwards, so skip this.
            self.lgr.debug('ropCopBreakRange, already did code page for %x, skipping this page' % start)
            return
        self.lgr.debug('ropCopBreakRange not using discrete returns for %s, virt: %x' % (comm, 
                 start))
        # Set exectution breakpoints for "ret" instructions
        code_break_num = SIM_breakpoint(cell, Sim_Break_Linear,
           Sim_Access_Execute, start, length, 0)
        #self.checkExceptions(code_break_num, start, limit, cpu)
        command = 'set-prefix %d "ret"' % code_break_num
        SIM_run_alone(SIM_run_command, command)
        cb_num = SIM_hap_add_callback_index("Core_Breakpoint_Memop", 
	    	    self.rop_cop_ret_callback, my_args, code_break_num)
        # use 'kind' of 2 to indicate these are Rop breaks
        self.hap_manager.addBreak(cell_name, pid, code_break_num, start, 2)
        self.hap_manager.addHap(cpu, cell_name, pid, cb_num, start, 2)
                    

    ''' handle the hitting of "ret" instructions '''
    def rop_cop_ret_callback(self, my_args, third, forth, memory):
        if self.context_manager.getDebugging():
            return

        cell_name = self.top.getTopComponentName(my_args.cpu)
        cpu, cur_addr, comm, pid = self.os_p_utils[cell_name].getPinfo(my_args.cpu)
        if pid != my_args.pid:
            eip = self.os_p_utils[cell_name].mem_utils.getRegValue(my_args.cpu, 'eip')
            #self.lgr.debug('rop_cop_ret_callback %d  but I am %d  at %x' % (my_args.pid,
            #     pid, eip))
            return
        current_eip = self.os_p_utils[cell_name].mem_utils.getRegValue(my_args.cpu, 'eip')
        
        esp = self.os_p_utils[cell_name].mem_utils.getRegValue(my_args.cpu, 'esp')
        #return_to = self.os_p_utils[cell_name].mem_utils.readPtr(my_args.cpu, esp)
        return_to = self.os_p_utils[cell_name].mem_utils.readWord32(my_args.cpu, esp)
        eip = return_to - 8
        done = False
        #self.lgr.debug("rop_cop_ret_callback current_eip: %x return_to %x" % (current_eip, return_to))
        while not done and eip < return_to:
            # TBD use instruction length to confirm it is a true call
            try:
                instruct = SIM_disassemble_address(cpu, eip, 1, 0)
            except:
                self.lgr.debug('ropCop  failed to disassble instruct %x, for %s:%d (%s) likely a corrupt return-to pointer' % (eip, cell_name, pid, comm))
                self.top.addLogEvent(cell_name, pid, comm, forensicEvents.USER_ROP,
                    'Return to non-executable at %x return to %x' % (current_eip, return_to))
                return
            if instruct[1].startswith('call'):
                #self.lgr.debug('is a call eip 0x%x len %d  return to 0x%x' % (eip, instruct[0], return_to))
                if eip + instruct[0] == return_to:
                    done = True
                else:
                    eip += 1
            else:
                eip = eip+1
        if not done:
            ''' is the return instruction to executable code, i.e., text areas? '''
            phys_block = my_args.cpu.iface.processor_info.logical_to_physical(return_to, Sim_Access_Read)
            self.lgr.debug('no call found for %x phys addr is %x' % (return_to, phys_block.address))
            if not self.noX.isIn(cell_name, pid, return_to) and phys_block.address != 0 and return_to < self.param[cell_name].kernel_base:
                last_ret_eip = self.top.getLastRetEIP(cell_name, pid)
                if last_ret_eip == current_eip:
                    self.lgr.debug('on return, we did get rescheduled %s:%d (%s) return to %x' % (cell_name, pid, comm, return_to))
                    return
                elif last_ret_eip is not None:
                    self.lgr.debug('last_ret_eip was %x' % last_ret_eip)
                self.lgr.info('Return does not match call, %s:%d (%s) current_eip: %x ret is to %x' % \
                               (cell_name, pid, comm, current_eip, return_to))
                if comm == self.master_config.player_name:
                    self.top.addLogEvent(cell_name, pid, comm, forensicEvents.PLAYER_ROP,
                        'Player return without a call at %x return to %x' % (current_eip, return_to))
                else:
                    self.top.addLogEvent(cell_name, pid, comm, forensicEvents.USER_ROP,
                        'Return without a call at %x return to %x' % (current_eip, return_to), low_priority=True)
                #self.lgr.info('third is %s  forth is %s value %d' % (type(third), type(forth), forth))
                if self.master_config.stopOnSomething():
                    bm='rop:0x%x' % return_to
                    self.top.setDebugBookmark(bm, cpu)
                if self.master_config.stop_on_rop:
                    self.context_manager.setIdaMessage('Return does not match call, %s:%d (%s) current_eip: %x ret is to %x' % \
                               (cell_name, pid, comm, current_eip, return_to))
                    #self.top.replay_log.doneItem()
	            SIM_break_simulation('stopping in rop_cop_ret_callback')
                    frame = self.os_p_utils[cell_name].frameFromRegs(cpu)
                    dbi = debugInfo.debugInfo(self.context_manager, self.hap_manager, 
                            pid, comm, None, cgcEvents.CGCEventType.rop_cop, None, 'dum cb', 
                            'dum pov', cell_name, cpu, frame, current_eip, self.lgr)
                    self.lgr.debug('rop_cop_ret_callback, call startDebugging')
                    self.top.cleanupAll()
                    self.top.clearProtectedBookmarks()
                    dbi.context_manager.setDebugging(True)
                    startDebugging2.startDebugging2(dbi)
            else:
                ''' return is to non-executable code, should be caught by notCode and/or signal handling'''
                self.lgr.info('Return to non-executable, %s:%d (%s) current_eip: %x ret is to %x' % \
                   (cell_name, pid, comm, current_eip, return_to))
                self.top.addLogEvent(cell_name, pid, comm, forensicEvents.USER_ROP,
                    'Return to non-executable at %x return to %x' % (current_eip, return_to))
                ''' note location in case we are debugging and the return to is on mars '''
                self.top.recordReturnToCycle(cpu, cell_name, pid)
                bm = 'rop:0x%x' % return_to
                self.top.setDebugBookmark(bm, cpu)

