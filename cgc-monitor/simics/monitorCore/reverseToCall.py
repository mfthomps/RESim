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
import logging
import decode
import memUtils
import pageUtils
from monitorLibs import utils
'''
BEWARE syntax errors are not seen.  TBD make unit test
'''
''' 
    Manage reverse step into and over
    TBD add other executable pages 
    The log for this is in its own log file
'''

class reverseToCall():
    def __init__(self, top, param, os_utils, page_size, context_manager, name, is_monitor_running, bookmarks, logdir):
            #print('call getLogger')
            self.lgr = utils.getLogger(name, logdir)
            self.context_manager = context_manager 
            #sys.stderr = open('err.txt', 'w')
            self.top = top 
            self.cpu = None
            self.pid = None
            self.cell_name = None
            #self.lgr = lgr
            self.page_size = page_size
            self.lgr.debug('reverseToCall, in init')
            self.param = param
            self.os_utils = os_utils
            ''' hackish for sharing this with genMonitor and cgcMonitor '''
            self.x_pages = None
            self.the_breaks = []
            self.reg = None
            self.reg_num = None
            self.reg_val = None
            self.stop_hap = None
            self.uncall = False
            self.is_monitor_running = is_monitor_running
            self.taint = False
            self.bookmarks = bookmarks
            self.previous_eip = None
            self.step_into = None
            self.sysenter_cycles = []
            self.jump_stop_hap = None
            self.sysenter_hap = None
            self.enter_break1 = None
            self.enter_break2 = None
            self.start_cycles = None

    def getStartCycles(self):
        return self.start_cycles

    def noWatchSysenter(self):
        if self.enter_break1 is not None:
            self.lgr.debug('noWatchSystenter, remove sysenter breaks and hap')
            self.context_manager.genDeleteBreakpoint(self.enter_break1)
            self.context_manager.genDeleteBreakpoint(self.enter_break2)
            self.context_manager.genDeleteHap(self.sysenter_hap, immediate=True)
            self.enter_break1 = None

    def v2p(self, cpu, v):
        try:
            phys_block = cpu.iface.processor_info.logical_to_physical(v, Sim_Access_Read)
            if phys_block.address != 0:
                return phys_block.address
            else:
                if v < self.param.kernel_base:
                    phys_addr = v & ~self.param.kernel_base 
                    return phys_addr
                else:
                    return 0
                    
        except:
            return None

    def watchSysenter(self, dumb=None):
        cell = self.top.getCell()
        if self.enter_break1 is None:
            #pcell = self.cpu.physical_memory
            #self.sysenter_hap = SIM_hap_add_callback_range("Core_Breakpoint_Memop", self.sysenterHap, prec, self.enter_break1, self.enter_break2)
            self.lgr.debug('watchSysenter set linear breaks at 0x%x and 0x%x' % (self.param.sysenter, self.param.sys_entry))
            #self.lgr.debug('watchSysenter set phys breaks at 0x%x and 0x%x' % (self.v2p(self.cpu, self.param.sysenter), self.v2p(self.cpu, self.param.sys_entry)))
            #self.enter_break1 = self.context_manager.genBreakpoint(pcell, Sim_Break_Physical, Sim_Access_Execute, self.v2p(self.cpu, self.param.sysenter), 1, 0)
            #self.enter_break2 = self.context_manager.genBreakpoint(pcell, Sim_Break_Physical, Sim_Access_Execute, self.v2p(self.cpu, self.param.sys_entry), 1, 0)

            self.enter_break1 = self.context_manager.genBreakpoint(cell, Sim_Break_Linear, Sim_Access_Execute, self.param.sysenter, 1, 0)
            self.enter_break2 = self.context_manager.genBreakpoint(cell, Sim_Break_Linear, Sim_Access_Execute, self.param.sys_entry, 1, 0)
            self.sysenter_hap = self.context_manager.genHapRange("Core_Breakpoint_Memop", self.sysenterHap, None, self.enter_break1, self.enter_break2, 'reverseToCall sysenter')

    def setup(self, cpu, x_pages, bookmarks=None):
            self.lgr.debug('reverseToCall setup')
            self.cpu = cpu
            self.start_cycles = SIM_cycle_count(self.cpu)
            self.cell_name = self.top.getTopComponentName(cpu)
            self.x_pages = x_pages
            if bookmarks is not None: 
                self.bookmarks = bookmarks
            if hasattr(self.param, 'sysenter') and self.param.sysenter is not None:
                '''  Track sysenter to support reverse over those.  TBD currently only works with genMonitor'''
                pid, cell_name, cpu = self.context_manager.getDebugPid() 
                self.pid = pid
                SIM_run_alone(self.watchSysenter, None)



    def doBreaks(self, pcell, range_start, page_count, call_ret):
        size = page_count * pageUtils.PAGE_SIZE
        if call_ret:
            # Set exectution breakpoints for "call" and "ret" instructions
            #call_break_num = self.context_manager.genBreakpoint(pcell, Sim_Break_Physical, 
            #   Sim_Access_Execute, range_start, size, 0)
            call_break_num = SIM_breakpoint(pcell, Sim_Break_Physical, 
               Sim_Access_Execute, range_start, size, 0)
            self.the_breaks.append(call_break_num)
            command = 'set-prefix %d "call"' % call_break_num
            SIM_run_alone(SIM_run_command, command)
            #ret_break_num = self.context_manager.genBreakpoint(pcell, Sim_Break_Physical, 
            #   Sim_Access_Execute, range_start, size, 0)
            ret_break_num = SIM_breakpoint(pcell, Sim_Break_Physical, 
               Sim_Access_Execute, range_start, size, 0)
            self.the_breaks.append(ret_break_num)
            command = 'set-prefix %d "ret"' % ret_break_num
            SIM_run_alone(SIM_run_command, command)
            self.lgr.debug('done setting breakpoints for call and ret addr: 0x%x len: 0x%x' % (range_start, size))
        else:
            break_num = self.context_manager.genBreakpoint(pcell, Sim_Break_Physical, Sim_Access_Execute, 
                range_start, size, 0)
            self.the_breaks.append(break_num)

    def pageTableBreaks(self, call_ret):
        pages = pageUtils.getPageBases(self.cpu, self.lgr, self.param.kernel_base)
        range_start = None
        prev_physical = None
        pcell = self.cpu.physical_memory
        page_count = 1
        for page_info in pages:
            writable = memUtils.testBit(page_info.entry, 1)
            accessed = memUtils.testBit(page_info.entry, 5)
            if writable or not accessed:
                self.lgr.debug('will skip %r %r' % (writable, accessed)) 
                continue
            self.lgr.debug('phys: 0x%x  logical: 0x%x' % (page_info.physical, page_info.logical))
            if range_start is None:
                range_start = page_info.physical
                prev_physical = page_info.physical
            else:
                if page_info.physical == prev_physical + pageUtils.PAGE_SIZE:
                    prev_physical = page_info.physical
                    page_count = page_count + 1
                else:
                    self.lgr.debug('Page not contiguous: 0x%x  range_start: 0x%x  prev_physical: 0x%x' % (page_info.physical, range_start, prev_physical))
                    self.doBreaks(pcell, range_start, page_count, call_ret) 
                    page_count = 1
                    range_start = page_info.physical
                    prev_physical = page_info.physical
        self.doBreaks(pcell, range_start, page_count, call_ret) 
        self.lgr.debug('set %d breaks', len(self.the_breaks)) 

    def doUncall(self):
        self.need_calls = 0
        self.got_calls = 0
        self.is_monitor_running.setRunning(True)
        self.first_back = True
        dum_cpu, cur_addr, comm, pid = self.os_utils[self.cell_name].currentProcessInfo(self.cpu)
        self.lgr.debug('reservseToCall, back from call get procInfo %s' % comm)
        my_args = procInfo.procInfo(comm, self.cpu, pid)
        self.lgr.debug('doUncall, got my_args ')
        self.stop_hap = SIM_hap_add_callback("Core_Simulation_Stopped", 
	        self.stoppedReverseToCall, my_args)
        self.lgr.debug('doUncall, added stop hap')
        self.need_calls = 1
        self.uncall = True
        self.pageTableBreaks(True)
        #for item in self.x_pages:
        #    self.setBreakRange(self.cell_name, pid, item.address, item.length, self.cpu, comm, True)
        self.lgr.debug('doUncall, set break range')
        SIM_run_alone(SIM_run_command, 'reverse')
        #self.lgr.debug('reverseToCall, did reverse-step-instruction')
        self.lgr.debug('doUncall, did reverse')

    def tryBackOneXX(self, step_into):
        current = SIM_cycle_count(self.cpu)
        previous = current - 1
        start_cycle = self.bookmarks.getCycle('_start+1')

        SIM_run_command('pselect cpu-name = %s' % self.cpu.name)
        SIM_run_command('skip-to cycle = 0x%x' % start_cycle)
        cycles = SIM_cycle_count(self.cpu)
        self.lgr.debug('tryBackOne, did skip to start at cycle %x, expected %x ' % (cycles, start_cycle))

        SIM_run_command('skip-to cycle = %d' % previous)
        eip = self.top.getEIP(self.cpu)
        instruct = SIM_disassemble_address(self.cpu, eip, 1, 0)
        self.lgr.debug('tryBackOne skipped to %x eip: %x  %s' % (previous, eip, instruct[1]))
        cpl = memUtils.getCPL(self.cpu)
        done = False
        if cpl > 0:
            mn = decode.getMn(instruct[1])
            if step_into or mn != 'ret':
                self.lgr.debug('tryBackOne worked ok')
                done = True
                self.top.skipAndMail()
                self.context_manager.setExitBreak(self.cpu)
        if not done:
            # more complicated than just back one, reset and return
            #SIM_run_command('skip-to cycle = %d' % current)
            pass
        return done

    def tryBackOne(self, my_args):
        
        self.stop_hap = SIM_hap_add_callback("Core_Simulation_Stopped", 
	        self.tryOneStopped, my_args)
        self.lgr.debug('tryBackOne from cycle 0x%x' % my_args.cpu.cycles)
        SIM_run_command('rev 1')

    def jumpStopped(self, my_args, one, exception, error_string):
        eip = self.top.getEIP(self.cpu)
        self.lgr.debug('jumpStopped at 0x%x' % eip)
        SIM_hap_delete_callback_id("Core_Simulation_Stopped", self.jump_stop_hap)
        self.top.skipAndMail()

    def jumpCycle(self, cycle):
        self.lgr.debug('would jump to 0x%x' % cycle)
        #self.jump_stop_hap = SIM_hap_add_callback("Core_Simulation_Stopped", 
	#        self.jumpStopped, None)
        cmd = 'skip-to cycle = %d ' % cycle
        SIM_run_command(cmd)
        self.top.skipAndMail()

    def tryOneStopped(self, my_args, one, exception, error_string):
        '''
        Invoked when the simulation stops after trying to go back one
        '''
        if self.stop_hap is None:
            self.lgr.error('stoppedReverseToCall invoked though hap is none')
            return
        SIM_hap_delete_callback_id("Core_Simulation_Stopped", self.stop_hap)
        self.stop_hap = None
        #cmd = 'reverse-step-instruction'
        if self.cpu.cycles <= self.start_cycles:
            self.lgr.debug('At start of recording, cycle: 0x%x' % self.cpu.cycles)
            print('At start of recording, cycle: 0x%x' % self.cpu.cycles)
            self.cleanup(self.cpu)
            self.top.skipAndMail() 
            return
        self.lgr.debug('tryOneStopped, entered at cycle 0x%x' % self.cpu.cycles)
        eip = self.top.getEIP(self.cpu)
        instruct = SIM_disassemble_address(self.cpu, eip, 1, 0)
        self.lgr.debug('tryOneStopped reversed 1, eip: %x  %s' % (eip, instruct[1]))
        cpl = memUtils.getCPL(self.cpu)
        done = False
        if cpl > 0:
            mn = decode.getMn(instruct[1])
            if self.step_into or mn != 'ret':
                self.lgr.debug('tryBackOne worked ok')
                done = True
                self.cleanup(self.cpu)
                self.top.skipAndMail()
                self.context_manager.setExitBreak(self.cpu)
        elif len(self.sysenter_cycles) > 0:
            mn = decode.getMn(instruct[1])
            cur_cycles = self.cpu.cycles
            cur_cpu, comm, pid  = self.os_utils[self.cell_name].curProc()
            if pid == my_args.pid and (mn == 'sysexit' or mn == 'iretd'):
                self.lgr.debug('is sysexit, cur_cycles is 0x%x' % cur_cycles)
                prev_cycles = None
                got_it = None
                for cycles in sorted(self.sysenter_cycles):
                    if cycles > cur_cycles:
                        self.lgr.debug('tryOneStopped found cycle between 0x%x and 0x%x' % (prev_cycles, cycles))
                        got_it = prev_cycles - 1
                        break
                    else:
                        self.lgr.debug('tryOneStopped is not cycle 0x%x' % (cycles))
                        prev_cycles = cycles
                if not got_it:
                    self.lgr.debug('tryOneStopped nothing between, assume last cycle of 0x%x' % prev_cycles)
                    got_it = prev_cycles - 1
                SIM_run_alone(self.jumpCycle, got_it)
                done = True

        if not done:
            self.lgr.debug('tryOneStopped, back one did not work, starting at %x' % eip)
            self.stop_hap = SIM_hap_add_callback("Core_Simulation_Stopped", 
    	        self.stoppedReverseToCall, my_args)
            self.lgr.debug('tryOneStopped, added stop hap')
            if self.previous_eip is not None and eip != self.previous_eip and cpl > 0:
                self.lgr.debug('tryOneStopped, prev %x not equal eip %x, assume syscall, set break on prev and rev' % (self.previous_eip, eip))
                self.setOneBreak(self.previous_eip, self.cpu)
            else: 
                self.uncall = False
                for item in self.x_pages:
                    self.setBreakRange(self.cell_name, my_args.pid, item.address, item.length, self.cpu, my_args.comm, False)
                self.lgr.debug('tryOneStopped, set break range')
            SIM_run_alone(SIM_run_command, 'reverse')
            #self.lgr.debug('reverseToCall, did reverse-step-instruction')
            self.lgr.debug('tryOneStopped, did reverse')

        
    def doRevToCall(self, step_into, prev=None):
        self.noWatchSysenter()
        '''
        Run backwards.  If uncall is true, run until the previous call.
        If step_into is true, and the previous instruction is a return,
        enter the function at its return.
        '''

        dum_cpu, cur_addr, comm, pid = self.os_utils[self.cell_name].currentProcessInfo(self.cpu)
        self.is_monitor_running.setRunning(True)
        self.step_into = step_into
        self.first_back = True
        self.lgr.debug('reservseToCall, call get procInfo')
        self.lgr.debug('reservseToCall, back from call get procInfo %s' % comm)
        my_args = procInfo.procInfo(comm, self.cpu, pid)
        self.lgr.debug('reservseToCall, got my_args ')
        self.previous_eip = prev
        self.tryBackOne(my_args)
        #if self.tryBackOne(step_into):
        #    self.is_monitor_running.setRunning(False)
        #    self.lgr.debug('reverseToCall, doRevToCall, tryBackOne worked, we are done')
        #    return
        ''' 
        eip = self.top.getEIP(self.cpu)
        self.lgr.debug('reservseToCall starting at %x' % eip)
        self.stop_hap = SIM_hap_add_callback("Core_Simulation_Stopped", 
	        self.stoppedReverseToCall, my_args)
        self.lgr.debug('reverseToCall, added stop hap')
        if prev is not None and eip != prev:
            self.lgr.debug('reverseToCall, prev %x not equal eip %x, assume syscall, set break on prev and rev' % (prev, eip))
            self.setOneBreak(prev, self.cpu)
        else: 
            self.uncall = False
            for item in self.x_pages:
                self.setBreakRange(self.cell_name, pid, item.address, item.length, self.cpu, comm, False)
            self.lgr.debug('reverseToCall, set break range')
        SIM_run_alone(SIM_run_command, 'reverse')
        #self.lgr.debug('reverseToCall, did reverse-step-instruction')
        self.lgr.debug('reverseToCall, did reverse')
        ''' 

    '''
    BEWARE syntax errors are not seen.  TBD make unit test
    '''
    def doRevToModReg(self, reg, taint=False, offset=0, value=None, num_bytes=None):
        '''
        Run backwards until a write to the given register
        '''
        self.offset =  offset 
        self.taint = taint
        self.value = value
        self.num_bytes = num_bytes
        self.lgr.debug('\ndoRevToModReg cycle 0x%x for register %s offset is %x' % (self.cpu.cycles, reg, offset))
        self.reg = reg
        dum_cpu, cur_addr, comm, pid = self.os_utils[self.cell_name].currentProcessInfo(self.cpu)
        self.reg_num = self.cpu.iface.int_register.get_number(reg)
        self.reg_val = self.cpu.iface.int_register.read(self.reg_num)
        eip = self.top.getEIP(self.cpu)
        self.lgr.debug('doRevToModReg starting at %x, looking for %s change from 0x%x' % (eip, reg, self.reg_val))
        if not self.cycleRegisterMod():
            my_args = procInfo.procInfo(comm, self.cpu, pid)
            self.stop_hap = SIM_hap_add_callback("Core_Simulation_Stopped", 
        	     self.stoppedReverseModReg, my_args)
            self.lgr.debug('doRevToModReg, added stop hap')
            self.cell_name = self.top.getTopComponentName(self.cpu)
            self.pageTableBreaks(False)
            #for item in self.x_pages:
            #    self.setBreakRange(self.cell_name, pid, item.address, item.length, self.cpu, comm, False, reg)
            self.lgr.debug('doRevToModReg, set break range')
            #SIM_run_alone(SIM_run_command, 'reverse-step-instruction')
            SIM_run_alone(SIM_run_command, 'reverse')
            #self.lgr.debug('reverseToCall, did reverse-step-instruction')
            self.lgr.debug('reverseToModReg, did reverse')
        else:
            self.lgr.debug('reverseToModReg got mod reg right off')
            if not self.taint:
                self.cleanup(self.cpu)
            else:
                self.followTaint()

    def rmBreaks(self):
        self.lgr.debug('rmBreaks')
        for breakpt in self.the_breaks:
            SIM_delete_breakpoint(breakpt)
        self.the_breaks = []

    def conditionalMove(self, mn):
        eflags = self.top.getReg('eflags', self.cpu)
        if mn == 'cmovne' and not memUtils.testBit(eflags, 6):
            return True
        elif mn == 'cmove' and memUtils.testBit(eflags, 6):
            return True
        else:
            return False

    def cycleRegisterMod(self):
        '''
        Step backwards one cycle at a time looking for the register being modified.
        If kernel entered, use breakpoints to continue back to user space
        '''
        retval = False
        done = False
        self.lgr.debug('cycleRegisterMod start for %s' % self.reg)
        while not done:
            current = SIM_cycle_count(self.cpu)
            previous = current - 1
            SIM_run_command('pselect cpu-name = %s' % self.cpu.name)
            SIM_run_command('skip-to cycle = %d' % previous)
            if SIM_processor_privilege_level(self.cpu) == 0:
                self.lgr.debug('cycleRegisterMod entered kernel')
                done = True
            else:
                cur_val = self.cpu.iface.int_register.read(self.reg_num)
                #self.lgr.debug('compare %x to %x eip: %x' % (cur_val, self.reg_val, eip))
                '''
                if cur_val != self.reg_val: 
                    eip = self.top.getEIP(self.cpu)
                    self.lgr.debug('cycleRegisterMod at %x, we are done' % eip)
                    done = True
                    retval = True
                    self.is_monitor_running.setRunning(False)
                '''
                eip = self.top.getEIP(self.cpu)
                self.lgr.debug('cycleRegisterMod do disassemble for eip 0x%x' % eip)
                instruct = SIM_disassemble_address(self.cpu, eip, 1, 0)
                self.lgr.debug('cycleRegisterMod disassemble for eip 0x%x is %s' % (eip, str(instruct)))
                mn = decode.getMn(instruct[1])
                self.lgr.debug('cycleRegisterMod decode is %s' % mn)
                if decode.modifiesOp0(mn) or self.conditionalMove(mn):
                    self.lgr.debug('get operands from %s' % instruct[1])
                    op1, op0 = decode.getOperands(instruct[1])
                    self.lgr.debug('cycleRegisterMod mn: %s op0: %s  op1: %s' % (mn, op0, op1))
                    if decode.isReg(op0) and decode.regIsPart(op0, self.reg):
                        self.lgr.debug('cycleRegisterMod at %x, we are done' % eip)
                        done = True
                        retval = True
                
        return retval
                       

    def multOne(self, op0, mn):
        self.lgr.debug('multOne %s %s' % (op0, mn))
        if mn == 'imul':
            self.lgr.debug('multOne is imul')
            if decode.isReg(op0):
                mul = decode.getValue(op0, self.cpu, self.lgr)
                self.lgr.debug('multOne val of %s is 0x%x' % (op0, mul))
                if mul == 1:
                    return True
        return False

    def orValue(self, op1, mn):
        if self.value is not None and mn == 'or':
            if self.num_bytes == 1:
                address = decode.getAddressFromOperand(self.cpu, op1, self.lgr)
                if address is not None:
                    value = self.os_utils[self.cell_name].getMemUtils().readWord32(self.cpu, address)
                    self.lgr.debug('orValue, address is 0x%x value 0x%x' % (address, value))
                    if value == self.value:
                        return True
        return False
            
    def followTaint(self):
        eip = self.top.getEIP(self.cpu)
        instruct = SIM_disassemble_address(self.cpu, eip, 1, 0)
        self.lgr.debug('followTaint instruct at 0x%x is %s' % (eip, str(instruct)))
        op1, op0 = decode.getOperands(instruct[1])
        mn = decode.getMn(instruct[1])
        if not self.multOne(op0, mn) and not mn.startswith('mov') and not mn == 'pop' and not mn.startswith('cmov') \
                                     and not self.orValue(op1, mn) and not mn == 'add':
            ''' NOTE: treating "or" and "add" and imult of one as a "mov" '''
            if mn == 'add':
               offset = None
               #offset = int(op1, 16)
               if '[' in op1:
                   address = decode.getAddressFromOperand(self.cpu, op1, self.lgr)
                   offset = self.os_utils[self.cell_name].getMemUtils().readWord32(self.cpu, address)
                   self.lgr.debug('followTaint, add check of %s, address 0x%x offset is 0x%x' % (op1, address, offset))
               else:
                   offset = decode.getValue(op1, self.cpu, self.lgr)
                   self.lgr.debug('followTaint, add check offset of %s is 0x%x' % (op1, offset))
               if offset is not None and offset <= 8:
                   ''' wth, just an address adjustment? '''
                   self.lgr.debug('followTaint, add of %x, assume address adjust, e.g., heap struct' % offset)
                   self.bookmarks.setDebugBookmark('backtrack eip:0x%x inst:"%s"' % (eip, instruct[1]))
                   self.doRevToModReg(op0, taint=True)
                   return 
            self.lgr.debug('followTaint, not a move, we are stumped')
            self.bookmarks.setDebugBookmark('backtrack eip:0x%x inst:"%s" stumped' % (eip, instruct[1]))
            self.top.skipAndMail()

        elif mn == 'pop':
            esp = self.top.getReg('esp', self.cpu) 
            self.bookmarks.setDebugBookmark('backtrack eip:0x%x inst:"%s"' % (eip, instruct[1]))
            self.cleanup(self.cpu)
            self.top.stopAtKernelWrite(esp, self)

        elif decode.isReg(op1) and not decode.isIndirect(op1):
            self.lgr.debug('followTaint, is reg, track %s' % op1)
            self.doRevToModReg(op1, taint=True)
        elif decode.isReg(op1) and decode.isIndirect(op1):
            self.lgr.debug('followTaint, is indrect reg, track %s' % op1)
            address = decode.getAddressFromOperand(self.cpu, op1, self.lgr)
            self.bookmarks.setDebugBookmark('backtrack switch to indirect value:0x%x eip:0x%x inst:"%s"' % (self.value, eip, instruct[1]))
            self.doRevToModReg(op1, taint=True)

        #elif mn == 'lea':
        #    address = decode.getAddressFromOperand(self.cpu, op1, self.lgr)

        else:
            self.lgr.debug('followTaint, see if %s is an address' % op1)
            address = decode.getAddressFromOperand(self.cpu, op1, self.lgr)
            if address is not None:
                self.lgr.debug('followTaint, yes, address is 0x%x' % address)
                if decode.isByteReg(op0):
                    value = self.os_utils[self.cell_name].getMemUtils().readByte(self.cpu, address)
                else:
                    value = self.os_utils[self.cell_name].getMemUtils().readWord32(self.cpu, address)
                newvalue = self.os_utils[self.cell_name].getMemUtils().getUnsigned(address+self.offset)
                protected_memory = ''
                if self.top.isProtectedMemory(newvalue):
                    protected_memory = ' protected'
                self.lgr.debug('followTaint BACKTRACK eip: 0x%x value 0x%x at address of 0x%x wrote to register %s call stopAtKernelWrite for 0x%x' % (eip, value, address, op0, newvalue))
                if not mn.startswith('mov'):
                    self.bookmarks.setDebugBookmark('taint branch %s eip:0x%x inst:%s' % (protected_memory, eip, instruct[1]))
                    self.lgr.debug('BT bookmark: taint branch %s eip:0x%x inst %s' % (protected_memory, eip, instruct[1]))
                else:
                    self.bookmarks.setDebugBookmark('backtrack%s eip:0x%x inst:"%s"' % (protected_memory, eip, instruct[1]))
                    self.lgr.debug('BT bookmark: backtrack %s eip:0x%x inst:"%s"' % (protected_memory, eip, instruct[1]))
                self.cleanup(self.cpu)
                if len(protected_memory) == 0:
                    self.top.stopAtKernelWrite(newvalue, self)
                else:
                    self.top.skipAndMail()
            else:
                self.lgr.debug('followTaint, BACKTRACK op1 %s not an address or register, stopping traceback' % op1)
                self.bookmarks.setDebugBookmark('backtrack eip:0x%x inst:"%s" stumped' % (eip, instruct[1]))
                self.top.skipAndMail()
        
 
    def stoppedReverseModReg(self, my_args, one, exception, error_string):
        '''
        Invoked when the simulation stops while looking for a modified register
        '''
        cmd = 'reverse'
        self.lgr.debug('stoppedReverseModReg, entered looking for %s' % self.reg)
        dum_cpu, cur_addr, comm, pid = self.os_utils[self.cell_name].currentProcessInfo(self.cpu)
        if pid == my_args.pid and SIM_processor_privilege_level(self.cpu) != 0:
            if not self.cycleRegisterMod():
                self.lgr.debug('stoppedReverseModReg must have entered kernel, continue to previous place where this process ran')
                SIM_run_alone(SIM_run_command, cmd)
            else:
                if not self.taint:
                    self.cleanup(self.cpu)
                else:
                    self.followTaint()
        else:
            self.lgr.error('stoppedReverseModReg wrong process or in kernel pid is %d expected %d' % (pid, my_args.pid))
            SIM_run_alone(SIM_run_command, cmd)
 
    def cleanup(self, cpu):
        self.lgr.debug('cleanup')
        self.context_manager.setExitBreak(cpu)
        if self.stop_hap is not None:
            SIM_hap_delete_callback_id("Core_Simulation_Stopped", self.stop_hap)
            self.stop_hap = None
        self.rmBreaks()
        self.is_monitor_running.setRunning(False)
        if not self.taint:
            self.top.skipAndMail()
        self.lgr.debug('cleanup complete')

    def stoppedReverseToCall(self, my_args, one, exception, error_string):
        '''
        Invoked when the simulation stops while looking for a previous call
        '''
        if self.stop_hap is None:
            self.lgr.error('stoppedReverseToCall invoked though hap is none')
            return
        #cmd = 'reverse-step-instruction'
        cmd = 'reverse'
        cpu, cur_addr, comm, pid = self.os_utils[self.cell_name].currentProcessInfo(self.cpu)
        current = SIM_cycle_count(cpu)
        self.lgr.debug('stoppedReverseToCall, entered %d (%s) cycle: 0x%x' % (pid, comm, current))
        #if current < self.top.getFirstCycle():
        if current <= self.start_cycles:
            self.lgr.debug('stoppedReverseToCall found cycle 0x%x prior to first, stop here' %(current))
            self.cleanup(cpu)
        elif pid == my_args.pid and SIM_processor_privilege_level(cpu) != 0:
            eip = self.top.getEIP(cpu)
            instruct = SIM_disassemble_address(cpu, eip, 1, 0)
            if self.first_back and instruct[1].startswith('int 128'):
                self.lgr.debug('stoppedReverseToCall first back is int 128 at %x, we are done' % eip)
                self.cleanup(cpu)
            elif (self.first_back and not self.uncall) and (not instruct[1].startswith('ret') or self.step_into):
                self.lgr.debug('stoppedReverseToCall first back not a ret or step_into at %x, we are done' % eip)
                self.cleanup(cpu)
            elif instruct[1].startswith('call'):
                self.got_calls += 1
                if self.got_calls == self.need_calls:
                    self.lgr.debug('stoppedReverseToCall at %x we must be done' % eip)
                    self.cleanup(cpu)
                else:
                    self.lgr.debug('stoppedReverseToCall got call %d, need %d' % (self.got_calls, self.need_calls))
                    SIM_run_alone(SIM_run_command, cmd)
            elif instruct[1].startswith('ret'):
                self.need_calls += 1
                self.lgr.debug('stoppedReverseToCall got ret %d' % self.need_calls)
                if self.first_back and not self.uncall:
                    self.rmBreaks()
                    for item in self.x_pages:
                        self.setBreakRange(self.cell_name, pid, item.address, item.length, cpu, comm, True)
                SIM_run_alone(SIM_run_command, cmd)
            else:
                self.lgr.debug('stoppedReverseToCall Not call at %x, is %s' % (eip, instruct[1]))
                SIM_run_alone(SIM_run_command, cmd)
        else:
            self.lgr.debug('stoppedReverseInstruction in wrong pid (%d) or in kernel, try again' % pid)
            SIM_run_alone(SIM_run_command, cmd)
        self.first_back = False
   
    def setOneBreak(self, address, cpu):
        self.lgr.debug('setOneBreak at 0x%x' % address)
        phys_block = cpu.iface.processor_info.logical_to_physical(address, Sim_Access_Read)
        cell = cpu.physical_memory
        call_break_num = SIM_breakpoint(cell, Sim_Break_Physical, 
                       Sim_Access_Execute, phys_block.address, 1, 0)
        self.the_breaks.append(call_break_num)

    def setBreakRange(self, cell_name, pid, start, length, cpu, comm, call_ret, reg=None):
        '''
        Set breakpoints to carpet the process's address space
        '''
        self.lgr.debug('setBreakRange begin')
        start, end = pageUtils.adjust(start, length, self.page_size)
        cell = cpu.physical_memory
        my_args = procInfo.procInfo(comm, cpu, pid, None, False)
      
        self.lgr.debug('Adding breakpoints for %s:%d (%s) at %x through %x, given length was %x' % (cell_name, pid, comm, start, end, length))
        while start <= end:
            limit = start + self.page_size
            phys_block = cpu.iface.processor_info.logical_to_physical(start, Sim_Access_Read)
            if phys_block.address != 0:
                if call_ret:
                    # Set exectution breakpoints for "call" and "ret" instructions
                    call_break_num = SIM_breakpoint(cell, Sim_Break_Physical, 
                       Sim_Access_Execute, phys_block.address, self.page_size, 0)
                    self.the_breaks.append(call_break_num)
                    command = 'set-prefix %d "call"' % call_break_num
                    SIM_run_alone(SIM_run_command, command)
                    ret_break_num = SIM_breakpoint(cell, Sim_Break_Physical, 
                       Sim_Access_Execute, phys_block.address, self.page_size, 0)
                    self.the_breaks.append(ret_break_num)
                    command = 'set-prefix %d "ret"' % ret_break_num
                    SIM_run_alone(SIM_run_command, command)
                    self.lgr.debug('done setting breakpoints for call and ret addr: %x', phys_block.address)
                elif reg is not None:
                    all_break_num = SIM_breakpoint(cell, Sim_Break_Physical, 
                       Sim_Access_Execute, phys_block.address, self.page_size, 0)
                    # TBD substr only applies to mnemonic?
                    #command = 'set-substr %d "%s"' % (all_break_num, reg)
                    #SIM_run_alone(SIM_run_command, command)
                    self.the_breaks.append(all_break_num)
                    self.lgr.debug('done setting breakpoints for reg substring %s addr: %x' % (reg, phys_block.address))
                else:
                    all_break_num = SIM_breakpoint(cell, Sim_Break_Physical, 
                       Sim_Access_Execute, phys_block.address, self.page_size, 0)
                    self.lgr.debug('setBreakRange set phys addr 0x%x linear 0x%x' % (phys_block.address, start))
                    self.the_breaks.append(all_break_num)
                    
            elif phys_block.address == 0:
                self.lgr.debug('reverseToCall FAILED breakpoints for %s:%d (%s) at %x ' % (cell_name, pid, comm,
                    start))

            start = limit
        self.lgr.debug('setBreakRange done')

    def sysenterHap(self, prec, third, forth, memory):
        #reversing = SIM_run_command('simulation-reversing')
        reversing = False
        if reversing:
            return
        else:
            cur_cpu, comm, pid  = self.os_utils[self.cell_name].curProc()
            if cur_cpu == self.cpu and pid == self.pid:
                cycles = self.cpu.cycles
                if cycles not in self.sysenter_cycles:
                    eip = self.top.getEIP(self.cpu)
                    reg_num = self.cpu.iface.int_register.get_number('eax')
                    eax = self.cpu.iface.int_register.read(reg_num)
                    #self.lgr.debug('sysenterHap call %d at 0x%x, add cycle 0x%x' % (eax, eip, cycles))
                    #self.lgr.debug('third: %s  forth: %s' % (str(third), str(forth)))
                    self.sysenter_cycles.append(cycles)
            

