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
import taskUtils
import procInfo
import traceback
import sys
import os
import decode
import decodeArm
import memUtils
import pageUtils
import resimUtils
import armCond
import net
import syscall
import resimHaps
import time
import pickle
from resimHaps import *
'''
BEWARE syntax errors are not seen.  TBD make unit test
'''
''' 
    Manage reverse step into and over
    TBD add other executable pages 
    The log for this is in its own log file
'''
class RegisterModType():
    UNKNOWN = 0
    REG = 1
    ADDR = 2
    FUN_VAL = 3
    ''' pursuing taint via other means '''
    BAIL = 4
    def __init__(self, value, mod_type, src_reg=None):
        ''' may be a reg name or an address'''
        self.value = value
        self.mod_type = mod_type
        self.src_reg = None
    def toString(self):
        retval = None
        if self.mod_type == RegisterModType.ADDR:
            retval = 'Address: 0x%x' % self.value
        elif self.mod_type == RegisterModType.REG:
            retval = 'Register: %s' % self.value
        elif self.mod_type == RegisterModType.FUN_VAL:
            retval = 'Function return r0 of zero'
        else:
            retval = 'Bail'
        return retval

class RegisterToTrack():
    def __init__(self, reg, value, cycle):
        self.reg = reg
        self.value = value
        self.cycle = cycle


class reverseToCall():
    def __init__(self, top, cell_name, param, task_utils, mem_utils, page_size, context_manager, name, 
                 is_monitor_running, bookmarks, logdir, compat32, run_from_snap):
            #print('call getLogger')
            logname = '%s-%s' % (name, cell_name)
            self.lgr = resimUtils.getLogger(logname, logdir)
            self.context_manager = context_manager 
            #sys.stderr = open('err.txt', 'w')
            self.top = top 
            self.cpu = None
            self.pid = None
            self.cell_name = cell_name
            self.compat32 = compat32
            #self.lgr = lgr
            self.page_size = page_size
            self.lgr.debug('reverseToCall, in init cell %s' % self.cell_name)
            self.param = param
            self.task_utils = task_utils
            self.mem_utils = mem_utils
            self.decode = None
            ''' hackish for sharing this with genMonitor and cgcMonitor '''
            self.x_pages = None
            self.the_breaks = []
            self.reg = None
            self.reg_num = None
            self.reg_val = None
            self.prev_reg_val = None
            self.stop_hap = None
            self.uncall = False
            self.is_monitor_running = is_monitor_running
            self.taint = False
            self.bookmarks = bookmarks
            self.previous_eip = None
            self.step_into = None
            self.sysenter_cycles = {}
            self.recent_cycle = {}
            self.jump_stop_hap = None
            self.sysenter_hap = None
            self.start_cycles = None
            self.page_faults = None
            self.frame_ips = []
            self.uncall_hap = None
            self.uncall_break = None
            self.value = None
            ''' used for undoing ghost frames '''
            self.save_cycle = None
            self.save_reg_mod = None
            self.satisfy_value = None
            self.run_from_snap = run_from_snap
            ''' keep tracking when entering the kernel '''
            self.kernel = False
            ''' what to do when address found and not doing taint (or end of taint) '''
            self.callback = None
            ''' list of addresses whose values contribute to a register value'''
            self.buf_addrs = []
            ''' registers that contribute to a register value of type RegisterToTrack '''
            self.reg_queue = []

    def getStartCycles(self):
        return self.start_cycles

    def resetStartCycles(self):
        self.start_cycles = self.cpu.cycles

    def noWatchSysenter(self):
        if self.sysenter_hap is not None:
            self.lgr.debug('noWatchSystenter, remove sysenter breaks and hap handle %d' % self.sysenter_hap)
            self.context_manager.genDeleteHap(self.sysenter_hap, immediate=True)
            self.sysenter_hap = None
        else:
           self.lgr.debug('noWatchSysenter, NO ENTER BREAK')

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
        if self.cpu is None:
            return
        cell = self.top.getCell()
        if self.sysenter_hap is None:
            if self.cpu.architecture == 'arm':
                self.lgr.debug('watchSysenter set linear break at 0x%x' % (self.param.arm_entry))
                enter_break1 = self.context_manager.genBreakpoint(None, Sim_Break_Linear, Sim_Access_Execute, self.param.arm_entry, 1, 0)
                self.sysenter_hap = self.context_manager.genHapIndex("Core_Breakpoint_Memop", self.sysenterHap, None, enter_break1, 'reverseToCall sysenter')
            else:
                if self.param.sysenter is not None and self.param.sys_entry is not None:
                    self.lgr.debug('watchSysenter set linear breaks at 0x%x and 0x%x' % (self.param.sysenter, self.param.sys_entry))
                    enter_break1 = self.context_manager.genBreakpoint(None, Sim_Break_Linear, Sim_Access_Execute, self.param.sysenter, 1, 0)
                    enter_break2 = self.context_manager.genBreakpoint(None, Sim_Break_Linear, Sim_Access_Execute, self.param.sys_entry, 1, 0)
                    self.sysenter_hap = self.context_manager.genHapRange("Core_Breakpoint_Memop", self.sysenterHap, None, enter_break1, enter_break2, 'reverseToCall sysenter')
                elif self.param.sysenter is not None:
                    self.lgr.debug('watchSysenter sysenter set linear breaks at 0x%x ' % (self.param.sysenter))
                    enter_break1 = self.context_manager.genBreakpoint(None, Sim_Break_Linear, Sim_Access_Execute, self.param.sysenter, 1, 0)
                    self.sysenter_hap = self.context_manager.genHapIndex("Core_Breakpoint_Memop", self.sysenterHap, None, enter_break1, 'reverseToCall sysenter')
                elif self.param.sys_entry is not None:
                    self.lgr.debug('watchSysenter sys_entry set linear breaks at 0x%x ' % (self.param.sys_entry))
                    enter_break1 = self.context_manager.genBreakpoint(None, Sim_Break_Linear, Sim_Access_Execute, self.param.sys_entry, 1, 0)
                    self.sysenter_hap = self.context_manager.genHapIndex("Core_Breakpoint_Memop", self.sysenterHap, None, enter_break1, 'reverseToCall sys_entry')

    def setup(self, cpu, x_pages, bookmarks=None, page_faults = None):
        if self.cpu is None:
            self.cpu = cpu
            self.start_cycles = self.cpu.cycles & 0xFFFFFFFFFFFFFFFF
            self.x_pages = x_pages
            self.page_faults = page_faults
            if self.run_from_snap is not None:
                self.loadPickle(self.run_from_snap)
            if bookmarks is not None: 
                self.bookmarks = bookmarks
            if (hasattr(self.param, 'sysenter') and self.param.sysenter is not None) or \
               (hasattr(self.param, 'sys_entry') and self.param.sys_entry is not None) or \
               (hasattr(self.param, 'arm_entry') and self.param.arm_entry is not None):
                '''  Track sysenter to support reverse over those.  TBD currently only works with genMonitor'''
                SIM_run_alone(self.watchSysenter, None)

            dum_cpu, cur_addr, comm, pid = self.task_utils.currentProcessInfo(self.cpu)
            self.context_manager.changeDebugPid(pid) 
            self.lgr.debug('reverseToCall setup')
            if cpu.architecture == 'arm':
                self.decode = decodeArm
                self.lgr.debug('setup using arm decoder')
            else:
                self.decode = decode
        else:
            self.lgr.debug('setup already called')


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
            if self.cpu.architecture == 'arm':
                command = 'set-prefix %d "bl"' % call_break_num
            else:
                command = 'set-prefix %d "call"' % call_break_num
            SIM_run_alone(SIM_run_command, command)
            if self.cpu.architecture == 'arm':
                ret_break_num = SIM_breakpoint(pcell, Sim_Break_Physical, 
                   Sim_Access_Execute, range_start, size, 0)
                self.the_breaks.append(ret_break_num)
                command = 'set-substr %d "PC"' % ret_break_num
                SIM_run_alone(SIM_run_command, command)
                ret_break_num = SIM_breakpoint(pcell, Sim_Break_Physical, 
                   Sim_Access_Execute, range_start, size, 0)
                self.the_breaks.append(ret_break_num)
                command = 'set-substr %d "LR"' % ret_break_num
                SIM_run_alone(SIM_run_command, command)
            else:
                ret_break_num = SIM_breakpoint(cell, Sim_Break_Physical, 
                   Sim_Access_Execute, range_start, size, 0)
                self.the_breaks.append(ret_break_num)
                command = 'set-prefix %d "ret"' % ret_break_num
                SIM_run_alone(SIM_run_command, command)
            self.lgr.debug('done setting breakpoints for call and ret addr: 0x%x len: 0x%x' % (range_start, size))
        else:
            break_num = self.context_manager.genBreakpoint(pcell, Sim_Break_Physical, Sim_Access_Execute, 
                range_start, size, 0)
            self.the_breaks.append(break_num)

    def thinkExecuted(self, page_info):
        if self.cpu.architecture == 'arm':
            nx = memUtils.testBit(page_info.entry, 0)
            accessed = memUtils.testBit(page_info.entry, 4)
            if nx or not accessed: 
                #self.lgr.debug('thinkExecuted will skip 0x%x nx %r accessed %r' % (page_info.logical, nx, accessed)) 
                return False
        else:
            writable = memUtils.testBit(page_info.entry, 1)
            accessed = memUtils.testBit(page_info.entry, 5)
            if writable or not accessed:
                #self.lgr.debug('thinkExecuted will skip %r %r' % (writable, accessed)) 
                return False
        return True

    def pageTableBreaks(self, call_ret):
        ''' set call/ret breaks on all pages that appear executable '''
        pages = pageUtils.getPageBases(self.cpu, self.lgr, self.param.kernel_base)
        range_start = None
        prev_physical = None
        pcell = self.cpu.physical_memory
        page_count = 1
        for page_info in pages:
            if not self.thinkExecuted(page_info):
                continue
            #self.lgr.debug('phys: 0x%x  logical: 0x%x' % (page_info.physical, page_info.logical))
            if range_start is None:
                range_start = page_info.physical
                prev_physical = page_info.physical
            else:
                if page_info.physical == prev_physical + pageUtils.PAGE_SIZE:
                    prev_physical = page_info.physical
                    page_count = page_count + 1
                else:
                    #self.lgr.debug('Page not contiguous: 0x%x  range_start: 0x%x  prev_physical: 0x%x' % (page_info.physical, range_start, prev_physical))
                    self.doBreaks(pcell, range_start, page_count, call_ret) 
                    page_count = 1
                    range_start = page_info.physical
                    prev_physical = page_info.physical
        self.doBreaks(pcell, range_start, page_count, call_ret) 
        self.lgr.debug('set %d breaks', len(self.the_breaks)) 

    def doUncall(self, frame_ips=[]):
        ''' set breaks on calls and returns and reverse to find call into current function'''
        self.frame_ips = frame_ips
        self.need_calls = 0
        self.got_calls = 0
        self.is_monitor_running.setRunning(True)
        self.first_back = True
        dum_cpu, cur_addr, comm, pid = self.task_utils.currentProcessInfo(self.cpu)
        self.pid = pid
        self.lgr.debug('reservseToCall, back from call get procInfo %s' % comm)
        my_args = procInfo.procInfo(comm, self.cpu, pid)
        self.stop_hap = RES_hap_add_callback("Core_Simulation_Stopped", 
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

    def tryBackOne(self, my_args):
        
        self.stop_hap = RES_hap_add_callback("Core_Simulation_Stopped", 
	        self.tryOneStopped, my_args)
        self.lgr.debug('tryBackOne from cycle 0x%x' % my_args.cpu.cycles)
        SIM_run_command('rev 1')

    def jumpStopped(self, my_args, one, exception, error_string):
        eip = self.top.getEIP(self.cpu)
        self.lgr.debug('jumpStopped at 0x%x' % eip)
        RES_hap_delete_callback_id("Core_Simulation_Stopped", self.jump_stop_hap)
        self.top.skipAndMail()

    def jumpCycle(self, cycle):
        self.lgr.debug('would jump to 0x%x' % cycle)
        #self.jump_stop_hap = RES_hap_add_callback("Core_Simulation_Stopped", 
	#        self.jumpStopped, None)
        cmd = 'skip-to cycle = %d ' % cycle
        SIM_run_command(cmd)
        self.top.skipAndMail()

    def skipToTest(self, cycle):
        while SIM_simics_is_running():
            self.lgr.error('skipToTest but simics running')
            time.sleep(1)
        retval = True
        SIM_run_command('pselect %s' % self.cpu.name)
        cmd = 'skip-to cycle = %d ' % cycle
        SIM_run_command(cmd)
        now = self.cpu.cycles
        if now != cycle:
            self.lgr.error('skipToTest failed wanted 0x%x got 0x%x' % (cycle, now))
            time.sleep(1)
            SIM_run_command(cmd)
            now = self.cpu.cycles
            if now != cycle:
                self.lgr.error('skipToTest failed again wanted 0x%x got 0x%x' % (cycle, now))
                retval = False
        return retval
    
    def isExit(self, instruct, eip):
        if self.cpu.architecture == 'arm':
            lr = self.top.getReg('lr', self.cpu)
            #if eip == self.param.arm_ret or (instruct.startswith('mov') and instruct.endswith('lr') and lr < self.param.kernel_base):
            if eip == self.param.arm_ret:
                return True
            else:
                self.lgr.debug('isExit, NOT.  eip 0x%x arm_ret 0x%x' % (eip, self.param.arm_ret))
        else: 
            if instruct == 'sysexit' or instruct == 'iretd' or instruct.startswith('sysret'):
                return True
        return False

    def isRet(self, instruct, eip):
        if self.cpu.architecture == 'arm':
            parts = instruct.split()
            if parts[0].strip().startswith('ld') and parts[1].startswith('pc'):
                op2, op1 = self.decode.getOperands(instruct)
                #if '[' in op2 and 'pc' in op2:
                if op2 == 'lr':
                    return True
                return False
            if parts[0].strip().startswith('ldm') and 'pc' in instruct:
                return True

            if parts[0].strip().startswith('bxcc'):
                #return not armCond.cSet(self.cpu)
                # TBD fix this ?
                return False
            if parts[0].strip().startswith('bxeq'):
                return armCond.zSet(self.cpu)
            if parts[0].strip().startswith('bxne'):
                return not armCond.zSet(self.cpu)
            elif parts[0].strip().startswith('bx') and parts[1] == 'lr':
                return True

            if parts[0] == 'pop' and 'pc' in instruct:
                return True
        else:
            if instruct.startswith('ret'):
                return True
        return False

    def tooFarBack(self):
        cycles = self.cpu.cycles & 0xFFFFFFFFFFFFFFFF
        self.lgr.debug('tooFarBack cycles: 0x%x  started at 0x%x' % (cycles, self.start_cycles))
        if cycles-1 <= self.start_cycles:
            return True
        else:
            return False

    def tryOneStopped(self, my_args, one, exception, error_string):
        '''
        Invoked when the simulation stops after trying to go back one
        '''
        if self.stop_hap is None:
            self.lgr.error('stoppedReverseToCall invoked though hap is none')
            return
        self.lgr.debug('tryoneStopped delete stop hap')
        RES_hap_delete_callback_id("Core_Simulation_Stopped", self.stop_hap)
        self.stop_hap = None
        #cmd = 'reverse-step-instruction'
        if self.tooFarBack():
            self.lgr.debug('At start of recording, cycle: 0x%x' % self.cpu.cycles)
            print('At start of recording, cycle: 0x%x' % self.cpu.cycles)
            self.cleanup(None)
            self.top.skipAndMail() 
            return
        cur_cpu, comm, pid  = self.task_utils.curProc()
        self.lgr.debug('tryOneStopped, pid:%d entered at cycle 0x%x' % (pid, self.cpu.cycles))
        eip = self.top.getEIP(self.cpu)
        instruct = SIM_disassemble_address(self.cpu, eip, 1, 0)
        self.lgr.debug('tryOneStopped reversed 1, eip: %x  %s' % (eip, instruct[1]))
        cpl = memUtils.getCPL(self.cpu)
        done = False
        if cpl > 0 or self.kernel:
            self.lgr.debug('tryBackOne user space')
            if self.step_into or not self.isRet(instruct[1], eip):
                self.lgr.debug('tryBackOne worked ok')
                done = True
                self.cleanup(None)
                self.top.skipAndMail()
                self.context_manager.setExitBreaks()
            elif self.isRet(instruct[1], eip):
                ''' First step back from a reverse step over got a ret.  Assume previous instruction is a call '''
                cell = self.top.getCell()
                self.uncall_break = SIM_breakpoint(cell, Sim_Break_Linear, Sim_Access_Execute, my_args.eip-1, 1, 0)
                self.uncall_hap = RES_hap_add_callback("Core_Simulation_Stopped", self.uncallHapSimple, None)
                self.lgr.debug('tryBackOne found ret, try runnning backwards to previous eip-1.  break %d set at 0x%x now do rev' % (self.uncall_break, my_args.eip-1))
                #self.top.removeDebugBreaks()
                self.lgr.debug('now rev')
                SIM_run_alone(SIM_run_command, 'rev')
                self.lgr.debug('did rev')
                done = True

        elif pid in self.sysenter_cycles and len(self.sysenter_cycles[pid]) > 0:
            cur_cycles = self.cpu.cycles
            self.lgr.debug('tryOneStopped kernel space pid %d expected %d' % (pid, my_args.pid))
            is_exit = self.isExit(instruct[1], eip)
            if pid in self.sysenter_cycles and is_exit:
                self.lgr.debug('tryOneStopped is sysexit, cur_cycles is 0x%x' % cur_cycles)
                prev_cycles = None
                got_it = None
                page_cycles = self.sysenter_cycles[pid]
                if self.page_faults is not None:
                    pass
                    #self.lgr.debug('tryBackOne NOT !!!! adding %d page faults to cycles' % (len(self.page_faults.getFaultingCycles())))
                    #page_cycles = page_cycles + self.page_faults.getFaultingCycles()
                for cycles in sorted(page_cycles):
                    if cycles > cur_cycles:
                        self.lgr.debug('tryOneStopped found cycle between 0x%x and 0x%x' % (prev_cycles, cycles))
                        got_it = prev_cycles - 1
                        break
                    else:
                        #self.lgr.debug('tryOneStopped is not cycle 0x%x' % (cycles))
                        prev_cycles = cycles

                if not got_it:
                    self.lgr.debug('tryOneStopped nothing between, assume last cycle of 0x%x' % prev_cycles)
                    got_it = prev_cycles - 1
                SIM_run_alone(self.jumpCycle, got_it)
                done = True
            elif pid in self.sysenter_cycles and not is_exit:
                self.lgr.debug('tryOneStopped in kernel but not exit? 0x%x  %s' % (eip, instruct[1]))
        

        if not done:
            self.lgr.debug('tryOneStopped, back one did not work, starting at %x' % eip)
            self.stop_hap = RES_hap_add_callback("Core_Simulation_Stopped", 
    	        self.stoppedReverseToCall, my_args)
            self.lgr.debug('tryOneStopped, added stop hap')
            if self.previous_eip is not None and eip != self.previous_eip and cpl > 0:
                self.lgr.debug('tryOneStopped, prev %x not equal eip %x, assume syscall, set break on prev and rev' % (self.previous_eip, eip))
                self.setOneBreak(self.previous_eip, self.cpu)
            else: 
                self.uncall = False
                #for item in self.x_pages:
                #    self.setBreakRange(self.cell_name, my_args.pid, item.address, item.length, self.cpu, my_args.comm, False)
                self.pageTableBreaks(False)
                self.lgr.debug('tryOneStopped, set break range')
            SIM_run_alone(SIM_run_command, 'reverse')
            #self.lgr.debug('reverseToCall, did reverse-step-instruction')
            self.lgr.debug('tryOneStopped, did reverse')

        
    def doRevToCall(self, step_into, prev=None):
        self.noWatchSysenter()
        '''
        Run backwards.  
        If step_into is true, and the previous instruction is a return,
        enter the function at its return.
        '''

        dum_cpu, cur_addr, comm, pid = self.task_utils.currentProcessInfo(self.cpu)
        self.pid = pid
        self.is_monitor_running.setRunning(True)
        self.step_into = step_into
        self.first_back = True
        self.lgr.debug('reservseToCall, call get procInfo')
        self.lgr.debug('reservseToCall, back from call get procInfo %s' % comm)
        eip = self.top.getEIP(self.cpu)
        my_args = procInfo.procInfo(comm, self.cpu, self.pid, eip=eip)
        self.lgr.debug('reservseToCall, got my_args ')
        self.previous_eip = prev
        self.tryBackOne(my_args)

    def jumpOverKernel(self, pid):
        ''' Jump backwards over the kernel.  Returns True if skip works and reg unchanged, False if changed or None if left in kernel'''
        ''' We were stepping backwards and entered the kernel.  '''
        self.pid = pid
        retval = False
        if self.cpu is None:
            self.lgr.debug('reverseToCall cannot jump, cpu not yet defined.')
            return
        cur_cycles = self.cpu.cycles
        eip = self.top.getEIP(self.cpu)
        instruct = SIM_disassemble_address(self.cpu, eip, 1, 0)
        self.lgr.debug('jumpOverKernel kernel space pid %d eip:0x%x %s cycle: 0x%x' % (pid, eip, instruct[1], self.cpu.cycles))
        is_exit = self.isExit(instruct[1], eip)
        if pid in self.sysenter_cycles and is_exit:
            self.lgr.debug('jumpOverKernel is sysexit, cur_cycles is 0x%x' % cur_cycles)

            prev_cycles = None
            got_it = None
            page_cycles = self.sysenter_cycles[pid]
            if self.page_faults is not None:
                #self.lgr.debug('jumpOverKernel adding %d page faults to cycles' % (len(self.page_faults.getFaultingCycles())))
                #page_cycles = page_cycles + self.page_faults.getFaultingCycles()
                pass
            for cycles in sorted(page_cycles):
                if cycles > cur_cycles:
                    self.lgr.debug('jumpOverKernel found cycle between 0x%x and 0x%x' % (prev_cycles, cycles))
                    got_it = prev_cycles - 1
                    break
                else:
                    #self.lgr.debug('tryOneStopped is not cycle 0x%x' % (cycles))
                    prev_cycles = cycles

            if not got_it:
                self.lgr.debug('jumpOverKernel nothing between, assume last cycle of 0x%x' % prev_cycles)
                got_it = prev_cycles - 1

            status = SIM_simics_is_running()
            if status:
                self.lgr.error('jumpOverKernel found simics running prior to skip to')
                return None
            skip_ok = self.skipToTest(got_it)
            if not skip_ok:
                self.lgr.error('jumpOverKernel skip-to failed')
                return None
            if self.reg is not None:
                dum_cpu, cur_addr, comm, pid = self.task_utils.currentProcessInfo(self.cpu)
                rval = self.top.getReg(self.reg, self.cpu) 
                self.lgr.debug('jumpOverKernel pid:%d did skip to 0x%x landed at 0x%x rval 0x%x' % (pid, got_it, self.cpu.cycles, rval))
                if rval == self.reg_val:
                    retval = True
                else:
                    retval = False
                    self.lgr.debug('jumpOverKernel register changed -- assume kernel did it, return to user space')
                    user_cycles = cur_cycles+1
                    skip_ok = self.skipToTest(user_cycles)
                    if not skip_ok:
                        return None
        else:
            ''' assume entered kernel due to interrupt? '''
            ''' cheesy.. go back to user space and then previous instruction? '''
            rev_to = None
            if self.cpu.architecture == 'arm' and (instruct[1].startswith('bx lr') or (instruct[1].startswith('mov') and instruct[1].endswith('lr'))): 
                rev_to = self.top.getReg('lr', self.cpu)
                self.lgr.debug('jumpOverKernel ARM got lr value 0x%x' % rev_to)
         
            else:
                forward = self.cpu.cycles+1
                skip_ok = self.skipToTest(forward)
                if not skip_ok:
                    return None
                eip = self.top.getEIP(self.cpu)
                dum_cpu, cur_addr, comm, pid = self.task_utils.currentProcessInfo(self.cpu)
                self.lgr.debug('skipped to 0x%x got 0x%x eip 0x%x pid is %d' % (forward, self.cpu.cycles, eip, pid))
                rev_to = eip
            self.lgr.debug('jumpOverKernel in kernel, but not exit %s run back to 0x%x' % (instruct[1], rev_to))
            page_faults = self.page_faults.getFaultingCycles(pid)
            if rev_to in page_faults:
                skip_to = self.getClosestFault(page_faults[rev_to])
                if skip_to is None:
                    self.lgr.debug('jumpOverKernel did not find page fault prior to current cycle')
                    return None
                #skip_to = page_faults[rev_to] - 1
                skip_ok = self.skipToTest(skip_to)
                self.lgr.debug('jumpOverKernel found page fault for 0x%x, skipped back to 0x%x' % (rev_to, skip_to))
                if not skip_ok:
                    return None
                rval = self.top.getReg(self.reg, self.cpu) 
                if rval == self.reg_val:
                    retval = True
                else:
                    retval = False
                    self.lgr.debug('jumpOverKernel pagefault register changed value was 0x%x, but now 0x%x -- assume kernel did it, return to user space' % (self.reg_val,
                       rval))
            elif self.cpu.architecture == 'arm' and self.tryShortCall():
                retval = True
            elif self.tryRecentCycle(page_faults, pid):
                self.lgr.debug('jumpOverKernel simply returned to previous know user space.')
            else:
                cell = self.top.getCell()
                self.uncall_break = SIM_breakpoint(cell, Sim_Break_Linear, Sim_Access_Execute, rev_to-4, 1, 0)
                self.uncall_hap = RES_hap_add_callback("Core_Simulation_Stopped", self.kernInterruptHap, None)
                self.lgr.debug('jumpOverKernel, NOT syscall or page fault, try runnning backwards to eip-4, ug.  break %d set at 0x%x now do rev' % (self.uncall_break, rev_to-4))
                self.top.removeDebugBreaks()
                self.context_manager.showHaps()
                SIM_run_alone(SIM_run_command, 'rev')
                retval = None
        return retval

    def tryShortCall(self):
        ''' Arm libc will call the kernel for memory barriers?  iae, the kernel does not execute a lot of instructions '''
        retval = False
        initial = self.cpu.cycles 
        for i in range(20):
            skip_to = self.cpu.cycles - 1
            skip_ok = self.skipToTest(skip_to)
            if not skip_ok:
                self.lgr.error('reverseToCall tryShortCall skip to failed')
                break
            cpl = memUtils.getCPL(self.cpu)
            if cpl > 0:
                retval = True
                break
        if not retval:
            skip_ok = self.skipToTest(initial)
        return retval

    def tryRecentCycle(self, page_faults, pid):
        retval = False
        all_faults = self.expandFaultList(page_faults)
        closest_fault = self.getClosestFault(all_faults)
        frame, closest_call = self.getPreviousCycleFrame(pid)
        if closest_fault is None or closest_call > closest_fault:
            if closest_call is not None:
                self.lgr.debug('tryRecentCycle skipping to recent call')
                self.skipToTest(closest_call-1)
                retval = True
            else:
                self.lgr.debug('tryRecentCycle got None looking for previous cycle')
        elif closet_fault is not None: 
            self.lgr.debug('tryRecentCycle skipping to recent fault')
            self.skipToTest(closest_fault-1)
            retval = True
        return retval
        

    def expandFaultList(self, page_faults):
        retval = []
        for eip in page_faults:
            for cycle in page_faults[eip]:
                retval.append(cycle) 
        return retval

    def getClosestFault(self, fault_list):
        best = None
        now = self.cpu.cycles
        for cycle in fault_list:
            if cycle < now:
                if best is None:
                    best = cycle 
                else:
                    if (now-cycle) < (now-best):
                        best = cycle
        return best
        
    def kernInterruptHap(self, my_args, one, exception, error_string):
        if self.uncall_break is None:
            return
        eip = self.top.getEIP(self.cpu)
        dum_cpu, cur_addr, comm, pid = self.task_utils.currentProcessInfo(self.cpu)
        if self.pid is None:
            self.lgr.error('kernInterrupt self.pid is None')
            return
        if self.uncall_break is None:
            self.lgr.error('kernInterrupt uncall break turned to  None')
            return
        if pid is not None:
            self.lgr.debug('kernInterruptHap ip: 0x%x uncall_break %d pid: %d expected %d reg:%s self.reg_val 0x%s cycle: 0x%x' % (eip, self.uncall_break, 
                  pid, self.pid, self.reg, str(self.reg_val), self.cpu.cycles))
        else:
            self.lgr.error('kernInterruptHap pid is None')    
            return
        if pid == self.pid:
            RES_delete_breakpoint(self.uncall_break)
            RES_hap_delete_callback_id("Core_Simulation_Stopped", self.uncall_hap)
            self.uncall_break = None
            if self.reg_val is not None:
                val = self.top.getReg(self.reg, self.cpu) 
                if val == self.reg_val:
                    self.lgr.debug('kernInterruptHap reg %s still 0x%x, now cycle back through instructions, but run alone' % (self.reg, val))
                    SIM_run_alone(self.cycleAlone, pid)
                else: 
                    self.lgr.error('kernInterruptHap got val 0x%x, does not match 0x%x return to previous cycle?' % (val, self.reg_val))
                
        else:
            self.lgr.debug('kernInterruptHap, wrong pid, rev')
            SIM_run_alone(SIM_run_command, 'rev')

    '''
    BEWARE syntax errors are not seen.  TBD make unit test
    '''
    def doRevToModReg(self, reg, taint=False, offset=0, value=None, num_bytes=None, kernel=False):
        '''
        Run backwards until a write to the given register
        '''
        self.offset =  offset 
        self.taint = taint
        self.value = value
        self.num_bytes = num_bytes
        self.kernel = kernel
        eip = self.top.getEIP(self.cpu)
        self.lgr.debug('\ndoRevToModReg eip: 0x%x cycle 0x%x for register %s offset is %d taint: %r' % (eip, self.cpu.cycles, reg, offset, taint))
        self.reg = reg
        dum_cpu, cur_addr, comm, pid = self.task_utils.currentProcessInfo(self.cpu)
        self.pid = pid
        self.reg_num = self.cpu.iface.int_register.get_number(reg.upper())
        try:
            self.reg_val = self.cpu.iface.int_register.read(self.reg_num)
        except:
            self.lgr.error('doRevToModReg got bad regnum %d for reg <%s>' % (self.reg_num, reg))
            return
        self.prev_reg_val = self.reg_val
        self.lgr.debug('doRevToModReg starting at PC %x, looking for %s change from 0x%x' % (eip, reg, self.reg_val))
        done = False
        self.save_reg_mod = RegisterModType(reg, RegisterModType.REG)
        rval = None
        while not done:
            reg_mod_type = self.cycleRegisterMod()
            if reg_mod_type is None:
                ''' stepped back into kernel.  set hap and reverse '''
                self.lgr.debug('doRevToModReg entered kernel')
                if not self.tooFarBack():
    
                    #if pid in self.sysenter_cycles and len(self.sysenter_cycles[pid]) > 0:
                    if True:
                        kjump = self.jumpOverKernel(pid)
                        if kjump is None:
                            self.lgr.debug('doRevModReg must be reversing to point kernel entry via asynch interrupt')
                            done = True
                        elif not kjump:
                            eip = self.top.getEIP(self.cpu)
                            self.lgr.debug('doRevModReg kernel changed register? eip now 0x%x' % eip)
                            rval = self.top.getReg(self.reg, self.cpu) 
                            ida_message = 'Kernel modified register %s to 0x%x' % (self.reg, rval)
                            bm = "eip:0x%x follows kernel modification of reg:%s to 0x%x" % (eip, self.reg, rval)
                            self.bookmarks.setBacktrackBookmark(bm)
                            self.context_manager.setIdaMessage(ida_message)
                            self.cleanup(None)
                            self.top.skipAndMail()
                            done = True
                    else:
                        ''' TBD use cheesy jumpOverKernel instead ?? '''
                        my_args = procInfo.procInfo(comm, self.cpu, self.pid)
                        self.stop_hap = RES_hap_add_callback("Core_Simulation_Stopped", 
                    	     self.stoppedReverseModReg, my_args)
                        dum_cpu, cur_addr, ncomm, npid = self.task_utils.currentProcessInfo(self.cpu)
                        self.lgr.debug('doRevToModReg, added stop hap pid %d' % npid)
                        self.cell_name = self.top.getTopComponentName(self.cpu)
                        self.pageTableBreaks(False)
                        #for item in self.x_pages:
                        #    self.setBreakRange(self.cell_name, pid, item.address, item.length, self.cpu, comm, False, reg)
                        self.lgr.debug('doRevToModReg, set break range')
                        #SIM_run_alone(SIM_run_command, 'reverse-step-instruction')
                        SIM_run_alone(SIM_run_command, 'reverse')
                        #self.lgr.debug('reverseToCall, did reverse-step-instruction')
                        self.lgr.debug('reverseToModReg, did reverse')
                        done=True
                else:
                    ida_message = 'doRevModReg must have backed to 0x%x, first cycle was 0x%x' % (self.cpu.cycles, self.start_cycles)
                    self.lgr.debug(ida_message)
                    self.context_manager.setIdaMessage(ida_message)
                    self.cleanup(None)
                    self.top.skipAndMail()
                    done=True
            elif reg_mod_type.mod_type == RegisterModType.FUN_VAL:
                eip = self.top.getEIP(self.cpu)
                self.bookmarks.setBacktrackBookmark('eip:0x%x function return set to 0' % eip)
                ida_message = 'Function returned zero at 0x%x' % eip
                done=True
                self.cleanup(None)

            elif reg_mod_type.mod_type != RegisterModType.BAIL:
                done=True
                ''' current eip modifies self.reg, done, or continue taint '''
                self.lgr.debug('reverseToModReg got mod reg right off self.taint is %r reg_mod: %s' % (self.taint, reg_mod_type.toString()))
                if not self.taint:
                    addr = None
                    if reg_mod_type.mod_type == RegisterModType.ADDR:
                        self.lgr.debug('reverseToModReg type ADDR record and check queue for more')
                        addr = reg_mod_type.value + self.offset
                        ''' record the address and check the register queue for other registers to backtrace'''
                        self.checkRegQueue(addr)
                        self.lgr.debug('reverseToModReg back from checkRegQueue')
                    elif reg_mod_type.mod_type == RegisterModType.REG and self.callback is not None:
                        ''' Assume looking for address containing data in the reg '''
                        self.lgr.debug('reverseToModReg type REG assume looking for source of reg, use follow taint')
                        self.followTaint(reg_mod_type)
                else:
                    if not self.tooFarBack():
                        self.followTaint(reg_mod_type)
                    else:
                        self.lgr.debug('doRevModReg must have backed to first cycle 0x%x' % self.start_cycles)
            else:
                self.lgr.debug('doRevModReg bailed, maybe trying uncall')
                done=True

    def rmBreaks(self):
        self.lgr.debug('rmBreaks')
        for breakpt in self.the_breaks:
            RES_delete_breakpoint(breakpt)
        self.the_breaks = []

    def conditionalMet(self, mn):
        if self.cpu.architecture == 'arm':
            return armCond.condMet(self.cpu, mn)
        else:
            if mn.startswith('cmov'):
                eflags = self.top.getReg('eflags', self.cpu)
                if mn == 'cmovne' and not memUtils.testBit(eflags, 6):
                    return True
                elif mn == 'cmove' and memUtils.testBit(eflags, 6):
                    return True
                else:
                    return False
            else: 
                return True
    
    def cycleRegisterMod(self):
        '''
        Step backwards one cycle at a time looking for the register being modified.
        If kernel entered before the register is found, return False.
        TBD: ARM write-back operations
        '''
        retval = None
        done = False
        cur_val = self.cpu.iface.int_register.read(self.reg_num)
        eip = self.top.getEIP(self.cpu)
        self.lgr.debug('cycleRegisterMod start eip: 0x%x for %s value 0x%x cur_val 0x%x' % (eip, self.reg, self.reg_val, cur_val))
        while not done:
            #current = SIM_cycle_count(self.cpu)
            current = self.cpu.cycles
            previous = current - 1
            skip_ok = self.skipToTest(previous)
            self.lgr.debug('cycleRegisterMod skipped to 0x%x  cycle is 0x%x' % (previous, self.cpu.cycles))
            if not skip_ok:
                self.lgr.error('cycleRegisterMod, skipped to wrong cycle')
                return None
            if self.tooFarBack():
                self.lgr.debug('cycleRegisterMod prev cycle 0x%x prior to first 0x%x, stop here' %(previous, self.start_cycles))
                break
            cpl = memUtils.getCPL(self.cpu)
            if cpl == 0 and not self.kernel:
                self.lgr.debug('cycleRegisterMod entered kernel')
                done = True
            else:
                cur_val = self.cpu.iface.int_register.read(self.reg_num)
                eip = self.top.getEIP(self.cpu)
                self.lgr.debug('crm compare %x to %x eip: %x' % (cur_val, self.reg_val, eip))
                '''
                if cur_val != self.reg_val: 
                    eip = self.top.getEIP(self.cpu)
                    self.lgr.debug('cycleRegisterMod at %x, we are done' % eip)
                    done = True
                    retval = True
                    self.is_monitor_running.setRunning(False)
                '''
                eip = self.top.getEIP(self.cpu)
                #self.lgr.debug('cycleRegisterMod do disassemble for eip 0x%x' % eip)
                instruct = SIM_disassemble_address(self.cpu, eip, 1, 0)
                self.lgr.debug('cycleRegisterMod disassemble for eip 0x%x is %s  curval: 0x%x' % (eip, str(instruct), cur_val))
                mn = self.decode.getMn(instruct[1])
                self.lgr.debug('cycleRegisterMod decode is %s' % mn)
                if self.conditionalMet(mn):
                    ''' TBD generalize '''
                    if (self.reg == 'r0' or self.reg == 'eax') and self.reg_val == 0 and self.isRet(instruct[1], eip):
                        done = True 
                        retval = RegisterModType(None, RegisterModType.FUN_VAL)
                    elif self.decode.modifiesOp0(mn):
                        self.lgr.debug('get operands from %s' % instruct[1])
                        op1, op0 = self.decode.getOperands(instruct[1])
                        self.lgr.debug('cycleRegisterMod mn: %s op0: %s  op1: %s' % (mn, op0, op1))
                        #self.lgr.debug('cycleRegisterMod compare <%s> to <%s>' % (op0.lower(), self.reg.lower()))
                        if self.decode.isReg(op0) and self.decode.regIsPart(op0, self.reg) or (mn.startswith('xchg') and self.decode.regIsPart(op1, self.reg)):
                            self.lgr.debug('cycleRegisterMod at %x, we be may done, type is unknown' % eip)
                            done = True
                            retval = RegisterModType(None, RegisterModType.UNKNOWN)
                            #if mn.startswith('ldr') and op1.startswith('[') and op1.endswith(']'):
                            if mn.startswith('ldr') and op1.startswith('['):
                                self.lgr.debug('is ldr op1 is %s' % op1)
                                addr = decodeArm.getAddressFromOperand(self.cpu, op1, self.lgr)
                                addr = addr & self.task_utils.getMemUtils().SIZE_MASK
                                if addr is not None:
                                    self.lgr.debug('cycleRegisterMod, set as addr type for 0x%x' % addr)
                                    retval = RegisterModType(addr, RegisterModType.ADDR)
                            elif mn.startswith('mov') and '[' in op1:
                                self.lgr.debug('is mov op1 is %s' % op1)
                                addr = decode.getAddressFromOperand(self.cpu, op1, self.lgr)
                                addr = addr & self.task_utils.getMemUtils().SIZE_MASK
                                if addr is not None:
                                    self.lgr.debug('cycleRegisterMod, x86 set as addr type for 0x%x' % addr)
                                    retval = RegisterModType(addr, RegisterModType.ADDR)
                            elif mn.startswith('xchg'):
                                if self.decode.regIsPart(op1, self.reg):
                                    retval = RegisterModType(op0, RegisterModType.REG)
                                else:
                                    retval = RegisterModType(op1, RegisterModType.REG)

                            elif mn.startswith('mov') and self.decode.isReg(op1):
                                self.lgr.debug('cycleRegisterMod type is reg')
                                retval = RegisterModType(op1, RegisterModType.REG)
                            elif mn.startswith('add') or mn.startswith('sub') or mn.startswith('rsb'):
                                parts = op1.split(',') 
                                if len(parts) == 2:
                                   rn = parts[0].strip()
                                   if self.decode.isReg(rn):
                                       op2 = parts[1].strip()
                                       if not self.decode.isReg(op2):
                                           rn_val = self.top.getReg(rn, self.cpu) 
                                           self.lgr.debug('cycleRegisterMod type of rn is reg op2 not reg, val of rn 0x%x' % rn_val)
                                           retval = RegisterModType(rn, RegisterModType.REG)
                                       else: 
                                           op2_val = self.top.getReg(op2, self.cpu) 
                                           self.lgr.debug('cycleRegisterMod op2 (%s) is reg, value 0x%x reg_val 0x%x' % (op2, op2_val, self.reg_val))
                                           if op2_val == self.reg_val:
                                               retval = RegisterModType(op2, RegisterModType.REG)
                                               self.lgr.debug('cycleRegisterMod type is reg')
                                           else:
                                               rn_val = self.top.getReg(rn, self.cpu) 
                                               if rn_val == self.reg_val:
                                                   retval = RegisterModType(rn, RegisterModType.REG)
                                                   self.lgr.debug('cycleRegisterMod type is reg')
                                               elif self.callback is not None:
                                                   self.lgr.debug('cycleRegisterMod, handle each register')
                                                   self.handleRegisters(rn, rn_val, op2, op2_val)
                                               else:
                                                   self.lgr.debug('cycleRegisterMod, out of ideas, bail')
                                                   self.context_manager.setIdaMessage('As far as we can go back.  TBD look for user input on add or sub.')
                                                   self.top.skipAndMail()
                                
                    elif self.cpu.architecture == 'arm': 
                        if ']!' in instruct[1]:
                            ''' Look for write-back register mod '''
                            ''' for now just look for [myreg, xxx]! '''
                            if self.decode.armWriteBack(instruct[1], self.reg):
                                done = True
                                self.lgr.debug('cycleRegisterMod armWriteBack, set type to unknown')
                                retval = RegisterModType(None, RegisterModType.UNKNOWN)
                        elif mn.startswith('ldm') and self.reg in instruct[1] and '{' in instruct[1]:
                            addr = self.decode.armLDM(self.cpu, instruct[1], self.reg, self.lgr)
                            rval = self.task_utils.getMemUtils().readPtr(self.cpu, addr)
                            if addr is None or rval is None:
                                self.lgr.debug('cycleRegisterMod eip 0x%x cannot get register value from %s' % (eip, instruct[1]))
                                continue
                            self.lgr.debug('cycleRegisterMod at eip 0x%x, is ldm instruction addr 0x%x reg val 0x%x wanting 0x%x prev 0x%x' % (eip, addr, 
                                    rval, self.reg_val, self.prev_reg_val))
                            if addr is not None and self.reg == 'pc':
                                self.lgr.debug('cycleRegisterMod, modification of PC register, set as addr type for 0x%x' % addr)
                                retval = RegisterModType(addr, RegisterModType.ADDR)
                                done=True
                            elif abs(rval - self.prev_reg_val) > 64:
                                self.lgr.error('cycleRegisterMod wrong value (diff > 64)')
                                done = True
                                retval = RegisterModType(None, RegisterModType.BAIL)
                            elif addr is not None:
                                self.prev_reg_val = rval
                                done = True
                                pc_addr = self.decode.armLDM(self.cpu, instruct[1], 'pc', self.lgr)
                                if pc_addr is not None:
                                    pc = self.task_utils.getMemUtils().readPtr(self.cpu, pc_addr)
                                    self.lgr.debug('cycleRegisterMod try uncalling pc_addr 0x%x  pc 0x%x' % (pc_addr, pc))
                                    cell = self.top.getCell()
                                    pre_call = pc - 4
                                    self.uncall_break = SIM_breakpoint(cell, Sim_Break_Linear, Sim_Access_Execute, pre_call, 1, 0)
                                    self.uncall_hap = RES_hap_add_callback("Core_Simulation_Stopped", self.uncallHap, None)
                                    retval = RegisterModType(None, RegisterModType.BAIL)
                                    self.lgr.debug('cycleRegisterMod set break number %d stop hap, now rev to 0x%x' % (self.uncall_break, pre_call))
                                    self.save_cycle = self.cpu.cycles
                                    self.save_reg_mod = RegisterModType(addr, RegisterModType.ADDR)
                                    SIM_run_alone(SIM_run_command,'rev')
                                else:
                                    self.lgr.debug('cycleRegisterMod at %x, armLDM got None for addr, do for that addr 0x%x' % (eip, addr))
                                    retval = RegisterModType(addr, RegisterModType.ADDR)
                            else:
                                self.lgr.debug('cycleRegisterMod at %x, ldm instruction got None for addr' % eip)
                    
        if retval is not None and (retval.mod_type == RegisterModType.REG or retval.mod_type == RegisterModType.ADDR):
            self.lgr.debug('cycleRegisterMod set save_reg_mod to %s' % str(retval.mod_type))
            self.save_reg_mod = retval
        self.lgr.debug('cycleRegisterMod return') 
        return retval

    def resumeAlone(self, dumb):
                skip_ok = self.skipToTest(self.save_cycle)
                if not skip_ok:
                    return
                eip = self.top.getEIP(self.cpu)
                self.lgr.debug('resumeAlone skipped back to saved cycle 0x%x.  PC now 0x%x' % (self.save_cycle, eip))
                
                if not self.taint:
                    self.lgr.debug('resumeAlone call cleanup')
                    self.cleanup(None)
                else:
                    self.lgr.debug('resumeAlone follow taint')
                    self.followTaint(self.save_reg_mod)

    def uncallHapSimple(self, my_args, one, exception, error_string):
        ''' Hit when an initial rev 1 from a reverse step over leads to a ret '''
        if self.uncall_break is None:
            return
        eip = self.top.getEIP(self.cpu)
        dum_cpu, cur_addr, comm, pid = self.task_utils.currentProcessInfo(self.cpu)
        self.lgr.debug('uncallHapSimple ip: 0x%x uncall_break %d pid: %d expected %d ' % (eip, self.uncall_break, 
              pid, self.pid))
        if pid == self.pid:
            RES_delete_breakpoint(self.uncall_break)
            RES_hap_delete_callback_id("Core_Simulation_Stopped", self.uncall_hap)
            self.uncall_break = None
            self.cleanup(None)
            self.top.skipAndMail()
            self.context_manager.setExitBreaks()

    def uncallHap(self, my_args, one, exception, error_string):
        ''' used in back-tracing registers '''
        if self.uncall_break is None:
            return
        eip = self.top.getEIP(self.cpu)
        dum_cpu, cur_addr, comm, pid = self.task_utils.currentProcessInfo(self.cpu)
        self.lgr.debug('uncallHap ip: 0x%x uncall_break %d pid: %d expected %d reg:%s self.reg_val 0x%x' % (eip, self.uncall_break, 
              pid, self.pid, self.reg, self.reg_val))
        if pid == self.pid:
            RES_delete_breakpoint(self.uncall_break)
            RES_hap_delete_callback_id("Core_Simulation_Stopped", self.uncall_hap)
            self.uncall_break = None
            val = self.top.getReg(self.reg, self.cpu) 
            if val == self.reg_val:
                self.lgr.debug('uncallHap reg %s still 0x%x, now cycle back through instructions, but run alone' % (self.reg, val))
                SIM_run_alone(self.cycleAlone, pid)
            else: 
                self.lgr.debug('uncallHap got val 0x%x, does not match 0x%x return to previous cycle 0x%x' % (val, self.reg_val, self.save_cycle))
                SIM_run_alone(self.resumeAlone, None)
                
        else:
            self.lgr.debug('uncallHap, wrong pid, rev')
            SIM_run_alone(SIM_run_command, 'rev')
                       

    def multOne(self, op0, mn):
        self.lgr.debug('multOne %s %s' % (op0, mn))
        if mn == 'imul':
            self.lgr.debug('multOne is imul')
            if self.decode.isReg(op0):
                mul = self.decode.getValue(op0, self.cpu, self.lgr)
                self.lgr.debug('multOne val of %s is 0x%x' % (op0, mul))
                if mul == 1:
                    return True
        return False

    def orValue(self, op1, mn):
        if self.value is not None and mn == 'or':
            if self.num_bytes == 1:
                address = self.decode.getAddressFromOperand(self.cpu, op1, self.lgr)
                if address is not None:
                    value = self.task_utils.getMemUtils().readWord32(self.cpu, address)
                    self.lgr.debug('orValue, address is 0x%x value 0x%x' % (address, value))
                    if value == self.value:
                        return True
        return False
            
    def followTaintArm(self, reg_mod_type):
        eip = self.top.getEIP(self.cpu)
        instruct = SIM_disassemble_address(self.cpu, eip, 1, 0)
        self.lgr.debug('followTaintArm %s' % instruct[1])
        self.lgr.debug('followTaintArm reg_mod_type: %s' % reg_mod_type.toString())
        if reg_mod_type is not None:
            if reg_mod_type.mod_type == RegisterModType.ADDR:
                address = reg_mod_type.value + self.offset
                value = self.task_utils.getMemUtils().readWord32(self.cpu, address)
                if value is None:
                    self.lgr.debug('followTaintArm value None read from 0x%x' % address)
                    self.cleanup(None)
                    return
                 
                self.lgr.debug('followTaintArm address 0x%x value 0x%x' % (address, value))
                self.bookmarks.setBacktrackBookmark('eip:0x%x inst:"%s"' % (eip, instruct[1]))
                #self.cleanup(None)
                self.top.stopAtKernelWrite(address, self, satisfy_value = self.satisfy_value, kernel=self.kernel)
            elif reg_mod_type.mod_type == RegisterModType.REG:
                self.lgr.debug('followTaintArm reg %s' % reg_mod_type.value)
                self.bookmarks.setBacktrackBookmark('eip:0x%x inst:"%s"' % (eip, instruct[1]))
                self.doRevToModReg(reg_mod_type.value, taint=self.taint, kernel=self.kernel)
            else:
                self.lgr.debug('folowTrainArm, no plan, bailing')
                self.cleanup(None)
                 
    def followTaint(self, reg_mod_type):
        if self.cpu.architecture == 'arm':
            self.followTaintArm(reg_mod_type)
        else:
            self.followTaintX86(reg_mod_type)

    def followTaintX86(self, reg_mod_type):
        ''' we believe the instruction at the current ip modifies self.reg 
            Where does its value come from? '''
        eip = self.top.getEIP(self.cpu)
        instruct = SIM_disassemble_address(self.cpu, eip, 1, 0)
        self.lgr.debug('followTaint instruct at 0x%x is %s' % (eip, str(instruct)))
        op1, op0 = self.decode.getOperands(instruct[1])
        mn = self.decode.getMn(instruct[1])
        if not self.multOne(op0, mn) and not mn.startswith('mov') and not mn == 'pop' and not mn.startswith('cmov') \
                                     and not self.orValue(op1, mn) and not mn == 'add':
            ''' NOTE: treating "or" and "add" and imult of one as a "mov" '''
            if mn == 'add':
               offset = None
               #offset = int(op1, 16)
               if '[' in op1:
                   address = self.decode.getAddressFromOperand(self.cpu, op1, self.lgr)
                   offset = self.task_utils.getMemUtils().readWord32(self.cpu, address)
                   self.lgr.debug('followTaint, add check of %s, address 0x%x offset is 0x%x' % (op1, address, offset))
               else:
                   offset = self.decode.getValue(op1, self.cpu, self.lgr)
                   self.lgr.debug('followTaint, add check offset of %s is 0x%x' % (op1, offset))
               if offset is not None and offset <= 8:
                   ''' wth, just an address adjustment? '''
                   self.lgr.debug('followTaint, add of %x, assume address adjust, e.g., heap struct' % offset)
                   self.bookmarks.setBacktrackBookmark('eip:0x%x inst:"%s"' % (eip, instruct[1]))
                   self.doRevToModReg(op0, taint=self.taint, kernel=self.kernel)
                   return 
            elif mn == 'xchg':
                self.lgr.debug('followTaint, is xchg, track %s' % reg_mod_type.value)
                self.doRevToModReg(reg_mod_type.value, taint=self.taint, kernel=self.kernel)
                return
             
            self.lgr.debug('followTaint, not a move, we are stumped')
            self.bookmarks.setBacktrackBookmark('eip:0x%x inst:"%s" stumped' % (eip, instruct[1]))
            self.top.skipAndMail()

        elif mn == 'pop':
            esp = self.top.getReg('esp', self.cpu) 
            self.bookmarks.setBacktrackBookmark('eip:0x%x inst:"%s"' % (eip, instruct[1]))
            self.cleanup(None)
            self.top.stopAtKernelWrite(esp, self, satisfy_value = self.satisfy_value, kernel=self.kernel)

        elif self.decode.isReg(op1) and (mn == 'mov' or not self.decode.isIndirect(op1)):
            self.lgr.debug('followTaint, is reg, track %s' % op1)
            self.doRevToModReg(op1, taint=self.taint, kernel=self.kernel)
        elif self.decode.isReg(op1) and self.decode.isIndirect(op1):
            self.lgr.debug('followTaint, is indrect reg, track %s' % op1)
            address = self.decode.getAddressFromOperand(self.cpu, op1, self.lgr)
            self.bookmarks.setBacktrackBookmark('switch to indirect value:0x%x eip:0x%x inst:"%s"' % (self.value, eip, instruct[1]))
            self.doRevToModReg(op1, taint=self.taint, kernel=self.kernel)

        #elif mn == 'lea':
        #    address = decode.getAddressFromOperand(self.cpu, op1, self.lgr)

        else:
            self.lgr.debug('followTaint, see if %s is an address' % op1)
            address = self.decode.getAddressFromOperand(self.cpu, op1, self.lgr)
            if address is not None:
                self.lgr.debug('followTaint, yes, address is 0x%x' % address)
                if self.decode.isByteReg(op0):
                    value = self.task_utils.getMemUtils().readByte(self.cpu, address)
                else:
                    value = self.task_utils.getMemUtils().readWord32(self.cpu, address)
                newvalue = self.task_utils.getMemUtils().getUnsigned(address+self.offset)
                if newvalue is not None and value is not None: 
                    self.lgr.debug('followTaint BACKTRACK eip: 0x%x value 0x%x at address of 0x%x wrote to register %s call stopAtKernelWrite for 0x%x' % (eip, value, address, op0, newvalue))
                if not mn.startswith('mov'):
                    self.bookmarks.setBacktrackBookmark('taint branch eip:0x%x inst:%s' % (eip, instruct[1]))
                    self.lgr.debug('BT bookmark: taint branch eip:0x%x inst %s' % (eip, instruct[1]))
                else:
                    self.bookmarks.setBacktrackBookmark('eip:0x%x inst:"%s"' % (eip, instruct[1]))
                    self.lgr.debug('BT bookmark: backtrack eip:0x%x inst:"%s"' % (eip, instruct[1]))
                #self.cleanup(None)
                self.top.stopAtKernelWrite(newvalue, self, satisfy_value=self.satisfy_value, kernel=self.kernel)
            else:
                self.lgr.debug('followTaint, BACKTRACK op1 %s not an address or register, stopping traceback' % op1)
                self.bookmarks.setBacktrackBookmark('eip:0x%x inst:"%s" stumped' % (eip, instruct[1]))
                self.top.skipAndMail()
       
    def cycleAlone(self, pid): 
        self.lgr.debug('cycleAlone, pid %d entered looking for %s' % (pid, self.reg))
        cmd = 'reverse'
        reg_mod_type = self.cycleRegisterMod()
        if reg_mod_type is None:
            if not self.tooFarBack():
                ''' stepped back into kernel, rev '''
                self.lgr.debug('cycleAlone must have entered kernel, continue to previous place where this process ran')
                #SIM_run_alone(SIM_run_command, cmd)
                reg_ok = self.jumpOverKernel(pid)
                if reg_ok: 
                    SIM_run_alone(self.cycleAlone, pid)
                else:
                    self.lgr.debug('cycleAlone, assume jumpOverKernel took over the search')
            else:
                self.lgr.debug('cycleAlone must have backed to first cycle 0x%x' % self.start_cycles)
        elif reg_mod_type.mod_type != RegisterModType.BAIL:
            ''' current eip modifies self.reg, done, or continue taint '''
            self.lgr.debug('cycleAlone, not bail mod type %s' % reg_mod_type.mod_type)
            if not self.taint:
                self.lgr.debug('cycleAlone not taint, cleanup')
                self.cleanup(None)
            else:
                if not self.tooFarBack():
                    self.lgr.debug('cycleAlone, not too far back, follow taint?')
                    self.followTaint(reg_mod_type)
                else:
                    self.lgr.debug('cycleAlone must backed to first cycle 0x%x' % self.start_cycles)
 
    def stoppedReverseModReg(self, my_args, one, exception, error_string):
        '''
        Invoked when the simulation stops while looking for a modified register
        '''
        dum_cpu, cur_addr, comm, pid = self.task_utils.currentProcessInfo(self.cpu)
        self.lgr.debug('stoppedReverseModReg, entered looking for %s cur pid:%d' % (self.reg, pid))
        cpl = memUtils.getCPL(self.cpu)
        if pid == self.pid and (cpl != 0 or self.kernel):
            self.cycleAlone(pid)
        else:
            self.lgr.error('stoppedReverseModReg wrong process or in kernel pid %d expected %d' % (pid, self.pid))
            #SIM_run_alone(SIM_run_command, cmd)
           
 
    def cleanup(self, addr_list):
        self.lgr.debug('reverseToCall cleanup')
        self.context_manager.setExitBreaks()
        if self.stop_hap is not None:
            RES_hap_delete_callback_id("Core_Simulation_Stopped", self.stop_hap)
            self.stop_hap = None
        self.rmBreaks()
        self.is_monitor_running.setRunning(False)
        if not self.taint:
            if self.callback is None:
                self.top.skipAndMail()
            else:
                if addr_list is not None:
                    self.lgr.debug('reverseToCall cleanup len of addr_list: %d' % len(addr_list))
                    tmp_buf_addrs = list(addr_list)
                else:
                    tmp_buf_addrs = list(self.buf_addrs)
                tmp_callback = self.callback
                self.callback = None
                self.buf_addrs = []
                tmp_callback(tmp_buf_addrs)
        elif self.callback is not None:
            tmp_callback = self.callback
            self.callback = None
            self.buf_addrs = []
            tmp_buf_addrs = list(self.buf_addrs)
            tmp_callback(tmp_buf_addrs)
        else:
            self.context_manager.setIdaMessage('As far as we can go back.')
            self.top.skipAndMail()
        self.lgr.debug('cleanup complete')

    def isSyscall(self, instruct):
        if self.cpu.architecture == 'arm':
            if instruct.startswith('svc 0'):
                return True
        else:
            if instruct.startswith('int 128') or instruct.startswith('sysenter'):
                return True
        return False

    def stoppedReverseToCall(self, my_args, one, exception, error_string):
        '''
        Invoked when the simulation stops while looking for a previous call
        '''
        if self.stop_hap is None:
            self.lgr.error('stoppedReverseToCall invoked though hap is none')
            return
        #cmd = 'reverse-step-instruction'
        cmd = 'reverse'
        cpu, cur_addr, comm, pid = self.task_utils.currentProcessInfo(self.cpu)
        current = SIM_cycle_count(cpu)
        self.lgr.debug('stoppedReverseToCall, entered %d (%s) cycle: 0x%x' % (pid, comm, current))
        #if current < self.top.getFirstCycle():
        if current <= self.start_cycles:
            self.lgr.debug('stoppedReverseToCall found cycle 0x%x prior to first, stop here' %(current))
            self.cleanup(None)
        #elif pid == my_args.pid and SIM_processor_privilege_level(cpu) != 0:
        elif pid == self.pid and (memUtils.getCPL(cpu) != 0 or self.kernel):
            eip = self.top.getEIP(cpu)
            instruct = SIM_disassemble_address(cpu, eip, 1, 0)
            if self.first_back and self.isSyscall(instruct[1]):
                self.lgr.debug('stoppedReverseToCall first back is syscall at %x, we are done' % eip)
                self.cleanup(None)
            elif (self.first_back and not self.uncall) and (not self.isRet(instruct[1], eip) or self.step_into):
                self.lgr.debug('stoppedReverseToCall first back not a ret or step_into at %x, we are done' % eip)
                self.cleanup(None)
            elif self.decode.isCall(self.cpu, instruct[1]):
                self.got_calls += 1
                if self.got_calls == self.need_calls:
                    self.lgr.debug('stoppedReverseToCall %s at %x we must be done' % (instruct[1], eip))
                    self.cleanup(None)
                elif eip in self.frame_ips:
                    self.lgr.debug('stoppedReverseToCall %s at %x found stack frame entry, declare we are done' % (instruct[1], eip))
                    self.cleanup(None)
                else:
                   self.lgr.debug('stoppedReverseToCall 0x%x got call %s   got_calls %d, need %d' % (eip, instruct[1], self.got_calls, self.need_calls))
                   SIM_run_alone(SIM_run_command, cmd)
            elif self.isRet(instruct[1], eip):
                self.need_calls += 1
                self.lgr.debug('stoppedReverseToCall 0x%x got ret %s  need: %d' % (eip, instruct[1], self.need_calls))
                if self.first_back and not self.uncall:
                    self.rmBreaks()
                    ''' TBD fix this? '''
                    for item in self.x_pages:
                        self.setBreakRange(self.cell_name, pid, item.address, item.length, cpu, comm, True)
                SIM_run_alone(SIM_run_command, cmd)
            else:
                self.lgr.debug('stoppedReverseToCall Not call or ret at %x, is %s' % (eip, instruct[1]))
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
        self.pid = pid
      
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
                    if cpu.architecture == 'arm':
                        command = 'set-prefix %d "bl"' % call_break_num
                    else:
                        command = 'set-prefix %d "call"' % call_break_num
                    SIM_run_alone(SIM_run_command, command)
                 
                    if cpu.architecture == 'arm':
                        ''' TBD much too ugly'''
                        ret_break_num = SIM_breakpoint(cell, Sim_Break_Physical, 
                           Sim_Access_Execute, phys_block.address, self.page_size, 0)
                        self.the_breaks.append(ret_break_num)
                        command = 'set-substr %d "PC"' % ret_break_num
                        SIM_run_alone(SIM_run_command, command)
                        ret_break_num = SIM_breakpoint(cell, Sim_Break_Physical, 
                           Sim_Access_Execute, phys_block.address, self.page_size, 0)
                        self.the_breaks.append(ret_break_num)
                        command = 'set-substr %d "LR"' % ret_break_num
                        SIM_run_alone(SIM_run_command, command)
                    else:
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
        #self.lgr.debug('sysenterHap')
        cur_cpu, comm, pid  = self.task_utils.curProc()
        if pid is not None:
            if True:
                cycles = self.cpu.cycles
                if pid not in self.sysenter_cycles:
                    self.sysenter_cycles[pid] = {}
                if cycles not in self.sysenter_cycles[pid]:
                    #self.lgr.debug('third: %s  forth: %s' % (str(third), str(forth)))
                    frame = self.task_utils.frameFromRegs(compat32=self.compat32)
                    call_num = self.mem_utils.getCallNum(self.cpu)
                    frame['syscall_num'] = call_num
                    self.lgr.debug('sysenterHap pid:%d frame pc 0x%x sp 0x%x param3 0x%x cycles: 0x%x' % (pid, frame['pc'], frame['sp'], frame['param3'], self.cpu.cycles))
                    #self.lgr.debug(taskUtils.stringFromFrame(frame))
                    #SIM_break_simulation('debug me')
                    callname = self.task_utils.syscallName(call_num, self.compat32)
                    if callname is None:
                        self.lgr.debug('sysenterHap bad call num %d, ignore' % call_num)
                        return
                    if callname == 'select' or callname == '_newselect':        
                        select_info = syscall.SelectInfo(frame['param1'], frame['param2'], frame['param3'], frame['param4'], frame['param5'], 
                             self.cpu, self.mem_utils, self.lgr)
                        frame['select'] = select_info.getFDList()
                    elif callname == 'socketcall':        
                        ''' must be 32-bit get params from struct '''
                        socket_callnum = frame['param1']
                        socket_callname = net.callname[socket_callnum].lower()
                        self.lgr.debug('sysenterHap socket_callnum is %d name %s' % (socket_callnum, socket_callname))
                        if socket_callname != 'socket' and socket_callname != 'setsockopt':
                            ss = net.SockStruct(self.cpu, frame['param2'], self.mem_utils)
                            frame['ss'] = ss

                    self.sysenter_cycles[pid][cycles] = frame 
                    if pid in self.recent_cycle:
                        recent_cycle, recent_frame = self.recent_cycle[pid]
                        if cycles > recent_cycle:
                            self.recent_cycle[pid] = [cycles, frame]
                            #self.lgr.debug('sysenterHap setting most recent cycle')
                    else:
                        self.recent_cycle[pid] = [cycles, frame]
                        #self.lgr.debug('sysenterHap setting first recent cycle')
                else:
                    self.lgr.debug('sysenterHap, cycles already there for pid %d' % pid) 

    def getEnterCycles(self, pid):
        retval = []
        if pid in self.sysenter_cycles:
            for cycle in sorted(self.sysenter_cycles[pid]):
                retval.append(cycle)
        return retval

    def clearEnterCycles(self):
        self.lgr.debug('clearEnterCycles')
        self.sysenter_cycles.clear()

    def getRecentCycleFrame(self, pid):
        ''' TBD sort out use of this and getPreviousCycleFrame.  Seems latter 
            is better if skipping around.  This just returns the most recent entry,
            whose cycle is not related to the current cycle.
        '''
        ''' NOTE these frames do not reflect socket call decoding '''
        retval = None
        ret_cycles = None
        cur_cycles = self.cpu.cycles
        self.lgr.debug('getRecentCycleFrame pid %d' % pid)
        if pid in self.recent_cycle:
            ret_cycles, retval = self.recent_cycle[pid]
        else:
            self.lgr.debug('getRecentCycleFrame pid %d not there')
        return retval, ret_cycles

    def getPreviousCycleFrame(self, pid):
        ''' NOTE these frames do not reflect socket call decoding '''
        retval = None
        ret_cycles = None
        cur_cycles = self.cpu.cycles
        self.lgr.debug('getPreviousCycleFrame pid %d cur_cycles 0x%x' % (pid, cur_cycles))
        if pid in self.sysenter_cycles:
            got_it = None
            for cycles in sorted(self.sysenter_cycles[pid]):
                if cycles > cur_cycles:
                    self.lgr.debug('getPreviousCycleFrame found cycle between 0x%x and 0x%x' % (prev_cycles, cycles))
                    got_it = prev_cycles
                    break
                else:
                    prev_cycles = cycles

            if got_it is not None:
                retval = self.sysenter_cycles[pid][got_it] 
                ret_cycles = got_it
            else:
                retval = self.sysenter_cycles[pid][cycles] 
                ret_cycles = cycles
        else:
            self.lgr.debug('getPreviousCycleFrame pid not in sysenter_cycles')
        return retval, ret_cycles

    def satisfyCondition(self, pc):
        ''' See the findKernelWrite skipAlone function for memory mod and retrack call '''
        retval = True
        instruct = SIM_disassemble_address(self.cpu, pc, 1, 0)
        mn = self.decode.getMn(instruct[1])
        op1, op0 = self.decode.getOperands(instruct[1])
        val = self.decode.getValue(op1, self.cpu, self.lgr)
        self.lgr.debug('satisfyCondition mn is %s op0: %s op1: %s' % (mn, op0, op1))
        if self.decode.isReg(op0) and mn == 'cmp' and val is not None:
            self.lgr.debug('satisfyCondition, val is 0x%x' % val) 
            self.satisfy_value = val
            self.doRevToModReg(op0, taint=True, kernel=self.kernel)
        else:
            if val is None:
                self.lgr.error('Cannot get val from %s' % op1)
            else:
                self.lgr.error('Cannot yet handle condition %s' % instruct[1])
            retval = False
        return retval 

    def preCallFD(self, fd):
        if self.cpu is None:
            self.lgr.error('preCallFD called before reverseToCall setup')
            return
        read_calls = ['read', 'recv', 'recvfrom', 'recvmsg']
        plist = {}
        pid_list = self.context_manager.getThreadPids()
        tasks = self.task_utils.getTaskStructs()
        plist = {}
        for t in tasks:
            if tasks[t].pid in pid_list:
                plist[tasks[t].pid] = t 
        in_kernel = False
        frame = None
        cycles = None
        for pid in plist:
            t = plist[pid]
            if tasks[t].state > 0:
                frame, cycles = self.getRecentCycleFrame(pid)
                if frame is not None:
                    call = self.task_utils.syscallName(frame['syscall_num'], self.compat32)
                    if call in read_calls and frame['param1'] == fd:
                        print('pid %d in kernel on %s of fd %d' % (pid, call, fd))
                        in_kernel = True
                        break
                    elif call == 'select' or call == '_newselect':
                        select_list = frame['select']
                        self.lgr.debug('DataWatch trackIO check select for %d' % fd)
                        if fd in select_list:
                            print('pid %d in kernel on select including %d' % (pid, fd))
                            in_kernel = True
                            break
                    elif call == 'socketcall' and 'ss' in frame:
                        socket_callnum = frame['param1']
                        socket_callname = net.callname[socket_callnum].lower()
                        ss = frame['ss']
                        if ss.fd == fd:
                            print('pid %d in kernel on %s of fd %d' % (pid, socket_callname, fd)) 
                            in_kernel = True
                            break
       
        if in_kernel:
            self.lgr.debug('DataWatch trackIO in kernel, do skip to cycle 0x%x' % cycles)
            self.top.removeDebugBreaks()
            if not self.skipToTest(cycles-1):
            #cmd = 'skip-to cycle = %d ' % (cycles)
            #SIM_run_command(cmd)
            #print('skipped back to 0x%x' % cycles)
                dum_cpu, cur_addr, comm, pid = self.task_utils.currentProcessInfo(self.cpu)
                eip = self.top.getEIP(self.cpu)
                self.lgr.debug('DataWatch trackIO skip back from kernel failed going to 0x%x, pid:%d eip:0x%x' % (self.cpu.cycles, pid, eip))
                return False

            self.top.restoreDebugBreaks(was_watching=True)
    def loadPickle(self, name):
        self.lgr.debug('reverseToCall load pickle for %s  cell_name %s' % (name, self.cell_name))
        rev_call_file = os.path.join('./', name, self.cell_name, 'revCall.pickle')
        if os.path.isfile(rev_call_file):
            self.lgr.debug('reverseToCall pickle from %s' % rev_call_file)
            #rev_call_pickle = pickle.load( open(rev_call_file, 'rb') ) 
            self.recent_cycle = pickle.load( open(rev_call_file, 'rb') ) 
            for pid in self.recent_cycle:
                self.lgr.debug('loadPickle pid %d frame %s' % (pid, str(self.recent_cycle[pid])))
            #self.recent_cycle = rev_call_pickle['recent_cycle']

    def pickleit(self, name, cell_name):
        rev_call_file = os.path.join('./', name, cell_name, 'revCall.pickle')
        #rev_call_pickle = {}
        #rev_call_pickle['recent_cycle'] = self.recent_cycle
        #pickle.dump( rev_call_pickle, open( rev_call_file, "wb")) 
        self.lgr.debug('reverseToCall pickleit to %s ' % (rev_call_file))
        for pid in self.recent_cycle:
            r, f = self.recent_cycle[pid]
            self.lgr.debug('pickleit pid %d cycle 0x%x f %s' % (pid, r, str(f)))
        try:
            pickle.dump( self.recent_cycle, open( rev_call_file, "wb") ) 
        except TypeError as ex:
            self.lgr.error('trouble dumping pickle of recent_cycle %s' % ex)

    def setCallback(self, callback):
        self.callback = callback

    def handleRegisters(self, reg1, reg1_val, reg2, reg2_val):
        self.lgr.debug('handleRegisters')
        reg_to_track = RegisterToTrack(reg1, reg1_val, self.cpu.cycles)
        self.reg_queue.append(reg_to_track)
        reg_to_track = RegisterToTrack(reg2, reg2_val, self.cpu.cycles)
        self.reg_queue.append(reg_to_track)
        self.checkRegQueue(None)

    def checkRegQueue(self, buf_addr):
        if buf_addr is not None:
            self.buf_addrs.append(buf_addr)
        self.lgr.debug('checkRegQueue')
        if len(self.reg_queue) > 0:
            reg_to_track = self.reg_queue.pop()
            self.skipToTest(reg_to_track.cycle) 
            my_reg_mod_type = RegisterModType(reg_to_track.reg, RegisterModType.REG)
            self.lgr.debug('checkRegQueue, now follow for reg %s' % reg_to_track.reg)
            self.followTaint(my_reg_mod_type)
            self.lgr.debug('checkRegQueue, now back from followTaint for  %s' % reg_to_track.reg)
        else:
            self.cleanup(None)
