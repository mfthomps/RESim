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
import decodePPC32
import memUtils
import pageUtils
import resimUtils
import armCond
import net
import syscall
import resimHaps
import time
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
                 is_monitor_running, bookmarks, logdir, compat32, run_from_snap, record_entry, reverse_mgr):
            #print('call getLogger')
            logname = '%s-%s' % (name, cell_name)
            self.lgr = resimUtils.getLogger(logname, logdir)
            self.context_manager = context_manager 
            self.record_entry = record_entry 
            self.reverse_mgr = reverse_mgr 
            #sys.stderr = open('err.txt', 'w')
            self.top = top 
            self.cpu = None
            self.tid = None
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
            self.reg_val = None
            self.prev_reg_val = None
            self.stop_hap = None
            self.uncall = False
            self.is_monitor_running = is_monitor_running
            self.taint = False
            self.bookmarks = bookmarks
            self.step_into = None
            self.jump_stop_hap = None
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

            self.lgr.debug('__init__ bookmarks is %s' % self.bookmarks)

            self.callmn = None
            # recent process attributes otherwise passed as user value in Haps
            self.recent_proc_info = None

    def noWatchSysenter(self):
        self.record_entry.noWatchSysenter()

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
        self.record_entry.watchSysenter()

    def setup(self, cpu, x_pages, bookmarks=None, page_faults = None):
        if self.cpu is None:
            self.cpu = cpu
            self.x_pages = x_pages
            self.page_faults = page_faults
            if bookmarks is not None: 
                self.bookmarks = bookmarks
                self.lgr.debug('reverseToCall setup bookmarks set to %s' % str(bookmarks))
            if (hasattr(self.param, 'sysenter') and self.param.sysenter is not None) or \
               (hasattr(self.param, 'sys_entry') and self.param.sys_entry is not None) or \
               (hasattr(self.param, 'ppc32_entry') and self.param.ppc32_entry is not None) or \
               (hasattr(self.param, 'arm_entry') and self.param.arm_entry is not None):
                '''  Track sysenter to support reverse over those.  TBD currently only works with genMonitor'''
                #SIM_run_alone(self.watchSysenter, None)
                SIM_run_alone(self.top.recordEntry, None)

            # TBD why do this here? Do where this is called if it needs doing. 
            #dum_cpu, comm, tid = self.task_utils.curThread()
            #self.context_manager.changeDebugTid(tid) 
            self.lgr.debug('reverseToCall setup')
            if cpu.architecture.startswith('arm'):
                self.decode = decodeArm
                self.lgr.debug('setup using arm decoder')
            elif cpu.architecture == 'ppc32':
                self.decode = decodePPC32
                self.lgr.debug('setup using PPC32 decoder')
            else:
                self.decode = decode
            if self.cpu.architecture.startswith('arm'):
                self.callmn = 'bl'
            if self.cpu.architecture == 'ppc32':
                self.callmn = 'bl'
            else:
                self.callmn = 'call'
        else:
            self.lgr.debug('setup already called')


    def doBreaks(self, pcell, range_start, page_count, call_ret):
        size = page_count * pageUtils.PAGE_SIZE
        if call_ret:
            # Set exectution breakpoints for "call" and "ret" instructions
            #call_break_num = self.context_manager.genBreakpoint(pcell, Sim_Break_Physical, 
            #   Sim_Access_Execute, range_start, size, 0)
            self.lgr.debug('reverseToCall doBreaks will do prefix')
            call_break_num = self.reverse_mgr.SIM_breakpoint(pcell, Sim_Break_Physical, 
               Sim_Access_Execute, range_start, size, 0)
            self.the_breaks.append(call_break_num)
            if self.cpu.architecture.startswith('arm'):
                prefix = 'bl' 
            else:
                prefix = 'call' 
            resimSimicsUtils.setBreakpointPrefix(self.top.conf, call_break_num, prefix)
            if self.cpu.architecture.startswith('arm'):
                ret_break_num = self.reverse_mgr.SIM_breakpoint(pcell, Sim_Break_Physical, 
                   Sim_Access_Execute, range_start, size, 0)
                self.the_breaks.append(ret_break_num)
                #command = 'set-substr %d "PC"' % ret_break_num
                #SIM_run_alone(SIM_run_command, command)
                resimSimicsUtils.setBreakpointSubstring(self.top.conf, ret_break_num, 'PC')
                ret_break_num = self.reverse_mgr.SIM_breakpoint(pcell, Sim_Break_Physical, 
                   Sim_Access_Execute, range_start, size, 0)
                self.the_breaks.append(ret_break_num)
                resimSimicsUtils.setBreakpointSubstring(self.top.conf, ret_break_num, 'LR')
                #command = 'set-substr %d "LR"' % ret_break_num
                #SIM_run_alone(SIM_run_command, command)
            else:
                ret_break_num = self.reverse_mgr.SIM_breakpoint(cell, Sim_Break_Physical, 
                   Sim_Access_Execute, range_start, size, 0)
                self.the_breaks.append(ret_break_num)
                resimSimicsUtils.setBreakpointPrefix(self.top.conf, ret_break_num, 'ret')
                #command = 'set-prefix %d "ret"' % ret_break_num
                #SIM_run_alone(SIM_run_command, command)
            self.lgr.debug('done setting breakpoints for call and ret addr: 0x%x len: 0x%x' % (range_start, size))
        else:
            break_num = self.context_manager.genBreakpoint(pcell, Sim_Break_Physical, Sim_Access_Execute, 
                range_start, size, 0)
            self.the_breaks.append(break_num)

    def thinkExecuted(self, page_info):
        if self.cpu.architecture.startswith('arm'):
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
        # TBD does not handle ppc with bl blr confusion
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
        dum_cpu, comm, tid = self.task_utils.curThread()
        self.tid = tid
        self.lgr.debug('reservseToCall, back from call get procInfo %s' % comm)
        self.recent_proc_info = procInfo.procInfo(comm, self.cpu, tid)
        self.lgr.debug('doUncall, added stop hap')
        self.need_calls = 1
        self.uncall = True
        self.pageTableBreaks(True)
        #for item in self.x_pages:
        #    self.setBreakRange(self.cell_name, tid, item.address, item.length, self.cpu, comm, True)
        self.lgr.debug('doUncall, set break range')
        self.stop_hap = 'set' 
        self.reverse_mgr.reverse(callback=self.stoppedReverseToCall)
        #self.lgr.debug('reverseToCall, did reverse-step-instruction')
        self.lgr.debug('doUncall, did reverse')

    def tryBackOne(self, dumb=None):
        '''
        Skip back one cycle.  If at a return, find the call.  If in the kernel, back out of it
        '''
        self.lgr.debug('tryBackOne from cycle 0x%x' % self.recent_proc_info.cpu.cycles)
        self.top.rev1NoMail()
        if self.tooFarBack():
            self.lgr.debug('reverseToCall tryBackOne at start of recording, cycle: 0x%x' % self.cpu.cycles)
            print('At start of recording, cycle: 0x%x' % self.cpu.cycles)
            self.cleanup(None)
            self.top.skipAndMail() 
            return
        cur_cpu, comm, tid  = self.task_utils.curThread()
        self.lgr.debug('tryBackOne, tid:%s entered at cycle 0x%x' % (tid, self.cpu.cycles))
        eip = self.top.getEIP(self.cpu)
        instruct = SIM_disassemble_address(self.cpu, eip, 1, 0)
        self.lgr.debug('tryBackOne reversed 1, eip: %x  %s' % (eip, instruct[1]))
        cpl = memUtils.getCPL(self.cpu)
        done = False
        entry_cycles = self.record_entry.getEnterCycles(tid)
        if cpl > 0 or self.kernel:
            if cpl > 0:
                self.lgr.debug('tryBackOne user space')
            else:
                self.lgr.debug('tryBackOne kernel space')
            if self.step_into or not self.isRet(instruct[1], eip):
                self.lgr.debug('tryBackOne worked ok')
                done = True
                self.cleanup(None)
                self.top.skipAndMail()
                self.context_manager.setExitBreaks()
            elif self.isRet(instruct[1], eip):
                ''' First step back from a reverse step over got a ret.  Assume previous instruction is a call '''
                SIM_run_alone(self.tryBackToCall, None)

                '''
                cell = self.top.getCell()
                self.uncall_break = SIM_breakpoint(cell, Sim_Break_Linear, Sim_Access_Execute, my_args.eip-1, 1, 0)
                self.uncall_hap = self.top.RES_add_stop_callback(self.uncallHapSimple, None)
                self.lgr.debug('tryBackOne found ret, try running backwards to previous eip-1.  break %d set at 0x%x now do rev' % (self.uncall_break, my_args.eip-1))
                #self.top.removeDebugBreaks()
                self.lgr.debug('now rev')
                SIM_run_alone(SIM_run_command, 'rev')
                self.lgr.debug('did rev')
                '''
                done = True

        elif len(entry_cycles) > 0:
            cur_cycles = self.cpu.cycles
            self.lgr.debug('tryBackOne kernel space tid %s expected %s' % (tid, self.recent_proc_info.tid))
            is_exit = self.isExit(instruct[1], eip)
            if is_exit:
                self.lgr.debug('tryBackOne is sysexit, cur_cycles is 0x%x' % cur_cycles)
                prev_cycles = None
                got_it = None
                # TBD why call it page cycles?
                page_cycles = entry_cycles
                if self.page_faults is not None:
                    pass
                    #self.lgr.debug('tryOneStopped NOT !!!! adding %d page faults to cycles' % (len(self.page_faults.getFaultingCycles())))
                    #page_cycles = page_cycles + self.page_faults.getFaultingCycles()
                for cycles in sorted(page_cycles):
                    if cycles > cur_cycles:
                        self.lgr.debug('tryBackOne found cycle between 0x%x and 0x%x' % (prev_cycles, cycles))
                        got_it = prev_cycles - 1
                        break
                    else:
                        #self.lgr.debug('tryOneStopped is not cycle 0x%x' % (cycles))
                        prev_cycles = cycles

                if not got_it:
                    self.lgr.debug('tryBackOne nothing between, assume last cycle of 0x%x' % prev_cycles)
                    got_it = prev_cycles - 1
                SIM_run_alone(self.jumpCycle, got_it)
                done = True
            else:
                self.lgr.debug('tryBackOne in kernel but not exit? 0x%x  %s' % (eip, instruct[1]))
        

        if not done:
            self.lgr.debug('tryBackOne, back one did not work, starting at %x' % eip)
            if self.cpu.architecture == 'ppc32':
                self.lgr.error('reverseToCall tryOneStopped did not work, and is ppc32, bail')
                return
            self.lgr.debug('tryBackOne, added stop hap')
            self.uncall = False
            self.pageTableBreaks(False)
            self.lgr.debug('tryBackOne, set break range')
            SIM_run_alone(self.reverseAlone, stoppedReverseToCall)
            #self.lgr.debug('reverseToCall, did reverse-step-instruction')
            self.lgr.debug('tryBackOne, did reverse')

        #SIM_run_command('rev 1')

    def tryBackToCall(self, dumb):
        # Doing a step-over, we stepped into a ret.
        # self.recent_proc_info.eip is where we came from.  find its previous instruction 
        # mftmft 
        call_addr = self.findCallBehind(self.recent_proc_info.eip)
        if call_addr is not None:
            self.lgr.debug('tryBackToCall got 0x%x from findCallBehind' % call_addr)
            cell = self.top.getCell()
            self.uncall_break = self.reverse_mgr.SIM_breakpoint(cell, Sim_Break_Linear, Sim_Access_Execute, call_addr, 1, 0)
            self.lgr.debug('tryBackToCall from cycle 0x%x' % self.recent_proc_info.cpu.cycles)
            self.stop_hap = 'set'
            self.reverse_mgr.reverse(callback=self.tryBackToCallStopped)
        else:
            self.lgr.error('tryBackToCall failed to find call behind 0x%x' % self.recent_proc_info.eip)

    def tryBackToCallStopped(self, param_from_rev_mgr, one, exception, error_string):
        if self.stop_hap is None and param_from_rev_mgr is None:
            return
        cur_cpu, comm, tid  = self.task_utils.curThread()
        if tid != self.recent_proc_info.tid:
            self.lgr.debug('tryBackToCallStopped tid:%s but expected %s' % (tid, self.recent_proc_info.tid))
            return 
        self.reverse_mgr.SIM_delete_breakpoint(self.uncall_break)
        self.uncall_break = None
        if self.stop_hap is not None:
            self.top.RES_delete_stop_hap_run_alone(None, your_stop=True)
            self.stop_hap = None
        self.lgr.debug('tryBackToCallStopped tid:%s' % tid)
        self.cleanup(None)
        #self.top.restoreDebugBreaks(was_watching=True)
        self.top.skipAndMail()
        self.lgr.debug('tryBackToCallStopped did skipAndMail')
        self.context_manager.setExitBreaks()

    def jumpStopped(self, dumb, one, exception, error_string):
        eip = self.top.getEIP(self.cpu)
        self.lgr.debug('jumpStopped at 0x%x' % eip)
        self.top.RES_delete_stop_hap(self.jump_stop_hap)
        self.top.skipAndMail()

    def jumpCycle(self, cycle):
        self.lgr.debug('would jump to 0x%x' % cycle)
        #self.jump_stop_hap = self.top.RES_add_stop_callback(self.jumpStopped, None)
        self.skipToTest(cycle)
        self.top.skipAndMail()

    def skipToTest(self, cycle):
        retval = True
        if not self.reverse_mgr.nativeReverse():
            self.reverse_mgr.skipToCycle(cycle)
        else:
            count = 0 
            while SIM_simics_is_running():
                self.lgr.error('skipToTest but simics running')
                time.sleep(1)
                if count > 10:
                    self.lgr.error('too much, bail')
                    break 
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
        if self.cpu.architecture.startswith('arm'):
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
        if self.cpu.architecture.startswith('arm'):
            parts = instruct.split()
            if instruct.startswith('ret'):
                return True
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
        elif self.cpu.architecture == 'ppc32':
            if instruct.startswith('blr'):
                return True
        else:
            if instruct.startswith('ret'):
                return True
        return False

    def tooFarBack(self):
        cycles = self.cpu.cycles & 0xFFFFFFFFFFFFFFFF
        start_cycles = self.top.getFirstCycle()
        self.lgr.debug('tooFarBack cycles: 0x%x  started at 0x%x' % (cycles, start_cycles))
        if cycles-1 <= start_cycles:
            return True
        else:
            return False

    def doRevToCall(self, step_into):
        self.noWatchSysenter()
        '''
        Run backwards.  
        If step_into is true, and the previous instruction is a return,
        enter the function at its return.
        '''
        dum_cpu, comm, tid = self.task_utils.curThread()
        self.tid = tid
        self.is_monitor_running.setRunning(True)
        self.step_into = step_into
        self.first_back = True
        self.lgr.debug('reservseToCall, call get procInfo')
        eip = self.top.getEIP(self.cpu)
        self.recent_proc_info = procInfo.procInfo(comm, self.cpu, self.tid, eip=eip)
        self.lgr.debug('reverseToCall doRevtoCall, got my_args ')
        self.tryBackOne()
        self.lgr.debug('reservseToCall, back from tryBackOne')

    def jumpOverKernel(self, tid):
        ''' Jump backwards over the kernel.  Returns True if skip works and reg unchanged, False if changed or None if left in kernel'''
        ''' We were stepping backwards and entered the kernel.  '''
        self.tid = tid
        retval = False
        if self.cpu is None:
            self.lgr.debug('reverseToCall cannot jump, cpu not yet defined.')
            return
        cur_cycles = self.cpu.cycles
        eip = self.top.getEIP(self.cpu)
        instruct = SIM_disassemble_address(self.cpu, eip, 1, 0)
        self.lgr.debug('jumpOverKernel kernel space tid %s eip:0x%x %s cycle: 0x%x' % (tid, eip, instruct[1], self.cpu.cycles))
        is_exit = self.isExit(instruct[1], eip)
        entry_cycles = self.record_entry.getEnterCycles(tid)
        if len(entry_cycles)>0 and is_exit:
            self.lgr.debug('jumpOverKernel is sysexit, cur_cycles is 0x%x' % cur_cycles)

            prev_cycles = None
            got_it = None
            page_cycles = entry_cycles
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
                dum_cpu, comm, tid = self.task_utils.curThread()
                rval = self.top.getReg(self.reg, self.cpu) 
                self.lgr.debug('jumpOverKernel tid:%s did skip to 0x%x landed at 0x%x rval 0x%x' % (tid, got_it, self.cpu.cycles, rval))
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
            if self.cpu.architecture.startswith('arm') and (instruct[1].startswith('bx lr') or (instruct[1].startswith('mov') and instruct[1].endswith('lr'))): 
                rev_to = self.top.getReg('lr', self.cpu)
                self.lgr.debug('jumpOverKernel ARM got lr value 0x%x' % rev_to)
         
            else:
                forward = self.cpu.cycles+1
                skip_ok = self.skipToTest(forward)
                if not skip_ok:
                    return None
                eip = self.top.getEIP(self.cpu)
                dum_cpu, comm, tid = self.task_utils.curThread()
                self.lgr.debug('skipped to 0x%x got 0x%x eip 0x%x tid is %s' % (forward, self.cpu.cycles, eip, tid))
                rev_to = eip
            page_faults = self.page_faults.getFaultingCycles(tid)
            self.lgr.debug('jumpOverKernel in kernel, but not exit %s len of page_faults is %d. Trying to run back to 0x%x' % (instruct[1], len(page_faults), rev_to))
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
            elif self.cpu.architecture.startswith('arm') and self.tryShortCall():
                retval = True
            elif self.tryRecentCycle(page_faults, tid):
                self.lgr.debug('jumpOverKernel simply returned to previous know user space.')
            else:
                cell = self.top.getCell()
                self.uncall_break = self.reverse_mgr.SIM_breakpoint(cell, Sim_Break_Linear, Sim_Access_Execute, rev_to-4, 1, 0)
                self.lgr.debug('jumpOverKernel, NOT syscall or page fault, try runnning backwards to eip-4, ug.  break %d set at 0x%x now do rev' % (self.uncall_break, rev_to-4))
                self.top.removeDebugBreaks()
                self.context_manager.showHaps()
                self.uncall_hap = self.reverse_mgr.reverse(callback=self.kernInterruptHap)
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

    def tryRecentCycle(self, page_faults, tid):
        retval = False
        all_faults = self.expandFaultList(page_faults)
        closest_fault = self.getClosestFault(all_faults)
        frame, closest_call = self.record_entry.getPreviousCycleFrame(tid)
        if closest_fault is None or closest_call > closest_fault:
            if closest_call is not None:
                self.lgr.debug('tryRecentCycle skipping to recent call')
                self.skipToTest(closest_call-1)
                retval = True
            else:
                self.lgr.debug('tryRecentCycle got None looking for previous cycle')
        elif closest_fault is not None: 
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
        
    def kernInterruptHap(self, dumb, one, exception, error_string):
        if self.uncall_break is None:
            return
        eip = self.top.getEIP(self.cpu)
        dum_cpu, comm, tid = self.task_utils.curThread()
        if self.tid is None:
            self.lgr.error('kernInterrupt self.tid is None')
            return
        if self.uncall_break is None:
            self.lgr.error('kernInterrupt uncall break turned to  None')
            return
        if tid is not None:
            self.lgr.debug('kernInterruptHap ip: 0x%x uncall_break %d tid: %s expected %s reg:%s self.reg_val 0x%s cycle: 0x%x' % (eip, self.uncall_break, 
                  tid, self.tid, self.reg, str(self.reg_val), self.cpu.cycles))
        else:
            self.lgr.error('kernInterruptHap tid is None')    
            return
        if tid == self.tid:
            RES_delete_breakpoint(self.uncall_break)
            self.top.RES_delete_stop_hap(self.uncall_hap)
            self.uncall_break = None
            if self.reg_val is not None:
                val = self.top.getReg(self.reg, self.cpu) 
                if val == self.reg_val:
                    self.lgr.debug('kernInterruptHap reg %s still 0x%x, now cycle back through instructions, but run alone' % (self.reg, val))
                    SIM_run_alone(self.cycleAlone, tid)
                else: 
                    self.lgr.error('kernInterruptHap got val 0x%x, does not match 0x%x return to previous cycle?' % (val, self.reg_val))
                
        else:
            self.lgr.debug('kernInterruptHap, wrong tid, rev')
            SIM_run_alone(SIM_run_command, 'rev')

    '''
    BEWARE syntax errors are not seen.  TBD make unit test
    '''
    def doRevToModReg(self, reg, taint=False, offset=0, value=None, num_bytes=None, kernel=False, no_increments=False):
        '''
        Run backwards until a write to the given register
        '''
        self.offset =  offset 
        self.taint = taint
        self.value = value
        self.num_bytes = num_bytes
        self.kernel = kernel
        eip = self.top.getEIP(self.cpu)
        self.lgr.debug('\ndoRevToModReg eip: 0x%x cycle 0x%x for register %s offset is %d num_bytes %s taint: %r kernel: %r' % (eip, self.cpu.cycles, reg, offset, num_bytes, taint, kernel))
        self.reg = reg
        dum_cpu, comm, tid = self.task_utils.curThread()
        self.tid = tid
        self.reg_val = self.mem_utils.getRegValue(self.cpu, reg)
        if self.reg_val is None:
            self.lgr.error('doRevToModReg failed to get value for reg %s' % reg)
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
    
                    if True:
                        kjump = self.jumpOverKernel(tid)
                        if kjump is None:
                            self.lgr.debug('doRevToModReg must be reversing to point kernel entry via asynch interrupt')
                            done = True
                        elif not kjump:
                            eip = self.top.getEIP(self.cpu)
                            self.lgr.debug('doRevToModReg kernel changed register? eip now 0x%x' % eip)
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
                        self.recent_proc_info = procInfo.procInfo(comm, self.cpu, self.tid)
                        dum_cpu, comm, tid = self.task_utils.curThread()
                        self.lgr.debug('doRevToModReg, added stop hap tid %s' % ntid)
                        self.cell_name = self.top.getTopComponentName(self.cpu)
                        self.pageTableBreaks(False)
                        #for item in self.x_pages:
                        #    self.setBreakRange(self.cell_name, tid, item.address, item.length, self.cpu, comm, False, reg)
                        self.lgr.debug('doRevToModReg, set break range')
                        SIM_run_alone(self.reverseAlone, self.stoppedReverseModReg)
                        #self.lgr.debug('reverseToCall, did reverse-step-instruction')
                        self.lgr.debug('reverseToModReg, did reverse')
                        done=True
                else:
                    ida_message = 'doRevToModReg must have backed to 0x%x, first cycle was 0x%x' % (self.cpu.cycles, self.top.getFirstCycle())
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
                self.lgr.debug('reverseToModReg got mod reg right off self.taint is %r reg_mod: %s no_increments %r' % (self.taint, reg_mod_type.toString(), no_increments))
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
                        if no_increments:
                            eip = self.top.getEIP(self.cpu)
                            instruct = SIM_disassemble_address(self.cpu, eip, 1, 0)
                            if instruct[1].startswith('add'):
                                self.lgr.debug('reverseToModReg, %s is an add, but asked for no increments, done' % instruct[1])
                                bm = "eip:0x%x %s" % (eip, instruct[1])
                                self.bookmarks.setBacktrackBookmark(bm)
                                done = True
                                self.cleanup(None)
                            else:
                                self.lgr.debug('doToRevModReg no increments, not add call follow taint')
                                self.followTaint(reg_mod_type)
                        else:
                            self.lgr.debug('doToRevModReg NOT no increments, call follow taint')
                            self.followTaint(reg_mod_type)
                            
                    else:
                        self.lgr.debug('doToRevModReg must have backed to first cycle 0x%x' % self.top.getFirstCycle())
            else:
                self.lgr.debug('doRevToModReg bailed, maybe trying uncall')
                done=True

    def revAlone(self, callback):
        self.stop_hap = 'set'
        self.reverse_mgr.reverse(callback=callback)

    def rmBreaks(self):
        self.lgr.debug('rmBreaks')
        for breakpt in self.the_breaks:
            self.reverse_mgr.SIM_delete_breakpoint(breakpt)
        self.the_breaks = []

    def conditionalMet(self, mn):
        if self.cpu.architecture.startswith('arm'):
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
        cur_val = self.mem_utils.getRegValue(self.cpu, self.reg)
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
                print('Reversed to original cycle')
                self.lgr.debug('cycleRegisterMod prev cycle 0x%x prior to first 0x%x, stop here' %(previous, self.top.getFirstCycle()))
                break
            cpl = memUtils.getCPL(self.cpu)
            if cpl == 0 and not self.kernel:
                self.lgr.debug('cycleRegisterMod entered kernel')
                done = True
            else:
                cur_val = self.mem_utils.getRegValue(self.cpu, self.reg)
                eip = self.top.getEIP(self.cpu)
                self.lgr.debug('crm compare %x (value of self.reg) to %x (self.reg_val) eip: %x' % (cur_val, self.reg_val, eip))
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
                        self.lgr.debug('cycleRegisterMod compare <%s> to <%s>' % (op0.lower(), self.reg.lower()))
                        if self.decode.isReg(op0) and self.decode.regIsPart(op0, self.reg, lgr=self.lgr) or (mn.startswith('xchg') and self.decode.regIsPart(op1, self.reg)):
                            self.lgr.debug('cycleRegisterMod at eip %x, we may be done, type is unknown' % eip)
                            done = True
                            retval = RegisterModType(None, RegisterModType.UNKNOWN)
                            #if mn.startswith('ldr') and op1.startswith('[') and op1.endswith(']'):
                            if (mn.startswith('ldr') or mn.startswith('ldu')) and op1.startswith('['):
                                self.lgr.debug('is ldr op1 is %s' % op1)
                                addr = self.decode.getAddressFromOperand(self.cpu, op1, self.lgr)
                                addr = addr & self.task_utils.getMemUtils().SIZE_MASK
                                if addr is not None:
                                    addr = addr + self.offset
                                    self.lgr.debug('cycleRegisterMod, set as addr type for addr 0x%x reflects offset %s' % (addr, self.offset))
                                    retval = RegisterModType(addr, RegisterModType.ADDR)
                            elif self.cpu.architecture == 'ppc32' and mn.startswith('l'):
                                # TBD incomplete by a mile
                                self.lgr.debug('cycleRegisterMod is ppc l op1 is %s' % op1)
                                addr = self.decode.getAddressFromOperand(self.cpu, op1, self.lgr)
                                if addr is not None:
                                    retval = RegisterModType(addr, RegisterModType.ADDR)
                                else:
                                    self.lgr.debug('cycleRegisterMod failed to get addr from %s' % op1)
                                
                            elif mn.startswith('mov') and '[' in op1:
                                self.lgr.debug('is mov op1 is %s' % op1)
                                addr = self.decode.getAddressFromOperand(self.cpu, op1, self.lgr)
                                addr = addr & self.task_utils.getMemUtils().SIZE_MASK
                                if addr is not None:
                                    addr = addr + self.offset
                                    self.lgr.debug('cycleRegisterMod, x86 set as addr type for addr 0x%x reflects offset %d' % (addr, self.offset))
                                    retval = RegisterModType(addr, RegisterModType.ADDR)
                            elif mn.startswith('xchg'):
                                if self.decode.regIsPart(op1, self.reg):
                                    retval = RegisterModType(op0, RegisterModType.REG)
                                else:
                                    retval = RegisterModType(op1, RegisterModType.REG)

                            elif (mn.startswith('mov') or mn.startswith('sxt')) and self.decode.isReg(op1):
                                self.lgr.debug('cycleRegisterMod type is reg')
                                retval = RegisterModType(op1, RegisterModType.REG)
                            elif mn == 'lea':
                                self.lgr.debug('cycleRegisterMod is lea %s' % instruct[1])
                                lea_reg = self.decode.adjustRegInBrackets(op1, self.lgr)
                                if lea_reg is not None: 
                                    self.lgr.debug('cycleRegisterMod lea is constant adjust, new reg %s' % lea_reg)
                                    if lea_reg == self.reg:
                                        done = False
                                    else:
                                        self.lgr.debug('cycleRegisterMod lea set mod type')
                                        retval = RegisterModType(lea_reg, RegisterModType.REG)
                            elif mn.startswith('add') or mn.startswith('sub') or mn.startswith('rsb'):
                                # looks like arm stuff?
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
                                elif not self.decode.isReg(op1) and not '[' in op1:
                                    # assume constant 
                                    self.lgr.debug('cycleRegisterMod, constant adjust to %s, keep going' % op0)
                                    done = False 
                            elif self.cpu.architecture == 'ppc32' and (mn.startswith('rl') or mn.startswith('rr')):
                                src_reg = op1.split(',')[0].strip()
                                if mn.endswith('mi'):
                                    self.lgr.debug('cycleRegisterMod ppc rotate mask src reg is %s but we are guessing the meat of the result is the target register because zero bit positions cause r0 bits to be unchanged, so ignore' % src_reg)
                                    done = False 
                                else:
                                    # TBD taint branch.  src is masked with 
                                    retval = RegisterModType(src_reg, RegisterModType.REG)
                                    self.lgr.debug('cycleRegisterMod ppc rotate mask src reg is %s' % src_reg)
                                
                    elif self.cpu.architecture.startswith('arm'):
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
                                    #TBD how do we know the instructions are linear?
                                    pc = self.task_utils.getMemUtils().readPtr(self.cpu, pc_addr)
                                    self.lgr.debug('cycleRegisterMod try uncalling pc_addr 0x%x  pc 0x%x' % (pc_addr, pc))
                                    cell = self.top.getCell()
                                    pre_call = pc - 4
                                    self.uncall_break = self.reverse_mgr.SIM_breakpoint(cell, Sim_Break_Linear, Sim_Access_Execute, pre_call, 1, 0)
                                    retval = RegisterModType(None, RegisterModType.BAIL)
                                    self.lgr.debug('cycleRegisterMod set break number %d stop hap, now rev to 0x%x' % (self.uncall_break, pre_call))
                                    self.save_cycle = self.cpu.cycles
                                    self.save_reg_mod = RegisterModType(addr, RegisterModType.ADDR)
                                    self.uncall_hap = self.reverse_mgr.reverse(callback=self.uncallHap)
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

    def uncallHap(self, dumb, one, exception, error_string):
        ''' used in back-tracing registers '''
        if self.uncall_break is None:
            return
        eip = self.top.getEIP(self.cpu)
        dum_cpu, comm, tid = self.task_utils.curThread()
        self.lgr.debug('uncallHap ip: 0x%x uncall_break %d tid: %s expected %s reg:%s self.reg_val 0x%x' % (eip, self.uncall_break, 
              tid, self.tid, self.reg, self.reg_val))
        if tid == self.tid:
            RES_delete_breakpoint(self.uncall_break)
            self.top.RES_delete_stop_hap(self.uncall_hap)
            self.uncall_break = None
            val = self.top.getReg(self.reg, self.cpu) 
            if val == self.reg_val:
                self.lgr.debug('uncallHap reg %s still 0x%x, now cycle back through instructions, but run alone' % (self.reg, val))
                SIM_run_alone(self.cycleAlone, tid)
            else: 
                self.lgr.debug('uncallHap got val 0x%x, does not match 0x%x return to previous cycle 0x%x' % (val, self.reg_val, self.save_cycle))
                SIM_run_alone(self.resumeAlone, None)
                
        else:
            self.lgr.debug('uncallHap, wrong tid, rev')
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
            
    def followTaintArmPpc(self, reg_mod_type):
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
                self.top.stopAtKernelWrite(address, self, satisfy_value = self.satisfy_value, kernel=self.kernel, num_bytes=4, track=True)
            elif reg_mod_type.mod_type == RegisterModType.REG:
                self.lgr.debug('followTaintArm reg %s' % reg_mod_type.value)
                self.bookmarks.setBacktrackBookmark('eip:0x%x inst:"%s"' % (eip, instruct[1]))
                self.doRevToModReg(reg_mod_type.value, taint=self.taint, kernel=self.kernel)
            else:
                self.lgr.debug('folowTrainArm, no plan, bailing')
                self.cleanup(None)
                 
    def followTaint(self, reg_mod_type):
        if self.cpu.architecture.startswith('arm') or self.cpu.architecture == 'ppc32':
            self.followTaintArmPpc(reg_mod_type)
        else:
            self.followTaintX86(reg_mod_type)

    def getOpValue(self, op):
        retval = None
        if '[' in op:
            address = self.decode.getAddressFromOperand(self.cpu, op, self.lgr)
            retval = self.task_utils.getMemUtils().readWord32(self.cpu, address)
        else:
            retval = self.decode.getValue(op, self.cpu, self.lgr)
        return retval
         
    def followTaintX86(self, reg_mod_type):
        ''' we believe the instruction at the current ip modifies self.reg 
            Where does its value come from? '''
        eip = self.top.getEIP(self.cpu)
        instruct = SIM_disassemble_address(self.cpu, eip, 1, 0)
        self.lgr.debug('followTaintX86 instruct at 0x%x self.reg %s instruct is %s' % (eip, self.reg, str(instruct)))
        op1, op0 = self.decode.getOperands(instruct[1])
        mn = self.decode.getMn(instruct[1])
        if not self.multOne(op0, mn) and not mn.startswith('mov') and not mn == 'pop' and not mn.startswith('cmov') \
                                     and not self.orValue(op1, mn) and not mn == 'add' and not mn == 'xor':
            ''' NOTE: treating "or" and "add" and imult of one as a "mov" '''
            if mn == 'xchg':
                self.lgr.debug('followTaintX86, is xchg, track %s' % reg_mod_type.value)
                self.doRevToModReg(reg_mod_type.value, taint=self.taint, kernel=self.kernel)
                return
            elif mn == 'lea':
                self.lgr.debug('followTaintX86, is lea, track %s' % reg_mod_type.value)
                self.doRevToModReg(reg_mod_type.value, taint=self.taint, kernel=self.kernel)
                return
             
            self.lgr.debug('followTaintX86, %s not a move, we are stumped cycle 0x%x' % (instruct[1], self.cpu.cycles))
            self.bookmarks.setBacktrackBookmark('eip:0x%x inst:"%s" stumped' % (eip, instruct[1]))
            self.top.skipAndMail()

        elif mn == 'add':
           offset = None
           #offset = int(op1, 16)
           offset = self.getOpValue(op1)
           if offset is not None:
               offset = self.mem_utils.getUnsigned(offset)
               self.lgr.debug('followTaint, add check offset of %s is 0x%x' % (op1, offset))
           if offset is not None and offset <= 8:
               ''' wth, just an address adjustment? '''
               self.lgr.debug('followTaintX86, add of %x, assume address adjust, e.g., heap struct' % offset)
               self.bookmarks.setBacktrackBookmark('eip:0x%x inst:"%s"' % (eip, instruct[1]))
               self.doRevToModReg(op0, taint=self.taint, kernel=self.kernel)
               return 
           else:
               offset = self.getOpValue(op0)
               if offset is not None:
                   offset = self.mem_utils.getUnsigned(offset)
               self.lgr.debug('followTaint, add check offset of %s is 0x%x' % (op0, offset))
               if offset is not None and offset <= 0xff:
                   # minor adjustment?
                   self.lgr.debug('followTaintX86, add of %x, assume minor adjust of op1 %s' % (offset, op1))
                   self.bookmarks.setBacktrackBookmark('eip:0x%x inst:"%s"' % (eip, instruct[1]))
                   self.doRevToModReg(op1, taint=self.taint, kernel=self.kernel)
                   return 
        elif mn == 'pop':
            esp = self.top.getReg('esp', self.cpu) 
            self.bookmarks.setBacktrackBookmark('eip:0x%x inst:"%s"' % (eip, instruct[1]))
            self.cleanup(None)
            word_size = self.top.getWordSize()
            self.top.stopAtKernelWrite(esp, self, satisfy_value = self.satisfy_value, kernel=self.kernel, num_bytes=word_size, track=True)

        elif self.decode.isReg(op1) and (mn == 'mov' or not self.decode.isIndirect(op1)):
            self.lgr.debug('followTaintX86, is reg, track %s' % op1)
            self.doRevToModReg(op1, taint=self.taint, kernel=self.kernel)
        elif mn == 'xor':
            value = self.getOpValue(op1)
            if value is None:
                self.lgr.debug('followTaintX86, is xor failed to get value from %s' % op1)
            elif memUtils.isNull(value):
                self.lgr.debug('followTaintX86, is xor with ffff.. keep looking at this reg')
                self.bookmarks.setBacktrackBookmark('eip:0x%x inst:"%s"' % (eip, instruct[1]))
                self.doRevToModReg(op0, taint=self.taint, kernel=self.kernel)
            else:
                self.lgr.debug('followTaintX86, xor with value 0x%x, stumped' % value)
                self.top.skipAndMail()

        elif self.decode.isReg(op1) and self.decode.isIndirect(op1):
            self.lgr.debug('followTaintX86, is indrect reg, track %s' % op1)
            address = self.decode.getAddressFromOperand(self.cpu, op1, self.lgr)
            self.bookmarks.setBacktrackBookmark('switch to indirect op1 %s eip:0x%x inst:"%s"' % (op1, eip, instruct[1]))
            self.doRevToModReg(op1, taint=self.taint, kernel=self.kernel)

        #elif mn == 'lea':
        #    address = self.decode.getAddressFromOperand(self.cpu, op1, self.lgr)

        else:
            self.lgr.debug('followTaintX86, see if %s is an address' % op1)
            address = self.decode.getAddressFromOperand(self.cpu, op1, self.lgr)
            if address is not None:
                self.lgr.debug('followTaintX86, yes, address is 0x%x' % address)
                if self.decode.isByteReg(op0) or 'byte ptr' in op1:
                    value = self.task_utils.getMemUtils().readByte(self.cpu, address)
                else:
                    value = self.task_utils.getMemUtils().readWord32(self.cpu, address)
                newvalue = self.task_utils.getMemUtils().getUnsigned(address+self.offset)
                if newvalue is not None and value is not None: 
                    self.lgr.debug('followTaintX86 BACKTRACK eip: 0x%x value 0x%x at address of 0x%x loaded into register %s call stopAtKernelWrite for 0x%x' % (eip, value, address, op0, newvalue))
                if not mn.startswith('mov'):
                    self.bookmarks.setBacktrackBookmark('taint branch eip:0x%x inst:%s' % (eip, instruct[1]))
                    self.lgr.debug('BT bookmark: taint branch eip:0x%x inst %s' % (eip, instruct[1]))
                else:
                    self.bookmarks.setBacktrackBookmark('eip:0x%x inst:"%s"' % (eip, instruct[1]))
                    self.lgr.debug('BT bookmark: backtrack eip:0x%x inst:"%s"' % (eip, instruct[1]))
                #self.cleanup(None)
                if 'byte ptr' in op1:
                    num_bytes = 1 
                elif self.num_bytes is None:
                    num_bytes = self.decode.regLen(op0)
                else:
                    num_bytes = self.num_bytes
                self.top.stopAtKernelWrite(newvalue, self, satisfy_value=self.satisfy_value, kernel=self.kernel, num_bytes=num_bytes, track=True)
            else:
                self.lgr.debug('followTaintX86, BACKTRACK op1 %s not an address or register, stopping traceback' % op1)
                self.bookmarks.setBacktrackBookmark('eip:0x%x inst:"%s" stumped' % (eip, instruct[1]))
                self.top.skipAndMail()
       
    def cycleAlone(self, tid): 
        self.lgr.debug('cycleAlone, tid %s entered looking for %s' % (tid, self.reg))
        cmd = 'reverse'
        reg_mod_type = self.cycleRegisterMod()
        if reg_mod_type is None:
            if not self.tooFarBack():
                ''' stepped back into kernel, rev '''
                self.lgr.debug('cycleAlone must have entered kernel, continue to previous place where this process ran')
                #SIM_run_alone(SIM_run_command, cmd)
                reg_ok = self.jumpOverKernel(tid)
                if reg_ok: 
                    SIM_run_alone(self.cycleAlone, tid)
                else:
                    self.lgr.debug('cycleAlone, assume jumpOverKernel took over the search')
            else:
                self.lgr.debug('cycleAlone must have backed to first cycle 0x%x' % self.top.getFirstCycle())
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
                    self.lgr.debug('cycleAlone must backed to first cycle 0x%x' % self.top.getFirstCycle())
 
    def stoppedReverseModReg(self, dumb, one, exception, error_string):
        '''
        Invoked when the simulation stops while looking for a modified register
        '''
        dum_cpu, comm, tid = self.task_utils.curThread()
        self.lgr.debug('stoppedReverseModReg, entered looking for %s cur tid:%s' % (self.reg, tid))
        cpl = memUtils.getCPL(self.cpu)
        if tid == self.tid and (cpl != 0 or self.kernel):
            self.cycleAlone(tid)
        else:
            self.lgr.error('stoppedReverseModReg wrong process or in kernel tid %s expected %s' % (tid, self.tid))
            #SIM_run_alone(SIM_run_command, cmd)
           
 
    def cleanup(self, addr_list):
        self.lgr.debug('reverseToCall cleanup')
        self.context_manager.setExitBreaks()
        if self.stop_hap is not None:
            self.top.RES_delete_stop_hap_run_alone(None, your_stop=True)
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

    def stoppedReverseToCall(self, param_from_rev_mgr, one, exception, error_string):
        '''
        Invoked when the simulation stops while looking for a previous call
        '''
        if self.stop_hap is None and param_from_rev_mgr is None:
            self.lgr.error('stoppedReverseToCall invoked though hap is none')
            return
        dum_cpu, comm, tid = self.task_utils.curThread()
        current = SIM_cycle_count(cpu)
        self.lgr.debug('stoppedReverseToCall, entered %s (%s) cycle: 0x%x' % (tid, comm, current))
        #if current < self.top.getFirstCycle():
        if current <= self.top.getFirstCycle():
            print('Reversed to original cycle')
            self.lgr.debug('stoppedReverseToCall found cycle 0x%x prior to first, stop here' %(current))
            self.cleanup(None)
        elif tid == self.tid and (memUtils.getCPL(cpu) != 0 or self.kernel):
            eip = self.top.getEIP(cpu)
            instruct = SIM_disassemble_address(cpu, eip, 1, 0)
            if self.first_back and resimUtils.isSysEnter(instruct[1]):
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
                   SIM_run_alone(self.reverseAlone, self.stoppedReverseToCall)

            elif self.isRet(instruct[1], eip):
                self.need_calls += 1
                self.lgr.debug('stoppedReverseToCall 0x%x got ret %s  need: %d' % (eip, instruct[1], self.need_calls))
                if self.first_back and not self.uncall:
                    self.rmBreaks()
                    ''' TBD fix this? '''
                    for item in self.x_pages:
                        self.setBreakRange(self.cell_name, tid, item.address, item.length, cpu, comm, True)
                SIM_run_alone(self.reverseAlone, self.stoppedReverseToCall)
            else:
                self.lgr.debug('stoppedReverseToCall Not call or ret at %x, is %s' % (eip, instruct[1]))
                SIM_run_alone(self.reverseAlone, self.stoppedReverseToCall)
        else:
            self.lgr.debug('stoppedReverseInstruction in wrong tid (%s) or in kernel, try again' % tid)
            SIM_run_alone(self.reverseAlone, self.stoppedReverseToCall)
        self.first_back = False
   
    def setOneBreak(self, address, cpu):
        self.lgr.debug('setOneBreak at 0x%x' % address)
        phys_block = cpu.iface.processor_info.logical_to_physical(address, Sim_Access_Read)
        cell = cpu.physical_memory
        call_break_num = self.reverse_mgr.SIM_breakpoint(cell, Sim_Break_Physical, 
                       Sim_Access_Execute, phys_block.address, 1, 0)
        self.the_breaks.append(call_break_num)

    def setBreakRange(self, cell_name, tid, start, length, cpu, comm, call_ret, reg=None):
        '''
        Set breakpoints to carpet the process's address space
        '''
        self.lgr.debug('setBreakRange begin')
        start, end = pageUtils.adjust(start, length, self.page_size)
        cell = cpu.physical_memory
        self.recent_proc_info = procInfo.procInfo(comm, cpu, tid, None, False)
        self.tid = tid
      
        self.lgr.debug('Adding breakpoints for %s:%s (%s) at %x through %x, given length was %x' % (cell_name, tid, comm, start, end, length))
        while start <= end:
            limit = start + self.page_size
            phys_block = cpu.iface.processor_info.logical_to_physical(start, Sim_Access_Read)
            if phys_block.address != 0:
                if call_ret:
                    # Set exectution breakpoints for "call" and "ret" instructions
                    call_break_num = self.reverse_mgr.SIM_breakpoint(cell, Sim_Break_Physical, Sim_Access_Execute, phys_block.address, self.page_size, 0)
                    self.the_breaks.append(call_break_num)
                    if self.cpu.architecture.startswith('arm'):
                        prefix = 'bl' 
                    else:
                        prefix = 'call' 
                    resimSimicsUtils.setBreakpointPrefix(self.top.conf, call_break_num, prefix)
                 
                    if self.cpu.architecture.startswith('arm'):
                        ''' TBD much too ugly'''
                        ret_break_num = self.reverse_mgr.SIM_breakpoint(cell, Sim_Break_Physical, 
                           Sim_Access_Execute, phys_block.address, self.page_size, 0)
                        self.the_breaks.append(ret_break_num)
                        resimSimicsUtils.setBreakpointSubstring(self.top.conf, ret_break_num, 'PC')
                        ret_break_num = self.reverse_mgr.SIM_breakpoint(cell, Sim_Break_Physical, 
                           Sim_Access_Execute, phys_block.address, self.page_size, 0)
                        self.the_breaks.append(ret_break_num)
                        resimSimicsUtils.setBreakpointSubstring(self.top.conf, ret_break_num, 'LR')
                    else:
                        ret_break_num = self.reverse_mgr.SIM_breakpoint(cell, Sim_Break_Physical, 
                           Sim_Access_Execute, phys_block.address, self.page_size, 0)
                        self.the_breaks.append(ret_break_num)
                        resimSimicsUtils.setBreakpointPrefix(self.top.conf, ret_break_num, 'ret')
                    self.lgr.debug('done setting breakpoints for call and ret addr: %x', phys_block.address)
                elif reg is not None:
                    all_break_num = self.reverse_mgr.SIM_breakpoint(cell, Sim_Break_Physical, 
                       Sim_Access_Execute, phys_block.address, self.page_size, 0)
                    # TBD substr only applies to mnemonic?
                    #command = 'set-substr %d "%s"' % (all_break_num, reg)
                    #SIM_run_alone(SIM_run_command, command)
                    self.the_breaks.append(all_break_num)
                    self.lgr.debug('done setting breakpoints for reg substring %s addr: %x' % (reg, phys_block.address))
                else:
                    all_break_num = self.reverse_mgr.SIM_breakpoint(cell, Sim_Break_Physical, 
                       Sim_Access_Execute, phys_block.address, self.page_size, 0)
                    self.lgr.debug('setBreakRange set phys addr 0x%x linear 0x%x' % (phys_block.address, start))
                    self.the_breaks.append(all_break_num)
                    
            elif phys_block.address == 0:
                self.lgr.debug('reverseToCall FAILED breakpoints for %s:%s (%s) at %x ' % (cell_name, tid, comm,
                    start))

            start = limit
        self.lgr.debug('setBreakRange done')

    def clearEnterCycles(self):
        self.record_entry.clearEnterCycles()


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
        ''' reverse to just before the most recent call naming the given FD '''
        if self.cpu is None:
            self.lgr.error('preCallFD called before reverseToCall setup')
            return
        read_calls = ['read', 'recv', 'recvfrom', 'recvmsg']
        plist = {}
        tid_list = self.context_manager.getThreadTids()
        # TBD for windows need method to get thread list reflecting state, e.g., waiting in kernel?
        tasks = self.task_utils.getTaskStructs()
        plist = {}
        for t in tasks:
            tid = str(tasks[t].pid)
            if tid in tid_list:
                plist[tid] = t 
        in_kernel = False
        frame = None
        cycles = None
        for tid in plist:
            t = plist[tid]
            if tasks[t].state > 0:
                frame, cycles = self.record_entry.getPreviousCycleFrame(tid)
                if frame is not None:
                    call = self.task_utils.syscallName(frame['syscall_num'], self.compat32)
                    if call in read_calls and frame['param1'] == fd:
                        print('tid %s in kernel on %s of fd %d' % (tid, call, fd))
                        in_kernel = True
                        break
                    elif call == 'select' or call == '_newselect':
                        select_list = frame['select']
                        self.lgr.debug('DataWatch trackIO check select for %d' % fd)
                        if fd in select_list:
                            print('tid %s in kernel on select including %d' % (tid, fd))
                            in_kernel = True
                            break
                    elif call == 'socketcall' and 'ss' in frame:
                        socket_callnum = frame['param1']
                        socket_callname = net.callname[socket_callnum].lower()
                        ss = frame['ss']
                        if ss.fd == fd:
                            print('tid %s in kernel on %s of fd %d' % (tid, socket_callname, fd)) 
                            in_kernel = True
                            break
       
        if in_kernel:
            self.lgr.debug('DataWatch trackIO in kernel, do skip to cycle 0x%x' % cycles)
            self.top.removeDebugBreaks()
            if not self.skipToTest(cycles-1):
            #cmd = 'skip-to cycle = %d ' % (cycles)
            #SIM_run_command(cmd)
            #print('skipped back to 0x%x' % cycles)
                dum_cpu, comm, tid = self.task_utils.curThread()
                eip = self.top.getEIP(self.cpu)
                self.lgr.debug('DataWatch trackIO skip back from kernel failed going to 0x%x, tid:%s eip:0x%x' % (self.cpu.cycles, tid, eip))
                return False

            self.top.restoreDebugBreaks(was_watching=True)

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

    def findCallBehind(self, return_to):
        ''' given a returned to address, look backward for the address of the call instruction '''
        retval = None
        if self.cpu.architecture.startswith('arm') or self.cpu.architecture == 'ppc32':
            eip = return_to - 4
            instruct = SIM_disassemble_address(self.cpu, eip, 1, 0)
            self.lgr.debug('findCallBehind instruct is %s' % instruct[1])
            if self.decode.isCall(self.cpu, instruct[1], ignore_flags=True):
                self.lgr.debug('followCall arm or ppceip 0x%x' % eip)
                retval = eip
        else:
            eip = return_to - 2
            self.lgr.debug('findCallBehind return_to is 0x%x  ip 0x%x' % (return_to, eip))
            # TBD use instruction length to confirm it is a true call
            # not always 2* word size?
            count = 0
            while retval is None and count < 4*self.mem_utils.wordSize(self.cpu) and eip>0:
                instruct = SIM_disassemble_address(self.cpu, eip, 1, 0)
                #self.lgr.debug('stackTrace followCall count %d eip 0x%x instruct %s' % (count, eip, instruct[1]))
                ''' TBD hack.  Fix this by getting bb start and walking forward '''
                if instruct[1].startswith(self.callmn) and 'call far ' not in instruct[1]:
                    parts = instruct[1].split()
                    if len(parts) == 2:
                        try:
                            dst = int(parts[1],16)
                        except:
                            retval = eip
                            continue
                        if self.top.isCode(dst, tid=self.tid):
                            retval = eip
                        else:
                            self.lgr.debug('stackTrace dst not code 0x%x' % dst)
                            eip = eip-1
                    else:        
                        retval = eip
                elif 'illegal memory mapping' in instruct[1]:
                    break
                else:
                    eip = eip-1
                count = count+1
        return retval
