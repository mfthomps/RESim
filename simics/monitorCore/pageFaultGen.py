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
import os
import memUtils
import pageUtils
import pageUtilsPPC32
import hapCleaner
import resimUtils
import cycleCallback
import decodePPC32
from resimHaps import *
'''
Watch page faults for indications of a SEGV exception
'''
class Prec():
    def __init__(self, cpu, comm, tid=None, cr2=None, eip=None, name=None, fsr=None, page_fault=False):
        self.cpu = cpu
        self.comm = comm
        self.tid = tid
        self.cr2 = cr2
        self.eip = eip
        self.name = name
        self.fsr = fsr
        self.cycles = cpu.cycles
        self.page_fault = page_fault

class PageFaultGen():
    def __init__(self, top, target, param, cell_config, mem_utils, task_utils, context_manager, lgr):
        self.cell_config = cell_config
        self.top = top
        self.target = target
        self.context_manager = context_manager
        self.param = param
        self.mem_utils = mem_utils
        self.task_utils = task_utils
        self.lgr = lgr
        self.exit_break = {}
        self.exit_break2 = {}
        self.exit_hap = {}
        self.exit_hap2 = {}
        self.pdir_break = None
        self.pdir_hap = None
        self.ptable_break = None
        self.ptable_hap = None
        self.pteg1_break = None
        self.pteg2_break = None
        self.pteg1_hap = None
        self.pteg2_hap = None
        self.stop_hap = None
        self.stop_skip_hap = None
        self.cpu = self.cell_config.cpuFromCell(target)
        self.cell = self.cell_config.cell_context[target]
        self.page_entry_size = pageUtils.getPageEntrySize(self.cpu)
        self.faulted_pages = {}
        self.fault_hap = None
        self.exception_eip = None
        self.debugging_tid = None
        self.faulting_cycles = {}
        self.fault_hap1 = None
        self.fault_hap2 = None
        self.fault_hap_return = None
        self.exception_hap = None
        self.exception_hap2 = None
        self.pending_faults = {}
        self.pending_sigill = {}
        self.mode_hap = None
        self.ignore_probes = []
        self.user_eip = None
        self.afl = False
        self.missing_ptegs = {}
        ''' hack to tell context manager to call back to PageFaultGen on context switches to watched processes '''
        context_manager.callMe(self)
        ''' TIDS that have returned to user space to find the fault is not resolved.  Assumes reschedule on fault and lazy
            return to the user space without resoving it. 
        '''
        self.pending_double_faults = {}
        name = 'pageFaultGen_%s' % target
        self.cycle_event_callback = cycleCallback.CycleCallback(self.cpu, name, self.lgr)
        # TBD MAKE THIS A PARAM
        self.data_storage_fault = 0x300

    def rmExit(self, tid):
        if tid in self.exit_break:
            self.context_manager.genDeleteHap(self.exit_hap[tid])
            self.context_manager.genDeleteHap(self.exit_hap2[tid])
            del self.exit_break[tid]
            del self.exit_hap[tid]
            del self.exit_hap2[tid]
        self.context_manager.watchPageFaults(False)
        if tid in self.pending_faults:
            #self.lgr.debug('pageFaultGen rmExit remove pending for %s %s' % (tid, str(self.pending_faults[tid])))
            del self.pending_faults[tid]
        if tid in self.pending_sigill:
            #self.lgr.debug('pageFaultGen rmExit remove pending for %s %s' % (tid, str(self.pending_sigill[tid])))
            del self.pending_sigill[tid]
        
    def rmPDirHap(self, hap):
        if hap is not None:
            RES_hap_delete_callback_id('Core_Breakpoint_Memop', hap)
            RES_delete_breakpoint(self.pdir_break)

    def pdirWriteHap(self, prec, third, forth, memory):
        pdir_entry = SIM_get_mem_op_value_le(memory)
        cpu, comm, tid = self.task_utils.curThread() 
        #self.lgr.debug('pageFaultGen dirWriteHap, %s (%s) new entry value 0x%x set by tid:%s' % (tid, comm, pdir_entry, prec.tid))
        if self.pdir_break is not None:
            hap = self.pdir_hap
            SIM_run_alone(self.rmPDirHap, hap)
            #self.lgr.debug('pageFaultGen pdirWriteHap delete bp %d' % self.pdir_break)
            self.pdir_hap = None
            if pdir_entry != 0xff:
                self.rmExit(tid)
            else:
                self.lgr.debug('pageFaultGen pdirWriteHap assuming entry of 0xff implies a segv')

    def watchPdir(self, pdir_addr, prec):
        if self.pdir_break is not None:
            #self.lgr.debug('pageFaultGen watchPdir already a break. wanted to set one one 0x%x' % pdir_addr)
            return
        if pdir_addr is None:
            self.lgr.error('pageFaultGen called with pdir_addr of None')
        
        pcell = self.cpu.physical_memory
        #self.pdir_break = self.context_manager.genBreakpoint(pcell, Sim_Break_Physical, Sim_Access_Write, pdir_addr, self.page_entry_size, 0)
        self.pdir_break = SIM_breakpoint(pcell, Sim_Break_Physical, Sim_Access_Write, pdir_addr, self.page_entry_size, 0)
        #self.lgr.debug('pageFaultGen watchPdir tid: %s break %d at 0x%x' % (prec.tid, self.pdir_break, pdir_addr))
        #self.pdir_hap = self.context_manager.genHapIndex("Core_Breakpoint_Memop", self.pdirWriteHap, prec, self.pdir_break, name='watchPdir')
        self.pdir_hap = RES_hap_add_callback_index("Core_Breakpoint_Memop", self.pdirWriteHap, prec, self.pdir_break)

    def rmPtableHap(self, hap):
        RES_hap_delete_callback_id('Core_Breakpoint_Memop', hap)

    def ptableWriteHap(self, prec, third, forth, memory):
        ptable_entry = SIM_get_mem_op_value_le(memory)
        cpu, comm, tid = self.task_utils.curThread() 
        #self.lgr.debug('pageFaultGen tableWriteHap, %s (%s) new entry value 0x%x was set for tid: %s' % (tid, comm, ptable_entry, prec.tid))
        if self.ptable_break is not None:
            hap = self.ptable_hap
            SIM_run_alone(self.rmPtableHap, hap)
            RES_delete_breakpoint(self.ptable_break)
            #self.lgr.debug('pageFaultGen ptableWrite delete bp %d' % self.ptable_break)
            self.ptable_hap = None
            self.rmExit(tid)

    def ptegWriteHap(self, prec, third, forth, memory):
        self.lgr.debug('pageFaultGen ptegWriteHap')
        cpu, comm, tid = self.task_utils.curThread() 
        if self.pteg1_break is not None:
            hap = self.pteg1_hap
            SIM_run_alone(self.rmPtableHap, hap)
            RES_delete_breakpoint(self.pteg1_break)
            self.rmExit(tid)
        if self.pteg2_break is not None:
            hap = self.pteg2_hap
            SIM_run_alone(self.rmPtableHap, hap)
            RES_delete_breakpoint(self.pteg2_break)
            self.rmExit(tid)

    def watchPtable(self, ptable_addr, prec):
        if self.ptable_break is not None:
            #self.lgr.debug('pageFaultGen watchPtable wanted break on 0x%x but already a break set' % (ptable_addr))
            return
        pcell = self.cpu.physical_memory
        #self.ptable_break = self.context_manager.genBreakpoint(pcell, Sim_Break_Physical, Sim_Access_Write, ptable_addr, self.page_entry_size, 0)
        self.ptable_break = SIM_breakpoint(pcell, Sim_Break_Physical, Sim_Access_Write, ptable_addr, self.page_entry_size, 0)
        #self.lgr.debug('pageFaultGen watchPtable tid:%s break %d at 0x%x' % (prec.tid, self.ptable_break, ptable_addr))
        #self.ptable_hap = self.context_manager.genHapIndex("Core_Breakpoint_Memop", self.ptableWriteHap, prec, self.ptable_break, name='watchPtable')
        self.ptable_hap = RES_hap_add_callback_index("Core_Breakpoint_Memop", self.ptableWriteHap, prec, self.ptable_break)

    def watchPteg(self, pt, prec):
        self.pteg1_break = SIM_breakpoint(self.cpu.physical_memory, Sim_Break_Physical, Sim_Access_Write, pt.pteg1, 64, 0)
        self.lgr.debug('pagetFaultsGen setTableHaps set break %d on pteg1 0x%x' % (self.pteg1_break, pt.pteg1))
        self.pteg1_hap = SIM_hap_add_callback_index("Core_Breakpoint_Memop", self.ptegWriteHap, prec, self.pteg1_break)
        if pt.pteg2 is not None:
            self.pteg2_break = SIM_breakpoint(self.cpu.physical_memory, Sim_Break_Physical, Sim_Access_Write, pt.pteg2, 64, 0)
            self.lgr.debug('pagetFaultsGen setTableHaps set break %d on pteg2 0x%x' % (self.pteg2_break, pt.pteg2))
            self.pteg2_hap = SIM_hap_add_callback_index("Core_Breakpoint_Memop", self.ptegWriteHap, prec, self.pteg2_break)
  
    def hapAlone(self, prec):
       
        if self.top.isRunning():
            self.stop_hap = self.top.RES_add_stop_callback(self.stopHap, prec)
            self.lgr.debug('pageFaultGen hapAlone set stop hap, now stop?')
            self.top.undoDebug(None)
            SIM_break_simulation('SEGV, task rec for %s (%s) modified mem reference was 0x%x' % (prec.tid, prec.comm, prec.cr2))
        else:
            self.lgr.debug('pageFaultGen hapAlone already stopped')
        self.top.removeDebugBreaks(keep_coverage=False)
        self.top.stopTrackIO(immediate=True)
 
    def pageFaultHapPPC32(self, compat32, third, forth, memory):
        reg_num = self.cpu.iface.int_register.get_number("msr")
        msr = self.cpu.iface.int_register.read(reg_num)
        #self.lgr.debug('pageFaultHapPPC32 msr 0x%x memory 0x%x' % (msr, memory.logical_address)) 
        if not memUtils.testBit(msr, 4) and memory.logical_address != self.data_storage_fault:
            return
        cpu, comm, tid = self.task_utils.curThread() 
        reg_num = self.cpu.iface.int_register.get_number('srr0')
        reg_value = self.cpu.iface.int_register.read(reg_num)
        self.user_eip = reg_value
        cur_pc = self.mem_utils.getRegValue(cpu, 'pc')
        eip = cur_pc    
        #self.lgr.debug('pageFaultHapPPC32 tid:%s (%s) eip: 0x%x cycle 0x%x user_eip: 0x%x' % (tid, comm, eip, self.cpu.cycles, self.user_eip))
        if not self.context_manager.watchingThis():
            #self.lgr.debug('pageFaultHapPPC32 tid:%s, contextManager says not watching' % tid)
            return
        if self.exception_eip is not None:
            eip = self.exception_eip
        
        access_type = None
        if memory.logical_address == self.data_storage_fault:
            # dar should have fauling address
            dar = self.mem_utils.getRegValue(cpu, 'dar')
            fault_addr = dar
            #self.lgr.debug('pageFaultHapPPC32 data fault addr 0x%x' % (dar))
        else: 
            fault_addr = self.user_eip
        # TBD why were we recording this? Check other architectures to see if that makes sense.  Why not just bail?
        #if self.mem_utils.isKernel(self.user_eip):
        #    # record cycle and eip for reversing back to user space    
        #    self.recordFault(tid, self.user_eip)
        if self.mem_utils.isKernel(self.user_eip):
             # what about validation of user space-provided pointers? Would those involve a page fault?
             self.lgr.debug('pageFaultHapPPC32 within kernel, 0x%x, bail.' % self.user_eip)
             return
        if self.top.isCode(fault_addr, tid, target=self.target):
            #self.lgr.debug('pageFaultHap 0x%x is code, bail' % fault_addr)
            return
        if tid not in self.faulted_pages:
            self.faulted_pages[tid] = []
        if fault_addr in self.faulted_pages[tid]:
            #self.lgr.debug('pageFaultHap, addr 0x%x already handled for tid:%s cur_pc: 0x%x' % (fault_addr, tid, cur_pc))
            return
        self.faulted_pages[tid].append(fault_addr)
        page_info = pageUtilsPPC32.findPageTable(self.cpu, fault_addr, self.lgr)
        prec = Prec(self.cpu, comm, tid=tid, cr2=fault_addr, eip=cur_pc, page_fault=True)
        if tid not in self.pending_faults:
            self.lgr.debug('pageFaultHapPPC32 add pending fault for %s (%s) addr 0x%x cycle 0x%x' % (tid, comm, prec.cr2, prec.cycles))
            if self.mem_utils.isKernel(fault_addr):
                #self.lgr.debug('pageFaultGen pageFaultHap tid:%s, faulting address is in kernel, treat as SEGV 0x%x cycles: 0x%x' % (tid, fault_addr, self.cpu.cycles))
                self.pending_faults[tid] = prec
            else:
                self.pending_faults[tid] = prec
                if self.mode_hap is None:
                    #self.lgr.debug('pageFaultGen adding mode hap')
                    self.mode_hap = RES_hap_add_callback_obj("Core_Mode_Change", cpu, 0, self.modeChanged, tid)
        #else:
        #    self.lgr.debug('pageFaultHap tid %s already in pending faults' % tid)
            
        if not self.mem_utils.isKernel(fault_addr):
            hack_rec = (compat32, page_info, prec)
            SIM_run_alone(self.pageFaultHapAlone, hack_rec)

    def pageFaultHap(self, compat32, third, forth, memory):
        ''' Invoked when the kernel's page fault entry point is hit'''
        # BEWARE of many returns
        if self.fault_hap is None:
            return
        #cpu, comm, tid = self.task_utils.curThread() 
        #self.lgr.debug('pageFaultHap tid:%s third: %s  forth: %s' % (tid, str(third), str(forth)))
        #cpu = SIM_current_processor()
        #if cpu != hap_cpu:
        #    self.lgr.debug('pageFaultHap, wrong cpu %s %s' % (cpu.name, hap_cpu.name))
        #    return
        #use_cell = self.cell
        #if self.debugging_tid is not None:
        #    use_cell = self.context_manager.getRESimContext()

        if self.cpu.architecture == 'arm64':
            # arm64 v8, anyway, shares kernel entry address between syscalls and faults.  Vectors are instructions vice addresses?
            reg_num = self.cpu.iface.int_register.get_number('esr_el1')
            reg_value = self.cpu.iface.int_register.read(reg_num)
            reg_value = reg_value >> 26
            #self.lgr.debug('pageFaultHap arm64 reg_value 0x%x cycle 0x%x' % (reg_value, self.cpu.cycles))
            if reg_value == 0x11 or reg_value == 0x15:
                return

        cpu, comm, tid = self.task_utils.curThread() 
        sp = self.mem_utils.getRegValue(cpu, 'sp')

        user_ip_addr = sp + self.mem_utils.WORD_SIZE
        self.user_eip = self.mem_utils.readWord(self.cpu, user_ip_addr)
        if self.user_eip is None:
            SIM_break_simulation('remove this')
            self.lgr.warning('pageFaultgen nothing read from user_ip_addr 0x%x' % user_ip_addr)
            return
        if self.user_eip in self.ignore_probes:
            self.lgr.debug('pageFaultHap user eip: 0x%x in probes, ignore' % self.user_eip)
            return
        
        cur_pc = self.mem_utils.getRegValue(cpu, 'pc')
        eip = cur_pc    
        #self.lgr.debug('pageFaultHap tid:%s eip: 0x%x cycle 0x%x user_eip: 0x%x' % (tid, eip, self.cpu.cycles, self.user_eip))
        if not self.context_manager.watchingThis():
            #self.lgr.debug('pageFaultHap tid:%s, contextManager says not watching' % tid)
            return
        if self.exception_eip is not None:
            eip = self.exception_eip

        access_type = None
        if self.cpu.architecture == 'arm':
            # Get faulting user eip
            bad_reg = False
            try:
                i_reg_num = self.cpu.iface.int_register.get_number("instruction_far")
                self.user_eip = self.cpu.iface.int_register.read(i_reg_num)
                #self.lgr.debug('pageFaultHap arm user_eip is 0x%x' % self.user_eip)
            except SimExc_General:
                #self.lgr.debug('pageFaultGen pageFaultHap bad reg num')
                bad_reg = True

            if bad_reg or eip == self.param.data_abort:
                data_fault_reg = self.cpu.iface.int_register.get_number("combined_data_fsr")
                fault = self.cpu.iface.int_register.read(data_fault_reg)
                access_type = memUtils.testBit(fault, 11)
                data_far_reg_num = self.cpu.iface.int_register.get_number("combined_data_far")
                fault_addr = self.cpu.iface.int_register.read(data_far_reg_num)
                #self.lgr.debug('pageFaultGen **DATA stuff data_fault_reg %d fault 0x%x type %d fault_addr 0x%X' % (data_fault_reg, fault, access_type, fault_addr))

            else:
                i_fault_reg = self.cpu.iface.int_register.get_number("instruction_fsr")
                i_fault = self.cpu.iface.int_register.read(i_fault_reg)
                i_access_type = memUtils.testBit(i_fault, 11)
                fault_addr = self.user_eip
                #self.lgr.debug('pageFaultGen **INSTRUCTION stuff reg %d fault 0x%x type %d, fault_addr 0x%x' % (i_fault_reg, i_fault, i_access_type, fault_addr))
        elif self.cpu.architecture == 'arm64':
            fault_reg = self.cpu.iface.int_register.get_number("far_el1")
            fault_addr = self.cpu.iface.int_register.read(fault_reg)
            #ret_reg = self.cpu.iface.int_register.get_number("elr_el1")
            #ret_addr = self.cpu.iface.int_register.read(ret_reg)
            #if fault_addr == ret_addr:
            #    self.lgr.debug('pageFaultHap arm64 Instruction page fault addr 0x%x' % (fault_addr))
        else:
            reg_num = self.cpu.iface.int_register.get_number("cr2")
            if reg_num is not None:
                fault_addr = self.cpu.iface.int_register.read(reg_num)
                #self.lgr.debug('pageFaultHap cr2 read is 0x%x' % fault_addr)
            else:
                self.lgr.debug('pageFaultHap cr2 reg is NONE????? set to faulting addr to eip 0x%x' % eip)
                fault_addr = eip
        if self.mem_utils.isKernel(self.user_eip):
            # record cycle and eip for reversing back to user space    
            self.recordFault(tid, self.user_eip)
        if self.top.isCode(fault_addr, tid, target=self.target):
            #self.lgr.debug('pageFaultHap 0x%x is code, bail' % fault_addr)
            return
        if tid not in self.faulted_pages:
            self.faulted_pages[tid] = []
        if fault_addr in self.faulted_pages[tid]:
            #self.lgr.debug('pageFaultHap, addr 0x%x already handled for tid:%s cur_pc: 0x%x' % (fault_addr, tid, cur_pc))
            return
        self.faulted_pages[tid].append(fault_addr)
        #self.lgr.debug('pageFaultHap for %s (%s)  faulting address: 0x%x eip: 0x%x cycle: 0x%x context:%s user_eip: 0x%x' % (tid, comm, fault_addr, cur_pc, self.cpu.cycles, self.cpu.current_context, self.user_eip))

        #self.lgr.debug('pageFaultHap for %s (%s) at 0x%x  faulting address: 0x%x' % (tid, comm, eip, fault_addr))
        #self.lgr.debug('len of faulted pages is now %d' % len(self.faulted_pages))
        if cpu.architecture == 'arm':
            page_info = pageUtils.findPageTableArm(self.cpu, fault_addr, self.lgr)
        elif cpu.architecture == 'arm64':
            page_info = pageUtils.findPageTableArmV8(self.cpu, fault_addr, self.lgr)
        elif pageUtils.isIA32E(cpu):
            page_info = pageUtils.findPageTableIA32E(self.cpu, fault_addr, self.lgr)
        else:
            page_info = pageUtils.findPageTable(self.cpu, fault_addr, self.lgr)
        prec = Prec(self.cpu, comm, tid=tid, cr2=fault_addr, eip=cur_pc, page_fault=True)
        if tid not in self.pending_faults:
            #self.lgr.debug('pageFaultHap add pending fault for %s addr 0x%x cycle 0x%x' % (tid, prec.cr2, prec.cycles))
            if self.mem_utils.isKernel(fault_addr):
                if not self.top.isWindows(target=self.target):
                    self.lgr.debug('pageFaultGen pageFaultHap tid:%s, faulting address is in kernel, treat as SEGV 0x%x cycles: 0x%x' % (tid, fault_addr, self.cpu.cycles))
                    self.pending_faults[tid] = prec
                else:
                    self.lgr.debug('pageFaultGen pageFaultHap tid:%s, faulting address in kernel, addr: 0x%x cycles: 0x%x IGNORE in windows?' % (tid, fault_addr, self.cpu.cycles))
            else:
                self.pending_faults[tid] = prec
                if self.mode_hap is None:
                    self.lgr.debug('pageFaultGen adding mode hap')
                    self.mode_hap = RES_hap_add_callback_obj("Core_Mode_Change", cpu, 0, self.modeChanged, tid)
        #else:
        #    self.lgr.debug('pageFaultHap tid %s already in pending faults' % tid)
            
        if not self.mem_utils.isKernel(fault_addr):
            hack_rec = (compat32, page_info, prec)
            SIM_run_alone(self.pageFaultHapAlone, hack_rec)

    def rmModeHapAlone(self, dumb):
        #self.lgr.debug('last fault, remove hap')
        if self.mode_hap is not None:
            RES_hap_delete_callback_id("Core_Mode_Change", self.mode_hap)
            self.mode_hap = None

    def modeChanged(self, want_tid, one, old, new):
        # we had pending page fault, and we now changed mode.  if user space, see if the fault has cleared.
        if self.mode_hap is None:
            return
        dumb, comm, tid = self.task_utils.curThread() 
        if tid != want_tid:
            #self.lgr.debug('pageFaultGen modeChanged wrong tid  tid:%s wanted: %s old: %d new: %d' % (tid, want_tid, old, new))
            return

        self.lgr.debug('pageFaultGen modeChanged tid:%s wanted: %s old: %d new: %d' % (tid, want_tid, old, new))
        if new != Sim_CPU_Mode_Supervisor:
            self.lgr.debug('pageFaultGen modeChanged user space')
            if tid in self.pending_faults:
                self.lgr.debug('pageFaultGen modeChanged user space, was a pending fault for addr 0x%x cycle: 0x%x' % (self.pending_faults[tid].cr2, self.cpu.cycles))
                prec = self.pending_faults[tid]
                if prec.cr2 is None:
                    self.lgr.error('pageFaultGen modeChanged with no prec.cr2 set. Not expecting this')
                    return

                # should be in user space, so if mapped, should be able to use iface
                #phys_addr = self.mem_utils.v2p(self.cpu, prec.cr2)
                phys_block = self.cpu.iface.processor_info.logical_to_physical(prec.cr2, Sim_Access_Read)
                #if phys_addr is None:
                #    #TBD remove this, seems redundant
                #    self.lgr.debug('pageFaultGen modeChanged v2p failed on prec.cr2 of 0x%x.' % prec.cr2)
                #    phys_block = self.cpu.iface.processor_info.logical_to_physical(prec.cr2, Sim_Access_Read)
                #    if phys_block is not None and phys_block.address is not None and phys_block.address != 0:
                #        #self.lgr.debug('pageFaultGen modeChanged in user space cr2  0x%x mapped to phys 0x%x' % (prec.cr2, phys_block.address))
                #        phys_addr = phys_block.address
                  
                if phys_block is not None:  
                    phys_addr = phys_block.address
                    if tid in self.pending_double_faults:
                        self.pending_double_faults[tid].cancel()
                        del self.pending_double_faults[tid]
                    #self.lgr.debug('pageFaultGen modeChanged remove pending fault for %s phys_addr 0x%x' % (tid, phys_addr))
                    del self.pending_faults[tid]
                    if self.ptable_hap is not None:
                        hap = self.ptable_hap
                        SIM_run_alone(self.rmPtableHap, hap)
                        RES_delete_breakpoint(self.ptable_break)
                        self.ptable_hap = None
                    if self.pdir_hap is not None:
                        hap = self.pdir_hap
                        SIM_run_alone(self.rmPDirHap, hap)
                        self.pdir_hap = None

                elif not self.cpu.architecture.startswith('arm'):
                    ''' TBD handle reflection of segv to user space for arm? '''
                    instruct = SIM_disassemble_address(self.cpu, self.user_eip, 1, 0)
                   
                    if self.mem_utils.isKernel(prec.cr2): 
                        self.lgr.debug('pageFaultGen modeChanged fault addr 0x%x is in kernel, we are now user space and still not mapped??' % prec.cr2)

                    if instruct[1].startswith('push') or 'sp' in instruct[1] or instruct[1].startswith('call'):
                        ''' growing stack  TBD what about call to reg whose value is corrupted?'''
                        #self.lgr.debug('pageFaultGen modeChanged fault addr 0x%x instruct is stack or something related: %s' % (prec.cr2, instruct[1]))
                        del self.pending_faults[tid]
                    elif self.mem_utils.isKernel(self.user_eip):
                        self.lgr.debug('pageFaultHap tid:%s user_eip: 0x%x is kernel.  TBD misses kernel ref to passed pointers' % (tid, self.user_eip))
                        del self.pending_faults[tid]
                    elif tid not in self.pending_double_faults:
                        if len(self.pending_double_faults) > 0:
                            self.lgr.error('pageFaultGen have two pending double faults TBD fix this')
                            return
                        self.pending_double_faults[tid] = self.cycle_event_callback
                        self.cycle_event_callback.setCallback(0xfff, self.cycleCallbackFunction, tid)
                        self.lgr.debug('pageFaultGen modeChanged in user space but 0x%x still not mapped. Instruct %s.  Watch for double fault cycle now 0x%x' % (prec.cr2, instruct[1], self.cpu.cycles))
                    else:
                        self.lgr.debug('pageFaultGen modeChanged in user space but 0x%x still not mapped, DOUBLE fault. Instruct %s' % (prec.cr2, instruct[1]))
                        SIM_run_alone(self.hapAlone, self.pending_faults[tid])
                        SIM_run_alone(self.rmModeHapAlone, None) 
                        #SIM_break_simulation('remove this')
                else:
                    pass
                    #if self.user_eip is not None:
                    #    instruct = SIM_disassemble_address(self.cpu, self.user_eip, 1, 0)
                    #    self.lgr.debug('pageFaultGen modeChanged arm user space instruct %s' % instruct[1])
                    #else:
                    #    self.lgr.debug('pageFaultGen modeChanged arm user space user_eip None')
                    
            if len(self.pending_faults) == 0:
                SIM_run_alone(self.rmModeHapAlone, None) 


    def pageFaultHapAlone(self, hack_rec):
        compat32, page_info, prec = hack_rec 
        ''' TBD FIX ME'''
        if False and self.debugging_tid is None:
            #SIM_run_alone(self.watchExit, compat32)
            #self.lgr.debug('pageFaultGen pageFaultHapAlone')
            self.watchExit(compat32)
            ''' Rely on ContextManager to watch for task kills if debugging -- and not '''
            # TBD fix for ability to watch full system for segv
            #self.context_manager.watchExit()
        if not page_info.page_exists:
            if self.cpu.architecture == 'ppc32':
                self.watchPteg(page_info, prec)
            elif page_info.ptable_addr is None:
                self.lgr.debug('pageFaultGen pageFaultHapAlone ptable_addr is None? %s' % page_info.valueString())

            elif not page_info.ptable_exists:
                if page_info.ptable_addr is not None:
                    #self.lgr.debug('watch pdir address of 0x%x' % page_info.pdir_addr)
                    #self.lgr.debug('watch pdir address of 0x%x' % page_info.ptable_addr)
                    self.watchPdir(page_info.ptable_addr, prec)
                else:
                    #self.lgr.debug('pageFaultGen pageFaultHapAlone ptable_addr was None')
                    self.watchPdir(page_info.pdir_addr, prec)
            elif page_info.phys_addr is not None:
                #self.lgr.debug('watch ptable address of 0x%x' % page_info.ptable_addr)
                #self.lgr.debug('watch ptable address of 0x%x' % page_info.phys_addr)
                self.watchPtable(page_info.phys_addr, prec)
            elif page_info.ptable_addr is not None:
                #self.lgr.debug('pageFaultGen pageFaultHapAlone phys_addr was None')
                self.watchPtable(page_info.ptable_addr, prec)
            elif not self.top.isWindows(target=self.target):
                self.lgr.error('pageFaultGen pageFaultHapAlone got zilch')


    def watchPageFaults(self, tid=None, compat32=False, afl=False):
        if self.fault_hap1 is not None or self.fault_hap is not None:
            self.lgr.debug('pageFaultGen watchPageFaults, already watching, do reset.  current context %s' % self.cpu.current_context)
            self.stopWatchPageFaults(tid=tid)
            #return
        self.afl = afl
        #if self.top.isWindows(target=self.target):
        #    ''' TBD fix for windows '''
        #    return 
        self.debugging_tid = tid
        ''' TBD explain why arm only uses faultCallback yet x86 also uses pageFaultHap '''
        if self.cpu.architecture == 'arm':
            
            #self.lgr.debug('watchPageFaults set break at page_fault 0x%x and data_abort 0x%x' % (self.param.page_fault, self.param.data_abort))
            #note page_fault is prefech abort 
            proc_break = self.context_manager.genBreakpoint(None, Sim_Break_Linear, Sim_Access_Execute, self.param.page_fault, self.mem_utils.WORD_SIZE, 0)
            proc_break2 = self.context_manager.genBreakpoint(None, Sim_Break_Linear, Sim_Access_Execute, self.param.data_abort, self.mem_utils.WORD_SIZE, 0)
            self.fault_hap = self.context_manager.genHapRange("Core_Breakpoint_Memop", self.pageFaultHap, compat32, proc_break, proc_break2, name='watchPageFaults')
           
            undefined_instruction = 5
            #self.fault_hap1 = RES_hap_add_callback_obj_range("Core_Exception", self.cpu, 0,
            #         self.faultCallback, self.cpu, 0, 13) 
            self.fault_hap1 = RES_hap_add_callback_obj_index("Core_Exception", self.cpu, 0,
                     self.faultCallback, self.cpu, undefined_instruction) 
            #self.lgr.debug('pageFaultGen watching Core_Exception faults')
        elif self.cpu.architecture == 'arm64':
            self.lgr.debug('watchPageFaults set break at at arm entry 0x%x' % self.param.arm_entry)
            proc_break = self.context_manager.genBreakpoint(None, Sim_Break_Linear, Sim_Access_Execute, self.param.arm64_entry, self.mem_utils.WORD_SIZE, 0)
            self.fault_hap = self.context_manager.genHapIndex("Core_Breakpoint_Memop", self.pageFaultHap, compat32, proc_break, name='watchPageFaults')
            self.fault_hap1 = RES_hap_add_callback_obj_range("Core_Exception", self.cpu, 0,  self.faultCallback, self.cpu, 3, 5) 
        elif self.cpu.architecture == 'ppc32':
            proc_break = self.context_manager.genBreakpoint(None, Sim_Break_Linear, Sim_Access_Execute, self.param.page_fault, 1, 0)
            proc_break2 = self.context_manager.genBreakpoint(None, Sim_Break_Linear, Sim_Access_Execute, self.data_storage_fault, self.mem_utils.WORD_SIZE, 0)
            self.fault_hap = self.context_manager.genHapRange("Core_Breakpoint_Memop", self.pageFaultHapPPC32, compat32, proc_break, proc_break2, name='watchPageFaults')
            self.lgr.debug('watchPageFaults ppc32break at 0x%x  and 0x%x tid %s current context %s' % (self.param.page_fault, self.data_storage_fault, tid, self.cpu.current_context))
        else:
            #self.lgr.debug('watchPageFaults not arm set break at 0x%x tid %s current context %s' % (self.param.page_fault, tid, self.cpu.current_context))
            proc_break = self.context_manager.genBreakpoint(None, Sim_Break_Linear, Sim_Access_Execute, self.param.page_fault, 1, 0)
            self.fault_hap = self.context_manager.genHapIndex("Core_Breakpoint_Memop", self.pageFaultHap, compat32, proc_break, name='watchPageFaults')
            ''' TBD catch illegal instruction '''
            #max_intr = 255
            undefined_instruction = 6
            self.fault_hap1 = RES_hap_add_callback_obj_index("Core_Exception", self.cpu, 0,
                     self.faultCallback, self.cpu, undefined_instruction)
            #self.fault_hap2 = RES_hap_add_callback_obj_range("Core_Exception", self.cpu, 0,
            #     self.faultCallback, self.cpu, 15, max_intr) 
        self.loadProbes()

    def recordFault(self, tid, eip):
        if tid not in self.faulting_cycles:
            self.faulting_cycles[tid] = {} 
        if eip not in self.faulting_cycles[tid]:
            self.faulting_cycles[tid][eip] = []
        self.faulting_cycles[tid][eip].append(self.cpu.cycles)
        #self.lgr.debug('recordFault tid:%s eip 0x%x cycles 0x%x' % (tid, eip, self.cpu.cycles))


    def faultCallback(self, cpu, one, exception_number):
        ''' Called when an undefined instruction exception is hit '''
        cell_name = self.top.getTopComponentName(cpu)
        cpu, comm, tid = self.task_utils.curThread() 
        name = self.cpu.iface.exception.get_name(exception_number)
        eip = self.mem_utils.getRegValue(cpu, 'pc')
        instruct = SIM_disassemble_address(self.cpu, eip, 1, 0)
        #self.lgr.debug('faultCallback %s  (%d)  tid:%s (%s)  eip: 0x%x %s cycle: 0x%x' % (name, 
        #        exception_number, tid, comm, eip, instruct[1], cpu.cycles))
        prec = Prec(self.cpu, comm, tid=tid, eip=eip, name=name)
        self.pending_sigill[tid] = prec
        # record cycle and eip for reversing back to user space    
        self.recordFault(tid, eip)

    def stopWatchPageFaults(self, tid = None, immediate=False):
        if self.fault_hap is not None:
            #self.lgr.debug('stopWatchPageFaults delete fault_hap')
            self.context_manager.genDeleteHap(self.fault_hap, immediate=immediate)
            self.fault_hap = None
        if self.fault_hap1 is not None:
            #self.lgr.debug('stopWatchPageFaults delete fault_hap1')
            RES_hap_delete_callback_id("Core_Exception", self.fault_hap1)
            self.fault_hap1 = None
        if self.fault_hap2 is not None:
            #self.lgr.debug('stopWatchPageFaults delete fault_hap2')
            RES_hap_delete_callback_id("Core_Exception", self.fault_hap2)
            self.fault_hap2 = None
        if tid is not None:
            if tid in self.exit_hap: 
                #self.lgr.debug('stopWatchPageFaults delete exit_hap')
                self.context_manager.genDeleteHap(self.exit_hap[tid], immediate=immediate)
                self.context_manager.genDeleteHap(self.exit_hap2[tid], immediate=immediate)
                del self.exit_break[tid]
                del self.exit_hap[tid]
                del self.exit_hap2[tid]
        #self.lgr.debug('pageFaultGen stopWatchPageFaults before clear len is %s' % len(self.pending_faults))
        self.faulted_pages.clear()
        #self.faulting_cycles.clear()
        self.pending_faults.clear()
        self.pending_sigill.clear()
        self.pending_double_faults.clear()
        if self.mode_hap is not None:
            self.lgr.debug('pageFaultGen stopWatchPageFaults remove mode hap')
            RES_hap_delete_callback_id("Core_Mode_Change", self.mode_hap)
            self.mode_hap = None

    def clearFaultingCycles(self):
        self.faulting_cycles.clear()

    def exitHap2(self, prec, third, forth, memory):
        self.exitHap(prec, third, forth, memory)

    def exitHap(self, prec, third, forth, memory):
        #cpu = SIM_current_processor()
        #if cpu != prec.cpu:
        #    self.lgr.debug('exitHap, wrong cpu %s %s' % (cpu.name, hap_cpu.name))
        #    return
        #self.lgr.debug('pageFaultGen exitHap')
        cpu, comm, tid = self.task_utils.curThread() 
        if tid != prec.tid and prec.tid in self.exit_break:
            self.lgr.debug('exitHap wrong tid:%s expected %s' % (tid, prec.tid))
            return
        self.rmExit(tid)

    def watchExit(self, compat32=False):
        ''' tell context manager to not break on process kill '''
        self.context_manager.watchPageFaults(True)
        cpu, comm, tid = self.task_utils.curThread() 
        prec = Prec(cpu, comm, tid)
        callnum = self.task_utils.syscallNumber('exit_group', compat32)
        exit_group = self.task_utils.getSyscallEntry(callnum, compat32)
        self.exit_break[tid] = self.context_manager.genBreakpoint(None, Sim_Break_Linear, Sim_Access_Execute, exit_group, self.mem_utils.WORD_SIZE, 0)
        callnum = self.task_utils.syscallNumber('exit', compat32)
        exit = self.task_utils.getSyscallEntry(callnum, compat32)
        self.exit_break2[tid] = self.context_manager.genBreakpoint(None, Sim_Break_Linear, Sim_Access_Execute, exit, self.mem_utils.WORD_SIZE, 0)
        self.exit_hap[tid] = self.context_manager.genHapIndex("Core_Breakpoint_Memop", self.exitHap, prec, self.exit_break[tid], name='watchExit')
        self.exit_hap2[tid] = self.context_manager.genHapIndex("Core_Breakpoint_Memop", self.exitHap2, prec, self.exit_break2[tid], name='watchExit2')
        #self.lgr.debug('pageFaultGen watchExit set breaks %d %d for tid:%s at 0x%x 0x%x' % (self.exit_break[tid], self.exit_break2[tid], tid, exit_group, exit))

    def skipAlone(self, prec):
        ''' page fault caught in kernel, back up to user space?  '''
        ''' TBD what about segv generated within kernel '''
       
        self.lgr.debug('pageFaultGen skipAlone')
        if self.top.hasBookmarks() and self.top.reverseEnabled():
            self.lgr.debug('pageFaultGen skipAlone to cycle 0x%x' % prec.cycles) 
            target_cycles = prec.cycles
            print('skipping back to user space, please wait.')
            if not self.top.skipToCycle(target_cycles, self.cpu, disable=True):
                return
            print('Completed skip.')
            eip = self.mem_utils.getRegValue(self.cpu, 'pc')
            if eip != prec.eip:
                if not self.top.skipToCycle(target_cycles-1, self.cpu, disable=True):
                    return
                cur_eip = self.mem_utils.getRegValue(self.cpu, 'pc')
                self.lgr.warning('pageFaultGen skipAlone, wrong eip is 0x%x wanted 0x%x, skipped again, now eip is 0x%x' % (eip, prec.eip, cur_eip))
                eip = cur_eip
            if self.mem_utils.isKernel(eip):
                target_cycles = self.cpu.cycles - 1
                if not self.top.skipToCycle(target_cycles, self.cpu, disable=True):
                    return
                else:
                    cur_eip = self.mem_utils.getRegValue(self.cpu, 'pc')
                    self.lgr.debug('pageFaultGen skipAlone landed in kernel 0x%x, backed up one to 0x%x eip:0x%x' % (eip, target_cycles, cur_eip))
                    if cur_eip == eip: 
                        self.lgr.debug('pageFaultGen skipAlone same eip, back up more')
                        target_cycles = self.cpu.cycles - 1
                        if not self.top.skipToCycle(target_cycles, self.cpu, disable=True):
                            return
                        
                        cur_eip = self.mem_utils.getRegValue(self.cpu, 'pc')
                        self.lgr.debug('pageFaultGen skipAlone after another backup, eip is 0x%x' % (cur_eip))
                    elif self.mem_utils.isKernel(cur_eip):
                        target_cycles = self.cpu.cycles - 1
                        if not self.top.skipToCycle(target_cycles, self.cpu, disable=True):
                            return
                        cur_eip = self.mem_utils.getRegValue(self.cpu, 'pc')
                        self.lgr.debug('pageFaultGen still in kernel after back one, after another backup, eip is 0x%x' % (cur_eip))
    
            if prec.fsr is not None and prec.fsr == 2:            
                self.top.setDebugBookmark('Unhandled fault: External abort? on access to 0x%x' % prec.cr2)
            else:
                print('SEGV access to 0x%x' % prec.cr2)
                self.top.setDebugBookmark('SEGV access to 0x%x' % prec.cr2)
            self.context_manager.resetWatchTasks()
        else:
            print('SEGV with no bookmarks.  Not yet debugging?')
            self.lgr.debug('SEGV with no bookmarks.  Not yet debugging?')
        self.lgr.debug('pageFaultGen call to stop trackIO and then skip and mail')
        self.stopWatchPageFaults()
        self.top.stopTracking()
        self.top.skipAndMail(restore_debug=False)

    def stopAlone(self, prec):
        self.top.RES_delete_stop_hap(self.stop_hap)
        self.stop_hap = None
        self.context_manager.setIdaMessage('SEGV access to memory 0x%x' % prec.cr2)
        self.lgr.debug('SEGV access to memory 0x%x' % prec.cr2)
        SIM_run_command('pselect %s' % self.cpu.name)
        SIM_run_alone(self.skipAlone, prec)

    def stopHap(self, prec, one, exception, error_string):
        if self.stop_hap is None:
            return 
        self.lgr.debug('pageFaultGen stopHap')
        SIM_run_alone(self.stopAlone, prec)


    def recordPageFaults(self):
        ''' REPLACED by moving logic into fault callback '''
        self.lgr.debug('recordPageFaults')
        if self.cpu.architecture == 'arm':
            prefetch_fault = 4
            data_fault = 1
            self.exception_hap = RES_hap_add_callback_obj_index("Core_Exception", self.cpu, 0,
                     self.pageExceptionHap, self.cpu, prefetch_fault)
            self.exception_hap2 = RES_hap_add_callback_obj_index("Core_Exception", self.cpu, 0,
                     self.pageExceptionHap, self.cpu, data_fault)
        else:
            page_fault = 14
            self.exception_hap = RES_hap_add_callback_obj_index("Core_Exception", self.cpu, 0,
                     self.pageExceptionHap, self.cpu, page_fault)

    def stopPageFaults(self):
        if self.exception_hap is not None:
            self.lgr.debug('stopPageFaults delete excption_hap')
            RES_hap_delete_callback_id("Core_Exception", self.exception_hap)
            self.exception_hap = None
        if self.exception_hap2 is not None:
            self.lgr.debug('stopPageFaults delete excption_hap2')
            RES_hap_delete_callback_id("Core_Exception", self.exception_hap2)
            self.exception_hap2 = None

    def pageExceptionHap(self, cpu, one, exception_number):
        ''' used by recordPageFaults '''
        eip = self.mem_utils.getRegValue(cpu, 'eip')
        self.lgr.debug('pageExceptionHap eip 0x%x cycles 0x%x' % (eip, cpu.cycles))
        if self.exception_hap is None:
            return
        if self.debugging_tid is not None:
            cpu, comm, tid = self.task_utils.curThread() 
            if tid not in self.faulting_cycles:
                self.faulting_cycles[tid] = {} 
            if eip not in self.faulting_cycles[tid]:
                self.faulting_cycles[tid][eip] = []
            self.faulting_cycles[tid][eip].append(cpu.cycles)
            self.lgr.debug('pageExceptionHap tid:%s eip 0x%x cycles 0x%x' % (tid, eip, cpu.cycles))
        self.exception_eip = eip
        '''
        if cpu.architecture == 'arm':
            #reg_num = cpu.iface.int_register.get_number("combined_data_far")
            #dfar = cpu.iface.int_register.read(reg_num)
            #reg_num = cpu.iface.int_register.get_number("instruction_far")
            #ifar = cpu.iface.int_register.read(reg_num)
            cpu, comm, tid = self.task_utils.curThread() 
            name = cpu.iface.exception.get_name(exception_number)
            instruct = SIM_disassemble_address(self.cpu, eip, 1, 0)
            #self.lgr.debug('pageExceptionHap tid:%s eip: 0x%x faulting cycles 0x%x' % (tid, eip, self.cpu.cycles))
            #self.lgr.debug('pageExceptionHap %s  (%d)  tid:%s (%s)  eip: 0x%x %s ifar: 0x%x dfar: 0x%x' % (name, 
            #  exception_number, tid, comm, eip, instruct[1], ifar, dfar))
            #if eip == 0xc013fea8:
            #    SIM_break_simulation('Data Abort')
        else:
            cpu, comm, tid = self.task_utils.curThread() 
            #self.lgr.debug('pageExceptionHap tid:%s (%s) eip 0x%x' % (tid, comm, eip))
        '''

    def getFaultingCycles(self, tid):
        if tid in self.faulting_cycles:
            return self.faulting_cycles[tid] 
        else:
            return {}

    def handleExit(self, tid, leader, report_only=False):
        ''' We believe a process has been killed.  Determine if three is a pending page fault. 
            If the tid is within a thread group, look at all threads for most recent reference, assuming a 
            true fault is handled without rescheduling. 
            Return True if we think a segv occured
        '''
        retval = False
        self.lgr.debug('pageFaultGen handleExit tid:%s leader:%s len of pending_faults %d' % (tid, str(leader), len(self.pending_faults)))
        if len(self.pending_faults) > 0:
            thread_group = self.task_utils.getGroupTids(tid)
            recent_cycle = 0
            recent_tid = None
            for pending_tid in self.pending_faults:
                if pending_tid not in thread_group:
                    continue
                self.lgr.debug('compare pending_tid:%s cycle 0x%x to recent 0x%x' % (pending_tid, self.pending_faults[pending_tid].cycles, recent_cycle))
                if self.pending_faults[pending_tid].cycles > recent_cycle:
                    # TBD weak algorithm for determining which thread is a fault
                    if recent_tid is None or not self.mem_utils.isKernel(self.pending_faults[pending_tid].eip):
                        recent_cycle = self.pending_faults[pending_tid].cycles
                        recent_tid = pending_tid
            if recent_tid == tid or tid == leader or leader is None: 
                if self.pending_faults[recent_tid].page_fault:
                    self.lgr.debug('pageFaultGen handleExit tid:%s has pending fault.  SEGV?' % recent_tid)
                else:
                    self.lgr.debug('pageFaultGen handleExit tid:%s has pending fault.  %s' % (recent_tid, self.pending_faults[recent_tid].name))
                if not report_only:
                    if self.top.isRunning():
                        self.lgr.debug('pageFaultGen handleExit, is running, call hapAlone')
                        SIM_run_alone(self.hapAlone, self.pending_faults[recent_tid])
                    else:
                        prec = self.pending_faults[recent_tid]
                        self.lgr.debug('pageFaultGen handleExit, not running, call skipAlone')
                        self.skipAlone(prec)
                    # this cleanup should happen after the haps ??
                    self.pending_faults = {}
                    self.stopPageFaults()
                    self.stopWatchPageFaults()
                    retval = True
                else:
                    self.lgr.debug('pageFaultGen handleExit report_only')
                    prec = self.pending_faults[recent_tid]
                    if prec.page_fault:
                        self.lgr.debug('SEGV access to memory 0x%x cycle: 0x%x' % (prec.cr2, prec.cycles))
                        print('SEGV access to memory 0x%x cycles: 0x%x' % (prec.cr2, prec.cycles))
                    else:
                        self.lgr.debug('pageFaultGen handleExit fault %s eip: 0x%x cycle: 0x%x' % (prec.name, prec.eip, prec.cycles))
                        print('Fault %s tid:%s eip: 0x%x cycle: 0x%x' % (prec.name, tid, prec.eip, prec.cycles))
            else:
                self.lgr.debug('pageFaultGen handleExit confused, recent_tid %s, tid %s' % (recent_tid, tid))
        if retval:
            msg = 'tid:%s Thread exit.  SEGV.\n' % tid
        else:
            msg = 'tid:%s Thread exit.\n' % tid
        self.lgr.debug('pageFaultGen call top.traceWrite with %s' % msg)
        self.top.traceWrite(msg) 
                    
        return retval

    def hasPendingPageFault(self, tid):
        retval = False
        if tid in self.pending_faults:
            prec = self.pending_faults[tid]
            if prec.page_fault:
                self.lgr.debug('pageFaultGen hasPendingFault tid:%s fault: %s pending page fault cr2 0x%x cycle: 0x%x' % (tid, prec.name, prec.cr2, prec.cycles))
                retval = True
            else:
                self.lgr.debug('pageFaultGen hasPendingFault tid:%s fault: %s pending fault eip 0x%x' % (tid, prec.name, prec.eip))
        #else:
        #    self.lgr.debug('pageFaultGen hasPendingFault NO pending fault for tid:%s' % tid)
        return retval

    def getPendingFault(self, tid):
        if tid in self.pending_faults:
            return self.pending_faults[tid]
        else:
            return None

    def getPendingFaultCycle(self, tid):
        if tid in self.pending_faults:
            return self.pending_faults[tid].cycles
        else:
            return None

    def addProbe(self, probe):
        self.ignore_probes.append(probe)

    def loadProbes(self):
        fname = '%s.probes' % self.target
        if os.path.isfile(fname):
            with open(fname) as fh:
                for line in fh:
                    if line.strip().startswith('#'):
                        continue
                    try:
                        probe = int(line.strip(), 16)
                    except:
                        self.lgr.error('pageFaultGen bad line in %s %s' % (fname, line))
                        continue     
                    if probe not in self.ignore_probes:
                        self.ignore_probes.append(probe)
                        #self.lgr.debug('pageFaultGen added probe 0x%x' % probe)
        
    def cycleCallbackFunction(self, tid):
        self.lgr.debug('pageFaultGen cycleCallback assume dump or such')
        if self.afl:
            SIM_run_alone(self.rmModeHapAlone, None) 
            self.lgr.debug('pageFaultGen cycleCallbackFunction afl, stop')
            self.handleExit(tid, tid, report_only=True)
            SIM_break_simulation('cycleCallbackFunction')
        else:
            SIM_run_alone(self.hapAlone, self.pending_faults[tid])
            SIM_run_alone(self.rmModeHapAlone, None) 

    def clearPendingFaults(self):
        self.pending_faults.clear()
        self.pending_sigill.clear()
        self.pending_double_faults.clear()
