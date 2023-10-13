from simics import *
import os
import memUtils
import pageUtils
import hapCleaner
import resimUtils
from resimHaps import *
'''
Watch page faults for indications of a SEGV exception
'''
class Prec():
    def __init__(self, cpu, comm, tid=None, cr2=None, eip=None, name=None, fsr=None):
        self.cpu = cpu
        self.comm = comm
        self.tid = tid
        self.cr2 = cr2
        self.eip = eip
        self.name = name
        self.fsr = fsr
        self.cycles = cpu.cycles

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
        self.mode_hap = None
        self.ignore_probes = []
        self.user_eip = None
        ''' hack to tell context manager to call back to PageFaultGen on context switches to watched processes '''
        context_manager.callMe(self)

    def rmExit(self, tid):
        if tid in self.exit_break:
            self.context_manager.genDeleteHap(self.exit_hap[tid])
            self.context_manager.genDeleteHap(self.exit_hap2[tid])
            del self.exit_break[tid]
            del self.exit_hap[tid]
            del self.exit_hap2[tid]
        self.context_manager.watchPageFaults(False)
        if tid in self.pending_faults:
            #self.lgr.debug('pageFaultGen rmExit remove pending for %d %s' % (tid, str(self.pending_faults[tid])))
            del self.pending_faults[tid]
        
    def rmPDirHap(self, hap):
        RES_hap_delete_callback_id('Core_Breakpoint_Memop', hap)
        RES_delete_breakpoint(self.pdir_break)

    def pdirWriteHap(self, prec, third, forth, memory):
        pdir_entry = SIM_get_mem_op_value_le(memory)
        cpu, comm, tid = self.task_utils.curThread() 
        #self.lgr.debug('pageFaultGen dirWriteHap, %d (%s) new entry value 0x%x set by tid:%s' % (tid, comm, pdir_entry, prec.tid))
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
        pcell = self.cpu.physical_memory
        #self.pdir_break = self.context_manager.genBreakpoint(pcell, Sim_Break_Physical, Sim_Access_Write, pdir_addr, self.page_entry_size, 0)
        self.pdir_break = SIM_breakpoint(pcell, Sim_Break_Physical, Sim_Access_Write, pdir_addr, self.page_entry_size, 0)
        #self.lgr.debug('pageFaultGen watchPdir tid: %d break %d at 0x%x' % (prec.tid, self.pdir_break, pdir_addr))
        #self.pdir_hap = self.context_manager.genHapIndex("Core_Breakpoint_Memop", self.pdirWriteHap, prec, self.pdir_break, name='watchPdir')
        self.pdir_hap = RES_hap_add_callback_index("Core_Breakpoint_Memop", self.pdirWriteHap, prec, self.pdir_break)

    def rmPtableHap(self, hap):
        RES_hap_delete_callback_id('Core_Breakpoint_Memop', hap)
        RES_delete_breakpoint(self.ptable_break)

    def ptableWriteHap(self, prec, third, forth, memory):
        ptable_entry = SIM_get_mem_op_value_le(memory)
        cpu, comm, tid = self.task_utils.curThread() 
        #self.lgr.debug('pageFaultGen tableWriteHap, %d (%s) new entry value 0x%x was set for tid: %d' % (tid, comm, ptable_entry, prec.tid))
        if self.ptable_break is not None:
            hap = self.ptable_hap
            SIM_run_alone(self.rmPtableHap, hap)
            #self.lgr.debug('pageFaultGen ptableWrite delete bp %d' % self.ptable_break)
            self.ptable_hap = None
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
  
    def hapAlone(self, prec):
        self.top.removeDebugBreaks()
       
        self.stop_hap = RES_hap_add_callback("Core_Simulation_Stopped", self.stopHap, prec)
        self.lgr.debug('pageFaultGen hapAlone set stop hap, now stop?')
        self.top.undoDebug(None)
        SIM_break_simulation('SEGV, task rec for %d (%s) modified mem reference was 0x%x' % (prec.tid, prec.comm, prec.cr2))
 
    def pageFaultHap(self, compat32, third, forth, memory):
        ''' Invoked when the kernel's page fault entry point is hit'''
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
        cpu, comm, tid = self.task_utils.curThread() 
        sp = self.mem_utils.getRegValue(cpu, 'sp')

        user_ip_addr = sp + self.mem_utils.WORD_SIZE
        self.user_eip = self.mem_utils.readWord(self.cpu, user_ip_addr)
        if self.user_eip in self.ignore_probes:
            self.lgr.debug('pageFaultHap user eip: 0x%x in probes, ignore' % self.user_eip)
            return
        eip = self.mem_utils.getRegValue(cpu, 'pc')
        #self.lgr.debug('pageFaultHap tid:%s eip: 0x%x cycle 0x%x' % (tid, eip, self.cpu.cycles))
        if not self.context_manager.watchingThis():
            #self.lgr.debug('pageFaultHap tid:%s, contextManager says not watching' % tid)
            return
        if self.exception_eip is None:
            eip = self.mem_utils.getRegValue(cpu, 'pc')
            #self.lgr.debug('pageFaultHap exception_eip was none, use current 0x%x' % eip)
        else:
            eip = self.exception_eip
        cur_pc = self.mem_utils.getRegValue(cpu, 'pc')
        access_type = None
        if self.cpu.architecture == 'arm':
            if cur_pc == self.param.page_fault:
                ''' prefetch abort '''
                reg_num = None
            else:
                reg_num = self.cpu.iface.int_register.get_number("combined_data_far")
                data_fault_reg = self.cpu.iface.int_register.get_number("combined_data_fsr")
                fault = self.cpu.iface.int_register.read(data_fault_reg)
                access_type = memUtils.testBit(fault, 11)
                #self.lgr.debug('data fault tid:%s reg value 0x%x  violation type: %d' % (tid, fault, access_type))
        else:
            reg_num = self.cpu.iface.int_register.get_number("cr2")
        if reg_num is not None:
            cr2 = self.cpu.iface.int_register.read(reg_num)
            #self.lgr.debug('pageFaultHap cr2 read is 0x%x' % cr2)
        else:
            #self.lgr.debug('pageFaultHap cr2 set to eip 0x%x' % eip)
            cr2 = eip

        if tid not in self.faulted_pages:
            self.faulted_pages[tid] = []
        if cr2 in self.faulted_pages[tid]:
            #self.lgr.debug('pageFaultHap, addr 0x%x already handled for tid:%s cur_pc: 0x%x' % (cr2, tid, cur_pc))
            return
        self.faulted_pages[tid].append(cr2)
        #self.lgr.debug('pageFaultHapAlone for %d (%s)  faulting address: 0x%x eip: 0x%x cycle: 0x%x context:%s' % (tid, comm, cr2, cur_pc, self.cpu.cycles, self.cpu.current_context))
        #self.lgr.debug('pageFaultHap for %d (%s) at 0x%x  faulting address: 0x%x' % (tid, comm, eip, cr2))
        #self.lgr.debug('len of faulted pages is now %d' % len(self.faulted_pages))
        if cpu.architecture == 'arm':
            page_info = pageUtils.findPageTableArm(self.cpu, cr2, self.lgr)
        elif pageUtils.isIA32E(cpu):
            page_info = pageUtils.findPageTableIA32E(self.cpu, cr2, self.lgr)
        else:
            page_info = pageUtils.findPageTable(self.cpu, cr2, self.lgr)
        prec = Prec(self.cpu, comm, tid, cr2, cur_pc)
        if tid not in self.pending_faults:
            self.pending_faults[tid] = prec
            #self.lgr.debug('pageFaultHap add pending fault for %d addr 0x%x cycle 0x%x' % (tid, prec.cr2, prec.cycles))
            if self.mode_hap is None:
                #self.lgr.debug('pageFaultGen adding mode hap')
                self.mode_hap = RES_hap_add_callback_obj("Core_Mode_Change", cpu, 0, self.modeChanged, tid)
        hack_rec = (compat32, page_info, prec)
        SIM_run_alone(self.pageFaultHapAlone, hack_rec)

    def rmModeHapAlone(self, dumb):
        #self.lgr.debug('last fault, remove hap')
        if self.mode_hap is not None:
            RES_hap_delete_callback_id("Core_Mode_Change", self.mode_hap)
            self.mode_hap = None

    def modeChanged(self, want_tid, one, old, new):
        if self.mode_hap is None:
            return
        cpu, comm, tid = self.task_utils.curThread() 
        if tid != want_tid:
            #self.lgr.debug('pageFaultGen modeChanged wrong tid  tid:%s wanted: %d old: %d new: %d' % (tid, want_tid, old, new))
            return

        #self.lgr.debug('pageFaultGen modeChanged tid:%s wanted: %s old: %d new: %d' % (tid, want_tid, old, new))
        if new != Sim_CPU_Mode_Supervisor:
            #self.lgr.debug('pageFaultGen modeChanged user space')
            if tid in self.pending_faults:
                #self.lgr.debug('pageFaultGen modeChanged user space, was a pending fault for addr 0x%x' % self.pending_faults[tid].cr2)
                prec = self.pending_faults[tid]
                phys_block = cpu.iface.processor_info.logical_to_physical(prec.cr2, Sim_Access_Read)
                if phys_block.address is not None and phys_block.address != 0:
                    #self.lgr.debug('pageFaultGen modeChanged in user space  0x%x mapped to 0x%x' % (prec.cr2, phys_block.address))
                    del self.pending_faults[tid]
                    if self.ptable_hap is not None:
                        hap = self.ptable_hap
                        SIM_run_alone(self.rmPtableHap, hap)
                        self.ptable_hap = None
                    if self.pdir_hap is not None:
                        hap = self.pdir_hap
                        SIM_run_alone(self.rmPDirHap, hap)
                        self.pdir_hap = None
                elif self.cpu.architecture != 'arm':
                    ''' TBD handle reflection of segv to user space for arm? '''
                    instruct = SIM_disassemble_address(self.cpu, self.user_eip, 1, 0)
                    if instruct[1].startswith('push'):
                        ''' growing stack '''
                        del self.pending_faults[tid]
                    else:
                        #self.lgr.debug('pageFaultGen modeChanged in user space but 0x%x still not mapped' % prec.cr2)
                        SIM_run_alone(self.hapAlone, self.pending_faults[tid])
                        SIM_run_alone(self.rmModeHapAlone, None) 
                        #SIM_break_simulation('remove this')
                else:
                    instruct = SIM_disassemble_address(self.cpu, self.user_eip, 1, 0)
                    self.lgr.debug('pageFaultGen modeChanged arm user space instruct %s' % instruct[1])
                    
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

            if not page_info.ptable_exists:
                if page_info.ptable_addr is not None:
                    #self.lgr.debug('watch pdir address of 0x%x' % page_info.pdir_addr)
                    #self.lgr.debug('watch pdir address of 0x%x' % page_info.ptable_addr)
                    self.watchPdir(page_info.ptable_addr, prec)
                else:
                    #self.lgr.debug('pageFaultGen pageFaultHapAlone ptable_addr was None')
                    self.watchPdir(page_info.pdir_addr, prec)
            elif page_info.page_addr is not None:
                #self.lgr.debug('watch ptable address of 0x%x' % page_info.ptable_addr)
                #self.lgr.debug('watch ptable address of 0x%x' % page_info.page_addr)
                self.watchPtable(page_info.page_addr, prec)
            elif page_info.ptable_addr is not None:
                #self.lgr.debug('pageFaultGen pageFaultHapAlone page_addr was None')
                self.watchPtable(page_info.ptable_addr, prec)
            elif not self.top.isWindows(target=self.target):
                self.lgr.error('pageFaultGen pageFaultHapAlone got zilch')


    def watchPageFaults(self, tid=None, compat32=False):
        if self.fault_hap1 is not None or self.fault_hap is not None:
            self.lgr.debug('pageFaultGen watchPageFaults, already watching, do reset.  current context %s' % self.cpu.current_context)
            self.stopWatchPageFaults(tid=tid)
            #return
        #if self.top.isWindows(target=self.target):
        #    ''' TBD fix for windows '''
        #    return 
        self.debugging_tid = tid
        ''' TBD explain why arm only uses faultCallback yet x86 also uses pageFaultHap '''
        if self.cpu.architecture == 'arm':
            '''
            self.lgr.debug('watchPageFaults set break at 0x%x' % self.param.page_fault)
            #note page_fault is prefech abort 
            proc_break = self.context_manager.genBreakpoint(self.cell, Sim_Break_Linear, Sim_Access_Execute, self.param.page_fault, self.mem_utils.WORD_SIZE, 0)
            proc_break2 = self.context_manager.genBreakpoint(self.cell, Sim_Break_Linear, Sim_Access_Execute, self.param.data_abort, self.mem_utils.WORD_SIZE, 0)
            self.fault_hap = self.context_manager.genHapRange("Core_Breakpoint_Memop", self.pageFaultHap, compat32, proc_break, proc_break2, name='watchPageFaults')
            '''
            max_intr = 255
            #self.fault_hap1 = RES_hap_add_callback_obj_range("Core_Exception", self.cpu, 0,
            #         self.faultCallback, self.cpu, 0, 13) 
            self.fault_hap1 = RES_hap_add_callback_obj_range("Core_Exception", self.cpu, 0,
                     self.faultCallback, self.cpu, 0, max_intr) 
            #self.lgr.debug('pageFaultGen watching Core_Exception faults')
        else:
            #self.lgr.debug('watchPageFaults not arm set break at 0x%x tid %s current context %s' % (self.param.page_fault, tid, self.cpu.current_context))
            proc_break = self.context_manager.genBreakpoint(None, Sim_Break_Linear, Sim_Access_Execute, self.param.page_fault, 1, 0)
            self.fault_hap = self.context_manager.genHapIndex("Core_Breakpoint_Memop", self.pageFaultHap, compat32, proc_break, name='watchPageFaults')
            ''' TBD catch illegal instruction '''
            max_intr = 255
            self.fault_hap1 = RES_hap_add_callback_obj_range("Core_Exception", self.cpu, 0,
                     self.faultCallback, self.cpu, 0, 13) 
            self.fault_hap2 = RES_hap_add_callback_obj_range("Core_Exception", self.cpu, 0,
                 self.faultCallback, self.cpu, 15, max_intr) 
        self.loadProbes()

    def recordFault(self, cpu, tid, eip):
        if tid not in self.faulting_cycles:
            self.faulting_cycles[tid] = {} 
        if eip not in self.faulting_cycles[tid]:
            self.faulting_cycles[tid][eip] = []
        self.faulting_cycles[tid][eip].append(cpu.cycles)
        #self.lgr.debug('pageExceptionHap tid:%s eip 0x%x cycles 0x%x' % (tid, eip, cpu.cycles))


    def faultCallback(self, cpu, one, exception_number):
        ''' invoked when a processor exception occurs.  Also see pageFaultHap'''
        if not self.context_manager.watchingThis():
            #self.lgr.debug('faultCallback, contextManager says not watching')
            return
        cell_name = self.top.getTopComponentName(cpu)
        cpu, comm, tid = self.task_utils.curThread() 
        name = cpu.iface.exception.get_name(exception_number)
        eip = self.mem_utils.getRegValue(cpu, 'pc')
        instruct = SIM_disassemble_address(self.cpu, eip, 1, 0)
        if cpu.architecture == 'arm':
            #self.lgr.debug('faultCallback %s  (%d)  tid:%s (%s)  eip: 0x%x %s cycle: 0x%x' % (name, 
            #    exception_number, tid, comm, eip, instruct[1], cpu.cycles))
            if exception_number == 4 or exception_number == 1 or exception_number == 5:
                if exception_number == 4:
                    # instruction_far fails on older arm, just use eip.
                    #reg_num = cpu.iface.int_register.get_number("instruction_far")
                    #ifar = cpu.iface.int_register.read(reg_num)
                    prec = Prec(self.cpu, comm, tid, eip, eip, name=name)
                elif exception_number == 5:
                    prec = Prec(self.cpu, comm, tid, eip, eip, name=name)
                else:
                    reg_num = cpu.iface.int_register.get_number("combined_data_far")
                    dfar = cpu.iface.int_register.read(reg_num)
                    reg_num = cpu.iface.int_register.get_number("combined_data_fsr")
                    fsr = cpu.iface.int_register.read(reg_num)
                    if fsr == 2:
                       cpu.iface.int_register.write(reg_num,1)
                       self.lgr.warning('hacked ARM fsr register from 2 to 1')
                    prec = Prec(self.cpu, comm, tid, dfar, eip, name=name, fsr=fsr)
                if tid not in self.pending_faults:
                    self.pending_faults[tid] = prec
                    #self.lgr.debug('faultCallback add pending fault for tid:%s addr 0x%x  fsr: %s eip: 0x%x cycle 0x%x' % (tid, prec.cr2, str(prec.fsr), eip, prec.cycles))
                    if self.mode_hap is None:
                        self.mode_hap = RES_hap_add_callback_obj("Core_Mode_Change", cpu, 0, self.modeChanged, tid)

                self.recordFault(cpu, tid, eip)
            
            #if (exception_number == 4 or exception_number == 1)and tid == 875:
            #    SIM_break_simulation('how?')
        else:
            reg_num = self.cpu.iface.int_register.get_number("cr2")
            cr2 = self.cpu.iface.int_register.read(reg_num)
            #self.lgr.debug('cr2 read is 0x%x' % cr2)
            if tid not in self.faulted_pages:
                self.faulted_pages[tid] = []
            if cr2 in self.faulted_pages[tid]:
                #self.lgr.debug('pageFaultHap, addr 0x%x already handled for tid:%s cur_pc: 0x%x' % (cr2, tid, cur_pc))
                return
            self.faulted_pages[tid].append(cr2)
            #self.lgr.debug('faultCallback %s  (%d)  tid:%s (%s)  eip: 0x%x %s' % (name, exception_number, tid, comm, eip, instruct[1]))
            prec = Prec(self.cpu, comm, tid, cr2, eip)
            if tid not in self.pending_faults:
                self.pending_faults[tid] = prec
                #self.lgr.debug('pageFaultHap add pending fault for %d addr 0x%x eip: 0x%x cycle 0x%x' % (tid, prec.cr2, eip, prec.cycles))
                if self.mode_hap is None:
                    self.mode_hap = RES_hap_add_callback_obj("Core_Mode_Change", cpu, 0, self.modeChanged, tid)
            self.recordFault(cpu, tid, eip)

    '''
    def faultReturnCallback(self, cpu, one, exception_number):
        cell_name = self.top.getTopComponentName(cpu)
        cpu, comm, tid = self.task_utils.curThread() 
        if exception_number != 7:
            #self.lgr.debug('fault_callback %d (%s) got fault 0x%x' % (tid, comm, exception_number))
            pass
        if cpu.architecture == 'arm':
            name = cpu.iface.exception.get_name(exception_number)
            eip = self.mem_utils.getRegValue(cpu, 'pc')
            self.lgr.debug('faultReturnCallback %s  (%d)  tid:%s  eip0x%x' % (name, exception_number, tid, eip))
    '''

    def stopWatchPageFaults(self, tid = None):
        if self.fault_hap is not None:
            #self.lgr.debug('stopWatchPageFaults delete fault_hap')
            self.context_manager.genDeleteHap(self.fault_hap)
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
                self.context_manager.genDeleteHap(self.exit_hap[tid])
                self.context_manager.genDeleteHap(self.exit_hap2[tid])
                del self.exit_break[tid]
                del self.exit_hap[tid]
                del self.exit_hap2[tid]
        #self.lgr.debug('pageFaultGen stopWatchPageFaults before clear len is %s' % len(self.pending_faults))
        self.faulted_pages.clear()
        #self.faulting_cycles.clear()
        self.pending_faults.clear()
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
            self.lgr.debug('exitHap wrong tid:%s expected %d' % (tid, prec.tid))
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
       
        if self.top.hasBookmarks() and self.top.reverseEnabled():
            self.lgr.debug('pageFaultGen skipAlone to cycle 0x%x' % prec.cycles) 
            target_cycles = prec.cycles
            print('skipping back to user space, please wait.')
            if not resimUtils.skipToTest(self.cpu, target_cycles, self.lgr):
                return
            print('Completed skip.')
            eip = self.mem_utils.getRegValue(self.cpu, 'pc')
            if eip != prec.eip:
                if not resimUtils.skipToTest(self.cpu, target_cycles-1, self.lgr):
                    return
                cur_eip = self.mem_utils.getRegValue(self.cpu, 'pc')
                self.lgr.warning('pageFaultGen skipAlone, wrong eip is 0x%x wanted 0x%x, skipped again, now eip is 0x%x' % (eip, prec.eip, cur_eip))
                eip = cur_eip
            if self.mem_utils.isKernel(eip):
                target_cycles = self.cpu.cycles - 1
                if not resimUtils.skipToTest(self.cpu, target_cycles, self.lgr):
                    return
                else:
                    cur_eip = self.mem_utils.getRegValue(self.cpu, 'pc')
                    self.lgr.debug('pageFaultGen skipAlone landed in kernel 0x%x, backed up one to 0x%x eip:0x%x' % (eip, target_cycles, cur_eip))
                    if cur_eip == eip: 
                        self.lgr.debug('pageFaultGen skipAlone same eip, back up more')
                        target_cycles = self.cpu.cycles - 1
                        if not resimUtils.skipToTest(self.cpu, target_cycles, self.lgr):
                            return
                        
                        cur_eip = self.mem_utils.getRegValue(self.cpu, 'pc')
                        self.lgr.debug('pageFaultGen skipAlone after another backup, eip is 0x%x' % (cur_eip))
    
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
        self.top.stopTrackIO()
        self.top.skipAndMail()

    def stopAlone(self, prec):
        RES_hap_delete_callback_id("Core_Simulation_Stopped", self.stop_hap)
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
        ''' Assumed called while debugging a tid group.  Search all tids for most recent reference, assuming a 
            true fault is handled without rescheduling. 
            Return True if we think a segv occured
        '''
        retval = False
        self.lgr.debug('pageFaultGen handleExit tid:%s leader:%s len of pending_faults %d' % (tid, str(leader), len(self.pending_faults)))
        if len(self.pending_faults) > 0:
            recent_cycle = 0
            recent_tid = None
            for pending_tid in self.pending_faults:
                self.lgr.debug('compare pending_tid:%s cycle 0x%x to recent 0x%x' % (pending_tid, self.pending_faults[pending_tid].cycles, recent_cycle))
                if self.pending_faults[pending_tid].cycles > recent_cycle:
                    # TBD weak algorithm for determining which thread is a fault
                    if recent_tid is None or not self.mem_utils.isKernel(self.pending_faults[pending_tid].eip):
                        recent_cycle = self.pending_faults[pending_tid].cycles
                        recent_tid = pending_tid
            if recent_tid == tid or tid == leader or leader is None: 
                self.lgr.debug('pageFaultGen handleExit tid:%s has pending fault.  SEGV?' % recent_tid)
                if not report_only:
                    SIM_run_alone(self.hapAlone, self.pending_faults[recent_tid])
                    self.pending_faults = {}
                    self.stopPageFaults()
                    self.stopWatchPageFaults()
                    retval = True
                else:
                    prec = self.pending_faults[recent_tid]
                    self.lgr.debug('SEGV access to memory 0x%x cycle: 0x%x' % (prec.cr2, prec.cycles))
                    print('SEGV access to memory 0x%x cycles: 0x%x' % (prec.cr2, prec.cycles))
                    
        return retval

    def hasPendingPageFault(self, tid):
        if tid in self.pending_faults:
            self.lgr.debug('pageFaultGen pending fault cr2 0x%x' % self.pending_faults[tid].cr2)
            return True
        else:
            return False

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
        
    
