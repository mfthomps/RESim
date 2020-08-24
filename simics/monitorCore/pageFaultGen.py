from simics import *
import memUtils
import pageUtils
import hapCleaner
'''
Watch page faults for indications of a SEGV exception
'''
class Prec():
    def __init__(self, cpu, comm, pid=None, cr2=None, eip=None):
        self.cpu = cpu
        self.comm = comm
        self.pid = pid
        self.cr2 = cr2
        self.eip = eip
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
        self.task_rec_break = {}
        self.task_rec_hap = {}
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
        self.debugging_pid = None
        self.faulting_cycles = {}
        self.fault_hap1 = None
        self.fault_hap2 = None
        self.fault_hap_return = None
        self.exception_hap = None
        self.exception_hap2 = None
        self.pending_faults = {}
        ''' hack to tell context manager to call back to PageFaultGen on context switches to watched processes '''
        context_manager.callMe(self)

    def rmExit(self, pid):
        if pid in self.exit_break:
            self.context_manager.genDeleteHap(self.exit_hap[pid])
            self.context_manager.genDeleteHap(self.exit_hap2[pid])
            del self.exit_break[pid]
            del self.exit_hap[pid]
            del self.exit_hap2[pid]
        if pid in self.task_rec_break:
            SIM_delete_breakpoint(self.task_rec_break[pid])
            SIM_hap_delete_callback_id("Core_Breakpoint_Memop", self.task_rec_hap[pid])
            del self.task_rec_hap[pid]
            del self.task_rec_break[pid]
        self.context_manager.watchPageFaults(False)
        if pid in self.pending_faults:
            #self.lgr.debug('pageFaultGen rmExit remove pending for %d' % pid)
            del self.pending_faults[pid]
        
    def pdirWriteHap(self, prec, third, forth, memory):
        pdir_entry = SIM_get_mem_op_value_le(memory)
        cpu, comm, pid = self.task_utils.curProc() 
        #self.lgr.debug('ppageFaultGen dirWriteHap, %d (%s) new entry value 0x%x set by pid %d' % (pid, comm, pdir_entry, prec.pid))
        if self.pdir_break is not None:
            SIM_hap_delete_callback_id('Core_Breakpoint_Memop', self.pdir_hap)
            SIM_delete_breakpoint(self.pdir_break)
            #self.context_manager.genDeleteHap(self.pdir_hap)
            self.pdir_break = None
            self.pdir_hap = None
            self.rmExit(pid)

    def watchPdir(self, pdir_addr, prec):
        pcell = self.cpu.physical_memory
        #self.pdir_break = self.context_manager.genBreakpoint(pcell, Sim_Break_Physical, Sim_Access_Write, pdir_addr, self.page_entry_size, 0)
        self.pdir_break = SIM_breakpoint(pcell, Sim_Break_Physical, Sim_Access_Write, pdir_addr, self.page_entry_size, 0)
        #self.lgr.debug('pageFaultGen watchPdir pid: %d break %d at 0x%x' % (prec.pid, self.pdir_break, pdir_addr))
        #self.pdir_hap = self.context_manager.genHapIndex("Core_Breakpoint_Memop", self.pdirWriteHap, prec, self.pdir_break, name='watchPdir')
        self.pdir_hap = SIM_hap_add_callback_index("Core_Breakpoint_Memop", self.pdirWriteHap, prec, self.pdir_break)

    def ptableWriteHap(self, prec, third, forth, memory):
        ptable_entry = SIM_get_mem_op_value_le(memory)
        cpu, comm, pid = self.task_utils.curProc() 
        #self.lgr.debug('pageFaultGen tableWriteHap, %d (%s) new entry value 0x%x was set for pid: %d' % (pid, comm, ptable_entry, prec.pid))
        if self.ptable_break is not None:
            SIM_hap_delete_callback_id('Core_Breakpoint_Memop', self.ptable_hap)
            SIM_delete_breakpoint(self.ptable_break)
            #self.context_manager.genDeleteHap(self.ptable_hap)
            self.ptable_break = None
            self.ptable_hap = None
            self.rmExit(pid)

    def watchPtable(self, ptable_addr, prec):
        pcell = self.cpu.physical_memory
        #self.ptable_break = self.context_manager.genBreakpoint(pcell, Sim_Break_Physical, Sim_Access_Write, ptable_addr, self.page_entry_size, 0)
        self.ptable_break = SIM_breakpoint(pcell, Sim_Break_Physical, Sim_Access_Write, ptable_addr, self.page_entry_size, 0)
        #self.lgr.debug('pageFaultGen watchPtable pid %d break %d at 0x%x' % (prec.pid, self.ptable_break, ptable_addr))
        #self.ptable_hap = self.context_manager.genHapIndex("Core_Breakpoint_Memop", self.ptableWriteHap, prec, self.ptable_break, name='watchPtable')
        self.ptable_hap = SIM_hap_add_callback_index("Core_Breakpoint_Memop", self.ptableWriteHap, prec, self.ptable_break)
  
    def hapAlone(self, prec):
        self.top.removeDebugBreaks()
       
        self.stop_hap = SIM_hap_add_callback("Core_Simulation_Stopped", self.stopHap, prec)
        self.lgr.debug('pageFaultGen hapAlone set stop hap, now stop?')
        SIM_break_simulation('SEGV, task rec for %d (%s) modified mem reference was 0x%x' % (prec.pid, prec.comm, prec.cr2))
 
    def taskRecHap(self, prec, third, forth, memory):
        cpu, comm, pid = self.task_utils.curProc() 
        addr = memory.logical_address
        #self.lgr.debug('pageFaultGen taskRecHap eh pid %d wrote to 0x%x which is next for pid %d' % (pid, addr, prec.pid))
        if prec.pid in self.task_rec_break:
            #self.lgr.debug('pageFaultGen taskRecHap pid %d wrote to 0x%x which is next for pid %d' % (pid, addr, prec.pid))
            if self.ptable_break is not None:
                #self.context_manager.genDeleteHap(self.ptable_hap)
                SIM_hap_delete_callback_id('Core_Breakpoint_Memop', self.ptable_hap)
                SIM_delete_breakpoint(self.ptable_break)
                self.ptable_break = None
                self.ptable_hap = None
            if self.pdir_break is not None:
                #self.context_manager.genDeleteHap(self.pdir_hap)
                SIM_hap_delete_callback_id('Core_Breakpoint_Memop', self.pdir_hap)
                SIM_delete_breakpoint(self.pdir_hap)
                self.pdir_break = None
                self.pdir_hap = None
            #self.rmExit(prec.pid)
            if pid in self.pending_faults:
                #self.lgr.debug('pageFaultGen taskRecHap remove pending for %d' % pid)
                del self.pending_faults[pid]
       
            self.lgr.debug('SEGV from %d (%s) eip: 0x%x accessing memory 0x%x cycle 0x%x' % (prec.pid, prec.comm, prec.eip, prec.cr2, prec.cycles))
            print('SEGV from %d (%s) eip: 0x%x accessing memory 0x%x' % (prec.pid, prec.comm, prec.eip, prec.cr2))
            SIM_run_alone(self.hapAlone, prec)

    def pageFaultHap(self, compat32, third, forth, memory):
        #cpu, comm, pid = self.task_utils.curProc() 
        #self.lgr.debug('pageFaultHap pid:%d third: %s  forth: %s' % (pid, str(third), str(forth)))
        SIM_run_alone(self.pageFaultHapAlone, compat32)

    def pageFaultHapAlone(self, compat32):
        #cpu = SIM_current_processor()
        #if cpu != hap_cpu:
        #    self.lgr.debug('pageFaultHap, wrong cpu %s %s' % (cpu.name, hap_cpu.name))
        #    return
        use_cell = self.cell
        if self.debugging_pid is not None:
            use_cell = self.context_manager.getRESimContext()
        cpu, comm, pid = self.task_utils.curProc() 
        eip = self.exception_eip
        cur_pc = self.mem_utils.getRegValue(cpu, 'pc')
        if self.cpu.architecture == 'arm':
            if cur_pc == self.param.page_fault:
                ''' prefetch abort '''
                reg_num = None
            else:
                reg_num = self.cpu.iface.int_register.get_number("combined_data_far")
        else:
            reg_num = self.cpu.iface.int_register.get_number("cr2")
        if reg_num is not None:
            cr2 = self.cpu.iface.int_register.read(reg_num)
        else:
            cr2 = eip
        if pid not in self.faulted_pages:
            self.faulted_pages[pid] = []
        if cr2 in self.faulted_pages[pid]:
            self.lgr.debug('pageFaultHapAlone, addr 0x%x already handled for pid:%d cur_pc: 0x%x' % (cr2, pid, cur_pc))
            return
        self.faulted_pages[pid].append(cr2)
        #self.lgr.debug('pageFaultHapAlone for %d (%s)  faulting address: 0x%x' % (pid, comm, cr2))
        #self.lgr.debug('pageFaultHap for %d (%s) at 0x%x  faulting address: 0x%x' % (pid, comm, eip, cr2))
        if eip != cr2:
            instruct = SIM_disassemble_address(self.cpu, eip, 1, 0)
            #self.lgr.debug('faulting instruction %s' % instruct[1])
        else:
            #self.lgr.debug('eip 0x%x not mapped' % eip)
            pass
        if cpu.architecture == 'arm':
            page_info = pageUtils.findPageTableArm(self.cpu, cr2, self.lgr)
        elif pageUtils.isIA32E(cpu):
            page_info = pageUtils.findPageTableIA32E(self.cpu, cr2, self.lgr)
        else:
            page_info = pageUtils.findPageTable(self.cpu, cr2, self.lgr)
        if not page_info.page_exists:
            prec = Prec(self.cpu, comm, pid, cr2, eip)
            if pid not in self.pending_faults:
                self.pending_faults[pid] = prec
                #self.lgr.debug('pageFaultHapAlone add pending fault for %d cycle 0x%x' % (pid, prec.cycles))
            else:
                #self.lgr.debug('pageFaultHapAlone ALREADY pending fault for %d this cycle 0x%x' % (pid, prec.cycles))
                pass

            ''' Rely on ContextManager to watch for task kills if debugging -- and not '''
            if self.debugging_pid is None:
                #SIM_run_alone(self.watchExit, compat32)
                self.context_manager.watchExit()
                ''' 
                list_addr = self.task_utils.getTaskListPtr()
                if list_addr is not None:
                    SIM_run_alone(self.watchExit, compat32)
                    self.task_rec_break[pid] = SIM_breakpoint(use_cell, Sim_Break_Linear, Sim_Access_Write, list_addr, self.mem_utils.WORD_SIZE, 0)
                    self.lgr.debug('pageFaultHap pid:%d set list break %d at 0x%x cycle 0x%x' % (pid, self.task_rec_break[pid], list_addr, prec.cycles))
                    self.task_rec_hap[pid] = SIM_hap_add_callback_index("Core_Breakpoint_Memop", self.taskRecHap, prec, self.task_rec_break[pid])
                    #SIM_break_simulation('page fault page does not exist at 0x%x proc %d (%s)' % (cr2, pid, comm))         
                    #self.lgr.debug('page fault page does not exist at 0x%x proc %d (%s)' % (cr2, pid, comm))         
                    ##self.lgr.debug(page_info.valueString())
                else:
                    self.lgr.error('pageFaultHap proc %s (%d) gone?' % (comm, pid))
                ''' 

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
            else:
                #self.lgr.debug('pageFaultGen pageFaultHapAlone page_addr was None')
                self.watchPtable(page_info.ptable_addr, prec)

        else:
            #self.lgr.debug('pageFaultHap page must exist? pid %d  %s' % (pid, page_info.valueString()))   
            pass


    def watchPageFaults(self, pid=None, compat32=False):
        self.debugging_pid = pid
        if self.cpu.architecture == 'arm':
            #self.lgr.debug('watchPageFaults set break at 0x%x' % self.param.page_fault)
            ''' note page_fault is prefect abort '''
            proc_break = self.context_manager.genBreakpoint(self.cell, Sim_Break_Linear, Sim_Access_Execute, self.param.page_fault, self.mem_utils.WORD_SIZE, 0)
            proc_break2 = self.context_manager.genBreakpoint(self.cell, Sim_Break_Linear, Sim_Access_Execute, self.param.data_abort, self.mem_utils.WORD_SIZE, 0)
            self.fault_hap = self.context_manager.genHapRange("Core_Breakpoint_Memop", self.pageFaultHap, compat32, proc_break, proc_break2, name='watchPageFaults')
            #max_intr = 255
            #self.fault_hap1 = SIM_hap_add_callback_obj_range("Core_Exception", self.cpu, 0,
            #         self.faultCallback, self.cpu, 0, 13) 
        else:
            #self.lgr.debug('watchPageFaults set break at 0x%x' % self.param.page_fault)
            proc_break = self.context_manager.genBreakpoint(self.cell, Sim_Break_Linear, Sim_Access_Execute, self.param.page_fault, self.mem_utils.WORD_SIZE, 0)
            self.fault_hap = self.context_manager.genHapIndex("Core_Breakpoint_Memop", self.pageFaultHap, compat32, proc_break, name='watchPageFaults')
            ''' TBD catch illegal instruction '''
            #max_intr = 255
            #self.fault_hap1 = SIM_hap_add_callback_obj_range("Core_Exception", self.cpu, 0,
            #         self.faultCallback, self.cpu, 0, 13) 
            #self.fault_hap2 = SIM_hap_add_callback_obj_range("Core_Exception", self.cpu, 0,
            #     self.faultCallback, self.cpu, 15, max_intr) 

    def faultCallback(self, cpu, one, exception_number):
        cell_name = self.top.getTopComponentName(cpu)
        cpu, comm, pid = self.task_utils.curProc() 
        name = cpu.iface.exception.get_name(exception_number)
        eip = self.mem_utils.getRegValue(cpu, 'pc')
        instruct = SIM_disassemble_address(self.cpu, eip, 1, 0)
        if cpu.architecture == 'arm':
            reg_num = cpu.iface.int_register.get_number("combined_data_far")
            dfar = cpu.iface.int_register.read(reg_num)
            reg_num = cpu.iface.int_register.get_number("instruction_far")
            ifar = cpu.iface.int_register.read(reg_num)
            self.lgr.debug('faultCallback %s  (%d)  pid:%d (%s)  eip: 0x%x %s ifar: 0x%x  dfar: 0x%x' % (name, 
                exception_number, pid, comm, eip, instruct[1], ifar, dfar))
            #if (exception_number == 4 or exception_number == 1)and pid == 875:
            #    SIM_break_simulation('how?')
        else:
            #self.lgr.debug('faultCallback %s  (%d)  pid:%d (%s)  eip: 0x%x %s' % (name, exception_number, pid, comm, eip, instruct[1]))
            pass

    '''
    def faultReturnCallback(self, cpu, one, exception_number):
        cell_name = self.top.getTopComponentName(cpu)
        cpu, comm, pid = self.task_utils.curProc() 
        if exception_number != 7:
            #self.lgr.debug('fault_callback %d (%s) got fault 0x%x' % (pid, comm, exception_number))
            pass
        if cpu.architecture == 'arm':
            name = cpu.iface.exception.get_name(exception_number)
            eip = self.mem_utils.getRegValue(cpu, 'pc')
            self.lgr.debug('faultReturnCallback %s  (%d)  pid:%d  eip0x%x' % (name, exception_number, pid, eip))
    '''

    def stopWatchPageFaults(self, pid = None):
        if self.fault_hap is not None:
            self.lgr.debug('stopWatchPageFaults delete fault_hap')
            self.context_manager.genDeleteHap(self.fault_hap)
            self.fault_hap = None
        if self.fault_hap1 is not None:
            self.lgr.debug('stopWatchPageFaults delete fault_hap1')
            SIM_hap_delete_callback_id("Core_Exception", self.fault_hap1)
            self.fault_hap1 = None
        if self.fault_hap2 is not None:
            self.lgr.debug('stopWatchPageFaults delete fault_hap2')
            SIM_hap_delete_callback_id("Core_Exception", self.fault_hap2)
            self.fault_hap2 = None
        if pid is not None:
            if pid in self.exit_hap: 
                self.lgr.debug('stopWatchPageFaults delete exit_hap')
                self.context_manager.genDeleteHap(self.exit_hap[pid])
                self.context_manager.genDeleteHap(self.exit_hap2[pid])
                del self.exit_break[pid]
                del self.exit_hap[pid]
                del self.exit_hap2[pid]

    def exitHap2(self, prec, third, forth, memory):
        self.exitHap(prec, third, forth, memory)

    def exitHap(self, prec, third, forth, memory):
        #cpu = SIM_current_processor()
        #if cpu != prec.cpu:
        #    self.lgr.debug('exitHap, wrong cpu %s %s' % (cpu.name, hap_cpu.name))
        #    return
        #self.lgr.debug('pageFaultGen exitHap')
        cpu, comm, pid = self.task_utils.curProc() 
        if pid != prec.pid and prec.pid in self.exit_break:
            #self.lgr.debug('exitHap wrong pid %d expected %d' % (pid, prec.pid))
            return
        self.rmExit(pid)

    def watchExit(self, compat32=False):
        ''' tell context manager to not break on process kill '''
        self.context_manager.watchPageFaults(True)
        cpu, comm, pid = self.task_utils.curProc() 
        prec = Prec(cpu, comm, pid)
        callnum = self.task_utils.syscallNumber('exit_group', compat32)
        exit_group = self.task_utils.getSyscallEntry(callnum, compat32)
        self.exit_break[pid] = self.context_manager.genBreakpoint(self.cell, Sim_Break_Linear, Sim_Access_Execute, exit_group, self.mem_utils.WORD_SIZE, 0)
        callnum = self.task_utils.syscallNumber('exit', compat32)
        exit = self.task_utils.getSyscallEntry(callnum, compat32)
        self.exit_break2[pid] = self.context_manager.genBreakpoint(self.cell, Sim_Break_Linear, Sim_Access_Execute, exit, self.mem_utils.WORD_SIZE, 0)
        self.exit_hap[pid] = self.context_manager.genHapIndex("Core_Breakpoint_Memop", self.exitHap, prec, self.exit_break[pid], name='watchExit')
        self.exit_hap2[pid] = self.context_manager.genHapIndex("Core_Breakpoint_Memop", self.exitHap2, prec, self.exit_break2[pid], name='watchExit2')
        #self.lgr.debug('pageFaultGen watchExit set breaks %d %d for pid %d at 0x%x 0x%x' % (self.exit_break[pid], self.exit_break2[pid], pid, exit_group, exit))

    def skipAlone(self, prec):
        ''' page fault caught in kernel, back up to user space?  '''
        ''' TBD what about segv generated within kernel '''
        if self.debugging_pid is not None:
            target_cycles = prec.cycles - 1
            self.lgr.debug('skipAlone skip to 0x%x' % target_cycles)
            SIM_run_command('skip-to cycle = 0x%x' % target_cycles)
            self.top.setDebugBookmark('SEGV access to 0x%x' % prec.cr2)
            self.context_manager.resetWatchTasks()
        self.stopWatchPageFaults()
        self.top.skipAndMail()

    def stopAlone(self, prec):
        SIM_hap_delete_callback_id("Core_Simulation_Stopped", self.stop_hap)
        self.stop_hap = None
        self.context_manager.setIdaMessage('SEGV access to memory 0x%x' % prec.cr2)
        SIM_run_command('pselect %s' % self.cpu.name)
        SIM_run_alone(self.skipAlone, prec)

    def stopHap(self, prec, one, exception, error_string):
        if self.stop_hap is None:
            return 
        self.lgr.debug('pageFaultGen stopHap')
        SIM_run_alone(self.stopAlone, prec)


    def recordPageFaults(self):
        #self.lgr.debug('recordPageFaults')
        if self.cpu.architecture == 'arm':
            prefetch_fault = 4
            data_fault = 1
            self.exception_hap = SIM_hap_add_callback_obj_index("Core_Exception", self.cpu, 0,
                     self.pageExceptionHap, self.cpu, prefetch_fault)
            self.exception_hap2 = SIM_hap_add_callback_obj_index("Core_Exception", self.cpu, 0,
                     self.pageExceptionHap, self.cpu, data_fault)
        else:
            page_fault = 14
            self.exception_hap = SIM_hap_add_callback_obj_index("Core_Exception", self.cpu, 0,
                     self.pageExceptionHap, self.cpu, page_fault)

    def stopPageFaults(self):
        if self.exception_hap is not None:
            self.lgr.debug('stopPageFaults delete excption_hap')
            SIM_hap_delete_callback_id("Core_Exception", self.exception_hap)
            self.exception_hap = None
        if self.exception_hap2 is not None:
            self.lgr.debug('stopPageFaults delete excption_hap2')
            SIM_hap_delete_callback_id("Core_Exception", self.exception_hap2)
            self.exception_hap2 = None

    def pageExceptionHap(self, cpu, one, exception_number):
        if self.exception_hap is None:
            return
        eip = self.mem_utils.getRegValue(cpu, 'eip')
        if self.debugging_pid is not None:
            cpu, comm, pid = self.task_utils.curProc() 
            if pid not in self.faulting_cycles:
                self.faulting_cycles[pid] = {} 
            self.faulting_cycles[pid][eip] = cpu.cycles
        self.exception_eip = eip
        if cpu.architecture == 'arm':
            #reg_num = cpu.iface.int_register.get_number("combined_data_far")
            #dfar = cpu.iface.int_register.read(reg_num)
            #reg_num = cpu.iface.int_register.get_number("instruction_far")
            #ifar = cpu.iface.int_register.read(reg_num)
            cpu, comm, pid = self.task_utils.curProc() 
            name = cpu.iface.exception.get_name(exception_number)
            instruct = SIM_disassemble_address(self.cpu, eip, 1, 0)
            #self.lgr.debug('pageExceptionHap pid:%d eip: 0x%x faulting cycles 0x%x' % (pid, eip, self.cpu.cycles))
            #self.lgr.debug('pageExceptionHap %s  (%d)  pid:%d (%s)  eip: 0x%x %s ifar: 0x%x dfar: 0x%x' % (name, 
            #  exception_number, pid, comm, eip, instruct[1], ifar, dfar))
            #if eip == 0xc013fea8:
            #    SIM_break_simulation('Data Abort')
        else:
            cpu, comm, pid = self.task_utils.curProc() 
            #self.lgr.debug('pageExceptionHap pid:%d (%s) eip 0x%x' % (pid, comm, eip))

    def getFaultingCycles(self, pid):
        return self.faulting_cycles[pid] 

    def handleExit(self, pid):
        ''' Assumed called while debugging a pid group.  Search all pids for most recent reference, assuming a 
            true fault is handled without rescheduling. 
            Return True if we think a segv occured
        '''
        retval = False
        self.lgr.debug('pageFaultGen handleExit pid:%d' % pid)
        if len(self.pending_faults) > 0:
            recent_cycle = 0
            recent_pid = None
            for pid in self.pending_faults:
                #self.lgr.debug('compare pid %d cycle 0x%x to recent 0x%x' % (pid, self.pending_faults[pid].cycles, recent_cycle))
                if self.pending_faults[pid].cycles > recent_cycle:
                    recent_cycle = self.pending_faults[pid].cycles
                    recent_pid = pid
            #self.lgr.debug('pageFaultGen handleExit pid:%d has pending fault.  SEGV?' % recent_pid)
            SIM_run_alone(self.hapAlone, self.pending_faults[recent_pid])
            self.pending_faults = {}
            self.stopPageFaults()
            self.stopWatchPageFaults()
            retval = True
        return retval
