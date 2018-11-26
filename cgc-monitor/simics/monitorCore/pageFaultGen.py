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

class PageFaultGen():
    def __init__(self, target, param, cell_config, mem_utils, task_utils, lgr):
        self.cell_config = cell_config
        self.target = target
        self.param = param
        self.mem_utils = mem_utils
        self.task_utils = task_utils
        self.lgr = lgr
        self.exit_break = {}
        self.exit_hap = {}
        self.task_rec_break = {}
        self.task_rec_hap = {}
        self.pdir_break = None
        self.pdir_hap = None
        self.ptable_break = None
        self.ptable_hap = None
        self.cpu = self.cell_config.cpuFromCell(target)
        self.cell = self.cell_config.cell_context[target]

    def rmExit(self, pid):
        if pid in self.exit_break:
            SIM_delete_breakpoint(self.exit_break[pid])
            SIM_hap_delete_callback_id("Core_Breakpoint_Memop", self.exit_hap[pid])
            del self.exit_break[pid]
            del self.exit_hap[pid]
        if pid in self.task_rec_break:
            SIM_delete_breakpoint(self.task_rec_break[pid])
            SIM_hap_delete_callback_id("Core_Breakpoint_Memop", self.task_rec_hap[pid])
            del self.task_rec_hap[pid]
            del self.task_rec_break[pid]
        
    def pdirWriteHap(self, hap_cpu, third, forth, memory):
        pdir_entry = SIM_get_mem_op_value_le(memory)
        cpu, comm, pid = self.task_utils.curProc() 
        self.lgr.debug('pdirWriteHap, %d (%s) new entry value 0x%x' % (pid, comm, pdir_entry))
        if self.pdir_break is not None:
            SIM_delete_breakpoint(self.pdir_break)
            SIM_hap_delete_callback_id("Core_Breakpoint_Memop", self.pdir_hap)
            self.pdir_break = None
            self.pdir_hap = None
            self.rmExit(pid)

    def watchPdir(self, pdir_addr):
        pcell = self.cpu.physical_memory
        self.pdir_break = SIM_breakpoint(pcell, Sim_Break_Physical, Sim_Access_Write, pdir_addr, self.mem_utils.WORD_SIZE, 0)
        self.pdir_hap = SIM_hap_add_callback_index("Core_Breakpoint_Memop", self.pdirWriteHap, self.cpu, self.pdir_break)

    def ptableWriteHap(self, hap_cpu, third, forth, memory):
        ptable_entry = SIM_get_mem_op_value_le(memory)
        cpu, comm, pid = self.task_utils.curProc() 
        self.lgr.debug('ptableWriteHap, %d (%s) new entry value 0x%x' % (pid, comm, ptable_entry))
        if self.ptable_break is not None:
            SIM_delete_breakpoint(self.ptable_break)
            SIM_hap_delete_callback_id("Core_Breakpoint_Memop", self.ptable_hap)
            self.ptable_break = None
            self.ptable_hap = None
            self.rmExit(pid)

    def watchPtable(self, ptable_addr):
        pcell = self.cpu.physical_memory
        self.ptable_break = SIM_breakpoint(pcell, Sim_Break_Physical, Sim_Access_Write, ptable_addr, self.mem_utils.WORD_SIZE, 0)
        self.ptable_hap = SIM_hap_add_callback_index("Core_Breakpoint_Memop", self.ptableWriteHap, self.cpu, self.ptable_break)
   
    def taskRecHap(self, prec, third, forth, memory):
        if prec.pid in self.task_rec_break:
            addr = memory.logical_address
            self.lgr.debug('taskRecHap wrote to 0x%x' % addr)
            if self.ptable_break is not None:
                SIM_delete_breakpoint(self.ptable_break)
                SIM_hap_delete_callback_id("Core_Breakpoint_Memop", self.ptable_hap)
                self.ptable_break = None
                self.ptable_hap = None
            if self.pdir_break is not None:
                SIM_delete_breakpoint(self.pdir_break)
                SIM_hap_delete_callback_id("Core_Breakpoint_Memop", self.pdir_hap)
                self.pdir_break = None
                self.pdir_hap = None
            self.rmExit(prec.pid)
            self.lgr.debug('SEGV from %d (%s) eip: 0x%x accessing memory 0x%x' % (prec.pid, prec.comm, prec.eip, prec.cr2))
            SIM_break_simulation('SEGV ?? task rec modified mem reference was 0x%x' % prec.cr2)
        

    def pageFaultHap(self, hap_cpu, third, forth, memory):
        cpu = SIM_current_processor()
        if cpu != hap_cpu:
            self.lgr.debug('execveHap, wrong cpu %s %s' % (cpu.name, hap_cpu.name))
            return
        cpu, comm, pid = self.task_utils.curProc() 
        eip = self.mem_utils.getRegValue(cpu, 'eip')
        reg_num = cpu.iface.int_register.get_number("cr2")
        cr2 = cpu.iface.int_register.read(reg_num)
        #self.lgr.debug('pageFaultHap for %d (%s) at 0x%x  faulting address: 0x%x' % (pid, comm, eip, cr2))
        page_info = pageUtils.findPageTable(cpu, cr2, self.lgr)
        if not page_info.page_exists:
            #SIM_break_simulation('page fault page does not exist at 0x%x proc %d (%s)' % (cr2, pid, comm))         
            self.lgr.debug('page fault page does not exist at 0x%x proc %d (%s)' % (cr2, pid, comm))         
            self.lgr.debug(page_info.valueString())
            if not page_info.ptable_exists:
                self.lgr.debug('watch pdir address of 0x%x' % page_info.pdir_addr)
                self.watchPdir(page_info.pdir_addr)
            else:
                self.lgr.debug('watch ptable address of 0x%x' % page_info.ptable_addr)
                self.watchPtable(page_info.ptable_addr)
            self.watchExit()
            prec = Prec(cpu, comm, pid, cr2, eip)
            list_addr = self.task_utils.getTaskListPtr()
            self.task_rec_break[pid] = SIM_breakpoint(self.cell, Sim_Break_Linear, Sim_Access_Write, list_addr, self.mem_utils.WORD_SIZE, 0)
            self.task_rec_hap[pid] = SIM_hap_add_callback_index("Core_Breakpoint_Memop", self.taskRecHap, prec, self.task_rec_break[pid])

    def watchPageFaults(self):
        self.lgr.debug('watchPageFaults set break at 0x%x' % self.param.page_fault)
        proc_break = SIM_breakpoint(self.cell, Sim_Break_Linear, Sim_Access_Execute, self.param.page_fault, self.mem_utils.WORD_SIZE, 0)
        proc_hap = SIM_hap_add_callback_index("Core_Breakpoint_Memop", self.pageFaultHap, self.cpu, proc_break)


    def exitHap(self, prec, third, forth, memory):
        cpu = SIM_current_processor()
        if cpu != prec.cpu:
            self.lgr.debug('exitHap, wrong cpu %s %s' % (cpu.name, hap_cpu.name))
            return
        cpu, comm, pid = self.task_utils.curProc() 
        if pid != prec.pid and prec.pid in self.exit_break:
            self.lgr.debug('exitHap wrong pid %d expected %d' % (pid, prec.pid))
            return
        if pid in self.exit_break:
            self.lgr.debug('Exiting %d (%s)' % (pid, comm))
            SIM_delete_breakpoint(self.exit_break[pid])
            SIM_hap_delete_callback_id("Core_Breakpoint_Memop", self.exit_hap[pid])
            del self.exit_break[pid]
            del self.exit_hap[pid]
            SIM_break_simulation('exit hap %d' % pid)

    def watchExit(self):
        cpu, comm, pid = self.task_utils.curProc() 
        prec = Prec(cpu, comm, pid)
        self.exit_break[pid] = SIM_breakpoint(self.cell, Sim_Break_Linear, Sim_Access_Execute, self.param.sys_exit, self.mem_utils.WORD_SIZE, 0)
        self.exit_hap[pid] = SIM_hap_add_callback_index("Core_Breakpoint_Memop", self.exitHap, prec, self.exit_break[pid])
