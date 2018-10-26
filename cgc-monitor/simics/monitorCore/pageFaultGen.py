from simics import *
import memUtils
import pageUtils

class PageFaultGen():
    def __init__(self, target, param, cell_config, mem_utils, task_utils, lgr):
        self.cell_config = cell_config
        self.target = target
        self.param = param
        self.mem_utils = mem_utils
        self.task_utils = task_utils
        self.lgr = lgr

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
        #self.lgr.debug('page_info is %s' % str(page_info)) 
        if not page_info.page_present:
            #SIM_break_simulation('page fault page not present at 0x%x proc %d (%s)' % (cr2, pid, comm))         
            self.lgr.debug('page fault page not present at 0x%x proc %d (%s)' % (cr2, pid, comm))         

    def watchPageFaults(self):
        cpu = self.cell_config.cpuFromCell(self.target)
        cell = self.cell_config.cell_context[self.target]
        self.lgr.debug('watchPageFaults set break at 0x%x' % self.param.page_fault)
        proc_break = SIM_breakpoint(cell, Sim_Break_Linear, Sim_Access_Execute, self.param.page_fault, self.mem_utils.WORD_SIZE, 0)
        proc_hap = SIM_hap_add_callback_index("Core_Breakpoint_Memop", self.pageFaultHap, cpu, proc_break)
