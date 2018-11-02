from simics import *
class GenBreakpoint():
    def __init__(self, cell, addr_type, mode, addr, length, flags):
        self.cell = cell
        self.addr_type = addr_type
        self.mode = mode
        self.addr = addr
        self.length = length
        self.flags = flags
        self.break_num = None
        self.set()

    def set(self):
        self.break_num = SIM_breakpoint(self.cell, self.addr_type, self.mode, self.addr, self.length, self.flags)

    def clear(self):
        if self.break_num is not None:
            SIM_delete_breakpoint(self.break_num)
            self.break_num = None

class GenHap():
    def __init__(self, hap_type, callback, parameter, breakpoint_start, breakpoint_end = None):
        self.hap_type = hap_type
        self.callback = callback
        self.parameter = parameter
        self.breakpoint_start = breakpoint_start
        self.breakpoint_end = breakpoint_end
        self.hap_num = None
        self.set()

    def set(self):
        if self.breakpoint_end is not None:
            self.hap_num = SIM_hap_add_callback_range(self.hap_type, self.callback, self.parameter, self.breakpoint_start.break_num, self.breakpoint_end.break_num)
        else:
            self.hap_num = SIM_hap_add_callback_index(self.hap_type, self.callback, self.parameter, self.breakpoint_start.break_num)

    def clear(self, dumb=None):
        if self.hap_num is not None:
            SIM_hap_delete_callback_id(self.hap_type, self.hap_num)
            self.hap_num = None
   
class GenContextMgr():
    def __init__(self, top, task_utils, lgr):
        self.top = top
        self.task_utils = task_utils
        self.mem_utils = task_utils.getMemUtils()
        self.debugging_pid = None
        self.debugging_cellname = None
        self.debugging_cell = None
        self.debugging_cpu = None
        self.debugging_rec = None
        self.debugging_scheduled = False
        self.lgr = lgr
        self.ida_message = None
        self.exit_break_num = None
        self.exit_cb_num = None
        self.current_task = task_utils.getCurrentTask()
        self.task_break = None
        self.task_hap = None
        self.breakpoints = []
        self.haps = []

    def genBreakpoint(self, cell, addr_type, mode, addr, length, flags):
        bp = GenBreakpoint(cell, addr_type, mode, addr, length, flags) 
        self.breakpoints.append(bp)
        self.lgr.debug('num break is now %d' % len(self.breakpoints))
        return bp.break_num

    def genDeleteBreakpoint(self, break_num):
        for bp in self.breakpoints:
            if bp.break_num == break_num:
                bp.clear()
                self.breakpoints.remove(bp)
                break

    def genDeleteHap(self, hap_num):
        for hap in self.haps:
            if hap.hap_num == hap_num:
                SIM_run_alone(hap.clear, None)
                self.haps.remove(hap)
                break

    def genHapIndex(self, hap_type, callback, parameter, breakpoint):
        for bp in self.breakpoints:
            if bp.break_num == breakpoint:
                hap = GenHap(hap_type, callback, parameter, bp)
                self.haps.append(hap)
                return hap.hap_num
        self.lgr.error('genHapIndex failed to find break %d' % breakpoint)

    def genHapRange(self, hap_type, callback, parameter, breakpoint_start, breakpoint_end):
        bp_start = None
        for bp in self.breakpoints:
            if bp.break_num == breakpoint_start:
                bp_start = bp
            if bp.break_num == breakpoint_end:
                hap = GenHap(hap_type, callback, parameter, bp_start, bp)
                self.haps.append(hap)
                return hap.hap_num
        self.lgr.error('genHapIndex failed to find break %d or %d' % (breakpoint_start, breakpoint_end))

    def setAll(self, dumb):
        for bp in self.breakpoints:
            bp.set()
        for hap in self.haps:
            hap.set()

    def clearAll(self, dumb):
        for bp in self.breakpoints:
            bp.clear()
        for hap in self.haps:
            hap.clear()
        
    def changedThread(self, cpu, third, forth, memory):
        # get the value that will be written into the current thread address
        cur_addr = SIM_get_mem_op_value_le(memory)
        #self.lgr.debug('changedThread compare 0x%x to 0x%x' % (cur_addr, self.debugging_rec))
        if cur_addr == self.debugging_rec:
            self.lgr.debug('Now scheduled')
            self.debugging_scheduled = True
            SIM_run_alone(self.setAll, None)
        elif self.debugging_scheduled:
            self.lgr.debug('No longer scheduled')
            self.debugging_scheduled = False
            SIM_run_alone(self.clearAll, None)

    def watchTasks(self):
        self.task_break = SIM_breakpoint(self.debugging_cell, Sim_Break_Linear, Sim_Access_Write, self.current_task, self.mem_utils.WORD_SIZE, 0)
        cb_num = SIM_hap_add_callback_index("Core_Breakpoint_Memop", self.changedThread, self.debugging_cpu, self.task_break)
        self.debugging_scheduled = True
        self.debugging_rec = self.mem_utils.readPtr(self.debugging_cpu, self.current_task)
        
    def setDebugPid(self, debugging_pid, debugging_cellname, debugging_cpu):
        self.debugging_pid = debugging_pid
        self.debugging_cellname = debugging_cellname
        self.debugging_cpu = debugging_cpu
        self.debugging_cell = self.top.getCell()

    def setExitBreak(self, cpu):
        ''' watch for exit of this process, to reinit monitoring '''    
        '''
        if self.exit_break_num is None:
            cell_name = self.top.getTopComponentName(cpu)
            p_cell = cpu.physical_memory
            self.exit_break_num = SIM_breakpoint(p_cell, Sim_Break_Physical, 
                Sim_Access_Write, self.task_utils.getCurrentTaskAddr(), 4, 0)
              
            self.exit_cb_num = SIM_hap_add_callback_index("Core_Breakpoint_Memop", 
                                                   self.changedThread, self.proc_info, self.exit_break_num)
            self.lgr.debug('contextManager setExitBreak set breakpoint %d' % self.exit_break_num)
        '''

    def clearExitBreak(self):
        if self.exit_break_num is not None:
            SIM_delete_breakpoint(self.exit_break_num)
            SIM_hap_delete_callback_id("Core_Breakpoint_Memop", self.exit_cb_num)
            self.lgr.debug('contextManager clearExitBreak removed breakpoint %d' % self.exit_break_num)
            self.exit_break_num = None
            self.exit_cb_num = None

    def resetBackStop(self):
        pass

    def getIdaMessage(self):
        return self.ida_message

    def getDebugPid(self):
        return self.debugging_pid, self.debugging_cellname, self.debugging_cpu

    def showIdaMessage(self):
        print 'genMonitor says: %s' % self.ida_message
        self.lgr.debug('genMonitor says: %s' % self.ida_message)

    def setIdaMessage(self, message):
        self.lgr.debug('ida message set to %s' % message)
        self.ida_message = message
