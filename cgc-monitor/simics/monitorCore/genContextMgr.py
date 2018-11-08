from simics import *
class GenBreakpoint():
    def __init__(self, cell, addr_type, mode, addr, length, flags, handle, lgr):
        self.cell = cell
        self.addr_type = addr_type
        self.mode = mode
        self.addr = addr
        self.length = length
        self.flags = flags
        self.break_num = None
        self.lgr = lgr
        self.handle = handle

        self.set()

    def set(self):
        #self.break_num = SIM_breakpoint(self.cell, self.addr_type, self.mode, self.addr, self.length, self.flags)
        ''' do set in hap? '''
        #self.lgr.debug('GenBreakpoint set done in hap, the break handle is %d' % self.handle)

    def clear(self):
        if self.break_num is not None:
            SIM_delete_breakpoint(self.break_num)
            #self.lgr.debug('GenBreakpoint clear %d handle is %d' % (self.break_num, self.handle))
            self.break_num = None

class GenHap():
    def __init__(self, hap_type, callback, parameter, lgr, breakpoint_start, breakpoint_end = None):
        ''' breakpoint_start and breakpont_end are GenBreakpoint types '''
        self.hap_type = hap_type
        self.callback = callback
        self.parameter = parameter
        self.breakpoint_start = breakpoint_start
        self.breakpoint_end = breakpoint_end
        self.lgr = lgr
        self.hap_num = None
        self.set()

    def set(self):
        if self.breakpoint_end is not None:
            bs = self.breakpoint_start
            be = self.breakpoint_end
            bs.break_num = SIM_breakpoint(bs.cell, bs.addr_type, bs.mode, bs.addr, bs.length, bs.flags)
            be.break_num = SIM_breakpoint(be.cell, be.addr_type, be.mode, be.addr, be.length, be.flags)
            self.hap_num = SIM_hap_add_callback_range(self.hap_type, self.callback, self.parameter, bs.break_num, be.break_num)
            #self.lgr.debug('GenHap set hap %d on range %d %d handles %d %d' % (self.hap_num, bs.break_num, be.break_num, bs.handle, be.handle))
        else:
            bs = self.breakpoint_start
            bs.break_num = SIM_breakpoint(bs.cell, bs.addr_type, bs.mode, bs.addr, bs.length, bs.flags)
            self.hap_num = SIM_hap_add_callback_index(self.hap_type, self.callback, self.parameter, bs.break_num)
            #self.lgr.debug('GenHap set hap %d on break %d handle %d' % (self.hap_num, bs.break_num, bs.handle))

    def clear(self, dumb=None):
        if self.hap_num is not None:
            if self.breakpoint_start is not None:
                self.breakpoint_start.clear()
            if self.breakpoint_end is not None:
                self.breakpoint_end.clear()
            SIM_hap_delete_callback_id(self.hap_type, self.hap_num)
            #self.lgr.debug('GenHap clear hap %d' % (self.hap_num))
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
        self.debugging_rec = []
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
        self.break_handle = 0

    def nextHandle(self):
        self.break_handle = self.break_handle+1
        return self.break_handle 

    def genBreakpoint(self, cell, addr_type, mode, addr, length, flags):
        handle = self.nextHandle()
        bp = GenBreakpoint(cell, addr_type, mode, addr, length, flags, handle, self.lgr) 
        self.breakpoints.append(bp)
        #self.lgr.debug('genBreakpoint handle %d  number of breakpoints is now %d' % (handle, len(self.breakpoints)))
        return handle

    def genDeleteBreakpoint(self, handle):
        #self.lgr.debug('genDeleteBreakpoint handle %d  -- do not delete, will be done in GenHap' % handle)
        #for bp in self.breakpoints:
        #    if bp.handle == handle:
        #        bp.clear()
        #        self.breakpoints.remove(bp)
        #        return
        #self.lgr.debug('genDeleteBreakpoint could not find break handle %d' % handle)
        pass

    def genDeleteHap(self, hap_num):
        #self.lgr.debug('genDeleteHap hap_num %d' % hap_num)
        for hap in self.haps:
            if hap.hap_num == hap_num:
                SIM_run_alone(hap.clear, None)
                if hap.breakpoint_start is not None:
                    self.breakpoints.remove(hap.breakpoint_start)
                if hap.breakpoint_end is not None:
                    self.breakpoints.remove(hap.breakpoint_end)
                self.haps.remove(hap)
                return
        #self.lgr.debug('genDeleteHap could not find hap_num %d' % hap_num)

    def genHapIndex(self, hap_type, callback, parameter, handle):
        #self.lgr.debug('genHapIndex break handle %d' % handle)
        for bp in self.breakpoints:
            if bp.handle == handle:
                hap = GenHap(hap_type, callback, parameter, self.lgr, bp)
                self.haps.append(hap)
                return hap.hap_num
        #self.lgr.error('genHapIndex failed to find break %d' % breakpoint)

    def genHapRange(self, hap_type, callback, parameter, handle_start, handle_end):
        #self.lgr.debug('genHapRange break handle %d %d' % (handle_start, handle_end))
        bp_start = None
        for bp in self.breakpoints:
            if bp.handle == handle_start:
                bp_start = bp
            if bp.handle == handle_end:
                hap = GenHap(hap_type, callback, parameter, self.lgr, bp_start, bp)
                self.haps.append(hap)
                return hap.hap_num
        #self.lgr.error('genHapIndex failed to find break for handles %d or %d' % (breakpoint_start, breakpoint_end))

    def setAllBreak(self):
        for bp in self.breakpoints:
            bp.set()

    def setAllHap(self, dumb):
        for hap in self.haps:
            hap.set()

    def clearAllBreak(self):
        for bp in self.breakpoints:
            bp.clear()
        
    def clearAllHap(self, dumb):
        for hap in self.haps:
            hap.clear()
        
    def changedThread(self, cpu, third, forth, memory):
        # get the value that will be written into the current thread address
        cur_addr = SIM_get_mem_op_value_le(memory)
        #self.lgr.debug('changedThread compare 0x%x to 0x%x' % (cur_addr, self.debugging_rec))
        if not self.debugging_scheduled and cur_addr in self.debugging_rec:
            self.lgr.debug('Now scheduled')
            self.debugging_scheduled = True
            self.setAllBreak()
            SIM_run_alone(self.setAllHap, None)
        elif self.debugging_scheduled:
            self.lgr.debug('No longer scheduled')
            self.debugging_scheduled = False
            self.clearAllBreak()
            SIM_run_alone(self.clearAllHap, None)

    def addTask(self, pid):
        rec = self.task_utils.getRecAddrForPid(pid)
        self.debugging_rec.append(rec)

    def watchTasks(self):
        self.task_break = SIM_breakpoint(self.debugging_cell, Sim_Break_Linear, Sim_Access_Write, self.current_task, self.mem_utils.WORD_SIZE, 0)
        cb_num = SIM_hap_add_callback_index("Core_Breakpoint_Memop", self.changedThread, self.debugging_cpu, self.task_break)
        self.lgr.debug('watchTasks break %d set on 0x%x' % (self.task_break, self.current_task))
        self.debugging_scheduled = True
        self.debugging_rec.append(self.mem_utils.readPtr(self.debugging_cpu, self.current_task))
        
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
