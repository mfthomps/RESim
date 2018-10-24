class GenContextMgr():
    def __init__(self, top, task_utils, lgr):
        self.top = top
        self.task_utils = task_utils
        self.debugging_pid = None
        self.debugging_cell = None
        self.debugging_cpu = None
        self.lgr = lgr
        self.ida_message = None
        self.exit_break_num = None
        self.exit_cb_num = None

    def setDebugPid(self, debugging_pid, debugging_cell, debugging_cpu):
        self.debugging_pid = debugging_pid
        self.debugging_cell = debugging_cell
        self.debugging_cpu = debugging_cpu

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
        return None 
    def getDebugPid(self):
        return self.debugging_pid, self.debugging_cell, self.debugging_cpu
    def showIdaMessage(self):
        print 'cgcMonitor says: %s' % self.ida_message
        self.lgr.debug('cgcMonitor says: %s' % self.ida_message)
