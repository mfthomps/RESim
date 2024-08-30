from simics import *
import resimUtils
class VxKCallExit():
    ''' assumes all modules could be part of all tasks.  TBD refine relationship between modules and tasks'''
    ''' TBD will need a context manager to disable breaks when in non-watched tasks '''
    def __init__(self, top, cpu, cell_name, mem_utils, task_utils, so_map, trace_mgr, dataWatch, lgr):
        self.top = top
        self.cpu = cpu
        self.mem_utils = mem_utils
        self.task_utils = task_utils
        self.so_map = so_map
        self.trace_mgr = trace_mgr
        self.dataWatch = dataWatch
        self.cell_name = cell_name
        self.lgr = lgr
        self.pending = {}
        self.module_bp = {}
        self.module_hap = {}
        self.exit_info = {}
        self.kbuffer = False
        self.trace_files = None
        

    def setExit(self, exit_info):
        task = self.task_utils.curTID()
        if task in self.pending:
            self.lgr.error('vxKCallExit setExit call %s task 0x%x but already pending for %s' % (exit_info.call_name, task, self.pending[task]))
            return
        self.pending[task] = exit_info.call_name
        self.exit_info[task] = exit_info
        for module in self.so_map.moduleList():
            if module not in self.module_bp:
                module_info = self.so_map.getModuleInfo(module)
                bp = SIM_breakpoint(self.cpu.current_context, Sim_Break_Linear, Sim_Access_Execute, module_info.addr, module_info.size, 0)
                self.module_bp[module] = bp
                hap = SIM_hap_add_callback_index("Core_Breakpoint_Memop", self.moduleHap, exit_info, bp)
                self.module_hap[module] = hap
                self.lgr.debug('vxKCallExit setExit set on 0x%x size 0x%x' % (module_info.addr, module_info.size))


    def moduleHap(self, exit_info, conf_object, break_num, memory):
        # hit when module code entered, e.g., first time or return from vxworks call
        trace_msg = None
        task = self.task_utils.curTID()
        if task not in self.pending:
            self.lgr.debug('vxCallExit moduleHap task 0x%x not pending' % task)
            return
        del self.pending[task]
        addr = memory.logical_address
        module = self.so_map.getSOFile(addr)
        if module not in self.module_hap:
            self.lgr.debug('vxCallExit moduleHap addr 0x%x module %s not in hap list' % (addr, module))
            return
        # TBD remove this
        self.exit_info[task].syscall_instance.clearHackme()
        r0 = self.mem_utils.getRegValue(self.cpu, 'r0')
        trace_msg = '\t return from %s r0: 0x%x' % (self.exit_info[task].call_name, r0)
        self.lgr.debug('vxKCallExit moduleHap cycle: 0x%x %s ' % (self.cpu.cycles, trace_msg))
        hap = self.module_hap[module]
        bp = self.module_bp[module]
        SIM_delete_breakpoint(bp)
        SIM_run_alone(self.rmHap, hap)
        del self.module_bp[module]
        del self.module_hap[module]
        self.exit_info[task].syscall_instance.enableSyms()
        pc = self.top.getEIP(self.cpu)
        if trace_msg is not None and self.trace_mgr is not None:
            if len(trace_msg.strip()) > 0:
                self.trace_mgr.write(trace_msg+'\n')
        if self.exit_info[task].stop_on_exit:
            if exit_info.call_name == 'fopen':
                self.top.setCommandCallbackParam(r0)
                #TBD NOTE this is to avoid real world affects on fopen of real files
                SIM_run_alone(self.top.resetOrigin, None)
            #SIM_break_simulation('Return to application, pc 0x%x' % pc)
            SIM_run_alone(exit_info.syscall_instance.stopAlone, trace_msg)
            return
        else:
            for param in exit_info.call_params:
                if param.name == 'runToCall' and param.subcall == exit_info.call_name:
                    SIM_break_simulation('Run to call %s, pc 0x%x' % (exit_info.call_name, pc))
                    return
        # NOTE returns above
        if exit_info.call_name == 'fgets':
            if r0 > 0 and exit_info.retval_addr is not None:
                s = self.mem_utils.readString(self.cpu, exit_info.retval_addr, 200)
                strlen = len(s)
                self.lgr.debug('vxKCallExit return from fgets FD: %d' % exit_info.old_fd)
                trace_msg = trace_msg+('FD: %d returned string length: %d into 0x%x given count: %d cycle: 0x%x \n\t%s\n' % (exit_info.old_fd, 
                              strlen, exit_info.retval_addr, exit_info.count, self.cpu.cycles, s))
                self.lgr.debug(trace_msg)

                my_syscall = exit_info.syscall_instance
                self.lgr.debug('vxKCallExit return from read matched_param is %s linger %r my_syscall %s' % (str(exit_info.matched_param), my_syscall.linger, my_syscall.name))
                if exit_info.matched_param is not None and (exit_info.matched_param.break_simulation or my_syscall.linger) and self.dataWatch is not None \
                   and type(exit_info.matched_param.match_param) is int and exit_info.matched_param.match_param == exit_info.old_fd:
                    ''' in case we want to break on a read of this data. NOTE break range is based on given count, not returned length '''
                    self.lgr.debug('vxKCallExit bout to call dataWatch.setRange for read string length is %d' % strlen)
                    # Set range over max length of read to catch coding error reference to previous reads or such
                    if strlen > 0:
                        self.dataWatch.setRange(exit_info.retval_addr, strlen, msg=trace_msg, max_len=exit_info.count, fd=exit_info.old_fd, data_stream=True)
                    if my_syscall.linger: 
                        self.dataWatch.stopWatch() 
                        self.dataWatch.watch(break_simulation=False, i_am_alone=True)
                    '''
                    if exit_info.origin_reset:
                        self.lgr.debug('vxKCallExit found origin reset, do it')
                        SIM_run_alone(self.stopAlone, None)
                    if self.kbuffer is not None:
                        self.kbuffer.readReturn(strlen)
                    '''
    def rmHap(self, hap):
        if hap is not None:
            SIM_hap_delete_callback_id("Core_Breakpoint_Memop", hap)

    def rmExitHap(self, dumb=None):
        # TBD 
        pass
