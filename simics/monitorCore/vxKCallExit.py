from simics import *
import resimUtils
class VxKCallExit():
    ''' assumes all modules could be part of all tasks.  TBD refine relationship between modules and tasks'''
    def __init__(self, top, cpu, cell_name, mem_utils, task_utils, so_map, trace_mgr, dataWatch, context_manager, lgr):
        self.top = top
        self.cpu = cpu
        self.mem_utils = mem_utils
        self.task_utils = task_utils
        self.so_map = so_map
        self.trace_mgr = trace_mgr
        self.dataWatch = dataWatch
        self.context_manager = context_manager
        self.cell_name = cell_name
        self.lgr = lgr
        self.module_hap = {}
        self.exit_info = {}
        self.kbuffer = False
        self.trace_files = None
        

    def setExit(self, exit_info):
        task = self.task_utils.getCurrentTask()
        if task in self.exit_info:
            self.lgr.error('vxKCallExit setExit call %s task 0x%x but already pending for %s' % (exit_info.call_name, task, self.exit_info[task].call_name))
            return
        self.exit_info[task] = exit_info
        current_context = self.cpu.current_context
        self.lgr.debug('vxKCallExit setExit set pending task 0x%x call %s' % (task, exit_info.call_name))
        for module in self.so_map.moduleList():
            if module not in self.module_hap:
                module_info = self.so_map.getModuleInfo(module)
                bp = self.context_manager.genBreakpoint(current_context, Sim_Break_Linear, Sim_Access_Execute, module_info.addr, module_info.size, 0)
                hap = self.context_manager.genHapIndex("Core_Breakpoint_Memop", self.moduleHap, exit_info, bp, 'syscall')
                self.module_hap[module] = hap
                self.lgr.debug('vxKCallExit setExit set on 0x%x size 0x%x context %s' % (module_info.addr, module_info.size, str(current_context)))


    def moduleHap(self, exit_info, conf_object, break_num, memory):
        # hit when module code entered, e.g., first time or return from vxworks call
        #self.lgr.debug('vxKCallExit moduleHap') 
        if self.context_manager.isReverseContext():
            return
        trace_msg = None
        task = self.task_utils.getCurrentTask()
        if task not in self.exit_info:
            self.lgr.debug('vxCallExit moduleHap task 0x%x not pending exit info' % task)
            return
        # TBD remove this
        self.exit_info[task].syscall_instance.clearHackme()
        self.lgr.debug('vxKCallExit moduleHap remove pending task 0x%x call %s' % (task, self.exit_info[task].call_name))
        self.exit_info[task].syscall_instance.enableSyms()
        r0 = self.mem_utils.getRegValue(self.cpu, 'r0')
        trace_msg = '\t return from %s r0: 0x%x' % (self.exit_info[task].call_name, r0)
        del self.exit_info[task]
        addr = memory.logical_address
        module = self.so_map.getSOFile(addr)
        if module not in self.module_hap:
            self.lgr.debug('vxCallExit moduleHap addr 0x%x module %s not in hap list' % (addr, module))
            return
        pc = self.top.getEIP(self.cpu)
        self.lgr.debug('vxKCallExit moduleHap cycle: 0x%x pc: 0x%x %s ' % (self.cpu.cycles, pc, trace_msg))
        self.context_manager.genDeleteHap(self.module_hap[module])
        del self.module_hap[module]
        # NOTE returns above
        if exit_info.call_name == 'fopen':
            if exit_info.matched_param is not None:
                self.top.setCommandCallbackParam(r0)
                #TBD NOTE this is to avoid real world affects on fopen of real files, should not really depend on matched_param, but quite disruptive.
                #self.lgr.debug('vxKCallExit is fopen, reset origin')
                #SIM_run_alone(self.top.resetOrigin, None)

        elif exit_info.call_name == 'fgets':
            if r0 > 0 and exit_info.retval_addr is not None:
                s = self.mem_utils.readString(self.cpu, exit_info.retval_addr, 200)
                strlen = len(s)
                self.lgr.debug('vxKCallExit return from fgets FD: %d' % exit_info.old_fd)
                trace_msg = trace_msg+(' FD: %d returned string length: %d into 0x%x given count: %d cycle: 0x%x \n\t%s\n' % (exit_info.old_fd, 
                              strlen, exit_info.retval_addr, exit_info.count, self.cpu.cycles, s))
                self.lgr.debug(trace_msg)

                my_syscall = exit_info.syscall_instance
                self.lgr.debug('vxKCallExit return from read matched_param is %s linger %r my_syscall %s' % (str(exit_info.matched_param), my_syscall.linger, my_syscall.name))
                self.checkDataWatch(exit_info, strlen, my_syscall, trace_msg)
        elif exit_info.call_name == 'fgetc':
            trace_msg = trace_msg + (' FD: "%d returned 0x%x cycle: 0x%x' % (exit_info.old_fd, r0, self.cpu.cycles))
            r0_signed = self.mem_utils.getSigned(r0)
            if r0_signed >= 0:
                self.lgr.debug(trace_msg)

                my_syscall = exit_info.syscall_instance
                self.lgr.debug('vxKCallExit return from fgetc matched_param is %s linger %r my_syscall %s' % (str(exit_info.matched_param), my_syscall.linger, my_syscall.name))
                if exit_info.matched_param is not None and (exit_info.matched_param.break_simulation or my_syscall.linger) and self.dataWatch is not None \
                   and type(exit_info.matched_param.match_param) is int and exit_info.matched_param.match_param == exit_info.old_fd:
                    
                    #self.lgr.debug('vxKCallExit bout to call dataWatch.setRange for fgetc')
                    #self.dataWatch.setRange(exit_info.retval_addr, 1, msg=trace_msg, max_len=exit_info.count, fd=exit_info.old_fd, data_stream=True)
                    #if my_syscall.linger: 
                    #    self.dataWatch.stopWatch() 
                    #    self.dataWatch.watch(break_simulation=False, i_am_alone=True)
                    
                    self.dataWatch.fgetc(exit_info.old_fd, r0)
            else:
                self.lgr.debug('vxKCallExit got error %d' % r0_signed)
        elif exit_info.call_name == 'fscanf':
            trace_msg = trace_msg + (' FD: "%d returned %d values cycle: 0x%x' % (exit_info.old_fd, r0, self.cpu.cycles))
            if True:
                self.lgr.debug(trace_msg)

                my_syscall = exit_info.syscall_instance
                self.lgr.debug('vxKCallExit return from read matched_param is %s linger %r my_syscall %s' % (str(exit_info.matched_param), my_syscall.linger, my_syscall.name))
                if exit_info.matched_param is not None and (exit_info.matched_param.break_simulation or my_syscall.linger) and self.dataWatch is not None \
                   and type(exit_info.matched_param.match_param) is int and exit_info.matched_param.match_param == exit_info.old_fd:
                    
                    #self.lgr.debug('vxKCallExit bout to call dataWatch.setRange for fgetc')
                    #self.dataWatch.setRange(exit_info.retval_addr, 1, msg=trace_msg, max_len=exit_info.count, fd=exit_info.old_fd, data_stream=True)
                    #if my_syscall.linger: 
                    #    self.dataWatch.stopWatch() 
                    #    self.dataWatch.watch(break_simulation=False, i_am_alone=True)
                    
                    self.dataWatch.fscanf(exit_info.old_fd, exit_info.fname, r0, exit_info.retval_addr_list)

        elif exit_info.call_name == 'recv':
            if r0 > 0 and exit_info.retval_addr is not None:
                nbytes = min(r0, 256)
                byte_array = self.mem_utils.getBytes(self.cpu, r0, exit_info.retval_addr)
                if byte_array is not None:
                    s = resimUtils.getHexDump(byte_array[:nbytes])
                else:
                    s = '<< NOT MAPPED >>'
                trace_msg = trace_msg+(' FD: %d returned length: %d into 0x%x given count: %d cycle: 0x%x \n\t%s\n' % (exit_info.old_fd, 
                              r0, exit_info.retval_addr, exit_info.count, self.cpu.cycles, s))
                self.lgr.debug(trace_msg)
                my_syscall = exit_info.syscall_instance
                self.lgr.debug('vxKCallExit return from recv matched_param is %s linger %r my_syscall %s' % (str(exit_info.matched_param), my_syscall.linger, my_syscall.name))
                self.checkDataWatch(exit_info, r0, my_syscall, trace_msg)
        if exit_info.matched_param is not None:
            self.lgr.debug('vxCallExit moduleHap, matched_param: %s  break_simulation %r' % (str(exit_info.matched_param), exit_info.matched_param.break_simulation))
        else:
            self.lgr.debug('vxCallExit moduleHap no matched_param')
        if exit_info.matched_param is not None and exit_info.matched_param.break_simulation:
            '''  Use syscall module that got us here to handle stop actions '''
            self.lgr.debug('exitHap found matching call parameter %s' % str(exit_info.matched_param.match_param))
            self.matching_exit_info = exit_info
            self.context_manager.setIdaMessage(trace_msg)
            #self.lgr.debug('exitHap found matching call parameters callnum %d name %s' % (exit_info.callnum, callname))
            #my_syscall = self.top.getSyscall(self.cell_name, callname)
            my_syscall = exit_info.syscall_instance
            if my_syscall is None:
                self.lgr.error('sharedSyscall could not get syscall for %s' % callname)
            else:
                if not my_syscall.linger: 
                    self.stopTrace()
                self.lgr.debug('sharedSyscall add call param %s to syscall remove list' % exit_info.matched_param.name)
                #my_syscall.appendRmParam(exit_info.matched_param.name)
                SIM_run_alone(my_syscall.stopAlone, exit_info.call_name)
    
        if trace_msg is not None and len(trace_msg.strip())>0:
            self.lgr.debug('cell %s %s'  % (self.cell_name, trace_msg.strip()))
            self.trace_mgr.write(trace_msg+'\n') 

        return True
    def rmHap(self, hap):
        if hap is not None:
            SIM_hap_delete_callback_id("Core_Breakpoint_Memop", hap)

    def rmExitHap(self, dumb=None):
        # TBD 
        pass

    def stopTrace(self):
        # TBD
        pass

    def getPendingCall(self, task):
        retval = None
        if task in self.exit_info:
            # TBD why care about match param?
            #exit_info = self.exit_info[task]
            #if exit_info.matched_param is not None and  type(exit_info.matched_param.match_param) is int and exit_info.matched_param.match_param == exit_info.old_fd:
            retval = self.exit_info[task].call_name
        return retval

    def checkDataWatch(self, exit_info, actual_len, my_syscall, trace_msg):
        if exit_info.matched_param is not None and (exit_info.matched_param.break_simulation or my_syscall.linger) and self.dataWatch is not None \
           and type(exit_info.matched_param.match_param) is int and exit_info.matched_param.match_param == exit_info.old_fd:
            ''' in case we want to break on a read of this data. NOTE break range is based on given count, not returned length '''
            self.lgr.debug('vxKCallExit checkDataWatch call dataWatch.setRange for read string length is %d' % actual_len)
            # Set range over max length of read to catch coding error reference to previous reads or such
            if actual_len > 0:
                self.dataWatch.setRange(exit_info.retval_addr, actual_len, msg=trace_msg, max_len=exit_info.count, fd=exit_info.old_fd, data_stream=True)
            if my_syscall.linger: 
                self.dataWatch.stopWatch() 
                self.dataWatch.watch(break_simulation=False, i_am_alone=True)
