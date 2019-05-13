from simics import *
import syscall
class TrackThreads():
    def __init__(self, cpu, cell_name, cell, pid, context_manager, task_utils, mem_utils, param, traceProcs, soMap, targetFS, sharedSyscall, lgr):
        self.traceProcs = traceProcs
        self.parent_pid = pid
        self.pid_list = [pid]
        self.cpu = cpu
        self.cell = cell
        self.cell_name = cell_name
        self.param = param
        self.context_manager = context_manager
        self.task_utils = task_utils
        self.mem_utils = mem_utils
        self.soMap = soMap
        self.targetFS = targetFS
        self.sharedSyscall = sharedSyscall
        self.lgr = lgr
        self.exit_break1 = {}
        self.exit_break2 = {}
        self.exit_break3 = {}
        self.exit_hap = {}
        self.call_break = None
        self.call_hap = None
        self.execve_break = None
        self.execve_hap = None
        self.startTrack()
        self.finish_hap = {}
        self.finish_break = {}

        self.open_syscall = None

    def startTrack(self):
         
        if self.call_hap is not None:
            #self.lgr.debug('TrackThreads startTrack called, but already tracking')
            return
        self.lgr.debug('TrackThreads startTrack')
        callnum = self.task_utils.syscallNumber('clone')
        entry = self.task_utils.getSyscallEntry(callnum)
        self.call_break = self.context_manager.genBreakpoint(self.cell, Sim_Break_Linear, Sim_Access_Execute, entry, 1, 0)
        self.call_hap = self.context_manager.genHapIndex("Core_Breakpoint_Memop", self.cloneHap, 'nothing', self.call_break, 'trackThreads clone')

        execve_callnum = self.task_utils.syscallNumber('execve')
        execve_entry = self.task_utils.getSyscallEntry(execve_callnum)
        self.execve_break = self.context_manager.genBreakpoint(self.cell, Sim_Break_Linear, Sim_Access_Execute, execve_entry, 1, 0)
        self.execve_hap = self.context_manager.genHapIndex("Core_Breakpoint_Memop", self.execveHap, 'nothing', self.execve_break, 'trackThreads execve')
        self.lgr.debug('TrackThreads set execve break at 0x%x clone at 0x%x startTrack return' % (execve_entry, entry))

        self.trackSO()

    def stopTrack(self):
        self.lgr.debug('TrackThreads, stop tracking')
        self.context_manager.genDeleteHap(self.call_hap)
        self.context_manager.genDeleteHap(self.execve_hap)
        self.context_manager.genDeleteHap(self.open_hape)
        for hap in self.exit_hap:
            self.context_manager.genDeleteHap(hap)
        self.open_syscall.stopTrace()

    def execveHap(self, dumb, third, forth, memory):
        if self.execve_hap is None:
            return
        cpu = SIM_current_processor()
        if cpu != self.cpu:
            self.lgr.debug('TrackThreads  execveHap, wrong cpu %s %s' % (cpu.name, self.cpu.name))
            return
        cpu, comm, pid = self.task_utils.curProc() 
        if pid not in self.pid_list:
            #self.lgr.debug('TrackThreads  execveHap looked for pid %s, found %d.  Do nothing' % (str(self.pid_list), pid))
            return
        if len(self.pid_list) == 1:
            self.lgr.debug('TrackThreads execveHap who is execing to what? eh? pid: %d' % pid)
            return
        self.lgr.debug('TrackThreads execveHap remove pid %d from lists' % pid)
        self.context_manager.rmTask(pid)
        self.pid_list.remove(pid)
        self.parseExecve()

    def cloneHap(self, dumb, third, forth, memory):
        if self.call_hap is None:
            return
        cpu = SIM_current_processor()
        if cpu != self.cpu:
            self.lgr.debug('TrackThreads  cloneHap, wrong cpu %s %s' % (cpu.name, self.cpu.name))
            return
        cpu, comm, pid = self.task_utils.curProc() 
        if pid not in self.pid_list:
            self.lgr.debug('TrackThreads  cloneHap looked for pid %s, found %d.  Do nothing' % (str(self.pid_list), pid))
            return
        self.lgr.debug('TrackThreads  cloneHap pid %d' % (pid))
        stack_frame = self.task_utils.frameFromStackSyscall()
        if cpu.architecture == 'arm':
            exit_eip1 = self.param.arm_ret
            self.exit_break1[pid] = self.context_manager.genBreakpoint(self.cell, 
                                Sim_Break_Linear, Sim_Access_Execute, exit_eip1, 1, 0)
            self.exit_hap[pid] = self.context_manager.genHapIndex("Core_Breakpoint_Memop", self.exitHap, cpu, self.exit_break1[pid], 'trackThreads syscall')
        else: 
            exit_eip3 = None
            if self.mem_utils.WORD_SIZE == 8:
                stack_frame = self.task_utils.frameFromRegs(cpu)
                exit_eip1 = self.param.sysexit
                exit_eip2 = self.param.iretd
                exit_eip3 = self.param.sysret64
                self.lgr.debug('trackThreads clonehap exit eips: 0x%x  0x%x 0x%x' % (exit_eip1, exit_eip2, exit_eip3))
            else:
                stack_frame = self.task_utils.frameFromStackSyscall()
                exit_eip1 = self.param.sysexit
                exit_eip2 = self.param.iretd
            #exit_eip1 = self.param.sysexit
            #exit_eip2 = self.param.iretd
            self.exit_break1[pid] = self.context_manager.genBreakpoint(self.cell, 
                                Sim_Break_Linear, Sim_Access_Execute, exit_eip1, 1, 0)
            self.exit_break2[pid] = self.context_manager.genBreakpoint(self.cell, 
                                    Sim_Break_Linear, Sim_Access_Execute, exit_eip2, 1, 0)
            if exit_eip3 is not None:
                self.exit_break3[pid] = self.context_manager.genBreakpoint(self.cell, 
                                    Sim_Break_Linear, Sim_Access_Execute, exit_eip3, 1, 0)
                self.exit_hap[pid] = self.context_manager.genHapRange("Core_Breakpoint_Memop", self.exitHap, cpu, 
                       self.exit_break1[pid], self.exit_break3[pid], 'trackThreads syscall')
            else:
                self.exit_hap[pid] = self.context_manager.genHapRange("Core_Breakpoint_Memop", self.exitHap, cpu, 
                       self.exit_break1[pid], self.exit_break2[pid], 'trackThreads syscall')


    def exitHap(self, dumb, third, forth, memory):
        cpu, comm, pid = self.task_utils.curProc() 
        if pid not in self.exit_hap:
            prog = self.traceProcs.getProg(pid)
            if prog is None or prog == 'unknown':
                self.lgr.debug('trackThreads exitHap assume clone return to child for pid %d ?' % pid)
                self.context_manager.addTask(pid)
                self.traceProcs.addProc(pid, None, clone=True)
            return

        if self.cpu != cpu:
                return
        if pid in self.pid_list:
            ''' returned from parent '''
            ueax = self.mem_utils.getRegValue(cpu, 'syscall_ret')
            eax = self.mem_utils.getSigned(ueax)
            eip = self.mem_utils.getRegValue(cpu, 'pc')
            instruct = SIM_disassemble_address(self.cpu, eip, 1, 0)
            self.lgr.debug('trackThreads exitHap eip 0x%x instruct %s'  % (eip, instruct[1]))
            if instruct[1] == 'iretd' or instruct[1] == 'iret64':
                reg_num = self.cpu.iface.int_register.get_number(self.mem_utils.getESP())
                esp = self.cpu.iface.int_register.read(reg_num)
                ret_addr = self.mem_utils.readPtr(cpu, esp)
                self.lgr.debug('ret_addr 0x%x' % ret_addr)
                if ret_addr > self.param.kernel_base:
                    ''' nested '''
                    self.lgr.debug('trackThreads exitHap exitHap nested')
                    #SIM_break_simulation('nested ?')
                    return
            if eax <= 0:
                self.lgr.debug('TrackThreads exitHap error return from clone? pid: %d eax: %d' % (pid, eax))
                if eax != 0:
                    SIM_break_simulation('clone error')
                    #self.context_manager.genDeleteHap(self.exit_hap[pid])
                    #del self.exit_hap[pid] 
                    return
            child_pid = eax
            self.lgr.debug('TrackThreads exitHap for pid: %d adding child pid %d to contextManager' % (pid, child_pid))
            self.context_manager.addTask(child_pid)
            self.context_manager.genDeleteHap(self.exit_hap[pid])
            #self.top.addProcList(pid, None)
            self.traceProcs.addProc(child_pid, pid, clone=True)
            del self.exit_hap[pid]
            self.pid_list.append(child_pid)
            del self.exit_break1[pid]
            if pid in self.exit_break2: 
                del self.exit_break2[pid]
            if pid in self.exit_break3: 
                del self.exit_break3[pid]
        else: 
            self.lgr.debug('TrackThreads exitHap wrong pid %d looking for %s' % (pid, str(self.pid_list)))

    def finishParseExecve(self, call_info, third, forth, memory):
        cpu, comm, pid = self.task_utils.curProc() 
        if cpu != call_info.cpu or pid != call_info.pid:
            return
        if pid not in self.finish_hap:
            return
        prog_string, arg_string_list = self.task_utils.readExecParamStrings(call_info.pid, call_info.cpu)
        if cpu.architecture == 'arm' and prog_string is None:
            self.lgr.debug('trackThreads finishParseExecve progstring None, arm fu?')
            return
        self.lgr.debug('trackThreads finishParseExecve progstring (%s)' % (prog_string))
        self.traceProcs.setName(pid, prog_string, None)

        SIM_hap_delete_callback_id("Core_Breakpoint_Memop", self.finish_hap[pid])
        SIM_delete_breakpoint(self.finish_break[pid])
        del self.finish_hap[pid]
        del self.finish_break[pid]

    def parseExecve(self):
        cpu, comm, pid = self.task_utils.curProc() 
        ''' allows us to ignore internal kernel syscalls such as close socket on exec '''
        prog_string, arg_string_list = self.task_utils.getProcArgsFromStack(pid, False, cpu)
        
        if prog_string is None:
            ''' prog string not in ram, break on kernel read of the address and then read it '''
            prog_addr = self.task_utils.getExecProgAddr(pid, cpu)
            call_info = SyscallInfo(cpu, pid, None, None, None)
            self.lgr.debug('trackThreads parseExecve prog string missing, set break on 0x%x' % prog_addr)
            if prog_addr == 0:
                self.lgr.error('trackThreads parseExecve zero prog_addr pid %d' % pid)
                SIM_break_simulation('trackThreads parseExecve zero prog_addr pid %d' % pid)
            self.finish_break[pid] = SIM_breakpoint(cpu.current_context, Sim_Break_Linear, Sim_Access_Read, prog_addr, 1, 0)
            self.finish_hap[pid] = SIM_hap_add_callback_index("Core_Breakpoint_Memop", self.finishParseExecve, call_info, self.finish_break[pid])
            return
        else:
            self.traceProcs.setName(pid, prog_string, None)

    def firstMmapHap(self, syscall_info, third, forth, memory):
        ''' invoked after mmap call, looking to track SO libraries.  Intended to be called after open of .so. '''
        cpu, comm, pid = self.task_utils.curProc() 
        #self.lgr.debug('firstMmapHap in pid %d look for pid %d' % (pid, syscall_info.pid))
        if syscall_info.pid not in self.first_mmap_hap:
            return
        if syscall_info.cpu is not None and cpu != syscall_info.cpu:
            self.lgr.debug('firstMmapHap, wrong cpu %s %s' % (cpu.name, syscall_info.cpu.name))
            return
        if syscall_info.pid is not None and pid != syscall_info.pid:
            self.lgr.debug('firstMmapHap, wrong pid %d %d' % (pid, syscall_info.pid))
            return
        if self.debugging and not self.context_manager.amWatching(pid):
            self.lgr.debug('firstMmapHap looked  found %d.  Do nothing' % (pid))
            return
        if self.bang_you_are_dead:
            self.lgr.error('firstMmapHap call to dead hap pid %d' % pid) 
            return
        if cpu.architecture == 'arm':
            frame = self.task_utils.frameFromRegs(cpu)
        else:
            frame = self.task_utils.frameFromStackSyscall()
        callname = self.task_utils.syscallName(syscall_info.callnum)
        if self.mem_utils.WORD_SIZE == 4: 
            ida_msg = 'firstMmapHap %s pid:%d FD: %d buf: 0x%x len: %d  File FD was %d' % (callname, pid, frame['param3'], frame['param1'], frame['param2'], 
                  syscall_info.fd)
        else:
            ida_msg = 'firstMmapHap %s pid:%d FD: %d buf: 0x%x len: %d offset: 0x%x  File FD was %d' % (callname, pid, 
               frame['param5'], frame['param1'], frame['param2'], frame['param6'], syscall_info.fd)

        self.lgr.debug(ida_msg)
        self.traceMgr.write(ida_msg+'\n')
        syscall_info.call_count = syscall_info.call_count+1
        #self.lgr.debug('firstMmapHap delete self?')
        self.context_manager.genDeleteHap(self.first_mmap_hap[pid])
        del self.first_mmap_hap[pid]
        syscall_info.call_count = syscall_info.call_count+1
        exit_info = ExitInfo(cpu, pid, syscall_info.callnum)
        exit_info.fname = syscall_info.fname
        exit_info.count = frame['param2']
        exit_info.syscall_entry = self.top.getEIP()
        name = 'firstMmap exit'
        try:
            ''' backward compatibility '''
            sysret64 = self.param.sysret64
        except AttributeError:
            sysret64 = None
        if cpu.architecture == 'arm':
            self.sharedSyscall.addExitHap(pid, self.param.arm_ret, None, None, syscall_info.callnum, exit_info, self.traceProcs, name)
        else:
            self.sharedSyscall.addExitHap(pid, self.param.sysexit, self.param.iretd, sysret64, syscall_info.callnum, exit_info, self.traceProcs, name)


    def trackSO(self):
        callnum = self.task_utils.syscallNumber('open')
        self.open_syscall = syscall.Syscall(None, self.cell_name, self.cell, self.param, self.mem_utils, self.task_utils, 
                           self.context_manager, None, self.sharedSyscall, self.lgr, None, callnum_list=[callnum], 
                           soMap=self.soMap, targetFS=self.targetFS, skip_and_mail=False)
