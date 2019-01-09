from simics import *
class TrackThreads():
    def __init__(self, cpu, cell, pid, context_manager, task_utils, mem_utils, lgr):
        self.parent_pid = pid
        self.pid_list = [pid]
        self.cpu = cpu
        self.cell = cell
        self.context_manager = context_manager
        self.task_utils = task_utils
        self.mem_utils = mem_utils
        self.lgr = lgr
        self.exit_break = {}
        self.exit_hap = {}
        self.call_break = None
        self.call_hap = None
        self.execve_break = None
        self.execve_hap = None
        self.startTrack()

    def startTrack(self):
         
        if self.call_hap is not None:
            #self.lgr.debug('TrackThreads startTrack called, but already tracking')
            return
        self.lgr.debug('TrackThreads startTrack')
        callnum = self.task_utils.syscallNumber('clone')
        entry = self.task_utils.getSyscallEntry(callnum)
        self.call_break = self.context_manager.genBreakpoint(self.cell, Sim_Break_Linear, Sim_Access_Execute, entry, 1, 0)
        self.call_hap = self.context_manager.genHapIndex("Core_Breakpoint_Memop", self.syscallHap, 'nothing', self.call_break, 'trackThreads clone')

        execve_callnum = self.task_utils.syscallNumber('execve')
        execve_entry = self.task_utils.getSyscallEntry(execve_callnum)
        self.execve_break = self.context_manager.genBreakpoint(self.cell, Sim_Break_Linear, Sim_Access_Execute, execve_entry, 1, 0)
        self.execve_hap = self.context_manager.genHapIndex("Core_Breakpoint_Memop", self.execveHap, 'nothing', self.execve_break, 'trackThreads execve')
        self.lgr.debug('TrackThreads startTrack return')

    def stopTrack(self):
        self.lgr.debug('TrackThreads, stop tracking')
        self.context_manager.genDeleteHap(self.call_hap)
        self.context_manager.genDeleteHap(self.execve_hap)
        for hap in self.exit_hap:
            self.context_manager.genDeleteHap(hap)

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

    def syscallHap(self, dumb, third, forth, memory):
        if self.call_hap is None:
            return
        cpu = SIM_current_processor()
        if cpu != self.cpu:
            self.lgr.debug('TrackThreads  syscallHap, wrong cpu %s %s' % (cpu.name, self.cpu.name))
            return
        cpu, comm, pid = self.task_utils.curProc() 
        if pid not in self.pid_list:
            self.lgr.debug('TrackThreads  syscallHap looked for pid %s, found %d.  Do nothing' % (str(self.pid_list), pid))
            return
        stack_frame = self.task_utils.frameFromStackSyscall()
        phys = self.mem_utils.v2p(self.cpu, stack_frame['eip'])
        self.lgr.debug('TrackThreads  pid %d syscallHap set exit break at 0x%x (0x%x)' % (pid, stack_frame['eip'], phys))
        self.exit_break[pid] = self.context_manager.genBreakpoint(self.cpu.physical_memory, Sim_Break_Physical, Sim_Access_Execute, phys, 1, 0)
        self.exit_hap[pid] = self.context_manager.genHapIndex("Core_Breakpoint_Memop", self.exitHap, cpu, self.exit_break[pid], 'trackThreads syscall')

    def exitHap(self, dumb, third, forth, memory):
        cpu, comm, pid = self.task_utils.curProc() 
        if pid not in self.exit_hap:
            return
        if self.cpu != cpu:
                return
        if pid in self.pid_list:
            ''' returned from parent '''
            reg_num = self.cpu.iface.int_register.get_number('eax')
            ueax = self.cpu.iface.int_register.read(reg_num)
            eax = self.mem_utils.getSigned(ueax)
            if eax <= 0:
                self.lgr.debug('error return from clone? %d' % eax)
                self.context_manager.genDeleteHap(self.exit_hap[pid])
                del self.exit_hap[pid] 
                return
            child_pid = eax
            self.lgr.debug('TrackThreads exitHap for pid: %d adding child pid %d to contextManager' % (pid, child_pid))
            self.context_manager.addTask(child_pid)
            self.context_manager.genDeleteHap(self.exit_hap[pid])
            del self.exit_hap[pid]
            self.pid_list.append(child_pid)
        else: 
            self.lgr.debug('TrackThreads exitHap wrong pid %d looking for %s' % (pid, str(self.pid_list)))
