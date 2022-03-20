from simics import *
import syscall
import elfText
from resimHaps import *
class TrackThreads():
    def __init__(self, cpu, cell_name, cell, pid, context_manager, task_utils, mem_utils, param, traceProcs, soMap, targetFS, sharedSyscall, compat32, lgr):
        self.traceProcs = traceProcs
        self.parent_pid = pid
        self.pid_list = [pid]
        self.cpu = cpu
        ''' tbd, cell not used.  future ability to watch multiple task SO? '''
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
        self.finish_hap = {}
        self.finish_break = {}
        self.open_syscall = None
        self.first_mmap_hap = {}
        self.compat32 = compat32
        self.clone_hap = None
        self.child_stacks = {}


        ''' NOTHING AFTER THIS CALL! '''
        self.startTrack()
    def startTrack(self):
         
        if self.call_hap is not None:
            self.lgr.debug('TrackThreads startTrack called, but already tracking')
            return
        #self.lgr.debug('TrackThreads startTrack for %s compat32 is %r' % (self.cell_name, self.compat32))

        execve_callnum = self.task_utils.syscallNumber('execve', self.compat32)
        execve_entry = self.task_utils.getSyscallEntry(execve_callnum, self.compat32)
        self.execve_break = self.context_manager.genBreakpoint(None, Sim_Break_Linear, Sim_Access_Execute, execve_entry, 1, 0)
        self.execve_hap = self.context_manager.genHapIndex("Core_Breakpoint_Memop", self.execveHap, 'nothing', self.execve_break, 'trackThreads execve')
        #self.lgr.debug('TrackThreads set execve break at 0x%x startTrack' % (execve_entry))

        self.trackSO()
        #self.trackClone()
        if self.open_syscall is None:
            self.lgr.error('trackThreads startTrack, open_syscall is none')

    def stopSOTrack(self, immediate=True):
        #self.lgr.debug('TrackThreads hap syscall is %s' % str(self.open_syscall))
        if self.open_syscall is not None:
            #self.lgr.debug('TrackThreads stopTrack stop open trace')
            self.open_syscall.stopTrace(immediate=immediate)
            self.open_syscall = None
        else:
            self.lgr.debug('TrackThreads stopTrack no open syscall for %s' % self.cell_name)

    def stopTrack(self, immediate=False):
        #self.lgr.debug('TrackThreads, stop tracking for %s' % self.cell_name)
        self.context_manager.genDeleteHap(self.call_hap, immediate=immediate)
        self.context_manager.genDeleteHap(self.execve_hap, immediate=immediate)
        self.call_hap = None
        self.execve_hap = None
        for pid in self.exit_hap:
            self.context_manager.genDeleteHap(self.exit_hap[pid], immediate=immediate)
        self.stopSOTrack(immediate)
        for pid in self.first_mmap_hap:
            #self.lgr.debug('syscall stopTrace, delete mmap hap pid %d' % pid)
            self.context_manager.genDeleteHap(self.first_mmap_hap[pid], immediate=immediate)
        self.first_mmap_hap = {}
        self.stopTrackClone(immediate)


    def execveHap(self, dumb, third, forth, memory):
        ''' One of the threads we are tracking is going its own way via an execve, stop watching it '''
        if self.execve_hap is None:
            return
        
        cpu, comm, pid = self.task_utils.curProc() 
        if pid not in self.pid_list:
            #self.lgr.debug('TrackThreads  execveHap looked for pid %s, found %d.  Do nothing after parsing and updating proc trace' % (str(self.pid_list), pid))
            self.parseExecve()
            return
        if len(self.pid_list) == 1:
            self.lgr.debug('TrackThreads execveHap who is execing to what? eh? pid: %d' % pid)
            return
        #self.lgr.debug('TrackThreads execveHap remove pid %d from lists' % pid)
        self.context_manager.rmTask(pid)
        self.pid_list.remove(pid)
        self.parseExecve()


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
        #self.lgr.debug('trackThreads finishParseExecve progstring (%s)' % (prog_string))
        self.traceProcs.setName(pid, prog_string, None)
        self.addSO(prog_string, pid)
        RES_hap_delete_callback_id("Core_Breakpoint_Memop", self.finish_hap[pid])
        SIM_delete_breakpoint(self.finish_break[pid])
        del self.finish_hap[pid]
        del self.finish_break[pid]

    def addSO(self, prog_name, pid):
        full_path = self.targetFS.getFull(prog_name, self.lgr)
        if full_path is not None:
            #self.lgr.debug('trackThreads addSO, set target fs, progname is %s  full: %s' % (prog_name, full_path))

            elf_info = self.soMap.addText(full_path, prog_name, pid)
            if elf_info is None:
                self.lgr.debug('trackThreads addSO, could not get elf info from %s' % full_path)

    def parseExecve(self):
        cpu, comm, pid = self.task_utils.curProc() 
        ''' allows us to ignore internal kernel syscalls such as close socket on exec '''
        prog_string, arg_string_list = self.task_utils.getProcArgsFromStack(pid, False, cpu)
        
        if prog_string is None:
            ''' prog string not in ram, break on kernel read of the address and then read it '''
            prog_addr = self.task_utils.getExecProgAddr(pid, cpu)
            call_info = syscall.SyscallInfo(cpu, pid, None, None, None)
            self.lgr.debug('trackThreads parseExecve prog string missing, set break on 0x%x' % prog_addr)
            if prog_addr == 0:
                self.lgr.error('trackThreads parseExecve zero prog_addr pid %d' % pid)
                SIM_break_simulation('trackThreads parseExecve zero prog_addr pid %d' % pid)
            self.finish_break[pid] = SIM_breakpoint(cpu.current_context, Sim_Break_Linear, Sim_Access_Read, prog_addr, 1, 0)
            self.finish_hap[pid] = RES_hap_add_callback_index("Core_Breakpoint_Memop", self.finishParseExecve, call_info, self.finish_break[pid])
            return
        else:
            self.traceProcs.setName(pid, prog_string, None)
            self.addSO(prog_string, pid)




    def trackSO(self):
        call_list = ['open', 'mmap']
        if self.mem_utils.WORD_SIZE == 4 or self.compat32: 
            call_list.append('mmap2')
        ''' Use cell of None so only our threads get tracked '''
        self.open_syscall = syscall.Syscall(None, self.cell_name, None, self.param, self.mem_utils, self.task_utils, 
                           self.context_manager, None, self.sharedSyscall, self.lgr, None, call_list=call_list,
                           soMap=self.soMap, targetFS=self.targetFS, skip_and_mail=False, compat32=self.compat32, name='trackSO')
        #self.lgr.debug('TrackThreads watching open syscall for %s is %s' % (self.cell_name, str(self.open_syscall)))

    def cloneHap(self, dumb, third, forth, memory):
        ''' TBD remove not used '''
        if self.clone_hap is None:
            return
        cpu, comm, pid = self.task_utils.curProc() 
        if cpu.architecture == 'arm':
            frame = self.task_utils.frameFromRegs(cpu)
        else:
            frame = self.task_utils.frameFromStackSyscall()
        flags = frame['param1']
        child_stack = frame['param2']
        self.lgr.debug('cloneHap pid:%d flags:0x%x  stack:0x%x' % (pid, flags, child_stack))
        if pid not in self.child_stacks:
            self.child_stacks[pid] = []
        self.child_stacks[pid].append(child_stack)

    def getChildStack(self, pid):
        ''' TBD assumes first scheduled clone is the one first created '''
        if pid in self.child_stacks and len(self.child_stacks[pid]) > 0:
            return self.child_stacks[pid].pop(0)
        else:
            return None

    def trackClone(self):
        ''' TBD not used '''
        callnum = self.task_utils.syscallNumber('clone', self.compat32)
        entry = self.task_utils.getSyscallEntry(callnum, self.compat32)
        self.lgr.debug('trackClone entry 0x%x' % entry)
        proc_break = self.context_manager.genBreakpoint(None, Sim_Break_Linear, Sim_Access_Execute, entry, 1, 0)
        self.clone_hap = self.context_manager.genHapIndex("Core_Breakpoint_Memop", self.cloneHap, None, proc_break, 'track-clone')

    def stopTrackClone(self, immediate):
        if self.clone_hap is not None:
            self.context_manager.genDeleteHap(self.clone_hap, immediate) 
