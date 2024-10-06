from simics import *
import syscall
import elfText
import doInUser
from resimHaps import *
''' TBD rework scheme of when to track shared code loading.  maybe this should only be for linux clone '''
class TrackThreads():
    def __init__(self, top, cpu, cell_name, tid, context_manager, task_utils, mem_utils, param, traceProcs, soMap, targetFS, sharedSyscall, syscallManager, compat32, lgr):
        self.top = top
        self.traceProcs = traceProcs
        self.parent_tid = tid
        self.cpu = cpu
        self.cell_name = cell_name
        self.param = param
        self.context_manager = context_manager
        self.task_utils = task_utils
        self.mem_utils = mem_utils
        self.soMap = soMap
        self.targetFS = targetFS
        self.sharedSyscall = sharedSyscall
        self.syscallManager = syscallManager
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
        self.first_mmap_hap = {}
        self.compat32 = compat32
        self.clone_hap = None
        self.child_stacks = {}
        self.so_track = None


        ''' NOTHING AFTER THIS CALL! '''
        self.startTrack()
    def startTrack(self):
         
        if self.call_hap is not None:
            self.lgr.debug('TrackThreads startTrack called, but already tracking')
            return
        #self.lgr.debug('TrackThreads startTrack for %s compat32 is %r' % (self.cell_name, self.compat32))

        if not self.top.isWindows(): 
            # TBD move execve hap to syscall and use callback?  not good to duplicate computed entry point handling
            if self.cpu.architecture == 'arm64':
                platform = self.top.getCompDict(self.cell_name, 'PLATFORM')
                if platform == 'armMixed':
                    self.setExecveBreaks(arm64_app=True)
                    self.setExecveBreaks(arm64_app=False)
                elif platform == 'arm64':
                    self.setExecveBreaks(arm64_app=True)
                else:
                    self.setExecveBreaks(arm64_app=False)
            else:
                self.setExecveBreaks()

        self.trackSO()
        #self.trackClone()

    def setExecveBreaks(self, arm64_app=None):
        execve_callnum = self.task_utils.syscallNumber('execve', self.compat32, arm64_app=arm64_app)
        if execve_callnum is not None:
            execve_entry = self.task_utils.getSyscallEntry(execve_callnum, self.compat32, arm64_app=arm64_app)
            self.execve_break = self.context_manager.genBreakpoint(None, Sim_Break_Linear, Sim_Access_Execute, execve_entry, 1, 0)
            self.execve_hap = self.context_manager.genHapIndex("Core_Breakpoint_Memop", self.execveHap, 'nothing', self.execve_break, 'trackThreads execve')
            self.lgr.debug('TrackThreads set execve break at 0x%x startTrack' % (execve_entry))
        else:
            self.lgr.error('TrackThreads setExecveBreaks callnum is None')

    def stopSOTrack(self, immediate=True):
        #self.lgr.debug('TrackThreads hap syscall is %s' % str(self.open_syscall))
        pass

    def stopTrack(self, immediate=False):
        self.lgr.debug('TrackThreads, stop tracking for %s immediate: %r' % (self.cell_name, immediate))
        self.context_manager.genDeleteHap(self.call_hap, immediate=immediate)
        self.call_hap = None
        if self.execve_hap is not None:
            self.context_manager.genDeleteHap(self.execve_hap, immediate=immediate)
            self.execve_hap = None
        for tid in self.exit_hap:
            self.context_manager.genDeleteHap(self.exit_hap[tid], immediate=immediate)
        self.stopSOTrack(immediate)
        for tid in self.first_mmap_hap:
            #self.lgr.debug('syscall stopTrace, delete mmap hap tid:%s' % tid)
            self.context_manager.genDeleteHap(self.first_mmap_hap[tid], immediate=immediate)
        self.first_mmap_hap = {}
        self.stopTrackClone(immediate)
        ''' try deleting both contexts '''
        resim_context = self.context_manager.getRESimContextName()
        self.syscallManager.rmSyscall('trackSO', context=resim_context, immediate=immediate)
        default_context = self.context_manager.getDefaultContextName()
        self.syscallManager.rmSyscall('trackSO', context=default_context, immediate=immediate)
        #self.so_track.stopTrace()


    def execveHap(self, dumb, third, forth, memory):
        ''' One of the threads we are tracking is going its own way via an execve, stop watching it '''
        if self.execve_hap is None:
            return
        cpu, comm, tid = self.task_utils.curThread() 
        if tid == '0':
            return
        if not self.context_manager.amWatching(tid):
            self.lgr.debug('TrackThreads  execveHap failed to find tid %s in context manager ' % (tid))
            self.parseExecve()
            return
        if len(self.context_manager.getWatchTids()) == 1:
            self.lgr.debug('TrackThreads execveHap context manager tid list has only one, assume it is us? tid: %s' % tid)
            return
        self.lgr.debug('TrackThreads execveHap remove tid:%s from context manager watch' % tid)
        self.context_manager.rmTask(tid)
        self.parseExecve()


    def finishParseExecve(self, call_info, third, forth, memory):
        cpu, comm, tid = self.task_utils.curThread() 
        if cpu != call_info.cpu or tid != call_info.tid:
            return
        if tid not in self.finish_hap:
            return
        prog_string, arg_string_list = self.task_utils.readExecParamStrings(call_info.tid, call_info.cpu)
        if cpu.architecture == 'arm' and prog_string is None:
            self.lgr.debug('trackThreads finishParseExecve progstring None, arm fu?')
            return
        self.lgr.debug('trackThreads finishParseExecve progstring (%s)' % (prog_string))
        self.traceProcs.setName(tid, prog_string, None)
        param = (prog_string, tid)
        doInUser.DoInUser(self.top, self.cpu, self.addSO, param, self.task_utils, self.mem_utils, self.lgr)
        #self.addSO(prog_string, tid)
        RES_hap_delete_callback_id("Core_Breakpoint_Memop", self.finish_hap[tid])
        RES_delete_breakpoint(self.finish_break[tid])
        del self.finish_hap[tid]
        del self.finish_break[tid]

    def addSO(self, param_tuple):
        prog_name, tid = param_tuple
        full_path = self.targetFS.getFull(prog_name, self.lgr)
        if full_path is not None:
            self.lgr.debug('trackThreads addSO, set target fs, progname is %s  full: %s' % (prog_name, full_path))

            elf_info = self.soMap.addText(full_path, prog_name, tid)
            if elf_info is None:
                self.lgr.debug('trackThreads addSO, could not get elf info from %s' % full_path)

    def parseExecve(self):
        cpu, comm, tid = self.task_utils.curThread() 
        ''' allows us to ignore internal kernel syscalls such as close socket on exec '''
        prog_string, arg_string_list = self.task_utils.getProcArgsFromStack(tid, False, cpu)
        
        if prog_string is None:
            ''' prog string not in ram, break on kernel read of the address and then read it '''
            prog_addr = self.task_utils.getExecProgAddr(tid, cpu)
            call_info = syscall.SyscallInfo(cpu, tid, None, None, None)
            self.lgr.debug('trackThreads parseExecve prog string missing, set break on 0x%x' % prog_addr)
            if prog_addr == 0:
                self.lgr.error('trackThreads parseExecve zero prog_addr tid:%s' % tid)
                SIM_break_simulation('trackThreads parseExecve zero prog_addr tid:%s' % tid)
            self.finish_break[tid] = SIM_breakpoint(cpu.current_context, Sim_Break_Linear, Sim_Access_Read, prog_addr, 1, 0)
            self.finish_hap[tid] = RES_hap_add_callback_index("Core_Breakpoint_Memop", self.finishParseExecve, call_info, self.finish_break[tid])
            return
        else:
            self.traceProcs.setName(tid, prog_string, None)
            param = (prog_string, tid)
            doInUser.DoInUser(self.top, self.cpu, self.addSO, param, self.task_utils, self.mem_utils, self.lgr)
            #self.addSO(prog_string, tid)


    def trackSO(self):
        if self.top.isWindows():
            call_list = ['OpenFile', 'CreateSection', 'MapViewOfSection', 'CreateUserProcess', 'CreateFile', 'OpenSection']
        else:
            call_list = ['open', 'mmap']
            if self.mem_utils.WORD_SIZE == 4 or self.compat32: 
                call_list.append('mmap2')
        ''' Use cell of None so only our threads get tracked '''
        call_params = []
        self.so_track = self.syscallManager.watchSyscall(None, call_list, call_params, 'trackSO', stop_on_call=False, linger=True)
        self.lgr.debug('TrackThreads trackSO')
        #self.lgr.debug('TrackThreads watching open syscall for %s is %s' % (self.cell_name, str(self.open_syscall)))

    def cloneHap(self, dumb, third, forth, memory):
        ''' TBD remove not used '''
        if self.clone_hap is None:
            return
        cpu, comm, tid = self.task_utils.curThread() 
        if cpu.architecture == 'arm':
            frame = self.task_utils.frameFromRegs()
        else:
            frame = self.task_utils.frameFromStackSyscall()
        flags = frame['param1']
        child_stack = frame['param2']
        self.lgr.debug('cloneHap tid:%s flags:0x%x  stack:0x%x' % (tid, flags, child_stack))
        if tid not in self.child_stacks:
            self.child_stacks[tid] = []
        self.child_stacks[tid].append(child_stack)

    def getChildStack(self, tid):
        ''' TBD assumes first scheduled clone is the one first created '''
        if tid in self.child_stacks and len(self.child_stacks[tid]) > 0:
            return self.child_stacks[tid].pop(0)
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

    def checkContext(self):
        self.lgr.debug('trackThreads checkContext')
        self.stopTrack()
        self.startTrack()
