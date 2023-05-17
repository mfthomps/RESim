import os
import re
from simics import *
import hapCleaner
import taskUtils
import net
import ipc
import memUtils
import stopFunction
import pageUtils
import dmod
import resimUtils
import syscall
import sys
import copy
import ntpath
from resimHaps import *
from resimUtils import rprint
class WinSyscall():

    def __init__(self, top, cell_name, cell, param, mem_utils, task_utils, context_manager, traceProcs, sharedSyscall, lgr, 
                   traceMgr, call_list=None, trace = False, flist_in=None, soMap = None, 
                   call_params=[], connectors=None, stop_on_call=False, targetFS=None, skip_and_mail=True, linger=False,
                   background=False, name=None, record_fd=False, callback=None, swapper_ok=False, kbuffer=None): 
        self.lgr = lgr
        self.traceMgr = traceMgr
        self.mem_utils = mem_utils
        self.task_utils = task_utils
        self.context_manager = context_manager
        ''' mostly a test if we are debugging (if pid is not none). not very clean '''
        pid, cpu = context_manager.getDebugPid()
        self.debugging = False
        self.stop_on_call = stop_on_call
        if pid is not None:
            self.debugging = True
            #self.lgr.debug('Syscall is debugging cell %s' % cell_name)
        self.cpu = cpu
        ''' Note cell may be None, leaving it up to the context manager '''
        self.cell_name = cell_name
        self.cell = cell
        if cell is not None:
            self.lgr.debug('syscall _init_ cell_name %s, name: %s, param: %s cell is not none, cell.name: %s' % (cell_name, name, str(call_params), cell.name))
        else:
            self.lgr.debug('syscall _init_ cell_name %s, name: %s, param: %s cell is none.' % (cell_name, name, str(call_params)))
        self.top = top
        self.param = param
        self.sharedSyscall = sharedSyscall
        self.traceProcs = traceProcs
        self.stop_hap = None
        self.finish_hap = {}
        self.finish_break = {}
        self.finish_hap_page = {}
        self.finish_hap_table = {}
        self.first_mmap_hap = {}
        self.soMap = soMap
        self.proc_hap = []
        ''' lists of sockets by pid that we are watching for selected tracing '''
        self.timeofday_count = {}
        self.timeofday_start_cycle = {}
        self.call_list = call_list
        self.trace = trace
        if call_params is None:
            self.call_params = []
        else:
            self.call_params = call_params
        self.stop_action = None
        self.stop_maze_hap = None
        self.targetFS = targetFS
        self.linger = linger
        self.linger_cycles = []
        self.background_break = None
        self.background_hap = None
        self.name = name
        self.watch_first_mmap = None
        self.mmap_fname = None
        self.comm_cache = {}
        self.record_fd = record_fd
        self.syscall_info = None
        self.alt_syscall_info = None
        self.callback = callback
        ''' normally ignore syscalls made by swapper '''
        self.swapper_ok = swapper_ok

        ''' catch dual invocation of syscallHap.  TBD, find root cause and yank it out '''
        self.hack_cycle = 0

        self.ignore_progs = context_manager.getIgnoredProgs()

        if trace is None and self.traceMgr is not None:
            tf = '/tmp/syscall_trace.txt'
            #self.traceMgr.open(tf, cpu, noclose=True)
            self.traceMgr.open(tf, cpu)
        ''' track kernel buffers '''
        self.kbuffer = kbuffer

        '''complex means of tracking socket info'''
        self.pid_sockets = {}
        self.pid_fd_sockets = {}

        ''' And one for tracking epoll info '''
        self.epolls = {}
      
        self.syscall_context = None 
        self.background = background
        break_list, break_addrs = self.doBreaks(background)
 
        if flist_in is not None:
            ''' Given function list to use after syscall completes '''
            hap_clean = hapCleaner.HapCleaner(cpu)
            for ph in self.proc_hap:
                hap_clean.add("Core_Breakpoint_Memop", ph)
            self.stop_action = hapCleaner.StopAction(hap_clean, break_list, flist_in, break_addrs = break_addrs)
            self.lgr.debug('Syscall cell %s stop action includes given flist_in.  stop_on_call is %r linger: %r name: %s' % (self.cell_name, stop_on_call, self.linger, name))
        elif self.debugging and not self.breakOnProg() and not trace and skip_and_mail:
            hap_clean = hapCleaner.HapCleaner(cpu)
            for ph in self.proc_hap:
                hap_clean.add("Core_Breakpoint_Memop", ph)
            #f1 = stopFunction.StopFunction(self.top.skipAndMail, [], nest=False)
            f1 = stopFunction.StopFunction(self.top.stepN, [1], nest=False)
            flist = [f1]
            self.stop_action = hapCleaner.StopAction(hap_clean, break_list, flist, break_addrs = break_addrs)
            self.lgr.debug('Syscall cell %s stop action includes stepN in flist. SOMap exists: %r linger: %r name: %s' % (self.cell_name, (soMap is not None), self.linger, name))
        else:
            hap_clean = hapCleaner.HapCleaner(cpu)
            for ph in self.proc_hap:
                hap_clean.add("Core_Breakpoint_Memop", ph)
            self.stop_action = hapCleaner.StopAction(hap_clean, break_list, [], break_addrs = break_addrs)
            self.lgr.debug('Syscall cell %s stop action includes NO flist linger: %r name: %s' % (self.cell_name, self.linger, name))

        self.exit_calls = []
        ''' TBD '''
        self.stop_on_exit = False

        ''' Used when finding newly created tasks '''
        self.cur_task_break = None
        self.cur_task_hap = None
        self.current_tasks = []

    def breakOnProg(self):
        for call in self.call_params:
            if call is not None and call.subcall == 'CreateUserProcess' and call.break_simulation:
                return True
        return False

    def doBreaks(self, background):
        break_list = []
        break_addrs = []
        self.timeofday_count = {}
        self.timeofday_start_cycle = {}
        self.lgr.debug('winSyscall cell_name %s doBreaks.  reset timeofdaycount' % (self.cell_name))
        if self.call_list is None:
            ''' trace all calls '''
            self.syscall_info = syscall.SyscallInfo(self.cpu, None, None, None, self.trace)
            if self.cpu.architecture == 'arm':
                #phys = self.mem_utils.v2p(self.cpu, self.param.arm_entry)
                #self.lgr.debug('Syscall arm no callnum, set break at 0x%x ' % (self.param.arm_entry))
                proc_break = self.context_manager.genBreakpoint(self.cell, Sim_Break_Linear, Sim_Access_Execute, self.param.arm_entry, 1, 0)
                if self.syscall_context is None:
                    self.syscall_context = self.context_manager.getBPContext(proc_break)
                    #self.lgr.debug('syscall, setting syscall_context to %s' % self.syscall_context)
                #proc_break = self.context_manager.genBreakpoint(self.cpu.physical_memory, Sim_Break_Physical, Sim_Access_Execute, phys, 1, 0)
                break_addrs.append(self.param.arm_entry)
                self.proc_hap.append(self.context_manager.genHapIndex("Core_Breakpoint_Memop", self.syscallHap, self.syscall_info, proc_break, 'syscall'))
            else:
                if self.param.sysenter is not None:
                    proc_break = self.context_manager.genBreakpoint(self.cell, Sim_Break_Linear, Sim_Access_Execute, self.param.sysenter, 1, 0)
                    break_addrs.append(self.param.sysenter)
                    break_list.append(proc_break)
                    if self.param.sys_entry is not None and self.param.sys_entry != 0:
                        ''' Has sys_entry as well. '''
                        #self.lgr.debug('Syscall no callnum, set sysenter and sys_entry break at 0x%x & 0x%x' % (self.param.sysenter, self.param.sys_entry))
                        self.lgr.debug('Syscall no callnum, set sys_entry break at 0x%x ' % (self.param.sys_entry))
                        proc_break1 = self.context_manager.genBreakpoint(self.cell, Sim_Break_Linear, Sim_Access_Execute, self.param.sys_entry, 1, 0)
                        break_addrs.append(self.param.sys_entry)
                        break_list.append(proc_break1)
                        self.proc_hap.append(self.context_manager.genHapRange("Core_Breakpoint_Memop", self.syscallHap, self.syscall_info, proc_break, proc_break1, 'syscall'))
                    else:
                        self.lgr.debug('Syscall no callnum, set sysenter break at 0x%x ' % (self.param.sysenter))
                        self.proc_hap.append(self.context_manager.genHapIndex("Core_Breakpoint_Memop", self.syscallHap, self.syscall_info, proc_break, 'syscall'))
                elif self.param.sys_entry is not None and self.param.sys_entry != 0:
                        #self.lgr.debug('Syscall no callnum, set sys_entry break at 0x%x' % (self.param.sys_entry))
                        proc_break1 = self.context_manager.genBreakpoint(self.cell, Sim_Break_Linear, Sim_Access_Execute, self.param.sys_entry, 1, 0)
                        break_addrs.append(self.param.sys_entry)
                        break_list.append(proc_break1)
                        self.proc_hap.append(self.context_manager.genHapIndex("Core_Breakpoint_Memop", self.syscallHap, self.syscall_info, proc_break1, 'syscall'))
                else:
                    self.lgr.debug('SysCall no call list, no breaks set.  parms: %s' % self.param.getParamString())
        
        else:
            ''' will stop within the kernel at the computed entry point '''
            for call in self.call_list:
                callnum = self.task_utils.syscallNumber(call)
                self.lgr.debug('SysCall doBreaks call: %s  num: %d' % (call, callnum))
                if callnum is not None and callnum < 0:
                    self.lgr.error('Syscall bad call number %d for call <%s>' % (callnum, call))
                    return None, None
                entry = self.task_utils.getSyscallEntry(callnum)
                if entry is None:
                    self.lgr.error('Failed to get entry for callnum %d' % callnum)
                    return None, None
                #phys = self.mem_utils.v2p(cpu, entry)
                #proc_break = self.context_manager.genBreakpoint(self.cpu.physical_memory, Sim_Break_Physical, Sim_Access_Execute, phys, 1, 0)
                syscall_info = syscall.SyscallInfo(self.cpu, None, callnum, entry, self.trace, self.call_params)
                self.syscall_info = syscall_info
                debug_pid, dumb = self.context_manager.getDebugPid() 
                if not background or debug_pid is not None:
                    self.lgr.debug('Syscall callnum %s name %s entry 0x%x call_params %s' % (callnum, call, entry, str(syscall_info)))
                    proc_break = self.context_manager.genBreakpoint(self.cell, Sim_Break_Linear, Sim_Access_Execute, entry, 1, 0)
                    proc_break1 = None
                    break_list.append(proc_break)
                    break_addrs.append(entry)
                    self.proc_hap.append(self.context_manager.genHapIndex("Core_Breakpoint_Memop", self.syscallHap, syscall_info, proc_break, call))
                if background:
                    dc = self.context_manager.getDefaultContext()
                    self.lgr.debug('doBreaks set background breaks at 0x%x' % entry)
                    self.background_break = SIM_breakpoint(dc, Sim_Break_Linear, Sim_Access_Execute, entry, 1, 0)
                    self.background_hap = RES_hap_add_callback_index("Core_Breakpoint_Memop", self.syscallHap, syscall_info, self.background_break)

        return break_list, break_addrs

    def syscallHap(self, syscall_info, context, break_num, memory):
        ''' Invoked when syscall is detected.  May set a new breakpoint on the
            return to user space so as to collect remaining parameters, or to stop
            the simulation as part of a debug session '''
        ''' NOTE Does not track Tar syscalls! '''
        cpu, comm, pid = self.task_utils.curProc() 
        #self.lgr.debug('winSyscall syscallHap pid:%d (%s) %s context %s break_num %s cpu is %s t is %s' % (pid, comm, self.name, str(context), str(break_num), str(memory.ini_ptr), type(memory.ini_ptr)))
        #self.lgr.debug('memory.ini_ptr.name %s' % (memory.ini_ptr.name))

        break_eip = self.mem_utils.getRegValue(self.cpu, 'pc')
        if syscall_info.cpu != cpu:
            self.lgr.error('syscallHap wrong cell, cur: %s, expected %s' % (cpu.name, syscall_info.cpu.name))
            return

        self.comm_cache[pid] = comm
        if self.linger:
            if cpu.cycles in self.linger_cycles:
                #self.lgr.debug('syscalHap for lingering call we already made.')
                return
            else:
                self.linger_cycles.append(cpu.cycles)
        else:
            ''' for example, rec calls rec_from '''
            if self.hack_cycle+20 >= cpu.cycles:
                self.lgr.debug('syscallHap pid:%d skip back-to-back calls within 10 cycles. TBD fix this for cases where cycles match?.' % pid)
                return
            else:
                self.hack_cycle = cpu.cycles

        callnum = self.mem_utils.getCallNum(cpu)
        #self.lgr.debug('syscallHap callnum %d' % callnum)
        if syscall_info.callnum is None:
           ''' tracing all'''
           callname = self.task_utils.syscallName(callnum)
           if self.record_fd and (callname not in record_fd_list or comm in skip_proc_list):
               self.lgr.debug('syscallHap not in record_fd list: %s' % callname)
               return
           syscall_instance = self.top.getSyscall(self.cell_name, callname) 
           if syscall_instance is not None and syscall_instance != self and syscall_instance.isBackground() == self.isBackground() and callname != 'exit_group' and syscall_instance.getContext() == self.cell:
               #self.lgr.debug(str(syscall_instance))
               #self.lgr.debug(str(self))
               self.lgr.debug('syscallHap tracing all pid %d callnum %d name %s found more specific syscall hap, so ignore this one' % (pid, callnum, callname))
               return
           if callname == 'mmap' and pid in self.first_mmap_hap:
               return
        else:
           ''' not callnum from reg may not be the real callnum, Use syscall_info.callnum.
               Also, this is a cacluated entry....'''
           callname = self.task_utils.syscallName(syscall_info.callnum) 
           if self.record_fd and (callname not in record_fd_list or comm in skip_proc_list):
               return
           if pid == 1 and callname in ['open', 'mmap', 'mmap2']:
               ''' ad-hoc noise reduction '''
               return
           callnum = syscall_info.callnum
        ''' call 0 is read in 64-bit '''
        if callnum == 0 and self.mem_utils.WORD_SIZE==4:
            self.lgr.debug('syscallHap callnum is zero')
            return
        value = memory.logical_address
        #self.lgr.debug('syscallHap cell %s context %sfor pid:%s (%s) at 0x%x (memory 0x%x) callnum %d expected %s name: %s cycle: 0x%x' % (self.cell_name, str(context), 
        #     pid, comm, break_eip, value, callnum, str(syscall_info.callnum), self.name, self.cpu.cycles))
           
        if not self.swapper_ok and comm == 'swapper/0' and pid == 1:
            self.lgr.debug('syscallHap, skipping call from init/swapper')
            return

        if len(self.proc_hap) == 0 and self.background_break is None:
            self.lgr.debug('syscallHap entered for pid %d after hap deleted' % pid)
            return
        if syscall_info.cpu is not None and cpu != syscall_info.cpu:
            self.lgr.debug('syscallHap, wrong cpu %s %s' % (cpu.name, syscall_info.cpu.name))
            return

        ''' catch stray calls from wrong pid.  Allow calls if the syscall instance's cell is not None, which means it is not up to the context manager
            to watch or not.  TBD needed for windows?'''
        if self.debugging and not self.context_manager.amWatching(pid) and syscall_info.callnum is not None and self.background_break is None and self.cell is None:
            self.lgr.debug('syscallHap name: %s pid:%d missing from context manager.  Debugging and specific syscall watched. callnum: %d' % (self.name, 
                 pid, syscall_info.callnum))
            return


        if pid == 0:
            value = memory.logical_address
            ''' TBD debug simics?  seems broken '''
            self.lgr.debug('syscallHap pid 0, unexpected break_ip 0x%x memory says 0x%x len of haps is %d' % (break_eip, value, len(self.proc_hap)))
            return

        #self.lgr.debug('syscallhap for %s at 0x%x' % (pid, break_eip))
            
        frame, exit_eip1, exit_eip2, exit_eip3 = self.getExitAddrs(break_eip, syscall_info)
        if frame is None:
            value = memory.logical_address
            ''' TBD Simics broken???? occurs due to a mov dword ptr fs:[0xc149b454],ebx '''
            self.lgr.debug('syscallHap pid:%d unexpected break_ip 0x%x memory says 0x%x len of haps is %d' % (pid, break_eip, value, len(self.proc_hap)))
            #SIM_break_simulation('unexpected break eip 0x%x' % break_eip)

            return

        if callnum > 0xfff:
            self.lgr.warning('syscallHap callnum is too big')
            #SIM_break_simulation('remove this call %d' % callnum)
            return
        
        if self.sharedSyscall.isPendingExecve(pid):
            ''' TBD fix for windows '''
            if callname == 'close':
                self.lgr.debug('syscallHap must be a close on exec? pid:%d' % pid)
                return
            elif callname == 'CreateUserProcess':
                self.lgr.debug('syscallHap must be a CreateUserProcess in CreateUserProcess? pid:%d' % pid)
                return
            elif callname == 'exit_group':
                self.lgr.debug('syscallHap exit_group called from within execve %d' % pid)
                return
            elif callname == 'uname':
                self.lgr.debug('syscallHap uname called from within execve %d' % pid)
                return
            else:
                self.lgr.error('fix this, syscall within exec? pid:%d call: %s' % (pid, callname))
                SIM_break_simulation('fix this')
                return

        if self.name is None:
            exit_info_name = '%s-exit' % (callname)
        else:
            exit_info_name = '%s-%s-exit' % (callname, self.name)

        pending_call = self.sharedSyscall.getPendingCall(pid, exit_info_name)
                 

        if callname in self.exit_calls:
            self.context_manager.pidExit(pid)
            if callname == 'tgkill':
                tgid = frame['param1']
                tid = frame['param2']
                sig = frame['param3']
                ida_msg = '%s pid:%d tgid: %d  tid: %d sig:%d' % (callname, pid, tgid, tid, sig)
                if tid != pid:
                    self.lgr.error('tgkill called from %d for other process %d, fix this TBD!' % (pid, tid))
                    return
            else: 
                ida_msg = '%s pid:%d' % (callname, pid)
            self.lgr.debug('syscallHap %s exit of pid:%d stop_on_exit: %r' % (self.name, pid, self.stop_on_exit))
            if callname == 'exit_group':
                self.handleExit(pid, ida_msg, exit_group=True)
            elif callname == 'tgkill' and sig == 6:
                self.handleExit(pid, ida_msg, killed=True)
            else:
                self.handleExit(pid, ida_msg)
            self.context_manager.stopWatchPid(pid)
            if self.stop_on_exit:
                self.lgr.debug('syscall break simulation for stop_on_exit')
                SIM_break_simulation(ida_msg)
            return

        ''' Set exit breaks '''
        #self.lgr.debug('syscallHap in proc %d (%s), callnum: 0x%x  EIP: 0x%x' % (pid, comm, callnum, break_eip))
        #self.lgr.debug('syscallHap frame: %s' % frame_string)
        frame_string = taskUtils.stringFromFrame(frame)
        #self.lgr.debug('syscallHap frame: %s' % frame_string)


        if syscall_info.callnum is not None:
            self.lgr.debug('syscallHap cell %s callnum %d syscall_info.callnum %d stop_on_call %r' % (self.cell_name, 
                 callnum, syscall_info.callnum, self.stop_on_call))
            if syscall_info.callnum == callnum:
                exit_info = self.syscallParse(callnum, callname, frame, cpu, pid, comm, syscall_info)
                if exit_info is not None:
                    if comm != 'tar':
                            ''' watch syscall exit unless call_params narrowed a search failed to find a match '''
                            tracing_all = False 
                            if self.top is not None:
                                tracing_all = self.top.tracingAll(self.cell_name, pid)
                            if self.callback is None:
                                if len(syscall_info.call_params) == 0 or exit_info.call_params is not None or tracing_all or pid in self.pid_sockets:
                                    if self.stop_on_call:
                                        cp = CallParams(None, None, break_simulation=True)
                                        exit_info.call_params = cp
                                    self.lgr.debug('exit_info.call_params pid %d is %s' % (pid, str(exit_info.call_params)))
                                    self.sharedSyscall.addExitHap(self.cpu.current_context, pid, exit_eip1, exit_eip2, exit_eip3, exit_info, exit_info_name)
                                else:
                                    self.lgr.debug('did not add exitHap')
                                    pass
                            else:
                                self.lgr.debug('syscall invoking callback')
                                self.callback()
                    else:
                        self.lgr.debug('syscallHap skipping tar %s, no exit' % comm)
                else:
                    self.lgr.debug('syscallHap exitInfo is None')
            else:
                self.lgr.debug('syscallHap call num does not match?')
                
        else:
            ''' tracing all syscalls, or watching for any syscall, e.g., during debug '''
            exit_info = self.syscallParse(callnum, callname, frame, cpu, pid, comm, syscall_info)
            #self.lgr.debug('syscall looking for any, got %d from %d (%s) at 0x%x ' % (callnum, pid, comm, break_eip))

            if exit_info is not None:
                if comm != 'tar':
                    name = callname+'-exit' 
                    #self.lgr.debug('syscallHap call to addExitHap for pid %d' % pid)
                    if self.stop_on_call:
                        cp = CallParams(None, None, break_simulation=True)
                        exit_info.call_params = cp
                    self.sharedSyscall.addExitHap(self.cell, pid, exit_eip1, exit_eip2, exit_eip3, exit_info, name)
                else:
                    self.lgr.debug('syscallHap pid:%d skip exitHap for tar' % pid)


    def syscallParse(self, callnum, callname, frame, cpu, pid, comm, syscall_info, quiet=False):
        '''
        Parse a system call using many if blocks.  Note that setting exit_info to None prevent the return from the
        syscall from being observed (which is useful if this turns out to be not the exact syscall you were looking for.
        '''
        exit_info = syscall.ExitInfo(self, cpu, pid, callnum, None, frame)
        exit_info.syscall_entry = self.mem_utils.getRegValue(self.cpu, 'pc')
        ida_msg = None
        frame_string = taskUtils.stringFromFrame(frame)
        self.lgr.debug('syscallParse syscall name: %s pid:%d callname <%s> params: %s' % (self.name, pid, callname, str(syscall_info.call_params)))
        for call_param in syscall_info.call_params:
            if call_param.match_param.__class__.__name__ == 'PidFilter':
                if pid != call_param.match_param.pid:
                    self.lgr.debug('syscall syscallParse, pid filter did not match')
                    return
                else:
                    exit_info.call_params = call_param
                    self.lgr.debug('syscall syscallParse %s, pid filter matched, added call_param' % callname)
            elif call_param.match_param.__class__.__name__ == 'Dmod' and len(syscall_info.call_params) == 1:
                if call_param.match_param.comm is not None and call_param.match_param.comm != comm:
                    #self.lgr.debug('syscall syscallParse, Dmod %s does not match comm %s, return' % (call_param.match_param.comm, comm))
                    self.lgr.debug('syscall syscallParse, Dmod does not match comm %s, return' % (comm))
                    return
        frame_string = taskUtils.stringFromFrame(frame)
        ida_msg = 'pid:%d (%s) %s %s' % (pid, comm, callname, frame_string)
        if callname == 'CreateUserProcess':
            rsp = frame['rsp']
            ptr = rsp + 0x58
            base = self.mem_utils.readPtr(self.cpu, ptr)
            if base is not None:
                ptr2 = base + 0x18
                ptr3 = self.mem_utils.readPtr(self.cpu, ptr2)

                prog = self.mem_utils.readWinString(self.cpu, ptr3, 200)
                ida_msg = 'pid:%d (%s) %s %s %s' % (pid, comm, callname, prog, frame_string)
                self.lgr.debug('Windows syscallParse, got it  %s ptr: 0x%x, base 0x%x, ptr2: 0x%x ptr3 0x%x  prog %s' % (callname, ptr, base, ptr2, ptr3, prog))
                want_to_debug = self.checkProg(prog, pid, exit_info)
                if want_to_debug:
                    ''' remove param '''
                    exit_info.call_params = None
        elif callname == 'ReadFile':
            exit_info.old_fd = frame['param1']
            exit_info.retval_addr = self.stackParam(2, frame)
            count_ptr = self.stackParam(1, frame)
            count_val = self.mem_utils.readWord(self.cpu, count_ptr)
            ida_msg = 'pid:%d (%s) %s FD: %d buf_addr: 0x%x  count_ptr: 0x%x given count: %d' % (pid, comm, callname, exit_info.old_fd, exit_info.retval_addr, count_ptr, count_val) 
        elif callname == 'OpenFile':
            exit_info.fname_addr = self.paramOffPtr(3, [0x10, 8], frame)
            exit_info.retval_addr = frame['param1']
            self.lgr.debug('inSyscall syscallParse got fname addr 0x%x' % exit_info.fname_addr)
            ida_msg = 'pid:%d (%s) %s fname addr: 0x%x fd return addr 0x%x' % (pid, comm, callname, exit_info.fname_addr, exit_info.retval_addr)
            #SIM_break_simulation('remove this')
        elif callname == 'ConnectPort':
            exit_info.fname_addr = self.paramOffPtr(2, [8], frame)
            exit_info.retval_addr = frame['param1']
            self.lgr.debug('inSyscall syscallParse got fname addr 0x%x' % exit_info.fname_addr)
            ida_msg = 'pid:%d (%s) %s fname addr: 0x%x fd return addr 0x%x' % (pid, comm, callname, exit_info.fname_addr, exit_info.retval_addr)



        #elif callname == 'QueryInformationProcess':
        #    entry = self.task_utils.getSyscallEntry(callnum)
        #    SIM_break_simulation('query information process computed 0x%x' % entry)
           
        else:
            #self.lgr.debug(ida_msg)
            pass
        self.lgr.debug('winSyscall syscallParse %s' % ida_msg)
        #else:
        #    self.lgr.debug('Windows syscallParse, not looking for <%s>, remove exit info.' % callname)
        #    exit_info = None
        if ida_msg is not None and not quiet:
            #self.lgr.debug(ida_msg.strip()) 
            
            #if ida_msg is not None and self.traceMgr is not None and (len(syscall_info.call_params) == 0 or exit_info.call_params is not None):
            if ida_msg is not None and self.traceMgr is not None:
                if len(ida_msg.strip()) > 0:
                    self.traceMgr.write(ida_msg+'\n')
        return exit_info

    def stackParam(self, pnum, frame):
        rsp = frame['rsp']
        offset = 0x20 + (pnum * self.mem_utils.WORD_SIZE)
        ptr = rsp + offset
        value = self.mem_utils.readPtr(self.cpu, ptr)
        return value
        
    def paramOffPtr(self, pnum, offset_list, frame):
        param = 'param%d' % pnum
        pval = frame[param]
        for offset in offset_list:
            ptr = pval + offset
            #self.lgr.debug('paramOffPtr offset 0x%x from pval 0x%x ptr 0x%x' % (offset, pval, ptr))
            pval = self.mem_utils.readPtr(self.cpu, ptr)
            #if pval is not None:
            #    self.lgr.debug('paramOffPtr got new pval 0x%x' % (pval))
            #else:
            #    self.lgr.debug('paramOffPtr got new pval is None')
        return pval
    

    def getExitAddrs(self, break_eip, syscall_info, frame = None):
        exit_eip1 = None
        exit_eip2 = None
        exit_eip3 = None
        frame = None 
        if break_eip == self.param.sysenter:
            ''' caller frame will be in regs'''
            if frame is None:
                frame = self.task_utils.frameFromRegs()
                frame_string = taskUtils.stringFromFrame(frame)
            exit_eip1 = self.param.sysexit
            ''' catch interrupt returns such as wait4 '''
            exit_eip2 = self.param.iretd
            try:
                exit_eip3 = self.param.sysret64
                #self.lgr.debug('syscall getExitAddrs has sysret64 exit1 0x%x 2 0x%x 3 0x%x' % (exit_eip1, exit_eip2, exit_eip3))
            except AttributeError:
                exit_eip3 = None
                #self.lgr.debug('syscall getExitAddrs no sysret64 exit1 0x%x 2 0x%x ' % (exit_eip1, exit_eip2))
        elif False and break_eip == self.param.arm_entry:
            exit_eip1 = self.param.arm_ret
            exit_eip2 = self.param.arm_ret2
            if frame is None:
                frame = self.task_utils.frameFromRegsComputed()
                frame_string = taskUtils.stringFromFrame(frame)
                #SIM_break_simulation(frame_string)
        elif break_eip == syscall_info.calculated:
            ''' Note EIP in stack frame is unknown '''
            #frame['eax'] = syscall_info.callnum
            if self.cpu.architecture == 'arm':
                if frame is None:
                    frame = self.task_utils.frameFromRegsComputed()
                exit_eip1 = self.param.arm_ret
                exit_eip2 = self.param.arm_ret2
                exit_eip2 = None
                #exit_eip3 = self.param.sysret64
            elif self.mem_utils.WORD_SIZE == 8:
                if frame is None:
                    frame = self.task_utils.frameFromRegsComputed()
                    frame_string = taskUtils.stringFromFrame(frame)
                    self.lgr.debug('frame computed string %s' % frame_string)
                exit_eip1 = self.param.sysexit
                exit_eip2 = self.param.iretd
                exit_eip3 = self.param.sysret64
            else:
                self.lgr.error('syscallHap calculated, bad word size?')
            if frame is not None:     
                frame_string = taskUtils.stringFromFrame(frame)
            self.lgr.debug('frame string %s' % frame_string)
        return frame, exit_eip1, exit_eip2, exit_eip3

    def checkProg(self, prog_string, pid, exit_info):
        retval = True
        self.lgr.debug('checkProg syscall %s  %s' % (self.name, prog_string))
        cp = None
        for call in self.call_params:
            #self.lgr.debug('checkProg call %s' % call)
            if call.subcall == 'CreateUserProcess':
                cp = call
                break
        if cp is None:
            for call in self.syscall_info.call_params:
                self.lgr.debug('checkProg traceall call %s' % call)
                if call.subcall == 'CreateUserProcess':
                    cp = call
                    break
            
        if cp is not None: 
            if cp.match_param.__class__.__name__ == 'Dmod':
               self.task_utils.modExecParam(pid, self.cpu, cp.match_param)
            else: 

                retval = False
                if '\\' in cp.match_param:
                    ''' compare full path '''
                    base = prog_string
                else:
                    base = ntpath.basename(prog_string)
                self.lgr.debug('checkProg base %s against %s' % (base, cp.match_param))
                if base.startswith(cp.match_param):
                    ''' is program file we are looking for.  do we care if it is a binary? '''
                    self.lgr.debug('matches base')
                    wrong_type = False
                    '''
                    TBD fix for Windows
                    if self.traceProcs is not None:
                        ftype = self.traceProcs.getFileType(pid)
                        if ftype is None:
                            full_path = self.targetFS.getFull(prog_string, self.lgr)
                            if full_path is not None and os.path.isfile(full_path):
                                ftype = magic.from_file(full_path)
                                if ftype is None:
                                    self.lgr.error('checkProg failed to find file type for %s pid:%d' % (prog_string, pid))
                                    return
                        if ftype is not None and 'binary' in cp.param_flags and 'elf' not in ftype.lower():
                            wrong_type = True
                    '''
                    if not wrong_type:
                        self.lgr.debug('checkProg CreateUserProc of %s call toNewProc' % prog_string)
                        retval = True
                        #exit_info.call_params = cp 
                        exit_info.call_params = None
                        self.toNewProc(prog_string)
                        #SIM_run_alone(self.stopAlone, 'CreateUserProc of %s' % prog_string)
                    else:
                        self.lgr.debug('checkProg, got %s when looking for binary %s, skip' % (ftype, prog_string))
        return retval

    def stopAlone(self, msg):
        ''' NOTE: this is also called by sharedSyscall '''
        eip = self.top.getEIP()
        if self.stop_action is not None:
            self.stop_action.setExitAddr(eip)
        self.stop_hap = RES_hap_add_callback("Core_Simulation_Stopped", 
            	     self.stopHap, msg)
        #self.lgr.debug('Syscall stopAlone cell %s added stopHap %d Now stop. msg: %s' % (self.cell_name, self.stop_hap, msg))
        SIM_break_simulation(msg)

    def stopHap(self, msg, one, exception, error_string):
        '''  Invoked when a syscall (or more typically its exit back to user space) triggers
             a break in the simulation
        '''
        if self.stop_hap is not None:
            RES_hap_delete_callback_id("Core_Simulation_Stopped", self.stop_hap)
            self.stop_hap = None
            eip = self.mem_utils.getRegValue(self.cpu, 'pc')
            if self.stop_action is not None:
                self.lgr.debug('syscall stopHap name: %s cycle: 0x%x eip: 0x%x exception %s error %s linger: %r' % (self.name, self.stop_action.hap_clean.cpu.cycles, eip, str(exception), str(error_string), self.linger))
            else:
                self.lgr.debug('syscall stopHap, no stop_action') 
            if not self.linger:
                break_list = self.stop_action.getBreaks()
                if eip not in break_list and eip != self.stop_action.getExitAddr():
                    self.lgr.debug('syscall stopHap 0x%x not in break list, not our stop %s' % (eip, ' '.join(hex(x) for x in break_list)))
                    #self.top.skipAndMail()
                    return
       
                for hc in self.stop_action.hap_clean.hlist:
                    if hc.hap is not None:
                        #self.lgr.debug('will delete hap %s' % str(hc.hap))
                        self.context_manager.genDeleteHap(hc.hap)
                        hc.hap = None
                self.lgr.debug('syscall stopHap will delete hap %s' % str(self.stop_hap))
                for bp in self.stop_action.breakpoints:
                    self.context_manager.genDeleteBreakpoint(bp)
                ''' check functions in list '''
                self.lgr.debug('syscall stopHap call to rmExitHap')
                self.sharedSyscall.rmExitHap(None)

                ''' TBD do this as a stop function? '''
                cpu, comm, pid = self.task_utils.curProc() 
                self.sharedSyscall.rmPendingExecve(pid)

                ''' TBD when would we want to close it?'''
                if self.traceMgr is not None:
                    self.traceMgr.flush()
                self.top.idaMessage() 
                ''' Run the stop action, which is a hapCleaner class '''
                self.lgr.debug('syscall stopHap run stop_action')
                self.stop_action.run(cb_param=msg)

                if self.call_list is not None:
                    for callname in self.call_list:
                        #self.top.rmCallTrace(self.cell_name, callname)
                        self.top.rmCallTrace(self.cell_name, self.name)
            else:
                self.lgr.debug('syscall will linger and catch next occurance')
                self.top.skipAndMail()

    def setExits(self, frames, origin_reset=False, context_override=None):
        ''' set exits for a list of frames, intended for tracking when syscall has already been made and the process is waiting '''
        for pid in frames:
            self.lgr.debug('setExits frame of pid %d is %s' % (pid, taskUtils.stringFromFrame(frames[pid])))
            if frames[pid] is None:
                continue
            pc = frames[pid]['pc']
            callnum = frames[pid]['syscall_num']
            syscall_info = SyscallInfo(self.cpu, None, callnum, pc, self.trace, self.call_params)
            callname = self.task_utils.syscallName(callnum, syscall_info.compat32) 

            frame, exit_eip1, exit_eip2, exit_eip3 = self.getExitAddrs(pc, syscall_info, frames[pid])

            exit_info = ExitInfo(self, self.cpu, pid, callnum, syscall_info.compat32, frame)
            exit_info.retval_addr = frames[pid]['param2']
            exit_info.count = frames[pid]['param3']
            exit_info.old_fd = frames[pid]['param1']
            self.lgr.debug('setExits set count to parm3 now 0x%x' % exit_info.count)

            the_callname = callname
            ''' tbd for socket calls and selectish calls...'''
            if callname == 'socketcall' or callname.upper() in net.callname:
                the_callname = self.handleReadOrSocket(callname, frames[pid], exit_info, syscall_info)
            elif callname in ['select','_newselect', 'pselect6']:        
                self.handleSelect(callname, pid, frames[pid], exit_info, syscall_info)

            if exit_info.call_params is not None:
                exit_info.origin_reset = origin_reset
                if exit_info.retval_addr is not None:
                    self.lgr.debug('setExits almost done for pid %d call %d retval_addr is 0x%x' % (pid, callnum, exit_info.retval_addr))
                else:
                    self.lgr.debug('setExits almost done for pid %d call %d retval_addr is None' % (pid, callnum))
                exit_info_name = '%s-%s-exit' % (the_callname, self.name)
                self.sharedSyscall.addExitHap(self.cell, pid, exit_eip1, exit_eip2, exit_eip3, exit_info, exit_info_name, context_override=context_override)
            else:
                self.lgr.debug('setExits call_param is none')

    def toNewProc(self, prog_string):
        self.lgr.debug('toNewProc %s' % prog_string)
        phys_current_task = self.task_utils.getPhysCurrentTask()
        self.cur_task_break = SIM_breakpoint(self.cpu.physical_memory, Sim_Break_Physical, Sim_Access_Write, 
                             phys_current_task, self.mem_utils.WORD_SIZE, 0)
        self.cur_task_hap = RES_hap_add_callback_index("Core_Breakpoint_Memop", self.toNewProcHap, prog_string, self.cur_task_break)
        self.current_tasks = self.task_utils.getTaskList()
        #SIM_run_alone(SIM_continue, 0)

    def toNewProcHap(self, prog_string, third, forth, memory):
        if self.cur_task_hap is None:
            return
        #self.lgr.debug('winMonitor toNewProcHap for proc %s' % proc)
        cur_thread = SIM_get_mem_op_value_le(memory)
        cur_proc = self.task_utils.getCurTaskRec(cur_thread=cur_thread)
        if cur_proc not in self.current_tasks:
            comm = self.mem_utils.readString(self.cpu, cur_proc+self.param.ts_comm, 16)
            proc = ntpath.basename(prog_string)
            self.lgr.debug('winMonitor does %s start with %s?' % (proc, comm))
            if proc.startswith(comm):
                pid_ptr = cur_proc + self.param.ts_pid
                pid = self.mem_utils.readWord(self.cpu, pid_ptr)
                self.lgr.debug('winMonitor toNewProcHap got new %s pid:%d' % (comm, pid))
                SIM_run_alone(self.rmNewProcHap, self.cur_task_hap)
                self.cur_task_hap = None
                self.task_utils.addProgram(pid, prog_string)
                self.context_manager.addTask(pid)
                new_fun = stopFunction.StopFunction(self.context_manager.watchTasks, [True], nest=False)
                if self.stop_action is not None:
                    flist = self.stop_action.getFlist()
                    flist.append(new_fun)
                else:
                    flist = [new_fun]
                SIM_run_alone(self.top.toUser, flist)
                SIM_run_alone(self.stopTrace, False)
                #SIM_break_simulation('got new proc %s' % proc)

    def rmNewProcHap(self, newproc_hap):
        SIM_hap_delete_callback_id("Core_Breakpoint_Memop", newproc_hap)
        if self.cur_task_break is not None:
            SIM_delete_breakpoint(self.cur_task_break)
            self.cur_task_break = None

    def stopTraceAlone(self, dumb):
        #self.lgr.debug('stopTraceAlone')
        if self.stop_hap is not None:
            RES_hap_delete_callback_id("Core_Simulation_Stopped", self.stop_hap)
            self.stop_hap = None

        #self.lgr.debug('stopTraceAlone2')
        if self.background_break is not None:
            self.lgr.debug('stopTraceAlone delete background_break %d' % self.background_break)
            RES_delete_breakpoint(self.background_break)
            RES_hap_delete_callback_id("Core_Breakpoint_Memop", self.background_hap)
            self.background_break = None
            self.background_hap = None
        self.sharedSyscall.rmExitBySyscallName(self.name, self.cell)
        #self.lgr.debug('stopTraceAlone done')


    def stopTrace(self, immediate=False):
        #self.lgr.debug('syscall stopTrace call_list %s immediat: %r' % (str(self.call_list), immediate))
        proc_copy = list(self.proc_hap)
        for ph in proc_copy:
            #self.lgr.debug('syscall stopTrace, delete self.proc_hap %d' % ph)
            self.context_manager.genDeleteHap(ph, immediate=immediate)
            self.proc_hap.remove(ph)

        #self.lgr.debug('do call to alone')
        SIM_run_alone(self.stopTraceAlone, None)
        #self.lgr.debug('did call to alone')
        if self.top is not None and not self.top.remainingCallTraces(cell_name=self.cell_name):
            self.sharedSyscall.stopTrace()

        for pid in self.first_mmap_hap:
            self.lgr.debug('syscall stopTrace, delete mmap hap pid %d' % pid)
            self.context_manager.genDeleteHap(self.first_mmap_hap[pid], immediate=immediate)
        self.first_mmap_hap = {}

        ''' Remove from syscall lists managed by genMonitor '''
        if self.top is not None and self.call_list is not None:
            for callname in self.call_list:
                self.top.rmCallTrace(self.cell_name, callname)
            ''' and try removing based on the syscall name '''
            self.top.rmCallTrace(self.cell_name, self.name)
        ''' reset SO map tracking ''' 
        self.sharedSyscall.trackSO(True)
        self.bang_you_are_dead = True
        #self.lgr.debug('syscall stopTrace return for %s' % self.name)
