import os
import binascii
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
import winProg
import winSocket
import net
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

        self.sockwatch = syscall.SockWatch()

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

        break_simulation = False
        for call in self.call_params:
            if call is not None and call.break_simulation:
                break_simulation = True
                break 
 
        if flist_in is not None:
            ''' Given function list to use after syscall completes '''
            hap_clean = hapCleaner.HapCleaner(cpu)
            #for ph in self.proc_hap:
            #    self.lgr.debug('winSyscall proc hap %s adding to hap cleander' % str(ph))
            #    hap_clean.add("GenContext", ph)
            self.stop_action = hapCleaner.StopAction(hap_clean, break_list, flist_in, break_addrs = break_addrs)
            self.lgr.debug('Syscall cell %s stop action includes given flist_in.  stop_on_call is %r linger: %r name: %s' % (self.cell_name, stop_on_call, self.linger, name))
        elif (break_simulation or self.debugging) and not self.breakOnProg() and not trace and skip_and_mail:
            hap_clean = hapCleaner.HapCleaner(cpu)
            #for ph in self.proc_hap:
            #    hap_clean.add("GenContext", ph)
            #f1 = stopFunction.StopFunction(self.top.skipAndMail, [], nest=False)
            f1 = stopFunction.StopFunction(self.top.stepN, [1], nest=False)
            flist = [f1]
            self.stop_action = hapCleaner.StopAction(hap_clean, break_list, flist, break_addrs = break_addrs)
            self.lgr.debug('Syscall cell %s stop action includes stepN in flist. SOMap exists: %r linger: %r name: %s' % (self.cell_name, (soMap is not None), self.linger, name))
        else:
            hap_clean = hapCleaner.HapCleaner(cpu)
            #for ph in self.proc_hap:
            #    hap_clean.add("GenContext", ph)
            self.stop_action = hapCleaner.StopAction(hap_clean, break_list, [], break_addrs = break_addrs)
            self.lgr.debug('Syscall cell %s stop action includes NO flist linger: %r name: %s' % (self.cell_name, self.linger, name))

        self.exit_calls = ['TerminateProcess']
        
        ''' TBD '''
        self.stop_on_exit = False

        ''' Used when finding newly created tasks '''
        self.cur_task_break = None
        self.cur_task_hap = None
        self.current_tasks = []

        self.ioctl_op_map = winSocket.getOpMap()

    def breakOnProg(self):
        for call in self.call_params:
            if call is not None and call.subcall == 'CreateUserProcess' and call.break_simulation:
                self.lgr.debug('winSyscall breakOnProg return true')
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
            did_callnum = []
            for call in self.call_list:
                callnum = self.task_utils.syscallNumber(call)
                if callnum in did_callnum:
                    continue
                else:
                    did_callnum.append(callnum)
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
                    self.lgr.debug('winSyscall callnum %s name %s entry 0x%x call_params %s' % (callnum, call, entry, str(syscall_info)))
                    proc_break = self.context_manager.genBreakpoint(self.cell, Sim_Break_Linear, Sim_Access_Execute, entry, 1, 0)
                    proc_break1 = None
                    break_list.append(proc_break)
                    break_addrs.append(entry)
                    self.proc_hap.append(self.context_manager.genHapIndex("Core_Breakpoint_Memop", self.syscallHap, syscall_info, proc_break, call))
                if background:
                    dc = self.context_manager.getDefaultContext()
                    self.lgr.debug('winSyscall doBreaks set background breaks at 0x%x' % entry)
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

        if syscall_info.callnum is None:
           callnum = self.mem_utils.getCallNum(cpu)
           #self.lgr.debug('syscallHap callnum %d' % callnum)
           if callnum == 9999:
               SIM_break_simulation('0x4254, is that you?')
               reutrn
           ''' tracing all'''
           callname = self.task_utils.syscallName(callnum)
           if callname is None:
               self.lgr.debug('winSyscallHap tracing all bad callnum')
               return
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
           if callname is None:
               self.lgr.debug('winSyscallHap tracing selected callnumbers, bad call number %d  ?????' % (syscall_info.callnum))
               return
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
            self.lgr.debug('winSyscall %s exit of pid:%d stop_on_exit: %r' % (self.name, pid, self.stop_on_exit))
            ida_msg = '%s pid:%d' % (callname, pid)
            if callname == 'TerminateProcess':
                who = frame['param1']
                self.lgr.debug('winSyscall %s process who: 0x%x' % (callname, who))
                if who == 0xffffffffffffffff:
                    self.lgr.debug('winSyscall %s process will exit' % callname)
                    self.handleExit(pid, ida_msg, exit_group=True)
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
            #self.lgr.debug('syscallHap cell %s callnum %d syscall_info.callnum %d stop_on_call %r' % (self.cell_name, 
            #     callnum, syscall_info.callnum, self.stop_on_call))
            if syscall_info.callnum == callnum:
                exit_info = self.syscallParse(callnum, callname, frame, cpu, pid, comm, syscall_info)
                if exit_info is not None:
                    if comm != 'tar':
                            ''' watch syscall exit unless call_params narrowed a search failed to find a match '''
                            tracing_all = False 
                            if self.top is not None:
                                tracing_all = self.top.tracingAll(self.cell_name, pid)
                            if self.callback is None:
                                #if len(syscall_info.call_params) == 0 or exit_info.call_params is not None or tracing_all or pid in self.pid_sockets:
                                if not syscall.hasParamMatchRequest(syscall_info) or exit_info.call_params is not None or tracing_all or pid in self.pid_sockets:

                                    if self.stop_on_call:
                                        if exit_info.call_params is None or exit_info.call_params.name != 'runToCall':
                                            cp = syscall.CallParams('stop_on_call', None, None, break_simulation=True)
                                            exit_info.call_params = cp
                                    #self.lgr.debug('exit_info.call_params pid %d is %s' % (pid, str(exit_info.call_params)))
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
                        cp = CallParams('stop_on_call', None, None, break_simulation=True)
                        exit_info.call_params = cp
                    #self.lgr.debug('syscallHap pid:%d call addExitHap' % pid)
                    self.sharedSyscall.addExitHap(self.cell, pid, exit_eip1, exit_eip2, exit_eip3, exit_info, name)
                else:
                    self.lgr.debug('syscallHap pid:%d skip exitHap for tar' % pid)
            else:
                self.lgr.debug('winSyscall syscallHap pid:%d trace all got exit_info of none' % pid)


    def syscallParse(self, callnum, callname, frame, cpu, pid, comm, syscall_info, quiet=False):
        '''
        Parse a system call using many if blocks.  Note that setting exit_info to None prevent the return from the
        syscall from being observed (which is useful if this turns out to be not the exact syscall you were looking for.
        '''
        exit_info = syscall.ExitInfo(self, cpu, pid, callnum, None, frame)
        exit_info.syscall_entry = self.mem_utils.getRegValue(self.cpu, 'pc')
        trace_msg = None
        frame_string = taskUtils.stringFromFrame(frame)
        #self.lgr.debug('syscallParse syscall name: %s pid:%d callname <%s> params: %s' % (self.name, pid, callname, str(syscall_info.call_params)))
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
            elif call_param.name == 'runToCall':
                alter_callname = callname
                if callname == 'DeviceIoControlFile':
                    operation = frame['param6'] & 0xffffffff
                    if operation in self.ioctl_op_map:
                        alter_callname = self.ioctl_op_map[operation]
                if alter_callname not in self.call_list:
                    self.lgr.debug('syscall syscallParse, runToCall %s not in call list' % alter_callname)
                    return
                else:
                    exit_info.call_params = call_param
                    self.lgr.debug('syscall syscallParse %s, runToCall, no filter, matched, added call_param' % alter_callname)


        frame_string = taskUtils.stringFromFrame(frame)
        #trace_msg = 'pid:%d (%s) %s %s' % (pid, comm, callname, frame_string)
        #self.lgr.debug('winSyscall syscallParse '+trace_msg)
        pid_thread = self.task_utils.getPidAndThread()
        trace_msg = 'pid:%s (%s) %s' % (pid_thread, comm, callname)
        if callname == 'CreateUserProcess':
            ''' TBD move offsets into param '''
            rsp = frame['sp']
            ptr = rsp + 0x58
            base = self.mem_utils.readPtr(self.cpu, ptr)
            if base is not None:
                ptr2 = base + 0x18
                ptr3 = self.mem_utils.readPtr(self.cpu, ptr2)
                if ptr3 is None:
                    self.lgr.debug('winSyscall syscallParse cup %s ptr3 is None' % (trace_msg))
                else:
                    prog = self.mem_utils.readWinString(self.cpu, ptr3, 200)
                    trace_msg = trace_msg+' prog: %s frame: %s' % (prog, frame_string)
                    self.lgr.debug('winSyscall syscallparse cup %s' % trace_msg)
                    if self.name == 'CreateUserProcess': 
                        ''' TBD section needs cleanup.  criteria for debugging seems hazy'''
                        ''' checkProg will initiate debug sequence '''
                        want_to_debug = self.checkProg(prog, pid, exit_info)
                        if want_to_debug:
                            ''' remove param, no more syscall processing here '''
                            self.lgr.debug('winSyscall cup wants to debug?  remove call_params')
                            exit_info.call_params = None
                        else:
                            self.lgr.debug('winSyscall cup add %s as pending proc' % prog)
                            self.soMap.addPendingProc(prog)
            else:
                trace_msg = trace_msg + ' base read from 0x%x was none' % ptr
                self.lgr.debug(trace_msg)
                SIM_break_simulation(trace_msg)
        elif callname == 'ReadFile':
            exit_info.old_fd = frame['param1']
            exit_info.retval_addr = self.stackParam(2, frame)
            if exit_info.retval_addr is not None:
                count_ptr = self.stackParam(1, frame)
                count_val = self.mem_utils.readWord(self.cpu, count_ptr)
                trace_msg = trace_msg+' Handle: 0x%x buf_addr: 0x%x  count_ptr: 0x%x given count: %d' % (exit_info.old_fd, exit_info.retval_addr, count_ptr, count_val) 
            else:
                trace_msg = trace_msg+' Bad buffer address'

        elif callname == 'WriteFile':
            exit_info.old_fd = frame['param1']
            exit_info.retval_addr = self.stackParam(1, frame)
            count = self.stackParam(3, frame) & 0x00000000FFFFFFFF
            buffer_addr = self.stackParam(2, frame)
            write_string = self.mem_utils.readWinString(self.cpu, buffer_addr, count)
            trace_msg = trace_msg+' Handle: 0x%x retval_addr: 0x%x buff_addr: 0x%x  count: %d contents: %s' % (exit_info.old_fd, exit_info.retval_addr, buffer_addr, count, write_string)

        elif callname == 'CreateFile':
            if self.mem_utils.isKernel(frame['param1']):
                self.lgr.debug('winSyscall CreateFile internel to kernel')
            else: 
                str_size_addr = self.paramOffPtr(3, [0x10], frame) 
                str_size = self.mem_utils.readWord16(self.cpu, str_size_addr)
                exit_info.fname_addr = self.paramOffPtr(3, [0x10, 8], frame)
                
                if exit_info.fname_addr is None:
                    trace_msg = trace_msg+' fname address is None' 
                    self.lgr.debug(trace_msg)
                else:
                    exit_info.fname = self.mem_utils.readWinString(self.cpu, exit_info.fname_addr, str_size)
                    # TBD better approach?
                    exit_info.retval_addr = frame['param1']

                    # Permissions
                    access_mask = frame['param2']
                    file_attributes = self.stackParam(2, frame) & 0xffffffff
                    share_access = self.stackParam(3, frame) & 0xffffffff
                    create_disposition = self.stackParam(4, frame) & 0xffffffff
                    trace_msg = trace_msg+' fname: %s fname_addr: 0x%x retval_addr: 0x%x' % (exit_info.fname, exit_info.fname_addr, exit_info.retval_addr)

                    if exit_info.fname.endswith('Endpoint'):
                        extended_size = self.stackParam(7, frame)
                        if extended_size is not None:
                            extended_size = min(extended_size, 200)
                            extended_addr = self.stackParam(6, frame)
                            if extended_addr is not None:
                                extended = self.mem_utils.readBytes(self.cpu, extended_addr, extended_size)
                                if extended is not None:
                                    extended_hx = binascii.hexlify(extended)
                                    trace_msg = trace_msg + 'AFD extended: %s' % extended_hx
>>>>>>> origin/win7
                        

        elif callname in ['OpenFile', 'OpenKeyEx', 'OpenKey']:
            object_attr = frame['param3']
            str_size_addr = self.paramOffPtr(3, [0x10], frame) 
            str_size = self.mem_utils.readWord16(self.cpu, str_size_addr)
            if str_size is not None:
                self.lgr.debug('winSyscall Openfile str_size_addr 0x%x size %d' % (str_size_addr, str_size))

                exit_info.fname_addr = self.paramOffPtr(3, [0x10, 8], frame)
                exit_info.retval_addr = frame['param1']
                exit_info.fname = self.mem_utils.readWinString(self.cpu, exit_info.fname_addr, str_size)
                trace_msg = trace_msg+' fname: %s fname_addr: 0x%x fd_return_addr 0x%x' % (exit_info.fname, exit_info.fname_addr, exit_info.retval_addr)
                if True:
                    for call_param in syscall_info.call_params:
                        #self.lgr.debug('got param type %s' % type(call_param.match_param))
                        if call_param.match_param.__class__.__name__ == 'Dmod':
                             mod = call_param.match_param
                             #self.lgr.debug('is dmod, mod.getMatch is %s' % mod.getMatch())
                             #if mod.fname_addr is None:
                             if mod.getMatch() == exit_info.fname:
                                 self.lgr.debug('syscallParse, dmod match on fname %s, cell %s' % (exit_info.fname, self.cell_name))
                                 exit_info.call_params = call_param
                        if type(call_param.match_param) is str and (call_param.subcall is None or call_param.subcall.startswith(callname) and (call_param.proc is None or call_param.proc == self.comm_cache[pid])):
                            self.lgr.debug('syscall %s, found match_param %s' % (callname, call_param.match_param))
                            exit_info.call_params = call_param
                            
                            break
            #SIM_break_simulation('string at 0x%x' % exit_info.fname_addr)
  
        elif callname == 'DeviceIoControlFile':
            exit_info.old_fd = frame['param1']
            operation = frame['param6'] & 0xffffffff
            if operation in self.ioctl_op_map:
                op_cmd = self.ioctl_op_map[operation]
                trace_msg = trace_msg + ' '+op_cmd
                exit_info.socket_callname = op_cmd
            else:
                op_cmd = ''
            pdata_addr = frame['param7']
            len_pdata = frame['param8']
            size = min(len_pdata, 200)
            pdata = self.mem_utils.readBytes(self.cpu, pdata_addr, size)
            pdata_hx = None
            if pdata is not None:
                pdata_hx = binascii.hexlify(pdata)
            if op_cmd == 'BIND':
                #sock_addr = pdata_addr+self.mem_utils.wordSize(self.cpu)
                sock_addr = pdata_addr+4
                self.lgr.debug('pdata_addr 0x%x  socK_addr 0x%x' % (pdata_addr, sock_addr))
                sock_struct = net.SockStruct(self.cpu, sock_addr, self.mem_utils, exit_info.old_fd)
                to_string = sock_struct.getString()
                trace_msg = trace_msg+' '+to_string
                for call_param in syscall_info.call_params:
                    if call_param.subcall == 'BIND' and (call_param.proc is None or call_param.proc == self.comm_cache[pid]):
                         if call_param.match_param is not None:
                             go = None
                             if sock_struct.port is not None:
                                 ''' look to see if this address matches a given pattern '''
                                 s = sock_struct.dottedPort()
                                 pat = call_param.match_param
                                 try:
                                     go = re.search(pat, s, re.M|re.I)
                                 except:
                                     self.lgr.error('invalid expression: %s' % pat)
                                     return None
                             
                                 self.lgr.debug('socketParse look for match %s %s' % (pat, s))
                             if len(call_param.match_param.strip()) == 0 or go or call_param.match_param == sock_struct.sa_data: 
                                 self.lgr.debug('socketParse found match %s' % (call_param.match_param))
                                 exit_info.call_params = call_param
                                 if go:
                                     ida_msg = 'BIND to %s, FD: %d' % (s, sock_struct.fd)
                                 else:
                                     ida_msg = 'BIND to %s, FD: %d' % (call_param.match_param, sock_struct.fd)
                                 self.context_manager.setIdaMessage(ida_msg)
                                 exit_info.call_params = call_param
                                 break
    
                         if syscall.AF_INET in call_param.param_flags and sock_struct.sa_family == net.AF_INET:
                             exit_info.call_params = call_param
                             self.sockwatch.bind(pid, sock_struct.fd, call_param)
            elif op_cmd == 'CONNECT':
                sock_addr = pdata_addr+self.mem_utils.wordSize(self.cpu)
                self.lgr.debug('pdata_addr 0x%x  sock_addr 0x%x' % (pdata_addr, sock_addr))
                sock_struct = net.SockStruct(self.cpu, sock_addr, self.mem_utils, exit_info.old_fd)
                to_string = sock_struct.getString()
                trace_msg = trace_msg+' '+to_string

            if op_cmd in ['ACCEPT', '12083_ACCEPT']:
                if op_cmd == '12083_ACCEPT':
                    exit_info.new_fd = self.paramOffPtr(7, [4], frame)
                    trace_msg = trace_msg+' handle: 0x%x other handle 0x%x' % (exit_info.old_fd, exit_info.new_fd)
                else:
                    handle_addr = pdata_addr+self.mem_utils.wordSize(self.cpu)
                    exit_info.new_fd = self.mem_utils.readWord(self.cpu, handle_addr)
                trace_msg = trace_msg + " bind handle: 0x%x  connect handle: 0x%x" % (exit_info.old_fd, exit_info.new_fd)
                self.lgr.debug(trace_msg)
                for call_param in syscall_info.call_params:
                    self.lgr.debug('syscall accept subcall %s call_param.match_param is %s fd is %d' % (call_param.subcall, str(call_param.match_param), exit_info.old_fd))
                    if type(call_param.match_param) is int:
                        if (call_param.subcall == 'accept' or self.name=='runToIO') and (call_param.match_param < 0 or call_param.match_param == exit_info.old_fd):
                            self.lgr.debug('did accept match')
                            exit_info.call_params = call_param
                            self.context_manager.setIdaMessage(trace_msg)
                            break

            elif op_cmd == 'RECV':
                ''' buffer '''
                exit_info.retval_addr = self.paramOffPtr(7, [0, self.mem_utils.wordSize(self.cpu)], frame)
                # the return count address.
                exit_info.fname_addr = frame['param5'] + self.mem_utils.wordSize(self.cpu)
                ''' hack until we have method of figuring out 32/64 bit app. '''
                if exit_info.retval_addr is None or exit_info.retval_addr == 0:
                    exit_info.retval_addr = self.paramOffPtr(7, [0, 4], frame)
                    #exit_info.fname_addr = frame['param5'] + 4
                    exit_info.fname_addr = self.paramOffPtr(5, [0], frame) + 4
                exit_info.count = self.paramOffPtr(7, [0, 0], frame)
                trace_msg = trace_msg + ' handle: 0x%x buffer: 0x%x count: 0x%x ret_count_addr: 0x%x' %  (exit_info.old_fd, 
                       exit_info.retval_addr, exit_info.count, exit_info.fname_addr)
                trace_msg = trace_msg + ' '+str(pdata_hx)
                self.lgr.debug(trace_msg)
                #self.lgr.debug('RECV frame %s' % frame_string)
            elif op_cmd == 'SEND':
                #off = 3*self.mem_utils.wordSize(self.cpu)
                #exit_info.retval_addr = self.paramOffPtr(7, [0, off], frame)
                ''' buffer '''
                exit_info.retval_addr = self.paramOffPtr(7, [0, self.mem_utils.wordSize(self.cpu)], frame)
                ''' count return addr '''
                exit_info.fname_addr = frame['param5'] + self.mem_utils.wordSize(self.cpu)
                ''' hack until we have method of figuring out 32/64 bit app. '''
                if exit_info.retval_addr is None or exit_info.retval_addr == 0:
                    exit_info.retval_addr = self.paramOffPtr(7, [0, 4], frame)
                    exit_info.fname_addr = frame['param5'] + 4
                exit_info.count = self.paramOffPtr(7, [0, 0], frame)
                trace_msg = trace_msg + ' handle: 0x%x buffer: 0x%x count: 0x%x ret_count_addr: 0x%x' %  (exit_info.old_fd, exit_info.retval_addr, exit_info.count, exit_info.fname_addr)
            elif op_cmd == 'SEND_DATAGRAM':
                sock_addr = pdata_addr+self.mem_utils.wordSize(self.cpu)
                self.lgr.debug('pdata_addr 0x%x  sock_addr 0x%x' % (pdata_addr, sock_addr))
                sock_struct = net.SockStruct(self.cpu, sock_addr, self.mem_utils, exit_info.old_fd)
                to_string = sock_struct.getString()
                trace_msg = trace_msg+' '+to_string
            #elif op_cmd == 'TCP_FASTOPEN':
            #    trace_msg = trace_msg+' '+to_string

            else:
                trace_msg = trace_msg+' Handle: 0x%x operation: 0x%x' % (exit_info.old_fd, operation)
                if pdata is not None:
                    trace_msg = trace_msg+' pdata: %s' % pdata_hx
            self.lgr.debug('winSyscall socket check call params')
            for call_param in syscall_info.call_params:
                self.lgr.debug('winSyscall %s op_cmd: %s subcall is %s handle is %s match_param is %s call_param.name is %s' % (self.name, op_cmd, call_param.subcall, str(exit_info.old_fd), str(call_param.match_param), call_param.name))
                if (op_cmd in self.call_list or call_param.subcall == op_cmd)  and type(call_param.match_param) is int and \
                             (call_param.match_param == -1 or call_param.match_param == exit_info.old_fd) and \
                             (call_param.proc is None or call_param.proc == self.comm_cache[pid]):
                    if call_param.nth is not None:
                        call_param.count = call_param.count + 1
                        self.lgr.debug('syscall parse socket %s call_param.nth not none, is %d, count incremented to  %d' % (op_cmd, call_param.nth, call_param.count))
                        if call_param.count >= call_param.nth:
                            self.lgr.debug('count >= param, set exit_info.call_params to catch return')
                            exit_info.call_params = call_param
                            if self.kbuffer is not None:
                                self.lgr.debug('syscall read kbuffer for addr 0x%x' % exit_info.retval_addr)
                                self.kbuffer.read(exit_info.retval_addr, ss.length)
                    else:
                        self.lgr.debug('call_param.nth is none, call it matched')
                        exit_info.call_params = call_param
                        if self.kbuffer is not None:
                            self.lgr.debug('syscall read kbuffer for addr 0x%x' % exit_info.retval_addr)
                            self.kbuffer.read(exit_info.retval_addr, ss.length)
                    break
                elif call_param.name == 'runToCall':
                    if (op_cmd not in self.call_list):
                        self.lgr.debug('winSyscall parse socket call %s, but not what we think is a runToCall.' % op_cmd)
                        exit_info = None
                    else:
                        self.lgr.debug('winSyscall parse socket call %s, add call_param to exit_info' % op_cmd)
                        exit_info.call_params = call_param
 
        elif callname in ['CreateEvent', 'OpenProcessToken', 'OpenProcess']:
            exit_info.retval_addr = frame['param1']
            trace_msg = trace_msg+' handle addr: 0x%x' % (exit_info.retval_addr)

        elif callname in ['WaitForSingleObject']:
            exit_info.old_fd = frame['param1']
            trace_msg = trace_msg+' Handle: 0x%x' % (exit_info.old_fd)

        elif callname in ['WaitForMultipleObjects32']:
            count = frame['param1'] & 0xffff
            for i in range(count):
                #addr = frame['param2']+i*self.mem_utils.wordSize(self.cpu)
                addr = frame['param2']+i*4
                handle = self.mem_utils.readWord32(self.cpu, addr)
                trace_msg = trace_msg + " handle[%d]: 0x%x" % (i, handle)
 
        elif callname in ['ClearEvent']:
            exit_info.old_fd = frame['param1']
            trace_msg = trace_msg+' Handle: 0x%x' % (exit_info.old_fd)

        elif callname in ['QueryInformationFile', 'QueryInformationToken', 'RequestWaitReplyPort']:
            exit_info.old_fd = frame['param1']
            trace_msg = trace_msg+' Handle: 0x%x' % (exit_info.old_fd)

        elif callname in ['AlpcSendWaitReceivePort']:
            exit_info.old_fd = frame['param1']
            # contains size and will contain returned size
            exit_info.retval_addr = frame['param3']
            exit_info.count = self.mem_utils.readWord16(self.cpu, exit_info.retval_addr)
            if exit_info.count is not None:
                buf_start = frame['param3']+5*self.mem_utils.wordSize(self.cpu) 
                limit_count = min(exit_info.count, 100)
                buf = self.mem_utils.readBytes(self.cpu, buf_start, limit_count)
                trace_msg = trace_msg+' Handle: 0x%x count: 0x%x data: %s' % (exit_info.old_fd, exit_info.count, binascii.hexlify(buf))
            else:
                trace_msg = trace_msg+' Handle: 0x%x count is None' % (exit_info.old_fd)

        elif callname == 'ConnectPort':
            exit_info.fname_addr = self.paramOffPtr(2, [8], frame)
            str_size_addr = frame['param2']
            str_size = self.mem_utils.readWord16(self.cpu, str_size_addr)
            exit_info.fname = self.mem_utils.readWinString(self.cpu, exit_info.fname_addr, str_size)
            exit_info.retval_addr = frame['param1']
            trace_msg = trace_msg+' fname: %s fname addr: 0x%x fd return addr 0x%x' % (exit_info.fname, exit_info.fname_addr, exit_info.retval_addr)

        elif callname == 'AlpcConnectPort':
            exit_info.fname_addr = self.paramOffPtr(2, [8], frame)
            str_size_addr = frame['param2']
            str_size = self.mem_utils.readWord16(self.cpu, str_size_addr)
            exit_info.fname = self.mem_utils.readWinString(self.cpu, exit_info.fname_addr, str_size)
            exit_info.retval_addr = frame['param1']
            trace_msg = trace_msg+' fname: %s fname addr: 0x%x fd return addr 0x%x' % (exit_info.fname, exit_info.fname_addr, exit_info.retval_addr)
        elif callname == 'Continue':
            pass
        
            #if comm == 'TeamViewer_Ser':
            #    SIM_break_simulation('team viewer')
        elif callname == 'QueryValueKey':
            exit_info.old_fd = frame['param1']
            trace_msg = trace_msg+' Handle: 0x%x' % (exit_info.old_fd)

        elif callname == 'Close':
            exit_info.old_fd = frame['param1']
            trace_msg = trace_msg+' Handle: 0x%x' % (exit_info.old_fd)

        elif callname == 'CreateSection':
            exit_info.old_fd = self.stackParam(3, frame) 
            if exit_info.old_fd is not None:
                trace_msg = trace_msg+' Handle: 0x%x' % (exit_info.old_fd)
            else:
                trace_msg = trace_msg+' Handle: is None'

        elif callname == 'MapViewOfSection':
            exit_info.old_fd = frame['param1']
            trace_msg = trace_msg+' Handle: 0x%x' % (exit_info.old_fd)

        elif callname in ['CreateThread', 'CreateThreadEx']:
            exit_info.retval_addr = frame['param1']
            trace_msg = trace_msg+' handle addr 0x%x' % (exit_info.retval_addr)

        elif callname in ['AllocateVirtualMemory']:
            who = frame['param1']
            if who == 0xffffffffffffffff:
                trace_msg = trace_msg + ' for_process: %d (this one)' % (pid_thread)
            else:
                trace_msg = trace_msg+' for_process: 0x%x' % (who)  
            size = self.paramOffPtr(2, [0], frame)
            alloc_type = self.stackParam(1, frame)
            base = self.paramOffPtr(2, [0], frame)
<<<<<<< HEAD
            trace_msg = trace_msg+' base 0x%x size: 0x%x type: 0x%x' % (base, size, alloc_type)
=======
            if size is None or base is None:
                trace_msg = trace_msg+' failed reading base/size'
            else:
                trace_msg = trace_msg+' base 0x%x size: 0x%x' % (base, size)
>>>>>>> origin/win7
                
        elif callname == 'TerminateProcess':
            who = frame['param1']
            trace_msg = trace_msg+' who: 0x%x' % (who)
            if who == 0xffffffffffffffff:
                trace_msg = trace_msg+' (this process)'

        elif callname == 'DuplicateObject':
            exit_info.old_fd = frame['param2']
            exit_info.retval_addr = frame['param4']
            trace_msg = trace_msg+' handle: 0x%x  reval addr 0x%x' % (exit_info.old_fd, exit_info.retval_addr)
            for call_param in syscall_info.call_params:
                self.lgr.debug('syscall DuplicateObject subcall %s call_param.match_param is %s fd is %d' % (call_param.subcall, 
                     str(call_param.match_param), exit_info.old_fd))
                if type(call_param.match_param) is int:
                    if (call_param.subcall == 'accept' or self.name=='runToIO') and (call_param.match_param < 0 or call_param.match_param == exit_info.old_fd):
                        exit_info.call_params = call_param
                        self.lgr.debug('syscall DuplicateObject set call param to handle in exit')
                        break

        elif callname == 'QueryInformationProcess':
            who = frame['param1']
            if who == 0xffffffffffffffff:
                trace_msg = trace_msg + ' Process: %d (this one)' % (pid_thread)
            else:
                trace_msg = trace_msg+' Process: 0x%x' % (who) 
        #    entry = self.task_utils.getSyscallEntry(callnum)
        #    SIM_break_simulation('query information process computed 0x%x' % entry)
           
        else:
            #self.lgr.debug(trace_msg)
            pass
        self.lgr.debug('winSyscall syscallParse %s cycles:0x%x' % (trace_msg, self.cpu.cycles))
        #else:
        #    self.lgr.debug('Windows syscallParse, not looking for <%s>, remove exit info.' % callname)
        #    exit_info = None
        if exit_info is not None:
            exit_info.trace_msg = trace_msg
        if trace_msg is not None and not quiet:
            #self.lgr.debug(trace_msg.strip()) 
            
            #if trace_msg is not None and self.traceMgr is not None and (len(syscall_info.call_params) == 0 or exit_info.call_params is not None):
            if trace_msg is not None and self.traceMgr is not None:
                if len(trace_msg.strip()) > 0:
                    self.traceMgr.write(trace_msg+'\n'+frame_string+'\n')
        return exit_info

    def stackParam(self, pnum, frame):
        rsp = frame['sp']
        offset = 0x20 + (pnum * self.mem_utils.WORD_SIZE)
        ptr = rsp + offset
        value = self.mem_utils.readPtr(self.cpu, ptr)
        return value

    def stackParamPtr(self, pnum, ptr_offset, frame):
        value = None
        rsp = frame['sp']
        offset = 0x20 + (pnum * self.mem_utils.WORD_SIZE)
        ptr = rsp + offset
        #self.lgr.debug('stackParamPtr rsp 0x%x ptr 0x%x' % (rsp, ptr))
        ptr_value = self.mem_utils.readPtr(self.cpu, ptr)
        if ptr_value is not None:
            new_ptr = ptr_value++ptr_offset
            #self.lgr.debug('stackParamPtr new_ptr 0x%x' % new_ptr)
            value = self.mem_utils.readWord(self.cpu, new_ptr) 
        return value
        
    def paramOffPtr(self, pnum, offset_list, frame):
        param = 'param%d' % pnum
        pval = frame[param]
        for offset in offset_list:
            ptr = pval + offset
            #self.lgr.debug('paramOffPtr offset 0x%x from pval 0x%x ptr 0x%x' % (offset, pval, ptr))
            #pval = self.mem_utils.readPtr(self.cpu, ptr)
            pval = self.mem_utils.readWord32(self.cpu, ptr)
            if pval is not None:
                #self.lgr.debug('paramOffPtr got new pval 0x%x' % (pval))
                pass
            else:
                self.lgr.error('paramOffPtr got new pval is None reading from ptr 0x%x' % ptr)
                break
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
                    #self.lgr.debug('frame computed string %s' % frame_string)
                exit_eip1 = self.param.sysexit
                exit_eip2 = self.param.iretd
                exit_eip3 = self.param.sysret64
            else:
                self.lgr.error('syscallHap calculated, bad word size?')
            if frame is not None:     
                frame_string = taskUtils.stringFromFrame(frame)
            #self.lgr.debug('frame string %s' % frame_string)
        return frame, exit_eip1, exit_eip2, exit_eip3

    def checkProg(self, prog_string, pid, exit_info):
        ''' return True if we think the syscall params indicate we want to debug this'''
        retval = True
        self.lgr.debug('checkProg syscall %s  prog: %s' % (self.name, prog_string))
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
                        win_prog = winProg.WinProg(self.top, self.cpu, self.mem_utils, self.task_utils, self.context_manager, self.soMap, self.stop_action, self.param, self.lgr)
                        SIM_run_alone(win_prog.toNewProc, prog_string)
                        #SIM_run_alone(self.stopAlone, 'CreateUserProc of %s' % prog_string)
                    else:
                        self.lgr.debug('checkProg, got %s when looking for binary %s, skip' % (ftype, prog_string))
        else:
            retval = False
        return retval

    def stopAlone(self, msg):
        ''' NOTE: this is also called by sharedSyscall '''
        eip = self.top.getEIP()
        if self.stop_action is not None:
            self.stop_action.setExitAddr(eip)
        self.stop_hap = RES_hap_add_callback("Core_Simulation_Stopped", 
            	     self.stopHap, msg)
        self.lgr.debug('Syscall stopAlone cell %s added stopHap %d Now stop. msg: %s' % (self.cell_name, self.stop_hap, msg))
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
                #self.top.idaMessage() 
                ''' Run the stop action, which is a hapCleaner class '''
                funs = self.stop_action.listFuns()
                self.lgr.debug('syscall stopHap run stop_action, funs: %s' % funs)
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
            syscall_info = syscall.SyscallInfo(self.cpu, None, callnum, pc, self.trace, self.call_params)
            callname = self.task_utils.syscallName(callnum, syscall_info.compat32) 

            frame, exit_eip1, exit_eip2, exit_eip3 = self.getExitAddrs(pc, syscall_info, frames[pid])

            exit_info = syscall.ExitInfo(self, self.cpu, pid, callnum, syscall_info.compat32, frame)
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

    def stopTrace(self, immediate=False):
        #self.lgr.debug('Winsyscall stopTrace call_list %s immediat: %r' % (str(self.call_list), immediate))
        proc_copy = list(self.proc_hap)
        for ph in proc_copy:
            #self.lgr.debug('syscall stopTrace, delete self.proc_hap %d' % ph)
            self.context_manager.genDeleteHap(ph, immediate=immediate)
            self.proc_hap.remove(ph)

        #self.lgr.debug('winSyscall do call to stopTraceAlone alone')
        SIM_run_alone(self.stopTraceAlone, None)
        #self.lgr.debug('did call to alone')
        if self.top is not None and not self.top.remainingCallTraces(cell_name=self.cell_name):
            self.sharedSyscall.stopTrace()

        for pid in self.first_mmap_hap:
            #self.lgr.debug('syscall stopTrace, delete mmap hap pid %d' % pid)
            self.context_manager.genDeleteHap(self.first_mmap_hap[pid], immediate=immediate)
        self.first_mmap_hap = {}

        ''' Remove from syscall lists managed by genMonitor '''
        if self.top is not None and self.call_list is not None:
            for callname in self.call_list:
                #self.lgr.debug('winSyscall stopTrace call top rmCallTrace for call_list item %s' % callname)
                self.top.rmCallTrace(self.cell_name, callname)
            ''' and try removing based on the syscall name '''
            #self.lgr.debug('winSyscall stopTrace call top rmCallTrace for %s' % self.name)
            self.top.rmCallTrace(self.cell_name, self.name)
        ''' reset SO map tracking ''' 
        self.sharedSyscall.trackSO(True)
        self.bang_you_are_dead = True
        #self.lgr.debug('winSyscall stopTrace return for %s' % self.name)

    def stopTraceAlone(self, dumb):
        #self.lgr.debug('winSyscall stopTraceAlone')
        if self.stop_hap is not None:
            RES_hap_delete_callback_id("Core_Simulation_Stopped", self.stop_hap)
            self.stop_hap = None

        #self.lgr.debug('winSyscall stopTraceAlone2')
        if self.background_break is not None:
            #self.lgr.debug('winSyscall stopTraceAlone delete background_break %d' % self.background_break)
            RES_delete_breakpoint(self.background_break)
            RES_hap_delete_callback_id("Core_Breakpoint_Memop", self.background_hap)
            self.background_break = None
            self.background_hap = None
        self.sharedSyscall.rmExitBySyscallName(self.name, self.cell)

        if self.cur_task_hap is not None:
            rmNewProcHap(self.cur_task_hap)
            self.cur_task_hap = None
        #self.lgr.debug('stopTraceAlone done')

    def resetTimeofdayCount(self, pid):
        self.timeofday_count[pid] = 0

    def getTimeofdayCount(self, pid):
        return self.timeofday_count[pid]

    def stopMazeHap(self, syscall, one, exception, error_string):
        if self.stop_maze_hap is not None:
            SIM_run_alone(self.top.exitMaze, syscall)
            RES_hap_delete_callback_id("Core_Simulation_Stopped", self.stop_maze_hap)
            self.stop_maze_hap = None

    def stopForMazeAlone(self, syscall):
        self.stop_maze_hap = RES_hap_add_callback("Core_Simulation_Stopped", self.stopMazeHap, syscall)
        self.lgr.debug('Syscall added stopMazeHap Now stop, syscall: %s' % (syscall))
        SIM_break_simulation('automaze')

    def checkMaze(self, syscall):
        cpu, comm, pid = self.task_utils.curProc() 
        self.lgr.debug('Syscall checkMaze pid:%d in timer loop' % pid)
        #maze_exit = self.top.checkMazeReturn()
        #if False and maze_exit is not None:
        #    self.lgr.debug('mazeExit checkMaze pid:%d found existing maze exit that matches' % pid)
        #    maze_exit.mazeReturn(True)
        #else:
        if True:
            if self.top.getAutoMaze():
                SIM_run_alone(self.stopForMazeAlone, syscall)
            else:
                rprint("Pid %d seems to be in a timer loop.  Try exiting the maze? Use @cgc.exitMaze('%s')" % (pid, syscall))
                SIM_break_simulation('timer loop?')
   
 
    def modeChanged(self, fun_arg, one, old, new):
        the_fun, arg = fun_arg
        if self.mode_hap is None:
            return
        self.lgr.debug('syscall modeChanged old %d new %d' % (old, new))
        if old == Sim_CPU_Mode_Supervisor:
            RES_hap_delete_callback_id("Core_Mode_Change", self.mode_hap)
            self.mode_hap = None
            SIM_run_alone(the_fun, arg)
            

    def checkTimeLoop(self, callname, pid):
        if self.cpu.architecture == 'arm':
            return
        limit = 800
        delta_limit = 0x12a05f200
        if pid not in self.timeofday_count:
            self.timeofday_count[pid] = 0
        self.lgr.debug('checkTimeLoop pid:%d timeofday_count: %d' % (pid, self.timeofday_count[pid]))
        ''' crude measure of whether we are in a delay loop '''
        if self.timeofday_count[pid] == 0:
            self.timeofday_start_cycle[pid] = self.cpu.cycles
        self.timeofday_count[pid] = self.timeofday_count[pid] + 1
        if self.timeofday_count[pid] >= limit:
            now = self.cpu.cycles
            delta = now - self.timeofday_start_cycle[pid]
            self.lgr.debug('timeofday pid:%d count is %d, now 0x%x was 0x%x delta 0x%x' % (pid, self.timeofday_count[pid], now, self.timeofday_start_cycle[pid], delta))
            #if delta < 0x2540be40:
            if delta < delta_limit:
                self.timeofday_count[pid] = 0
                self.mode_hap = RES_hap_add_callback_obj("Core_Mode_Change", self.cpu, 0, self.modeChanged, (self.checkMaze, callname))
            else:
                self.timeofday_count[pid] = 0
                self.lgr.debug('checkTimeLoop pid:%d reset tod count' % pid)

    def stopOnExit(self):
        self.stop_on_exit=True
        self.lgr.debug('syscall stopOnExit')

    def handleExit(self, pid, ida_msg, killed=False, retain_so=False, exit_group=False):
            ''' TBD fix for windws?'''
            if self.traceProcs is not None:
                self.traceProcs.exit(pid)
            if killed:
                self.lgr.debug('syscall handleExit, was killed so remove skipAndMail from stop_action')
                self.stop_action.rmFun(self.top.skipAndMail)
            self.lgr.debug(ida_msg)
            if self.traceMgr is not None:
                self.traceMgr.write(ida_msg+'\n')
            self.context_manager.setIdaMessage(ida_msg)
            if self.soMap is not None:
                if not retain_so and not self.context_manager.amWatching(pid):
                    self.soMap.handleExit(pid, killed)
            else:
                self.lgr.debug('syscallHap exit soMap is None, pid:%d' % (pid))
            last_one = self.context_manager.rmTask(pid, killed) 
            debugging_pid, dumb = self.context_manager.getDebugPid()
            self.lgr.debug('syscallHap handleExit %s pid %d last_one %r debugging %d retain_so %r exit_group %r debugging_pid %s' % (self.name, pid, last_one, self.debugging, retain_so, exit_group, str(debugging_pid)))
            if (killed or last_one or (exit_group and pid == debugging_pid)) and self.debugging:
                if self.top.hasProcHap():
                    ''' exit before we got to text section '''
                    self.lgr.debug('syscall handleExit  exit of %d before we got to text section ' % pid)
                    SIM_run_alone(self.top.undoDebug, None)
                self.lgr.debug('syscall handleExit exit or exit_group or tgkill pid:%d' % pid)
                self.sharedSyscall.stopTrace()
                ''' record exit so we don't see this proc, e.g., when going to debug its next instantiation '''
                self.task_utils.setExitPid(pid)
                #fun = stopFunction.StopFunction(self.top.noDebug, [], False)
                #self.stop_action.addFun(fun)
                print('exit pid %d' % pid)
                SIM_run_alone(self.stopAlone, 'exit or exit_group pid:%d' % pid)

    def addCallParams(self, call_params):
        gotone = False
        for call in call_params:
            if call not in self.syscall_info.call_params:
                self.syscall_info.call_params.append(call)
                gotone = True
        ''' TBD inconsistent stop actions????'''
        if gotone:
            if self.stop_action is None:
                f1 = stopFunction.StopFunction(self.top.skipAndMail, [], nest=False)
                flist = [f1]
                hap_clean = hapCleaner.HapCleaner(self.cpu)
                self.stop_action = hapCleaner.StopAction(hap_clean, [], flist)
            self.lgr.debug('syscall addCallParams added params')
        else:
            pass
            #self.lgr.debug('syscall addCallParams, no new params')

    def isRecordFD(self):
        return self.record_fd

    def setRecordFD(self, tof):
        self.record_fd = tof

    def getContext(self):
        return self.cell

    def rmCallParam(self, call_param):
        if call_param in self.syscall_info.call_params: 
            self.syscall_info.call_params.remove(call_param)
        else: 
            self.lgr.error('sycall rmCallParam, but param does not exist?')

    def rmCallParamName(self, call_param_name):
        return_list = []
        rm_list = []
        for cp in self.syscall_info.call_params:
            if cp.name == call_param_name:
                rm_list.append(cp)
            else:
                return_list.append(cp)
        for cp in rm_list:
            self.syscall_info.call_params.remove(cp)
        return return_list

    def getCallParams(self):
        return self.syscall_info.call_params

    def remainingDmod(self):
        for call_param in self.syscall_info.call_params:
            if call_param.match_param.__class__.__name__ == 'Dmod':
                 return True
        return False

    def hasCallParam(self, param_name):
        retval = False
        for call_param in self.syscall_info.call_params:
            if call_param.name == param_name:
                retval = True
                break 
        return retval

    def getDmods(self):
        retval = []
        for call_param in self.syscall_info.call_params:
            if call_param.match_param.__class__.__name__ == 'Dmod':
                 dmod = call_param.match_param
                 if dmod not in retval:
                     retval.append(dmod)
        return retval

    def rmDmods(self):
        params_copy = list(self.syscall_info.call_params)
        rm_list = []
        for call_param in params_copy:
            if call_param.match_param.__class__.__name__ == 'Dmod':
                self.lgr.debug('syscall rmDmods, removing dmod %s' % call_param.match_param.path)
                rm_list.append(call_param)

        for call_param in rm_list:
            self.rmCallParam(call_param)
        if len(self.syscall_info.call_params) == 0:
            self.lgr.debug('syscall rmDmods, no more call_params, remove syscall')
            self.stopTrace()

    def getCallList(self):
        return self.call_list

    def callListContains(self, call_list):
        retval = True
        if self.call_list is not None and len(self.call_list)>0:
            for call in call_list:
                if call not in self.call_list:
                    retval = False
                    break
        else:
           retval = False
        return retval 

    def callListIntersects(self, call_list):
        retval = False
        if self.call_list is not None and len(self.call_list)>0:
            for call in call_list:
                #self.lgr.debug('syscall compare %s to %s' % (call, str(self.call_list)))
                if call in self.call_list:
                    retval = True
                    break
        return retval 

