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
import elfText
import dmod
import sys
import copy
from resimHaps import *
from resimUtils import rprint
'''
how does simics not have this in its python sys.path?
'''
sys.path.append('/usr/local/lib/python2.7/dist-packages')
import magic
'''
    Trace syscalls.  Used for process tracing and debug, e.g., runToConnect.
    When used in debugging, or tracing a single process, we assume that
    genContextManager enables and disables breakpoints based on what process
    is scheduled.
    Will get parameters from registers:
x86:32
Syscall #	Param 1	Param 2	Param 3	Param 4	Param 5	Param 6
eax		ebx	ecx	edx	esi	edi	ebp
Return value
eax

'''
exec_skip_list = ['sleep']
def is_ascii(s):
    return all(ord(c) < 128 for c in s)

class SockWatch():
    ''' track selected socket activity '''
    def __init__(self):
        self.watches = {}
    class sockFD():
        def __init__(self, fd, call_param):
            self.fd = fd
            self.call_param = call_param

    def bind(self, pid, fd, call_param):
        if pid not in self.watches:
            self.watches[pid] = []
        self.watches[pid].append(self.sockFD(fd, call_param))

    def getParam(self, pid, fd):
        retval = None
        if pid in self.watches:
            for watch in self.watches[pid]:
                if watch.fd == fd:
                    return watch.call_param
        return retval 

    def close(self, pid, fd):
        if pid in self.watches:
            got_it = None
            for watch in self.watches[pid]:
                if watch.fd == fd:
                    print('close %d for %d' % (fd, pid))
                    got_it = watch
                    break
            if got_it is not None:
                self.watches[pid].remove(got_it) 

class SockParams():
    def __init__(self, domain, sock_type, protocol):
        self.domain = domain
        self.sock_type = sock_type
        self.protocol = protocol
    def getString(self):
        return 'SockParams: domain %s type: %s protocol: %s' % (self.domain, self.sock_type, self.protocol)

class SyscallInfo():
    def __init__(self, cpu, pid, callnum, calculated, trace, call_params = []):
        self.cpu = cpu
        self.pid = pid
        self.callnum = callnum
        self.calculated = calculated
        self.trace = trace
        self.call_count = 0
        self.fname = None
        self.fd = None
        ''' 32-bit compatibility mode for this task '''
        self.compat32 = False
        ''' list of criteria to narrow search to information about the call '''
        self.call_params = call_params

class SelectInfo():
    def __init__(self, nfds, readfds, writefds, exceptfds, timeout, cpu, mem_utils, lgr):
        self.nfds = nfds
        self.readfds = readfds
        self.writefds = writefds
        self.exceptfds = exceptfds
        self.timeout = timeout
        self.cpu = cpu
        self.mem_utils = mem_utils
        self.lgr = lgr
       
    def readit(self, addr):
        if addr > 0:
            low = self.mem_utils.readWord(self.cpu, addr)
            high = self.mem_utils.readWord(self.cpu, addr+self.mem_utils.WORD_SIZE)
            return low, high
        else:
            return None, None

    def writeit(self, addr, value):
        if addr > 0:
            low_mask = 0xffffffff
            low = value & low_mask
            high_mask = low_mask << 32
            high = value & high_mask 
            high = high >> 32
            self.mem_utils.writeWord(self.cpu, addr, low)
            self.mem_utils.writeWord(self.cpu, addr+self.mem_utils.WORD_SIZE, high)

    def getSet(self, addr):
        if addr == 0:
            return "NULL"
        else:
            low, high = self.readit(addr)
            if low is None:
                return 'unable to read from 0x%x' % addr
            else:
                return '0x%x (0x%x:0x%x)' % (addr, low, high)

    def getAllFDString(self):
        read_list = self.getFDString(self.readfds)     
        write_list = self.getFDString(self.writefds)     
        except_list = self.getFDString(self.exceptfds)     
        fd_list = ''
        if len(read_list)>0:
            fd_list = 'read FD: %s' % read_list
        if len(write_list)>0:
            fd_list = fd_list+' write FD: %s' % write_list
        if len(except_list)>0:
            fd_list = fd_list+' except FD: %s' % except_list
        return fd_list

    def getString(self):

        return 'nfds: %d  readfds: %s writefds: %s exceptfds: %s timeout: 0x%x %s' % (self.nfds, 
              self.getSet(self.readfds), self.getSet(self.writefds), 
              self.getSet(self.exceptfds), self.timeout, self.getAllFDString())

    def setHasFD(self, fd, fd_set):
        retval = False
        if fd < self.nfds:
            #self.lgr.debug('SelectInfo hasFD under newfds %d' % fd)
            if fd_set is not None:
                read_low, read_high = self.readit(fd_set)
                if read_low is not None:
                    the_set = read_low | (read_high << 32) 
                    if memUtils.testBit(the_set, fd):
                        #self.lgr.debug('SeletInfo found %d in the read set 0x%x' % (fd, the_set))
                        retval = True
        return retval

    def resetFD(self, fd, fd_set):
        if fd < self.nfds:
            self.lgr.debug('SelectInfo reset fd %d' % fd)
            if fd_set is not None:
                read_low, read_high = self.readit(fd_set)
                if read_low is not None:
                    the_set = read_low | (read_high << 32) 
                    new_value = memUtils.clearBit(the_set, fd)
                    self.writeit(fd_set, new_value)
                    self.lgr.debug('SelectInfo reset fdset new value 0x%x' % new_value)

    def getFDString(self, fd_set):
        retval = ''
        for i in range(0, self.nfds):
            if self.setHasFD(i, fd_set):
                if len(retval) == 0:
                    retval = '%d' % i
                else:
                    retval = retval + ', %d' % i 
        return retval

    def hasFD(self, fd):
        retval = False
        if self.setHasFD(fd, self.readfds) or self.setHasFD(fd, self.writefds) or self.setHasFD(fd, self.exceptfds):
            retval = True
        return retval 

    def getFDList(self):
        retval = []
        for i in range(0, self.nfds):
            if self.hasFD(i):
                retval.append(i)
        return retval

class EPollInfo():
    EPOLL_CTL_ADD = 1
    EPOLL_CTL_DEL = 2
    EPOLL_CTL_MOD = 3
    EPOLL_OPER = ['None', 'ADD', 'DEL', 'MOD']

    class FDS():
        def __init__(self, fd, events):
            self.fd = fd
            self.events = events
    def __init__(self, epfd):
        self.epfd = epfd
        self.fd_set = []
    def add(self, fd, events):
        entry = self.FDS(fd, events)
        self.fd_set.append(entry)

class PollInfo():
    class FDS():
        def __init__(self, fd, events, revents):
            self.fd = fd
            self.events = events
            self.revents = revents
    def __init__(self, fds_addr, nfds, timeout, mem_utils, cpu, lgr):
        self.nfds = nfds
        self.fds_addr = fds_addr
        self.timeout = timeout
        self.mem_utils = mem_utils
        self.cpu = cpu
        self.lgr = lgr
        self.fds_list = []
        cur_addr = fds_addr
        for i in range (nfds):
            fd = self.mem_utils.readWord32(cpu, cur_addr)
            cur_addr += 4
            events = self.mem_utils.readWord32(cpu, cur_addr)
            cur_addr += 2
            revents = self.mem_utils.readWord32(cpu, cur_addr)
            cur_addr += 2
            self.fds_list.append(self.FDS(fd, events, revents))

    def hasFD(self, fd):
        for fds in self.fds_list:
            if fds.fd == fd:
                return True
        return False

    def getString(self):
        fd_list = ', '.join(map(lambda x: str(x.fd), self.fds_list))
        return 'poll, %d FDs: %s Timeout: %d' % (self.nfds, fd_list, self.timeout) 

class ExitInfo():
    def __init__(self, syscall_instance, cpu, pid, callnum, compat32, frame):
        self.cpu = cpu
        self.pid = pid
        self.callnum = callnum
        self.fname = None
        self.fname_addr = None
        self.retval_addr = None
        self.cmd = None
        self.flags = None
        self.mode = None
        self.old_fd = None
        self.new_fd = None
        self.count = None
        self.socket_callname = None
        self.sock_struct = None
        self.select_info = None
        self.poll_info = None
        ''' for sendmsg/recvmsg '''
        self.msghdr = None
        self.compat32 = compat32
        self.frame = frame
        ''' narrow search to information about the call '''
        self.call_params = None
        self.syscall_entry = None
        self.mode_hap = None
   
        ''' who to call from sharedSyscall, e.g., to watch mmap for SO maps '''
        self.syscall_instance = syscall_instance
        ''' stop and reset reversing origin if set '''
        self.origin_reset = False


EXTERNAL = 1
AF_INET = 2
DEST_PORT = 3
class CallParams():
    def __init__(self, subcall, match_param, break_simulation=False, proc=None):
        self.subcall = subcall
        self.match_param = match_param
        self.param_flags = []
        self.break_simulation = break_simulation
        self.proc = proc
        self.nth = None
        self.count = 0
    def toString(self):
        retval = 'subcall %s  match_param %s' % (self.subcall, str(self.match_param))
        return retval


''' syscalls to watch when record_df is true on traceAll.  Note gettimeofday and waitpid are included for exitMaze '''
record_fd_list = ['connect', 'bind', 'accept', 'open', 'socketcall', 'gettimeofday', 'waitpid', 'exit', 'exit_group', 'execve', 'clone', 'fork', 'vfork']
skip_proc_list = ['udevd', 'udevadm', 'modprobe', 'path_id']
class Syscall():

    def __init__(self, top, cell_name, cell, param, mem_utils, task_utils, context_manager, traceProcs, sharedSyscall, lgr, 
                   traceMgr, call_list=None, trace = False, flist_in=None, soMap = None, 
                   call_params=[], netInfo=None, binders=None, connectors=None, stop_on_call=False, targetFS=None, skip_and_mail=True, linger=False,
                   compat32=False, background=False, name=None, record_fd=False, callback=None, swapper_ok=False, kbuffer=None): 
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
        self.binders = binders
        self.connectors = connectors
        ''' lists of sockets by pid that we are watching for selected tracing '''
        self.sockwatch = SockWatch()
        ''' experimental watch for reads of data read from interfaces '''
        self.timeofday_count = {}
        self.timeofday_start_cycle = {}
        self.call_list = call_list
        self.trace = trace
        if call_params is None:
            self.call_params = []
        else:
            self.call_params = call_params
        self.stop_action = None
        self.netInfo = netInfo
        self.bang_you_are_dead = False
        self.stop_maze_hap = None
        self.targetFS = targetFS
        self.linger = linger
        self.linger_cycles = []
        self.compat32 = compat32
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
        for prog in exec_skip_list:
            self.ignore_progs.append(prog)

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
        break_list, break_addrs = self.doBreaks(compat32, background)
 
        if flist_in is not None:
            ''' Given function list to use after syscall completes '''
            hap_clean = hapCleaner.HapCleaner(cpu)
            for ph in self.proc_hap:
                hap_clean.add("Core_Breakpoint_Memop", ph)
            self.stop_action = hapCleaner.StopAction(hap_clean, break_list, flist_in, break_addrs = break_addrs)
            #self.lgr.debug('Syscall cell %s stop action includes given flist_in.  stop_on_call is %r linger: %r name: %s' % (self.cell_name, stop_on_call, self.linger, name))
        elif self.debugging and not self.breakOnExecve() and not trace and skip_and_mail:
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
            #self.lgr.debug('Syscall cell %s stop action includes NO flist linger: %r name: %s' % (self.cell_name, self.linger, name))

        self.exit_calls = []
        self.exit_calls.append('exit_group')
        self.exit_calls.append('exit')
        self.exit_calls.append('tkill')
        self.exit_calls.append('tgkill')
        self.stop_on_exit = False

    def breakOnExecve(self):
        for call in self.call_params:
            if call is not None and call.subcall == 'execve' and call.break_simulation:
                return True
        return False

    def stopAlone(self, msg):
        ''' NOTE: this is also called by sharedSyscall '''
        eip = self.top.getEIP()
        if self.stop_action is not None:
            self.stop_action.setExitAddr(eip)
        self.stop_hap = RES_hap_add_callback("Core_Simulation_Stopped", 
            	     self.stopHap, msg)
        #self.lgr.debug('Syscall stopAlone cell %s added stopHap %d Now stop. msg: %s' % (self.cell_name, self.stop_hap, msg))
        SIM_break_simulation(msg)

    def doBreaks(self, compat32, background):
        break_list = []
        break_addrs = []
        self.timeofday_count = {}
        self.timeofday_start_cycle = {}
        #self.lgr.debug('syscall cell_name %s doBreaks.  compat32: %r reset timeofdaycount' % (self.cell_name, compat32))
        if self.call_list is None:
            ''' trace all calls '''
            self.syscall_info = SyscallInfo(self.cpu, None, None, None, self.trace)
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
                        proc_break1 = self.context_manager.genBreakpoint(self.cell, Sim_Break_Linear, Sim_Access_Execute, self.param.sys_entry, 1, 0)
                        break_addrs.append(self.param.sys_entry)
                        break_list.append(proc_break1)
                        self.proc_hap.append(self.context_manager.genHapRange("Core_Breakpoint_Memop", self.syscallHap, self.syscall_info, proc_break, proc_break1, 'syscall'))
                    else:
                        #self.lgr.debug('Syscall no callnum, set sysenter break at 0x%x ' % (self.param.sysenter))
                        self.proc_hap.append(self.context_manager.genHapIndex("Core_Breakpoint_Memop", self.syscallHap, self.syscall_info, proc_break, 'syscall'))
                elif self.param.sys_entry is not None and self.param.sys_entry != 0:
                        #self.lgr.debug('Syscall no callnum, set sys_entry break at 0x%x' % (self.param.sys_entry))
                        proc_break1 = self.context_manager.genBreakpoint(self.cell, Sim_Break_Linear, Sim_Access_Execute, self.param.sys_entry, 1, 0)
                        break_addrs.append(self.param.sys_entry)
                        break_list.append(proc_break1)
                        self.proc_hap.append(self.context_manager.genHapIndex("Core_Breakpoint_Memop", self.syscallHap, self.syscall_info, proc_break1, 'syscall'))
                else:
                    self.lgr.debug('SysCall no call list, no breaks set.  parms: %s' % self.param.getParamString())
                if self.param.compat_32_entry is not None and self.param.compat_32_entry != 0:
                    ''' support 32 bit compatability '''
                    self.alt_syscall_info = copy.copy(self.syscall_info)
                    self.alt_syscall_info.compat32 = True
                    #self.lgr.debug('Syscall no callnum, compat32 break at 0x%x and 0x%x' % (self.param.compat_32_entry, self.param.compat_32_int128))
                    proc_break1 = self.context_manager.genBreakpoint(self.cell, Sim_Break_Linear, Sim_Access_Execute, self.param.compat_32_entry, 1, 0)
                    break_addrs.append(self.param.compat_32_entry)
                    break_list.append(proc_break1)
                    proc_break2 = self.context_manager.genBreakpoint(self.cell, Sim_Break_Linear, Sim_Access_Execute, self.param.compat_32_int128, 1, 0)
                    break_addrs.append(self.param.compat_32_int128)
                    break_list.append(proc_break2)
                    self.proc_hap.append(self.context_manager.genHapRange("Core_Breakpoint_Memop", self.syscallHap, self.alt_syscall_info, proc_break1, proc_break2, 'syscall32'))
        
        else:
            ''' will stop within the kernel at the computed entry point '''
            for call in self.call_list:
                # TBD fix for compat 32
                callnum = self.task_utils.syscallNumber(call, compat32)
                #self.lgr.debug('SysCall doBreaks call: %s  num: %d' % (call, callnum))
                if callnum is not None and callnum < 0:
                    self.lgr.error('Syscall bad call number %d for call <%s>' % (callnum, call))
                    return None, None
                entry = self.task_utils.getSyscallEntry(callnum, compat32)
                #phys = self.mem_utils.v2p(cpu, entry)
                #proc_break = self.context_manager.genBreakpoint(self.cpu.physical_memory, Sim_Break_Physical, Sim_Access_Execute, phys, 1, 0)
                syscall_info = SyscallInfo(self.cpu, None, callnum, entry, self.trace, self.call_params)
                syscall_info.compat32 = compat32
                self.syscall_info = syscall_info
                if not background:
                    #self.lgr.debug('Syscall callnum %s name %s entry 0x%x compat32: %r' % (callnum, call, entry, compat32))
                    proc_break = self.context_manager.genBreakpoint(self.cell, Sim_Break_Linear, Sim_Access_Execute, entry, 1, 0)
                    proc_break1 = None
                    break_list.append(proc_break)
                    break_addrs.append(entry)
                    self.proc_hap.append(self.context_manager.genHapIndex("Core_Breakpoint_Memop", self.syscallHap, syscall_info, proc_break, call))
                else:
                    self.lgr.debug('doBreaks set background break at 0x%x' % entry)
                    self.background_break = SIM_breakpoint(self.cell, Sim_Break_Linear, Sim_Access_Execute, entry, 1, 0)
                    self.background_hap = RES_hap_add_callback_index("Core_Breakpoint_Memop", self.syscallHap, syscall_info, self.background_break)

        return break_list, break_addrs
        
    def frameFromStackSyscall(self):
        reg_num = self.cpu.iface.int_register.get_number(self.mem_utils.getESP())
        esp = self.cpu.iface.int_register.read(reg_num)
        regs_addr = esp + self.mem_utils.WORD_SIZE
        #self.lgr.debug('frameFromStackSyscall regs_addr is 0x%x  ' % (regs_addr))
        frame = self.task_utils.getFrame(regs_addr, self.cpu)
        return frame

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
        if self.top is not None and not self.top.remainingCallTraces():
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
       
    def watchFirstMmap(self, pid, fname, fd, compat32):
        self.lgr.debug('syscall watchFirstMmap fd: %d fname %s' % (fd, fname))
        self.watch_first_mmap = fd
        self.mmap_fname = fname
        return
        
    def parseOpen(self, frame, callname):
        #self.lgr.debug('parseOpen for %s' % callname)
        if callname == 'openat':
            fname_addr = frame['param2']
            flags = frame['param3']
            mode = frame['param4']
        else:
            fname_addr = frame['param1']
            flags = frame['param2']
            mode = frame['param3']
        fname = self.mem_utils.readString(self.cpu, fname_addr, 256)
        #if fname is not None:
        #    try:
        #        fname.decode('ascii')
        #    except:
        #        self.lgr.warning('non-ascii fname at 0x%x %s' % (fname_addr, fname))
        #        #SIM_break_simulation('non-ascii fname at 0x%x %s' % (fname_addr, fname))
        #        #return None, None, None, None, None
        cpu, comm, pid = self.task_utils.curProc() 
        if callname == 'openat':
            ida_msg = '%s flags: 0%o  mode: 0x%x  fname_addr 0x%x filename: %s  dirfd: %d  pid:%d' % (callname, flags, 
                mode, fname_addr, fname, frame['param1'], pid)
        else:
            ida_msg = '%s flags: 0%o  mode: 0x%x  fname_addr 0x%x filename: %s   pid:%d' % (callname, flags, mode, fname_addr, fname, pid)
        #self.lgr.debug('parseOpen set ida message to %s' % ida_msg)
        self.context_manager.setIdaMessage(ida_msg)
        #if fname is None:
        #    SIM_break_simulation('fname zip')
        return fname, fname_addr, flags, mode, ida_msg

    #def fnamePhysAlone(self, (pid, fname_addr, exit_info)):
    def fnamePhysAlone(self, pinfo):
        pid, fname_addr, exit_info = pinfo 
        self.finish_break[pid] = SIM_breakpoint(self.cpu.physical_memory, Sim_Break_Physical, Sim_Access_Write, fname_addr, 1, 0)
        self.finish_hap[pid] = RES_hap_add_callback_index("Core_Breakpoint_Memop", self.finishParseOpen, exit_info, self.finish_break[pid])

    def fnameTable (self, exit_info, third, forth, memory):
        ''' only used with 64-bit IA32E paging '''
        cpu, comm, pid = self.task_utils.curProc() 
        if pid not in self.finish_hap_table:
            return
        self.lgr.debug('fnameTable delete finish_break')
        RES_delete_breakpoint(self.finish_break[pid])
        RES_hap_delete_callback_id("Core_Breakpoint_Memop", self.finish_hap_table[pid])
        del self.finish_hap_table[pid]
        length = memory.size
        op_type = SIM_get_mem_op_type(memory)
        type_name = SIM_get_mem_op_type_name(op_type)
        physical = memory.physical_address
        #self.lgr.debug('fnamePage phys 0x%x len %d  type %s' % (physical, length, type_name))
        if length == 8:
            if op_type is Sim_Trans_Store:
                value = SIM_get_mem_op_value_le(memory)
            else:
                self.lgr.error('syscall fnamePage unexpected op_type %d' % op_type)
                return
        else:
            self.lgr.error('syscall fnamePage unexpected length %d' % length)
            return

        value_40 = memUtils.bitRange(value, 12, 50) << 12
        table_entry = memUtils.bitRange(exit_info.fname_addr, 12, 20)
        page_base_addr = value_40 + (table_entry * 8)
        #self.lgr.debug('fnameTable pid %d would write value of 0x%x value_40 0x%x table_entry %d  break at page_base_addr 0x%x' % (pid, 
        #    value, value_40, table_entry, page_base_addr))

        self.finish_break[pid] = SIM_breakpoint(cpu.physical_memory, Sim_Break_Physical, Sim_Access_Write, page_base_addr, 1, 0)
        self.finish_hap_page[pid] = RES_hap_add_callback_index("Core_Breakpoint_Memop", self.fnamePage, exit_info, self.finish_break[pid])


    def fnamePage(self, exit_info, third, forth, memory):
        ''' only used with 64-bit IA32E paging '''
        cpu, comm, pid = self.task_utils.curProc() 
        if pid not in self.finish_hap_page:
            return
        self.lgr.debug('fnamePage delete finish_break')
        RES_delete_breakpoint(self.finish_break[pid])
        RES_hap_delete_callback_id("Core_Breakpoint_Memop", self.finish_hap_page[pid])
        del self.finish_hap_page[pid]

        length = memory.size
        op_type = SIM_get_mem_op_type(memory)
        type_name = SIM_get_mem_op_type_name(op_type)
        physical = memory.physical_address
        self.lgr.debug('fnamePage phys 0x%x len %d  type %s' % (physical, length, type_name))
        if length == 8:
            if op_type is Sim_Trans_Store:
                value = SIM_get_mem_op_value_le(memory)
            else:
                self.lgr.error('syscall fnamePage unexpected op_type %d' % op_type)
                return
        else:
            self.lgr.error('syscall fnamePage unexpected length %d' % length)
            return

        value_40 = memUtils.bitRange(value, 12, 50) << 12
        offset = memUtils.bitRange(exit_info.fname_addr, 0, 11)
 
        fname_addr = value_40 + offset
        self.lgr.debug('fnamePage pid %d would write value of 0x%x value_40 0x%x offset 0x%x  break at fname_addr 0x%x' % (pid, value, value_40, offset, fname_addr))
        got = self.mem_utils.readStringPhys(self.cpu, fname_addr, 256)
        if len(got) > 0:
            exit_info.fname = got
            self.lgr.debug('fnamePage read %s' % exit_info.fname)
        else:
            SIM_run_alone(self.fnamePhysAlone, (pid, fname_addr, exit_info))


    def finishParseOpen(self, exit_info, third, forth, memory):
        ''' in case the file name is in memory that was not mapped when open call was issued '''
        cpu, comm, pid = self.task_utils.curProc() 
        #self.lgr.debug('finishParseOpen pid %d' % pid)
        if cpu != exit_info.cpu or pid != exit_info.pid:
            return
        if pid not in self.finish_hap:
            return
        exit_info.fname = self.mem_utils.readString(self.cpu, exit_info.fname_addr, 256)
        if exit_info.fname is not None:
            #self.lgr.debug('finishParseOpen pid %d got fid %s' % (pid, exit_info.fname))
            RES_hap_delete_callback_id("Core_Breakpoint_Memop", self.finish_hap[pid])
            self.lgr.debug('finishParseOpen delete finish_break')
            RES_delete_breakpoint(self.finish_break[pid])
            del self.finish_hap[pid]
            del self.finish_break[pid]
        else:
            self.lgr.debug('finishParseOpen pid %d got fid none, arm fu?' % (pid))

    def addElf(self, prog_string, pid):
        retval = True
        if self.targetFS is not None and prog_string is not None:
            full_path = self.targetFS.getFull(prog_string, self.lgr)
            if full_path is None:
                self.lgr.debug('Unable to get full path for %s' % prog_string)
                return
            if os.path.isfile(full_path):
                elf_info = None
                if self.soMap is not None:
                    elf_info = self.soMap.addText(full_path, prog_string, pid)
                if elf_info is not None:
                    if self.soMap is not None:
                        if elf_info.address is not None:
                            self.lgr.debug('syscall addElf 0x%x - 0x%x' % (elf_info.address, elf_info.address+elf_info.size))       
                            self.context_manager.recordText(elf_info.address, elf_info.address+elf_info.size)
                        else:
                            self.lgr.error('addElf got text segment but no text, unexpected.  pid %d' % pid)
                else:
                    if self.soMap is not None:
                        self.lgr.debug('syscall addElf, no text segment found, advise SO we have an exec, but no starting map')
                        self.soMap.noText(prog_string, pid)
                    retval = False
                    ftype = magic.from_file(full_path)
                    self.traceProcs.setFileType(pid, ftype) 
            else:
                self.lgr.debug('addElf, no file at %s' % full_path)
                if self.soMap is not None:
                    self.soMap.noText(prog_string, pid)
      
        return retval

    def finishParseExecve(self, call_info, third, forth, memory):
        cpu, comm, pid = self.task_utils.curProc() 
        if cpu != call_info.cpu or pid != call_info.pid:
            return
        if pid not in self.finish_hap:
            return
        prog_string, arg_string_list = self.task_utils.readExecParamStrings(call_info.pid, call_info.cpu)
        if cpu.architecture == 'arm' and prog_string is None:
            self.lgr.debug('finishParseExecve progstring None, arm fu?')
            return
        RES_hap_delete_callback_id("Core_Breakpoint_Memop", self.finish_hap[pid])
        self.lgr.debug('finishParseExec delete finish_break')
        RES_delete_breakpoint(self.finish_break[pid])
        del self.finish_hap[pid]
        del self.finish_break[pid]
        if prog_string in self.ignore_progs:
            self.lgr.debug('finishParseExecve pid:%d skipping (%s)' % (pid, prog_string))
            return False
        self.lgr.debug('finishParseExecve pid:%d progstring (%s)' % (pid, prog_string))
        nargs = min(4, len(arg_string_list))
        arg_string = ''
        for i in range(nargs):
            if is_ascii(arg_string_list[i]):
                arg_string += arg_string_list[i]+' '
            else:
                break
        ida_msg = 'execve prog: %s %s  pid:%d  breakonexecve: %r' % (prog_string, arg_string, call_info.pid, self.breakOnExecve())
        if self.traceMgr is not None:
            self.traceMgr.write(ida_msg+'\n')
        if self.traceProcs is not None:
            self.traceProcs.setName(call_info.pid, prog_string, arg_string)

        self.addElf(prog_string, pid)

        if self.netInfo is not None:
            self.netInfo.checkNet(prog_string, arg_string)
        self.checkExecve(prog_string, arg_string_list, call_info.pid)
        self.context_manager.newProg(prog_string, call_info.pid)


    def checkExecve(self, prog_string, arg_string_list, pid):
        #self.lgr.debug('checkExecve syscall %s  %s' % (self.name, prog_string))
        cp = None
        for call in self.call_params:
            #self.lgr.debug('checkExecve call %s' % call)
            if call.subcall == 'execve':
                cp = call
                break
        if cp is None:
            for call in self.syscall_info.call_params:
                self.lgr.debug('checkExecve traceall call %s' % call)
                if call.subcall == 'execve':
                    cp = call
                    break
        
            
        if cp is not None: 
            if cp.match_param.__class__.__name__ == 'Dmod':
               self.task_utils.modExecParam(pid, self.cpu, cp.match_param)
            else: 

                if '/' in cp.match_param:
                    ''' compare full path '''
                    base = prog_string
                else:
                    base = os.path.basename(prog_string)
                self.lgr.debug('checkExecve base %s against %s' % (base, cp.match_param))
                if base.startswith(cp.match_param):
                    ''' is program file we are looking for.  do we care if it is a binary? '''
                    self.lgr.debug('matches base')
                    wrong_type = False
                    if self.traceProcs is not None:
                        ftype = self.traceProcs.getFileType(pid)
                        if ftype is None:
                            full_path = self.targetFS.getFull(prog_string, self.lgr)
                            if full_path is not None and os.path.isfile(full_path):
                                ftype = magic.from_file(full_path)
                                if ftype is None:
                                    self.lgr.error('checkExecve failed to find file type for %s pid:%d' % (prog_string, pid))
                                    return
                        if ftype is not None and 'binary' in cp.param_flags and 'elf' not in ftype.lower():
                            wrong_type = True
                    if not wrong_type:
                        self.lgr.debug('checkExecve execve of %s now stop alone ' % prog_string)
                        SIM_run_alone(self.stopAlone, 'execve of %s' % prog_string)
                    else:
                        self.lgr.debug('checkExecve, got %s when looking for binary %s, skip' % (ftype, prog_string))
                elif base == 'sh' and cp.match_param.startswith('sh '):
                    # TBD add bash, etc.
                    base = os.path.basename(arg_string_list[0])
                    sw = cp.match_param.split()[1]
                    #self.lgr.debug('syscall execve compare %s to %s' % (base, sw))
                    if base.startswith(sw):
                        self.lgr.debug('checkExecve execve of %s %s' % (prog_string, sw))
                        SIM_run_alone(self.stopAlone, 'execve of %s %s' % (prog_string, sw))

    def parseExecve(self, syscall_info):
        retval = True
        cpu, comm, pid = self.task_utils.curProc() 
        ''' allows us to ignore internal kernel syscalls such as close socket on exec '''
        at_enter = True
        if syscall_info.calculated is not None:
            at_enter = False
        prog_string, arg_string_list = self.task_utils.getProcArgsFromStack(pid, at_enter, cpu)
        if prog_string is not None and os.path.basename(prog_string) in self.ignore_progs:
            return False
        #self.lgr.debug('parseExecve len of arg_string_list %d' % len(arg_string_list))
          
        pid_list = self.context_manager.getThreadPids()
        db_pid, dumbcpu = self.context_manager.getDebugPid()
        
        if pid in pid_list and pid != db_pid:
            self.lgr.debug('syscall parseExecve remove %d from list being watched.' % (pid))
            #self.context_manager.rmTask(pid)
            self.context_manager.stopWatchPid(pid)
        
        if prog_string is None:
            ''' prog string not in ram, break on kernel read of the address and then read it '''
            prog_addr = self.task_utils.getExecProgAddr(pid, cpu)
            call_info = SyscallInfo(cpu, pid, None, None, None)
            self.lgr.debug('parseExecve pid:%d prog string missing, set break on 0x%x' % (pid, prog_addr))
            if prog_addr == 0:
                self.lgr.error('parseExecve zero prog_addr pid %d' % pid)
                SIM_break_simulation('parseExecve zero prog_addr pid %d' % pid)
            if pid in pid_list and pid != db_pid:
                context = self.context_manager.getDefaultContext()
            else:
                context = cpu.current_context
            self.finish_break[pid] = SIM_breakpoint(context, Sim_Break_Linear, Sim_Access_Read, prog_addr, 1, 0)
            self.finish_hap[pid] = RES_hap_add_callback_index("Core_Breakpoint_Memop", self.finishParseExecve, call_info, self.finish_break[pid])
            return False
        nargs = min(4, len(arg_string_list))
        arg_string = ''
        for i in range(nargs):
            if is_ascii(arg_string_list[i]):
                arg_string += arg_string_list[i]+' '
            else:
                break
        ida_msg = 'execve prog: %s %s  pid:%d' % (prog_string, arg_string, pid)
        self.context_manager.newProg(prog_string, pid)
        self.lgr.debug(ida_msg)
        if self.traceMgr is not None:
            self.traceMgr.write(ida_msg+'\n')
        if self.traceProcs is not None:
            self.traceProcs.setName(pid, prog_string, arg_string)

        self.addElf(prog_string, pid)

        if self.netInfo is not None:
            self.netInfo.checkNet(prog_string, arg_string)
        self.checkExecve(prog_string, arg_string_list, pid)

        return retval

    def getSockParams(self, frame, syscall_info):
        domain = None
        sock_type = None
        protocol = None
        if self.cpu.architecture == 'arm':
            domain = frame['param1']
            sock_type_full = frame['param2']
            protocol = frame['param3']
        elif self.mem_utils.WORD_SIZE==8 and not syscall_info.compat32:
            frame_string = taskUtils.stringFromFrame(frame)
            self.lgr.debug('socket call params: %s' % (frame_string))
            domain = frame['param1']
            sock_type_full = frame['param2']
            protocol = frame['param3']
        else:
            ''' 32 bit '''
            self.lgr.debug('syscall socketParse 32bit')
            params = frame['param2']
            #SIM_break_simulation('socket param2 0x%x' % params)
            domain = self.mem_utils.readWord32(self.cpu, params)
            sock_type_full = self.mem_utils.readWord32(self.cpu, params+4)
            protocol = self.mem_utils.readWord32(self.cpu, params+8)
        if sock_type_full is not None:
            sock_type = sock_type_full & net.SOCK_TYPE_MASK
            try:
                type_string = net.socktype[sock_type]
            except:
                self.lgr.debug('syscall doSocket could not get type string from type 0x%x full 0x%x' % (sock_type, sock_type_full))
        sock_params = SockParams(domain, sock_type, protocol)
        self.lgr.debug('syscall getSockParams returning %s' % sock_params.getString())
        return sock_params

    def bindFDToSocket(self, pid, fd):
        if pid in self.pid_sockets:
            if pid not in self.pid_fd_sockets:
                self.pid_fd_sockets[pid] = {}
            self.pid_fd_sockets[pid][fd] = self.pid_sockets[pid]
            del self.pid_sockets[pid]

    def socketParse(self, callname, syscall_info, frame, exit_info, pid):
        ss = None
        comm = None
        if pid in self.comm_cache:
            comm = self.comm_cache[pid]
        if callname == 'socketcall':        
            ''' must be 32-bit get params from struct '''
            ida_msg = None
            socket_callnum = frame['param1']
            socket_callname = net.callname[socket_callnum].lower()
            #self.lgr.debug('syscall socketParse is socketcall call %s from %d' % (socket_callname, pid))
            if socket_callname == 'socket':
                self.pid_sockets[pid] = self.getSockParams(frame, syscall_info)
 
            ''' Is the call intended for this syscall instance? '''
            got_good = False 
            got_bad = False 
            if self.name != 'traceAll' and socket_callname != 'socket':
                for call_param in syscall_info.call_params:
                    if call_param is not None and call_param.subcall is not None:
                        #self.lgr.debug('syscall socketParse subcall in call_param of %s' % call_param.subcall)
                        if call_param.subcall == socket_callname:
                            got_good = True
                        else:
                            got_bad = True
                if got_bad and not got_good:
                    self.lgr.debug('syscall socketParse socketcall %s not in list, skip it' % socket_callname)
                    return None

            if self.record_fd and socket_callname not in record_fd_list:
                self.lgr.debug('syscall socketParse %s not in list, skip it' % socket_callname)
                return None
            self.lgr.debug('socketParse socket_callnum is %d name: %s record_fd: %r' % (socket_callnum, socket_callname, self.record_fd))
            #if syscall_info.compat32:
            #    SIM_break_simulation('socketcall')
            exit_info.socket_callname = socket_callname
            if socket_callname != 'socket' and socket_callname != 'setsockopt':
                self.lgr.debug('syscall socketParse get SockStruct from param2: 0x%x' % frame['param2'])
                ss = net.SockStruct(self.cpu, frame['param2'], self.mem_utils)
                if pid in self.pid_fd_sockets and ss.fd is not None and ss.fd in self.pid_fd_sockets[pid]:
                    ss.addParams(self.pid_fd_sockets[pid][ss.fd])
                self.lgr.debug('ss is %s' % ss.getString())
        else:
            socket_callname = callname
            self.lgr.debug('syscall socketParse call %s param1 0x%x param2 0x%x' % (callname, frame['param1'], frame['param2']))
            if callname != 'socket':
                ss = net.SockStruct(self.cpu, frame['param2'], self.mem_utils, fd=frame['param1'], length=frame['param3'])
                if pid in self.pid_fd_sockets and ss.fd is not None and ss.fd in self.pid_fd_sockets[pid]:
                    ss.addParams(self.pid_fd_sockets[pid][ss.fd])
                self.lgr.debug('socketParse ss %s  param2: 0x%x' % (ss.getString(), frame['param1']))
            else:
                self.pid_sockets[pid] = self.getSockParams(frame, syscall_info)
        ''' NOTE returns above '''
        exit_info.sock_struct = ss

        if socket_callname == 'socket':
            #self.lgr.debug('syscall socketParse is socket')
            if self.cpu.architecture == 'arm':
                domain = frame['param1']
                sock_type_full = frame['param2']
                protocol = frame['param3']
            elif self.mem_utils.WORD_SIZE==8 and not syscall_info.compat32:
                frame_string = taskUtils.stringFromFrame(frame)
                self.lgr.debug('socket call params: %s' % (frame_string))
                domain = frame['param1']
                sock_type_full = frame['param2']
                protocol = frame['param3']
            else:
                ''' 32 bit '''
                self.lgr.debug('syscall socketParse 32bit')
                params = frame['param2']
                #SIM_break_simulation('socket param2 0x%x' % params)
                domain = self.mem_utils.readWord32(self.cpu, params)
                sock_type_full = self.mem_utils.readWord32(self.cpu, params+4)
                protocol = self.mem_utils.readWord32(self.cpu, params+8)
            if domain is None or sock_type_full is None:
                ida_msg = '%s - %s pid:%s input values not mapped???? ' % (callname, socket_callname, pid)
            else:
                sock_type = sock_type_full & net.SOCK_TYPE_MASK
                try:
                    type_string = net.socktype[sock_type]
                    ida_msg = '%s - %s pid:%s domain: 0x%x type: %s protocol: 0x%x' % (callname, socket_callname, pid, domain, type_string, protocol)
                    #self.lgr.debug(ida_msg)
                except:
                    self.lgr.debug('syscall doSocket could not get type string from type 0x%x full 0x%x' % (sock_type, sock_type_full))
                    ida_msg = '%s - %s pid:%d domain: 0x%x type: %d protocol: 0x%x' % (callname, socket_callname, pid, domain, sock_type, protocol)
        elif socket_callname == 'connect':
            ida_msg = '%s - %s pid:%d %s %s  param at: 0x%x' % (callname, socket_callname, pid, ss.getString(), ss.addressInfo(), frame['param2'])
            for call_param in syscall_info.call_params:
                self.lgr.debug('check for match subcall %s' % call_param.subcall)
                if call_param.subcall == 'connect' and (call_param.proc is None or call_param.proc == self.comm_cache[pid]):
                     if call_param.match_param is not None:
                         go = None
                         if ss.port is not None:
                             ''' look to see if this address matches a given pattern '''
                             s = ss.dottedPort()
                             pat = call_param.match_param
                             try:
                                 go = re.search(pat, s, re.M|re.I)
                             except:
                                 self.lgr.error('invalid expression: %s' % pat)
                                 return None
                         
                         if len(call_param.match_param.strip()) == 0 or go or call_param.match_param == ss.sa_data: 
                             #self.lgr.debug('socketParse found match %s' % (call_param.match_param))
                             if call_param.nth is not None:
                                 #self.lgr.debug('socketParse has call_param.nth is %s' % str(call_param.nth))
                                 call_param.count = call_param.count + 1
                                 if call_param.count >= call_param.nth:
                                     exit_info.call_params = call_param
                                     if go:
                                         ida_msg = 'connect to %s, FD: %d count: %d' % (s, ss.fd, call_param.count)
                                     else:
                                         ida_msg = 'connect to %s, FD: %d count: %d' % (call_param.match_param, ss.fd, call_param.count)
                                     self.context_manager.setIdaMessage(ida_msg)
                             else:
                                 exit_info.call_params = call_param
                                 if go:
                                     ida_msg = 'connect to %s, FD: %d' % (s, ss.fd)
                                 else:
                                     ida_msg = 'connect to %s, FD: %d' % (call_param.match_param, ss.fd)
                                 self.context_manager.setIdaMessage(ida_msg)
                             break
                     elif EXTERNAL in call_param.param_flags and ss.isExternal():
                         self.lgr.debug('socketParse external in flags and is external')
                         exit_info.call_params = call_param
              
        elif socket_callname == 'bind':
            ida_msg = '%s - %s pid:%d socket_string: %s' % (callname, socket_callname, pid, ss.getString())
            #if ss.famName() == 'AF_CAN':
            #    frame_string = taskUtils.stringFromFrame(frame)
            #    self.lgr.debug('bind params %s' % frame_string)
            #    SIM_break_simulation('bind')
            
            for call_param in syscall_info.call_params:
                if call_param.subcall == 'bind' and (call_param.proc is None or call_param.proc == self.comm_cache[pid]):
                     if call_param.match_param is not None:
                         go = None
                         if ss.port is not None:
                             ''' look to see if this address matches a given pattern '''
                             s = ss.dottedPort()
                             pat = call_param.match_param
                             try:
                                 go = re.search(pat, s, re.M|re.I)
                             except:
                                 self.lgr.error('invalid expression: %s' % pat)
                                 return None
                         
                         #self.lgr.debug('socketParse look for match %s %s' % (pat, s))
                         if len(call_param.match_param.strip()) == 0 or go or call_param.match_param == ss.sa_data: 
                             self.lgr.debug('socketParse found match %s' % (call_param.match_param))
                             exit_info.call_params = call_param
                             if go:
                                 ida_msg = 'BIND to %s, FD: %d' % (s, ss.fd)
                             else:
                                 ida_msg = 'BIND to %s, FD: %d' % (call_param.match_param, ss.fd)
                             self.context_manager.setIdaMessage(ida_msg)
                             break

                     if AF_INET in call_param.param_flags and ss.sa_family == net.AF_INET:
                         exit_info.call_params = call_param
                         self.sockwatch.bind(pid, ss.fd, call_param)

        elif socket_callname == 'getpeername':
            ida_msg = '%s - %s pid:%d FD: %d' % (callname, socket_callname, pid, ss.fd)
            #exit_info.call_params = self.sockwatch.getParam(pid, ss.fd)
            for call_param in syscall_info.call_params:
                if (call_param.subcall is None or call_param.subcall == 'getpeername') and type(call_param.match_param) is int and call_param.match_param == ss.fd:
                #if call_param.subcall == 'GETPEERNAME' and call_param.match_param == ss.fd:
                    exit_info.call_params = call_param
                    break

        elif socket_callname == 'accept' or socket_callname == 'accept4':
            phys = self.mem_utils.v2p(self.cpu, ss.addr)
            if ss.addr is not None and ss.addr != 0:
                ida_msg = '%s - %s pid:%d FD: %d addr:0x%x len_addr:0x%x  phys_addr:0x%x' % (callname, socket_callname, pid, ss.fd, ss.addr, ss.length, phys)
            elif ss.fd is not None:
                ida_msg = '%s - %s pid:%d FD: %d' % (callname, socket_callname, pid, ss.fd)
            else:
                ida_msg = '%s - %s pid:%d FD is None?' % (callname, socket_callname, pid)
                self.lgr.debug('syscall acccept with ss.fd of none?')
             
            if ss.fd is not None:
                #exit_info.call_params = self.sockwatch.getParam(pid, ss.fd)
                for call_param in syscall_info.call_params:
                    self.lgr.debug('syscall accept subcall %s call_param.match_param is %s fd is %d' % (call_param.subcall, str(call_param.match_param), ss.fd))
                    if type(call_param.match_param) is int:
                        if (call_param.subcall == 'accept' or self.name=='runToIO') and (call_param.match_param < 0 or call_param.match_param == ss.fd):
                            self.lgr.debug('did accept match')
                            exit_info.call_params = call_param
                            break

        elif socket_callname == 'getsockname':
            ida_msg = '%s - %s pid:%d FD: %d' % (callname, socket_callname, pid, ss.fd)
            #exit_info.call_params = self.sockwatch.getParam(pid, ss.fd)
            for call_param in syscall_info.call_params:
                if call_param.subcall == 'getsockname' and call_param.match_param == ss.fd:
                    exit_info.call_params = call_param
                    break

        elif socket_callname == "recv" or socket_callname == "recvfrom":
            exit_info.old_fd = ss.fd
            exit_info.call_params = self.sockwatch.getParam(pid, ss.fd)
            exit_info.retval_addr = ss.addr
            src_addr = None
            src_addr_len = 0
            if socket_callname == 'recvfrom':
                if callname == 'socketcall':        
                    src_addr = self.mem_utils.readWord32(self.cpu, frame['param2']+16)
                    src_addr_len = self.mem_utils.readWord32(self.cpu, frame['param2']+20)
                else:
                    src_addr = frame['param5']
                    src_addr_len = frame['param6']
                    #SIM_break_simulation('recvfrom param5 0x%x' % src_addr)
            if src_addr is not None and src_addr != 0:
                source_ss = net.SockStruct(self.cpu, src_addr, self.mem_utils, fd=-1)
                if source_ss.sa_family is not None:
                    exit_info.fname_addr = src_addr
                    exit_info.count = src_addr_len
                ida_msg = '%s - %s pid:%d FD: %d len: %d' % (callname, socket_callname, pid, ss.fd, ss.length)
                #if source_ss.famName() == 'AF_CAN':
                #    frame_string = taskUtils.stringFromFrame(frame)
                #    print(frame_string)
                #    SIM_break_simulation(ida_msg)
            elif ss.length is None:
                self.lgr.error('ss length none') 
            elif ss.fd is None:
                self.lgr.error('ss fd none') 
            elif pid is None:
                self.lgr.error('pid is none') 
            else:
                ida_msg = '%s - %s pid:%d FD: %d len: %d %s' % (callname, socket_callname, pid, ss.fd, ss.length, ss.getString())
            for call_param in syscall_info.call_params:
                #self.lgr.debug('syscall parse socket rec... subcall is %s ss.fd is %s match_param is %s' % (call_param.subcall, str(ss.fd), str(call_param.match_param)))
                if (call_param.subcall is None or call_param.subcall == 'recv' or call_param.subcall == 'recvfrom') and type(call_param.match_param) is int and call_param.match_param == ss.fd and (call_param.proc is None or call_param.proc == self.comm_cache[pid]):
                    if call_param.nth is not None:
                        call_param.count = call_param.count + 1
                        self.lgr.debug('call_param.nth not none, is %d, count is %d' % (call_param.nth, call_param.count))
                        if call_param.count >= call_param.nth:
                            self.lgr.debug('count >= param, set it')
                            exit_info.call_params = call_param
                            if self.kbuffer is not None:
                                self.lgr.debug('syscall read kbuffer for addr 0x%x' % exit_info.retval_addr)
                                self.kbuffer.read(exit_info.retval_addr, ss.length)
                    else:
                        self.lgr.debub('call_param.nth is none, call it matched')
                        exit_info.call_params = call_param
                        if self.kbuffer is not None:
                            self.lgr.debug('syscall read kbuffer for addr 0x%x' % exit_info.retval_addr)
                            self.kbuffer.read(exit_info.retval_addr, ss.length)
                    break
        elif socket_callname == "recvmsg": 
            
            if self.mem_utils.WORD_SIZE==8 and not syscall_info.compat32:
                exit_info.old_fd = frame['param1']
                exit_info.retval_addr = frame['param2']
                msghdr = net.Msghdr(self.cpu, self.mem_utils, frame['param2'], self.lgr)
                ida_msg = '%s - %s pid:%d FD: %d msghdr: 0x%x %s' % (callname, socket_callname, pid, exit_info.old_fd, frame['param2'], msghdr.getString())
            elif self.cpu.architecture == 'arm':
                exit_info.old_fd = frame['param1']
                msg_hdr_ptr = frame['param2']
                msghdr = net.Msghdr(self.cpu, self.mem_utils, msg_hdr_ptr, self.lgr)
                ida_msg = '%s - %s pid:%d FD: %d msghdr: 0x%x %s' % (callname, socket_callname, pid, exit_info.old_fd, msg_hdr_ptr, msghdr.getString())
                self.lgr.debug(ida_msg) 
 
            else:
                ''' TBD is this right for x86 32?'''
                params = frame['param2']
                exit_info.old_fd = self.mem_utils.readWord32(self.cpu, params)
                msg_hdr_ptr = self.mem_utils.readWord32(self.cpu, params+4)
                exit_info.retval_addr = msg_hdr_ptr
                msghdr = net.Msghdr(self.cpu, self.mem_utils, msg_hdr_ptr, self.lgr)
                ida_msg = '%s - %s pid:%d FD: %d msghdr: 0x%x %s' % (callname, socket_callname, pid, exit_info.old_fd, msg_hdr_ptr, msghdr.getString())
            exit_info.msghdr = msghdr
            exit_info.call_params = self.sockwatch.getParam(pid, exit_info.old_fd)

            for call_param in syscall_info.call_params:
                #self.lgr.debug('syscall call_params %s' % call_param.toString())
                if (call_param.subcall is None or call_param.subcall == 'recvmsg') and type(call_param.match_param) is int and call_param.match_param == frame['param1'] and (call_param.proc is None or call_param.proc == self.comm_cache[pid]):
                    #self.lgr.debug('syscall %s watch exit for FD call_param %s' % (socket_callname, call_param.match_param))
                    exit_info.call_params = call_param
                    break
                elif type(call_param.match_param) is str and call_param.subcall == 'recvmsg' and (call_param.proc is None or call_param.proc == self.comm_cache[pid]):
                    #self.lgr.debug('syscall %s watch exit for call_param %s' % (socket_callname, call_param.match_param))
                    exit_info.call_params = call_param
                    break
            
        elif socket_callname == "sendmsg":
            if self.cpu.architecture == 'arm':
                exit_info.old_fd = frame['param1']
                msg_hdr_ptr = frame['param2']
                msghdr = net.Msghdr(self.cpu, self.mem_utils, msg_hdr_ptr, self.lgr)
                exit_info.msghdr = msghdr
                ida_msg = '%s - %s pid:%d FD: %d msghdr: 0x%x %s' % (callname, socket_callname, pid, exit_info.old_fd, msg_hdr_ptr, msghdr.getString())
                self.lgr.debug(ida_msg) 
                #SIM_break_simulation('sendmsg')

        elif socket_callname == "send" or socket_callname == "sendto":
            exit_info.old_fd = ss.fd
            exit_info.retval_addr = ss.addr
            exit_info.call_params = self.sockwatch.getParam(pid, ss.fd)
            dest_addr = None
            dest_ss = None
            if socket_callname == 'sendto':
                if callname == 'socketcall':        
                    dest_addr_addr = frame['param2']+16
                    dest_addr = self.mem_utils.readWord32(self.cpu, dest_addr_addr)
                    self.lgr.debug('sendto dest addr addr at 0x%x  got 0x%x' % (dest_addr_addr, dest_addr))
                else:
                    dest_addr = frame['param5']
            #if ss.fd == 5:
            #    SIM_break_simulation('is sendto dest_addr 0x%x' % dest_addr)
            if dest_addr is not None and dest_addr != 0:
                dest_ss = net.SockStruct(self.cpu, dest_addr, self.mem_utils, fd=-1)
                #frame_string = taskUtils.stringFromFrame(frame)
                #print(frame_string)
                #SIM_break_simulation('sendto addr is 0x%x' % dest_addr)
                ida_msg = '%s - %s pid:%d buf: 0x%x %s dest: %s' % (callname, socket_callname, pid, ss.addr, ss.getString(), dest_ss.getString())
                #if dest_ss.famName() == 'AF_CAN':
                #    frame_string = taskUtils.stringFromFrame(frame)
                #    print(frame_string)
                #    SIM_break_simulation(ida_msg)
            else:
                ida_msg = '%s - %s pid:%d buf: 0x%x %s' % (callname, socket_callname, pid, ss.addr, ss.getString())
            for call_param in syscall_info.call_params:
                if (call_param.subcall is None or call_param.subcall == 'send') and type(call_param.match_param) is int and call_param.match_param == ss.fd and (call_param.proc is None or call_param.proc == self.comm_cache[pid]):
                    #self.lgr.debug('call param found %d, matches %d' % (call_param.match_param, ss.fd))
                    exit_info.call_params = call_param
                    break
                elif DEST_PORT in call_param.param_flags: 
                    if dest_ss is not None:
                        if dest_ss.port == call_param.match_param and (call_param.proc is None or call_param.proc == self.comm_cache[pid]):
                            self.lgr.debug('call param DEST_PORT found')
                            exit_info.call_params = call_param
                            break
                        else:
                            self.lgr.debug('syscall no match of %d to %d in  sendto from %d' % (call_param.match_param, dest_ss.port, pid))
                    else:
                        self.lgr.debug('syscall no ss in sendto from %d' % pid)
                
                elif type(call_param.match_param) is str and (call_param.subcall == 'send' or call_param.subcall == 'sendto') and (call_param.proc is None or call_param.proc == self.comm_cache[pid]):
                    ''' look for string in output '''
                    self.lgr.debug('syscall %s watch exit for call_param %s' % (socket_callname, call_param.match_param))
                    exit_info.call_params = call_param
                    break

        elif socket_callname == 'listen':
            exit_info.call_params = self.sockwatch.getParam(pid, ss.fd)
            ida_msg = '%s - %s pid:%d %s' % (callname, socket_callname, pid, ss.getString())
                
        elif socket_callname == 'setsockopt' or socket_callname == 'getsockopt':
            if callname == 'socketcall':
                self.fd = self.mem_utils.readWord32(self.cpu, frame['param2'])
                level = self.mem_utils.readWord32(self.cpu, frame['param2']+4)
                optname = self.mem_utils.readWord32(self.cpu, frame['param2']+8)
                optval = self.mem_utils.readWord32(self.cpu, frame['param2']+12)
                optlen = self.mem_utils.readWord32(self.cpu, frame['param2']+16)
            else:
                self.fd = frame['param1']
                level = frame['param2']
                optname = frame['param3']
                optval = frame['param4']
                optlen = frame['param5']
            exit_info.retval_addr = optval
            ''' this is an address '''
            exit_info.count = optlen
            optval_val = ''
            if socket_callname == 'setsockopt' and optval != 0:
                rcount = min(optlen, 80)
                thebytes, dumb =  self.mem_utils.getBytes(self.cpu, rcount, optval)
                if thebytes is not None:
                    optval_val = 'option: %s' % thebytes
                else:
                    optval_val = 'option: page not mapped'
            ida_msg = '%s - %s pid:%d FD: %d level: %d  optname: %d optval: 0x%x  oplen %d  %s' % (callname, 
                 socket_callname, pid, self.fd, level, optname, optval, optlen, optval_val)
        elif socket_callname == 'socketpair':
            if callname == 'socketcall':
                exit_info.retval_addr = self.mem_utils.readWord32(self.cpu, frame['param4'])
            else:
                exit_info.retval_addr = frame['param4']
            ida_msg = '%s - %s %s pid:%d ' % (callname, socket_callname, taskUtils.stringFromFrame(frame), pid)
            
        else:
            ida_msg = '%s - %s %s   pid:%d' % (callname, socket_callname, taskUtils.stringFromFrame(frame), pid)


        return ida_msg

    def syscallParse(self, callnum, callname, frame, cpu, pid, comm, syscall_info, quiet=False):
        exit_info = ExitInfo(self, cpu, pid, callnum, syscall_info.compat32, frame)
        exit_info.syscall_entry = self.mem_utils.getRegValue(self.cpu, 'pc')
        ida_msg = None
        #self.lgr.debug('syscallParse pid:%d callname <%s>' % (pid, callname))
        if callname == 'open' or callname == 'openat':        
            #self.lgr.debug('syscallParse, is %s' % callname)
            exit_info.fname, exit_info.fname_addr, exit_info.flags, exit_info.mode, ida_msg = self.parseOpen(frame, callname)
            if self.record_fd and exit_info.fname is not None and (exit_info.fname.endswith('localtime') or exit_info.fname.startswith('/proc/')):
                return None
            if exit_info.fname is None and not quiet:
                if exit_info.fname_addr is None:
                    self.lgr.debug('exit_info.fname_addr is none')
                    return None
                ''' filename not yet present in ram, do the two step '''
                ''' TBD think we are triggering off kernel's own read of the fname, then again someitme it seems corrupted...'''
                ''' Do not use context manager on superstition that filename could be read in some other task context.'''
                
                if self.mem_utils.WORD_SIZE == 4:
                    self.lgr.debug('syscallParse, open pid %d filename not yet here... set break at 0x%x ' % (pid, exit_info.fname_addr))
                    self.finish_break[pid] = SIM_breakpoint(cpu.current_context, Sim_Break_Linear, Sim_Access_Read, exit_info.fname_addr, 1, 0)
                    self.finish_hap[pid] = RES_hap_add_callback_index("Core_Breakpoint_Memop", self.finishParseOpen, exit_info, self.finish_break[pid])
                else:
                    if pageUtils.isIA32E(cpu):
                        ptable_info = pageUtils.findPageTableIA32E(cpu, exit_info.fname_addr, self.lgr)
                        if not ptable_info.ptable_exists:
                            self.lgr.debug('syscallParse, open pid %d filename not yet here... set ptable break at 0x%x ' % (pid, ptable_info.table_addr))
                            self.finish_break[pid] = SIM_breakpoint(cpu.physical_memory, Sim_Break_Physical, Sim_Access_Write, ptable_info.table_addr, 1, 0)
                            self.finish_hap_table[pid] = RES_hap_add_callback_index("Core_Breakpoint_Memop", self.fnameTable, exit_info, self.finish_break[pid])
                        elif not ptable_info.page_exists:
                            self.lgr.debug('syscallParse, open pid %d filename not yet here... set page break at 0x%x ' % (pid, ptable_info.page_addr))
                            self.finish_break[pid] = SIM_breakpoint(cpu.physical_memory, Sim_Break_Physical, Sim_Access_Write, ptable_info.page_addr, 1, 0)
                            self.finish_hap_page[pid] = RES_hap_add_callback_index("Core_Breakpoint_Memop", self.fnamePage, exit_info, self.finish_break[pid])
                        
                #SIM_break_simulation('fname is none...')
            else:
                #self.lgr.debug('got fname %s' % exit_info.fname)
                for call_param in syscall_info.call_params:
                    #self.lgr.debug('got param type %s' % type(call_param.match_param))
                    if call_param.match_param.__class__.__name__ == 'Dmod':
                         mod = call_param.match_param
                         #self.lgr.debug('is dmod, mod.getMatch is %s' % mod.getMatch())
                         #if mod.fname_addr is None:
                         if mod.getMatch() == exit_info.fname:
                             self.lgr.debug('syscallParse, dmod match on fname %s, cell %s' % (exit_info.fname, self.cell_name))
                             exit_info.call_params = call_param
                    if type(call_param.match_param) is str and (call_param.subcall is None or call_param.subcall.startswith('open') and (call_param.proc is None or call_param.proc == self.comm_cache[pid])):
                        self.lgr.debug('syscall open, found match_param %s' % call_param.match_param)
                        exit_info.call_params = call_param
                             
                        
                        break

        if callname == 'mkdir':        
            exit_info.fname, exit_info.fname_addr, exit_info.flags, exit_info.mode, ida_msg = self.parseOpen(frame, callname)
            if exit_info.fname is None and not quiet:
                ''' filename not yet present in ram, do the two step '''
                ''' TBD think we are triggering off kernel's own read of the fname, then again someitme it seems corrupted...'''
                ''' Do not use context manager on superstition that filename could be read in some other task context.'''
                self.lgr.debug('syscallParse, mkdir pid %d filename not yet here... set break at 0x%x ' % (pid, exit_info.fname_addr))
                self.finish_break[pid] = SIM_breakpoint(cpu.current_context, Sim_Break_Linear, Sim_Access_Read, exit_info.fname_addr, 1, 0)
                self.finish_hap[pid] = RES_hap_add_callback_index("Core_Breakpoint_Memop", self.finishParseOpen, exit_info, self.finish_break[pid])

        elif callname == 'execve':        
            retval = self.parseExecve(syscall_info)
            if not retval:
                exit_info = None
        elif callname == 'close':        
            fd = frame['param1']
            if self.traceProcs is not None:
                #self.lgr.debug('syscallparse for close pid %d' % pid)
                self.traceProcs.close(pid, fd)
            exit_info.old_fd = fd
            exit_info.call_params = self.sockwatch.getParam(pid, fd)
            self.sockwatch.close(pid, fd)

            for call_param in syscall_info.call_params:
                if call_param.match_param == frame['param1'] and (call_param.proc is None or call_param.proc == self.comm_cache[pid]):
                    if not self.linger:
                        self.lgr.debug('closed fd %d, stop trace' % fd)
                        self.stopTrace()
                        ida_msg = 'Closed FD %d' % fd
                        exit_info.call_params = call_param
                        break 
                elif call_param.match_param.__class__.__name__ == 'Dmod' and call_param.match_param.pid == pid and exit_info.old_fd == call_param.match_param.fd:
                    self.lgr.debug('sysall close Dmod, pid and fd match')
                    exit_info.call_params = call_param
                

        elif callname == 'dup':        
            exit_info.old_fd = frame['param1']
            ida_msg = '%s pid:%d fid:%d' % (callname, pid, frame['param1'])
        elif callname == 'dup2':        
            exit_info.old_fd = frame['param1']
            exit_info.new_fd = frame['param2']
            ida_msg = '%s pid:%d fid:%d newfid:%d' % (callname, pid, frame['param1'], frame['param2'])
        elif callname == 'clone':        

            flags = frame['param1']
            child_stack = frame['param2']
            exit_info.fname_addr = child_stack
            ida_msg = '%s pid:%d flags:0x%x child_stack: 0x%x ptid: 0x%x ctid: 0x%x iregs: 0x%x' % (callname, pid, flags, 
                child_stack, frame['param3'], frame['param4'], frame['param5'])
              
            self.context_manager.setIdaMessage(ida_msg)
            for call_param in syscall_info.call_params:
                if call_param.nth is not None:
                    call_param.count = call_param.count + 1
                    self.lgr.debug('syscall clone call_param.count %s call_param.nth %s' % (str(call_param.count), str(call_param.nth)))
                    ''' negative nth means stop in parent '''
                    if call_param.count >= abs(call_param.nth):
                        exit_info.call_params = call_param
                        self.lgr.debug('syscall clone added call_param')
                break
            #self.traceProcs.close(pid, fd)
        elif callname == 'pipe' or callname == 'pipe2':        
            exit_info.retval_addr = frame['param1']
            

        elif callname == 'ipc':        
            call = frame['param1']
            callname = ipc.call[call]
            exit_info.socket_callname = callname
            if call == ipc.MSGGET or call == ipc.SHMGET:
                key = frame['param2']
                exit_info.fname = key
                ida_msg = 'ipc %s pid:%d key: 0x%x size: %d  flags: 0x%x\n %s' % (callname, pid, key, frame['param3'], frame['param4'],
                       taskUtils.stringFromFrame(frame)) 
            elif call == ipc.MSGSND or call == ipc.MSGRCV:
                ida_msg = 'ipc %s pid:%d quid: 0x%x size: %d addr: 0x%x' % (callname, pid, frame['param4'], frame['param3'], frame['param5'])
            elif call == ipc.SHMAT:
                ida_msg = 'ipc %s pid:%d segid: 0x%x ret_addr: 0x%x' % (callname, pid, frame['param2'], frame['param4'])
            else:
                ida_msg = 'ipc %s pid:%d %s' % (callname, pid, taskUtils.stringFromFrame(frame) )

        elif callname == 'ioctl':        
            fd = frame['param1']
            cmd = frame['param2']
            param = frame['param3']
            exit_info.cmd = cmd
            exit_info.old_fd = fd
            if cmd == net.FIONBIO:
                value = self.mem_utils.readWord32(cpu, param)
                ida_msg = 'ioctl pid:%d FD: %d FIONBIO: %d' % (pid, fd, value) 
            elif cmd == net.FIONREAD:
                ida_msg = 'ioctl pid:%d FD: %d FIONREAD ptr: 0x%x' % (pid, fd, param) 
                exit_info.retval_addr = param
            else:
                ida_msg = 'ioctl pid:%d FD: %d cmd: 0x%x' % (pid, fd, cmd) 
            for call_param in syscall_info.call_params:
                if call_param.match_param == fd and (call_param.proc is None or call_param.proc == self.comm_cache[pid]):
                    exit_info.call_params = call_param
                    break

        elif callname == 'gettimeofday':        
            if not self.record_fd:
                timeval_ptr = frame['param1']
                ida_msg = 'gettimeofday pid:%d (%s) timeval_ptr: 0x%x' % (pid, comm, timeval_ptr)
                exit_info.retval_addr = timeval_ptr
            else:
                self.checkTimeLoop(callname, pid)
                exit_info = None

        elif callname == 'waitpid':        
            if not self.record_fd:
                wait_pid = frame['param1']
                ida_msg = 'waitfor pid:%d (%s) wait_pid: %d' % (pid, comm, wait_pid)
            else:
                self.checkTimeLoop(callname, pid)
                exit_info = None
 
        elif callname == 'nanosleep':        
            time_spec = frame['param1']
            seconds = self.mem_utils.readWord32(cpu, time_spec)
            nano = self.mem_utils.readWord32(cpu, time_spec+self.mem_utils.WORD_SIZE)
            ida_msg = 'nanosleep pid:%d time_spec: 0x%x seconds: %d nano: %d' % (pid, time_spec, seconds, nano)
            #SIM_break_simulation(ida_msg)

        elif callname == 'fcntl64':        
            fd = frame['param1']
            cmd_val = frame['param2']
            cmd = net.fcntlCmd(cmd_val)
            arg = frame['param3']
            if cmd == 'F_SETFD':
                ida_msg = 'fcntl64 pid:%d FD: %d %s flags: 0%o' % (pid, fd, cmd, arg)
            else:
                ida_msg = 'fcntl64 pid:%d FD: %d command: %s arg: %d\n\t%s' % (pid, fd, cmd, arg, taskUtils.stringFromFrame(frame)) 
            exit_info.old_fd = fd
            exit_info.cmd = cmd_val
            
            for call_param in syscall_info.call_params:
                if call_param.match_param == fd:
                    exit_info.call_params = call_param
                    break

        elif callname in ['_llseek','lseek']:        
            low = None
            if self.mem_utils.WORD_SIZE == 4:
                fd = frame['param1']
                high = frame['param2']
                low = frame['param3']
                result =  frame['param4']
                whence = frame['param5']
                ida_msg = '%s pid:%d FD: %d high: 0x%x low: 0x%x result: 0x%x whence: 0x%x \n%s' % (callname, pid, fd, high, low, 
                        result, whence, taskUtils.stringFromFrame(frame))
                exit_info.retval_addr = result
            else:
                fd = frame['param1']
                offset = frame['param2']
                origin = frame['param3']
                ida_msg = '%s pid:%d FD: %d offset: 0x%x origin: 0x%x' % (callname, pid, fd, offset, origin)

            exit_info.old_fd = fd
            for call_param in syscall_info.call_params:
                #self.lgr.debug('llseek call_params class is %s' % call_param.match_param.__class__.__name__)
                if call_param.match_param.__class__.__name__ == 'DmodSeek':
                    if pid == call_param.match_param.pid and fd == call_param.match_param.fd:
                        self.lgr.debug('syscall llseek would adjust by %d' % call_param.match_param.delta)
                        ''' assume seek cur, moving backwards, so negate the delta Assumes 32-bit x86?'''
                        if low is None:
                            self.lgr.error('syscall llseek dmod no low offset in frame ')
                        else:
                            new_value = low + call_param.match_param.delta
                            self.mem_utils.setRegValue(self.cpu, 'param3', new_value)
                            esp = self.mem_utils.getRegValue(self.cpu, 'esp')
                            self.mem_utils.writeWord(self.cpu, esp+3*self.mem_utils.WORD_SIZE, new_value)
                            #SIM_break_simulation('wrote 0x%x to param3' % new_value)
                        self.stopTrace()
                elif call_param.match_param.__class__.__name__ == 'Dmod' and call_param.match_param.pid == pid and exit_info.old_fd == call_param.match_param.fd:
                    self.lgr.debug('sysall lseek Dmod, pid and fd match')
                    exit_info.call_params = call_param

                elif call_param.match_param == frame['param1']:
                    exit_info.call_params = call_param
                    break

        elif callname == 'read':        
            exit_info.old_fd = frame['param1']
            ida_msg = 'read pid:%s (%s) FD: %s buf: 0x%x count: %s' % (str(pid), comm, str(frame['param1']), frame['param2'], str(frame['param3']))
            #self.lgr.debug(ida_msg)
            #ida_msg = 'read pid:%d (%s) FD: %d buf: 0x%x count: %d' % (pid, comm, frame['param1'], frame['param2'], frame['param3'])
            exit_info.retval_addr = frame['param2']
            exit_info.count = frame['param3']
            ''' check runToIO '''
            #self.lgr.debug('syscall read loop %d call_params ' % len(syscall_info.call_params))
            for call_param in syscall_info.call_params:
                ''' look for matching FD '''
                if type(call_param.match_param) is int:
                    if call_param.match_param == frame['param1'] and (call_param.proc is None or call_param.proc == self.comm_cache[pid]):


                        if call_param.nth is not None:
                            call_param.count = call_param.count + 1
                            self.lgr.debug('syscall read call_param.nth not none, is %d, count is %d' % (call_param.nth, call_param.count))
                            if call_param.count >= call_param.nth:
                                self.lgr.debug('count >= param, set it')
                                exit_info.call_params = call_param
                                if self.kbuffer is not None:
                                    self.lgr.debug('syscall read kbuffer for addr 0x%x' % exit_info.retval_addr)
                                    self.kbuffer.read(exit_info.retval_addr, exit_info.count)
                        else:
                            self.lgr.debug('syscall read, call_param.nth is none, call it matched')
                            exit_info.call_params = call_param
                            if self.kbuffer is not None:
                                self.lgr.debug('syscall read kbuffer for addr 0x%x' % exit_info.retval_addr)
                                self.kbuffer.read(exit_info.retval_addr, exit_info.count)
                        break
                elif call_param.match_param.__class__.__name__ == 'Dmod':
                    ''' handle read dmod during syscall return '''
                    #self.lgr.debug('syscall read, is dmod from %s' % call_param.match_param.getPath())
                    if call_param.match_param.pid is not None and (pid != call_param.match_param.pid or exit_info.old_fd == call_param.match_param.fd):
                        #self.lgr.debug('syscall read, is dmod, but pid or fd does not match')
                        continue
                    exit_info.call_params = call_param
                    '''
                    if call_param.match_param.pid is not None:
                        if pid == call_param.match_param.pid and exit_info.old_fd == call_param.match_param.fd:
                            self.lgr.debug('syscall read, pid and FD match')
                            exit_info.call_params = call_param

                    else:
                        exit_info.call_params = call_param
                    '''
                    break

        elif callname == 'write':        
            exit_info.old_fd = frame['param1']
            count = frame['param3']
            ida_msg = 'write pid:%d (%s) FD: %d buf: 0x%x count: %d' % (pid, comm, frame['param1'], frame['param2'], count)
            exit_info.retval_addr = frame['param2']
            ''' check runToIO '''
            for call_param in syscall_info.call_params:
                if type(call_param.match_param) is int and call_param.match_param == frame['param1'] and (call_param.proc is None or call_param.proc == self.comm_cache[pid]):
                    self.lgr.debug('call param found %d, matches %d' % (call_param.match_param, frame['param1']))
                    exit_info.call_params = call_param
                    break
                elif type(call_param.match_param) is str:
                    self.lgr.debug('write match param for pid:%d is string, add to exit info' % pid)
                    exit_info.call_params = call_param
                    break
                elif call_param.match_param.__class__.__name__ == 'Dmod':
                    if count < 4028:
                        self.lgr.debug('syscall write check dmod count %d' % count)
                        mod = call_param.match_param
                        if mod.checkString(self.cpu, frame['param2'], count):
                            if mod.getCount() == 0:
                                self.lgr.debug('syscall write found final dmod %s' % mod.getPath())
                                self.syscall_info.callparams.remove(call_param)
                                if not self.remainingDmod():
                                    self.top.stopTrace(cell_name=self.cell_name, syscall=self)
                                    if not self.top.remainingCallTraces() and SIM_simics_is_running():
                                        self.top.notRunning(quiet=True)
                                        SIM_break_simulation('dmod done on cell %s file: %s' % (self.cell_name, mod.getPath()))
                                    else:
                                        print('%s performed' % mod.getPath())
                else:
                    self.lgr.debug('syscall write call_param match_param is type %s' % (call_param.match_param.__class__.__name__))
 
        elif callname == 'mmap' or callname == 'mmap2':        
            self.lgr.debug('syscall mmap')
            exit_info.count = frame['param2']
            '''
            if self.mem_utils.WORD_SIZE == 4 and self.cpu.architecture == 'arm' and frame['param1'] != 0:
                #self.lgr.debug(taskUtils.stringFromFrame(frame))
                arg_addr = frame['param1']
                addr = self.mem_utils.readPtr(self.cpu, arg_addr)
                length = self.mem_utils.readPtr(self.cpu, arg_addr+4)
                prot = self.mem_utils.readPtr(self.cpu, arg_addr+8)
                flags = self.mem_utils.readPtr(self.cpu, arg_addr+12)
                fd = self.mem_utils.readPtr(self.cpu, arg_addr+16)
                offset = self.mem_utils.readPtr(self.cpu, arg_addr+20)
                if fd is not None:
                    self.lgr.debug('mmap pid:%d FD: %d' % (pid, fd))
                    pass
                if pid is None:
                    self.lgr.error('PID is NONE?')
                    SIM_break_simulation('eh?, over?')
                elif length is None:
                    ida_msg = '%s pid:%d len is NONE' % (callname, pid)
                elif fd is None:
                    ida_msg = '%s pid:%d FD: NONE' % (callname, pid)
                else:
                    ida_msg = '%s pid:%d FD: %d buf: 0x%x  len: %d prot: 0x%x  flags: 0x%x  offset: 0x%x' % (callname, pid, fd, arg_addr, length, prot, flags, offset)
            '''
            if self.mem_utils.WORD_SIZE == 4 and self.cpu.architecture == 'arm':
                ''' tbd wth? the above seems wrong, why key on addr of zero? '''
                fd = frame['param5']
                prot = frame['param3']
                ida_msg = '%s pid:%d FD: %d addr: 0x%x len: %d prot: 0x%x  flags: 0x%x offset: 0x%x' % (callname, pid, 
                    fd, frame['param1'], frame['param2'], frame['param3'], frame['param4'], frame['param6'])
                self.lgr.debug('syscall mmap arm 4 '+taskUtils.stringFromFrame(frame))
            else:
                fd = frame['param5']
                prot = frame['param3']
                ida_msg = '%s pid:%d FD: %d addr: 0x%x len: %d prot: 0x%x  flags: 0x%x offset: 0x%x' % (callname, pid, 
                    fd, frame['param1'], frame['param2'], frame['param3'], frame['param4'], frame['param6'])
                if self.watch_first_mmap is not None:
                    self.lgr.debug('syscall mmap fd: %d from param5  watch_first_mmap is %d' % (fd, self.watch_first_mmap))
                else:
                    self.lgr.debug('syscall mmap watch_first_mmap is none')
                self.lgr.debug('syscall mmap '+taskUtils.stringFromFrame(frame))
            is_ex = prot & 4
            self.lgr.debug('is exec? %d' % is_ex)
            if self.watch_first_mmap == fd and is_ex:
                self.lgr.debug('syscall mmap fd MATCHES watch_first_mmap %d' % fd)
                exit_info.fname = self.mmap_fname
                self.watch_first_mmap = None

        elif callname in ['select','_newselect', 'pselect6']:        
            exit_info.select_info = SelectInfo(frame['param1'], frame['param2'], frame['param3'], frame['param4'], frame['param5'], 
                 cpu, self.mem_utils, self.lgr)

            ida_msg = '%s pid:%d %s\n' % (callname, pid, exit_info.select_info.getString())
            for call_param in syscall_info.call_params:
                if type(call_param.match_param) is int and exit_info.select_info.hasFD(call_param.match_param) and (call_param.proc is None or call_param.proc == self.comm_cache[pid]):
                    self.lgr.debug('call param found %d' % (call_param.match_param))
                    exit_info.call_params = call_param
                    break

        elif callname == 'poll' or callname == 'ppoll':
            exit_info.poll_info = PollInfo(frame['param1'], frame['param2'], frame['param3'], self.mem_utils, cpu, self.lgr)

            ida_msg = '%s pid:%d %s\n' % (callname, pid, exit_info.poll_info.getString())
            for call_param in syscall_info.call_params:
                if type(call_param.match_param) is int and exit_info.poll_info.hasFD(call_param.match_param) and (call_param.proc is None or call_param.proc == self.comm_cache[pid]):
                    self.lgr.debug('call param found %d' % (call_param.match_param))
                    exit_info.call_params = call_param
                    break

        elif callname == 'epoll_ctl':
            epfd = frame['param1']
            op = frame['param2']
            fd = frame['param3']
            events = frame['param4']
            if pid not in self.epolls:
                self.epolls[pid] = {}
            if epfd not in self.epolls[pid]:
                self.epolls[pid][epfd] = EPollInfo(epfd)
                self.epolls[pid][epfd].add(fd, events)
            ida_msg = '%s pid:%d epfd: %d op: %s fd: %d\n' % (callname, pid, epfd, EPollInfo.EPOLL_OPER[op], fd)

        elif callname == 'epoll_wait' or callname == 'epoll_pwait':
            exit_info.old_fd = frame['param1']
            ida_msg = '%s pid:%d epfd: %d\n' % (callname, pid, exit_info.old_fd)

        elif callname == 'socketcall' or callname.upper() in net.callname:
            ida_msg = self.socketParse(callname, syscall_info, frame, exit_info, pid)
            if ida_msg is None and self.record_fd:
                self.lgr.debug('syscall parse ida_msg none for call %s, SKIP call' % callname)
                ''' Not a call we are watching. '''
                exit_info = None

        elif callname == 'wait4':
            ida_msg = '%s pid:%d waitforpid: %d  loc: 0x%x  options: %d rusage: 0x%x' % (callname, pid, frame['param1'], frame['param2'], frame['param3'], frame['param4'])

        else:
            ida_msg = '%s %s   pid:%d (%s)' % (callname, taskUtils.stringFromFrame(frame), pid, comm)
            self.context_manager.setIdaMessage(ida_msg)
        if ida_msg is not None and not quiet:
            #self.lgr.debug(ida_msg.strip()) 
            
            #if ida_msg is not None and self.traceMgr is not None and (len(syscall_info.call_params) == 0 or exit_info.call_params is not None):
            if ida_msg is not None and self.traceMgr is not None:
                if len(ida_msg.strip()) > 0:
                    self.traceMgr.write(ida_msg+'\n')
        return exit_info


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
                #self.lgr.debug('will delete hap %s' % str(self.stop_hap))
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
                ''' Run the stop action, which is a hapCleaner class '''
                self.stop_action.run(cb_param=msg)

                if self.call_list is not None:
                    for callname in self.call_list:
                        #self.top.rmCallTrace(self.cell_name, callname)
                        self.top.rmCallTrace(self.cell_name, self.name)
            else:
                self.lgr.debug('syscall will linger and catch next occurance')
                self.top.skipAndMail()

    def getExitAddrs(self, break_eip, syscall_info, frame = None):
        exit_eip1 = None
        exit_eip2 = None
        exit_eip3 = None
 
        if break_eip == self.param.sysenter or break_eip == self.param.compat_32_entry or break_eip == self.param.compat_32_int128:
            ''' caller frame will be in regs'''
            if frame is None:
                frame = self.task_utils.frameFromRegs(self.cpu, compat32=syscall_info.compat32)
                frame_string = taskUtils.stringFromFrame(frame)
            exit_eip1 = self.param.sysexit
            ''' catch interrupt returns such as wait4 '''
            exit_eip2 = self.param.iretd
            try:
                exit_eip3 = self.param.sysret64
                #self.lgr.debug('sysenter exit1 0x%x 2 0x%x 3 0x%x' % (exit_eip1, exit_eip2, exit_eip3))
            except AttributeError:
                exit_eip3 = None
                #self.lgr.debug('sysenter exit1 0x%x 2 0x%x ' % (exit_eip1, exit_eip2))
            
        elif break_eip == self.param.sys_entry:
            if frame is None:
                frame = self.task_utils.frameFromRegs(syscall_info.cpu, compat32=syscall_info.compat32)
                ''' fix up regs based on eip and esp found on stack '''
                reg_num = self.cpu.iface.int_register.get_number(self.mem_utils.getESP())
                esp = self.cpu.iface.int_register.read(reg_num)
                frame['eip'] = self.mem_utils.readPtr(self.cpu, esp)
                frame['esp'] = self.mem_utils.readPtr(self.cpu, esp+12)
                frame_string = taskUtils.stringFromFrame(frame)
            #self.lgr.debug('sys_entry frame %s' % frame_string)
            exit_eip1 = self.param.iretd
        elif break_eip == self.param.arm_entry:
            exit_eip1 = self.param.arm_ret
            exit_eip2 = self.param.arm_ret2
            if frame is None:
                frame = self.task_utils.frameFromRegs(self.cpu)
                frame_string = taskUtils.stringFromFrame(frame)
                #SIM_break_simulation(frame_string)
        elif break_eip == syscall_info.calculated:
            ''' Note EIP in stack frame is unknown '''
            #frame['eax'] = syscall_info.callnum
            if self.cpu.architecture == 'arm':
                if frame is None:
                    frame = self.task_utils.frameFromRegs(self.cpu)
                exit_eip1 = self.param.arm_ret
                exit_eip2 = self.param.arm_ret2
                exit_eip2 = None
                #exit_eip3 = self.param.sysret64
            elif self.mem_utils.WORD_SIZE == 8:
                if frame is None:
                    frame = self.task_utils.frameFromRegs(self.cpu, compat32=syscall_info.compat32)
                exit_eip1 = self.param.sysexit
                exit_eip2 = self.param.iretd
                exit_eip3 = self.param.sysret64
            else:
                if frame is None:
                    frame = self.task_utils.frameFromStackSyscall()
                exit_eip1 = self.param.sysexit
                exit_eip2 = self.param.iretd
            #self.lgr.debug('syscallHap calculated')
            frame_string = taskUtils.stringFromFrame(frame)
            #self.lgr.debug('frame string %s' % frame_string)
        return frame, exit_eip1, exit_eip2, exit_eip3
        
    def syscallHap(self, syscall_info, context, break_num, memory):
        ''' Invoked when syscall is detected.  May set a new breakpoint on the
            return to user space so as to collect remaining parameters, or to stop
            the simulation as part of a debug session '''
        ''' NOTE Does not track Tar syscalls! '''
        #self.lgr.debug('syscalhap %s context %s break_num %s cpu is %s t is %s' % (self.name, str(context), str(break_num), str(memory.ini_ptr), type(memory.ini_ptr)))
        #self.lgr.debug('memory.ini_ptr.name %s' % (memory.ini_ptr.name))

        break_eip = self.mem_utils.getRegValue(self.cpu, 'pc')
        cpu, comm, pid = self.task_utils.curProc() 
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
        if syscall_info.callnum is None:
           ''' tracing all'''
           callname = self.task_utils.syscallName(callnum, syscall_info.compat32) 
           if self.record_fd and (callname not in record_fd_list or comm in skip_proc_list):
               #self.lgr.debug('syscallHap not in record_fd list: %s' % callname)
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
           ''' not callnum from reg may not be the real callnum, e.g., 32-bit compatability.  Use syscall_info.callnum.
               Also, this is a cacluated entry, so compat32 conventions are already undone '''
           callname = self.task_utils.syscallName(syscall_info.callnum, syscall_info.compat32) 
           if self.record_fd and (callname not in record_fd_list or comm in skip_proc_list):
               return
           if pid == 1 and callname in ['open', 'mmap', 'mmap2']:
               ''' ad-hoc noise reduction '''
               return
           callnum = syscall_info.callnum
           #syscall_info.compat32 = False
        ''' call 0 is read in 64-bit '''
        if callnum == 0 and self.mem_utils.WORD_SIZE==4:
            self.lgr.debug('syscallHap callnum is zero')
            return
        value = memory.logical_address
        #self.lgr.debug('syscallHap cell %s context %sfor pid:%s (%s) at 0x%x (memory 0x%x) callnum %d expected %s compat32 set for the HAP? %r name: %s cycle: 0x%x' % (self.cell_name, str(context), 
            #pid, comm, break_eip, value, callnum, str(syscall_info.callnum), syscall_info.compat32, self.name, self.cpu.cycles))
           
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
            to watch or not.  An example is execve, which must be watched for all processes to provide a toExecve function. '''
        if self.debugging and not self.context_manager.amWatching(pid) and syscall_info.callnum is not None and self.background_break is None and self.cell is None:
            self.lgr.debug('syscallHap name: %s pid:%d missing from context manager.  Debugging and specific syscall watched. callnum: %d' % (self.name, 
                 pid, syscall_info.callnum))
            return

        if self.bang_you_are_dead:
            self.lgr.error('syscallhap call to dead hap pid %d' % pid) 
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

        if callnum > 400:
            self.lgr.debug('syscallHap callnum is too big... %d' % callnum)
            return
        
        if self.sharedSyscall.isPendingExecve(pid):
            if callname == 'close':
                self.lgr.debug('syscallHap must be a close on exec? pid:%d' % pid)
                return
            elif callname == 'execve':
                self.lgr.debug('syscallHap must be a execve in execve? pid:%d' % pid)
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
        if pending_call is not None and not self.swapper_ok:
            if callname == 'sigreturn':
                return
            else:
                if pending_call == self.task_utils.syscallNumber('pipe', self.compat32) and callnum == self.task_utils.syscallNumber('pipe2', self.compat32):
                    self.lgr.debug('syscall was pending pipe  pid:%d call %d' % (pid, pending_call))
                    return
                else:
                    self.lgr.debug('syscall was pending pid:%d call %d' % (pid, pending_call))
                    return
                 

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
                                if len(syscall_info.call_params) == 0 or exit_info.call_params is not None or tracing_all or pid in self.pid_sockets:
                                    if self.stop_on_call:
                                        cp = CallParams(None, None, break_simulation=True)
                                        exit_info.call_params = cp
                                    #self.lgr.debug('exit_info.call_params pid %d is %s' % (pid, str(exit_info.call_params)))
                                    if syscall_info.call_params is not None:
                                        self.lgr.debug('syscallHap %s cell: %s call to addExitHap for pid %d call  %d len %d trace_all %r' % (self.name, 
                                           self.cell_name, pid, syscall_info.callnum, len(syscall_info.call_params), tracing_all))
                                    else:
                                        self.lgr.debug('syscallHap %s cell: %s call to addExitHap for pid %d call  %d no params trace_all %r' % (self.name, self.cell, 
                                           pid, syscall_info.callnum, tracing_all))
                                    self.sharedSyscall.addExitHap(self.cell, pid, exit_eip1, exit_eip2, exit_eip3, exit_info, exit_info_name)
                                    #self.sharedSyscall.addExitHap(cell, pid, exit_eip1, exit_eip2, exit_eip3, exit_info, exit_info_name)
                                else:
                                    #self.lgr.debug('did not add exitHap')
                                    pass
                            else:
                                self.lgr.debug('syscall invoking callback')
                                self.callback()
                    else:
                        self.lgr.debug('syscallHap skipping tar %s, no exit' % comm)
                
            else:
                ''' TBD no longer reached.  callnum set to syscall_info to handle 32 bit compat mode where we don't know how we got here '''
                self.lgr.debug('syscallHap looked for call %d, got %d, calculated 0x%x do nothing' % (syscall_info.callnum, callnum, syscall_info.calculated))
                pass
        else:
            ''' tracing all syscalls, or watching for any syscall, e.g., during debug '''
            exit_info = self.syscallParse(callnum, callname, frame, cpu, pid, comm, syscall_info)
            #self.lgr.debug('syscall looking for any, got %d from %d (%s) at 0x%x ' % (callnum, pid, comm, break_eip))

            if exit_info is not None:
                if comm != 'tar':
                    name = callname+'-exit' 
                    self.lgr.debug('syscallHap call to addExitHap for pid %d' % pid)
                    if self.stop_on_call:
                        cp = CallParams(None, None, break_simulation=True)
                        exit_info.call_params = cp
                    self.sharedSyscall.addExitHap(self.cell, pid, exit_eip1, exit_eip2, exit_eip3, exit_info, name)
                else:
                    self.lgr.debug('syscallHap pid:%d skip exitHap for tar' % pid)


    def handleExit(self, pid, ida_msg, killed=False, retain_so=False, exit_group=False):
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
            self.lgr.debug('syscallHap handleExit %s pid %d last_one %r debugging %d retain_so %r' % (self.name, pid, last_one, self.debugging, retain_so))
            if (last_one or (exit_group and pid == debugging_pid)) and self.debugging:
                if self.top.hasProcHap():
                    ''' exit before we got to text section '''
                    self.lgr.debug('syscall handleExit  exit of %d before we got to text section ' % pid)
                    SIM_run_alone(self.top.undoDebug, None)
                self.lgr.debug('syscall handleExit exit or exit_group pid:%d' % pid)
                self.sharedSyscall.stopTrace()
                ''' record exit so we don't see this proc, e.g., when going to debug its next instantiation '''
                self.task_utils.setExitPid(pid)
                #fun = stopFunction.StopFunction(self.top.noDebug, [], False)
                #self.stop_action.addFun(fun)
                print('exit pid %d' % pid)
                SIM_run_alone(self.stopAlone, 'exit or exit_group pid:%d' % pid)

    def getBinders(self):
        return self.binders

    def getConnectors(self):
        return self.connectors

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

    def isBackground(self):
        ''' Is this syscall hap watching background processes? '''
        retval = False
        if self.background_break != None:
            pid, cpu = self.context_manager.getDebugPid()
            if pid is not None:
                ''' debugging some process, and we are background.  thus we are in a different context than the process being debugged. '''
                retval = True
        return retval

    def handleReadOrSocket(self, callname, frame, exit_info, syscall_info):
        
        retval = None
        the_callname = callname
        if 'ss' in frame:
            ss = frame['ss']
            #ida_msg = self.socketParse(callname, syscall_info, frame, exit_info, pid)
            exit_info.old_fd = ss.fd
            exit_info.sock_struct = ss
            socket_callnum = frame['param1']
            exit_info.socket_callname = net.callname[socket_callnum].lower()
            ida_msg = 'syscall socketcall %s ss is %s' % (exit_info.socket_callname, ss.getString())
            self.lgr.debug('setExits socket parsed: %s' % ida_msg)
            the_callname = exit_info.socket_callname
            if ss.addr is not None:
                exit_info.retval_addr = ss.addr
                self.lgr.debug('ss addr is 0x%x len is %d' % (ss.addr, ss.length))
            if the_callname == 'recvfrom' and callname == 'socketcall':        
                src_addr = self.mem_utils.readWord32(self.cpu, frame['param2']+16)
                src_addr_len = self.mem_utils.readWord32(self.cpu, frame['param2']+20)
                exit_info.fname_addr = src_addr
                exit_info.count = src_addr_len

        else:
            self.lgr.debug('setExits socket no ss struct, set old_fd to %d' % frame['param1'])
            exit_info.old_fd = frame['param1']

        if exit_info.old_fd is not None:
    
            retval = the_callname
            self.lgr.debug('syscall setExists callname %s' % the_callname)
            if the_callname in ['accept', 'recv', 'recvfrom', 'read', 'recvmsg']:
                for call_param in syscall_info.call_params:
                    self.lgr.debug('syscall setExists subcall %s' % call_param.subcall)
                    if call_param.subcall is None or call_param.subcall == the_callname:
                        self.lgr.debug('Syscall name %s setExits syscall %s subcall %s call_param.match_param is %s fd is %d' % (self.name, the_callname, call_param.subcall, str(call_param.match_param), exit_info.old_fd))
                        ''' TBD why not do for any and all?'''
                        #if (call_param.subcall == 'accept' or self.name=='runToIO' or self.name=='runToInput') and (call_param.match_param < 0 or call_param.match_param == ss.fd):
                        if (call_param.match_param < 0 or call_param.match_param == exit_info.old_fd):
                            self.lgr.debug('setExits set the call_params')
                            exit_info.call_params = call_param
                            if call_param.match_param == exit_info.old_fd:
                                this_pid = self.top.getPID()
                                self.lgr.debug('syscall setExits found fd %d, this pid %d' % (exit_info.old_fd, this_pid))
                            if self.kbuffer is not None:
                                self.lgr.debug('syscall recv kbuffer for addr 0x%x' % exit_info.retval_addr)
                                self.kbuffer.read(exit_info.retval_addr, exit_info.count)
                            break
       
        else:
            self.lgr.warning('syscall setExits pid %d has old_fd of None')
            retval = None
        return retval

    def handleSelect(self, callname, pid, frame, exit_info, syscall_info):
            exit_info.select_info = SelectInfo(frame['param1'], frame['param2'], frame['param3'], frame['param4'], frame['param5'], 
                 self.cpu, self.mem_utils, self.lgr)

            ida_msg = '%s pid:%d %s\n' % (callname, pid, exit_info.select_info.getString())
            #self.lgr.debug('handleSelect %s' % ida_msg)
            for call_param in syscall_info.call_params:
                #self.lgr.debug('handleSelect call_param %s' % str(call_param))
                #if type(call_param.match_param) is int and exit_info.select_info.hasFD(call_param.match_param) and (call_param.proc is None or call_param.proc == self.comm_cache[pid]):
                if type(call_param.match_param) is int and (call_param.proc is None or call_param.proc == self.comm_cache[pid]):
                    #self.lgr.debug('handleSelect call param found %d' % (call_param.match_param))
                    exit_info.call_params = call_param
                    break

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

    def addCallParams(self, call_params):
        gotone = False
        for call in call_params:
            if call not in self.syscall_info.call_params:
                self.syscall_info.call_params.append(call)
                gotone = True
        if gotone:
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

    def getCallParams(self):
        return self.syscall_info.call_params

    def remainingDmod(self):
        for call_param in self.syscall_info.call_params:
            if call_param.match_param.__class__.__name__ == 'Dmod':
                 return True
        return False

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

    def stopOnExit(self):
        self.stop_on_exit=True
        self.lgr.debug('syscall stopOnExit')
