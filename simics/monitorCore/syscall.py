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
import resimUtils
import sys
import copy
from resimHaps import *
import resimSimicsUtils
from resimSimicsUtils import rprint
'''
how does simics not have this in its python sys.path?
'''
sys.path.append('/usr/local/lib/python2.7/dist-packages')
sys.path.append('/usr/local/lib/python3.6/dist-packages')
sys.path.append('/usr/lib/python3/dist-packages')
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

def addParam(exit_info, param):
    # Add a parameter to the exit_info parameters list and make it the default.
    # Intended for use by sycalls in which we know the call matches without
    # waiting to see return values.
    if param is None:
        print('addParam called with None **************************')
    exit_info.call_params.append(param)
    if exit_info.matched_param is None:
        exit_info.matched_param = param

class SockWatch():
    ''' track selected socket activity '''
    def __init__(self):
        self.watches = {}
    class sockFD():
        def __init__(self, fd, call_param):
            self.fd = fd
            self.call_param = call_param

    def bind(self, tid, fd, call_param):
        if tid not in self.watches:
            self.watches[tid] = []
        self.watches[tid].append(self.sockFD(fd, call_param))

    def getParam(self, tid, fd):
        retval = None
        if tid in self.watches:
            for watch in self.watches[tid]:
                if watch.fd == fd:
                    return watch.call_param
        return retval 

    def close(self, tid, fd):
        if tid in self.watches:
            got_it = None
            for watch in self.watches[tid]:
                if watch.fd == fd:
                    print('close %d for %s' % (fd, tid))
                    got_it = watch
                    break
            if got_it is not None:
                self.watches[tid].remove(got_it) 

class SockParams():
    def __init__(self, domain, sock_type, protocol):
        self.domain = domain
        self.sock_type = sock_type
        self.protocol = protocol
    def getString(self):
        return 'SockParams: domain %s type: %s protocol: %s' % (self.domain, self.sock_type, self.protocol)

class SyscallInfo():
    def __init__(self, cpu, tid, calculated, trace):
        self.cpu = cpu
        self.tid = tid
        self.callnum = None
        self.callnum_arm64 = None
        self.calculated = calculated
        self.trace = trace
        self.call_count = 0
        self.fname = None
        self.fd = None
        ''' 32-bit compatibility mode for this task '''
        self.compat32 = False
    def addCall(self, callnum, entry, arm64_app):
        if self.callnum is None:
            self.callnum = {}
            self.callnum_arm64 = {}
        if arm64_app:
            self.callnum_arm64[entry] = callnum
        else:
            self.callnum[entry] = callnum
    def getCall(self, entry, arm64_app):
        retval = None
        if arm64_app:
            if entry in self.callnum_arm64:
                retval = self.callnum_arm64[entry]
        else:
            if entry in self.callnum:
                retval = self.callnum[entry]
        return retval
    def hasEntry(self, entry):
        retval = False
        if self.callnum is not None:
            if entry in self.callnum or entry in self.callnum_arm64:
                retval = True
        return retval
        


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
            #self.lgr.debug('SelectInfo reset fd %d' % fd)
            if fd_set is not None:
                read_low, read_high = self.readit(fd_set)
                if read_low is not None:
                    the_set = read_low | (read_high << 32) 
                    new_value = memUtils.clearBit(the_set, fd)
                    self.writeit(fd_set, new_value)
                    #self.lgr.debug('SelectInfo reset fdset new value 0x%x' % new_value)

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

class EPollEvent():
    def __init__(self, events_ptr, cpu, mem_utils, lgr=None):
        self.events = mem_utils.readWord32(cpu, events_ptr)
        if lgr is not None:
            if self.events is not None:
                lgr.debug('EPollEvent events_ptr 0x%x got events 0x%x' % (events_ptr, self.events))
            else:
                lgr.debug('EPollEvent events_ptr 0x%x got None' % events_ptr)
        data_ptr = events_ptr + 4
        self.data = mem_utils.readWord(cpu, data_ptr)
        if lgr is not None:
            if self.data is not None:
                lgr.debug('EPollEvent data_ptr 0x%x got data 0x%x' % (data_ptr, self.data))
            else:
                lgr.debug('EPollEvent data_ptr 0x%x got None' % data_ptr)
    def toString(self):
        if self.events is not None:
            if self.data is not None:
                retval = 'events: 0x%x data 0x%x' % (self.events, self.data)
            else:
                retval = 'events: 0x%x data is NONE?' % (self.events)
        else:
            retval = 'Events is None?'
        return retval

class EPollWaitInfo():
    def __init__(self, epfd, events, maxevents, timeout, epoll_info):
        self.epfd = epfd
        self.events = events
        self.maxevents = maxevents
        self.timeout = timeout
        self.epoll_info = epoll_info
    def toString(self):
        if self.epoll_info is not None:
            retval = 'epfd: %d events: 0x%x maxevents: %d  timeout: 0x%x %s' % (self.epfd, self.events, self.maxevents, self.timeout, self.epoll_info.toString())
        else:
            retval = 'epfd: %d events: 0x%x maxevents: %d  timeout: 0x%x (no epoll_info)' % (self.epfd, self.events, self.maxevents, self.timeout)
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
    def __init__(self, epfd, cpu, mem_utils, lgr):
        self.epfd = epfd
        self.cpu = cpu
        self.mem_utils = mem_utils
        self.lgr = lgr
        self.fd_set = []
    def add(self, fd, events):
        entry = self.FDS(fd, events)
        self.fd_set.append(entry)
    def hasFD(self, fd):
        for entry in self.fd_set:
            if entry.fd == fd:
                return True
        return False
    def findFD(self, event):
        retval = None
        for entry in self.fd_set:
            if entry.events.data == event.data:
                retval = entry.fd
        return retval
 
    def toString(self):
        retval = ''
        for entry in self.fd_set:
            event_string = entry.events.toString()
            retval = ' FD: %d events: %s' % (entry.fd, event_string)
        return retval


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
            if fd == 0xffffffff:
                break
            elif fd == 0xffffffffffffffff:
                break
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
    def __init__(self, syscall_instance, cpu, tid, callnum, callname, compat32, frame):
        self.cpu = cpu
        self.tid = tid
        self.callnum = callnum
        self.callname = callname
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
        self.epoll_wait = None
        ''' for sendmsg/recvmsg '''
        self.msghdr = None
        self.compat32 = compat32
        self.frame = frame
        ''' narrow search to information about the call '''
        self.call_params = []
        self.matched_param = None
        self.syscall_entry = None
        self.mode_hap = None
   
        ''' who to call from sharedSyscall, e.g., to watch mmap for SO maps '''
        self.syscall_instance = syscall_instance
        ''' stop and reset reversing origin if set '''
        self.origin_reset = False
        self.bytes_to_write = None
        self.trace_msg = None
        self.asynch_handler = None
        self.sock_addr = None
        self.word_size = 8
        self.append_msg = None

        self.count_addr = None
        # address used if asynch read is not ready
        self.delay_count_addr = None
        self.did_delay = False
        self.src_addr = None
        self.src_addr_len = None
        self.prot = None

EXTERNAL = 1
AF_INET = 2
DEST_PORT = 3
class CallParams():
    def __init__(self, name, subcall, match_param, break_simulation=False, proc=None, sub_match=None):
        self.name = name
        self.subcall = subcall
        self.match_param = match_param
        self.sub_match = sub_match
        self.param_flags = []
        self.break_simulation = break_simulation
        self.proc = proc
        self.nth = None
        self.count = 0
        self.call_list = []
    def toString(self):
        retval = 'name: %s subcall %s  match_param %s proc: %s call_list: %s' % (self.name, self.subcall, str(self.match_param), self.proc, str(self.call_list))
        return retval

class TidFilter():
    def __init__(self, tid):
        self.tid = tid

class IPCFilter():
    def __init__(self, call):
        self.call = call

def hasParamMatchRequest(call_params):
    retval = True
    if len(call_params) == 0:
        retval = False
    elif len(call_params) == 1:
        if call_params[0].subcall is None and call_params[0].match_param is None:
            retval = False
    return retval

''' syscalls to watch when record_df is true on traceAll.  Note gettimeofday and waitpid are included for exitMaze '''
record_fd_list = ['connect', 'bind', 'accept', 'open', 'openat', 'socketcall', 'gettimeofday', 'waitpid', 'exit', 'exit_group', 'execve', 'clone', 'fork', 'vfork']
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
        ''' mostly a test if we are debugging (if tid is not none). not very clean '''
        tid, cpu = context_manager.getDebugTid()
        self.debugging = False
        self.stop_on_call = stop_on_call
        if tid is not None or name == 'debugExit':
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
        ''' lists of sockets by tid that we are watching for selected tracing '''
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
        self.tid_sockets = {}
        self.tid_fd_sockets = {}

        ''' And one for tracking epoll info '''
        self.epolls = {}
      
        self.syscall_context = None 
        self.background = background
        break_list, break_addrs = self.doBreaks(compat32, background)

        ''' tbd, was only setting skip and mail in hap cleaner if self.debugging was set.  but with the "only" lists, we need a better scheme, so try this'''
        break_simulation = False
        for call in self.call_params:
            if call is not None and call.break_simulation:
                break_simulation = True
                break 
        # for recreating the syscall TBD needs to be tied to call params not the call
        self.flist_in = flist_in
        if flist_in is not None:
            ''' Given function list to use after syscall completes '''
            hap_clean = hapCleaner.HapCleaner(cpu)
            #for ph in self.proc_hap:
            #    hap_clean.add("GenContext", ph)
            self.stop_action = hapCleaner.StopAction(hap_clean, flist=flist_in, break_addrs = break_addrs)
            #self.lgr.debug('Syscall cell %s stop action includes given flist_in.  stop_on_call is %r linger: %r name: %s' % (self.cell_name, stop_on_call, self.linger, name))
        elif (break_simulation or self.debugging) and not self.breakOnExecve() and not trace and skip_and_mail:
            hap_clean = hapCleaner.HapCleaner(cpu)
            #for ph in self.proc_hap:
            #    hap_clean.add("GenContext", ph)
            #f1 = stopFunction.StopFunction(self.top.skipAndMail, [], nest=False)
            f1 = stopFunction.StopFunction(self.top.stepN, [1], nest=False)
            flist = [f1]
            self.stop_action = hapCleaner.StopAction(hap_clean, flist=flist, break_addrs = break_addrs)
            self.lgr.debug('Syscall cell %s stop action includes stepN in flist. SOMap exists: %r linger: %r name: %s' % (self.cell_name, (soMap is not None), self.linger, name))
        else:
            hap_clean = hapCleaner.HapCleaner(cpu)
            #for ph in self.proc_hap:
            #    hap_clean.add("GenContext", ph)
            self.stop_action = hapCleaner.StopAction(hap_clean, break_addrs = break_addrs)
            #self.lgr.debug('Syscall cell %s stop action includes NO flist linger: %r name: %s' % (self.cell_name, self.linger, name))

        self.exit_calls = []
        self.exit_calls.append('exit_group')
        self.exit_calls.append('exit')
        self.exit_calls.append('tkill')
        self.exit_calls.append('tgkill')

        self.sig_handler = {}
        self.platform = self.top.getTargetPlatform()

        # when stophap it, remove these parameters
        self.rm_param_queue = []

        # Determine when to stop tracing due to a close FD for trackIO
        self.clone_fd_count = 1

        self.no_exit_maze = False

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
        self.lgr.debug('Syscall stopAlone cell %s added stopHap %d Now stop. msg: %s' % (self.cell_name, self.stop_hap, msg))
        SIM_break_simulation(msg)

    def doBreaks(self, compat32, background):
        break_list = []
        break_addrs = []
        self.timeofday_count = {}
        self.timeofday_start_cycle = {}
        self.lgr.debug('syscall cell_name %s doBreaks.  compat32: %r current context %s' % (self.cell_name, compat32, self.cpu.current_context))
        if self.call_list is None:
            ''' trace all calls '''
            self.syscall_info = SyscallInfo(self.cpu, None,  False, self.trace)
            if self.cpu.architecture.startswith('arm'):
                #phys = self.mem_utils.v2p(self.cpu, self.param.arm_entry)
                if self.param.arm_entry is not None:
                    self.lgr.debug('Syscall arm no callnum, set break at 0x%x ' % (self.param.arm_entry))
                    proc_break = self.context_manager.genBreakpoint(self.cell, Sim_Break_Linear, Sim_Access_Execute, self.param.arm_entry, 1, 0)
                    if self.syscall_context is None:
                        self.syscall_context = self.context_manager.getBPContext(proc_break)
                        #self.lgr.debug('syscall, setting syscall_context to %s' % self.syscall_context)
                    #proc_break = self.context_manager.genBreakpoint(self.cpu.physical_memory, Sim_Break_Physical, Sim_Access_Execute, phys, 1, 0)
                    break_addrs.append(self.param.arm_entry)
                    self.proc_hap.append(self.context_manager.genHapIndex("Core_Breakpoint_Memop", self.syscallHap, self.syscall_info, proc_break, 'syscall'))
                if self.cpu.architecture == 'arm64' and hasattr(self.param, 'arm64_entry'):
                    proc_break = self.context_manager.genBreakpoint(self.cell, Sim_Break_Linear, Sim_Access_Execute, self.param.arm64_entry, 1, 0)
                    self.lgr.debug('syscall doBreaks set entry for arm64 proc_break 0x%x' % proc_break)
                    break_addrs.append(self.param.arm64_entry)
                    self.proc_hap.append(self.context_manager.genHapIndex("Core_Breakpoint_Memop", self.syscallHap, self.syscall_info, proc_break, 'syscall64'))
            elif self.cpu.architecture == 'ppc32':
                if self.param.ppc32_entry is not None:
                    self.lgr.debug('Syscall ppc32 no callnum, set break at 0x%x ' % (self.param.ppc32_entry))
                    proc_break = self.context_manager.genBreakpoint(self.cell, Sim_Break_Linear, Sim_Access_Execute, self.param.ppc32_entry, 1, 0)
                    if self.syscall_context is None:
                        self.syscall_context = self.context_manager.getBPContext(proc_break)
                        #self.lgr.debug('syscall, setting syscall_context to %s' % self.syscall_context)
                    break_addrs.append(self.param.ppc32_entry)
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
                        self.proc_hap.append(self.context_manager.genHapIndex("Core_Breakpoint_Memop", self.syscallHap, self.syscall_info, proc_break, 'syscall'))
                        self.proc_hap.append(self.context_manager.genHapIndex("Core_Breakpoint_Memop", self.syscallHap, self.syscall_info, proc_break1, proc_break1, 'syscall'))
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
                    self.lgr.debug('SysCall no call list, no breaks set.  params: %s' % self.param.getParamString())
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
                    self.proc_hap.append(self.context_manager.genHapIndex("Core_Breakpoint_Memop", self.syscallHap, self.alt_syscall_info, proc_break1, 'syscall32'))
                    self.proc_hap.append(self.context_manager.genHapIndex("Core_Breakpoint_Memop", self.syscallHap, self.alt_syscall_info, proc_break2, 'syscall32'))
        
        else:
            ''' will stop within the kernel at the computed entry point '''
            if self.cpu.architecture == 'arm64':
                platform = self.top.getCompDict(self.cell_name, 'PLATFORM')
                if platform == 'armMixed':
                    self.setComputeBreaks(False, background, break_list, break_addrs, arm64_app=True)
                    self.setComputeBreaks(False, background, break_list, break_addrs, arm64_app=False)
                elif platform == 'arm64':
                    self.setComputeBreaks(False, background, break_list, break_addrs, arm64_app=True)
                else:
                    self.setComputeBreaks(False, background, break_list, break_addrs, arm64_app=False)
            else:
                self.setComputeBreaks(compat32, background, break_list, break_addrs)

        return break_list, break_addrs

    def setComputeBreaks(self, compat32, background, break_list, break_addrs, arm64_app=None):
        for call in self.call_list:
            callnum = self.task_utils.syscallNumber(call, compat32, arm64_app=arm64_app)
            #self.lgr.debug('SysCall setComputeBreaks call: %s  num: %d arm64_app %s' % (call, callnum, str(arm64_app)))
            if callnum is not None and callnum < 0:
                self.lgr.error('Syscall setComputeBreaks bad call number %d for call <%s>' % (callnum, call))
                return None, None
            entry = self.task_utils.getSyscallEntry(callnum, compat32, arm64_app=arm64_app)
            #phys = self.mem_utils.v2p(cpu, entry)
            #proc_break = self.context_manager.genBreakpoint(self.cpu.physical_memory, Sim_Break_Physical, Sim_Access_Execute, phys, 1, 0)
            if self.syscall_info is None:
                self.syscall_info = SyscallInfo(self.cpu, None, True, self.trace)
                self.syscall_info.compat32 = compat32
            has_entry = self.syscall_info.hasEntry(entry)
            self.syscall_info.addCall(callnum, entry, arm64_app)
            #self.lgr.debug('syscall computeBreaks to syscallInfo add callnum %d entry 0x%x arm64_app %r' % (callnum, entry, arm64_app))
            debug_tid, dumb = self.context_manager.getDebugTid() 
            if not background or debug_tid is not None and not has_entry:
                proc_break = self.context_manager.genBreakpoint(self.cell, Sim_Break_Linear, Sim_Access_Execute, entry, 1, 0)
                proc_break1 = None
                break_list.append(proc_break)
                break_addrs.append(entry)
                callname = call
                if self.cpu.architecture.startswith('arm') and not arm64_app:
                    callname = '%s-arm32' % call
                self.proc_hap.append(self.context_manager.genHapIndex("Core_Breakpoint_Memop", self.syscallHap, self.syscall_info, proc_break, callname))
                #self.lgr.debug('Syscall setComputeBreaks callnum %s name %s entry 0x%x compat32: %r call_params %s self.cell %s break 0x%x' % (callnum, call, entry, compat32, str(self.syscall_info), self.cell, proc_break))
            if background:
                dc = self.context_manager.getDefaultContext()
                self.background_break = SIM_breakpoint(dc, Sim_Break_Linear, Sim_Access_Execute, entry, 1, 0)
                self.background_hap = RES_hap_add_callback_index("Core_Breakpoint_Memop", self.syscallHap, None, self.background_break)
                self.lgr.debug('Syscall setComputeBreaks doBreaks set background breaks at 0x%x callnum %s break 0x%x' % (entry, callnum, self.background_break))
        
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
        self.sharedSyscall.rmExitBySyscallName(self.name, self.cell, immediate=True)
        #self.lgr.debug('stopTraceAlone done')


    def stopTrace(self, immediate=False):
        self.lgr.debug('syscall stopTrace syscall name %s call_list %s immediat: %r' % (self.name, str(self.call_list), immediate))
        proc_copy = list(self.proc_hap)
        for ph in proc_copy:
            #self.lgr.debug('syscall stopTrace, delete self.proc_hap %d' % ph)
            self.context_manager.genDeleteHap(ph, immediate=immediate)
            self.proc_hap.remove(ph)

        SIM_run_alone(self.stopTraceAlone, None)
        if self.top is not None and not self.top.remainingCallTraces(cell_name=self.cell_name):
            self.sharedSyscall.stopTrace()

        for tid in self.first_mmap_hap:
            #self.lgr.debug('syscall stopTrace, delete mmap hap tid %s' % tid)
            self.context_manager.genDeleteHap(self.first_mmap_hap[tid], immediate=immediate)
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
        self.lgr.debug('syscall stopTrace return for %s' % self.name)
       
    def watchFirstMmap(self, tid, fname, fd, compat32):
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
        cpu, comm, tid = self.task_utils.curThread() 
        if callname == 'openat':
            fd = resimSimicsUtils.fdString(frame['param1'])
            ida_msg = '%s flags: 0%o  mode: %s  fname_addr 0x%x filename: %s  dirfd: %s  tid:%s (%s)' % (callname, flags, 
                oct(mode), fname_addr, fname, fd, tid, comm)
        else:
            ida_msg = '%s flags: 0%o  mode: %s  fname_addr 0x%x filename: %s   tid:%s (%s)' % (callname, flags, oct(mode), fname_addr, fname, tid, comm)

        #self.lgr.debug('parseOpen set ida message to %s' % ida_msg)
        #self.lgr.debug('parseOpen params: taskUtils.stringFromFrame(frame))

        self.context_manager.setIdaMessage(ida_msg)
        #if fname is None:
        #    SIM_break_simulation('fname zip')
        return fname, fname_addr, flags, mode, ida_msg

    def fnamePhysAlone(self, pinfo):
        tid, fname_addr, exit_info = pinfo 
        #self.lgr.debug('fnamePhysAlone 0x%x' % fname_addr)
        self.finish_break[tid] = SIM_breakpoint(self.cpu.physical_memory, Sim_Break_Physical, Sim_Access_Write, fname_addr, 1, 0)
        self.finish_hap[tid] = RES_hap_add_callback_index("Core_Breakpoint_Memop", self.finishParseOpen, exit_info, self.finish_break[tid])

    def rmBreakAndHap(self, break_hap):
        break_num, hap = break_hap
        RES_delete_breakpoint(break_num)
        RES_hap_delete_callback_id("Core_Breakpoint_Memop", hap)

    def fnameTable (self, exit_info, third, forth, memory):
        ''' only used with 64-bit IA32E paging '''
        cpu, comm, tid = self.task_utils.curThread() 
        if tid not in self.finish_hap_table:
            return
        self.lgr.debug('fnameTable delete finish_break')
        break_num = self.finish_break[tid]
        hap = self.finish_hap_table[tid]
        SIM_run_alone(self.rmBreakAndHap, (break_num, hap))
        del self.finish_hap_table[tid]
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
        #self.lgr.debug('fnameTable tid %s would write value of 0x%x value_40 0x%x table_entry %d  break at page_base_addr 0x%x' % (tid, 
        #    value, value_40, table_entry, page_base_addr))

        self.finish_break[tid] = SIM_breakpoint(cpu.physical_memory, Sim_Break_Physical, Sim_Access_Write, page_base_addr, 1, 0)
        self.finish_hap_page[tid] = RES_hap_add_callback_index("Core_Breakpoint_Memop", self.fnamePage, exit_info, self.finish_break[tid])


    def fnamePage(self, exit_info, third, forth, memory):
        ''' only used with 64-bit IA32E paging '''
        cpu, comm, tid = self.task_utils.curThread() 
        if tid not in self.finish_hap_page:
            return
        self.lgr.debug('fnamePage delete finish_break')
        break_num = self.finish_break[tid]
        hap = self.finish_hap_page[tid]
        SIM_run_alone(self.rmBreakAndHap, (break_num, hap))

        del self.finish_hap_page[tid]

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
        self.lgr.debug('fnamePage tid %s would write value of 0x%x value_40 0x%x offset 0x%x  break at fname_addr 0x%x' % (tid, value, value_40, offset, fname_addr))
        got = self.mem_utils.readStringPhys(self.cpu, fname_addr, 256)
        if len(got) > 0:
            exit_info.fname = got
            self.lgr.debug('fnamePage read %s' % exit_info.fname)
        else:
            SIM_run_alone(self.fnamePhysAlone, (tid, fname_addr, exit_info))


    def finishParseOpen(self, exit_info, third, forth, memory):
        ''' in case the file name is in memory that was not mapped when open call was issued '''
        cpu, comm, tid = self.task_utils.curThread() 
        #self.lgr.debug('finishParseOpen tid %s' % tid)
        if cpu != exit_info.cpu or tid != exit_info.tid:
            return
        if tid not in self.finish_hap:
            return
        exit_info.fname = self.mem_utils.readString(self.cpu, exit_info.fname_addr, 256)
        if exit_info.fname is not None:
            #self.lgr.debug('finishParseOpen tid %s got fid %s' % (tid, exit_info.fname))

            break_num = self.finish_break[tid]
            hap = self.finish_hap[tid]
            SIM_run_alone(self.rmBreakAndHap, (break_num, hap))

            self.lgr.debug('finishParseOpen delete finish_break')
            del self.finish_hap[tid]
            del self.finish_break[tid]
        else:
            self.lgr.debug('finishParseOpen tid %s got fid none, arm fu?' % (tid))

    def addElf(self, prog_string, tid):
        self.lgr.debug('syscall addElf %s' % prog_string)
        if self.targetFS is not None and prog_string is not None:
            full_path = self.targetFS.getFull(prog_string, self.lgr)
            if full_path is None:
                #self.lgr.debug('Unable to get full path for %s' % prog_string)
                return
            if os.path.isfile(full_path):
                elf_info = None
                if self.soMap is not None:
                    load_info = self.soMap.addText(full_path, prog_string, tid)
                    
                ftype = magic.from_file(full_path)
                if self.traceProcs is not None:
                    self.traceProcs.setFileType(tid, ftype) 
            else:
                self.lgr.debug('addElf, no file at %s' % full_path)
                if self.soMap is not None:
                    self.soMap.noText(prog_string, tid)
      

    def finishParseExecve(self, call_info, third, forth, memory):
        cpu, comm, tid = self.task_utils.curThread() 
        if cpu != call_info.cpu or tid != call_info.tid:
            return
        if tid not in self.finish_hap:
            return
        prog_string, arg_string_list = self.task_utils.readExecParamStrings(call_info.tid, call_info.cpu)
        if cpu.architecture.startswith('arm') and prog_string is None:
            self.lgr.debug('finishParseExecve progstring None, arm fu?')
            return

        break_num = self.finish_break[tid]
        hap = self.finish_hap[tid]
        SIM_run_alone(self.rmBreakAndHap, (break_num, hap))

        self.lgr.debug('finishParseExec delete finish_break')
        del self.finish_hap[tid]
        del self.finish_break[tid]
        prog_comm = os.path.basename(prog_string)[:self.task_utils.commSize()]
        if prog_comm in self.ignore_progs:
            self.lgr.debug('finishParseExecve tid:%s skipping (%s)' % (tid, prog_string))
            return False
        self.lgr.debug('finishParseExecve tid:%s progstring (%s)' % (tid, prog_string))
        nargs = min(4, len(arg_string_list))
        arg_string = ''
        for i in range(nargs):
            if is_ascii(arg_string_list[i]):
                arg_string += arg_string_list[i]+' '
            else:
                break
        ida_msg = 'execve prog: %s %s  tid:%s (%s)  breakonexecve: %r' % (prog_string, arg_string, call_info.tid, comm, self.breakOnExecve())
        if self.traceMgr is not None:
            self.traceMgr.write(ida_msg+'\n')
        if self.traceProcs is not None:
            self.traceProcs.setName(call_info.tid, prog_string, arg_string)

        if self.name != 'traceAll' and self.top.trackingThreads():
            self.addElf(prog_string, tid)
        else:
            # Assume done by trackThreads
            pass

        if self.netInfo is not None:
            self.netInfo.checkNet(prog_string, arg_string)
        if len(arg_string_list) > 0:
            arg0 = arg_string_list[0]
        else:
            arg0 = None
        self.checkExecve(prog_string, arg_string, arg0, call_info.tid, comm)
        self.context_manager.newProg(prog_string, call_info.tid)


    def checkExecve(self, prog_string, arg_string, arg0, tid, comm):
        self.lgr.debug('checkExecve syscall %s  %s' % (self.name, prog_string))
        cp = None
        for call in self.call_params:
            #self.lgr.debug('checkExecve call %s' % call)
            if call.subcall == 'execve':
                cp = call
                break
        if cp is None:
            for call in self.call_params:
                self.lgr.debug('checkExecve traceall call %s' % call)
                if call.subcall == 'execve':
                    cp = call
                    break
            
        if cp is not None: 
            if cp.match_param.__class__.__name__ == 'Dmod':
               self.task_utils.modExecParam(tid, self.cpu, cp.match_param)
            elif cp.match_param is not None:

                if '/' in cp.match_param:
                    ''' compare full path '''
                    base = prog_string
                else:
                    base = os.path.basename(prog_string)
                #self.lgr.debug('checkExecve base %s against %s' % (base, cp.match_param))
                if base.startswith(cp.match_param):
                    self.lgr.debug('syscall checkExecve matches base')
                    wrong_type = False
                    missing_file = False
                    if self.traceProcs is not None and 'any_exec' not in cp.param_flags:
                        ftype = self.traceProcs.getFileType(tid)
                        if ftype is None:
                            full_path = self.targetFS.getFull(prog_string, self.lgr)
                            if full_path is not None and os.path.isfile(full_path):
                                ftype = magic.from_file(full_path)
                                if ftype is None:
                                    self.lgr.error('syscall checkExecve failed to find file type for %s tid:%s' % (prog_string, tid))
                                    return
                            else:
                                self.lgr.debug('syscall checkExecve failed to find file for %s, assume target will fail execve' % prog_string)
                                print('Warning, program file for %s not found relative to Root Prefix.' % prog_string)
                                missing_file = True
                        # is program file we are looking for.  do we care if it is a binary? 
                        if ftype is not None and 'binary' in cp.param_flags and 'elf' not in ftype.lower():
                            wrong_type = True
                    if not wrong_type and not missing_file:
                        self.recordExecve(prog_string, arg_string, tid, comm)
                        if not self.top.trackingThreads():
                            self.lgr.debug('checkExecve not tracking threads, remove the syscall param')
                            self.top.rmSyscall(cp.name)
                        self.lgr.debug('checkExecve execve of %s now stop alone ' % prog_string)
                        SIM_run_alone(self.stopAlone, 'execve of %s' % prog_string)
                    elif missing_file:
                        self.lgr.debug('syscall checkExecve missing file.  prog %s  param %s' % (prog_string, cp.match_param))
                        if prog_string == cp.match_param:
                            if not self.top.trackingThreads():
                                self.lgr.debug('checkExecve missing file not tracking threads, remove the syscall param')
                                self.top.rmSyscall(cp.name)
                            self.lgr.debug('checkExecve missing file execve of %s now stop alone ' % prog_string)
                            SIM_run_alone(self.stopAlone, 'execve of %s' % prog_string)
                        else:
                            print('Did not find a file relative to the Root Prefix, and the program string of %s does not match %s, maybe try an absolute path' % (prog_string, cp.match_param)) 
                    elif wrong_type:
                        self.lgr.debug('checkExecve, got %s when looking for binary %s, skip' % (ftype, prog_string))
                    else:
                        pass
                elif base == 'sh' and cp.match_param.startswith('sh '):
                    # TBD add bash, etc.
                    base = os.path.basename(arg0)
                    sw = cp.match_param.split()[1]
                    #self.lgr.debug('syscall execve compare %s to %s' % (base, sw))
                    if base.startswith(sw):
                        self.lgr.debug('checkExecve execve of %s %s' % (prog_string, sw))
                        SIM_run_alone(self.stopAlone, 'execve of %s %s' % (prog_string, sw))

    def parseExecve(self, syscall_info):
        retval = True
        cpu, comm, tid = self.task_utils.curThread() 
        ''' allows us to ignore internal kernel syscalls such as close socket on exec '''
        at_enter = True
        if syscall_info.calculated:
            at_enter = False
        prog_string, arg_string_list = self.task_utils.getProcArgsFromStack(tid, at_enter, cpu)
        self.lgr.debug('parseExecve prog_string <%s>' % prog_string)
        if prog_string is not None:
            prog_comm = os.path.basename(prog_string)[:self.task_utils.commSize()]
            if prog_string is not None and prog_comm in self.ignore_progs:
                return False
        #self.lgr.debug('parseExecve len of arg_string_list %d' % len(arg_string_list))
          
        tid_list = self.context_manager.getThreadTids()
        db_tid, dumbcpu = self.context_manager.getDebugTid()
        if db_tid is not None:
            self.lgr.debug('parseExecve db_tid:%s tid_list: %s' % (db_tid, str(tid_list)))
        
        if tid in tid_list and tid != db_tid and not self.top.watchingExitTid(tid):
            self.lgr.debug('syscall parseExecve remove %s from list being watched.' % (tid))
            #self.context_manager.rmTask(tid)
            self.context_manager.stopWatchTid(tid)
        
        if prog_string is None:
            ''' prog string not in ram, break on kernel read of the address and then read it '''
            prog_addr = self.task_utils.getExecProgAddr(tid, cpu)
            if prog_addr is None:
                self.lgr.debug('parseExecve tid:%s prog_addr is None, bail' % tid) 
                return False
            call_info = SyscallInfo(cpu, tid, False, None)
            self.lgr.debug('parseExecve tid:%s prog string missing, set break on 0x%x' % (tid, prog_addr))
            if prog_addr == 0:
                self.lgr.error('parseExecve zero prog_addr tid:%s' % tid)
                SIM_break_simulation('parseExecve zero prog_addr tid:%s' % tid)
            if tid in tid_list and tid != db_tid:
                context = self.context_manager.getDefaultContext()
            else:
                context = cpu.current_context
            self.finish_break[tid] = SIM_breakpoint(context, Sim_Break_Linear, Sim_Access_Read, prog_addr, 1, 0)
            self.finish_hap[tid] = RES_hap_add_callback_index("Core_Breakpoint_Memop", self.finishParseExecve, call_info, self.finish_break[tid])
            return False
        nargs = min(4, len(arg_string_list))
        arg_string = ''
        for i in range(nargs):
            if is_ascii(arg_string_list[i]):
                arg_string += arg_string_list[i]+' '
            else:
                break
        self.recordExecve(prog_string, arg_string, tid, comm)
        if len(arg_string_list) > 0:
            arg0 = arg_string_list[0]
        else:
            arg0 = None
        self.checkExecve(prog_string, arg_string, arg0, tid, comm)

        return retval

    def recordExecve(self, prog_string, arg_string, tid, comm):
        ida_msg = 'execve prog: %s %s  tid:%s (%s)' % (prog_string, arg_string, tid, comm)
        self.context_manager.newProg(prog_string, tid)
        self.lgr.debug(ida_msg)
        if self.traceMgr is not None:
            self.traceMgr.write(ida_msg+'\n')
        if self.traceProcs is not None:
            self.traceProcs.setName(tid, prog_string, arg_string)

        if self.top.trackingThreads():
            self.lgr.debug('recordExecve tracking threads, record new program info.')
            self.addElf(prog_string, tid)
            if self.netInfo is not None:
                self.netInfo.checkNet(prog_string, arg_string)

    def getSockParams(self, frame, syscall_info):
        domain = None
        sock_type = None
        protocol = None
        if self.cpu.architecture.startswith('arm'):
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
        #self.lgr.debug('syscall getSockParams returning %s' % sock_params.getString())
        return sock_params

    def bindFDToSocket(self, tid, fd):
        if tid in self.tid_sockets:
            if tid not in self.tid_fd_sockets:
                self.tid_fd_sockets[tid] = {}
            self.tid_fd_sockets[tid][fd] = self.tid_sockets[tid]
            del self.tid_sockets[tid]

    def socketParse(self, callname, syscall_info, frame, exit_info, tid):
        ss = None
        comm = None
        if tid in self.comm_cache:
            comm = self.comm_cache[tid]
        ida_msg = None
        if callname == 'socketcall':        
            ''' must be 32-bit get params from struct '''
            socket_callnum = frame['param1']
            if socket_callnum < len(net.callname):
                socket_callname = net.callname[socket_callnum].lower()
            else:
                self.lgr.error('syscall socketParse call_num %s not found' % socket_callnum)
                return
            self.lgr.debug('syscall socketParse is socketcall call %s from %s' % (socket_callname, tid))
            if socket_callname == 'socket':
                self.tid_sockets[tid] = self.getSockParams(frame, syscall_info)
 
            ''' Is the call intended for this syscall instance? '''
            got_good = False 
            got_bad = False 
            if self.name != 'traceAll' and socket_callname != 'socket':
                for call_param in self.call_params:
                    if call_param is not None and call_param.subcall is not None:
                        self.lgr.debug('syscall socketParse subcall in call_param of %s' % call_param.subcall)
                        if call_param.subcall.lower() == socket_callname.lower():
                            got_good = True
                        else:
                            got_bad = True
                if got_bad and not got_good:
                    self.lgr.debug('syscall socketParse tid:%s socketcall %s not in list, skip it' % (tid, socket_callname))
                    return None

            if self.record_fd and socket_callname not in record_fd_list:
                self.lgr.debug('syscall socketParse %s not in list, skip it' % socket_callname)
                return None
            #self.lgr.debug('socketParse tid:%s socket_callnum is %d name: %s record_fd: %r' % (tid, socket_callnum, socket_callname, self.record_fd))
            #if syscall_info.compat32:
            #    SIM_break_simulation('socketcall')
            exit_info.socket_callname = socket_callname
            if socket_callname != 'socket':
                # Overloaded structure being used for parsing 32 bit sockcall
                ss = net.SockStruct(self.cpu, frame['param2'], self.mem_utils, lgr=self.lgr)
                if tid in self.tid_fd_sockets and ss.fd is not None and ss.fd in self.tid_fd_sockets[tid]:
                    ss.addParams(self.tid_fd_sockets[tid][ss.fd])
                exit_info.old_fd = ss.fd
                if socket_callname.startswith('rec') or socket_callname.startswith('send'): 
                    exit_info.count = ss.length
                    exit_info.retval_addr = ss.addr
                    exit_info.old_fd = ss.fd
                    self.lgr.debug('syscall socketParse socketcall rec/send count %d FD: %d' % (exit_info.count, exit_info.old_fd))
                elif socket_callname.startswith('accept'):
                    exit_info.retval_addr = ss.addr
                    exit_info.count_addr = ss.length
                #self.lgr.debug('syscall socketParse socket_callname %s got SockStruct from param2: 0x%x %s' % (socket_callname, frame['param2'], ss.getString()))
        else:
            # Not socketcall
            socket_callname = callname
            exit_info.old_fd = frame['param1']
            self.lgr.debug('syscall socketParse call %s param1 0x%x param2 0x%x' % (callname, frame['param1'], frame['param2']))
            if callname == 'socket':
                self.tid_sockets[tid] = self.getSockParams(frame, syscall_info)
            elif callname in ['bind', 'connect', 'getsockname']:
                self.lgr.debug('socketParse param1: 0x%x param2: 0x%x' % (frame['param1'], frame['param2']))
                ss = net.SockStruct(self.cpu, frame['param2'], self.mem_utils, fd=frame['param1'], lgr=self.lgr)
                if tid in self.tid_fd_sockets and ss.fd is not None and ss.fd in self.tid_fd_sockets[tid]:
                    ss.addParams(self.tid_fd_sockets[tid][ss.fd])
                self.lgr.debug('socketParse ss %s  param2: 0x%x' % (ss.getString(), frame['param1']))
            elif callname.startswith('rec') or callname.startswith('send'):
                exit_info.count = frame['param3']
                exit_info.retval_addr = frame['param2']
            elif callname.startswith('accept'):
                exit_info.retval_addr = frame['param2']
                exit_info.count_addr = frame['param3']
            else:
                pass
        ''' NOTE returns above '''
        exit_info.sock_struct = ss

        if socket_callname == 'socket':
            self.lgr.debug('syscall socketParse is socket')
            if self.cpu.architecture.startswith('arm'):
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
                ida_msg = '%s - %s tid:%s (%s) input values not mapped???? ' % (callname, socket_callname, tid, comm)
            else:
                sock_type = sock_type_full & net.SOCK_TYPE_MASK
                try:
                    type_string = net.socktype[sock_type]
                    ida_msg = '%s - %s tid:%s (%s) domain: 0x%x type: %s protocol: 0x%x' % (callname, socket_callname, tid, comm, domain, type_string, protocol)
                    #self.lgr.debug(ida_msg)
                except:
                    self.lgr.debug('syscall doSocket could not get type string from type 0x%x full 0x%x' % (sock_type, sock_type_full))
                    ida_msg = '%s - %s tid:%s (%s) domain: 0x%x type: %d protocol: 0x%x' % (callname, socket_callname, tid, comm, domain, sock_type, protocol)
        elif socket_callname == 'connect':
            ida_msg = '%s - %s tid:%s (%s) %s %s  param at: 0x%x' % (callname, socket_callname, tid, comm, ss.getString(), ss.addressInfo(), frame['param2'])
            for call_param in self.call_params:
                self.lgr.debug('check for match subcall %s' % call_param.subcall)
                if call_param.subcall == 'connect' and (call_param.proc is None or call_param.proc == self.comm_cache[tid]):
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
                                     addParam(exit_info, call_param)
                                     if go:
                                         ida_msg = 'connect to %s, FD: %d count: %d' % (s, ss.fd, call_param.count)
                                     else:
                                         ida_msg = 'connect to %s, FD: %d count: %d' % (call_param.match_param, ss.fd, call_param.count)
                                     self.context_manager.setIdaMessage(ida_msg)
                             else:
                                 addParam(exit_info, call_param)
                                 if go:
                                     ida_msg = 'connect to %s, FD: %d' % (s, ss.fd)
                                 else:
                                     ida_msg = 'connect to %s, FD: %d' % (call_param.match_param, ss.fd)
                                 self.context_manager.setIdaMessage(ida_msg)
                     elif EXTERNAL in call_param.param_flags and ss.isExternal():
                         self.lgr.debug('socketParse external in flags and is external')
                         addParam(exit_info, call_param)
              
        elif socket_callname == 'bind':
            ida_msg = '%s - %s tid:%s (%s) socket_string: %s' % (callname, socket_callname, tid, comm, ss.getString())
            self.lgr.debug(ida_msg)
            #if ss.famName() == 'AF_CAN':
            #    frame_string = taskUtils.stringFromFrame(frame)
            #    self.lgr.debug('bind params %s' % frame_string)
            #    SIM_break_simulation('bind')
            
            for call_param in self.call_params:
                self.lgr.debug('socketParse bind subcall %s' % call_param.subcall)
                if call_param.subcall is not None and call_param.subcall.lower() == 'bind' and (call_param.proc is None or call_param.proc == self.comm_cache[tid]):
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
                         
                             self.lgr.debug('socketParse look for match %s %s' % (pat, s))
                         else:
                             self.lgr.debug('socketParse bind ss.port is None')
                         if len(call_param.match_param.strip()) == 0 or go or call_param.match_param == ss.sa_data: 
                             self.lgr.debug('socketParse found match %s' % (call_param.match_param))
                             addParam(exit_info, call_param)
                             if go:
                                 ida_msg = 'BIND to %s, FD: %d' % (s, ss.fd)
                             else:
                                 ida_msg = 'BIND to %s, FD: %d' % (call_param.match_param, ss.fd)
                             self.context_manager.setIdaMessage(ida_msg)

                     if AF_INET in call_param.param_flags and ss.sa_family == net.AF_INET:
                         addParam(exit_info, call_param)
                         self.sockwatch.bind(tid, ss.fd, call_param)

        elif socket_callname == 'getpeername':
            ida_msg = '%s - %s tid:%s (%s) FD: %d' % (callname, socket_callname, tid, comm, exit_info.old_fd)
            for call_param in self.call_params:
                if (call_param.subcall is None or call_param.subcall == 'getpeername') and type(call_param.match_param) is int and call_param.match_param == exit_info.old_fd:
                #if call_param.subcall == 'GETPEERNAME' and call_param.match_param == ss.fd:
                    addParam(exit_info, call_param)

        elif socket_callname == 'accept' or socket_callname == 'accept4':
            if exit_info.retval_addr is not None and exit_info.retval_addr != 0:
                phys = self.mem_utils.v2p(self.cpu, exit_info.retval_addr)
                #ida_msg = '%s - %s tid:%s (%s) FD: %d addr:0x%x len_addr:0x%x  phys_addr:0x%x' % (callname, socket_callname, tid, comm, exit_info.old_fd, 
                #       exit_info.retval_addr, exit_info.count, phys)
                ida_msg = '%s - %s tid:%s (%s) FD: %d addr:0x%x len_addr:0x%x  phys_addr:0x%x' % (callname, socket_callname, tid, comm, exit_info.old_fd, 
                       exit_info.retval_addr, exit_info.count_addr, phys)
            elif exit_info.old_fd is not None:
                ida_msg = '%s - %s tid:%s (%s) FD: %d' % (callname, socket_callname, tid, comm, exit_info.old_fd)
            else:
                ida_msg = '%s - %s tid:%s (%s) FD is None?' % (callname, socket_callname, tid, comm)
                self.lgr.debug('syscall acccept with ss.fd of none?')
             
            if exit_info.old_fd is not None:
                for call_param in self.call_params:
                    self.lgr.debug('syscall accept subcall %s call_param.match_param is %s fd is %d' % (call_param.subcall, str(call_param.match_param), exit_info.old_fd))
                    if type(call_param.match_param) is int:
                        if (call_param.subcall == 'accept' or self.name=='runToIO') and (call_param.match_param < 0 or call_param.match_param == exit_info.old_fd):
                            self.lgr.debug('did accept match')
                            addParam(exit_info, call_param)

        elif socket_callname == 'getsockname':
            ida_msg = '%s - %s tid:%s (%s) FD: %d' % (callname, socket_callname, tid, comm, exit_info.old_fd)
            for call_param in self.call_params:
                if call_param.subcall == 'getsockname' and call_param.match_param == exit_info.old_fd:
                    addParam(exit_info, call_param)

        elif socket_callname == "recv" or socket_callname == "recvfrom":
            sock_param = self.sockwatch.getParam(tid, exit_info.old_fd)
            if sock_param is not None:
                exit_info.call_params.append(sock_param)
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
                source_ss = net.SockStruct(self.cpu, src_addr, self.mem_utils, fd=-1, lgr=self.lgr)
                if source_ss.sa_family is not None:
                    exit_info.src_addr = src_addr
                    exit_info.src_addr_len = src_addr_len
                ida_msg = '%s - %s tid:%s (%s) FD: %d len: %d' % (callname, socket_callname, tid, comm, exit_info.old_fd, exit_info.count)
                #if source_ss.famName() == 'AF_CAN':
                #    frame_string = taskUtils.stringFromFrame(frame)
                #    print(frame_string)
                #    SIM_break_simulation(ida_msg)
            elif exit_info.old_fd is None:
                self.lgr.error('sock fd none') 
            elif tid is None:
                self.lgr.error('tid is none') 
            else:
                ida_msg = '%s - %s tid:%s (%s) FD: %d len: %d' % (callname, socket_callname, tid, comm, exit_info.old_fd, exit_info.count)
            for call_param in self.call_params:
                self.lgr.debug('syscall parse tid:%s socket rec... param: %s subcall is %s exit_info.old_fd is %s match_param is %s' % (tid, call_param.name, call_param.subcall, str(exit_info.old_fd), str(call_param.match_param)))
                if call_param.name == 'runToReceive':
                    exit_info.call_params.append(call_param)
                elif (call_param.subcall is None or call_param.subcall == 'recv' or call_param.subcall == 'recvfrom') and type(call_param.match_param) is int and call_param.match_param == exit_info.old_fd and (call_param.proc is None or call_param.proc == self.comm_cache[tid]):

                    if call_param.nth is not None and self.kbuffer is not None and (call_param.count+1) >= call_param.nth:
                        self.lgr.debug('syscall read kbuffer for addr 0x%x' % exit_info.retval_addr)
                        self.kbuffer.read(exit_info.retval_addr, exit_info.count, exit_info.old_fd)
                    else:
                        if self.kbuffer is not None:
                            self.lgr.debug('syscall read kbuffer for addr 0x%x' % exit_info.retval_addr)
                            self.kbuffer.read(exit_info.retval_addr, exit_info.count, exit_info.old_fd)
                    addParam(exit_info, call_param)

                    # keep kernel from triggering data watch mods if just reading more data into buffer
                    # TBD apply this whereever we enter that might modify buffers
                    self.top.stopDataWatch(leave_backstop=True)
        elif socket_callname == "recvmsg": 
            #frame_string = taskUtils.stringFromFrame(frame)
            #self.lgr.debug('recvmsg frame %s' % frame_string)
            if self.cpu.architecture.startswith('arm'):
                exit_info.old_fd = frame['param1']
                msg_hdr_ptr = frame['param2']
                msghdr = net.Msghdr(self.cpu, self.mem_utils, msg_hdr_ptr, self.lgr)
                ida_msg = '%s - %s tid:%s (%s) FD: %d msghdr: 0x%x %s' % (callname, socket_callname, tid, comm, exit_info.old_fd, msg_hdr_ptr, msghdr.getString())
                self.lgr.debug(ida_msg) 
            elif self.mem_utils.WORD_SIZE==8 and not syscall_info.compat32:
                exit_info.old_fd = frame['param1']
                exit_info.retval_addr = frame['param2']
                msghdr = net.Msghdr(self.cpu, self.mem_utils, frame['param2'], self.lgr)
                ida_msg = '%s - %s tid:%s (%s) FD: %d msghdr: 0x%x %s' % (callname, socket_callname, tid, comm, exit_info.old_fd, frame['param2'], msghdr.getString())
 
            else:
                ''' TBD is this right for x86 32?'''
                params = frame['param2']
                exit_info.old_fd = self.mem_utils.readWord32(self.cpu, params)
                msg_hdr_ptr = self.mem_utils.readWord32(self.cpu, params+4)
                exit_info.retval_addr = msg_hdr_ptr
                msghdr = net.Msghdr(self.cpu, self.mem_utils, msg_hdr_ptr, self.lgr)
                ida_msg = '%s - %s tid:%s (%s) FD: %d msghdr: 0x%x %s' % (callname, socket_callname, tid, comm, exit_info.old_fd, msg_hdr_ptr, msghdr.getString())
            exit_info.msghdr = msghdr
            sock_param = self.sockwatch.getParam(tid, exit_info.old_fd)
            if sock_param is not None:
                exit_info.call_params.append(sock_param)

            for call_param in self.call_params:
                # TBD does not handle kbuffer as done in read/recv
                self.lgr.debug('syscall %s FD: %d call_params %s' % (callname, exit_info.old_fd, call_param.toString()))
                if (call_param.subcall is None or call_param.subcall == 'recvmsg') and type(call_param.match_param) is int and call_param.match_param == exit_info.old_fd and (call_param.proc is None or call_param.proc == self.comm_cache[tid]):
                    self.lgr.debug('syscall %s watch exit for FD call_param %s' % (socket_callname, call_param.match_param))
                    addParam(exit_info, call_param)
                elif type(call_param.match_param) is str and (call_param.subcall is None or call_param.subcall == 'recvmsg') and (call_param.proc is None or call_param.proc == self.comm_cache[tid]):
                    #self.lgr.debug('syscall %s watch exit for call_param %s' % (socket_callname, call_param.match_param))
                    addParam(exit_info, call_param)
            
        elif socket_callname == "sendmsg":
            # TBD Not complete
            if self.cpu.architecture.startswith('arm'):
                exit_info.old_fd = frame['param1']
                msg_hdr_ptr = frame['param2']
                msghdr = net.Msghdr(self.cpu, self.mem_utils, msg_hdr_ptr, self.lgr)
                exit_info.msghdr = msghdr
                ida_msg = '%s - %s tid:%s (%s) FD: %d msghdr: 0x%x %s' % (callname, socket_callname, tid, comm, exit_info.old_fd, msg_hdr_ptr, msghdr.getString())
                self.lgr.debug(ida_msg) 
                #SIM_break_simulation('sendmsg')
            else:
                self.lgr.error('syscall sendmsg not yet built for x86!')
                return
                ida_msg = '%s - %s tid:%s (%s) buf: 0x%x FD: %d' % (callname, socket_callname, tid, comm, exit_info.retval_addr, exit_info.old_fd)
            self.checkSendParams(syscall_info, exit_info, None, None, None)

        elif socket_callname == "send" or socket_callname == "sendto":
            # there are 2 sockets, the ss is our socket, with the buffer and the addr.  dest_ss has the destination IP/Port, etc.
            sock_param = self.sockwatch.getParam(tid, exit_info.old_fd)
            if sock_param is not None:
                exit_info.call_params.append(sock_param)
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
                dest_ss = net.SockStruct(self.cpu, dest_addr, self.mem_utils, fd=-1, lgr=self.lgr)
                #frame_string = taskUtils.stringFromFrame(frame)
                #print(frame_string)
                ida_msg = '%s - %s tid:%s (%s) buf: 0x%x FD: %d dest: %s' % (callname, socket_callname, tid, comm, exit_info.retval_addr, exit_info.old_fd, dest_ss.getString())
                #self.lgr.debug(ida_msg)
                #if dest_ss.famName() == 'AF_CAN':
                #    frame_string = taskUtils.stringFromFrame(frame)
                #    print(frame_string)
                #    SIM_break_simulation(ida_msg)
            else:
                ida_msg = '%s - %s tid:%s (%s) buf: 0x%x FD: %d' % (callname, socket_callname, tid, comm, exit_info.retval_addr, exit_info.old_fd)



            max_len = max(exit_info.count, 300)
            byte_tuple = self.mem_utils.getBytes(self.cpu, max_len, exit_info.retval_addr)
            s = None
            if byte_tuple is not None:
                s = resimUtils.getHexDump(byte_tuple[:max_len])
            self.checkSendParams(syscall_info, exit_info, ss, dest_ss, s)

        elif socket_callname == 'listen':
            sock_param = self.sockwatch.getParam(tid, exit_info.old_fd)
            if sock_param is not None:
                exit_info.call_params.append(sock_param)
            ida_msg = '%s - %s tid:%s (%s) FD: %d' % (callname, socket_callname, tid, comm, exit_info.old_fd)
                
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
                thebytes =  self.mem_utils.getBytesHex(self.cpu, rcount, optval)
                if thebytes is not None:
                    optval_val = 'option: %s' % str(thebytes)
                else:
                    optval_val = 'option: page not mapped'
            ida_msg = '%s - %s tid:%s (%s) FD: %d level: %d  optname: %d optval: 0x%x  oplen %d  %s' % (callname, 
                 socket_callname, tid, comm, self.fd, level, optname, optval, optlen, optval_val)
        elif socket_callname == 'socketpair':
            if callname == 'socketcall':
                exit_info.retval_addr = self.mem_utils.readWord32(self.cpu, frame['param4'])
            else:
                exit_info.retval_addr = frame['param4']
            ida_msg = '%s - %s %s tid:%s (%s) ' % (callname, socket_callname, taskUtils.stringFromFrame(frame), tid, comm)
            
        else:
            ida_msg = '%s - %s %s   tid:%s (%s)' % (callname, socket_callname, taskUtils.stringFromFrame(frame), tid, comm)

        return ida_msg

    def syscallParse(self, callnum, callname, frame, cpu, tid, comm, syscall_info, quiet=False):
        '''
        Parse a system call using many if blocks.  Note that setting exit_info to None prevent the return from the
        syscall from being observed (which is useful if this turns out to be not the exact syscall you were looking for.
        '''
        exit_info = ExitInfo(self, cpu, tid, callnum, callname, syscall_info.compat32, frame)
        exit_info.syscall_entry = self.mem_utils.getRegValue(self.cpu, 'pc')
        ida_msg = None
        #self.lgr.debug('syscallParse syscall name: %s tid:%s (%s) callname <%s> (%d) params: %s context: %s cycle: 0x%x' % (self.name, tid, comm, callname, callnum, str(self.call_params), 
        #    str(self.cpu.current_context), self.cpu.cycles))

        do_stop_from_call = False
        # Optimization to see if call parameters exclude this sytem call
        # some exit_info params will be set in per-call blocks
        if self.name not in ['traceAll', 'traceWindows', 'traceProcs']:
            got_one = False
            bail_if_not_got = False
            for call_param in self.call_params:
                #self.lgr.debug('syscallParse call_param.name: %s' % call_param.name)
                if call_param.match_param.__class__.__name__ == 'TidFilter':
                    if tid != call_param.match_param.tid:
                        #self.lgr.debug('syscall syscallParse, tid filter did not match')
                        bail_if_not_got = True
                    else:
                        exit_info.call_params.append(call_param)
                        self.lgr.debug('syscall syscallParse %s, tid filter matched, added call_param' % callname)
                        got_one = True
                elif call_param.match_param.__class__.__name__ == 'Dmod' and len(self.call_params) == 1:
                    if call_param.match_param.comm is not None and call_param.match_param.comm != comm:
                        #self.lgr.debug('syscall syscallParse, Dmod %s does not match comm %s, return' % (call_param.match_param.comm, comm))
                        #self.lgr.debug('syscall syscallParse, Dmod does not match comm %s, return' % (comm))
                        bail_if_not_got = True
                    elif call_param.match_param is not None:
                        self.lgr.debug('syscall syscallParse, Dmod %s match comm %s' % (call_param.match_param.comm, comm))
                        got_one = True
                      
                elif call_param.name == 'runToCall':
                    if callname not in self.call_list:
                        self.lgr.debug('syscall syscallParse, runToCall %s not in call list' % callname)
                        bail_if_not_got = True
                    else:
                        if self.stop_on_call:
                            do_stop_from_call = True
                        exit_info.call_params.append(call_param)
                        self.lgr.debug('syscall syscallParse %s, runToCall, no filter, matched, added call_param' % callname)
                        got_one = True
                        # default this to the matched param in case call that is not otherwised parsed in sharedSyscall
                        exit_info.matched_param = call_param
            if bail_if_not_got and not got_one:
                return
                 
        ''' NOTE returns above '''
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
                    self.lgr.debug('syscallParse, open tid:%s filename not yet here... set break at 0x%x ' % (tid, exit_info.fname_addr))
                    self.finish_break[tid] = SIM_breakpoint(cpu.current_context, Sim_Break_Linear, Sim_Access_Read, exit_info.fname_addr, 1, 0)
                    self.finish_hap[tid] = RES_hap_add_callback_index("Core_Breakpoint_Memop", self.finishParseOpen, exit_info, self.finish_break[tid])
                else:
                    if pageUtils.isIA32E(cpu):
                        ptable_info = pageUtils.findPageTableIA32E(cpu, exit_info.fname_addr, self.lgr)
                        if not ptable_info.ptable_exists:
                            self.lgr.debug('syscallParse, open tid:%s filename not yet here... set ptable break at 0x%x ' % (tid, ptable_info.ptable_addr))
                            self.finish_break[tid] = SIM_breakpoint(cpu.physical_memory, Sim_Break_Physical, Sim_Access_Write, ptable_info.ptable_addr, 1, 0)
                            self.finish_hap_table[tid] = RES_hap_add_callback_index("Core_Breakpoint_Memop", self.fnameTable, exit_info, self.finish_break[tid])
                        elif not ptable_info.page_exists:
                            self.lgr.debug('syscallParse, open tid:%s filename not yet here... set page break at 0x%x ' % (tid, ptable_info.page_base_addr))
                            self.finish_break[tid] = SIM_breakpoint(cpu.physical_memory, Sim_Break_Physical, Sim_Access_Write, ptable_info.page_base_addr, 1, 0)
                            self.finish_hap_page[tid] = RES_hap_add_callback_index("Core_Breakpoint_Memop", self.fnamePage, exit_info, self.finish_break[tid])
                        
                #SIM_break_simulation('fname is none...')
            elif exit_info.fname is not None:
                #self.lgr.debug('syscallParse got fname %s ida_msg is %s' % (exit_info.fname, ida_msg))
                for call_param in self.call_params:
                    #self.lgr.debug('got param name %s type %s subcall %s' % (call_param.name, type(call_param.match_param), call_param.subcall))
                    if call_param.match_param.__class__.__name__ == 'Dmod':
                         mod = call_param.match_param
                         #self.lgr.debug('is dmod, mod.getMatch is %s' % mod.getMatch())
                         #if mod.fname_addr is None:
                         if mod.getMatch() == exit_info.fname:
                             self.lgr.debug('syscallParse, dmod match on fname %s, cell %s' % (exit_info.fname, self.cell_name))
                             exit_info.call_params.append(call_param)
                    elif type(call_param.match_param) is str and (call_param.subcall is None or call_param.subcall.startswith('open') and (call_param.proc is None or call_param.proc == self.comm_cache[tid])):
                        if exit_info.fname is None:
                            self.lgr.debug('syscall open, found potential match_param %s' % call_param.match_param)
                        else:
                            self.lgr.debug('syscall open, file is %s' % exit_info.fname)
                        if exit_info.fname is None or call_param.match_param in exit_info.fname:
                            self.lgr.debug('syscall open, found actual match_param %s' % call_param.match_param)
                            exit_info.call_params.append(call_param)
                        
                        break
                    elif self.name == 'runToText':
                        # TBD what SO libs loaded after we hit text?
                        self.lgr.debug('syscall open, is runToText, set param')
                        exit_info.call_params.append(call_param)
            elif exit_info.fname is not None:
                self.lgr.debug('syscallParse did not get fname')
                         

        elif callname == 'mkdir':        
            exit_info.fname, exit_info.fname_addr, exit_info.flags, exit_info.mode, ida_msg = self.parseOpen(frame, callname)
            if exit_info.fname is None and not quiet:
                ''' filename not yet present in ram, do the two step '''
                ''' TBD think we are triggering off kernel's own read of the fname, then again sometime it seems corrupted...'''
                ''' Do not use context manager on superstition that filename could be read in some other task context.'''
                self.lgr.debug('syscallParse, mkdir tid:%s filename not yet here... set break at 0x%x ' % (tid, exit_info.fname_addr))
                self.finish_break[tid] = SIM_breakpoint(cpu.current_context, Sim_Break_Linear, Sim_Access_Read, exit_info.fname_addr, 1, 0)
                self.finish_hap[tid] = RES_hap_add_callback_index("Core_Breakpoint_Memop", self.finishParseOpen, exit_info, self.finish_break[tid])

        elif callname == 'creat':        
            exit_info.fname, exit_info.fname_addr, exit_info.flags, exit_info.mode, ida_msg = self.parseOpen(frame, callname)
            if exit_info.fname is None and not quiet:
                ''' filename not yet present in ram, do the two step '''
                self.lgr.debug('syscallParse, creat tid:%s filename not yet here... set break at 0x%x ' % (tid, exit_info.fname_addr))
                self.finish_break[tid] = SIM_breakpoint(cpu.current_context, Sim_Break_Linear, Sim_Access_Read, exit_info.fname_addr, 1, 0)
                self.finish_hap[tid] = RES_hap_add_callback_index("Core_Breakpoint_Memop", self.finishParseOpen, exit_info, self.finish_break[tid])

        elif callname == 'execve':        
            retval = self.parseExecve(syscall_info)
            ''' TBD why not set exit hap even though we don't yet have the params?'''
            if not retval:
                exit_info = None
        elif callname == 'close':        
            fd = frame['param1']
            if self.traceProcs is not None:
                #self.lgr.debug('syscallparse for close tid:%s' % tid)
                self.traceProcs.close(tid, fd)
            exit_info.old_fd = fd
       
            sock_param = self.sockwatch.getParam(tid, fd)
            if sock_param is not None:
                exit_info.call_params.append(sock_param)
            self.sockwatch.close(tid, fd)

            for call_param in self.call_params:
                self.lgr.debug('syscall close FD: %d call_param match_param %s call_param.proc %s' % (fd, str(call_param.match_param), str(call_param.proc)))
                if call_param.match_param == frame['param1'] and (call_param.proc is None or call_param.proc == self.comm_cache[tid]):
                    ida_msg = 'Closed FD %d' % fd
                    self.lgr.debug(ida_msg)
                    exit_info.call_params.append(call_param)
                    if not self.linger or self.name=='runToIO':
                        if self.clone_fd_count <= 1:
                            self.lgr.debug('closed fd %d, stop trace' % fd)
                            self.stopTrace()
                        else:
                            self.lgr.debug('closed fd %d, but clone_fd_count not yet 1 %d' % (fd, self.clone_fd_count))
                            self.clone_fd_count -= 1
                elif call_param.match_param.__class__.__name__ == 'Dmod' and call_param.match_param.tid == tid and exit_info.old_fd == call_param.match_param.fd:
                    self.lgr.debug('sysall close Dmod, tid and fd match')
                    exit_info.call_params.append(call_param)
                

        elif callname == 'dup':        
            exit_info.old_fd = frame['param1']
            ida_msg = '%s tid:%s (%s) fid:%d' % (callname, tid, comm, frame['param1'])
        elif callname in ['dup2', 'dup3']:        
            exit_info.old_fd = frame['param1']
            exit_info.new_fd = frame['param2']
            ida_msg = '%s tid:%s (%s) fid:%d newfid:%d' % (callname, comm, tid, frame['param1'], frame['param2'])
            for call_param in self.call_params:
                self.lgr.debug('syscall dup call_param match_param %s' % str(call_param.match_param))
                if call_param.match_param == frame['param1'] and (call_param.proc is None or call_param.proc == self.comm_cache[tid]):
                    # assume intent is to change fd, but not from 0
                    if call_param.match_param != 0:
                        call_param.match_param = exit_info.new_fd
                        self.lgr.debug('syscall dup Changed match param to new fd of %d' % exit_info.new_fd)
        elif callname == 'clone':        

            flags = frame['param1']
            child_stack = frame['param2']
            exit_info.fname_addr = child_stack
            ida_msg = '%s tid:%s (%s) flags:0x%x child_stack: 0x%x ptid: 0x%x ctid: 0x%x iregs: 0x%x' % (callname, tid, comm, flags, 
                child_stack, frame['param3'], frame['param4'], frame['param5'])

            #./include/linux/sched.h:#define CLONE_FILES	0x00000400	/* set if open files shared between processes */
            if not flags & 0x00000400 and self.name == 'runToIO':
                self.lgr.debug('syscall clone FD not shared, increment FD count for clones')
                self.clone_fd_count += 1
              
            self.context_manager.setIdaMessage(ida_msg)
            for call_param in self.call_params:
                if call_param.name != 'runToClone':
                    continue
                if call_param.nth is not None:
                    call_param.count = call_param.count + 1
                    self.lgr.debug('syscall clone call_param.count %s call_param.nth %s' % (str(call_param.count), str(call_param.nth)))
                    ''' negative nth means stop in parent '''
                    if call_param.count >= abs(call_param.nth):
                        addParam(exit_info, call_param)
                        self.lgr.debug('syscall clone added call_param')
            #self.traceProcs.close(tid, fd)
        elif callname == 'pipe' or callname == 'pipe2':        
            exit_info.retval_addr = frame['param1']
            

        elif callname == 'ipc':        
            call = frame['param1']
            callname = ipc.call[call]
            exit_info.socket_callname = callname
            if call == ipc.MSGGET or call == ipc.SHMGET:
                key = frame['param2']
                exit_info.fname = key
                ida_msg = 'ipc %s tid:%s (%s) key: 0x%x size: %d  flags: 0x%x\n %s' % (callname, tid, comm, key, frame['param3'], frame['param4'],
                       taskUtils.stringFromFrame(frame)) 
            elif call == ipc.MSGSND or call == ipc.MSGRCV:
                exit_info.retval_addr = frame['param5']
                exit_info.count = frame['param3']
                exit_info.fname = frame['param4']
                if call == ipc.MSGSND:
                    exit_info.bytes_to_write = self.mem_utils.getBytes(self.cpu, frame['param3'], frame['param5'])
                    ida_msg = 'ipc %s tid:%s (%s) quid: 0x%x size: %d addr: 0x%x' % (callname, tid, comm, frame['param4'], frame['param3'], frame['param5'])
                    call_name = 'MSGSND'
                else:
                    ida_msg = 'ipc %s tid:%s (%s) quid: 0x%x size: %d addr: 0x%x' % (callname, tid, comm, frame['param4'], frame['param3'], frame['param5'])
                    call_name = 'MSGRCV'
                #self.lgr.debug(ida_msg)
                #SIM_break_simulation(call_name)    
            elif call == ipc.SHMAT:
                ida_msg = 'ipc %s tid:%s (%s) segid: 0x%x ret_addr: 0x%x' % (callname, tid, comm, frame['param2'], frame['param4'])
            else:
                ida_msg = 'ipc %s tid:%s (%s) %s' % (callname, tid, comm, taskUtils.stringFromFrame(frame) )
            #self.lgr.debug(ida_msg)
            for call_param in self.call_params:
                if call_param.match_param.__class__.__name__ == 'IPCFilter':
                    if call_param.match_param.call != call:
                        #self.lgr.debug('ipc subcall %d does not match filter %d' % (call, call_param.match_param.call))
                        exit_info = None
                    else: 
                        #self.lgr.debug('ipc subcall match, set call_param')
                        exit_info.call_params.append(call_param)

        elif callname == 'ioctl':        
            fd = frame['param1']
            cmd = frame['param2']
            param = frame['param3']
            exit_info.cmd = cmd
            exit_info.old_fd = fd
            if cmd == net.FIONBIO:
                value = self.mem_utils.readWord32(cpu, param)
                ida_msg = 'ioctl tid:%s (%s) FD: %d FIONBIO: %d' % (tid, comm, fd, value) 
            elif cmd == net.FIONREAD:
                ida_msg = 'ioctl tid:%s (%s) FD: %d FIONREAD ptr: 0x%x' % (tid, comm, fd, param) 
                exit_info.retval_addr = param
            elif cmd == 0x703:
                ida_msg = 'ioctl tid:%s (%s) FD: %d slave address: 0x%x' % (tid, comm, fd, param) 
                exit_info.flags = param
            else:
                ida_msg = 'ioctl tid:%s (%s) FD: %d cmd: 0x%x ptr: 0x%x' % (tid, comm, fd, cmd, param) 
                exit_info.retval_addr = param
            self.lgr.debug(ida_msg)
            for call_param in self.call_params:
                if call_param.match_param == fd and (call_param.proc is None or call_param.proc == self.comm_cache[tid]):
                    exit_info.call_params.append(call_param)
                    exit_info.matched_param = call_param

        elif callname == 'gettimeofday':        
            if not self.record_fd:
                timeval_ptr = frame['param1']
                ida_msg = 'gettimeofday tid:%s (%s) timeval_ptr: 0x%x' % (tid, comm, timeval_ptr)
                exit_info.retval_addr = timeval_ptr
            else:
                self.checkTimeLoop(callname, tid)
                exit_info = None

        elif callname == 'waitpid':        
            if not self.record_fd:
                wait_tid = frame['param1']
                exit_info.retval_addr = frame['param2']
                options = frame['param3']
                frame_string = taskUtils.stringFromFrame(frame)
                self.lgr.debug('syscall waitpid params: %s' % frame_string)
                ida_msg = '%s tid:%s (%s) wait_tid: %d wstatus 0x%x options %x' % (callname, tid, comm, wait_tid, exit_info.retval_addr, options)
            else:
                self.checkTimeLoop(callname, tid)
                exit_info = None
 
        elif callname == 'kill':        
            target_tid = frame['param1']
            signal = frame['param2']
            ida_msg = '%s tid:%s (%s) target_tid: %d signal %d' % (callname, tid, comm, target_tid, signal)
            self.lgr.debug(ida_msg)
            
        elif callname == 'nanosleep':        
            time_spec = frame['param1']
            seconds = self.mem_utils.readWord32(cpu, time_spec)
            nano = self.mem_utils.readWord32(cpu, time_spec+self.mem_utils.WORD_SIZE)
            ida_msg = 'nanosleep tid:%s (%s) time_spec: 0x%x seconds: %d nano: %d' % (tid, comm, time_spec, seconds, nano)
            #SIM_break_simulation(ida_msg)

        elif callname in ['fcntl64', 'fcntl']:        
            fd = frame['param1']
            cmd_val = frame['param2']
            #cmd = net.fcntlCmd(cmd_val)
            cmd = net.fcntlGetCmd(cmd_val)
            arg = frame['param3']
            if cmd == 'F_SETFD':
                ida_msg = 'fcntl64 tid:%s (%s) FD: %d %s flags: 0%o' % (tid, comm, fd, cmd, arg)
            else:
                ida_msg = 'fcntl64 tid:%s (%s) FD: %d command: %s arg: %d\n\t%s' % (tid, comm, fd, cmd, arg, taskUtils.stringFromFrame(frame)) 
            exit_info.old_fd = fd
            exit_info.cmd = cmd_val
            
            for call_param in self.call_params:
                if call_param.match_param == fd:
                    exit_info.call_params.append(call_param)

        elif callname in ['_llseek','lseek']:        
            low = None
            if callname == '_llseek' and self.mem_utils.WORD_SIZE == 4:
                fd = frame['param1']
                high = frame['param2']
                low = frame['param3']
                result =  frame['param4']
                whence = frame['param5']
                ida_msg = '%s tid:%s (%s) FD: %d high: 0x%x low: 0x%x result: 0x%x whence: 0x%x \n%s' % (callname, tid, comm, fd, high, low, 
                        result, whence, taskUtils.stringFromFrame(frame))
                exit_info.retval_addr = result
            else:
                fd = frame['param1']
                offset = frame['param2']
                origin = frame['param3']
                ida_msg = '%s tid:%s (%s) FD: %d offset: 0x%x origin: 0x%x' % (callname, tid, comm, fd, offset, origin)

            exit_info.old_fd = fd
            for call_param in self.call_params:
                #self.lgr.debug('llseek call_params class is %s' % call_param.match_param.__class__.__name__)
                if call_param.match_param.__class__.__name__ == 'DmodSeek':
                    if tid == call_param.match_param.tid and fd == call_param.match_param.fd:
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
                elif call_param.match_param.__class__.__name__ == 'Dmod' and call_param.match_param.tid == tid and exit_info.old_fd == call_param.match_param.fd:
                    self.lgr.debug('sysall lseek Dmod, tid and fd match')
                    exit_info.call_params.append(call_param)

                elif call_param.match_param == frame['param1']:
                    exit_info.call_params.append(call_param)

        elif callname == 'read':        
            exit_info.old_fd = frame['param1']
            ida_msg = 'read tid:%s (%s) FD: %s buf: 0x%x count: %s' % (str(tid), comm, str(frame['param1']), frame['param2'], str(frame['param3']))
            #self.lgr.debug(ida_msg)
            exit_info.retval_addr = frame['param2']
            exit_info.count = frame['param3']
            ''' check runToIO '''
            #self.lgr.debug('syscall read loop %d call_params ' % len(self.call_params))
            ''' Look for matching params, preference to non-Dmods.  TBD refine this to allow Dmods with other call params.'''
            for call_param in self.call_params:
                ''' look for matching FD '''
                if type(call_param.match_param) is int:
                    if call_param.match_param == frame['param1'] and (call_param.proc is None or call_param.proc == self.comm_cache[tid]):
                        if call_param.nth is not None and self.kbuffer is not None and (call_param.count+1) >= call_param.nth:
                            self.lgr.debug('syscall read kbuffer for addr 0x%x' % exit_info.retval_addr)
                            self.kbuffer.read(exit_info.retval_addr, exit_info.count, exit_info.old_fd)
                        else:
                            if self.kbuffer is not None:
                                self.lgr.debug('syscall read kbuffer for addr 0x%x' % exit_info.retval_addr)
                                self.kbuffer.read(exit_info.retval_addr, exit_info.count, exit_info.old_fd)
                        addParam(exit_info, call_param)
                elif call_param.match_param.__class__.__name__ == 'Dmod':
                    ''' handle read dmod during syscall return '''
                    #self.lgr.debug('syscall read, is dmod: %s' % call_param.match_param.toString())
                    if call_param.match_param.tid is not None and (tid != call_param.match_param.tid or exit_info.old_fd != call_param.match_param.fd):
                        #self.lgr.debug('syscall read, is dmod, but tid or fd does not match, tid:%s match:%s fd:%d  match %d' % (tid, call_param.match_param.tid, exit_info.old_fd, call_param.match_param.fd))
                        continue
                    elif call_param.match_param.getComm() is not None and call_param.match_param.getComm() != comm:
                        #self.lgr.debug('syscall read, is dmod, but comm does not match,  match') 
                        continue
                    exit_info.call_params.append(call_param)
                if type(call_param.match_param) is str:
                    exit_info.call_params.append(call_param)

        elif callname == 'write':        
            exit_info.old_fd = frame['param1']
            count = frame['param3']
            ida_msg = 'write tid:%s (%s) FD: %d buf: 0x%x count: %d' % (tid, comm, frame['param1'], frame['param2'], count)
            self.lgr.debug(ida_msg)
            exit_info.retval_addr = frame['param2']
            '''
            max_len = min(count, 1024)
            byte_string, byte_array = self.mem_utils.getBytes(self.cpu, max_len, exit_info.retval_addr)
            if byte_array is not None:
                if resimUtils.isPrintable(byte_array):
                    s = ''.join(map(chr,byte_array))
                else:
                    s = byte_string
                exit_info.fname = s
            '''

            ''' check runToIO '''
            self.lgr.debug('syscallParse write %d params' % (len(self.call_params)))
            for call_param in self.call_params:
                if type(call_param.match_param) is int and call_param.match_param == frame['param1'] and (call_param.proc is None or call_param.proc == self.comm_cache[tid]):
                    self.lgr.debug('call param found %d, matches %d' % (call_param.match_param, frame['param1']))
                    exit_info.call_params.append(call_param)
                elif type(call_param.match_param) is str:
                    self.lgr.debug('write match param for tid:%s is string, check match' % tid)
                    max_len = min(count, 1024)
                    byte_tuple = self.mem_utils.getBytes(self.cpu, max_len, exit_info.retval_addr)
                    if byte_tuple is not None:
                        if resimUtils.isPrintable(byte_tuple):
                            s = ''.join(map(chr,byte_tuple))
                            if call_param.match_param in s:
                                addParam(exit_info, call_param)
                elif call_param.match_param.__class__.__name__ == 'Dmod':
                    if count < 4028:
                        self.lgr.debug('syscall write check dmod count %d' % count)
                        mod = call_param.match_param
                        if mod.checkString(self.cpu, frame['param2'], count):
                            if mod.getCount() == 0:
                                self.lgr.debug('syscall write found final dmod %s' % mod.getPath())
                                self.top.rmDmod(self.cell_name, mod.getPath())
                                if not self.remainingDmod(call_param.name):
                                    #self.top.stopTrace(cell_name=self.cell_name, syscall=self)
                                    self.top.rmSyscall(call_param.name)
                                    if not self.top.remainingCallTraces(cell_name=self.cell_name) and SIM_simics_is_running():
                                        self.top.notRunning(quiet=True)
                                        SIM_break_simulation('dmod done on cell %s file: %s' % (self.cell_name, mod.getPath()))
                                    else:
                                        print('%s performed' % mod.getPath())
                                else:
                                    self.call_params.remove(call_param)
                else:
                    #self.lgr.debug('syscall write call_param match_param is type %s' % (call_param.match_param.__class__.__name__))
                    pass

        elif callname == 'writev':
            exit_info.old_fd = frame['param1']
            # iovec addr
            exit_info.retval_addr = frame['param2']
            # iovcnt
            exit_info.count = frame['param3']
            ida_msg = '%s tid:%s (%s) FD: %d iovec: 0x%x iovcnt: %d' % (callname, tid, comm, exit_info.old_fd, exit_info.retval_addr, exit_info.count)
            self.lgr.debug(ida_msg)
            add_msg, byte_tuple = self.getIOV(exit_info)
            ida_msg = ida_msg + add_msg
            for call_param in self.call_params:
                if type(call_param.match_param) is int and call_param.match_param == frame['param1'] and (call_param.proc is None or call_param.proc == self.comm_cache[tid]):
                    self.lgr.debug('syscall writev call param found %d, matches %d' % (call_param.match_param, frame['param1']))
                    exit_info.call_params.append(call_param)
                elif type(call_param.match_param) is str:
                    self.lgr.debug('syscall writev match param for tid:%s is string, check match' % tid)
                    if byte_tuple is not None:
                        if resimUtils.isPrintable(byte_tuple):
                            s = ''.join(map(chr,byte_tuple))
                            if call_param.match_param in s:
                                self.lgr.debug('syscall writev found match for %s' % call_param.match_param)
                                addParam(exit_info, call_param)
                            else:
                                self.lgr.debug('syscall writev failed to find match of %s in %s' % (call_param.match_param, s))
                        else:
                            s = ''.join(map(chr,byte_tuple))
                            self.lgr.debug('syscall writev byte not printable: %s' % s)
                       

        elif callname == 'readv':
            exit_info.old_fd = frame['param1']
            # iovec addr
            exit_info.retval_addr = frame['param2']
            # iovcnt
            exit_info.count = frame['param3']
            ida_msg = '%s tid:%s (%s) FD: %d iovec: 0x%x iovcnt: %d' % (callname, tid, comm, exit_info.old_fd, exit_info.retval_addr, exit_info.count)
            self.lgr.debug(ida_msg)
 
        elif callname == 'mmap' or callname == 'mmap2':        
            #self.lgr.debug('syscall mmap')
            exit_info.count = frame['param2']
            # TBD added arm_svc check to this.
            if self.mem_utils.WORD_SIZE == 4 and self.cpu.architecture == 'arm' and frame['param1'] != 0 and self.platform == 'arm5' and self.param.arm_svc:
                self.lgr.debug(taskUtils.stringFromFrame(frame))
                arg_addr = frame['param1']
                addr = self.mem_utils.readPtr(self.cpu, arg_addr)
                length = self.mem_utils.readPtr(self.cpu, arg_addr+4)
                prot = self.mem_utils.readPtr(self.cpu, arg_addr+8)
                flags = self.mem_utils.readPtr(self.cpu, arg_addr+12)
                fd = self.mem_utils.readPtr(self.cpu, arg_addr+16)
                offset = self.mem_utils.readPtr(self.cpu, arg_addr+20)
                if fd == 0xffffffff:
                    fd = 'NULL'
                elif fd == 0xffffffffffffffff:
                    fd = 'NULL'
                elif fd is not None:
                    fd = str(fd)  
                if fd is not None:
                    self.lgr.debug('mmap tid:%s FD: %s' % (tid, fd))
                    pass
                if tid is None:
                    self.lgr.error('TID is NONE?')
                    SIM_break_simulation('eh?, over?')
                elif length is None:
                    ida_msg = '%s tid:%s (%s) len is NONE' % (callname, tid, comm)
                elif fd is None:
                    ida_msg = '%s tid:%s (%s) FD: NONE' % (callname, tid, comm)
                else:
                    ida_msg = '%s tid:%s (%s) FD: %s buf: 0x%x  len: %d prot: 0x%x  flags: 0x%x  offset: 0x%x' % (callname, tid, comm, fd, arg_addr, length, prot, flags, offset)

            #elif self.mem_utils.WORD_SIZE == 4 and self.cpu.architecture == 'arm':
            elif self.cpu.architecture.startswith('arm'):
                ''' tbd wth? the above seems wrong, why key on addr of zero? '''
                fd = frame['param5']
                if fd == 0xffffffff:
                    fd = 'NULL'
                elif fd == 0xffffffffffffffff:
                    fd = 'NULL'
                elif fd is not None:
                    fd = str(fd)  
                prot = frame['param3']
                ida_msg = '%s tid:%s (%s) FD: %s addr: 0x%x len: %d prot: 0x%x  flags: 0x%x offset: 0x%x' % (callname, tid, comm,
                    fd, frame['param1'], frame['param2'], frame['param3'], frame['param4'], frame['param6'])
                self.lgr.debug('syscall mmap arm 4 '+taskUtils.stringFromFrame(frame))
                self.lgr.debug(ida_msg)
            else:
                fd = frame['param5']
                if fd == 0xffffffffffffffff:
                    fd = 'NULL'
                elif fd is not None:
                    fd = str(fd)  
                prot = frame['param3']
                ida_msg = '%s tid:%s (%s) FD: %s addr: 0x%x len: %d prot: 0x%x  flags: 0x%x offset: 0x%x' % (callname, tid, comm,
                    fd, frame['param1'], frame['param2'], frame['param3'], frame['param4'], frame['param6'])
                #if self.watch_first_mmap is not None:
                #    self.lgr.debug('syscall mmap fd: %d from param5  watch_first_mmap is %d' % (fd, self.watch_first_mmap))
                #else:
                #    self.lgr.debug('syscall mmap watch_first_mmap is none')
                self.lgr.debug('syscall mmap '+taskUtils.stringFromFrame(frame))
            if prot is not None:
                is_ex = prot & 4
            else:
                is_ex = 0
            exit_info.prot = prot
            self.lgr.debug('syscall mmap fd %s  watch_first_mmap %s  prot %s is exec? %d' % (fd, self.watch_first_mmap, prot, is_ex))
            if fd is not None and fd != 'NULL' and self.watch_first_mmap == int(fd) and is_ex:
                self.lgr.debug('syscall mmap fd MATCHES watch_first_mmap %d' % int(fd))
                exit_info.fname = self.mmap_fname
                self.watch_first_mmap = None

        elif callname in ['select','_newselect', 'pselect6']:        
            exit_info.select_info = SelectInfo(frame['param1'], frame['param2'], frame['param3'], frame['param4'], frame['param5'], 
                 cpu, self.mem_utils, self.lgr)

            ida_msg = '%s tid:%s (%s) %s\n' % (callname, tid, comm, exit_info.select_info.getString())
            self.lgr.debug('syscall: '+ida_msg)
            for call_param in self.call_params:
                if type(call_param.match_param) is int and exit_info.select_info.hasFD(call_param.match_param) and (call_param.proc is None or call_param.proc == self.comm_cache[tid]):
                    self.lgr.debug('call param found %d' % (call_param.match_param))
                    exit_info.call_params.append(call_param)

        elif callname == 'poll' or callname == 'ppoll':
            self.lgr.debug('%s frames: %s' % (callname, taskUtils.stringFromFrame(frame)))
            exit_info.poll_info = PollInfo(frame['param1'], frame['param2'], frame['param3'], self.mem_utils, cpu, self.lgr)

            ida_msg = '%s tid:%s (%s) poll_info: %s\n' % (callname, tid, comm, exit_info.poll_info.getString())
            for call_param in self.call_params:
                if type(call_param.match_param) is int and exit_info.poll_info.hasFD(call_param.match_param) and (call_param.proc is None or call_param.proc == self.comm_cache[tid]):
                    self.lgr.debug('syscall %s call param found %d' % (callname, call_param.match_param))
                    exit_info.call_params.append(call_param)

        elif callname == 'epoll_ctl':
            epfd = resimSimicsUtils.fdString(frame['param1'])
            op = frame['param2']
            fd = frame['param3']
            events_ptr = frame['param4']
            if tid not in self.epolls:
                self.epolls[tid] = {}
            # read events struct from events_ptr)
            if events_ptr != 0 and epfd != 'NULL':
                if frame['param1'] not in self.epolls[tid]:
                    self.epolls[tid][frame['param1']] = EPollInfo(frame['param1'], self.cpu, self.mem_utils, self.lgr)
                events = EPollEvent(events_ptr, self.cpu, self.mem_utils, lgr=self.lgr) 
                self.epolls[tid][frame['param1']].add(fd, events)

                ida_msg = '%s tid:%s (%s) epfd: %s op: %s FD: %d events_ptr: 0x%x\n' % (callname, tid, comm, epfd, EPollInfo.EPOLL_OPER[op], fd, events_ptr)
                ida_msg = ida_msg+events.toString()
            else:
                ida_msg = '%s tid:%s (%s) epfd: %s \n' % (callname, tid, comm, epfd)

            self.lgr.debug(ida_msg)

        elif callname == 'epoll_wait' or callname == 'epoll_pwait':
            epfd = frame['param1']
            if tid in self.epolls and epfd in self.epolls[tid]:
                epoll_info = self.epolls[tid][epfd]
                exit_info.epoll_wait = EPollWaitInfo(epfd, frame['param2'], frame['param3'], frame['param4'], epoll_info)
                exit_info.old_fd = frame['param1']
                ida_msg = '%s tid:%s (%s) %s\n' % (callname, tid, comm, exit_info.epoll_wait.toString())
            else:
                exit_info.epoll_wait = EPollWaitInfo(epfd, frame['param2'], frame['param3'], frame['param4'], None)
                exit_info.old_fd = frame['param1']
                ida_msg = '%s tid:%s (%s) Did not find epoll_ctl for this epfd for this tid %s\n' % (callname, tid, comm, exit_info.epoll_wait.toString())
               
            self.lgr.debug(ida_msg)

        elif callname == 'timerfd_settime':
            exit_info.old_fd = frame['param1']
            exit_info.retval_addr = frame['param3']
            ida_msg = '%s tid:%s (%s) FD: %d struct: 0x%x\n' % (callname, tid, comm, exit_info.old_fd, exit_info.retval_addr)
            self.lgr.debug(ida_msg)

        elif callname == 'socketcall' or callname.upper() in net.callname:
            ida_msg = self.socketParse(callname, syscall_info, frame, exit_info, tid)
            if ida_msg is None and self.record_fd:
                self.lgr.debug('syscall parse ida_msg none for call %s, SKIP call' % callname)
                ''' Not a call we are watching. '''
                exit_info = None

        elif callname == 'wait4':
            ida_msg = '%s tid:%s (%s) waitfortid: %d  loc: 0x%x  options: %d rusage: 0x%x' % (callname, tid, comm, frame['param1'], frame['param2'], frame['param3'], frame['param4'])

        elif callname == 'rt_sigaction':
            handler = self.mem_utils.readPtr(self.cpu, frame['param2'])
            if handler is not None and handler > 100:
                proc_break = self.context_manager.genBreakpoint(self.cell, Sim_Break_Linear, Sim_Access_Execute, handler, 1, 0)
                self.sig_handler[tid] = self.context_manager.genHapIndex("Core_Breakpoint_Memop", self.sigHandlerHap, self.syscall_info, proc_break, 'sig_handler')
                self.lgr.debug('syscallHap %s set break on handler 0x%x' % (callname, handler))
            if handler is not None:
                ida_msg = '%s tid:%s (%s) signum: %d sigaction: 0x%x handler: 0x%x' % (callname, tid, comm, frame['param1'], frame['param2'], handler)
            else:
                ida_msg = '%s tid:%s (%s) signum: %d sigaction: 0x%x no handler found' % (callname, tid, comm, frame['param1'], frame['param2'])
            self.lgr.debug(ida_msg)
            #SIM_break_simulation(ida_msg)

        elif callname.startswith('stat'):
            fname_addr = frame['param1']
            retval_addr = frame['param2']
            fname = self.mem_utils.readString(self.cpu, fname_addr, 256)
            exit_info.retval_addr = retval_addr
            exit_info.fname_addr = fname_addr
            if fname is None:
                ida_msg = '%s tid:%s (%s) path: not yet mapped? return buffer: 0x%x' % (callname, tid, comm, retval_addr) 
            else:
                ida_msg = '%s tid:%s (%s) path_addr: 0x%x path: %s return buffer: 0x%x' % (callname, tid, comm, fname_addr, fname, retval_addr)
            #SIM_break_simulation(ida_msg)
            #return
        elif callname.startswith('fstat'):
            fd = frame['param1']
            retval_addr = frame['param2']
            exit_info.retval_addr = retval_addr
            exit_info.old_fd = fd
            ida_msg = '%s tid:%s (%s) FD: %d return buffer: 0x%x' % (callname, tid, comm, fd, retval_addr)
            #SIM_break_simulation(ida_msg)
            #return
        elif callname.startswith('newfstatat'):
            exit_info.old_fd = frame['param1']
            fname_addr = frame['param2']
            fname = self.mem_utils.readString(self.cpu, fname_addr, 256)
            retval_addr = frame['param2']
            exit_info.retval_addr = retval_addr
            fd = resimSimicsUtils.fdString(exit_info.old_fd)
            ida_msg = '%s tid:%s (%s) FD: %s file: %s return buffer: 0x%x' % (callname, tid, comm, fd, fname, retval_addr)
        elif callname.startswith('faccessat'):
            exit_info.old_fd = frame['param1']
            fname_addr = frame['param2']
            fname = self.mem_utils.readString(self.cpu, fname_addr, 256)
            fd = resimSimicsUtils.fdString(exit_info.old_fd)
            mode = frame['param3']
            flags = frame['param4']
            ida_msg = '%s tid:%s (%s) FD: %s file: %s mode: 0x%x flags: 0x%x' % (callname, tid, comm, fd, fname, mode, flags)
            #SIM_break_simulation(ida_msg)
            #return
        elif callname == 'prctl':
            option = frame['param1']
            opt_name = 'unknown'
            if option == 15:
                opt_name = 'SET_NAME'
            elif option == 16:
                opt_name = 'GET_NAME'
            self.lgr.debug(ida_msg)
            if option == 15:
                retval_addr = frame['param2']
                new_comm = self.mem_utils.readString(self.cpu, retval_addr, 256)
                ida_msg = '%s option: %s changed comm to: %s tid:%s (%s) cycle:0x%x' % (callname, opt_name, new_comm, tid, comm, self.cpu.cycles)
            else:
                ida_msg = '%s option: %s  %s   tid:%s (%s) cycle:0x%x' % (callname, opt_name, taskUtils.stringFromFrame(frame), tid, comm, self.cpu.cycles)
        elif callname == 'msgsnd':
            msqid = frame['param1']
            msgp = frame['param2']
            msgsz = frame['param3']
            mtype = self.mem_utils.readWord32(self.cpu, msgp)
            max_len = min(msgsz, 1024)
            mtext_addr = msgp + 4
            byte_tuple = self.mem_utils.getBytes(self.cpu, max_len, mtext_addr)
            s = None
            if byte_tuple is not None:
                s = resimUtils.getHexDump(byte_tuple[:max_len])
            ida_msg = '%s msqid: 0x%x mtype: 0x%x msgsz: %d msg: %s   tid:%s (%s) cycle:0x%x' % (callname, msqid, mtype, msgsz, s, tid, comm, self.cpu.cycles)
            self.lgr.debug(ida_msg.strip()) 
        elif callname == 'msgrcv':
            msqid = frame['param1']
            msgp = frame['param2']
            msgsz = frame['param3']
            mtype = self.mem_utils.readWord32(self.cpu, msgp)
            mtext_addr = msgp + 4
            exit_info.old_fd = msqid
            exit_info.retval_addr = msgp
            exit_info.count = msgsz
            ida_msg = '%s msqid: 0x%x msgsz: %d tid:%s (%s) cycle:0x%x' % (callname, msqid, msgsz, tid, comm, self.cpu.cycles)
        elif callname == 'shmget':
            key = frame['param1']
            size = frame['param2']
            flag = frame['param3']
            ida_msg = '%s key: 0x%x size 0x%x flag: 0x%x tid:%s (%s) cycle:0x%x' % (callname, key, size, flag, tid, comm, self.cpu.cycles)
        elif callname in ['setuid', 'setgid']:
            uid = frame['param1']
            ida_msg = '%s id: %d tid:%s (%s) cycle:0x%x' % (callname, uid, tid, comm, self.cpu.cycles)
        elif callname == 'link':
            oldpath_addr = frame['param1']
            oldpath = self.mem_utils.readString(self.cpu, oldpath_addr, 256)
            newpath_addr = frame['param2']
            newpath = self.mem_utils.readString(self.cpu, newpath_addr, 256)
            ida_msg = '%s tid:%s (%s) oldpath: %s newpath: %s cycle:0x%x' % (callname, tid, comm, oldpath, newpath, self.cpu.cycles)
        elif callname == 'linkat':
            olddirfd= resimSimicsUtils.fdString(frame['param1'])
            oldpath_addr = frame['param2']
            oldpath = self.mem_utils.readString(self.cpu, oldpath_addr, 256)
            newdirfd = resimSimicsUtils.fdString(frame['param3'])
            newpath_addr = frame['param4']
            newpath = self.mem_utils.readString(self.cpu, newpath_addr, 256)
            ida_msg = '%s tid:%s (%s) olddirfd: %s oldpath: %s newdirfd: %s newpath: %s cycle:0x%x' % (callname, tid, comm, olddirfd, oldpath, newdirfd, newpath, self.cpu.cycles)
        elif callname in ['unlink']:
            exit_info.fname_addr = frame['param1']
            exit_info.fname = self.mem_utils.readString(self.cpu, exit_info.fname_addr, 256)
            ida_msg = '%s tid:%s (%s) fname: %s cycle:0x%x' % (callname, tid, comm, exit_info.fname, self.cpu.cycles)
        elif callname in ['unlinkat']:
            exit_info.old_fd = frame['param1']
            exit_info.fname_addr = frame['param2']
            exit_info.fname = self.mem_utils.readString(self.cpu, exit_info.fname_addr, 256)
            ida_msg = '%s tid:%s (%s) fname: %s cycle:0x%x' % (callname, tid, comm, exit_info.fname, self.cpu.cycles)
        elif callname in ['rename']:
            exit_info.fname_addr = frame['param1']
            exit_info.fname = frame['param1'] = self.mem_utils.readString(self.cpu, exit_info.fname_addr, 256)
            addr2 = frame['param2']
            fname2 = self.mem_utils.readString(self.cpu, addr2, 256)
            ida_msg = '%s %s to %s tid:%s (%s) cycle:0x%x' % (callname, exit_info.fname, fname2, tid, comm, self.cpu.cycles)
        elif callname in ['chmod']:
            exit_info.fname_addr = frame['param1']
            exit_info.fname = frame['param1'] = self.mem_utils.readString(self.cpu, exit_info.fname_addr, 256)
            mode = oct(frame['param2'])
            ida_msg = '%s %s mode: %s tid:%s (%s) cycle:0x%x' % (callname, exit_info.fname, mode, tid, comm, self.cpu.cycles)
        elif callname == 'readlinkat':
            dirfd= resimSimicsUtils.fdString(frame['param1'])
            exit_info.fname_addr = frame['param2']
            exit_info.fname = self.mem_utils.readString(self.cpu, exit_info.fname_addr, 256)
            exit_info.retval_addr = frame['param3'] 
            exit_info.count = frame['param4'] 
            ida_msg = '%s tid:%s (%s) dirfd: %s fname: %s buf addr: 0x%x size: 0x%x cycle:0x%x' % (callname, tid, comm, dirfd, exit_info.fname, exit_info.retval_addr, exit_info.count, self.cpu.cycles)
        else:
            ida_msg = '%s %s   tid:%s (%s) cycle:0x%x' % (callname, taskUtils.stringFromFrame(frame), tid, comm, self.cpu.cycles)
            self.lgr.debug(ida_msg)
            self.context_manager.setIdaMessage(ida_msg)
        if exit_info is not None:
            exit_info.trace_msg = ida_msg
        if ida_msg is not None and not quiet:
            self.lgr.debug(ida_msg.strip()) 
            
            #if ida_msg is not None and self.traceMgr is not None and (len(self.call_params) == 0 or exit_info.call_params is not None):
            if ida_msg is not None and self.traceMgr is not None:
                if len(ida_msg.strip()) > 0:
                    #self.lgr.debug('syscall call traceMgr with %s' % (ida_msg))
                    self.traceMgr.write(ida_msg+'\n')

        if do_stop_from_call:
            self.top.rmSyscall('runToCall')
            SIM_run_alone(self.stopAlone, 'run to call %s' % callname)

        return exit_info

    def rmStopHap(self, hap):
       RES_hap_delete_callback_id("Core_Simulation_Stopped", hap)

    def stopHap(self, msg, one, exception, error_string):
        '''  Invoked when a syscall (or more typically its exit back to user space) triggers
             a break in the simulation
        '''
        if self.stop_hap is not None:
            hap = self.stop_hap
            SIM_run_alone(self.rmStopHap, hap)
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
                ''' check functions in list '''
                #self.lgr.debug('syscall stopHap call to rmExitHap')
                self.sharedSyscall.rmExitHap(None)

                ''' TBD do this as a stop function? '''
                cpu, comm, tid = self.task_utils.curThread() 
                self.sharedSyscall.rmPendingExecve(tid)

                ''' TBD when would we want to close it?'''
                if self.traceMgr is not None:
                    self.traceMgr.flush()
                self.top.idaMessage() 
                ''' Run the stop action, which is a hapCleaner class '''
                self.lgr.debug('syscall stopHap run stop_action')
                self.stop_action.run(cb_param=msg)

                for param in self.call_params:
                    #self.lgr.debug('syscall stopHap call rmSyscall for param %s' % param.name)
                    self.top.rmSyscall(param.name, cell_name=self.cell_name)
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
                frame = self.task_utils.frameFromRegs(compat32=syscall_info.compat32)
                frame_string = taskUtils.stringFromFrame(frame)
                #self.lgr.debug('syscall getExitAddrs first if, frame %s' % frame_string)
            exit_eip1 = self.param.sysexit
            ''' catch interrupt returns such as wait4 '''
            exit_eip2 = self.param.iretd
            try:
                exit_eip3 = self.param.sysret64
                #self.lgr.debug('syscall getExitAddrs has sysret64 exit1 0x%x 2 0x%x 3 0x%x' % (exit_eip1, exit_eip2, exit_eip3))
            except AttributeError:
                exit_eip3 = None
                #self.lgr.debug('syscall getExitAddrs no sysret64 exit1 0x%x 2 0x%x ' % (exit_eip1, exit_eip2))
            
        elif break_eip == self.param.sys_entry:
            if frame is None:
                frame = self.task_utils.frameFromRegs(compat32=syscall_info.compat32)
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
                frame = self.task_utils.frameFromRegs()
                frame_string = taskUtils.stringFromFrame(frame)
                #SIM_break_simulation(frame_string)
        elif hasattr(self.param, 'arm64_entry') and break_eip == self.param.arm64_entry:
            exit_eip1 = self.param.arm_ret
            if frame is None:
                frame = self.task_utils.frameFromRegs()
                frame_string = taskUtils.stringFromFrame(frame)
                #SIM_break_simulation(frame_string)
        #elif break_eip == syscall_info.calculated:
        elif break_eip == self.param.ppc32_entry:
            exit_eip1 = self.param.ppc32_exit
            if frame is None:
                frame = self.task_utils.frameFromRegs()
                frame_string = taskUtils.stringFromFrame(frame)
        elif syscall_info.calculated:
            ''' Note EIP in stack frame is unknown '''
            #frame['eax'] = syscall_info.callnum
            if self.cpu.architecture.startswith('arm'):
                if frame is None:
                    if (self.cpu.architecture == 'arm64'): 
                        frame = self.task_utils.frameArm64Computed()
                    else:
                        # aarch32 regs unmolested
                        frame = self.task_utils.frameFromRegs()
                exit_eip1 = self.param.arm_ret
                exit_eip2 = self.param.arm_ret2
                exit_eip2 = None
                #exit_eip3 = self.param.sysret64
            elif self.cpu.architecture == ('ppc32'):
                if frame is None:
                    frame = self.task_utils.frameFromRegs()
                exit_eip1 = self.param.ppc32_exit
                self.lgr.debug('syscallHap calculated exit_eip1 0x%x' % exit_eip1)
            elif self.mem_utils.WORD_SIZE == 8:
                if frame is None:
                    #self.lgr.debug('syscallHap calculated, word size 8')
                    frame = self.task_utils.frameFromRegs(compat32=syscall_info.compat32)
                exit_eip1 = self.param.sysexit
                exit_eip2 = self.param.iretd
                exit_eip3 = self.param.sysret64
            else:
                if frame is None:
                    #self.lgr.debug('syscallHap calculated, word size 4')
                    frame = self.task_utils.frameFromStackSyscall()
                exit_eip1 = self.param.sysexit
                exit_eip2 = self.param.iretd
            #self.lgr.debug('syscallHap calculated')
            frame_string = taskUtils.stringFromFrame(frame)
            #self.lgr.debug('frame string %s' % frame_string)
        return frame, exit_eip1, exit_eip2, exit_eip3
        
    def sigHandlerHap(self, syscall_info, context, break_num, memory):
        cpu, comm, tid = self.task_utils.curThread() 
        ida_msg = 'signal handler tid: %s (%s)' % (tid, comm)
        self.lgr.debug(ida_msg)
        #SIM_break_simulation(ida_msg)

    def arm64BailCheck(self, break_num):
        # return True if arm64 syscall that should be ignored due to shared entry points
        retval = False
        # arm64 v8, anyway, shares kernel entry address between syscalls and faults.  Vectors are instructions vice addresses?
        reg_num = self.cpu.iface.int_register.get_number('esr_el1')
        reg_value = self.cpu.iface.int_register.read(reg_num)
        reg_value = reg_value >> 26
        if reg_value != 0x11 and reg_value != 0x15:
            callnum = self.mem_utils.getCallNum(self.cpu)
            #self.lgr.debug('syscallHap arm64 NOT a syscall, reg_value is 0x%x callnum 0x%x' % (reg_value, callnum))
            #if callnum == 0xdc:
            #    SIM_break_simulation('remove this')
            retval = True
        else:
            hap_name = self.context_manager.getHapName(break_num)
            if hap_name is not None:
                arm64_app = self.mem_utils.arm64App(self.cpu)
                #self.lgr.debug('syscallHap ENTER addr 0x%x break 0x%x hap_name %s cycle: 0x%x' % (memory.logical_address, break_num, hap_name, self.cpu.cycles))
                if hap_name.endswith('arm32') and arm64_app:
                    #self.lgr.debug('sycallHap arm32 break hit for arm64 app, bail')
                    retval = True
        return retval

    def syscallHap(self, dumb, context, break_num, memory):
        ''' Invoked when syscall is detected.  May set a new breakpoint on the
            return to user space so as to collect remaining parameters, or to stop
            the simulation as part of a debug session '''
        ''' NOTE Does not track Tar syscalls! '''
        if self.context_manager.isReverseContext():
            return
        if self.context_manager.isIgnoreContext():
            return
        cpu, comm, tid = self.task_utils.curThread() 
        if self.cpu.architecture == 'arm64' and self.arm64BailCheck(break_num):
            return
 
        if self.syscall_info.callnum is None and self.callback is not None:
            # only used syscall to set breaks, we'll take it from here.
            self.callback()
            return
        if tid == '0':
            return
        # beware some systems execv init to some other process that you may care about
        #if tid == '1':
        #    return
        #self.lgr.debug('syscallHap tid:%s (%s) %s context %s break_num %s cpu is %s t is %s' % (tid, comm, self.name, str(context), str(break_num), str(memory.ini_ptr), type(memory.ini_ptr)))
        #self.lgr.debug('memory.ini_ptr.name %s' % (memory.ini_ptr.name))

        #if comm == 'tar':
        #    return

        memory_address = memory.logical_address
        break_eip = self.mem_utils.getRegValue(self.cpu, 'pc')
        if memory_address != break_eip:
            self.lgr.debug('syscallHap pc 0x%x does not match memory.logical address 0x%x' % (break_eip, memory_address))
        if self.syscall_info.cpu != cpu:
            self.lgr.error('syscallHap wrong cell, cur: %s, expected %s' % (cpu.name, self.syscall_info.cpu.name))
            return

        self.comm_cache[tid] = comm
        if self.linger:
            if cpu.cycles in self.linger_cycles:
                #self.lgr.debug('syscalHap for lingering call we already made.')
                return
            else:
                self.linger_cycles.append(cpu.cycles)
        else:
            ''' for example, rec calls rec_from '''
            if self.hack_cycle+20 >= cpu.cycles:
                callnum = self.mem_utils.getCallNum(cpu)
                callname = self.task_utils.syscallName(callnum, self.syscall_info.compat32) 
                self.lgr.debug('syscallHap tid:%s (%s) skip back-to-back calls within 10 cycles. name: %s TBD fix this for cases where cycles match. call_num %d call_name %s cycles now 0x%x?.' % (tid, comm, self.name, callnum, callname, cpu.cycles))
                return
            else:
                self.hack_cycle = cpu.cycles

        tracing_all = False
        if self.syscall_info.callnum is None:
           ''' tracing all'''
           tracing_all = True
           callnum = self.mem_utils.getCallNum(cpu)
           callname = self.task_utils.syscallName(callnum, self.syscall_info.compat32) 
           self.lgr.debug('syscallHap tid:%s traceAll callnum 0x%x name %s' % (tid, callnum, callname))
           if self.record_fd and (callname not in record_fd_list or comm in skip_proc_list):
               self.lgr.debug('syscallHap not in record_fd list: %s' % callname)
               return
           syscall_instance = self.top.getSyscall(self.cell_name, callname) 
           if syscall_instance is not None and syscall_instance != self and syscall_instance.isBackground() == self.isBackground() and callname != 'exit_group' and syscall_instance.getContext() == self.cell:
               #self.lgr.debug(str(syscall_instance))
               #self.lgr.debug(str(self))
               self.lgr.debug('syscallHap tracing all tid %s callnum %d name %s found more specific syscall hap, so ignore this one' % (tid, callnum, callname))
               return
           if callname == 'mmap' and tid in self.first_mmap_hap:
               return
        else:
           arm64_app = None
           if self.cpu.architecture == 'arm64':
               arm64_app = self.mem_utils.arm64App(self.cpu)
           callnum = self.syscall_info.getCall(break_eip, arm64_app)
           if callnum is None:
               break_handle = self.context_manager.getBreakHandle(break_num)
               self.lgr.debug('syscallHap name: %s break eip 0x%x not in syscall_info arm64_app %r break_num 0x%x handle: 0x%x  Assume computed break set is not applicable to this process' % (self.name, break_eip, arm64_app, break_num, break_handle))
               return
           callname = self.task_utils.syscallName(callnum, self.syscall_info.compat32) 
           #self.lgr.debug('syscallHap computed, callnum is %s name %s cycle: 0x%x' % (callnum, callname, self.cpu.cycles))
           if self.record_fd and (callname not in record_fd_list or comm in skip_proc_list):
               return
           if tid == 1 and callname in ['open', 'openat', 'mmap', 'mmap2']:
               ''' ad-hoc noise reduction '''
               return
           #syscall_info.compat32 = False
        ''' call 0 is read in 64-bit '''
        if callnum == 0 and self.mem_utils.WORD_SIZE==4:
            self.lgr.debug('syscallHap callnum is zero')
            return
        #self.lgr.debug('syscallHap cell %s context %sfor tid:%s (%s) at 0x%x (memory 0x%x) callnum %d (%s) expected %s compat32 set for the HAP? %r name: %s cycle: 0x%x' % (self.cell_name, str(context), 
        #     tid, comm, break_eip, memory_address, callnum, callname, str(self.syscall_info.callnum), self.syscall_info.compat32, self.name, self.cpu.cycles))
           
        if not self.swapper_ok and comm == 'swapper/0' and tid == 1:
            self.lgr.debug('syscallHap, skipping call from init/swapper')
            return

        if len(self.proc_hap) == 0 and self.background_break is None:
            self.lgr.debug('syscallHap entered for tid %s after hap deleted' % tid)
            return
        if self.syscall_info.cpu is not None and cpu != self.syscall_info.cpu:
            self.lgr.debug('syscallHap, wrong cpu %s %s' % (cpu.name, self.syscall_info.cpu.name))
            return

        ''' catch stray calls from wrong tid.  Allow calls if the syscall instance's cell is not None, which means it is not up to the context manager
            to watch or not.  An example is execve, which must be watched for all processes to provide a toExecve function. '''
        if self.debugging and not self.context_manager.amWatching(tid) and not tracing_all and self.background_break is None and self.cell is None and not self.context_manager.watchingExit(tid):
            # will happen in afl if some other process exits.  TBD, method to watch selected processes as part of AFL run
            #self.lgr.debug('syscallHap name: %s tid:%s missing from context manager.  Debugging and specific syscall watched. callnum: %d' % (self.name, 
            #     tid, self.syscall_info.callnum))
            return

        if self.bang_you_are_dead:
            self.lgr.error('syscallhap call to dead hap tid %s' % tid) 
            return

        if tid == 0:
            ''' TBD debug simics?  seems broken '''
            self.lgr.debug('syscallHap tid 0, break_eip 0x%x memory says 0x%x len of haps is %d' % (break_eip, memory_address, len(self.proc_hap)))
            return

        #self.lgr.debug('syscallhap for %s at 0x%x' % (tid, break_eip))
            
        frame, exit_eip1, exit_eip2, exit_eip3 = self.getExitAddrs(break_eip, self.syscall_info)
        if frame is None:
            ''' TBD Simics broken???? occurs due to a mov dword ptr fs:[0xc149b454],ebx '''
            self.lgr.debug('syscallHap tid:%s frame none break_eip 0x%x memory says 0x%x len of haps is %d' % (tid, break_eip, memory_address, len(self.proc_hap)))
            #SIM_break_simulation('unexpected break eip 0x%x' % break_eip)

            return

        if callnum > 400:
            self.lgr.debug('syscallHap callnum is too big... %d' % callnum)
            return
        
        if self.sharedSyscall.isPendingExecve(tid):
            if callname == 'close':
                self.lgr.debug('syscallHap must be a close on exec? tid:%s' % tid)
                return
            elif callname == 'execve':
                self.lgr.debug('syscallHap must be a execve in execve? tid:%s' % tid)
                return
            elif callname == 'exit_group':
                self.lgr.debug('syscallHap exit_group called from within execve %d' % tid)
                return
            elif callname == 'uname':
                self.lgr.debug('syscallHap uname called from within execve %d' % tid)
                return
            else:
                if self.context_manager.watchingThis():
                    self.lgr.error('fix this, syscall within exec? tid:%s call: %s' % (tid, callname))
                    SIM_break_simulation('fix this')
                    return
                else:
                    self.lgr.debug('syscall with pending exec, but no longer watching.  TBD, remove pending exec when no longer watching?')
                    return
        if self.name is None:
            exit_info_name = '%s-exit' % (callname)
        else:
            exit_info_name = '%s-%s-exit' % (callname, self.name)

        pending_call = self.sharedSyscall.getPendingCall(tid, exit_info_name)
        if pending_call is not None and not self.swapper_ok:
            if callname == 'sigreturn':
                return
            else:
                if pending_call == self.task_utils.syscallNumber('pipe', self.compat32) and callnum == self.task_utils.syscallNumber('pipe2', self.compat32):
                    self.lgr.debug('syscall was pending pipe  tid:%s call %d' % (tid, pending_call))
                    return
                else:
                    self.lgr.debug('syscall was pending tid:%s call %d' % (tid, pending_call))
                    return
                 

        if callname in self.exit_calls:
            if callname == 'tgkill':
                tgid = frame['param1']
                tid = frame['param2']
                sig = frame['param3']
                ida_msg = '%s tid:%s (%s) tgid: %d  tid: %d sig:%d' % (callname, tid, comm, tgid, tid, sig)
                if tid != tid:
                    self.lgr.error('tgkill called from %d for other process %d, fix this TBD!' % (tid, tid))
                    self.context_manager.tidExit(tid)
                    return
            else: 
                ida_msg = '%s tid:%s (%s)' % (callname, tid, comm)
            self.lgr.debug('syscallHap %s exit of tid:%s callname %s stop_on_exit: %r' % (self.name, tid, callname, self.top.getStopOnExit(target=self.cell_name)))
            if callname == 'exit_group':
                self.handleExit(tid, ida_msg, exit_group=True)
            elif callname == 'tgkill' and sig == 6:
                self.handleExit(tid, ida_msg, killed=True)
            else:
                self.handleExit(tid, ida_msg)
            #moved tidExit until after handle exit so SOMap is updated
            self.context_manager.tidExit(tid)
            self.context_manager.stopWatchTid(tid)
            if self.top.getStopOnExit(target=self.cell_name):
                self.lgr.debug('syscall break simulation for stop_on_exit')
                SIM_break_simulation(ida_msg)
            return

        ''' Set exit breaks '''
        frame_string = taskUtils.stringFromFrame(frame)
        #self.lgr.debug('syscallHap in tid:%s (%s), callnum: 0x%x (%s)  EIP: 0x%x' % (tid, comm, callnum, callname, break_eip))
        #self.lgr.debug('syscallHap frame: %s syscall_info.callnum %s' % (frame_string, str(self.syscall_info.callnum)))

        if not tracing_all:
            #self.lgr.debug('syscallHap cell %s callnum %d self.syscall_info.callnum %d stop_on_call %r' % (self.cell_name, 
            #     callnum, str(self.syscall_info.callnum), self.stop_on_call))
            exit_info = self.syscallParse(callnum, callname, frame, cpu, tid, comm, self.syscall_info)
            if exit_info is not None:
                if comm != 'tar':
                        ''' watch syscall exit unless call_params narrowed a search failed to find a match '''
                        tracing_all = False 
                        if self.top is not None:
                            tracing_all = self.top.tracingAll(self.cell_name, tid)
                        if self.callback is None:
                            if not hasParamMatchRequest(self.call_params) or len(exit_info.call_params)>0 or tracing_all or tid in self.tid_sockets:
                                if self.stop_on_call:
                                    cp = CallParams('stop_on_call', None, None, break_simulation=True)
                                    exit_info.call_params.append(cp)
                                #self.lgr.debug('exit_info.call_params tid %s self.name %s is %s' % (tid, self.name, str(exit_info.call_params)))
                                if tracing_all or len(exit_info.call_params) > 0:
                                    if len(self.call_params) > 0:
                                        self.lgr.debug('syscallHap %s cell: %s call to addExitHap for tid %s call  %d len %d trace_all %r tid_sockes? %s' % (self.name, 
                                           self.cell_name, tid, callnum, len(self.call_params), tracing_all, str(self.tid_sockets)))
                                    else:
                                        self.lgr.debug('syscallHap %s cell: %s call to addExitHap for tid %s call  %d no params trace_all %r tid_sockets? %s' % (self.name, self.cell, 
                                           tid, callnum, tracing_all, str(self.tid_sockets)))
                                    self.sharedSyscall.addExitHap(self.cpu.current_context, tid, exit_eip1, exit_eip2, exit_eip3, exit_info, exit_info_name)
                                elif callname.startswith('mmap') and self.name in ['runToText', 'trackSO'] and exit_info.fname == self.mmap_fname:
                                    #self.lgr.debug('syscallHap is mmap and runToText and match')
                                    self.sharedSyscall.addExitHap(self.cpu.current_context, tid, exit_eip1, exit_eip2, exit_eip3, exit_info, exit_info_name)
                                elif callname.startswith('mmap') and self.name in ['dataWatchMmap']:
                                    #self.lgr.debug('syscallHap is dataWatchMmap ')
                                    self.sharedSyscall.addExitHap(self.cpu.current_context, tid, exit_eip1, exit_eip2, exit_eip3, exit_info, exit_info_name)
                                elif callname.startswith('open') and self.name in ['runToText', 'trackSO']:
                                    #self.lgr.debug('syscallHap callname %s  my name %s, add exit' % (callname, self.name))
                                    self.sharedSyscall.addExitHap(self.cpu.current_context, tid, exit_eip1, exit_eip2, exit_eip3, exit_info, exit_info_name)
                                else:
                                    self.lgr.debug('syscallHap not trace all and no exit_info call params, so no exit hap')
                                    pass
                            elif callname.startswith('mmap') and self.name == 'runToText':
                                # TBD this is broken, what about so added after we hit text segment.  Problem is syscall that includes multiple param requests.
                                self.sharedSyscall.addExitHap(self.cpu.current_context, tid, exit_eip1, exit_eip2, exit_eip3, exit_info, exit_info_name)
                            else:
                                #self.lgr.debug('did not add exitHap')
                                pass
                        else:
                            self.lgr.debug('syscall invoking callback')
                            self.callback()
                else:
                    self.lgr.debug('syscallHap skipping tar %s, no exit' % comm)
                
        else:
            ''' tracing all syscalls, or watching for any syscall, e.g., during debug '''
            exit_info = self.syscallParse(callnum, callname, frame, cpu, tid, comm, self.syscall_info)
            #self.lgr.debug('syscall looking for any, got %d from %s (%s) at 0x%x  exit_info %s' % (callnum, tid, comm, break_eip, str(exit_info)))

            if exit_info is not None:
                if comm != 'tar':
                    name = callname+'-exit' 
                    #self.lgr.debug('syscallHap call to addExitHap for tid:%s' % tid)
                    if self.stop_on_call:
                        cp = CallParams('stop_on_call', None, None, break_simulation=True)
                        exit_info.call_params.append(cp)
                    self.sharedSyscall.addExitHap(self.cell, tid, exit_eip1, exit_eip2, exit_eip3, exit_info, name)
                else:
                    self.lgr.debug('syscallHap tid:%s skip exitHap for tar' % tid)


    def handleExit(self, tid, ida_msg, killed=False, retain_so=False, exit_group=False):
            if self.traceProcs is not None:
                self.traceProcs.exit(tid)
            if killed:
                self.lgr.debug('syscall handleExit, was killed so remove skipAndMail from stop_action')
                self.stop_action.rmFun(self.top.skipAndMail)
        
            if self.traceMgr is not None:
                self.traceMgr.write(ida_msg+'\n')
            self.context_manager.setIdaMessage(ida_msg)
            am_watching = self.context_manager.amWatching(tid)
            self.lgr.debug('syscall handleExit retain_so %r am_watching %r ida_msg is %s' % (retain_so, am_watching, ida_msg))
            if self.soMap is not None:
                if not retain_so and not am_watching:
                    self.lgr.debug('syscall handleExit not watching, call soMap.handleExit')
                    self.soMap.handleExit(tid, killed)
            else:
                self.lgr.debug('syscall exit soMap is None, tid:%s' % (tid))
            last_one = self.context_manager.rmTask(tid, killed)
            debugging_tid, dumb = self.context_manager.getDebugTid()
            self.lgr.debug('syscall handleExit %s tid:%s last_one %r debugging %d retain_so %r exit_group %r debugging_tid %s killed %r am_watching %r' % (self.name, tid, last_one, self.debugging, retain_so, exit_group, str(debugging_tid), killed, am_watching))
            #if (killed or last_one or (exit_group and tid == debugging_tid)) and self.debugging:
            if (killed or last_one or (exit_group and am_watching)) and self.debugging:
                if self.top.hasProcHap():
                    ''' exit before we got to text section '''
                    self.lgr.debug('syscall handleExit  exit of %d before we got to text section ' % tid)
                    SIM_run_alone(self.top.undoDebug, None)
                self.lgr.debug('syscall handleExit exit or exit_group or tgkill tid:%s' % tid)
                self.sharedSyscall.stopTrace()
                ''' record exit so we don't see this proc, e.g., when going to debug its next instantiation '''
                self.task_utils.setExitTid(tid)

                frame, cycle = self.top.getRecentEnterCycle()
                if cycle is not None:
                    enter_cycle = cycle-1
                    self.lgr.debug('syscall handleExit frame %s  cycle 0x%x' % (str(frame), cycle))
                    self.top.setDebugBookmark('Process exit', cpu=self.cpu, cycles=enter_cycle, eip = frame['pc'])
                #fun = stopFunction.StopFunction(self.top.noDebug, [], False)
                #self.stop_action.addFun(fun)
                print('exit tid:%s' % tid)
                self.lgr.debug('syscall handleExit call stopAlone and checkExitCallback')
                #if self.top.pendingFault():
                if self.top.hasPendingPageFault(tid):
                    self.lgr.debug('syscall handleExit killed or group exit %s HAD pending fault, do something!' % tid)
                SIM_run_alone(self.stopAlone, 'exit or exit_group tid:%s' % tid)
                self.context_manager.checkExitCallback()
            else:
                #if self.top.pendingFault():
                if self.top.hasPendingPageFault(tid):
                    self.lgr.debug('syscall handleExit %s HAD pending fault, do something!' % tid)


    def getBinders(self):
        return self.binders

    def getConnectors(self):
        return self.connectors

    def resetTimeofdayCount(self, tid):
        self.timeofday_count[tid] = 0

    def getTimeofdayCount(self, tid):
        return self.timeofday_count[tid]

    def stopMazeHap(self, syscall, one, exception, error_string):
        if self.stop_maze_hap is not None:
            SIM_run_alone(self.top.exitMaze, syscall)
            hap = self.stop_maze_hap
            SIM_run_alone(self.rmStopHap, hap)
            self.stop_maze_hap = None

    def stopForMazeAlone(self, syscall):
        self.stop_maze_hap = RES_hap_add_callback("Core_Simulation_Stopped", self.stopMazeHap, syscall)
        self.lgr.debug('Syscall added stopMazeHap Now stop, syscall: %s' % (syscall))
        SIM_break_simulation('automaze')

    def checkMaze(self, syscall):
        cpu, comm, tid = self.task_utils.curThread() 
        self.lgr.debug('Syscall checkMaze tid:%s in timer loop' % tid)
        #maze_exit = self.top.checkMazeReturn()
        #if False and maze_exit is not None:
        #    self.lgr.debug('mazeExit checkMaze tid:%s found existing maze exit that matches' % tid)
        #    maze_exit.mazeReturn(True)
        #else:
        if True:
            if self.top.getAutoMaze():
                SIM_run_alone(self.stopForMazeAlone, syscall)
            else:
                rprint("Tid %s seems to be in a timer loop.  Try exiting the maze? Use @cgc.exitMaze('%s').  \nOr autoMaze() to always exit.\nor noExitMaze() to not check for loops." % (tid, syscall))
                SIM_break_simulation('timer loop?')
  
    def rmModeHap(self, hap): 
        RES_hap_delete_callback_id("Core_Mode_Change", hap)
 
    def modeChanged(self, fun_arg, one, old, new):
        the_fun, arg = fun_arg
        if self.mode_hap is None:
            return
        self.lgr.debug('syscall modeChanged old %d new %d' % (old, new))
        if old == Sim_CPU_Mode_Supervisor:
            hap = self.mode_hap
            SIM_run_alone(self.rmModeHap, hap)
            self.mode_hap = None
            SIM_run_alone(the_fun, arg)
            

    def checkTimeLoop(self, callname, tid):
        if self.cpu.architecture.startswith('arm') or self.no_exit_maze:
            return
        limit = 800
        delta_limit = 0x12a05f200
        if tid not in self.timeofday_count:
            self.timeofday_count[tid] = 0
        #self.lgr.debug('checkTimeLoop tid:%s timeofday_count: %d' % (tid, self.timeofday_count[tid]))
        ''' crude measure of whether we are in a delay loop '''
        if self.timeofday_count[tid] == 0:
            self.timeofday_start_cycle[tid] = self.cpu.cycles
        self.timeofday_count[tid] = self.timeofday_count[tid] + 1
        if self.timeofday_count[tid] >= limit:
            now = self.cpu.cycles
            delta = now - self.timeofday_start_cycle[tid]
            self.lgr.debug('timeofday tid:%s count is %d, now 0x%x was 0x%x delta 0x%x' % (tid, self.timeofday_count[tid], now, self.timeofday_start_cycle[tid], delta))
            #if delta < 0x2540be40:
            if delta < delta_limit:
                self.timeofday_count[tid] = 0
                self.mode_hap = RES_hap_add_callback_obj("Core_Mode_Change", self.cpu, 0, self.modeChanged, (self.checkMaze, callname))
            else:
                self.timeofday_count[tid] = 0
                self.lgr.debug('checkTimeLoop tid:%s reset tod count' % tid)

    def isBackground(self):
        ''' Is this syscall hap watching background processes? '''
        retval = False
        if self.background_break != None:
            tid, cpu = self.context_manager.getDebugTid()
            if tid is not None:
                ''' debugging some process, and we are background.  thus we are in a different context than the process being debugged. '''
                retval = True
        return retval

    def handleReadOrSocket(self, callname, frame, exit_info):
        # Called by handleExit for calls already in the kernel.
        # TBD merge call parameter handling into common functions 
        retval = None
        the_callname = callname
        if 'ss' in frame and frame['ss'] is not None:
            ss = frame['ss']
            exit_info.old_fd = ss.fd
            exit_info.sock_struct = ss
            socket_callnum = frame['param1']
            exit_info.socket_callname = net.callname[socket_callnum].lower()
            ida_msg = 'syscall handleReadOrSocket socketcall %s ss is %s' % (exit_info.socket_callname, ss.getString())
            self.lgr.debug('syscall handleReadOrSocket setExits socket parsed: %s' % ida_msg)
            the_callname = exit_info.socket_callname
            if ss.addr is not None:
                exit_info.retval_addr = ss.addr
                self.lgr.debug('syscall handleReadOrSocket ss addr is 0x%x len is %d' % (ss.addr, ss.length))
                exit_info.count = ss.length
            if the_callname == 'recvfrom' and callname == 'socketcall':        
                addr_addr = frame['param2']+16
                src_addr = self.mem_utils.readWord32(self.cpu, addr_addr)
                if src_addr is None:
                    self.lgr.debug('syscall handleReadOrSocket got None for src addr reading from 0x%x' % addr_addr)
                else:
                    src_addr_len = self.mem_utils.readWord32(self.cpu, frame['param2']+20)
                    exit_info.fname_addr = src_addr
                    exit_info.src_addr_len = src_addr_len

        else:
            self.lgr.debug('syscall handleReadOrSocket setExits socket no ss struct, set old_fd to %d' % frame['param1'])
            exit_info.old_fd = frame['param1']

        if exit_info.old_fd is not None:
    
            retval = the_callname
            self.lgr.debug('syscall handleReadOrSocket setExists callname %s' % the_callname)
            if the_callname in ['accept', 'recv', 'recvfrom', 'read', 'recvmsg']:
                for call_param in self.call_params:
                    self.lgr.debug('syscall handleReadOrSocket subcall %s' % call_param.subcall)
                    if call_param.subcall is None or call_param.subcall == the_callname:
                        self.lgr.debug('Syscall name %s handleReadOrSocket syscall %s subcall %s call_param.match_param is %s fd is %d' % (self.name, the_callname, call_param.subcall, str(call_param.match_param), exit_info.old_fd))
                        ''' TBD why not do for any and all?'''
                        #if (call_param.subcall == 'accept' or self.name=='runToIO' or self.name=='runToInput') and (call_param.match_param < 0 or call_param.match_param == ss.fd):
                        if call_param.match_param is not None and (call_param.match_param < 0 or call_param.match_param == exit_info.old_fd):
                            self.lgr.debug('setExits set the call_params')
                            exit_info.call_params.append(call_param)
                            if call_param.match_param == exit_info.old_fd:
                                this_tid = self.top.getTID()
                                self.lgr.debug('syscall handleReadOrSocket found fd %d, this tid:%s' % (exit_info.old_fd, this_tid))
                            if self.kbuffer is not None:
                                self.lgr.debug('syscall handleReadOrSocket recv kbuffer for addr 0x%x' % exit_info.retval_addr)
                                self.kbuffer.read(exit_info.retval_addr, exit_info.count, exit_info.old_fd)
                            break
       
        else:
            self.lgr.warning('syscall setExits tid:%s has old_fd of None')
            retval = None
        return retval

    def handleSelect(self, callname, tid, comm, frame, exit_info):
            exit_info.select_info = SelectInfo(frame['param1'], frame['param2'], frame['param3'], frame['param4'], frame['param5'], 
                 self.cpu, self.mem_utils, self.lgr)

            ida_msg = '%s tid:%s (%s) %s\n' % (callname, tid, comm, exit_info.select_info.getString())
            #self.lgr.debug('handleSelect %s' % ida_msg)
            for call_param in self.call_params:
                #self.lgr.debug('handleSelect call_param %s' % str(call_param))
                #if type(call_param.match_param) is int and exit_info.select_info.hasFD(call_param.match_param) and (call_param.proc is None or call_param.proc == self.comm_cache[tid]):
                if type(call_param.match_param) is int and (call_param.proc is None or call_param.proc == self.comm_cache[tid]):
                    #self.lgr.debug('handleSelect call param found %d' % (call_param.match_param))
                    exit_info.call_params.append(call_param)
                    break

    def setExits(self, frames, origin_reset=False, context_override=None):
        ''' set exits for a list of frames, intended for tracking when syscall has already been made and the process is waiting '''
        cpu, comm, cur_tid = self.task_utils.curThread() 
        eip = self.top.getEIP()
        self.lgr.debug('setExits cur_tid: %s eip: 0x%x cycles: 0x%x' % (cur_tid, eip, self.cpu.cycles))
        for tid in frames:
            self.lgr.debug('setExits frame of tid:%s is %s cycles: 0x%x' % (tid, taskUtils.stringFromFrame(frames[tid]), self.cpu.cycles))
            if frames[tid] is None:
                continue
            pc = frames[tid]['pc']
            callnum = frames[tid]['syscall_num']
            syscall_info = SyscallInfo(self.cpu, None, True, self.trace)
            callname = self.task_utils.syscallName(callnum, False) 

            frame, exit_eip1, exit_eip2, exit_eip3 = self.getExitAddrs(pc, syscall_info, frames[tid])
            if tid == cur_tid:
                if memUtils.getCPL(cpu) != 0:
                    self.lgr.debug('sharedSyscall setExits tid:%s is current thread which is not in kernel, skip it' % tid)
                    continue   
                if eip in [exit_eip1, exit_eip2, exit_eip3]:
                    self.lgr.debug('sharedSyscall  tid:%s setExits is current thread about to exit, skip this one' % tid)
                    continue   

            exit_info = ExitInfo(self, self.cpu, tid, callnum, callname, False, frame)
            exit_info.retval_addr = frames[tid]['param2']
            exit_info.count = frames[tid]['param3']
            exit_info.old_fd = frames[tid]['param1']
            self.lgr.debug('setExits set count to param3 now 0x%x' % exit_info.count)

            the_callname = callname
            if callname == 'socketcall' or callname.upper() in net.callname:
                the_callname = self.handleReadOrSocket(callname, frames[tid], exit_info)
            elif callname in ['select','_newselect', 'pselect6']:        
                self.handleSelect(callname, tid, comm, frames[tid], exit_info)

            # See if there is a call param that matches the syscall
            for cp in self.call_params:
                if type(cp.match_param) is int:
                    if cp.match_param == exit_info.old_fd:
                        if cp.nth is not None:
                            self.lgr.debug('setExits found call param as integer our fd, cp.nth is not None it is %s' % str(cp.nth))
                            cp.count = cp.count + 1
                            if cp.count >= cp.nth:
                                self.lgr.debug('setExits found call param as integer set call params to %s' % str(cp))
                                exit_info.call_params.append(cp)
                                exit_info.matched_param = cp
                        else:
                            self.lgr.debug('setExits found call param as integer set call params to %s' % str(cp))
                            exit_info.call_params.append(cp)
                            exit_info.matched_param = cp
                 
                else:
                    exit_info.call_params.append(cp)
                     
            if len(exit_info.call_params) > 0:
                exit_info.origin_reset = origin_reset
                if exit_info.retval_addr is not None:
                    self.lgr.debug('setExits almost done for tid:%s call %d retval_addr is 0x%x' % (tid, callnum, exit_info.retval_addr))
                else:
                    self.lgr.debug('setExits almost done for tid:%s call %d retval_addr is None' % (tid, callnum))
                exit_info_name = '%s-%s-exit' % (the_callname, self.name)
                self.sharedSyscall.addExitHap(self.cell, tid, exit_eip1, exit_eip2, exit_eip3, exit_info, exit_info_name, context_override=context_override)
            else:
                self.lgr.debug('setExits no potential call_params after removing non-matching integers, NO EXIT set.')


    def addCallParams(self, call_params):
        gotone = False
        for call in call_params:
            if not self.hasCallParam(call.name):
                self.lgr.debug('syscall addCallParams %s' % call.name)
                self.call_params.append(call)
                gotone = True
        ''' TBD inconsistent stop actions????'''
        if gotone:
            if self.stop_action is None:
                f1 = stopFunction.StopFunction(self.top.skipAndMail, [], nest=False)
                flist = [f1]
                hap_clean = hapCleaner.HapCleaner(self.cpu)
                self.stop_action = hapCleaner.StopAction(hap_clean, flist=flist)
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

    def rmCallParam(self, call_param, quiet=False):
        self.lgr.debug('sycall rmCallParam syscall %s param %s' % (self.name, call_param.name))
        if call_param in self.call_params: 
            self.call_params.remove(call_param)
        elif not quiet:
            self.lgr.error('sycall rmCallParam, but param does not exist?')

    def rmCallParamName(self, call_param_name):
        return_list = []
        rm_list = []
        for cp in self.call_params:
            if cp.name == call_param_name:
                rm_list.append(cp)
            else:
                return_list.append(cp)
        for cp in rm_list:
            self.call_params.remove(cp)
        return return_list

    def getCallParams(self):
        if self.syscall_info is not None:
            return self.call_params
        else:
            return None

    def remainingDmod(self, besides):
        for call_param in self.call_params:
            if call_param.match_param.__class__.__name__ == 'Dmod' and call_param.name != besides:
                 return True
        return False

    def hasCallParam(self, param_name):
        retval = False
        for call_param in self.call_params:
            if call_param.name == param_name:
                retval = True
                break 
        return retval

    def getDmods(self):
        retval = []
        for call_param in self.call_params:
            if call_param.match_param.__class__.__name__ == 'Dmod':
                 dmod = call_param.match_param
                 if dmod not in retval:
                     retval.append(dmod)
        return retval

    def rmDmods(self):
        params_copy = list(self.call_params)
        rm_list = []
        for call_param in params_copy:
            if call_param.match_param.__class__.__name__ == 'Dmod':
                self.lgr.debug('syscall rmDmods, removing dmod %s' % call_param.match_param.path)
                rm_list.append(call_param)

        for call_param in rm_list:
            self.rmCallParam(call_param)
        if len(self.call_params) == 0:
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

    def resetHackCycle(self):
        #self.lgr.debug('syscall resetHackCycle')
        self.hack_cycle= 0
        self.linger_cycles = []

    #def stopOnExit(self):
    #    self.stop_on_exit=True
    #    self.lgr.debug('syscall stopOnExit')
    def appendRmParam(self, param):
        self.rm_param_queue.append(param)

    def rmRmParam(self, param):
        retval = False
        if param in self.rm_param_queue: 
            self.rm_param_queue.remove(param)
            retval = True
        return retval


    def checkSendParams(self, syscall_info, exit_info, ss, dest_ss, s):
            for call_param in self.call_params:
                self.lgr.debug('syscall checkSendParams subcall %s' % call_param.subcall)
                if (call_param.subcall is None or call_param.subcall in ['send', 'sendto', 'sendmsg']) and type(call_param.match_param) is int and call_param.match_param == exit_info.old_fd and (call_param.proc is None or call_param.proc == self.comm_cache[tid]):
                    #self.lgr.debug('call param found %d, matches %d' % (call_param.match_param, ss.fd))
                    exit_info.call_params.append(call_param)
                    break
                elif DEST_PORT in call_param.param_flags: 
                    if dest_ss is not None:
                        if dest_ss.port == call_param.match_param and (call_param.proc is None or call_param.proc == self.comm_cache[tid]):
                            self.lgr.debug('call param DEST_PORT found')
                            exit_info.call_params.append(call_param)
                            break
                        else:
                            self.lgr.debug('syscall no match of %d to %d in  sendto from %d' % (call_param.match_param, dest_ss.port, tid))
                    else:
                        self.lgr.debug('syscall no ss in sendto from %d' % tid)
                
                elif type(call_param.match_param) is str and (call_param.subcall in ['send', 'sendto', 'sendmsg']) and (call_param.proc is None or call_param.proc == self.comm_cache[tid]):
                    ''' look for string in output '''
                    self.lgr.debug('look in string %s' % s)
                    if call_param.match_param in s:
                        self.lgr.debug('syscall %s found match string, watch exit for param%s' % (call_param.subcall, call_param.name))
                        addParam(exit_info, call_param)

    def getIOV(self, exit_info):
        # Read data from IOV structures
        # 
        # how many iov structures will we look at? 
        limit = min(10, exit_info.count)
        iov_size = 2*self.mem_utils.WORD_SIZE
        iov_addr = exit_info.retval_addr
        # TBD better starting guess?
        remain = 2000
        self.lgr.debug('syscall getIOV %s starting remain %d iov_addr 0x%x' % (exit_info.callname, remain, iov_addr))
        trace_msg = 'FD: %d iov count: %d' % (exit_info.old_fd, exit_info.count)
        full_byte_tuple = ()
        for i in range(limit):
            base = self.mem_utils.readPtr(self.cpu, iov_addr)
            if base == 0:
                continue
            length = self.mem_utils.readPtr(self.cpu, iov_addr+self.mem_utils.WORD_SIZE)
            if remain > length:
                data_len = length
            else:
                data_len = remain
            self.lgr.debug('syscall getIOV length 0x%x  data_len 0x%x' % (length, data_len))

            max_len = min(length, 1024)
            byte_tuple = self.mem_utils.getBytes(self.cpu, max_len, base)
            if byte_tuple is not None:
                s = resimUtils.getHexDump(byte_tuple[:max_len])
                full_byte_tuple = full_byte_tuple + byte_tuple
            else:
                s = '<<NOT MAPPED>>'

            self.lgr.debug('syscall getIOV %s base: 0x%x length: %d data: %s' % (exit_info.callname, base, length, s))
            trace_msg = trace_msg+' buffer: 0x%x len: %d data: %s' % (base, length, s)
            remain = remain - data_len 
            iov_addr = iov_addr+iov_size
        trace_msg = trace_msg+'\n'
        return trace_msg, full_byte_tuple

    def noExitMaze(self):
        self.lgr.debug('syscall noExitMaze') 
        self.no_exit_maze = True
