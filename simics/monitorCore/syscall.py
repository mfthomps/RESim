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
import diddler
import sys
import copy
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

    def getSet(self, addr):
        if addr == 0:
            return "NULL"
        else:
            low, high = self.readit(addr)
            return '0x%x (0x%x:0x%x)' % (addr, low, high)

    def getString(self):
        return 'nfds: %d  readfds: %s writefds: %s exceptfds: %s timeout: 0x%x' % (self.nfds, 
              self.getSet(self.readfds), self.getSet(self.writefds), 
              self.getSet(self.exceptfds), self.timeout)

    def hasFD(self, fd):
        retval = False
        self.lgr.debug('SelectInfo hasFD test newfds %d against %d' % (fd, self.nfds))
        if fd < self.nfds:
            self.lgr.debug('SelectInfo hasFD under newfds %d' % fd)
            if self.readfds is not None:
                read_low, read_high = self.readit(self.readfds)
                if read_low is not None:
                    the_set = read_low | (read_high << 32) 
                    self.lgr.debug('the read set 0x%x' % the_set)
                    if memUtils.testBit(the_set, fd):
                        retval = True
            if self.writefds is not None:
                write_low, write_high = self.readit(self.writefds)
                if write_low is not None:
                    the_set = write_low | (write_high << 32) 
                    self.lgr.debug('the write set 0x%x' % the_set)
                    if memUtils.testBit(the_set, fd):
                        retval = True
        return retval 

class ExitInfo():
    def __init__(self, syscall_instance, cpu, pid, callnum, compat32):
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
        self.compat32 = compat32
        ''' narrow search to information about the call '''
        self.call_params = None
        self.syscall_entry = None
        self.mode_hap = None
   
        ''' who to call from sharedSyscall, e.g., to watch mmap for SO maps '''
        self.syscall_instance = syscall_instance

ROUTABLE = 1
AF_INET = 2
DEST_PORT = 3
class CallParams():
    def __init__(self, subcall, match_param, break_simulation=False):
        self.subcall = subcall
        self.match_param = match_param
        self.param_flags = []
        self.break_simulation = break_simulation
        self.nth = None
        self.count = 0

class Syscall():

    def __init__(self, top, cell_name, cell, param, mem_utils, task_utils, context_manager, traceProcs, sharedSyscall, lgr, 
                   traceMgr, call_list=None, trace = False, flist_in=None, soMap = None, 
                   call_params=[], netInfo=None, binders=None, connectors=None, stop_on_call=False, targetFS=None, skip_and_mail=True, linger=False,
                   debugging_exit=False, compat32=False, background=False, name=None): 
        self.lgr = lgr
        self.traceMgr = traceMgr
        self.mem_utils = mem_utils
        self.task_utils = task_utils
        self.context_manager = context_manager
        ''' mostly a test if we are debugging. not very clean '''
        pid, dumb, cpu = context_manager.getDebugPid()
        self.debugging = False
        self.stop_on_call = stop_on_call
        self.debugging_exit = debugging_exit
        if pid is not None or debugging_exit:
            self.debugging = True
            self.lgr.debug('Syscall is debugging cell %s' % cell_name)
        self.cpu = cpu
        self.cell = cell
        self.cell_name = cell_name
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

        if trace is None and self.traceMgr is not None:
            tf = '/tmp/syscall_trace.txt'
            #self.traceMgr.open(tf, cpu, noclose=True)
            self.traceMgr.open(tf, cpu)
       
        break_list, break_addrs = self.doBreaks(compat32, background)
 
        if self.debugging and not self.breakOnExecve() and not trace and skip_and_mail:
            hap_clean = hapCleaner.HapCleaner(cpu)
            for ph in self.proc_hap:
                hap_clean.add("Core_Breakpoint_Memop", ph)
            f1 = stopFunction.StopFunction(self.top.skipAndMail, [], nest=False)
            flist = [f1]
            self.stop_action = hapCleaner.StopAction(hap_clean, break_list, flist, break_addrs = break_addrs)
            self.lgr.debug('Syscall cell %s stop action includes skipAndMail in flist. SOMap exists: %r name: %s' % (self.cell_name, (soMap is not None), name))
        elif flist_in is not None:
            hap_clean = hapCleaner.HapCleaner(cpu)
            for ph in self.proc_hap:
                hap_clean.add("Core_Breakpoint_Memop", ph)
            self.stop_action = hapCleaner.StopAction(hap_clean, break_list, flist_in, break_addrs = break_addrs)
            self.lgr.debug('Syscall cell %s stop action includes given flist.  stop_on_call is %r name: %s' % (self.cell_name, stop_on_call, name))
        else:
            hap_clean = hapCleaner.HapCleaner(cpu)
            for ph in self.proc_hap:
                hap_clean.add("Core_Breakpoint_Memop", ph)
            self.stop_action = hapCleaner.StopAction(hap_clean, break_list, [], break_addrs = break_addrs)
            self.lgr.debug('Syscall cell %s stop action includes NO flist name: %s' % (self.cell_name, name))

        self.exit_calls = []
        self.exit_calls.append('exit_group')
        self.exit_calls.append('exit')
        self.exit_calls.append('tkill')
        self.exit_calls.append('tgkill')

    def breakOnExecve(self):
        for call in self.call_params:
            if call.subcall == 'execve' and call.break_simulation:
                return True
        return False

    def stopAlone(self, msg):
        ''' NOTE: this is also called by sharedSyscall '''
        eip = self.top.getEIP()
        if self.stop_action is not None:
            self.stop_action.setExitAddr(eip)
        self.stop_hap = SIM_hap_add_callback("Core_Simulation_Stopped", 
            	     self.stopHap, self.stop_action)
        self.lgr.debug('Syscall stopAlone cell %s added stopHap %d Now stop. msg: %s' % (self.cell_name, self.stop_hap, msg))
        SIM_break_simulation(msg)

    def doBreaks(self, compat32, background):
        break_list = []
        break_addrs = []
        self.timeofday_count = {}
        self.timeofday_start_cycle = {}
        self.lgr.debug('syscall cell %s doBreaks.  compat32: %r reset timeofdaycount' % (self.cell_name, compat32))
        if self.call_list is None:
            ''' trace all calls '''
            if self.cpu.architecture == 'arm':
                #phys = self.mem_utils.v2p(self.cpu, self.param.arm_entry)
                self.lgr.debug('Syscall arm no callnum, set break at 0x%x ' % (self.param.arm_entry))
                proc_break = self.context_manager.genBreakpoint(self.cell, Sim_Break_Linear, Sim_Access_Execute, self.param.arm_entry, 1, 0)
                #proc_break = self.context_manager.genBreakpoint(self.cpu.physical_memory, Sim_Break_Physical, Sim_Access_Execute, phys, 1, 0)
                break_addrs.append(self.param.arm_entry)
                syscall_info = SyscallInfo(self.cpu, None, None, None, self.trace)
                self.proc_hap.append(self.context_manager.genHapIndex("Core_Breakpoint_Memop", self.syscallHap, syscall_info, proc_break, 'syscall'))
            else:
                syscall_info = SyscallInfo(self.cpu, None, None, None, self.trace)

                if self.param.sysenter is not None:
                    if self.param.sys_entry is not None and self.param.sys_entry != 0:
                        proc_break = self.context_manager.genBreakpoint(self.cell, Sim_Break_Linear, Sim_Access_Execute, self.param.sysenter, 1, 0)
                        break_addrs.append(self.param.sysenter)
                        break_list.append(proc_break)
                        if self.param.sys_entry is not None and self.param.sys_entry != 0:
                            self.lgr.debug('Syscall no callnum, set sysenter and sys_entry break at 0x%x & 0x%x' % (self.param.sysenter, self.param.sys_entry))
                            proc_break1 = self.context_manager.genBreakpoint(self.cell, Sim_Break_Linear, Sim_Access_Execute, self.param.sys_entry, 1, 0)
                            break_addrs.append(self.param.sys_entry)
                            break_list.append(proc_break1)
                            self.proc_hap.append(self.context_manager.genHapRange("Core_Breakpoint_Memop", self.syscallHap, syscall_info, proc_break, proc_break1, 'syscall'))
                        else:
                            self.lgr.debug('Syscall no callnum, set sysenter break at 0x%x ' % (self.param.sysenter))
                            self.proc_hap.append(self.context_manager.genHapIndex("Core_Breakpoint_Memop", self.syscallHap, syscall_info, proc_break, 'syscall'))
                elif self.param.sys_entry is not None and self.param.sys_entry != 0:
                        self.lgr.debug('Syscall no callnum, set sys_entry break at 0x%x' % (self.param.sys_entry))
                        proc_break1 = self.context_manager.genBreakpoint(self.cell, Sim_Break_Linear, Sim_Access_Execute, self.param.sys_entry, 1, 0)
                        break_addrs.append(self.param.sys_entry)
                        break_list.append(proc_break1)
                        self.proc_hap.append(self.context_manager.genHapIndex("Core_Breakpoint_Memop", self.syscallHap, syscall_info, proc_break1, 'syscall'))
                if self.param.compat_32_entry is not None and self.param.compat_32_entry != 0:
                    ''' support 32 bit compatability '''
                    newcall_info = copy.copy(syscall_info)
                    newcall_info.compat32 = True
                    self.lgr.debug('Syscall no callnum, compat32 break at 0x%x and 0x%x' % (self.param.compat_32_entry, self.param.compat_32_int128))
                    proc_break1 = self.context_manager.genBreakpoint(self.cell, Sim_Break_Linear, Sim_Access_Execute, self.param.compat_32_entry, 1, 0)
                    break_addrs.append(self.param.compat_32_entry)
                    break_list.append(proc_break1)
                    proc_break2 = self.context_manager.genBreakpoint(self.cell, Sim_Break_Linear, Sim_Access_Execute, self.param.compat_32_int128, 1, 0)
                    break_addrs.append(self.param.compat_32_int128)
                    break_list.append(proc_break2)
                    self.proc_hap.append(self.context_manager.genHapRange("Core_Breakpoint_Memop", self.syscallHap, newcall_info, proc_break1, proc_break2, 'syscall32'))
        else:
            ''' will stop within the kernel at the computed entry point '''
            for call in self.call_list:
                # TBD fix for compat 32
                callnum = self.task_utils.syscallNumber(call, compat32)
                if callnum is not None and callnum < 0:
                    self.lgr.error('Syscall bad call number %d' % callnum)
                    return None, None
                entry = self.task_utils.getSyscallEntry(callnum, compat32)
                #phys = self.mem_utils.v2p(cpu, entry)
                #proc_break = self.context_manager.genBreakpoint(self.cpu.physical_memory, Sim_Break_Physical, Sim_Access_Execute, phys, 1, 0)
                syscall_info = SyscallInfo(self.cpu, None, callnum, entry, self.trace, self.call_params)
                syscall_info.compat32 = compat32
                if not background:
                    self.lgr.debug('Syscall callnum %s name %s entry 0x%x compat32: %r' % (callnum, call, entry, compat32))
                    proc_break = self.context_manager.genBreakpoint(self.cell, Sim_Break_Linear, Sim_Access_Execute, entry, 1, 0)
                    proc_break1 = None
                    break_list.append(proc_break)
                    break_addrs.append(entry)
                    self.proc_hap.append(self.context_manager.genHapIndex("Core_Breakpoint_Memop", self.syscallHap, syscall_info, proc_break, call))
                else:
                    self.lgr.debug('doBreaks set background break at 0x%x' % entry)
                    self.background_break = SIM_breakpoint(self.cell, Sim_Break_Linear, Sim_Access_Execute, entry, 1, 0)
                    self.background_hap = SIM_hap_add_callback_index("Core_Breakpoint_Memop", self.syscallHap, syscall_info, self.background_break)

        return break_list, break_addrs
        
    def frameFromStackSyscall(self):
        reg_num = self.cpu.iface.int_register.get_number(self.mem_utils.getESP())
        esp = self.cpu.iface.int_register.read(reg_num)
        regs_addr = esp + self.mem_utils.WORD_SIZE
        #self.lgr.debug('frameFromStackSyscall regs_addr is 0x%x  ' % (regs_addr))
        frame = self.task_utils.getFrame(regs_addr, self.cpu)
        return frame

    def stopTrace(self, immediate=False):
        #self.lgr.debug('syscall stopTrace call_list %s' % str(self.call_list))
        proc_copy = list(self.proc_hap)
        for ph in proc_copy:
            self.lgr.debug('syscall stopTrace, delete self.proc_hap %d' % ph)
            self.context_manager.genDeleteHap(ph, immediate=immediate)
            self.proc_hap.remove(ph)

        if self.top is not None and not self.top.remainingCallTraces():
            self.sharedSyscall.stopTrace()

        for pid in self.first_mmap_hap:
            #self.lgr.debug('syscall stopTrace, delete mmap hap pid %d' % pid)
            self.context_manager.genDeleteHap(self.first_mmap_hap[pid], immediate=immediate)
        self.first_mmap_hap = {}

        if self.stop_hap is not None:
            SIM_hap_delete_callback_id("Core_Simulation_Stopped", self.stop_hap)
            self.stop_hap = None

        if self.background_break is not None:
            SIM_delete_breakpoint(self.background_break)
            SIM_hap_delete_callback_id("Core_Breakpoint_Memop", self.background_hap)
            self.background_break = None
            self.background_hap = None

        if self.top is not None and self.call_list is not None:
            for callname in self.call_list:
                self.top.rmCallTrace(self.cell_name, callname)
        ''' reset SO map tracking ''' 
        self.sharedSyscall.trackSO(True)
        self.bang_you_are_dead = True
        self.lgr.debug('syscall stopTrace return')
       
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
        callname = self.task_utils.syscallName(syscall_info.callnum, syscall_info.compat32)
        if self.mem_utils.WORD_SIZE == 4: 
            ida_msg = 'firstMmapHap %s pid:%d FD: %d buf: 0x%x len: %d  File FD was %d' % (callname, pid, frame['param3'], frame['param1'], frame['param2'], 
                  syscall_info.fd)
        else:
            ida_msg = 'firstMmapHap %s pid:%d FD: %d buf: 0x%x len: %d offset: 0x%x  File FD was %d' % (callname, pid, 
               frame['param5'], frame['param1'], frame['param2'], frame['param6'], syscall_info.fd)

        self.lgr.debug(ida_msg)
        if self.traceMgr is not None:
            self.traceMgr.write(ida_msg+'\n')
        syscall_info.call_count = syscall_info.call_count+1
        #self.lgr.debug('firstMmapHap delete self?')
        self.context_manager.genDeleteHap(self.first_mmap_hap[pid])
        del self.first_mmap_hap[pid]
        syscall_info.call_count = syscall_info.call_count+1
        exit_info = ExitInfo(self, cpu, pid, syscall_info.callnum, syscall_info.compat32)
        exit_info.fname = syscall_info.fname
        exit_info.count = frame['param2']
        exit_info.syscall_entry = self.mem_utils.getRegValue(self.cpu, 'pc')
        name = 'firstMmap exit'
        try:
            ''' backward compatibility '''
            sysret64 = self.param.sysret64
        except AttributeError:
            sysret64 = None
        if cpu.architecture == 'arm':
            self.sharedSyscall.addExitHap(pid, self.param.arm_ret, None, None, exit_info, self.traceProcs, name)
        else:
            self.sharedSyscall.addExitHap(pid, self.param.sysexit, self.param.iretd, sysret64, exit_info, self.traceProcs, name)

    def watchFirstMmap(self, pid, fname, fd, compat32):
        if self.mem_utils.WORD_SIZE == 4:
            callnum = self.task_utils.syscallNumber('mmap2', compat32)
        else:
            callnum = self.task_utils.syscallNumber('mmap', compat32)
        if callnum < 0:
            self.lgr.error('watchFirstMmap failed to find mmap2 call from syscallNumber module')
            return
        entry = self.task_utils.getSyscallEntry(callnum, compat32)
        #self.lgr.debug('watchFirstMmap callnum is %s entry 0x%x' % (callnum, entry))
        proc_break = self.context_manager.genBreakpoint(self.cell, Sim_Break_Linear, Sim_Access_Execute, entry, 1, 0)
        syscall_info = SyscallInfo(self.cpu, pid, callnum, entry, True)
        syscall_info.fname = fname
        syscall_info.pid = pid
        syscall_info.fd = fd
        if pid in self.first_mmap_hap:
            self.context_manager.genDeleteHap(self.first_mmap_hap[pid])
            del self.first_mmap_hap[pid]
        self.first_mmap_hap[pid] = self.context_manager.genHapIndex("Core_Breakpoint_Memop", self.firstMmapHap, syscall_info, proc_break, 'watchFirstMmap')
        
    def parseOpen(self, frame, callname):
        self.lgr.debug('parseOpen for %s' % callname)
        if callname == 'openat':
            fname_addr = frame['param2']
            flags = frame['param3']
            mode = frame['param4']
        else:
            fname_addr = frame['param1']
            flags = frame['param2']
            mode = frame['param3']
        fname = self.mem_utils.readString(self.cpu, fname_addr, 256)
        if fname is not None:
            try:
                fname.decode('ascii')
            except:
                SIM_break_simulation('non-ascii fname at 0x%x %s' % (fname_addr, fname))
                return None, None, None, None, None
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

    def fnamePhysAlone(self, (pid, fname_addr, exit_info)):
        self.finish_break[pid] = SIM_breakpoint(self.cpu.physical_memory, Sim_Break_Physical, Sim_Access_Write, fname_addr, 1, 0)
        self.finish_hap[pid] = SIM_hap_add_callback_index("Core_Breakpoint_Memop", self.finishParseOpen, exit_info, self.finish_break[pid])

    def fnameTable (self, exit_info, third, forth, memory):
        ''' only used with 64-bit IA32E paging '''
        cpu, comm, pid = self.task_utils.curProc() 
        if pid not in self.finish_hap_table:
            return
        SIM_delete_breakpoint(self.finish_break[pid])
        SIM_hap_delete_callback_id("Core_Breakpoint_Memop", self.finish_hap_table[pid])
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
        self.finish_hap_page[pid] = SIM_hap_add_callback_index("Core_Breakpoint_Memop", self.fnamePage, exit_info, self.finish_break[pid])


    def fnamePage(self, exit_info, third, forth, memory):
        ''' only used with 64-bit IA32E paging '''
        cpu, comm, pid = self.task_utils.curProc() 
        if pid not in self.finish_hap_page:
            return
        SIM_delete_breakpoint(self.finish_break[pid])
        SIM_hap_delete_callback_id("Core_Breakpoint_Memop", self.finish_hap_page[pid])
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
        self.lgr.debug('finishParseOpen pid %d' % pid)
        if cpu != exit_info.cpu or pid != exit_info.pid:
            return
        if pid not in self.finish_hap:
            return
        exit_info.fname = self.mem_utils.readString(self.cpu, exit_info.fname_addr, 256)
        if exit_info.fname is not None:
            self.lgr.debug('finishParseOpen pid %d got fid %s' % (pid, exit_info.fname))
            SIM_hap_delete_callback_id("Core_Breakpoint_Memop", self.finish_hap[pid])
            SIM_delete_breakpoint(self.finish_break[pid])
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
                text_segment = elfText.getText(full_path, self.lgr)
                if text_segment is not None:
                    if self.soMap is not None:
                        if text_segment.address is not None:
                            self.lgr.debug('syscall addElf 0x%x - 0x%x' % (text_segment.address, text_segment.address+text_segment.size))       
                            self.context_manager.recordText(text_segment.address, text_segment.address+text_segment.size)
                            self.soMap.addText(text_segment.address, text_segment.size, prog_string, pid)
                        else:
                            self.lgr.error('addElf got text segment but no text, unexpected.  pid %d' % pid)
                else:
                    self.lgr.debug('syscall addElf, no text segment found, advise SO we have an exec, but no starting map')
                    if self.soMap is not None:
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
        SIM_hap_delete_callback_id("Core_Breakpoint_Memop", self.finish_hap[pid])
        SIM_delete_breakpoint(self.finish_break[pid])
        del self.finish_hap[pid]
        del self.finish_break[pid]
        self.checkExecve(prog_string, arg_string_list, call_info.pid)



    def checkExecve(self, prog_string, arg_string_list, pid):
        self.lgr.debug('checkExecve %s' % prog_string)
        cp = None
        for call in self.call_params:
            if call.subcall == 'execve':
                cp = call
                break
        
            
        if cp is not None: 
            if cp.match_param.__class__.__name__ == 'Diddler':
               self.task_utils.modExecParam(pid, self.cpu, cp.match_param)
            else: 

                if '/' in cp.match_param:
                    ''' compare full path '''
                    base = prog_string
                else:
                    base = os.path.basename(prog_string)
                #self.lgr.debug('checkExecve base %s against %s' % (base, cp.match_param))
                if base.startswith(cp.match_param):
                    ''' is program file we are looking for.  do we care if it is a binary? '''
                    wrong_type = False
                    if self.traceProcs is not None:
                        ftype = self.traceProcs.getFileType(pid)
                        if ftype is None:
                            full_path = self.targetFS.getFull(prog_string, self.lgr)
                            if os.path.isfile(full_path):
                                ftype = magic.from_file(full_path)
                                if ftype is None:
                                    self.lgr.error('checkExecve failed to find file type for %s pid %d' % (prog_string, pid))
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
        cpu, comm, pid = self.task_utils.curProc() 
        ''' allows us to ignore internal kernel syscalls such as close socket on exec '''
        at_enter = True
        if syscall_info.calculated is not None:
            at_enter = False
        prog_string, arg_string_list = self.task_utils.getProcArgsFromStack(pid, at_enter, cpu)
        self.lgr.debug('parseExecve len of arg_string_list %d' % len(arg_string_list))
          
        pid_list = self.context_manager.getThreadPids()
        db_pid, dumb, dumbcpu = self.context_manager.getDebugPid()
        if pid in pid_list and pid != db_pid:
            self.lgr.debug('syscall parseExecve remove %d from list being watched.' % (pid))
            self.context_manager.rmTask(pid)
        
        if prog_string is None:
            ''' prog string not in ram, break on kernel read of the address and then read it '''
            prog_addr = self.task_utils.getExecProgAddr(pid, cpu)
            call_info = SyscallInfo(cpu, pid, None, None, None)
            self.lgr.debug('parseExecve pid:%d prog string missing, set break on 0x%x' % (pid, prog_addr))
            if prog_addr == 0:
                self.lgr.error('parseExecve zero prog_addr pid %d' % pid)
                SIM_break_simulation('parseExecve zero prog_addr pid %d' % pid)
            self.finish_break[pid] = SIM_breakpoint(cpu.current_context, Sim_Break_Linear, Sim_Access_Read, prog_addr, 1, 0)
            self.finish_hap[pid] = SIM_hap_add_callback_index("Core_Breakpoint_Memop", self.finishParseExecve, call_info, self.finish_break[pid])
            
            return
        nargs = min(4, len(arg_string_list))
        arg_string = ''
        for i in range(nargs):
            if is_ascii(arg_string_list[i]):
                arg_string += arg_string_list[i]+' '
            else:
                break
        ida_msg = 'execve prog: %s %s  pid:%d' % (prog_string, arg_string, pid)
        self.lgr.debug(ida_msg)
        if self.traceMgr is not None:
            self.traceMgr.write(ida_msg+'\n')
        if self.traceProcs is not None:
            self.traceProcs.setName(pid, prog_string, arg_string)

        self.addElf(prog_string, pid)

        if self.netInfo is not None:
            self.netInfo.checkNet(prog_string, arg_string)
        self.checkExecve(prog_string, arg_string_list, pid)

        return prog_string


    def socketParse(self, callname, syscall_info, frame, exit_info, pid):
        ss = None
        if callname == 'socketcall':        
            ''' must be 32-bit get params from struct '''
            ida_msg = None
            socket_callnum = frame['param1']
            self.lgr.debug('socketParse socket_callnum is %d' % socket_callnum)
            #if syscall_info.compat32:
            #    SIM_break_simulation('socketcall')
            socket_callname = net.callname[socket_callnum].lower()
            exit_info.socket_callname = socket_callname
            if socket_callname != 'socket' and socket_callname != 'setsockopt':
                ss = net.SockStruct(self.cpu, frame['param2'], self.mem_utils)
        else:
            ''' callname is the socket function '''
            socket_callname = callname
            self.lgr.debug('syscall socketParse call %s param1 0x%x param2 0x%x' % (callname, frame['param1'], frame['param2']))
            if callname != 'socket':
                ss = net.SockStruct(self.cpu, frame['param2'], self.mem_utils, fd=frame['param1'], length=frame['param3'])
                self.lgr.debug('socketParse ss %s  param2: 0x%x' % (ss.getString(), frame['param1']))
        exit_info.sock_struct = ss

        if socket_callname == 'socket':
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
                except:
                    self.lgr.debug('sharedSyscall doSocket could not get type string from type 0x%x full 0x%x' % (sock_type, sock_type_full))
                    ida_msg = '%s - %s pid:%d domain: 0x%x type: %d protocol: 0x%x' % (callname, socket_callname, pid, domain, sock_type, protocol)
        elif socket_callname == 'connect':
            ida_msg = '%s - %s pid:%d %s %s  param at: 0x%x' % (callname, socket_callname, pid, ss.getString(), ss.addressInfo(), frame['param2'])
            for call_param in syscall_info.call_params:
                self.lgr.debug('check for match subcall %s' % call_param.subcall)
                if call_param.subcall == 'connect':
                     if call_param.match_param is not None and ss.port is not None:
                         ''' look to see if this address matches a given pattern '''
                         s = ss.dottedPort()
                         pat = call_param.match_param
                         self.lgr.debug('socketParse look for match %s %s' % (pat, s))
                         try:
                             go = re.search(pat, s, re.M|re.I)
                         except:
                             self.lgr.error('invalid expression: %s' % pat)
                             return
                         if len(call_param.match_param.strip()) == 0 or go: 
                             self.lgr.debug('socketParse found match %s %s' % (pat, s))
                             if call_param.nth is not None:
                                 call_param.count = call_param.count + 1
                                 if call_param.count >= call_param.nth:
                                     exit_info.call_params = call_param
                                     ida_msg = 'Connect to %s, FD: %d count: %d' % (s, ss.fd, call_param.count)
                                     self.context_manager.setIdaMessage(ida_msg)
                             else:
                                 exit_info.call_params = call_param
                                 ida_msg = 'Connect to %s, FD: %d' % (s, ss.fd)
                                 self.context_manager.setIdaMessage(ida_msg)
                             break
                     elif ROUTABLE in call_param.param_flags and ss.isRoutable():
                         self.lgr.debug('socketParse routable in flags and is routable')
                         exit_info.call_params = call_param
            if self.traceProcs is not None and ss.isRoutable(): 
                prog = self.traceProcs.getProg(pid)
                self.lgr.debug('adding connector for pid:%d %s %s %s' % (pid, prog, ss.dottedIP(), str(ss.port)))
                self.connectors.add(pid, prog, ss.dottedIP(), ss.port)
              
        elif socket_callname == 'bind':
            ida_msg = '%s - %s pid:%d socket_string: %s' % (callname, socket_callname, pid, ss.getString())
            #if ss.famName() == 'AF_CAN':
            #    frame_string = taskUtils.stringFromFrame(frame)
            #    self.lgr.debug('bind params %s' % frame_string)
            #    SIM_break_simulation('bind')
            
            for call_param in syscall_info.call_params:
                if call_param.subcall == 'bind':
                     if call_param.match_param is not None and ss.port is not None:
                         ''' look to see if this address matches a given pattern '''
                         s = ss.dottedPort()
                         pat = call_param.match_param
                         go = re.search(pat, s, re.M|re.I)
                         
                         #self.lgr.debug('socketParse look for match %s %s' % (pat, s))
                         if len(call_param.match_param.strip()) == 0 or go: 
                             self.lgr.debug('socketParse found match %s %s' % (pat, s))
                             exit_info.call_params = call_param
                             ida_msg = 'BIND to %s, FD: %d' % (s, ss.fd)
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

        elif socket_callname == 'accept':
            phys = self.mem_utils.v2p(self.cpu, ss.addr)
            ida_msg = '%s - %s pid:%d FD: %d addr:0x%x len_addr:0x%x  phys_addr:0x%x' % (callname, socket_callname, pid, ss.fd, ss.addr, ss.length, phys)
            #exit_info.call_params = self.sockwatch.getParam(pid, ss.fd)
            for call_param in syscall_info.call_params:
                if call_param.subcall == 'accept' and (call_param.match_param < 0 or call_param.match_param == ss.fd):
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
                exit_info.fname_addr = src_addr
                exit_info.count = src_addr_len
                ida_msg = '%s - %s pid:%d FD: %d len: %d' % (callname, socket_callname, pid, ss.fd, ss.length)
                #if source_ss.famName() == 'AF_CAN':
                #    frame_string = taskUtils.stringFromFrame(frame)
                #    print(frame_string)
                #    SIM_break_simulation(ida_msg)
            else:
                ida_msg = '%s - %s pid:%d FD: %d len: %d %s' % (callname, socket_callname, pid, ss.fd, ss.length, ss.getString())
            for call_param in syscall_info.call_params:
                if (call_param.subcall is None or call_param.subcall == 'recv') and type(call_param.match_param) is int and call_param.match_param == ss.fd:
                    exit_info.call_params = call_param
                    break
        elif socket_callname == "recvmsg": 
            
            if self.mem_utils.WORD_SIZE==8 and not syscall_info.compat32:
                exit_info.old_fd = frame['param1']
                exit_info.retval_addr = frame['param2']
                msghdr = net.Msghdr(self.cpu, self.mem_utils, frame['param2'])
                ida_msg = '%s - %s pid:%d FD: %d msghdr: 0x%x %s' % (callname, socket_callname, pid, exit_info.old_fd, frame['param2'], msghdr.getString())
            else:
                params = frame['param2']
                exit_info.old_fd = self.mem_utils.readWord32(self.cpu, params)
                msg_hdr_ptr = self.mem_utils.readWord32(self.cpu, params+4)
                exit_info.retval_addr = msg_hdr_ptr
                msghdr = net.Msghdr(self.cpu, self.mem_utils, msg_hdr_ptr)
                ida_msg = '%s - %s pid:%d FD: %d msghdr: 0x%x %s' % (callname, socket_callname, pid, exit_info.old_fd, msg_hdr_ptr, msghdr.getString())
            exit_info.call_params = self.sockwatch.getParam(pid, exit_info.old_fd)

            for call_param in syscall_info.call_params:
                if (call_param.subcall is None or call_param.subcall == 'recvmsg') and type(call_param.match_param) is int and call_param.match_param == frame['param1']:
                    exit_info.call_params = call_param
                    break
                elif type(call_param.match_param) is str and call_param.subcall == 'recvmsg':
                    self.lgr.debug('syscall %s watch exit for call_param %s' % (socket_callname, call_param.match_param))
                    exit_info.call_params = call_param
                    break
            
        elif socket_callname == "send" or socket_callname == "sendto" or \
                     socket_callname == "sendmsg": 
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
                if (call_param.subcall is None or call_param.subcall == 'send') and type(call_param.match_param) is int and call_param.match_param == ss.fd:
                    self.lgr.debug('call param found %d, matches %d' % (call_param.match_param, ss.fd))
                    exit_info.call_params = call_param
                    break
                elif DEST_PORT in call_param.param_flags: 
                    if dest_ss is not None:
                        if str(dest_ss.port) == call_param.match_param:
                            self.lgr.debug('call param DEST_PORT found')
                            exit_info.call_params = call_param
                            break
                        else:
                            self.lgr.debug('syscall no match of %s to %s in  sendto from %d' % (call_param.match_param, str(dest_ss.port), pid))
                    else:
                        self.lgr.debug('syscall no ss in sendto from %d' % pid)
                
                elif type(call_param.match_param) is str and (call_param.subcall == 'send' or call_param.subcall == 'sendto'):
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

    def syscallParse(self, callnum, callname, frame, cpu, pid, comm, syscall_info):
        exit_info = ExitInfo(self, cpu, pid, callnum, syscall_info.compat32)
        exit_info.syscall_entry = self.mem_utils.getRegValue(self.cpu, 'pc')
        ida_msg = None
        self.lgr.debug('syscallParse pid:%d callname <%s>' % (pid, callname))
        if callname == 'open' or callname == 'openat':        
            self.lgr.debug('syscallParse, yes is %s' % callname)
            exit_info.fname, exit_info.fname_addr, exit_info.flags, exit_info.mode, ida_msg = self.parseOpen(frame, callname)
            if exit_info.fname is None:
                if exit_info.fname_addr is None:
                    self.lgr.debug('exit_info.fname_addr is none')
                    return
                ''' filename not yet present in ram, do the two step '''
                ''' TBD think we are triggering off kernel's own read of the fname, then again someitme it seems corrupted...'''
                ''' Do not use context manager on superstition that filename could be read in some other task context.'''
                
                if self.mem_utils.WORD_SIZE == 4:
                    self.lgr.debug('syscallParse, open pid %d filename not yet here... set break at 0x%x ' % (pid, exit_info.fname_addr))
                    self.finish_break[pid] = SIM_breakpoint(cpu.current_context, Sim_Break_Linear, Sim_Access_Read, exit_info.fname_addr, 1, 0)
                    self.finish_hap[pid] = SIM_hap_add_callback_index("Core_Breakpoint_Memop", self.finishParseOpen, exit_info, self.finish_break[pid])
                else:
                    if pageUtils.isIA32E(cpu):
                        ptable_info = pageUtils.findPageTableIA32E(cpu, exit_info.fname_addr, self.lgr)
                        if not ptable_info.ptable_exists:
                            self.lgr.debug('syscallParse, open pid %d filename not yet here... set ptable break at 0x%x ' % (pid, ptable_info.table_addr))
                            self.finish_break[pid] = SIM_breakpoint(cpu.physical_memory, Sim_Break_Physical, Sim_Access_Write, ptable_info.table_addr, 1, 0)
                            self.finish_hap_table[pid] = SIM_hap_add_callback_index("Core_Breakpoint_Memop", self.fnameTable, exit_info, self.finish_break[pid])
                        elif not ptable_info.page_exists:
                            self.lgr.debug('syscallParse, open pid %d filename not yet here... set page break at 0x%x ' % (pid, ptable_info.page_addr))
                            self.finish_break[pid] = SIM_breakpoint(cpu.physical_memory, Sim_Break_Physical, Sim_Access_Write, ptable_info.page_addr, 1, 0)
                            self.finish_hap_page[pid] = SIM_hap_add_callback_index("Core_Breakpoint_Memop", self.fnamePage, exit_info, self.finish_break[pid])
                        
                #SIM_break_simulation('fname is none...')
            else:
                for call_param in syscall_info.call_params:
                    if type(call_param.match_param) is str:
                        self.lgr.debug('syscall open, found match_param %s' % call_param.match_param)
                        exit_info.call_params = call_param
                        break

        if callname == 'mkdir':        
            exit_info.fname, exit_info.fname_addr, exit_info.flags, exit_info.mode, ida_msg = self.parseOpen(frame, callname)
            if exit_info.fname is None:
                ''' filename not yet present in ram, do the two step '''
                ''' TBD think we are triggering off kernel's own read of the fname, then again someitme it seems corrupted...'''
                ''' Do not use context manager on superstition that filename could be read in some other task context.'''
                self.lgr.debug('syscallParse, mkdir pid %d filename not yet here... set break at 0x%x ' % (pid, exit_info.fname_addr))
                self.finish_break[pid] = SIM_breakpoint(cpu.current_context, Sim_Break_Linear, Sim_Access_Read, exit_info.fname_addr, 1, 0)
                self.finish_hap[pid] = SIM_hap_add_callback_index("Core_Breakpoint_Memop", self.finishParseOpen, exit_info, self.finish_break[pid])

        elif callname == 'execve':        
            retval = self.parseExecve(syscall_info)
        elif callname == 'close':        
            fd = frame['param1']
            if self.traceProcs is not None:
                #self.lgr.debug('syscallparse for close pid %d' % pid)
                self.traceProcs.close(pid, fd)
            exit_info.old_fd = fd
            exit_info.call_params = self.sockwatch.getParam(pid, fd)
            self.sockwatch.close(pid, fd)

            for call_param in syscall_info.call_params:
                if call_param.match_param == frame['param1']:
                    self.lgr.debug('closed fd %d, stop trace' % fd)
                    self.stopTrace()
                    ida_msg = 'Closed FD %d' % fd
                    exit_info.call_params = call_param
                    break 

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
                    if call_param.count >= call_param.nth:
                        exit_info.call_params = call_param
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
                if call_param.match_param == fd:
                    exit_info.call_params = call_param
                    break

        elif callname == 'gettimeofday':        
            timeval_ptr = frame['param1']
            ida_msg = 'gettimeofday pid:%d timeval_ptr: 0x%x' % (pid, timeval_ptr)
            exit_info.retval_addr = timeval_ptr
 
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

        elif callname == '_llseek':        
            low = None
            if self.mem_utils.WORD_SIZE == 4:
                fd = frame['param1']
                high = frame['param2']
                low = frame['param3']
                result =  frame['param4']
                whence = frame['param5']
                ida_msg = '_llseek pid:%d FD: %d high: 0x%x low: 0x%x result: 0x%x whence: 0x%x \n%s' % (pid, fd, high, low, 
                        result, whence, taskUtils.stringFromFrame(frame))
                exit_info.retval_addr = result
            else:
                fd = frame['param1']
                offset = frame['param2']
                origin = frame['param3']
                ida_msg = 'lseek pid:%d FD: %d offset: 0x%x origin: 0x%x' % (pid, fd, offset, origin)

            exit_info.old_fd = fd
            for call_param in syscall_info.call_params:
                #self.lgr.debug('llseek call_params class is %s' % call_param.match_param.__class__.__name__)
                if call_param.match_param.__class__.__name__ == 'DiddleSeek':
                    if pid == call_param.match_param.pid and fd == call_param.match_param.fd:
                        self.lgr.debug('syscall llseek would adjust by %d' % call_param.match_param.delta)
                        ''' assume seek cur, moving backwards, so negate the delta Assumes 32-bit x86?'''
                        if low is None:
                            self.lgr.error('syscall llseek diddle no low offset in frame ')
                        else:
                            new_value = low + call_param.match_param.delta
                            self.mem_utils.setRegValue(self.cpu, 'param3', new_value)
                            esp = self.mem_utils.getRegValue(self.cpu, 'esp')
                            self.mem_utils.writeWord(self.cpu, esp+3*self.mem_utils.WORD_SIZE, new_value)
                            #SIM_break_simulation('wrote 0x%x to param3' % new_value)
                        self.stopTrace()
                elif call_param.match_param == frame['param1']:
                    exit_info.call_params = call_param
                    break

        elif callname == 'read':        
            exit_info.old_fd = frame['param1']
            ida_msg = 'read pid:%d (%s) FD: %d buf: 0x%x count: %d' % (pid, comm, frame['param1'], frame['param2'], frame['param3'])
            exit_info.retval_addr = frame['param2']
            exit_info.count = frame['param3']
            ''' check runToIO '''
            for call_param in syscall_info.call_params:
                ''' look for matching FD '''
                if type(call_param.match_param) is int:
                    if call_param.match_param == frame['param1']:
                        exit_info.call_params = call_param
                        break
                elif call_param.match_param.__class__.__name__ == 'Diddler':
                    ''' handle read diddle during syscall return '''
                    exit_info.call_params = call_param
                    break

        elif callname == 'write':        
            exit_info.old_fd = frame['param1']
            count = frame['param3']
            ida_msg = 'write pid:%d FD: %d buf: 0x%x count: %d' % (pid, frame['param1'], frame['param2'], count)
            exit_info.retval_addr = frame['param2']
            ''' check runToIO '''
            for call_param in syscall_info.call_params:
                if type(call_param.match_param) is int and call_param.match_param == frame['param1']:
                    self.lgr.debug('call param found %d, matches %d' % (call_param.match_param, frame['param1']))
                    exit_info.call_params = call_param
                    break
                elif type(call_param.match_param) is str:
                    self.lgr.debug('write match param for pid:%d is string, add to exit info' % pid)
                    exit_info.call_params = call_param
                    break
                elif call_param.match_param.__class__.__name__ == 'Diddler':
                    if count < 4028:
                        self.lgr.debug('syscall write check diddler count %d' % count)
                        diddler = exit_info.call_params.match_param
                        if diddler.checkString(self.cpu, frame['param2'], count):
                            self.lgr.debug('syscall write found final diddler %s' % diddler.getPath())
                            self.top.stopTrace(cell_name=self.cell_name, syscall=self)
                            if not self.top.remainingCallTraces() and SIM_simics_is_running():
                                self.top.notRunning(quiet=True)
                                SIM_break_simulation('diddle done on cell %s file: %s' % (self.cell_name, diddler.getPath()))
                            else:
                                print('%s performed' % diddler.getPath())
                else:
                    self.lgr.debug('syscall write call_param match_param is type %s' % (call_param.match_param.__class__.__name__))
 
        elif callname == 'mmap' or callname == 'mmap2':        
            exit_info.count = frame['param2']
            if self.mem_utils.WORD_SIZE == 4: 
                ida_msg = '%s pid:%d FD: %d buf: 0x%x len: %d' % (callname, pid, frame['param3'], frame['param1'], frame['param2'])
            else:
                ida_msg = '%s pid:%d FD: %d buf: 0x%x len: %d prot: 0x%x  flags: 0x%x offset: 0x%x' % (callname, pid, 
                   frame['param5'], frame['param1'], frame['param2'], frame['param3'], frame['param4'], frame['param6'])
                self.lgr.debug(taskUtils.stringFromFrame(frame))

        elif callname == 'select' or callname == '_newselect':        
            exit_info.select_info = SelectInfo(frame['param1'], frame['param2'], frame['param3'], frame['param4'], frame['param5'], 
                 cpu, self.mem_utils, self.lgr)

            ida_msg = '%s %s\n' % (callname, exit_info.select_info.getString())
            for call_param in syscall_info.call_params:
                if type(call_param.match_param) is int and exit_info.select_info.hasFD(call_param.match_param):
                    self.lgr.debug('call param found %d' % (call_param.match_param))
                    exit_info.call_params = call_param
                    break

        elif callname == 'socketcall' or callname.upper() in net.callname:
            ida_msg = self.socketParse(callname, syscall_info, frame, exit_info, pid)

        else:
            ida_msg = '%s %s   pid:%d' % (callname, taskUtils.stringFromFrame(frame), pid)
            self.context_manager.setIdaMessage(ida_msg)
        if ida_msg is not None:
            self.lgr.debug(ida_msg.strip()) 
            ''' trace syscall exit unless call_params narrowed a search failed to find a match '''
            if ida_msg is not None and self.traceMgr is not None and (len(syscall_info.call_params) == 0 or exit_info.call_params is not None):
                if len(ida_msg.strip()) > 0:
                    self.traceMgr.write(ida_msg+'\n')
        return exit_info


    def stopHap(self, stop_action, one, exception, error_string):
        '''  Invoked when a syscall (or more typically its exit back to user space) triggers
             a break in the simulation
        '''
        if self.stop_hap is not None:
            SIM_hap_delete_callback_id("Core_Simulation_Stopped", self.stop_hap)
            self.stop_hap = None
            eip = self.mem_utils.getRegValue(self.cpu, 'pc')
            self.lgr.debug('syscall stopHap cycle: 0x%x eip: 0x%x exception %s error %s' % (self.stop_action.hap_clean.cpu.cycles, eip, str(exception), str(error_string)))
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
                self.sharedSyscall.rmExitHap(None)

                ''' TBD do this as a stop function? '''
                cpu, comm, pid = self.task_utils.curProc() 
                self.sharedSyscall.rmPendingExecve(pid)

                if self.traceMgr is not None:
                    self.traceMgr.close()
                self.stop_action.run()
                if self.call_list is not None:
                    for callname in self.call_list:
                        self.top.rmCallTrace(self.cell_name, callname)
            else:
                self.lgr.debug('syscall will linger and catch next occurance')

        
    def syscallHap(self, syscall_info, third, forth, memory):
        ''' Invoked when syscall is detected.  May set a new breakpoint on the
            return to user space so as to collect remaining parameters, or to stop
            the simulation as part of a debug session '''
        ''' NOTE Does not track Tar syscalls! '''
        break_eip = self.mem_utils.getRegValue(self.cpu, 'pc')
        cpu, comm, pid = self.task_utils.curProc() 
        if syscall_info.cpu != cpu:
            self.lgr.error('syscallHap wrong cell, cur: %s, expected %s' % (cpu.name, syscall_info.cpu.name))
            return

        if self.linger:
            if cpu.cycles in self.linger_cycles:
                self.lgr.debug('syscalHap for lingering call we already made.')
                return
            else:
                self.linger_cycles.append(cpu.cycles)

        callnum = self.mem_utils.getRegValue(cpu, 'syscall_num')
        if syscall_info.callnum is None:
           callname = self.task_utils.syscallName(callnum, syscall_info.compat32) 
           syscall_instance = self.top.getSyscall(self.cell_name, callname) 
           if syscall_instance != self and syscall_instance.isBackground() == self.isBackground():
               #self.lgr.debug(str(syscall_instance))
               #self.lgr.debug(str(self))
               #self.lgr.debug('syscallHap tracing all pid %d callnum %d name %s found more specific syscall hap, so ignore this one' % (pid, callnum, callname))
               return
           if callname == 'mmap' and pid in self.first_mmap_hap:
               return
        else:
           ''' not callnum from reg may not be the real callnum, e.g., 32-bit compatability.  Use syscall_info.callnum.
               Also, this is a cacluated entry, so compat32 conventions are already undone '''
           callname = self.task_utils.syscallName(syscall_info.callnum, syscall_info.compat32) 
           callnum = syscall_info.callnum
           #syscall_info.compat32 = False
        ''' call 0 is read in 64-bit '''
        if callnum == 0 and self.mem_utils.WORD_SIZE==4:
            self.lgr.debug('syscallHap callnum is zero')
            return
        value = memory.logical_address
        self.lgr.debug('syscallHap cell %s for pid:%s (%s) at 0x%x (memory 0x%x) callnum %d expected %s compat32 set for the HAP? %r name: %s cycle: 0x%x' % (self.cell_name, 
            pid, comm, break_eip, value, callnum, str(syscall_info.callnum), syscall_info.compat32, self.name, self.cpu.cycles))
            
        if comm == 'swapper/0' and pid == 1:
            self.lgr.debug('syscallHap, skipping call from init/swapper')
            return

        if len(self.proc_hap) == 0 and self.background_break is None:
            self.lgr.debug('syscallHap entered for pid %d after hap deleted' % pid)
            return
        if syscall_info.cpu is not None and cpu != syscall_info.cpu:
            self.lgr.debug('syscallHap, wrong cpu %s %s' % (cpu.name, syscall_info.cpu.name))
            return

        if self.debugging and not self.context_manager.amWatching(pid) and syscall_info.callnum is not None and self.background_break is None:
            self.lgr.debug('syscallHap  pid:%d missing from context manager.  Debugging and specific syscall watched' % pid)
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
        frame = None
        exit_eip1 = None
        exit_eip2 = None
        exit_eip3 = None
 
        if break_eip == self.param.sysenter or break_eip == self.param.compat_32_entry or break_eip == self.param.compat_32_int128:
            ''' caller frame will be in regs'''
            frame = self.task_utils.frameFromRegs(cpu, compat32=syscall_info.compat32)
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
            frame = self.task_utils.frameFromRegs(syscall_info.cpu, compat32=syscall_info.compat32)
            ''' fix up regs based on eip and esp found on stack '''
            reg_num = self.cpu.iface.int_register.get_number(self.mem_utils.getESP())
            esp = self.cpu.iface.int_register.read(reg_num)
            frame['eip'] = self.mem_utils.readPtr(cpu, esp)
            frame['esp'] = self.mem_utils.readPtr(cpu, esp+12)
            frame_string = taskUtils.stringFromFrame(frame)
            #self.lgr.debug('sys_entry frame %s' % frame_string)
            exit_eip1 = self.param.iretd
        elif break_eip == self.param.arm_entry:
            #self.lgr.debug('sys_entry frame %s' % frame_string)
            exit_eip1 = self.param.arm_ret
            frame = self.task_utils.frameFromRegs(cpu)
            frame_string = taskUtils.stringFromFrame(frame)
            #SIM_break_simulation(frame_string)
        elif break_eip == syscall_info.calculated:
            ''' Note EIP in stack frame is unknown '''
            #frame['eax'] = syscall_info.callnum
            if self.cpu.architecture == 'arm':
                frame = self.task_utils.frameFromRegs(cpu)
                exit_eip1 = self.param.arm_ret
                exit_eip2 = None
                #exit_eip3 = self.param.sysret64
            elif self.mem_utils.WORD_SIZE == 8:
                frame = self.task_utils.frameFromRegs(cpu, compat32=syscall_info.compat32)
                exit_eip1 = self.param.sysexit
                exit_eip2 = self.param.iretd
                exit_eip3 = self.param.sysret64
            else:
                frame = self.task_utils.frameFromStackSyscall()
                exit_eip1 = self.param.sysexit
                exit_eip2 = self.param.iretd
            #self.lgr.debug('syscallHap calculated')
            #frame_string = taskUtils.stringFromFrame(frame)
            #self.lgr.debug('frame string %s' % frame_string)
            
        else:
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
        if pending_call is not None:
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
            if callname == 'tgkill':
                tgid = frame['param1']
                tid = frame['param2']
                sig = frame['param3']
                ida_msg = '%s pid %d tgid: %d  tid: %d sig:%d' % (callname, pid, tgid, tid, sig)
                if tid != pid:
                    self.lgr.error('tgkill called from %d for other process %d, fix this TBD!' % (pid, tid))
                    return
            else: 
                ida_msg = '%s pid %d' % (callname, pid)
            self.lgr.debug('syscallHap exit of pid:%d' % pid)
            self.handleExit(pid, ida_msg)
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
                if comm != 'tar':
                        ''' watch syscall exit unless call_params narrowed a search failed to find a match '''
                        tracing_all = False 
                        if self.top is not None:
                            tracing_all = self.top.tracingAll(self.cell_name, pid)
                        if len(syscall_info.call_params) == 0 or exit_info.call_params is not None or tracing_all:
                            if self.stop_on_call:
                                cp = CallParams(None, None, break_simulation=True)
                                exit_info.call_params = cp
                            #self.lgr.debug('exit_info.call_params pid %d is %s' % (pid, str(exit_info.call_params)))
                            self.lgr.debug('syscallHap call to addExitHap for pid %d call  %d len %d trace_all %r' % (pid, syscall_info.callnum, 
                               len(syscall_info.call_params), tracing_all))
                            self.sharedSyscall.addExitHap(pid, exit_eip1, exit_eip2, exit_eip3, exit_info, self.traceProcs, exit_info_name)
                        else:
                            self.lgr.debug('did not add exitHap')
                            pass
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

            if comm != 'tar':
                name = callname+'-exit' 
                self.lgr.debug('syscallHap call to addExitHap for pid %d' % pid)
                if self.stop_on_call:
                    cp = CallParams(None, None, break_simulation=True)
                    exit_info.call_params = cp
                self.sharedSyscall.addExitHap(pid, exit_eip1, exit_eip2, exit_eip3, exit_info, self.traceProcs, name)
            else:
                self.lgr.debug('syscallHap pid:%d skip exitHap for tar' % pid)

    def unsetDebuggingExit(self):
        self.debugging_exit = False

    def handleExit(self, pid, ida_msg, killed=False):
            if self.traceProcs is not None:
                self.traceProcs.exit(pid)
            self.lgr.debug(ida_msg)
            if self.traceMgr is not None:
                self.traceMgr.write(ida_msg+'\n')
            self.context_manager.setIdaMessage(ida_msg)
            if self.soMap is not None:
                self.soMap.handleExit(pid)
            else:
                self.lgr.debug('syscallHap exit soMap is None, callnum is %s' % (syscall_info.callnum))
            last_one = self.context_manager.rmTask(pid, killed) 
            self.lgr.debug('syscallHap exit pid %d last_one %r debugging %d' % (pid, last_one, self.debugging))
            if last_one and self.debugging:
                if self.debugging_exit:
                    ''' exit before we got to text section '''
                    self.lgr.debug(' exit of %d before we got to text section ' % pid)
                    SIM_run_alone(self.top.undoDebug, None)
                self.lgr.debug('exit or exit_group pid:%d' % pid)
                self.sharedSyscall.stopTrace()
                ''' record exit so we don't see this proc, e.g., when going to debug its next instantiation '''
                self.task_utils.setExitPid(pid)
                #fun = stopFunction.StopFunction(self.top.noDebug, [], False)
                #self.stop_action.addFun(fun)
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
            SIM_hap_delete_callback_id("Core_Simulation_Stopped", self.stop_maze_hap)
            self.stop_maze_hap = None

    def stopForMazeAlone(self, syscall):
        self.stop_maze_hap = SIM_hap_add_callback("Core_Simulation_Stopped", self.stopMazeHap, syscall)
        self.lgr.debug('Syscall added stopMazeHap Now stop, syscall: %s' % (syscall))
        SIM_break_simulation('automaze')

    def checkMaze(self, syscall):
        cpu, comm, pid = self.task_utils.curProc() 
        self.lgr.debug('Syscall checkMaze pid:%d in timer loop' % pid)
        maze_exit = self.top.checkMazeReturn()
        if False and maze_exit is not None:
            self.lgr.debug('mazeExit checkMaze pid:%d found existing maze exit that matches' % pid)
            maze_exit.mazeReturn(True)
        else:
            if self.top.getAutoMaze():
                SIM_run_alone(self.stopForMazeAlone, syscall)
            else:
                print("Pid %d seems to be in a timer loop.  Try exiting the maze? Use @cgc.exitMaze('%s')" % (pid, syscall))
                SIM_break_simulation('timer loop?')
   
 
    def modeChanged(self, (the_fun, arg), one, old, new):
        if self.mode_hap is None:
            return
        self.lgr.debug('syscall modeChanged old %d new %d' % (old, new))
        if old == Sim_CPU_Mode_Supervisor:
            SIM_hap_delete_callback_id("Core_Mode_Change", self.mode_hap)
            self.mode_hap = None
            SIM_run_alone(the_fun, arg)
            

    def checkTimeLoop(self, callname, pid):
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
                self.mode_hap = SIM_hap_add_callback_obj("Core_Mode_Change", self.cpu, 0, self.modeChanged, (self.checkMaze, callname))
            else:
                self.timeofday_count[pid] = 0
                self.lgr.debug('checkTimeLoop pid:%d reset tod count' % pid)

    def isBackground(self):
        ''' Is this syscall hap watching background processes? '''
        retval = False
        if self.background_break != None:
            pid, dumb, cpu = self.context_manager.getDebugPid()
            if pid is not None:
                ''' debugging some process, and we are background.  thus we are in a different context than the process being debugged. '''
                retval = True
        return retval
            
