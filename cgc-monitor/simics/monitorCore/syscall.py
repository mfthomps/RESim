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
import traceFiles
import elfText
import diddler
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
        ''' list of criteria to narrow search to information about the call '''
        self.call_params = call_params

class ExitInfo():
    def __init__(self, cpu, pid, callnum):
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
        self.socket_callnum = None
        self.socket_params = None
        self.sock_struct = None
        ''' narrow search to information about the call '''
        self.call_params = None
        self.syscall_entry = None
        self.mode_hap = None

ROUTABLE = 1
AF_INET = 2
class CallParams():
    def __init__(self, subcall, match_param, break_simulation=False):
        self.subcall = subcall
        self.match_param = match_param
        self.param_flags = []
        self.break_simulation = break_simulation
        self.nth = None
        self.count = 0

class Syscall():

    def __init__(self, top, cell, param, mem_utils, task_utils, context_manager, traceProcs, sharedSyscall, lgr, 
                   traceMgr, callnum_list=None, trace = False, break_on_execve=None, flist_in=None, soMap = None, 
                   call_params=[], traceFiles=None, netInfo=None, binders=None, connectors=None, stop_on_call=False): 
        self.lgr = lgr
        self.traceMgr = traceMgr
        self.mem_utils = mem_utils
        self.task_utils = task_utils
        self.context_manager = context_manager
        ''' mostly a test if we are debugging. not very clean '''
        pid, dumb, cpu = context_manager.getDebugPid()
        self.debugging = False
        self.stop_on_call = False
        if pid is not None:
            self.debugging = True
            self.lgr.debug('Syscall is debugging')
        self.cpu = cpu
        self.cell = cell
        self.top = top
        self.param = param
        self.sharedSyscall = sharedSyscall
        self.traceProcs = traceProcs
        self.stop_hap = None
        self.finish_hap = {}
        self.finish_break = {}
        self.break_on_execve = break_on_execve
        self.first_mmap_hap = {}
        self.soMap = soMap
        self.proc_hap = []
        self.binders = binders
        self.connectors = connectors
        ''' lists of sockets by pid that we are watching for selected tracing '''
        self.sockwatch = SockWatch()
        ''' experimental watch for reads of data read from interfaces '''
        self.traceFiles = traceFiles
        self.timeofday_count = {}
        self.timeofday_start_cycle = {}
        self.callnum_list = callnum_list
        self.trace = trace
        self.call_params = call_params
        self.stop_action = None
        self.netInfo = netInfo
        self.bang_you_are_dead = False
        self.stop_maze_hap = None

        if trace is None:
            tf = '/tmp/syscall_trace.txt'
            #self.traceMgr.open(tf, cpu, noclose=True)
            self.traceMgr.open(tf, cpu)
       
        break_list, break_addrs = self.doBreaks()
 
        if self.debugging and self.break_on_execve is None and not trace:
            hap_clean = hapCleaner.HapCleaner(cpu)
            for ph in self.proc_hap:
                hap_clean.add("Core_Breakpoint_Memop", ph)
            f1 = stopFunction.StopFunction(self.top.skipAndMail, [], False)
            flist = [f1]
            self.stop_action = hapCleaner.StopAction(hap_clean, break_list, flist, break_addrs = break_addrs)
            self.lgr.debug('Syscall stop action includes skipAndMail in flist')
        elif flist_in is not None:
            hap_clean = hapCleaner.HapCleaner(cpu)
            for ph in self.proc_hap:
                hap_clean.add("Core_Breakpoint_Memop", ph)
            self.stop_action = hapCleaner.StopAction(hap_clean, break_list, flist_in, break_addrs = break_addrs)
            self.lgr.debug('Syscall stop action includes given flist')
        else:
            hap_clean = hapCleaner.HapCleaner(cpu)
            for ph in self.proc_hap:
                hap_clean.add("Core_Breakpoint_Memop", ph)
            self.stop_action = hapCleaner.StopAction(hap_clean, break_list, [], break_addrs = break_addrs)
            self.lgr.debug('Syscall stop action includes NO flist')


    def stopAlone(self, msg):
        eip = self.top.getEIP()
        if self.stop_action is not None:
            self.stop_action.setExitAddr(eip)
        self.stop_hap = SIM_hap_add_callback("Core_Simulation_Stopped", 
            	     self.stopHap, self.stop_action)
        self.lgr.debug('Syscall added stopHap %d Now stop msg %s' % (self.stop_hap, msg))
        SIM_break_simulation(msg)

    def breakOnExecve(self, comm):
        self.break_on_execve = comm

    def doBreaks(self, dumb=None):
        break_list = []
        break_addrs = []
        self.timeofday_count = {}
        self.timeofday_start_cycle = {}
        self.lgr.debug('syscall doBreaks reset timeofdaycount')
        if self.callnum_list is None:
            self.lgr.debug('Syscall no callnum, set break at 0x%x & 0x%x' % (self.param.sysenter, self.param.sys_entry))
            #proc_break = SIM_breakpoint(cell, Sim_Break_Linear, Sim_Access_Execute, param.sysenter, 1, 0)
            #proc_break1 = SIM_breakpoint(cell, Sim_Break_Linear, Sim_Access_Execute, param.sys_entry, 1, 0)
            proc_break = self.context_manager.genBreakpoint(self.cell, Sim_Break_Linear, Sim_Access_Execute, self.param.sysenter, 1, 0)
            proc_break1 = self.context_manager.genBreakpoint(self.cell, Sim_Break_Linear, Sim_Access_Execute, self.param.sys_entry, 1, 0)
            break_addrs.append(self.param.sysenter)
            break_addrs.append(self.param.sys_entry)
            break_list.append(proc_break)
            break_list.append(proc_break1)
            syscall_info = SyscallInfo(self.cpu, None, None, None, self.trace)
            self.proc_hap.append(self.context_manager.genHapRange("Core_Breakpoint_Memop", self.syscallHap, syscall_info, proc_break, proc_break1, 'syscall'))
        else:
            ''' will stop within the kernel at the computed entry point '''
            for callnum in self.callnum_list:
                entry = self.task_utils.getSyscallEntry(callnum)
                #phys = self.mem_utils.v2p(cpu, entry)
                #proc_break = self.context_manager.genBreakpoint(self.cpu.physical_memory, Sim_Break_Physical, Sim_Access_Execute, phys, 1, 0)
                #self.lgr.debug('Syscall callnum is %s entry 0x%x (0x%x)' % (callnum, entry, phys))
                self.lgr.debug('Syscall callnum is %s entry 0x%x' % (callnum, entry))
                proc_break = self.context_manager.genBreakpoint(self.cell, Sim_Break_Linear, Sim_Access_Execute, entry, 1, 0)
                proc_break1 = None
                break_list.append(proc_break)
                break_addrs.append(entry)
                syscall_info = SyscallInfo(self.cpu, None, callnum, entry, self.trace, self.call_params)
                name = self.task_utils.syscallName(callnum) 
                self.proc_hap.append(self.context_manager.genHapIndex("Core_Breakpoint_Memop", self.syscallHap, syscall_info, proc_break, name))
        return break_list, break_addrs
        
    def frameFromStackSyscall(self):
        reg_num = self.cpu.iface.int_register.get_number(self.mem_utils.getESP())
        esp = self.cpu.iface.int_register.read(reg_num)
        regs_addr = esp + self.mem_utils.WORD_SIZE
        #self.lgr.debug('frameFromStackSyscall regs_addr is 0x%x  ' % (regs_addr))
        frame = self.task_utils.getFrame(regs_addr, self.cpu)
        return frame

    def stopTrace(self, immediate=False):
        self.lgr.debug('syscall stopTrace')
        proc_copy = list(self.proc_hap)
        for ph in proc_copy:
            self.lgr.debug('syscall stopTrace, delete self.proc_hap %d' % ph)
            self.context_manager.genDeleteHap(ph, immediate=immediate)
            self.proc_hap.remove(ph)

        self.sharedSyscall.stopTrace()

        mmap_copy = list(self.first_mmap_hap)
        for pid in mmap_copy:
            self.lgr.debug('syscall stopTrace, delete mmap hap')
            self.context_manager.genDeleteHap(mmap_copy[pid], immediate=immediate)
            del self.first_mmap_hap[pid]
        self.first_mmap_hap = {}

        if self.stop_hap is not None:
            SIM_hap_delete_callback_id("Core_Simulation_Stopped", self.stop_hap)
            self.stop_hap = None
 
        self.bang_you_are_dead = True
        self.lgr.debug('syscall stopTrace return')
       
    def firstMmapHap(self, syscall_info, third, forth, memory):
        ''' invoked after mmap call, looking to track SO libraries.  Intended to be called after open of .so. '''
        cpu, comm, pid = self.task_utils.curProc() 
        self.lgr.debug('firstMmapHap in pid %d look for pid %d' % (pid, syscall_info.pid))
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
        frame = self.task_utils.frameFromStackSyscall()
        ida_msg = 'firstMmapHap %s pid:%d FD: %d buf: 0x%x count: %d File FD was %d' % (self.task_utils.syscallName(syscall_info.callnum), 
                   pid, frame['edi'], frame['ebx'], frame['ecx'], syscall_info.fd)
        self.lgr.debug(ida_msg)
        self.traceMgr.write(ida_msg+'\n')
        syscall_info.call_count = syscall_info.call_count+1
        self.lgr.debug('firstMmapHap delete self?')
        self.context_manager.genDeleteHap(self.first_mmap_hap[pid])
        del self.first_mmap_hap[pid]
        syscall_info.call_count = syscall_info.call_count+1
        exit_info = ExitInfo(cpu, pid, syscall_info.callnum)
        exit_info.fname = syscall_info.fname
        exit_info.count = frame['ecx']
        exit_info.syscall_entry = self.top.getEIP()
        phys = self.mem_utils.v2p(cpu, frame['eip'])
        name = 'firstMmap exit'
        self.sharedSyscall.addExitHap(pid, self.param.sysexit, self.param.iretd, syscall_info.callnum, exit_info, self.traceProcs, name)

    def watchFirstMmap(self, pid, fname, fd):
        callnum = self.task_utils.syscallNumber('mmap2')
        entry = self.task_utils.getSyscallEntry(callnum)
        self.lgr.debug('watchFirstMmap callnum is %s entry 0x%x' % (callnum, entry))
        proc_break = self.context_manager.genBreakpoint(self.cell, Sim_Break_Linear, Sim_Access_Execute, entry, 1, 0)
        syscall_info = SyscallInfo(self.cpu, pid, callnum, entry, True)
        syscall_info.fname = fname
        syscall_info.pid = pid
        syscall_info.fd = fd
        if pid in self.first_mmap_hap:
            self.context_manager.genDeleteHap(self.first_mmap_hap[pid])
            del self.first_mmap_hap[pid]
        self.first_mmap_hap[pid] = self.context_manager.genHapIndex("Core_Breakpoint_Memop", self.firstMmapHap, syscall_info, proc_break, 'watchFirstMmap')
        
    def parseOpen(self, frame):
        fname_addr = frame['ebx']
        flags = frame['ecx']
        mode = frame['edx']
        fname = self.mem_utils.readString(self.cpu, fname_addr, 256)
        cpu, comm, pid = self.task_utils.curProc() 
        ida_msg = 'open flags: 0x%x  mode: 0x%x  filename: %s   pid:%d' % (flags, mode, fname, pid)
        #self.lgr.debug('parseOpen set ida message to %s' % ida_msg)
        self.context_manager.setIdaMessage(ida_msg)
        return fname, fname_addr, flags, mode

    def readSilly(self, exit_info):
        # NOT USED
        ''' run this alone to get the page after it is mapped, simics timing fu '''
        exit_info.fname = self.mem_utils.readString(self.cpu, exit_info.fname_addr, 256)
        self.lgr.debug('readSilly got fid %s' % (exit_info.fname))
        if exit_info.fname is None:
            page_info = pageUtils.findPageTable(self.cpu, exit_info.fname_addr, self.lgr)
            self.lgr.debug('readSilly, filename not yet at 0x%x... ptable: %s' % (exit_info.fname_addr, page_info.valueString()))

    def finishParseOpen(self, exit_info, third, forth, memory):
        ''' in case the file name is in memory that was not mapped when open call was issued '''
        cpu, comm, pid = self.task_utils.curProc() 
        self.lgr.debug('finishParseOpen pid %d' % pid)
        if cpu != exit_info.cpu or pid != exit_info.pid:
            return
        if pid not in self.finish_hap:
            return
        exit_info.fname = self.mem_utils.readString(self.cpu, exit_info.fname_addr, 256)
        self.lgr.debug('finishParseOpen pid %d got fid %s' % (pid, exit_info.fname))
        SIM_hap_delete_callback_id("Core_Breakpoint_Memop", self.finish_hap[pid])
        SIM_delete_breakpoint(self.finish_break[pid])
        del self.finish_hap[pid]
        del self.finish_break[pid]
        #if exit_info.fname is None:
        #    SIM_run_alone(self.readSilly, exit_info)

    def addElf(self, prog_string, pid):
        root_prefix = self.top.getRootPrefix()
        if root_prefix is not None:
            full_path = os.path.join(root_prefix, prog_string[1:])
            self.lgr.debug('syscall finishParseExecve, prefix is %s progname is %s  full: %s' % (root_prefix, prog_string, full_path))
            text_segment = elfText.getText(full_path)
            if self.soMap is not None and text_segment is not None and text_segment.start is not None:
                self.lgr.debug('syscall finishParseExecve 0x%x - 0x%x' % (text_segment.start, text_segment.start+text_segment.size))       
                self.context_manager.recordText(text_segment.start, text_segment.start+text_segment.size)
                self.soMap.addText(text_segment.start, text_segment.size, prog_string, pid)

    def finishParseExecve(self, call_info, third, forth, memory):
        cpu, comm, pid = self.task_utils.curProc() 
        if cpu != call_info.cpu or pid != call_info.pid:
            return
        if pid not in self.finish_hap:
            return
        prog_string, arg_string_list = self.task_utils.readExecParamStrings(call_info.pid, call_info.cpu)
        self.lgr.debug('finishParseExecve progstring (%s)' % (prog_string))
        nargs = min(4, len(arg_string_list))
        arg_string = ''
        for i in range(nargs):
            if is_ascii(arg_string_list[i]):
                arg_string += arg_string_list[i]+' '
            else:
                break
        ida_msg = 'execve prog: %s %s  pid:%d' % (prog_string, arg_string, call_info.pid)
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
        base = os.path.basename(prog_string)
        if self.break_on_execve is not None: 
            if base.startswith(self.break_on_execve):
                self.lgr.debug('finishParseExecve execve of %s' % prog_string)
                self.sharedSyscall.rmPendingExecve(call_info.pid)
                SIM_run_alone(self.stopAlone, 'execve of %s' % prog_string)
            self.top.addProcList(pid, prog_string)

    def parseExecve(self, syscall_info):
        cpu, comm, pid = self.task_utils.curProc() 
        ''' allows us to ignore internal kernel syscalls such as close socket on exec '''
        prog_string, arg_string_list = self.task_utils.getProcArgsFromStack(pid, syscall_info, cpu)
        entry = self.task_utils.getSyscallEntry(11)
        self.lgr.debug('parseExecve pid:%d  got prog_string %s entry would be 0x%x' % (pid, prog_string, entry))
        self.lgr.debug('append %d to pending_execve' % pid) 
        self.sharedSyscall.addPendingExecve(pid)
        if prog_string is None:
            ''' prog string not in ram, break on kernel read of the address and then read it '''
            prog_addr = self.task_utils.getExecProgAddr(pid, cpu)
            call_info = SyscallInfo(cpu, pid, None, None, None)
            self.lgr.debug('parseExecve prog string missing, set break on 0x%x' % prog_addr)
            if prog_addr == 0:
                self.lgr.error('parseExecve zero prog_addr pid %d' % pid)
                SIM_break_simulation('parseExecve zero prog_addr pid %d' % pid)
            self.finish_break[pid] = SIM_breakpoint(self.cell, Sim_Break_Linear, Sim_Access_Read, prog_addr, 1, 0)
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
        self.traceMgr.write(ida_msg+'\n')
        if self.traceProcs is not None:
            self.traceProcs.setName(pid, prog_string, arg_string)

        self.addElf(prog_string, pid)

        if self.netInfo is not None:
            self.netInfo.checkNet(prog_string, arg_string)
        base = os.path.basename(prog_string)
        if self.break_on_execve is not None: 
            self.lgr.debug('parseExecve break_on_execve not none')
            if base.startswith(self.break_on_execve):
                eip = self.top.getEIP()
                self.sharedSyscall.rmPendingExecve(pid)
                self.lgr.debug('parseExecve execve of %s pid:%d eip: 0x%x  break simulation' % (prog_string, pid, eip))
                SIM_run_alone(self.stopAlone, 'execve %s' % prog_string)
            self.top.addProcList(pid, prog_string)

        return prog_string

    def syscallParse(self, frame, cpu, pid, syscall_info):
        callnum = frame['eax']
        callname = self.task_utils.syscallName(callnum) 
        exit_info = ExitInfo(cpu, pid, callnum)
        exit_info.syscall_entry = self.top.getEIP()
        ida_msg = None
        if callname == 'open':        
            exit_info.fname, exit_info.fname_addr, exit_info.flags, exit_info.mode = self.parseOpen(frame)
            if exit_info.fname is None:
                ''' filename not yet present in ram, do the two step '''
                ''' TBD think we are triggering off kernel's own read of the fname, then again someitme it seems corrupted...'''
                self.lgr.debug('syscallParse, pid %d filename not yet here... set break at 0x%x' % (pid, exit_info.fname_addr))
                self.finish_break[pid] = SIM_breakpoint(self.cell, Sim_Break_Linear, Sim_Access_Read, exit_info.fname_addr, 1, 0)
                self.finish_hap[pid] = SIM_hap_add_callback_index("Core_Breakpoint_Memop", self.finishParseOpen, exit_info, self.finish_break[pid])
            else:
                for call_param in syscall_info.call_params:
                    if type(call_param.match_param) is str:
                        exit_info.call_params = call_param
                        break

        if callname == 'mkdir':        
            exit_info.fname, exit_info.fname_addr, exit_info.flags, exit_info.mode = self.parseOpen(frame)

        elif callname == 'execve':        
            retval = self.parseExecve(syscall_info)
        elif callname == 'close':        
            fd = frame['ebx']
            if self.traceProcs is not None:
                #self.lgr.debug('syscallparse for close pid %d' % pid)
                self.traceProcs.close(pid, fd)
            exit_info.old_fd = fd
            exit_info.call_params = self.sockwatch.getParam(pid, fd)
            self.sockwatch.close(pid, fd)

            for call_param in syscall_info.call_params:
                if call_param.match_param == frame['ebx']:
                    self.lgr.debug('closed fd %d, stop trace' % fd)
                    self.stopTrace()
                    ida_msg = 'Closed FD %d' % fd
                    exit_info.call_params = call_param
                    break 

        elif callname == 'dup':        
            exit_info.old_fd = frame['ebx']
        elif callname == 'dup2':        
            exit_info.old_fd = frame['ebx']
            exit_info.new_fd = frame['ecx']
        elif callname == 'clone':        

            ''' NOT! clone syscall is like fork, parent and child resume at same EIP '''
            function_ptr = frame['ebx']
            arg_ptr = frame['esi']
            ida_msg = '%s pid:%d function: 0x%x arg: 0x%x' % (callname, pid, function_ptr, arg_ptr)
              
            self.context_manager.setIdaMessage(ida_msg)
            #self.traceProcs.close(pid, fd)
        elif callname == 'pipe' or callname == 'pipe2':        
            exit_info.retval_addr = frame['ebx']
            
        elif callname == 'socketcall':        
            ida_msg = None
            socket_callnum = frame['ebx']
            exit_info.socket_callnum = socket_callnum
            socket_callname = net.callname[socket_callnum]
            exit_info.socket_params = frame['ecx']
            if socket_callname == 'CONNECT':
                ss = net.SockStruct(cpu, frame['ecx'], self.mem_utils)
                exit_info.sock_struct = ss
                ida_msg = '%s - %s pid:%d %s %s  param at: 0x%x' % (callname, socket_callname, pid, ss.getString(), ss.addressInfo(), frame['ecx'])
                for call_param in syscall_info.call_params:
                    if call_param.subcall == 'CONNECT':
                         if call_param.match_param is not None and ss.port is not None:
                             ''' look to see if this address matches a given pattern '''
                             s = ss.dottedPort()
                             pat = call_param.match_param
                             self.lgr.debug('syscallParse look for match %s %s' % (pat, s))
                             go = re.search(pat, s, re.M|re.I)
                             
                             if len(call_param.match_param.strip()) == 0 or go: 
                                 self.lgr.debug('syscallParse found match %s %s' % (pat, s))
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
                             self.lgr.debug('syscallParse routable in flags and is routable')
                             exit_info.call_params = call_param
                if self.traceProcs is not None and ss.isRoutable(): 
                    prog = self.traceProcs.getProg(pid)
                    self.lgr.debug('adding connector for pid:%d %s %s %s' % (pid, prog, ss.dottedIP(), str(ss.port)))
                    self.connectors.add(pid, prog, ss.dottedIP(), ss.port)
                  
            elif socket_callname == 'BIND':
                ss = net.SockStruct(cpu, frame['ecx'], self.mem_utils)
                exit_info.sock_struct = ss
                ida_msg = '%s - %s pid:%d %s' % (callname, socket_callname, pid, ss.getString())
                for call_param in syscall_info.call_params:
                    if call_param.subcall == 'BIND':
                         if call_param.match_param is not None and ss.port is not None:
                             ''' look to see if this address matches a given patter '''
                             s = ss.dottedPort()
                             pat = call_param.match_param
                             go = re.search(pat, s, re.M|re.I)
                             
                             #self.lgr.debug('syscallParse look for match %s %s' % (pat, s))
                             if len(call_param.match_param.strip()) == 0 or go: 
                                 self.lgr.debug('syscallParse found match %s %s' % (pat, s))
                                 exit_info.call_params = call_param
                                 ida_msg = 'BIND to %s, FD: %d' % (s, ss.fd)
                                 self.context_manager.setIdaMessage(ida_msg)
                                 break
                    if call_param.subcall == 'BIND':
                         if AF_INET in call_param.param_flags and ss.sa_family == net.AF_INET:
                             exit_info.call_params = call_param
                             self.sockwatch.bind(pid, ss.fd, call_param)

            elif socket_callname == 'GETPEERNAME':
                ss = net.SockStruct(cpu, frame['ecx'], self.mem_utils)
                ida_msg = '%s - %s pid:%d FD: %d' % (callname, socket_callname, pid, ss.fd)
                #exit_info.call_params = self.sockwatch.getParam(pid, ss.fd)
                for call_param in syscall_info.call_params:
                    if type(call_param.match_param) is int and call_param.match_param == ss.fd:
                    #if call_param.subcall == 'GETPEERNAME' and call_param.match_param == ss.fd:
                        exit_info.call_params = call_param
                        break

            elif socket_callname == 'ACCEPT':
                ss = net.SockStruct(cpu, frame['ecx'], self.mem_utils)
                ida_msg = '%s - %s pid:%d FD: %d' % (callname, socket_callname, pid, ss.fd)
                #exit_info.call_params = self.sockwatch.getParam(pid, ss.fd)
                for call_param in syscall_info.call_params:
                    if call_param.subcall == 'ACCEPT' and call_param.match_param == ss.fd:
                        exit_info.call_params = call_param
                        break

            elif socket_callname == 'GETSOCKNAME':
                ss = net.SockStruct(cpu, frame['ecx'], self.mem_utils)
                ida_msg = '%s - %s pid:%d FD: %d' % (callname, socket_callname, pid, ss.fd)
                #exit_info.call_params = self.sockwatch.getParam(pid, ss.fd)
                for call_param in syscall_info.call_params:
                    if call_param.subcall == 'GETSOCKNAME' and call_param.match_param == ss.fd:
                        exit_info.call_params = call_param
                        break

            elif socket_callnum == net.RECV or socket_callnum == net.RECVFROM or \
                         socket_callnum == net.RECVMSG: 
                ss = net.SockStruct(cpu, frame['ecx'], self.mem_utils)
                exit_info.old_fd = ss.fd
                exit_info.call_params = self.sockwatch.getParam(pid, ss.fd)
                exit_info.retval_addr = ss.addr
                ida_msg = '%s - %s pid:%d %s len: %d  flags: 0x%x' % (callname, socket_callname, pid, ss.getString(), ss.length, ss.flags)
                for call_param in syscall_info.call_params:
                    if type(call_param.match_param) is int and call_param.match_param == ss.fd:
                        exit_info.call_params = call_param
                        break
            elif exit_info.socket_callnum == net.SEND or exit_info.socket_callnum == net.SENDTO or \
                         exit_info.socket_callnum == net.SENDMSG: 
                ss = net.SockStruct(cpu, frame['ecx'], self.mem_utils)
                exit_info.old_fd = ss.fd
                exit_info.retval_addr = ss.addr
                exit_info.call_params = self.sockwatch.getParam(pid, ss.fd)
                ida_msg = '%s - %s pid:%d %s' % (callname, socket_callname, pid, ss.getString())
                for call_param in syscall_info.call_params:
                    if type(call_param.match_param) is int and call_param.match_param == ss.fd:
                        self.lgr.debug('call param found %d, matches %d' % (call_param.match_param, ss.fd))
                        exit_info.call_params = call_param
                        break
                    elif type(call_param.match_param) is str and (call_param.subcall == 'SEND' or call_param.subcall == 'SENDTO'):
                        self.lgr.debug('syscall write watch exit for call_param %s' % call_param.match_param)
                        exit_info.call_params = call_param
                        break

            elif socket_callname == 'LISTEN':
                ss = net.SockStruct(cpu, frame['ecx'], self.mem_utils)
                exit_info.call_params = self.sockwatch.getParam(pid, ss.fd)
                ida_msg = '%s - %s pid:%d %s' % (callname, socket_callname, pid, ss.getString())
                    
            else:
                ida_msg = '%s - %s %s   pid:%d' % (callname, socket_callname, taskUtils.stringFromFrame(frame), pid)

        elif callname == 'ipc':        
            call = frame['ebx']
            exit_info.socket_callnum = call
            if call == ipc.MSGGET or call == ipc.SHMGET:
                key = frame['ecx']
                callname = ipc.call[call]
                exit_info.fname = key
                ida_msg = 'ipc %s pid:%d key: 0x%x size: %d  flags: 0x%x\n %s' % (callname, pid, key, frame['edx'], frame['esi'],
                       taskUtils.stringFromFrame(frame)) 
            elif call == ipc.MSGSND or call == ipc.MSGRCV:
                callname = ipc.call[call]
                ida_msg = 'ipc %s pid:%d quid: 0x%x size: %d addr: 0x%x' % (callname, pid, frame['esi'], frame['edx'], frame['edi'])
            else:
                ida_msg = 'ipc %s pid:%d %s' % (callname, pid, taskUtils.stringFromFrame(frame) )

        elif callname == 'ioctl':        
            fd = frame['ebx']
            cmd = frame['ecx']
            param = frame['edx']
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
            timeval_ptr = frame['ebx']
            ida_msg = 'gettimeofday pid:%d timeval_ptr: 0x%x' % (pid, timeval_ptr)
            exit_info.retval_addr = timeval_ptr
 
        elif callname == 'nanosleep':        
            time_spec = frame['ebx']
            seconds = self.mem_utils.readWord32(cpu, time_spec)
            nano = self.mem_utils.readWord32(cpu, time_spec+self.mem_utils.WORD_SIZE)
            ida_msg = 'nanosleep pid:%d time_spec: 0x%x seconds: %d nano: %d' % (pid, time_spec, seconds, nano)
            #SIM_break_simulation(ida_msg)

        elif callname == 'fcntl64':        
            fd = frame['ebx']
            cmd = frame['ecx']
            ida_msg = 'fcntl64 pid:%d FD: %d command: %d\n%s' % (pid, fd, cmd, taskUtils.stringFromFrame(frame)) 
            for call_param in syscall_info.call_params:
                if call_param.match_param == fd:
                    exit_info.call_params = call_param
                    break

        elif callname == '_llseek':        
            fd = frame['ebx']
            high = frame['ecx']
            low = frame['edx']
            result =  frame['esi']
            whence = frame['edi']
            ida_msg = '_llseek pid:%d FD: %d high: 0x%x low: 0x%x result: 0x%x whence: 0x%x \n%s' % (pid, fd, high, low, 
                    result, whence, taskUtils.stringFromFrame(frame))
            exit_info.retval_addr = result
            exit_info.old_fd = fd
            for call_param in syscall_info.call_params:
                if call_param.match_param == frame['ebx']:
                    exit_info.call_params = call_param
                    break

        elif callname == 'read':        
            exit_info.old_fd = frame['ebx']
            ida_msg = 'read pid:%d FD: %d buf: 0x%x count: %d' % (pid, frame['ebx'], frame['ecx'], frame['edx'])
            exit_info.retval_addr = frame['ecx']
            ''' check runToIO '''
            for call_param in syscall_info.call_params:
                if call_param.match_param == frame['ebx']:
                    exit_info.call_params = call_param
                    break

        elif callname == 'write':        
            exit_info.old_fd = frame['ebx']
            count = frame['edx']
            ida_msg = 'write pid:%d FD: %d buf: 0x%x count: %d' % (pid, frame['ebx'], frame['ecx'], count)
            exit_info.retval_addr = frame['ecx']
            ''' check runToIO '''
            for call_param in syscall_info.call_params:
                if type(call_param.match_param) is int and call_param.match_param == frame['ebx']:
                    self.lgr.debug('call param found %d, matches %d' % (call_param.match_param, frame['ebx']))
                    exit_info.call_params = call_param
                    break
                elif type(call_param.match_param) is str:
                    exit_info.call_params = call_param
                    break
                elif call_param.match_param.__class__.__name__ == 'Diddler':
                    if count < 1024:
                        self.lgr.debug('syscall write check diddler count %d' % count)
                        if call_param.match_param.checkString(self.cpu, frame['ecx'], count):
                            self.lgr.debug('syscall write found final diddler')
                            self.stopTrace()
                            if SIM_simics_is_running():
                                SIM_break_simulation('diddle done')
                else:
                    self.lgr.debug('syscall write call_param match_param is type %s' % (call_param.match_param.__class__.__name__))
 

        elif callname == 'mmap' or callname == 'mmap2':        
            exit_info.count = frame['ecx']
            ida_msg = '%s pid:%d FD: %d buf: 0x%x count: %d' % (callname, pid, frame['edi'], frame['ebx'], frame['ecx'])

        else:
            ida_msg = '%s %s   pid:%d' % (callname, taskUtils.stringFromFrame(frame), pid)
            self.context_manager.setIdaMessage(ida_msg)
        if ida_msg is not None:
            self.lgr.debug(ida_msg.strip()) 
            ''' trace syscall exit unless call_params narrowed a search failed to find a match '''
            if ida_msg is not None and (len(syscall_info.call_params) == 0 or exit_info.call_params is not None):
                if len(ida_msg.strip()) > 0:
                    self.traceMgr.write(ida_msg+'\n')
        return exit_info


    def stopHap(self, stop_action, one, exception, error_string):
        '''  Invoked when a syscall (or more typically its exit back to user space) triggers
             a break in the simulation
        '''
        if self.stop_hap is not None:
            eip = self.top.getEIP()
            self.lgr.debug('syscall stopHap cycle: 0x%x eip: 0x%x exception %s error %s' % (self.stop_action.hap_clean.cpu.cycles, eip, str(exception), str(error_string)))
            break_list = self.stop_action.getBreaks()
            if eip not in break_list and eip != self.stop_action.getExitAddr():
                self.lgr.debug('syscall stopHap 0x%x not in break list, not our stop %s' % (eip, ' '.join(hex(x) for x in break_list)))
                #self.top.skipAndMail()
                return
       
            for hc in self.stop_action.hap_clean.hlist:
                if hc.hap is not None:
                    self.lgr.debug('will delete hap %s' % str(hc.hap))
                    self.context_manager.genDeleteHap(hc.hap)
                    hc.hap = None
            #self.lgr.debug('will delete hap %s' % str(self.stop_hap))
            SIM_hap_delete_callback_id("Core_Simulation_Stopped", self.stop_hap)
            self.stop_hap = None
            for bp in self.stop_action.breakpoints:
                self.context_manager.genDeleteBreakpoint(bp)
            ''' check functions in list '''
            self.sharedSyscall.rmExitHap(None)
            self.traceMgr.close()
            self.stop_action.run()



        
    def syscallHap(self, syscall_info, third, forth, memory):
        ''' Invoked when syscall is detected.  May set a new breakpoint on the
            return to user space so as to collect remaining parameters, or to stop
            the simulation as part of a debug session '''
        ''' NOTE Does not track Tar syscalls! '''
        break_eip = self.top.getEIP()
        cpu, comm, pid = self.task_utils.curProc() 
        if comm == 'swapper/0' and pid == 1:
            self.lgr.debug('syscallHap, skipping call from init/swapper')
            return

        #self.lgr.debug('syscallhap for pid %s at 0x%x' % (pid, break_eip))
        if len(self.proc_hap) == 0:
            self.lgr.debug('syscallHap entered for pid %d after hap deleted' % pid)
            return
        if syscall_info.cpu is not None and cpu != syscall_info.cpu:
            self.lgr.debug('syscallHap, wrong cpu %s %s' % (cpu.name, syscall_info.cpu.name))
            return
        if self.debugging and not self.context_manager.amWatching(pid):
            #self.lgr.debug('syscallHap looked for pid in contextManager  found %d.  Do nothing' % (pid))
            return

        if self.bang_you_are_dead:
            self.lgr.error('syscallhap call to dead hap pid %d' % pid) 
            return

        #self.lgr.debug('syscallhap for %s at 0x%x' % (pid, break_eip))
        stack_frame = None
        exit_eip1 = None
        exit_eip2 = None
        if break_eip == self.param.sysenter:
            ''' caller frame will be in regs'''
            ''' NOTE eip is unknown '''
            stack_frame = self.task_utils.frameFromRegs(syscall_info.cpu)
            frame_string = taskUtils.stringFromFrame(stack_frame)
            exit_eip1 = self.param.sysexit
            ''' catch interrupt returns such as wait4 '''
            exit_eip2 = self.param.iretd
            #self.lgr.debug('sysenter frame %s' % frame_string)
        elif break_eip == self.param.sys_entry:
            stack_frame = self.task_utils.frameFromRegs(syscall_info.cpu)
            ''' fix up regs based on eip and esp found on stack '''
            reg_num = self.cpu.iface.int_register.get_number(self.mem_utils.getESP())
            esp = self.cpu.iface.int_register.read(reg_num)
            stack_frame['eip'] = self.mem_utils.readPtr(cpu, esp)
            stack_frame['esp'] = self.mem_utils.readPtr(cpu, esp+12)
            frame_string = taskUtils.stringFromFrame(stack_frame)
            #self.lgr.debug('sys_entry frame %s' % frame_string)
            exit_eip1 = self.param.iretd
        elif break_eip == syscall_info.calculated:
            ''' Note EIP in stack frame is unknown '''
            stack_frame = self.task_utils.frameFromStackSyscall()
            stack_frame['eax'] = syscall_info.callnum
            frame_string = taskUtils.stringFromFrame(stack_frame)
            exit_eip1 = self.param.sysexit
            exit_eip2 = self.param.iretd
            #self.lgr.debug('calculated')
            
        else:
            value = memory.logical_address
            self.lgr.error('syscallHap unexpected break_ip 0x%x memory says 0x%x' % (break_eip, value))
            #SIM_break_simulation('unexpected break eip 0x%x' % break_eip)

            return

        eax = stack_frame['eax']
        if eax == 0:
            self.lgr.debug('syscallHap eax is zero')
            return

        if self.sharedSyscall.isPendingExecve(pid):
            if eax == self.task_utils.syscallNumber('close'):
                self.lgr.debug('syscallHap must be a close on exec? pid:%d' % pid)
                return
            elif eax == self.task_utils.syscallNumber('execve'):
                self.lgr.debug('syscallHap must be a execve in execve? pid:%d' % pid)
                return
            elif eax == self.task_utils.syscallNumber('exit_group'):
                self.lgr.debug('syscallHap exit_group called from within execve %d' % pid)
                return
            else:
                self.lgr.error('fix this, syscall within exec? pid:%d eax: %d' % (pid, eax))
                SIM_break_simulation('fix this')
                return

        pending_call = self.sharedSyscall.getPendingCall(pid)
        if pending_call is not None:
            if eax == self.task_utils.syscallNumber('sigreturn'):
                return
            else:
                pending_call = self.sharedSyscall.getPendingCall(pid)
                if pending_call is not None:
                    if pending_call == self.task_utils.syscallNumber('pipe') and eax == self.task_utils.syscallNumber('pipe2'):
                        return
                else:
                    self.lgr.error('syscallHap pid %d call %d,  still has exit break???' % (pid, eax))
                    self.lgr.debug('syscallHap frame: %s' % frame_string)
                    SIM_break_simulation('syscallHap pid %d call %d,  still has exit break???' % (pid, eax))
                    return

        if eax == self.task_utils.syscallNumber('exit_group') or eax == self.task_utils.syscallNumber('exit'):
            self.lgr.debug('syscallHap exit of pid:%d' % pid)
            if self.traceProcs is not None:
                self.traceProcs.exit(pid)
            callname = self.task_utils.syscallName(eax) 
            ida_msg = '%s pid %d' % (callname, pid)
            self.lgr.debug(ida_msg)
            self.traceMgr.write(ida_msg+'\n')
            self.context_manager.setIdaMessage(ida_msg)
            last_one = self.context_manager.rmTask(pid) 
            self.lgr.debug('syscallHap exit pid %d last_one %r debugging %d' % (pid, last_one, self.debugging))
            if last_one and self.debugging:
                self.lgr.debug('exit or exit_group pid %d' % pid)
                self.sharedSyscall.stopTrace()
                ''' record exit so we don't see this proc, e.g., when going to debug its next instantiation '''
                self.task_utils.setExitPid(pid)
                SIM_run_alone(self.stopAlone, 'exit or exit_group pid %d' % pid)
                SIM_run_alone(self.top.noDebug, None)
            return

        ''' Set exit breaks '''
        #self.lgr.debug('syscallHap in proc %d (%s), eax: 0x%x  EIP: 0x%x' % (pid, comm, eax, break_eip))
        #self.lgr.debug('syscallHap frame: %s' % frame_string)
        frame_string = taskUtils.stringFromFrame(stack_frame)
        #self.lgr.debug('syscallHap frame: %s' % frame_string)
        if syscall_info.callnum is not None:
            #self.lgr.debug('syscallHap callnum %d eax %d' % (syscall_info.callnum, eax))
            # TBD we forced this above, seems eax is sometimes not set to callnumber when we reach a calculated address?
            if eax == syscall_info.callnum:
                exit_info = self.syscallParse(stack_frame, cpu, pid, syscall_info)
                #self.lgr.debug('syscall 0x%d from %d (%s) at 0x%x cycles: 0x%x' % (eax, pid, comm, break_eip, cpu.cycles))
                #if self.break_on_execve is None and len(syscall_info.call_params) == 0:
                #    if eax != self.task_utils.syscallNumber('gettimeofday'):
                #        self.lgr.error('syscallHap for specific call, not tod, no parameters.  syscall frame was %s' % frame_string)
                #        SIM_break_simulation('syscall frame was %s' % frame_string)
                #    else:
                #        self.sharedSyscall.addExitHap(pid, exit_eip1, exit_eip2, syscall_info.callnum, exit_info, self.traceProcs, name)
                if comm != 'tar':
                        #self.lgr.debug('set return ip break at 0x%x' % stack_frame['eip'])
                        #self.exit_break = self.context_manager.genBreakpoint(self.cell, Sim_Break_Linear, Sim_Access_Execute, stack_frame['eip'], 1, 0)
                        ''' watch syscall exit unless call_params narrowed a search failed to find a match '''
                        if len(syscall_info.call_params) == 0 or exit_info.call_params is not None:
                            if self.stop_on_call:
                                cp = CallParams(None, None, break_simulation=True)
                                exit_info.call_params = cp
                            name = self.task_utils.syscallName(syscall_info.callnum)+' exit' 
                            #self.lgr.debug('syscllHap call to addExitHap for pid %d call  %d' % (pid, syscall_info.callnum))
                            self.sharedSyscall.addExitHap(pid, exit_eip1, exit_eip2, syscall_info.callnum, exit_info, self.traceProcs, name)
                        else:
                            #self.lgr.debug('did not add exitHap')
                            pass
                else:
                    self.lgr.debug('syscallHap skipping %s, no exit' % comm)
                
            else:
                self.lgr.debug('syscallHap looked for call %d, got %d, calculated 0x%x do nothing' % (syscall_info.callnum, eax, syscall_info.calculated))
                pass
        else:
            ''' tracing all syscalls, or watching for any syscall, e.g., during debug '''
            exit_info = self.syscallParse(stack_frame, cpu, pid, syscall_info)
            #self.lgr.debug('syscall looking for any, got %d from %d (%s) at 0x%x ' % (eax, pid, comm, break_eip))

            if comm != 'tar' and (pid not in self.first_mmap_hap):
                name = self.task_utils.syscallName(syscall_info.callnum)+' exit' 
                #self.lgr.debug('syscllHap call to addExitHap for pid %d' % pid)
                if self.stop_on_call:
                    cp = CallParams(None, None, break_simulation=True)
                    exit_info.call_params = cp
                self.sharedSyscall.addExitHap(pid, exit_eip1, exit_eip2, syscall_info.callnum, exit_info, self.traceProcs, name)

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
