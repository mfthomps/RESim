import os
import re
from simics import *
import hapCleaner
import taskUtils
import net
import memUtils
import stopFunction
import binder
import connector
'''
    Trace syscalls
x86:32
Syscall #	Param 1	Param 2	Param 3	Param 4	Param 5	Param 6
eax		ebx	ecx	edx	esi	edi	ebp
Return value
eax

'''
def is_ascii(s):
    return all(ord(c) < 128 for c in s)

class SockStruct():
    def __init__(self, cpu, params, mem_utils):
        self.fd = mem_utils.readWord32(cpu, params)
        self.port = None
        self.sin_addr = None
        self.sa_data = None
        addr = mem_utils.readWord32(cpu, params+4)
        self.sa_family = mem_utils.readWord16(cpu, addr) 
        if self.sa_family == 1:
            self.sa_data = mem_utils.readString(cpu, addr+2, 256)
        elif self.sa_family == 2:
            self.port = mem_utils.readWord16(cpu, addr+2)
            self.sin_addr = mem_utils.readWord32(cpu, addr+4)

    def famName(self):
        if self.sa_family is not None and self.sa_family < len(net.domaintype):
            return net.domaintype[self.sa_family]
        else:
            return None

    def dottedIP(self):
      "Convert 32-bit integer to dotted IPv4 address."
      return ".".join(map(lambda n: str(self.sin_addr>>n & 0xFF), [0,8,16,24]))

    def dottedPort(self):
        return '%s:%s' % (self.dottedIP(), self.port)

    def getName(self):
        if self.sa_family == 1:
            return self.sa_data
        elif self.sa_family == 2:
            name = '%s:%s' % (self.dottedIP(), self.port)
            return name
        else:
            return None

    def isRoutable(self):
        if self.sa_family == 2:
            ip = self.dottedIP()
            if not ip.startswith('0.0.') and not ip.startswith('127.'):
                return True
        return False

    def addressInfo(self):
        ''' for use in printing traces '''
        flag = ''
        if self.isRoutable():
            flag = 'ROUTABLE IP'
        return flag

    def getString(self):
        if self.sa_family == 1:
            retval = ('FD: %d sa_family: %s  sa_data: %s' % (self.fd, self.famName(), self.sa_data))
        elif self.sa_family == 2:
            retval = ('FD: %d sa_family: %s  address: %s:%d' % (self.fd, self.famName(), self.dottedIP(), self.port))
        else:
            retval = ('FD: %d sa_family: %s  TBD' % (self.fd, self.famName()))
        return retval

class SockWatch():
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
        self.count = 0
        self.fname = None
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
        self.flags = None
        self.mode = None
        self.old_fd = None
        self.new_fd = None
        self.socket_callnum = None
        self.socket_params = None
        ''' narrow search to information about the call '''
        self.call_params = None

ROUTABLE = 1
AF_INET = 2
class CallParams():
    def __init__(self, subcall, match_param, break_simulation=False):
        self.subcall = subcall
        self.match_param = match_param
        self.param_flags = []
        self.break_simulation = break_simulation

class Syscall():

    def __init__(self, top, cell, param, mem_utils, task_utils, context_manager, traceProcs, lgr, 
                   callnum=None, trace = False, trace_fh = None, break_on_execve=None, flist_in=None, soMap = None, call_params=[]): 
        self.mem_utils = mem_utils
        self.task_utils = task_utils
        self.context_manager = context_manager
        ''' mostly a test if we are debugging. not very clean '''
        pid, dumb, cpu = context_manager.getDebugPid()
        self.debugging = False
        if cpu is None:
            cpu = top.getCPU() 
        else:
            self.debugging = True
        self.cpu = cpu
        self.cell = cell
        self.top = top
        self.param = param
        self.traceProcs = traceProcs
        self.lgr = lgr
        self.stop_hap = None
        self.trace_fh = trace_fh
        self.exit_hap = {}
        self.exit_break = {}
        self.finish_hap = {}
        self.finish_break = {}
        self.break_on_execve = break_on_execve
        self.first_mmap_hap = {}
        self.soMap = soMap
        self.proc_hap = None
        self.binders = binder.Binder()
        self.connectors = connector.Connector()
        ''' lists of sockets by pid that we are watching for selected tracing '''
        self.sockwatch = SockWatch()
        break_list = []
        if trace and self.trace_fh is None:
            self.trace_fh = open('/tmp/syscall_trace.txt', 'w')
        ''' will stop within the kernel at the computed entry point '''
        entry = None
        if callnum is None:
            self.lgr.debug('runToSyscall no callnum, set break at 0x%x & 0x%x' % (param.sysenter, param.sys_entry))
            #proc_break = SIM_breakpoint(cell, Sim_Break_Linear, Sim_Access_Execute, param.sysenter, 1, 0)
            #proc_break1 = SIM_breakpoint(cell, Sim_Break_Linear, Sim_Access_Execute, param.sys_entry, 1, 0)
            proc_break = self.context_manager.genBreakpoint(cell, Sim_Break_Linear, Sim_Access_Execute, param.sysenter, 1, 0)
            proc_break1 = self.context_manager.genBreakpoint(cell, Sim_Break_Linear, Sim_Access_Execute, param.sys_entry, 1, 0)
            break_list.append(proc_break)
            break_list.append(proc_break1)
            syscall_info = SyscallInfo(self.cpu, None, callnum, entry, trace)
            self.proc_hap = self.context_manager.genHapRange("Core_Breakpoint_Memop", self.syscallHap, syscall_info, proc_break, proc_break1)
        else:
            entry = self.task_utils.getSyscallEntry(callnum)
            self.lgr.debug('runToSyscall callnum is %s entry 0x%x' % (callnum, entry))
            proc_break = self.context_manager.genBreakpoint(cell, Sim_Break_Linear, Sim_Access_Execute, entry, 1, 0)
            proc_break1 = None
            break_list.append(proc_break)
            syscall_info = SyscallInfo(self.cpu, None, callnum, entry, trace, call_params)
            self.proc_hap = self.context_manager.genHapIndex("Core_Breakpoint_Memop", self.syscallHap, syscall_info, proc_break)
        
        if not trace and self.break_on_execve is None:
            hap_clean = hapCleaner.HapCleaner(cpu)
            hap_clean.add("Core_Breakpoint_Memop", self.proc_hap)
            f1 = stopFunction.StopFunction(self.top.skipAndMail, [], False)
            flist = [f1]
            stop_action = hapCleaner.StopAction(hap_clean, break_list, flist)
            self.stop_hap = SIM_hap_add_callback("Core_Simulation_Stopped", 
            	     self.stopHap, stop_action)
            self.lgr.debug('runToSyscall added stopHap %d and skipAndMail in flist' % (self.stop_hap))
        elif flist_in is not None:
            hap_clean = hapCleaner.HapCleaner(cpu)
            hap_clean.add("Core_Breakpoint_Memop", self.proc_hap)
            stop_action = hapCleaner.StopAction(hap_clean, break_list, flist_in)
            self.stop_hap = SIM_hap_add_callback("Core_Simulation_Stopped", 
            	     self.stopHap, stop_action)
            self.lgr.debug('runToSyscall added stopHap %d and actions %s' % (self.stop_hap, str(flist_in)))
        if not trace:
            SIM_run_command('c')

    def breakOnExecve(self, comm):
        self.break_on_execve = comm

    def frameFromStackSyscall(self):
        reg_num = self.cpu.iface.int_register.get_number(self.mem_utils.getESP())
        esp = self.cpu.iface.int_register.read(reg_num)
        regs_addr = esp + self.mem_utils.WORD_SIZE
        #self.lgr.debug('frameFromStackSyscall regs_addr is 0x%x  ' % (regs_addr))
        frame = self.task_utils.getFrame(regs_addr, self.cpu)
        return frame

    def stopTrace(self):
        if self.proc_hap is not None:
            self.lgr.debug('syscall stopTrace, delete self.proc_hap')
            self.context_manager.genDeleteHap(self.proc_hap)
            self.proc_hap = None
        for pid in self.exit_hap:
            self.context_manager.genDeleteHap(self.exit_hap[pid])

    def firstMmapHap(self, syscall_info, third, forth, memory):
        self.lgr.debug('firstMmapHap look for pid %d' % syscall_info.pid)
        if syscall_info.pid not in self.first_mmap_hap:
            return
        cpu, comm, pid = self.task_utils.curProc() 
        if syscall_info.cpu is not None and cpu != syscall_info.cpu:
            self.lgr.debug('firstMmapHap, wrong cpu %s %s' % (cpu.name, syscall_info.cpu.name))
            return
        if self.debugging and not self.context_manager.amWatching(pid):
            self.lgr.debug('firstMmapHap looked  found %d.  Do nothing' % (pid))
            return
        frame = self.task_utils.frameFromStackSyscall()
        ida_msg = '%s pid:%d FD: %d buf: 0x%x count: %d' % (self.task_utils.syscallName(syscall_info.callnum), pid, frame['ebx'], frame['ecx'], frame['edx'])
        self.lgr.debug(ida_msg)
        if self.trace_fh is not None:
            self.trace_fh.write(ida_msg+'\n')
        syscall_info.count = syscall_info.count+1
        if syscall_info.count >= 1:
            self.context_manager.genDeleteHap(self.first_mmap_hap[pid])
            del self.first_mmap_hap[pid]
        exit_info = ExitInfo(cpu, pid, syscall_info.callnum)
        exit_info.fname = syscall_info.fname
        phys = self.mem_utils.v2p(cpu, frame['eip'])
        self.exit_break[pid] = self.context_manager.genBreakpoint(self.cpu.physical_memory, Sim_Break_Physical, Sim_Access_Execute, phys, 1, 0)
        self.exit_hap[pid] = self.context_manager.genHapIndex("Core_Breakpoint_Memop", self.exitHap, exit_info, self.exit_break[pid])

    def watchFirstMmap(self, pid, fd, fname):
        callnum = self.task_utils.syscallNumber('mmap2')
        entry = self.task_utils.getSyscallEntry(callnum)
        self.lgr.debug('watchFirstMmap callnum is %s entry 0x%x' % (callnum, entry))
        proc_break = self.context_manager.genBreakpoint(self.cell, Sim_Break_Linear, Sim_Access_Execute, entry, 1, 0)
        syscall_info = SyscallInfo(self.cpu, pid, callnum, entry, True)
        syscall_info.fname = fname
        syscall_info.pid = pid
        self.first_mmap_hap[pid] = self.context_manager.genHapIndex("Core_Breakpoint_Memop", self.firstMmapHap, syscall_info, proc_break)
        
    def parseOpen(self, frame):
        fname_addr = frame['ebx']
        flags = frame['ecx']
        mode = frame['edx']
        fname = self.mem_utils.readString(self.cpu, fname_addr, 256)
        cpu, comm, pid = self.task_utils.curProc() 
        ida_msg = 'open flags: 0x%x  mode: 0x%x  filename: %s   pid: %d' % (flags, mode, fname, pid)
        #self.lgr.debug('parseOpen set ida message to %s' % ida_msg)
        if self.trace_fh is not None:
            #self.trace_fh.write(ida_msg+'\n')
            pass
        else:
            self.context_manager.setIdaMessage(ida_msg)
        return fname, fname_addr, flags, mode

    def finishParseOpen(self, exit_info, third, forth, memory):
        cpu, comm, pid = self.task_utils.curProc() 
        if cpu != exit_info.cpu or pid != exit_info.pid:
            return
        if pid not in self.finish_hap:
            return
        exit_info.fname = self.mem_utils.readString(self.cpu, exit_info.fname_addr, 256)
        SIM_hap_delete_callback_id("Core_Breakpoint_Memop", self.finish_hap[pid])
        SIM_delete_breakpoint(self.finish_break[pid])
        del self.finish_hap[pid]
        del self.finish_break[pid]

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
        ida_msg = 'execve prog: %s %s  pid: %d' % (prog_string, arg_string, call_info.pid)
        if self.trace_fh is not None:
            self.trace_fh.write(ida_msg+'\n')
            if self.traceProcs is not None:
                self.traceProcs.setName(call_info.pid, prog_string, arg_string)
        else:
            #self.context_manager.setIdaMessage(ida_msg)
            pass
        SIM_hap_delete_callback_id("Core_Breakpoint_Memop", self.finish_hap[pid])
        SIM_delete_breakpoint(self.finish_break[pid])
        del self.finish_hap[pid]
        del self.finish_break[pid]
        base = os.path.basename(prog_string)
        if self.break_on_execve is not None and base.startswith(self.break_on_execve):
            self.lgr.debug('finishParseExecve execve of %s' % prog)
            SIM_break_simulation('finishParseExecve execve of %s pid %d' % (prog, call_info.pid))

    def parseExecve(self, frame):
        cpu, comm, pid = self.task_utils.curProc() 
        prog_string, arg_string_list = self.task_utils.getProcArgsFromStack(pid, None, cpu)
        if prog_string is None:
            ''' prog string not in ram, break on kernel read of the address and then read it '''
            prog_addr = self.task_utils.getExecProgAddr(pid, cpu)
            call_info = SyscallInfo(cpu, pid, None, None, None)
            self.finish_break[pid] = SIM_breakpoint(self.cell, Sim_Break_Linear, Sim_Access_Read, prog_addr, 1, 0)
            self.finish_hap[pid] = SIM_hap_add_callback_index("Core_Breakpoint_Memop", self.finishParseExecve, call_info, self.finish_break[pid])
            
            #SIM_break_simulation('finishParseExec')
            return
        nargs = min(4, len(arg_string_list))
        arg_string = ''
        for i in range(nargs):
            if is_ascii(arg_string_list[i]):
                arg_string += arg_string_list[i]+' '
            else:
                break
        ida_msg = 'execve prog: %s %s  pid: %d' % (prog_string, arg_string, pid)
        if self.trace_fh is not None:
            self.trace_fh.write(ida_msg+'\n')
            if self.traceProcs is not None:
                self.traceProcs.setName(pid, prog_string, arg_string)
        else:
            #self.context_manager.setIdaMessage(ida_msg)
            pass
        base = os.path.basename(prog_string)
        if self.break_on_execve is not None and base.startswith(self.break_on_execve):
            SIM_break_simulation('parseExecve execve of %s' % prog_string)
            self.lgr.debug('parseExecve execve of %s pid: %d' % (prog_string, pid))
        return prog_string

    def syscallParse(self, frame, cpu, pid, syscall_info):
        callnum = frame['eax']
        callname = self.task_utils.syscallName(callnum) 
        exit_info = ExitInfo(cpu, pid, callnum)
        if callname == 'open':        
            exit_info.fname, exit_info.fname_addr, exit_info.flags, exit_info.mode = self.parseOpen(frame)
            if exit_info.fname is None:
                ''' filename not yet present in ram, do the two step '''
                self.finish_break[pid] = SIM_breakpoint(self.cell, Sim_Break_Linear, Sim_Access_Read, exit_info.fname_addr, 1, 0)
                self.finish_hap[pid] = SIM_hap_add_callback_index("Core_Breakpoint_Memop", self.finishParseOpen, exit_info, self.finish_break[pid])
        elif callname == 'execve':        
            retval = self.parseExecve(frame)
        elif callname == 'close':        
            fd = frame['ebx']
            if self.traceProcs is not None:
                self.traceProcs.close(pid, fd)
            exit_info.old_fd = fd
            exit_info.call_params = self.sockwatch.getParam(pid, fd)
            self.sockwatch.close(pid, fd)
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
              
            if self.trace_fh is not None:
                self.trace_fh.write(ida_msg+'\n')
            else:
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
                ss = SockStruct(cpu, frame['ecx'], self.mem_utils)
                ida_msg = '%s - %s pid:%d %s %s' % (callname, socket_callname, pid, ss.getString(), ss.addressInfo())
                self.lgr.debug('%s' % ida_msg)
                for call_param in syscall_info.call_params:
                    if call_param.subcall == 'CONNECT':
                         if call_param.match_param is not None and ss.port is not None:
                             ''' look to see if this address matches a given patter '''
                             s = ss.dottedPort()
                             pat = call_param.match_param
                             go = re.search(pat, s, re.M|re.I)
                             if go: 
                                 self.lgr.debug('syscallParse found match %s %s' % (pat, s))
                                 exit_info.call_params = call_param
                                 break
                         elif ROUTABLE in call_param.param_flags and ss.isRoutable():
                             exit_info.call_params = call_param
                             prog = self.traceProcs.getProg(pid)
                             self.connectors.add(pid, prog, ss.dottedIP(), ss.port)
                  
            elif socket_callname == 'BIND':
                ss = SockStruct(cpu, frame['ecx'], self.mem_utils)
                ida_msg = '%s - %s pid:%d %s' % (callname, socket_callname, pid, ss.getString())
                for call_param in syscall_info.call_params:
                    if call_param.subcall == 'BIND':
                         if AF_INET in call_param.param_flags and ss.sa_family == net.AF_INET:
                             exit_info.call_params = call_param
                             self.sockwatch.bind(pid, ss.fd, call_param)

            elif socket_callname == 'ACCEPT':
                ss = SockStruct(cpu, frame['ecx'], self.mem_utils)
                ida_msg = '%s - %s pid:%d FD:%d' % (callname, socket_callname, pid, ss.fd)
                exit_info.call_params = self.sockwatch.getParam(pid, ss.fd)

            elif socket_callnum == net.RECV or socket_callnum == net.RECVFROM or \
                         socket_callnum == net.RECVMSG: 
                ss = SockStruct(cpu, frame['ecx'], self.mem_utils)
                exit_info.old_fd = ss.fd
                exit_info.call_params = self.sockwatch.getParam(pid, ss.fd)
                ida_msg = '%s - %s pid:%d %s' % (callname, socket_callname, pid, ss.getString())
            elif exit_info.socket_callnum == net.SEND or exit_info.socket_callnum == net.SENDTO or \
                         exit_info.socket_callnum == net.SENDMSG: 
                ss = SockStruct(cpu, frame['ecx'], self.mem_utils)
                exit_info.old_fd = ss.fd
                exit_info.call_params = self.sockwatch.getParam(pid, ss.fd)
                ida_msg = '%s - %s pid:%d %s' % (callname, socket_callname, pid, ss.getString())
            elif socket_callname == 'LISTEN':
                ss = SockStruct(cpu, frame['ecx'], self.mem_utils)
                exit_info.call_params = self.sockwatch.getParam(pid, ss.fd)
                ida_msg = '%s - %s pid:%d %s' % (callname, socket_callname, pid, ss.getString())
                    
            else:
                ida_msg = '%s - %s %s   pid:%d' % (callname, socket_callname, taskUtils.stringFromFrame(frame), pid)

            if self.trace_fh is not None:
                ''' trace syscall exit unless call_params narrowed a search failed to find a match '''
                if ida_msg is not None and self.trace_fh is not None and (len(syscall_info.call_params) == 0 or exit_info.call_params is not None):
                    self.trace_fh.write(ida_msg+'\n')
        elif callname == 'read':        
            exit_info.old_fd = frame['ebx']
            ida_msg = 'read pid:%d FD: %d buf: 0x%x count: %d' % (pid, frame['ebx'], frame['ecx'], frame['edx'])
            if self.trace_fh is not None:
                self.trace_fh.write(ida_msg+'\n')
        elif callname == 'write':        
            exit_info.old_fd = frame['ebx']
            ida_msg = 'write pid:%d FD: %d buf: 0x%x count: %d' % (pid, frame['ebx'], frame['ecx'], frame['edx'])
            if self.trace_fh is not None:
                self.trace_fh.write(ida_msg+'\n')
        else:
            ida_msg = '%s %s   pid:%d' % (callname, taskUtils.stringFromFrame(frame), pid)
            if self.trace_fh is not None:
                self.trace_fh.write(ida_msg+'\n')
            else:
                self.context_manager.setIdaMessage(ida_msg)
            if callname == 'pselect6':
                self.trace_fh.flush()
                #SIM_break_simulation('pselect6')
        return exit_info


    def stopHap(self, stop_action, one, exception, error_string):
        if self.stop_hap is not None:
            eip = self.top.getEIP()
            self.lgr.debug('syscall stopHap cycle: 0x%x eip: 0x%x exception %s error %s' % (stop_action.hap_clean.cpu.cycles, eip, str(exception), str(error_string)))
       
            for hc in stop_action.hap_clean.hlist:
                if hc.hap is not None:
                    self.lgr.debug('will delete hap %s' % str(hc.hap))
                    self.context_manager.genDeleteHap(hc.hap)
                    hc.hap = None
            self.lgr.debug('will delete hap %s' % str(self.stop_hap))
            SIM_hap_delete_callback_id("Core_Simulation_Stopped", self.stop_hap)
            self.stop_hap = None
            for bp in stop_action.breakpoints:
                self.context_manager.genDeleteBreakpoint(bp)
            ''' check functions in list '''
            stop_action.run()


    def exitHap(self, exit_info, third, forth, memory):
        ''' assumes we are tracing, record results of call and add
            the clone if that is the call.  TBD race, clone could
            be scheduled before parent returns?
        '''
        cpu, comm, pid = self.task_utils.curProc() 
        callname = self.task_utils.syscallName(exit_info.callnum) 
        if pid in self.exit_break or callname == 'vfork' or callname == 'clone':
            if exit_info.cpu != cpu:
                return
            reg_num = self.cpu.iface.int_register.get_number('eax')
            ueax = self.cpu.iface.int_register.read(reg_num)
            eax = self.mem_utils.getSigned(ueax)
            if eax > 0xffff0000:
                print('eax is 0x%x' % eax)
                print('ueax is 0x%x' % ueax)
                SIM_break_simulation('wtf?, over')
            if exit_info.pid != pid:
                callname = self.task_utils.syscallName(exit_info.callnum) 
                if callname == 'vfork':
                    ''' is fork, TBD assume child returns first?   do not delete Hap ''' 
                    self.trace_fh.write('\texit code: 0x%x  pid: %d\n' % (eax, pid))
                    #self.lgr.debug('exitHap call addProc for pid: %d parent %d' % (eax, pid))
                    if self.traceProcs is not None:
                        self.traceProcs.addProc(eax, pid)
                        self.traceProcs.copyOpen(pid, eax)
                elif callname == 'clone':
                    ''' clone in child '''
                    if exit_info.pid in self.exit_break:
                        self.lgr.debug('clone in child, pid is %d' % pid)
                        self.context_manager.genDeleteBreakpoint(self.exit_break[exit_info.pid])
                        self.context_manager.genDeleteHap(self.exit_hap[exit_info.pid])
                        del self.exit_break[exit_info.pid]
                        del self.exit_hap[exit_info.pid]
                        #SIM_break_simulation('clone in child pid %d parent was %d' % (pid, exit_info.pid))
                else:
                    self.lgr.debug('exitHap expected pid %d, got %d.  Not fork, Do nothing. ' % (exit_info.pid, pid))
                    return
            else:
                if exit_info.callnum == self.task_utils.syscallNumber('clone'):
                    if  self.traceProcs is not None and self.traceProcs.addProc(eax, pid, clone=True):
                        self.trace_fh.write('\treturn from clone, new pid: %d  calling pid: %d\n' % (eax, pid))
                        self.lgr.debug('exitHap call addProc for pid: %d parent %d' % (eax, pid))
                        self.traceProcs.copyOpen(pid, eax)
                        #SIM_break_simulation('exitHap call addProc for pid: %d parent %d' % (eax, pid))
                    elif self.traceProcs is None:
                        self.trace_fh.write('\treturn from clone, new pid: %d  calling pid: %d\n' % (eax, pid))
                    else:
                        ''' must be repeated hap '''
                        return
                elif exit_info.callnum == self.task_utils.syscallNumber('open'):
                    fname = self.mem_utils.readString(exit_info.cpu, exit_info.fname_addr, 256)
                    if eax >= 0:
                        if self.traceProcs is not None:
                            self.traceProcs.open(pid, fname, eax)
                        self.trace_fh.write('\treturn from open pid: %d FD: %d file: %s flags: 0x%x mode: 0x%x\n' % (pid, eax, fname, exit_info.flags, exit_info.mode))
                        if '.so.' in fname:
                            self.watchFirstMmap(pid, eax, fname)
                        
                elif exit_info.callnum == self.task_utils.syscallNumber('pipe') or \
                     exit_info.callnum == self.task_utils.syscallNumber('pipe2'):
                    if eax == 0:
                        fd1 = self.mem_utils.readWord32(cpu, exit_info.retval_addr)
                        fd2 = self.mem_utils.readWord32(cpu, exit_info.retval_addr+4)
                        #self.lgr.debug('return from pipe pid:%d fd1 %d fd2 %d from 0x%x' % (pid, fd1, fd2, exit_info.retval_addr))
                        self.trace_fh.write('\treturn from pipe pid:%d fd1 %d fd2 %d from 0x%x\n' % (pid, fd1, fd2, exit_info.retval_addr))
                        if self.traceProcs is not None:
                            self.traceProcs.pipe(pid, fd1, fd2)

                elif exit_info.callnum == self.task_utils.syscallNumber('read'):
                    if eax >= 0:
                        self.trace_fh.write('\treturn from read pid:%d FD: %d count: %d\n' % (pid, exit_info.old_fd, eax))
                elif exit_info.callnum == self.task_utils.syscallNumber('write'):
                    if eax >= 0:
                        self.trace_fh.write('\treturn from write pid:%d FD: %d count: %d\n' % (pid, exit_info.old_fd, eax))
                elif exit_info.callnum == self.task_utils.syscallNumber('socketcall'):
                    params = exit_info.socket_params
                    socket_callname = net.callname[exit_info.socket_callnum]
                    
                    if exit_info.socket_callnum == net.SOCKET and eax >= 0:
                        if self.traceProcs is not None:
                            self.traceProcs.socket(pid, eax)
                        domain = self.mem_utils.readWord32(cpu, params)
                        sock_type_full = self.mem_utils.readWord32(cpu, params+4)
                        sock_type = sock_type_full & net.SOCK_TYPE_MASK
                        protocol = self.mem_utils.readWord32(cpu, params+8)
                        dstring = net.domaintype[domain]
                        self.trace_fh.write('\treturn from socketcall SOCKET pid:%d, FD: %d domain: %s  type: %d protocol: %d\n' % (pid, eax, dstring, sock_type, protocol))
                        if domain == 2:
                            #SIM_break_simulation('domain 2, params is 0x%x' % params)
                            pass
                    elif exit_info.socket_callnum == net.CONNECT:
                        if eax < 0:
                            if self.trace_fh is not None:
                                self.trace_fh.write('\texception from socketcall CONNECT pid:%d, eax %s\n' % (pid, eax))
                        else:     
                            ss = SockStruct(cpu, params, self.mem_utils)
                            if self.traceProcs is not None:
                                self.traceProcs.connect(pid, ss.fd, ss.getName())
                            if self.trace_fh is not None:
                                self.trace_fh.write('\treturn from socketcall CONNECT pid:%d, %s\n' % (pid, ss.getString()))
                    elif exit_info.socket_callnum == net.BIND:
                        if eax < 0:
                            if self.trace_fh is not None:
                                self.trace_fh.write('\texception from socketcall BIND eax:%d, %s\n' % (pid, eax))
                        else:
                            ss = SockStruct(cpu, params, self.mem_utils)
                            if self.trace_fh is not None:
                                if self.traceProcs is not None:
                                    self.traceProcs.bind(pid, ss.fd, ss.getName())
                                    prog_name = self.traceProcs.getProg(pid)
                                    self.binders.add(pid, prog_name, ss.dottedIP(), ss.port)
                                self.trace_fh.write('\treturn from socketcall BIND pid:%d, %s\n' % (pid, ss.getString()))
                                
                    elif exit_info.socket_callnum == net.ACCEPT:
                        #SIM_break_simulation('socket CONNECT params at 0x%x' % params)
                        new_fd = eax
                        if new_fd < 0:
                            return 
                        ss = SockStruct(cpu, params, self.mem_utils)
                        if self.trace_fh is None:
                            return
                        if ss.sa_family == 1:
                            if self.traceProcs is not None:
                                self.traceProcs.accept(pid, ss.fd, new_fd, None)
                            self.trace_fh.write('\treturn from socketcall ACCEPT pid:%d, sock_fd: %d  new_fd: %d sa_family: %s  name: %s\n' % (pid, ss.fd,
                               new_fd, ss.famName(), ss.getName()))
                        elif ss.sa_family == 2:
                            if self.traceProcs is not None:
                                self.traceProcs.accept(pid, ss.fd, new_fd, ss.getName())
                            self.trace_fh.write('\treturn from socketcall ACCEPT pid:%d, sock_fd: %d  new_fd: %d sa_family: %s  addr: %s\n' % (pid, ss.fd,
                               new_fd, ss.famName(), ss.getName()))
                        else:
                            self.trace_fh.write('\treturn from socketcall ACCEPT pid:%d, sock_fd: %d  new_fd: %d sa_family: %s  SA Family not handled\n' % (pid, ss.fd,
                               new_fd, ss.famName()))
                    elif exit_info.socket_callnum == net.SOCKETPAIR:
                        sock_fd_addr = self.mem_utils.readPtr(cpu, params+12)
                        fd1 = self.mem_utils.readWord32(cpu, sock_fd_addr)
                        fd2 = self.mem_utils.readWord32(cpu, sock_fd_addr+4)
                        if self.traceProcs is not None:
                            self.traceProcs.socketpair(pid, fd1, fd2)
                        self.trace_fh.write('\treturn from socketcall SOCKETPAIR pid:%d, fd1: %d fd2: %d\n' % (pid, fd1, fd2))
                        #self.lgr.debug('\treturn from socketcall SOCKETPAIR pid:%d, fd1: %d fd2: %d' % (pid, fd1, fd2))

                    elif exit_info.socket_callnum == net.SEND or exit_info.socket_callnum == net.SENDTO or \
                         exit_info.socket_callnum == net.SENDMSG: 
                        self.trace_fh.write('\treturn from socketcall %s pid: %d, FD: %d, count: %d\n' % (socket_callname, pid, exit_info.fd, eax))
                    elif exit_info.socket_callnum == net.RECV or exit_info.socket_callnum == net.RECVFROM or \
                         exit_info.socket_callnum == net.RECVMSG: 
                        self.trace_fh.write('\treturn from socketcall %s pid: %d, FD: %d, count: %d\n' % (socket_callname, pid, exit_info.old_fd, eax))
                    elif exit_info.socket_callnum == net.GETPEERNAME:
                        ss = SockStruct(cpu, params, self.mem_utils)
                        self.trace_fh.write('\treturn from socketcall GETPEERNAME pid:%d, %s\n' % (pid, ss.getString()))
                    else:
                        fd = self.mem_utils.readWord32(cpu, params)
                        addr = self.mem_utils.readWord32(cpu, params+4)
                        self.trace_fh.write('\treturn from socketcall %s pid:%d FD:%d addr:0x%x eax: 0x%x\n' % (socket_callname, pid, fd, addr, eax)) 

                elif exit_info.callnum == self.task_utils.syscallNumber('close'):
                    if eax == 0:
                        if self.traceProcs is not None:
                            self.traceProcs.close(pid, eax)
                        self.trace_fh.write('\treturn from close pid:%d, FD: %d\n' % (pid, exit_info.old_fd))
                    
                elif exit_info.callnum == self.task_utils.syscallNumber('dup'):
                    self.lgr.debug('exit pid %d from dup eax %x, old_fd is %d' % (pid, eax, exit_info.old_fd))
                    if eax >= 0:
                        if self.traceProcs is not None:
                            self.traceProcs.dup(pid, exit_info.old_fd, eax)
                        self.trace_fh.write('\treturn from dup pid %d, old_fd: %d new: %d\n' % (pid, exit_info.old_fd, eax))
                elif exit_info.callnum == self.task_utils.syscallNumber('dup2'):
                    self.lgr.debug('return from dup2 pid %d eax %x, old_fd is %d new_fd %d' % (pid, eax, exit_info.old_fd, exit_info.new_fd))
                    if eax >= 0:
                        if exit_info.old_fd != exit_info.new_fd:
                            if self.traceProcs is not None:
                                self.traceProcs.dup(pid, exit_info.old_fd, exit_info.new_fd)
                            self.trace_fh.write('\treturn from dup2 pid:%d, old_fd: %d new: %d\n' % (pid, exit_info.old_fd, eax))
                        else:
                            self.trace_fh.write('\treturn from dup2 pid:%d, old_fd: and new both %d   Eh?\n' % (pid, eax))
                elif exit_info.callnum == self.task_utils.syscallNumber('mmap2'):
                    ''' TBD error handling? '''
                    if exit_info.fname is not None and self.soMap is not None:
                        self.trace_fh.write('\treturn from mmap pid:%d, addr: 0x%x\n' % (pid, ueax))
                        if '/etc/ld.so.cache' not in exit_info.fname:
                            self.soMap.addSO(pid, exit_info.fname, ueax)
                else:
                    callname = self.task_utils.syscallName(exit_info.callnum)
                    self.trace_fh.write('\treturn from call %s code: 0x%x  pid: %d\n' % (callname, ueax, pid))

                if not exit_info.callnum == self.task_utils.syscallNumber('clone'):
                    ''' will be done in clone child.  TBD, assumes child runs second? '''
                    self.context_manager.genDeleteBreakpoint(self.exit_break[pid])
                    self.context_manager.genDeleteHap(self.exit_hap[pid])
                    del self.exit_break[pid]
                    del self.exit_hap[pid]
                ''' if debugging a proc, and clone call, add the new process '''
                if self.debugging and exit_info.callnum == self.task_utils.syscallNumber('clone'):
                    self.lgr.debug('adding clone %d to watched pids' % eax)
                    self.context_manager.addTask(eax)

                if exit_info.call_params is not None and exit_info.call_params.break_simulation:
                    SIM_break_simulation('exitHap found matching call parameters')
                    self.lgr.debug('exitHap found matching call parameters')
                    self.stopTrace()
                    if pid in self.exit_break:
                        del self.exit_break[pid]
                        del self.exit_hap[pid]

            if self.trace_fh is not None:
                self.trace_fh.flush()
        
    def syscallHap(self, syscall_info, third, forth, memory):
        ''' NOTE assumes breaks are only in place while procs of interest are scheduled '''
        ''' NOTE Does not track Tar syscalls! '''
        break_eip = self.top.getEIP()
        cpu, comm, pid = self.task_utils.curProc() 
        #self.lgr.debug('syscallhap for %s at 0x%x' % (pid, break_eip))
        if self.proc_hap is None:
            #self.lgr.debug('syscallHap entered for pid %d after hap deleted' % pid)
            return
        if syscall_info.cpu is not None and cpu != syscall_info.cpu:
            self.lgr.debug('syscallHap, wrong cpu %s %s' % (cpu.name, syscall_info.cpu.name))
            return
        if self.debugging and not self.context_manager.amWatching(pid):
            #self.lgr.debug('syscallHap looked for pid in contextManager  found %d.  Do nothing' % (pid))
            return
        stack_frame = None
        if break_eip == self.param.sysenter:
            ''' caller frame will be in regs'''
            stack_frame = self.task_utils.frameFromRegs(syscall_info.cpu)
            frame_string = taskUtils.stringFromFrame(stack_frame)
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
        elif break_eip == syscall_info.calculated:
            stack_frame = self.task_utils.frameFromStackSyscall()
            frame_string = taskUtils.stringFromFrame(stack_frame)
            #self.lgr.debug('calculated syscall frame %s' % frame_string)
        else:
            self.lgr.error('syscallHap unexpected break_ip 0x%x' % break_eip)
            return

        eax = stack_frame['eax']
        if eax == 0:
            self.lgr.debug('syscallHap eax is zero')
            return
        #self.lgr.debug('syscallHap in proc %d (%s), eax: 0x%x  EIP: 0x%x' % (pid, comm, eax, break_eip))
        frame_string = taskUtils.stringFromFrame(stack_frame)
        #self.lgr.debug('syscallHap frame: %s' % frame_string)
        if syscall_info.callnum is not None:
            if eax == syscall_info.callnum:
                exit_info = self.syscallParse(stack_frame, cpu, pid, syscall_info)
                #self.lgr.debug('syscall 0x%d from %d (%s) at 0x%x cycles: 0x%x' % (eax, pid, comm, break_eip, cpu.cycles))
                if self.trace_fh is None and self.break_on_execve is None and len(syscall_info.call_params) == 0:
                    SIM_break_simulation('syscall frame was %s' % frame_string)
                elif eax != self.task_utils.syscallNumber('execve'):
                    if comm != 'tar':
                        #self.lgr.debug('set return ip break at 0x%x' % stack_frame['eip'])
                        #self.exit_break = self.context_manager.genBreakpoint(self.cell, Sim_Break_Linear, Sim_Access_Execute, stack_frame['eip'], 1, 0)
                        ''' watch syscall exit unless call_params narrowed a search failed to find a match '''
                        if len(syscall_info.call_params) == 0 or exit_info.call_params is not None:
                            phys = self.mem_utils.v2p(cpu, stack_frame['eip'])
                            self.exit_break[pid] = self.context_manager.genBreakpoint(self.cpu.physical_memory, 
                                                                            Sim_Break_Physical, Sim_Access_Execute, phys, 1, 0)
                            self.exit_hap[pid] = self.context_manager.genHapIndex("Core_Breakpoint_Memop", self.exitHap, exit_info, self.exit_break[pid])
                
            else:
                #self.lgr.debug('syscallHap looked for call %d, got %d, calculated 0x%x do nothing' % (syscall_info.callnum, eax, syscall_info.calculated))
                pass
        else:
            exit_info = self.syscallParse(stack_frame, cpu, pid, syscall_info)
            #self.lgr.debug('syscall looking for any, got 0x%d from %d (%s) at 0x%x ' % (eax, pid, comm, break_eip))
            if self.trace_fh is None:
                SIM_break_simulation('syscall')
            elif eax != self.task_utils.syscallNumber('execve') and comm != 'tar':
                #self.lgr.debug('set return ip break at 0x%x' % stack_frame['eip'])
                #self.exit_break = self.context_manager.genBreakpoint(self.cell, Sim_Break_Linear, Sim_Access_Execute, stack_frame['eip'], 1, 0)
                phys = self.mem_utils.v2p(cpu, stack_frame['eip'])
                self.exit_break[pid] = self.context_manager.genBreakpoint(self.cpu.physical_memory, Sim_Break_Physical, Sim_Access_Execute, phys, 1, 0)
                self.exit_hap[pid] = self.context_manager.genHapIndex("Core_Breakpoint_Memop", self.exitHap, exit_info, self.exit_break[pid])

    def getBinders(self):
        return self.binders
    def getConnectors(self):
        return self.connectors
