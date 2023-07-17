'''
 * This software was created by United States Government employees
 * and may not be copyrighted.
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
 * ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
'''
from simics import *
import pageUtils
import memUtils
import net
import ipc
import allWrite
import syscall
import resimUtils
import epoll
import winCallExit
from resimHaps import *
'''
Handle returns to user space from system calls.  May result in call_params matching.  NOTE: stop actions (stop_action) for 
matched parameters are handled by the stopHap in the syscall module that handled the call.
'''
class SharedSyscall():
    def __init__(self, top, cpu, cell, cell_name, param, mem_utils, task_utils, context_manager, traceProcs, traceFiles, soMap, dataWatch, traceMgr, lgr):
        self.pending_execve = []
        self.lgr = lgr
        self.cpu = cpu
        self.cell = cell
        self.cell_name = cell_name
        self.task_utils = task_utils
        self.param = param
        self.mem_utils = mem_utils
        self.context_manager = context_manager
        self.traceProcs = traceProcs
        self.exit_info = {}
        self.matching_exit_info = None
        self.exit_pids = {}
        self.trace_procs = []
        self.exit_hap = {}
        self.exit_names = {} 
        self.debugging = False
        self.traceMgr = traceMgr
        self.traceFiles = traceFiles
        self.soMap = soMap
        self.dataWatch = dataWatch
        self.top = top
        self.track_so = True
        self.all_write = False
        self.allWrite = allWrite.AllWrite()
        ''' used for origin reset'''
        self.stop_hap = None
        ''' used by writeData to make application think fd has no more data '''
        self.fool_select = None
        ''' piggyback datawatch kernel returns '''
        self.callback = None
        self.callback_param = None
   
        self.kbuffer = None
        ''' Adjust read return counts using writeData '''
        self.read_fixup_callback = None

        if self.top.isWindows():
            self.win_call_exit = winCallExit.WinCallExit(top, cpu, cell, cell_name, param, mem_utils, task_utils, 
                      context_manager, traceProcs, traceFiles, self.soMap, dataWatch, traceMgr, self.lgr)
        else:
            self.win_call_exit = None

        ''' optimization if "only" or "ignore" lists are used '''
        self.preserve_exit = False

    def trackSO(self, track_so):
        #self.lgr.debug('sharedSyscall track_so %r' % track_so)
        self.track_so = track_so

    def setDebugging(self, debugging):
        self.lgr.debug('SharedSyscall set debugging %r' % debugging)
        self.debugging = debugging

    def getPendingCall(self, pid, name):
        if pid in self.exit_info:
            if name in self.exit_info[pid] and self.exit_info[pid][name] is not None:
                return self.exit_info[pid][name].callnum
            elif len(self.exit_info[pid]) > 0:
                existing = next(iter(self.exit_info[pid]))
                #self.lgr.debug('sharedSyscall getPendingCall, no call for %s, returning for %s' % (name, existing))
                if existing in self.exit_info[pid] and self.exit_info[pid][existing] is not None:
                    return self.exit_info[pid][existing].callnum
          
        return None

    def stopTrace(self):
        for context in self.exit_pids:
            #self.lgr.debug('sharedSyscall stopTrace context %s' % str(context))
            for eip in self.exit_hap:
                self.context_manager.genDeleteHap(self.exit_hap[eip], immediate=True)
                #self.lgr.debug('sharedSyscall stopTrace removed exit hap for eip 0x%x context %s' % (eip, str(context)))
            self.exit_pids[context] = {}
        for eip in self.exit_hap:
            self.exit_info[eip] = {}

    def showExitHaps(self):
        if self.cpu.current_context not in self.exit_pids:
            print('context %s not in exit_pids' % self.cpu.current_context)
            return
        my_exit_pids = self.exit_pids[self.cpu.current_context]
        for eip in my_exit_pids:
            print('eip: 0x%x' % eip)
            for pid in my_exit_pids[eip]:
                prog = self.task_utils.getProgName(pid)
                if prog is not None:
                    print('\t%d %s' % (pid, prog))
                else:
                    print('\t%d' % (pid))

    def rmExitHap(self, pid, context=None):
        if context is not None:
            use_context = context
        else:
            use_context = self.cpu.current_context
        if use_context not in self.exit_pids:
            #self.lgr.debug('rmExitHap context %s not in exit_pids, do nothing?' % str(use_context))
            return
        my_exit_pids = self.exit_pids[use_context]
        if pid is not None:
            #self.lgr.debug('rmExitHap for pid %d' % pid)
            for eip in my_exit_pids:
                if pid in my_exit_pids[eip]:
                    my_exit_pids[eip].remove(pid)
                    #self.lgr.debug('rmExitHap removed pid %d for eip 0x%x cycle: 0x%x' % (pid, eip, self.cpu.cycles))
                    if len(my_exit_pids[eip]) == 0:
                        if  self.preserve_exit:
                            ''' add a dummy entry to preserve exit haps '''
                            self.lgr.debug('rmExitHap len of exit_pids[0x%x] is zero, but we are preserving os add a dummy entry' % eip)
                            my_exit_pids[eip].append(-1)
                        else:
                            self.lgr.debug('rmExitHap len of exit_pids[0x%x] is zero, delete exit hap' % eip)
                            self.context_manager.genDeleteHap(self.exit_hap[eip])
            self.exit_info[pid] = {}     

        else:
            ''' assume the exitHap was for a one-off syscall such as execve that
                broke the simulation. '''
            ''' TBD NOTE procs returning from blocked syscalls will not be caught! '''
            for eip in my_exit_pids:
                #del my_exit_pids[eip][:]
                my_exit_pids[eip] = []
                if eip in self.exit_hap:
                    #self.lgr.debug('sharedSyscall rmExitHap, call contextManager to delete exit hap')
                    self.context_manager.genDeleteHap(self.exit_hap[eip])
                    del self.exit_hap[eip]
                self.lgr.debug('sharedSyscall rmExitHap, assume one-off syscall, cleared exit hap')


    def addExitHap(self, cell, pid, exit_eip1, exit_eip2, exit_eip3, exit_info, name, context_override=None):
        if pid not in self.exit_info:
            self.exit_info[pid] = {}
        self.exit_info[pid][name] = exit_info
        if self.traceProcs is not None:
            self.trace_procs.append(pid)
        self.exit_names[pid] = name
        if context_override is None:
            current_context = self.cpu.current_context
        else:
            current_context = context_override
        #self.lgr.debug('sharedSyscall addExitHap pid:%d name %s current_context %s' % (pid, name, str(current_context)))
        if current_context not in self.exit_pids:
            self.exit_pids[current_context] = {}
        my_exit_pids = self.exit_pids[current_context]
        if exit_eip1 not in my_exit_pids:
            my_exit_pids[exit_eip1] = []

        if cell is None and exit_info.syscall_instance.name is not None:
            if exit_info.syscall_instance.name.startswith('dmod'):
                cell = self.top.getCell(self.cell_name)
                #self.lgr.debug('sharedSyscall addExitHap, cell is None, is dmod, set cell to %s' % cell) 

        if exit_eip1 is not None: 
            #self.lgr.debug('addExitHap exit_eip1 0x%x not none, len of exit pids is %d' % (exit_eip1, len(my_exit_pids[exit_eip1])))
            if len(my_exit_pids[exit_eip1]) == 0:
                self.lgr.debug('addExitHap new exit EIP1 0x%x for pid %d cell: %s' % (exit_eip1, pid, cell))
                exit_break = self.context_manager.genBreakpoint(cell, 
                                    Sim_Break_Linear, Sim_Access_Execute, exit_eip1, 1, 0)
                self.exit_hap[exit_eip1] = self.context_manager.genHapIndex("Core_Breakpoint_Memop", self.exitHap, 
                                   None, exit_break, 'exit hap')
                self.lgr.debug('sharedSyscall addExitHap added exit hap %d' % self.exit_hap[exit_eip1])
            my_exit_pids[exit_eip1].append(pid)
            #self.lgr.debug('sharedSyscall addExitHap appended pid %d for exitHap for 0x%x' % (pid, exit_eip1))
        else:
            pass
            #self.lgr.debug('sharedSyscall addExitHap exit_eip1 is None')

        if exit_eip2 is not None:
            if exit_eip2 not in my_exit_pids:
                my_exit_pids[exit_eip2] = []

            if len(my_exit_pids[exit_eip2]) == 0:
                #self.lgr.debug('addExitHap new exit EIP2 0x%x for pid %d' % (exit_eip2, pid))
                exit_break = self.context_manager.genBreakpoint(cell, 
                                    Sim_Break_Linear, Sim_Access_Execute, exit_eip2, 1, 0)
                self.exit_hap[exit_eip2] = self.context_manager.genHapIndex("Core_Breakpoint_Memop", self.exitHap, 
                                   None, exit_break, 'exit hap2')
                self.lgr.debug('sharedSyscall added exit hap2 %d' % self.exit_hap[exit_eip2])
            else:
                #self.lgr.debug('sharedSyscall has exit pid for EIP2, len is %d' % len(my_exit_pids[exit_eip2]))
                #for pid in my_exit_pids[exit_eip2]:
                #    self.lgr.debug('\t got pid %d in exit_pids for exit_eip2' % pid)
                pass
            my_exit_pids[exit_eip2].append(pid)
        else:
            #self.lgr.debug('sharedSyscall addExitHap exit_eip2 is None')
            pass

        if exit_eip3 is not None:
            if exit_eip3 not in my_exit_pids:
                my_exit_pids[exit_eip3] = []

            if len(my_exit_pids[exit_eip3]) == 0:
                #self.lgr.debug('addExitHap new exit EIP3 0x%x for pid %d' % (exit_eip3, pid))
                exit_break = self.context_manager.genBreakpoint(cell, 
                                    Sim_Break_Linear, Sim_Access_Execute, exit_eip3, 1, 0)
                self.exit_hap[exit_eip3] = self.context_manager.genHapIndex("Core_Breakpoint_Memop", self.exitHap, 
                                   None, exit_break, 'exit hap3')
                #self.lgr.debug('sharedSyscall added exit hap3 %d' % self.exit_hap[exit_eip3])
            my_exit_pids[exit_eip3].append(pid)

        if exit_info is not None:
            callname = self.task_utils.syscallName(exit_info.callnum, exit_info.compat32)
            if callname == 'execve':
                self.addPendingExecve(pid)
        else:
            self.lgr.debug('exit_info was None for name: %s' % name)


        #self.lgr.debug('sharedSyscall addExitHap return pid %d' % pid)


    def addPendingExecve(self, pid):
        self.lgr.debug('sharedSyscall addPendingExecve pid:%d' % pid)
        if pid not in self.pending_execve:
            self.pending_execve.append(pid)

    def rmPendingExecve(self, pid):
        if pid in self.pending_execve:
            self.lgr.debug('sharedSyscall rmPendingExecve remove %d' % pid)
            self.pending_execve.remove(pid)
            self.rmExitHap(pid)
        else:
            self.lgr.debug('sharedSyscall rmPendingExecve nothing pending for %d' % pid)

    def isPendingExecve(self, pid):
        if pid in self.pending_execve:
            return True
        else:
            return False

    def getEIP(self):
        eip = self.mem_utils.getRegValue(self.cpu, 'eip')
        return eip

    def doSockets(self, exit_info, eax, pid):
        trace_msg = ''
        if exit_info.callnum == self.task_utils.syscallNumber('socketcall', exit_info.compat32):
            socket_callname = exit_info.socket_callname
            socket_syscall = self.top.getSyscall(self.cell_name, 'socketcall')
        else:
            socket_callname = self.task_utils.syscallName(exit_info.callnum, exit_info.compat32) 
            socket_syscall = self.top.getSyscall(self.cell_name, socket_callname)
                    
        if socket_callname == "socket" and eax >= 0:
            if pid in self.trace_procs:
                self.traceProcs.socket(pid, eax)
            trace_msg = ('\treturn from socketcall SOCKET pid:%d, FD: %d\n' % (pid, eax))
            exit_info.syscall_instance.bindFDToSocket(pid, eax)
        elif socket_callname == "connect":
            if eax < 0:
                trace_msg = ('\texception from socketcall CONNECT pid:%d FD: %d, eax %s  addr: 0x%x\n' % (pid, 
                    exit_info.sock_struct.fd, eax, exit_info.sock_struct.addr))
            if True:
                ss = exit_info.sock_struct
                if pid in self.trace_procs:
                    self.traceProcs.connect(pid, ss.fd, ss.getName())
                if eax >= 0:
                    trace_msg = ('\treturn from socketcall CONNECT pid:%d, %s  addr: 0x%x\n' % (pid, ss.getString(), exit_info.sock_struct.addr))
                if socket_syscall is not None:
                    connectors = socket_syscall.getConnectors()
                    if connectors is not None:
                        if self.traceProcs is not None:
                            prog = self.traceProcs.getProg(pid)
                            if ss.port is not None:
                                self.lgr.debug('adding connector for pid:%d %s %s %s' % (pid, prog, ss.dottedIP(), str(ss.port)))
                                connectors.add(pid, ss.fd, prog, ss.dottedIP(), ss.port)
                            else:
                                self.lgr.debug('adding connector for pid:%d %s %s' % (pid, prog, ss.sa_data))
                                connectors.add(pid, ss.fd, prog, '', ss.sa_data)
                    
        elif socket_callname == "bind":
            if eax < 0:
                trace_msg = ('\texception from socketcall BIND eax:%d, %s\n' % (pid, eax))
            else:
                ss = exit_info.sock_struct
                if pid in self.trace_procs:
                    self.traceProcs.bind(pid, ss.fd, ss.getName())
                    prog_name = self.traceProcs.getProg(pid)
                    if socket_syscall is not None:
                        binders = socket_syscall.getBinders()
                        if binders is not None:
                            if ss.port is not None:
                                binders.add(pid, ss.fd, prog_name, ss.dottedIP(), ss.port)
                            else:
                                binders.add(pid, ss.fd, prog_name, ss.dottedIP(), ss.sa_data)
                trace_msg = ('\treturn from socketcall BIND pid:%d, %s\n' % (pid, ss.getString()))
                    
        elif socket_callname == "getsockname":
            ss = net.SockStruct(self.cpu, exit_info.sock_struct.addr, self.mem_utils, exit_info.sock_struct.fd)
            trace_msg = ('\t return from getsockname pid:%d %s\n' % (pid, ss.getString()))

        elif socket_callname == "accept" or socket_callname == "accept4":
            new_fd = eax
            if new_fd < 0:
                trace_msg = ('\terror return from socketcall ACCEPT pid:%d, error: %d\n' % (pid, eax))
            elif exit_info.sock_struct.addr != 0:
                in_ss = exit_info.sock_struct
                addr_len = self.mem_utils.readWord32(self.cpu, in_ss.length)
                self.lgr.debug('accept addr 0x%x  len_addr 0x%x, len %d' % (in_ss.addr, in_ss.length, addr_len))
                ss = net.SockStruct(self.cpu, exit_info.sock_struct.addr, self.mem_utils)
                if ss.sa_family == 1:
                    if pid in self.trace_procs:
                        self.traceProcs.accept(pid, exit_info.sock_struct.fd, new_fd, None)
                    trace_msg = ('\treturn from socketcall ACCEPT pid:%d, sock_fd: %d  new_fd: %d sa_family: %s  name: %s\n' % (pid, exit_info.sock_struct.fd,
                       new_fd, ss.famName(), ss.getName()))
                elif ss.sa_family == 2:
                    if pid in self.trace_procs:
                        self.traceProcs.accept(pid, exit_info.sock_struct.fd, new_fd, ss.getName())
                    trace_msg = ('\treturn from socketcall ACCEPT pid:%d, sock_fd: %d  new_fd: %d sa_family: %s  addr: %s\n' % (pid, exit_info.sock_struct.fd,
                       new_fd, ss.famName(), ss.getName()))
                else:
                    trace_msg = ('\treturn from socketcall ACCEPT pid:%d, sock_fd: %d  new_fd: %d sa_family: %s  SA Family not handled addr: 0x%x\n' % (pid, 
                         exit_info.sock_struct.fd, new_fd, ss.famName(), exit_info.sock_struct.addr))
                    #SIM_break_simulation(trace_msg)
                self.lgr.debug(trace_msg)
                my_syscall = exit_info.syscall_instance
                if exit_info.call_params is not None and (exit_info.call_params.break_simulation or my_syscall.linger) and self.dataWatch is not None:
                    ''' in case we want to break on a read of address data '''
                    self.dataWatch.setRange(in_ss.addr, addr_len, trace_msg, back_stop=False)
                    #if my_syscall.linger: 
                    ''' TBD better way to distinguish linger from trackIO '''
                    if not self.dataWatch.wouldBreakSimulation():
                        self.dataWatch.stopWatch() 
                        #self.dataWatch.watch(break_simulation=False)
                        self.lgr.debug('sharedSyscall accept call dataWatch watch')
                        self.dataWatch.watch(break_simulation=exit_info.call_params.break_simulation, i_am_alone=True)
                if exit_info.call_params is not None and my_syscall.name == 'runToIO' and exit_info.call_params.match_param == exit_info.sock_struct.fd:
                    self.lgr.debug('sharedSyscall for runToIO, change param fd to %d' % new_fd)
                    exit_info.call_params.match_param = new_fd
                if socket_syscall is not None:
                    binders = socket_syscall.getBinders()
                    if binders is not None:
                        binders.accept(pid, exit_info.sock_struct.fd, new_fd)
            else:
                trace_msg = ('\treturn from socketcall ACCEPT pid:%d, sock_fd: %d  new_fd: %d NULL addr\n' % (pid, exit_info.sock_struct.fd, new_fd))
        elif socket_callname == "socketpair":
            if exit_info.retval_addr is None:
                self.lgr.error('sharedSyscall socketpair got null retval addr')
                return 'socketpair bad retval addr?'
            fd1 = self.mem_utils.readWord32(self.cpu, exit_info.retval_addr)
            fd2 = self.mem_utils.readWord32(self.cpu, exit_info.retval_addr+4)
            if pid in self.trace_procs:
                self.traceProcs.socketpair(pid, fd1, fd2)
            trace_msg = ('\treturn from socketcall SOCKETPAIR pid:%d, fd1: %s fd2: %s\n' % (pid, str(fd1), str(fd2)))
            #self.lgr.debug('\treturn from socketcall SOCKETPAIR pid:%d, fd1: %d fd2: %d' % (pid, fd1, fd2))

        elif socket_callname == "send" or socket_callname == "sendto": 
            if eax >= 0:
                nbytes = min(eax, 256)
                byte_array = self.mem_utils.getBytes(self.cpu, eax, exit_info.retval_addr)
                ''' byte_array is a tuple of bytes'''
                if byte_array is not None:
                    s = resimUtils.getHexDump(byte_array[:nbytes])
                    if self.traceFiles is not None:
                        self.traceFiles.write(pid, exit_info.old_fd, byte_array)
                else:
                    s = '<< NOT MAPPED >>'
                eip = self.getEIP()
                if exit_info.retval_addr is None:
                    self.lgr.error('sharedSyscall %s failed to get retval addr' % socket_callname)
                    return
                trace_msg = ('\treturn from socketcall %s pid:%d, FD: %d, count: %d from 0x%x cycle: 0x%x eip: 0x%x\n%s\n' % (socket_callname, pid, exit_info.old_fd, 
                    eax, exit_info.retval_addr, self.cpu.cycles, eip, s))
            else:
                trace_msg = ('\terror return from socketcall %s pid:%d, FD: %d, exception: %d\n' % (socket_callname, pid, exit_info.old_fd, eax))

            if exit_info.call_params is not None:
                if syscall.DEST_PORT in exit_info.call_params.param_flags: 
                    self.lgr.debug('sharedSyscall sendto found dest port match.')
                elif type(exit_info.call_params.match_param) is str and eax > 0:
                    self.lgr.debug('sharedSyscall SEND check string %s against %s' % (s, exit_info.call_params.match_param))
                    if exit_info.call_params.match_param not in s:
                        ''' no match, set call_param to none '''
                        exit_info.call_params = None

        elif socket_callname == "sendmsg":
            s = ''
            if eax >= 0:
                msghdr = exit_info.msghdr
                if msghdr is None:
                    trace_msg = ('\treturn from socketcall %s pid:%d FD: %s count: %d no msghdr' % (socket_callname, pid, str(exit_info.old_fd), eax))
                else:
                    trace_msg = ('\treturn from socketcall %s pid:%d FD: %s count: %d %s' % (socket_callname, pid, str(exit_info.old_fd), eax, msghdr.getString()))
                if pid in self.trace_procs:
                    if self.traceProcs.isExternal(pid, exit_info.old_fd):
                        trace_msg = trace_msg +' EXTERNAL'
                trace_msg = trace_msg + '\n'
                if msghdr is not None:
                    s =msghdr.getBytes()
                    trace_msg = trace_msg+'\t'+s+'\n'
            else:
                trace_msg = ('\terror return from socketcall %s pid:%d, FD: %s, exception: %d\n' % (socket_callname, pid, str(exit_info.old_fd), eax))
            if exit_info.call_params is not None:
                if syscall.DEST_PORT in exit_info.call_params.param_flags: 
                    self.lgr.debug('sharedSyscall sendmsg found dest port match.')
                elif type(exit_info.call_params.match_param) is str and eax > 0:
                    self.lgr.debug('sharedSyscall SEND check string %s against %s' % (s, exit_info.call_params.match_param))
                    if exit_info.call_params.match_param not in s:
                        ''' no match, set call_param to none '''
                        exit_info.call_params = None

        elif socket_callname == "recv" or socket_callname == "recvfrom":
            if self.read_fixup_callback is not None:
                self.lgr.debug('sharedSyscall call read_fixup_callback eax was %d' % eax)
                eax = self.read_fixup_callback(exit_info.old_fd)
            if eax >= 0:
                nbytes = min(eax, 256)
                byte_array = self.mem_utils.getBytes(self.cpu, eax, exit_info.retval_addr)
                if byte_array is not None:
                    s = resimUtils.getHexDump(byte_array[:nbytes])
                    if self.traceFiles is not None:
                        self.traceFiles.read(pid, exit_info.old_fd, byte_array)
                else:
                    s = '<< NOT MAPPED >>'
                src = ''
                if exit_info.fname_addr is not None:
                    ''' obscure use of fname_addr to store source of recvfrom '''
                    src_ss = net.SockStruct(self.cpu, exit_info.fname_addr, self.mem_utils, fd=-1)
                    src = 'from: %s' % src_ss.getString()
                if exit_info.old_fd is None:
                    self.lgr.error('sharedSyscall exit_info old_fd is None for recv call')
                    exit_info.call_params = None
                    trace_msg = ('\treturn from socketcall %s pid:%d  FD: None' % (socket_callname, pid))
                    return trace_msg 
                if exit_info.sock_struct.length is None:
                    self.lgr.debug('sharedSyscall exit_info sock_struct.length is None for recv call')
                    trace_msg = ('\treturn from socketcall %s pid:%d  FD: %d length none (from revToCall?)' % (socket_callname, pid, exit_info.old_fd))
                    return trace_msg 
                trace_msg = ('\treturn from socketcall %s pid:%d, FD: %d, len: %d count: %d into 0x%x %s\n%s\n' % (socket_callname, pid, 
                     exit_info.old_fd, exit_info.sock_struct.length, eax, exit_info.retval_addr, src, s))
                self.lgr.debug(trace_msg)
                my_syscall = exit_info.syscall_instance
                if exit_info.call_params is not None and (exit_info.call_params.break_simulation or my_syscall.linger) and self.dataWatch is not None:
                    ''' in case we want to break on a read of this data.  NOTE: length was the given length, changed to count'''
                    self.lgr.debug('recv call setRange retval_addr 0x%x count len %d length %d' % (exit_info.retval_addr, eax, exit_info.sock_struct.length))
                    if self.kbuffer is not None:
                        self.kbuffer.readReturn(eax)
                    self.dataWatch.setRange(exit_info.retval_addr, eax, msg=trace_msg, 
                               max_len=exit_info.sock_struct.length, recv_addr=exit_info.retval_addr, fd=exit_info.old_fd)
                    if exit_info.fname_addr is not None:
                        count = self.mem_utils.readWord32(self.cpu, exit_info.count)
                        msg = 'recvfrom source for above, addr 0x%x %d bytes' % (exit_info.fname_addr, count)
                        self.dataWatch.setRange(exit_info.fname_addr, count, msg)
                    if my_syscall.linger: 
                        self.dataWatch.stopWatch() 
                        self.dataWatch.watch(break_simulation=False, i_am_alone=True)
            
                    if exit_info.origin_reset:
                        self.lgr.debug('sharedSyscall found origin reset, do it')
                        SIM_run_alone(self.stopAlone, None)
            else:
                if exit_info.retval_addr is None:
                    self.lgr.debug('sharedSyscall exit_info retval_addr is None for recv call with nonzero eax')
                    trace_msg = ('\treturn from socketcall %s pid:%d  eax nonzero retval_addr: None' % (socket_callname, pid))
                    return trace_msg
                if exit_info.old_fd is None:
                    self.lgr.error('sharedSyscall exit_info old_fd is None for recv call with nonzero eax')
                    exit_info.call_params = None
                    trace_msg = ('\treturn from socketcall %s pid:%d  eax nonzeroFD: None' % (socket_callname, pid))
                    return trace_msg
                trace_msg = ('\terror return from socketcall %s pid:%d, FD: %d, exception: %d into 0x%x\n' % (socket_callname, pid, exit_info.old_fd, eax, exit_info.retval_addr))
                exit_info.call_params = None

        elif socket_callname == "recvmsg": 
            self.lgr.debug('sharedSyscall doSockets recvmsg')
            if eax < 0:
                trace_msg = ('\terror return from socketcall %s pid:%d FD: %d exception: %d \n' % (socket_callname, pid, exit_info.old_fd, eax))
                exit_info.call_params = None
            else:
                #msghdr = net.Msghdr(self.cpu, self.mem_utils, exit_info.retval_addr)
                msghdr = exit_info.msghdr
                iovec = msghdr.getIovec()
                trace_msg = ('\treturn from socketcall %s pid:%d FD: %d count: %d first buffer: 0x%x' % (socket_callname, pid, exit_info.old_fd, eax, iovec[0].base))
                if pid in self.trace_procs:
                    if self.traceProcs.isExternal(pid, exit_info.old_fd):
                        trace_msg = trace_msg +' EXTERNAL'
                trace_msg = trace_msg + '\n'
                s = msghdr.getBytes()
                trace_msg = trace_msg+'\t'+s+'\n'
                if exit_info.call_params is not None:
                    self.lgr.debug('sharedSyscall recvms has param %s' % exit_info.call_params)
                my_syscall = exit_info.syscall_instance
                if exit_info.call_params is not None and (exit_info.call_params.break_simulation or my_syscall.linger) and self.dataWatch is not None:
                    ''' in case we want to break on a read of this data. ''' 

                    iov_size = 2*self.mem_utils.WORD_SIZE
                    iov_addr = msghdr.msg_iov
                    limit = min(10, msghdr.msg_iovlen)
                    remain = eax 
                    self.lgr.debug('dataWatch recvmsg eax is %d' % eax)
                    if self.kbuffer is not None:
                        self.kbuffer.readReturn(eax)
                    for i in range(limit):
                        base = self.mem_utils.readPtr(self.cpu, iov_addr)
                        length = self.mem_utils.readPtr(self.cpu, iov_addr+self.mem_utils.WORD_SIZE)
                        if remain > length:
                            data_len = length
                        else:
                            data_len = remain
                        remain = remain - data_len 
                        iov_addr = iov_addr+iov_size
                        if exit_info.retval_addr is None:
                            ''' TBD generalize this for use by prepInject'''
                            exit_info.retval_addr = base
                            exit_info.count = data_len
                        self.lgr.debug('dataWatch recvmsg setRange base 0x%x len %d' % (base, data_len))
                        self.dataWatch.setRange(base, data_len, msg=trace_msg, max_len=length, fd=exit_info.old_fd)
                    self.lgr.debug('recvmsg set dataWatch')
                    if my_syscall.linger: 
                        self.dataWatch.stopWatch() 
                        self.dataWatch.watch(break_simulation=False, i_am_alone=True)
                    if type(exit_info.call_params.match_param) is str:
                        self.lgr.debug('sharedSyscall recvmsg check string %s against %s' % (s, exit_info.call_params.match_param))
                        if exit_info.call_params.match_param not in s: 
                            exit_info.call_params = None
                    #else:
                    #    self.lgr.error('sharedSyscall unhandled call_param %s' % (exit_info.call_params))
                    #    exit_info.call_params = None
                    if exit_info.origin_reset:
                        self.lgr.debug('sharedSyscall found origin reset, do it')
                        SIM_run_alone(self.stopAlone, None)
            
        elif socket_callname == "getpeername":
            ss = net.SockStruct(self.cpu, exit_info.sock_struct.addr, self.mem_utils)
            trace_msg = ('\treturn from socketcall GETPEERNAME pid:%d, %s  eax: 0x%x\n' % (pid, ss.getString(), eax))
        elif socket_callname == 'setsockopt':
            trace_msg = ('\treturn from socketcall SETSOCKOPT pid:%d eax: 0x%x\n' % (pid, eax))
        elif socket_callname == 'getsockopt':
            optval_val = ''
            if exit_info.retval_addr != 0 and eax == 0:
                ''' note exit_info.count is ptr to returned count '''
                count = self.mem_utils.readWord32(self.cpu, exit_info.count)
                rcount = min(count, 80)
                thebytes = self.mem_utils.getBytesHex(self.cpu, rcount, exit_info.retval_addr)
                optval_val = 'optlen: %d option: %s' % (count, thebytes)
            trace_msg = ('\treturn from getsockopt pid:%d %s result %d\n' % (pid, optval_val, eax))
          
        else:
            #fd = self.mem_utils.readWord32(self.cpu, params)
            #addr = self.mem_utils.readWord32(self.cpu, params+4)
            #trace_msg = ('\treturn from socketcall %s pid:%d FD: %d addr:0x%x eax: 0x%x\n' % (socket_callname, pid, fd, addr, eax)) 
            if exit_info.sock_struct is not None:
                trace_msg = ('\treturn from socketcall %s pid:%d FD: %d addr:0x%x eax: 0x%x\n' % (socket_callname, pid, exit_info.sock_struct.fd, exit_info.sock_struct.addr, eax)) 
            elif socket_callname != 'socket':
                self.lgr.debug('sharedSyscall pid:%d %s missing sock_struct, double call, it hap twice??' % (pid, socket_callname))
        return trace_msg

    def exitHap(self, dumb, context, break_num, memory):
        if self.context_manager.isReverseContext():
            return
        cpu, comm, pid = self.task_utils.curProc() 
        if cpu is None:
            self.lgr.error('sharedSyscall exitHap got nothing from curProc')
            return
        #self.lgr.debug('sharedSyscall exitHap pid:%d (%s) context: %s  break_num: %s cycle: 0x%x reverse context? %r' % (pid, comm, str(context), str(break_num), self.cpu.cycles, self.context_manager.isReverseContext()))
        did_exit = False
        if pid in self.exit_info:
            for name in self.exit_info[pid]:
                try:
                    exit_info = self.exit_info[pid][name]
                except:
                    continue
                #self.lgr.debug('exitHap pid:%d name: %s' % (pid, name))
                if self.win_call_exit is not None:
                    did_exit = self.win_call_exit.handleExit(exit_info, pid, comm)
                else:
                    did_exit = self.handleExit(exit_info, pid, comm)
        else:
            if self.win_call_exit is not None:
                #self.lgr.debug('sharedSyscall exitHap pid %d not in exit_info' % pid)
                did_exit = self.win_call_exit.handleExit(None, pid, comm)
            else:
                did_exit = self.handleExit(None, pid, comm)
        if did_exit:
            #self.lgr.debug('sharedSyscall exitHap remove exitHap for %d' % pid)
            self.rmExitHap(pid)
            if self.callback is not None:
                self.lgr.debug('sharedSyscall exitHap call callback (dataWatch kernelReturnHap?)')
                self.callback(self.callback_param, context, break_num, memory)
                self.callback = None

    def fcntl(self, pid, eax, exit_info):
        if net.fcntlCmdIs(exit_info.cmd, 'F_DUPFD'):
            if pid in self.trace_procs:
                self.traceProcs.dup(pid, exit_info.old_fd, eax)
            trace_msg = ('\treturn from fcntl64 F_DUPFD pid %d, old_fd: %d new: %d\n' % (pid, exit_info.old_fd, eax))
        elif net.fcntlCmdIs(exit_info.cmd, 'F_GETFL'):
            trace_msg = ('\treturn from fcntl64 F_GETFL pid %d, old_fd: %d  flags: 0%o\n' % (pid, exit_info.old_fd, eax))
        else:
            trace_msg = ('\treturn from fcntl64  pid %d, old_fd: %d retval: %d\n' % (pid, exit_info.old_fd, eax))
            return trace_msg
       
            
    def handleExit(self, exit_info, pid, comm):
        ''' 
           Invoked on (almost) return to user space after a system call.
           Includes parameter checking to see if the call meets criteria given in
           a paramter buried in exit_info (see ExitInfo class).
        '''
        trace_msg = ''
        if pid == 0:
            #self.lgr.debug('exitHap cell %s pid is zero' % (self.cell_name))
            return False
        ''' If this is a new pid, assume it is a child clone or fork return '''
        if exit_info is None:
            ''' no pending syscall for this pid '''
            if not self.traceProcs.pidExists(pid):
                ''' new PID, add it without parent for now? ''' 
                '''
                clonenum = self.task_utils.syscallNumber('clone', exit_info.compat32)
                for ppid in self.exit_info:
                    if self.exit_info[ppid].callnum == clonenum:
                        if self.exit_info[ppid].call_params is not None:
                            self.lgr.debug('clone returning in child %d parent maybe %d' % (pid, ppid))
                            SIM_break_simulation('clone returning in child %d parent maybe %d' % (pid, ppid))
                            return    
                '''
                leader_pid = self.task_utils.getCurrentThreadLeaderPid()
                self.lgr.debug('sharedSyscall handleExit maybe clone child return no parent pid %s (%s)  group leader is %s' % (pid, comm, leader_pid))
                if leader_pid != pid:
                    self.traceProcs.addProc(pid, leader_pid, comm=comm)
                    if self.context_manager.amWatching(leader_pid):
                        self.context_manager.addTask(pid)
                else:
                    self.traceProcs.addProc(pid, None, comm=comm)
                return False
            if self.isPendingExecve(pid):
                self.lgr.debug('sharedSyscall handleExit cell %s call reschedule from execve?  for pid %d  Remove pending' % (self.cell_name, pid))
                self.rmPendingExecve(pid)
                return False 
            else:
                ''' pid exists, but no execve syscall pending, assume reschedule? '''
                #self.lgr.debug('exitHap call reschedule for pid %d' % pid)
                return False 
        
        ''' check for nested interrupt return '''
        eip = self.getEIP()
        instruct = SIM_disassemble_address(self.cpu, eip, 1, 0)
        if instruct[1].startswith('iret'):
            reg_num = self.cpu.iface.int_register.get_number(self.mem_utils.getESP())
            esp = self.cpu.iface.int_register.read(reg_num)
            ret_addr = self.mem_utils.readPtr(self.cpu, esp)
            if ret_addr > self.param.kernel_base:
                ''' nested '''
                #self.lgr.debug('sharedSyscall cell %s exitHap nested' % (self.cell_name))
                #SIM_break_simulation('nested ?')
                return False
            else:
                #self.lgr.debug('exitHap ret_addr 0x%x  kbase 0x%x ' % (ret_addr, self.param.kernel_base))
                pass

        if eip == exit_info.syscall_entry:
            self.lgr.error('sharedSyscall handleExit entered from syscall breakpoint.  eh?.')
            return False

        eax = self.mem_utils.getRegValue(self.cpu, 'syscall_ret')
        ueax = self.mem_utils.getUnsigned(eax)
        eax = self.mem_utils.getSigned(eax)
        callname = self.task_utils.syscallName(exit_info.callnum, exit_info.compat32)
        #self.lgr.debug('exitHap cell %s callnum %d name %s  pid %d ' % (self.cell_name, exit_info.callnum, callname, pid))
        if callname == 'clone':
            self.lgr.debug('exitHap is clone pid %d  eax %d' % (pid, eax))
            if eax > 20000:
                SIM_break_simulation('confused clone')
                return False
            #if eax == 120:
            #    SIM_break_simulation('clone faux return?')
            #    return
            self.top.recordStackBase(eax, exit_info.fname_addr)
            if  pid in self.trace_procs and self.traceProcs.addProc(eax, pid, clone=True):
                trace_msg = ('\treturn from clone (tracing), new pid:%d  calling pid:%d (%s)\n' % (eax, pid, comm))
                #self.lgr.debug('exitHap clone called addProc for pid:%d parent %d' % (eax, pid))
                self.traceProcs.copyOpen(pid, eax)
            elif pid not in self.trace_procs:
                trace_msg = ('\treturn from clone, new pid:%d  calling pid:%d\n' % (eax, pid))
            else:
                ''' must be repeated hap or trackThreads already added the clone '''
                self.lgr.debug('exitHap clone repeated call? pid: %d eax %d' % (pid, eax))
                trace_msg = ('\treturn from clone, new pid:%d  calling pid:%d\n' % (eax, pid))
                
            if exit_info.call_params is not None:
                if exit_info.call_params.nth is not None:
                    self.lgr.debug('exitHap clone, nth is %d' % exit_info.call_params.nth)
                    if exit_info.call_params.nth >= 0:
                        self.lgr.debug('exitHap clone, run to pid %d' % eax)
                        SIM_run_alone(self.top.toProcPid, eax)
                        self.top.rmSyscall(self.exit_info.call_params.name, cell_name=self.cell_name)
                        exit_info.call_params = None
                        #my_syscall = exit_info.syscall_instance
                        #my_syscall.stopTrace()
            
            #dumb_pid, dumb, dumb2 = self.context_manager.getDebugPid() 
            #if dumb_pid is not None:
            #    self.lgr.debug('sharedSyscall adding clone %d to watched pids' % eax)
            #    self.context_manager.addTask(eax)
             
        elif callname == 'mkdir':
            #fname = self.mem_utils.readString(exit_info.cpu, exit_info.fname_addr, 256)
            if exit_info.fname is None:
                self.lgr.error('fname is None? in exit from mkdir pid %d fname addr was 0x%x' % (pid, exit_info.fname_addr))
                #SIM_break_simulation('fname is none on exit of open')
                exit_info.fname = 'unknown'
            trace_msg = ('\treturn from mkdir pid:%d file: %s flags: 0x%x mode: 0x%x eax: 0x%x\n' % (pid, exit_info.fname, exit_info.flags, exit_info.mode, eax))
                
        elif callname == 'open' or callname == 'openat':
            #fname = self.mem_utils.readString(exit_info.cpu, exit_info.fname_addr, 256)
            if exit_info.fname is None:
                self.lgr.error('fname is None? in exit from open pid %d fname addr was 0x%x' % (pid, exit_info.fname_addr))
                #ptable_info = pageUtils.findPageTableIA32E(self.cpu, exit_info.fname_addr, self.lgr)
                SIM_break_simulation('fname is none on exit of open')
                exit_info.fname = 'unknown'
            trace_msg = ('\treturn from open pid:%d FD: %d file: %s flags: 0%o mode: 0x%x eax: 0x%x\n' % (pid, eax, 
                   exit_info.fname, exit_info.flags, exit_info.mode, eax))
            self.lgr.debug('return from open pid:%d (%s) FD: %d file: %s flags: 0%o mode: 0x%x eax: 0x%x' % (pid, comm, 
                   eax, exit_info.fname, exit_info.flags, exit_info.mode, eax))
            if eax >= 0:
                if pid in self.trace_procs:
                    self.traceProcs.open(pid, comm, exit_info.fname, eax)
                ''' TBD cleaner way to know if we are getting ready for a debug session? '''
                if ('.so.' in exit_info.fname or exit_info.fname.endswith('.so')) and self.track_so:
                    #self.lgr.debug('is open so')
                    #open_syscall = self.top.getSyscall(self.cell_name, 'open')
                    open_syscall = exit_info.syscall_instance
                    if open_syscall is not None: 
                        open_syscall.watchFirstMmap(pid, exit_info.fname, eax, exit_info.compat32)
                    else:
                        self.lgr.debug('sharedSyscall no syscall_instance in exit_info %d' % pid)
                if self.traceFiles is not None:
                    self.traceFiles.open(exit_info.fname, eax)

            if eax < 0 and exit_info.call_params is not None and exit_info.call_params.match_param.__class__.__name__ == 'Dmod':
                dmod = exit_info.call_params.match_param
                self.lgr.debug('sharedSyscall open, dmod kind %s' % dmod.kind)
                if dmod.kind == 'open_replace':
                    self.lgr.debug('sharedSyscall open, setting return FD to 99')
                    self.top.writeRegValue('syscall_ret', 99, alone=True)
                    dmod.setFD(99)
                    dmod.setPid(pid)
                    #self.top.runToRead(dmod, ignore_running=True)
                    call_params = syscall.CallParams('sharedSyscall', 'read', dmod, break_simulation=False)        
                    cell_name = dmod.getCellName()
                    cell = self.top.getCell(cell_name = cell_name)
                    self.top.runTo(['read','close','lseek','_llseek'], call_params, name='read-dmod', ignore_running=True, 
                       cell_name=dmod.getCellName(), cell=cell)

                    trace_msg = ('\treturn from open pid:%s DMOD! forced return FD of 99 \n' % (str(pid)))
                exit_info.call_params = None

            if exit_info.call_params is not None and type(exit_info.call_params.match_param) is str:
                self.lgr.debug('sharedSyscall open check string %s against %s' % (exit_info.fname, exit_info.call_params.match_param))
                #if eax < 0 or exit_info.call_params.match_param not in exit_info.fname:
                if exit_info.call_params.match_param not in exit_info.fname:
                    ''' no match, set call_param to none '''
                    exit_info.call_params = None


                
        elif callname == 'pipe' or \
             callname == 'pipe2':
            if eax == 0:
                fd1 = self.mem_utils.readWord32(self.cpu, exit_info.retval_addr)
                fd2 = self.mem_utils.readWord32(self.cpu, exit_info.retval_addr+4)
                #self.lgr.debug('return from pipe pid:%d fd1 %d fd2 %d from 0x%x' % (pid, fd1, fd2, exit_info.retval_addr))
                trace_msg = ('\treturn from pipe pid:%s fd1 %s fd2 %s from 0x%x\n' % (str(pid), str(fd1), str(fd2), exit_info.retval_addr))
                if pid in self.trace_procs:
                    self.traceProcs.pipe(pid, fd1, fd2)

        elif callname == 'read':
            #self.lgr.debug('is read eax 0x%x' % eax)
            if self.read_fixup_callback is not None:
                self.lgr.debug('sharedSyscall read call read_fixup_callback')
                eax = self.read_fixup_callback(exit_info.old_fd)
            if eax < 0: 

                call_params = exit_info.syscall_instance.getCallParams()
                tmp_params = list(call_params)
                for call_param in tmp_params:
                    if call_param.match_param.__class__.__name__ == 'Dmod' and call_param.match_param.pid == pid and exit_info.old_fd == call_param.match_param.fd:
                        self.lgr.debug('sharedSyscall read Dmod FD and pid match')     
                        becomes = call_param.match_param.getBecomes()
                        length = call_param.match_param.getWas()
                        length = int(length, 16)
                        if length == 0:
                            length = len(becomes)
                        self.mem_utils.writeString(self.cpu, exit_info.retval_addr, becomes)
                        self.top.writeRegValue('syscall_ret', length, alone=True)
                        eax = length
                        if exit_info.call_params == call_param:
                            self.lgr.debug('sharedSyscall, read assuming exit_info.call_params was what we found, remove it.')
                            exit_info.call_params = None
                        trace_msg = ('\treturn from read DMOD! pid:%d FD: %d forced return val to %d\n' % (pid, exit_info.old_fd, length))
                        break

            if eax >= 0 and exit_info.retval_addr is not None:

                max_len = min(eax, 1024)
                byte_array = self.mem_utils.getBytes(self.cpu, eax, exit_info.retval_addr)
                if byte_array is not None:
                    s = resimUtils.getHexDump(byte_array[:max_len])
                    if self.traceFiles is not None:
                        self.traceFiles.read(pid, exit_info.old_fd, byte_array)
                else:
                    s = '<<NOT MAPPED>>'
                trace_msg = ('\treturn from read pid:%d (%s) FD: %d returned length: %d into 0x%x given count: %d cycle: 0x%x \n\t%s\n' % (pid, comm, exit_info.old_fd, 
                              eax, exit_info.retval_addr, exit_info.count, self.cpu.cycles, s))
                my_syscall = exit_info.syscall_instance
                if exit_info.call_params is not None and (exit_info.call_params.break_simulation or my_syscall.linger) and self.dataWatch is not None \
                   and type(exit_info.call_params.match_param) is int:
                    ''' in case we want to break on a read of this data. NOTE break range is based on given count, not returned length '''
                    self.lgr.debug('sharedSyscall bout to call dataWatch.setRange for read length (eax) is %d' % eax)
                    # Set range over max length of read to catch coding error reference to previous reads or such
                    if eax > 0:
                        self.dataWatch.setRange(exit_info.retval_addr, eax, msg=trace_msg, max_len=exit_info.count, fd=exit_info.old_fd)
                    if my_syscall.linger: 
                        self.dataWatch.stopWatch() 
                        self.dataWatch.watch(break_simulation=False, i_am_alone=True)
                    if exit_info.origin_reset:
                        self.lgr.debug('sharedSyscall found origin reset, do it')
                        SIM_run_alone(self.stopAlone, None)
                    if self.kbuffer is not None:
                        self.kbuffer.readReturn(eax)
                elif exit_info.call_params is not None and exit_info.call_params.match_param.__class__.__name__ == 'Dmod':
                  exit_info.call_params = None
                  if eax < 16000:
                    call_params = exit_info.syscall_instance.getCallParams()
                    self.lgr.debug('read dmod check %d params' % len(call_params))
                    tmp_params = list(call_params)
                    for call_param in tmp_params:
                        self.lgr.debug('dmod check %s' % call_param.match_param.__class__.__name__) 
                        if call_param.match_param.__class__.__name__ == 'Dmod':
                            dmod = call_param.match_param
                            self.lgr.debug('sharedSyscall %s read check dmod %s count %d %s' % (self.cell_name, dmod.getPath(), eax, s))
                            if dmod is not None and dmod.getComm() is not None and dmod.getComm() != comm:
                                self.lgr.debug('sharedSyscall read is dmod, but wrong comm, wanted %s, this is %s' % (dmod.getComm(), comm))
                            elif dmod.checkString(self.cpu, exit_info.retval_addr, eax, pid, exit_info.old_fd):
                                self.lgr.debug('sharedSyscall read did dmod %s count now %d' % (dmod.getPath(), dmod.getCount()))
                                if dmod.getCount() == 0:
                                    self.lgr.debug('sharedSyscall read found final dmod %s' % dmod.getPath())
                                    exit_info.syscall_instance.rmCallParam(call_param)
                                    if not exit_info.syscall_instance.remainingDmod() and exit_info.syscall_instance.name != 'traceAll':
                                        self.lgr.debug('sharedSyscall read Dmod stopping trace')
                                        self.top.rmSyscall(call_param.name, cell_name=self.cell_name)
                                        #self.top.stopTrace(cell_name=self.cell_name, syscall=exit_info.syscall_instance)
                                        self.stopTrace()
                                        #if not self.top.remainingCallTraces(exception='_llseek') and SIM_simics_is_running():
                                        if not self.top.remainingCallTraces(cell_name=self.cell_name, exception='_llseek') and SIM_simics_is_running():
                                            self.top.notRunning(quiet=True)
                                            SIM_break_simulation('dmod done on cell %s file: %s' % (self.cell_name, dmod.getPath()))
                                else:
                                    print('%s performed' % dmod.getPath())
                                if call_param.break_simulation:
                                    SIM_break_simulation('dmod break simulation')

                

            elif exit_info.old_fd is not None:
                trace_msg = ('\treturn from read pid:%d FD: %d exception %d\n' % (pid, exit_info.old_fd, eax))
                exit_info.call_params = None

        elif callname == 'write':
            if eax >= 0 and exit_info.retval_addr is not None:
                    max_len = min(eax, 1024)
                    byte_array = self.mem_utils.getBytes(self.cpu, eax, exit_info.retval_addr)
                    if byte_array is not None:
                        s = resimUtils.getHexDump(byte_array[:max_len])
                        '''
                        if s != exit_info.fname[:max_len]:
                            self.lgr.error('write is not what was written cycles: 0x%x' % self.cpu.cycles)
                            self.lgr.error('at call time: %s' % exit_info.fname)
                            self.lgr.error('now         : %s' % s)
                        '''
                        if self.traceFiles is not None:
                            self.traceFiles.write(pid, exit_info.old_fd, byte_array)
                    else:
                        s = '<<NOT MAPPED>>'
                    #trace_msg = ('\treturn from write pid:%d FD: %d count: %d\n\t%s\n' % (pid, exit_info.old_fd, eax, byte_string))
                    trace_msg = ('\treturn from write pid:%d FD: %d count: %d\n\t%s\n' % (pid, exit_info.old_fd, eax, s))
                    if exit_info.call_params is not None and type(exit_info.call_params.match_param) is str:
                        self.lgr.debug('sharedSyscall write check string %s against %s' % (s, exit_info.call_params.match_param))
                        if exit_info.call_params.match_param not in s:
                            ''' no match, set call_param to none '''
                            exit_info.call_params = None
                        else:
                            self.lgr.debug('MATCHED')
                    elif exit_info.call_params is not None:
                        self.lgr.debug('type of param %s' % (type(exit_info.call_params.match_param)))
                    if self.all_write:
                        self.allWrite.write(comm, pid, exit_info.old_fd, s)
            else:
                trace_msg = ('\treturn from write pid:%d FD: %d exception %d\n' % (pid, exit_info.old_fd, eax))
                exit_info.call_params = None

        elif callname in ['_llseek', 'lseek']:
            if eax >= 0:
                if self.mem_utils.WORD_SIZE == 4:
                    result = self.mem_utils.readWord32(self.cpu, exit_info.retval_addr)
                    if result is not None:
                        trace_msg = ('\treturn from %s pid:%d FD: %d result: 0x%x\n' % (callname, pid, exit_info.old_fd, result))
                    else:
                        trace_msg = ('\treturn from %s pid:%d FD: %d result failed read of addr 0x%x\n' % (callname, pid, 
                              exit_info.old_fd, exit_info.retval_addr))
                else:
                    trace_msg = ('\treturn from %s pid:%d FD: %d eax: 0x%x\n' % (callname, pid, exit_info.old_fd, eax))

            elif exit_info.call_params is not None and exit_info.call_params.match_param.__class__.__name__ == 'Dmod' \
               and exit_info.call_params.match_param.pid == pid and exit_info.old_fd == exit_info.call_params.match_param.fd:
                self.lgr.debug('sharedSyscall lseek Dmod FD and pid match, set return value to 0, tbd extend?')     
                self.top.writeRegValue('syscall_ret', 0, alone=True)
                trace_msg = ('\treturn from %s pid:%d DMOD! FD: %d forced return to 0\n' % (callname, pid, exit_info.old_fd))
                exit_info.call_params = None

        elif callname == 'ioctl':
            if exit_info.retval_addr is not None:
                if exit_info.cmd == 0x720:
                    ''' i2c bus xfer '''
                    xfer_byte_addr = exit_info.retval_addr+2*self.mem_utils.WORD_SIZE
                    result_ptr = self.mem_utils.readPtr(self.cpu, xfer_byte_addr)
                    result = self.mem_utils.readByte(self.cpu, result_ptr)
                    if result is not None:
                        trace_msg = ('\treturn from ioctl pid:%d FD: %d cmd: 0x%x retval_addr: 0x%x result: 0x%x written to 0x%x\n' % (pid, 
                            exit_info.old_fd, exit_info.cmd, exit_info.retval_addr, result, result_ptr))
                    else:
                        trace_msg = ('\treturn from ioctl pid:%d FD: %d cmd: 0x%x could not read bye written to 0x%x\n' % (pid, exit_info.old_fd, exit_info.cmd, result, result_ptr))

                else:
                    result = self.mem_utils.readWord32(self.cpu, exit_info.retval_addr)
                    if result is not None:
                        trace_msg = ('\treturn from ioctl pid:%d FD: %d cmd: 0x%x result: 0x%x written to 0x%x\n' % (pid, exit_info.old_fd, exit_info.cmd, result, exit_info.retval_addr))
                    else:
                        self.lgr.debug('sharedSyscall read None from 0x%x cmd: 0x%x' % (exit_info.retval_addr, exit_info.cmd))
                        trace_msg = ('\treturn from ioctl pid:%d FD: %d cmd: 0x%x eax: 0x%x\n' % (pid, exit_info.old_fd, exit_info.cmd, eax))
                    if exit_info.call_params is not None and (exit_info.call_params.break_simulation or exit_info.syscall_instance.linger) and self.dataWatch is not None:
                        ''' in case we want to break on a read of waiting bytes '''
                        self.dataWatch.setRange(exit_info.retval_addr, 4, trace_msg, back_stop=True, no_backstop=True)
                        if exit_info.syscall_instance.linger: 
                            self.dataWatch.stopWatch() 
                            self.dataWatch.watch(break_simulation=False, no_backstop=True, i_am_alone=True)
            elif exit_info.cmd == 0x703:
                ''' i2c slave address '''
                trace_msg = ('\treturn from ioctl pid:%d FD: %d cmd: 0x%x slave_addr 0x%x\n' % (pid, exit_info.old_fd, exit_info.cmd, exit_info.flags)) 
            else:
                trace_msg = ('\treturn from ioctl pid:%d FD: %d cmd: 0x%x eax: 0x%x\n' % (pid, exit_info.old_fd, exit_info.cmd, eax))

        elif callname == 'gettimeofday': 
            if exit_info.retval_addr is not None:
                result = self.mem_utils.readWord32(self.cpu, exit_info.retval_addr)
                trace_msg = ('\treturn from gettimeofday pid:%d result: 0x%x\n' % (pid, result))
                timer_syscall = self.top.getSyscall(self.cell_name, 'gettimeofday')
                if timer_syscall is not None:
                    timer_syscall.checkTimeLoop('gettimeofday', pid)

        elif callname == 'waitpid': 
            timer_syscall = self.top.getSyscall(self.cell_name, 'waitpid')
            if timer_syscall is not None:
                timer_syscall.checkTimeLoop('waitpid', pid)
            else:
                self.lgr.debug('timer_syscall is None')


        elif callname == 'close':
            if eax == 0:
                if pid in self.trace_procs:
                    #self.lgr.debug('exitHap for close pid %d' % pid)
                    self.traceProcs.close(pid, exit_info.old_fd)
                trace_msg = ('\treturn from close pid:%d, FD: %d  eax: 0x%x\n' % (pid, exit_info.old_fd, eax))
                if self.traceFiles is not None:
                    self.traceFiles.close(exit_info.old_fd)
                if exit_info.call_params is not None:
                    self.dataWatch.close(exit_info.old_fd)
            elif exit_info.call_params is not None and exit_info.call_params.match_param.__class__.__name__ == 'Dmod' \
               and exit_info.call_params.match_param.pid == pid and exit_info.old_fd == exit_info.call_params.match_param.fd:
                self.lgr.debug('sharedSyscall close Dmod FD and pid match, set return value to 0')     
                self.top.writeRegValue('syscall_ret', 0, alone=True)
                trace_msg = ('\terror return from close DMOD! pid:%d, FD: %d  eax: 0x%x\n' % (pid, exit_info.old_fd, eax))
                exit_info.call_params.match_param.resetOpen()
                if exit_info.syscall_instance.name == 'read-dmod':
                    self.lgr.debug('sharedSyscall close stopping read-dmod syscall')
                    self.top.rmSyscall(exit_info.call_params.name, cell_name=self.cell_name)
                    #exit_info.syscall_instance.stopTrace()
                exit_info.call_params = None
            else:
                trace_msg = ('\terror return from close pid:%d, FD: %d  eax: 0x%x\n' % (pid, exit_info.old_fd, eax))
            
        elif callname == 'fcntl64':        
            if eax >= 0:
                trace_msg = self.fcntl(pid, eax, exit_info)
            else:
                trace_msg = ('\terror return from fcntl64  pid %d, old_fd: %d retval: %d\n' % (pid, exit_info.old_fd, eax))

        elif callname == 'dup':
            #self.lgr.debug('exit pid %d from dup eax %x, old_fd is %d' % (pid, eax, exit_info.old_fd))
            if eax >= 0:
                if pid in self.trace_procs:
                    self.traceProcs.dup(pid, exit_info.old_fd, eax)
                trace_msg = ('\treturn from dup pid %d, old_fd: %d new: %d\n' % (pid, exit_info.old_fd, eax))
        elif callname == 'dup2':
            #self.lgr.debug('return from dup2 pid %d eax %x, old_fd is %d new_fd %d' % (pid, eax, exit_info.old_fd, exit_info.new_fd))
            if eax >= 0:
                if exit_info.old_fd != exit_info.new_fd:
                    if pid in self.trace_procs:
                        self.traceProcs.dup(pid, exit_info.old_fd, exit_info.new_fd)
                    trace_msg = ('\treturn from dup2 pid:%d, old_fd: %d new: %d\n' % (pid, exit_info.old_fd, eax))
                else:
                    trace_msg = ('\treturn from dup2 pid:%d, old_fd: and new both %d   Eh?\n' % (pid, eax))
        elif callname == 'mmap2' or callname == 'mmap':
            ''' TBD error handling? '''
            if exit_info.fname is not None and self.soMap is not None:
                self.lgr.debug('return from mmap pid:%d, addr: 0x%x so fname: %s' % (pid, ueax, exit_info.fname))
                trace_msg = ('\treturn from mmap pid:%d, addr: 0x%x so fname: %s\n' % (pid, ueax, exit_info.fname))
                if '/etc/ld.so.cache' not in exit_info.fname:
                    self.soMap.addSO(pid, exit_info.fname, ueax, exit_info.count)
            else:
                trace_msg = ('\treturn from mmap pid:%d, addr: 0x%x \n' % (pid, ueax))
        elif callname == 'ipc':
            callname = exit_info.socket_callname
            call = exit_info.frame['param1']
            if call == ipc.MSGGET or callname == ipc.SHMGET:
                trace_msg = ('\treturn from ipc %s pid:%d key: 0x%x quid: 0x%x\n' % (callname, pid, exit_info.fname, ueax)) 
                #SIM_break_simulation('msgget pid %d ueax 0x%x eax 0x%x' % (pid, ueax, eax))
            elif call == ipc.SHMAT:
                ret_addr = exit_info.frame['param4']
                mem_addr = self.mem_utils.readPtr(self.cpu, ret_addr)
                trace_msg = ('\treturn from ipc %s pid:%d mem_addr: 0x%x\n' % (callname, pid, mem_addr)) 
            elif eax < 0:
                    trace_msg = ('\treturn ERROR from ipc %s pid:%d result: %d\n' % (callname, pid, eax)) 
            elif call == ipc.MSGSND:
                nbytes = min(exit_info.count, 1024)
                if exit_info.bytes_to_write is not None:
                    s = resimUtils.getHexDump(exit_info.bytes_to_write[:nbytes])
                    trace_msg = ('\treturn from ipc %s pid:%d result: 0x%x size %d from 0x%x %s\n' % (callname, pid, ueax, exit_info.count, exit_info.retval_addr, s)) 
                else:
                    trace_msg = ('\treturn from ipc %s pid:%d result: 0x%x but not bytes written?\n' % (callname, pid, ueax)) 
                #self.lgr.debug(trace_msg)
                #SIM_break_simulation('return MSGSND')    
            elif call == ipc.MSGRCV:
                nbytes = min(eax, 1024)
                msg_ptr = self.mem_utils.readPtr(self.cpu, exit_info.retval_addr)
                byte_array = self.mem_utils.getBytes(self.cpu, eax, msg_ptr)
                #self.lgr.debug('MSGRCV retval_addr 0x%x got %d bytes, nbytes is %d' % (exit_info.retval_addr, len(byte_array), nbytes))
                if byte_array is not None:
                    s = resimUtils.getHexDump(byte_array[:nbytes])
                    trace_msg = ('\treturn from ipc %s pid:%d received: %d bytes from 0x%x %s\n' % (callname, pid, ueax, exit_info.retval_addr, s)) 
                else:
                    trace_msg = ('\treturn from ipc %s pid:%d result: 0x%x but not bytes read?\n' % (callname, pid, ueax)) 
                #self.lgr.debug(trace_msg)
                #SIM_break_simulation('return MSGRCV')    
            else:
                trace_msg = ('\treturn from ipc %s pid:%d result: 0x%x\n' % (callname, pid, ueax)) 

        elif callname == 'select' or callname == '_newselect' or callname == 'pselect6':
            if exit_info.select_info is not None:
                trace_msg = ('\treturn from %s pid:%d %s  result: %d\n' % (callname, pid, exit_info.select_info.getString(), eax))
                if self.fool_select is not None and eax > 0:
                    self.modifySelect(exit_info.select_info, eax)
                elif exit_info.call_params is not None:
                    if type(exit_info.call_params.match_param) is int:
                        if exit_info.syscall_instance.name == 'runToIO':
                            if not exit_info.select_info.setHasFD(exit_info.call_params.match_param, exit_info.select_info.readfds):
                                self.lgr.debug('sharedSyscall select for runToIO fd %d not in read fds, no match' % exit_info.call_params.match_param)
                                exit_info.call_params = None
                        elif not exit_info.select_info.hasFD(exit_info.call_params.match_param):
                            self.lgr.debug('sharedSyscall select fd %d not in any fds, no match' % exit_info.call_params.match_param)
                            exit_info.call_params = None
                    
            else:
                trace_msg = ('\treturn from %s pid:%d NO select info result: %d\n' % (callname, pid, eax))
        elif callname == 'poll' or callname == 'ppoll':
            trace_msg = ('\treturn from %s pid:%d %s  result: %d\n' % (callname, pid, exit_info.poll_info.getString(), eax))
            exit_info.call_params = None

        elif callname == 'vfork':
            trace_msg = ('\treturn from vfork in parent %d child pid:%d\n' % (pid, ueax))
            if pid in self.trace_procs:
                self.traceProcs.addProc(ueax, pid)
                self.traceProcs.copyOpen(pid, eax)
        elif callname == 'execve':
            self.lgr.debug('syscall handleExit from execve pid:%d  remove from pending_execve' % pid)
            if self.isPendingExecve(pid):
                self.rmPendingExecve(pid)
        elif callname == 'socketcall' or callname.upper() in net.callname:
            trace_msg = self.doSockets(exit_info, eax, pid)
        elif callname == 'epoll_wait' or callname == 'epoll_pwait':
             cur_ptr = exit_info.epoll_wait.events
             trace_msg = ('\treturn from %s pid:%d epfd: %d eax %d maxevents: %d cur_ptr: 0x%x\n' % (callname, pid, exit_info.old_fd, eax, exit_info.epoll_wait.maxevents, cur_ptr))
             self.lgr.debug(trace_msg)
             for i in range(eax):
                 trace_msg = trace_msg+epoll.getEvent(self.cpu, self.mem_utils, cur_ptr, self.lgr)
                 cur_ptr = cur_ptr+4+self.mem_utils.WORD_SIZE+12
        elif callname == 'eventfd' or callname == 'eventfd2':
             trace_msg = ('\treturn from %s pid:%d  FD: %d\n' % (callname, pid, eax))
        elif callname == 'timerfd_create':
             trace_msg = ('\treturn from %s pid:%d  FD: %d\n' % (callname, pid, eax))
        else:
            trace_msg = ('\treturn from call %s code: 0x%x  pid:%d\n' % (callname, ueax, pid))


        ''' if debugging a proc, and clone call, add the new process '''
        dumb_pid, dumb2 = self.context_manager.getDebugPid() 
        if dumb_pid is not None and callname == 'clone':
            if eax == 0:
                self.lgr.debug('sharedSyscall clone but eax is zero ??? pid is %d' % pid)
                return True
            self.lgr.debug('sharedSyscall adding clone %d to watched pids' % eax)
            self.context_manager.addTask(eax)

        if exit_info.call_params is not None and exit_info.call_params.break_simulation:
            '''  Use syscall module that got us here to handle stop actions '''
            self.lgr.debug('exitHap found matching call parameter %s' % str(exit_info.call_params.match_param))
            self.matching_exit_info = exit_info
            self.context_manager.setIdaMessage(trace_msg)
            #self.lgr.debug('exitHap found matching call parameters callnum %d name %s' % (exit_info.callnum, callname))
            #my_syscall = self.top.getSyscall(self.cell_name, callname)
            my_syscall = exit_info.syscall_instance
            if not my_syscall.linger: 
                self.stopTrace()
            if my_syscall is None:
                self.lgr.error('sharedSyscall could not get syscall for %s' % callname)
            else:
                SIM_run_alone(my_syscall.stopAlone, callname)
    
        if trace_msg is not None and len(trace_msg.strip())>0:
            self.lgr.debug('cell %s %s'  % (self.cell_name, trace_msg.strip()))
            self.traceMgr.write(trace_msg) 
        return True

    def startAllWrite(self):
        self.all_write = True
       
    def getMatchingExitInfo(self):
        return self.matching_exit_info 

    def stopAlone(self, Dumb):
        self.stop_hap = RES_hap_add_callback("Core_Simulation_Stopped", self.stopHapReset, None)
        self.lgr.debug('sharedSyscall stopAlone for origin reset, added hap, now stop')
        SIM_break_simulation('origin reset')

    def delStopAlone(self, dumb):
        if self.stop_hap is not None:
            RES_hap_delete_callback_id("Core_Simulation_Stopped", self.stop_hap)
            self.stop_hap = None

    def stopHapReset(self, stop_action, one, exception, error_string):
        if self.stop_hap is not None:
            SIM_run_alone(self.top.resetOrigin, self.cpu)
            SIM_run_alone(self.delStopAlone, None)
            self.lgr.debug('sharedSyscall did reset, now continue')
            SIM_run_alone(SIM_run_command, 'c')

    def getExitList(self, name):
        exit_info_list = {}
        for pid in self.exit_info: 
            self.lgr.debug('sharedSyscall getExistList pid:%d' % pid)
            for name in self.exit_info[pid]:
                self.lgr.debug('sharedSyscall getExistList name %s' % name)
                if name in self.exit_info[pid]:
                    exit_info_list[pid] = self.exit_info[pid][name].frame
                    exit_info_list[pid]['syscall_num'] = self.exit_info[pid][name].callnum
        return exit_info_list

    def foolSelect(self, fd):
        ''' Modify return values from select to reflect no data for this fd ''' 
        self.fool_select = fd

    def modifySelect(self, select_info, eax):
        if select_info.setHasFD(self.fool_select, select_info.readfds): 
            select_info.resetFD(self.fool_select, select_info.readfds)
            eax = eax -1
            self.top.writeRegValue('syscall_ret', eax, alone=True)
            self.lgr.debug('sharedSyscall modified select resut, cleared fd and set eax to %d' % eax)

    def rmExitBySyscallName(self, name, cell):
        #self.lgr.debug('rmExitBySyscallName %s' % name)
        exit_name = '%s-exit' % name
        rmlist = []
        if name is None or name == 'None':
            self.lgr.debug('rmExitBySyscall name is none, experiment, ug')
            return
        for pid in self.exit_names:
            the_name = self.exit_names[pid]
            if the_name.endswith(exit_name):
                rmlist.append(pid)
                #self.lgr.debug('sharedSyscall rmExitBySyscallName pid:%d removing: %s context %s' % (pid, name, str(cell))) 
                self.rmExitHap(pid, context=cell)
                if pid in self.exit_info and the_name in self.exit_info[pid]:
                    del self.exit_info[pid][the_name]
        for pid in rmlist:
            del self.exit_names[pid]

        #self.lgr.debug('rmExitBySyscallName return from %s' % name)

    def setcallback(self, callback, param):
        self.callback = callback
        self.callback_param = param

    def callbackPending(self):
        if self.callback is not None:
            return True
        else:
            return False

    def setKbuffer(self, kbuffer):
        self.kbuffer = kbuffer

    def setReadFixup(self, read_fixup_callback):
        self.read_fixup_callback = read_fixup_callback

    def preserveExit(self):
        self.preserve_exit = True
