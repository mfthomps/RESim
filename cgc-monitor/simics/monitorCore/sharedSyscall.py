from simics import *
import pageUtils
import memUtils
import net
import ipc
class SharedSyscall():
    def __init__(self, top, cpu, cell, param, mem_utils, task_utils, context_manager, traceProcs, traceFiles, soMap, dataWatch, traceMgr, lgr):
        self.pending_call = {}
        self.pending_execve = []
        self.lgr = lgr
        self.cpu = cpu
        self.cell = cell
        self.task_utils = task_utils
        self.param = param
        self.mem_utils = mem_utils
        self.context_manager = context_manager
        self.traceProcs = traceProcs
        self.exit_info = {}
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


    def setDebugging(self, debugging):
        self.lgr.debug('SharedSyscall set debugging %r' % debugging)
        self.debugging = debugging

    def getPendingCall(self, pid):
        if pid in self.pending_call:
            return self.pending_call[pid]
        else:
            return None

    def stopTrace(self):

        for eip in self.exit_hap:
            self.context_manager.genDeleteHap(self.exit_hap[eip])
        self.exit_pids = {}

    def showExitHaps(self):
        for eip in self.exit_pids:
            print('eip: 0x%x' % eip)
            for pid in self.exit_pids[eip]:
                prog = self.task_utils.getProgName(pid)
                if prog is not None:
                    print('\t%d %s' % (pid, prog))
                else:
                    print('\t%d' % (pid))

    def rmExitHap(self, pid):
        if pid is not None:
            #self.lgr.debug('rmExitHap for pid %d' % pid)
            for eip in self.exit_pids:
                if pid in self.exit_pids[eip]:
                    self.exit_pids[eip].remove(pid)
                    if len(self.exit_pids[eip]) == 0:
                        self.context_manager.genDeleteHap(self.exit_hap[eip])
            self.exit_info.pop(pid, None)

        else:
            ''' assume the exitHap was for a one-off syscall such as execve that
                broke the simulation. '''
            ''' TBD NOTE procs returning from blocked syscalls will not be caught! '''
            for eip in self.exit_pids:
                del self.exit_pids[eip][:]
                self.context_manager.genDeleteHap(self.exit_hap[eip])
                self.lgr.debug('sharedSyscall rmExitHap, assume one-off syscall, cleared exit hap')


    def addExitHap(self, pid, exit_eip1, exit_eip2, callnum, exit_info, traceProcs, name):
        self.exit_info[pid] = exit_info
        if traceProcs is not None:
            self.trace_procs.append(pid)
        self.exit_names[pid] = name

        if exit_eip1 not in self.exit_pids:
            self.exit_pids[exit_eip1] = []

        if len(self.exit_pids[exit_eip1]) == 0:
            #self.lgr.debug('addExitHap new exit EIP1 0x%x for pid %d' % (exit_eip1, pid))
            exit_break = self.context_manager.genBreakpoint(self.cell, 
                                Sim_Break_Linear, Sim_Access_Execute, exit_eip1, 1, 0)
            self.exit_hap[exit_eip1] = self.context_manager.genHapIndex("Core_Breakpoint_Memop", self.exitHap, 
                               None, exit_break, 'exit hap')
            self.lgr.debug('sharedSyscall added exit hap %d' % self.exit_hap[exit_eip1])
        self.exit_pids[exit_eip1].append(pid)

        if exit_eip2 is not None:
            if exit_eip2 not in self.exit_pids:
                self.exit_pids[exit_eip2] = []

            if len(self.exit_pids[exit_eip2]) == 0:
                #self.lgr.debug('addExitHap new exit EIP2 0x%x for pid %d' % (exit_eip2, pid))
                exit_break = self.context_manager.genBreakpoint(self.cell, 
                                    Sim_Break_Linear, Sim_Access_Execute, exit_eip2, 1, 0)
                self.exit_hap[exit_eip2] = self.context_manager.genHapIndex("Core_Breakpoint_Memop", self.exitHap, 
                                   None, exit_break, 'exit hap2')
                self.lgr.debug('sharedSyscall added exit hap2 %d' % self.exit_hap[exit_eip1])
            self.exit_pids[exit_eip2].append(pid)
        #self.lgr.debug('sharedSyscall addExitHap return')


    def addPendingExecve(self, pid):
        self.pending_execve.append(pid)

    def rmPendingExecve(self, pid):
        if pid in self.pending_execve:
            self.lgr.debug('sharedSyscall rmPendingExecve remove %d' % pid)
            self.pending_execve.remove(pid)
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

    def exitHap(self, dumb, third, forth, memory):
        ''' 
           Invoked on return to user space after a system call.
           Includes parameter checking to see if the call meets criteria given in
           a paramter buried in exit_info (see ExitInfo class).
        '''
        cpu, comm, pid = self.task_utils.curProc() 
        #self.lgr.debug('exitHap pid %d' % pid)
        exit_info = None
        if pid in self.exit_info:
            exit_info = self.exit_info[pid]
        trace_msg = ''
        if pid == 0:
            #self.lgr.debug('exitHap pid is zero')
            return
        ''' If this is a new pid, assume it is a child clone or fork return '''
        if exit_info is None:
            ''' no pending syscall for this pid '''
            if not self.traceProcs.pidExists(pid):
                ''' new PID, add it without parent for now? ''' 
                self.lgr.debug('exitHap call traceProcs.addProc for pid %d' % pid)
                self.traceProcs.addProc(pid, None, comm=comm)
                return
            else:
                ''' pid exists, but no syscall pending, assume reschedule? '''
                #self.lgr.debug('exitHap call reschedule for pid %d' % pid)
                return 
        
        ''' check for nested interrupt return '''
        eip = self.getEIP()
        instruct = SIM_disassemble_address(self.cpu, eip, 1, 0)
        if instruct[1] == 'iretd':
            reg_num = self.cpu.iface.int_register.get_number(self.mem_utils.getESP())
            esp = self.cpu.iface.int_register.read(reg_num)
            ret_addr = self.mem_utils.readPtr(cpu, esp)
            if ret_addr > self.param.kernel_base:
                ''' nested '''
                self.lgr.debug('sharedSyscall exitHap nested')
                return

        if eip == exit_info.syscall_entry:
            self.lgr.error('exitHap entered from syscall breakpoint.  wtf?, over.')
            return
        eax = self.mem_utils.getRegValue(self.cpu, 'eax')
        ueax = self.mem_utils.getUnsigned(eax)
        eax = self.mem_utils.getSigned(eax)
        #cur_eip = SIM_get_mem_op_value_le(memory)
        #self.lgr.debug('exitHap pid %d eax %d third:%s forth:%s cur_eip 0x%x' % (pid, eax, str(third), str(forth), cur_eip))
        #self.lgr.debug('exitHap pid %d eax %d third:%s forth:%s ' % (pid, eax, str(third), str(forth)))
        if True:
                if exit_info.callnum == self.task_utils.syscallNumber('clone'):
                    self.lgr.debug('is clone pid %d  eax %d' % (pid, eax))
                    if eax == 120:
                        SIM_break_simulation('clone faux return?')
                        return
                    if  pid in self.trace_procs and self.traceProcs.addProc(eax, pid, clone=True):
                        trace_msg = ('\treturn from clone (tracing), new pid:%d  calling pid:%d\n' % (eax, pid))
                        self.lgr.debug('exitHap clone called addProc for pid:%d parent %d' % (eax, pid))
                        self.traceProcs.copyOpen(pid, eax)
                    elif pid not in self.trace_procs:
                        trace_msg = ('\treturn from clone, new pid:%d  calling pid:%d\n' % (eax, pid))
                    else:
                        ''' must be repeated hap '''
                        return
                    self.top.addProcList(eax, comm)
                    
                    dumb_pid, dumb, dumb2 = self.context_manager.getDebugPid() 
                    #if dumb_pid is not None:
                    #    self.lgr.debug('sharedSyscall adding clone %d to watched pids' % eax)
                    #    self.context_manager.addTask(eax)
                     
                elif exit_info.callnum == self.task_utils.syscallNumber('mkdir'):
                    #fname = self.mem_utils.readString(exit_info.cpu, exit_info.fname_addr, 256)
                    if exit_info.fname is None:
                        self.lgr.error('fname is None? in exit from mkdir pid %d fname addr was 0x%x' % (pid, exit_info.fname_addr))
                        #SIM_break_simulation('fname is none on exit of open')
                        exit_info.fname = 'unknown'
                    trace_msg = ('\treturn from mkdir pid:%d file: %s flags: 0x%x mode: 0x%x eax: 0x%x\n' % (pid, exit_info.fname, exit_info.flags, exit_info.mode, eax))
                        
                elif exit_info.callnum == self.task_utils.syscallNumber('open'):
                    #fname = self.mem_utils.readString(exit_info.cpu, exit_info.fname_addr, 256)
                    if exit_info.fname is None:
                        self.lgr.error('fname is None? in exit from open pid %d fname addr was 0x%x' % (pid, exit_info.fname_addr))
                        #SIM_break_simulation('fname is none on exit of open')
                        exit_info.fname = 'unknown'
                    if eax >= 0:
                        if pid in self.trace_procs:
                            self.traceProcs.open(pid, comm, exit_info.fname, eax)
                        trace_msg = ('\treturn from open pid:%d FD: %d file: %s flags: 0x%x mode: 0x%x eax: 0x%x\n' % (pid, eax, exit_info.fname, exit_info.flags, exit_info.mode, eax))
                        self.lgr.debug('return from open pid:%d (%s) FD: %d file: %s flags: 0x%x mode: 0x%x eax: 0x%x' % (pid, comm, eax, exit_info.fname, exit_info.flags, exit_info.mode, eax))
                        ''' TBD cleaner way to know if we are getting ready for a debug session? '''
                        if '.so.' in exit_info.fname:
                            open_syscall = self.top.getSyscall('open')
                            if open_syscall is not None: 
                                open_syscall.watchFirstMmap(pid, exit_info.fname, eax)
                        if self.traceFiles is not None:
                            self.traceFiles.open(exit_info.fname, eax)
                    if exit_info.call_params is not None and type(exit_info.call_params.match_param) is str:
                        self.lgr.debug('sharedSyscall open check string %s against %s' % (exit_info.fname, exit_info.call_params.match_param))
                        if eax < 0 or exit_info.call_params.match_param not in exit_info.fname:
                            ''' no match, set call_param to none '''
                            exit_info.call_params = None

                        
                elif exit_info.callnum == self.task_utils.syscallNumber('pipe') or \
                     exit_info.callnum == self.task_utils.syscallNumber('pipe2'):
                    if eax == 0:
                        fd1 = self.mem_utils.readWord32(cpu, exit_info.retval_addr)
                        fd2 = self.mem_utils.readWord32(cpu, exit_info.retval_addr+4)
                        #self.lgr.debug('return from pipe pid:%d fd1 %d fd2 %d from 0x%x' % (pid, fd1, fd2, exit_info.retval_addr))
                        trace_msg = ('\treturn from pipe pid:%d fd1 %d fd2 %d from 0x%x\n' % (pid, fd1, fd2, exit_info.retval_addr))
                        if pid in self.trace_procs:
                            self.traceProcs.pipe(pid, fd1, fd2)

                elif exit_info.callnum == self.task_utils.syscallNumber('read'):
                    if eax >= 0 and exit_info.retval_addr is not None:
                        byte_string, dumb = self.mem_utils.getBytes(cpu, eax, exit_info.retval_addr)
                        limit = min(len(byte_string), 10)
                        trace_msg = ('\treturn from read pid:%d FD: %d count: %d into 0x%x\n\t%s\n' % (pid, exit_info.old_fd, 
                                      eax, exit_info.retval_addr, byte_string[:limit]))
                        if exit_info.call_params is not None and exit_info.call_params.break_simulation and self.dataWatch is not None:
                            ''' in case we want to break on a read of this data '''
                            self.dataWatch.setRange(exit_info.retval_addr, eax)
                    elif exit_info.old_fd is not None:
                        trace_msg = ('\treturn from read pid:%d FD: %d exception %d\n' % (pid, exit_info.old_fd, eax))

                elif exit_info.callnum == self.task_utils.syscallNumber('write'):
                    if eax >= 0 and exit_info.retval_addr is not None:
                        if eax < 1024:
                            byte_string, byte_array = self.mem_utils.getBytes(cpu, eax, exit_info.retval_addr)
                            trace_msg = ('\treturn from write pid:%d FD: %d count: %d\n\t%s\n' % (pid, exit_info.old_fd, eax, byte_string))
                            if self.traceFiles is not None:
                                self.traceFiles.write(exit_info.old_fd, byte_array)
                            if exit_info.call_params is not None and type(exit_info.call_params.match_param) is str:
                                s = ''.join(map(chr,byte_array))
                                self.lgr.debug('sharedSyscall write check string %s against %s' % (s, exit_info.call_params.match_param))
                                if exit_info.call_params.match_param not in s:
                                    ''' no match, set call_param to none '''
                                    exit_info.call_params = None
                                else:
                                    self.lgr.debug('MATCHED')
                            elif exit_info.call_params is not None:
                                self.lgr.debug('type of param %s' % (type(exit_info.call_params.match_param)))
                        else:
                            trace_msg = ('\treturn from write pid:%d FD: %d count: %d\n' % (pid, exit_info.old_fd, eax))
                            exit_info.call_params = None
                    else:
                        exit_info.call_params = None

                elif exit_info.callnum == self.task_utils.syscallNumber('_llseek'):
                    result = self.mem_utils.readWord32(cpu, exit_info.retval_addr)
                    trace_msg = ('\treturn from _llseek pid:%d FD: %d result: 0x%x\n' % (pid, exit_info.old_fd, result))

                elif exit_info.callnum == self.task_utils.syscallNumber('ioctl'):
                    if exit_info.retval_addr is not None:
                        result = self.mem_utils.readWord32(cpu, exit_info.retval_addr)
                        if result is not None:
                            trace_msg = ('\treturn from ioctl pid:%d FD: %d cmd: 0x%x result: 0x%x\n' % (pid, exit_info.old_fd, exit_info.cmd, result))
                        else:
                            self.lgr.debug('sharedSyscall read None from 0x%x cmd: 0x%x' % (exit_info.retval_addr, exit_info.cmd))
                    else:
                        trace_msg = ('\treturn from ioctl pid:%d FD: %d cmd: 0x%x eax: 0x%x\n' % (pid, exit_info.old_fd, exit_info.cmd, eax))

                elif exit_info.callnum == self.task_utils.syscallNumber('gettimeofday'): 
                    if exit_info.retval_addr is not None:
                        result = self.mem_utils.readWord32(cpu, exit_info.retval_addr)
                        trace_msg = ('\treturn from gettimeofday pid:%d result: 0x%x\n' % (pid, result))
                        timer_syscall = self.top.getSyscall('gettimeofday')
                        if timer_syscall is not None:
                            timer_syscall.checkTimeLoop('gettimeofday', pid)

                elif exit_info.callnum == self.task_utils.syscallNumber('waitpid'): 
                    timer_syscall = self.top.getSyscall('waitpid')
                    if timer_syscall is not None:
                        timer_syscall.checkTimeLoop('waitpid', pid)
                    else:
                        self.lgr.debug('timer_syscall is None')

                elif exit_info.callnum == self.task_utils.syscallNumber('socketcall'):
                    params = exit_info.socket_params
                    socket_callname = net.callname[exit_info.socket_callnum]
                    
                    if exit_info.socket_callnum == net.SOCKET and eax >= 0:
                        if pid in self.trace_procs:
                            self.traceProcs.socket(pid, eax)
                        domain = self.mem_utils.readWord32(cpu, params)
                        sock_type_full = self.mem_utils.readWord32(cpu, params+4)
                        sock_type = sock_type_full & net.SOCK_TYPE_MASK
                        type_string = net.socktype[sock_type]
                        protocol = self.mem_utils.readWord32(cpu, params+8)
                        dstring = net.domaintype[domain]
                        trace_msg = ('\treturn from socketcall SOCKET pid:%d, FD: %d domain: %s  type: %s protocol: %d  socket params at 0x%x\n' % (pid, 
                             eax, dstring, type_string, protocol, exit_info.socket_params))
                        if domain == 2:
                            pass
                    elif exit_info.socket_callnum == net.CONNECT:
                        if eax < 0:
                            trace_msg = ('\texception from socketcall CONNECT pid:%d FD: %d, eax %s  socket params: 0x%x addr: 0x%x\n' % (pid, 
                                exit_info.sock_struct.fd, eax, exit_info.socket_params, exit_info.sock_struct.addr))
                        else:     
                            ss = exit_info.sock_struct
                            if pid in self.trace_procs:
                                self.traceProcs.connect(pid, ss.fd, ss.getName())
                            trace_msg = ('\treturn from socketcall CONNECT pid:%d, %s  socket params: 0x%x addr: 0x%x\n' % (pid, ss.getString(), 
                                exit_info.socket_params, exit_info.sock_struct.addr))
                    elif exit_info.socket_callnum == net.BIND:
                        if eax < 0:
                            trace_msg = ('\texception from socketcall BIND eax:%d, %s\n' % (pid, eax))
                        else:
                            ss = exit_info.sock_struct
                            if pid in self.trace_procs:
                                self.traceProcs.bind(pid, ss.fd, ss.getName())
                                prog_name = self.traceProcs.getProg(pid)
                                socket_syscall = self.top.getSyscall('socketcall')
                                if socket_syscall is not None:
                                    binders = socket_syscall.getBinders()
                                    binders.add(pid, prog_name, ss.dottedIP(), ss.port)
                            trace_msg = ('\treturn from socketcall BIND pid:%d, %s\n' % (pid, ss.getString()))
                                
                    elif exit_info.socket_callnum == net.GETSOCKNAME:
                        ss = net.SockStruct(cpu, params, self.mem_utils)
                        trace_msg = ('\t return from GETSOCKNAME pid:%d %s\n' % (pid, ss.getString()))

                    elif exit_info.socket_callnum == net.ACCEPT:
                        new_fd = eax
                        if new_fd < 0:
                            return 
                        ss = net.SockStruct(cpu, params, self.mem_utils)
                        if ss.sa_family == 1:
                            if pid in self.trace_procs:
                                self.traceProcs.accept(pid, ss.fd, new_fd, None)
                            trace_msg = ('\treturn from socketcall ACCEPT pid:%d, sock_fd: %d  new_fd: %d sa_family: %s  name: %s\n' % (pid, ss.fd,
                               new_fd, ss.famName(), ss.getName()))
                        elif ss.sa_family == 2:
                            if pid in self.trace_procs:
                                self.traceProcs.accept(pid, ss.fd, new_fd, ss.getName())
                            trace_msg = ('\treturn from socketcall ACCEPT pid:%d, sock_fd: %d  new_fd: %d sa_family: %s  addr: %s\n' % (pid, ss.fd,
                               new_fd, ss.famName(), ss.getName()))
                        else:
                            trace_msg = ('\treturn from socketcall ACCEPT pid:%d, sock_fd: %d  new_fd: %d sa_family: %s  SA Family not handled\n' % (pid, ss.fd,
                               new_fd, ss.famName()))
                    elif exit_info.socket_callnum == net.SOCKETPAIR:
                        sock_fd_addr = self.mem_utils.readPtr(cpu, params+12)
                        fd1 = self.mem_utils.readWord32(cpu, sock_fd_addr)
                        fd2 = self.mem_utils.readWord32(cpu, sock_fd_addr+4)
                        if pid in self.trace_procs:
                            self.traceProcs.socketpair(pid, fd1, fd2)
                        trace_msg = ('\treturn from socketcall SOCKETPAIR pid:%d, fd1: %d fd2: %d\n' % (pid, fd1, fd2))
                        #self.lgr.debug('\treturn from socketcall SOCKETPAIR pid:%d, fd1: %d fd2: %d' % (pid, fd1, fd2))

                    elif exit_info.socket_callnum == net.SEND or exit_info.socket_callnum == net.SENDTO or \
                         exit_info.socket_callnum == net.SENDMSG: 
                        if eax >= 0:
                            trace_msg = ('\treturn from socketcall %s pid:%d, FD: %d, count: %d\n' % (socket_callname, pid, exit_info.old_fd, eax))
                        else:
                            trace_msg = ('\terror return from socketcall %s pid:%d, FD: %d, exception: %d\n' % (socket_callname, pid, exit_info.old_fd, eax))

                        if exit_info.call_params is not None and type(exit_info.call_params.match_param) is str:
                            byte_string, byte_array = self.mem_utils.getBytes(cpu, eax, exit_info.retval_addr)
                            s = ''.join(map(chr,byte_array))
                            self.lgr.debug('sharedSyscall SEND check string %s against %s' % (s, exit_info.call_params.match_param))
                            if exit_info.call_params.match_param not in s:
                                ''' no match, set call_param to none '''
                                exit_info.call_params = None

                    elif exit_info.socket_callnum == net.RECV or exit_info.socket_callnum == net.RECVFROM or \
                         exit_info.socket_callnum == net.RECVMSG: 
                        if eax >= 0:
                            trace_msg = ('\treturn from socketcall %s pid:%d, FD: %d, count: %d into 0x%x\n' % (socket_callname, pid, exit_info.old_fd, eax, exit_info.retval_addr))
                        else:
                            trace_msg = ('\terror return from socketcall %s pid:%d, FD: %d, exception: %d into 0x%x\n' % (socket_callname, pid, exit_info.old_fd, eax, exit_info.retval_addr))
                        if exit_info.call_params is not None and exit_info.call_params.break_simulation and self.dataWatch is not None:
                            ''' in case we want to break on a read of this data '''
                            self.dataWatch.setRange(exit_info.retval_addr, eax)
                    elif exit_info.socket_callnum == net.GETPEERNAME:
                        ss = net.SockStruct(cpu, params, self.mem_utils)
                        trace_msg = ('\treturn from socketcall GETPEERNAME pid:%d, %s  eax: 0x%x\n' % (pid, ss.getString(), eax))
                    else:
                        fd = self.mem_utils.readWord32(cpu, params)
                        addr = self.mem_utils.readWord32(cpu, params+4)
                        trace_msg = ('\treturn from socketcall %s pid:%d FD: %d addr:0x%x eax: 0x%x\n' % (socket_callname, pid, fd, addr, eax)) 

                elif exit_info.callnum == self.task_utils.syscallNumber('close'):
                    if eax == 0:
                        if pid in self.trace_procs:
                            #self.lgr.debug('exitHap for close pid %d' % pid)
                            self.traceProcs.close(pid, eax)
                        trace_msg = ('\treturn from close pid:%d, FD: %d  eax: 0x%x\n' % (pid, exit_info.old_fd, eax))
                        if self.traceFiles is not None:
                            self.traceFiles.close(exit_info.old_fd)
                    
                elif exit_info.callnum == self.task_utils.syscallNumber('dup'):
                    #self.lgr.debug('exit pid %d from dup eax %x, old_fd is %d' % (pid, eax, exit_info.old_fd))
                    if eax >= 0:
                        if pid in self.trace_procs:
                            self.traceProcs.dup(pid, exit_info.old_fd, eax)
                        trace_msg = ('\treturn from dup pid %d, old_fd: %d new: %d\n' % (pid, exit_info.old_fd, eax))
                elif exit_info.callnum == self.task_utils.syscallNumber('dup2'):
                    #self.lgr.debug('return from dup2 pid %d eax %x, old_fd is %d new_fd %d' % (pid, eax, exit_info.old_fd, exit_info.new_fd))
                    if eax >= 0:
                        if exit_info.old_fd != exit_info.new_fd:
                            if pid in self.trace_procs:
                                self.traceProcs.dup(pid, exit_info.old_fd, exit_info.new_fd)
                            trace_msg = ('\treturn from dup2 pid:%d, old_fd: %d new: %d\n' % (pid, exit_info.old_fd, eax))
                        else:
                            trace_msg = ('\treturn from dup2 pid:%d, old_fd: and new both %d   Eh?\n' % (pid, eax))
                elif exit_info.callnum == self.task_utils.syscallNumber('mmap2'):
                    ''' TBD error handling? '''
                    if exit_info.fname is not None and self.soMap is not None:
                        self.lgr.debug('return from mmap pid:%d, addr: 0x%x so fname: %s' % (pid, ueax, exit_info.fname))
                        trace_msg = ('\treturn from mmap pid:%d, addr: 0x%x so fname: %s\n' % (pid, ueax, exit_info.fname))
                        if '/etc/ld.so.cache' not in exit_info.fname:
                            self.soMap.addSO(pid, exit_info.fname, ueax, exit_info.count)
                    else:
                        trace_msg = ('\treturn from mmap pid:%d, addr: 0x%x \n' % (pid, ueax))
                elif exit_info.callnum == self.task_utils.syscallNumber('ipc'):
                    call = exit_info.socket_callnum
                    callname = ipc.call[call]
                    if call == ipc.MSGGET or call == ipc.SHMGET:
                        trace_msg = ('\treturn from ipc %s pid:%d key: 0x%x quid: 0x%x\n' % (callname, pid, exit_info.fname, ueax)) 
                        #SIM_break_simulation('msgget pid %d ueax 0x%x eax 0x%x' % (pid, ueax, eax))
                    else:
                        if eax < 0:
                            trace_msg = ('\treturn ERROR from ipc %s pid:%d result: %d\n' % (callname, pid, eax)) 
                        else:
                            trace_msg = ('\treturn from ipc %s pid:%d result: 0x%x\n' % (callname, pid, ueax)) 

                elif exit_info.callnum == self.task_utils.syscallNumber('vfork'):
                    trace_msg = ('\treturn from vfork in parent %d child pid:%d' % (pid, ueax))
                    if pid in self.trace_procs:
                        self.traceProcs.addProc(ueax, pid)
                        self.traceProcs.copyOpen(pid, eax)
                elif exit_info.callnum == self.task_utils.syscallNumber('execve'):
                    self.lgr.debug('exitHap from execve pid:%d  remove from pending_execve' % pid)
                    if self.isPendingExecve(pid):
                        self.rmPendingExecve(pid)
                else:
                    callname = self.task_utils.syscallName(exit_info.callnum)
                    trace_msg = ('\treturn from call %s code: 0x%x  pid:%d\n' % (callname, ueax, pid))

                if not self.debugging or (exit_info.callnum != self.task_utils.syscallNumber('clone')):
                    ''' will be done in clone child.  TBD, assumes child runs second? '''
                    #self.lgr.debug('exitHap pid %d delete breakpoints' % pid)
                    self.rmExitHap(pid)
                ''' if debugging a proc, and clone call, add the new process '''
                dumb_pid, dumb, dumb2 = self.context_manager.getDebugPid() 
                if dumb_pid is not None and exit_info.callnum == self.task_utils.syscallNumber('clone'):
                    self.lgr.debug('adding clone %d to watched pids' % eax)
                    self.context_manager.addTask(eax)

                if exit_info.call_params is not None and exit_info.call_params.break_simulation:
                    self.lgr.debug('exitHap found matching call parameter %s' % str(exit_info.call_params.match_param))
                    self.context_manager.setIdaMessage(trace_msg)
                    self.rmExitHap(pid)
                    self.stopTrace()
                    callname = self.task_utils.syscallName(exit_info.callnum)
                    #self.lgr.debug('exitHap found matching call parameters callnum %d name %s' % (exit_info.callnum, callname))
                    my_syscall = self.top.getSyscall(callname)
                    if my_syscall is None:
                        self.lgr.error('sharedSyscall could not get syscall for %s' % callname)
                    else:
                        SIM_run_alone(my_syscall.stopAlone, 'found matching call parameters')
                self.lgr.debug(trace_msg.strip())
    
                if len(trace_msg.strip())>0:
                    self.traceMgr.write(trace_msg) 

