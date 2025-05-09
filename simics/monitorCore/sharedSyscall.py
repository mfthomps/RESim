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
        self.exit_tids = {}
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
        self.select_fixup_callback = None
        self.poll_fixup_callback = None

        if self.top.isWindows(target=self.cell_name):
            self.win_call_exit = winCallExit.WinCallExit(top, cpu, cell, cell_name, param, mem_utils, task_utils, 
                      context_manager, traceProcs, traceFiles, self.soMap, dataWatch, traceMgr, self.lgr)
        else:
            self.win_call_exit = None

        ''' optimization if "only" or "ignore" lists are used '''
        self.preserve_exit = False

        ''' TBD arm linux seems to set a process TID to 1 for some period (when opening /var/run/utmp?)'''
        self.hack_exit_tid = None
        self.lgr.debug('sharedSyscall traceFiles: %s' % self.traceFiles)

    def trackSO(self, track_so):
        #self.lgr.debug('sharedSyscall track_so %r' % track_so)
        self.track_so = track_so

    def setDebugging(self, debugging):
        self.lgr.debug('SharedSyscall set debugging %r' % debugging)
        self.debugging = debugging

    def getPendingCall(self, tid, name):
        if tid in self.exit_info:
            if name in self.exit_info[tid] and self.exit_info[tid][name] is not None:
                return self.exit_info[tid][name].callnum
            elif len(self.exit_info[tid]) > 0:
                existing = next(iter(self.exit_info[tid]))
                #self.lgr.debug('sharedSyscall getPendingCall, no call for %s, returning for %s' % (name, existing))
                if existing in self.exit_info[tid] and self.exit_info[tid][existing] is not None:
                    return self.exit_info[tid][existing].callnum
          
        return None

    def stopTrace(self):
        for context in self.exit_tids:
            #self.lgr.debug('sharedSyscall stopTrace context %s' % str(context))
            for eip in self.exit_hap:
                self.context_manager.genDeleteHap(self.exit_hap[eip], immediate=True)
                self.lgr.debug('sharedSyscall stopTrace removed exit hap %d for eip 0x%x context %s' % (self.exit_hap[eip], eip, str(context)))
            self.exit_tids[context] = {}
        for eip in self.exit_hap:
            self.exit_info[eip] = {}

    def showExitHaps(self):
        if self.cpu.current_context not in self.exit_tids:
            print('context %s not in exit_tids' % self.cpu.current_context)
            return
        my_exit_tids = self.exit_tids[self.cpu.current_context]
        for eip in my_exit_tids:
            print('eip: 0x%x' % eip)
            for tid in my_exit_tids[eip]:
                prog = self.task_utils.getProgName(tid)
                if prog is not None:
                    print('\t%s %s' % (tid, prog))
                else:
                    print('\t%s' % (tid))

    def rmExitHap(self, tid, context=None, immediate=False):
        if context is not None:
            use_context = context
        else:
            use_context = self.cpu.current_context
        if use_context not in self.exit_tids:
            self.lgr.debug('rmExitHap context %s not in exit_tids, do nothing?' % str(use_context))
            return
        my_exit_tids = self.exit_tids[use_context]
        if tid is not None:
            rm_tids = {}
            #self.lgr.debug('rmExitHap for tid:%s use_context %s' % (tid, use_context))
            for eip in my_exit_tids:
                if tid in my_exit_tids[eip]:
                    if eip not in rm_tids:
                        rm_tids[eip] = []
                    rm_tids[eip].append(tid)
                    #my_exit_tids[eip].remove(tid)
                    #self.lgr.debug('rmExitHap removed tid:%s for eip 0x%x cycle: 0x%x' % (tid, eip, self.cpu.cycles))
            self.exit_info[tid] = {}     
            for eip in rm_tids:
                for tid in rm_tids[eip]:
                    self.exit_tids[use_context][eip].remove(tid)
                if len(self.exit_tids[use_context][eip]) == 0:
                    if  self.preserve_exit:
                        ''' add a dummy entry to preserve exit haps '''
                        #self.lgr.debug('rmExitHap len of exit_tids[0x%x] is zero, but we are preserving os add a dummy entry' % eip)
                        self.exit_tids[use_context][eip].append(-1)
                    else:
                        #self.lgr.debug('rmExitHap len of exit_tids[0x%x] is zero, delete exit hap context: %s hap %d' % (eip, use_context, self.exit_hap[eip]))
                        self.context_manager.genDeleteHap(self.exit_hap[eip], immediate=immediate)

        else:
            ''' assume the exitHap was for a one-off syscall such as execve that
                broke the simulation. '''
            ''' TBD NOTE procs returning from blocked syscalls will not be caught! '''
            for eip in my_exit_tids:
                #del my_exit_tids[eip][:]
                my_exit_tids[eip] = []
                if eip in self.exit_hap:
                    self.lgr.debug('sharedSyscall rmExitHap, call contextManager to delete exit hap %d' % self.exit_hap[eip])
                    self.context_manager.genDeleteHap(self.exit_hap[eip], immediate=immediate)
                    del self.exit_hap[eip]
                #self.lgr.debug('sharedSyscall rmExitHap, assume one-off syscall, cleared exit hap')
        #self.lgr.debug('sharedSyscall rmExitHap done')


    def addExitHap(self, cell, tid, exit_eip1, exit_eip2, exit_eip3, exit_info, name, context_override=None):
        ''' only use current context value, ignore cell!'''
        self.hack_exit_tid = tid
        if tid not in self.exit_info:
            self.exit_info[tid] = {}
        self.exit_info[tid][name] = exit_info
        if self.traceProcs is not None:
            self.trace_procs.append(tid)
        self.exit_names[tid] = name
        if context_override is None:
            current_context = self.cpu.current_context
        else:
            current_context = context_override
        #self.lgr.debug('sharedSyscall addExitHap tid:%s name %s current_context %s cell %s' % (tid, name, str(current_context), cell))
        if current_context not in self.exit_tids:
            self.exit_tids[current_context] = {}
        my_exit_tids = self.exit_tids[current_context]
        if exit_eip1 not in my_exit_tids:
            my_exit_tids[exit_eip1] = []

        #if cell is None and exit_info.syscall_instance.name is not None:
        #    if exit_info.syscall_instance.name.startswith('dmod'):
        #        cell = self.top.getCell(self.cell_name)
        #        #self.lgr.debug('sharedSyscall addExitHap, cell is None, is dmod, set cell to %s' % cell) 

        if exit_eip1 is not None: 
            #self.lgr.debug('addExitHap exit_eip1 0x%x not none, len of exit tids is %d %s' % (exit_eip1, len(my_exit_tids[exit_eip1]), current_context))
            if len(my_exit_tids[exit_eip1]) == 0:
                #self.lgr.debug('addExitHap new exit EIP1 0x%x for tid:%s current_context: %s' % (exit_eip1, tid, current_context))
                exit_break = self.context_manager.genBreakpoint(current_context, 
                                    Sim_Break_Linear, Sim_Access_Execute, exit_eip1, 1, 0)
                hap_name = 'exit hap %s' % current_context
                self.exit_hap[exit_eip1] = self.context_manager.genHapIndex("Core_Breakpoint_Memop", self.exitHap, 
                                   None, exit_break, hap_name)
                #self.lgr.debug('sharedSyscall addExitHap added exit hap %d' % self.exit_hap[exit_eip1])
            my_exit_tids[exit_eip1].append(tid)
            #self.lgr.debug('sharedSyscall addExitHap appended tid:%s for exitHap for 0x%x' % (tid, exit_eip1))
        else:
            pass
            #self.lgr.debug('sharedSyscall addExitHap exit_eip1 is None')

        if exit_eip2 is not None:
            if exit_eip2 not in my_exit_tids:
                my_exit_tids[exit_eip2] = []

            if len(my_exit_tids[exit_eip2]) == 0:
                #self.lgr.debug('addExitHap new exit EIP2 0x%x for tid:%s' % (exit_eip2, tid))
                exit_break = self.context_manager.genBreakpoint(current_context, 
                                    Sim_Break_Linear, Sim_Access_Execute, exit_eip2, 1, 0)
                self.exit_hap[exit_eip2] = self.context_manager.genHapIndex("Core_Breakpoint_Memop", self.exitHap, 
                                   None, exit_break, 'exit hap2')
                #self.lgr.debug('sharedSyscall added exit hap2 %d' % self.exit_hap[exit_eip2])
            else:
                #self.lgr.debug('sharedSyscall has exit tid for EIP2, len is %d' % len(my_exit_tids[exit_eip2]))
                #for tid in my_exit_tids[exit_eip2]:
                #    self.lgr.debug('\t got tid:%s in exit_tids for exit_eip2' % tid)
                pass
            my_exit_tids[exit_eip2].append(tid)
        else:
            #self.lgr.debug('sharedSyscall addExitHap exit_eip2 is None')
            pass

        if exit_eip3 is not None:
            if exit_eip3 not in my_exit_tids:
                my_exit_tids[exit_eip3] = []

            if len(my_exit_tids[exit_eip3]) == 0:
                #self.lgr.debug('addExitHap new exit EIP3 0x%x for tid:%s' % (exit_eip3, tid))
                exit_break = self.context_manager.genBreakpoint(current_context, 
                                    Sim_Break_Linear, Sim_Access_Execute, exit_eip3, 1, 0)
                self.exit_hap[exit_eip3] = self.context_manager.genHapIndex("Core_Breakpoint_Memop", self.exitHap, 
                                   None, exit_break, 'exit hap3')
                #self.lgr.debug('sharedSyscall added exit hap3 %d' % self.exit_hap[exit_eip3])
            my_exit_tids[exit_eip3].append(tid)

        if exit_info is not None:
            if exit_info.callname == 'execve':
                self.addPendingExecve(tid)
        else:
            self.lgr.debug('exit_info was None for name: %s' % name)


        #self.lgr.debug('sharedSyscall addExitHap return tid:%s' % tid)


    def addPendingExecve(self, tid):
        self.lgr.debug('sharedSyscall addPendingExecve tid:%s' % tid)
        if tid not in self.pending_execve:
            self.pending_execve.append(tid)

    def rmPendingExecve(self, tid):
        if tid in self.pending_execve:
            self.lgr.debug('sharedSyscall rmPendingExecve remove %s' % tid)
            self.pending_execve.remove(tid)
            self.rmExitHap(tid)
        else:
            self.lgr.debug('sharedSyscall rmPendingExecve nothing pending for %s' % tid)

    def isPendingExecve(self, tid):
        if tid in self.pending_execve:
            return True
        else:
            return False

    def getEIP(self):
        eip = self.mem_utils.getRegValue(self.cpu, 'eip')
        return eip

    def doSockets(self, exit_info, eax, tid, comm):
        if exit_info.callnum == self.task_utils.syscallNumber('socketcall', exit_info.compat32):
            socket_callname = exit_info.socket_callname
            socket_syscall = self.top.getSyscall(self.cell_name, 'socketcall')
            trace_msg = '\treturn from socketcall %s tid:%s (%s), ' % (socket_callname, tid, comm)
            err_trace_msg = '\terror return from socketcall %s tid:%s (%s) ' % (socket_callname, tid, comm)
        else:
            socket_callname = exit_info.callname
            socket_syscall = self.top.getSyscall(self.cell_name, socket_callname)
            trace_msg = '\treturn from %s tid:%s (%s), ' % (socket_callname, tid, comm)
            err_trace_msg = '\terror return from %s tid:%s (%s) ' % (socket_callname, tid, comm)
                    
        if socket_callname == "socket" and eax >= 0:
            if tid in self.trace_procs:
                self.traceProcs.socket(tid, eax)
            trace_msg = trace_msg+('FD: %d\n' % (eax))
            exit_info.syscall_instance.bindFDToSocket(tid, eax)
        elif socket_callname == "connect":
            if eax < 0:
                if exit_info.sock_struct is not None:
                    trace_msg = err_trace_msg+('FD: %d, eax %s  addr: 0x%x\n' % (exit_info.sock_struct.fd, eax, exit_info.sock_struct.addr))
                else:
                    trace_msg = err_trace_msg+('No sock struct\n' % (tid))
            if exit_info.sock_struct is not None:
                ss = exit_info.sock_struct
                if tid in self.trace_procs:
                    self.traceProcs.connect(tid, ss.fd, ss.getName())
                if eax >= 0:
                    trace_msg = trace_msg+('%s  addr: 0x%x\n' % (ss.getString(), exit_info.sock_struct.addr))
                if socket_syscall is not None:
                    connectors = socket_syscall.getConnectors()
                    if connectors is not None:
                        if self.traceProcs is not None:
                            prog = self.traceProcs.getProg(tid)
                            if ss.port is not None:
                                self.lgr.debug('adding connector for tid:%s %s %s %s' % (tid, prog, ss.dottedIP(), str(ss.port)))
                                connectors.add(tid, ss.fd, prog, ss.dottedIP(), ss.port)
                            else:
                                self.lgr.debug('adding connector for tid:%s %s %s' % (tid, prog, ss.sa_data))
                                connectors.add(tid, ss.fd, prog, '', ss.sa_data)
                    
        elif socket_callname == "bind":
            if eax < 0:
                trace_msg = err_trace_msg+('\texception from socketcall BIND eax:%d\n' % (eax))
            else:
                ss = exit_info.sock_struct
                if tid in self.trace_procs:
                    self.traceProcs.bind(tid, ss.fd, ss.getName())
                    prog_name = self.traceProcs.getProg(tid)
                    if socket_syscall is not None:
                        binders = socket_syscall.getBinders()
                        if binders is not None:
                            if ss.port is not None:
                                binders.add(tid, ss.fd, prog_name, ss.dottedIP(), ss.port)
                            else:
                                binders.add(tid, ss.fd, prog_name, ss.dottedIP(), ss.sa_data)
                trace_msg = trace_msg+('%s\n' % (ss.getString()))
                    
        elif socket_callname == "getsockname":
            ss = net.SockStruct(self.cpu, exit_info.sock_struct.addr, self.mem_utils, exit_info.sock_struct.fd)
            trace_msg = trace_msg+('%s\n' % (ss.getString()))

        elif socket_callname == "accept" or socket_callname == "accept4":
            new_fd = eax
            if new_fd < 0:
                trace_msg = err_trace_msg+('error: %d\n' % (eax))
            #elif exit_info.sock_struct is not None and exit_info.sock_struct.addr != 0:
            elif exit_info.retval_addr is not None and exit_info.retval_addr != 0:
                #in_ss = exit_info.sock_struct
                addr_len = self.mem_utils.readWord32(self.cpu, exit_info.count_addr)
                self.lgr.debug('accept addr 0x%x  len_addr 0x%x, len %d' % (exit_info.retval_addr, exit_info.count_addr, addr_len))
                ss = net.SockStruct(self.cpu, exit_info.retval_addr, self.mem_utils)
                if ss.sa_family == 1:
                    if tid in self.trace_procs:
                        self.traceProcs.accept(tid, exit_info.old_fd, new_fd, None)
                    trace_msg = trace_msg+('sock_fd: %d  new_fd: %d sa_family: %s  name: %s\n' % (exit_info.old_fd,
                       new_fd, ss.famName(), ss.getName()))
                elif ss.sa_family == 2:
                    if tid in self.trace_procs:
                        self.traceProcs.accept(tid, exit_info.old_fd, new_fd, ss.getName())
                    trace_msg = trace_msg+('sock_fd: %d  new_fd: %d sa_family: %s  addr: %s\n' % (exit_info.old_fd,
                       new_fd, ss.famName(), ss.getName()))
                else:
                    trace_msg = trace_msg+('sock_fd: %d  new_fd: %d sa_family: %s  SA Family not handled addr: 0x%x\n' % (exit_info.old_fd, new_fd, ss.famName(), exit_info.retval_addr))
                    #SIM_break_simulation(trace_msg)
                self.lgr.debug(trace_msg)
                my_syscall = exit_info.syscall_instance
                if exit_info.matched_param is not None and (exit_info.matched_param.break_simulation or my_syscall.linger) and self.dataWatch is not None and addr_len > 0:
                    ''' in case we want to break on a read of address data '''
                    self.dataWatch.setRange(exit_info.retval_addr, addr_len, trace_msg, back_stop=False)
                    #if my_syscall.linger: 
                    ''' TBD better way to distinguish linger from trackIO '''
                    if not self.dataWatch.wouldBreakSimulation():
                        self.dataWatch.stopWatch() 
                        #self.dataWatch.watch(break_simulation=False)
                        self.lgr.debug('sharedSyscall accept call dataWatch watch')
                        self.dataWatch.watch(break_simulation=exit_info.matched_param.break_simulation, i_am_alone=True)
                if exit_info.matched_param is not None and my_syscall.name == 'runToIO' and exit_info.matched_param.match_param == exit_info.old_fd:
                    self.lgr.debug('sharedSyscall for runToIO, change param fd to %d' % new_fd)
                    exit_info.matched_param.match_param = new_fd
                if socket_syscall is not None:
                    binders = socket_syscall.getBinders()
                    if binders is not None:
                        binders.accept(tid, exit_info.old_fd, new_fd)
                if self.traceFiles is not None:
                    self.traceFiles.accept(tid, exit_info.old_fd, new_fd)
            elif exit_info.old_fd is not None:
                trace_msg = trace_msg+('sock_fd: %d  new_fd: %d NULL addr\n' % (exit_info.old_fd, new_fd))
            else:
                trace_msg = trace_msg+('no sock struct, maybe half baked setExits?\n')
        elif socket_callname == "socketpair":
            if exit_info.retval_addr is None:
                self.lgr.error('sharedSyscall socketpair got null retval addr')
                return 'socketpair bad retval addr?'
            fd1 = self.mem_utils.readWord32(self.cpu, exit_info.retval_addr)
            fd2 = self.mem_utils.readWord32(self.cpu, exit_info.retval_addr+4)
            if tid in self.trace_procs:
                self.traceProcs.socketpair(tid, fd1, fd2)
            trace_msg = trace_msg+('fd1: %s fd2: %s\n' % (str(fd1), str(fd2)))
            #self.lgr.debug('\treturn from socketcall SOCKETPAIR tid:%s, fd1: %d fd2: %d' % (tid, fd1, fd2))

        elif socket_callname == "send" or socket_callname == "sendto": 
            if eax >= 0:
                nbytes = min(eax, 256)
                byte_array = self.mem_utils.getBytes(self.cpu, eax, exit_info.retval_addr)
                ''' byte_array is a tuple of bytes'''
                if byte_array is not None:
                    s = resimUtils.getHexDump(byte_array[:nbytes])
                    if self.traceFiles is not None:
                        self.traceFiles.write(tid, exit_info.old_fd, byte_array)
                else:
                    s = '<< NOT MAPPED >>'
                eip = self.getEIP()
                if exit_info.retval_addr is None:
                    self.lgr.error('sharedSyscall %s failed to get retval addr' % socket_callname)
                    return
                trace_msg = trace_msg+('FD: %d, count: %d from 0x%x cycle: 0x%x eip: 0x%x\n%s\n' % (exit_info.old_fd, 
                    eax, exit_info.retval_addr, self.cpu.cycles, eip, s))
            else:
                trace_msg = err_trace_msg+('FD: %d, exception: %d\n' % (exit_info.old_fd, eax))

            if exit_info.matched_param is not None:
                if syscall.DEST_PORT in exit_info.matched_param.param_flags: 
                    self.lgr.debug('sharedSyscall sendto found dest port match.')
                elif type(exit_info.matched_param.match_param) is str and eax > 0:
                    self.lgr.debug('sharedSyscall call param %s was matched during syscall as having desired string.' % exit_info.matched_param.name)
                    #if exit_info.matched_param.match_param not in s:
                    #    ''' no match, set call_param to none '''
                    #    exit_info.call_params = None

        elif socket_callname == "sendmsg":
            s = ''
            if eax >= 0:
                msghdr = exit_info.msghdr
                if msghdr is None:
                    trace_msg = trace_msg+('FD: %s count: %d no msghdr' % (str(exit_info.old_fd), eax))
                else:
                    trace_msg = trace_msg+('FD: %s count: %d %s' % (str(exit_info.old_fd), eax, msghdr.getString()))
                if tid in self.trace_procs:
                    if self.traceProcs.isExternal(tid, exit_info.old_fd):
                        trace_msg = trace_msg +' EXTERNAL'

                trace_msg = trace_msg + '\n'
                if msghdr is not None:
                    s =msghdr.getDumpString()
                    trace_msg = trace_msg+'\t'+s+'\n'
            else:
                trace_msg = err_trace_msg+('FD: %s, exception: %d\n' % (str(exit_info.old_fd), eax))

        elif socket_callname == "recv" or socket_callname == "recvfrom":
            if self.read_fixup_callback is not None and eax >= 0:
                self.lgr.debug('sharedSyscall recv call read_fixup_callback eax was %d fixup callback %s' % (eax, str(self.read_fixup_callback)))
                fixed_eax = self.read_fixup_callback(exit_info.old_fd, callname=socket_callname)
                if fixed_eax is not None:
                    eax = fixed_eax
                else:
                    self.lgr.debug('sharedSyscall recv got None from read_fixup, likely ioctl')
                    
            if eax >= 0:
                nbytes = min(eax, 256)
                byte_array = self.mem_utils.getBytes(self.cpu, eax, exit_info.retval_addr)
                if byte_array is not None:
                    s = resimUtils.getHexDump(byte_array[:nbytes])
                    if self.traceFiles is not None:
                        self.traceFiles.read(tid, exit_info.old_fd, byte_array)
                else:
                    s = '<< NOT MAPPED >>'
                src = ''
                if exit_info.src_addr is not None:
                    src_ss = net.SockStruct(self.cpu, exit_info.src_addr, self.mem_utils, fd=-1)
                    src = 'from: %s' % src_ss.getString()
                if exit_info.old_fd is None:
                    # TBD remove this block?  reachable?
                    self.lgr.error('sharedSyscall exit_info old_fd is None for recv call')
                    exit_info.matched_param = None
                    trace_msg = trace_msg+('\treturn from socketcall %s tid:%s  FD: None' % (socket_callname, tid))
                    return trace_msg 
                #if exit_info.sock_struct is None or exit_info.sock_struct.length is None:
                #    self.lgr.debug('sharedSyscall exit_info sock_struct.length is None for recv call, assume was a setExit from snapshot')
                #    count = exit_info.count
                #else:
                #    count = exit_info.sock_struct.length
                count = exit_info.count
                trace_msg = trace_msg+('\treturn from socketcall %s tid:%s, FD: %d, len: %d count: %d into 0x%x %s\n%s\n' % (socket_callname, tid, 
                     exit_info.old_fd, count, eax, exit_info.retval_addr, src, s))
                self.lgr.debug(trace_msg)
                my_syscall = exit_info.syscall_instance
                self.lgr.debug('sharedSyscall matched_param is %s, my_syscall %s linger %r' % (str(exit_info.matched_param), my_syscall.name, my_syscall.linger))
                if exit_info.matched_param is not None and (exit_info.matched_param.break_simulation or my_syscall.linger) and self.dataWatch is not None:
                    if not self.checkCount(eax, exit_info, trace_msg, s):
                        self.dataWatch.setRange(exit_info.retval_addr, eax, msg=trace_msg, max_len=exit_info.count, fd=exit_info.old_fd, data_stream=True, kbuffer=self.kbuffer)
                        if exit_info.src_addr is not None:
                            count = self.mem_utils.readWord32(self.cpu, exit_info.src_addr_len)
                            msg = 'recvfrom source for above, addr 0x%x %d bytes' % (exit_info.src_addr, count)
                            if count > 0:
                                self.dataWatch.setRange(exit_info.src_addr, count, msg)
                for call_param in exit_info.call_params:
                    if call_param == exit_info.matched_param:
                        continue
                    if call_param.name == 'runToReceive':
                        if call_param.match_param in s:
                            self.lgr.debug('sharedSyscall %s found matched string for %s' % (socket_callname, call_param.name))
                            exit_info.matched_param = param
            else:
                if exit_info.retval_addr is None:
                    self.lgr.debug('sharedSyscall exit_info retval_addr is None for recv call with nonzero eax')
                    trace_msg = trace_msg+('\treturn from socketcall %s tid:%s  eax nonzero retval_addr: None' % (socket_callname, tid))
                    return trace_msg
                if exit_info.old_fd is None:
                    self.lgr.error('sharedSyscall exit_info old_fd is None for recv call with nonzero eax')
                    exit_info.matched_param = None
                    trace_msg = trace_msg+('\treturn from socketcall %s tid:%s  eax nonzeroFD: None' % (socket_callname, tid))
                    return trace_msg
                trace_msg = err_trace_msg+('\terror return from socketcall %s tid:%s, FD: %d, exception: %d into 0x%x\n' % (socket_callname, tid, exit_info.old_fd, eax, exit_info.retval_addr))
                exit_info.matched_param = None

        elif socket_callname == "recvmsg": 
            self.lgr.debug('sharedSyscall doSockets recvmsg')
            if eax < 0:
                trace_msg = err_trace_msg+('\terror return from socketcall %s tid:%s FD: %d exception: %d \n' % (socket_callname, tid, exit_info.old_fd, eax))
                exit_info.matched_param = None
            elif exit_info.msghdr is not None:
                #msghdr = net.Msghdr(self.cpu, self.mem_utils, exit_info.retval_addr)
                msghdr = exit_info.msghdr
                iovec = msghdr.getIovec()
                byte_array = msghdr.getByteArray()
                trace_msg = trace_msg+('\t FD: %d count: %d first buffer: 0x%x num_bytes read: %d' % (exit_info.old_fd, eax, iovec[0].base, len(byte_array)))
                if tid in self.trace_procs:
                    if self.traceProcs.isExternal(tid, exit_info.old_fd):
                        trace_msg = trace_msg +' EXTERNAL'
                trace_msg = trace_msg + '\n'
                s = msghdr.getDumpString()
                trace_msg = trace_msg+'\t'+s+'\n'
                if exit_info.matched_param is not None:
                    self.lgr.debug('sharedSyscall recvmsg has param %s' % exit_info.matched_param)
                my_syscall = exit_info.syscall_instance
                if exit_info.matched_param is not None and (exit_info.matched_param.break_simulation or my_syscall.linger) and self.dataWatch is not None:
                    ''' in case we want to break on a read of this data. ''' 
                    self.lgr.debug('sharedSyscall recvmsg call checkCount')
                    if not self.checkCount(eax, exit_info, trace_msg, s):
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
                            if data_len > 0:
                                self.dataWatch.setRange(base, data_len, msg=trace_msg, max_len=length, fd=exit_info.old_fd, data_stream=True, kbuffer=self.kbuffer)
                        self.lgr.debug('recvmsg set dataWatch')
                        if my_syscall.linger: 
                            self.dataWatch.stopWatch() 
                            self.dataWatch.watch(break_simulation=False, i_am_alone=True)
                        #else:
                        #    self.lgr.error('sharedSyscall unhandled call_param %s' % (exit_info.call_params))
                        #    exit_info.call_params = None
                        if exit_info.origin_reset:
                            self.lgr.debug('sharedSyscall found origin reset, do it')
                            SIM_run_alone(self.stopAlone, None)
                self.checkStringMatch(exit_info, byte_array, tid)
            else:
                self.lgr.debug('sharedSyscall recvmsg no msghdr, assume return from syscall we already handled')
                exit_info.matched_param = None
            
        elif socket_callname == "getpeername":
            if exit_info.sock_struct is not None:
                ss = net.SockStruct(self.cpu, exit_info.sock_struct.addr, self.mem_utils)
                trace_msg = trace_msg+('\treturn from socketcall GETPEERNAME tid:%s, %s  eax: 0x%x\n' % (tid, ss.getString(), eax))
            else:
                trace_msg = trace_msg+('\treturn from socketcall GETPEERNAME tid:%s, sock_struct is None, eax: 0x%x\n' % (tid, eax))
        elif socket_callname == 'setsockopt':
            trace_msg = trace_msg+('\treturn from socketcall SETSOCKOPT tid:%s eax: 0x%x\n' % (tid, eax))
        elif socket_callname == 'getsockopt':
            optval_val = ''
            if exit_info.retval_addr != 0 and eax == 0:
                ''' note exit_info.count is ptr to returned count '''
                count = self.mem_utils.readWord32(self.cpu, exit_info.count)
                rcount = min(count, 80)
                thebytes = self.mem_utils.getBytesHex(self.cpu, rcount, exit_info.retval_addr)
                optval_val = 'optlen: %d option: %s' % (count, thebytes)
            trace_msg = trace_msg+('\treturn from getsockopt tid:%s %s result %d\n' % (tid, optval_val, eax))
          
        else:
            #fd = self.mem_utils.readWord32(self.cpu, params)
            #addr = self.mem_utils.readWord32(self.cpu, params+4)
            #trace_msg = ('\treturn from socketcall %s tid:%s FD: %d addr:0x%x eax: 0x%x\n' % (socket_callname, tid, fd, addr, eax)) 
            if exit_info.sock_struct is not None:
                trace_msg = trace_msg+('\treturn from socketcall %s tid:%s FD: %d addr:0x%x eax: 0x%x\n' % (socket_callname, tid, exit_info.sock_struct.fd, exit_info.sock_struct.addr, eax)) 
            elif socket_callname != 'socket':
                self.lgr.debug('sharedSyscall tid:%s %s missing sock_struct, double call, it hap twice??' % (tid, socket_callname))
        return trace_msg

    def exitHap(self, dumb, context, break_num, memory):
        if self.context_manager.isReverseContext():
            return
        #self.lgr.debug('sharedSyscall call curThread')
        cpu, comm, tid = self.task_utils.curThread() 
        if cpu is None:
            self.lgr.error('sharedSyscall exitHap got nothing from curThread')
            return
        #self.lgr.debug('sharedSyscall exitHap tid:%s (%s) context: %s  break_num: %s cycle: 0x%x reverse context? %r' % (tid, comm, str(context), str(break_num), self.cpu.cycles, self.context_manager.isReverseContext()))
        #if tid == '1' and self.hack_exit_tid != '1':
        #    self.lgr.debug('sharedSyscall exitHap tid 1 bail')
        #    return
        #    self.lgr.debug('sharedSyscall exitHap tid 1 !!!!!!!  prev tid was %s set to that.' % self.hack_exit_tid)
        #    tid = self.hack_exit_tid
        #    SIM_break_simulation('remove this')
        did_exit = False
        if tid in self.exit_info:
            for name in self.exit_info[tid]:
                try:
                    exit_info = self.exit_info[tid][name]
                except:
                    continue
                #self.lgr.debug('exitHap tid:%s name: %s' % (tid, name))
                if self.win_call_exit is not None:
                    did_exit = self.win_call_exit.handleExit(exit_info, tid, comm)
                else:
                    did_exit = self.handleExit(exit_info, tid, comm)
        else:
            if self.win_call_exit is not None:
                #self.lgr.debug('sharedSyscall exitHap tid:%s not in exit_info' % tid)
                did_exit = self.win_call_exit.handleExit(None, tid, comm)
            else:
                did_exit = self.handleExit(None, tid, comm)
        if did_exit:
            #self.lgr.debug('sharedSyscall exitHap remove exitHap for %s' % tid)
            self.rmExitHap(tid)
            if self.callback is not None:
                self.lgr.debug('sharedSyscall exitHap call callback (dataWatch kernelReturnHap?)')
                self.callback(self.callback_param, context, break_num, memory)
                self.callback = None

    def fcntl(self, eax, exit_info, tid):
        if net.fcntlCmdIs(exit_info.cmd, 'F_DUPFD'):
            if tid in self.trace_procs:
                self.traceProcs.dup(tid, exit_info.old_fd, eax)
            trace_msg = ('F_DUPFD  old_fd: %d new: %d\n' % (exit_info.old_fd, eax))
        elif net.fcntlCmdIs(exit_info.cmd, 'F_GETFL'):
            trace_msg = ('F_GETFL, old_fd: %d  flags: 0%o\n' % (exit_info.old_fd, eax))
        elif exit_info.old_fd is not None:
            trace_msg = ('old_fd: %d retval: %d\n' % (exit_info.old_fd, eax))
        else:
            trace_msg = (' retval: %d\n' % (eax))
        return trace_msg
       
            
    def handleExit(self, exit_info, tid, comm):
        ''' 
           Invoked on (almost) return to user space after a system call.
           Includes parameter checking to see if the call meets criteria given in
           a paramter buried in exit_info (see ExitInfo class).
        '''
        trace_msg = ''
        if tid == '0':
            #self.lgr.debug('exitHap cell %s tid is zero' % (self.cell_name))
            return False
        ''' If this is a new tid, assume it is a child clone or fork return '''
        if exit_info is None:
            ''' no pending syscall for this tid '''
            if not self.traceProcs.tidExists(tid):
                ''' new TID, add it without parent for now? ''' 
                '''
                clonenum = self.task_utils.syscallNumber('clone', exit_info.compat32)
                for ptid in self.exit_info:
                    if self.exit_info[ptid].callnum == clonenum:
                        if self.exit_info[ptid].call_params is not None:
                            self.lgr.debug('clone returning in child %d parent maybe %d' % (tid, ptid))
                            SIM_break_simulation('clone returning in child %d parent maybe %d' % (tid, ptid))
                            return    
                '''
                leader_tid = self.task_utils.getCurrentThreadLeaderTid()
                self.lgr.debug('sharedSyscall handleExit maybe clone child return no parent tid %s (%s)  group leader is %s' % (tid, comm, leader_tid))
                if leader_tid != tid:
                    self.traceProcs.addProc(tid, leader_tid, comm=comm)
                    if self.context_manager.amWatching(leader_tid):
                        self.context_manager.addTask(tid)
                else:
                    self.traceProcs.addProc(tid, None, comm=comm)
                return False
            if self.isPendingExecve(tid):
                self.lgr.debug('sharedSyscall handleExit cell %s call reschedule from execve?  for tid %s  Remove pending' % (self.cell_name, tid))
                self.rmPendingExecve(tid)
                return False 
            else:
                ''' tid exists, but no execve syscall pending, assume reschedule? '''
                #self.lgr.debug('exitHap call reschedule for tid %s' % tid)
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
        callname = exit_info.callname
        #self.lgr.debug('exitHap cell %s callnum %d name %s  tid %s cycle: 0x%x' % (self.cell_name, exit_info.callnum, callname, tid, self.cpu.cycles))
        trace_msg = '\treturn from %s tid:%s (%s), ' % (callname, tid, comm)
        err_trace_msg = '\terror return from %s tid:%s (%s) ' % (callname, tid, comm)
        if callname == 'clone':
            if eax == 0:
                self.lgr.debug('exitHap is clone tid %s  eax zero just return' % tid)
                return
          
            self.lgr.debug('exitHap is clone tid %s  eax %d' % (tid, eax))
            if eax > 20000:
                SIM_break_simulation('confused clone')
                return False
            #if eax == 120:
            #    SIM_break_simulation('clone faux return?')
            #    return
            if exit_info.fname_addr is not None:
                self.top.recordStackBase(eax, exit_info.fname_addr)
            else:
                self.lgr.debug('exitHap clone fname_addr is None, cannot call recordStackBase')
            if  tid in self.trace_procs and self.traceProcs.addProc(eax, tid, clone=True):
                trace_msg = trace_msg+('(tracing), new tid:%s\n' % (eax))
                #self.lgr.debug('exitHap clone called addProc for eax:0x%x parent %s' % (eax, tid))
                self.traceProcs.copyOpen(tid, eax)
                self.task_utils.didClone(tid, eax)
            elif tid not in self.trace_procs:
                trace_msg = trace_msg+('new tid:%s\n' % (eax))
            else:
                ''' must be repeated hap or trackThreads already added the clone '''
                self.lgr.debug('exitHap clone repeated call? tid: %s eax %d' % (tid, eax))
                trace_msg = trace_msg+('new tid:%s\n' % (eax))
            if self.traceFiles is not None:
                self.traceFiles.clone(tid, str(eax))
                
            if exit_info.matched_param is not None:
                if exit_info.matched_param.nth is not None:
                    self.lgr.debug('exitHap clone, nth is %d' % exit_info.matched_param.nth)
                    if exit_info.matched_param.nth >= 0:
                        self.lgr.debug('exitHap clone, run to tid:%s' % eax)
                        SIM_run_alone(self.top.toProcTid, eax)
                        context = self.context_manager.getContextName(self.cpu.current_context)
                        self.top.rmSyscall(exit_info.matched_param.name, cell_name=self.cell_name, context=context)
                        exit_info.matched_param = None
                        #my_syscall = exit_info.syscall_instance
                        #my_syscall.stopTrace()
            
            #dumb_tid, dumb, dumb2 = self.context_manager.getDebugTid() 
            #if dumb_tid is not None:
            #    self.lgr.debug('sharedSyscall adding clone %d to watched tids' % eax)
            #    self.context_manager.addTask(eax)
             
        elif callname in ['mkdir', 'creat']:
            #fname = self.mem_utils.readString(exit_info.cpu, exit_info.fname_addr, 256)
            if exit_info.fname is None:
                if exit_info.fname_addr is None:
                    self.lgr.debug('fname_addr is None? Maybe from setExits in exit from mkdir tid:%s ' % (tid))
                else:
                    self.lgr.error('fname is None? in exit from mkdir tid:%s fname addr was 0x%x' % (tid, exit_info.fname_addr))
                #SIM_break_simulation('fname is none on exit of open')
                exit_info.fname = 'unknown'
            else:
                if callname == 'creat':
                    trace_msg = trace_msg+('FD: %d file: %s flags: 0x%x mode: 0x%x\n' % (eax, exit_info.fname, exit_info.flags, exit_info.mode))
                else:
                    trace_msg = trace_msg+('file: %s flags: 0x%x mode: 0x%x eax: 0x%x\n' % (exit_info.fname, exit_info.flags, exit_info.mode, eax))
                
        elif callname == 'open' or callname == 'openat':
            #fname = self.mem_utils.readString(exit_info.cpu, exit_info.fname_addr, 256)
            if exit_info.fname is None:
                #ptable_info = pageUtils.findPageTableIA32E(self.cpu, exit_info.fname_addr, self.lgr)
                if exit_info.fname_addr is None:
                    self.lgr.debug('sharedSyscall %s no fname_addr, debug starting in kernel???' % callname)
                    return
                if tid != '1':
                    self.lgr.error('fname is None? in exit from open tid:%s fname addr was 0x%x' % (tid, exit_info.fname_addr))
                    SIM_break_simulation('fname is none on exit of open')
                else:
                    self.lgr.debug('fname is None? in exit from open tid:%s fname addr was 0x%x' % (tid, exit_info.fname_addr))
                exit_info.fname = 'unknown'
            trace_msg = trace_msg+('FD: %d file: %s flags: 0%o mode: 0x%x eax: 0x%x\n' % (eax, 
                   exit_info.fname, exit_info.flags, exit_info.mode, eax))
            #self.lgr.debug('sharedSyscall exitHap return from open tid:%s (%s) FD: %d file: %s flags: 0%o mode: 0x%x eax: 0x%x' % (tid, comm, 
            #       eax, exit_info.fname, exit_info.flags, exit_info.mode, eax))
            if eax >= 0:
                if tid in self.trace_procs:
                    self.traceProcs.open(tid, comm, exit_info.fname, eax)
                ''' TBD cleaner way to know if we are getting ready for a debug session? '''
                if ('.so.' in exit_info.fname or exit_info.fname.endswith('.so')) and self.track_so:
                    #self.lgr.debug('sharedSyscall is open so')
                    #open_syscall = self.top.getSyscall(self.cell_name, 'open')
                    open_syscall = exit_info.syscall_instance
                    if open_syscall is not None: 
                        open_syscall.watchFirstMmap(tid, exit_info.fname, eax, exit_info.compat32)
                    else:
                        self.lgr.debug('sharedSyscall no syscall_instance in exit_info %s' % tid)
                if self.traceFiles is not None:
                    self.traceFiles.open(exit_info.fname, eax)

            if eax < 0:
                for call_param in exit_info.call_params:
                    if call_param.match_param is not None and call_param.match_param.__class__.__name__ == 'Dmod':
                        dmod = call_param.match_param
                        self.lgr.debug('sharedSyscall open, dmod kind %s' % dmod.kind)
                        if dmod.kind == 'open_replace':
                            self.lgr.debug('sharedSyscall open, setting return FD to 99')
                            self.top.writeRegValue('syscall_ret', 99, alone=True)
                            dmod.setFD(99)
                            dmod.setTid(tid)
                            trace_msg = trace_msg+('file: %s DMOD! forced return FD of 99 \n' % (exit_info.fname))
                        exit_info.matched_param = None
            for call_param in exit_info.call_params:
                if type(call_param.match_param) is str:
                    self.lgr.debug('sharedSyscall open check string %s against %s' % (exit_info.fname, call_param.match_param))
                    if call_param.match_param is not None and call_param.match_param in exit_info.fname:
                        ''' no match, set call_param to none '''
                        exit_info.matched_param = call_param
                        break
                
        elif callname == 'pipe' or \
             callname == 'pipe2':
            if eax == 0:
                fd1 = self.mem_utils.readWord32(self.cpu, exit_info.retval_addr)
                fd2 = self.mem_utils.readWord32(self.cpu, exit_info.retval_addr+4)
                #self.lgr.debug('return from pipe tid:%s fd1 %d fd2 %d from 0x%x' % (tid, fd1, fd2, exit_info.retval_addr))
                trace_msg = trace_msg+('fd1 %s fd2 %s from 0x%x\n' % (str(fd1), str(fd2), exit_info.retval_addr))
                if tid in self.trace_procs:
                    self.traceProcs.pipe(tid, fd1, fd2)

        elif callname == 'read':
            #self.lgr.debug('is read eax 0x%x' % eax)
            if self.read_fixup_callback is not None and eax >= 0:
                self.lgr.debug('sharedSyscall read call read_fixup_callback')
                eax = self.read_fixup_callback(exit_info.old_fd, callname=callname)
                if eax is None:
                    return
            if eax < 0: 
                for call_param in exit_info.call_params:
                    if call_param.match_param is not None and call_param.match_param.__class__.__name__ == 'Dmod' and call_param.match_param.tid == tid and exit_info.old_fd == call_param.match_param.fd:
                        self.lgr.debug('sharedSyscall read Dmod FD and tid match')     
                        becomes = call_param.match_param.getBecomes()
                        length = call_param.match_param.getWas()
                        length = int(length, 16)
                        if length == 0:
                            length = len(becomes)
                        self.mem_utils.writeString(self.cpu, exit_info.retval_addr, becomes)
                        self.top.writeRegValue('syscall_ret', length, alone=True)
                        eax = length
                        trace_msg = trace_msg+('FD: %d forced return val to %d\n' % (exit_info.old_fd, length))
                        break

            if eax >= 0 and exit_info.retval_addr is not None:

                max_len = min(eax, 1024)
                #max_max_len = min(eax, 10000000)
                max_max_len = min(eax, 100000)
                byte_array = self.mem_utils.getBytes(self.cpu, max_max_len, exit_info.retval_addr)
                if byte_array is not None:
                    s = resimUtils.getHexDump(byte_array[:max_len])
                    if self.traceFiles is not None:
                        self.lgr.debug('sharedSyscall call traceFiles read')
                        self.traceFiles.read(tid, exit_info.old_fd, byte_array)
                else:
                    s = '<<NOT MAPPED>>'
                self.lgr.debug('sharedSyscall return from read fd %d' % exit_info.old_fd)
                trace_msg = trace_msg+('FD: %d returned length: %d into 0x%x given count: %d cycle: 0x%x \n\t%s\n' % (exit_info.old_fd, 
                              eax, exit_info.retval_addr, exit_info.count, self.cpu.cycles, s))
                self.lgr.debug(trace_msg)

                my_syscall = exit_info.syscall_instance
                self.lgr.debug('sharedSyscall return from read matched_param is %s linger %r my_syscall %s' % (str(exit_info.matched_param), my_syscall.linger, my_syscall.name))
                if exit_info.matched_param is not None and (exit_info.matched_param.break_simulation or my_syscall.linger) and self.dataWatch is not None \
                                and type(exit_info.matched_param.match_param) is int and exit_info.matched_param.match_param == exit_info.old_fd:
                    if not self.checkCount(eax, exit_info, trace_msg, s):
                        self.dataWatch.setRange(exit_info.retval_addr, eax, msg=trace_msg, max_len=exit_info.count, fd=exit_info.old_fd, data_stream=True, kbuffer=self.kbuffer)
                # TBD make a config parameter
                if eax < 16000:
                    self.lgr.debug('sharedSyscall is read check %d params' % len(exit_info.call_params))
                    for call_param in exit_info.call_params:

                        if type(call_param.match_param) is str:
                            self.lgr.debug('syscall read match param for tid:%s is string, check match' % tid)
                            if byte_array is not None:
                                if resimUtils.isPrintable(byte_array):
                                    s = ''.join(map(chr,byte_array))
                                    if call_param.match_param in s:
                                       exit_info.matched_param = call_param 
                                       self.lgr.debug('syscall read match param for tid:%s is matching string' % tid)

                        elif call_param.match_param is not None and call_param.match_param.__class__.__name__ == 'Dmod':
                            dmod = call_param.match_param
                            self.lgr.debug('sharedSyscall %s read check dmod %s count %d' % (self.cell_name, dmod.getPath(), eax))
                            if dmod is not None and dmod.getComm() is not None and dmod.getComm() != comm:
                                self.lgr.debug('sharedSyscall read is dmod, but wrong comm, wanted %s, this is %s' % (dmod.getComm(), comm))
                            elif dmod.checkString(self.cpu, exit_info.retval_addr, eax, tid, exit_info.old_fd):
                                self.lgr.debug('sharedSyscall read did dmod %s count now %d' % (dmod.getPath(), dmod.getCount()))
                                if dmod.getCount() == 0:
                                    self.lgr.debug('sharedSyscall read found final dmod %s' % dmod.getPath())
                                    if not exit_info.syscall_instance.remainingDmod(call_param.name) and exit_info.syscall_instance.name != 'traceAll':
                                        self.lgr.debug('sharedSyscall read Dmod stopping trace dmod %s' % dmod.getPath())
                                        self.top.rmSyscall(call_param.name, cell_name=self.cell_name, all_contexts=True)
                                        #self.top.stopTrace(cell_name=self.cell_name, syscall=exit_info.syscall_instance)
                                        self.stopTrace()
                                        # note rmDmod simply notes it has been removed so we know if future snapshot loads
                                        self.top.rmDmod(self.cell_name, dmod.getPath())
                                        #if not self.top.remainingCallTraces(exception='_llseek') and SIM_simics_is_running():
                                        if dmod.getBreak():
                                            self.top.notRunning(quiet=True)
                                            SIM_break_simulation('dmod break_on_dmod,  on cell %s file: %s' % (self.cell_name, dmod.getPath()))
                                        elif not self.top.remainingCallTraces(cell_name=self.cell_name, exception='_llseek') and SIM_simics_is_running():
                                            self.top.notRunning(quiet=True)
                                            SIM_break_simulation('dmod done on cell %s file: %s' % (self.cell_name, dmod.getPath()))
                                    else:
                                        self.top.rmDmod(self.cell_name, dmod.getPath())
                                        exit_info.syscall_instance.rmCallParam(call_param)
                                else:
                                    print('%s performed' % dmod.getPath())
                                if call_param.break_simulation:
                                    SIM_break_simulation('dmod break simulation')
                

            elif exit_info.old_fd is not None:
                trace_msg = trace_msg+('FD: %d exception %d\n' % (exit_info.old_fd, eax))
                exit_info.matched_param = None

        elif callname == 'write':
            if eax >= 0 and exit_info.retval_addr is not None:
                    max_len = min(eax, 1024)
                    max_max_len = min(eax, 10000)
                    byte_array = self.mem_utils.getBytes(self.cpu, max_max_len, exit_info.retval_addr)
                    if byte_array is not None:
                        s = resimUtils.getHexDump(byte_array[:max_len])
                        '''
                        if s != exit_info.fname[:max_len]:
                            self.lgr.error('write is not what was written cycles: 0x%x' % self.cpu.cycles)
                            self.lgr.error('at call time: %s' % exit_info.fname)
                            self.lgr.error('now         : %s' % s)
                        '''
                        if self.traceFiles is not None:
                            self.traceFiles.write(tid, exit_info.old_fd, byte_array)
                    else:
                        s = '<<NOT MAPPED>>'
                    #trace_msg = ('\treturn from write tid:%s FD: %d count: %d\n\t%s\n' % (tid, exit_info.old_fd, eax, byte_string))
                    trace_msg = trace_msg+('FD: %d count: %d\n\t%s\n' % (exit_info.old_fd, eax, s))
                    if exit_info.matched_param is not None and type(exit_info.matched_param.match_param) is str:
                        self.lgr.debug('sharedSyscall write call_param %s string already matched in syscall' % exit_info.matched_param.name)
                    elif exit_info.matched_param is not None:
                        self.lgr.debug('sharedSyscall call param NOT HANDLED type of param %s' % (type(exit_info.matched_param.match_param)))
                    if self.all_write:
                        self.allWrite.write(comm, tid, exit_info.old_fd, s)
            else:
                trace_msg = trace_msg+('FD: %d exception %d\n' % (exit_info.old_fd, eax))
                exit_info.matched_param = None

        elif callname == 'writev' or callname == 'readv':
            if eax >= 0:
                add_msg, byte_tuple = self.getIOV(eax, exit_info)
                trace_msg = trace_msg + add_msg
                #if callname == 'writev':
                self.checkStringMatch(exit_info, bytearray(byte_tuple), tid)
      
        elif callname in ['_llseek', 'lseek']:
            if eax >= 0:
                if callname == '_llseek' and self.mem_utils.WORD_SIZE == 4:
                    result = self.mem_utils.readWord32(self.cpu, exit_info.retval_addr)
                    if result is not None:
                        trace_msg = trace_msg+('FD: %d result: 0x%x\n' % (exit_info.old_fd, result))
                    else:
                        trace_msg = trace_msg+('FD: %d result failed read of addr 0x%x\n' % (exit_info.old_fd, exit_info.retval_addr))
                else:
                    trace_msg = trace_msg+('FD: %d eax: 0x%x\n' % (exit_info.old_fd, eax))

            else:
                for call_param in exit_info.call_params:
                    if call_param.match_param is not None and call_param.match_param.__class__.__name__ == 'Dmod' \
                            and call_param.match_param.tid == tid and exit_info.old_fd == call_param.match_param.fd:
                        self.lgr.debug('sharedSyscall lseek Dmod FD and tid match, set return value to 0, tbd extend?')     
                        self.top.writeRegValue('syscall_ret', 0, alone=True)
                        trace_msg = trace_msg+('DMOD! FD: %d forced return to 0\n' % (exit_info.old_fd))

        elif callname == 'ioctl':
            if exit_info.retval_addr is not None:
                if exit_info.cmd == 0x720:
                    ''' i2c bus xfer '''
                    xfer_byte_addr = exit_info.retval_addr+2*self.mem_utils.WORD_SIZE
                    result_ptr = self.mem_utils.readPtr(self.cpu, xfer_byte_addr)
                    result = self.mem_utils.readByte(self.cpu, result_ptr)
                    if result is not None:
                        trace_msg = trace_msg+('FD: %d cmd: 0x%x retval_addr: 0x%x result: 0x%x written to 0x%x\n' % (exit_info.old_fd, exit_info.cmd, exit_info.retval_addr, result, result_ptr))
                    else:
                        trace_msg = trace_msg+('FD: %d cmd: 0x%x could not read bye written to 0x%x\n' % (exit_info.old_fd, exit_info.cmd, result_ptr))

                else:
                    if self.read_fixup_callback is not None:
                        result = self.mem_utils.readWord32(self.cpu, exit_info.retval_addr)
                        if result is not None:
                            self.lgr.debug('sharedSyscall ioctl call read_fixup_callback result was 0x%x' % result) 
                            self.read_fixup_callback(exit_info.old_fd, callname=callname, addr_of_count=exit_info.retval_addr)
                    result = self.mem_utils.readWord32(self.cpu, exit_info.retval_addr)
                    if result is not None:

                        trace_msg = trace_msg+('FD: %d cmd: 0x%x result: 0x%x written to 0x%x\n' % (exit_info.old_fd, exit_info.cmd, result, exit_info.retval_addr))
                        self.lgr.debug(trace_msg)
                        #if exit_info.cmd == 0x541b:
                            
                    elif exit_info.cmd is not None and exit_info.retval_addr is not None:
                        self.lgr.debug('sharedSyscall ioctl read None from 0x%x cmd: 0x%x' % (exit_info.retval_addr, exit_info.cmd))
                        trace_msg = trace_msg+('FD: %d cmd: 0x%x eax: 0x%x\n' % (exit_info.old_fd, exit_info.cmd, eax))
                    else:
                        self.lgr.error('sharedSyscall exit_info cmd or retval_addr is none')
                    # TBD fix to only apply to appropriate ioctl calls
                    self.lgr.debug('sharedSyscall matched_param %s' % str(exit_info.matched_param))
                    if exit_info.matched_param is not None and (exit_info.matched_param.break_simulation or exit_info.syscall_instance.linger) and self.dataWatch is not None:
                        ''' in case we want to break on a read of waiting bytes '''
                        self.dataWatch.setRange(exit_info.retval_addr, 4, trace_msg, back_stop=True, no_backstop=True, fd=exit_info.old_fd)
                        if exit_info.syscall_instance.linger: 
                            self.dataWatch.stopWatch() 
                            self.dataWatch.watch(break_simulation=False, no_backstop=True, i_am_alone=True)
            elif exit_info.cmd == 0x703:
                ''' i2c slave address '''
                trace_msg = trace_msg+('FD: %d cmd: 0x%x slave_addr 0x%x\n' % (exit_info.old_fd, exit_info.cmd, exit_info.flags)) 
            else:
                trace_msg = trace_msg+('FD: %d cmd: 0x%x eax: 0x%x\n' % (exit_info.old_fd, exit_info.cmd, eax))

        elif callname == 'gettimeofday': 
            if exit_info.retval_addr is not None:
                result = self.mem_utils.readWord32(self.cpu, exit_info.retval_addr)
                trace_msg = trace_msg+('result: 0x%x\n' % (result))
                timer_syscall = self.top.getSyscall(self.cell_name, 'gettimeofday')
                if timer_syscall is not None:
                    timer_syscall.checkTimeLoop('gettimeofday', tid)

        elif callname == 'waitpid': 
            timer_syscall = self.top.getSyscall(self.cell_name, 'waitpid')
            if timer_syscall is not None:
                timer_syscall.checkTimeLoop('waitpid', tid)
            else:
                self.lgr.debug('timer_syscall is None')
            if exit_info.retval_addr != 0:
                wstatus = self.mem_utils.readWord32(self.cpu, exit_info.retval_addr)
                trace_msg = trace_msg+('eax: 0x%x wstatus: 0x%x\n' % (eax, wstatus))
            else:
                trace_msg = trace_msg+('eax: 0x%x wstatus addr was none\n' % (eax))
            self.lgr.debug(trace_msg)


        elif callname == 'close':
            got_msg = False
            if eax == 0:
                if tid in self.trace_procs:
                    #self.lgr.debug('exitHap for close tid:%s' % tid)
                    self.traceProcs.close(tid, exit_info.old_fd)
                trace_msg = trace_msg+('FD: %d  eax: 0x%x\n' % (exit_info.old_fd, eax))
                got_msg = True
                if self.traceFiles is not None:
                    self.traceFiles.close(exit_info.old_fd)
                if exit_info.matched_param is not None:
                    self.dataWatch.close(exit_info.old_fd)
            for call_param in exit_info.call_params:
                if call_param.match_param is not None and call_param.match_param.__class__.__name__ == 'Dmod' \
                                and call_param.match_param.tid == tid and exit_info.old_fd == call_param.match_param.fd:
                    self.lgr.debug('sharedSyscall close Dmod FD and tid match, set return value to 0')     
                    self.top.writeRegValue('syscall_ret', 0, alone=True)
                    trace_msg = err_trace_msg+('DMOD!, FD: %d  eax: 0x%x\n' % (exit_info.old_fd, eax))
                    got_msg = True
                    call_param.match_param.resetOpen()
            if not got_msg:
                trace_msg = err_trace_msg+('FD: %d  eax: 0x%x\n' % (exit_info.old_fd, eax))
            
        elif callname in ['fcntl64', 'fcntl']:        
            if eax >= 0:
                trace_msg = trace_msg+self.fcntl(eax, exit_info, tid)
            else:
                trace_msg = err_trace_msg+('old_fd: %d retval: %d\n' % (exit_info.old_fd, eax))

        elif callname == 'dup':
            #self.lgr.debug('exit tid:%s from dup eax %x, old_fd is %d' % (tid, eax, exit_info.old_fd))
            if eax >= 0:
                if tid in self.trace_procs:
                    self.traceProcs.dup(tid, exit_info.old_fd, eax)
                trace_msg = trace_msg+('old_fd: %d new: %d\n' % (exit_info.old_fd, eax))
                if self.traceFiles is not None:
                    self.traceFiles.dup(exit_info.old_fd, eax)
        elif callname in ['dup2', 'dup3']:
            #self.lgr.debug('return from dup2 tid:%s eax %x, old_fd is %d new_fd %d' % (tid, eax, exit_info.old_fd, exit_info.new_fd))
            if eax >= 0:
                if exit_info.old_fd != exit_info.new_fd:
                    if tid in self.trace_procs:
                        self.traceProcs.dup(tid, exit_info.old_fd, exit_info.new_fd)
                    trace_msg = trace_msg+('old_fd: %d new: %d\n' % (exit_info.old_fd, eax))
                else:
                    trace_msg = trace_msg+('old_fd: and new both %d   Eh?\n' % (eax))
                self.traceFiles.dup(exit_info.old_fd, exit_info.new_fd)
        elif callname == 'mmap2' or callname == 'mmap':
                self.lgr.debug('sharedSyscall exitHap for %s' % callname)
                # TBD still need error detection/handline
                if exit_info.fname is not None and self.soMap is not None:
                    self.lgr.debug('sharedSyscall return from mmap tid:%s, addr: 0x%x so fname: %s' % (tid, ueax, exit_info.fname))
                    trace_msg = trace_msg+('addr: 0x%x so fname: %s\n' % (ueax, exit_info.fname))
                    if '/etc/ld.so.cache' not in exit_info.fname:
                        if self.top.trackingThreads() or self.context_manager.amWatching(tid):
                            self.soMap.addSO(tid, exit_info.fname, ueax, exit_info.count)
                        else:
                            self.lgr.debug('sharedSyscall %s not watching threads or debugging tid:%s.  SO not recorded.' % (callname, tid))
                else:
                    self.lgr.debug('sharedSyscall exitHap fname soMap none')
                    trace_msg = trace_msg+('addr: 0x%x \n' % (ueax))
                    #if exit_info.prot is not None and exit_info.prot & 2 > 0:
                    self.lgr.debug('sharedSyscall exitHap mmap prot %s' % exit_info.prot) 
                    self.dataWatch.mmap(ueax)
        elif callname == 'ipc':
            callname = exit_info.socket_callname
            call = exit_info.frame['param1']
            if call == ipc.MSGGET or callname == ipc.SHMGET:
                trace_msg = trace_msg+('key: 0x%x quid: 0x%x\n' % (exit_info.fname, ueax)) 
                #SIM_break_simulation('msgget tid:%s ueax 0x%x eax 0x%x' % (tid, ueax, eax))
            elif call == ipc.SHMAT:
                ret_addr = exit_info.frame['param4']
                mem_addr = self.mem_utils.readPtr(self.cpu, ret_addr)
                trace_msg = trace_msg+(' mem_addr: 0x%x\n' % (mem_addr)) 
            elif eax < 0:
                    trace_msg = trace_msg+('result: %d\n' % (eax)) 
            elif call == ipc.MSGSND:
                nbytes = min(exit_info.count, 1024)
                if exit_info.bytes_to_write is not None:
                    s = resimUtils.getHexDump(exit_info.bytes_to_write[:nbytes])
                    trace_msg = trace_msg+('result: 0x%x size %d from 0x%x %s\n' % (ueax, exit_info.count, exit_info.retval_addr, s)) 
                else:
                    trace_msg = trace_msg+('result: 0x%x but not bytes written?\n' % (ueax)) 
                #self.lgr.debug(trace_msg)
                #SIM_break_simulation('return MSGSND')    
            elif call == ipc.MSGRCV:
                nbytes = min(eax, 1024)
                msg_ptr = self.mem_utils.readPtr(self.cpu, exit_info.retval_addr)
                byte_array = self.mem_utils.getBytes(self.cpu, eax, msg_ptr)
                #self.lgr.debug('MSGRCV retval_addr 0x%x got %d bytes, nbytes is %d' % (exit_info.retval_addr, len(byte_array), nbytes))
                if byte_array is not None:
                    s = resimUtils.getHexDump(byte_array[:nbytes])
                    trace_msg = trace_msg+('received: %d bytes from 0x%x %s\n' % (ueax, exit_info.retval_addr, s)) 
                else:
                    trace_msg = trace_msg+('result: 0x%x but not bytes read?\n' % (ueax)) 
                #self.lgr.debug(trace_msg)
                #SIM_break_simulation('return MSGRCV')    
            else:
                trace_msg = trace_msg+('result: 0x%x\n' % (ueax)) 

        elif callname == 'select' or callname == '_newselect' or callname == 'pselect6':
            if exit_info.select_info is not None:
                trace_msg = trace_msg+('%s result: %d\n' % (exit_info.select_info.getString(), eax))
                if self.select_fixup_callback is not None and not self.select_fixup_callback(exit_info.select_info):
                    self.lgr.debug('sharedSyscall select, select_fixup_callback returned false, bail')
                    return 
                if self.fool_select is not None and eax > 0:
                    eax = self.modifySelect(exit_info.select_info, eax)
                    if self.dataWatch is not None:
                        trace_msg = trace_msg.strip() + (' NOTE: eax altered to 0x%x\n' % eax) 
                        self.dataWatch.markCall(trace_msg, exit_info.old_fd)
                else:
                    for call_param in exit_info.call_params:
                        if type(call_param.match_param) is int:
                            if exit_info.syscall_instance.name == 'runToIO':
                                if exit_info.select_info.setHasFD(call_param.match_param, exit_info.select_info.readfds):
                                    self.lgr.debug('sharedSyscall select for runToIO fd %d in read fds, has match' % call_param.match_param)
                                    exit_info.matched_param = call_param
                                    if self.dataWatch is not None:
                                        msg = trace_msg
                                        self.dataWatch.markCall(msg, call_param.match_param)
                                    break
                            elif exit_info.select_info.hasFD(call_param.match_param):
                                self.lgr.debug('sharedSyscall select fd %d found' % call_param.match_param)
                                exit_info.matched_param = call_param
                    
            else:
                trace_msg = trace_msg+('NO select info result: %d\n' % (eax))
        elif callname == 'poll' or callname == 'ppoll':
            if exit_info.poll_info is not None:
                trace_msg = trace_msg+('%s result: %d\n' % (exit_info.poll_info.getString(), eax))
                if self.poll_fixup_callback is not None and not self.poll_fixup_callback(exit_info.poll_info):
                    self.lgr.debug('sharedSyscall select, poll_fixup_callback returned false, bail')
                    return 
                self.lgr.debug('sharedSyscall %s fool_select is %s' % (callname, self.fool_select))
                if self.fool_select is not None and eax > 0:
                    eax = self.modifyPoll(exit_info.poll_info, eax)
                    if self.dataWatch is not None:
                        trace_msg = trace_msg.strip() + (' NOTE: eax altered to 0x%x\n' % eax) 
                        self.dataWatch.markCall(trace_msg, exit_info.old_fd)
 
                exit_info.matched_param = None
            else:
                trace_msg = trace_msg+('poll info was None  result: %d\n' % (eax))

        elif callname == 'vfork':
            trace_msg = trace_msg+('in parent %s child tid:%s\n' % (tid, ueax))
            if tid in self.trace_procs:
                self.traceProcs.addProc(ueax, tid)
                self.traceProcs.copyOpen(tid, eax)
        elif callname == 'execve':
            self.lgr.debug('sharedSyscall execve tid:%s  remove from pending_execve' % tid)
            trace_msg = trace_msg+('result: 0x%x\n' % eax)
            if self.isPendingExecve(tid):
                self.rmPendingExecve(tid)
        elif callname == 'socketcall' or callname.upper() in net.callname:
            trace_msg = self.doSockets(exit_info, eax, tid, comm)
        elif callname == 'epoll_wait' or callname == 'epoll_pwait':
             # epoll_wait.events is the epoll_event ptr
             if exit_info.epoll_wait  is not None:
                 cur_ptr = exit_info.epoll_wait.events
                 trace_msg = trace_msg+('epfd: %d eax %d maxevents: %d cur_ptr: 0x%x\n' % (exit_info.old_fd, eax, exit_info.epoll_wait.maxevents, cur_ptr))
                 self.lgr.debug(trace_msg)
                 epoll_info = exit_info.epoll_wait.epoll_info
                 for i in range(eax):
                     events = syscall.EPollEvent(cur_ptr, self.cpu, self.mem_utils)
                     trace_msg = trace_msg+' '+events.toString()
                     if epoll_info is not None:
                         match_fd = epoll_info.findFD(events)
                         if match_fd is not None:
                             trace_msg = trace_msg + 'FD: %d' % match_fd 
                     cur_ptr = cur_ptr+4+self.mem_utils.WORD_SIZE+12
             else:
                 trace_msg = trace_msg+' no epoll wait value\n'
             trace_msg = trace_msg+'\n'
        elif callname == 'eventfd' or callname == 'eventfd2':
             trace_msg = trace_msg+('FD: %d\n' % (eax))
        elif callname == 'timerfd_create':
             trace_msg = trace_msg+('FD: %d\n' % (eax))

        elif callname == 'msgrcv':
            self.lgr.debug('is msgrcv')
            msqid = exit_info.old_fd
            if eax < 0:
                trace_msg = trace_msg+' msqid: 0x%x failed code: 0x%x cycle:0x%x' % (msqid, eax, self.cpu.cycles)
                self.lgr.debug(trace_msg.strip()) 
            else:
                msgsz = exit_info.count
                max_len = min(msgsz, 1024)
                msgp = exit_info.retval_addr
                mtext_addr = msgp + 4
                byte_array = self.mem_utils.getBytes(self.cpu, max_len, mtext_addr)
                mtype = self.mem_utils.readWord32(self.cpu, msgp)
                s = None
                if byte_array is not None:
                    s = resimUtils.getHexDump(byte_array[:max_len])
                trace_msg = trace_msg+'msqid: 0x%x mtype: 0x%x msgsz: %d msg: %s cycle:0x%x' % (msqid, mtype, msgsz, s, self.cpu.cycles)
                self.lgr.debug(trace_msg.strip()) 
        elif callname == 'shmget':
            if eax > 0:
                trace_msg = trace_msg+'return code 0x%x cycle:0x%x' % (eax, self.cpu.cycles)
                self.lgr.debug(trace_msg.strip()) 
            else:
                trace_msg = err_trace_msg+'failed code: 0x%x cycle:0x%x' % (eax, self.cpu.cycles)
                self.lgr.debug(trace_msg.strip()) 
        else:
            trace_msg = trace_msg+('code: 0x%x\n' % (ueax))


        ''' if debugging a proc, and clone call, add the new process '''
        dumb_tid, dumb2 = self.context_manager.getDebugTid() 
        if dumb_tid is not None and callname == 'clone':
            if eax == 0:
                self.lgr.debug('sharedSyscall clone but eax is zero ??? tid is %s' % tid)
                return True
            self.lgr.debug('sharedSyscall adding clone %d to watched tids' % eax)
            self.context_manager.addTask(eax)

        if exit_info.matched_param is not None and exit_info.matched_param.match_param is not None and exit_info.matched_param.break_simulation:
            '''  Use syscall module that got us here to handle stop actions '''
            self.lgr.debug('exitHap found matching call parameter %s' % str(exit_info.matched_param.match_param))
            self.matching_exit_info = exit_info
            self.context_manager.setIdaMessage(trace_msg)
            #self.lgr.debug('exitHap found matching call parameters callnum %d name %s' % (exit_info.callnum, callname))
            #my_syscall = self.top.getSyscall(self.cell_name, callname)
            my_syscall = exit_info.syscall_instance
            if my_syscall is None:
                self.lgr.error('sharedSyscall could not get syscall for %s' % callname)
            else:
                if not my_syscall.linger: 
                    self.stopTrace()
                self.lgr.debug('sharedSyscall add call param %s to syscall remove list' % exit_info.matched_param.name)
                my_syscall.appendRmParam(exit_info.matched_param.name)
                SIM_run_alone(my_syscall.stopAlone, callname)
                print(trace_msg)
    
        if trace_msg is not None and len(trace_msg.strip())>0:
            #self.lgr.debug('sharedSyscall exitHap cell %s %s'  % (self.cell_name, trace_msg.strip()))
            self.traceMgr.write(trace_msg) 
        return True

    def checkCount(self, eax, exit_info, trace_msg, data_string):
        # determine if a runToInput type syscall has an associated count; and if so, 
        # whether that count has been reached
        self.lgr.debug('sharedSyscall checkCount sub_match: %s data_string %s' % (exit_info.matched_param.sub_match, data_string))
        wait_for_count = False
        my_syscall = exit_info.syscall_instance
        if exit_info.matched_param.nth is not None:
            wait_for_count = True
            exit_info.matched_param.count = exit_info.matched_param.count + 1
            self.lgr.debug('sharedSyscall checkCount call_param.nth not none, is %d, count is %d' % (exit_info.matched_param.nth, exit_info.matched_param.count))
            if exit_info.matched_param.count >= exit_info.matched_param.nth:
                wait_for_count = False
            else:
                exit_info.matched_param = None
        if not wait_for_count and exit_info.matched_param.sub_match is not None:
            self.lgr.debug('sharedSyscall checkCount check sub_match %s' % exit_info.matched_param.sub_match)
            if exit_info.matched_param.sub_match not in data_string:
                wait_for_count = True
                self.lgr.debug('sharedSyscall checkCount submatch not found, set wait_for_count')
            else:
                self.lgr.debug('sharedSyscall checkCount submatch was found')
        self.lgr.debug('sharedSyscall checkCount wait_for_count is %r' % wait_for_count)
       
        if not wait_for_count:
            if my_syscall.linger: 
                self.dataWatch.stopWatch() 
                self.dataWatch.watch(break_simulation=False, i_am_alone=True)
            if exit_info.origin_reset:
                self.lgr.debug('sharedSyscall checkCount found origin reset, do it')
                SIM_run_alone(self.stopAlone, None)
            if self.kbuffer is not None:
                self.kbuffer.readReturn(eax)
        else:
            exit_info.matched_param = None
        return wait_for_count

    def checkStringMatch(self, exit_info, byte_array, tid):
        for call_param in exit_info.call_params:
            if type(call_param.match_param) is str:
                self.lgr.debug('sharedSyscall checkStringMatch match param for tid:%s is string, check match' % tid)
                bmatch = call_param.match_param.encode()
                if bmatch in byte_array:
                    exit_info.matched_param = call_param 
                    self.lgr.debug('sharedSyscall checkStringMatch match param for tid:%s is matching string' % tid)
                else:
                    exit_info.matched_param = None
                break

    def startAllWrite(self):
        self.all_write = True
       
    def getMatchingExitInfo(self):
        if self.top.isWindows():
            return self.win_call_exit.getMatchingExitInfo() 
        else:
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
        for tid in self.exit_info: 
            self.lgr.debug('sharedSyscall getExistList tid:%s' % tid)
            for name in self.exit_info[tid]:
                self.lgr.debug('sharedSyscall getExistList name %s' % name)
                if name in self.exit_info[tid]:
                    exit_info_list[tid] = self.exit_info[tid][name].frame
                    exit_info_list[tid]['syscall_num'] = self.exit_info[tid][name].callnum
        return exit_info_list

    def foolSelect(self, fd):
        ''' Modify return values from select to reflect no data for this fd ''' 
        self.lgr.debug('sharedSyscall foolSelect set select fd to %d' % fd)
        self.fool_select = fd

    def modifySelect(self, select_info, eax):
        if select_info.setHasFD(self.fool_select, select_info.readfds): 
            select_info.resetFD(self.fool_select, select_info.readfds)
            eax = eax -1
            self.top.writeRegValue('syscall_ret', eax, alone=True)
            self.lgr.debug('sharedSyscall modified select result, cleared fd and set eax to %d' % eax)
        return eax

    def modifyPoll(self, poll_info, eax):
        if poll_info.hasFD(self.fool_select):
            eax = 0
            self.top.writeRegValue('syscall_ret', eax, alone=True)
            self.lgr.debug('sharedSyscall modified poll result, eax to %d' % eax)
        return eax

    def rmExitBySyscallName(self, name, cell, immediate=False):
        self.lgr.debug('rmExitBySyscallName %s immediate: %r' % (name, immediate))
        exit_name = '%s-exit' % name
        rmlist = []
        if name is None or name == 'None':
            self.lgr.debug('rmExitBySyscall name is none, experiment, ug')
            return
        for tid in self.exit_names:
            the_name = self.exit_names[tid]
            if the_name.endswith(exit_name):
                rmlist.append(tid)
                #self.lgr.debug('sharedSyscall rmExitBySyscallName tid:%s removing: %s context %s' % (tid, name, str(cell))) 
                self.rmExitHap(tid, context=cell, immediate=immediate)
                if tid in self.exit_info and the_name in self.exit_info[tid]:
                    del self.exit_info[tid][the_name]
        for tid in rmlist:
            del self.exit_names[tid]

        #self.lgr.debug('rmExitBySyscallName return from %s' % name)

    def setcallback(self, callback, param):
        self.lgr.debug('sharedSyscall setcallback to %s' % str(callback))
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
        if self.top.isWindows(target=self.cell_name):
            self.win_call_exit.setReadFixup(read_fixup_callback) 
        else:
            self.read_fixup_callback = read_fixup_callback

    def setSelectFixup(self, select_fixup_callback):
        if self.top.isWindows(target=self.cell_name):
            self.win_call_exit.setSelectFixup(select_fixup_callback) 
        else:
            self.select_fixup_callback = select_fixup_callback

    def setPollFixup(self, poll_fixup_callback):
        self.poll_fixup_callback = poll_fixup_callback

    def preserveExit(self):
        self.preserve_exit = True

    def getIOV(self, count, exit_info):
       
        limit = min(10, exit_info.count)
        iov_size = 2*self.mem_utils.WORD_SIZE
        iov_addr = exit_info.retval_addr
        remain = count 
        self.lgr.debug('sharedSyscall %s return count %d iov_addr 0x%x' % (exit_info.callname, count, iov_addr))
        trace_msg = 'FD: %d count: %d' % (exit_info.old_fd, count)
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

            max_len = min(length, 1024)
            max_max_len = min(count, 10000)
            byte_tuple = self.mem_utils.getBytes(self.cpu, max_max_len, base)
            if byte_tuple is not None:
                s = resimUtils.getHexDump(byte_tuple[:max_len])
                if self.traceFiles is not None:
                    self.traceFiles.write(exit_info.tid, exit_info.old_fd, byte_tuple)
                full_byte_tuple = full_byte_tuple + byte_tuple
            else:
                s = '<<NOT MAPPED>>'

            self.lgr.debug('sharedSyscall %s base: 0x%x length: %d data: %s' % (exit_info.callname, base, length, s))
            trace_msg = trace_msg+' buffer: 0x%x len: %d data: %s' % (base, length, s)
            remain = remain - data_len 
            iov_addr = iov_addr+iov_size
        trace_msg = trace_msg+'\n'
        return trace_msg, full_byte_tuple

