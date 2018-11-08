from simics import *
import hapCleaner
import taskUtils
import net
import memUtils
def is_ascii(s):
    return all(ord(c) < 128 for c in s)

def ip2String(ip):
  "Convert 32-bit integer to dotted IPv4 address."
  return ".".join(map(lambda n: str(ip>>n & 0xFF), [0,8,16,24]))

class SyscallInfo():
    def __init__(self, cpu, pid, callnum, calculated, trace):
        self.cpu = cpu
        self.pid = pid
        self.callnum = callnum
        self.calculated = calculated
        self.trace = trace

class ExitInfo():
    def __init__(self, cpu, pid, callnum):
        self.cpu = cpu
        self.pid = pid
        self.callnum = callnum
        self.fname_addr = None
        self.flags = None
        self.mode = None
        self.old_fd = None
        self.new_fd = None
        self.socket_callnum = None
        self.socket_params = None

class Syscall():

    def __init__(self, top, cell, param, mem_utils, task_utils, context_manager, traceProcs, lgr, callnum=None, trace = False, trace_fh = None): 
        self.mem_utils = mem_utils
        self.task_utils = task_utils
        self.context_manager = context_manager
        pid, dumb, cpu = context_manager.getDebugPid()
        if cpu is None:
            cpu = top.getCPU() 
        self.cpu = cpu
        self.cell = cell
        self.pid = pid
        self.top = top
        self.param = param
        self.traceProcs = traceProcs
        self.lgr = lgr
        self.stop_hap = None
        self.trace_fh = trace_fh
        self.exit_hap = {}
        self.exit_break = {}
        self.mode_hap = None
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
            syscall_info = SyscallInfo(self.cpu, self.pid, callnum, entry, trace)
            proc_hap = self.context_manager.genHapRange("Core_Breakpoint_Memop", self.syscallHap, syscall_info, proc_break, proc_break1)
        else:
            entry = self.task_utils.getSyscallEntry(callnum)
            self.lgr.debug('runToSyscall callnum is %s entry 0x%x' % (callnum, entry))
            proc_break = self.context_manager.genBreakpoint(cell, Sim_Break_Linear, Sim_Access_Execute, entry, 1, 0)
            proc_break1 = None
            break_list.append(proc_break)
            syscall_info = SyscallInfo(self.cpu, self.pid, callnum, entry, trace)
            proc_hap = self.context_manager.genHapIndex("Core_Breakpoint_Memop", self.syscallHap, syscall_info, proc_break)
        
        if not trace:
            hap_clean = hapCleaner.HapCleaner(cpu)
            hap_clean.add("Core_Breakpoint_Memop", proc_hap)
            flist = [self.top.skipAndMail]
            stop_action = hapCleaner.StopAction(hap_clean, break_list, flist)
            self.stop_hap = SIM_hap_add_callback("Core_Simulation_Stopped", 
            	     self.stopHap, stop_action)
        if not trace:
            SIM_run_command('c')

    def frameFromStackSyscall(self):
        reg_num = self.cpu.iface.int_register.get_number(self.mem_utils.getESP())
        esp = self.cpu.iface.int_register.read(reg_num)
        regs_addr = esp + self.mem_utils.WORD_SIZE
        #self.lgr.debug('frameFromStackSyscall regs_addr is 0x%x  ' % (regs_addr))
        frame = self.task_utils.getFrame(regs_addr, self.cpu)
        return frame

    def parseOpen(self, frame):
        fname_addr = frame['ebx']
        flags = frame['ecx']
        mode = frame['edx']
        fname = self.mem_utils.readString(self.cpu, fname_addr, 256)
        cpu, comm, pid = self.task_utils.curProc() 
        ida_msg = 'Syscall: open flags: 0x%x  mode: 0x%x  filename: %s   pid: %d' % (flags, mode, fname, pid)
        #self.lgr.debug('parseOpen set ida message to %s' % ida_msg)
        if self.trace_fh is not None:
            #self.trace_fh.write(ida_msg+'\n')
            pass
        else:
            self.context_manager.setIdaMessage(ida_msg)
        return fname_addr, flags, mode

    def finishParseExecve(self, call_info, third, forth, memory):
        cpu, comm, pid = self.task_utils.curProc() 
        if cpu != call_info.cpu or pid != call_info.pid:
            return
        if self.execve_hap is None:
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
        ida_msg = 'Syscall: execve prog: %s %s  pid: %d' % (prog_string, arg_string, call_info.pid)
        if self.trace_fh is not None:
            self.trace_fh.write(ida_msg+'\n')
            self.traceProcs.setName(call_info.pid, prog_string, arg_string)
        else:
            self.context_manager.setIdaMessage(ida_msg)
        SIM_hap_delete_callback_id("Core_Breakpoint_Memop", self.execve_hap)
        SIM_delete_breakpoint(self.execve_break)
        self.execve_hap = None
        self.execve_break = None

    def parseExecve(self, frame):
        cpu, comm, pid = self.task_utils.curProc() 
        prog_string, arg_string_list = self.task_utils.getProcArgsFromStack(pid, None, cpu)
        if prog_string is None:
            ''' prog string not in ram, break on kernel read of the address and then read it '''
            prog_addr = self.task_utils.getExecProgAddr(pid, cpu)
            call_info = SyscallInfo(cpu, pid, None, None, None)
            self.execve_break = SIM_breakpoint(self.cell, Sim_Break_Linear, Sim_Access_Read, prog_addr, 1, 0)
            self.execve_hap = SIM_hap_add_callback_index("Core_Breakpoint_Memop", self.finishParseExecve, call_info, self.execve_break)
            
            #SIM_break_simulation('finishParseExec')
            #call_info = SyscallInfo(cpu, pid, None, None, None)
            #self.lgr.debug('parseExecve, %d(%s) prog string not present in ram, run to user' % (pid, comm))
            #self.mode_hap = SIM_hap_add_callback_obj("Core_Mode_Change", cpu, 0, self.finishParseExecve, call_info)
            return
        nargs = min(4, len(arg_string_list))
        arg_string = ''
        for i in range(nargs):
            if is_ascii(arg_string_list[i]):
                arg_string += arg_string_list[i]+' '
            else:
                break
        ida_msg = 'Syscall: execve prog: %s %s  pid: %d' % (prog_string, arg_string, pid)
        if self.trace_fh is not None:
            self.trace_fh.write(ida_msg+'\n')
            self.traceProcs.setName(pid, prog_string, arg_string)
        else:
            self.context_manager.setIdaMessage(ida_msg)
        return prog_string

    def syscallParse(self, frame, cpu, pid):
        callnum = frame['eax']
        callname = self.task_utils.syscallName(callnum) 
        exit_info = ExitInfo(cpu, pid, callnum)
        if callname == 'open':        
            exit_info.fname_addr, exit_info.flags, exit_info.mode = self.parseOpen(frame)
        elif callname == 'execve':        
            retval = self.parseExecve(frame)
        elif callname == 'close':        
            fd = frame['ebx']
            self.traceProcs.close(pid, fd)
            exit_info.old_fd = fd
        elif callname == 'dup':        
            exit_info.old_fd = frame['ebx']
        elif callname == 'dup2':        
            exit_info.old_fd = frame['ebx']
            exit_info.new_fd = frame['ecx']
            
            #self.traceProcs.close(pid, fd)
        elif callname == 'pipe' or callname == 'pipe2':        
            exit_info.fname_addr = frame['ebx']
            
        elif callname == 'socketcall':        
            socket_callnum = frame['ebx']
            exit_info.socket_callnum = socket_callnum
            socket_callname = net.callname[socket_callnum]
            exit_info.socket_params = frame['ecx']
            ida_msg = 'Syscall: %s - %s %s   pid:%d' % (callname, socket_callname, taskUtils.stringFromFrame(frame), pid)
            if self.trace_fh is not None:
                self.trace_fh.write(ida_msg+'\n')
                
        else:
            ida_msg = 'Syscall: %s %s   pid:%d' % (callname, taskUtils.stringFromFrame(frame), pid)
            if self.trace_fh is not None:
                self.trace_fh.write(ida_msg+'\n')
            else:
                self.context_manager.setIdaMessage(ida_msg)
            if callname == 'pselect6':
                self.trace_fh.flush()
                SIM_break_simulation('pselect6')
        return exit_info


    def stopHap(self, stop_action, one, exception, error_string):
        if self.stop_hap is not None:
            self.lgr.debug('syscall stopHap cycle: 0x%x' % stop_action.hap_clean.cpu.cycles)
            for hc in stop_action.hap_clean.hlist:
                if hc.hap is not None:
                    self.lgr.debug('will delete hap %s' % str(hc.hap))
                    self.context_manager.genDeleteHap(hc.htype, hc.hap)
                    hc.hap = None
            self.lgr.debug('will delete hap %s' % str(self.stop_hap))
            SIM_hap_delete_callback_id("Core_Simulation_Stopped", self.stop_hap)
            self.stop_hap = None
            for bp in stop_action.breakpoints:
                self.context_manager.genDeleteBreakpoint(bp)
            ''' check functions in list '''
            if len(stop_action.flist) > 0:
                fun = stop_action.flist.pop(0)
                fun(stop_action.flist) 

    def exitHap(self, exit_info, third, forth, memory):
        ''' assumes we are tracing, record results of call and add
            the clone if that is the call.  TBD race, clone could
            be scheduled before parent returns?
        '''
        cpu, comm, pid = self.task_utils.curProc() 
        if pid in self.exit_break:
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
                if callname != 'vfork':
                    self.lgr.debug('exitHap expected pid %d, got %d.  Not fork, Do nothing. ' % (exit_info.pid, pid))
                    return
                ''' is fork, TBD assume child returns first?   do not delete Hap ''' 
                self.trace_fh.write('\texit code: 0x%x  pid: %d\n' % (eax, pid))
                #self.lgr.debug('exitHap call addProc for pid: %d parent %d' % (eax, pid))
                self.traceProcs.addProc(eax, pid)
                self.traceProcs.copyOpen(pid, eax)
            else:
                if exit_info.callnum == self.task_utils.syscallNumber('clone'):
                    self.trace_fh.write('\texit from clone, new pid: %d  calling pid: %d\n' % (eax, pid))
                    self.lgr.debug('exitHap call addProc for pid: %d parent %d' % (eax, pid))
                    self.traceProcs.addProc(eax, pid, clone=True)
                    self.traceProcs.copyOpen(pid, eax)
                elif exit_info.callnum == self.task_utils.syscallNumber('open'):
                    fname = self.mem_utils.readString(exit_info.cpu, exit_info.fname_addr, 256)
                    if eax >= 0:
                        self.traceProcs.open(pid, fname, eax)
                        self.trace_fh.write('\texit from open pid: %d fd: %d file: %s flags: 0x%x mode: 0x%x\n' % (pid, eax, fname, exit_info.flags, exit_info.mode))
                elif exit_info.callnum == self.task_utils.syscallNumber('pipe') or \
                     exit_info.callnum == self.task_utils.syscallNumber('pipe2'):
                    if eax == 0:
                        fd1 = self.mem_utils.readWord32(cpu, exit_info.fname_addr)
                        fd2 = self.mem_utils.readWord32(cpu, exit_info.fname_addr+4)
                        self.lgr.debug('exit from pipe pid:%d fd1 %d fd2 %d from 0x%x' % (pid, fd1, fd2, exit_info.fname_addr))
                        self.trace_fh.write('\texit from pipe pid:%d fd1 %d fd2 %d from 0x%x' % (pid, fd1, fd2, exit_info.fname_addr))
                        self.traceProcs.pipe(pid, fd1, fd2)

                elif exit_info.callnum == self.task_utils.syscallNumber('socketcall'):
                    params = exit_info.socket_params
                    if exit_info.socket_callnum == net.SOCKET and eax >= 0:
                        self.traceProcs.socket(pid, eax)
                        domain = self.mem_utils.readWord32(cpu, params)
                        sock_type_full = self.mem_utils.readWord32(cpu, params+4)
                        sock_type = sock_type_full & net.SOCK_TYPE_MASK
                        self.trace_fh.write('\texit from socketcall SOCKET pid:%d, FD: %d domain: %d  type: %d\n' % (pid, eax, domain, sock_type))
                        if domain == 2:
                            #SIM_break_simulation('domain 2, params is 0x%x' % params)
                            pass
                    elif exit_info.socket_callnum == net.CONNECT:
                        #SIM_break_simulation('socket CONNECT params at 0x%x' % params)
                        fd = self.mem_utils.readWord32(cpu, params)
                        addr = self.mem_utils.readWord32(cpu, params+4)
                        sa_family = self.mem_utils.readWord16(cpu, addr) 
                        if sa_family == 1:
                            sa_data = self.mem_utils.readString(cpu, addr+2, 256)
                            self.trace_fh.write('\texit from socketcall CONNECT pid:%d, fd: %d sa_family: %d  sa_data: %s\n' % (pid, fd, sa_family, sa_data))
                            self.traceProcs.connect(pid, fd, sa_data)
                        elif sa_family == 2:
                            port = self.mem_utils.readWord16(cpu, addr+2)
                            sin_addr = self.mem_utils.readWord32(cpu, addr+4)
                            self.trace_fh.write('\texit from socketcall CONNECT pid:%d, fd: %d sa_family: %d  port: %d addr: %s\n' % (pid, 
                               fd, sa_family, port, ip2String(sin_addr)))
                            self.traceProcs.connect(pid, fd, ip2String(sin_addr))
                    elif exit_info.socket_callnum == net.BIND:
                        #SIM_break_simulation('socket CONNECT params at 0x%x' % params)
                        fd = self.mem_utils.readWord32(cpu, params)
                        addr = self.mem_utils.readWord32(cpu, params+4)
                        sa_family = self.mem_utils.readWord16(cpu, addr) 
                        if sa_family == 1:
                            sa_data = self.mem_utils.readString(cpu, addr+2, 14)
                            self.trace_fh.write('\texit from socketcall BIND pid:%d, fd: %d sa_family: %d  sa_data: %s\n' % (pid, fd, sa_family, sa_data))
                            self.traceProcs.bind(pid, fd, sa_data)
                            #if len(sa_data.strip()) == 0:
                                #SIM_break_simulation('sa_data empty from addr 0x%x' % addr)
                        elif sa_family == 2:
                            port = self.mem_utils.readWord16(cpu, addr+2)
                            sin_addr = self.mem_utils.readWord32(cpu, addr+4)
                            self.trace_fh.write('\texit from socketcall BIND pid:%d, fd: %d sa_family: %d  port: %d addr: %s\n' % (pid, 
                               fd, sa_family, port, ip2String(sin_addr)))
                            self.traceProcs.bind(pid, fd, ip2String(sin_addr))
                    elif exit_info.socket_callnum == net.ACCEPT:
                        #SIM_break_simulation('socket CONNECT params at 0x%x' % params)
                        new_fd = eax
                        if new_fd < 0:
                            return 
                        sock_fd = self.mem_utils.readWord32(cpu, params)
                        addr = self.mem_utils.readWord32(cpu, params+4)
                        sa_family = self.mem_utils.readWord16(cpu, addr) 
                        if sa_family == 1:
                            sa_data = self.mem_utils.readString(cpu, addr+2, 14)
                            self.trace_fh.write('\texit from socketcall ACCEPT pid:%d, sock_fd: %d new_fd: %d sa_family: %d  sa_data: %s\n' % (pid, sock_fd, 
                                   new_fd, sa_family, sa_data))
                            self.traceProcs.accept(pid, sock_fd, new_fd, None)
                        elif sa_family == 2:
                            port = self.mem_utils.readWord16(cpu, addr+2)
                            sin_addr = self.mem_utils.readWord32(cpu, addr+4)
                            self.trace_fh.write('\texit from socketcall ACCEPT pid:%d, sock_fd: %d  new_fd: %d sa_family: %d  port: %d addr: %s\n' % (pid, sock_fd,
                               new_fd, sa_family, port, ip2String(sin_addr)))
                            self.traceProcs.accept(pid, sock_fd, new_fd, ip2String(sin_addr))
                    else:
                        socket_callname = net.callname[exit_info.socket_callnum]
                        self.trace_fh.write('\texit from socketcall %s pid:%d eax: 0x%x\n' % (socket_callname, pid, eax)) 

                elif exit_info.callnum == self.task_utils.syscallNumber('close'):
                    if eax == 0:
                        self.traceProcs.close(pid, eax)
                        self.trace_fh.write('\texit from close pid:%d, FD: %d\n' % (pid, exit_info.old_fd))
                    
                elif exit_info.callnum == self.task_utils.syscallNumber('dup'):
                    self.lgr.debug('exit pid %d from dup eax %x, old_fd is %d' % (pid, eax, exit_info.old_fd))
                    if eax >= 0:
                        self.traceProcs.dup(pid, exit_info.old_fd, eax)
                        self.trace_fh.write('\texit from dup pid %d, old_fd: %d new: %d\n' % (pid, exit_info.old_fd, eax))
                elif exit_info.callnum == self.task_utils.syscallNumber('dup2'):
                    self.lgr.debug('exit from dup2 pid %d eax %x, old_fd is %d new_fd %d' % (pid, eax, exit_info.old_fd, exit_info.new_fd))
                    if eax >= 0:
                        if exit_info.old_fd != exit_info.new_fd:
                            self.traceProcs.dup(pid, exit_info.old_fd, exit_info.new_fd)
                            self.trace_fh.write('\texit from dup2 pid:%d, old_fd: %d new: %d\n' % (pid, exit_info.old_fd, eax))
                        else:
                            self.trace_fh.write('\texit from dup2 pid:%d, old_fd: and new both %d   Eh?\n' % (pid, eax))
                else:
                    callname = self.task_utils.syscallName(exit_info.callnum)
                    self.trace_fh.write('\texit from call %s code: 0x%x  pid: %d\n' % (callname, eax, pid))
                self.context_manager.genDeleteBreakpoint(self.exit_break[pid])
                self.context_manager.genDeleteHap(self.exit_hap[pid])
                del self.exit_break[pid]
                del self.exit_hap[pid]
                ''' if debugging a proc, and clone call, add the new process '''
                if self.pid is not None and exit_info.callnum == self.task_utils.syscallNumber('clone'):
                    self.lgr.debug('adding clone %d to watched pids' % eax)
                    self.context_manager.addTask(eax)
            self.trace_fh.flush()
        
    def syscallHap(self, syscall_info, third, forth, memory):
        ''' NOTE assumes breaks are only in place while procs of interest are scheduled '''
        ''' NOTE Does not track Tar syscalls! '''
        cpu = SIM_current_processor()
        if syscall_info.cpu is not None and cpu != syscall_info.cpu:
            self.lgr.debug('syscallHap, wrong cpu %s %s' % (cpu.name, syscall_info.cpu.name))
            return
        cpu, comm, pid = self.task_utils.curProc() 
        if syscall_info.pid is not None and syscall_info.pid != pid: 
            self.lgr.debug('syscallHap looked for pid %d, found %d.  Do nothing' % (syscall_info.pid, pid))
            return
        break_eip = self.top.getEIP()
        stack_frame = None
        if break_eip == self.param.sysenter:
            ''' caller frame will be on stack '''
            stack_frame = self.frameFromStackSyscall()
        elif break_eip == self.param.sys_entry:
            stack_frame = self.task_utils.frameFromRegs(syscall_info.cpu)
            ''' fix up regs based on eip and esp found on stack '''
            reg_num = self.cpu.iface.int_register.get_number(self.mem_utils.getESP())
            esp = self.cpu.iface.int_register.read(reg_num)
            stack_frame['eip'] = self.mem_utils.readPtr(cpu, esp)
            stack_frame['esp'] = self.mem_utils.readPtr(cpu, esp+12)
        elif break_eip == syscall_info.calculated:
            stack_frame = self.task_utils.frameFromStackSyscall()
        else:
            self.lgr.error('syscallHap unexpected break_ip 0x%x' % break_eip)
            return

        eax = stack_frame['eax']
        if eax == 0:
            return
        #self.lgr.debug('syscallHap in proc %d (%s), eax: 0x%x  EIP: 0x%x' % (pid, comm, eax, break_eip))
        frame_string = taskUtils.stringFromFrame(stack_frame)
        #self.lgr.debug('syscallHap frame: %s' % frame_string)
        if syscall_info.callnum is not None:
            if eax == syscall_info.callnum:
                exit_info = self.syscallParse(stack_frame, cpu, pid)
                #self.lgr.debug('syscall 0x%d from %d (%s) at 0x%x cycles: 0x%x' % (eax, pid, comm, break_eip, cpu.cycles))
                if self.trace_fh is None:
                    SIM_break_simulation('syscall frame was %s' % frame_string)
                elif eax != self.task_utils.syscallNumber('execve') and comm != 'tar':
                    #self.lgr.debug('set return ip break at 0x%x' % stack_frame['eip'])
                    #self.exit_break = self.context_manager.genBreakpoint(self.cell, Sim_Break_Linear, Sim_Access_Execute, stack_frame['eip'], 1, 0)
                    phys = self.mem_utils.v2p(cpu, stack_frame['eip'])
                    self.exit_break[pid] = self.context_manager.genBreakpoint(self.cpu.physical_memory, Sim_Break_Physical, Sim_Access_Execute, phys, 1, 0)
                    self.exit_hap[pid] = self.context_manager.genHapIndex("Core_Breakpoint_Memop", self.exitHap, exit_info, self.exit_break[pid])
            else:
                self.lgr.debug('syscallHap looked for call %d, got %d, calculated 0x%x do nothing' % (syscall_info.callnum, eax, syscall_info.calculated))
        else:
            exit_info = self.syscallParse(stack_frame, cpu, pid)
            self.lgr.debug('syscall looking for any, got 0x%d from %d (%s) at 0x%x ' % (eax, pid, comm, break_eip))
            if self.trace_fh is None:
                SIM_break_simulation('syscall')
            elif eax != self.task_utils.syscallNumber('execve') and comm != 'tar':
                self.lgr.debug('set return ip break at 0x%x' % stack_frame['eip'])
                #self.exit_break = self.context_manager.genBreakpoint(self.cell, Sim_Break_Linear, Sim_Access_Execute, stack_frame['eip'], 1, 0)
                phys = self.mem_utils.v2p(cpu, stack_frame['eip'])
                self.exit_break[pid] = self.context_manager.genBreakpoint(self.cpu.physical_memory, Sim_Break_Physical, Sim_Access_Execute, phys, 1, 0)
                self.exit_hap[pid] = self.context_manager.genHapIndex("Core_Breakpoint_Memop", self.exitHap, exit_info, self.exit_break[pid])


