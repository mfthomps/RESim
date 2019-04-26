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
import memUtils
import osUtils
'''
Track the current process and provide APIs to get the address of the current task's record
and parameters to exec calls
TBD this module now instantiated per cell, so remove the per-cell structures
'''

class ListHead(object):
    """Represents a struct list_head. But the pointers point to the
    task struct, rather than to another list_head"""

    def __init__(self, next, prev):
        self.next = next
        self.prev = prev

    def __repr__(self):
        return 'ListHead(%r, %r)' % (self.next, self.prev)
    


class TaskStruct(object):
    """The interesting information contained in a task_struct."""
    __slots__ = ['addr',
     'state',
     'tasks',
     'binfmt',
     'pid',
     'tgid',
     'comm',
     'real_parent',
     'parent',
     'children',
     'sibling',
     'group_leader',
     'thread_group',
     'active_mm',
     'mm',
     'good',
     'in_main_list',
     'in_sibling_list']

    def __init__(self, **kw):
        self.in_main_list = False
        self.in_sibling_list = None
        for k, v in kw.items():
            setattr(self, k, v)

    def __str__(self):
        return 'TaskStruct(%s)' % (', '.join(('%s = %s' % (slot, getattr(self, slot, None)) for slot in self.__slots__)),)

    def __repr__(self):
        return self.__str__()

    @property
    def next(self):
        return self.tasks.next

    @property
    def prev(self):
        return self.tasks.prev

    
class linuxProcessUtils():
    # Note COMM_SIZE is not long enough for all CGC bin names, linuxProcUtils will keep a map
    COMM_SIZE = 16
    EXEC_SYS_CALL = 11
    LIST_POISON2 = object()
    os_type = 'linux'
    #replay_user_sig no longer used, remove it
    REPLAY_USER_SIG = 12
    SIGUSR1 = 10
    SIGKILL = 9
    SIGFPE = 8
    SIGSEGV = 11
    SIGALRM = 14
    SIGINT = 2
    SIGHUP = 1
    SIGQUIT = 3
    SIGILL = 4
    SIGTRAP = 5
    SIGBUS = 7
    READ_SYSCALL = 3
    WRITE_SYSCALL = 4
    BRK = 45
    MMAP = 192
    MUNMAP = 91
    SOCKET = 102
    
    def __init__(self, top, cell_name, param, cell_config, master_config, hap_manager, current_task_addr, mem_utils, lgr, always_watch_calls=False):
        self.param = param
        self.top = top
        self.cell_name = cell_name
        self.cell_config = cell_config
        self.master_config = master_config
        self.hap_manager = hap_manager
        self.always_watch_calls = always_watch_calls
        self.lgr = lgr
        self.watch_kernel = None
        self.pinfo = {}
        self.current_task_virt = {}
        self.current_task_addr = current_task_addr
        # comm string not long enough for full proc name
        self.comm_map = {}
        self.mem_utils = mem_utils
        # for obtaining parameters to the exec call
        self.prog_read_break = {}
        self.prog_read_hap = {}
        self.exec_addrs = {}
        self.lgr.debug("do linuxProcessUtils for %s" % cell_name)
        print("do linuxProcessUtils for %s" % cell_name)
        cmd = '%s.get-processor-list' % self.cell_name
        proclist = SIM_run_command(cmd)
        self.cpu = []
        self.watching_current = {}
        self.current_task = {}
        for proc in proclist:
            cpu = SIM_get_object(proc)
            self.cpu.append(cpu)
            self.watching_current[cpu] = False
            cur_thread_addr = self.getPhysAddrOfCurrentThread(cpu)
            if cur_thread_addr is not None:
                self.current_task[cpu] = cur_thread_addr
                print('bsdProcessUtils current task for cpu %s is %x' % (proc, self.current_task[cpu]))
            self.pinfo[cpu] = self.pInfo(cpu, None, None, None)
            self.setCurrentTask(cpu)
        if hap_manager is not None:
            self.setBreaks()

    def setCurrentTask(self, cpu):
        ''' intended to set value if this module instantiated before kernel init '''
        while SIM_processor_privilege_level(cpu) != 0:
            self.lgr.debug('not in pl0, fiddle some')
	    SIM_continue(900000000)
        if self.mem_utils.WORD_SIZE == 4:
            self.current_task_virt[cpu] = self.current_task_addr
            #self.current_task = memUtils.v2p(self.cpu, self.current_task_addr)
            #print('first current_task virt is 0x%x is phys 0x%x' % (self.current_task_addr, self.current_task))
            phys_addr = self.mem_utils.v2p(cpu, self.current_task_addr)
            self.current_task[cpu] = phys_addr
            print('second current_task is 0x%x' % self.current_task)
        elif self.mem_utils.WORD_SIZE == 8:
            gs_b700 = self.getGSCurrent_task_offset(cpu)
            phys_addr = self.mem_utils.v2p(cpu, gs_b700)
            self.current_task[cpu] = phys_addr
            self.current_task_virt[cpu] = gs_b700
            self.lgr.debug('linuxProcessUtils, %s is 64 bit, gs_b700 is 0x%x phys is 0x%x' % (self.cell_name, gs_b700, phys_addr))
            print('linuxProcessUtils, %s is 64 bit, gs_b700 is 0x%x phys is 0x%x' % (self.cell_name, gs_b700, phys_addr))
        else:
            print('unknown word size %d' % self.mem_utils.WORD_SIZE)
            return
        print('linuxProcessUtils %s current task is %x' % (self.cell_name, self.current_task[cpu]))
        self.lgr.debug('linuxProcessUtils %s current task is %x' % (self.cell_name, self.current_task[cpu]))

    '''
        Map the program name the pid (process comm string is too short for full program names)
    '''
    def setCommMap(self, pid, comm, cpu):
        self.lgr.debug('linuxProcessUtils setCommMap of %d to %s' % (pid, comm))
        self.comm_map[pid] = comm
        # should always be this pid, redundant check
        if self.pinfo[cpu].pid == pid:
            self.pinfo[cpu].comm = comm

    def setKernelWatch(self, watch_kernel):
        self.lgr.debug('linuxProcessUtils, setKernelwatch')
        self.watch_kernel = watch_kernel

    def setBreaks(self):
        #if not self.master_config.needSched():
        #    return
        #p_cell = cpu.physical_memory
        #code_break_num = SIM_breakpoint(p_cell, Sim_Break_Physical, 
        #    Sim_Access_Write, self.current_task[cell_name], 4, 0)
        cell = self.cell_config.cell_context[self.cell_name]
        for cpu in self.cpu:#
             virt = self.current_task_virt[cpu]
             if self.mem_utils.WORD_SIZE == 4:
                 # TBD will break on 32 bit
                 virt = self.param.kernel_base + self.current_task[cpu]

             #self.hap_manager.breakLinear(self.cell_name, virt, Sim_Access_Write, self.changedThread, 'changed_thread')
             self.lgr.debug('linuxProcessUtils setBreaks cell: %s current_task is 0x%x   virt is 0x%x' % (self.cell_name, self.current_task[cpu], virt))
             code_break_num = SIM_breakpoint(cell, Sim_Break_Linear, Sim_Access_Write, virt, self.mem_utils.WORD_SIZE, 0)
             cb_num = SIM_hap_add_callback_index("Core_Breakpoint_Memop", 
                    self.changedThread, cpu, code_break_num)
             self.lgr.debug('linuxProcessUtils setBreaks for cell %s' % self.cell_name)
             self.hap_manager.addBreak(self.cell_name, None, code_break_num, None)
             self.hap_manager.addHap(cpu, self.cell_name, None, cb_num, None)

    def cleanAll(self):
        self.lgr.debug('linuxProcessUtils cleanAll for %s' % self.cell_name)
        #self.top.watching_current_syscalls[self.cell_name] = False
        for pid in self.prog_read_break:
            self.lgr.debug('linuxProcessUtils, cleanAll, del breakpint %d  hap %d' % (self.prog_read_break[pid],
                self.prog_read_hap[pid]))
            SIM_delete_breakpoint(self.prog_read_break[pid])
            SIM_hap_delete_callback_id("Core_Breakpoint_Memop", self.prog_read_hap[pid])
        self.prog_read_break = {}
        self.prog_read_hap = {}
        self.exec_addrs = {}
        self.comm_map = {}
        self.lgr.debug('linuxProcessUtils return from cleanAll')

    def reInit(self):
        self.lgr.debug('linuxProcessUtils reInit, set the breakpoints')
        #self.top.watching_current_syscalls[self.cell_name] = False
        self.setBreaks()

    def updateComm(self, pid, cpu):
        comm = None
        if pid in self.comm_map:
            comm = self.comm_map[pid]
            self.lgr.debug('linuxProcessUtils updateComm found %d in comm map return %s' % (pid, comm))
        else:
            cur_addr = self.pinfo[cpu].cur_addr
            self.pinfo[cpu].comm = self.mem_utils.readString(cpu, cur_addr + self.param.ts_comm, self.COMM_SIZE)
            comm =self.pinfo[cpu].comm
            self.lgr.debug('linuxProcessUtils updateComm NOT found %d in comm map return %s' % (pid, comm))
        return comm

    def processExiting(self, cpu):
        dum_cpu, cur_addr, comm, pid = self.getPinfo(cpu)
        if self.watch_kernel is not None and (self.master_config.kernelRop(comm) or self.master_config.kernelPageTable(comm)):
            #SIM_run_alone(self.watch_kernel.undoRop, cpu)
            #SIM_run_alone(self.watch_kernel.undoKernelPage, cpu)
            self.watch_kernel.undoRop(cpu)
            self.watch_kernel.undoKernelPage(cpu)
            self.lgr.debug('linuxProcessUtils processExiting called undoKernelPage & rop')
            #self.undoRop(self.cpu)
            self.watching_current[cpu] = False
        else:
            self.lgr.debug('processExiting, no undo for comm %s' % comm) 
            if self.watch_kernel is None:
                self.lgr.debug('processExiting, is none') 
            else:
                self.lgr.debug('processExiting, is kernelPageTable is %r' % self.master_config.kernelPageTable(comm)) 

        self.lgr.debug('linuxProcessUtils processExiting call clearKernelSysCalls')
        #self.top.watching_current_syscalls[self.cell_name] = self.hap_manager.clearKernelSysCalls(self.cell_name)
        self.hap_manager.clearKernelSysCalls(self.cell_name, pid)

    def cleanPid(self, pid):
        if pid in self.comm_map:
            self.lgr.debug('linuxProcUtils cleaning pid %d (%s)' % (pid, self.comm_map[pid]))
            del self.comm_map[pid]
        if pid in self.prog_read_break:
            SIM_delete_breakpoint(self.prog_read_break[pid])
            SIM_hap_delete_callback_id("Core_Breakpoint_Memop", self.prog_read_hap[pid])
            del self.exec_addrs[pid]
            del self.prog_read_break[pid]

    class pInfo():
        def __init__(self, cpu, cur_addr, comm, pid):
            self.cpu = cpu
            self.cur_addr = cur_addr
            self.comm = comm
            self.pid = pid
        def get(self):
            return self.cpu, self.cur_addr, self.comm, self.pid

    def getPinfo(self, cpu):
        if self.pinfo[cpu] is not None:
            return self.pinfo[cpu].get()
        else:
            return None, None, None, None

    def clearPinfo(self):
        '''
        Intended to be called by the monitor when a monitored process is exiting, so that death noise does not result in
        ongoing haps and recording.
        '''
        for cpu in self.cpu:
            old_cpu, old_cur_addr, old_comm, old_pid = self.pinfo[cpu].get()
            if old_comm is not None and (self.master_config.kernelRop(old_comm) or self.master_config.kernelUnx(old_comm) or self.master_config.kernelPageTable(old_comm)): 
                self.stopWatching(cpu)
            self.pinfo[cpu] = None

    def changedThread(self, cpu, third, forth, memory):
        # get previous task info
        old_comm = None
        old_pid = None
        if self.pinfo[cpu] is not None:
            old_cpu, old_cur_addr, old_comm, old_pid = self.pinfo[cpu].get()
        # get the value that will be written into the current thread address
        cur_addr = SIM_get_mem_op_value_le(memory)
        pid = self.mem_utils.readWord32(cpu, cur_addr + self.param.ts_pid)
        if pid in self.comm_map:
            comm = self.comm_map[pid]
        else:
            comm = self.mem_utils.readString(cpu, cur_addr + self.param.ts_comm, self.COMM_SIZE)
        self.top.switchedPid(cpu, pid, comm)
        cell = self.cell_config.cell_context[self.cell_name]
        #if self.cell_name == 'ids' and comm == 'cfe-proxy':
        #    self.lgr.debug("in change thread, got new current_task value of %x  proc: %s:%d (%s)" % (cur_addr, self.cell_name, pid, comm))
        self.pinfo[cpu] = self.pInfo(cpu, cur_addr, comm, pid)
        #if pid == 0:
        #    return
      
        if not self.always_watch_calls: 
            # either set or clear kernel syscall breaks/haps
            #if self.top.isWatching(cell_name, pid):
            if self.top.watchSysCalls(self.cell_name, pid, comm): 
                if not self.top.watching_current_syscalls(self.cell_name, pid): 
                    self.top.doKernelSysCalls(cpu, self.cell_name, comm)
                    #self.lgr.debug('changedThread did kernelSysCalls for %s %d (%s)' % (self.cell_name, pid, comm))
            elif old_comm is not None and self.master_config.watchCalls(self.cell_name, old_comm):
                if self.top.watching_current_syscalls(cell_name, pid): 
                    #self.top.watching_current_syscalls[self.cell_name] = self.hap_manager.clearKernelSysCalls(self.cell_name)
                    self.hap_manager.clearKernelSysCalls(self.cell_name, pid)
                    #self.lgr.debug('changedThread removed kernelSysCalls for %s %d (%s)' % (self.cell_name, pid, comm))

       
        if (self.master_config.kernelRop(comm) or self.master_config.kernelUnx(comm) or self.master_config.kernelPageTable(comm)) and self.top.isWatching(self.cell_name, pid):
                #self.lgr.debug("changeThread to %s:%d (%s)" % (self.cell_name, pid, comm))
                if not (self.watch_kernel is not None and self.watching_current[cpu]):
                    #cell = obj.cell_context
                    if self.master_config.kernelRop(comm):
                        self.watch_kernel.doRop(cell, cpu, pid, comm)
                    else:
                        self.lgr.debug("changeThread no doing kernel rop %s:%d (%s)" % (self.cell_name, pid, comm))
                    if self.master_config.kernelPageTable(comm):
                        self.watch_kernel.watchKernelPage(cpu, cell, pid, comm)
                        #self.lgr.debug('changedThread did watchKernelPage for %s %d (%s)' % (self.cell_name, pid, comm))
                    if self.master_config.kernelUnx(comm):
                        self.watch_kernel.doUnexpected(cell, cpu)
                    self.watching_current[cpu] = True
        elif old_comm is not None and (self.master_config.kernelRop(old_comm) or self.master_config.kernelUnx(old_comm) or self.master_config.kernelPageTable(comm)): 
                if self.watch_kernel is not None and self.watching_current[cpu]:
                    #self.lgr.debug("thread no longer being watched, now %s:%d (%s)" % (self.cell_name, pid, comm))
                    self.stopWatching(cpu)

    def stopWatching(self, cpu):
        #self.lgr.debug('linux stopWatchin')
        SIM_run_alone(self.watch_kernel.undoRop, cpu)
        SIM_run_alone(self.watch_kernel.undoKernelPage, cpu)
        self.watching_current[cpu] = False


    def getProcList(self):
        for cpu in self.cpu:
            plist = []
            tasks = self.getTaskStructs(cpu)
            for task in tasks:
               comm = tasks[task].comm
               if tasks[task].pid in self.comm_map:
                   comm = self.comm_map[tasks[task].pid]
               pi = self.pInfo(cpu, task, comm, tasks[task].pid)
               plist.append(pi)
           
        return plist
  
    def getCommByPid(self, pid):
        tasks = self.getTaskStructs()
        for task in tasks:
           if tasks[task].pid == pid:
               if pid in self.comm_map:
                   return self.comm_map[pid]
               else:
                   return tasks[task].comm
        return None

    def getTaskAddrByPid(self, pid):
        tasks = self.getTaskStructs()
        for task in tasks:
           if tasks[task].pid == pid:
               return tasks[task].addr
        return None

    ''' get the pid of the real parent of the given pid '''
    def getParent(self, pid, cpu):
        tasks = self.getTaskStructs()
        for task in tasks:
           if tasks[task].pid == pid:
               parent = self.readTaskStruct(tasks[task].real_parent, cpu)
               return parent.pid, parent.comm
        return None
 
    ''' Return a list of PIDs that have the given name ''' 
    def getPidByName(self, name):
        #print 'in getPidByName, look for %s' % name
        pid = []
        tasks = self.getTaskStructs()
        for task in tasks:
           comm = tasks[task].comm
           if tasks[task].pid in self.comm_map:
               comm = self.comm_map[pid]
           if comm == name:
               pid.append(tasks[task].pid)
        return pid

    def hasPid(self, pid):
        plist = self.getProcList(self.param)
        for p in plist:
            #print 'check %d against %d' % (pid, p.pid)
            if p.pid == pid:
                return True
        return False


    def getPhysAddrOfCurrentThread(self, cpu):
        if cpu in self.current_task:
            return self.current_task[cpu]
        else:
            return 0
        

    def readExecParamStrings(self, pid, cpu):
        #self.lgr.debug('readExecParamStrings with pid %d' % pid)
        if pid is None:
            self.lgr.debug('readExecParamStrings called with pid of None')
            return None, None, None
        if pid not in self.exec_addrs:
            self.lgr.debug('readExecParamStrings called with unknown pid %d' % pid)
            return None, None, None
        arg_string_list = []
        prog_string = self.mem_utils.readString(cpu, self.exec_addrs[pid].prog_addr, 512)
        if prog_string is not None:
            #self.lgr.debug('readExecParamStrings got prog_string of %s' % prog_string)
            for arg_addr in self.exec_addrs[pid].arg_addr_list:
                arg_string = self.mem_utils.readString(cpu, arg_addr, 512)
                if arg_string is not None:
                    arg_string_list.append(arg_string.strip())
                    #self.lgr.debug('readExecParamStrings on %s adding arg %s' % (self.cell_name, arg_string))

            prog_string = prog_string.strip()
        return prog_string, arg_string_list


    ''' get the arguments off the stack at SyS_execve
        These were fished out by memory inspection.
        TBD identify struct that corresponds to the arguments
    '''
    def getProcArgsFromStack(self, pid, finishCallback, cpu):
        if pid is None:
            return None, None


        mult = 0
        done = False
        arg_addr_list = []
        limit = 15
        i=0
        prog_addr = None
        if self.mem_utils.WORD_SIZE == 4:
            reg_num = cpu.iface.int_register.get_number(self.mem_utils.getESP())
            esp = cpu.iface.int_register.read(reg_num)
            reg_num = cpu.iface.int_register.get_number(self.mem_utils.getESP())
            esp = cpu.iface.int_register.read(reg_num)

            sptr = esp + 2*self.mem_utils.WORD_SIZE
            argv = self.mem_utils.readPtr(cpu, sptr)
            while not done and i < limit:
                xaddr = argv + mult*self.mem_utils.WORD_SIZE
                arg_addr = self.mem_utils.readPtr(cpu, xaddr)
                if arg_addr is not None and arg_addr != 0:
                   #self.lgr.debug("getProcArgsFromStack adding arg addr %x read from 0x%x" % (arg_addr, xaddr))
                   arg_addr_list.append(arg_addr)
                mult = mult + 1
                i = i + 1
            sptr = esp + self.mem_utils.WORD_SIZE
            prog_addr = self.mem_utils.readPtr(cpu, sptr)
            #self.lgr.debug('getProcArgsFromStack %s pid: %d esp: 0x%x argv 0x%x' % (self.cell_name, pid, esp, argv))
        else:
            reg_num = cpu.iface.int_register.get_number("rsi")
            rsi = cpu.iface.int_register.read(reg_num)
            prog_addr = self.mem_utils.readPtr(cpu, rsi)
            #self.lgr.debug('getProcArgsFromStack 64 bit rsi is 0x%x prog_addr 0x%x' % (rsi, prog_addr))
            i=0
            done = False
            while not done and i < 30:
                rsi = rsi+self.mem_utils.WORD_SIZE
                arg_addr = self.mem_utils.readPtr(cpu, rsi)
                if arg_addr != 0:
                    #self.lgr.debug("getProcArgsFromStack adding arg addr %x read from 0x%x" % (arg_addr, rsi))
                    arg_addr_list.append(arg_addr)
                else:
                    done = True
                i += 1

     

        #xaddr = argv + 4*self.mem_utils.WORD_SIZE
        #arg2_addr = memUtils.readPtr(cpu, xaddr)
        #print 'arg2 esp is %x sptr at %x  argv %x xaddr %x saddr %x string: %s ' % (esp, sptr, 
        #     argv, xaddr, saddr, arg2_string)


        self.exec_addrs[pid] = osUtils.execStrings(cpu, pid, arg_addr_list, prog_addr, finishCallback)
        prog_string, arg_string_list = self.readExecParamStrings(pid, cpu)
        #self.lgr.debug('getProcArgsFromStack prog_string is %s' % prog_string)
        #if prog_string == 'cfe-poll-player':
        #    SIM_break_simulation('debug')
        #self.lgr.debug('args are %s' % str(arg_string_list))
        if prog_string is None:
            # program string in unmapped memory; break on it's being read (won't occur until os maps the page)
            cell = self.cell_config.cell_context[self.cell_name]

            self.prog_read_break[pid] = SIM_breakpoint(cell, Sim_Break_Linear, 
                Sim_Access_Read, prog_addr, 1, 0)
            #self.lgr.debug('getProcArgsFromStack set hap on read of param addr %d ' % (pid)) 
            self.prog_read_hap[pid] = SIM_hap_add_callback_index("Core_Breakpoint_Memop", 
               self.readExecProg, self.exec_addrs[pid], self.prog_read_break[pid])
            #SIM_run_alone(SIM_run_command, 'list-breakpoints')

        return prog_string, arg_string_list

    '''
        Hap that reads a program name that had been missing from mapped memory.
        Note obscure hack to call finishExecParams in syscallHap.
    '''
    def readExecProg(self, exec_addrs, third, forth, memory):
        cpu, cur_addr, comm, pid = self.getPinfo(exec_addrs.cpu)
        self.lgr.debug('readExecProg xx for %d (%s), call finishExecParams' % (pid, comm))
        # TBD note extra check for pid in prog_read_break, deleting haps is flakey?
        if exec_addrs.exec_addrs.pid == pid and pid is not None and pid in self.prog_read_break:
            self.lgr.debug('readExecProg for %d (%s), call finishExecParams' % (pid, comm))
            prog_string, arg_string_list = self.readExecParamStrings(exec_addrs.pid, cpu)
            exec_addrs.exec_addrs.callback(exec_addrs.cpu, exec_addrs.pid, prog_string, arg_string_list, cur_addr)
            #self.lgr.debug('readExecProg found prog string of %s' % prog_string)
            SIM_delete_breakpoint(self.prog_read_break[pid])
            SIM_hap_delete_callback_id("Core_Breakpoint_Memop", self.prog_read_hap[pid])
            del self.exec_addrs[pid]
            del self.prog_read_break[pid]
            del self.prog_read_hap[pid]

    '''
        Get address of the current task record
    '''
    def getCurrentProcAddr(self, cpu):
        if self.mem_utils.WORD_SIZE == 4:
            cpl = memUtils.getCPL(cpu)
            #if cpl == simics.Sim_CPU_Mode_User:
            if cpl != 0:
                tr_base = cpu.tr[7]
                esp = self.mem_utils.readPtr(cpu, tr_base + 4)
            else:
                reg_num = cpu.iface.int_register.get_number(self.mem_utils.getESP())
                esp = cpu.iface.int_register.read(reg_num)
            ptr = esp - 1 & ~(self.param.stack_size - 1)
            ret_ptr = self.mem_utils.readPtr(cpu, ptr)
        else:
            ret_ptr = self.getGSCurrent_task_offset()
        return ret_ptr
    
    def readTaskStruct(self, addr, cpu):
        """Read the task_struct at addr and return a TaskStruct object
        with the information."""
        task = TaskStruct(addr=addr)
        if self.param.ts_next != None:
            if self.param.ts_next_relative:
                assert self.param.ts_prev == self.param.ts_next + self.mem_utils.WORD_SIZE
                task.tasks = self.read_list_head(cpu, addr, self.param.ts_next)
            else:
                task.tasks = ListHead(self.mem_utils.readPtr(cpu, addr + self.param.ts_next), self.mem_utils.readPtr( cpu, addr + self.param.ts_prev))
        if self.param.ts_state != None:
            task.state = self.mem_utils.readWord32(cpu, addr + self.param.ts_state)
        if self.param.ts_active_mm != None:
            task.active_mm = self.mem_utils.readPtr(cpu, addr + self.param.ts_active_mm)
        if self.param.ts_mm != None:
            task.mm = self.mem_utils.readPtr(cpu, addr + self.param.ts_mm)
        if self.param.ts_binfmt != None:
            task.binfmt = self.mem_utils.readPtr(cpu, addr + self.param.ts_binfmt)
        if self.param.ts_pid != None:
            task.pid = self.mem_utils.readWord32(cpu, addr + self.param.ts_pid)
        if self.param.ts_tgid != None:
            task.tgid = self.mem_utils.readWord32(cpu, addr + self.param.ts_tgid)
        if self.param.ts_comm != None:
            task.comm = self.mem_utils.readString(cpu, addr + self.param.ts_comm, self.COMM_SIZE)
        for field in ['ts_real_parent',
         'ts_parent']:
         #'ts_p_opptr',
         #'ts_p_pptr',
         #'ts_p_cptr',
         #'ts_p_ysptr',
         #'ts_p_osptr']:
            offs = getattr(self.param, field)
            if offs != None:
                p = self.mem_utils.readPtr(cpu, addr + offs)
                if field in ('ts_real_parent', 'ts_p_opptr'):
                    task.real_parent = p
                elif field in ('ts_parent', 'ts_p_pptr'):
                    task.parent = p
                elif field == 'ts_p_cptr':
                    task.children = [p]
                elif field in ('ts_p_ysptr', 'ts_p_osptr'):
                    a = getattr(task, 'sibling', [])
                    a.append(p)
                    task.sibling = a
                else:
                    setattr(task, field, p)
    
        if self.param.ts_group_leader != None:
            task.group_leader = self.mem_utils.readPtr(cpu, addr + self.param.ts_group_leader)
        if self.param.ts_children_list_head != None and self.param.ts_sibling_list_head != None and self.param.ts_real_parent != None:
            c = self.read_list_head(cpu, addr, self.param.ts_children_list_head, other_offset=self.param.ts_sibling_list_head)
            task.children = [c.next, c.prev]
            if task.in_sibling_list:
                s = self.read_list_head(cpu, addr, self.param.ts_sibling_list_head, head_addr=task.in_sibling_list, head_offset=self.param.ts_children_list_head)
                task.sibling = [s.next, s.prev]
            else:
                task.sibling = []
        if self.param.ts_thread_group_list_head not in (None, -1):
            task.thread_group = self.read_list_head(cpu, addr, self.param.ts_thread_group_list_head)
        return task
    
    def is_kernel_virtual(self, addr):
        return addr >= self.param.kernel_base

    def read_list_head(self, cpu, addr, offset, head_addr = None, head_offset = None, other_offset = None):
        next = self.mem_utils.readPtr(cpu, addr + offset)
        prev = self.mem_utils.readPtr(cpu, addr + offset + self.mem_utils.WORD_SIZE)
    
        def transform(p):
            if p == 0:
                return
            if p == 2097664:
                return LIST_POISON2
            if not self.is_kernel_virtual(p): 
                #print '%#x is not a kernel address' % p
                #traceback.print_stack()
                #SIM_break_simulation("debug")
                pass
            if head_addr != None and p - head_offset == head_addr:
                return head_addr
            if p - offset == addr:
                return addr
            if other_offset != None:
                return p - other_offset
            return p - offset
    
        return ListHead(transform(next), transform(prev))
    
    '''
       Is the process named by cur_addr a decendent of any of thethe given parent 
       list, (direct or one-level grand)?
       TBD: limited to single-cpu/core models.  Extend by doing for all cpus.
    '''
    def spawnedBy(self, parent_pid, cur_addr, child_pid):
    
        self.lgr.debug('spawned by looking if %d is a child of %s, cur_addr is 0x%x' % (child_pid, str(parent_pid), cur_addr))
        if child_pid in parent_pid:
            return False
        retval = False
        i=0
        too_much = 1000
        cur_pid = child_pid
        for cpu in self.cpu:
            while not retval and cur_addr is not None and cur_addr is not 0 and cur_pid is not 0:
                cur_addr = self.mem_utils.readPtr(self.cpu, cur_addr+self.param.ts_parent)
                #cur_addr = self.mem_utils.readPtr(self.cpu, cur_addr+self.param.ts_real_parent)
                if cur_addr is not None and cur_addr is not 0:
                    cur_pid = self.mem_utils.readWord32(self.cpu, cur_addr+self.param.ts_pid)
                    self.lgr.debug('cur_pid is %d parent:%s 0x%x' % (cur_pid, str(parent_pid), cur_addr))
                    if cur_pid in parent_pid:
                        retval = True
                i += 1
                if i > too_much:
                    self.lgr.error('linuxProcessUtils, spawnedBy, fatal loop with cur_addr 0x%x' % cur_addr)
                    return False
            if retval or cur_addr is None or curAddr == 0 or cur_pid == 0:
                break 
        return retval
    
        
    '''
    With linux, this seems valid whether in user or kernel space
    '''
    def currentProcessInfo(self, cpu=None):
        if cpu is None:
            cpu = SIM_current_processor()
        #cur_addr = self.getCurrentProcAddr()
        cur_addr = SIM_read_phys_memory(cpu, self.current_task[cpu], self.mem_utils.WORD_SIZE)
        comm = self.mem_utils.readString(cpu, cur_addr + self.param.ts_comm, self.COMM_SIZE)
        pid = self.mem_utils.readWord32(cpu, cur_addr + self.param.ts_pid)
        return cpu, cur_addr, comm, pid
    
    def getParentPid(self, cur_addr, cpu):
        ts_real_parent = self.mem_utils.readPtr(cpu, cur_addr + self.param.ts_parent)
        parent_pid = self.mem_utils.readWord32(cpu, ts_real_parent + self.param.ts_pid)
        return ts_real_parent, parent_pid
    
    '''
        Is the given pid a child of one of the given servers (server_pid is a list) 
    '''
    def isDecended(self, server_pid, cur_addr, comm, pid):
        decended = True
        ''' Only interested in decendants of server '''
        #if comm == serverName:
        #   decended = False
        if not self.spawnedBy(server_pid, cur_addr, pid):
           decended = False
        return decended
    
    
    def frameFromStack(self, cpu):
        reg_num = cpu.iface.int_register.get_number(self.mem_utils.getESP())
        esp = cpu.iface.int_register.read(reg_num)
        frame = self.getFrame(esp, cpu)
        #print 'frame: %s' % stringFromFrame(frame)
        #traceback.print_stack()
        #SIM_break_simulation("debug")
        return frame
    
    '''
    CURRENTLY:  reading stack from off r0 stack at resume_userspace.
    Commented logic below is to get frame from task structure -- NOT WORKING YET
    from processor.h
    #define THREAD_SIZE_ORDER       1
    #define THREAD_SIZE             (PAGE_SIZE << THREAD_SIZE_ORDER)
    
    #define THREAD_SIZE_LONGS      (THREAD_SIZE/sizeof(unsigned long))
    #define KSTK_TOP(info)                                                 \
    ({                                                                     \
           unsigned long *__ptr = (unsigned long *)(info);                 \
           (unsigned long)(&__ptr[THREAD_SIZE_LONGS]);                     \
    })
    
    
    #define task_pt_regs(task)                                             \
    ({                                                                     \
           struct pt_regs *__regs__;                                       \
           __regs__ = (struct pt_regs *)(KSTK_TOP(task_stack_page(task))-8); \
           __regs__ - 1;                                                   \
    })
    
    from sched.h
    #define task_stack_page(task)   ((task)->stack)
    
    
    '''
    def frameFromThread(self, cpu):
        current = self.getCurrentProcAddr(cpu)
        '''
        OR, the other ifdef block in processor.h (for 64bit cpu??)
        thread = current + 0x24c
        sp0_addr = thread + 0x18
        sp0 = memUtils.readWord(cpu, sp0_addr)
        reg_ptr = sp0-1
        frame = getFrame(cpu, reg_ptr)
        print 'sp0 %x frame: %s' % (sp0, stringFromFrame(frame))
        '''
        # TBD put this in memUtils and share everywhere
        #PAGE_SIZE = 4096
        #THREAD_SIZE = PAGE_SIZE << 1
        #THREAD_SIZE_LONGS = THREAD_SIZE/WORD_SIZE
        #print 'THREAD_SIZE = %x   THREAD_SIZE_LONGS = %x' % (THREAD_SIZE, THREAD_SIZE_LONGS) 
    
        # task_stack_page is just task->stack stack value is second word
        task_stack_page = self.mem_utils.readPtr(cpu, current+self.mem_utils.WORD_SIZE)
    
        # no bloody idea how this offset is computed.      
        mft_ptr = task_stack_page + 0x1fb4
        #ptr = task_stack_page + (WORD_SIZE * THREAD_SIZE_LONGS)
        # MFT TBD this can't be right
        frame = self.getFrame(mft_ptr, cpu)
        #print 'task_stack_page %x mft_ptr: %x frame: %s' % (task_stack_page, mft_ptr, stringFromFrame(frame))
        #SIM_break_simulation("debug frame from thread")
        return frame
    
    def frameFromStackSyscall(self, cpu):
        reg_num = cpu.iface.int_register.get_number(self.mem_utils.getESP())
        esp = cpu.iface.int_register.read(reg_num)
        regs_addr = esp + self.mem_utils.WORD_SIZE
        regs = self.mem_utils.readPtr(cpu, regs_addr)
        print 'regs_addr is %x  regs is %x' % (regs_addr, regs)
        frame = self.getFrame(regs, cpu)
        return frame
    
         
    '''
        Given the address of a linux stack frame, return a populated dictionary of its values.
    '''
    def getFrame(self, v_addr, cpu):
            phys_addr = self.mem_utils.v2p(cpu, v_addr)
            retval = {}
            retval['ebx'] = SIM_read_phys_memory(cpu, phys_addr, self.mem_utils.WORD_SIZE)
            retval['ecx'] = SIM_read_phys_memory(cpu, phys_addr+self.mem_utils.WORD_SIZE, self.mem_utils.WORD_SIZE)
            retval['edx'] = SIM_read_phys_memory(cpu, phys_addr+2*self.mem_utils.WORD_SIZE, self.mem_utils.WORD_SIZE)
            retval['esi'] = SIM_read_phys_memory(cpu, phys_addr+3*self.mem_utils.WORD_SIZE, self.mem_utils.WORD_SIZE)
            retval['edi'] = SIM_read_phys_memory(cpu, phys_addr+4*self.mem_utils.WORD_SIZE, self.mem_utils.WORD_SIZE)
            retval['ebp'] = SIM_read_phys_memory(cpu, phys_addr+5*self.mem_utils.WORD_SIZE, self.mem_utils.WORD_SIZE)
            retval['eax'] = SIM_read_phys_memory(cpu, phys_addr+6*self.mem_utils.WORD_SIZE, self.mem_utils.WORD_SIZE)
            retval['eds'] = SIM_read_phys_memory(cpu, phys_addr+7*self.mem_utils.WORD_SIZE, self.mem_utils.WORD_SIZE)
            retval['es'] = SIM_read_phys_memory(cpu, phys_addr+8*self.mem_utils.WORD_SIZE, self.mem_utils.WORD_SIZE)
            retval['fs'] = SIM_read_phys_memory(cpu, phys_addr+9*self.mem_utils.WORD_SIZE, self.mem_utils.WORD_SIZE)
            retval['gs'] = SIM_read_phys_memory(cpu, phys_addr+10*self.mem_utils.WORD_SIZE, self.mem_utils.WORD_SIZE)
            retval['orig_ax'] = SIM_read_phys_memory(cpu, phys_addr+11*self.mem_utils.WORD_SIZE, self.mem_utils.WORD_SIZE)
            retval['eip'] = SIM_read_phys_memory(cpu, phys_addr+12*self.mem_utils.WORD_SIZE, self.mem_utils.WORD_SIZE)
            retval['cs'] = SIM_read_phys_memory(cpu, phys_addr+13*self.mem_utils.WORD_SIZE, self.mem_utils.WORD_SIZE)
            retval['flags'] = SIM_read_phys_memory(cpu, phys_addr+14*self.mem_utils.WORD_SIZE, self.mem_utils.WORD_SIZE)
            retval['esp'] = SIM_read_phys_memory(cpu, phys_addr+15*self.mem_utils.WORD_SIZE, self.mem_utils.WORD_SIZE)
            retval['ss'] = SIM_read_phys_memory(cpu, phys_addr+16*self.mem_utils.WORD_SIZE, self.mem_utils.WORD_SIZE)
            return retval
    
    def frameFromRegs(self, cpu):
            regs = {"eax", "ebx", "ecx", "edx", "ebp", "edi", "esi", "eip", "esp"}
            frame = {}
            for reg in regs:
                frame[reg] = self.mem_utils.getRegValue(cpu, reg)
            frame['orig_ax'] = frame['eax']
            frame['flags'] = 0
            return frame
    
    def stringFromFrame(self, frame):
        if frame is not None:
            return 'eax:0x%x ebx:0x%x ecx:0x%x edx:0x%x ebp:0x%x edi:0x%x esi:0x%x eip:0x%x esp:0x%x orig_ax:0x%x flags:0x%x' % (frame['eax'], 
                frame['ebx'], frame['ecx'], frame['edx'], frame['ebp'], frame['edi'], frame['esi'],
                frame['eip'], frame['esp'], frame['orig_ax'], frame['flags'])
        else:
            return None
    
    def printFrame(self, frame):
        print '%s' % stringFromFrame(frame)
    
    def sysCallNumBytes(self, cgc_bytes_offset, cpu):
    
        '''
        Get the number of bytes read or written by looking
        at the cgc_bytes field of the task_struct
        '''
        task = self.getCurrentProcAddr()
        #num_bytes = memUtils.readPtr(cpu, task + 0x450)
        num_bytes = self.mem_utils.readPtr(cpu, task + cgc_bytes_offset)
        return num_bytes
    
    def findSwapper(self, current_task, cpu):
            task = SIM_read_phys_memory(cpu, current_task, self.mem_utils.WORD_SIZE)
            done = False
            while not done:
                comm = self.mem_utils.readString(cpu, task + self.param.ts_comm, self.COMM_SIZE)
                print 'findSwapper task is %x comm: %s' % (task, comm)
                ts_real_parent = self.mem_utils.readPtr(cpu, task + self.param.ts_real_parent)
                if ts_real_parent == task:
                    #print 'parent is same as task, done?'
                    done = True
                else:
                    if ts_real_parent != 0:
                        task = ts_real_parent
                    else:
                        print 'got zero for ts_real_parent'
                        #SIM_break_simulation('got zero for ts_real parent')
                        task = None
                        done = True
            return task    
    
    def getTaskStructs(self):
        seen = set()
        tasks = {}
        for cpu in self.cpu:
            print('getTaskStructs current_task is %x' % self.current_task[cpu])
            swapper_addr = self.findSwapper(self.current_task[cpu], cpu) 
            if swapper_addr is None:
                return tasks
            print('using swapper_addr of %x' % swapper_addr)
            stack = []
            stack.append((swapper_addr, True))
            while stack:
                (task_addr, x,) = stack.pop()
                if (task_addr, x) in seen:
                    continue
                seen.add((task_addr, x))
                seen.add((task_addr, False))
                task = self.readTaskStruct(task_addr, cpu)
                #print 'reading task struct for %x got comm of %s next %x' % (task_addr, task.comm, task.next)
                #print 'reading task struct for got comm of %s ' % (task.comm)
                tasks[task_addr] = task
                for child in task.children:
                    if child:
                        stack.append((child, task_addr))
        
                if task.real_parent:
                    stack.append((task.real_parent, False))
                if self.param.ts_thread_group_list_head != None:
                    if task.thread_group.next:
                        stack.append((task.thread_group.next, False))
        
                if x is True:
                    task.in_main_list = True
                    if task.next:
                        stack.append((task.next, True))
                elif x is False:
                    pass
                else:
                    task.in_sibling_list = x
                    for s in task.sibling:
                        if s and s != x:
                            stack.append((s, x))
        
        return tasks
    
    def getGSCurrent_task_offset(self, cpu):
        gs_base = cpu.ia32_gs_base
        retval = gs_base + self.param.cur_task_offset_into_gs
        print('linuxProcessUtils gs base is 0x%x, plus current_task offset is 0x%x for cpu %s' % (gs_base, retval, str(cpu)))
        self.lgr.debug('linuxProcessUtils getGSCurrent_task_offset gs base is 0x%x, plus current_task offset is 0x%x' % (gs_base, retval))
        return retval

    ''' which signals should the montitor stop and then start analysis? 
        or treat as if they are fatal if just monitoring
    '''
    def getStopFor(self):
        retval = range(1,16)
        #retval.remove(SIGUSR1)
        return retval
    
    def isTimer(self, call_num):
        if call_num ==  162:
            return True
        return False
    
    def isSysExit(self, call_num):
        if call_num == 1 or call_num == 0xfc:
            return True
        return False
    
