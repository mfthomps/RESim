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
import bsdUtils
import memUtils
import osUtils
import gc
from monitorLibs import utils
'''
Track the current process and provide APIs to get the address of the current task's record
This module is instantiated per cell
'''

class bsdProcessUtils():
    watching_current = {}
    EXEC_SYS_CALL = 59
    READ_SYSCALL = 3
    WRITE_SYSCALL = 4
    BRK = 0
    MMAP = 0
    MUNMAP = 0
    SOCKET = 0
    COMM_SIZE = 16
    os_type = 'freeBSD'
    REPLAY_USER_SIG = 30
    SIGHUP = 1
    SIGINT = 2
    SIGQUIT = 3
    SIGILL = 4
    SIGTRAP = 5
    SIGABRT = 6
    SIGEMT = 7
    SIGFPE = 8
    SIGKILL = 9
    SIGBUS = 10
    SIGSEGV = 11
    SIGALRM = 14
    SIGTERM = 15
    SIGUSR1 = 30
    SIGUSR2 = 31
    
    def __init__(self, top, cell_name, param, cell_config, master_config, hap_manager, watch_kernel, mem_utils, lgr, always_watch_calls=False):
        self.param = param
        self.top = top
        self.cell_name = cell_name
        self.cell_config = cell_config
        self.master_config = master_config
        self.hap_manager = hap_manager
        self.mem_utils = mem_utils
        self.watch_kernel = watch_kernel
        self.always_watch_calls = always_watch_calls
        self.lgr = lgr
        self.exec_addrs = {}
        self.comm_map = {}
        # for obtaining parameters to the exec call
        self.prog_read_break = {}
        self.prog_read_hap = {}
        self.cpu = []
        self.watching_current = {}
        ''' physical address of current thread '''
        self.current_task = {}
        self.pinfo = {}
        self.proc_0 = {}
        for cpu in cell_config.cell_cpu_list[cell_name]:
            self.cpu.append(cpu)
            cur_thread_addr = self.getPhysAddrOfCurrentThread(cpu)
            self.watching_current[cpu] = False
            if cur_thread_addr != 0:
                self.current_task[cpu] = cur_thread_addr
                print('bsdProcessUtils current task for cpu %s is %x' % (str(cpu), self.current_task[cpu]))
            self.pinfo[cpu] = self.pInfo(cpu, None, None, None)
        if hap_manager is not None:
            self.setBreaks()

    def setBreaks(self):
        cell = self.cell_config.cell_context[self.cell_name]
        for cpu in self.cpu:
            if cpu not in self.current_task:
                self.lgr.error('bsdProcessUtils, setBreaks, %s not in current task set' % cpu.name)
                return 
            virt = self.param.kernel_base + self.current_task[cpu]
            #self.hap_manager.breakLinear(self.cell_name, virt, Sim_Access_Write, self.changedThread, 'changed_thread')
            code_break_num = SIM_breakpoint(cell, Sim_Break_Linear, Sim_Access_Write, virt, 4, 0)
          
            cb_num = SIM_hap_add_callback_index("Core_Breakpoint_Memop", 
                   self.changedThread, cpu, code_break_num)
            self.lgr.debug('bsdProcessUtils setBreaks for currentTasks on cell %s at phys address 0x%x' % (self.cell_name, 
                   self.current_task[cpu]))
            self.hap_manager.addBreak(self.cell_name, None, code_break_num, None)
            self.hap_manager.addHap(cpu, self.cell_name, None, cb_num, None)

    def cleanAll(self):
        #self.top.watching_current_syscalls(self.cell_name, pid) = False
        for pid in self.prog_read_break:
            if pid in self.comm_map:
                self.lgr.debug('bsdProcUtils cleaning pid %d (%s)' % (pid, self.comm_map[pid]))
                del self.comm_map[pid]
            SIM_delete_breakpoint(self.prog_read_break[pid])
            SIM_hap_delete_callback_id("Core_Breakpoint_Memop", self.prog_read_hap[pid])
        self.prog_read_break = {}
        self.prog_read_hap = {}
        self.exec_addrs = {}
        self.comm_map = {}
        num_items=gc.collect()
        self.lgr.debug('bsdProcessUtils clean all, gc got %x' % num_items)

    def reInit(self):
        self.lgr.debug('bsdProcessUtils reInit')
        #self.top.watching_current_syscalls[self.cell_name] = False
        self.setBreaks()
           
    def getMemUtils(self):
        return self.mem_utils 

    def getCurrentProcAddrFromThreadPtr(self, ptr2thread, cpu):
        ''' back pointer to this thread's process is one word from the start of the struct '''
        back_pointer = ptr2thread+self.mem_utils.WORD_SIZE
        thread_phys_block = cpu.iface.processor_cli.translate_to_physical('ds', back_pointer)
        #self.lgr.debug('getCurrentProcAddrFromThreadPtr phys of %x is %x' % (ptr2thread+self.mem_utils.WORD_SIZE, thread_phys_block.address))
        #other = self.watch_kernel.decodeKernelAddress(cpu, ptr2thread+self.mem_utils.WORD_SIZE)
        #self.lgr.debug('and from decode: 0x%x' % (other))
        phys_addr = thread_phys_block.address
        if thread_phys_block.address == 0:
            ''' cheat '''
            phys_addr = back_pointer & ~self.param.kernel_base 
            #self.lgr.debug('cheat phys addr is %x' % phys_addr)
        ptr = SIM_read_phys_memory(cpu, phys_addr, self.mem_utils.WORD_SIZE)
        return ptr

    def updateComm(self, pid, cpu):
        if pid in self.comm_map:
            comm = self.comm_map[pid]
        else:
            cur_addr = self.pinfo[cpu].cur_addr
            comm = self.mem_utils.readString(cpu, cur_addr + self.param.ts_comm, 16)
            self.lgr.debug('updateComm pid %d cur_addr %x was %s now %s' % (pid, cur_addr, self.pinfo[cpu].comm, comm))
            self.pinfo[cpu].comm = comm
        return comm

    def currentProcessInfoFromThreadAddr(self, ptr2thread, cpu):
        cur_addr = self.getCurrentProcAddrFromThreadPtr(ptr2thread, cpu)
        if cur_addr is None:
            return None, None, None
        #self.lgr.debug('currentProcessInfoFromThreadAddr read cur_addr %x' % cur_addr)
        pid = self.mem_utils.readWord32(cpu, cur_addr + self.param.ts_pid)
        if pid in self.comm_map:
            comm = self.comm_map[pid]
        else:
            comm = self.mem_utils.readString(cpu, cur_addr + self.param.ts_comm, 16)
        return cur_addr, comm, pid

    def processExiting(self, cpu, force=False):
        dum_cpu, cur_addr, comm, pid = self.getPinfo(cpu)
        self.lgr.debug('bsdProcessUtils processExiting cell %s %d (%s)' % (self.cell_name, pid, comm))
        if dum_cpu is None:
            self.lgr.error('bsdProcessUtils processExiting on %s but no pinfo' % self.cell_name)
            return
        if self.watch_kernel is not None and (self.master_config.kernelRop(comm) or self.master_config.kernelPageTable(comm)):
            #SIM_run_alone(self.watch_kernel.undoRop, self.cpu)
            #SIM_run_alone(self.watch_kernel.undoKernelPage, self.cpu)
            self.watch_kernel.undoRop(cpu)
            self.watch_kernel.undoKernelPage(cpu)
            self.lgr.debug('bsdProcessUtils processExiting called undoKernelPage & rop')
            #self.undoRop(self.cpu)
            self.watching_current[cpu] = False
        else:
            self.lgr.debug('processExiting, no undo for comm %s' % comm) 
            if self.watch_kernel is None:
                self.lgr.debug('processExiting, is none') 
            else:
                self.lgr.debug('processExiting, is kernelPageTable is %r' % self.master_config.kernelPageTable(comm)) 

        #self.top.watching_current_syscalls[self.cell_name] = self.hap_manager.clearKernelSysCalls(self.cell_name)
        self.hap_manager.clearKernelSysCalls(self.cell_name, pid, force=force)
        self.lgr.debug('bsdProcessUtils processExiting call clearKernelSysCalls')

    class pInfo():
        def __init__(self, cpu, cur_addr, comm, pid):
            self.cpu = cpu
            self.cur_addr = cur_addr
            self.comm = comm
            self.pid = pid
        def get(self):
            return self.cpu, self.cur_addr, self.comm, self.pid

    def clearPinfo(self):
        for cpu in self.cpu:
            old_cpu, old_cur_addr, old_comm, old_pid = self.pinfo[cpu].get()
            if old_comm is not None and (self.master_config.kernelRop(old_comm) or self.master_config.kernelUnx(old_comm) or self.master_config.kernelPageTable(old_comm)): 
                self.stopWatching(cpu)
            self.pinfo[cpu] = self.pInfo(cpu, None, None, None)

    def getPinfo(self, cpu):
        if self.pinfo[cpu] is not None:
            return self.pinfo[cpu].get()
        else:
            return None, None, None, None

    def changedThread(self, cpu, third, forth, memory):
        old_comm = None
        old_pid = None
        if self.pinfo[cpu] is not None:
            old_cpu, old_cur_addr, old_comm, old_pid = self.pinfo[cpu].get()
        ''' get the value that will be written into the current thread address '''
        value = SIM_get_mem_op_value_le(memory)
        cur_addr, comm, pid = self.currentProcessInfoFromThreadAddr(value, cpu)
        self.top.switchedPid(cpu, pid, comm)
        #if pid == 0 or comm == "idle":
        #    return
        cell_name = self.top.getTopComponentName(cpu)
        cell = self.cell_config.cell_context[self.cell_name]
        #self.lgr.debug("changeThread, BEGIN: got new ptr2thread value of %x  proc: %s:%d (%s) on cpu: %s" % (value, cell_name, pid, comm, str(cpu)))
        self.pinfo[cpu] = self.pInfo(cpu, cur_addr, comm, pid)
        obj = SIM_get_object(cell_name)

        if not self.always_watch_calls: 
            # either set or clear kernel syscall breaks/haps
            #if self.top.isWatching(cell_name, pid):
            if self.top.watchSysCalls(self.cell_name, pid, comm): 
                #if not self.top.watching_current_syscalls[self.cell_name]: 
                if not self.top.watching_current_syscalls(self.cell_name, pid): 
                    self.top.doKernelSysCalls(cpu, self.cell_name, comm, pid)
                    #self.lgr.debug('changedThread now watching kernelSysCalls for %s %d (%s)' % (self.cell_name, pid, comm))
                else:
                    #self.lgr.debug('changedThread already watching syscalls for %s %d (%s)' % (cell_name, pid, comm))
                    pass
            elif old_comm is not None and self.master_config.watchCalls(self.cell_name, old_comm):
                if self.top.watching_current_syscalls(self.cell_name, pid): 
                    #self.top.watching_current_syscalls[self.cell_name] = self.hap_manager.clearKernelSysCalls(cell_name)
                    self.hap_manager.clearKernelSysCalls(cell_name, pid)
                    #self.lgr.debug('changedThread removed kernelSysCalls for %s %d (%s)' % (self.cell_name, pid, comm))
                else:
                    #self.lgr.debug('changedThread not watching current syscalls and should not watch kernelSysCalls for %s %d (%s)' % (cell_name, pid, comm))
                    pass

       
        if (self.master_config.kernelRop(comm) or self.master_config.kernelUnx(comm) or self.master_config.kernelPageTable(comm)) and self.top.isWatching(self.cell_name, pid):
                #self.lgr.debug("changed thread to %s:%d (%s)" % (cell_name, pid, comm))
                if not (self.watch_kernel is not None and self.watching_current[cpu]):
                    #cell = obj.cell_context
                    if self.master_config.kernelRop(comm):
                        self.watch_kernel.doRop(cell, cpu, pid, comm)
                        #self.top.setRopPending(self.cell_name)
                    if self.master_config.kernelUnx(comm):
                        self.watch_kernel.doUnexpected(cell, cpu)
                        #self.lgr.debug('changedThread did unEx for %s %d (%s)' % (self.cell_name, pid, comm))
                    if self.master_config.kernelPageTable(comm):
                        self.watch_kernel.watchKernelPage(cpu, cell, pid, comm)
                        #self.lgr.debug('changedThread did watchKernelPage for %s %d (%s)' % (self.cell_name, pid, comm))
                    #self.lgr.debug('changedThread did doRop/unEx for %s %d (%s)' % (self.cell_name, pid, comm))
                    self.watching_current[cpu] = True
        elif old_comm is not None and (self.master_config.kernelRop(old_comm) or self.master_config.kernelUnx(old_comm) or self.master_config.kernelPageTable(old_comm)):
                if self.watch_kernel is not None and self.watching_current[cpu]:
                    #self.lgr.debug("changedThread, thread no longer being watched, now %s:%d (%s)" % (self.cell_name, pid, comm))
                    self.stopWatching(cpu)

    def stopWatching(self, cpu):
        #self.lgr.debug('stopWatching')
        SIM_run_alone(self.watch_kernel.undoRop, cpu)
        SIM_run_alone(self.watch_kernel.undoKernelPage, cpu)
        self.watching_current[cpu] = False

    
    def hasPid(self, pid):
        retval = False
        for cpu in self.cpu:
            curtask = self.findProc0(cpu)
            while curtask != 0 and not retval:
               comm = self.mem_utils.readString(cpu, curtask + self.param.ts_comm, self.COMM_SIZE)
               tpid = self.mem_utils.readWord32(cpu, curtask + self.param.ts_pid)
               if tpid == pid:
                   retval = True
               prev_task = self.mem_utils.readPtr(cpu, curtask + self.param.ts_prev)
               curtask = prev_task
            if retval:
                break
        return retval

    def getCommByPid(self, pid):
        for cpu in self.cpu:
            self.lgr.debug('getCommByPid look for pid %d on cpu %s' % (pid, str(cpu)))
            curtask = self.findProc0(cpu)
            self.lgr.debug('getCommByPid curtask is 0x%x' % curtask)
            retval = None
            count = 0
            while curtask != 0 and retval is None:
               tpid = self.mem_utils.readWord32(cpu, curtask + self.param.ts_pid)
               #self.lgr.debug('getCommByPid, tpid is %d' % tpid)
               if tpid == pid:
                   if pid in self.comm_map:
                       retval = self.comm_map[pid]
                   else:
                       retval = self.mem_utils.readString(cpu, curtask + self.param.ts_comm, self.COMM_SIZE)
                   self.lgr.debug('bsdProcessUtils, getCommByPid, found pid %d, comm is %s' % (pid, retval))
                   if retval is None:
                       curtask = 0
               else:
                   prev_task = self.mem_utils.readPtr(cpu, curtask + self.param.ts_prev)
                   #self.lgr.debug('prev_task is %x' % prev_task)
                   curtask = prev_task
                   count += 1
                   if count > 1000:
                       self.lgr.error('bsdProcessUtils, getCommByPid, panic, too many procs...')
                       retval = 0
            if retval is not None:
                break
             
        return retval
   
    ''' Return a list of PIDs that have the given name ''' 
    def getPidByName(self, name):
        #print 'in getPidByName, look for %s' % name
        pid = []
        for cpu in self.cpu:
            curtask = self.findProc0(cpu)
            i = 0
            while curtask != 0:
               comm = self.mem_utils.readString(cpu, curtask + self.param.ts_comm, self.COMM_SIZE)
               if comm == name:
                   retval = self.mem_utils.readString(cpu, curtask + self.param.ts_comm, self.COMM_SIZE)
                   tpid = self.mem_utils.readWord32(cpu, curtask + self.param.ts_pid)
                   pid.append(tpid)
               prev_task = self.mem_utils.readPtr(cpu, curtask + self.param.ts_prev)
               curtask = prev_task
               i += 1 
               if i > 1000:
                   self.lgr.error('bsdProcessUtils getPidByName, too many iterations')
                   curtask = 0
        return pid

    def getParentPid(self, cur_addr, cpu):
        ts_real_parent = self.mem_utils.readPtr(cpu, cur_addr + self.param.ts_parent)
        parent_pid = self.mem_utils.readWord32(cpu, ts_real_parent + self.param.ts_pid)
        return ts_real_parent, parent_pid

    ''' get the pid of the parent of the given pid ''' 
    #TBD no real parent field?  eh?
    def getParent(self, pid, ignore_cpu):
        #self.lgr.debug('getParent')
        retval = None
        comm = None
        for cpu in self.cpu:
            curtask = self.findProc0(cpu)
            while curtask != 0 and retval is None:
               tpid = self.mem_utils.readWord32(cpu, curtask + self.param.ts_pid)
               if tpid == pid:
                   parent = self.mem_utils.readWord32(cpu, curtask + self.param.ts_parent)
                   retval = self.mem_utils.readWord32(cpu, parent + self.param.ts_pid)
                   comm = self.mem_utils.readString(cpu, curtask + self.param.ts_comm, 16)
               else:
                   prev_task = self.mem_utils.readPtr(cpu, curtask + self.param.ts_prev)
                   curtask = prev_task
            if retval is not None:
                break
        return retval, comm


    def setKernelWatch(self, watch_kernel):
        self.lgr.debug('bsdProcessUtils, setKernelwatch')
        self.watch_kernel = watch_kernel

    def getProcArgsFromStack(self, pid, finishCallback, cpu):
        ''' 
        get the arguments off the stack at sys_execve
        '''
        #self.lgr.debug('bsdProcUtils getProcArgsFromStack')
        if pid is None:
            return None, None

        if self.mem_utils.WORD_SIZE == 4:
            esp = self.mem_utils.getRegValue(cpu, 'esp')
    
            sptr = esp + 2*self.mem_utils.WORD_SIZE
            self.lgr.debug('bsdProcUtils esp is 0x%x sptr is 0x%x' % (esp, sptr))
            argv = self.mem_utils.readPtr(cpu, sptr)
            self.lgr.debug('argv is 0x%x' % argv)
    
            done = False
            
            arg_string_list = []
            limit = 15
            i=0
            arg_addr = self.mem_utils.readPtr(cpu, argv)
            self.lgr.debug('arg_addr is 0x%x' % arg_addr)
            prog_addr = self.mem_utils.readPtr(cpu, argv+self.mem_utils.WORD_SIZE)
            self.lgr.debug('prog_addr is 0x%x' % prog_addr)
            program = self.mem_utils.readString(cpu, prog_addr, 512)
            if program is not None:
                program = program.strip()
                env_addr = self.mem_utils.readPtr(cpu, argv+2*self.mem_utils.WORD_SIZE)
                #self.lgr.debug('env_addr is 0x%x' % env_addr)
                while arg_addr != env_addr and i < limit:
                    arg_string = self.mem_utils.readString(cpu, arg_addr, 512)
                    if arg_string is not None:
                        arg_string_list.append(arg_string.strip())
                        #self.lgr.debug("getProcArgsFromStack adding arg  %s read from 0x%x" % (arg_string.strip(), arg_addr))
                        arg_addr = arg_addr + len(arg_string)+1
                    else:
                        self.lgr.debug("bsdProcessUtils, getProcArgsFromStack no string from 0x%x" % (arg_addr))
                    i = i + 1
        else:
            reg_num = cpu.iface.int_register.get_number("rsi")
            rsi = cpu.iface.int_register.read(reg_num)
            i=0
            done = False
            arg_string_list = []
            rsi = rsi+self.mem_utils.WORD_SIZE
            arg_addr = self.mem_utils.readPtr(cpu, rsi)
            program = self.mem_utils.readString(cpu, arg_addr, 512)
            self.lgr.debug('bsdProcessUtils, program %s from 0x%x' % (program, arg_addr))
            limit = 15
            if program is not None:
                arg_addr = arg_addr + len(program)+1
                program = program.strip()
                rsi = rsi+self.mem_utils.WORD_SIZE
                env_addr = self.mem_utils.readPtr(cpu, rsi)
                #self.lgr.debug('env_addr is 0x%x arg_addr 0x%x' % (env_addr, arg_addr))
                while arg_addr != env_addr and i < limit:
                    arg_string = self.mem_utils.readString(cpu, arg_addr, 512)
                    if arg_string is not None:
                        arg_string_list.append(arg_string.strip())
                        #self.lgr.debug("getProcArgsFromStack adding arg  %s read from 0x%x" % (arg_string.strip(), arg_addr))
                        arg_addr = arg_addr + len(arg_string)+1
                    else:
                        self.lgr.debug("bsdProcessUtils, getProcArgsFromStack no string from 0x%x" % (arg_addr))
                    i = i + 1
            '''
            while not done and i < 30:
                rsi = rsi+self.mem_utils.WORD_SIZE
                arg_addr = self.mem_utils.readPtr(self.cpu, rsi)
                if arg_addr != 0:
                    arg_string = memUtils.readString(self.cpu, arg_addr, 512)
                    self.lgr.debug("getProcArgsFromStack adding arg addr %x string: %s read from 0x%x" % (arg_addr, arg_string, rsi))
                    if arg_string == 'launcher':
                        SIM_break_simulation('debug args')
                    arg_string_list.append(arg_string)
                else:
                    done = True
                i += 1
            '''


        return program, arg_string_list


    '''
        Map the program name the pid (process comm string is too short for full program names)
    '''
    def setCommMap(self, pid, comm, cpu):
        self.comm_map[pid] = comm
        if self.pinfo[cpu].pid == pid:
            self.pinfo[cpu].comm = comm
        self.lgr.debug('bsdProcessUtils setCommMap, %d to %s, pinfo pid was %d' % (pid, comm, self.pinfo[cpu].pid))
        return
    '''
        Return the physical address of the location of BSD's pointer to the current thread
    '''
    def getPhysAddrOfCurrentThread(self, cpu):
        if cpu in self.current_task:
            return self.current_task[cpu]
    	''' In BSD, the fs register points to the current thread (struct thread), whose 
        second pointer points to to the proc structure.  However, we can't dereference fs because it may
        not be properly loaded if we are in user space.  So use the GDT as per below.
        
        Use the gdtr task register which points to the GDT.  Then assume 
        the thread segment (which BSD loads into FS as selector 8) is the second entry
        in the GDT.  Each GDT entry is 8 bytes, 3 lobs are at bits 16 to 31.  1 hob is 23-31 of 2nd word
        mft TBD:  It should also be possible to to use the BSD "gdt" global variable from the symbol table to 
        get this information. 


        for AMD64: 
		include/pcpu.h:#define	OFFSETOF_CURTHREAD	0

		static __inline __pure2 struct thread *
		__curthread(void)
		{
		        struct thread *td;

		        __asm("movq %%gs:%1,%0" : "=r" (td)
		            : "m" (*(char *)OFFSETOF_CURTHREAD));
		        return (td);
		}
       
        '''
        if self.mem_utils.WORD_SIZE == 4:
            gdt_tr_base = cpu.gdtr_base
            gdt_tr_base_phys = utils.getUnsigned(gdt_tr_base - self.param.kernel_base)
            select8 = gdt_tr_base_phys + 8
            select8 = utils.getUnsigned(select8)
            #print 'select8 is %x' % select8
            select8_lob = select8 + 2
            select8_hob = select8 + 7
            try:
                low_order_bytes = SIM_read_phys_memory(cpu, select8_lob, 3)
            except:
                print 'FAILED reading physical memory in bsdProcessUtils, gdt_tr_base_phys is %x  lob: %x' % (gdt_tr_base_phys, select8_lob)
                return 0
            high_order_byte = SIM_read_phys_memory(cpu, select8_hob, 1)
            base = utils.getUnsigned((high_order_byte << 24) | low_order_bytes)
            print 'gdt_phys: %x  low: %x  high: %x  base: %x' % (gdt_tr_base_phys, low_order_bytes, high_order_byte, base)
            phys_addr_of_curthread = base - self.param.kernel_base
            return utils.getUnsigned(phys_addr_of_curthread)
        else:
            gs_base = cpu.ia32_gs_base
            if gs_base > self.param.kernel_base:
                retval = self.mem_utils.v2p(cpu, gs_base)
            else:
                retval = 0
            print('bsdProcUtils gs base is 0x%x' % (gs_base))
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
    
            
    
    '''
        Return the address of the currently running thread
    '''
    def getCurrentThreadAddr(self, cpu):
            # read value from the physical address obtained above 
            phys_addr_of_curthread = self.getPhysAddrOfCurrentThread(cpu)
            #print 'getCurrentThreadAddr phys_addr_of_curthread is %x' % phys_addr_of_curthread
    
    	    ptr2thread = SIM_read_phys_memory(cpu, phys_addr_of_curthread, self.mem_utils.WORD_SIZE)
            #print 'getCurrentThreadAddr ptr2thread is %x' % ptr2thread
            return ptr2thread
    
    '''
        Return the address of the currently running process
    '''
    def getCurrentProcAddr(self, cpu):
        ptr2thread = self.getCurrentThreadAddr(cpu)
        # back pointer to this thread's process is one word from the start of the struct

        task_addr = ptr2thread+self.mem_utils.WORD_SIZE
        thread_phys_block_ds = cpu.iface.processor_cli.translate_to_physical('ds', task_addr)
        thread_phys_block = cpu.iface.processor_info.logical_to_physical(task_addr, Sim_Access_Read)
        if thread_phys_block_ds.address !=  thread_phys_block.address:
            SIM_break_simulation('physical address translation fu')
        #thread_phys_block = self.cpu.iface.processor_info.logical_to_physical(ptr2thread+WORD_SIZE, Sim_Access_Read)
        ptr = SIM_read_phys_memory(cpu, thread_phys_block.address, self.mem_utils.WORD_SIZE)
        #reg_num = cpu.iface.int_register.get_number("ds")
        #ds = cpu.iface.int_register.read(reg_num)
        #print 'getCurrrentProcAddr thread_phys_block address %x  ptr %x ds %x' % (thread_phys_block.address, ptr, ds)
        return ptr
    
    
    '''
        Return the a list of pids of processes having the given name. 
    '''
    ''' 
    def getPidByName(self, name, param, cpu):
        pid = []
        cur_addr = self.getCurrentProcAddr(param, cpu)
        curtask = cur_addr
        #print 'looking for %s' % name
        comm = memUtils.readString(cpu, curtask + param.ts_comm, self.COMM_SIZE)
        tpid = memUtils.readWord32(cpu, curtask + param.ts_pid)
        #print 'curtask is %x   first com is %s' % (curtask, comm)
        while curtask is not None:
            if comm == name:
                pid.append(tpid)
            next_task = self.mem_utils.readPtr(cpu, curtask + param.ts_next)
            #print 'next_task is %x' % next_task
            if next_task is not None and next_task != 0:
               curtask = next_task
               comm = memUtils.readString(cpu, curtask + param.ts_comm, self.COMM_SIZE)
               tpid = memUtils.readWord32(cpu, curtask + param.ts_pid)
               #print 'next com is %s pid:%d' % (comm, tpid)
            else:
               curtask = None
        curtask = cur_addr
        while curtask is not None:
            if comm == name and tpid not in pid:
                pid.append(tpid)    
            prev_task = self.mem_utils.readPtr(cpu, curtask + param.ts_prev)
            #print 'prev_task is %x' % prev_task
            if prev_task is not None and prev_task != 0:
               curtask = prev_task
               comm = memUtils.readString(cpu, curtask + param.ts_comm, self.COMM_SIZE)
               tpid = memUtils.readWord32(cpu, curtask + param.ts_pid)
               #print 'prev com is %s pid:%d' % (comm, tpid)
            else:
               curtask = None
    
        return pid
    ''' 
    def getTaskByPid(self, pid):
        for cpu in self.cpu:
            cur_addr = self.getCurrentProcAddr(cpu)
            curtask = cur_addr
            #print 'looking for %s' % name
            tpid = self.mem_utils.readWord32(cpu, curtask + self.param.ts_pid)
            #print 'curtask is %x   first com is %s' % (curtask, comm)
            retval = None
            while curtask is not None and retval is None:
                if tpid == pid:
                    retval = curtask
                else:
                    next_task = self.mem_utils.readPtr(cpu, curtask + self.param.ts_next)
                    #print 'next_task is %x' % next_task
                    if next_task is not None and next_task != 0:
                       curtask = next_task
                       tpid = self.mem_utils.readWord32(cpu, curtask + self.param.ts_pid)
                       #print 'next com is %s pid:%d' % (comm, tpid)
                    else:
                       curtask = None
            curtask = cur_addr
            while curtask is not None and retval is None:
                if tpid == pid:
                    retval = curtask
                else:
                    prev_task = self.mem_utils.readPtr(cpu, curtask + self.param.ts_prev)
                    #print 'prev_task is %x' % prev_task
                    if prev_task is not None and prev_task != 0:
                       curtask = prev_task
                       tpid = self.mem_utils.readWord32(cpu, curtask + self.param.ts_pid)
                       #print 'prev com is %s pid:%d' % (comm, tpid)
                    else:
                       curtask = None
            if retval is not None:
                break 
        return retval
    
    '''
       Is the process named by cur_addr a decendent of the given parent?
       TBD: limited to single-cpu/core models.  Extend by doing for all cpus.
    '''
    def spawnedBy(self, parent_pid, cur_addr, child_pid):
        #logging.debug('spawned by looking for %d, current pid is %d' % (parent_pid, child_pid))
        if child_pid in parent_pid:
            return False
        retval = False
        i = 0
        dead_count = 10000
        for cpu in self.cpu:
            while not retval and cur_addr is not None and cur_addr is not 0:
                cur_addr = self.mem_utils.readPtr(self.cpu, cur_addr+self.param.ts_parent) 
                if cur_addr is not None and cur_addr is not 0:
                    cur_pid = self.mem_utils.readWord32(self.cpu, cur_addr+self.param.ts_pid)
                    #logging.debug('parent pid is %d' % cur_pid)
                    if cur_pid in parent_pid:
    		        retval = True
                    else:
                        i += 1
                        if i > dead_count:
                            self.lgr.error('spawnedBy in a terminal loop, return False')
                            return False 
            if cur_addr is None or cur_addr == 0 or retval:
                break
        return retval
    
    
    '''
        Given the address of a freeBSD stack frame, return a populated dictionary of its values.
        Offsets derived from i386/include/frame.h
        TBD: ASSUMES 4byte words!
    '''
    def getFrame(self, v_addr, cpu):
        phys_addr = self.mem_utils.v2p(cpu, v_addr)
        retval = {}
        if self.mem_utils.WORD_SIZE == 4:
            retval['edi'] = SIM_read_phys_memory(cpu, phys_addr+3*self.mem_utils.WORD_SIZE, self.mem_utils.WORD_SIZE)
            retval['esi'] = SIM_read_phys_memory(cpu, phys_addr+4*self.mem_utils.WORD_SIZE, self.mem_utils.WORD_SIZE)
            retval['ebp'] = SIM_read_phys_memory(cpu, phys_addr+5*self.mem_utils.WORD_SIZE, self.mem_utils.WORD_SIZE)
            retval['esp'] = SIM_read_phys_memory(cpu, phys_addr+6*self.mem_utils.WORD_SIZE, self.mem_utils.WORD_SIZE)
            retval['ebx'] = SIM_read_phys_memory(cpu, phys_addr+7*self.mem_utils.WORD_SIZE, self.mem_utils.WORD_SIZE)
            retval['edx'] = SIM_read_phys_memory(cpu, phys_addr+8*self.mem_utils.WORD_SIZE, self.mem_utils.WORD_SIZE)
            retval['ecx'] = SIM_read_phys_memory(cpu, phys_addr+9*self.mem_utils.WORD_SIZE, self.mem_utils.WORD_SIZE)
            retval['eax'] = SIM_read_phys_memory(cpu, phys_addr+10*self.mem_utils.WORD_SIZE, self.mem_utils.WORD_SIZE)
            retval['trap_no'] = SIM_read_phys_memory(cpu, phys_addr+11*self.mem_utils.WORD_SIZE, self.mem_utils.WORD_SIZE)
            retval['err'] = SIM_read_phys_memory(cpu, phys_addr+12*self.mem_utils.WORD_SIZE, self.mem_utils.WORD_SIZE)
            retval['eip'] = SIM_read_phys_memory(cpu, phys_addr+13*self.mem_utils.WORD_SIZE, self.mem_utils.WORD_SIZE)
            return retval
        else:
            retval['edi'] = SIM_read_phys_memory(cpu, phys_addr, self.mem_utils.WORD_SIZE)
            retval['esi'] = SIM_read_phys_memory(cpu, phys_addr+1*self.mem_utils.WORD_SIZE, self.mem_utils.WORD_SIZE)
            retval['edx'] = SIM_read_phys_memory(cpu, phys_addr+2*self.mem_utils.WORD_SIZE, self.mem_utils.WORD_SIZE)
            retval['ecx'] = SIM_read_phys_memory(cpu, phys_addr+3*self.mem_utils.WORD_SIZE, self.mem_utils.WORD_SIZE)
            retval['r8'] = SIM_read_phys_memory(cpu, phys_addr+4*self.mem_utils.WORD_SIZE, self.mem_utils.WORD_SIZE)
            retval['r9'] = SIM_read_phys_memory(cpu, phys_addr+5*self.mem_utils.WORD_SIZE, self.mem_utils.WORD_SIZE)
            retval['eax'] = SIM_read_phys_memory(cpu, phys_addr+6*self.mem_utils.WORD_SIZE, self.mem_utils.WORD_SIZE)
            retval['ebx'] = SIM_read_phys_memory(cpu, phys_addr+7*self.mem_utils.WORD_SIZE, self.mem_utils.WORD_SIZE)
            retval['ebp'] = SIM_read_phys_memory(cpu, phys_addr+8*self.mem_utils.WORD_SIZE, self.mem_utils.WORD_SIZE)
            retval['r10'] = SIM_read_phys_memory(cpu, phys_addr+9*self.mem_utils.WORD_SIZE, self.mem_utils.WORD_SIZE)
            retval['r11'] = SIM_read_phys_memory(cpu, phys_addr+10*self.mem_utils.WORD_SIZE, self.mem_utils.WORD_SIZE)
            retval['r12'] = SIM_read_phys_memory(cpu, phys_addr+11*self.mem_utils.WORD_SIZE, self.mem_utils.WORD_SIZE)
            retval['r13'] = SIM_read_phys_memory(cpu, phys_addr+12*self.mem_utils.WORD_SIZE, self.mem_utils.WORD_SIZE)
            retval['r14'] = SIM_read_phys_memory(cpu, phys_addr+13*self.mem_utils.WORD_SIZE, self.mem_utils.WORD_SIZE)
            retval['r15'] = SIM_read_phys_memory(cpu, phys_addr+14*self.mem_utils.WORD_SIZE, self.mem_utils.WORD_SIZE)
            retval['trap_no'] = SIM_read_phys_memory(cpu, phys_addr+15*self.mem_utils.WORD_SIZE, 4)
            retval['tf_addr'] = SIM_read_phys_memory(cpu, phys_addr+16*self.mem_utils.WORD_SIZE, self.mem_utils.WORD_SIZE)
            retval['tf_flags'] = SIM_read_phys_memory(cpu, phys_addr+17*self.mem_utils.WORD_SIZE, 4)
            retval['err'] = SIM_read_phys_memory(cpu, phys_addr+18*self.mem_utils.WORD_SIZE, self.mem_utils.WORD_SIZE)
            retval['eip'] = SIM_read_phys_memory(cpu, phys_addr+19*self.mem_utils.WORD_SIZE, self.mem_utils.WORD_SIZE)
            retval['cs'] = SIM_read_phys_memory(cpu, phys_addr+20*self.mem_utils.WORD_SIZE, self.mem_utils.WORD_SIZE)
            retval['rflags'] = SIM_read_phys_memory(cpu, phys_addr+21*self.mem_utils.WORD_SIZE, self.mem_utils.WORD_SIZE)
            retval['esp'] = SIM_read_phys_memory(cpu, phys_addr+22*self.mem_utils.WORD_SIZE, self.mem_utils.WORD_SIZE)
            #print('v_addr is 0x%x' % v_addr) 
            #print str(retval)
            #SIM_break_simulation('debug getFrame')
            return retval
    
    def stringFromFrame(self, frame):
        return 'eax:%x ebx:%x ecx:%x edx:%x ebp:%x edi:%x esi:%x eip:%x esp:%x trap_no:%x err:%x' % (frame['eax'], 
            frame['ebx'], frame['ecx'], frame['edx'], frame['ebp'], frame['edi'], frame['esi'],
            frame['eip'], frame['esp'], frame['trap_no'], frame['err'])
    
    def frameFromRegs(self, cpu):
            regs = {"eax", "ebx", "ecx", "edx", "ebp", "edi", "esi", "eip", "esp"}
            frame = {}
            for reg in regs:
                frame[reg] = self.mem_utils.getRegValue(cpu, reg)
            frame['trap_no'] = None
            frame['err'] = None
            return frame
    
    def frameFromThread(self, cpu):
        thread_addr = self.getCurrentThreadAddr(cpu)
        frame_addr = self.mem_utils.readPtr(cpu, thread_addr + self.param.thread_frame)
        #self.lgr.debug('frameFromThread frame_addr 0x%x' % frame_addr)
        frame = self.getFrame(frame_addr, cpu)
        return frame
    
    def frameFromStack(self, cpu):
        esp = self.mem_utils.getRegValue(cpu, 'esp')
        ''' read from the top of the stack to get the pointer to the trap frame '''
        if self.mem_utils.WORD_SIZE == 4:
            frame_addr = self.mem_utils.readPtr(cpu, esp+self.mem_utils.WORD_SIZE)
        else:
            frame_addr = esp+self.mem_utils.WORD_SIZE
        ''' get frame '''
        #self.lgr.debug('frameFromStack for esp 0x%x and frame_add 0x%x' % (esp, frame_addr))
        return self.getFrame(frame_addr, cpu)
    
    def printFrame(self, frame):
        print '%s' % stringFromFrame(frame)
    
    def getSigned(self, iv):
        if(iv & 0x80000000):
            iv = -0x100000000 + iv
        return iv
    
    def getProcList(self):
        plist = []
        cpu = self.cpu[0]
        curtask = self.findProc0(cpu)
        self.lgr.debug('getProclist cpu %s' % str(cpu))
        while curtask != 0:
           comm = self.mem_utils.readString(cpu, curtask + self.param.ts_comm, self.COMM_SIZE)
           tpid = self.mem_utils.readWord32(cpu, curtask + self.param.ts_pid)
           #p_ucred = self.mem_utils.readPtr(cpu, curtask + 0x24)
           p_ucred = self.mem_utils.readPtr(cpu, curtask + self.param.p_ucred)
           if p_ucred != 0 and p_ucred >= self.param.kernel_base :
               #euid = memUtils.readWord32(cpu, p_ucred + self.mem_utils.WORD_SIZE)
               #ruid = memUtils.readWord32(cpu, p_ucred + 2*self.mem_utils.WORD_SIZE)
               euid = self.mem_utils.readWord32(cpu, p_ucred + 4)
               ruid = self.mem_utils.readWord32(cpu, p_ucred + 8)
           else:
               euid = 9999
               ruid = 9999
           threads = self.getThreads(cpu, curtask)
           single = self.mem_utils.readPtr(cpu, curtask + 0x308)
           #print 'getProcList curtask is %x got %d (%s) ' % (curtask, tpid, comm)
           pi = self.uidInfo(cpu, comm, tpid, euid, ruid, single, threads)
           plist.append(pi)
           prev_task = self.mem_utils.readPtr(cpu, curtask + self.param.ts_prev)
           if comm is not None and len(comm) > 0:
               curtask = prev_task
           else:
               curtask = 0
        return plist
        
 
    def findProc0(self, cpu):
        if cpu in self.proc_0:
            return self.proc_0[cpu]
        curtask = self.getCurrentProcAddr(cpu)
        done = False
        print 'first curtask is %x' % curtask
        self.lgr.debug('first curtask is %x' % curtask)
        limit = 1000
        i=0
        while not done and curtask is not None:
            next_task = self.mem_utils.readPtr(cpu, curtask + self.param.ts_next)
            print 'next_task is %x' % next_task
            self.lgr.debug('next_task is %x' % next_task)
            if next_task != 0:
               curtask = next_task
            else:
               print 'PROC0 is %x' % curtask
               self.lgr.debug('PROC0 is %x' % curtask)
               done = True
            i += 1
            if i > limit:
                print 'too many iterations, try back?'
                self.lgr.debug('too many iterations, try back?')
                done = True
        self.proc_0[cpu] = curtask
        return curtask
    
    def currentProcessInfo(self, cpu):

        #cur_addr = self.getCurrentProcAddr(cpu)
        #comm = self.mem_utils.readString(cpu, cur_addr + self.param.ts_comm, self.COMM_SIZE)
        #pid = self.mem_utils.readWord32(cpu, cur_addr + self.param.ts_pid)
        #self.lgr.debug('currentProcessInfo 2, cur_addr is 0x%x, pid is %d' % (cur_addr, pid))

        addr_of_current_thread = SIM_read_phys_memory(cpu, self.current_task[cpu], self.mem_utils.WORD_SIZE)
        cur_addr, comm, pid = self.currentProcessInfoFromThreadAddr(addr_of_current_thread, cpu)
        #if cur_addr is not None:
        #    self.lgr.debug('currentProcessInfo, addr_of_current_thread is 0x%x, cur_addr: %x  pid is %d' % (addr_of_current_thread, cur_addr, pid))
        return cpu, cur_addr, comm, pid
    
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
    
    
    class uidInfo():
        def __init__(self, cpu, comm, pid, euid, ruid, task_ptr, tlist=None):
            self.comm = comm 
            self.pid = pid 
            self.euid = euid 
            self.ruid = ruid 
            self.task_ptr = task_ptr 
            self.tlist = tlist 
            self.cpu = cpu
    
    def getThreads(self, cpu, curtask):
        ''' assumes 64bit '''
        td_name_offset = 0x284
        td_tid_offset = 0x90
        td_oncpu_offset = 0x101
        td_ucred_offset = 0x138
        p_ucred_offset = 0x40
        tlist = []
        #thread list is second word (second pointer) in proc struct
        done = False
        thread_off = 2*self.mem_utils.WORD_SIZE
        thread_addr = self.mem_utils.readPtr(cpu, curtask + thread_off)
        #print('getThreads, thread addr is 0x%x' % thread_addr)
        count = 0
        while not done and count < 20:
            td_name = self.mem_utils.readString(cpu, thread_addr + td_name_offset, self.COMM_SIZE)
            td_ucred_addr = self.mem_utils.readPtr(cpu, curtask + p_ucred_offset)
            if td_ucred_addr != 0:
               euid = self.mem_utils.readWord32(cpu, td_ucred_addr + self.mem_utils.WORD_SIZE)
               ruid = self.mem_utils.readWord32(cpu, td_ucred_addr + 2*self.mem_utils.WORD_SIZE)
            else:
               SIM_break_simulation("error reading td_ucred in getThreads")
               return
            td_tid = self.mem_utils.readWord32(cpu, thread_addr+td_tid_offset)
            td_oncpu = self.mem_utils.readByte(cpu, thread_addr+td_oncpu_offset)
            ti = self.uidInfo(td_oncpu, td_name, td_tid, euid, ruid, thread_addr)
            tlist.append(ti)
            next = thread_addr = self.mem_utils.readPtr(cpu, thread_addr + 2*self.mem_utils.WORD_SIZE)
            if next != 0 and td_name is not None:
               #print('getThreads, found next of 0x%x' % next)
               thread_addr = next
            else:
               done=True
            count += 1
        return tlist 
         
    def sysCallNumBytes(self, dum, cpu):
        thread_addr = self.getCurrentThreadAddr(cpu)
        num_bytes = self.mem_utils.readPtr(cpu, thread_addr + self.param.thread_retval1)
        return num_bytes
    
    def getStopFor(self):
        return [4, 6, 8, 10, 11, 15]
    
    def isTimer(self, call_num):
        SYS_TIMER_MIN = 232
        SYS_TIMER_MAX = 240
        if call_num >= SYS_TIMER_MIN and call_num <= SYS_TIMER_MAX:
            return True
        return False
    
    def isSysExit(self, call_num):
        if call_num == 1:
            return True
        return False
    
    def is_kernel_virtual(self, addr):
        return addr >= self.param.kernel_base

    def cleanPid(self, pid):
        if pid in self.comm_map:
            self.lgr.debug('bsdProcUtils cleaning pid %d (%s)' % (pid, self.comm_map[pid]))
            del self.comm_map[pid]
        if pid in self.prog_read_break:
            SIM_delete_breakpoint(self.prog_read_break[pid])
            SIM_hap_delete_callback_id("Core_Breakpoint_Memop", self.prog_read_hap[pid])
            del self.exec_addrs[pid]
            del self.prog_read_break[pid]
