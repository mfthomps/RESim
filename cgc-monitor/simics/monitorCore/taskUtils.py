from simics import *
import osUtils
import syscallNumbers
LIST_POISON2 = object()
def stringFromFrame(frame):
    if frame is not None:
        return 'eax:0x%x ebx:0x%x ecx:0x%x edx:0x%x ebp:0x%x edi:0x%x esi:0x%x eip:0x%x esp:0x%x orig_ax:0x%x flags:0x%x' % (frame['eax'], 
            frame['ebx'], frame['ecx'], frame['edx'], frame['ebp'], frame['edi'], frame['esi'],
            frame['eip'], frame['esp'], frame['orig_ax'], frame['flags'])
    else:
        return None
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

class TaskUtils():
    COMM_SIZE = 16
    def __init__(self, cpu, param, mem_utils, current_task, lgr):
        self.cpu = cpu
        self.lgr = lgr
        self.param = param
        self.mem_utils = mem_utils
        ''' address of current_task symbol, pointer at this address points to the current task record '''
        self.current_task = current_task
        self.lgr.debug('TaskUtils init with current_task of 0x%x' % current_task)
        self.exec_addrs = {}
        self.syscall_numbers = syscallNumbers.SyscallNumbers(self.param)

    def getCurrentTask(self):
        return self.current_task
       
    def getCurTaskRec(self):
        cur_task_rec = self.mem_utils.readPtr(self.cpu, self.current_task)
        return cur_task_rec

    def curProc(self):
        cur_task_rec = self.mem_utils.readPtr(self.cpu, self.current_task)
        comm = self.mem_utils.readString(self.cpu, cur_task_rec + self.param.ts_comm, 16)
        pid = self.mem_utils.readWord32(self.cpu, cur_task_rec + self.param.ts_pid)
        return self.cpu, comm, pid 

    def findSwapper(self, current_task, cpu):
            #task = SIM_read_phys_memory(cpu, current_task, self.mem_utils.WORD_SIZE)
            task = self.mem_utils.readPtr(cpu, current_task)
            #task = self.mem_utils.getCurrentTask(self.param, cpu)
            done = False
            while not done:
                comm = self.mem_utils.readString(cpu, task + self.param.ts_comm, self.COMM_SIZE)
                #print 'findSwapper task is %x comm: %s' % (task, comm)
                ts_real_parent = self.mem_utils.readPtr(cpu, task + self.param.ts_real_parent)
                if ts_real_parent == task:
                    #print 'parent is same as task, done?'
                    done = True
                else:
                    if ts_real_parent != 0:
                        task = ts_real_parent
                    else:
                        #print 'got zero for ts_real_parent'
                        #SIM_break_simulation('got zero for ts_real parent')
                        task = None
                        done = True
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

    def getTaskStructs(self):
        seen = set()
        tasks = {}
        cpu = self.cpu
        #print('getTaskStructs current_task is %x' % self.current_task)
        swapper_addr = self.findSwapper(self.current_task, cpu) 
        if swapper_addr is None:
            return tasks
        #print('using swapper_addr of %x' % swapper_addr)
        stack = []
        stack.append((swapper_addr, True))
        while stack:
            (task_addr, x,) = stack.pop()
            if (task_addr, x) in seen:
                continue
            seen.add((task_addr, x))
            seen.add((task_addr, False))
            task = self.readTaskStruct(task_addr, cpu)
            #print 'reading task struct for %x got comm of %s pid %d next %x' % (task_addr, task.comm, task.pid, task.next)
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

    def getPidsForComm(self, comm):
        retval = []
        ts_list = self.getTaskStructs()
        for ts in ts_list:
            if ts_list[ts].comm == comm:
                retval.append(ts_list[ts].pid)
        return retval

    def getPidCommMap(self):
        retval = {}
        ts_list = self.getTaskStructs()
        for ts in ts_list:
            retval[ts_list[ts].pid] = ts_list[ts].comm
        return retval

    def getRecAddrForPid(self, pid):
        ts_list = self.getTaskStructs()
        for ts in ts_list:
           if ts_list[ts].pid == pid:
               return ts
        return None
 
    def getTaskListPtr(self):
        ''' return address of the task list "next" entry that points to the current task '''
        task_rec_addr = self.mem_utils.readPtr(self.cpu, self.current_task)
        seen = set()
        tasks = {}
        cpu = self.cpu
        #print('getTaskStructs current_task is %x' % self.current_task)
        swapper_addr = self.findSwapper(self.current_task, cpu) 
        if swapper_addr is None:
            return tasks
        #print('using swapper_addr of %x' % swapper_addr)
        stack = []
        stack.append((swapper_addr, True))
        while stack:
            (task_addr, x,) = stack.pop()
            if (task_addr, x) in seen:
                continue
            seen.add((task_addr, x))
            seen.add((task_addr, False))
            task = self.readTaskStruct(task_addr, cpu)
            #print 'reading task struct for %x got comm of %s pid %d next %x' % (task_addr, task.comm, task.pid, task.next)
            #print 'reading task struct for got comm of %s ' % (task.comm)
            tasks[task_addr] = task
            for child in task.children:
                if child:
                    stack.append((child, task_addr))
    
            if task.real_parent:
                stack.append((task.real_parent, False))
            if self.param.ts_thread_group_list_head != None:
                if task.thread_group.next:
                    if task.thread_group.next == task_rec_addr:
                        return (task_addr + self.param.ts_next)
                    stack.append((task.thread_group.next, False))
    
            if x is True:
                task.in_main_list = True
                if task.next:
                    if task.next == task_rec_addr:
                        return (task_addr + self.param.ts_next)
                    stack.append((task.next, True))
            elif x is False:
                pass
            else:
                task.in_sibling_list = x
                for s in task.sibling:
                    if s and s != x:
                        stack.append((s, x))
    
        return None

    def currentProcessInfo(self, cpu=None):
        #self.lgr.debug('currentProcessInfo, current_task is 0x%x' % self.current_task)
        #cur_addr = SIM_read_phys_memory(self.cpu, self.current_task, self.mem_utils.WORD_SIZE)
        cur_addr = self.mem_utils.readPtr(self.cpu, self.current_task)
        comm = self.mem_utils.readString(self.cpu, cur_addr + self.param.ts_comm, self.COMM_SIZE)
        pid = self.mem_utils.readWord32(self.cpu, cur_addr + self.param.ts_pid)
        return self.cpu, cur_addr, comm, pid

    def getMemUtils(self):
        return self.mem_utils

    def getExecProgAddr(self, pid, cpu):
        return self.exec_addrs[pid].prog_addr

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
            self.exec_addrs[pid].prog_name = prog_string
            self.exec_addrs[pid].arg_list = arg_string_list
        else:
            self.lgr.debug('readExecParamStrings got none from 0x%x ' % self.exec_addrs[pid].prog_addr)
        return prog_string, arg_string_list

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

            sptr = esp + 2*self.mem_utils.WORD_SIZE
            argv = self.mem_utils.readPtr(cpu, sptr)
            #SIM_break_simulation('proc args, sptr is 0x%x  esp 0x%x' % (sptr, esp))
            while not done and i < limit:
                xaddr = argv + mult*self.mem_utils.WORD_SIZE
                arg_addr = self.mem_utils.readPtr(cpu, xaddr)
                if arg_addr is not None and arg_addr != 0:
                   #self.lgr.debug("getProcArgsFromStack adding arg addr %x read from 0x%x" % (arg_addr, xaddr))
                   arg_addr_list.append(arg_addr)
                else:
                   done = True
                mult = mult + 1
                i = i + 1
            sptr = esp + self.mem_utils.WORD_SIZE
            prog_addr = self.mem_utils.readPtr(cpu, sptr)
            #self.lgr.debug('getProcArgsFromStack pid: %d esp: 0x%x argv 0x%x prog_addr 0x%x' % (pid, esp, argv, prog_addr))
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
        self.exec_addrs[pid].prog_name = prog_string
        self.exec_addrs[pid].arg_list = arg_string_list
        #self.lgr.debug('getProcArgsFromStack prog_string is %s' % prog_string)
        #if prog_string == 'cfe-poll-player':
        #    SIM_break_simulation('debug')
        #self.lgr.debug('args are %s' % str(arg_string_list))
        '''
        if prog_string is None:
            # program string in unmapped memory; break on it's being read (won't occur until os maps the page)
            cell = self.cell_config.cell_context[self.cell_name]

            self.prog_read_break[pid] = SIM_breakpoint(cell, Sim_Break_Linear, 
                Sim_Access_Read, prog_addr, 1, 0)
            #self.lgr.debug('getProcArgsFromStack set hap on read of param addr %d ' % (pid)) 
            self.prog_read_hap[pid] = SIM_hap_add_callback_index("Core_Breakpoint_Memop", 
               self.readExecProg, self.exec_addrs[pid], self.prog_read_break[pid])
            #SIM_run_alone(SIM_run_command, 'list-breakpoints')
        '''

        return prog_string, arg_string_list

    def getProgName(self, pid):
        if pid in self.exec_addrs:
            return self.exec_addrs[pid].prog_name, self.exec_addrs[pid].arg_list
        else: 
            return None
 
    def getSyscallEntry(self, callnum):
        ''' compute the entry point address for a given syscall using constant extracted from kernel code '''
        val = callnum * 4 - self.param.syscall_jump
        val = val & 0xffffffff
        entry = self.mem_utils.readPtr(self.cpu, val)
        return entry

    def frameFromStackSyscall(self):
        reg_num = self.cpu.iface.int_register.get_number(self.mem_utils.getESP())
        esp = self.cpu.iface.int_register.read(reg_num)
        regs_addr = esp + self.mem_utils.WORD_SIZE
        regs = self.mem_utils.readPtr(self.cpu, regs_addr)
        #self.lgr.debug('frameFromStackSyscall regs_addr is 0x%x  regs is 0x%x' % (regs_addr, regs))
        frame = self.getFrame(regs_addr, self.cpu)
        return frame
    
    def frameFromStack(self):
        reg_num = self.cpu.iface.int_register.get_number(self.mem_utils.getESP())
        esp = self.cpu.iface.int_register.read(reg_num)
        #self.lgr.debug('frameFromStack esp 0x%x' % (esp))
        frame = self.getFrame(esp, self.cpu)
        #print 'frame: %s' % stringFromFrame(frame)
        #traceback.print_stack()
        #SIM_break_simulation("debug")
        return frame
         
    '''
        Given the address of a linux stack frame, return a populated dictionary of its values.
    '''
    def getFrame(self, v_addr, cpu):
            phys_addr = self.mem_utils.v2p(cpu, v_addr)
            #self.lgr.debug('getFrame, v_addr: 0x%x  phys_addr: 0x%x' % (v_addr, phys_addr))
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

    def syscallName(self, callnum):
        return self.syscall_numbers.syscalls[callnum]
    def syscallNumber(self, callname):
        return self.syscall_numbers.callnums[callname]
