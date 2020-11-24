from simics import *
import os
import pickle
import osUtils
import memUtils
import syscallNumbers
LIST_POISON2 = object()
def stringFromFrame(frame):
    if frame is not None:
        return 'param1:0x%x param2:0x%x param3:0x%x param4:0x%x param5:0x%x param6:0x%x ' % (frame['param1'], 
            frame['param2'], frame['param3'], frame['param4'], frame['param5'], frame['param6'])
    else:
        return None
def stringFromFrameXXX(frame):
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
    def __init__(self, cpu, cell_name, param, mem_utils, unistd, unistd32, RUN_FROM_SNAP, lgr):
        self.cpu = cpu
        self.cell_name = cell_name
        self.lgr = lgr
        self.param = param
        self.mem_utils = mem_utils
        self.phys_current_task = None
        self.exit_cycles = 0
        self.exit_pid = 0
        self.exec_addrs = {}
        self.swapper = None

        if RUN_FROM_SNAP is not None:
            phys_current_task_file = os.path.join('./', RUN_FROM_SNAP, cell_name, 'phys_current_task.pickle')
            if os.path.isfile(phys_current_task_file):
                self.phys_current_task = pickle.load( open(phys_current_task_file, 'rb') ) 
            exec_addrs_file = os.path.join('./', RUN_FROM_SNAP, 'exec_addrs.pickle')
            if os.path.isfile(exec_addrs_file):
                self.exec_addrs = pickle.load( open(exec_addrs_file, 'rb') ) 
        if self.phys_current_task is None:
            ''' address of current_task symbol, pointer at this address points to the current task record '''
            ''' use physical address because some are relative to FS segment '''

            if self.param.current_task_fs:
                phys = cpu.ia32_fs_base + (self.param.current_task-self.param.kernel_base)
            else:
                #phys_block = self.cpu.iface.processor_info.logical_to_physical(self.param.current_task, Sim_Access_Read)
                #phys = phys_block.address
                phys = self.mem_utils.v2p(self.cpu, self.param.current_task)
                self.lgr.debug('TaskUtils init phys of current_task 0x%x is 0x%x' % (self.param.current_task, phys))
            self.lgr.debug('taskUtils param.current_task 0x%x phys 0x%x' % (param.current_task, phys))
            self.phys_current_task = phys

            if self.phys_current_task > 0xffffffff:
                self.lgr.debug('TaskUtils cell %s phys address for 0x%x is too large' % (self.cell_name, param.current_task))
                self.phys_current_task = 0
                return None
            #except:
            #    self.phys_current_task = 0
            #    self.lgr.debug('TaskUtils init failed to get phys addr of 0x%x' % (param.current_task))
            #    return None
        self.lgr.debug('TaskUtils init cell %s with current_task of 0x%x, phys: 0x%x' % (cell_name, param.current_task, self.phys_current_task))
        self.syscall_numbers = syscallNumbers.SyscallNumbers(unistd, self.lgr)
        if unistd32 is not None:
            self.syscall_numbers32 = syscallNumbers.SyscallNumbers(unistd32, self.lgr)
        else:
            self.syscall_numbers32 = None

    def getPhysCurrentTask(self):
        return self.phys_current_task

    def getCurTaskRec(self):
        if self.phys_current_task == 0:
            return 0
        #self.lgr.debug('taskUtils getCurTaskRec read phys from 0x%x' % self.phys_current_task)
        cur_task_rec = self.mem_utils.readPhysPtr(self.cpu, self.phys_current_task)
        #if cur_task_rec is None:
        #    self.lgr.debug('FAILED')
        #else:
        #    self.lgr.debug('taskUtils curTaskRec got task rec 0x%x' % cur_task_rec)
        return cur_task_rec

    def pickleit(self, fname):
        phys_current_task_file = os.path.join('./', fname, self.cell_name, 'phys_current_task.pickle')
        try:
            os.mkdir(os.path.dirname(phys_current_task_file))
        except:
            pass
        pickle.dump( self.phys_current_task, open( phys_current_task_file, "wb" ) )
        exec_addrs_file = os.path.join('./', fname, self.cell_name, 'exec_addrs.pickle')
        pickle.dump( self.exec_addrs, open( exec_addrs_file, "wb" ) )

    def curProc(self):
        #self.lgr.debug('taskUtils curProc')
        cur_task_rec = self.getCurTaskRec()
        comm = self.mem_utils.readString(self.cpu, cur_task_rec + self.param.ts_comm, 16)
        pid = self.mem_utils.readWord32(self.cpu, cur_task_rec + self.param.ts_pid)
        phys = self.mem_utils.v2p(self.cpu, cur_task_rec)
        #self.lgr.debug('taskProc cur_task 0x%x phys 0x%x  pid %d comm: %s  phys_current_task 0x%x' % (cur_task_rec, phys, pid, comm, self.phys_current_task))
        return self.cpu, comm, pid 

    def findSwapper(self):
        if self.swapper is not None:
            task = self.swapper
        else: 
            #task = SIM_read_phys_memory(cpu, current_task, self.mem_utils.WORD_SIZE)
            task = self.getCurTaskRec()
            #self.lgr.debug('taskUtils findSwapper got 0x%x' % task)
            cpu = self.cpu
            #task = self.mem_utils.getCurrentTask(self.param, cpu)
            done = False
            while not done:
                comm = self.mem_utils.readString(cpu, task + self.param.ts_comm, self.COMM_SIZE)
                pid = self.mem_utils.readWord32(cpu, task + self.param.ts_pid)
                #self.lgr.debug('findSwapper task is %x pid:%d com %s' % (task, pid, comm))
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
            self.swapper = task
        return task    
    
    def is_kernel_virtual(self, addr):
        return addr >= self.param.kernel_base

    def read_list_head(self, cpu, addr, offset, head_addr = None, head_offset = None, other_offset = None):
        addr = self.mem_utils.getUnsigned(addr)
        next = self.mem_utils.readPtr(cpu, addr + offset)
        #self.lgr.debug('read_list_head addr 0x%x  offset is 0x%x effective 0x%x  read 0x%x' % (addr, offset, (addr+offset), next)) 
        if next is None:
            self.lgr.debug('read_list_head got none for next addr 0x%x offset 0x%x' % (addr, offset))
            return None
        prev = self.mem_utils.readPtr(cpu, addr + offset + self.mem_utils.WORD_SIZE)
        if prev is None:
            self.lgr.error('read_list_head got none for prev addr 0x%x offset 0x%x' % (addr, offset))
            return None
    
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
                #print('returning head_addr')
                return head_addr
            if p - offset == addr:
                #print('returning addr p - offset')
                return addr
            if other_offset != None:
                #print('returning other offset p 0x%x minus %d' % (p, other_offset))
                return p - other_offset
            return p - offset
        #self.lgr.debug('read_list_head addr 0x%x  next is 0x%x' % (addr, next)) 
        return ListHead(transform(next), transform(prev))

    def readTaskStruct(self, addr, cpu):
        """Read the task_struct at addr and return a TaskStruct object
        with the information."""
        #self.lgr.debug('readTaskStruct for addr 0x%x' % addr)
        addr = self.mem_utils.getUnsigned(addr)
        task = TaskStruct(addr=addr)
        if self.param.ts_next != None:
            if self.param.ts_next_relative:
                assert self.param.ts_prev == self.param.ts_next + self.mem_utils.WORD_SIZE
                #self.lgr.debug('readTaskStruct bout to call read_list_head addr 0x%x' % addr)
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
            if task.pid is None:
                self.lgr.debug('readTaskStruct got pid of none for addr 0x%x' % addr)
                return None
        if self.param.ts_tgid != None:
            task.tgid = self.mem_utils.readWord32(cpu, addr + self.param.ts_tgid)
        if self.param.ts_comm != None:
            caddr = addr + self.param.ts_comm
            task.comm = self.mem_utils.readString(cpu, addr + self.param.ts_comm, self.COMM_SIZE)
            paddr = self.mem_utils.v2p(cpu, caddr)
            #self.lgr.debug('comm addr is 0x%x  phys 0x%x' % (caddr, paddr))
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
            #if c.next is not None:
                #print('read clist head children got 0x%x 0x%x' % (c.next, c.prev))
            if c is None:
                self.lgr.debug('readTaskStruct got none from read_list_head addr 0x%x' % addr)
                return None
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
        swapper_addr = self.findSwapper() 
        if swapper_addr is None:
            return tasks
        #self.lgr.debug('getTaskStructs using swapper_addr of %x' % swapper_addr)
        stack = []
        stack.append((swapper_addr, True))
        while stack:
            (task_addr, x,) = stack.pop()
            #self.lgr.debug('popped task_addr 0x%x' % task_addr)
            if (task_addr, x) in seen:
                #self.lgr.debug('seen it')
                continue
            seen.add((task_addr, x))
            seen.add((task_addr, False))
            task = self.readTaskStruct(task_addr, cpu)
            if task is None:
                break
            if task.pid is None:
                self.lgr.error('got pid of none for addr 0x%x' % task_addr)
            
            #if task.next == swapper_addr:
            #   self.lgr.debug('getTaskStructs next swapper, assume done TBD, why more on stack?')
            #   #return tasks
            if task_addr is None or task.next is None: 
                #self.lgr.debug('task_addr None')
                break
            if (task.comm is None or len(task.comm.strip()) == 0) and not (task.pid == 0 and len(stack)==0):
                # cleaner way to know we are done?
                self.lgr.debug('read task struct for %x got comm of ZIP pid %d next %x' % (task_addr, task.pid, task.next))
                break
                #continue
           
            #else:
            #    self.lgr.debug('read task struct for %x got comm of %s pid %d next %x previous list head reads were for this task' % (task_addr, task.comm, task.pid, task.next))
          
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

        ''' TBD: why does current task need to be seperately added, does not appear in task walk? '''
        task_rec_addr = self.getCurTaskRec()
        if task_rec_addr not in tasks:
            task = self.readTaskStruct(task_rec_addr, cpu)
            tasks[task_rec_addr] = task
        return tasks

    def getExitPid(self):
        ''' if we are at or past the point of exit, return the most recently exitied pid. 
            TBD, more robust, multiple PIDs? '''
        if self.exit_cycles is not None and self.cpu.cycles >= self.exit_cycles:
            return self.exit_pid
        else:
            return None

    def setExitPid(self, pid):
        self.exit_pid = pid
        self.exit_cycles = self.cpu.cycles
        self.lgr.debug('taskUtils setExitPid pid:%d cycles 0x%x' % (pid, self.exit_cycles))

    def getGroupLeaderPid(self, pid):
        retval = None
        ts_list = self.getTaskStructs()
        for ts in ts_list:
            if ts_list[ts].pid == pid:
                group_leader = self.mem_utils.readPtr(self.cpu, ts + self.param.ts_group_leader)
                if group_leader != ts:
                    retval = self.mem_utils.readWord32(self.cpu, group_leader + self.param.ts_pid)
                else:
                    retval = self.getCommLeaderPid(ts)
                break
        return retval

    def getGroupPids(self, leader_pid):
        retval = []
        #self.lgr.debug('getGroupPids for %d' % leader_pid)
        ts_list = self.getTaskStructs()
        leader_rec = None
        for ts in ts_list:
            if ts_list[ts].pid == leader_pid:
                leader_rec = ts
                break
        if leader_rec is None:
            self.lgr.debug('taskUtils getGroupPids did not find record for leader pid %d' % leader_pid)
            return None 
        #self.lgr.debug('getGroupPids leader_rec 0x%x' % leader_rec)
        for ts in ts_list:
            group_leader = self.mem_utils.readPtr(self.cpu, ts + self.param.ts_group_leader)
            if group_leader != ts:
                if group_leader == leader_rec:
                    pid = self.mem_utils.readWord32(self.cpu, group_leader + self.param.ts_pid)
                    ''' skip if exiting as recorded by syscall '''
                    if pid != self.exit_pid or self.cpu.cycles != self.exit_cycles:
                        retval.append(ts_list[ts].pid)
            else:
                ''' newer linux does not use group_leader like older ones did -- look for ancestor with same comm '''
                comm_leader_pid = self.getCommLeaderPid(ts)
                ts_pid = ts_list[ts].pid
                #self.lgr.debug('getGroupPids comm leader_pid %d  ts_pid %d' % (comm_leader_pid, ts_pid))
                if comm_leader_pid == leader_pid and ts_pid not in retval:
                    if ts_pid != self.exit_pid or self.cpu.cycles != self.exit_cycles:
                        #self.lgr.debug('getGroupPids added %d' % ts_pid)
                        retval.append(ts_pid)
          
        return retval

    def getPidsForComm(self, comm_in):
        comm = os.path.basename(comm_in).strip()
        retval = []
        #self.lgr.debug('getPidsForComm %s' % comm_in)
        ts_list = self.getTaskStructs()
        for ts in ts_list:
            #self.lgr.debug('getPidsForComm compare <%s> to %s  len is %d' % (comm, ts_list[ts].comm, len(comm)))
            if comm == ts_list[ts].comm or (len(comm)>self.COMM_SIZE and len(ts_list[ts].comm) == self.COMM_SIZE and comm.startswith(ts_list[ts].comm)):
                pid = ts_list[ts].pid
                #self.lgr.debug('getPidsForComm MATCHED ? %s to %s  pid %d' % (comm, ts_list[ts].comm, pid))
                ''' skip if exiting as recorded by syscall '''
                if pid != self.exit_pid or self.cpu.cycles != self.exit_cycles:
                    retval.append(ts_list[ts].pid)
        return retval

    def getPidCommMap(self):
        retval = {}
        ts_list = self.getTaskStructs()
        for ts in ts_list:
            retval[ts_list[ts].pid] = ts_list[ts].comm
        return retval

    def getPidParent(self, pid):
        rec = self.getRecAddrForPid(pid)
        parent = self.mem_utils.readPtr(self.cpu, rec + self.param.ts_real_parent)
        pid = self.mem_utils.readWord32(self.cpu, parent + self.param.ts_pid)
        return pid 
 
    def getRecAddrForPid(self, pid):
        #self.lgr.debug('getRecAddrForPid %d' % pid)
        ts_list = self.getTaskStructs()
        for ts in ts_list:
           if ts_list[ts].pid == pid:
               return ts
        self.lgr.debug('TaksUtils getRecAddrForPid %d no task rec found. %d task records found.' % (pid, len(ts_list)))
        return None
 
    def getTaskListPtr(self, rec=None):
        ''' return address of the task list "next" entry that points to the current task '''
        if rec is None:
            task_rec_addr = self.getCurTaskRec()
        else:
            task_rec_addr = rec
        comm = self.mem_utils.readString(self.cpu, task_rec_addr + self.param.ts_comm, self.COMM_SIZE)
        pid = self.mem_utils.readWord32(self.cpu, task_rec_addr + self.param.ts_pid)
        seen = set()
        tasks = {}
        cpu = self.cpu
        swapper_addr = self.findSwapper() 
        if swapper_addr is None:
            self.lgr.debug('getTaskListPtr got None for swapper, pid:%d %s' % (pid, comm))
            return None
        #self.lgr.debug('getTaskListPtr look for next pointer to current task 0x%x pid: %d (%s) using swapper_addr of %x' % (task_rec_addr, 
        #                pid, comm,  swapper_addr))
        stack = []
        stack.append((swapper_addr, True))
        while stack:
            (task_addr, x,) = stack.pop()
            if (task_addr, x) in seen:
                continue
            seen.add((task_addr, x))
            seen.add((task_addr, False))
            #self.lgr.debug('reading task addr 0x%x' % (task_addr))
            task = self.readTaskStruct(task_addr, cpu)
            if task is None or task.pid is None:
                self.lgr.error('got task or pid of none for addr 0x%x' % task_addr)
                return

            if task.next == swapper_addr:
               #self.lgr.debug('getTaskStructs next swapper, assume done TBD, why more on stack?')
               return None

            #self.lgr.debug('getTaskListPtr task struct for %x got comm of %s pid %d next %x thread_group.next 0x%x ts_next 0x%x' % (task_addr, task.comm, 
            #     task.pid, task.next, task.thread_group.next, self.param.ts_next))
            if (task.next) == task_rec_addr or task.next == (task_rec_addr+self.param.ts_next):
                next_addr = task_addr + self.param.ts_next
                #self.lgr.debug('getTaskListPtr return next 0x%x  pid:%d (%s)' % (next_addr, task.pid, task.comm))
                return next_addr
            #print 'reading task struct for got comm of %s ' % (task.comm)
            tasks[task_addr] = task
            for child in task.children:
                if child:
                    stack.append((child, task_addr))
    
            if task.real_parent:
                stack.append((task.real_parent, False))
            if self.param.ts_thread_group_list_head != None:
                if task.thread_group.next:
                    c = task.thread_group.next + self.mem_utils.WORD_SIZE
                    #if (task.thread_group.next - self.param.ts_next) == task_rec_addr:
                    if (task.thread_group.next) == task_rec_addr or (task.thread_group.next + self.mem_utils.WORD_SIZE) == task_rec_addr:
                        thread_group_addr = task_addr + self.param.ts_thread_group_list_head
                        self.lgr.debug('getTaskListPtr return thread group 0x%x' % thread_group_addr)
                        return thread_group_addr
                    stack.append((task.thread_group.next, False))
    
            if x is True:
                task.in_main_list = True
                if task.next:
                    if (task.next) == task_rec_addr:
                        retval = task_addr + self.param.ts_next
                        #self.lgr.debug('getTaskListPtr x true return 0x%x  pid:%d (%s)' % (retval, task.pid, task.comm))
                        return retval
                    stack.append((task.next, True))
            elif x is False:
                pass
            else:
                task.in_sibling_list = x
                for s in task.sibling:
                    if s and s != x:
                        stack.append((s, x))
    
        return None

    def getPidCommFromNext(self, next_addr):
        pid = None
        comm = None
        if next_addr is not None:
            rec = next_addr - self.param.ts_next
            comm = self.mem_utils.readString(self.cpu, rec + self.param.ts_comm, self.COMM_SIZE)
            pid = self.mem_utils.readWord32(self.cpu, rec + self.param.ts_pid)
        return pid, comm

    def currentProcessInfo(self, cpu=None):
        cur_addr = self.getCurTaskRec()
        comm = self.mem_utils.readString(self.cpu, cur_addr + self.param.ts_comm, self.COMM_SIZE)
        pid = self.mem_utils.readWord32(self.cpu, cur_addr + self.param.ts_pid)
        return self.cpu, cur_addr, comm, pid

    def getCurrentThreadParent(self):
        cur_addr = self.getCurTaskRec()
        parent = self.mem_utils.readPtr(self.cpu, cur_addr + self.param.ts_real_parent)
        pid = self.mem_utils.readWord32(self.cpu, parent + self.param.ts_pid)
        comm = self.mem_utils.readString(self.cpu, parent + self.param.ts_comm, self.COMM_SIZE)
        return pid, comm
               
    def getCommLeaderPid(self, cur_rec): 
        ''' return pid of oldest ancestor having same comm as cur_rec, which may be self'''
        comm = self.mem_utils.readString(self.cpu, cur_rec + self.param.ts_comm, 16)
        leader_pid = self.mem_utils.readWord32(self.cpu, cur_rec + self.param.ts_pid)
        parent = None
        prev_parent = None
        #self.lgr.debug('getCommLeaderPid 0x%x pid:%d (%s)' % (cur_rec, leader_pid, comm))
        while(True):
            parent = self.mem_utils.readPtr(self.cpu, cur_rec + self.param.ts_real_parent)
            #self.lgr.debug('getCommLeaderPid parent 0x%x' % parent)
            if parent == cur_rec:
                break
            else:
                leader_comm = self.mem_utils.readString(self.cpu, parent + self.param.ts_comm, 16)
                if leader_comm != comm:
                    break
                leader_pid = self.mem_utils.readWord32(self.cpu, parent + self.param.ts_pid)
                #self.lgr.debug('getCommLeaderPid parent pid %d comm %s' % (leader_pid, leader_comm))
            cur_rec = parent
        #self.lgr.debug('getCommLeaderPid returning %d' % leader_pid)
        return leader_pid

    def getCurrentThreadLeaderPid(self):
        ''' NOT really.  Our notion of leader includes parent of procs that were cloned.  Modern linux does not use
            group_leader if distinct processes '''
        cur_rec = self.getCurTaskRec()
        group_leader = self.mem_utils.readPtr(self.cpu, cur_rec + self.param.ts_group_leader)
        leader_pid = self.mem_utils.readWord32(self.cpu, group_leader + self.param.ts_pid)
        #self.lgr.debug('getCurrentThreadLeaderPid cur_rec 0x%x  group_leader 0x%x' % (cur_rec, group_leader))
        if group_leader == cur_rec:
            leader_pid = self.getCommLeaderPid(cur_rec)
        return leader_pid

    def getMemUtils(self):
        return self.mem_utils

    def getExecProgAddr(self, pid, cpu):
        return self.exec_addrs[pid].prog_addr

    def modExecParam(self, pid, cpu, dmod):
        for arg_addr in self.exec_addrs[pid].arg_addr_list:
            if dmod.checkString(cpu, arg_addr, 100):
                SIM_break_simulation('modified execve param')
     
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
                    #self.lgr.debug('readExecParamStrings adding arg %s' % (arg_string))

            prog_string = prog_string.strip()
            self.exec_addrs[pid].prog_name = prog_string
            self.exec_addrs[pid].arg_list = arg_string_list
        else:
            self.lgr.debug('readExecParamStrings got none from 0x%x ' % self.exec_addrs[pid].prog_addr)
        return prog_string, arg_string_list

    def getProcArgsFromStack(self, pid, at_enter, cpu):
        if pid is None:
            return None, None

        mult = 0
        done = False
        arg_addr_list = []
        limit = 15
        i=0
        prog_addr = None
        if self.mem_utils.WORD_SIZE == 4:
            if cpu.architecture == 'arm':
                prog_addr = self.mem_utils.getRegValue(cpu, 'r0')
                argv = self.mem_utils.getRegValue(cpu, 'r1')
                while not done and i < limit:
                    xaddr = argv + mult*self.mem_utils.WORD_SIZE
                    arg_addr = self.mem_utils.readPtr(cpu, xaddr)
                    if arg_addr is not None and arg_addr != 0:
                       #self.lgr.debug("getProcArgsFromStack ARM adding arg addr %x read from 0x%x" % (arg_addr, xaddr))
                       arg_addr_list.append(arg_addr)
                    else:
                       done = True
                    mult = mult + 1
                    i = i + 1
                
                #if pid == 841:
                #    SIM_break_simulation('prog_addr is 0x%x' % prog_addr)
            else:
                if not at_enter:
                    ''' ebx not right?  use stack '''
                    esp = self.mem_utils.getRegValue(self.cpu, 'esp')
                    sptr = esp + 2*self.mem_utils.WORD_SIZE
                    argv = self.mem_utils.readPtr(cpu, sptr)
                    while not done and i < limit:
                        xaddr = argv + mult*self.mem_utils.WORD_SIZE
                        arg_addr = self.mem_utils.readPtr(cpu, xaddr)
                        #self.lgr.debug('getProcArgsFromStack argv: 0x%x xaddr 0x%x esp: 0x%x sptr: 0x%x' % (argv, xaddr, esp, sptr))
                        if arg_addr is not None and arg_addr != 0:
                           #self.lgr.debug("getProcArgsFromStack adding arg addr %x read from 0x%x" % (arg_addr, xaddr))
                           arg_addr_list.append(arg_addr)
                        else:
                           #SIM_break_simulation('cannot read 0x%x' % xaddr)
                           done = True
                        mult = mult + 1
                    i = i + 1
                    sptr = esp + self.mem_utils.WORD_SIZE
                    prog_addr = self.mem_utils.readPtr(cpu, sptr)
                else:
                    ''' sysenter or int80, trust ebx and ecx '''
                    prog_addr = self.mem_utils.getRegValue(cpu, 'ebx') 
                    argv = self.mem_utils.getRegValue(cpu, 'ecx')
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
                    
            if prog_addr == 0:
                self.lgr.error('getProcArgsFromStack pid: %d esp: 0x%x argv 0x%x prog_addr 0x%x' % (pid, esp, argv, prog_addr))
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


        self.exec_addrs[pid] = osUtils.execStrings(cpu, pid, arg_addr_list, prog_addr, None)
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
        if pid not in self.exec_addrs:
            pid = self.getGroupLeaderPid(pid)
        if pid in self.exec_addrs:
            return self.exec_addrs[pid].prog_name, self.exec_addrs[pid].arg_list
        else: 
            return None, None
 
    def getSyscallEntry(self, callnum, compat32):
        if self.cpu.architecture == 'arm':
            val = callnum * self.mem_utils.WORD_SIZE + self.param.syscall_jump
            val = self.mem_utils.getUnsigned(val)
            entry = self.mem_utils.readPtr(self.cpu, val)
        elif not compat32:
            ''' compute the entry point address for a given syscall using constant extracted from kernel code '''
            val = callnum * self.mem_utils.WORD_SIZE - self.param.syscall_jump
            val = self.mem_utils.getUnsigned(val)
            entry = self.mem_utils.readPtr(self.cpu, val)
        else:
            val = callnum * self.mem_utils.WORD_SIZE - self.param.compat_32_jump
            val = self.mem_utils.getUnsigned(val)
            entry = self.mem_utils.readPtr(self.cpu, val)
            self.lgr.debug('getSyscallEntry call 0x%x val 0x%x entry 0x%x' % (callnum, val,entry))
        return entry

    def frameFromStackSyscall(self):
        #reg_num = self.cpu.iface.int_register.get_number(self.mem_utils.getESP())
        #esp = self.cpu.iface.int_register.read(reg_num)
        if self.cpu.architecture == 'arm':
            frame = self.frameFromRegs(self.cpu)
        else:
            esp = self.mem_utils.getRegValue(self.cpu, 'esp')
            regs_addr = esp + self.mem_utils.WORD_SIZE
            regs = self.mem_utils.readPtr(self.cpu, regs_addr)
            #self.lgr.debug('frameFromStackSyscall regs_addr is 0x%x  regs is 0x%x' % (regs_addr, regs))
            frame = self.getFrame(regs_addr, self.cpu)
        return frame
    
    def frameFromStack(self):
        #reg_num = self.cpu.iface.int_register.get_number(self.mem_utils.getESP())
        #esp = self.cpu.iface.int_register.read(reg_num)
        esp = self.mem_utils.getRegValue(self.cpu, 'esp')
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
            retval['param1'] = SIM_read_phys_memory(cpu, phys_addr, self.mem_utils.WORD_SIZE)
            retval['param2'] = SIM_read_phys_memory(cpu, phys_addr+self.mem_utils.WORD_SIZE, self.mem_utils.WORD_SIZE)
            retval['param3'] = SIM_read_phys_memory(cpu, phys_addr+2*self.mem_utils.WORD_SIZE, self.mem_utils.WORD_SIZE)
            retval['param4'] = SIM_read_phys_memory(cpu, phys_addr+3*self.mem_utils.WORD_SIZE, self.mem_utils.WORD_SIZE)
            retval['param5'] = SIM_read_phys_memory(cpu, phys_addr+4*self.mem_utils.WORD_SIZE, self.mem_utils.WORD_SIZE)
            retval['param6'] = SIM_read_phys_memory(cpu, phys_addr+5*self.mem_utils.WORD_SIZE, self.mem_utils.WORD_SIZE)
            retval['pc'] = SIM_read_phys_memory(cpu, phys_addr+22*self.mem_utils.WORD_SIZE, self.mem_utils.WORD_SIZE)
            retval['sp'] = SIM_read_phys_memory(cpu, phys_addr+25*self.mem_utils.WORD_SIZE, self.mem_utils.WORD_SIZE)
            return retval
    def getFrameXX(self, v_addr, cpu):
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
            #retval['eip'] = SIM_read_phys_memory(cpu, phys_addr+12*self.mem_utils.WORD_SIZE, self.mem_utils.WORD_SIZE)
            retval['eip'] = SIM_read_phys_memory(cpu, phys_addr+22*self.mem_utils.WORD_SIZE, self.mem_utils.WORD_SIZE)
            #retval['cs'] = SIM_read_phys_memory(cpu, phys_addr+13*self.mem_utils.WORD_SIZE, self.mem_utils.WORD_SIZE)
            retval['cs'] = SIM_read_phys_memory(cpu, phys_addr+23*self.mem_utils.WORD_SIZE, self.mem_utils.WORD_SIZE)
            #retval['flags'] = SIM_read_phys_memory(cpu, phys_addr+14*self.mem_utils.WORD_SIZE, self.mem_utils.WORD_SIZE)
            retval['flags'] = SIM_read_phys_memory(cpu, phys_addr+24*self.mem_utils.WORD_SIZE, self.mem_utils.WORD_SIZE)
            #retval['esp'] = SIM_read_phys_memory(cpu, phys_addr+15*self.mem_utils.WORD_SIZE, self.mem_utils.WORD_SIZE)
            retval['esp'] = SIM_read_phys_memory(cpu, phys_addr+25*self.mem_utils.WORD_SIZE, self.mem_utils.WORD_SIZE)
            #retval['ss'] = SIM_read_phys_memory(cpu, phys_addr+16*self.mem_utils.WORD_SIZE, self.mem_utils.WORD_SIZE)
            retval['ss'] = SIM_read_phys_memory(cpu, phys_addr+26*self.mem_utils.WORD_SIZE, self.mem_utils.WORD_SIZE)
            return retval

    def frameFromRegs(self, cpu, compat32=False):
        frame = {}
        if cpu.architecture == 'arm':
            for p in memUtils.param_map['arm']:
                frame[p] = self.mem_utils.getRegValue(cpu, memUtils.param_map['arm'][p])
            cpl = memUtils.getCPL(cpu)
            if cpl == 0:
                frame['sp'] = self.mem_utils.getRegValue(cpu, 'sp_usr')
                frame['pc'] = self.mem_utils.getRegValue(cpu, 'lr')
                frame['lr'] = self.mem_utils.getRegValue(cpu, 'lr_usr')
            else:
                frame['sp'] = self.mem_utils.getRegValue(cpu, 'sp')
                frame['pc'] = self.mem_utils.getRegValue(cpu, 'pc')
                frame['lr'] = self.mem_utils.getRegValue(cpu, 'lr')
        else:
            frame['sp'] = self.mem_utils.getRegValue(cpu, 'sp')
            frame['pc'] = self.mem_utils.getRegValue(cpu, 'pc')
            if self.mem_utils.WORD_SIZE == 8 and not compat32:
                for p in memUtils.param_map['x86_64']:
                    frame[p] = self.mem_utils.getRegValue(cpu, memUtils.param_map['x86_64'][p])
            else:
                for p in memUtils.param_map['x86_32']:
                    frame[p] = self.mem_utils.getRegValue(cpu, memUtils.param_map['x86_32'][p])
        
        return frame

    def socketCallName(self, callname, compat32):
        if self.cpu.architecture != 'arm' and (self.mem_utils.WORD_SIZE != 8 or compat32):
            return ['socketcall']
        elif callname == 'accept':
            return ['accept', 'accept4']
        else:
            return [callname]

    def syscallName(self, callnum, compat32):
        if not compat32:
            if callnum in self.syscall_numbers.syscalls:
                return self.syscall_numbers.syscalls[callnum]
            else:
                return 'not_mapped'
        elif self.syscall_numbers32 is not None:
            if callnum in self.syscall_numbers32.syscalls:
                return self.syscall_numbers32.syscalls[callnum]
            else:
                return 'not_mapped'
        else:
            self.lgr.error('taskUtils syscallName, compat32 but no syscall_numbers32.  Was the unistd file loaded?')

    def syscallNumber(self, callname, compat32):
        if not compat32:
            if callname in self.syscall_numbers.callnums:
                return self.syscall_numbers.callnums[callname]
            else:
                return -1
        else:
            if callname in self.syscall_numbers32.callnums:
                return self.syscall_numbers32.callnums[callname]
            else:
                return -1

    def getExecMode(self):
        mode = self.cpu.iface.x86_reg_access.get_exec_mode()
        return mode
