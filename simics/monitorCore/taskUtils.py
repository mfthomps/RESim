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
'''
Linux task information, e.g., task lists.
'''
from simics import *
import os
import pickle
import osUtils
import memUtils
import syscallNumbers
import traceback
LIST_POISON2 = object()
def stringFromFrame(frame):
    retval = None
    if frame is not None:
        retval = ''
        for item in frame:
            if item.startswith('param') and frame[item] is not None:
                try:
                    retval = retval + ' %s:0x%x' % (item, frame[item])
                except:
                    print('taskUtils stringFromFrame not an integer in frame[%s]? %s' % (item, str(frame[item])))
    
    return retval
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


COMM_SIZE = 15
class TaskUtils():
    def __init__(self, cpu, cell_name, param, mem_utils, unistd, unistd32, RUN_FROM_SNAP, lgr):
        self.cpu = cpu
        self.cell_name = cell_name
        self.lgr = lgr
        self.param = param
        self.mem_utils = mem_utils
        self.phys_current_task = None
        self.exit_cycles = 0
        self.exit_tid = None
        self.exec_addrs = {}
        self.swapper = None
        self.ia32_gs_base = None

        self.ts_cache = None
        self.ts_cache_cycle = None
  
        self.lgr.debug('TaskUtils init kernel base 0x%x' % param.kernel_base)
        
        if RUN_FROM_SNAP is not None:
            phys_current_task_file = os.path.join('./', RUN_FROM_SNAP, cell_name, 'phys_current_task.pickle')
            if os.path.isfile(phys_current_task_file):
                if not self.param.current_task_fs:
                    value = pickle.load( open(phys_current_task_file, 'rb') ) 
                    if type(value) is int:
                        self.phys_current_task = value
                    else:
                        self.phys_current_task = value['current_task_phys']
                        saved_cr3 = value['saved_cr3']
                        if saved_cr3 is not None:
                            self.lgr.debug('taskUtils, cell %s snapshot had saved cr3, value 0x%x' % (self.cell_name, saved_cr3))
                            #saved_cr3 = SIM_read_phys_memory(self.cpu, self.phys_saved_cr3, self.mem_utils.WORD_SIZE)
                            self.mem_utils.saveKernelCR3(self.cpu, saved_cr3=saved_cr3)
                else:
                    self.phys_current_task = pickle.load( open(phys_current_task_file, 'rb') ) 

            exec_addrs_file = os.path.join('./', RUN_FROM_SNAP, cell_name, 'exec_addrs.pickle')
            if os.path.isfile(exec_addrs_file):
                self.exec_addrs = pickle.load( open(exec_addrs_file, 'rb') ) 
        if self.phys_current_task is None:
            self.lgr.debug('taskUtils phys_currrent_task None')
            ''' address of current_task symbol, pointer at this address points to the current task record '''
            ''' use physical address because some are relative to FS segment '''

            if self.param.current_task_fs:
                phys = cpu.ia32_fs_base + (self.param.current_task-self.param.kernel_base)
            elif self.param.current_task_gs:
                va = cpu.ia32_gs_base + self.param.current_task
                phys = self.mem_utils.v2p(self.cpu, va)
                self.mem_utils.saveKernelCR3(self.cpu)
            else:
                #phys_block = self.cpu.iface.processor_info.logical_to_physical(self.param.current_task, Sim_Access_Read)
                #phys = phys_block.address
                phys = self.mem_utils.v2p(self.cpu, self.param.current_task)
                #if cpu.architecture.startswith('arm'):
                #    phys = self.mem_utils.kernel_v2p(self.param, self.cpu, self.param.current_task)
                #else:
                if phys is not None:
                    pass
                    #self.lgr.debug('TaskUtils init phys of current_task 0x%x is 0x%x' % (self.param.current_task, phys))
                else:
                    self.lgr.error('TaskUtils init phys of current_task 0x%x is None' % self.param.current_task)
                    return None
            if phys is not None:
                self.lgr.debug('taskUtils param.current_task 0x%x phys 0x%x' % (param.current_task, phys))
            else:
                self.lgr.debug('taskUtils param.current_task 0x%x phys is None' % (param.current_task))
            self.phys_current_task = phys

            if self.mem_utils.WORD_SIZE == 4 and self.phys_current_task > 0xffffffff:
                self.lgr.debug('TaskUtils cell %s phys address for 0x%x is too large' % (self.cell_name, param.current_task))
                self.phys_current_task = 0
                return None
            #except:
            #    self.phys_current_task = 0
            #    self.lgr.debug('TaskUtils init failed to get phys addr of 0x%x' % (param.current_task))
            #    return None
        #self.lgr.debug('TaskUtils init cell %s with current_task of 0x%x, phys: 0x%x' % (cell_name, param.current_task, self.phys_current_task))
        self.syscall_numbers = syscallNumbers.SyscallNumbers(unistd, self.lgr)
        if unistd32 is not None:
            self.syscall_numbers32 = syscallNumbers.SyscallNumbers(unistd32, self.lgr)
        else:
            self.syscall_numbers32 = None
        if cpu.architecture == 'arm64':
            self.arm64 = True
        else:
            self.arm64 = False

    def commSize(self):
        return COMM_SIZE

    def getPhysCurrentTask(self):
        return self.phys_current_task

    # match name in winTaskUtils
    def getCurProcRec(self):
        return self.getCurThreadRec()

    def getCurThreadRec(self):
        if self.phys_current_task == 0:
            return 0
        #self.lgr.debug('taskUtils getCurThreadRec read cur_task_rec from phys 0x%x' % self.phys_current_task)
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
        if self.param.current_task_fs:
            pickle.dump( self.phys_current_task, open( phys_current_task_file, "wb" ) )
        else:
            dict_val = {}
            dict_val['current_task_phys'] = self.phys_current_task
            dict_val['saved_cr3'] = self.mem_utils.getKernelSavedCR3()
            pickle.dump(dict_val , open( phys_current_task_file, "wb" ) )
        exec_addrs_file = os.path.join('./', fname, self.cell_name, 'exec_addrs.pickle')
        pickle.dump( self.exec_addrs, open( exec_addrs_file, "wb" ) )

    def curPID(self):
        cur_task_rec = self.getCurThreadRec()
        pid = self.mem_utils.readWord32(self.cpu, cur_task_rec + self.param.ts_pid)
        return pid

    def curTID(self):
        cur_task_rec = self.getCurThreadRec()
        pid = self.mem_utils.readWord32(self.cpu, cur_task_rec + self.param.ts_pid)
        if pid is not None:
            ret_pid = str(pid)
        else:
            ret_pid = None
        return ret_pid

    def curThread(self):
        #self.lgr.debug('taskUtils curThread')
        cur_task_rec = self.getCurThreadRec()
        #self.lgr.debug('taskUtils curThread cur_task_rec 0x%x' % cur_task_rec)
        pid = self.mem_utils.readWord32(self.cpu, cur_task_rec + self.param.ts_pid)
        if pid is None or pid > self.mem_utils.getUnsigned(0xf0000000):
            self.lgr.debug('taskUtils curThread cur_task_rec 0x%x got crazy pid %s, check saved' % (cur_task_rec, str(pid)))
            return None, None, None
            #traceback.print_stack()
            #self.mem_utils.checkSavedCR3(self.cpu)
            #SIM_break_simulation('remove this cur_task_rec 0x%x' % cur_task_rec)
            #self.mem_utils.checkSavedCR3(self.cpu)
            #pid = self.mem_utils.readWord32(self.cpu, cur_task_rec + self.param.ts_pid)
        comm = self.mem_utils.readString(self.cpu, cur_task_rec + self.param.ts_comm, 16)
        #self.lgr.debug('taskUtils curThread comm %s' % comm)
        #self.lgr.debug('taskUtils curThread pid %s' % str(pid))
        #phys = self.mem_utils.v2p(self.cpu, cur_task_rec)
        #self.lgr.debug('taskProc cur_task 0x%x phys 0x%x  pid %d comm: %s  phys_current_task 0x%x' % (cur_task_rec, phys, pid, comm, self.phys_current_task))
        if pid is not None:
            ret_pid = str(pid)
        else:
            ret_pid = None
        return self.cpu, comm, ret_pid

    def findSwapper(self):
        task = None
        retval = None
        cpl = memUtils.getCPL(self.cpu)
        if True: 
            task = self.getCurThreadRec()
            if task is not None:
                done = False
                while not done and task is not None:
                    #self.lgr.debug('taskUtils findSwapper read comm task is 0x%x' % task)
                    comm = self.mem_utils.readString(self.cpu, task + self.param.ts_comm, COMM_SIZE)
                    pid = self.mem_utils.readWord32(self.cpu, task + self.param.ts_pid)
                    #if pid is not None:
                    #    self.lgr.debug('findSwapper task is %x pid:%d com %s' % (task, pid, comm))
                    ts_real_parent = self.mem_utils.readPtr(self.cpu, task + self.param.ts_real_parent)
                    if ts_real_parent == task:
                        if comm is not None and 'swap' in comm:
                            #print 'parent is same as task, done?'
                            #self.lgr.debug('findSwapper real parent same as task, assume done')
                            pass
                        else:
                            #self.lgr.debug('findSwapper real parent same as task, but not swap, bail')
                            task = None
                        done = True
                    else:
                        if ts_real_parent != 0:
                            task = ts_real_parent
                            #self.lgr.debug('findSwapper got 0x%x for ts_real_parent' % task)
                        else:
                            #print 'got zero for ts_real_parent'
                            #SIM_break_simulation('got zero for ts_real parent')
                            #self.lgr.debug('findSwapper got zero for ts_real_parent, callit done')
                            task = None
                            done = True
                self.swapper = task
                retval = task
            else:
                self.lgr.error('taskUtils getCurThreadRec got none')
        return retval    
    
    def is_kernel_virtual(self, addr):
        return addr >= self.param.kernel_base

    def read_list_head(self, cpu, addr, offset, head_addr = None, head_offset = None, other_offset = None):
        addr = self.mem_utils.getUnsigned(addr)
        next = self.mem_utils.readPtr(cpu, addr + offset)
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
            task.comm = self.mem_utils.readString(cpu, addr + self.param.ts_comm, COMM_SIZE)
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
            if task.thread_group.next is not None:
                ''' TBD why off by 4? '''
                #task.thread_group.next = task.thread_group.next + 4
                task.thread_group.next = task.thread_group.next 
        return task

    def getTaskStructs(self):
        if self.cpu.cycles == self.ts_cache_cycle:
            return self.ts_cache
        seen = set()
        tasks = {}
        cpu = self.cpu
        swapper_addr = self.findSwapper() 
        if swapper_addr is None:
            self.lgr.debug('taskUtils getTaskStructs failed to get swapper')
            return tasks
        self.lgr.debug('getTaskStructs using swapper_addr of %x' % swapper_addr)
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
                self.lgr.debug('task_addr None')
                break
            if (task.comm is None or len(task.comm.strip()) == 0) and not (task.pid == 0 and len(stack)==0):
                # cleaner way to know we are done?
                #self.lgr.debug('read task struct for %x got comm of ZIP pid %d next %x' % (task_addr, task.pid, task.next))
                break
                #continue
           
            #else:
            #    self.lgr.debug('read task struct for %x got comm of %s pid %d next %x previous list head reads were for this task' % (task_addr, task.comm, task.pid, task.next))
          
            #self.lgr.debug('reading task struct addr: 0x%x for got comm of %s pid:%d' % (task_addr, task.comm, task.pid))
            tasks[task_addr] = task
            for child in task.children:
                if child:
                    #self.lgr.debug('appending child 0x%x' % child)
                    stack.append((child, task_addr))
    
            if task.real_parent:
                stack.append((task.real_parent, False))
            if self.param.ts_thread_group_list_head != None:
                if task.thread_group.next:
                    ''' TBD more on this thread group hack'''
                    #hack_val = task.thread_group.next - 4
                    hack_val = task.thread_group.next
                    stack.append((hack_val, False))
                    #self.lgr.debug('appending group next 0x%x' % hack_val)
    
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
                        #self.lgr.debug('appending sib 0x%x' % s)

        ''' TBD: why does current task need to be seperately added, does not appear in task walk? '''
        task_rec_addr = self.getCurThreadRec()
        if task_rec_addr not in tasks:
            task = self.readTaskStruct(task_rec_addr, cpu)
            tasks[task_rec_addr] = task

        self.ts_cache_cycle = self.cpu.cycles 
        self.ts_cache = tasks

        return tasks

    def recentExitTid(self):
        return self.exit_tid

    def isExitTid(self, tid):
        retval = False
        etid = self.getExitTid()
        if etid is not None:
            etid = str(etid)
            if '-' in etid:
                if tid == etid:
                    retval = True
            else:
                proc_part = tid.split('-')[0]
                if proc_part == etid:
                    retval = True
        return retval
    def getExitTid(self):
        ''' if we are at or past the point of exit, return the most recently exited tid. 
            TBD, more robust, multiple PIDs? '''
        if self.exit_cycles is not None and self.cpu.cycles >= self.exit_cycles:
            return self.exit_tid
        else:
            return None

    def setExitTid(self, tid):
        self.exit_tid = tid
        self.exit_cycles = self.cpu.cycles
        self.lgr.debug('taskUtils setExitTid tid:%s cycles 0x%x' % (tid, self.exit_cycles))

    def clearExitTid(self):
        self.exit_tid = None
        self.exit_cycles = 0

    def getGroupLeaderTid(self, tid):
        if tid is None:
            return None
        retval = None
        ts_list = self.getTaskStructs()
        try:
            ipid=int(tid)
        except:
            self.lgr.error('taskUtils failed to get integer from %s.  Is this a Linux target with correct parameters?' % tid)
            return None
        for ts in ts_list:
            if ts_list[ts].pid == ipid:
                group_leader = self.mem_utils.readPtr(self.cpu, ts + self.param.ts_group_leader)
                if group_leader != ts:
                    retval = str(self.mem_utils.readWord32(self.cpu, group_leader + self.param.ts_pid))
                else:
                    retval = self.getCommLeaderTid(ts)
                break
        return retval

    def getGroupTids(self, tid):
        retval = {}
        if tid is None:
            self.lgr.error('taskUtils getGroupTids called with tid of None')
            return retval
        leader_tid = self.getGroupLeaderTid(tid)
        # BEWARE uses PIDs and casts tid to pid
        self.lgr.debug('getGroupTids for %s' % leader_tid)
        ts_list = self.getTaskStructs()
        leader_rec = None
        leader_prog = None
        if leader_tid in self.exec_addrs:
            leader_prog = self.exec_addrs[leader_tid].prog_name
        if leader_tid is None:
            self.lgr.debug('taskUtils getGroupTids no leader tid found for tid %s, use self.' % tid)
            leader_tid = tid
        leader_pid = int(leader_tid)
        leader_comm = None
        for ts in ts_list:
            if ts_list[ts].pid == leader_pid:
                leader_rec = ts
                leader_comm = ts_list[ts].comm
                break
        if leader_rec is None:
            self.lgr.debug('taskUtils getGroupTids did not find record for leader pid %d. Assume process exited add self and return' % leader_pid)
            retval[tid]=None
            return retval 
        #self.lgr.debug('getGroupTids leader_tid %s leader_comm: %s leader_rec 0x%x leader_prog %s' % (leader_tid, leader_comm, leader_rec, leader_prog))
        retval[leader_tid] = leader_rec
        decendents = []
        for ts in ts_list:
            #if ts_list[ts].comm != leader_comm:
            #    continue
            if leader_rec == ts:
                continue
            group_leader = self.mem_utils.readPtr(self.cpu, ts + self.param.ts_group_leader)
            this_leader_pid = self.mem_utils.readWord32(self.cpu, group_leader + self.param.ts_pid)
            this_leader_comm = self.mem_utils.readString(self.cpu, group_leader + self.param.ts_comm, COMM_SIZE)
            #self.lgr.debug('getGroupTids tid %s  group leader got %s' % (ts_list[ts].pid, this_leader_pid))
            if this_leader_pid == ts_list[ts].pid:
                # alternate thread management strategy
                group_leader = self.mem_utils.readPtr(self.cpu, ts + self.param.ts_parent)
                this_leader_pid = self.mem_utils.readWord32(self.cpu, group_leader + self.param.ts_pid)
                this_leader_comm = self.mem_utils.readString(self.cpu, group_leader + self.param.ts_comm, COMM_SIZE)
                #self.lgr.debug('getGroupTids TRY AGAIN tid %s  group leader got %s' % (ts_list[ts].pid, this_leader_pid))
            #self.lgr.debug('getGroupTids this_leader_tid %s  leader_pid: %s this_leader_comm %s' % (this_leader_pid, leader_pid, this_leader_comm))
            if (this_leader_pid == leader_pid or this_leader_pid in decendents) and leader_comm == this_leader_comm:
                #self.lgr.debug('getGroupTids tid matches')
                decendents.append(ts_list[ts].pid)
                this_tid = str(ts_list[ts].pid)
                #if str(pid) != self.exit_tid or self.cpu.cycles != self.exit_cycles:
                if not self.isExitTid(this_tid):
                    #retval.append(ts_list[ts].pid)
                    retval[this_tid] = ts
                    #self.lgr.debug('getGroupTids set retval(%d) to 0x%x' % (pid, ts))
        return retval

    def getTidsForComm(self, comm_in, ignore_exits=False):
        comm = os.path.basename(comm_in).strip()
        if len(comm) > COMM_SIZE:
            comm = comm[:COMM_SIZE]
        retval = []
        #self.lgr.debug('getTidsForComm %s' % comm_in)
        ts_list = self.getTaskStructs()
        for ts in ts_list:
            #self.lgr.debug('getTidsForComm compare <%s> to %s  len is %d COMM_SIZE %d' % (comm, ts_list[ts].comm, len(comm), COMM_SIZE))
            #if comm == ts_list[ts].comm or (len(comm)>COMM_SIZE and len(ts_list[ts].comm) == COMM_SIZE and comm.startswith(ts_list[ts].comm)):
            if comm == ts_list[ts].comm:
                tid = str(ts_list[ts].pid)
                #self.lgr.debug('getTidsForComm MATCHED ? %s to %s  tid %s' % (comm, ts_list[ts].comm, tid))
                ''' skip if exiting as recorded by syscall '''
                #if tid != self.exit_tid or (self.cpu.cycles != self.exit_cycles and not ignore_exits):
                if not (self.isExitTid(tid) and ignore_exits):
                    retval.append(tid)
        return retval

    def getTidCommMap(self):
        retval = {}
        ts_list = self.getTaskStructs()
        for ts in ts_list:
            retval[str(ts_list[ts].pid)] = ts_list[ts].comm
        return retval

    def getTidParent(self, tid):
        return_tid = None
        rec = self.getRecAddrForTid(tid)
        if rec is None:
            self.lgr.error('TaskUtils getTidParent got none for tid %s' % tid)
            return None
        parent = self.mem_utils.readPtr(self.cpu, rec + self.param.ts_real_parent)
        pid = self.mem_utils.readWord32(self.cpu, parent + self.param.ts_pid)
        if pid is not None:
            return_tid = str(pid)
        return return_tid 
 
    def getProcRecForTid(self, tid):
        # match windows
        return self.getRecAddrForTid(tid)

    def getRecAddrForTid(self, tid):
        retval = None
        #self.lgr.debug('getRecAddrForTid %s' % tid)
        ts_list = self.getTaskStructs()
        for ts in ts_list:
           #self.lgr.debug('getRecAddrForTid compare %s to %s' % (str(ts_list[ts].pid), tid))
           if str(ts_list[ts].pid) == tid:
               #self.lgr.debug('getRecAddrForTid got it returning ts 0x%x' % ts)
               retval = ts
               break
        if retval is None:
            self.lgr.debug('TaksUtils getRecAddrForTid %s no task rec found. %d task records found.' % (tid, len(ts_list)))
        return retval

    def getCommFromTid(self, tid):
        ts_list = self.getTaskStructs()
        pid = int(tid)
        for ts in ts_list:
           if ts_list[ts].pid == pid:
               return ts_list[ts].comm
        return None
 
    def getTaskListPtr(self, rec=None):
        ''' return address of the task list "next" entry that points to the current task '''
        if rec is None:
            task_rec_addr = self.getCurThreadRec()
        else:
            task_rec_addr = rec
        ts_list = self.getTaskStructs()
        comm = self.mem_utils.readString(self.cpu, task_rec_addr + self.param.ts_comm, COMM_SIZE)
        pid = self.mem_utils.readWord32(self.cpu, task_rec_addr + self.param.ts_pid)
        for ts in ts_list:
            task = ts_list[ts]
            if (task.next) == task_rec_addr or task.next == (task_rec_addr+self.param.ts_next):
                next_addr = ts + self.param.ts_next
                #self.lgr.debug('getTaskListPtr return next 0x%x  pid:%d (%s) task.next is 0x%x' % (next_addr, task.pid, task.comm, task.next))
                return next_addr
        return None

    def getTidCommFromNext(self, next_addr):
        tid = None
        comm = None
        if next_addr is not None:
            rec = next_addr - self.param.ts_next
            comm = self.mem_utils.readString(self.cpu, rec + self.param.ts_comm, COMM_SIZE)
            pid = self.mem_utils.readWord32(self.cpu, rec + self.param.ts_pid)
            if pid is not None:
                tid = str(pid)
        return tid, comm

    def getTidCommFromGroupNext(self, next_addr):
        tid = None
        comm = None
        if next_addr is not None:
            rec = next_addr - self.param.ts_thread_group_list_head
            #self.lgr.debug('taskUtils getTidCommFromGroupNext try rec 0x%x' % rec)
            comm = self.mem_utils.readString(self.cpu, rec + self.param.ts_comm, COMM_SIZE)
            pid = self.mem_utils.readWord32(self.cpu, rec + self.param.ts_pid)
            if pid is not None:
                tid = str(pid)
        return tid, comm

    def currentProcessInfo(self, cpu=None):
        tid = None
        cur_addr = self.getCurThreadRec()
        comm = self.mem_utils.readString(self.cpu, cur_addr + self.param.ts_comm, COMM_SIZE)
        pid = self.mem_utils.readWord32(self.cpu, cur_addr + self.param.ts_pid)
        if pid is not None:
            tid = str(pid)
        return self.cpu, cur_addr, comm, tid

    def getCurrentThreadParent(self):
        tid = None
        cur_addr = self.getCurThreadRec()
        parent = self.mem_utils.readPtr(self.cpu, cur_addr + self.param.ts_real_parent)
        pid = self.mem_utils.readWord32(self.cpu, parent + self.param.ts_pid)
        comm = self.mem_utils.readString(self.cpu, parent + self.param.ts_comm, COMM_SIZE)
        if pid is not None:
            tid = str(pid)
        return tid, comm
               
    def getCommLeaderTid(self, cur_rec): 
        ''' return pid of oldest ancestor having same comm as cur_rec, which may be self'''
        leader_tid = None
        leader_prog = None
        comm = self.mem_utils.readString(self.cpu, cur_rec + self.param.ts_comm, 16)
        leader_pid = self.mem_utils.readWord32(self.cpu, cur_rec + self.param.ts_pid)
        if str(leader_pid) in self.exec_addrs:
            leader_prog = self.exec_addrs[str(leader_pid)].prog_name
        parent = None
        prev_parent = None
        #self.lgr.debug('getCommLeaderTid 0x%x pid:%d (%s) leader_prog %s' % (cur_rec, leader_pid, comm, leader_prog))
        while(True):
            parent = self.mem_utils.readPtr(self.cpu, cur_rec + self.param.ts_real_parent)
            #self.lgr.debug('getCommLeaderTid parent 0x%x' % parent)
            if parent == cur_rec:
                break
            else:
                leader_comm = self.mem_utils.readString(self.cpu, parent + self.param.ts_comm, 16)
                if leader_comm != comm:
                    break
                this_pid = self.mem_utils.readWord32(self.cpu, parent + self.param.ts_pid)
                this_prog = None
                if str(this_pid) in self.exec_addrs:
                    this_prog = self.exec_addrs[str(this_pid)].prog_name
                if this_prog == leader_prog:
                    leader_pid = this_pid
                    #self.lgr.debug('getCommLeaderTid new leader? parent pid %d comm %s prog is %s' % (leader_pid, leader_comm, this_prog))
            cur_rec = parent
        if leader_pid is not None:
            leader_tid = str(leader_pid)
        #self.lgr.debug('getCommLeaderTid returning %s' % leader_tid)
        return leader_tid

    def getCurrentThreadLeaderTid(self):
        ''' NOT really.  Our notion of leader includes parent of procs that were cloned.  Modern linux does not use
            group_leader if distinct processes '''
        leader_tid = None
        cur_rec = self.getCurThreadRec()
        group_leader = self.mem_utils.readPtr(self.cpu, cur_rec + self.param.ts_group_leader)
        leader_pid = self.mem_utils.readWord32(self.cpu, group_leader + self.param.ts_pid)
        #self.lgr.debug('getCurrentThreadLeaderTid cur_rec 0x%x  group_leader 0x%x' % (cur_rec, group_leader))
        if group_leader == cur_rec:
            leader_pid = self.getCommLeaderTid(cur_rec)
        if leader_pid is not None:
            leader_tid = str(leader_pid)
        return leader_tid

    def getMemUtils(self):
        return self.mem_utils

    def getExecProgAddr(self, tid, cpu):
        return self.exec_addrs[tid].prog_addr

    def modExecParam(self, tid, cpu, dmod):
        for arg_addr in self.exec_addrs[tid].arg_addr_list:
            if dmod.checkString(cpu, arg_addr, 100):
                SIM_break_simulation('modified execve param')
     
    def readExecParamStrings(self, tid, cpu):
        self.lgr.debug('readExecParamStrings with tid %s' % tid)
        if tid is None:
            self.lgr.debug('readExecParamStrings called with tid of None')
            return None, None, None
        if tid not in self.exec_addrs:
            self.lgr.debug('readExecParamStrings called with unknown tid %s' % tid)
            return None, None, None
        arg_string_list = []
        prog_string = self.mem_utils.readString(cpu, self.exec_addrs[tid].prog_addr, 512)
        if prog_string is not None:
            prog_string = prog_string.strip()
            self.lgr.debug('readExecParamStrings got prog_string of %s from 0x%x' % (prog_string, self.exec_addrs[tid].prog_addr))
            for arg_addr in self.exec_addrs[tid].arg_addr_list:
                arg_string = self.mem_utils.readString(cpu, arg_addr, 512)
                if arg_string is not None:
                    arg_string_list.append(arg_string.strip())
                    #self.lgr.debug('readExecParamStrings adding arg %s' % (arg_string))

            prog_string = prog_string.strip()
            self.exec_addrs[tid].prog_name = prog_string
            self.exec_addrs[tid].arg_list = arg_string_list
        else:
            if self.exec_addrs[tid].prog_addr is not None:
                self.lgr.debug('readExecParamStrings got none from 0x%x ' % self.exec_addrs[tid].prog_addr)
            else:
                self.lgr.debug('readExecParamStrings prog_addr for tid %s is None???' % (tid))
        return prog_string, arg_string_list

    def getProcArgsFromStack(self, tid, at_enter, cpu):
        ''' NOTE side effect of populating exec_addrs '''
        # Poor name.  Some come from regs depending on if we are at entry or computed
        if tid is None:
            return None, None
        #self.lgr.debug('getProcArgsFromStack tid:%s at_enter %r' % (tid, at_enter))
        mult = 0
        done = False
        arg_addr_list = []
        limit = 15
        i=0
        prog_addr = None
        if self.mem_utils.WORD_SIZE == 4:
            #self.lgr.debug('getProcArgsFromStack word size 4')
            if cpu.architecture.startswith('arm'):
                if cpu.architecture == 'arm':
                    prog_addr = self.mem_utils.getRegValue(cpu, 'r0')
                    argv = self.mem_utils.getRegValue(cpu, 'r1')
                else:
                    prog_addr = self.mem_utils.getRegValue(cpu, 'x0')
                    argv = self.mem_utils.getRegValue(cpu, 'x1')
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
            elif cpu.architecture.startswith('ppc32'):
                prog_addr = self.mem_utils.getRegValue(cpu, 'r3')
                argv = self.mem_utils.getRegValue(cpu, 'r4')
                while not done and i < limit:
                    xaddr = argv + mult*self.mem_utils.WORD_SIZE
                    arg_addr = self.mem_utils.readPtr(cpu, xaddr)
                    if arg_addr is not None and arg_addr != 0:
                       arg_addr_list.append(arg_addr)
                    else:
                       done = True
                    mult = mult + 1
                    i = i + 1
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
                self.lgr.error('getProcArgsFromStack tid: %s esp: 0x%x argv 0x%x prog_addr 0x%x' % (tid, esp, argv, prog_addr))
        elif self.cpu.architecture == 'arm64':
            arm64_app = self.mem_utils.arm64App(self.cpu)
            if at_enter:
                if arm64_app:
                    prog_reg = 'x0'
                    arg_reg = 'x1'
                    addr_size = 8
                    #self.lgr.debug('getProcArgsFromStack is arm 64 bit app')
                else:
                    prog_reg = 'r0'
                    arg_reg = 'r1'
                    addr_size = 4
                    #self.lgr.debug('getProcArgsFromStack is arm 32 bit app')
                prog_addr = self.mem_utils.getRegValue(cpu, prog_reg)
                argv = self.mem_utils.getRegValue(cpu, arg_reg)
                #self.lgr.debug('getProcArgsFromStack prog_addr 0x%x  argv 0x%x' % (prog_addr, argv))

            else:
                x0 = self.mem_utils.getRegValue(self.cpu, 'x0')
                prog_addr = self.mem_utils.readPtr(cpu, x0)
                argv = self.mem_utils.readPtr(cpu, (x0+8))
                addr_size = 8
                #self.lgr.debug('getProcArgsFromStack ARM64 at computed, prog_addr 0x%x argv 0x%x' % (prog_addr, argv))
                
            while not done and i < limit:
                #xaddr = argv + mult*self.mem_utils.WORD_SIZE
                xaddr = argv + mult*addr_size
                arg_addr = self.mem_utils.readAppPtr(cpu, xaddr, size=addr_size)
                if arg_addr is not None and arg_addr != 0:
                   #self.lgr.debug("getProcArgsFromStack ARM64 (%d byte app) adding arg addr %x read from 0x%x" % (addr_size, arg_addr, xaddr))
                   arg_addr_list.append(arg_addr)
                else:
                   done = True
                mult = mult + 1
                i = i + 1
        else:
            #self.lgr.debug('getProcArgsFromStack word size 8')
            # if swap, use rdx
            if not at_enter and self.param.x86_reg_swap:
                use_reg = 'rdx'
            else:
                use_reg = 'rsi'
            reg_num = cpu.iface.int_register.get_number(use_reg)
            reg_val = cpu.iface.int_register.read(reg_num)
            prog_addr = self.mem_utils.readPtr(cpu, reg_val)
            #if prog_addr is not None:
            #    self.lgr.debug('getProcArgsFromStack 64 bit reg_val is 0x%x prog_addr 0x%x' % (reg_val, prog_addr))
            #else:
            #    self.lgr.debug('getProcArgsFromStack 64 bit reg_val is 0x%x prog_addr None' % (reg_val))
            i=0
            done = False
            while not done and i < 30:
                reg_val = reg_val+self.mem_utils.WORD_SIZE
                arg_addr = self.mem_utils.readPtr(cpu, reg_val)
                if arg_addr != 0:
                    #self.lgr.debug("getProcArgsFromStack adding arg addr %x read from 0x%x" % (arg_addr, reg_val))
                    arg_addr_list.append(arg_addr)
                else:
                    done = True
                i += 1
     

        #xaddr = argv + 4*self.mem_utils.WORD_SIZE
        #arg2_addr = memUtils.readPtr(cpu, xaddr)
        #print 'arg2 esp is %x sptr at %x  argv %x xaddr %x saddr %x string: %s ' % (esp, sptr, 
        #     argv, xaddr, saddr, arg2_string)


        self.lgr.debug('getProcArgsFromStack prog_addr 0x%x' % prog_addr)
        self.exec_addrs[tid] = osUtils.execStrings(cpu, tid, arg_addr_list, prog_addr, None)
        prog_string, arg_string_list = self.readExecParamStrings(tid, cpu)
        self.exec_addrs[tid].prog_name = prog_string
        self.exec_addrs[tid].arg_list = arg_string_list
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

    def getProgName(self, tid):
        if tid not in self.exec_addrs:
            tid = self.getGroupLeaderTid(tid)
        if tid in self.exec_addrs:
            return self.exec_addrs[tid].prog_name, self.exec_addrs[tid].arg_list
        else: 
            self.lgr.debug('taskUtils getProgName tid %s not in exec_addrs' % tid)
            return None, None

    def getProgNameFromComm(self, comm):
        for tid in self.exec_addrs:
            if self.exec_addrs[tid].prog_name.endswith(comm):
                return self.exec_addrs[tid].prog_name
        return None

    def swapExecTid(self, old, new):
        if old in self.exec_addrs and new in self.exec_addrs:
            self.exec_addrs[new] = self.exec_addrs[old]
            self.exec_addrs[new].tid = new
            del self.exec_addrs[old]
            self.lgr.debug('taskUtils, swapExecTid set exec tid from %s to %s  TBD deep copy/delete' % (old, new))
        else:
            self.lgr.error('taskUtils, swapExecTid some tid not in exec_addrs?  %s to %s  ' % (old, new))
 
    def getSyscallEntry(self, callnum, compat32, arm64_app=None):
        if callnum is None:
            self.lgr.error('taskUtils getSyscallEntry called with callnum of None')
            return None
        if self.cpu.architecture == 'arm':
            val = callnum * self.mem_utils.WORD_SIZE + self.param.syscall_jump
            val = self.mem_utils.getUnsigned(val)
            entry = self.mem_utils.readPtr(self.cpu, val)
            #self.lgr.debug('getSyscallEntry syscall_jump 0x%x callnum %d (0x%x), val 0x%x, entry: 0x%x' % (self.param.syscall_jump, callnum, callnum, val, entry))
        elif self.cpu.architecture == 'arm64':
            #         'ldr x1, [x22, x20, lsl #3]'
            if arm64_app is None:
                self.lgr.debug('taskUtils getSyscallEntry with arm64_app of None')
                arm64_app = self.mem_utils.arm64App(self.cpu)
            call_shifted = callnum << 3
            if arm64_app:
                val = self.param.syscall64_jump + call_shifted
            else:
                val = self.param.syscall_jump + call_shifted
            val = self.mem_utils.getUnsigned(val)
            entry = self.mem_utils.readPtr(self.cpu, val)
            #if entry is not None:
            #    self.lgr.debug('getSyscallEntry arm64 callnum %d (0x%x), val 0x%x, entry: 0x%x' % (callnum, callnum, val, entry))
            #else:
            #    self.lgr.error('getSyscallEntry arm64 callnum %d (0x%x), val 0x%x, entry is none' % (callnum, callnum, val))
                 
        elif self.cpu.architecture == 'ppc32':
            call_shifted = callnum << 2
            val = call_shifted + self.param.syscall_jump
            val = self.mem_utils.getUnsigned(val)
            entry = self.mem_utils.readPtr(self.cpu, val)
            self.lgr.debug('getSyscallEntry call 0x%x entry 0x%x' % (callnum, entry))
    
        elif not compat32:
            ''' compute the entry point address for a given syscall using constant extracted from kernel code '''
            val = callnum * self.mem_utils.WORD_SIZE - self.param.syscall_jump
            val = self.mem_utils.getUnsigned(val)
            entry = self.mem_utils.readPtr(self.cpu, val)
        else:
            val = callnum * self.mem_utils.WORD_SIZE - self.param.compat_32_jump
            val = self.mem_utils.getUnsigned(val)
            entry = self.mem_utils.readPtr(self.cpu, val)
        #self.lgr.debug('getSyscallEntry call 0x%x val 0x%x entry 0x%x syscall_jump 0x%x' % (callnum, val,entry, self.param.syscall_jump))
        return entry

    def frameFromStackSyscall(self):
        #reg_num = self.cpu.iface.int_register.get_number(self.mem_utils.getESP())
        #esp = self.cpu.iface.int_register.read(reg_num)
        if self.cpu.architecture.startswith('arm'):
            frame = self.frameFromRegs()
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
        retval = {}
        phys_addr = self.mem_utils.v2p(cpu, v_addr)
        #self.lgr.debug('getFrame, v_addr: 0x%x  phys_addr: 0x%x' % (v_addr, phys_addr))
        if phys_addr is not None:
            try:
                retval['param1'] = SIM_read_phys_memory(cpu, phys_addr, self.mem_utils.WORD_SIZE)
                retval['param2'] = SIM_read_phys_memory(cpu, phys_addr+self.mem_utils.WORD_SIZE, self.mem_utils.WORD_SIZE)
                retval['param3'] = SIM_read_phys_memory(cpu, phys_addr+2*self.mem_utils.WORD_SIZE, self.mem_utils.WORD_SIZE)
                retval['param4'] = SIM_read_phys_memory(cpu, phys_addr+3*self.mem_utils.WORD_SIZE, self.mem_utils.WORD_SIZE)
                retval['param5'] = SIM_read_phys_memory(cpu, phys_addr+4*self.mem_utils.WORD_SIZE, self.mem_utils.WORD_SIZE)
                retval['param6'] = SIM_read_phys_memory(cpu, phys_addr+5*self.mem_utils.WORD_SIZE, self.mem_utils.WORD_SIZE)
                retval['pc'] = SIM_read_phys_memory(cpu, phys_addr+22*self.mem_utils.WORD_SIZE, self.mem_utils.WORD_SIZE)
                retval['sp'] = SIM_read_phys_memory(cpu, phys_addr+25*self.mem_utils.WORD_SIZE, self.mem_utils.WORD_SIZE)
            except:
                self.lgr.error('taskUtils getFrame error reading stack from starting at 0x%x' % v_addr)
        return retval

    def frameArm64Computed(self):
        frame = {}
        addr = self.mem_utils.getRegValue(self.cpu, 'x0')
        for p in memUtils.param_map['arm64']:
            frame[p] = self.mem_utils.readWord(self.cpu, addr)
            addr = addr + 8
        frame['sp'] = self.mem_utils.getRegValue(self.cpu, 'x13')
        frame['lr'] = self.mem_utils.getRegValue(self.cpu, 'x14')
        return frame

    def frameFromRegs(self, compat32=False):
        frame = {}
        if self.cpu.architecture == ('arm') or (self.cpu.architecture == 'arm64' and not self.mem_utils.arm64App(self.cpu)):
            for p in memUtils.param_map['arm']:
                frame[p] = self.mem_utils.getRegValue(self.cpu, memUtils.param_map['arm'][p])
            cpl = memUtils.getCPL(self.cpu)
            if cpl == 0:
                frame['sp'] = self.mem_utils.getRegValue(self.cpu, 'sp_usr')
                frame['pc'] = self.mem_utils.getRegValue(self.cpu, 'lr')
                frame['lr'] = self.mem_utils.getRegValue(self.cpu, 'lr_usr')
            else:
                frame['sp'] = self.mem_utils.getRegValue(self.cpu, 'sp')
                frame['pc'] = self.mem_utils.getRegValue(self.cpu, 'pc')
                frame['lr'] = self.mem_utils.getRegValue(self.cpu, 'lr')
        elif self.cpu.architecture == ('arm64'):
            # arm64 64 bit app
            # only works on entry
            for p in memUtils.param_map['arm64']:
                frame[p] = self.mem_utils.getRegValue(self.cpu, memUtils.param_map['arm64'][p])
            #frame['sp'] = self.mem_utils.getRegValue(self.cpu, 'x13')
            frame['sp'] = self.mem_utils.getRegValue(self.cpu, 'sp')
            frame['lr'] = self.mem_utils.getRegValue(self.cpu, 'lr')
            frame['pc'] = self.mem_utils.getRegValue(self.cpu, 'pc')
        elif self.cpu.architecture == ('ppc32'):
            for p in memUtils.param_map['ppc32']:
                frame[p] = self.mem_utils.getRegValue(self.cpu, memUtils.param_map['ppc32'][p])
            frame['sp'] = self.mem_utils.getRegValue(self.cpu, 'r1')
            frame['lr'] = self.mem_utils.getRegValue(self.cpu, 'lr')
            frame['pc'] = self.mem_utils.getRegValue(self.cpu, 'pc')
        else:
            frame['sp'] = self.mem_utils.getRegValue(self.cpu, 'sp')
            frame['pc'] = self.mem_utils.getRegValue(self.cpu, 'pc')
            if self.mem_utils.WORD_SIZE == 8 and not compat32:
                map_id = 'x86_64'
                #self.lgr.debug('taskUtils frameFromRegs pc 0x%x sysenter 0x%x' % (frame['pc'], self.param.sysenter))
                if self.param.x86_reg_swap and frame['pc'] != self.param.sysenter:
                    map_id = 'x86_64swap'
                    # TBD Very odd way to load parameters.
                    offset = 0x70
                    rdi = self.mem_utils.getRegValue(self.cpu, 'rdi')
                    addr = rdi+offset
                    for p in memUtils.param_map[map_id]:
                        frame[p] = self.mem_utils.readWord(self.cpu, addr)
                        if p == 'param4':
                            addr = addr - 0x10
                        else:
                            addr = addr - 8
                else:
                    for p in memUtils.param_map[map_id]:
                        frame[p] = self.mem_utils.getRegValue(self.cpu, memUtils.param_map[map_id][p])
        
            else:
                for p in memUtils.param_map['x86_32']:
                    frame[p] = self.mem_utils.getRegValue(self.cpu, memUtils.param_map['x86_32'][p])
        
        return frame

    def socketCallName(self, callname, compat32):
        if not self.cpu.architecture.startswith('arm') and (self.mem_utils.WORD_SIZE != 8 or compat32):
            return ['socketcall']
        elif callname == 'accept':
            return ['accept', 'accept4']
        else:
            return [callname]

    def syscallName(self, callnum, compat32):
        if self.arm64:
            #self.lgr.debug('taskUtils syscallName for num %d' % callnum)
            if self.mem_utils.arm64App(self.cpu):
                if callnum in self.syscall_numbers.syscalls:
                    return self.syscall_numbers.syscalls[callnum]
                else:
                    return 'not_mapped'
            else:
                if self.syscall_numbers32 is None:
                    self.lgr.warning('taskUtils syscallName is 32bit app but no 32 bit call numbers defined in ini file')
                    return 'not_mapped'
                elif callnum in self.syscall_numbers32.syscalls:
                    return self.syscall_numbers32.syscalls[callnum]
                else:
                    return 'not_mapped'
                
        elif not compat32:
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
            return 'not_mapped'
        return 'not_mapped'

    def syscallNumber(self, callname, compat32, arm64_app=None):
        if self.arm64:
            if arm64_app is None:
                arm64_app = self.mem_utils.arm64App(self.cpu)
            if arm64_app:
               if callname in self.syscall_numbers.callnums:
                   return self.syscall_numbers.callnums[callname]
               else:
                   self.lgr.debug('taskUtils syscallNumber %s not in callnums' % callname)
                   return -1
            else:
                if callname in self.syscall_numbers32.callnums:
                    return self.syscall_numbers32.callnums[callname]
                else:
                    self.lgr.debug('taskUtils syscallNumber %s not in callnums32' % callname)
                    return -1
        elif not compat32:
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

    def getIds(self, address, hack=False):
        #uid_addr = address + 16
        uid_addr = address 
        uid = self.mem_utils.readWord32(self.cpu, uid_addr)
        if uid is not None:
            self.lgr.debug('getIDs address 0x%x uid_addr 0x%x read 0x%x' % (address, uid_addr, uid))
        else:
            self.lgr.debug('getIDs address 0x%x uid_addr 0x%x got None' % (address, uid_addr))

        #e_uid_addr = address + 32
        if not hack:
            e_uid_addr = address + 16
        else:
            e_uid_addr = address + 8
        e_uid = self.mem_utils.readWord32(self.cpu, e_uid_addr)
        if e_uid is not None:
            self.lgr.debug('getIDs address 0x%x e_uid_addr 0x%x read 0x%x' % (address, e_uid_addr, e_uid))
        else:
            self.lgr.debug('getIDs address 0x%x e_uid_addr 0x%x got None' % (address, e_uid_addr))
        return uid, e_uid


    def getCred(self, task_addr=None):
        if task_addr is None:
            cur_addr = self.getCurThreadRec()
        else:
            cur_addr = task_addr
        cred_offset = self.param.ts_comm - 2*self.mem_utils.WORD_SIZE
        real_cred_addr = cur_addr + cred_offset
        #cred_addr = cur_addr + (self.param.ts_comm - self.mem_utils.WORD_SIZE)
        read_value = self.mem_utils.readPtr(self.cpu, real_cred_addr) 
        #self.lgr.debug('getCred cur_addr 0x%x cred_offset 0x%x read_value 0x%x' % (cur_addr, cred_offset, read_value))
        hack=False
        if not self.mem_utils.isKernel(read_value):
            # hack TBD.  Add logic to getKernelParams to sort out where the creds are
            real_cred_addr = real_cred_addr - 2*self.mem_utils.WORD_SIZE - 0x10
            read_value = self.mem_utils.readPtr(self.cpu, real_cred_addr) 
            self.lgr.debug('getCred read value bad, try addr - 4 0x%x got value 0x%x' % (real_cred_addr, read_value))
            if not self.mem_utils.isKernel(read_value):
                self.lgr.warning('taskUtils, failed to find cred.')
                return None, None
            real_cred_struct = read_value + 5*self.mem_utils.WORD_SIZE
            hack=True
        else:
            real_cred_struct = read_value + self.mem_utils.WORD_SIZE
        #self.lgr.debug('getCred cur_addr 0x%x cred_offset 0x%x real_cred_addr 0x%x, real_cred_struct 0x%x' % (cur_addr, cred_offset, real_cred_addr, real_cred_struct))
        uid, eu_id = self.getIds(real_cred_struct, hack)
        return uid, eu_id


    #def getTidAndThread(self):
    #    dum, dum1, pid = self.curThread()
    #    retval = '%d' % (pid)
    #    return retval

    def getTidFromThreadRec(self, thread_rec):
        pid = self.mem_utils.readWord32(self.cpu, thread_rec + self.param.ts_pid)
        tid = '%d' %(pid)
        return tid

    def getTidCommFromThreadRec(self, thread_rec):
        pid = self.mem_utils.readWord32(self.cpu, thread_rec + self.param.ts_pid)
        comm = self.mem_utils.readWord32(self.cpu, thread_rec + self.param.ts_comm)
        tid = '%d' %(pid)
        return tid, comm

    def getTidList(self):
        task_list = self.getTaskStructs()
        tid_list = []
        for t in task_list:
            tid_list.append(str(task_list[t].pid))
        return tid_list

    def didClone(self, parent_tid, new_tid):
        #self.lgr.debug('taskUtils didClone parent %s new %s' % (parent_tid, new_tid))
        if parent_tid in self.exec_addrs and new_tid not in self.exec_addrs:
            self.exec_addrs[new_tid] = self.exec_addrs[parent_tid]
            self.lgr.debug('taskUtils didClone recorded clone of new tid %s in exec_addres' % (new_tid))
            
    def getTIB(self):
        va = 0xdeadbeef
        self.lgr.debug('taskUtils getTIB TBD fix this')
        return va

    def getTaskList(self):
        task_list = self.getTaskStructs()
        retval = []
        for t in task_list:
            retval.append(t)
        return retval

    def progComm(self, prog_string):
        prog_comm = os.path.basename(prog_string)[:self.commSize()]
        return prog_comm
