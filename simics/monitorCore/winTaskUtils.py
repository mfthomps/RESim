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
Windows task information, e.g., task lists.
'''
from simics import *
import os
import pickle
import json
import osUtils
import memUtils
import pageUtils
import w7Params
import taskUtils
import winSocket
class TaskStruct():
    def __init__(self, pid, comm):
        self.pid = pid
        self.comm = comm
        ''' TBD fix for windows so we know who is waiting in the kernel when setting exit haps'''
        self.state = 0

class WinTaskUtils():
    THREAD_ID_OFFSET = 0x3c0
    def __init__(self, cpu, cell_name, param, mem_utils, run_from_snap, lgr):
        self.cpu = cpu
        self.cell_name = cell_name
        self.lgr = lgr
        self.param = param
        self.mem_utils = mem_utils
        self.run_from_snap = run_from_snap
        self.phys_current_task = None
        # physical address of where to find the cr3 value
        self.phys_saved_cr3 = None

        self.program_map = {}
        self.exit_cycles = 0
        self.exit_pid = 0

        resim_dir = os.getenv('RESIM_DIR')
        self.call_map = {}
        self.call_num_map = {}
        w7mapfile = os.path.join(resim_dir, 'windows', 'win7.json')
        if os.path.isfile(w7mapfile):
            cm = json.load(open(w7mapfile))     
            for call in cm:
                self.call_map[int(call)] = cm[call] 
                ''' drop Nt prefix'''
                self.call_num_map[cm[call][2:]] = int(call)
        else:
            self.lgr.error('WinTaskUtils cannot open %s' % w7mapfile)
            return

        if run_from_snap is not None:
            phys_current_task_file = os.path.join('./', run_from_snap, cell_name, 'phys_current_task.pickle')
            if os.path.isfile(phys_current_task_file):
                value = pickle.load( open(phys_current_task_file, 'rb') ) 
                if type(value) is int:
                    self.phys_current_task = value
                    gs_base = self.cpu.ia32_gs_base
                    self.phys_saved_cr3 = gs_base+self.param.saved_cr3
                    self.lgr.debug('winTaskUtils, snapshop lacked saved cr3, use value computed from param saved_cr3 0x%x to 0x%x' % (self.param.saved_cr3, self.phys_saved_cr3))
                else:
                    self.phys_current_task = value['current_task_phys']
                    self.phys_saved_cr3 = value['saved_cr3_phys']
                    self.lgr.debug('winTaskUtils, snapshop had saved cr3, value 0x%x' % self.phys_saved_cr3)
                saved_cr3 = SIM_read_phys_memory(self.cpu, self.phys_saved_cr3, self.mem_utils.WORD_SIZE)
                self.mem_utils.saveKernelCR3(self.cpu, saved_cr3)

                self.lgr.debug('loaded phys_current_task from %s' % phys_current_task_file)
                self.lgr.debug('value 0x%x' % self.phys_current_task)
            else:
                ''' temporary hack TBD '''
                self.lgr.debug('winTaskUtils, no phys_current_task.pickle file, temporary hack.  fix this')
                pfile = os.path.join(self.run_from_snap, 'phys.pickle')
                if os.path.isfile(pfile):
                    value = pickle.load(open(pfile, 'rb'))
                    if type(value) is int:
                        self.phys_current_task = value
                        gs_base = self.cpu.ia32_gs_base
                        self.phys_saved_cr3 = gs_base+self.param.saved_cr3
                        self.lgr.debug('winTaskUtils, hacked snapshop lacked saved cr3, use value computed from param saved_cr3 0x%x to 0x%x' % (self.param.saved_cr3, self.phys_saved_cr3))
                        self.lgr.debug('winTaskUtils loaded only phys_current_task, value 0x%x' % value)
                    else:
                        self.phys_current_task = value['current_task_phys']
                        self.phys_saved_cr3 = value['saved_cr3_phys']
                        self.lgr.debug('winTaskUtils loaded phys_current_task value 0x%x and saved_cr3 0x%x' % (self.phys_current_task, 
                           self.phys_saved_cr3))
                    saved_cr3 = SIM_read_phys_memory(self.cpu, self.phys_saved_cr3, self.mem_utils.WORD_SIZE)
                    self.mem_utils.saveKernelCR3(self.cpu, saved_cr3)
                else:
                    self.lgr.error('winTaskUtils did not find %s' % pfile)
                    return

            exec_addrs_file = os.path.join('./', run_from_snap, cell_name, 'exec_addrs.pickle')
            if os.path.isfile(exec_addrs_file):
                self.program_map = pickle.load( open(exec_addrs_file, 'rb') ) 

    def commSize(self):
        return 14

    def getPhysCurrentTask(self):
        return self.phys_current_task

    def getCurTaskRecPhys(self):
        retval = None
        cur_thread = SIM_read_phys_memory(self.cpu, self.phys_current_task, self.mem_utils.WORD_SIZE)
        if cur_thread is None:
            self.lgr.error('winTaskUtils getCurTaskRecPhys got cur_thread of None reading 0x%x' % self.phys_current_task)
        else:
            ptr = cur_thread + self.param.proc_ptr
            retval = self.mem_utils.v2p(self.cpu, ptr)
            '''
            saved_cr3 = SIM_read_phys_memory(self.cpu, self.phys_saved_cr3, self.mem_utils.WORD_SIZE)
            self.lgr.debug('winTaskUtils getCurTaskRecPhys phys_saved_cr3  0x%x saved_cr3 0x%x' % (self.phys_saved_cr3, saved_cr3))
            pt = pageUtils.findPageTable(self.cpu, ptr, self.lgr, force_cr3=saved_cr3)
            self.lgr.debug('winTaskUtils getCurTaskRecPhys got pt.page_addr 0x%x' % pt.page_addr)
            cur_proc_linear = SIM_read_phys_memory(self.cpu, pt.page_addr, self.mem_utils.WORD_SIZE)
            self.lgr.debug('winTaskUtils getCurTaskRecPhys got cur_proc linear 0x%x' % cur_proc_linear)
            pt = pageUtils.findPageTable(self.cpu, cur_proc_linear, self.lgr, force_cr3=saved_cr3)
            retval = pt.page_addr
            if retval is None:
                self.lgr.error('winTaskUtils getCurTaskRecPhys got None from page table 0x%x ptr 0x%x phys_current is 0x%x' % (cur_thread, ptr, self.phys_current_task))
            else:
                self.lgr.debug('winTaskUtils getCurTaskRecPhys got cur proc 0x%x' % retval)
                pass
            '''
                
        return retval

    def getCurThreadRec(self):
        cur_thread_rec = SIM_read_phys_memory(self.cpu, self.phys_current_task, self.mem_utils.WORD_SIZE)
        return cur_thread_rec

    def getCurThread(self, rec=None):
        if rec == None:
            rec = self.getCurThreadRec()
        ptr = rec + self.THREAD_ID_OFFSET
        retval = self.mem_utils.readWord32(self.cpu, ptr)
        return retval

    def getCurTaskRec(self, cur_thread_in=None):
        retval = None
        if cur_thread_in is None:
            cur_thread = SIM_read_phys_memory(self.cpu, self.phys_current_task, self.mem_utils.WORD_SIZE)
            cur_thread = self.mem_utils.getUnsigned(cur_thread)
        else:
            cur_thread = cur_thread_in

        if cur_thread is None:
            self.lgr.error('winTaskUtils getCurTaskRec got cur_thread of None reading 0x%x' % self.phys_current_task)
        else:
            #self.lgr.debug('winTaskUtils getCurTaskRec got cur_thread 0x%x reading 0x%x' % (cur_thread, self.phys_current_task))
            ptr = cur_thread + self.param.proc_ptr
            ptr_phys = self.mem_utils.v2p(self.cpu, ptr)
            #self.lgr.debug('winTaskUtils getCurTaskRec got ptr_phys 0x%x reading ptr 0x%x (cur_thread + 0x%x' % (ptr_phys, ptr, self.param.proc_ptr))

            if ptr_phys is not None:
                retval = SIM_read_phys_memory(self.cpu, ptr_phys, self.mem_utils.WORD_SIZE)
            else:
                self.lgr.error('winTaskUtils getCurTaskRec failed getting phys address for ptr 0x%x  cur_thread: 0x%x  phys_current_task: 0x%x' % (ptr, cur_thread, self.phys_current_task))
                if cur_thread_in is not None:
                    self.lgr.debug('cur_thread passed in as 0x%x' % cur_thread_in)
                SIM_break_simulation('remove this')
                pass
        if retval is not None:
            retval = self.mem_utils.getUnsigned(retval)
            #self.lgr.debug('winTaskUtils getCurTaskRec returning 0x%x' % retval)
        return retval

    def getMemUtils(self):
        return self.mem_utils

    def syscallNumber(self, call, dumb=None):
        retval = None
        if call not in self.call_num_map:
            if call in winSocket.op_map_vals:
                retval = self.call_num_map['DeviceIoControlFile'] 
            else:
                self.lgr.warning('winTaskUtils, no map for call %s' % call)
        else:
            retval = self.call_num_map[call]
        return retval 

    def syscallName(self, call_num, dumb=None):
        retval = None
        if call_num not in self.call_map:
            self.lgr.warning('winTaskUtils, no map for call number %d' % call_num)
        else:
            retval = self.call_map[call_num][2:]
        return retval 

    def getSyscallEntry(self, callnum, compat32=False):
        ''' given a call number, compute the address of the kernel code that handles the call
            based on observations made walking the instructions that follow syscall entry.''' 
        # looks like  cs:0xfffff800034f1e1d p:0x0034f1e1d  movsx r11,dword ptr [r10+rax*4]
        #             cs:0xfffff800034f1e24 p:0x0034f1e24  sar r11,4
        #             cs:0xfffff800034f1e28 p:0x0034f1e28  add r10,r11
        #                                          ....    call r10
        # syscall_jump is the r10 value.  TBD, this may change based on different call tables, e.g., 
        # windows has separate gui calls?  
        val = callnum * 4 + self.param.syscall_jump
        val = self.mem_utils.getUnsigned(val)
        #self.lgr.debug('winTaskUtils getSyscallEntry syscall_jump 0x%x  val 0x%x  callnum %d' % (self.param.syscall_jump, val, callnum))
        entry = self.mem_utils.readPtr(self.cpu, val)
        if entry is None:
            self.lgr.error('winTaskUtils getSyscallEntry entry is None reading from 0x%x' % val)
            SIM_break_simulation('remove this')
            return None
        entry = entry & 0xffffffff
        entry_shifted = entry >> 4
        computed = self.param.syscall_jump + entry_shifted
        #self.lgr.debug('winTaskUtils getSyscallEntry call 0x%x val 0x%x entry 0x%x entry_shifted 0x%x computed 0x%x' % (callnum, val, entry, entry_shifted, computed))
        return computed

    def curProcXX(self):
        pid = None
        comm = None
        cur_proc = self.getCurTaskRec()
        if cur_proc is None:
            self.lgr.error('winTaskUtils curProc gotNone from getCurTaskRec')
            return None, None, None
        pid_ptr = cur_proc + self.param.ts_pid
        pid = self.mem_utils.readWord(self.cpu, pid_ptr)
        if pid is not None:
            #self.lgr.debug('getCurPid cur_proc, 0x%x pid_offset %d pid_ptr 0x%x pid %d' % (cur_proc, self.param.ts_pid, pid_ptr, pid))
            comm = self.mem_utils.readString(self.cpu, cur_proc+self.param.ts_comm, 16)
        else:
            self.lgr.debug('getCurPid cur_thread is None')
        return self.cpu, comm, pid

    def curProc(self):
        #self.lgr.debug('taskUtils curProc')
        cur_task_rec = self.getCurTaskRec()
        #self.lgr.debug('taskUtils curProc cur_task_rec 0x%x' % cur_task_rec)
        if cur_task_rec is None:
            return None, None, None
        comm = self.mem_utils.readString(self.cpu, cur_task_rec + self.param.ts_comm, 16)
        #self.lgr.debug('taskUtils curProc comm %s' % comm)
        pid = self.mem_utils.readWord32(self.cpu, cur_task_rec + self.param.ts_pid)
        #self.lgr.debug('taskUtils curProc pid %s' % str(pid))
        #phys = self.mem_utils.v2p(self.cpu, cur_task_rec)
        #self.lgr.debug('taskProc cur_task 0x%x phys 0x%x  pid %d comm: %s  phys_current_task 0x%x' % (cur_task_rec, phys, pid, comm, self.phys_current_task))
        return self.cpu, comm, pid 

    def frameFromRegs(self, compat32=None, swap_r10=True):
        frame = {}
        if self.cpu.architecture == 'arm':
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
        else:
            frame['sp'] = self.mem_utils.getRegValue(self.cpu, 'sp')
            frame['pc'] = self.mem_utils.getRegValue(self.cpu, 'pc')
            if self.mem_utils.WORD_SIZE == 8:
                for p in memUtils.param_map['x86_64']:
                    frame[p] = self.mem_utils.getRegValue(self.cpu, memUtils.win_param_map['x86_64'][p])
                if swap_r10:
                    frame['param1'] = self.mem_utils.getRegValue(self.cpu, 'r10')
            else:
                self.lgr.error('winTaskUtils frameFromRegs bad word size?') 
        user_stack = frame['sp']+0x28
        frame['param5'] = self.mem_utils.readWord(self.cpu, user_stack)
        frame['param6'] = self.mem_utils.readWord(self.cpu, user_stack+self.mem_utils.wordSize(self.cpu))
        frame['param7'] = self.mem_utils.readWord(self.cpu, user_stack+2*self.mem_utils.wordSize(self.cpu))
        frame['param8'] = self.mem_utils.readWord(self.cpu, user_stack+3*self.mem_utils.wordSize(self.cpu))
        return frame

    def frameFromRegsComputed(self):
        frame = self.frameFromRegs(swap_r10=False)

        gs_base = self.cpu.ia32_gs_base
        #ptr2stack = gs_base+0x6008
        ptr2stack = gs_base+self.param.ptr2stack
        stack_val = self.mem_utils.readPtr(self.cpu, ptr2stack)
        #self.lgr.debug('winTaskUtils frameFromRegsComputed gs_base 0x%x ptr2stack 0x%x stack_val 0x%x' % (gs_base, ptr2stack, stack_val))
        user_stack = self.mem_utils.readPtr(self.cpu, stack_val-16)
        
        r10 = self.mem_utils.getRegValue(self.cpu, 'r10')
        #self.lgr.debug('winTaskUtils frameFromRegsComputed user_stack 0x%x rcx is 0x%x  r10: 0x%x' % (user_stack, frame['param1'], r10))
        frame['sp'] = user_stack
        frame['rsp'] = user_stack
        user_stack_28 = user_stack+0x28 
        frame['param5'] = self.mem_utils.readWord(self.cpu, user_stack_28)
        frame['param6'] = self.mem_utils.readWord(self.cpu, user_stack_28+self.mem_utils.wordSize(self.cpu))
        frame['param7'] = self.mem_utils.readWord(self.cpu, user_stack_28+2*self.mem_utils.wordSize(self.cpu))
        frame['param8'] = self.mem_utils.readWord(self.cpu, user_stack_28+3*self.mem_utils.wordSize(self.cpu))
        #frame['param1'] = self.mem_utils.readPtr(self.cpu, stack_val-40)
        if frame['param1'] is None:
            self.lgr.error('frameFromRegsComputed got none reading from 0x%x -40' % stack_val)
        #rcx = self.mem_utils.getRegValue(self.cpu, 'rcx')
        #rdx = self.mem_utils.getRegValue(self.cpu, 'rdx')
        #r8 = self.mem_utils.getRegValue(self.cpu, 'r8')
        #r9 = self.mem_utils.getRegValue(self.cpu, 'r9')
        return frame

    def pickleit(self, fname):
        phys_current_task_file = os.path.join('./', fname, self.cell_name, 'phys_current_task.pickle')
        try:
            os.mkdir(os.path.dirname(phys_current_task_file))
        except:
            pass
        dict_val = {}
        dict_val['current_task_phys'] = self.phys_current_task
        dict_val['saved_cr3_phys'] = self.phys_saved_cr3
        pickle.dump(dict_val , open( phys_current_task_file, "wb" ) )
        exec_addrs_file = os.path.join('./', fname, self.cell_name, 'exec_addrs.pickle')
        pickle.dump( self.program_map, open( exec_addrs_file, "wb" ) )

    def getExecMode(self):
        mode = None
        if self.cpu.iface != 'arm':
            mode = self.cpu.iface.x86_reg_access.get_exec_mode()
        return mode

    def currentProcessInfo(self, cpu=None):
        cur_addr = self.getCurTaskRec()
        #self.lgr.debug('currentProcessInfo cur_addr is 0x%x' % cur_addr)
        if cur_addr is not None:
            comm = self.mem_utils.readString(self.cpu, cur_addr + self.param.ts_comm, self.commSize())
            pid = self.mem_utils.readWord32(self.cpu, cur_addr + self.param.ts_pid)
            return self.cpu, cur_addr, comm, pid
        else:
            self.lgr.error('winTaskUtils currentProcessInfo got None for cur_addr')
            return self.cpu, None, None, None

    def getTaskListPtr(self, rec=None):
        ''' return address of the task list "next" entry that points to the current task '''
        if rec is None:
            task_rec_addr = self.getCurTaskRec()
        else:
            task_rec_addr = rec
        comm = self.mem_utils.readString(self.cpu, task_rec_addr + self.param.ts_comm, self.commSize())
        pid = self.mem_utils.readWord32(self.cpu, task_rec_addr + self.param.ts_pid)
        seen = set()
        tasks = {}
        ''' TBD'''
        return None

    def getGroupLeaderPid(self, pid):
        ''' TBD '''
        return pid

    def walk(self, task_ptr_in, offset):
        done = False
        got = []
        task_ptr = task_ptr_in
        #self.lgr.debug('winTaskUtils walk task_ptr 0x%x offset 0x%x ts_pid: 0x%x' % (task_ptr, offset, self.param.ts_pid))
        while not done:
            pid_ptr = self.mem_utils.getUnsigned(task_ptr + self.param.ts_pid)
            #self.lgr.debug('winTaskUtils walk got pid_ptr 0x%x from task_ptr 0x%x plus ts_pid' % (pid_ptr, task_ptr))
            pid = self.mem_utils.readWord(self.cpu, pid_ptr)
            if pid is not None:
                got.append(task_ptr)
                #self.lgr.debug('winTaskUtils walk got pid %d from task_ptr 0x%x' % (pid, task_ptr))
            else:
                self.lgr.debug('got no pid for pid_ptr 0x%x' % pid_ptr)
                #print('got no pid for pid_ptr 0x%x' % pid_ptr)
                break
            task_next = self.mem_utils.getUnsigned(task_ptr + offset)
            val = self.mem_utils.readWord(self.cpu, task_next)
            if val is None:
                print('died on task_next 0x%x' % task_next)
                break
            else:
                next_head = self.mem_utils.getUnsigned(val)
            
            task_ptr = next_head - self.param.ts_prev
            task_ptr = self.mem_utils.getUnsigned(task_ptr)
            #self.lgr.debug('winTaskUtils got new task_ptr 0x%x from next_head of 0x%x' % (task_ptr, next_head))
            if task_ptr in got:
                #print('already got task_ptr 0x%x' % task_ptr)
                #self.lgr.debug('walk already got task_ptr 0x%x' % task_ptr)
                break
        return got

    def getTaskList(self):
        got = []
        done = False
        #self.lgr.debug('getTaskList ')
        task_ptr = self.getCurTaskRec()
        #self.lgr.debug('getTaskList task_ptr 0x%x' % task_ptr)
        got = self.walk(task_ptr, self.param.ts_next)
        #self.lgr.debug('getTaskList returning %d tasks' % len(got))
        return got
    
    def getTaskStructs(self):
        retval = {}
        task_list = self.getTaskList()
        for task in task_list:
            comm = self.mem_utils.readString(self.cpu, task + self.param.ts_comm, self.commSize())
            pid = self.mem_utils.readWord32(self.cpu, task + self.param.ts_pid)
            retval[task] = TaskStruct(pid, comm)

        return retval

    def getCommFromPid(self, pid):
        ts_list = self.getTaskStructs()
        for ts in ts_list:
           if ts_list[ts].pid == pid:
               return ts_list[ts].comm
        return None

    def addProgram(self, pid, program):
        self.program_map[pid] = program

    def getProgName(self, pid):
        retval = None
        if pid in self.program_map:
            retval = self.program_map[pid]
        ''' TBD find arg list? '''
        return retval, []

    def clearExitPid(self):
        self.exit_pid = 0
        self.exit_cycles = 0

    def getCurrentThreadLeaderPid(self):
        ''' TBD see taskUtils'''
        dumb, comm, pid = self.curProc()
        return pid

    def getRecAddrForPid(self, pid):
        #self.lgr.debug('getRecAddrForPid %d' % pid)
        ts_list = self.getTaskStructs()
        for ts in ts_list:
           if ts_list[ts].pid == pid:
               return ts
        #self.lgr.debug('TaksUtils getRecAddrForPid %d no task rec found. %d task records found.' % (pid, len(ts_list)))
        return None

    def getGroupPids(self, leader_pid):
        ''' TBD fix for windows'''
        retval = {}
        #self.lgr.debug('getGroupPids for %d' % leader_pid)
        ts_list = self.getTaskStructs()
        leader_rec = None
        for ts in ts_list:
            if ts_list[ts].pid == leader_pid:
                retval[leader_pid] = ts
                break
        return retval

    def getExitPid(self):
        ''' if we are at or past the point of exit, return the most recently exitied pid. 
            TBD, more robust, multiple PIDs? '''
        if self.exit_cycles is not None and self.cpu.cycles >= self.exit_cycles:
            return self.exit_pid
        else:
            return None
    def recentExitPid(self):
        return self.exit_pid

    def getPidsForComm(self, comm_in):
        comm = os.path.basename(comm_in).strip()
        retval = []
        #self.lgr.debug('getPidsForComm %s' % comm_in)
        ts_list = self.getTaskStructs()
        for ts in ts_list:
            #self.lgr.debug('getPidsForComm compare <%s> to %s  len is %d' % (comm, ts_list[ts].comm, len(comm)))
            if comm == ts_list[ts].comm or (len(comm)>self.commSize() and len(ts_list[ts].comm) == self.commSize() and comm.startswith(ts_list[ts].comm)):
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

    def getPidAndThread(self):
        dum, dum1, pid = self.curProc()
        thread = self.getCurThread()
        retval = '%d-%d' % (pid, thread)
        return retval

    def matchPidThread(self, pid_thread):
        cur = self.getPidAndThread()
        if pid_thread == cur:
            return True
        else:
            return False
        
    def findThreads(self):
        cur_thread = SIM_read_phys_memory(self.cpu, self.phys_current_task, self.mem_utils.WORD_SIZE)
        if cur_thread is None:
            self.lgr.error('winTaskUtils getCurTaskRecPhys got cur_thread of None reading 0x%x' % self.phys_current_task)
        else:
            ptr = cur_thread + self.param.proc_ptr
            cur_proc = self.mem_utils.readPtr(self.cpu, ptr)
            comm = self.mem_utils.readString(self.cpu, cur_proc + self.param.ts_comm, self.commSize())
            pid = self.mem_utils.readWord32(self.cpu, cur_proc + self.param.ts_pid)

            active_threads = self.mem_utils.readWord32(self.cpu, cur_proc + 0x328)
            self.lgr.debug('findThreads cur_thread 0x%x  ptr 0x%x  cur_proc 0x%x pid:%d (%s) active_threads 0x%x' % (cur_thread, ptr, cur_proc, pid, comm, active_threads))
            if active_threads < 4:
                print('not enough threads %d' % active_threads)
                return
            thread_list_head = self.mem_utils.readPtr(self.cpu, cur_proc + 0x308)
            self.lgr.debug('thread list head is 0x%x' % thread_list_head)


            next_thread = self.mem_utils.readPtr(self.cpu, thread_list_head+8)
            got = []
            got.append(next_thread)
            thread_recs = []
            for i in range(50):
          
                next_thread = self.mem_utils.readPtr(self.cpu, next_thread+8)
                if next_thread is None or next_thread in got:
                    break
                got.append(next_thread)
                ''' TBD compute this delta by looping each next_thread we find and computing the smallest delta from the cur_thread values'''
                rec_start = next_thread - 0x428
                this_proc = self.mem_utils.readPtr(self.cpu, rec_start+self.param.proc_ptr)
                if this_proc != 0: 
                    self.lgr.debug('next thread %d is 0x%x  rec_start 0x%x  proc_ptr 0x%x' % (i, next_thread, rec_start, this_proc))
                thread_recs.append(rec_start)

            offset=w7Params.hackpid(self.cpu, self.mem_utils, thread_recs, self.lgr, max_zeros=0)
                
            return


    def recentExitPid(self):
        return self.exit_pid

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

    def clearExitPid(self):
        self.exit_pid = 0
        self.exit_cycles = 0
        

     
