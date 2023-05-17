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
class TaskStruct():
    def __init__(self, pid, comm):
        self.pid = pid
        self.comm = comm
        ''' TBD fix for windows so we know who is waiting in the kernel when setting exit haps'''
        self.state = 0

class WinTaskUtils():
    COMM_SIZE = 16
    def __init__(self, cpu, cell_name, param, mem_utils, run_from_snap, lgr):
        self.cpu = cpu
        self.cell_name = cell_name
        self.lgr = lgr
        self.param = param
        self.mem_utils = mem_utils
        self.run_from_snap = run_from_snap
        self.phys_current_task = None
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
                self.phys_current_task = pickle.load( open(phys_current_task_file, 'rb') ) 
                self.lgr.debug('loaded phys_current_task from %s' % phys_current_task_file)
                self.lgr.debug('value 0x%x' % self.phys_current_task)
            else:
                ''' temporary hack TBD '''
                pfile = os.path.join(self.run_from_snap, 'phys.pickle')
                if os.path.isfile(pfile):
                    value = pickle.load(open(pfile, 'rb'))
                    if type(value) is int:
                        self.phys_current_task = pickle.load(open(pfile, 'rb'))
                    else:
                        self.phys_current_task = value['current_task_phys']
                        self.phys_saved_cr3 = value['saved_cr3_phys']
                else:
                    self.lgr.error('winTaskUtils did not find %s' % pfile)
                    return

            exec_addrs_file = os.path.join('./', run_from_snap, cell_name, 'exec_addrs.pickle')
            if os.path.isfile(exec_addrs_file):
                self.program_map = pickle.load( open(exec_addrs_file, 'rb') ) 

    def getPhysCurrentTask(self):
        return self.phys_current_task

    def getCurTaskRecPhys(self):
        retval = None
        cur_thread = SIM_read_phys_memory(self.cpu, self.phys_current_task, self.mem_utils.WORD_SIZE)
        if cur_thread is None:
            self.lgr.error('winTaskUtils getCurTaskRecPhys got cur_thread of None reading 0x%x' % self.phys_current_task)
        else:
            ptr = cur_thread + self.param.proc_ptr
            saved_cr3 = SIM_read_phys_memory(self.cpu, self.phys_saved_cr3, self.mem_utils.WORD_SIZE)
            #self.lgr.debug('winTaskUtils getCurTaskRecPhys phys_saved_cr3  0x%x saved_cr3 0x%x' % (self.phys_saved_cr3, saved_cr3))
            pt = pageUtils.findPageTable(self.cpu, ptr, self.lgr, force_cr3=saved_cr3)
            #self.lgr.debug('winTaskUtils getCurTaskRecPhys got pt.page_addr 0x%x' % pt.page_addr)
            cur_proc_linear = SIM_read_phys_memory(self.cpu, pt.page_addr, self.mem_utils.WORD_SIZE)
            #self.lgr.debug('winTaskUtils getCurTaskRecPhys got cur_proc linear 0x%x' % cur_proc_linear)
            pt = pageUtils.findPageTable(self.cpu, cur_proc_linear, self.lgr, force_cr3=saved_cr3)
            retval = pt.page_addr
            if retval is None:
                self.lgr.error('winTaskUtils getCurTaskRecPhys got None from page table 0x%x ptr 0x%x phys_current is 0x%x' % (cur_thread, ptr, self.phys_current_task))
            else:
                #self.lgr.debug('winTaskUtils getCurTaskRecPhys got cur proc 0x%x' % retval)
                pass
                
        return retval


    def getCurTaskRec(self, cur_thread=None):
        retval = None
        if cur_thread is None:
            cur_thread = SIM_read_phys_memory(self.cpu, self.phys_current_task, self.mem_utils.WORD_SIZE)
        if cur_thread is None:
            self.lgr.error('winTaskUtils getCurTaskRec got cur_thread of None reading 0x%x' % self.phys_current_task)
        else:
            ptr = cur_thread + self.param.proc_ptr
            retval = self.mem_utils.readPtr(self.cpu, ptr)
            if retval is None:
                #self.lgr.debug('winTaskUtils x getCurTaskRec got current Proc of None reading cur_thread 0x%x ptr 0x%x phys_current is 0x%x, try saved CR3' % (cur_thread, ptr, self.phys_current_task))
                ''' Try getting phys addr of saved cr3'''
                #gs_base = self.cpu.ia32_gs_base
                #saved_cr3_addr = gs_base+self.param.saved_cr3
                #saved_cr3 = self.mem_utils.readPtr(self.cpu, saved_cr3_addr)
                saved_cr3 = SIM_read_phys_memory(self.cpu, self.phys_saved_cr3, self.mem_utils.WORD_SIZE)
                #self.lgr.debug('winTaskUtils getCurTaskRec phys_saved_cr3  0x%x saved_cr3 0x%x' % (self.phys_saved_cr3, saved_cr3))
                pt = pageUtils.findPageTable(self.cpu, ptr, self.lgr, force_cr3=saved_cr3)
                self.lgr.debug('winTaskUtils getCurTaskRec got pt.page_addr 0x%x' % pt.page_addr)
                retval = SIM_read_phys_memory(self.cpu, pt.page_addr, self.mem_utils.WORD_SIZE)
                if retval is None:
                    self.lgr.error('winTaskUtils x getCurTaskRec got current Proc of None reading cur_thread 0x%x ptr 0x%x phys_current is 0x%x' % (cur_thread, ptr, self.phys_current_task))
                else:
                    #self.lgr.debug('winTaskUtils getCurTaskRec VIA saved CR3, got current Proc of 0x%x reading cur_thread 0x%x ptr 0x%x phys_current is 0x%x' % (retval, cur_thread, ptr, self.phys_current_task))
                    pass
                
            else:
                #self.lgr.debug('winTaskUtils getCurTaskRec got current Proc of 0x%x reading cur_thread 0x%x ptr 0x%x phys_current is 0x%x' % (retval, cur_thread, ptr, self.phys_current_task))
                pass
        return retval

    def getMemUtils(self):
        return self.mem_utils

    def syscallNumber(self, call, dumb=None):
        retval = self.call_num_map[call]
        return retval 

    def syscallName(self, call_num, dumb=None):
        retval = None
        if call_num not in self.call_map:
            self.lgr.error('winTaskUtils, no map for call number %d' % call_num)
        else:
            retval = self.call_map[call_num][2:]
        return retval 

    def getSyscallEntry(self, callnum):
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
        self.lgr.debug('getComputed syscall_jump 0x%x  val 0x%x  callnum %d' % (self.param.syscall_jump, val, callnum))
        entry = self.mem_utils.readPtr(self.cpu, val)
        if entry is None:
            self.lgr.error('getComputed entry is None reading from 0x%x' % val)
            return None
        entry = entry & 0xffffffff
        entry_shifted = entry >> 4
        computed = self.param.syscall_jump + entry_shifted
        self.lgr.debug('getComputed call 0x%x val 0x%x entry 0x%x entry_shifted 0x%x computed 0x%x' % (callnum, val, entry, entry_shifted, computed))
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
        pid = None
        comm = None
        cur_proc_phys = self.getCurTaskRecPhys()
        cur_proc = self.getCurTaskRec()
        if cur_proc_phys is None:
            self.lgr.error('winTaskUtils curProc gotNone from getCurTaskRec')
            return None, None, None
        pid_ptr = cur_proc_phys + self.param.ts_pid
        pid = SIM_read_phys_memory(self.cpu, pid_ptr, self.mem_utils.WORD_SIZE)
        if pid is not None:
            #self.lgr.debug('getCurPid cur_proc_phys 0x%x linear was 0x%x,  pid_offset %d pid_ptr 0x%x pid %d' % (cur_proc_phys, cur_proc, self.param.ts_pid, pid_ptr, pid))
            comm = self.mem_utils.readStringPhys(self.cpu, cur_proc_phys+self.param.ts_comm, 16)
        else:
            self.lgr.debug('getCurPid cur_thread is None')
        return self.cpu, comm, pid

    def frameFromRegs(self, compat32=None):
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
                frame['param1'] = self.mem_utils.getRegValue(self.cpu, 'r10')
            else:
                self.lgr.error('winTaskUtils frameFromRegs bad word size?') 
        return frame

    def frameFromRegsComputed(self):
        frame = self.frameFromRegs()

        gs_base = self.cpu.ia32_gs_base
        #ptr2stack = gs_base+0x6008
        ptr2stack = gs_base+self.param.ptr2stack
        stack_val = self.mem_utils.readPtr(self.cpu, ptr2stack)
        self.lgr.debug('winTaskUtils frameFromRegsComputed gs_base 0x%x ptr2stack 0x%x stack_val 0x%x' % (gs_base, ptr2stack, stack_val))
        user_stack = self.mem_utils.readPtr(self.cpu, stack_val-16)
        self.lgr.debug('winTaskUtils frameFromRegsComputed user_stack 0x%x' % (user_stack))
        frame['sp'] = user_stack
        frame['rsp'] = user_stack
        ''' TBD sometimes stepped on???
            r10 is hid in rcx.  don't ask me...
        '''
        frame['param5'] = user_stack
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
        pickle.dump( self.phys_current_task, open( phys_current_task_file, "wb" ) )
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
            comm = self.mem_utils.readString(self.cpu, cur_addr + self.param.ts_comm, self.COMM_SIZE)
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
        comm = self.mem_utils.readString(self.cpu, task_rec_addr + self.param.ts_comm, self.COMM_SIZE)
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
        while not done:
            pid_ptr = task_ptr + self.param.ts_pid
            pid = self.mem_utils.readWord(self.cpu, pid_ptr)
            if pid is not None:
                got.append(task_ptr)
            else:
                self.lgr.debug('got no pid for pid_ptr 0x%x' % pid_ptr)
                #print('got no pid for pid_ptr 0x%x' % pid_ptr)
                break
            task_next = task_ptr + offset
            val = self.mem_utils.readWord(self.cpu, task_next)
            if val is None:
                print('died on task_next 0x%x' % task_next)
                break
            else:
                next_head = val
            
            task_ptr = next_head - self.param.ts_prev

            if task_ptr in got:
                #print('already got task_ptr 0x%x' % task_ptr)
                self.lgr.debug('walk already got task_ptr 0x%x' % task_ptr)
                break
        return got

    def getTaskList(self):
        got = []
        done = False
        task_ptr = self.getCurTaskRec()
        got = self.walk(task_ptr, self.param.ts_next)
        self.lgr.debug('getTaskList returning %d tasks' % len(got))
        return got
    
    def getTaskStructs(self):
        retval = {}
        task_list = self.getTaskList()
        for task in task_list:
            comm = self.mem_utils.readString(self.cpu, task + self.param.ts_comm, self.COMM_SIZE)
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

