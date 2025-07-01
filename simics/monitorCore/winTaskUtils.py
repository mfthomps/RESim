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
THREAD_STATE_INITIALIZED = 0
THREAD_STATE_READY = 1
THREAD_STATE_RUNNING = 2
THREAD_STATE_STANDBY = 3
THREAD_STATE_TERMINATED = 4
THREAD_STATE_WAITING = 5
THREAD_STATE_TRANSITION = 6
THREAD_STATES = ['initialized', 'ready', 'running', 'standby', 'terminated', 'waiting', 'transistion']
class TaskStruct():
    def __init__(self, pid, comm, next):
        self.pid = pid
        self.comm = comm
        self.next = next
        ''' TBD fix for windows so we know who is waiting in the kernel when setting exit haps'''
        self.state = 0

class WinTaskUtils():
    # These are based on build 6.1
    # offset within ETHREAD of thread id
    THREAD_ID_OFFSET = 0x3c0
    # offset within EPROCESS of thread head
    THREAD_HEAD = 0x308
    # offset of head within ETHREAD
    THREAD_NEXT = 0x428
    # offset within EPROCESS of count of active threads
    ACTIVE_THREADS = 0x328
    THREAD_STATE = 0x164
    PEB_ADDR = 0x338
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
        self.exit_tid = None

        self.system_proc_rec = None

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
        self.gui_call_map = {}
        self.gui_call_num_map = {}
        w7GUImapfile = os.path.join(resim_dir, 'windows', 'win7GUI.json')
        if os.path.isfile(w7GUImapfile):
            cm = json.load(open(w7GUImapfile))     
            for call in cm:
                self.gui_call_map[int(call)] = cm[call] 
                ''' drop Nt prefix'''
                self.gui_call_num_map[cm[call][2:]] = int(call)
        else:
            self.lgr.error('WinTaskUtils cannot open %s' % w7GUImapfile)
            return

        if run_from_snap is None:
            va = cpu.ia32_gs_base + self.param.current_task
            phys = self.mem_utils.v2p(self.cpu, va)
            self.lgr.debug('winTaskUtils cell %s current task 0x%x, phys 0x%x now save cr3' % (self.cell_name, va, phys))
            self.mem_utils.saveKernelCR3(self.cpu)
            self.phys_current_task = phys
            self.savePhysCR3Addr()
            #self.phys_saved_cr3 = self.mem_utils.getKernelSavedCR3()
            if self.phys_saved_cr3 is not None:
                self.lgr.debug('winTaskUtils cell %s got phys_saved_cr3 of 0x%x' % (self.cell_name, self.phys_saved_cr3))
           
        else:
            phys_current_task_file = os.path.join('./', run_from_snap, cell_name, 'phys_current_task.pickle')
            if os.path.isfile(phys_current_task_file):
                value = pickle.load( open(phys_current_task_file, 'rb') ) 
                if type(value) is int:
                    self.phys_current_task = value
                    self.savePhysCR3Addr()
                    if self.phys_saved_cr3 is not None:
                            self.lgr.debug('winTaskUtils, cell %s snapshot lacked saved cr3, use value computed from param saved_cr3 0x%x to 0x%x' % (self.cell_name, self.param.saved_cr3, self.phys_saved_cr3))
                else:
                    self.phys_current_task = value['current_task_phys']
                    if 'saved_cr3_phys' in value:
                        self.phys_saved_cr3 = value['saved_cr3_phys']
                    if 'system_proc_rec' in value and value['system_proc_rec'] is not None:
                        self.system_proc_rec = value['system_proc_rec']
                        self.lgr.debug('winTaskUtils, cell %s got system_proc_rec 0x%x' % (self.cell_name, self.system_proc_rec))
                    else:
                        self.system_proc_rec = self.getSystemProcRec()
                        if self.system_proc_rec is None:
                            self.lgr.error('WinTaskUtils failed to get system thread record')
                        else:
                            self.lgr.debug('winTaskUtils, snapshot lacked system_proc_rec, got 0x%x' % self.system_proc_rec)
                    if self.phys_saved_cr3 is not None:
                        self.lgr.debug('winTaskUtils, cell %s snapshot had saved phys addr of cr3, value 0x%x' % (self.cell_name, self.phys_saved_cr3))
                #saved_cr3 = SIM_read_phys_memory(self.cpu, self.phys_saved_cr3, self.mem_utils.WORD_SIZE)
                if self.phys_saved_cr3 is not None:
                    self.mem_utils.saveKernelCR3(self.cpu, phys_cr3=self.phys_saved_cr3)

                self.lgr.debug('windTaskUtils cell %s loaded phys_current_task from %s value 0x%x' % (self.cell_name, phys_current_task_file, self.phys_current_task))
            else:
                ''' temporary hack TBD '''
                self.lgr.debug('winTaskUtils, no phys_current_task.pickle file, temporary hack.  fix this')
                pfile = os.path.join(self.run_from_snap, 'phys.pickle')
                if os.path.isfile(pfile):
                    value = pickle.load(open(pfile, 'rb'))
                    if type(value) is int:
                        if self.param.saved_cr3 is not None:
                            self.phys_current_task = value
                            gs_base = self.cpu.ia32_gs_base
                            self.phys_saved_cr3 = gs_base+self.param.saved_cr3
                            self.lgr.debug('winTaskUtils, hacked snapshot lacked saved cr3, use value computed from param saved_cr3 0x%x to 0x%x' % (self.param.saved_cr3, self.phys_saved_cr3))
                            self.lgr.debug('winTaskUtils loaded only phys_current_task, value 0x%x' % value)
                    else:
                        if self.param.saved_cr3 is not None:
                            self.phys_current_task = value['current_task_phys']
                            self.phys_saved_cr3 = value['saved_cr3_phys']
                        if 'system_proc_rec' in value:
                            self.system_proc_rec = value['system_proc_rec']
                        else:
                            self.system_proc_rec = self.getSystemProcRec()
                            if self.system_proc_rec is None:
                                self.lgr.error('WinTaskUtils temp hack failed to get system thread record')
                            else:
                                self.lgr.debug('winTaskUtils, hacked snapshot lacked system_proc_rec, got 0x%x' % self.system_proc_rec)
                        if self.param.saved_cr3 is not None:
                            self.lgr.debug('winTaskUtils loaded phys_current_task value 0x%x and saved_cr3 0x%x' % (self.phys_current_task, 
                               self.phys_saved_cr3))
                    #saved_cr3 = SIM_read_phys_memory(self.cpu, self.phys_saved_cr3, self.mem_utils.WORD_SIZE)
                    if self.param.saved_cr3 is not None:
                        self.mem_utils.saveKernelCR3(self.cpu, phys_cr3=self.phys_saved_cr3)
                else:
                    self.lgr.error('winTaskUtils did not find %s' % pfile)
                    return

            exec_addrs_file = os.path.join('./', run_from_snap, cell_name, 'exec_addrs.pickle')
            if os.path.isfile(exec_addrs_file):
                pmap = pickle.load( open(exec_addrs_file, 'rb') ) 
                for tid in pmap:
                    self.program_map[str(tid)] = pmap[tid]
                    self.lgr.debug('winTaskUtils from pickle got tid:%s  %s' % (tid, self.program_map[str(tid)]))
            else:
                self.lgr.error('winTaskUtils did not find %s for snap %s' % (exec_addrs_file, run_from_snap))

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

    def getThreadId(self, rec=None):
        ''' return the thread identifier from the ETHREAD record (either current or given) '''
        if rec == None:
            rec = self.getCurThreadRec()
        ptr = rec + self.THREAD_ID_OFFSET
        retval = self.mem_utils.readWord32(self.cpu, ptr)
        return retval

    def getCurProcRec(self, cur_thread_in=None):
        ''' Get the address of the current process record (EPROCESS).  Or get the process record
            for pointed to by the given address of a thread record.
        '''
        retval = None
        if cur_thread_in is None:
            cur_thread = SIM_read_phys_memory(self.cpu, self.phys_current_task, self.mem_utils.WORD_SIZE)
            cur_thread = self.mem_utils.getUnsigned(cur_thread)
        else:
            cur_thread = cur_thread_in

        if cur_thread is None:
            self.lgr.error('winTaskUtils getCurProcRec got cur_thread of None reading 0x%x' % self.phys_current_task)
        elif cur_thread < self.param.kernel_base:
            self.lgr.debug('winTaskUtils getCurProcRec got cur_thread 0x%x reading 0x%x, NOT in kernel address space, bail' % (cur_thread, self.phys_current_task))
            return None
        else:
            ptr = cur_thread + self.param.proc_ptr
            #self.lgr.debug('winTaskUtils getCurProcRec got cur_thread 0x%x reading 0x%x ptr: 0x%x' % (cur_thread, self.phys_current_task, ptr))
            ptr_phys = self.mem_utils.v2p(self.cpu, ptr, do_log=False)
            #self.lgr.debug('winTaskUtils getCurProcRec got ptr_phys 0x%x reading ptr 0x%x (cur_thread + 0x%x' % (ptr_phys, ptr, self.param.proc_ptr))
            if ptr_phys is None:
               if ptr > self.param.kernel_base: 
                    try:
                        phys_block = self.cpu.iface.processor_info.logical_to_physical(ptr, Sim_Access_Read)
                        ptr_phys = phys_block.address
                    except:
                        self.lgr.debug('memUtils v2p logical_to_physical failed on 0x%x' % v)
            if ptr_phys is not None:
                retval = SIM_read_phys_memory(self.cpu, ptr_phys, self.mem_utils.WORD_SIZE)
            else:
                self.lgr.error('winTaskUtils getCurProcRec failed getting phys address for ptr 0x%x  cur_thread: 0x%x  phys_current_task: 0x%x' % (ptr, cur_thread, self.phys_current_task))
                if cur_thread_in is not None:
                    self.lgr.debug('cur_thread passed in as 0x%x' % cur_thread_in)
                #SIM_break_simulation('remove this')
                pass
        if retval is not None:
            retval = self.mem_utils.getUnsigned(retval)
            #self.lgr.debug('winTaskUtils getCurProcRec returning 0x%x' % retval)
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
        if call_num  >= 4096:
           if call_num not in self.gui_call_map:
               self.lgr.warning('winTaskUtils, no gui map for call number %d' % call_num)
           else:
               retval = self.gui_call_map[call_num][2:]
        else:
            if call_num not in self.call_map:
                self.lgr.warning('winTaskUtils, no map for call number %d' % call_num)
            else:
                retval = self.call_map[call_num][2:]
        return retval 

    def isGUICall(self, call_num):
        if call_num  >= 4096:
            return True
        else:
            return False

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

    def curPID(self):
        cur_task_rec = self.getThreadId()
        if cur_task_rec is None:
            return None
        pid = self.mem_utils.readWord32(self.cpu, cur_task_rec + self.param.ts_pid)
        return pid

    def curTID(self):
        ''' Return pid-thread_id per the current scheduled thread '''
        cur_task_rec = self.getCurProcRec()
        if cur_task_rec is None:
            return None
        pid = self.mem_utils.readWord32(self.cpu, cur_task_rec + self.param.ts_pid)
        thread = self.getThreadId()
        pid_thread = '%d-%d' % (pid, thread)
        return pid_thread

    def curThread(self):
        ''' Return tuple of cpu, comm and tid '''
        #self.lgr.debug('winTaskUtils curThread')
        cur_proc_rec = self.getCurProcRec()
        #self.lgr.debug('winTaskUtils curThread cur_proc_rec 0x%x' % cur_proc_rec)
        if cur_proc_rec is None:
            return None, None, None
        #self.lgr.debug('winTaskUtils curThread get comm')
        comm = self.mem_utils.readString(self.cpu, cur_proc_rec + self.param.ts_comm, 16)
        #self.lgr.debug('winTaskUtils curThread comm %s' % comm)
        #self.lgr.debug('winTaskUtils curThread get pid')
        pid = self.mem_utils.readWord32(self.cpu, cur_proc_rec + self.param.ts_pid)
        #self.lgr.debug('winTaskUtils curThread pid %s' % pid)
        thread = self.getThreadId()
        if pid is None:
            pid = self.mem_utils.readWord32(self.cpu, cur_proc_rec + self.param.ts_pid)
            self.lgr.debug('winTaskUtils curThread tried again, pid %s' % pid)
        if pid is None or thread is None:
            self.lgr.debug('winTaskUtils curThread pid %s thread %s cur_proc_rec 0x%x' % (pid, thread, cur_proc_rec))
            return None, None, None
        comm = self.mem_utils.readString(self.cpu, cur_proc_rec + self.param.ts_comm, 16)
        pid_thread = '%d-%d' % (pid, thread)
        #self.lgr.debug('winTaskUtils curThread pid %s' % str(pid))
        #phys = self.mem_utils.v2p(self.cpu, cur_proc_rec)
        #self.lgr.debug('taskProc cur_task 0x%x phys 0x%x  pid %d comm: %s  phys_current_task 0x%x' % (cur_proc_rec, phys, pid, comm, self.phys_current_task))
        return self.cpu, comm, pid_thread

    def frameFromRegs(self, compat32=None, swap_r10=True, skip_sp=False):
        frame = {}
        if self.cpu.architecture.startswith('arm'):
            # TBD not suppored yet
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
        if not skip_sp:
            user_stack = frame['sp']+0x28
            #self.lgr.debug('wintTaskUtils frameFromRegs user_stack 0x%x' % user_stack)
            frame['param5'] = self.mem_utils.readWord(self.cpu, user_stack)
            frame['param6'] = self.mem_utils.readWord(self.cpu, user_stack+self.mem_utils.wordSize(self.cpu))
            frame['param7'] = self.mem_utils.readWord(self.cpu, user_stack+2*self.mem_utils.wordSize(self.cpu))
            frame['param8'] = self.mem_utils.readWord(self.cpu, user_stack+3*self.mem_utils.wordSize(self.cpu))
        return frame

    def frameFromRegsComputed(self):
        frame = self.frameFromRegs(swap_r10=False, skip_sp=True)

        gs_base = self.cpu.ia32_gs_base
        #ptr2stack = gs_base+0x6008
        ptr2stack = gs_base+self.param.ptr2stack
        if not hasattr(self.param, 'param_version') or int(self.param.param_version) < 11:
            stack_val = self.mem_utils.readPtr(self.cpu, ptr2stack)
            #self.lgr.debug('winTaskUtils frameFromRegsComputed, no_param_veresion or < 11 gs_base 0x%x ptr2stack 0x%x stack_val 0x%x' % (gs_base, ptr2stack, stack_val))
            user_stack = self.mem_utils.readPtr(self.cpu, stack_val-16)
        else:
            user_stack = self.mem_utils.readPtr(self.cpu, ptr2stack)
        
        r10 = self.mem_utils.getRegValue(self.cpu, 'r10')
        #self.lgr.debug('winTaskUtils frameFromRegsComputed gs_base: 0x%x ptr2stack: 0x%x user_stack 0x%x rcx is 0x%x  r10: 0x%x' % (gs_base, ptr2stack, user_stack, frame['param1'], r10))
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
        if self.phys_saved_cr3 is not None:
            dict_val['saved_cr3_phys'] = self.phys_saved_cr3
        dict_val['system_proc_rec'] = self.system_proc_rec 
        pickle.dump(dict_val , open( phys_current_task_file, "wb" ) )
        exec_addrs_file = os.path.join('./', fname, self.cell_name, 'exec_addrs.pickle')
        pickle.dump( self.program_map, open( exec_addrs_file, "wb" ) )

    def getExecMode(self):
        mode = None
        if not self.cpu.architecture.startswith('arm'):
            mode = self.cpu.iface.x86_reg_access.get_exec_mode()
        return mode

    def currentProcessInfo(self, cpu=None):
        cur_addr = self.getCurProcRec()
        #self.lgr.debug('currentProcessInfo cur_addr is 0x%x' % cur_addr)
        if cur_addr is not None:
            comm = self.mem_utils.readString(self.cpu, cur_addr + self.param.ts_comm, self.commSize())
            pid = self.mem_utils.readWord32(self.cpu, cur_addr + self.param.ts_pid)
            return self.cpu, cur_addr, comm, pid
        else:
            self.lgr.error('winTaskUtils currentProcessInfo got None for cur_addr')
            return self.cpu, None, None, None


    def getTaskListPtr(self, rec=None):
        retval = None
        if rec is None:
            rec_start = self.getCurThreadRec()
        else:
            rec_start = rec
        look_for = rec_start + self.THREAD_NEXT 
        #self.lgr.debug('winTaskUtils getTaskListPtr rec_start 0x%x  look_for 0x%x' % (rec_start, look_for))
        got = []
        for i in range(250):
            thread_id_ptr = rec_start + self.THREAD_ID_OFFSET
            thread_id = self.mem_utils.readWord32(self.cpu, thread_id_ptr)
            if thread_id is not None:
                next_thread_addr = rec_start + self.THREAD_NEXT
                next_thread = self.mem_utils.readWord(self.cpu, next_thread_addr)
                #self.lgr.debug('winTaskUtils getTaskListPtr thread_id %d next_thread 0x%x next_thread_addr 0x%x rec_start 0x%x' % (thread_id, next_thread, next_thread_addr, rec_start))
                if next_thread == look_for:
                    retval = next_thread_addr
                    break
                elif next_thread in got:
                    break
                got.append(next_thread)
                rec_start = next_thread - self.THREAD_NEXT
            else:
                break
        return retval        

    def getProcListPtr(self, rec=None):
        ''' return address of the task list "next" entry that points to the current process, or the given process record '''
        retval = None
        if rec is None:
            task_rec_addr = self.getCurProcRec()
        else:
            task_rec_addr = rec
        #comm = self.mem_utils.readString(self.cpu, task_rec_addr + self.param.ts_comm, self.commSize())
        #pid = self.mem_utils.readWord32(self.cpu, task_rec_addr + self.param.ts_pid)
        task_structs = self.getTaskStructs()
        look_for = task_rec_addr + self.param.ts_next - self.mem_utils.WORD_SIZE
        for t in task_structs:
            #self.lgr.debug('winTaskUtils getTaskListPtr compre 0x%x to 0x%x' % (task_structs[t].next, look_for))
            if task_structs[t].next == look_for:
                retval = t + self.param.ts_next
                self.lgr.debug('winTaskUtils getTaskListPtr got rec pointing to 0x%x, it is 0x%x returning 0x%x' % (task_rec_addr, t, retval))
                break
        return retval 
 

    def getGroupLeaderTid(self, tid):
        ''' TBD '''
        return tid

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
            #self.lgr.debug('read from task_next 0x%x' % task_next)
            val = self.mem_utils.readWord(self.cpu, task_next)
            if val is None:
                #self.lgr.debug('died on task_next 0x%x' % task_next)
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
        #self.lgr.debug('walk return')
        return got

    def getTaskList(self):
        ''' get a list of processes (EPROCESS)'''
        got = []
        done = False
        #self.lgr.debug('getTaskList ')
        if self.system_proc_rec is not None:
            task_ptr = self.system_proc_rec
            #self.lgr.debug('getTaskList using system_proc_rec 0x%x' % task_ptr)
        else:
            dum, dum1, pid = self.curThread()
            if pid != 0:
                task_ptr = self.getCurProcRec()
            else:
                self.lgr.error('Current process is the IDLE, unable to walk proc list from there.')
                return got
            self.lgr.debug('getTaskList using results of curThread??? 0x%x' % task_ptr)
        #self.lgr.debug('getTaskList task_ptr 0x%x' % task_ptr)
        got = self.walk(task_ptr, self.param.ts_next)
        #self.lgr.debug('getTaskList returning %d tasks' % len(got))
        return got

    def getPidList(self):
        retval = []
        task_list = self.getTaskList()
        for task in task_list:
            pid = self.mem_utils.readWord32(self.cpu, task + self.param.ts_pid)
            retval.append(str(pid))
        return retval
    
    def getTaskStructs(self):
        retval = {}
        task_list = self.getTaskList()
        for task in task_list:
            comm = self.mem_utils.readString(self.cpu, task + self.param.ts_comm, self.commSize())
            pid = self.mem_utils.readWord32(self.cpu, task + self.param.ts_pid)
            next = self.mem_utils.readWord(self.cpu, task + self.param.ts_next)
            retval[task] = TaskStruct(pid, comm, next)

        return retval

    def getCommFromTid(self, tid):
        if tid is None:
            return None
        ts_list = self.getTaskStructs()
        pid = int(self.pidString(tid))
        for ts in ts_list:
           if ts_list[ts].pid == pid:
               return ts_list[ts].comm
        return None

    def addProgram(self, tid_in, program):
        if '-' in tid_in:
            pid = tid_in.split('-')[0]
        else:
            pid = tid_in
        self.program_map[pid] = program

    def pidString(self, tid_in):
        if type(tid_in) is str and '-' in tid_in:
            pid = tid_in.split('-')[0]
        else:
            pid = str(tid_in)
        return pid

    def getProgName(self, tid_in):
        retval = None
        pid = self.pidString(tid_in)
        if pid in self.program_map:
            retval = self.program_map[pid]
        ''' TBD find arg list? '''
        return retval, []

    def getProgNameFromComm(self, comm):
        for tid in self.program_map:
            if self.program_map[tid].endswith(comm):
                return self.program_map[tid]
        return None

    def clearExitTid(self):
        self.exit_tid = None
        self.exit_cycles = 0

    def getCurrentThreadLeaderTid(self):
        ''' TBD see taskUtils'''
        return self.curTID()

    def getProcRecForTid(self, tid):
        tid_rec = self.getRecAddrForTid(tid)
        proc_rec = self.getCurProcRec(cur_thread_in=tid_rec)
        return proc_rec

    def getRecAddrForTid(self, tid):
        ''' find the current task pointer (ETHREAD) for a given tid (pid-thread_id)'''
        ret_rec = None
        thread_part = None
        if tid is None:
            return None
        if '-' in tid:
            pid = int(tid.split('-')[0])
            thread_part = int(tid.split('-')[1])
        else:
            pid = int(tid)
        #self.lgr.debug('getRecAddrForTid %d' % pid)
        ts_list = self.getTaskStructs()
        for ts in ts_list:
           if ts_list[ts].pid == pid:
               thread_head_addr = ts+self.THREAD_HEAD
               thread_head = self.mem_utils.readPtr(self.cpu, thread_head_addr)
               #self.lgr.debug('winTaskUtils getRecAddrForTid found for pid %d thread_head 0x%x' % (pid, thread_head))
               if thread_part is not None: 
                   rec_start = thread_head - self.THREAD_NEXT
                   #self.lgr.debug('winTaskUtils getRecAddrForTid rec_start 0x%x thread_part %d' % (rec_start, thread_part))
                   ret_rec = self.getThreadRecForThreadId(rec_start, thread_part)
                   #if ret_rec is not None:
                   #    self.lgr.debug('winTaskUtils getRecAddrForTid ret_rec 0x%x' % ret_rec)
               else:
                   ret_rec = thread_head - self.THREAD_NEXT
               break
        return ret_rec

    def tidDictFromProcRec(self, ts):
        thread_head_addr = ts+self.THREAD_HEAD
        thread_head = self.mem_utils.readPtr(self.cpu, thread_head_addr)
        rec_start = thread_head - self.THREAD_NEXT
        self.lgr.debug('tidDictFromProcRec ts: 0x%x thread_head 0x%x rec_start %x' % (ts, thread_head, rec_start))
        threads = self.findThreads(cur_thread=rec_start)
        return threads

    def getGroupTids(self, leader_tid):
        retval = {}
        self.lgr.debug('getGroupTids for %s' % leader_tid)
        ts_list = self.getTaskStructs()
        leader_rec = None
        pid = int(self.pidString(leader_tid))
        for ts in ts_list:
            if ts_list[ts].pid == pid:
                thread_dict = self.tidDictFromProcRec(ts)
                for t in thread_dict:
                    tid = '%d-%d' % (pid, t)
                    ''' skip if exiting as recorded by syscall '''
                    if not self.isExitTid(tid):
                        retval[tid] = thread_dict[t]
                break
        return retval

    def getTidsForComm(self, comm_in, ignore_exits=False):
        # get the tids whose comm matches the give comm.
        # If ignore_exits, then do not include any that are exiting
        comm = os.path.basename(comm_in).strip()
        retval = []
        self.lgr.debug('getTidsForComm %s' % comm_in)
        ts_list = self.getTaskStructs()
        for ts in ts_list:
            self.lgr.debug('getTidsForComm compare <%s> to %s  len is %d' % (comm, ts_list[ts].comm, len(comm)))
            if comm == ts_list[ts].comm or (len(comm)>self.commSize() and len(ts_list[ts].comm) == self.commSize() and comm.startswith(ts_list[ts].comm)):
                pid = ts_list[ts].pid
                self.lgr.debug('getTidsForComm MATCHED ? %s to %s  pid %d' % (comm, ts_list[ts].comm, pid))
                thread_dict = self.tidDictFromProcRec(ts)
                for t in thread_dict:
                    tid = '%d-%d' % (pid, t)
                    ''' skip if exiting as recorded by syscall '''
                    #if tid != self.exit_tid or (self.cpu.cycles != self.exit_cycles and not ignore_exits):
                    if not (ignore_exits and self.isExitTid(tid)):
                        retval.append(tid)
        return retval


    def getTidCommMap(self):
        retval = {}
        ts_list = self.getTaskStructs()
        self.lgr.debug('winTaskUtils getTidCommMap')
        for ts in ts_list:
            thread_dict = self.tidDictFromProcRec(ts)
            comm = ts_list[ts].comm
            pid = ts_list[ts].pid
            for t in thread_dict:
                tid = '%d-%d' % (pid, t)
                retval[tid] = comm
        return retval

    #def getPidAndThread(self):
    #    dum, dum1, pid = self.curThread()
    #    thread = self.getCurThread()
    #    retval = '%d-%d' % (pid, thread)
    #    return retval

    #def matchPidThread(self, pid_thread):
    #    cur = self.getPidAndThread()
    #    if pid_thread == cur:
    #        return True
    #    else:
    #        return False
    def getThreadRecForThreadId(self, rec_start, thread_id_in):
        ''' return the address of the thread record (ETHREAD) given a thread head and the id '''
        retval = None
        got = []
        for i in range(250):
            thread_id_ptr = rec_start + self.THREAD_ID_OFFSET
            thread_id = self.mem_utils.readWord32(self.cpu, thread_id_ptr)
            if thread_id is not None:
                #self.lgr.debug('winTaskUtils getThreadRecForThreadId %d thread_id_in: %d' % (thread_id, thread_id_in))
                if thread_id == thread_id_in:
                    #self.lgr.debug('winTaskUtils getThreadRecForThreadId got it 0x%x' % rec_start)
                    retval = rec_start
                    break
                next_thread_addr = rec_start + self.THREAD_NEXT
                next_thread = self.mem_utils.readWord(self.cpu, next_thread_addr)
                if next_thread is None or next_thread in got:
                    break
                got.append(next_thread)
                rec_start = next_thread - self.THREAD_NEXT
            else:
                break
        return retval        

    def findThreads(self, cur_thread=None, quiet=True):
        ''' return a dictionary of all threads for the current thread or given thread record address'''
        thread_id_dict = {}
        cur_proc = self.getCurProcRec(cur_thread_in=cur_thread)
        if cur_proc is None:
            self.lgr.error('winTaskUtils findThreads failed to get cur_proc from getCurProcRec')
            return thread_id_dict
        else:
            #self.lgr.debug('winTaskUtils findThreads cur_proc 0x%x ' % (cur_proc))
            comm = self.mem_utils.readString(self.cpu, cur_proc + self.param.ts_comm, self.commSize())
            pid = self.mem_utils.readWord32(self.cpu, cur_proc + self.param.ts_pid)
            if pid is None:
                self.lgr.debug('winTaskUtils findThreads failed to read pid.  cur_proc 0x%x ts_pid 0x%x' % (cur_proc, self.param.ts_pid))
                return thread_id_dict

            active_threads = self.mem_utils.readWord32(self.cpu, cur_proc + self.ACTIVE_THREADS)
            #self.lgr.debug('winTaskUtils findThreads cur_proc 0x%x pid:%d (%s) active_threads 0x%x' % (cur_proc, pid, comm, active_threads))
            if active_threads < 1:
                #print('not enough threads %d' % active_threads)
                self.lgr.debug('winTaskUtils findThreads not enough threads %d' % active_threads)
                return thread_id_dict
            thread_list_head = self.mem_utils.readPtr(self.cpu, cur_proc + self.THREAD_HEAD)
            #self.lgr.debug('thread list head is 0x%x' % thread_list_head)

            next_thread = self.mem_utils.readPtr(self.cpu, thread_list_head+8)
            got = []
            got.append(next_thread)
            for i in range(250):
          
                next_thread = self.mem_utils.readPtr(self.cpu, next_thread+8)
                if next_thread is None or next_thread in got:
                    break
                got.append(next_thread)
                ''' TBD compute this delta by looping each next_thread we find and computing the smallest delta from the cur_thread values'''
                rec_start = next_thread - self.THREAD_NEXT
                thread_id_ptr = rec_start + self.THREAD_ID_OFFSET
                thread_id = self.mem_utils.readWord32(self.cpu, thread_id_ptr)
                thread_id_dict[thread_id] = rec_start

        return thread_id_dict

    def isExitTid(self, tid):
        retval = False
        etid = self.getExitTid()
        if etid is not None:
            if '-' in etid:
                if tid == etid:
                    retval = True
            else:
                proc_part = tid.split('-')[0]
                if proc_part == etid:
                    retval = True
        return retval

    def recentExitTid(self):
        return self.exit_tid

    def getExitTid(self):
        ''' if we are at or past the point of exit, return the most recently exitied tid. 
            TBD, more robust, multiple PIDs? '''
        if self.exit_cycles is not None and self.cpu.cycles >= self.exit_cycles:
            return self.exit_tid
        else:
            return None

    def setExitTid(self, tid):
        self.exit_tid = tid
        self.exit_cycles = self.cpu.cycles
        self.lgr.debug('winTaskUtils setExitTid tid:%s cycles 0x%x' % (tid, self.exit_cycles))

    def clearExitTid(self):
        self.exit_tid = None
        self.exit_cycles = 0
        
    def getTidCommFromNext(self, next_addr):
        tid = None
        comm = None
        if next_addr is not None:
            rec = next_addr - self.param.ts_next
            comm = self.mem_utils.readString(self.cpu, rec + self.param.ts_comm, taskUtils.COMM_SIZE)
            pid = self.mem_utils.readWord32(self.cpu, rec + self.param.ts_pid)
            if pid is not None:
                tid = str(pid)
        return tid, comm

    def getTidFromThreadRec(self, thread_rec):
        thread_id = self.getThreadId(thread_rec)
        proc_rec = self.getCurProcRec(cur_thread_in=thread_rec)
        pid = self.mem_utils.readWord32(self.cpu, proc_rec + self.param.ts_pid)
        tid = '%d-%d' %(pid, thread_id)
        return tid

    def getTidCommFromThreadRec(self, thread_rec):
        thread_id = self.getThreadId(thread_rec)
        proc_rec = self.getCurProcRec(cur_thread_in=thread_rec)
        pid = self.mem_utils.readWord32(self.cpu, proc_rec + self.param.ts_pid)
        comm = self.mem_utils.readString(self.cpu, proc_rec + self.param.ts_comm, 16)
        tid = '%d-%d' %(pid, thread_id)
        return tid, comm

    def getTidList(self):
        task_list = self.getTaskStructs()
        tid_list = []
        self.lgr.debug('winTaskUtils getTidList')
        for t in task_list:
            pid = task_list[t].pid
            if pid is None: 
                break
            if pid == 0:
                break
            self.lgr.debug('winTaskUtils getTidList for pid %d' % pid)
            thread_dict = self.tidDictFromProcRec(t)
            for thread_id in thread_dict:
                tid = '%d-%d' % (pid, thread_id)
                tid_list.append(tid)
        return tid_list

    def showThreads(self):
        thread_dict = self.findThreads()
        for thread_id in thread_dict:
            state = self.mem_utils.readByte(self.cpu, thread_dict[thread_id]+self.THREAD_STATE)
            if state in range(len(THREAD_STATES)):
                print('thread_id: %s  rec: 0x%x state: %s' % (thread_id, thread_dict[thread_id], THREAD_STATES[state]))
            else:
                print('thread_id: %s  rec: 0x%x state: 0x%x' % (thread_id, thread_dict[thread_id], state))
        print('%d threads' % (len(thread_dict)))

    def showTidsForComm(self, comm):
        ts_list = self.getTaskStructs()
        for ts in ts_list:
            #self.lgr.debug('getTidsForComm compare <%s> to %s  len is %d' % (comm, ts_list[ts].comm, len(comm)))
            if comm == ts_list[ts].comm or (len(comm)>self.commSize() and len(ts_list[ts].comm) == self.commSize() and comm.startswith(ts_list[ts].comm)):
                pid = ts_list[ts].pid
                self.lgr.debug('getTidsForComm MATCHED ? %s to %s  pid %d' % (comm, ts_list[ts].comm, pid))
                thread_dict = self.tidDictFromProcRec(ts)
                for thread_id in thread_dict:
                    tid = '%d-%d' % (pid, thread_id)
                    state = self.mem_utils.readByte(self.cpu, thread_dict[thread_id]+self.THREAD_STATE)
                    if state in range(len(THREAD_STATES)):
                        print('%s %s' % (tid, THREAD_STATES[state]))
                    else:
                        print('%s 0x%x' % (tid, state))

    def getSystemProcRec(self):
        retval = None
        ts_list = self.getTaskStructs()
        for ts in ts_list:
           if ts_list[ts].pid == 4:
               retval = ts
               break
        return retval

    def setSystemProcessRec(self):
        val = self.getSystemProcRec()
        self.system_proc_rec = val
        self.lgr.debug('winTaskUtils setSystemProcessRec set to 0x%x' % val)
 

    def getTIB(self):
        va = self.cpu.ia32_gs_base + 0x30
        retval = self.mem_utils.readWord(self.cpu, va)
        self.lgr.debug('winTaskUtils getTIB gs_base is 0x%x  tib addr 0x%x' % (self.cpu.ia32_gs_base, va, retval))
        return va

    def savePhysCR3Addr(self):
        if self.param.saved_cr3 is not None:
            gs_base = self.cpu.ia32_gs_base
            self.phys_saved_cr3 = self.mem_utils.v2p(self.cpu, gs_base+self.param.saved_cr3)
            self.lgr.debug('winTaskUtils saved phys_saved_cr3 value 0x%x' % self.phys_saved_cr3)

    def progComm(self, prog_string):
        prog_comm = os.path.basename(prog_string)[:self.commSize()]
        return prog_comm
