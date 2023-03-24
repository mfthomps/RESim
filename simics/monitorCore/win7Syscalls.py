from simics import *
import os
import json
'''
Functions for experimenting with Win7 tasks,
such as determining how parameters are passed
to the kernel.
These assume a param has been built containing the pid offset.
And it assumes the param includes the syscall_jump value
reflecting jump table values for syscalls.
The physical address of the current task record is passed in,
e.g., from getKernelParam.  A real system would compute that from
the param, using gs_base and logic to account for aslr.

DO NOT rely on this for full traces -- it deliberately only looks
at one process at a time to keep it simple.

observed most syscalls have 1st param at offset 40 (0x28) from rsp
and at point of compute, rsi equals rsp+0x20
'''
class Win7Syscalls():
    def __init__(self, cpu, cell, mem_utils, current_task_phys, param, lgr, run_to=None):
        self.param = param
        self.pid_offset = param.ts_pid
        self.current_task_phys = 0x3634188
        #self.entry = 0xfffff80003622bc0
        self.entry_break = None
        self.entry_hap = None
        self.exit_break = None
        self.exit_hap = None
        self.cell = cell
        self.cpu = cpu
        self.run_to = run_to
        self.mem_utils = mem_utils
        self.lgr = lgr
        resim_dir = os.getenv('RESIM_DIR')
        self.call_map = {}
        self.call_num_map = {}
        w7mapfile = os.path.join(resim_dir, 'windows', 'win7.json')
        if os.path.isfile(w7mapfile):
            cm = json.load(open(w7mapfile))     
            for call in cm:
                self.call_map[int(call)] = cm[call] 
                self.call_num_map[cm[call]] = int(call)
        else:
            self.lgr.error('Cannot open %s' % w7mapfile)
            return
        self.doBreaks()

    def doBreaks(self):
        ''' set breaks on syscall entries and exits '''
        call_num = None
        if self.run_to is None:
            self.lgr.debug('Win7Syscalls doBreaks, no call given, hit all syscalls')
            self.entry_break = SIM_breakpoint(self.cell, Sim_Break_Linear, Sim_Access_Execute, self.param.sysenter, 1, 0)
        else:
            self.lgr.debug('Win7Syscalls doBreaks, run to call %s' % self.run_to)
            call_name = 'Nt%s' % self.run_to
            if call_name in self.call_num_map:
                call_num = self.call_num_map[call_name]
                entry = self.getComputed(call_num)     
                self.entry_break = SIM_breakpoint(self.cell, Sim_Break_Linear, Sim_Access_Execute, entry, 1, 0)
            else:
                self.lgr.error('%s not in call_num_map' % call_name)
                return
                
        self.entry_hap = SIM_hap_add_callback_index("Core_Breakpoint_Memop", self.syscallHap, call_num, self.entry_break)
        self.exit_break = SIM_breakpoint(self.cell, Sim_Break_Linear, Sim_Access_Execute, self.param.sysret64, 1, 0)
        self.exit_hap = SIM_hap_add_callback_index("Core_Breakpoint_Memop", self.exitHap, None, self.exit_break)

    def getComputed(self, callnum):
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
        val = val 
        self.lgr.debug('getComputed syscall_jump 0x%x  val 0x%x' % (self.param.syscall_jump, val))
        entry = self.mem_utils.readPtr(self.cpu, val)
        entry = entry & 0xffffffff
        entry_shifted = entry >> 4
        computed = self.param.syscall_jump + entry_shifted
        self.lgr.debug('getComputed call 0x%x val 0x%x entry 0x%x entry_shifted 0x%x computed 0x%x' % (callnum, val, entry, entry_shifted, computed))
        return computed

    def getCurPid(self):
        pid = None
        cur_task = SIM_read_phys_memory(self.cpu, self.current_task_phys, self.mem_utils.WORD_SIZE)
        if cur_task is not None:
            pid_ptr = cur_task + self.pid_offset
            pid = self.mem_utils.readWord(self.cpu, pid_ptr)
        return cur_task, pid
 
    def syscallHap(self, call_num, third, forth, memory):
        ''' hit when kernel is entered due to sysenter '''
        #self.lgr.debug('sycallHap')
        cur_task, pid = self.getCurPid()
        if pid is None:
            return
        if cur_task is not None:
            if self.run_to is None:
                eax = self.mem_utils.getRegValue(self.cpu, 'syscall_num')
                ''' Use the call map to get the call name, and strip off "nt" '''
                if eax in self.call_map:
                    self.current_call_num = eax
                    call_name = self.call_map[eax][2:]
                    if self.run_to is None:
                        if pid is not None:
                            entry = self.getComputed(eax)     
                            self.lgr.debug('syscallHap x cur_task 0x%x pid %d eax: %d computed: 0%x call: %s' % (cur_task, pid, eax, entry, call_name)) 
                            if call_name == 'OpenFile':
                                SIM_break_simulation('open')
                                rsp = self.mem_utils.getRegValue(self.cpu, 'rsp')
                                param_start = rsp + 40
                                first_param = self.mem_utils.readPtr(self.cpu, param_start)
                                second_param = self.mem_utils.readPtr(self.cpu, param_start+8)
                                third_param = self.mem_utils.readPtr(self.cpu, param_start+16)
                                forth_param = self.mem_utils.readPtr(self.cpu, param_start+24)
                                print('syscall OpenFile, p1: 0x%x p2: 0x%x p3: 0x%x p4 0x%x' % (first_param, second_param, third_param, forth_param))
                                self.lgr.debug('syscall OpenFile, p1: 0x%x p2: 0x%x p3: 0x%x p4 0x%x' % (first_param, second_param, third_param, forth_param))
                                
                               
            else:
                call_name = self.call_map[call_num][2:]
                rip = self.mem_utils.getRegValue(self.cpu, 'rip')
                self.lgr.debug('syscallHap computed cur_task 0x%x rip: 0x%x pid %d call_num: %d call: %s' % (cur_task, rip, pid, call_num, call_name)) 
                rsi = self.mem_utils.getRegValue(self.cpu, 'rsi')
                param_stack = (rsi - 0x20) + 0x28
                param1 = self.mem_utils.readPtr(self.cpu, param_stack)
                self.lgr.debug('rsi 0x%x param_stack 0x%x first param is 0x%x' % (rsi, param_stack, param1))
                SIM_break_simulation('computed') 



    def exitHap(self, dumb, third, forth, memory):
        ''' hit when kernel is about to exit back to user space via sysret64 '''
        #self.lgr.debug('exitHap')
        cur_task, pid = self.getCurPid()
        if pid is None:
            return
        if cur_task is not None:
            rax = self.mem_utils.getRegValue(self.cpu, 'rax')
            if pid is not None:
                self.lgr.debug('exitHap cur_task: 0x%x pid:%d rax 0x%x' % (cur_task, pid, rax))
            else:
                self.lgr.debug('exitHap PID is none for cur_task: 0x%x' % (cur_task))
