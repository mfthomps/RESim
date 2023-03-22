from simics import *
import os
import json
'''
Functions for experimenting with Win7 
to determine how parameters are passed to the kernel.
These assume a param has been built containing the pid offset.
And it assumes the param includes the syscall_jump value
reflecting jump table values for syscalls.
The physical address of the current task record is passed in,
e.g., from getKernelParam.  A real system would compute that from
the param, using gs_base and logic to account for aslr.

DO NOT rely on this for full traces -- it deliberately only looks
at one process at a time to keep it simple.
'''
class Win7CallParams():
    def __init__(self, cpu, cell, mem_utils, current_task_phys, param, lgr):
        self.param = param
        self.pid_offset = param.ts_pid
        self.current_task_phys = 0x3634188
        #self.entry = 0xfffff80003622bc0
        self.entry_break = None
        self.entry_hap = None
        self.exit_break = None
        self.exit_hap = None
        self.stack_param_break = None
        self.stack_param_hap = None
        self.mem_utils = mem_utils
        self.cell = cell
        self.cpu = cpu
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
        ''' for just watching one pid '''
        self.pid = None
        self.current_call_num = None
        ''' track parameters to different calls? '''
        self.call_param_offsets = {}
 
        #self.got_one = False

        self.doBreaks()

    def doBreaks(self):
        ''' set breaks on syscall entries and exits '''
        self.entry_break = SIM_breakpoint(self.cell, Sim_Break_Linear, Sim_Access_Execute, self.param.sysenter, 1, 0)
        self.entry_hap = SIM_hap_add_callback_index("Core_Breakpoint_Memop", self.syscallHap, None, self.entry_break)
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
 
    def syscallHap(self, dumb, third, forth, memory):
        ''' hit when kernel is entered due to sysenter '''
        #self.lgr.debug('sycallHap')
        cur_task, pid = self.getCurPid()
        if pid is None:
            return
        if self.pid is not None:
            if self.pid != pid:
                return
        if cur_task is not None:
            eax = self.mem_utils.getRegValue(self.cpu, 'syscall_num')
            ''' Use the call map to get the call name, and strip off "nt" '''
            if eax in self.call_map:
                self.current_call_num = eax
                call_name = self.call_map[eax][2:]
                #if not self.got_one and call_name != 'OpenFile':
                #    #self.lgr.debug('syscallHap looking for Open got %s' % call_name)
                #    return
                #self.got_one = True
                self.pid = pid
                if pid is not None:
                    entry = self.getComputed(eax)     
                    self.lgr.debug('syscallHap cur_task 0x%x pid %d eax: %d computed: 0%x call: %s' % (cur_task, pid, eax, entry, call_name)) 
                    '''
                    if call_name == 'OpenFile':
                        SIM_break_simulation('is open')
                        entry = self.getComputed(eax)     
                        self.lgr.debug('computed entry would be 0x%x' % entry)
                    '''
                    if self.current_call_num not in self.call_param_offsets:
                        self.call_param_offsets[self.current_call_num] = []
                    self.watchStackParams()
                else:
                    self.lgr.debug('got none for pid task 0x%x' % cur_task)
            elif pid is not None:
                self.lgr.debug('call number %d not in call map, pid:%d' % (eax, pid))
            else:
                self.lgr.debug('got none for pid and no bad call num %d for task 0x%x' % (eax, cur_task))

    def exitHap(self, dumb, third, forth, memory):
        ''' hit when kernel is about to exit back to user space via sysret64 '''
        #self.lgr.debug('exitHap')
        cur_task, pid = self.getCurPid()
        if pid is None:
            return
        if pid != self.pid:
            return
        if cur_task is not None:
            eax = self.mem_utils.getRegValue(self.cpu, 'syscall_num')
            if pid is not None:
                self.lgr.debug('exitHap cur_task: 0x%x pid:%d' % (cur_task, pid))
            else:
                self.lgr.debug('exitHap PID is none for cur_task: 0x%x' % (cur_task))
            self.pid = None
            SIM_run_alone(self.stopWatchStack, None)

    def watchStackParams(self):
        ''' Set a break on 80 bytes starting at the user-space sp to record kernel references to the
            user space stack '''
        rsp = self.mem_utils.getRegValue(self.cpu, 'rsp')
        self.lgr.debug('watchStackParams set break on sp 0x%x' % rsp)
        self.stack_param_break = SIM_breakpoint(self.cell, Sim_Break_Linear, Sim_Access_Read, rsp, 80, 0)
        self.stack_param_hap = SIM_hap_add_callback_index("Core_Breakpoint_Memop", self.stackParamHap, rsp, self.stack_param_break)

    def stopWatchStack(self, dumb):
        if self.stack_param_hap is not None:
            self.lgr.debug('stopWatchStack')
            SIM_hap_delete_callback_id("Core_Breakpoint_Memop", self.stack_param_hap)
            SIM_delete_breakpoint(self.stack_param_break)
            self.stack_param_hap = None
            self.task_param_break = None

    def stackParamHap(self, rsp, third, forth, memory):
        ''' Hit when kernel reads values in user space stack, implying they are parameters. '''
        #self.lgr.debug('stackParamHap') 
        cur_task, pid = self.getCurPid()
        if pid is None or pid != self.pid:
            return
        addr = memory.logical_address
        offset = addr - rsp 
        self.lgr.debug('stackParamHap read from 0x%x, offset %d from sp 0x%x' % (addr, offset, rsp))
        if offset not in self.call_param_offsets[self.current_call_num]:
            self.call_param_offsets[self.current_call_num].append(offset) 

    def showParams(self):
        for call_num in self.call_param_offsets:
            call_name = self.call_map[call_num][2:]
            print('%s' % call_name)
            for offset in sorted(self.call_param_offsets[call_num]):
                print('\t%d' % offset) 
