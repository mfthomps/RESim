from simics import *
import os
import json
class Win7Tasks():
    def __init__(self, cpu, cell, mem_utils, current_task_phys, param, lgr):
        self.param = param
        self.pid_offset = param.ts_pid
        self.current_task_phys = 0x3634188
        #self.entry = 0xfffff80003622bc0
        self.entry = param.sysenter
        self.entry_break = None
        self.entry_hap = None
        self.mem_utils = mem_utils
        self.cell = cell
        self.cpu = cpu
        self.lgr = lgr
        resim_dir = os.getenv('RESIM_DIR')
        self.call_map = {}
        w7mapfile = os.path.join(resim_dir, 'windows', 'win7.json')
        if os.path.isfile(w7mapfile):
            cm = json.load(open(w7mapfile))     
            for call in cm:
                self.call_map[int(call)] = cm[call] 
        else:
            self.lgr.error('Cannot open %s' % w7mapfile)
            return
        self.doBreaks()
     

    def doBreaks(self):
        self.entry_break = SIM_breakpoint(self.cell, Sim_Break_Linear, Sim_Access_Execute, self.entry, 1, 0)
        self.entry_hap = SIM_hap_add_callback_index("Core_Breakpoint_Memop", self.syscallHap, None, self.entry_break)

    def getComputed(self, callnum):
        # looks like  cs:0xfffff800034f1e1d p:0x0034f1e1d  movsx r11,dword ptr [r10+rax*4]
        #             cs:0xfffff800034f1e24 p:0x0034f1e24  sar r11,4
        #             cs:0xfffff800034f1e28 p:0x0034f1e28  add r10,r11
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

    def syscallHap(self, dumb, third, forth, memory):
        cur_task = SIM_read_phys_memory(self.cpu, self.current_task_phys, self.mem_utils.WORD_SIZE)
        if cur_task is not None:
            pid_ptr = cur_task + self.pid_offset
            pid = self.mem_utils.readWord(self.cpu, pid_ptr)
            eax = self.mem_utils.getRegValue(self.cpu, 'syscall_num')
            if eax in self.call_map:
                call_name = self.call_map[eax][2:]
                if pid is not None:
                    self.lgr.debug('syscall cur_task 0x%x pid %d eax: %d call: %s' % (cur_task, pid, eax, call_name)) 
                    if call_name == 'OpenFile':
                        SIM_break_simulation('is open')
                        entry = self.getComputed(eax)     
                        self.lgr.debug('computed entry would be 0x%x' % entry)
                else:
                    self.lgr.debug('got none for pid task 0x%x' % cur_task)
            elif pid is not None:
                self.lgr.debug('call number %d not in call map, pid %d' % (eax, pid))
            else:
                self.lgr.debug('got none for pid and no bad call num %d for task 0x%x' % (eax, cur_task))
