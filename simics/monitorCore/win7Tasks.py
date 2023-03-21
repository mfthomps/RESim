from simics import *
import os
import json
class Win7Tasks():
    def __init__(self, cpu, cell, mem_utils, current_task_phys, lgr):
        self.pid_offset = 960
        self.current_task_phys = 0x3634188
        self.entry = 0xfffff80003622bc0
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

    def syscallHap(self, dumb, third, forth, memory):
        cur_task = SIM_read_phys_memory(self.cpu, self.current_task_phys, self.mem_utils.WORD_SIZE)
        if cur_task is not None:
            pid_ptr = cur_task + self.pid_offset
            pid = self.mem_utils.readWord(self.cpu, pid_ptr)
            eax = self.mem_utils.getRegValue(self.cpu, 'syscall_num')
            call_name = self.call_map[eax]
            if pid is not None:
                print('syscall cur_task 0x%x pid %d eax: %d call: %s' % (cur_task, pid, eax, call_name)) 
            else:
                print('got none for pid task 0x%x' % cur_task)
