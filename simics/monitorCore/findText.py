from resimHaps import *
from simics import *
class FindText():
    def __init__(self, top, cpu,  mem_utils, so_map, lgr):
        self.top = top
        self.cpu = cpu
        self.mem_utils = mem_utils
        self.so_map = so_map
        self.lgr = lgr
        self.tid = self.top.getTID()
        self.break_num = None
        self.hap = None
        self.setBreak()
        
 
    def setBreak(self):
        # assume at return from execve
        ip = self.top.getEIP()
        # crude guess TBD look for loader in root fs?
        loader_start = ip - 0x53b00
        self.break_num = SIM_breakpoint(self.cpu.current_context, Sim_Break_Linear, Sim_Access_Execute, 0, loader_start, 0)
        self.hap = RES_hap_add_callback_index("Core_Breakpoint_Memop", self.codeHap, self.cpu, self.break_num)
        self.lgr.debug('findText set break range 0 to start of loader guessed at 0x%x' % loader_start)

    def codeHap(self, cpu, the_obj, the_break, memory):
        if self.hap is None:
            return
        tid = self.top.getTID()
        if tid != self.tid:
            return
        addr = memory.logical_address
        self.lgr.debug('findText codeHap break num 0x%x addr 0x%x' % (the_break, addr))
        print('findText found at 0x%x' % addr)
        SIM_break_simulation('remove this')

    def rmBreaks(self):
        RES_delete_breakpoint(self.break_num)
        hap = self.hap
        SIM_run_alone(RES_delete_mem_hap, hap)
        self.break_num = None
        self.hap = None
            
             
