from simics import *
from resimHaps import *
class DisableAndRun():
    def __init__(self, cpu, addr, context_manager, lgr, callback=None):
        self.cpu = cpu
        self.addr = addr
        self.lgr = lgr
        self.context_manager = context_manager
        self.callback = callback
        self.lgr.debug('DisableAndRun for 0x%x' % addr)
        SIM_run_alone(self.setBreakHap, addr)

    def setBreakHap(self, addr):
        phys_block = self.cpu.iface.processor_info.logical_to_physical(addr, Sim_Access_Execute)
        if phys_block is None or phys_block.address is None:
            self.lgr.error('DisableAndRun could not get phys addr for 0x%x' % addr)
            return
        else: 
            self.addr_break = SIM_breakpoint(self.cpu.physical_memory, Sim_Break_Physical, Sim_Access_Execute, phys_block.address, 1, 0)
            self.addr_hap = RES_hap_add_callback_index("Core_Breakpoint_Memop", self.hitAddr, None, self.addr_break)
            self.context_manager.disableAll()
            self.lgr.debug('DisableAndRun for 0x%x, set break and disabled context manager breaks' % addr)
 
    def hitAddr(self, deumb, the_object, the_break, memory):
        if self.addr_hap is not None:
            self.lgr.debug('DisableAndRun hit break 0x%x' % self.addr)
            self.context_manager.enableAll()
            hap = self.addr_hap
            RES_delete_breakpoint(self.addr_break)
            self.addr_break = None
            SIM_run_alone(self.rmHap, hap)
            self.addr_hap = None

    def rmHap(self, hap):
        RES_hap_delete_callback_id("Core_Breakpoint_Memop", hap)
        
