from simics import *
class WatchWrite():
    def __init__(self, top, cpu, context_manager, lgr):
        self.top = top
        self.cpu = cpu
        self.context_manager = context_manager
        self.lgr = lgr
        self.proc_hap = None

    def watchRange(self, start, count):
        proc_break = self.context_manager.genBreakpoint(None, Sim_Break_Linear, Sim_Access_Write, start, count, 0)
        self.proc_hap = self.context_manager.genHapIndex("Core_Breakpoint_Memop", self.writeHap, None, proc_break, 'watchWrite')
        self.lgr.debug('watchWrite watchRange start 0x%x count 0x%x' % (start, count))

    def writeHap(self, dumb, the_object, the_break, memory):
        tid = self.top.getTID()
        write_value = SIM_get_mem_op_value_le(memory)
        self.lgr.debug('watchWrite writeHap tid:%s address 0x%x value 0x%x cycle: 0x%x' % (tid, memory.logical_address, write_value, self.cpu.cycles))
