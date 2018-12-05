from simics import *
import pageUtils
class DataWatch():
    ''' Watch a range of memory and stop when it is read.  Intended for use in tracking
        reads to buffers into which data has been read, e.g., via RECV. '''
    def __init__(self, top, cpu, page_size, context_manager, lgr):
        self.start = None
        self.end = None
        self.top = top
        self.cpu = cpu
        self.context_manager = context_manager
        self.lgr = lgr
        self.page_size = page_size
        self.the_breaks = []

    def setRange(self, start, length):
        self.lgr.debug('DataWatch set range start 0x%x length 0x%x' % (start, length))
        self.start = start
        self.length = length

    def watch(self):
        if self.start is not None:
            self.setBreakRange()
            self.setStopHap()
            return True
        return False
 
    def rmBreaks(self):
        for breakpt in self.the_breaks:
            SIM_delete_breakpoint(breakpt)
        self.the_breaks = []

    def setBreakRange(self):
        context = self.context_manager.getRESimContext()
        break_num = SIM_breakpoint(context, Sim_Break_Linear, 
               Sim_Access_Read, self.start, self.length, 0)
        self.the_breaks.append(break_num)
        end = self.start + self.length 
        eip = self.top.getEIP(self.cpu)
        self.lgr.debug('DataWatch setBreakRange eip: 0x%x Adding breakpoint %d for %x-%x length %x' % (eip, break_num, self.start, end, self.length))

    def setBreakRangeNOTUSED (self):
        '''
        Set breakpoints to over a range
        TBD: fix to set per page
        '''
        self.lgr.debug('setBreakRange begin')
        cell = self.cpu.physical_memory
        phys_block = self.cpu.iface.processor_info.logical_to_physical(self.start, Sim_Access_Read)
     
        end = self.start + self.length 
        eip = self.top.getEIP(self.cpu)
        phys_block = self.cpu.iface.processor_info.logical_to_physical(self.start, Sim_Access_Read)

        if phys_block.address != 0:
            break_num = SIM_breakpoint(cell, Sim_Break_Physical, 
               Sim_Access_Read, phys_block.address, self.length, 0)
            self.the_breaks.append(break_num)
            self.lgr.debug('DataWatch setBreakRange eip: 0x%x Adding breakpoint %d for %x-%x phys: 0x%x length %x' % (eip, break_num, self.start, end, phys_block.address, self.length))
                    
        elif phys_block.address == 0:
            self.lgr.debug('DataWatch FAILED breakpoints for at %x ' % (self.start))

    def rmBreaks(self):
        for breakpt in self.the_breaks:
            SIM_delete_breakpoint(breakpt)
        self.the_breaks = []
        self.stop_hap = None

    def stopHap(self, dumb, one, exception, error_string):
        if self.stop_hap is None:
            return
        eip = self.top.getEIP(self.cpu)
        self.lgr.debug('DataWatch stopHap at eip: 0x%x  cycle: 0x%x' % (eip, self.cpu.cycles))
        self.context_manager.setIdaMessage('Data read from input buffer (%d bytes at 0x%x' % (self.length, self.start))
        SIM_hap_delete_callback_id("Core_Simulation_Stopped", self.stop_hap)
        self.stop_hap = None
        self.rmBreaks()
        self.top.skipAndMail()
         
    def setStopHap(self):
        self.stop_hap = SIM_hap_add_callback("Core_Simulation_Stopped", 
        	     self.stopHap, None)

