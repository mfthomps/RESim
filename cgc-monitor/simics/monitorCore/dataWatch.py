from simics import *
import pageUtils
import stopFunction
import hapCleaner
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
        self.read_hap = None

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
 
    def readHap(self, dumb, third, forth, memory):
        addr = memory.logical_address
        self.context_manager.setIdaMessage('Data read from 0x%x within input buffer (%d bytes at 0x%x' % (addr, self.length, self.start))
        SIM_break_simulation('DataWatch read data')
        
    def setBreakRange(self):
        context = self.context_manager.getRESimContext()
        break_num = self.context_manager.genBreakpoint(context, Sim_Break_Linear, Sim_Access_Read, self.start, self.length, 0)
        end = self.start + self.length 
        eip = self.top.getEIP(self.cpu)
        self.lgr.debug('DataWatch setBreakRange eip: 0x%x Adding breakpoint %d for %x-%x length %x' % (eip, break_num, self.start, end, self.length))
        self.read_hap = self.context_manager.genHapIndex("Core_Breakpoint_Memop", self.readHap, None, break_num, 'dataWatch')

    def setBreakRangeNOTUSED (self):
        ''' Physical breakpoints do not seem reliable when debugging is active?  no clue, but virtual is fine for this use '''
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

    def stopHapNOT(self, dumb, one, exception, error_string):
        if self.stop_hap is None:
            return
        eip = self.top.getEIP(self.cpu)
        self.lgr.debug('DataWatch stopHap at eip: 0x%x  cycle: 0x%x' % (eip, self.cpu.cycles))
        SIM_hap_delete_callback_id("Core_Simulation_Stopped", self.stop_hap)
        self.stop_hap = None
        self.rmBreaks()
        self.top.skipAndMail()

    def stopHap(self, stop_action, one, exception, error_string):
        if stop_action is None or stop_action.hap_clean is None:
            print('stopHap error, stop_action None?')
            return
        eip = self.top.getEIP(self.cpu)
        self.lgr.debug('stopHap d eip 0x%x cycle: 0x%x' % (eip, stop_action.hap_clean.cpu.cycles))
        for hc in stop_action.hap_clean.hlist:
            if hc.hap is not None:
                if hc.htype == 'GenContext':
                    #self.lgr.debug('will delete GenContext hap %s' % str(hc.hap))
                    self.context_manager.genDeleteHap(hc.hap)
                else:
                    #self.lgr.debug('stopHap will delete hap %s' % str(hc.hap))
                    SIM_hap_delete_callback_id(hc.htype, hc.hap)
                hc.hap = None
        if self.stop_hap is not None:
            self.lgr.debug('stopHap will delete hap %s' % str(self.stop_hap))
            SIM_hap_delete_callback_id("Core_Simulation_Stopped", self.stop_hap)
            self.stop_hap = None
            for bp in stop_action.breakpoints:
                SIM_delete_breakpoint(bp)
            ''' check functions in list '''
            self.lgr.debug('stopHap now run actions %s' % str(stop_action.flist))
            stop_action.run()
         
    def setStopHap(self):
        f1 = stopFunction.StopFunction(self.top.skipAndMail, [], False)
        flist = [f1]
        hap_clean = hapCleaner.HapCleaner(self.cpu)
        hap_clean.add("GenContext", self.read_hap)
        stop_action = hapCleaner.StopAction(hap_clean, None, flist)
        self.stop_hap = SIM_hap_add_callback("Core_Simulation_Stopped", 
        	     self.stopHap, stop_action)

