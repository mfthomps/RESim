from simics import *
import pageUtils
import memUtils
import hapCleaner
from resimHaps import *
class ReverseToUser():
    '''
    set breakpoints for entire user space and reverse
    '''
    def __init__(self, param, lgr, cpu, cell, pid = 0):
        self.pid = pid
        self.cpu = cpu
        self.lgr = lgr

        
        pages = pageUtils.getPageBases(cpu, lgr, param.kernel_base)
        breaks = []
        range_start = None
        prev_physical = None
        pcell = cpu.physical_memory
        for page_info in pages:
            if cpu.architecture != 'arm':
                writable = memUtils.testBit(page_info.entry, 1)
                accessed = memUtils.testBit(page_info.entry, 5)
                if writable or not accessed:
                    #self.lgr.debug('ReverseToUser will skip %r %r' % (writable, accessed)) 
                    continue
            else:
                nx = memUtils.testBit(page_info.entry, 0)
                if nx:
                    #self.lgr.debug('ReverseToUser will skip nx')
                    continue
            self.lgr.debug('phys: 0x%x  logical: 0x%x' % (page_info.physical, page_info.logical))
            if range_start is None:
                range_start = page_info.physical
                prev_physical = page_info.physical
            else:
                if page_info.physical == prev_physical + pageUtils.PAGE_SIZE:
                    prev_physical = page_info.physical
                else:
                    self.lgr.debug('Page not contiguous: 0x%x  range_start: 0x%x  prev_physical: 0x%x' % (page_info.physical, range_start, prev_physical))
                    break_num = SIM_breakpoint(pcell, Sim_Break_Physical, Sim_Access_Execute, 
                        range_start, pageUtils.PAGE_SIZE, 0)
                    breaks.append(break_num)
                    range_start = page_info.physical
                    prev_physical = page_info.physical
        break_num = SIM_breakpoint(pcell, Sim_Break_Physical, Sim_Access_Execute, 
              range_start, pageUtils.PAGE_SIZE, 0)
        breaks.append(break_num)
        self.lgr.debug('set %d breaks', len(breaks)) 
        '''
        break_num = SIM_breakpoint(cell, Sim_Break_Linear, Sim_Access_Execute, 0x100000, 0x10000000, 0)
        breaks = [break_num]
        '''
        hap_clean = hapCleaner.HapCleaner(cpu)
        #stop_action = hapCleaner.StopAction(hap_clean, [break_num])
        stop_action = hapCleaner.StopAction(hap_clean, breaks)
        self.stop_hap = SIM_hap_add_callback("Core_Simulation_Stopped", 
        	     self.stopHap, stop_action)
        SIM_run_command('reverse') 

    def stopHap(self, stop_action, one, exception, error_string):
        self.lgr.debug('reverseToUser stopHap')
        for hc in stop_action.hap_clean.hlist:
            if hc.hap is not None:
                self.lgr.debug('reverseToUser will delete hap %s' % str(hc.hap))
                SIM_hap_delete_callback_id(hc.htype, hc.hap)
                hc.hap = None
        if self.stop_hap is not None:
            self.lgr.debug('reverseToUser will delete hap %s' % str(self.stop_hap))
            SIM_hap_delete_callback_id("Core_Simulation_Stopped", self.stop_hap)
            self.stop_hap = None
            for bp in stop_action.breakpoints:
                RES_delete_breakpoint(bp)
            ''' check functions in list '''
            if len(stop_action.flist) > 0:
                fun = stop_action.flist.pop(0)
                fun(stop_action.flist) 

    def cleanup(self, breaks):
        for bp in breaks:
            RES_delete_breakpoint(bp)
        SIM_hap_delete_callback_id("Core_Breakpoint_Memop", self.user_hap)

