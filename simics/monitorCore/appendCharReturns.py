from simics import *
import sys
import os
'''
Manage returns from functions that append data to string buffers
'''
class AppendCharReturns():
    def __init__(self, top, data_watch, cpu, def_file, cell_name, mem_utils, context_manager, lgr):
        self.top = top
        self.data_watch = data_watch
        self.cpu = cpu
        self.cell_name = cell_name
        self.mem_utils = mem_utils
        self.context_manager = context_manager
        self.lgr = lgr
        self.return_addrs = {}
        self.breaks = {}
        self.haps = {}
        self.loadDefs(def_file)
        self.lgr.debug('appendCharReturns, no APPEND_CHAR_RETURNS defined')
        self.setBreaks()

    def loadDefs(self, def_file):
        if os.path.isfile(def_file):
            with open(def_file) as fh:
                for line in fh:
                    if len(line.strip())==0 or line.strip().startswith('#'):
                        continue
                    parts = line.strip().split()
                    if len(parts) != 2:
                        self.lgr.error('appendCharReturns bad line in %s, %s' % (def_file, line))
                        return
                    # for now addresses are linear without adjustments               
                    addr = int(parts[0], 16)
                    self.return_addrs[addr] = parts[1]
                    self.lgr.debug('appendCharReturns added addr 0x%x as %s' % (addr, parts[1]))
        else:
            self.lgr.error('appendCharReturns, loadDefs failed to find %s' % def_file)

    def setBreaks(self):
        for addr in self.return_addrs:
            if addr not in self.haps:
                phys = self.mem_utils.v2p(self.cpu, addr)
                if phys is not None:
                    break_num = self.context_manager.genBreakpoint(self.cpu.physical_memory, Sim_Break_Physical, Sim_Access_Execute, phys, 1, 0)
                    self.haps[addr] = self.context_manager.genHapIndex("Core_Breakpoint_Memop", self.returnHap, addr, break_num, 'appendCharReturn')
                    self.lgr.debug('appendCharReturns added break for add 0x%x phys 0x%x' % (addr, phys))
                else:
                    self.lgr.error('appendCharReturns failed to get phys for add 0x%x' % (addr))
            else:
                self.lgr.debug('appendCharReturns break alreayd exists for addr 0x%x' % addr)

    def returnHap(self, addr, an_object, break_num, memory):
        if addr not in self.haps:
            return
        this = self.mem_utils.getRegValue(self.cpu, 'syscall_ret')
        buf_start = self.mem_utils.getRegValue(self.cpu, 'this')
        self.lgr.debug('appendCharReturns returnHap addr 0x%x this: 0x%x buf_start 0x%x' % (addr, this, buf_start))
        self.data_watch.doAppend(this, buf_start) 

    def rmHaps(self):
        for addr in self.haps:
            self.context_manager.genDeleteHap(self.haps[addr], immediate=True)
            self.lgr.debug('appendCharReturns rmHap addr 0x%x' % (addr))
        self.haps = {}
