import os
import json
from simics import *
class Coverage():
    def __init__(self, full_path, context_manager, cell, lgr):
        self.lgr = lgr
        self.cell = cell
        self.context_manager = context_manager
        self.bp_list = []
        self.bb_hap = None
        self.blocks = None
        self.block_total = 0
        self.funs_hit = []
        self.blocks_hit = []
        self.full_path = full_path
        block_file = full_path+'.blocks'
        if os.path.isfile(block_file):
            with open(block_file) as fh:
                self.blocks = json.load(fh)
                self.orig_blocks = json.loads(json.dumps(self.blocks))
                self.funs_total = len(self.blocks)
        else:
            self.lgr.debug('Coverage, no blocks at %s' % block_file)


    def cover(self):
        if self.blocks is None:
            self.lgr.error('No basic blocks defined')
            return
        resim_context = self.context_manager.getResimContext()
        for fun in self.blocks:
            for bb in self.blocks[fun]['blocks']:
                #bp = self.context_manager.genBreakpoint(self.cell, Sim_Break_Linear, Sim_Access_Execute, bb, 1, Sim_Breakpoint_Temporary)
                bp = SIM_breakpoint(resim_context, Sim_Break_Linear, Sim_Access_Execute, bb, 1, Sim_Breakpoint_Temporary)
                self.bp_list.append(bp)                 
        self.lgr.debug('generated %d breaks' % len(self.bp_list))
        self.block_total = len(self.bp_list)
        #self.bb_hap = self.context_manager.genHapRange("Core_Breakpoint_Memop", self.bbHap, None, self.bp_list[0], self.bp_list[-1], name='coverage_hap')
        self.bb_hap = SIM_hap_add_callback_range("Core_Breakpoint_Memop", self.bbHap, None, self.bp_list[0], self.bp_list[-1])

    def bbHap(self, dumb, third, forth, memory):
        if self.context_manager.watchingThis():
            addr = memory.logical_address
            if addr not in self.blocks_hit:
                self.blocks_hit.append(addr)
                addr_str = '%d' % addr
                if addr_str in self.blocks:
                    self.funs_hit.append(addr)
                self.lgr.debug('bbHap hit 0x%x %s count %d of %d   Functions %d of %d' % (addr, addr_str, 
                       len(self.blocks_hit), self.block_total, len(self.funs_hit), len(self.blocks)))

    def showCoverage(self):
        cover = (len(self.blocks_hit)*100) / self.block_total 
        print('Hit %d of %d blocks  (%d percent)' % (len(self.blocks_hit), self.block_total, cover))
        print('Hit %d of %d functions' % (len(self.funs_hit), len(self.blocks)))
        hit_blocks = {}
        for fun in self.funs_hit:
            fun_str = '%s' % fun
            hit_blocks[fun_str] = []
        for bb in self.blocks_hit:
            for ofun in self.blocks:
                if bb in self.blocks[ofun]['blocks']:
                   try:
                       hit_blocks[ofun].append(bb)       
                   except:
                       self.lgr.error('%s not found in hit blocks???' % ofun)
                   break
        s = json.dumps(hit_blocks)
        with open(self.full_path+'.hits', 'w') as fh:
            fh.write(s)
  
