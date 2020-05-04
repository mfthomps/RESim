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

    def stopCover(self):
        self.lgr.debug('coverage, stopCover')
        for bp in self.bp_list:
            try:
                SIM_delete_breakpoint(bp)
            except:
                self.lgr.debug('coverage, stopCover bp %d does not exist?' % bp)
        self.bp_list = []
        if self.bb_hap is not None:
            SIM_hap_delete_callback_id('Core_Breakpoint_Memop', self.bb_hap)
            self.bb_hap = None
            self.funs_hit = []
            self.blocks_hit = []

    def cover(self):
        if self.blocks is None:
            self.lgr.error('No basic blocks defined')
            return
        self.stopCover()
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

    def bbHap(self, dumb, third, break_num, memory):
        ''' HAP when a bb is hit '''
        if self.context_manager.watchingThis() and self.bb_hap is not None:
            addr = memory.logical_address
            if addr not in self.blocks_hit:
                self.blocks_hit.append(addr)
                addr_str = '%d' % addr
                if addr_str in self.blocks:
                    self.funs_hit.append(addr)
                self.lgr.debug('bbHap hit 0x%x %s count %d of %d   Functions %d of %d' % (addr, addr_str, 
                       len(self.blocks_hit), self.block_total, len(self.funs_hit), len(self.blocks)))
            ''' remove from list '''
            if break_num in self.bp_list:
                self.bp_list.remove(break_num)

    def saveHits(self, fname):
        ''' save blocks_hit to named file '''
        save_name = '%s.%s.hits' % (self.full_path, fname)
        with open(save_name, 'w') as outj:
            json.dump(self.blocks_hit, outj)

    def showCoverage(self):
        ''' blocks_hit and funs_hit are populated via the HAP. '''
        cover = (len(self.blocks_hit)*100) / self.block_total 
        print('Hit %d of %d blocks  (%d percent)' % (len(self.blocks_hit), self.block_total, cover))
        print('Hit %d of %d functions' % (len(self.funs_hit), len(self.blocks)))

    def saveCoverage(self, fname = None):
        self.lgr.debug('saveCoverage for %d functions' % len(self.funs_hit))
        ''' New dictionary for json.   Key is function address as a string '''
        hit_blocks = {}
        ''' funs_hit is list of addresses as integers '''
        for fun in self.funs_hit:
            fun_str = '%d' % fun
            hit_blocks[fun_str] = []

        ''' Create a list of bb hit per function '''
        for bb in self.blocks_hit:
            ''' Find the function that contains the bb '''
            for ofun in self.blocks:
                if bb in self.blocks[ofun]['blocks']:
                   ''' bb is in ofun '''
                   try:
                       hit_blocks[ofun].append(bb)       
                       break
                   except:
                       self.lgr.debug('%s not found in hit blocks, meaning not in funs_hit???  bb was 0x%x, likely IDA error' % (ofun, bb))
        s = json.dumps(hit_blocks)
        if fname is None:
            save_name = '%s.hits' % self.full_path
        else:
            save_name = '%s.%s.hits' % (self.full_path, fname)
        with open(save_name, 'w') as fh:
            fh.write(s)
 
    def difCoverage(self, fname):
        save_name = '%s.%s.hits' % (self.full_path, fname)
        if not os.path.isfile(save_name):
            print('No file named %s' % save_name)
            return
        with open(save_name) as fh:
            jhits = json.load(fh)
            for i in range(len(jhits)):
                if jhits[i] != self.blocks_hit[i]:
                    print('new 0x%x  old 0x%x index: %d' % (self.blocks_hit[i], jhits[i], i))
                    break
