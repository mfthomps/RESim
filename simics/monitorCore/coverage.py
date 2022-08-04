import os
import json
import random
import backStop
from collections import OrderedDict
import time
from simics import *
import pageUtils
import resimUtils
from resimHaps import *
'''
Manage code coverage tracking, maintaining two hits files per coverage unit.

Note, ALL coverage defaults to physical addresses.  Use linear=True when enabling coverage to use
virtual addresses.  That assumes you have enable the contextManager to alter the cpu context on task switches.
Does not use the Context Manager for breakpoints

Tracks a single code file at a time, e.g., main or a single so file.  TBD expand to include multiple blocks_hit dictionaries?

Output files of hits use addresses from code file, i.e., not runtime addresses.
'''
class Coverage():
    def __init__(self, top, full_path, hits_path, context_manager, cell, so_map, cpu, run_from_snap, lgr):
        self.lgr = lgr
        self.cell = cell
        self.cpu = cpu
        self.top = top
        self.so_map = so_map
        self.context_manager = context_manager
        self.bp_list = []
        self.bb_hap = []
        self.blocks = None
        self.block_total = 0
        self.funs_hit = []
        self.blocks_hit = OrderedDict()
        self.full_path = full_path
        self.hits_path = hits_path
        self.did_cover = False
        self.enabled = False
        self.latest_hit = None
        self.backstop = None
        self.backstop_cycles = None
        self.afl = None
        self.prev_loc = None
        self.map_size = None
        self.trace_bits = None
        self.afl_map = {}
        self.proc_status = 0
        self.hit_count = 0
        self.afl_del_breaks = []
        self.pid = None
        self.linear = False
        # TBD not currently used
        self.physical = False
        self.addr_map = {}
        ''' offset due to relocation, e.g., of so file '''
        self.offset = 0
        if self.cpu.architecture == 'arm':
            pcreg = 'pc'
        else:
            pcreg = 'eip'
        self.pc_reg = self.cpu.iface.int_register.get_number(pcreg)
        ''' jump over crc calcs and such '''
        self.jumpers = None
        ''' manage set of basic block addresses we don't want to cover due to their being used in other threads (performance) '''
        self.crate_dead_zone = None
        self.dead_map = []
        self.run_from_snap = run_from_snap
        self.time_start = time.time()
        random.seed(12345)
   
        self.begin_tmp_bp = None 
        self.begin_tmp_hap = None 
        self.unmapped_addrs = []
        self.missing_pages = {}
        self.missing_tables = {}
        self.missing_breaks = {}
        self.missing_haps = {}
        self.force_default_context = False
        self.resim_context = self.context_manager.getRESimContext()
        self.default_context = self.context_manager.getDefaultContext()
        self.jumpers = {}
        self.did_exit=False
        self.so_entry = None
        self.no_save = False
        self.mode_hap = None
        self.only_thread = False
     
    def loadBlocks(self, block_file):
        if os.path.isfile(block_file):
            with open(block_file) as fh:
                self.blocks = json.load(fh)
                self.orig_blocks = json.loads(json.dumps(self.blocks))
                self.funs_total = len(self.blocks)
            self.lgr.debug('coverage loaded from %s' % block_file)
        else:
            self.lgr.debug('Coverage, no blocks at %s' % block_file)

    def stopCover(self, keep_hits=False):
        self.lgr.debug('coverage, stopCover')
        for bp in self.bp_list:
            try:
                RES_delete_breakpoint(bp)
            except:
                self.lgr.debug('coverage, stopCover bp %d does not exist?' % bp)
        self.bp_list = []
        for hap in self.bb_hap:
            SIM_hap_delete_callback_id('Core_Breakpoint_Memop', hap)
        self.bb_hap = []
        if not keep_hits:
            self.funs_hit = []
            self.blocks_hit = OrderedDict()

        for addr in self.missing_breaks:
            RES_delete_breakpoint(self.missing_breaks[addr])
        for bp in self.missing_haps:
            SIM_hap_delete_callback_id('Core_Breakpoint_Memop', self.missing_haps[bp])
        
        self.missing_breaks = {}    
        self.missing_haps = {}    
        self.begin_tmp_bp = None 
        self.begin_tmp_hap = None 
        self.unmapped_addrs = []
        self.missing_pages = {}
        self.missing_tables = {}
        self.did_cover=False

    def setBreak(self, bb_rel):
        ''' default is to use physical.  current exceptions are call for linear or default_context '''
        bp = None
        if self.linear:
            bp = SIM_breakpoint(self.resim_context, Sim_Break_Linear, Sim_Access_Execute, bb_rel, 1, 0)
        elif self.force_default_context:
            bp = SIM_breakpoint(self.default_context, Sim_Break_Linear, Sim_Access_Execute, bb_rel, 1, 0)
        else: 
            phys_block = self.cpu.iface.processor_info.logical_to_physical(bb_rel, Sim_Access_Execute)
            if phys_block.address == 0 or phys_block.address is None:
                #self.lgr.debug('coverage setBreak unmapped: 0x%x' % bb_rel)
                self.unmapped_addrs.append(bb_rel)
            else:
                if self.afl:
                    bp = SIM_breakpoint(self.cpu.physical_memory, Sim_Break_Physical, Sim_Access_Execute, phys_block.address, 1, 0)
                else:
                    bp = SIM_breakpoint(self.cpu.physical_memory, Sim_Break_Physical, Sim_Access_Execute, phys_block.address, 1, Sim_Breakpoint_Temporary)
                self.addr_map[bp] = bb_rel
        return bp
 
    def cover(self, force_default_context=False, physical=False):
        self.force_default_context = force_default_context
        self.lgr.debug('coverage: cover physical: %r linear: %r' % (physical, self.linear))
        self.offset = 0
        self.physical = physical
        block_file = self.full_path+'.blocks'
        if not os.path.isfile(block_file):
            self.lgr.error('coverage: No blocks file at %s' % block_file)
            return
        self.loadBlocks(block_file)         
        so_entry = self.so_map.getSOAddr(self.full_path, pid=self.pid)
        if so_entry is None:
           
            so_entry = self.so_map.getSOAddr(self.top.getProgName(self.pid), pid=self.pid)
            if so_entry is None:
                self.lgr.error('coverage no SO entry for %s' % self.full_path)
                return
        self.so_entry = so_entry
        if so_entry.address is not None:
            if so_entry.locate is not None:
                self.offset = so_entry.locate+so_entry.offset
            #else:
            #    self.offset = so_entry.address
        else:
            self.lgr.debug('coverage: cover no address in so_entry for %s' % self.full_path)
            return
        #self.lgr.debug('cover offset 0x%x' % self.offset)
        if self.blocks is None:
            self.lgr.error('Coverge: No basic blocks defined')
            return
        self.stopCover()
        tmp_list = []
        prev_bp = None
        for fun in self.blocks:
            for block_entry in self.blocks[fun]['blocks']:
                bb = block_entry['start_ea']
                bb_rel = bb + self.offset
                if bb_rel in self.dead_map:
                    #self.lgr.debug('skipping dead spot 0x%x' % bb_rel)
                    continue
                if self.afl:
                    rand = random.randrange(0, self.map_size)
                    self.afl_map[bb_rel] = rand
                bp = self.setBreak(bb_rel)
                if bp is not None:
                    self.bp_list.append(bp)                 
                    #self.lgr.debug('cover break at 0x%x fun 0x%x -- bb: 0x%x offset: 0x%x break num: %d' % (bb_rel, 
                    #   int(fun), bb, self.offset, bp))
                    if prev_bp is not None and bp != (prev_bp+1):
                        self.doHapRange(tmp_list)
                        tmp_list = []
                    tmp_list.append(bp) 
                    prev_bp = bp
                    

        if self.afl or self.force_default_context:
            self.lgr.debug('coverage generated ?? context %d breaks' % (len(self.bp_list)))
        else:
            self.lgr.debug('coverage generated %d RESim context breaks and %d unmapped' % (len(self.bp_list), len(self.unmapped_addrs)))
        self.block_total = len(self.bp_list)
        if len(tmp_list) > 0:
            self.doHapRange(tmp_list)

        if self.afl:
            self.lgr.debug('coverage watchGroupExits')
            self.context_manager.watchGroupExits()
            self.context_manager.setExitCallback(self.recordExit)
            self.loadExits()
        self.handleUnmapped()

    def doHapRange(self, bp_list):
        if self.afl:
            #hap = self.context_manager.genHapRange("Core_Breakpoint_Memop", self.bbHap, None, self.bp_list[0], self.bp_list[-1], name='coverage_hap')
            hap = SIM_hap_add_callback_range("Core_Breakpoint_Memop", self.bbHap, None, bp_list[0], bp_list[-1])
        else:
            hap = SIM_hap_add_callback_range("Core_Breakpoint_Memop", self.bbHap, None, bp_list[0], bp_list[-1])
        #self.lgr.debug('coverage cover add hap %d  bp %d-%d' % (hap, bp_list[0], bp_list[-1]))
        self.bb_hap.append(hap)

    def handleUnmapped(self):
        for bb_rel in self.unmapped_addrs:
            #self.lgr.debug('handleUnmapped for 0x%x' % bb_rel)
            pt = pageUtils.findPageTable(self.cpu, bb_rel, self.lgr)
            if pt.page_addr is not None:
                if pt.page_addr not in self.missing_pages:
                    self.missing_pages[pt.page_addr] = []
                    break_num = SIM_breakpoint(self.cpu.physical_memory, Sim_Break_Physical, Sim_Access_Write, pt.page_addr, 1, 0)
                    #self.lgr.debug('coverage no physical address for 0x%x, set break %d on page_addr 0x%x' % (bb_rel, break_num, pt.page_addr))
                    self.missing_breaks[pt.ptable_addr] = break_num
                    self.missing_haps[break_num] = SIM_hap_add_callback_index("Core_Breakpoint_Memop", self.pageHap, 
                          None, break_num)
                self.missing_pages[pt.page_addr].append(bb_rel)
                #self.lgr.debug('handleUnmapped bb 0x%x added to missing pages for page addr 0x%x' % (bb_rel, pt.page_addr))
            elif pt.ptable_addr is not None:
                if pt.ptable_addr not in self.missing_tables:
                    self.missing_tables[pt.ptable_addr] = []
                    break_num = SIM_breakpoint(self.cpu.physical_memory, Sim_Break_Physical, Sim_Access_Write, pt.ptable_addr, 1, 0)
                    self.lgr.debug('coverage no physical address for 0x%x, set break %d on phys ptable_addr 0x%x' % (bb_rel, break_num, pt.ptable_addr))
                    self.missing_breaks[pt.ptable_addr] = break_num
                    self.missing_haps[break_num] = SIM_hap_add_callback_index("Core_Breakpoint_Memop", self.tableHap, 
                          None, break_num)
                self.missing_tables[pt.ptable_addr].append(bb_rel)
                #self.lgr.debug('handleUnmapped bb 0x%x added to missing tables for table addr 0x%x' % (bb_rel, pt.ptable_addr))
            else:
                self.lgr.debug('coverage, no page table address for 0x%x ' % (bb_rel))
                ''' don't report on external jump tables etc.'''
                if self.so_entry.text_start is not None:
                    end = self.so_entry.text_start + self.so_entry.text_size
                    if bb_rel >= self.so_entry.text_start and bb_rel <= end:
                        self.lgr.error('coverage, no page table address for text 0x%x so_entry.text_start 0x%x - 0x%x' % (bb_rel, 
                             self.so_entry.text_start, end))
                    else:
                        self.lgr.error('coverage, has text_start but no page table address for 0x%x so_entry.address 0x%x' % (bb_rel, self.so_entry.address))
                else:
                    self.lgr.error('coverage, no page table address for 0x%x so_entry.address 0x%x' % (bb_rel, self.so_entry.address))


    def getNumBlocks(self):
        return len(self.bp_list)

    def recordExit(self):
        self.proc_status = 1
        self.lgr.debug('coverage recordExit of program under test')
        SIM_break_simulation('did exit')

    def recordHang(self, cycles):
        self.proc_status = 2
        self.lgr.debug('coverage recordhang of program under test cycle 0x%x' % cycles)
        SIM_break_simulation('did hang')

    def watchExits(self, pid=None, callback=None):
        self.context_manager.watchGroupExits(pid=pid)
        if self.afl:
            self.context_manager.setExitCallback(self.recordExit)
        elif callback is not None:
            self.context_manager.setExitCallback(callback)

    def getStatus(self):
        return self.proc_status

    def saveDeadFile(self):
        dead_file = '%s.dead' % self.run_from_snap
        with open(dead_file, 'w') as fh:
            fh.write(json.dumps(self.dead_map))
        SIM_run_alone(SIM_run_command, 'q')
                        
    def addHapAlone(self, bplist): 
        if len(bplist) == 0:
            self.lgr.error('coverage addHapAlone with empty bplist')
            return
        #self.lgr.debug('addHapAlone set on range %d to %d' % (bplist[0], bplist[-1]))
        hap = SIM_hap_add_callback_range("Core_Breakpoint_Memop", self.bbHap, None, bplist[0], bplist[-1])
        #self.lgr.debug('addHapAlone adding hap %d bp %d-%d' % (hap, bplist[0], bplist[-1]))
        self.bb_hap.append(hap)

    class MyMemTrans():
        def __init__(self, memory):
            self.length = memory.size
            self.op_type = SIM_get_mem_op_type(memory)
            self.type_name = SIM_get_mem_op_type_name(self.op_type)
            self.physical = memory.physical_address
            if self.op_type is Sim_Trans_Store:
                self.value = SIM_get_mem_op_value_le(memory)
            else:
                self.value = None
        
    def delModeAlone(self, dumb):
        if self.mode_hap is not None:
            SIM_hap_delete_callback_id("Core_Mode_Change", self.mode_hap)
            self.mode_hap = None

    def modeChanged(self, mem_trans, one, old, new):
        if self.mode_hap is None:
            return
        #self.lgr.debug('modeChanged after table updated, check pages in table')
        self.tableUpdated(mem_trans)
        SIM_run_alone(self.delModeAlone, None)
    
    def tableHap(self, dumb, third, break_num, memory):
        length = memory.size
        op_type = SIM_get_mem_op_type(memory)
        type_name = SIM_get_mem_op_type_name(op_type)
        physical = memory.physical_address
        #self.lgr.debug('tableHap phys 0x%x len %d  type %s' % (physical, length, type_name))
        if break_num in self.missing_haps:
            if length == 4:
                if op_type is Sim_Trans_Store:
                    mem_trans = self.MyMemTrans(memory)
                    self.mode_hap = SIM_hap_add_callback_obj("Core_Mode_Change", self.cpu, 0, self.modeChanged, mem_trans)
                else:
                    self.lgr.error('tableHap op_type is not store')
            else:
                self.lgr.error('coverage tableHap for 64 bits not yet handled')
        else:
            self.lgr.debug('coverage tableHap breaknum should have not hap %d' % break_num) 

    def tableUpdated(self, mem_trans):
            length = mem_trans.length
            op_type = mem_trans.op_type
            type_name = mem_trans.type_name
            physical = mem_trans.physical
            #self.lgr.debug('updateTable phys 0x%x len %d  type %s' % (physical, length, type_name))
            #if length == 4 and self.cpu.architecture == 'arm':
            if length == 4:
                if op_type is Sim_Trans_Store:
                    value = mem_trans.value
                    if value == 0:
                        #self.lgr.debug('tableHap value is zero')
                        return
                   
                    bb_index = len(self.bp_list) 
                    if self.begin_tmp_bp is None:
                        self.begin_tmp_bp = bb_index
                        self.begin_tmp_hap = len(self.bb_hap)
                        print('Warning, not all basic blocks in memory.  Will dynmaically add/remove breakpoints per page table accesses')
                        self.lgr.debug('coverage tableHap setting begin_tmp_bp to %d and begin_tmp_hap to %d' % (self.begin_tmp_bp, self.begin_tmp_hap))
                    prev_bp = None
                    got_one = False
                    for bb in self.missing_tables[physical]:
                        pt = pageUtils.findPageTable(self.cpu, bb, self.lgr, use_sld=value)
                        if pt.page_addr is None or pt.page_addr == 0:
                            self.lgr.debug('pt still not set for 0x%x, page table addr is 0x%x' % (bb, pt.ptable_addr))
                            continue
                        got_one = True
                        addr = pt.page_addr | (bb & 0x00000fff)
                        bp = SIM_breakpoint(self.cpu.physical_memory, Sim_Break_Physical, Sim_Access_Execute, addr, 1, 0)
                        #self.lgr.debug('tableHap bb: 0x%x added break %d at phys addr 0x%x %s' % (bb, bp, addr, pt.valueString()))
                        self.addr_map[bp] = bb
                        if prev_bp is not None and bp != (prev_bp+1):
                            #self.lgr.debug('coverage tableHap broken sequence set hap and update index')
                            SIM_run_alone(self.addHapAlone, self.bp_list[bb_index:])
                            bb_index = len(self.bp_list)
                        self.bp_list.append(bp)                 
                        prev_bp = bp
                    if not got_one:
                        self.lgr.error('tableHap no pt for any bb address 0x%x' % value)
                    SIM_run_alone(self.addHapAlone, self.bp_list[bb_index:])
            else:
                self.lgr.error('coverage tableHap for 64 bits not yet handled')

    def rmTableHap(self, break_num):
        SIM_hap_delete_callback_id('Core_Breakpoint_Memop', self.missing_haps[break_num])
        del self.missing_haps[break_num]
   
    def pageHap(self, dumb, third, break_num, memory):
        if break_num in self.missing_haps:
            length = memory.size
            op_type = SIM_get_mem_op_type(memory)
            type_name = SIM_get_mem_op_type_name(op_type)
            physical = memory.physical_address
            self.lgr.debug('pageHap phys 0x%x len %d  type %s' % (physical, length, type_name))
            if length == 4 and self.cpu.architecture == 'arm':
                if op_type is Sim_Trans_Store:
                    value = SIM_get_mem_op_value_le(memory)
                    #self.lgr.debug('pageHap value is 0x%x' % value)
                for bb in self.missing_pages[memory.physical_address]:
                    offset = memUtils.bitRange(pdir_entry, 0, 19)
                    addr = value + offset
                    bp = SIM_breakpoint(self.cpu.physical_memory, Sim_Break_Physical, Sim_Access_Execute, addr, 1, 0)
                    self.lgr.error('pageHap NOT YET FINISHED added break at phys addr 0x%x' % addr)
                    self.addr_map[bp] = bb
        else:
            self.lgr.debug('coverage pageHap breaknum should have no hap %d' % break_num)

    def bbHap(self, dumb, third, break_num, memory):
        ''' HAP when a bb is hit '''

        # TBD convoluted determination of phys vs linear
        if self.linear:
            addr = memory.logical_address
        elif self.force_default_context:
            addr = memory.logical_address
        else: 
            addr = memory.physical_address

        ''' 
        NOTE!  reading simulated memory may slow down fuzzing by a factor of 2!
        pid = self.top.getPID()
        if pid != self.pid:
            self.lgr.debug('converage bbHap, bp 0x%x not my pid, got %d I am %d' % (addr, pid, self.pid))
            return
        ''' 
        
        dead_set = False
        if self.create_dead_zone:
            ''' User wants to identify breakpoints hit by other threads so they can later be masked '''
            pid = self.top.getPID()
            if pid != self.pid:
                self.lgr.debug('converage bbHap, not my pid, got %d I am %d  num spots %d' % (pid, self.pid, len(self.dead_map)))
                dead_set = True

        if self.only_thread:
            pid = self.top.getPID()
            if pid != self.pid:
                self.lgr.debug('coverage bbHap, wrong thread: %d' % pid)
                return
        
        if addr == 0:
            self.lgr.error('bbHap,  address is zero? phys: 0x%x break_num %d' % (memory.physical_address, break_num))
            if memory.physical_address is not None:
                addr = memory.physical_address
            else:
                return
        this_addr = addr
        #if self.physical or (self.afl and not self.linear):
        if not self.linear and not self.force_default_context:
            this_addr = self.addr_map[break_num]
        if this_addr in self.afl_del_breaks:
            ''' already 255 hits, see if a jumper will alter the PC'''
            if self.backstop_cycles is not None and self.backstop_cycles > 0:
                self.backstop.setFutureCycle(self.backstop_cycles, now=True)
            if self.jumpers is not None and this_addr in self.jumpers:
                self.cpu.iface.int_register.write(self.pc_reg, self.jumpers[this_addr])
            #self.lgr.debug('coverage bbHap 0x%x in del_breaks, return' % this_addr)
            return


        #pid = self.top.getPID()
        #self.lgr.debug('coverage bbHap address 0x%x bp %d pid: %d cycle: 0x%x' % (this_addr, break_num, pid, self.cpu.cycles))

        if self.backstop_cycles is not None and self.backstop_cycles > 0:
            self.backstop.setFutureCycle(self.backstop_cycles, now=True)
        if (not self.linear or self.context_manager.watchingThis()) and len(self.bb_hap) > 0:
            #self.lgr.debug('phys %r  afl %r' % (self.physical, self.afl))
            ''' see if a jumper should skip over code by changing the PC '''
            prejump_addr = None
            if self.jumpers is not None and this_addr in self.jumpers:
                #self.lgr.debug('got jumper, skip from 0x%x' % this_addr)
                #phys_block = self.cpu.iface.processor_info.logical_to_physical(self.jumpers[this_addr], Sim_Access_Execute)
                self.cpu.iface.int_register.write(self.pc_reg, self.jumpers[this_addr])
                #self.lgr.debug('coverage jumpers jump to 0x%x' % self.jumpers[addr]) 
                prejump_addr = this_addr
            if not self.afl:
                #self.lgr.debug('coverage this_addr is 0x%x' % this_addr) 
                if this_addr not in self.blocks_hit:
                    self.blocks_hit[this_addr] = self.cpu.cycles
                    self.latest_hit = this_addr
                    addr_str = '%d' % (this_addr - self.offset)
                    if addr_str in self.blocks:
                        self.funs_hit.append(this_addr)
                        #self.lgr.debug('bbHap add funs_hit 0x%x' % addr)
                    #self.lgr.debug('bbHap hit 0x%x %s count %d of %d   Functions %d of %d' % (this_addr, addr_str, 
                    #       len(self.blocks_hit), self.block_total, len(self.funs_hit), len(self.blocks)))
                else:
                    #self.lgr.debug('addr already in blocks_hit')
                    pass
            else:
                ''' AFL mode '''
                if this_addr not in self.afl_map:
                    self.lgr.debug('broke at wrong addr linear 0x%x' % this_addr)
                    pid = self.top.getPID()
                    if pid != self.pid:
                        self.lgr.debug('converage bbHap, not my pid, got %d I am %d context: %s' % (pid, self.pid, str(self.cpu.current_context)))
                    #SIM_break_simulation('broken')
                    return
                if dead_set:
                    if this_addr not in self.dead_map:
                        self.dead_map.append(this_addr)
                        self.time_start = time.time()
                if self.create_dead_zone:
                    now = time.time()
                    delta = now - self.time_start 
                    #self.lgr.debug('delta is %d' % int(delta))
                    if int(delta) > 120: 
                        self.lgr.debug('120 seconds since last dead spot %d dead spots' % len(self.dead_map)) 
                        self.saveDeadFile()

                cur_loc = self.afl_map[this_addr]
                index = cur_loc ^ self.prev_loc
                #self.lgr.debug('coverage bbHap cur_loc %d, index %d' % (cur_loc, index))
                #self.lgr.debug('coverage bbHap addr 0x%x, offset 0x%x linear: 0x%x cycle: 0x%x' % (addr, self.offset, self.addr_map[break_num], self.cpu.cycles))
                if self.trace_bits[index] == 0:
                    self.hit_count += 1
                if self.trace_bits[index] == 255:
                    self.afl_del_breaks.append(this_addr)
                    if prejump_addr is not None: 
                        self.afl_del_breaks.append(prejump_addr)
                    if True:
                        ''' Current strategy is to assume deleting breaks is just as bad as hitting saturated breaks.  consider before 
                            prematurely optimizing'''
                        #self.lgr.debug('high hit break_num %d count index %d 0x%x' % (break_num, index, this_addr))
                        if this_addr not in self.afl_del_breaks:
                            #SIM_delete_breakpoint(break_num)
                            #index = self.bp_list.index(break_num)
                            self.afl_del_breaks.append(this_addr)
                            '''
                            if index < self.begin_tmp_bp:
                                self.afl_del_breaks.append(this_addr)
                            else:
                                self.bp_list.remove(break_num)
                            '''
                else:
                    self.trace_bits[index] =  self.trace_bits[index]+1
                #self.trace_bits[index] = min(255, self.trace_bits[index]+1)
                self.prev_loc = cur_loc >> 1
        
    def getTraceBits(self): 
        #self.lgr.debug('hit count is %d' % self.hit_count)
        return self.trace_bits

    def getHitCount(self):
        if self.afl:
            return self.hit_count;
        else:
            return len(self.blocks_hit)

    def saveHits(self, fname):
        ''' save blocks_hit to named file '''
        save_name = '%s.%s.hits' % (self.hits_path, fname)
        try:
            os.makedirs(os.path.dirname(self.hits_path))
        except:
            pass
        with open(save_name, 'w') as outj:
            json.dump(self.blocks_hit, outj)
            self.lgr.debug('coveraged saveHits saved blocks_hit to %s' % save_name)

    def showCoverage(self):
        ''' blocks_hit and funs_hit are populated via the HAP. '''
        cover = (len(self.blocks_hit)*100) / self.block_total 
        print('Hit %d of %d blocks  (%d percent)' % (len(self.blocks_hit), self.block_total, cover))
        print('Hit %d of %d functions' % (len(self.funs_hit), len(self.blocks)))

    def saveCoverage(self, fname = None):
        if not self.enabled or self.no_save:
            return
        self.lgr.debug('saveCoverage for %d functions' % len(self.funs_hit))
        #hit_list = list(self.blocks_hit.keys())
        hit_list = []
        for hit, cycle in self.blocks_hit.items():
            hit_list.append(hit)
        s = json.dumps(hit_list)
        if fname is None:
            save_name = '%s.hits' % self.hits_path
        else:
            save_name = '%s.%s.hits' % (self.hits_path, fname)
        try:
            os.makedirs(os.path.dirname(self.hits_path))
        except:
            pass
        with open(save_name, 'w') as fh:
            fh.write(s)
            fh.flush()
        self.lgr.debug('coverage saveCoverage to %s' % save_name)
        print('Coverage saveCoverage to %s' % save_name)

    def saveCoverageNOT_USED(self, fname = None):
        ''' Not used. More value in saving order of hits.  Function allocation can always be recalculated '''
        if not self.enabled:
            return
        self.lgr.debug('saveCoverage for %d functions' % len(self.funs_hit))
        ''' New dictionary for json.   Key is function address as a string '''
        hit_blocks = {}
        ''' funs_hit is list of addresses as integers '''
        ''' new hit_blocks will all be relocated '''
        '''
        for fun in self.funs_hit:
            fun_str = '%d' % fun
            hit_blocks[fun] = []
            self.lgr.debug('saveCoverage add %s (0x%x) to hit_blocks' % (fun_str, fun))
        '''

        ''' Create a list of bb hit per function '''
        ''' blocks_hit addresses are relocated from offset self.offset'''
        for bb in self.blocks_hit:
            ''' Find the function that contains the bb '''
            ''' self.blocks is not relocated '''
            bb_org = bb - self.offset
            got_it = False
            for ofun in self.blocks:
                for entry in self.blocks[ofun]['blocks']:
                    if entry['start_ea'] == bb_org:
                        ''' bb is in ofun '''
                        ofun_val = int(ofun)
                        ofun_rel = ofun_val + self.offset 
                        ofun_str = str(ofun_rel)
                        if ofun_str not in hit_blocks:
                            #self.lgr.debug('saveCoverage fun %s (0x%x) not in hit_blocks add it' % (ofun_str, ofun_rel))
                            hit_blocks[ofun_str] = []
                        hit_blocks[ofun_str].append(bb)       
                        got_it = True
                        #break
                # ida may put same block into multiple functions, e.g., arm "b fu"
                #if got_it:
                #    break
        s = json.dumps(hit_blocks)
        if fname is None:
            save_name = '%s.hits' % self.hits_path
        else:
            save_name = '%s.%s.hits' % (self.hits_path, fname)
        try:
            os.makedirs(os.path.dirname(self.hits_path))
        except:
            pass
        with open(save_name, 'w') as fh:
            fh.write(s)
            fh.flush()
        self.lgr.debug('coverage saveCoverage to %s' % save_name)
        print('Coverage saveCoverage to %s' % save_name)


    def restoreAFLBreaks(self):
        ''' leave unused code as cautionary tale re: pom '''
        self.lgr.debug('coverage restoreAFLBreaks')
        self.afl_del_breaks = []
        return 


        '''
        resim_context = self.context_manager.getRESimContext()
        bp_start = 0
        default_context = self.context_manager.getDefaultContext()
        for bb in self.afl_del_breaks:
            breakpoint = SIM_breakpoint(default_context, Sim_Break_Linear, Sim_Access_Execute, bb, 1, 0)
            if bp_start == 0:
                bp_start = breakpoint
        if len(self.afl_del_breaks) > 0:
            hap = SIM_hap_add_callback_range("Core_Breakpoint_Memop", self.bbHap, None, bp_start, breakpoint)
            self.bb_hap.append(hap)
            if len(self.bb_hap) > 100:
                self.lgr.debug('more than 100 haps')
            self.lgr.debug('coverage restoreAFLBreaks restored %d breaks' % len(self.afl_del_breaks))
            self.afl_del_breaks = []
        '''

            
    def restoreBreaks(self):
        ''' TBD any need for this?  YES used after pre-hits are stored, i.e., hits up until the first data reference'''
        #return
        ''' Restore the hits found in self.blocks_hit '''
        tmp_list = []
        prev_break = None
        self.lgr.debug('coverage restoreBreaks')
        for bb in self.blocks_hit:
            breakpoint = self.setBreak(bb)
            if breakpoint is not None:
                #self.lgr.debug('coverage restoreBreaks bb 0x%x break num %d' % (bb, breakpoint))
                if prev_break is not None and breakpoint != (prev_break+1):
                    self.lgr.debug('coverage restoreBreaks discontinuous first bb bp is %d last %d' % (tmp_list[0], tmp_list[-1]))
                    hap = SIM_hap_add_callback_range("Core_Breakpoint_Memop", self.bbHap, None, tmp_list[0], tmp_list[-1])
                    tmp_list = []
                    self.bb_hap.append(hap)

                tmp_list.append(breakpoint)
                ''' so it will be deleted '''
                self.bp_list.append(bb)
                prev_break = breakpoint    
        self.lgr.debug('coverage restoreBreaks restored %d breaks' % len(tmp_list))
        if len(tmp_list) > 0:
            self.lgr.debug('coverage restoreBreaks first bb bp is %d last %d' % (tmp_list[0], tmp_list[-1]))
            hap = SIM_hap_add_callback_range("Core_Breakpoint_Memop", self.bbHap, None, tmp_list[0], tmp_list[-1])
            self.bb_hap.append(hap)

    def mergeCover(self, target=None):
        ''' TBD fix this'''
        return
        all_name = '%s.all.hits' % (self.hits_path)
        self.lgr.debug('cover mergeCover into %s' % all_name)
        all_json = {}
        if os.path.isfile(all_name):
            fh = open(all_name, 'r')
            try:
                all_json = json.load(fh)
            except:
                pass
            fh.close()
        if target is None:
            last_name = '%s.hits' % self.hits_path
        else:
            last_name = '%s.%s.hits' % (self.hits_path, target)
        if not os.path.isfile(last_name):
            self.lgr.debug('coverage mergeCover failed to find recent hits file at %s' % last_name)
            return
        with open(last_name) as fh:
            last_json = json.load(fh)
        new_hits = 0
        for fun in last_json:
            if fun not in all_json:
                all_json[fun]=[]
            for bb in last_json[fun]:
                if bb not in all_json[fun]:
                    all_json[fun].append(bb)
                    new_hits += 1
        s = json.dumps(all_json)
        with open(all_name, 'w') as fh:
            fh.write(s)
        #os.remove(last_name) 
        self.lgr.debug('coverage merge %d new hits, removed %s' % (new_hits, last_name))
        print('Previous data run hit %d new BBs' % new_hits)
 

    def doCoverage(self, no_merge=False, physical=False):
        if not self.enabled:
            self.lgr.debug('cover NOT ENABLED')
            return
        ''' Reset coverage and merge last with all '''
        #self.lgr.debug('coverage doCoverage')    
        if not self.did_cover:
            self.cover(physical=physical)
            self.did_cover = True
        else:
            #self.restoreBreaks()
            #self.lgr.debug('coverage doCoverage had %d breaks' % len(self.bp_list))
            if self.begin_tmp_bp is not None:
                for bp in self.bp_list[self.begin_tmp_bp:]:
                    RES_delete_breakpoint(bp)
                for hap in self.bb_hap[self.begin_tmp_hap:]:
                    #self.lgr.debug('coverage doCoverage delete tmp_bp hap %d' % hap)
                    SIM_hap_delete_callback_id('Core_Breakpoint_Memop', hap)
                
                self.bp_list = self.bp_list[:self.begin_tmp_bp]
                self.bb_hap = self.bb_hap[:self.begin_tmp_hap]
                #self.lgr.debug('coverage doCoverage now have %d breaks' % len(self.bp_list))

        if not self.afl:
            if not no_merge:
                self.mergeCover()
            self.funs_hit = []
            self.blocks_hit = OrderedDict()
            self.lgr.debug('coverage reset blocks_hit')

        if self.backstop_cycles is not None and self.backstop_cycles > 0:
            self.backstop.setFutureCycle(self.backstop_cycles, now=True)

        if self.afl:
            self.trace_bits.__init__(self.map_size)
            #self.lgr.debug('coverage trace_bits array size %d' % self.map_size)
            self.prev_loc = 0
            self.proc_status = 0
            self.hit_count = 0
            self.afl_del_breaks = []

    def startDataSessions(self, dumb):
        if not self.enabled:
            return
        ''' all hits until now are IO setup, prior to any data session except we assume
            the very last hit is the bb that first referenced data '''
        self.lgr.debug('coverage startDataSessions')
        if self.latest_hit is not None:
            first_data_cycle = self.blocks_hit[self.latest_hit]
            del self.blocks_hit[self.latest_hit]
            self.saveCoverage(fname = 'pre')
            self.restoreBreaks()
            self.funs_hit = []
            self.blocks_hit = OrderedDict()
            self.blocks_hit[self.latest_hit] = first_data_cycle
            self.latest_hit = None
        else:
            self.lgr.debug('coverage startDataSession with no previous hits')

    def enableCoverage(self, pid, fname=None, backstop=None, backstop_cycles=None, afl=False, linear=False, create_dead_zone=False, no_save=False, only_thread=False):
        self.enabled = True
        self.pid = pid
        self.create_dead_zone = create_dead_zone
        self.no_save = no_save
        self.only_thread = only_thread
        if fname is not None:
            self.full_path = fname
            self.hits_path = resimUtils.getIdaData(fname)
        
        ida_path = resimUtils.getIdaData(self.full_path)
        # dynamically alter control flow, e.g., to avoid CRC checks
        self.loadJumpers(ida_path)

        self.backstop = backstop
        self.backstop_cycles = backstop_cycles
        if self.backstop_cycles is not None:
            self.lgr.debug('cover enableCoverage fname is %s linear: %r backstop_cycles: 0x%x' % (self.hits_path, linear, self.backstop_cycles))
        else:
            self.lgr.debug('cover enableCoverage fname is %s linear: %r no backstop given' % (self.hits_path, linear))
        # force use of linear breakpoints vice physical memory
        self.linear = linear
        self.afl = afl
        if afl:
            map_size_pow2 = 16
            self.map_size = 1 << map_size_pow2
            self.trace_bits = bytearray(self.map_size)
        if self.run_from_snap is not None:
            dead_file = '%s.dead' % self.run_from_snap
            if os.path.isfile(dead_file):
                with open(dead_file) as fh:
                    self.dead_map = json.load(fh)

    def disableCoverage(self):
        self.lgr.debug('coverage disableCoverage')
        self.enabled = False

    def difCoverage(self, fname):
        save_name = '%s.%s.hits' % (self.hits_path, fname)
        if not os.path.isfile(save_name):
            print('No file named %s' % save_name)
            return
        with open(save_name) as fh:
            jhits = json.load(fh)
            for i in range(len(jhits)):
                if jhits[i] != self.blocks_hit[i]:
                    print('new 0x%x  old 0x%x index: %d' % (self.blocks_hit[i], jhits[i], i))
                    break

    def getCoverageFile(self):
        ''' Intended to let IDA plugin get file without knowing symbolic links '''
        retval = '%s.hits' % self.hits_path
        self.lgr.debug('coverage returning file %s' % retval) 
        return retval

    def goToBasicBlock(self, addr):
        retval = None
        if addr in self.blocks_hit:
            dumb=SIM_run_command('pselect %s' % self.cpu.name)
            cmd = 'skip-to cycle = %d ' % self.blocks_hit[addr]
            self.lgr.debug('coverage goToBasicBlock cmd: %s' % cmd)
            dumb=SIM_run_command(cmd)
            #self.lgr.debug('coverage skipped to 0x%x' % self.cpu.cycles)
            retval = self.cpu.cycles
        else:
            self.lgr.debug('coverage goToBasicBlock 0x%x not in blocks_hit' % addr)
        return retval 

    def getBlocksHit(self):
        return self.blocks_hit

    def clearHits(self):
        #self.restoreBreaks()
        self.funs_hit = []
        self.blocks_hit = OrderedDict()
        if True:
            #self.lgr.debug('coverage clearHits had %d breaks' % len(self.bp_list))
            if self.begin_tmp_bp is not None:
                for bp in self.bp_list[self.begin_tmp_bp:]:
                    #self.lgr.debug('try to delete bp %d' % bp)
                    RES_delete_breakpoint(bp)
                for hap in self.bb_hap[self.begin_tmp_hap:]:
                    #self.lgr.debug('coverage doCoverage delete tmp_bp hap %d' % hap)
                    SIM_hap_delete_callback_id('Core_Breakpoint_Memop', hap)
                
                self.bp_list = self.bp_list[:self.begin_tmp_bp]
                self.bb_hap = self.bb_hap[:self.begin_tmp_hap]
                #self.lgr.debug('clearHits doCoverage now have %d breaks' % len(self.bp_list))

    def getHitsPath(self):
        return self.hits_path

    def getFullPath(self):
        return self.full_path

    def appendName(self, name):
        self.hits_path = '%s-%s' % (self.hits_path, name)

    def loadJumpers(self, fname):
        ''' jumpers are linear addresses '''
        jfile = fname+'.jumpers'
        if os.path.isfile(jfile):
            jumpers = json.load(open(jfile))
            self.jumpers = {}
            for from_bb in jumpers:
                #phys_block = self.cpu.iface.processor_info.logical_to_physical(int(from_bb), Sim_Access_Execute)
                #self.jumpers[phys_block.address] = jumpers[from_bb]
                self.jumpers[int(from_bb)] = jumpers[from_bb]
            self.lgr.debug('coverage loaded %d jumpers' % len(self.jumpers))

    def exitHap(self, dumb, third, break_num, memory):
        self.lgr.debug('coverage exitHap')
        SIM_break_simulation('coverage existHap')
        self.did_exit = True

    def didExit(self):
        return self.did_exit

    def loadExits(self):
        self.did_exit=False
        exit_file = 'prog.exit'
        self.lgr.debug('coverage load exits')
        if os.path.isfile(exit_file):
            with open(exit_file) as fh:
                bp_list = [] 
                for line in fh:
                    bb = int(line.strip(),16)
                    phys_block = self.cpu.iface.processor_info.logical_to_physical(bb, Sim_Access_Execute)
                    if phys_block.address == 0:
                        self.lgr.error('loadExists failed to get phy for 0x%x' % bb)
                        continue
                    bp = SIM_breakpoint(self.cpu.physical_memory, Sim_Break_Physical, Sim_Access_Execute, phys_block.address, 1, 0)
                    self.lgr.debug('loadExits set break on 0x%x, linear 0x%x' % (phys_block.address, bb))
                    bp_list.append(bp)
                hap = SIM_hap_add_callback_range("Core_Breakpoint_Memop", self.exitHap, None, bp_list[0], bp_list[-1])

