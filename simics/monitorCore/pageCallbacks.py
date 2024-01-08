'''
 * This software was created by United States Government employees
 * and may not be copyrighted.
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
 * ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
'''
from simics import *
import pageUtils
import resimUtils
from resimHaps import *
class PageCallbacks():
    def __init__(self, top, cpu, mem_utils, lgr):
        self.cpu = cpu
        self.lgr = lgr
        self.top = top
        self.mem_utils = mem_utils
        self.callbacks = {}
        self.unmapped_addrs = []
        self.missing_pages = {}
        self.missing_page_bases = {}
        self.missing_tables = {}
        self.missing_breaks = {}
        self.missing_haps = {}
        self.mode_hap = None

    def setCallback(self, addr, callback):
        phys_addr = self.mem_utils.v2p(self.cpu, addr)
        if phys_addr is None or phys_addr == 0:
            self.callbacks[addr] = callback
            self.lgr.debug('pageCallbacks setCallback for 0x%x' % addr)
            pt = pageUtils.findPageTable(self.cpu, addr, self.lgr)
            if pt.page_addr is not None:
                if pt.page_addr not in self.missing_pages:
                    self.missing_pages[pt.page_addr] = []
                    break_num = SIM_breakpoint(self.cpu.physical_memory, Sim_Break_Physical, Sim_Access_Write, pt.page_addr, 1, 0)
                    self.lgr.debug('pageCallbacks setCallback no physical address for 0x%x, set break %d on page_addr 0x%x' % (addr, break_num, pt.page_addr))
                    self.missing_breaks[pt.ptable_addr] = break_num
                    self.missing_haps[break_num] = SIM_hap_add_callback_index("Core_Breakpoint_Memop", self.pageHap, 
                          None, break_num)
                self.missing_pages[pt.page_addr].append(addr)
                self.lgr.debug('pageCallbacks setCallback addr 0x%x added to missing pages for page addr 0x%x' % (addr, pt.page_addr))
            if pt.page_base_addr is not None:
                if pt.page_base_addr not in self.missing_page_bases:
                    self.missing_page_bases[pt.page_base_addr] = []
                    break_num = SIM_breakpoint(self.cpu.physical_memory, Sim_Break_Physical, Sim_Access_Write, pt.page_base_addr, 1, 0)
                    self.lgr.debug('pageCallbacks no physical address for 0x%x, set break %d on page_base_addr 0x%x' % (addr, break_num, pt.page_base_addr))
                    self.missing_breaks[pt.ptable_addr] = break_num
                    self.missing_haps[break_num] = SIM_hap_add_callback_index("Core_Breakpoint_Memop", self.pageBaseHap, 
                          None, break_num)
                self.missing_page_bases[pt.page_base_addr].append(addr)
                self.lgr.debug('pageCallbacks setCallback addr 0x%x added to missing page bases for page addr 0x%x' % (addr, pt.page_base_addr))
            elif pt.ptable_addr is not None:
                if pt.ptable_addr not in self.missing_tables:
                    self.missing_tables[pt.ptable_addr] = []
                    break_num = SIM_breakpoint(self.cpu.physical_memory, Sim_Break_Physical, Sim_Access_Write, pt.ptable_addr, 1, 0)
                    self.lgr.debug('pageCallbacks setCallback no physical address for 0x%x, set break %d on phys ptable_addr 0x%x' % (addr, break_num, pt.ptable_addr))
                    self.missing_breaks[pt.ptable_addr] = break_num
                    self.missing_haps[break_num] = SIM_hap_add_callback_index("Core_Breakpoint_Memop", self.tableHap, 
                          None, break_num)
                self.missing_tables[pt.ptable_addr].append(addr)
                self.lgr.debug('pageCallbacks setCallback addr 0x%x added to missing tables for table addr 0x%x' % (addr, pt.ptable_addr))

    def delModeAlone(self, dumb):
        if self.mode_hap is not None:
            SIM_hap_delete_callback_id("Core_Mode_Change", self.mode_hap)
            self.mode_hap = None

    def modeChanged(self, mem_trans, one, old, new):
        if self.mode_hap is None:
            return
        self.lgr.debug('pageCallbacks modeChanged after table updated, check pages in table')
        self.tableUpdated(mem_trans)
        SIM_run_alone(self.delModeAlone, None)
    
    def tableHap(self, dumb, third, break_num, memory):
        length = memory.size
        op_type = SIM_get_mem_op_type(memory)
        type_name = SIM_get_mem_op_type_name(op_type)
        physical = memory.physical_address
        self.lgr.debug('pageCallbacks tableHap phys 0x%x len %d  type %s' % (physical, length, type_name))
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
            '''
            Called when a page table is updated.  Find all the page entries within this table and set breaks on each.
            '''
            length = mem_trans.length
            op_type = mem_trans.op_type
            type_name = mem_trans.type_name
            physical = mem_trans.physical
            self.lgr.debug('pageCallbacks tableUpdated phys 0x%x len %d  type %s len of missing_tables[physical] %d' % (physical, length, type_name, len(self.missing_tables[physical])))
            #if length == 4 and self.cpu.architecture == 'arm':
            if True or length == 4:
                if op_type is Sim_Trans_Store:
                    value = mem_trans.value
                    if value == 0:
                        #self.lgr.debug('tableHap value is zero')
                        return
                    prev_bp = None
                    got_one = False
                    got_missing = False
                    for addr in self.missing_tables[physical]:
                        if addr in self.did_missing:
                            got_missing=True
                            continue
                        pt = pageUtils.findPageTable(self.cpu, addr, self.lgr, use_sld=value)
                        if pt.page_addr is None or pt.page_addr == 0:
                            self.lgr.debug('pt still not set for 0x%x, page table addr is 0x%x' % (addr, pt.ptable_addr))
                            continue
                        phys_addr = pt.page_addr | (addr & 0x00000fff)
                        self.lgr.debug('callback here also?')
                        self.doCallback(addr)
            else:
                self.lgr.error('coverage tableHap for 64 bits not yet handled')

    def rmTableHap(self, break_num):
        # not used. strategy is to leave all breaks and haps?
        self.lgr.debug('pageCalbacks rmTableHap rmTableHap break_num %d' % break_num)
        SIM_hap_delete_callback_id('Core_Breakpoint_Memop', self.missing_haps[break_num])
        del self.missing_haps[break_num]

    def pageBaseHap(self, dumb, third, break_num, memory):
        if self.mode_hap is not None:
            #self.lgr.debug('coverage pageBaseHap alreay has a mode_hap, bail')
            return
        ''' hit when a page base address is updated'''
        length = memory.size
        op_type = SIM_get_mem_op_type(memory)
        type_name = SIM_get_mem_op_type_name(op_type)
        physical = memory.physical_address
        cpu, comm, tid = self.top.curThread(target_cpu=self.cpu)
        self.lgr.debug('pageCalbacks pageBaseHap phys 0x%x len %d  type %s tid:%s (%s)' % (physical, length, type_name, tid, comm))
        if break_num in self.missing_haps:
            if True or length == 4:
                if op_type is Sim_Trans_Store:
                    mem_trans = self.MyMemTrans(memory)
                    self.mode_hap = SIM_hap_add_callback_obj("Core_Mode_Change", self.cpu, 0, self.modeChangedPageBase, mem_trans)
                else:
                    self.lgr.error('pageCallbacks pageBaseHap op_type is not store')
            else:
                self.lgr.error('pageCallbacks pageBaseHap for 64 bits not yet handled')
        else:
            self.lgr.debug('pageCallbacks pageBaseHap breaknum should have not hap %d' % break_num) 

    def modeChangedPageBase(self, mem_trans, one, old, new):
        if self.mode_hap is None:
            return
        self.lgr.debug('pageCallbacks modeChanged after page base updated, check pages in page base')
        self.pageBaseUpdated(mem_trans)
        SIM_run_alone(self.delModeAlone, None)
    
    def pageBaseUpdated(self, mem_trans):
            '''
            Called when a page base is updated.  Find all the page entries within this table and set breaks on each.
            '''
            length = mem_trans.length
            op_type = mem_trans.op_type
            type_name = mem_trans.type_name
            physical = mem_trans.physical
            self.lgr.debug('pageBaseUpdated phys 0x%x len %d  type %s len of missing_tables[physical] %d' % (physical, length, type_name, len(self.missing_page_bases[physical])))
            #if length == 4 and self.cpu.architecture == 'arm':
            if True or length == 4:
                if op_type is Sim_Trans_Store:
                    value = mem_trans.value
                    if value == 0:
                        #self.lgr.debug('tableHap value is zero')
                        return
                   
                    for addr in self.missing_page_bases[physical]:
                        pt = pageUtils.findPageTable(self.cpu, addr, self.lgr, use_sld=value)
                        if pt.page_addr is None or pt.page_addr == 0:
                            self.lgr.debug('coverage pageBaseUpdated pt still not set for 0x%x, page table addr is 0x%x' % (addr, pt.ptable_addr))
                            continue
                        phys_addr = pt.page_addr | (addr & 0x00000fff)
                        #print('would do callback here')
                        self.doCallback(addr)
            else:
                self.lgr.error('coverage pageBaseUpdated for 64 bits not yet handled')

    def doCallback(self, addr):
            self.lgr.debug('would do callback here')
            if addr in self.callbacks:
                self.lgr.debug('pageCallbacks pageBaseUpdated addr 0x%x callback %s' % (addr, self.callbacks[addr]))
                self.callbacks[addr](addr)
            else:
                self.lgr.debug('pageCallbacks pageBaseUpdated addr 0x%x not in callbacks' % (addr))
   
    def pageHap(self, dumb, third, break_num, memory):
        if break_num in self.missing_haps:
            length = memory.size
            op_type = SIM_get_mem_op_type(memory)
            type_name = SIM_get_mem_op_type_name(op_type)
            physical = memory.physical_address
            #self.lgr.debug('pageHap phys 0x%x len %d  type %s' % (physical, length, type_name))
            #if length == 4 and self.cpu.architecture == 'arm':
            if True:
                if op_type is Sim_Trans_Store:
                    value = SIM_get_mem_op_value_le(memory)
                    #self.lgr.debug('pageHap value is 0x%x' % value)
                for addr in self.missing_pages[memory.physical_address]:
                    # TBD this was broken.  Not sure if it is now fixed
                    #offset = memUtils.bitRange(pdir_entry, 0, 19)
                    #addr = value + offset
                    pt = pageUtils.findPageTable(self.cpu, addr, self.lgr)
                    phys_addr = pt.page_addr
                    if phys_addr is None:
                        self.lgr.error('coverage pageHap got none for addr ofr addr 0x%x.  broken' % addr) 
                    else:
                        print('callback here also?')
                        self.doCallback(addr)
                        pass
        else:
            self.lgr.debug('coverage pageHap breaknum should have no hap %d' % break_num)

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
