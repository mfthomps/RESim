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
import memUtils
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
        # dictionary of page table entries keyed by table physical address, value is list of VAs 
        # that may be mapped by updates to the table
        self.missing_page_bases = {}
        self.missing_tables = {}
        # ppc32 page entries, keyed by phys of pteg, values are lists of va that may map to the ptegs
        self.missing_ptegs = {}
        self.other_pteg_break = {}
        self.missing_haps = {}
        self.mode_hap = None
        # list of address must be writable, i.e., to supress callbacks on RO copy-on-write pages
        # TBD potential collision on linear addresses?  Seems remote
        self.no_cows = []
        # so we can delete breaks/haps for missing pages mapped between an initial page table hap and return to user space
        self.missing_page_bases_break_nums = {}

    def setCallback(self, addr, callback, name=None, use_pid=None, writable=True):
        mapped = False
        if use_pid is None:
            self.lgr.debug('pageCallbacks setCallback for 0x%x' % addr)
            pt = pageUtils.findPageTable(self.cpu, addr, self.lgr)
            if pt.phys_addr is not None:
                if writable and not pt.writable:
                    self.lgr.debug('pageCallbacks setCallback, 0x%x mapped to 0x%x but cow' % (addr, pt.phys_addr))
                else:
                    self.lgr.debug('pageCallbacks setCallback, 0x%x mapped to 0x%x seems writable' % (addr, pt.phys_addr))
                    mapped = True
        else:
            self.lgr.debug('pageCallbacks setCallback for 0x%x use_pid %s' % (addr, use_pid))
            phys_addr = self.mem_utils.v2p(self.cpu, addr, use_pid=use_pid)
            if phys_addr is not None and phys_addr != 0:
                mapped = True
        if not mapped:    
            if name is None:
                name = 'NONE'
            if addr not in self.callbacks:
                self.callbacks[addr] = {}
            self.callbacks[addr][name] = callback
            self.setTableHaps(addr,use_pid=use_pid)
        else:
            self.lgr.debug('pageCallbacks setCallback for 0x%x but addr already mapped, just make the call uses_pid:%s' % (addr, use_pid))
            if name is None:
                callback(addr)
            else:
                callback(addr, name)

    def setTableHaps(self, addr, use_pid=None, writable=True):
        table_base = None
        cpu, comm, tid = self.top.curThread(target_cpu=self.cpu)
        self.lgr.debug('pageCallbacks setTableHaps for 0x%x tid:%s (%s)' % (addr, tid, comm))
        if use_pid is not None:
            if self.top.isWindows():
                table_base = self.mem_utils.getWindowsTableBase(self.cpu, use_pid)
            else: 
                table_base = self.mem_utils.getLinuxTableBase(self.cpu, use_pid)
            if table_base is not None:
                self.lgr.debug('pageCallbacks setTableHaps for pid %s table_base is 0x%x' % (use_pid, table_base))
            else:
                self.lgr.debug('pageCallbacks setTableHaps for pid %s failed to get table_base' % use_pid)
                #return
        pt = pageUtils.findPageTable(self.cpu, addr, self.lgr, force_cr3=table_base)
        if pt is None:
            self.lgr.error('pageCallbacks setTableHaps  no page table info found for address 0x%x' % (addr))
            return
        if writable:
            self.no_cows.append(addr)

        # COW CHECK HERE
        mapped = False
        if pt.phys_addr is not None:
            if writable and not pt.writable:
                self.lgr.debug('pageCallbacks setTableHaps is COW treat as not mapped')
            else:
                mapped = True
        if mapped:
            if pt.phys_addr not in self.missing_pages:
                self.missing_pages[pt.phys_addr] = []
                break_num = SIM_breakpoint(self.cpu.physical_memory, Sim_Break_Physical, Sim_Access_Write, pt.phys_addr, 1, 0)
                self.lgr.debug('pageCallbacks setTableHaps on physical address for 0x%x, set break %d on phys_addr 0x%x' % (addr, break_num, pt.phys_addr))
                self.missing_haps[break_num] = SIM_hap_add_callback_index("Core_Breakpoint_Memop", self.pageHap, 
                      None, break_num)
            self.missing_pages[pt.phys_addr].append(addr)
            self.lgr.debug('pageCallbacks setTableHaps addr 0x%x added to missing pages for page addr 0x%x' % (addr, pt.phys_addr))
        elif self.cpu.architecture == 'ppc32':
            if pt.pteg1 not in self.missing_ptegs:
                self.missing_ptegs[pt.pteg1] = []
                # 8 entries of 8 bytes each
                break_num = SIM_breakpoint(self.cpu.physical_memory, Sim_Break_Physical, Sim_Access_Write, pt.pteg1, 64, 0)
                self.lgr.debug('pageCallbacks setTableHaps tid:%s no physical address for 0x%x, set break %d on pteg1 0x%x' % (tid, addr, break_num, pt.pteg1))
                self.missing_haps[break_num] = SIM_hap_add_callback_index("Core_Breakpoint_Memop", self.ptegHap, 
                      tid, break_num)
                if pt.pteg2 is not None:
                    break_num2 = SIM_breakpoint(self.cpu.physical_memory, Sim_Break_Physical, Sim_Access_Write, pt.pteg2, 64, 0)
                    self.lgr.debug('pageCallbacks setTableHaps tid:%s no physical address for 0x%x, set break %d on pteg2 0x%x' % (tid, addr, break_num2, pt.pteg2))
                    self.missing_haps[break_num2] = SIM_hap_add_callback_index("Core_Breakpoint_Memop", self.ptegHap, 
                          tid, break_num2)
                    self.other_pteg_break[break_num] = break_num2
                    self.other_pteg_break[break_num2] = break_num
            if addr not in self.missing_ptegs[pt.pteg1]:
                self.missing_ptegs[pt.pteg1].append(addr)
        elif pt.page_base_addr is not None:
            if pt.page_base_addr not in self.missing_page_bases:
                self.missing_page_bases[pt.page_base_addr] = []
                break_num = SIM_breakpoint(self.cpu.physical_memory, Sim_Break_Physical, Sim_Access_Write, pt.page_base_addr, 1, 0)
                self.lgr.debug('pageCallbacks setTableHaps no physical address for 0x%x, set break %d on page_base_addr 0x%x' % (addr, break_num, pt.page_base_addr))
                self.missing_haps[break_num] = SIM_hap_add_callback_index("Core_Breakpoint_Memop", self.pageBaseHap, 
                      None, break_num)
                self.missing_page_bases_break_nums[pt.page_base_addr] = break_num
            self.missing_page_bases[pt.page_base_addr].append(addr)
            self.lgr.debug('pageCallbacks setTableHaps addr 0x%x added to missing page bases for page addr 0x%x' % (addr, pt.page_base_addr))
        elif pt.ptable_addr is not None:
            if pt.ptable_addr not in self.missing_tables:
                self.missing_tables[pt.ptable_addr] = []
                break_num = SIM_breakpoint(self.cpu.physical_memory, Sim_Break_Physical, Sim_Access_Write, pt.ptable_addr, 1, 0)
                self.lgr.debug('pageCallbacks setTableHaps no physical address for 0x%x, set break %d on phys ptable_addr 0x%x' % (addr, break_num, pt.ptable_addr))
                self.missing_haps[break_num] = SIM_hap_add_callback_index("Core_Breakpoint_Memop", self.tableHap, 
                      None, break_num)
            self.missing_tables[pt.ptable_addr].append(addr)
            self.lgr.debug('pageCallbacks setTableHaps addr 0x%x added to missing tables for table addr 0x%x' % (addr, pt.ptable_addr))

    def delModeAlone(self, hap):
        if hap is not None:
            SIM_hap_delete_callback_id("Core_Mode_Change", hap)

    def modeChanged(self, mem_trans, one, old, new):
        if self.mode_hap is None:
            return
        self.lgr.debug('pageCallbacks modeChanged after table updated, check pages in table')
        self.tableUpdated(mem_trans)
        hap = self.mode_hap
        self.mode_hap = None
        SIM_run_alone(self.delModeAlone, hap)
    
    def tableHap(self, dumb, third, break_num, memory):
        length = memory.size
        op_type = SIM_get_mem_op_type(memory)
        type_name = SIM_get_mem_op_type_name(op_type)
        physical = memory.physical_address
        self.lgr.debug('pageCallbacks tableHap phys 0x%x len %d  type %s' % (physical, length, type_name))
        if break_num in self.missing_haps:
            if op_type is Sim_Trans_Store:
                mem_trans = self.MyMemTrans(self.cpu, memory)
                self.mode_hap = SIM_hap_add_callback_obj("Core_Mode_Change", self.cpu, 0, self.modeChanged, mem_trans)
                self.rmTableHap(break_num)
            else:
                self.lgr.error('tableHap op_type is not store')
        else:
            self.lgr.debug('pageCallbacks tableHap breaknum %d not in missing_haps' % break_num) 

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
            if op_type is Sim_Trans_Store:
                value = mem_trans.value
                if value == 0:
                    #self.lgr.debug('tableHap value is zero')
                    return
                prev_bp = None
                got_one = False
                redo_addrs = []
                for addr in self.missing_tables[physical]:
                    pt = pageUtils.findPageTable(self.cpu, addr, self.lgr, use_sld=value)
                    if pt.phys_addr is None or pt.phys_addr == 0:
                        self.lgr.debug('pageCallbacks tableUpdated pt still not set for 0x%x, page table addr is 0x%x' % (addr, pt.ptable_addr))
                        redo_addrs.append(addr)
                        continue
                    phys_addr = pt.phys_addr | (addr & 0x00000fff)
                    self.lgr.debug('callback here also?')
                    self.doCallback(addr)
                del self.missing_tables[physical]
                for addr in redo_addrs:
                    self.setTableHaps(addr)

    def rmBreakHap(self, hap):
        SIM_hap_delete_callback_id('Core_Breakpoint_Memop', hap)

    def rmTableHap(self, break_num):
        self.lgr.debug('pageCallbacks rmTableHap rmTableHap break_num %d' % break_num)
        SIM_delete_breakpoint(break_num)
        hap = self.missing_haps[break_num]
        del self.missing_haps[break_num]
        SIM_run_alone(self.rmBreakHap, hap)

    def ptegHap(self, want_tid, third, break_num, memory):
        ''' hit when an entry in a pteg is updated '''
        if break_num not in self.missing_haps:
            return
        if self.mode_hap is not None:
            #self.lgr.debug('pageCallbacks pageBaseHap already has a mode_hap, bail')
            return
        op_type = SIM_get_mem_op_type(memory)
        if op_type is not Sim_Trans_Store:
            return
        if memory.physical_address == 0:
            return

        cpu, comm, tid = self.top.curThread(target_cpu=self.cpu)
        if tid != want_tid:
            self.lgr.debug('pageCallback ptegHap tid:%s expected:%s, bail' % (tid, want_tid))
            return
        length = memory.size
        type_name = SIM_get_mem_op_type_name(op_type)
        self.lgr.debug('pageCallbacks ptegHap tid:%s (%s) phys 0x%x len %d  type %s cycle: 0x%x' % (tid, comm, memory.physical_address, length, type_name, self.cpu.cycles))
        ''' Remove the hap and break.  They will be recreated at the end of this call chain unless all associated addresses are mapped. '''
        self.rmTableHap(break_num)
        if break_num in self.other_pteg_break:
            other_break = self.other_pteg_break[break_num]
            self.rmTableHap(self.other_pteg_break[break_num])
            del self.other_pteg_break[break_num]
            del self.other_pteg_break[other_break]
        ''' Set a mode hap so we recheck page entries after kernel finishes its mappings. '''
        mem_trans = self.MyMemTrans(self.cpu, memory, tid)
        self.mode_hap = SIM_hap_add_callback_obj("Core_Mode_Change", self.cpu, 0, self.modeChangedPteg, mem_trans)

    def modeChangedPteg(self, mem_trans, one, old, new):
        ''' In user mode after seeing that kernel was updating ppc pteg entry '''
        if self.mode_hap is None:
            return
        cpu, comm, tid = self.top.curThread(target_cpu=self.cpu)
        if tid != mem_trans.tid:
            self.lgr.debug('pageCallbacks modeChangedPteg, wrong tid:%s wanted %s' % (tid, mem_trans.tid))
            return 
        self.lgr.debug('pageCallbacks modeChangedPteg tid:%s (%s) after pteg updated' % (tid, comm))
        self.ptegUpdated(mem_trans)
        hap = self.mode_hap
        self.mode_hap = None
        SIM_run_alone(self.delModeAlone, hap)

    def ptegUpdated(self, mem_trans):
        '''
        Called when a pteg is updated.  We've returned to the user since the hap was hit.
        The hap was already removed.  Remove all associated entries and recreate those that need it.
        '''
        length = mem_trans.length
        type_name = mem_trans.type_name
        physical = mem_trans.physical

        # find the missing pteg entry for this hit.  Each break range is 64 bytes
        missing_entry = None
        for missing_addr in self.missing_ptegs:
            if physical >= missing_addr and physical < (missing_addr+64):
                missing_entry = missing_addr
                break            
        if missing_entry is None:
            self.lgr.error('pageCallback ptegUpdated, failed to find missing_pteg for phys 0x%x' % physical)
            return

        redo_addrs = []
        for addr in self.missing_ptegs[missing_entry]:
            pt = pageUtils.findPageTable(self.cpu, addr, self.lgr)
            if pt.phys_addr is None or pt.phys_addr == 0:
                self.lgr.debug('pageCallbacks ptegUpdated pt still not mapped for 0x%x, pteg phys is 0x%x' % (addr, physical))
                redo_addrs.append(addr)
                continue
            else:
                if addr in self.no_cows and not pt.writable:
                    self.lgr.debug('pageCallbacks ptegUpdated pt mapped at 0x%x but is RO COW, pteg phys is 0x%x, wait for writable' % (addr, physical))
                    redo_addrs.append(addr)
                    continue
            #print('would do callback here')
            self.doCallback(addr)

        del self.missing_ptegs[missing_entry]
        for addr in redo_addrs:
            self.lgr.debug('pageCallbacks ptegUpdated setTableHaps for addr 0x%x' % addr)
            self.setTableHaps(addr)
        

    def pageBaseHap(self, dumb, third, break_num, memory):
        ''' hit when a page base address is updated'''
        if break_num not in self.missing_haps:
            return
        if self.mode_hap is not None:
            #self.lgr.debug('pageCallbacks pageBaseHap already has a mode_hap, bail')
            return
        length = memory.size
        op_type = SIM_get_mem_op_type(memory)
        type_name = SIM_get_mem_op_type_name(op_type)
        physical = memory.physical_address
        cpu, comm, tid = self.top.curThread(target_cpu=self.cpu)
        self.lgr.debug('pageCa.lbacks pageBaseHap phys 0x%x len %d  type %s tid:%s (%s) cycle: 0x%x' % (physical, length, type_name, tid, comm, cpu.cycles))
        if op_type is Sim_Trans_Store:
            ''' Remove the hap and break.  They will be recreated at the end of this call chain unless all associated addresses are mapped. '''
            self.rmTableHap(break_num)
            ''' Set a mode hap so we recheck page entries after kernel finishes its mappings. '''
            mem_trans = self.MyMemTrans(self.cpu, memory, tid)
            self.mode_hap = SIM_hap_add_callback_obj("Core_Mode_Change", self.cpu, 0, self.modeChangedPageBase, mem_trans)
        else:
            self.lgr.error('pageCallbacks pageBaseHap op_type is not store')

    def modeChangedPageBase(self, mem_trans, one, old, new):
        ''' In user mode after seeing that kernel was updating page base '''
        if self.mode_hap is None:
            return
        self.lgr.debug('pageCallbacks modeChanged after page base updated, check pages in page base')
        self.pageBaseUpdated(mem_trans)
        hap = self.mode_hap
        self.mode_hap = None
        SIM_run_alone(self.delModeAlone, hap)
   
    def doCallbacksForMapped(self, physical, value):
        redo_addrs = []
        got_one = False
        for addr in self.missing_page_bases[physical]:
            phys_addr = self.mem_utils.v2p(self.cpu, addr)
            #pt = pageUtils.findPageTable(self.cpu, addr, self.lgr, use_sld=value)
            #if pt.phys_addr is None or pt.phys_addr == 0:
            if phys_addr is None or phys_addr == 0:
                #self.lgr.debug('pageCallbacks pageBaseUpdated pt still not set for 0x%x, page table addr is 0x%x' % (addr, pt.ptable_addr))
                self.lgr.debug('pageCallbacks pageBaseUpdated pt still not set for 0x%x' % (addr))
                redo_addrs.append(addr)
                continue
            #phys_addr = pt.phys_addr | (addr & 0x00000fff)
            self.lgr.debug('pageCallbacks doCallbacksForMapped thinks va 0x%x is mapped as phys 0x%x' % (addr, phys_addr))
            #print('would do callback here')
            self.doCallback(addr)
            got_one = True

        if value is None and got_one:
            # called for other than initially hit page table entry
            # remove the hap
            if physical in self.missing_page_bases_break_nums:
                break_num = self.missing_page_bases_break_nums[physical]
                self.rmTableHap(break_num)
            else:
                self.lgr.debug('pageCallbacks doCallbacksForMapped physical 0x%x not in missing_page_bases_break_nums' % physical)
        if value is not None or got_one:
            del self.missing_page_bases[physical]
            for addr in redo_addrs:
                self.setTableHaps(addr)

    def pageBaseUpdated(self, mem_trans):
        '''
        Called when a page base is updated.  We've returned to the user since the hap was hit.
        The hap was already removed.  Remove all associated entries and recreate those that need it.
        '''
        length = mem_trans.length
        op_type = mem_trans.op_type
        type_name = mem_trans.type_name
        physical = mem_trans.physical
        self.lgr.debug('pageBaseUpdated phys 0x%x len %d  type %s len of missing_tables[physical] %d' % (physical, length, type_name, len(self.missing_page_bases[physical])))
        #if length == 4 and self.cpu.architecture == 'arm':
        if op_type is Sim_Trans_Store:
            value = mem_trans.value
            if value == 0:
                #self.lgr.debug('tableHap value is zero')
                return
            self.doCallbacksForMapped(physical, value)
        # Now look at all others that may have been mapped before we got to user space
        phys_list = list(self.missing_page_bases.keys())
        for other_physical in phys_list:
            if other_physical == physical:
                continue
            self.lgr.debug('pageCallbacks pageBaseUpdated try other physical addr 0x%x' % other_physical)
            self.doCallbacksForMapped(other_physical, None)

    def doCallback(self, addr):
            self.lgr.debug('pageCallbacks doCallback would do callback here')
            if addr in self.callbacks:
                for name in self.callbacks[addr]:
                    if name == 'NONE':
                        self.lgr.debug('pageCallbacks doCallback addr 0x%x callback %s' % (addr, self.callbacks[addr]))
                        self.callbacks[addr]['NONE'](addr)
                    else:
                        self.lgr.debug('pageCallbacks doCallback addr 0x%x name %s callback %s' % (addr, name, self.callbacks[addr]))
                        self.callbacks[addr][name](addr, name)
                #SIM_break_simulation('remove this')
            else:
                self.lgr.debug('pageCallbacks doCallback addr 0x%x not in callbacks' % (addr))
   
    def pageHap(self, dumb, third, break_num, memory):
        ''' called when a page table entry is updated (mapped). '''
        if break_num in self.missing_haps:
            length = memory.size
            op_type = SIM_get_mem_op_type(memory)
            type_name = SIM_get_mem_op_type_name(op_type)
            physical = memory.physical_address
            if physical not in self.missing_pages:
                self.lgr.error('pageCallback pageHap mem ref physical 0x%x not in missing pages' % physical)
                return

            #self.lgr.debug('pageHap phys 0x%x len %d  type %s' % (physical, length, type_name))
            if op_type is Sim_Trans_Store:
                value = memUtils.memoryValue(self.cpu, memory)
                #self.lgr.debug('pageHap value is 0x%x' % value)
            for addr in self.missing_pages[memory.physical_address]:
                # TBD this was broken.  Not sure if it is now fixed
                #offset = memUtils.bitRange(pdir_entry, 0, 19)
                #addr = value + offset
                pt = pageUtils.findPageTable(self.cpu, addr, self.lgr)
                phys_addr = pt.phys_addr
                if phys_addr is None:
                    self.lgr.error('pageCallbacks pageHap got none for addr ofr addr 0x%x.  broken' % addr) 
                    return
                else:
                    print('callback here also?')
                    self.doCallback(addr)
                    pass
            self.rmTableHap(break_num)
            del self.missing_pages[memory.physical_address]
 
        else:
            self.lgr.debug('pageCallbacks pageHap breaknum should have no hap %d' % break_num)


    class MyMemTrans():
        def __init__(self, cpu, memory, tid):
            self.length = memory.size
            self.op_type = SIM_get_mem_op_type(memory)
            self.type_name = SIM_get_mem_op_type_name(self.op_type)
            self.physical = memory.physical_address
            self.tid = tid
            if self.op_type is Sim_Trans_Store:
                self.value = memUtils.memoryValue(cpu, memory)
            else:
                self.value = None

    def enableBreaks(self):
        self.lgr.debug('pageCallbacks enableBreaks')
        for break_num in self.missing_haps:
            SIM_enable_breakpoint(break_num)

    def disableBreaks(self):
        self.lgr.debug('pageCallbacks disableBreaks')
        for break_num in self.missing_haps:
            SIM_disable_breakpoint(break_num)
