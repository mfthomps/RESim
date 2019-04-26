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

'''
   Set watches on the kernel for execution of non-executable areas
   and returns that don't match calls.  Also watch for execution 
   of unexpected code, e.g., fork/exec and modifications of kernel
   page tables.
   The breakpoints are expected to be set as monitored processes are 
   scheduled, and unset when they are no longer scheduled.
'''
from simics import *
import signal
import os
from operator import itemgetter
import memUtils
import pageUtils
from monitorLibs import forensicEvents 
from monitorLibs import forensicEvents
PML4 = 'PML4 table'
PG_DIR_PTR_TBL = 'page directory pointer table'
PG_DIR = 'page directory'
PG_TBL = 'page table'

class watchKernel():
    kernel_ret_counts = {}
    kernel_ret_break = {}
    kernel_ret_hap = {}
    kernel_unx_hap = {}
    kernel_unx_break = {}
    kernel_pt_hap = {}
    kernel_pt_break = {}
    dir_ptr_entry = {}
    pairs = {}
    cpus = {}
    exempt_returns = {}
    ret_hits = {}
    total_ret_hits = {}
    ret_adders = {}
    
    def __init__(self, top, param, cell_config, master_config, hap_manager, os_utils, kernel_info, page_size, unx_regions, cr3, cr4, lgr):
        ''' cr3 and cr4 per-cpu dictionaries '''
        self.haps_added = 0
        self.haps_removed = 0
        self.lgr = lgr
        self.top = top
        self.cell_config = cell_config
        self.master_config = master_config
        self.param = param
        # note these are os_p_utils
        self.os_utils = os_utils
        self.kernel_info = kernel_info
        self.page_size = page_size
        self.rop_phys = False
        self.unx_regions = unx_regions
        self.cr3 = cr3
        self.cr4 = cr4
        self.PML4_entry = None
        #signal.signal(signal.SIGINT, self.signal_handler)
        self.record_profile = False
        if master_config.rop_profile_record:
            self.record_profile = True

        for cell_name in self.cell_config.cells:
            self.lgr.debug('watchKernel init for cell %s' % cell_name)
            obj = SIM_get_object(cell_name)
            cell = obj.cell_context
            #cmd = '%s.get-processor-list' % cell_name
            #proclist = SIM_run_command(cmd)
            #cpu = SIM_get_object(proclist[0])
            if master_config.kernelNoX(cell_name):
                self.lgr.debug('watchKernel nox for %s' % cell_name)
                # set the entire kernel space
                nox_break = SIM_breakpoint(cell, Sim_Break_Linear, Sim_Access_Execute, 
                    master_config.ps_strings+1, 0xffffffff, 0)
                # remove kernel text section from break area
                SIM_breakpoint_remove(nox_break, Sim_Access_Execute, 
                   master_config.kernel_text[cell_name],
                   master_config.kernel_text_size[cell_name])
                if cell_name in master_config.kernel_text2 and master_config.kernel_text2[cell_name] is not None:
                    SIM_breakpoint_remove(nox_break, Sim_Access_Execute, 
                       master_config.kernel_text2[cell_name],
                       master_config.kernel_text_size2[cell_name])

                # remove cgc text sections from break area
                if cell_name in cell_config.cell_cgc_address and cell_config.cell_cgc_address[cell_name] is not None:
                    SIM_breakpoint_remove(nox_break, Sim_Access_Execute, cell_config.cell_cgc_address[cell_name],
                       master_config.cgc_text_size)

                #master_config.text, master_config.text_size, 0)
                hap_manager.addBreak(cell_name, None, nox_break, None)
                for cpu in self.cell_config.cell_cpu_list[cell_name]:
                    self.haps_added += 1
                    nox_hap = SIM_hap_add_callback_index("Core_Breakpoint_Memop", 
            		self.nox_callback, cpu, nox_break)
                    hap_manager.addHap(cpu, cell_name, None, nox_hap, None)

            # TBD perhaps optimize to only allocate if needed, for now these config values are per process type
            # not per cell_name
            if True or master_config.kernelRop(cell_name) or master_config.kernelUnx(cell_name):
                #self.lgr.debug('watchKernel ropcop for %s' % cell_name)
                for cpu in self.cell_config.cell_cpu_list[cell_name]:
                    self.exempt_returns[cpu] = []
                    #self.loadProfiles(cell_name, cpu)
                    self.kernel_ret_counts[cpu] = {}
                    self.kernel_ret_break[cpu] = []
                    self.kernel_ret_hap[cpu] = []
                    self.kernel_unx_break[cpu] = []
                    self.kernel_unx_hap[cpu] = []
                    self.ret_hits[cpu] = 0
                    self.total_ret_hits[cpu] = 0

            if True or master_config.kernelPageTable(cell_name):
                #self.lgr.debug('watchKernel kernelPageTable for %s' % cell_name)
                self.kernel_pt_hap[cpu] = []
                self.kernel_pt_break[cpu] = []
                addr_extend = memUtils.testBit(cr4[cpu], 5)
                if addr_extend != 0:
                    if self.os_utils[cell_name].mem_utils.WORD_SIZE == 4:
                        self.initPageDirAddressExtended(cpu, cr3[cpu])
                        self.lgr.debug('watchKernel using Extended')
                    else:
                        self.initPageDirIA32E(cpu, cr3[cpu])
                        self.lgr.debug('watchKernel using IA32E paging')

                #self.loadRetBreaks('retAddresses.txt', cpu, cell, cell_name)
          

    '''
        A rop profile is an experimental scheme for identifying common valid returns.
        It is not currently utilized.
    '''
    def get_profile_filename(self, cell_name):
        fname = self.master_config.rop_profile_file+'_'+cell_name+'.txt'
        return fname

    '''
    def signal_handler(self, signal, frame):
        print( 'in signal_handler')
        #sys.exit(1)
        if self.record_profile:
            # experimental, not used
            for cell_name in self.cell_config.cells:
                fname = self.get_profile_filename(cell_name)
                f = open(fname, 'a')
                cpu = self.cpus[cell_name]
                what = sorted(self.kernel_ret_counts[cpu].items(), key=itemgetter(1), reverse=True)
                count = 0
                for huh in what:
                   f.write('%x : %d\n' % (huh[0], huh[1]))
                   count += 1
                   if count > self.master_config.rop_profile_count:
                        break
                   #print '%s : %d' % (huh, self.pairs[cpu][huh])
                f.close()

    def loadProfiles(self, cell_name, cpu):
        if self.master_config.rop_profile_file is not None:
                if self.master_config.kernelRop(cell_name):
                    cpu = self.cpus[cell_name]
                    fname = self.get_profile_filename(cell_name)
                    if not os.path.isfile(fname):
                        print 'could not find profile file %s' % fname
                        #SIM_break_simulation("error finding profile file")
                        return
                    f = open(fname, 'r')
                    i = 0
                    for line in f:
                        values = line.split(':')
                        ret = int(values[0], 16)
                        if ret not in self.exempt_returns[cpu]:
                            self.exempt_returns[cpu].append(ret)
                        i = i+1
                        #if i > self.master_config.rop_profile_count:
                        #    break
                print 'loadProfile loaded %d exempt returns for %s' % (len(self.exempt_returns[cpu]), cell_name)
    '''

    def nox_callback(self, cpu, third, forth, memory):
        cell_name = self.top.getTopComponentName(cpu)
        cpu, cur_addr, comm, pid = self.os_utils[cell_name].currentProcessInfo(cpu)
        print 'in watchKernel nox_callback for %s at %x' % (cell_name, memory.logical_address)
        self.lgr.critical('in watchKernel nox_callback for %s at %x' % (cell_name, memory.logical_address))
        self.top.addLogEvent(cell_name, pid, comm, forensicEvents.KERNEL_NO_X,
             'Kernel execution of nox at %x' % memory.logical_address)

    def unx_callback(self, cpu, third, forth, memory):
        cell_name = self.top.getTopComponentName(cpu)
        cpu, cur_addr, comm, pid = self.os_utils[cell_name].currentProcessInfo(cpu)
        if pid not in self.kernel_unx_break[cpu]:
            self.lgr.debug('unx_callback but breakpoint is gone!')
            return
        print 'in watchKernel unx_callback for %s at %x' % (cell_name, memory.logical_address)
        self.lgr.critical('in watchKernel unx_callback for %s at %x on %s %d (%s)' % (cell_name, memory.logical_address, cell_name, pid, comm))
        self.top.addLogEvent(cell_name, pid, comm, forensicEvents.KERNEL_UNEXPECTED,
             'Kernel execution of unexpected address for %s at %x on %s %d (%s)' % (cell_name, memory.logical_address, cell_name, pid, comm))

    def getCurrentProcAddr(self, ptr2thread, cpu):
        # back pointer to this thread's process is one word from the start of the struct
        thread_phys_block = cpu.iface.processor_cli.translate_to_physical('ds', ptr2thread+self.os_utils[cell_name].mem_utils.WORD_SIZE)
        ptr = SIM_read_phys_memory(cpu, thread_phys_block.address, self.os_utils[cell_name].mem_utils.WORD_SIZE)
        return ptr

    class callLength():
        def __init__(self, eip, size):
            self.eip = eip
            self.size = size

    def getTopComponentName(self, cpu):
         names = cpu.name.split('.')
         return names[0]

    def getRetAddrs(self):
        '''
        Mostly for debugging, find the eips that had the most return hits
        '''
        self.lgr.debug('getRetAddrs')
        for cpu in self.kernel_ret_counts:
            what = sorted(self.kernel_ret_counts[cpu].items(), key=itemgetter(1), reverse=True)
            count = 0
            self.lgr.debug('watchKernel getRetAddrs total returns: %d' % self.total_ret_hits[cpu])
            for huh in what:
               self.lgr.debug('eip: %x : %d\n' % (huh[0], huh[1]))
               count += 1
               if count > 10:
                   break
            self.kernel_ret_counts[cpu] = {}
            self.total_ret_hits[cpu] = 0
 
    def rop_cop_ret_callback(self, cpu, third, break_num, memory):
        cell_name = self.top.getTopComponentName(cpu)
        esp = self.os_utils[cell_name].mem_utils.getRegValue(cpu, 'esp')
        return_to = self.os_utils[cell_name].mem_utils.readPtr(cpu, esp)
        eip = return_to - 8
        done = False
        self.ret_hits[cpu] += 1
        # TBD use instruction length to confirm it is a true call
        while not done and eip < return_to:
            instruct = SIM_disassemble_address(cpu, eip, 1, 0)
            if instruct[1].startswith('call'):
                done = True
            else:
                eip = eip+1
        # if we did not find a call, perhaps we return to the linux kernel exit routine?
        
        exempt = self.kernel_info[cell_name].default_se_exit
        if not done and (exempt is None or return_to != exempt):
            my_eip = self.os_utils[cell_name].mem_utils.getRegValue(cpu, 'eip')
            dumcpu, cur_addr, comm, pid = self.os_utils[cell_name].currentProcessInfo(cpu)
            self.lgr.critical('watchKernel, ROP COP no call found for %x break_num %d my_eip: %x  on %s %d (%s)' % \
                 (return_to, break_num, my_eip, cell_name, pid, comm))
            self.top.addLogEvent(cell_name, pid, comm, forensicEvents.KERNEL_ROP,
                 'call with no return.  Return to %x at eip: %x' % (return_to, my_eip))
            #SIM_break_simulation('kernel rop cop')
        #self.lgr.debug('ret callback return to is %x' % return_to)

        if True:
            eip = self.os_utils[cell_name].mem_utils.getRegValue(cpu, 'eip')
            if eip not in self.kernel_ret_counts[cpu]:
                self.kernel_ret_counts[cpu][eip] = 0
            self.kernel_ret_counts[cpu][eip] += 1
            if eip < self.param[cell_name].kernel_base:
                SIM_break_simulation('eip less than kernel base?')


    def punchRetHoles(self, cpu, break_num, address, length):
        if cpu in self.exempt_returns:
            cell_name = self.top.getTopComponentName(cpu)
            #print 'punching %d holes' % len(self.exempt_returns[cpu])
            for hole in self.exempt_returns[cpu]:
                if hole >= address and hole <= (address+length):
                    self.lgr.debug( 'on %s punching return hole at %x break_num %d' % (cell_name, 
                        hole, break_num))
                    SIM_breakpoint_remove(break_num, Sim_Access_Execute, hole, 4)

    def doRopPhys(self, cpu, start, length, cell_name, pid, comm):
        cell = cpu.physical_memory
        start, end = pageUtils.adjust(start, length, self.page_size)
        #dumcpu, cur_addr, comm, pid = self.os_utils[cell_name].currentProcessInfo()
        #self.lgr.debug('Adding Rop Cop breakpoints for %s:%d (%s) at %x through %x, given length was %x ' % (cell_name, pid, comm, start, end, length))
        phys_block = cpu.iface.processor_info.logical_to_physical(start, Sim_Access_Read)
        #self.lgr.debug('add break at %x' % phys_block.address)
        code_break_num = SIM_breakpoint(cell, Sim_Break_Physical, Sim_Access_Execute, phys_block.address, length, 0)
        self.kernel_ret_break[cpu].append(code_break_num)
        command = 'set-prefix %d "ret"' % code_break_num
        SIM_run_alone(SIM_run_command, command)
        hap_num = SIM_hap_add_callback_index("Core_Breakpoint_Memop", 
             self.rop_cop_ret_callback, cpu, code_break_num)
        self.kernel_ret_hap[cpu].append(hap_num)

    def doRopLinear(self, cpu, cell, address, length, pid, comm):
        ret_break = SIM_breakpoint(cell, Sim_Break_Linear, Sim_Access_Execute, address, length, 0)
        #ret_break = SIM_breakpoint(cell, Sim_Break_Linear, Sim_Access_Execute, address+0x500000, 0x400000, 0)
        #0x9414d4
        self.kernel_ret_break[cpu].append(ret_break)
        command = 'set-prefix %d "ret"' % ret_break
        SIM_run_alone(SIM_run_command, command)
        self.punchRetHoles(cpu, ret_break, address, length)
        self.haps_added += 1
        ret_hap = SIM_hap_add_callback_index("Core_Breakpoint_Memop", 
            self.rop_cop_ret_callback, cpu, ret_break)
        self.kernel_ret_hap[cpu].append(ret_hap)

    def doingRop(self, cpu):
        if len(self.kernel_ret_hap[cpu]) > 0:
            return True
        else:
            return False

    def doRop(self, cell, cpu, pid, comm):
        cell_name = self.top.getTopComponentName(cpu)
        #hole_start = 0xc0742b40
        #hole_end = 0xc07626ca
        #hole_size = hole_end - hole_start
        pre_hole_size = self.master_config.kernel_text_size[cell_name]
        #pre_hole_size = hole_start - self.master_config.kernel_text[cell_name]
        #post_hole_size = self.master_config.kernel_text_size[cell_name] - hole_size
        if self.rop_phys:
            self.doRopPhys(cpu, self.master_config.kernel_text[cell_name], pre_hole_size, cell_name, pid, comm)
            #self.doRopPhys(cpu, hole_end, post_hole_size, cell_name)
            self.doRopPhys(cpu, self.master_config.kernel_text2[cell_name], self.master_config.kernel_text_size2[cell_name], cell_name, pid, comm)
        else:
            self.doRopLinear(cpu, cell, self.master_config.kernel_text[cell_name], pre_hole_size, pid, comm)
            #self.doRopLinear(cpu, cell, hole_end, post_hole_size)
            self.doRopLinear(cpu, cell, self.master_config.kernel_text2[cell_name], self.master_config.kernel_text_size2[cell_name], pid, comm)
        self.ret_hits[cpu] = 0

    def undoRop(self, cpu):
        #SIM_hap_delete_callback_id("Core_Breakpoint_Memop", self.kernel_call_hap[cpu])
        #SIM_hap_delete_callback_id("Core_Breakpoint_Memop", self.cgc_call_hap[cpu])
        if cpu in self.kernel_ret_hap:
            for bp in self.kernel_ret_break[cpu]:
                self.haps_removed += 1
                SIM_delete_breakpoint(bp)
            for bp in self.kernel_unx_break[cpu]:
                self.haps_removed += 1
                SIM_delete_breakpoint(bp)
            self.kernel_ret_break[cpu] = []
            self.kernel_unx_break[cpu] = []
            for hap in self.kernel_ret_hap[cpu]:
                SIM_hap_delete_callback_id("Core_Breakpoint_Memop", hap)
            for hap in self.kernel_unx_hap[cpu]:
                SIM_hap_delete_callback_id("Core_Breakpoint_Memop", hap)
            self.kernel_ret_hap[cpu] = []
            self.kernel_unx_hap[cpu] = []
            #self.lgr.debug('watchKernel undoRop ret_hits is %d' % self.ret_hits[cpu])
            self.total_ret_hits[cpu] = self.total_ret_hits[cpu] + self.ret_hits[cpu]

    def doUnexpected(self, cell, cpu):
        '''
        Set breaks for unexpected code execution in the kernel 
        '''
        cell_name = self.top.getTopComponentName(cpu)
        for region in self.unx_regions[cell_name]:
            #self.lgr.debug('watchKernel, doUnex region %x len %x on %s' % (region.start, region.length, cell_name))
            unx_break = SIM_breakpoint(cell, Sim_Break_Linear, Sim_Access_Execute, region.start, region.length, 0)
            if region.holes is not None:
                ''' remove holes from break range, e.g., get_dumpable in middle of exec code '''
                for hole in region.holes:
                    SIM_breakpoint_remove(unx_break, Sim_Access_Execute, hole.start, hole.length)

            self.kernel_unx_break[cpu].append(unx_break)
            unx_hap = SIM_hap_add_callback_index("Core_Breakpoint_Memop", self.unx_callback, cpu, unx_break)
            self.kernel_unx_hap[cpu].append(unx_hap)

    class ptInfo():
        def __init__(self, cpu, pt_type, pid, comm):
            self.cpu = cpu
            self.pt_type = pt_type
            self.pid = pid
            self.comm = comm

    def page_table_callback(self, pt_info, third, break_num, memory):
        '''
        Callback when kernel page table (or directory) is unexpectedly modified.
        '''
        cell_name = self.top.getTopComponentName(pt_info.cpu)
        cpu, cur_addr, comm, pid = self.os_utils[cell_name].currentProcessInfo(pt_info.cpu)
        if comm is None or pid == 0 or comm == "idle":
            # TBD need efficient way to not start watching until we actually return to user space (mode hap kill VMX, break on iret slow?
            return
        my_eip = self.os_utils[cell_name].mem_utils.getRegValue(cpu, 'eip')
        value = SIM_get_mem_op_value_le(memory)
        addr = memory.physical_address
        l_addr = memory.logical_address
        length = memory.size
        orig = SIM_read_phys_memory(cpu, addr, memory.size)
        self.lgr.critical('watchKernel page_table_callback, page table for pid %d (%s)  on %s modified at eip 0x%x, type %s by process %d (%s) addr: 0x%x (linear: 0x%x) orig value: %x new %x size: %d' % (pt_info.pid, pt_info.comm, cell_name, my_eip, pt_info.pt_type, pid, comm, addr, l_addr, orig, value, length))

        self.top.addLogEvent(cell_name, pid, comm, forensicEvents.KERNEL_PAGE_TBL,
             'Modification of process %d (%s) kernel page table on %s modified at eip 0x%x, type %s by process %d (%s) addr: 0x%x (linear: 0x%x) orig value: %x new %x size: %d' % (pt_info.pid, pt_info.comm, cell_name, my_eip, pt_info.pt_type, pid, comm, addr, l_addr, orig, value, length))
        #SIM_break_simulation("remove this")

    def setPageTableHap(self, cpu, cell, phys_address, length, pt_type, pid, comm):
        cell_name = self.top.getTopComponentName(cpu)
        l_address = self.param[cell_name].kernel_base | phys_address
        #phys_block = cpu.iface.processor_info.logical_to_physical(l_address, Sim_Access_Read)
        #self.lgr.debug('setPageTableHap add break at phys, 0x%x, linear %x (translated to %x) len 0x%x type %s' % (phys_address, 
        #    l_address, phys_block.address, length, pt_type))
        #cell = cpu.physical_memory
        #break_num = SIM_breakpoint(cell, Sim_Break_Physical, Sim_Access_Write, address, length, 0)
        break_num = SIM_breakpoint(cell, Sim_Break_Linear, Sim_Access_Write, l_address, length, 0)
        self.kernel_pt_break[cpu].append(break_num)
        pt_info = self.ptInfo(cpu, pt_type, pid, comm)
        hap_num = SIM_hap_add_callback_index("Core_Breakpoint_Memop", self.page_table_callback, pt_info, break_num)
        self.kernel_pt_hap[cpu].append(hap_num)

    def initPageDirAddressExtended(self, cpu, cr3):
        '''
        PAE: CR3 is address of table of four 64-bit pointers to pg table directories
        Linux kernel's ptr entry (fourth entry) is zeroed
        before going to user space.  Get it and keep it.
        '''
        dir_ptr_entry_addr = cr3+(3*8)
        #self.setPageTableHap(cpu, dir_ptr_entry_addr, 8, PG_DIR_PTR_TBL)
        '''
        0xc0000000 and up will use the the fourth entry
        '''
        self.dir_ptr_entry[cpu] = SIM_read_phys_memory(cpu, dir_ptr_entry_addr, 8)
        self.lgr.debug('watchKernel, initPageDirAddressExtended set dir_ptr_entry to 0x%x' % self.dir_ptr_entry[cpu])


    def watchKernelPageExtended(self, cpu, cell, cr3, pid, comm):
        '''
        PAE: Watch kernel page directories and tables for PAE configurations.
        This is used for linux.  Note we igore page tables whose s/u bit is u.
        Not clear why these page tables are updated when userland pages
        in an allocated page.
        '''
        self.lgr.debug('watchKernel, watchKernelPageExtended')
        mask64 = 0x000ffffffffff000
        big_pages = memUtils.testBit(self.dir_ptr_entry[cpu], 7)
        u_s = memUtils.testBit(self.dir_ptr_entry[cpu], 2)
        pg_dir_addr = self.dir_ptr_entry[cpu] & mask64
        if pg_dir_addr == 0:
            self.lgr.error('watchKernelPageExtended, got zero for pg_dir_addr')
            return
        #self.lgr.debug('watchPageExtended, dir_ptr_entry: 0x%x  pg_dir_addr: 0x%x big: %x u/s %x' % (self.dir_ptr_entry[cpu], 
        #   pg_dir_addr, big_pages, u_s))
        self.setPageTableHap(cpu, cell, pg_dir_addr, 4096, PG_DIR, pid, comm)

        for i in range(512):
            pg_dir_entry = SIM_read_phys_memory(cpu, pg_dir_addr, 8)
            big_pages = memUtils.testBit(pg_dir_entry, 7)
            u_s = memUtils.testBit(pg_dir_entry, 2)
            if big_pages == 0:
                pg_table_addr = pg_dir_entry & mask64
                if pg_table_addr != 0 and u_s == 0:
                    #self.lgr.debug('watchPageExtended, pg_dir_entry: 0x%x  pg_table_addr: 0x%x big: %x u/s %x' % (pg_dir_entry, pg_table_addr, big_pages, u_s)) 
                    self.setPageTableHap(cpu, cell, pg_table_addr, 4096, PG_TBL, pid, comm)
            else:
                #self.lgr.debug('watchKernelPageExtended pg_dir_entry 0x%x is to a big page u/s %x' % (pg_dir_entry, u_s))
                pass
            pg_dir_addr = pg_dir_addr + 8

            
    def initPageDirIA32E(self, cpu, cr3):
        '''
        IA32E: CR3 is base address of the PML4 table, which is 512 entries, of 64bits per entry.  
        Bits 47:39 of an address select the entry in the PML4 table.
        '''
        cell_name = self.top.getTopComponentName(cpu)
        kbase = self.param[cell_name].kernel_base
        self.PML4_entry = memUtils.bitRange(kbase, 39, 47)
        self.lgr.debug('initPageDirIA3E, PML4_entry is %x from kbase 0x%x' % (self.PML4_entry, kbase))

    def get40(self, cpu, addr):
        try:
            value = SIM_read_phys_memory(cpu, addr, 8)
        except:
            self.lgr.error('nothing mapped at 0x%x' % addr)
            return 0
        retval = memUtils.bitRange(value, 0, 39)
        return retval

    def decodeKernelAddress(self, cpu, virt):
        ''' not yet working? '''
        pg_dir_ptr_table_base_addr = (self.PML4_entry * 8) + self.cr3[cpu]
        pdpte_offset = memUtils.bitRange(virt, 30, 38)
        pdpte_addr = pg_dir_ptr_table_base_addr + (pdpte_offset * memUtils.MACHINE_WORD_SIZE)
        self.lgr.debug('watchKernel, decode virt 0x%x ' % (virt))
        self.lgr.debug('watchKernel, decode cr3 is %x  pg_dir_ptr_table_base_addr  0x%x ' % (self.cr3[cpu], pg_dir_ptr_table_base_addr))
        self.lgr.debug('watchKernel, decode pdpte_offset: %x addr: %x' % (pdpte_offset, pdpte_addr))

        page_dir_base = self.get40(cpu, pdpte_addr)
        pd_offset = memUtils.bitRange(virt, 21, 29)
        page_dir_address = page_dir_base + (pd_offset * memUtils.MACHINE_WORD_SIZE)        
        self.lgr.debug('watchKernel, decode pd_offset: %x addr: %x' % (pd_offset, page_dir_address))

        page_table_base = self.get40(cpu, page_dir_address)
        pt_offset = memUtils.bitRange(virt, 12, 20)
        page_table_addr = page_table_base + (pt_offset * memUtils.MACHINE_WORD_SIZE)
        self.lgr.debug('watchKernel, decode pt_offset: %x addr: %x' % (pt_offset, page_table_addr))

        page_table_entry = self.get40(cpu, page_table_addr)
        pg_offset = memUtils.bitRange(virt, 0, 11)
        retval = page_table_entry + pg_offset
        self.lgr.debug('watchKernel, decode offsest 0x%x to 0x%x' % (pg_offset, retval))
        return retval
 

        
    def watchKernelIA32E(self, cpu, cell, cr3, pid, comm):
        '''
        Watch kernel page directories and tables for IA32E 64-bit configurations.
        '''
        mask64 = 0x000ffffffffff000
        cell_name = self.top.getTopComponentName(cpu)
        #self.lgr.debug('watchKernelIA32E, first PML4 entry for kernel is %d on %s %d (%s)' % (self.PML4_entry, cell_name, pid, comm))
        pg_dir_ptr_table_base_addr = (self.PML4_entry * 8) + cr3
        ''' watch the kernel entry in the PML4 table '''
        self.setPageTableHap(cpu, cell, pg_dir_ptr_table_base_addr, 8, PML4, pid, comm)
        pg_dir_ptr_table_base = SIM_read_phys_memory(cpu, pg_dir_ptr_table_base_addr, 8)
        ''' watch the kernel page directory pointer table '''
        self.setPageTableHap(cpu, cell, pg_dir_ptr_table_base, 4096, PG_DIR_PTR_TBL, pid, comm)
        #self.lgr.debug('pg_dir_ptr_table_base_addr is 0x%x,  table base is 0x%x' % (pg_dir_ptr_table_base_addr, pg_dir_ptr_table_base))
        
        ''' Look at each entry in the page directory pointer table '''
        pg_dir_ptr_addr = pg_dir_ptr_table_base
        for i in range(512):
            pg_dir_ptr_entry = SIM_read_phys_memory(cpu, pg_dir_ptr_addr, 8)
            big_pages = memUtils.testBit(pg_dir_ptr_entry, 7)
            u_s = memUtils.testBit(pg_dir_ptr_entry, 2)
            if big_pages == 0:
                pg_dir_addr = pg_dir_ptr_entry & mask64
                if pg_dir_addr != 0 and u_s == 0:
                    #self.lgr.debug('watchKernelIA32E, pg_dir_ptr_entry: 0x%x  pg_dir_addr: 0x%x big: %x u/s %x on %s %d (%s)' % (pg_dir_ptr_entry, pg_dir_addr, big_pages, u_s, cell_name, pid, comm)) 
                    self.setPageTableHap(cpu, cell, pg_dir_addr, 4096, PG_DIR, pid, comm)
            pg_dir_ptr_addr = pg_dir_ptr_addr + 8

    def watchKernelPage(self, cpu, cell, pid, comm):
        '''
        Watch kernel page tables for modification
        ''' 
        mask32 = 0xfffff000
        cr3 = self.cr3[cpu]
        cr4 = self.cr4[cpu]
        cell_name = self.top.getTopComponentName(cpu)
        
        ''' determine if PAE being used '''
        addr_extend = memUtils.testBit(cr4, 5)
        if addr_extend != 0:
            if self.os_utils[cell_name].mem_utils.WORD_SIZE == 4:
                #self.lgr.debug('watchKernelPage, using PAE extended memory')
                self.watchKernelPageExtended(cpu, cell, cr3, pid, comm)
            else:
                #self.lgr.debug('watchKernelPage, using IA32E mode')
                self.watchKernelIA32E(cpu, cell, cr3, pid, comm)
        else:
            ''' 
            Traditional page table.  Assume upper half kernel, and watch those directories & page tables
            Get the directory table entry that starts kernel base address
            '''
            self.lgr.debug('watchKernelPage, traditional paging')
            bottom = self.param[cell_name].kernel_base
            index = bottom >> 22
            remain = 1024 - index
            offset = index * 4
            pg_dir_addr = cr3+offset
            #self.lgr.debug('watchKernelPage, index is %d remain %d offset %x' % (index, remain, offset))
            # watch the section of the page directory that the kernel uses for its stuff
            self.setPageTableHap(cpu, cell, pg_dir_addr, 4*remain, PG_DIR, pid, comm)
            for i in range(remain):
                entry = SIM_read_phys_memory(cpu, pg_dir_addr, 4)                
                pg_table_addr = entry & mask32
                big_pages = memUtils.testBit(entry, 7)
                u_s = memUtils.testBit(entry, 2)
                if big_pages == 0:
                    pg_table_addr = entry & mask32
                    #if pg_table_addr != 0 and u_s == 0:
                    if pg_table_addr != 0:
                        #self.lgr.debug('watchKernelPage, pg_dir_entry: 0x%x  pg_table_addr: 0x%x big: %x u/s %x' % (entry, pg_table_addr, big_pages, u_s)) 
                        self.setPageTableHap(cpu, cell, pg_table_addr, 4096, PG_TBL, pid, comm)
                else:
                    #self.lgr.debug('watchKernelPage pg_dir_entry 0x%x is to a big page u/s %x' % (entry, u_s))
                    pass
                pg_dir_addr = pg_dir_addr + 4

    def undoKernelPage(self, cpu):
        for break_num in self.kernel_pt_break[cpu]:
            SIM_delete_breakpoint(break_num)
        for hap_num in self.kernel_pt_hap[cpu]:
            SIM_hap_delete_callback_id("Core_Breakpoint_Memop", hap_num)
        self.kernel_pt_break[cpu] = []
        self.kernel_pt_hap[cpu] = []
        #self.lgr.debug('undoKernelPage')

    def clearCalls(self, cpu):
        #self.lgr.debug('watchKernel haps_added %d  removed %d' % (self.haps_added, self.haps_removed))
        pass

    '''
    # load enumerated set of ret addresses.  NOT USED, creates 20k breakpoints which kills simics
    def loadRetBreaks(self, fname, cpu, cell, cell_name):
        print 'start retAddress break load'
        f = open(fname, 'r')
        first_break = None
        last_break = None
        p_cell = cpu.physical_memory
        count = 0
        for line in f:
            addr = int(line, 16)
            if addr not in self.exempt_returns[cpu]:
                break_num = SIM_breakpoint(cell, Sim_Break_Linear, Sim_Access_Execute, 
                   addr, 1, 0)
                #phys_block = cpu.iface.processor_cli.translate_to_physical('ds', addr)
                #break_num = SIM_breakpoint(p_cell, Sim_Break_Physical, 
                #    Sim_Access_Execute, phys_block.address, 1, 0)
                if first_break is None:
                    first_break = break_num
                last_break = break_num
            else:
                #print 'skip exempt %x' % addr
                pass
            count += 1
            if count > 50:
                break
        self.kernel_ret_hap[cpu] = SIM_hap_add_callback_range("Core_Breakpoint_Memop", 
                                      self.rop_cop_ret_callback, cpu, first_break, last_break)
        print 'done retAddress break load'

    '''
