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
import decode
import logging
import procInfo
from resimHaps import *
'''
    Use page faults to monitor changes in mapping of pages in process address space
    Updates NoX and RoP Haps as virtual addresses get mapped to physical pages, which
    entails setting transient break/Haps on the OS return to the instruction that resulted in the page
    fault.
'''
class pageFaults():
    def __init__(self, top, master_config, cell_config, context_manager, protected_memory, 
                   noX, non_code, os_p_utils, param, use_cr2, lgr):
        self.haps_added = 0
        self.haps_removed = 0
        self.top = top
        self.param = param
        self.context_manager = context_manager
        self.protected_memory = protected_memory
        self.noX = noX
        self.non_code = non_code
        self.os_p_utils = os_p_utils
        self.use_cr2 = use_cr2
        self.lgr = lgr
        self.master_config = master_config
        self.cell_config = cell_config
        self.page_break_cb = {}
        self.page_break_breakpoint = {}
        self.cr2_read_hap = {}
        self.cr2_read_values = {}
        self.regs = {}
        self.fault_count = {}
        self.page_hap = None
        for cell_name in cell_config.cells:

            self.cr2_read_hap[cell_name] = {}
            self.cr2_read_values[cell_name] = {}

            self.page_break_cb[cell_name] = {}
            self.page_break_breakpoint[cell_name] = {}

            self.regs[cell_name] = {}
            self.fault_count[cell_name] = {}
            self.setHap(cell_name)

    def setHap(self, cell_name):
        if self.master_config.needPageFaults(cell_name):
            cmd = '%s.get-processor-list' % cell_name
            proclist = SIM_run_command(cmd)
            cpu = SIM_get_object(proclist[0])
            self.haps_added += 1
            self.page_hap = RES_hap_add_callback_obj_index("Core_Exception", cpu, 0,
                 self.page_fault_callback, cpu, 14)
            self.lgr.debug("pageFaults added exception hap %d" % self.page_hap)
        else:
            self.lgr.debug("pageFaults no page faults are being tracked for cell %s" % cell_name)

    '''
        Is the given cell_name/pid expecting the os to return to some EIP with a page fixed up?
    '''    
    def expecting(self, cell_name, pid):
        return pid in self.page_break_cb[cell_name]    

    '''
        The hap that is called for each and  every page fault.  Integral to being able to
        set breakpoints on physical addresses which may not yet be mapped into memory.
    '''
    def page_fault_callback(self, cpu, one, exception_number):
        cell_name = self.top.getTopComponentName(cpu)
        dumcpu, cur_addr, comm, pid = self.os_p_utils[cell_name].getPinfo(cpu)
        #TBD remove 3
        eip = self.os_p_utils[cell_name].mem_utils.getRegValue(cpu, 'eip')
        #self.lgr.debug('page_fault_callback %d (%s) eip: %x ' % (pid, comm, eip))
        if not self.top.cellHasServer(cell_name):
            #self.lgr.debug('process %s cell %s not in server pids' % (comm, cell_name))
            return

        if pid in self.cr2_read_values[cell_name]:
           #self.lgr.debug('must be reschedule for %s:%d value %x' % (cell_name, pid, self.cr2_read_values[cell_name][pid]))
           return 

        # TBD remove CB exception, here for debugging 
        #if not self.top.isWatching(cell_name, pid):
        if not self.top.isWatching(cell_name, pid) and not self.top.isCB(comm):
           #self.lgr.debug('not watching memory for %s comm: %s' % (cell_name, comm))
           pass

        elif (self.top.isPlayer(comm) and self.master_config.watchPlayer()) or self.master_config.watchCbUser():
           # save regs for use by cgcMonitor after a segv 
           self.regs[cell_name][pid] = self.os_p_utils[cell_name].frameFromRegs(cpu)
           #self.lgr.debug('page_fault for %s:%d (%s)' % (cell_name, pid, comm))
           #self.lgr.debug('page_fault for %s:%d add frame %s' % (cell_name, pid, 
           #    self.os_p_utils[cell_name].stringFromFrame(self.regs[cell_name][pid]))) 
           if self.context_manager.getDebugging() or self.top.hasPendingSignal(cell_name, pid):
               cycles = SIM_cycle_count(cpu)
               self.lgr.debug('page_fault callback at cycle %x, ignored we are debugging eip is %x' % (cycles, eip))
               return
           if self.os_p_utils[cell_name].is_kernel_virtual(eip):
               self.lgr.debug('page fault in kernel %s %d (%s), eip is %x' % (cell_name, pid, comm, eip))
               #return
           phys_block = cpu.iface.processor_info.logical_to_physical(eip, Sim_Access_Read)
           my_args = procInfo.procInfo(comm, cpu, pid, None, False)
           if phys_block.address == 0:
               ''' 
               eip is not mapped.  Record the unmapped eip so the rop cop can be fixed up.  
               Of course the eip can be on mars.  In case it is on mars, record the current 
               simulation cycle so we can come back to it during analysis.
               ''' 
               self.lgr.debug('pageFaults, call handleEipFault for %s %d (%s)' % (cell_name, pid, comm))
               self.top.handleEipFault(cpu, cell_name, pid, eip, comm)
               if self.top.isCB(comm):
                   self.lgr.debug('pageFaults, call forceWatchReturn for  %s %d' % (comm, pid))
                   self.top.forceWatchReturn(cpu, cell_name, comm, pid)
           else:
               #self.lgr.debug('page_fault call recordReturnToCycle for %s:%d eip: %x add frame %s' % (cell_name, pid, eip,
               #    self.os_p_utils[cell_name].stringFromFrame(self.regs[cell_name][pid]))) 
               #SIM_break_simulation('hey now')
               self.top.recordReturnToCycle(cpu, cell_name, pid)
               ''' TBD tracking cycles is still broken, does not handle page fault while running? '''
               self.top.pageFaultUpdateCycles(cell_name, cpu, pid, comm)
               ''' determine the address that caused the fault '''
               if self.use_cr2:
                   self.useCR2(cpu, eip, cell_name, pid, phys_block, my_args)
               else:
                   self.useDecode(cpu, eip, cell_name, pid, phys_block, my_args)

           if pid not in self.fault_count[cell_name]:
               #self.lgr.debug('page_fault pid %d not in fault_count, set to zero' % (pid))
               self.fault_count[cell_name][pid] = 0
           self.fault_count[cell_name][pid] = self.fault_count[cell_name][pid] + 1
           #self.lgr.debug('fault_count for %s %d is now %d' % (cell_name, pid, self.fault_count[cell_name][pid]))

    '''
        Intended to be invoked following OS fixup of a page table so that we can fix up
        haps for protected memory and non-executable code.  Note rop cop fixups occur
        elsewhere since we could not set a breakpoint for code that is not yet mapped.
    '''
    def postFixupCallback(self, my_args, third, forth, memory):
        cell_name = self.top.getTopComponentName(my_args.cpu)
        cpu, cur_addr, comm, pid = self.os_p_utils[cell_name].getPinfo(my_args.cpu)
        if pid != my_args.pid and cpu != my_args.cpu:
            loggign.debug('in postFixupCallback, but not for expected pid.  Expected %s:%d is %s:%d' % \
                (self.top.getTopComponentName(my_args.cpu), my_args.pid, cell_name, pid))
            return
        if pid not in self.page_break_breakpoint[cell_name]:
            # simics sometimes does not remove the hap before it is hit again....
            self.lgr.debug('in postFixupCallback from hap that should be gone pid %s:%d at address %x' % (cell_name, 
                pid, memory.physical_address))
            return
        #self.lgr.debug('in postFixupCallback, we think the OS has fixed up page tables for pid %s:%d at address %x' % (cell_name, pid, memory.physical_address))
        #self.lgr.debug('removing brekpoint %d' % self.page_break_breakpoint[cell_name][pid])
        cell = cpu.physical_memory
        # delete the hap that brought us here
        self.haps_removed += 1
        #self.lgr.debug('will delete hap %d' % self.page_break_cb[cell_name][pid])
        RES_hap_delete_callback_obj_id("Core_Breakpoint_Memop", cell, self.page_break_cb[cell_name][pid])
        RES_delete_breakpoint(self.page_break_breakpoint[cell_name][pid])
        del self.page_break_cb[cell_name][pid]
        del self.page_break_breakpoint[cell_name][pid]
       
        # remove pid from the cr2 values we employed to find the address that caused the fault 
        if pid in self.cr2_read_values[cell_name]:
            address = self.cr2_read_values[cell_name][pid]
            del self.cr2_read_values[cell_name][pid]

            if self.protected_memory is not None:
                self.protected_memory.checkAddress(cell_name, pid, cpu, address)

            # is the referenced virtual address one that should not be executed?  Page may be new or
            # may have changed, e.g., it may have had a CoW 
            if self.master_config.watchNoX(cell_name, comm):
                if self.noX.isIn(cell_name, pid, address):
                    self.non_code.nonCodeBreakRange(cell_name, pid, cpu, address, 1)
                    pass
        if pid in self.regs[cell_name]:
            #self.lgr.debug('removing regs frame for %s:%d' % (cell_name, pid))
            del self.regs[cell_name][pid]
               
       
    '''
    Read the CR2 value into a per-pid global.  Intended for use in finding the address that generated
    a page fault.  This callback is established when a monitored process gets a page fault, and
    is expected to fire when the OS goes to read CR2 as part of its page fault handling.
    ''' 
    def cr2_read_callback(self, my_args, obj, num):
        cell_name = self.top.getTopComponentName(my_args.cpu)
        if self.cell_config.os_type[cell_name] == 'linux':
            cpu, cur_addr, comm, pid =  self.os_p_utils[cell_name].currentProcessInfo()
        else:
            cpu, cur_addr, comm, pid = self.os_p_utils[cell_name].getPinfo(my_args.cpu)
        if pid == my_args.pid:
            cr2 = cpu.iface.int_register.read(num)
            self.cr2_read_values[cell_name][pid] = cr2
            hap = self.cr2_read_hap[cell_name][pid]
            #self.lgr.debug('cr2_read_callback for pid %s:%d read cr2 value of %x remove hap %d' % (cell_name, pid, cr2, hap))
            self.haps_removed += 1
            RES_hap_delete_callback_id("Core_Control_Register_Read", hap)
            del self.cr2_read_hap[cell_name][pid]
        else:
            self.lgr.info('cr2_read_callback unexpected pid, got %s:%d  expected %s:%d' % \
               (cell_name, pid, self.top.getTopComponentName(my_args.cpu), my_args.pid))

    '''
        Remove page fault haps and breakpoints for a given pid.
    '''
    def cleanPid(self, cell_name, cpu, pid):
        if pid in self.page_break_cb[cell_name]:
            cell = cpu.physical_memory
            self.haps_removed += 1
            cb = self.page_break_cb[cell_name][pid]
            bk = self.page_break_breakpoint[cell_name][pid]
            RES_delete_breakpoint(bk)
            self.lgr.debug('pageFault cleanPid removed break %d, hap %d' % (bk, cb))
            RES_hap_delete_callback_obj_id("Core_Breakpoint_Memop", cell, cb)
            del self.page_break_cb[cell_name][pid]
            del self.page_break_breakpoint[cell_name][pid]

        if pid in self.cr2_read_hap[cell_name]:
            self.haps_removed += 1
            hap =  self.cr2_read_hap[cell_name][pid]
            self.lgr.debug('pageFault cleanPid removed reg read hap %d' % (hap))
            RES_hap_delete_callback_id("Core_Control_Register_Read", hap)
            del self.cr2_read_hap[cell_name][pid]
  
    def getFaultCount(self, cell_name, pid):
        if pid in self.fault_count[cell_name]:
            return self.fault_count[cell_name][pid]
        else:
            return None

        #self.lgr.debug('page fault totals: added %d  removed %d' % (self.haps_added, self.haps_removed))

    def cleanAll(self):
        for cell_name in self.page_break_cb:
            cpu = self.cell_config.cpuFromCell(cell_name)
            tmp_list = list(self.page_break_cb[cell_name])
            for pid in tmp_list:
                self.cleanPid(cell_name, cpu, pid)    
            self.page_break_cb[cell_name] = {}
            self.fault_count[cell_name] = {}

            self.cr2_read_values[cell_name] = {}
        if self.page_hap is not None:
            self.lgr.debug('pageFaults remove page hap %d' % self.page_hap)
            RES_hap_delete_callback_id('Core_Exception', self.page_hap)
            self.haps_removed += 1
            self.page_hap = None
        self.lgr.debug('pageFaults cleanAll, haps added: %d, removed: %d' % (self.haps_added, self.haps_removed))

    def reInit(self):
        self.lgr.debug('pageFaults reInit')
        for cell_name in self.cell_config.cells:
            self.setHap(cell_name)

    ''' 
       Try to find the address reference that generated the fault.  We  should be able to
       just read CR2 here, but Simics does not update that register yet.  So, set a Hap
       to fire when the OS reads CR2, and record the value then.
    ''' 
    def useCR2(self, cpu, eip, cell_name, pid, phys_block, my_args):
       self.cleanPid(cell_name, cpu, pid)
       reg_num = cpu.iface.int_register.get_number("cr2")

       self.haps_added += 1
       self.cr2_read_hap[cell_name][pid] = RES_hap_add_callback_obj_index("Core_Control_Register_Read", 
           cpu, 0, self.cr2_read_callback, my_args, reg_num)

       ''' set a hap on the current eip so we hit it when the OS is done fixing the page table.'''
       ''' (this may be invoked many times for the same EIP, e.g., referencing elements of a large structure'''
       cell = cpu.physical_memory
       self.page_break_breakpoint[cell_name][pid] = SIM_breakpoint(cell, Sim_Break_Physical, 
            Sim_Access_Execute, phys_block.address, 1, 0)
       #self.lgr.debug('in useCR2 for page_fault_callback pid: %s:%d, set code break %d at %x' % \
       #         (cell_name, pid, self.page_break_breakpoint[cell_name][pid], phys_block.address))
       #print 'setting hap for pid %d cell_name %s' % (pid, cell_name)
       #self.page_break_cb[cell_name][pid] = RES_hap_add_callback_index("Core_Breakpoint_Memop", 
       # self.postFixupCallback, my_args, self.page_break_breakpoint[cell_name][pid])
       self.haps_added += 1
       self.page_break_cb[cell_name][pid] = RES_hap_add_callback_obj_index("Core_Breakpoint_Memop", 
                    cell, 0, self.postFixupCallback, my_args, self.page_break_breakpoint[cell_name][pid])


    '''
        Decode an instruction to determine which address reference generated a page fault.  Experimental
        alternative to using CR2, which may or may not disable optimizations (at least temporarily).  
        The docoding is not complete.  Using CR2 is preferable.
    '''
    def useDecode(self, cpu, eip, cell_name, pid, phys_block, my_args):
       SIM_break_simulation("in useDecode, this function is half baked, remove this stop to improve")
       unmapped = []
       instruct = SIM_disassemble_address(cpu, eip, 1, 0)
       if instruct[1] is None:
           self.lgr.debug('in page_fault callback, eip %x, no operand for %s' % (eip, instruct))
           SIM_break_simulation('trouble in page fault callback')
           return
       else:
           #print instruct
           address = decode.getUnmapped(cpu, instruct[1], self.lgr)

       # TBD, can these at least be used for read/write?
       #reg_num = cpu.iface.int_register.get_number("eflags")
       #eflags = cpu.iface.int_register.read(reg_num)
       #print 'eflags value is %x' % eflags
       #SIM_break_simulation('stopping for debug')

       if address is not None:
                       
           #set break at this eip so we hit it when the OS finishes mapping page 
           if pid not in self.cr2_read_values[cell_name]:
               cell = cpu.physical_memory
               self.page_break_breakpoint[cell_name][pid] = SIM_breakpoint(cell, Sim_Break_Physical, 
                    Sim_Access_Execute, phys_block.address, 1, 0)
               #cycles = SIM_cycle_count(cpu)
               self.lgr.debug('page_fault_callback %s:%d set code break %d at address %x trying to dereference %x %s' % \
                        (cell_name, pid, self.page_break_breakpoint[cell_name][pid], eip, address, instruct[1]))
               if address == 2:
                   SIM_break_simulation('why 2 for %s:%d ' % (cell_name, pid))
               self.haps_added += 1
               self.page_break_cb[cell_name][pid] = RES_hap_add_callback_index("Core_Breakpoint_Memop", 
                   self.postFixupCallback, my_args, self.page_break_breakpoint[cell_name][pid])
           else:
               SIM_break_simulation('why not caught at start for %s:%d ' % (cell_name, pid))
                           
       else:
           #SIM_break_simulation('stopping, page fault could not determine unmapped memory instruct[1] was %s' % instruct[1])
           self.lgr.debug('page_fault_callback %s:%d no unmapped address for %s' % \
                        (cell_name, pid, instruct[1]))

    def getRegs(self, cell_name, pid):
        retval = None 
        #self.lgr.debug('getRegs look for %s:%d' % (cell_name, pid))
        if pid in self.regs[cell_name]:
            #self.lgr.debug('getRegs foundfor %s:%d' % (cell_name, pid))
            retval = self.regs[cell_name][pid]
        return retval

    def getHapAccounts(self):
        return self.haps_added, self.haps_removed
