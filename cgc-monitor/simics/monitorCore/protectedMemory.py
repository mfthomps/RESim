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

import simics
from simics import *
import sys
import json
import ConfigParser
import logging
import time
import debugInfo
import cgcEvents
import pageUtils
import protectedInfo
import memUtils
import procInfo
from monitorLibs import forensicEvents
from monitorLibs import utils
'''
    Set breaks on access to protected memory areas.

    The module uses the hapManager to associate haps & breakpoints with 
    each pid.
'''
class protectedMemory():
    hap_manager = None
    context_manager = None
    protected = {}
    def __init__(self, top, cell_info, param, stop_on_memory, hap_manager, 
                   context_manager, os_p_utils, page_size, negotiate, other_faults, lgr, track_access = False):
        ''' IF YOU add parameters to the above, consider adding them to reInit as well! '''
        self.param = param
        self.stop_on_memory = stop_on_memory
        self.hap_manager = hap_manager
        self.context_manager = context_manager
        self.page_size = page_size
        self.top = top
        self.os_p_utils = os_p_utils
        self.lgr = lgr
        self.negotiate = negotiate
        if negotiate is None:
            self.lgr.error('negotiate is None')
            return
        self.other_faults = other_faults
        for cell_name in cell_info:
            self.protected[cell_name] = {}
        self.address_readers = {}
        self.address_bookmarks = {}
        self.start_cycle = None
        self.track_access = track_access
        self.ignore_me = False
        self.recent_value = None
        self.recent_where = None
        self.lgr.debug('protectedMemory init, stop_on_memory: %r  track_access: %r' % (stop_on_memory, track_access))

    def reInit(self, stop_on_memory, track_access):
        self.stop_on_memory = stop_on_memory
        self.track_access = track_access
        self.lgr.debug('protectedMemory reInit, stop_on_memory: %r  track_access: %r' % (stop_on_memory, track_access))
        self.ignore_me = False
        self.recent_value = None
        self.recent_where = None

    def findAddressReader(self, address):
        if address in self.address_readers:
            return self.address_readers[address]
        else:
            self.lgr.debug('protectedMemory, findAddressReader no reader for 0x%x' % address)
            return None

    def checkAddress(self, cell_name, pid, cpu, address):
       protected = None
       if pid in self.protected[cell_name]:
           protected = self.protected[cell_name][pid]
       anyAccess = Sim_Access_Write | Sim_Access_Read | Sim_Access_Execute
       if protected is not None and protected.isIn(address):
           ''' protected memory now mapped, determine how much of this page to set breakpoints on '''
           start, length = protected.getStartAndLength(address)
           self.hap_manager.add(cpu, pid, start, length, anyAccess, self.mem_callback)

    def newCB(self, cpu):
       self.lgr.debug('protectedMemory, newCB')
       self.address_readers = {}
       if self.start_cycle is None:
           self.start_cycle = cpu.cycles
           self.lgr.debug('protectedMemory, newCB, start_cycle set to 0x%x' % cpu.cycles)
       else:
           self.lgr.debug('protectedMemory, newCB, start_cycle NOT NONE, was 0x%x' % self.start_cycle)
       self.recent_value = None
       self.recent_where = None

    def clear(self, cell_name, pid):
       self.lgr.debug('protectedMemory, clear %s %d' % (cell_name, pid))
       if pid in self.protected[cell_name]:
           del self.protected[cell_name][pid]
       self.start_cycle = None

    '''
        Set haps to record access to protected memory
    '''
    def protectedBreakRange(self, orig_start, end, cpu, cell_name, pid, comm):
        cell = cpu.physical_memory
        any_access = Sim_Access_Write | Sim_Access_Read | Sim_Access_Execute
        mod = orig_start % self.page_size
        length = self.page_size - mod
        self.protected[cell_name][pid] = protectedInfo.protectedInfo(orig_start, length, self.page_size)
        ''' limit is the start of the next page '''
        limit = orig_start + length
        start = orig_start
        self.lgr.debug('protected break range for pid %d start: %x end: %x 1st page length: %x  limit: %x' % \
            (pid, start, end, length, limit))
        #print 'protected break range start: %x length: %x  limit: %x' % (start, length, limit)
         
        while end >= limit:
            self.hap_manager.add(cpu, cell_name, pid, start, length, any_access, self.mem_callback)
            start = limit
            limit = start + self.page_size
            length = self.page_size
 
        if end > start:
            length = end - start
            any_access = Sim_Access_Read | Sim_Access_Write | Sim_Access_Execute
            self.hap_manager.add(cpu, cell_name, pid, start, length, any_access, self.mem_callback)


    def getRecent(self):
        if self.recent_value is None:
            self.lgr.debug('protectedMemory, getRecent is None')
        else: 
            self.lgr.debug('protectedMemory, getRecent returning %s' % str(self.recent_value))
        return self.recent_value, self.recent_where

    '''
        Handle a memory read/write breakpoint
        Note: memory is of type:  generic_transaction_t
    '''
    def mem_callback(self, my_args, third, forth, memory):
        cell_name = self.top.getTopComponentName(my_args.cpu)
        cpu, cur_addr, comm, pid = self.os_p_utils[cell_name].getPinfo(my_args.cpu)
        self.lgr.debug('mem_callack, %s %d' % (comm, pid))
        if pid == my_args.pid:
            #if self.context_manager.getDebugging() or pid in self.top.__pending_signals:
            if self.context_manager.getDebugging() or self.top.hasPendingSignal(cell_name, pid):
               self.lgr.debug('mem_callack, debugging or pending signal?')
               return
            if self.ignore_me:
               self.lgr.debug('mem_callack, ignore me?')
               return
            self.ignore_me = True
            location = memory.logical_address
            physical = memory.physical_address
            if location is 0 and physical is 0:
               self.lgr.debug('mem_callack, location zero?')
               ''' recursive callback triggered by this Hap '''
               return
            elif location is 0:
               if pid in self.protected[cell_name]:
                   protected = self.protected[cell_name][pid]
                   if protected is not None:
                       offset = physical & 0x00000fff
                       location = protected.start + offset
 
            length = memory.size
            op_type = SIM_get_mem_op_type(memory)
            eip = self.os_p_utils[cell_name].mem_utils.getRegValue(cpu, 'eip')
            type_name = SIM_get_mem_op_type_name(op_type)
            self.lgr.debug('mem_callback location 0x%x phys 0x%x len %d  type %s' % (location, physical, length, type_name))
            value = 0xDEADBEEF
            where = location
            if length <= 8:
                if op_type is Sim_Trans_Store:
                    value = SIM_get_mem_op_value_le(memory)
                else:
                    if location is not 0:
                        value = int(self.top.getBytes(cpu, length, location), 16)
                    else:
                        value = int(self.top.getBytesPhys(cpu, length, physical), 16)
                        where = physical
                if length == 4:
                    self.recent_value = value
                    self.recent_where = where
                    self.lgr.debug('protectedMemory, set recent_value to 0x%x' % value)
                elif length == 1:
                    if self.recent_where is None:
                        self.recent_value = value
                        self.recent_where = where
                        self.lgr.debug('protectedMemory, set 1 byte recent_value to 0x%x' % value)
                    else: 
                        value_str = '%x' % self.recent_value
                        if len(value_str) >= 7:
                            ''' more than three bytes, reset '''                         
                            self.recent_value = value
                            self.recent_where = where
                            self.lgr.debug('protectedMemory, reset 1 byte recent_value to 0x%x' % value)
                        elif where == self.recent_where+1:
                            self.recent_value = (self.recent_value << 8) + value
                            self.recent_where = where
                            self.lgr.debug('protectedMemory, append 1 byte recent_value of 0x%x, now is 0x%x' % (value, self.recent_value))
                        else:
                            self.recent_value = value
                            self.recent_where = where
                            self.lgr.debug('protectedMemory, not contiguous, reset 1 byte recent_value to 0x%x' % value)
                    
            else:
                self.lgr.info('Following entry for memory operation > 8 bytes, IGNORE VALUE')

            self.negotiate.getPage(cpu, pid, cell_name)

            self.lgr.info('protectedMemory mem_callback cycle: 0x%x from eip: %x, %d (%s) %s address %x (phys %x)  (%d bytes) value: %x' % (my_args.cpu.cycles, 
                eip, pid, comm, type_name, location, physical, length, value))
            cpl = memUtils.getCPL(my_args.cpu)
            if cpl == 0:
                # assume transmit direct from protected page, what else would cause pl0 reference to it?
                if not self.track_access:
                    log_entry = "Protected memory, %d bytes, read from %x using kernel" % (length, where)
                    self.top.addLogEvent(cell_name, pid, comm, forensicEvents.USER_MEM_LEAK, 
                       log_entry , low_priority=True)


            ''' track the protected memory access for a CB magic page use assessment '''
            if self.track_access:
                #delta = my_args.cpu.cycles - self.start_cycle
                delta = self.top.getPidCycles(cell_name, my_args.pid)
                record = utils.protectedAccess(length, location, delta, cpl)
                #self.lgr.debug('delta is 0x%x' % delta)
                #json_dump = json.dumps(record, default=utils.jdefault)
                #log_entry = 'Protected memory tracker %d bytes from 0x%x cycle 0x%x' % (length, location, delta)
                #self.top.addLogEvent(cell_name, pid, comm, forensicEvents.USER_MEM_LEAK, 
                #   json_dump , low_priority=False)
                self.top.addProtectedAccess(record, my_args.pid, cell_name)

            if self.stop_on_memory:
                bm = 'protected_memory:0x%x' % location
                if cpl == 0:
                    cycles, eip = self.other_faults.getCycles(cell_name, my_args.pid)
                    if cycles is None:
                        self.lgr.error('protectedMemory failed to find cycle of int80 from otherFaults')
                        return
                    self.top.setDebugBookmark(bm, cpu=my_args.cpu, cycles=cycles, eip=eip)
                    self.lgr.debug('Protected memory, add bookmark for syscall %s' % bm)
                    #self.lgr.debug('Protected memory, add bookmark adjusted for user space %s set for address %x' % (bm, location))
                else:
                    self.top.setDebugBookmark(bm, cpu=my_args.cpu)
                    self.lgr.debug('Protected memory, add bookmark %s set for address %x' % (bm, location))
                
                t_cpu, t_cur_addr, t_comm, t_pid = self.os_p_utils[cell_name].currentProcessInfo(my_args.cpu)
                #self.lgr.debug('Protected memory os_p_utils says %s %d ' % (t_comm, t_pid))
                if location not in self.address_readers:
                    self.address_readers[location] = procInfo.procInfo(comm, cpu, pid)
                #SIM_break_simulation('address 0x%x (virt: 0x%x)  value 0x%x' % (physical, location, value))
        else:
            self.lgr.info('unexpected memory access in %s %d, comm: %s  address %x' % (cell_name, pid, comm, 
                memory.logical_address))
            pass

        self.ignore_me = False
