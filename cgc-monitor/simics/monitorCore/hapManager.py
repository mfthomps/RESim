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
import procInfo
import pageUtils
import osUtils
'''
Manage breakpoints and haps that monitor memory accesses.
Each call to this module is intended to add one page (or a portion of one page)
The breakpoint/haps are named by logical addresses, which need not be
on page boundaries.  The names also include a 'kind' that distinguishes between
Rop pages (2) and others (1).
'''
CODE_PAGE = 2
DATA_PAGE = 1
TAINT_PAGE = 3
class hapManager():
    __breaks = {}
    __haps = {}
    __kernel_breaks = {}
    __kernel_haps = {}
    __syscall_breaks = {}
    __syscall_haps = {}
    __syscall_break_count = {}
    __text_top = {}
    __text_start = {}
    __data_end = {}

    def __init__(self, top, cell_config, lgr, always_watch_calls=False):
        self.haps_added = 0
        self.haps_removed = 0
        self.always_watch_calls = always_watch_calls
        self.top = top
        self.lgr = lgr
        self.__cell_config = cell_config
        self.count_kernel_syscalls = {}
        self.watching_pids = {}
        for cell_name in cell_config.cells:
            self.__breaks[cell_name] = {}
            self.__haps[cell_name] = {}
            self.__kernel_breaks[cell_name] = []
            self.__kernel_haps[cell_name] = []
            self.__text_top[cell_name] = None
            self.__text_start[cell_name] = {}
            self.__data_end[cell_name] = {}
            self.__syscall_breaks[cell_name] = []
            self.__syscall_haps[cell_name] = []
            self.__syscall_break_count[cell_name] = 0
            self.count_kernel_syscalls[cell_name] = 0
            self.watching_pids[cell_name] = []

    # TBD hack for linux share of top of text and bottom of data at same page
    def onSamePage(self, cpu, cell_name, pid): 
        if True or self.__cell_config.os_type[cell_name] == osUtils.LINUX:
            text_block = cpu.iface.processor_info.logical_to_physical(self.__text_start[cell_name][pid], 
                Sim_Access_Read)
            data_block = cpu.iface.processor_info.logical_to_physical(self.__data_end[cell_name][pid], 
                Sim_Access_Read)
            #self.lgr.debug('onSamePage test text %x and data %x' % (text_block.address, 
                #data_block.address))
            if text_block.address != 0 and (text_block.address == data_block.address):
                return True
            else:
                return False
        else:
            return False

    def isLinuxOverlap(self, cpu, cell_name, pid, address):
        ''' is the given address the last page of text and does it overlap the first page of data? '''
        if pid in self.__text_start[cell_name]:
            given, dum = pageUtils.adjust(address,  0, self.top.PAGE_SIZE)
            last_text, dum = pageUtils.adjust(self.__text_start[cell_name][pid], 0, self.top.PAGE_SIZE)
            if given == last_text and self.onSamePage(cpu, cell_name, pid):
                return True
            else:
                return False
        else: 
            return False

    def getTextStart(self, cell_name, pid):
        return self.__text_start[cell_name][pid]

    def setTextStart(self, cell_name, pid, start):
        self.lgr.debug('setTextStart for %s:%d to %x' % (cell_name, pid, start))
        self.__text_start[cell_name][pid] = start

    def setDataEnd(self, cell_name, pid, end):
        self.lgr.debug('setDataEnd for %s:%d to %x' % (cell_name, pid, end))
        self.__data_end[cell_name][pid] = end

    def hasSysCalls(self, cell_name):
        if len(self.__syscall_breaks[cell_name]) > 0:
            return True
        return False

    def kernelSysCall(self, cpu, cell_name, cell, address, callback):
        if address is not None:
            #self.lgr.debug('kernelSysCall setting kernel syscall break at %x for callback %s' % (address, callback))
            pass
        else:
            self.lgr.error('kernelSysCall in %s called with no address' % cell_name)
            return
        if self.count_kernel_syscalls[cell_name] > 0:
            self.lgr.debug('kernelSysCall already set for %s' % cell_name)
            return
        syscall_break = None
        phys_block = cpu.iface.processor_info.logical_to_physical(address, Sim_Access_Read)
        if phys_block.address != 0:
            pcell = cpu.physical_memory
            syscall_break = SIM_breakpoint(pcell, Sim_Break_Physical, Sim_Access_Execute, 
                    phys_block.address, 1, 0)
            self.lgr.debug('hapManager, kernelSysCall using physical break on %s' % cell_name)
            for cpu in self.__cell_config.cell_cpu_list[cell_name]:
                phys_block = cpu.iface.processor_info.logical_to_physical(address, Sim_Access_Read)
                if phys_block.address != 0:
                    self.lgr.debug('cpu memory mapped %s' % str(cpu))
                else:
                    self.lgr.debug('cpu memory IS NOT mapped %s' % str(cpu))
 
        else:
            syscall_break = SIM_breakpoint(cell, Sim_Break_Linear, Sim_Access_Execute, 
                address, 1, 0)
            self.lgr.debug('hapManager, kernelSysCall using linear break on %s' % cell_name)
        syscall_hap = SIM_hap_add_callback_index("Core_Breakpoint_Memop", 
	    callback, cell_name, syscall_break)
        self.__syscall_breaks[cell_name].append(syscall_break)
        self.__syscall_haps[cell_name].append(syscall_hap)
        self.__syscall_break_count[cell_name] += 1
        #self.lgr.debug('kernelSysCall setting kernel syscall break at %x break_num: %d' % (address, syscall_break))
        return syscall_break

    def clearKernelSysCalls(self, cell_name, pid, force=False):
        ''' 
        Remove breakpoints & haps for kernel syscalls, but only if the count goes to zero.
        Return true if they have been cleared.
        '''
        retval = False
        if self.always_watch_calls and not force:
            return retval
        if pid in self.watching_pids[cell_name]:
            self.watching_pids[cell_name].remove(pid)
            self.lgr.debug('hapManager, clearKernelSyscalls remove pid %d from %s' % (pid, cell_name))
        else:
            self.lgr.debug('hapManager, clearKernelSyscalls pid %d not in %s' % (pid, cell_name))
        if self.count_kernel_syscalls[cell_name] > 1:
            self.count_kernel_syscalls[cell_name] -= 1
            self.lgr.debug('clearKernelSysCalls do nothing, but decrement to %d' % self.count_kernel_syscalls[cell_name])
        elif self.count_kernel_syscalls[cell_name] == 1:
            self.count_kernel_syscalls[cell_name] = 0
            self.__syscall_break_count[cell_name] -= len(self.__syscall_breaks[cell_name])
            for breakpt in self.__syscall_breaks[cell_name]:
                #self.lgr.debug('clearKernelSysCalls delete break %d' % breakpt)
                SIM_delete_breakpoint(breakpt)
            for hap in self.__syscall_haps[cell_name]:
                #self.lgr.debug('clearKernelSysCalls delete hap %d' % hap)
                SIM_hap_delete_callback_id("Core_Breakpoint_Memop", hap)
            self.__syscall_breaks[cell_name] = []
            self.__syscall_haps[cell_name] = []
            retval = True
            self.lgr.debug('clearKernelSysCalls num breaks is now: %d' % self.__syscall_break_count[cell_name])
        return retval
        
    '''
        Add a breakpoint and Hap for the given process, at the given address/mode with the given
        Hap callback.  Intended for adding data pages.  Code (for rop) gets added outside
        of this module, but addHap and addBreak will be used to manage the handles.
    '''
    def add(self, cpu, cell_name, pid, start, length, access_mode, mem_callback, 
              kind = DATA_PAGE):
        #self.lgr.debug('hap manager add, start is %x' % start)
        phys_block = cpu.iface.processor_info.logical_to_physical(start, Sim_Access_Read)
        my_args = procInfo.procInfo(None, cpu, pid, None, False)
        if phys_block.address != 0:
            # TBD see if this is also the top of the text.  If so, don't nox this page
            if pid in self.__data_end[cell_name] and start == self.__data_end[cell_name][pid]:
                if self.onSamePage(cpu, cell_name, pid):
                    return 
            cell = cpu.physical_memory
            break_num = SIM_breakpoint(cell, Sim_Break_Physical, access_mode, 
                phys_block.address, length, 0)
            self.lgr.debug('hap_manager %s:%d add, set break %d at phys: %x (virt: %x) length: %d mode %d' % \
                  (cell_name, pid, break_num, phys_block.address, start, length, access_mode))
            cb_num = SIM_hap_add_callback_index("Core_Breakpoint_Memop", mem_callback, my_args, break_num)
            self.addHap(cpu, cell_name, pid, cb_num, start, kind)
            self.addBreak(cell_name, pid, break_num, start, kind)
            #if start == 0x804c000:
            #    self.lgr.debug('setting test break at %x' % phys_block.address)
            #    break_num = SIM_breakpoint(cell, Sim_Break_Physical, Sim_Access_Write, 
            #        phys_block.address, length, 0)
            
           
        else:
          if False:
            self.lgr.debug('hap_manager add, no physical address for %x in pid %s:%d' % (start, cell_name, pid))

    def rm(self, cell_name, pid, start, kind=DATA_PAGE):
        self.lgr.debug('hapManager rm for %s:%d %x' % (cell_name, pid, start))
        self.rmBreak(cell_name, pid, start, kind)
        self.rmHap(cell_name, pid, start, kind)

    def hasCodePage(self, cell_name, pid, address):
        key = self.getKey(address, CODE_PAGE)
        #self.lgr.debug('hasCodePage look for %s' % key)
        if cell_name in self.__breaks and pid in self.__breaks[cell_name] and key in self.__breaks[cell_name][pid]:
            return True
        else:
            return False

    def getKey(self, address, kind):
        return '%x:%d' % (address, kind)

    '''
        Add a breakpoint to the database, deleting the breakpoint if one already exists for the logical
        address of the given pid.  The caller is to create the actual breakpoint.
    '''
    def addBreak(self, cell_name, pid, breakNum, address, kind = DATA_PAGE):
        if pid is not None:
            if pid not in self.__breaks[cell_name]:
                self.__breaks[cell_name][pid] = {}
            key = self.getKey(address, kind)
            self.lgr.debug('hapManager, addBreak adding process break %d for pid: %s:%d key: %s' % (breakNum, 
                cell_name, pid, key))
            if key in self.__breaks[cell_name][pid]:
                #TBD wtf 
                self.lgr.debug('addBreak delete break for pid: %s:%d key: %s breaknum: %d' % (cell_name, pid, key,
                    self.__breaks[cell_name][pid][key]))
                SIM_delete_breakpoint(self.__breaks[cell_name][pid][key])
                pass
            self.__breaks[cell_name][pid][key] = breakNum
        else:
            self.__kernel_breaks[cell_name].append(breakNum)
            self.lgr.debug('cell %s adding kernel break %d ' % (cell_name, breakNum))

    '''
        Add a hap to the database, deleting the hap if one already exists for the logical
        address of the given pid.  The caller (which may be external to this module) is to 
        create the actual Hap.
    '''
    def addHap(self, cpu, cell_name, pid, hapNum, address, kind = DATA_PAGE):
        if pid is not None:
            if pid not in self.__haps[cell_name]:
                self.__haps[cell_name][pid] = {}
            key = self.getKey(address, kind)
            ''' virtual address may have been previously mapped -- if so, remove it '''
            if key in self.__haps[cell_name][pid]:
                self.lgr.debug('addHap delete hap %d' % self.__haps[cell_name][pid][key])
                SIM_hap_delete_callback_id("Core_Breakpoint_Memop", self.__haps[cell_name][pid][key])
                self.haps_removed += 1
            self.haps_added += 1
            self.__haps[cell_name][pid][key] = hapNum
            self.lgr.debug('adding hap number %d for key %s' % (hapNum, key))
            
            ''' hack for linux page sharing between top of text & bottom of data '''
            if kind == CODE_PAGE and pid in self.__text_start[cell_name] and \
                address == self.__text_start[cell_name][pid] and \
                pid in self.__data_end[cell_name]:
                ''' mapping top of text section, if page shared with bottom of data, remove the
                    nox hap for the data page '''
                if self.onSamePage(cpu, cell_name, pid):
                    key = self.getKey(self.__data_end[cell_name][pid], 1)
                    if key in self.__haps[cell_name][pid]:
                        self.lgr.debug('linux shared page, undo the data nox hap')
                        SIM_hap_delete_callback_id("Core_Breakpoint_Memop", 
                           self.__haps[cell_name][pid][key])
                        pidBreaks = self.__breaks[cell_name][pid]
                        if key in pidBreaks:
                            SIM_delete_breakpoint(pidBreaks[key])
                        self.haps_removed += 1
                    else:
                        self.lgr.debug('hapManager, samepage hack could not find shared data page in addHap')
                        #SIM_break_simulation('could not find shared data page in addHap')
        else:
            self.lgr.debug('hapManager add kernel hapNum %d' % hapNum)
            self.__kernel_haps[cell_name].append(hapNum)
            self.haps_added += 1


    def rmHap(self, cell_name, pid, address, kind = DATA_PAGE):
        if pid in self.__haps[cell_name]:
            pidHaps = self.__haps[cell_name][pid]
            key = self.getKey(address, kind)
            if key in pidHaps:
                self.lgr.debug('removing hap number %d for key %s' % (pidHaps[key], key))
                SIM_hap_delete_callback_id("Core_Breakpoint_Memop", pidHaps[key])
                self.haps_removed += 1
                del pidHaps[key]

    def rmBreak(self, cell_name, pid, address, kind = DATA_PAGE):
        if pid in self.__breaks[cell_name]:
            pidBreaks = self.__breaks[cell_name][pid]
            key = self.getKey(address, kind)
            if key in pidBreaks:
                SIM_delete_breakpoint(pidBreaks[key])
                del pidBreaks[key]

    def pidHasEntries(self, cell_name, pid):
        '''
        Cheesy way to know if we've cleaned up for this pid
        '''
        if pid in self.__haps[cell_name] or pid in self.__breaks[cell_name]:
            return True
        else:
            return False

    def clear(self, cell_name, pid):
        #print 'IN CLEAR HAPS'
        self.lgr.debug('clearing haps and breakpoints for pid: %s:%d' % (cell_name, pid))
        if pid in self.__haps[cell_name]:
            #self.lgr.debug('clearing %d haps for pid: %d' % (len(self.__haps[cell_name][pid]), pid))
            haps = self.__haps[cell_name][pid]
            for h in haps:
                SIM_hap_delete_callback_id("Core_Breakpoint_Memop", haps[h])
                self.haps_removed += 1
                self.lgr.debug('clearing hap %d for pid: %d' % (haps[h], pid))
            del self.__haps[cell_name][pid]
        if pid in self.__breaks[cell_name]:
            #self.lgr.debug('clearing %d breakpoint for pid: %d' % (len(self.__breaks[cell_name][pid]), pid))
            breaks = self.__breaks[cell_name][pid]
            for b in breaks:
                self.lgr.debug('clearing breakpoint %d for pid: %d' % (breaks[b], pid))
                SIM_delete_breakpoint(breaks[b])
            del self.__breaks[cell_name][pid]
        else:
            self.lgr.debug('hapManager clear, no breaks for %s:%d' % (cell_name, pid))
        self.lgr.debug('hapManager clear haps added/removed: added %d removed %d' % (self.haps_added, self.haps_removed))
        
    def removeKernelBreaks(self, force=False):
        for cell_name in self.__cell_config.cells:
            for bn in self.__kernel_breaks[cell_name]:
                self.lgr.debug('removing kernel break %d' % bn)
                SIM_delete_breakpoint(bn)
            self.__kernel_breaks[cell_name] = []   
            for hn in self.__kernel_haps[cell_name]:
                self.lgr.debug('removeKernelBreaks delete hap %d' % hn)
                SIM_hap_delete_callback_id("Core_Breakpoint_Memop", hn)
                self.lgr.debug('hapManager removeKernelBreaks removed hap %d' % hn)
                self.haps_removed += 1
            self.__kernel_haps[cell_name] = []   
            self.clearKernelSysCalls(cell_name, force)
            
        self.lgr.debug('hapManager removeKernel added/removed: added %d removed %d' % (self.haps_added, self.haps_removed))
            

    def breakLinear(self, cell_name, offset, access_mode, callback, name):
        cell = self.__cell_config.cell_context[cell_name]
        the_break = SIM_breakpoint(cell, Sim_Break_Linear, Sim_Access_Execute, offset, 1, 0)
        cpu_list = self.__cell_config.cpuListFromCell(cell_name)
        self.addBreak(cell_name, None, the_break, None)
        #for cpu in cpu_list:
        the_hap = SIM_hap_add_callback_index("Core_Breakpoint_Memop", callback, cell_name, the_break)
        self.addHap(None, cell_name, None, the_hap, None)
        self.lgr.debug('hapManager, breakLinear for %s on %s, break %d set at %x' % (name, cell_name, the_break, offset))

    def incKernelSysCalls(self, cell_name, pid):
        self.count_kernel_syscalls[cell_name] += 1
        self.lgr.debug('hapManager incKernelSysCalls to %d on %s' %  (self.count_kernel_syscalls[cell_name], cell_name))
        if pid not in self.watching_pids[cell_name]:
            self.watching_pids[cell_name].append(pid)
            self.lgr.debug('hapManager, incKernelSysCalls added pid %d for %s' % (pid, cell_name))
        else:
            self.lgr.error('***************ERRROR *****hapManager, incKernelSysCalls pid %d already being watched for for %s' % (pid, cell_name))

    def watchingCurrentSyscalls(self, cell_name, pid):
        if pid in self.watching_pids[cell_name]:
            return True
        else:
            return False
