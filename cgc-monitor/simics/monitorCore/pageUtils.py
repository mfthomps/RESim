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

#import logging
from simics import *
import memUtils
PAGE_SIZE = 4096
class PtableInfo():
    def __init__(self):
        self.pdir_protect = None
        self.ptable_protect = None
        self.ptable_present = False
        self.page_present = False

''' return start and end adjusted to be on page boundaries '''
def unsigned64(val):
    return val & 0xFFFFFFFFFFFFFFFF
def adjust(start, length, page_size):
    max = 0xffffffff
    end = start + length
    if start > max: 
        end = unsigned64(start) + unsigned64(length)
        end = unsigned64(end)
    boundary = start % page_size
    #print 'page range for %x %x' % (start, end)
    #logging.debug('noncode break range for %x %x' % (start, end))
    if boundary is not 0:
        #logging.debug('start %x not on page boundary, adjust to %x' % (start, start- boundary))
        start = start - boundary
    boundary = (end+1) % page_size
    if boundary is not 0 and end < 0xffffffffffffffff:
        adjust = page_size - boundary
        #logging.debug('end %x not on page boundary, adjust to %x' % (start, end+adjust))
        end = end + adjust
    return start, end

''' return number of bytes between given start and end of page, inclusive '''
def pageLen(start, page_size):
    rem = page_size - (start % page_size) 
    return rem

def pageStart(start, page_size):
    page_start = start
    boundary = start % page_size
    if boundary is not 0:
       page_start = start - boundary
    return page_start


def findPageTable(cpu, addr, lgr):
        ptable_info = PtableInfo()
        mask32 = 0xfffff000
        reg_num = cpu.iface.int_register.get_number("cr3")
        cr3 = cpu.iface.int_register.read(reg_num)
        reg_num = cpu.iface.int_register.get_number("cr4")
        cr4 = cpu.iface.int_register.read(reg_num)
        ''' determine if PAE being used '''
        addr_extend = memUtils.testBit(cr4, 5)
        #print('addr_extend is %d' % addr_extend)
        if addr_extend == 0:
            ''' 
            Traditional page table.  Assume upper half kernel, and watch those directories & page tables
            Get the directory table entry that starts kernel base address
            '''
            offset = memUtils.bitRange(addr, 0,11) 
            ptable = memUtils.bitRange(addr, 12,21) 
            pdir = memUtils.bitRange(addr, 22,31) 
            #lgr.debug('traditional paging addr 0x%x pdir: 0x%x ptable: 0x%x offset 0x%x ' % (addr, pdir, ptable, offset))
            
            pdir_entry_addr = cr3+ (pdir * 4)
            #lgr.debug('cr3: 0x%x  pdir_entry_addr: 0x%x' % (cr3, pdir_entry_addr))
            pdir_entry = SIM_read_phys_memory(cpu, pdir_entry_addr, 4)                
            if pdir_entry == 0:
                return ptable_info
            ptable_info.ptable_protect = memUtils.testBit(pdir_entry, 2)
            ptable_info.ptable_present = True
            pdir_entry_20 = memUtils.bitRange(pdir_entry, 12, 31)
            ptable_base = pdir_entry_20 * PAGE_SIZE
            #lgr.debug('pdir_entry: 0x%x 20 0x%x ptable_base: 0x%x' % (pdir_entry, pdir_entry_20, ptable_base))

            ptable_entry_addr = ptable_base + (4*ptable)
            entry = SIM_read_phys_memory(cpu, ptable_entry_addr, 4)                
            #lgr.debug('ptable_entry_addr is 0x%x,  page table entry contains 0x%x' % (ptable_entry_addr, entry))
            if entry == 0:
                return ptable_info
            
            ptable_info.page_protect = memUtils.testBit(entry, 2)
            ptable_info.page_present = True
            entry_20 = memUtils.bitRange(entry, 12, 31)
            page_base = entry_20 * PAGE_SIZE
            paddr = page_base + offset
            #lgr.debug('phys addr is 0x%x' % paddr)
            return ptable_info

