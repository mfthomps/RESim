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
import pageUtilsPPC32
PAGE_SIZE = 4096
class PtableInfo():
    def __init__(self, cpu):
        self.cpu = cpu
        self.pdir_protect = None
        self.ptable_protect = None
        self.page_protect = None
        self.ptable_exists = False
        self.page_exists = False
        self.pdir_addr = None
        self.ptable_addr = None
        self.page_base_addr = None
        # the physical address including offset. 
        self.phys_addr = None
        self.entry_size = 4
        self.nx = 0
        self.writable = False
        self.entry = None
    def valueString(self):
        retval =  'pdir_protect: %s ptable_protect: %s page_protect %s  ptable_exists: %r  page_exists: %r ' % (str(self.pdir_protect), 
             str(self.ptable_protect), str(self.page_protect), self.ptable_exists, self.page_exists)
        if self.ptable_addr is not None:
            retval = retval + ' ptable_addr: 0x%x' % self.ptable_addr
        if self.page_base_addr is not None:
            retval = retval + ' page_base_addr: 0x%x' % self.page_base_addr
        if self.entry is not None:
            if self.phys_addr is not None:
                retval = retval + ' phys_addr: 0x%x  nx:%d write_protect:%d entry:0x%x' % (self.phys_addr, self.nx, self.writable, self.entry)
                other_info = PageEntryInfo(self.entry, self.cpu.architecture)
                retval = retval + ' writable: %r accessed: %r' % (other_info.writable, other_info.accessed) 
        else:
              
            if self.phys_addr is not None:
                retval = retval + ' page-addr: 0x%x  nx: %d writeable:%d Entry is None' % (self.phys_addr, self.nx, self.writable) 
            else:
                retval = retval + ' page-addr is None'
               
        return retval

class PageAddrInfo():
    def __init__(self, logical, physical, entry):
        self.logical = logical
        self.physical = physical
        self.entry = entry

class PageEntryInfo():
    def __init__(self, entry, arch):
        if not arch.startswith('arm'):
            self.writable = memUtils.testBit(entry, 1)
            self.accessed = memUtils.testBit(entry, 5)
        else:
            self.nx = memUtils.testBit(entry, 0)
            ap = memUtils.bitRange(entry, 4, 5)
            self.accessed = True
            self.writable = False
            if ap == 1 or ap == 0:
                self.accessed = False
                self.writable = False
            if ap == 3:
                self.writable = True
            

def unsigned64(val):
    return val & 0xFFFFFFFFFFFFFFFF

def readPhysMemory(cpu, addr, length, lgr):
    retval = None
    try:
        retval = SIM_read_phys_memory(cpu, addr, length)                
    except:
        #lgr.debug('pageUtils error reading physical addr 0x%x' % addr)
        pass
    return retval

''' return start and end adjusted to be on page boundaries '''
def adjust(start, length, page_size):
    max = 0xffffffff
    end = start + length
    if start > max: 
        end = unsigned64(start) + unsigned64(length)
        end = unsigned64(end)
    boundary = start % page_size
    #print 'page range for %x %x' % (start, end)
    #logging.debug('noncode break range for %x %x' % (start, end))
    if boundary != 0:
        #logging.debug('start %x not on page boundary, adjust to %x' % (start, start- boundary))
        start = start - boundary
    boundary = (end+1) % page_size
    if boundary != 0 and end < 0xffffffffffffffff:
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
    if boundary != 0:
       page_start = start - boundary
    return page_start

def getPageBases(cpu, lgr, kernel_base):
    if cpu.architecture.startswith('arm'):
        return getPageBasesArm(cpu, lgr, kernel_base)

    ENTRIES_PER_TABLE = 1024
    retval = []
    reg_num = cpu.iface.int_register.get_number("cr3")
    cr3 = cpu.iface.int_register.read(reg_num)
    pdir_entry_addr = cr3
    pdir_index = 0
    for i in range(ENTRIES_PER_TABLE):
        pdir_entry = readPhysMemory(cpu, pdir_entry_addr, 4, lgr)                
        pdir_entry_20 = memUtils.bitRange(pdir_entry, 12, 31)
        ptable_base = pdir_entry_20 * PAGE_SIZE
        if pdir_entry != 0:
            ptable_entry_addr = ptable_base
            ptable_index = 0
            for j in range(ENTRIES_PER_TABLE):
                ptable_entry = readPhysMemory(cpu, ptable_entry_addr, 4, lgr)
                present = memUtils.testBit(ptable_entry, 0)
                if present:
                    entry_20 = memUtils.bitRange(ptable_entry, 12, 31)
                    page_base = entry_20 * PAGE_SIZE
                    logical = 0
                    logical = memUtils.setBitRange(logical, pdir_index, 22)
                    #lgr.debug('logical now 0x%x from index %d' % (logical, pdir_index))
                    logical = memUtils.setBitRange(logical, ptable_index, 12)
                    if logical >= kernel_base:
                        break
                    #lgr.debug('logical now 0x%x from ptable index %d' % (logical, ptable_index))
                    addr_info = PageAddrInfo(logical, page_base, ptable_entry)
                    retval.append(addr_info)
                ptable_entry_addr += 4
                ptable_index += 1
        pdir_entry_addr += 4
        pdir_index += 1
    return retval
   
def getPageBasesArm(cpu, lgr, kernel_base):
    retval = []
    ttbr = cpu.translation_table_base0
    #print('ttbr is 0x%x' % ttbr)
    base = memUtils.bitRange(ttbr, 14,31)
    base_shifted = base << 14

    #print('base is 0x%x, shifted 0x%x' % (base, base_shifted))
    NUM_FIRST = 4096
    NUM_SECOND = 256
    first_index = 0
    #kernel_base = 0xc0000000
    for i in range(NUM_FIRST):
        first_addr = base_shifted | first_index*4
        ''' first level directory '''
        fld = readPhysMemory(cpu, first_addr, 4, lgr)
        if fld != 0:
            pta = memUtils.bitRange(fld, 10, 31)
            pta_shifted = pta << 10
            second_index = 0
            for j in range(NUM_SECOND):
                va = first_index << 20
                va = va | (second_index << 12)
                if va > kernel_base:
                    break
                second_addr = pta_shifted | second_index*4
                ''' second level directory '''
                sld = readPhysMemory(cpu, second_addr, 4, lgr)
                db = memUtils.bitRange(sld, 0, 1)
                if db != 0:
                    pbase = memUtils.bitRange(sld, 12, 31)
                    pbase_shifted = pbase << 12
                    #print('va: 0x%x page base 0x%x' % (va, pbase_shifted))
                    addr_info = PageAddrInfo(va, pbase_shifted, sld)
                    retval.append(addr_info)
                second_index += 1
        first_index += 1
    return retval
 
def getPageBasesExtended(cpu, lgr, kernel_base):
    ENTRIES_PER_TABLE = 512
    WORD_SIZE = 8
    retval = []
    reg_num = cpu.iface.int_register.get_number("cr3")
    cr3 = cpu.iface.int_register.read(reg_num)
    page_table_directory = cr3
    pdir_index = 0
    for pdir_table_index in range(4):
      pdir_entry_addr = readPhysMemory(cpu, page_table_directory, 8, lgr)
      for i in range(ENTRIES_PER_TABLE):
        pdir_entry = readPhysMemory(cpu, pdir_entry_addr, WORD_SIZE, lgr)                
        pdir_entry_20 = memUtils.bitRange(pdir_entry, 12, 31)
        ptable_base = pdir_entry_20 * PAGE_SIZE
        if pdir_entry != 0:
            ptable_entry_addr = ptable_base
            ptable_index = 0
            for j in range(ENTRIES_PER_TABLE):
                ptable_entry = readPhysMemory(cpu, ptable_entry_addr, WORD_SIZE, lgr)
                present = memUtils.testBit(ptable_entry, 0)
                if present:
                    entry_20 = memUtils.bitRange(ptable_entry, 12, 31)
                    page_base = entry_20 * PAGE_SIZE
                    logical = 0
                    logical = memUtils.setBitRange(logical, pdir_index, 22)
                    #lgr.debug('logical now 0x%x from index %d' % (logical, pdir_index))
                    logical = memUtils.setBitRange(logical, ptable_index, 12)
                    if logical >= kernel_base:
                        break
                    #lgr.debug('logical now 0x%x from ptable index %d' % (logical, ptable_index))
                    addr_info = PageAddrInfo(logical, page_base, ptable_entry)
                    retval.append(addr_info)
                ptable_entry_addr += WORD_SIZE
                ptable_index += 1
        pdir_entry_addr += WORD_SIZE
        pdir_index += 1
      page_table_directory += WORD_SIZE
    return retval
   
def getPageEntrySize(cpu): 
    ''' TBD FIX THIS '''
    if cpu.architecture == 'arm':
        return 4
    if cpu.architecture == 'arm64':
        return 8
    reg_num = cpu.iface.int_register.get_number("cr3")
    cr3 = cpu.iface.int_register.read(reg_num)
    reg_num = cpu.iface.int_register.get_number("cr4")
    cr4 = cpu.iface.int_register.read(reg_num)
    ''' determine if PAE being used '''
    addr_extend = memUtils.testBit(cr4, 5)
    #print('addr_extend is %d' % addr_extend)
    if addr_extend == 0:
        return 4
    else:
        return 8

def findPageTableArm(cpu, va, lgr, force_cr3=None, use_sld=None, do_log=False):
    ptable_info = PtableInfo(cpu)
    if force_cr3 is not None:
        ttbr = force_cr3
    else:
        ttbr = cpu.translation_table_base0
    base = memUtils.bitRange(ttbr, 14,31)
    base_shifted = base << 14
    if do_log:
        lgr.debug('findPageTableArm ttbr0 0x%x base 0x%x shifed 0x%x cpu.translation_talble_base0: 0x%x' % (ttbr, base, base_shifted, cpu.translation_table_base0))
    
    first_index = memUtils.bitRange(va, 20, 31)
    first_shifted = first_index << 2
    first_addr = base_shifted | first_shifted
    ptable_info.pdir_addr = first_addr
    if do_log:
        lgr.debug('findPageTableArm first_index 0x%x  ndex_shifted 0x%x addr 0x%x' % (first_index, first_shifted, first_addr))
   
    fld = readPhysMemory(cpu, first_addr, 4, lgr)
    if fld == 0:
        return ptable_info
    if do_log:
        ptable_info.ptable_protect = memUtils.testBit(fld, 2)
    ptable_info.ptable_exists = True
    pta = memUtils.bitRange(fld, 10, 31)
    pta_shifted = pta << 10
    #print('fld 0x%x  pta 0x%x pta_shift 0x%x' % (fld, pta, pta_shifted))
    if do_log:
        lgr.debug('fld 0x%x  pta 0x%x pta_shift 0x%x' % (fld, pta, pta_shifted))
    
    second_index = memUtils.bitRange(va, 12, 19)
    second_shifted = second_index << 2
    second_addr = pta_shifted | second_shifted
    ptable_info.ptable_addr = second_addr
    sld = readPhysMemory(cpu, second_addr, 4, lgr)
    #print('sld 0x%x  second_index 0x%x second_shifted 0x%x second_addr 0x%x' % (sld, second_index, second_shifted, second_addr))
    if do_log:
        lgr.debug('sld 0x%x  second_index 0x%x second_shifted 0x%x second_addr 0x%x' % (sld, second_index, second_shifted, second_addr))
    if use_sld is None:
        if sld == 0:
            return ptable_info
    else:
        sld = use_sld
    
    #ptable_info.page_protect = memUtils.testBit(sld, 2)
    ptable_info.page_exists = True
    small_page_base = memUtils.bitRange(sld, 12, 31)
    s_shifted = small_page_base << 12
    offset = memUtils.bitRange(va, 0, 11)
    ptable_info.phys_addr = s_shifted + offset
    page_entry_info = PageEntryInfo(sld, cpu.architecture)
    ptable_info.writable = page_entry_info.writable
    ptable_info.nx = memUtils.testBit(sld, 0)
    ptable_info.entry = sld
    return ptable_info 

def findPageTable(cpu, addr, lgr, use_sld=None, force_cr3=None, kernel=False, do_log=False):
    ''' sld is 2nd level directory, which we may already know from previous failures '''
    ''' TBD, seems off... if cannot read sld context may be wrong.  Why not always wait until
        return to user space? '''
    if do_log:
        lgr.debug('findPageTable cpu.architecture %s' % cpu.architecture)
    if cpu.architecture == 'arm':
        return findPageTableArm(cpu, addr, lgr, use_sld=use_sld, force_cr3=force_cr3, do_log=do_log)
    if cpu.architecture == 'arm64':
        return findPageTableArmV8(cpu, addr, lgr, do_log=do_log)
    if cpu.architecture == 'ppc32':
        return pageUtilsPPC32.findPageTable(cpu, addr, lgr)
    elif isIA32E(cpu):
        #lgr.debug('findPageTable is IA32E')
        return findPageTableIA32E(cpu, addr, lgr, force_cr3=force_cr3) 
    else:
        #lgr.debug('findPageTable not IA32E')
        ptable_info = PtableInfo(cpu)
        reg_num = cpu.iface.int_register.get_number("cr3")
        cr3 = cpu.iface.int_register.read(reg_num)
        reg_num = cpu.iface.int_register.get_number("cr4")
        cr4 = cpu.iface.int_register.read(reg_num)
        ''' determine if PAE being used '''
        addr_extend = memUtils.testBit(cr4, 5)
        #print('addr_extend is %d' % addr_extend)
        if addr_extend == 0:
            ''' 
            Traditional page table.  
            '''
            offset = memUtils.bitRange(addr, 0,11) 
            ptable = memUtils.bitRange(addr, 12,21) 
            pdir = memUtils.bitRange(addr, 22,31) 
            #lgr.debug('traditional paging addr 0x%x pdir: 0x%x ptable: 0x%x offset 0x%x ' % (addr, pdir, ptable, offset))
            
            pdir_entry_addr = cr3+ (pdir * 4)
            #lgr.debug('cr3: 0x%x  pdir_entry_addr: 0x%x' % (cr3, pdir_entry_addr))
            ptable_info.pdir_addr = pdir_entry_addr
            pdir_entry = readPhysMemory(cpu, pdir_entry_addr, 4, lgr)                
            if pdir_entry == 0:
                return ptable_info
            ptable_info.ptable_protect = memUtils.testBit(pdir_entry, 2)
            ptable_info.ptable_exists = True
            pdir_entry_20 = memUtils.bitRange(pdir_entry, 12, 31)
            ptable_base = pdir_entry_20 * PAGE_SIZE
            #lgr.debug('pdir_entry: 0x%x 20 0x%x ptable_base: 0x%x' % (pdir_entry, pdir_entry_20, ptable_base))

            ptable_entry_addr = ptable_base + (4*ptable)
            ptable_info.ptable_addr = ptable_entry_addr
            if use_sld is not None:
                entry = use_sld
            else:
                entry = readPhysMemory(cpu, ptable_entry_addr, 4, lgr)                
            #lgr.debug('ptable_entry_addr is 0x%x,  page table entry contains 0x%x' % (ptable_entry_addr, entry))
            if entry == 0:
                return ptable_info
            
            ptable_info.page_protect = memUtils.testBit(entry, 2)
            present = memUtils.testBit(entry, 0)
            rw = memUtils.testBit(entry, 1)
            user_sup = memUtils.testBit(entry, 2)
            #lgr.debug('page present: %d  rw %d user_sup %d' % (present, rw, user_sup))
            ptable_info.page_exists = True
            entry_20 = memUtils.bitRange(entry, 12, 31)
            page_base = entry_20 * PAGE_SIZE
            paddr = page_base + offset
            ptable_info.phys_addr = paddr
            ptable_info.entry = entry
            entry_info = PageEntryInfo(entry, cpu.architecture)
            ptable_info.writable = entry_info.writable
            #lgr.debug('phys addr is 0x%x' % paddr)
            return ptable_info
        else:
            #lgr.debug('call findPageTableExtend')
            return findPageTableExtended(cpu, addr, lgr, use_sld)

def findPageTableExtended(cpu, addr, lgr, use_sld=None):
        WORD_SIZE = 8
        mask64 = 0x000ffffffffff000
        ptable_info = PtableInfo(cpu)
        ptable_info.entry_size = WORD_SIZE
        reg_num = cpu.iface.int_register.get_number("cr3")
        cr3 = cpu.iface.int_register.read(reg_num)
        reg_num = cpu.iface.int_register.get_number("cr4")
        cr4 = cpu.iface.int_register.read(reg_num)
        ''' determine if PAE being used '''
        addr_extend = memUtils.testBit(cr4, 5)
        #lgr.debug('addr_extend is %d' % addr_extend)
        if addr_extend != 0:
            ''' 
            Extended page table.  
            '''
            offset = memUtils.bitRange(addr, 0,11) 
            ptable = memUtils.bitRange(addr, 12,20) 
            pdir = memUtils.bitRange(addr, 21,29) 
            pdir_pointer_table = memUtils.bitRange(addr, 30,31) 
          
            dir_ptr_entry_addr = cr3 + WORD_SIZE * pdir_pointer_table 
            dir_ptr_entry = readPhysMemory(cpu, dir_ptr_entry_addr, WORD_SIZE, lgr)
            dir_ptr_entry_addr = dir_ptr_entry & mask64 

            pdir_entry_addr = dir_ptr_entry_addr + (pdir * WORD_SIZE)

            ptable_info.pdir_addr = pdir_entry_addr

            pdir_entry = readPhysMemory(cpu, pdir_entry_addr, WORD_SIZE, lgr)                
            if pdir_entry == 0:
                return ptable_info

            ptable_info.ptable_protect = memUtils.testBit(pdir_entry, 2)
            ptable_info.ptable_exists = True
            
            pdir_entry_24 = pdir_entry & mask64
            ptable_base = pdir_entry_24
            #lgr.debug('pdir_entry: 0x%x 24 0x%x ptable_base: 0x%x' % (pdir_entry, pdir_entry_24, ptable_base))

            ptable_entry_addr = ptable_base + (WORD_SIZE*ptable)
            #lgr.debug('ptable_entry_addr 0x%x  ptable 0x%x' % (ptable_entry_addr, ptable_base))
            ptable_info.ptable_addr = ptable_entry_addr
            if use_sld is not None:
                entry = use_sld
            else:
                try:
                    entry = readPhysMemory(cpu, ptable_entry_addr, WORD_SIZE, lgr)                
                    #lgr.debug('ptable_entry_addr is 0x%x,  page table entry contains 0x%x' % (ptable_entry_addr, entry))
                except:
                    entry = 0
                    lgr.debug('pageUtils nothing mapped for ptable_entry_addr 0x%x' % ptable_entry_addr)
            if entry is None or entry == 0:
                return ptable_info
            
            ptable_info.page_protect = memUtils.testBit(entry, 2)
            ptable_info.page_exists = True
            entry_24 = entry & mask64
            page_base = entry_24 
            paddr = page_base + offset
            ptable_info.phys_addr = paddr
            #lgr.debug('phys addr is 0x%x' % paddr)
            return ptable_info
        else:
            lgr.error('addr_extended is zero?')
        return ptable_info

def isIA32E(cpu):
    reg_num = cpu.iface.int_register.get_number("cr4")
    cr4 = cpu.iface.int_register.read(reg_num)
    reg_num = cpu.iface.int_register.get_number("efer")
    efer = cpu.ia32_efer
    pae = memUtils.testBit(cr4, 5)
    lme = memUtils.testBit(efer, 8)
    #print('efer is 0x%x  lme %d  pae %d' % (efer, lme, pae))
    if pae and lme:
        return True
    else:
        return False
   
def get40(cpu, addr, lgr):
    retval = None
    present = None
    page_size = None
    value = None
    nx = None
    try:
        value = readPhysMemory(cpu, addr, 8, lgr)
    except:
        lgr.debug('nothing mapped at 0x%x' % addr)
    if value is not None:
        retval = memUtils.bitRange(value, 12, 50) << 12
        page_size = memUtils.testBit(value, 7) 
        present = memUtils.testBit(value, 0) 
        nx = memUtils.testBit(value, 63) 
    return retval, present, page_size, nx

def findPageTableIA32E(cpu, addr, lgr, force_cr3=None): 
    '''
    IA32E: CR3 is base address of the PML4 table, which is 512 entries, of 64bits per entry.  
    Bits 47:39 of an address select the entry in the PML4 table.
    '''
    ptable_info = PtableInfo(cpu)
    #lgr.debug('findPageTableIA32E addr 0x%x' % addr)
    if force_cr3 is None:
        reg_num = cpu.iface.int_register.get_number("cr3")
        cr3 = cpu.iface.int_register.read(reg_num)
        pml4_entry = memUtils.bitRange(addr, 39, 47)
        cr3_40 = memUtils.bitRange(cr3, 12, 50) << 12
        #lgr.debug('cr3 read from reg 0x%x  cr3_40 0x%x  pl4_entry %d' % (cr3, cr3_40, pml4_entry))
    else:
        cr3 = force_cr3
        pml4_entry = memUtils.bitRange(addr, 39, 47)
        cr3_40 = memUtils.bitRange(cr3, 12, 50) << 12
        #lgr.debug('cr3 passed as forced_cr3 0x%x  cr3_40 0x%x  pl4_entry %d' % (cr3, cr3_40, pml4_entry))

    dir_ptr_base_addr = (pml4_entry * 8) + cr3_40
    #lgr.debug('dir_ptr_base_addr 0x%x' % dir_ptr_base_addr)

    dir_ptr_base, present, page_size, nx = get40(cpu, dir_ptr_base_addr, lgr)
    #lgr.debug('dir_ptr_base is 0x%x present %d page_size 0x%x' % (dir_ptr_base, present, page_size))

    dir_ptr_entry = memUtils.bitRange(addr, 30, 38)
    #lgr.debug('dir_ptr_entry is %d' % dir_ptr_entry)

    if dir_ptr_base is None:
        return ptable_info

    dir_base_addr = dir_ptr_base + (dir_ptr_entry * 8)
    #lgr.debug('dir_base_addr 0x%x' % dir_base_addr)
    ptable_info.pdir_addr = dir_base_addr

    dir_base, present, page_size, nx = get40(cpu, dir_base_addr, lgr)                
    #lgr.debug('dir_base 0x%x present %d page_size 0x%x' % (dir_base, present, page_size))
    if dir_base == 0 or dir_base is None:
        return ptable_info
    else:
        dir_entry = memUtils.bitRange(addr, 21, 29)
        if dir_entry is None:
            lgr.error('dir_entry is None reading addr 0x%x' % addr)
            return ptable_info
        
        #lgr.debug('dir_entry %d' % dir_entry)
        table_base_addr = dir_base + (dir_entry * 8)
        #lgr.debug('table_base_addr 0x%x' % table_base_addr)
        ptable_info.ptable_addr = table_base_addr
        table_base, present, page_size, nx = get40(cpu, table_base_addr, lgr)                
         
        if table_base is None or table_base == 0:
            #lgr.debug('table_base could not be read from 0x%x' % table_base_addr)
            return ptable_info
        else:
            #lgr.debug('table_base 0x%x present %d page_size %d' % (table_base, present, page_size))
            ptable_info.ptable_exists = present
            if present and page_size > 0:
                offset = memUtils.bitRange(addr, 0, 20)
                ptable_info.phys_addr = table_base + offset
                ptable_info.page_exists = present
                #lgr.debug('table base 0x%x is the phys page.  Phys addr is 0x%x' % (table_base, ptable_info.phys_addr))
            else:
                table_entry = memUtils.bitRange(addr, 12, 20)
                ptable_info.entry = table_entry
                entry_info = PageEntryInfo(table_entry, cpu.architecture)
                ptable_info.writable = entry_info.writable
                page_base_addr = table_base + (table_entry * 8)
                #lgr.debug('page_base_addr 0x%x ' % (page_base_addr))
                page_base, present, page_size, nx = get40(cpu, page_base_addr, lgr) 
                #lgr.debug('page_base 0x%x present %d' % (page_base, present))
                ptable_info.page_base_addr = page_base_addr
                ptable_info.page_exists = present
                ptable_info.nx = nx
                if present:
                    offset = memUtils.bitRange(addr, 0, 11)
                    ptable_info.phys_addr = page_base + offset
                    #lgr.debug('phys_addr 0x%x' % ptable_info.phys_addr)
               

    return ptable_info


def get_cpu_attr(cpu, attr_name):
    """Helper to read Simics object attributes/registers."""
    return SIM_get_attribute(cpu, attr_name)

def findPageTableArmV8(cpu, va, lgr, do_log=False):
    # thanks Gemini
    # Determine if it's User Space (TTBR0) or Kernel Space (TTBR1) based on Bit 63
    ptable_info = PtableInfo(cpu)
    is_kernel = (va >> 63) & 1
    space_name = "Kernel Space (TTBR1)" if is_kernel else "User Space (TTBR0)"
    if do_log:
        lgr.debug(f"[*] Decoding Virtual Address: 0x{va:x} -> Identified as {space_name}")

    # Read the essential MMU control registers
    tcr = get_cpu_attr(cpu, "translation_table_base_control") # TCR_EL1
    
    if is_kernel:
        ttbr = get_cpu_attr(cpu, "translation_table_base1")   # TTBR1_EL1
        tgran = (tcr >> 30) & 0x3                        # TGran1 (Bits 31:30)
        tsz = (tcr >> 16) & 0x3F                         # T1SZ   (Bits 21:16)
    else:
        ttbr = get_cpu_attr(cpu, "translation_table_base0")   # TTBR0_EL1
        tgran = (tcr >> 14) & 0x3                        # TGran0 (Bits 15:14)
        tsz = tcr & 0x3F                                 # T0SZ   (Bits 5:0)

    # Parse Page Size (Granule) and select bit shift properties
    if tgran == 0x0 or tgran == 0x2: 
        # TGran0 uses 0b00 for 4KB, TGran1 uses 0b10 for 4KB
        page_size_shift = 12
        index_width = 9  # 512 entries per page table level
        granule_str = "4 KB"
    elif tgran == 0x1:               
        # Both use 0b01 for 16KB
        page_size_shift = 14
        index_width = 11 # 2048 entries per level
        granule_str = "16 KB"
    elif tgran == 0x3 or tgran == 0x2: 
        # TGran0 uses 0b11 for 64KB, TGran1 uses 0b11 for 64KB
        page_size_shift = 16
        index_width = 13 # 8192 entries per level
        granule_str = "64 KB"
    else:
        if do_log:
            lgr.debug(f"[-] Unknown or reserved TGran configuration: 0x{tgran:x}")
        return ptable_info

    # Calculate effective Virtual Address size configured in TCR
    va_size = 64 - tsz
    if do_log:
        lgr.debug(f"[*] MMU Config: Base Page Size = {granule_str}, Effective VA Size = {va_size}-bit")

    # Mask out ASID/attributes from the translation table base register pointer (Bits 47:1)
    current_table_base = ttbr & 0x0000FFFFFFFFFFFF
    
    # Dynamically determine the root level layout based on VA bits vs. Granule size
    bits_to_translate = va_size - page_size_shift
    total_levels = (bits_to_translate + index_width - 1) // index_width
    start_level = 4 - total_levels

    if do_log:
        lgr.debug(f"[*] Starting walk at Level {start_level} from Base Physical Address: 0x{current_table_base:x}")

    for level in range(start_level, 4):
        # Determine bit shift for slicing out index at current level
        level_shift = page_size_shift + (3 - level) * index_width
        level_mask = (1 << index_width) - 1
        index = (va >> level_shift) & level_mask

        # Compute physical location of the individual 64-bit descriptor entry
        desc_phys_addr = current_table_base + (index * 8)
        desc = readPhysMemory(cpu, desc_phys_addr, 8, lgr)

        if desc is None:
            return ptable_info

        if do_log:
            lgr.debug(f"    [Level {level}] Index: {index} (Addr: 0x{desc_phys_addr:x}) -> Desc: 0x{desc:x}")
        if level == 3:
            ptable_info.page_base_addr = desc_phys_addr
        elif level == 2:
            ptable_info.ptable_addr = desc_phys_addr

        # Check if descriptor is valid (Bit 0 must be 1)
        if (desc & 1) == 0:
            if do_log:
                lgr.debug(f"[-] Translation Fault: Unmapped address at Level {level} (Descriptor is Zero/Invalid).")
            ptable_info.exists = False
            ptable_info.phys_addr = None
            return ptable_info

        # Check for Block Mappings (Huge Pages): Bit 1 == 0 at Levels 0, 1, or 2
        if level < 3 and ((desc >> 1) & 1) == 0:
            offset_mask = (1 << level_shift) - 1
            phys_block_mask = 0x0000FFFFFFFFFFFF & ~offset_mask
            
            phys_addr = (desc & phys_block_mask) | (va & offset_mask)
            if do_log:
                lgr.debug(f"[+] Found Block Mapping (Huge Page) at Level {level}!")
                lgr.debug(f"[+] VA 0x{va:x} -> PA 0x{phys_addr:x}")
            return ptable_info

        # Step into next lower table structure using bits [47:12] of the descriptor
        if level == 3:
            ap = memUtils.bitRange(desc, 6,7)
            if ap == 1:
                ptable_info.writable = True 
            ptable_info.nx = memUtils.testBit(desc, 54)
        current_table_base = desc & 0x0000FFFFFFFFF000

    # Level 3 Page Table Entry (PTE) processing
    offset_mask = (1 << page_size_shift) - 1
    phys_addr = current_table_base | (va & offset_mask)
    ptable_info.phys_addr = phys_addr
    ptable_info.page_exists = True
    if do_log:
        lgr.debug(f"[+] Found Standard Page Mapping at Level 3!")
        lgr.debug(f"[+] VA 0x{va:x} -> PA 0x{phys_addr:x}")
    return ptable_info
