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

import pageUtils
import json
import sys
import struct
from simics import *
MACHINE_WORD_SIZE = 8
class ValueError(Exception):
    pass
def readPhysBytes(cpu, paddr, count):
    tot_read = 0
    retval = ()
    cur_addr = paddr
    if cur_addr is None:
        return None
    while tot_read < count:
        remain = count - tot_read
        #remain = min(remain, 1024)
        remain = min(remain, 4)
        try:
            #bytes_read = SIM_read_phys_memory(cpu, cur_addr, remain)
            bytes_read = cpu.iface.processor_info_v2.get_physical_memory().iface.memory_space.read(cpu, cur_addr, remain, 1)
        except:
            raise ValueError('failed to read %d bytes from 0x%x' % (remain, cur_addr))
        #retval = retval + tuple(bytes_read.to_bytes(4, 'little'))
        retval = retval + bytes_read
        tot_read = tot_read + remain
        cur_addr = cur_addr + remain
    return retval

def writePhysBytes(cpu, paddr, data):
    count = len(data)
    cur_addr = paddr
    tot_wrote = 0
    while tot_wrote < count:
        remain = count - tot_wrote
        remain = min(remain, 4)
        print('cur_addr 0x%x  remain %d')
        SIM_write_phys_memory(cpu, cur_addr, data[tot_wrote], remain)
        tot_wrote = tot_wrote + remain
        cur_addr = cur_addr + remain


def getCPL(cpu):
    #print('arch %s' % cpu.architecture)
    if cpu.architecture == 'arm':
        ''' TBD FIX this! '''
        reg_num = cpu.iface.int_register.get_number("sp")
        sp = cpu.iface.int_register.read(reg_num)
        #print('sp is 0x%x' % sp)
        if sp > 0xc0000000:
            return 0
        else:
            return 1
    else:
        reg_num = cpu.iface.int_register.get_number("cs")
        cs = cpu.iface.int_register.read(reg_num)
        mask = 3
    return cs & mask

def testBit(int_value, bit):
    mask = 1 << bit
    return(int_value & mask)

def clearBit(int_value, bit):
    mask = 1 << bit
    return(int_value & ~mask)

def bitRange(value, start, end):
    retval = None
    if value is not None:
        shifted = value >> start
        num_bits = (end - start) + 1 
        mask = 2**num_bits - 1
        retval = shifted & mask
    return retval

def setBitRange(initial, value, start):
    shifted = value << start
    retval = initial | shifted
    return retval

param_map = {}
param_map['arm'] = {}
param_map['arm']['param1'] = 'r0'
param_map['arm']['param2'] = 'r1'
param_map['arm']['param3'] = 'r2'
param_map['arm']['param4'] = 'r3'
param_map['arm']['param5'] = 'r4'
param_map['arm']['param6'] = 'r5'
param_map['x86_64'] = {}
param_map['x86_64']['param1'] = 'rdi'
param_map['x86_64']['param2'] = 'rsi'
param_map['x86_64']['param3'] = 'rdx'
param_map['x86_64']['param4'] = 'r10'
param_map['x86_64']['param5'] = 'r8'
param_map['x86_64']['param6'] = 'r9'
param_map['x86_32'] = {}
param_map['x86_32']['param1'] = 'ebx'
param_map['x86_32']['param2'] = 'ecx'
param_map['x86_32']['param3'] = 'edx'
param_map['x86_32']['param4'] = 'esi'
param_map['x86_32']['param5'] = 'edi'
param_map['x86_32']['param6'] = 'ebb'

win_param_map = {}
win_param_map['x86_64'] = {}
win_param_map['x86_64']['param1'] = 'rcx'
win_param_map['x86_64']['param2'] = 'rdx'
win_param_map['x86_64']['param3'] = 'r8'
win_param_map['x86_64']['param4'] = 'r9'
win_param_map['x86_64']['param5'] = 'r10'
win_param_map['x86_64']['param6'] = 'rsp'
class memUtils():
    def __init__(self, word_size, param, lgr, arch='x86-64', cell_name='unknown'):
        self.WORD_SIZE = word_size
        if word_size == 4:
            self.SIZE_MASK = 0xffffffff
        else:
            self.SIZE_MASK = 0xffffffffffffffff
        self.param = param
        self.cell_name = cell_name
        self.lgr = lgr
        self.hacked_v2p_offset = None
        self.kernel_saved_cr3 = None
        self.ia32_regs = ["eax", "ebx", "ecx", "edx", "ebp", "edi", "esi", "eip", "esp", "eflags"]
        self.ia64_regs = ["rax", "rbx", "rcx", "rdx", "rbp", "rdi", "rsi", "rip", "rsp", "eflags", "r8", "r9", "r10", "r11", 
                     "r12", "r13", "r14", "r15"]
        self.regs = {}
        self.lgr.debug('memUtils init. word size %d  arch is %s' % (word_size, arch))
        if arch == 'x86-64':
            i=0
            for ia32_reg in self.ia32_regs:
                self.regs[ia32_reg] = ia32_reg
                if self.WORD_SIZE == 8:
                    #print('assigning regs[%s] value %s' % (ia32_reg, self.ia64_regs[i]))
                    self.regs[ia32_reg] = self.ia64_regs[i]
                i+=1    
            self.regs['syscall_num'] = self.regs['eax']
            self.regs['syscall_ret'] = self.regs['eax']
            self.regs['pc'] = self.regs['eip']
            self.regs['sp'] = self.regs['esp']
        elif arch == 'arm':
            for i in range(13):
                r = 'R%d' % i
                self.regs[r] = r
            self.regs['sp'] = 'sp'
            self.regs['pc'] = 'pc'
            self.regs['lr'] = 'lr'
            self.regs['cpsr'] = 'cpsr'
            self.regs['syscall_num'] = 'r7'
            self.regs['syscall_ret'] = 'r0'
            self.regs['eip'] = 'pc'
            self.regs['esp'] = 'sp'
        else: 
            self.lgr.error('memUtils, unknown architecture %s' % arch)
        
    def isReg(self, reg):
        if reg.upper() in self.regs:
            return True
        elif reg.lower() in self.regs:
            return True
        else:
            self.lgr.debug('reg not in %s' % self.regs)
            return False    

    def v2p(self, cpu, v):
        retval = None
        cpl = getCPL(cpu)
        try:
            phys_block = cpu.iface.processor_info.logical_to_physical(v, Sim_Access_Read)
        except:
            #self.lgr.debug('memUtils v2p logical_to_physical failed on 0x%x' % v)
            return None

        if phys_block.address != 0:
            #self.lgr.debug('memUtils v2p iface worked cpl %d get unsigned of of phys 0x%x' % (cpl, phys_block.address))
            if self.WORD_SIZE == 8:
                ptable_info = pageUtils.findPageTable(cpu, v, self.lgr, force_cr3=self.kernel_saved_cr3)
                #if not ptable_info.page_exists:
                #    self.lgr.debug('memUtils cpl %d v2p iface worked but page tables do not for phys 0x%x' % (cpl, phys_block.address))
                #elif ptable_info.page_addr != phys_block.address:
                #    self.lgr.debug('memUtils cpl %d v2p iface worked but page value 0x%x does not match 0x%x' % (cpl, ptable_info.page_addr, phys_block.address))
                #else:
                #    self.lgr.debug('memUtils cpl %d v2p iface AND page tables worked  0x%x' % (cpl, ptable_info.page_addr))
            retval = self.getUnsigned(phys_block.address)

        else:
            ptable_info = pageUtils.findPageTable(cpu, v, self.lgr, force_cr3=self.kernel_saved_cr3)
            if v < self.param.kernel_base and not ptable_info.page_exists and self.WORD_SIZE==4:
                self.lgr.debug('memUtils v2p phys addr for 0x%x not mapped per page tables' % (v))
                return None
            #self.lgr.debug('memUtils v2p ptable fu cpl %d phys addr for 0x%x' % (cpl, v))
            if cpu.architecture == 'arm':
                phys_addr = v - (self.param.kernel_base - self.param.ram_base)
                retval = self.getUnsigned(phys_addr)
            else:
                mode = cpu.iface.x86_reg_access.get_exec_mode()
                if v < self.param.kernel_base and mode == 8:
                #if v < self.param.kernel_base:
                    phys_addr = v & ~self.param.kernel_base 
                    #self.lgr.debug('memUtils v2p memUtils ptable fu2 cpl %d get unsigned of 0x%x mode %d' % (cpl, v, mode))
                    retval = self.getUnsigned(phys_addr)
                else:
                    if self.WORD_SIZE == 8 and ptable_info.page_exists:
                        #self.lgr.debug('memUtils v2p mode is %d ptables page exists? phys 0x%x' % (mode, ptable_info.page_addr))
                        retval = ptable_info.page_addr
                    else:
                        if self.WORD_SIZE == 8:
                            retval = None
                            #self.lgr.error('memUtils v2p  cpl %d 32-bit Mode?  mode %d failed getting page info for 0x%x' % (cpl, mode, v)) 
                        else:
                            retval = v & ~self.param.kernel_base 
                            #self.lgr.debug('memUtils v2p  cpl %d 32-bit Mode?  mode %d  kernel addr base 0x%x  v 0x%x  phys 0x%x' % (cpl, mode, self.param.kernel_base, v, retval))
        return retval
                    

    def readByte(self, cpu, vaddr):
        phys = self.v2p(cpu, vaddr)
        if phys is not None:
            return SIM_read_phys_memory(cpu, phys, 1)
        else:
            return None
    '''
        Read a block of maxlen bytes, and return the null-terminated string
        found at the start of the block. (If there is no zero byte in the
        block, return a string that covers the entire block.)
    '''
    def readString(self, cpu, vaddr, maxlen):
        retval = None
        ps = self.v2p(cpu, vaddr)
        if ps is not None:
            #self.lgr.debug('readString vaddr 0x%x ps is 0x%x' % (vaddr, ps))
            remain_in_page = pageUtils.pageLen(ps, pageUtils.PAGE_SIZE)
            if remain_in_page < maxlen:
                #self.lgr.debug('remain_in_page %d' % remain_in_page)
                try:
                    first_read = self.readStringPhys(cpu, ps, remain_in_page)
                except ValueError:
                    self.lgr.debug('memUtils readString value error reading %d bytes from 0x%x' % (remain_in_page, ps))
                    return retval
                if first_read is not None and len(first_read) == remain_in_page:
                    ''' get the rest ''' 
                    ps = self.v2p(cpu, vaddr+remain_in_page)
                    #self.lgr.debug('first read %s new ps 0x%x' % (first_read, ps))
                    try:
                        second_read = self.readStringPhys(cpu, ps, maxlen - remain_in_page)
                    except ValueError:
                        self.lgr.debug('memUtils readString 2nd read value error reading %d bytes from 0x%x' % (remain_in_page, ps))
                        return retval
                    #self.lgr.debug('second read %s from 0x%x' % (second_read, ps))
                    retval = first_read+second_read
                else:
                    retval = first_read
            else: 
                retval = self.readStringPhys(cpu, ps, maxlen)
                #self.lgr.debug('normal read %s from phys 0x%x' % (retval, ps))
        return retval

    def readStringPhys(self, cpu, paddr, maxlen):
        s = ''
        try:
            read_data = readPhysBytes(cpu, paddr, maxlen)
        except ValueError:
            self.lgr.debug('readStringPhys, error reading paddr 0x%x' % paddr)
            return None
        for v in read_data:
            if v == 0:
                del read_data
                return s
            s += chr(v)
        if len(s) > 0:
            return s
        else: 
            return None
    
    def readBytes(self, cpu, vaddr, maxlen):
        ''' return a bytearray of maxlen read from vaddr '''
        remain = maxlen
        start = vaddr
        retval = ()
        while remain > 0:
            count = min(remain, 1024)
            ps = self.v2p(cpu, start)
            if ps is not None:
                remain_in_page = pageUtils.pageLen(ps, pageUtils.PAGE_SIZE)
                if remain_in_page < count:
                    #self.lgr.debug('readBytes remain_in_page %d' % remain_in_page)
                    try:
                        first_read = readPhysBytes(cpu, ps, remain_in_page)
                    except ValueError:
                        self.lgr.error('memUtils readBytes failed to read 0x%x' % ps)
                    if first_read is not None and len(first_read) == remain_in_page:
                        ''' get the rest ''' 
                        ps = self.v2p(cpu, start+remain_in_page)
                        if ps is None:
                            self.lgr.debug('readBytes, could not get phys addr of start+remain 0x%x wanted maxlen of %d' % ((start+remain_in_page), maxlen))
                            retval = retval+first_read
                        else:
                            #self.lgr.debug('readBytes first read %s new ps 0x%x' % (first_read, ps))
                            try:
                                second_read = readPhysBytes(cpu, ps, count - remain_in_page)
                            except ValueError:
                                self.lgr.error('memUtils readBytes, second read failed to read 0x%x' % ps)
                                retval = retval+first_read
                                break
                            #self.lgr.debug('readBytes second read %s from 0x%x' % (second_read, ps))
                            retval = retval+first_read+second_read
                    else:
                        retval = retval+first_read
                else: 
                    try:
                        retval = retval+readPhysBytes(cpu, ps, count)
                    except ValueError:
                        self.lgr.error('memUtils readBytes, second read %d bytes from  0x%x' % (count, ps))
                    #self.lgr.debug('readBytes normal read %s from phys 0x%x' % (retval, ps))
            #else:
            #    self.lgr.error('memUtils readBytes addr 0x%x not mapped?' % vaddr)
            #self.lgr.debug('readBytes got %d' % len(retval))
            start = start+count
            remain = remain - count
        retval = bytearray(retval)
        return retval


    def readWord32(self, cpu, vaddr):
        paddr = self.v2p(cpu, vaddr) 
        if paddr is None:
            self.lgr.debug('readWord32 phys of 0x%x is none' % vaddr)
            return None
        try:
            value = SIM_read_phys_memory(cpu, paddr, 4)
        except:
            self.lgr.error('readWord32 could not read content of %x' % paddr)
            value = None
        return value

    def readWord16(self, cpu, vaddr):
        paddr = self.v2p(cpu, vaddr) 
        if paddr is None:
            return None
        return SIM_read_phys_memory(cpu, paddr, 2)
    
    def readWord16le(self, cpu, vaddr):
        paddr = self.v2p(cpu, vaddr) 
        if paddr is None:
            return None
        paddrplus = self.v2p(cpu, vaddr+1) 
        if paddrplus is None:
            return None
        hi = SIM_read_phys_memory(cpu, paddr, 1)
        lo = SIM_read_phys_memory(cpu, paddrplus, 1)
        retval = hi << 8 | lo
        return retval

    def printRegJson(self, cpu):
        if cpu.architecture == 'arm':
            #self.lgr.debug('printRegJson is arm regs is %s' % (str(self.regs)))
            regs = self.regs.keys()
        elif self.WORD_SIZE == 8:
            ''' check for 32-bit compatibility mode '''
            mode = cpu.iface.x86_reg_access.get_exec_mode()
            if mode == 4:
                regs = self.ia64_regs
            else:
                regs = self.ia32_regs
        else:
            regs = self.ia32_regs

        reg_values = {}
        for reg in regs:
            try:
                reg_num = cpu.iface.int_register.get_number(reg)
                reg_value = cpu.iface.int_register.read(reg_num)
            except:
                #self.lgr.debug('except for %s' % reg)
                ''' Hack, regs contaminated with aliases, e.g., syscall_num '''
                continue
            reg_values[reg] = reg_value
        
        s = json.dumps(reg_values)
        print(s)
    
    def readPhysPtr(self, cpu, addr):
        if addr is None:
            self.lgr.error('readPhysPtr given addr of None')
            return None
        try:
            return self.getUnsigned(SIM_read_phys_memory(cpu, addr, self.WORD_SIZE))
        except:
            self.lgr.error('readPhysPtr fails on address 0x%x' % addr)
            return None

    def readPtr(self, cpu, vaddr):
        size = self.WORD_SIZE
        #if vaddr < self.param.kernel_base:
        #    size = min(size, 6)
        phys = self.v2p(cpu, vaddr)
        if phys is not None:
            try:
                return self.getUnsigned(SIM_read_phys_memory(cpu, phys, size))
            except:
                return None
        else:
            return None

    def readWord(self, cpu, vaddr):
        phys = self.v2p(cpu, vaddr)
        if phys is not None:
            return SIM_read_phys_memory(cpu, phys, self.WORD_SIZE)
        else:
            return None

    def readMemory(self, cpu, vaddr, size):
        phys = self.v2p(cpu, vaddr)
        if phys is not None:
            return SIM_read_phys_memory(cpu, phys, size)
        else:
            return None

    def getRegValue(self, cpu, reg):
        if reg in self.regs:
            reg_num = cpu.iface.int_register.get_number(self.regs[reg])
            #print('getRegValue self.regs[%s] is %s num %d' % (reg, self.regs[reg], reg_num))
        else:
            reg_num = cpu.iface.int_register.get_number(reg)
        reg_value = cpu.iface.int_register.read(reg_num)
        return reg_value

    def kernelArch(self, cpu):
        if cpu == 'arm':
            return 'arm'
        elif self.WORD_SIZE == 8:
            return 'x86_64'
        else:
            return 'x86_32'

    def setRegValue(self, cpu, reg, value):
        if reg in self.regs:
            reg_num = cpu.iface.int_register.get_number(self.regs[reg])
        elif reg in param_map[self.kernelArch(cpu)]:
            reg_num = cpu.iface.int_register.get_number(param_map[self.kernelArch(cpu)][reg])
        else:
            reg_num = cpu.iface.int_register.get_number(reg)
        reg_value = cpu.iface.int_register.write(reg_num, value)

    def getESP(self):
        if self.WORD_SIZE == 4:
            return 'esp'
        else:
            return 'rsp'

    def getSigned(self, val):
        if self.WORD_SIZE == 4:
            if(val & 0x80000000):
                val = -0x100000000 + val
        else:
            if(val & 0x8000000000000000):
                val = -0x10000000000000000 + val
        return val

    def getUnsigned(self, val):
        if self.WORD_SIZE == 4:
            retval = val & 0xFFFFFFFF
            return retval
        else:
            return val & 0xFFFFFFFFFFFFFFFF

    def getEIP(self):
        if self.WORD_SIZE == 4:
            return 'eip'
        else:
            return 'rip'

    def adjustParam(self, delta):
        ''' Adjust parameters for ASLR '''
        if self.WORD_SIZE == 4:
            self.param.current_task = self.param.current_task + delta
        #else:
        #    self.param.current_task = self.param.current_task + abs(delta)

        if self.param.sysenter is not None:
            self.lgr.debug('sysenter was to 0x%x' % self.param.sysenter)
            if self.WORD_SIZE == 4:
                self.param.sysenter = self.param.sysenter + delta
            else:
                # TBD remove if
                #self.param.sysenter = self.param.sysenter + delta
                pass
            self.lgr.debug('sysenter adjusted to 0x%x' % self.param.sysenter)
        if self.param.sysexit is not None:
            if self.WORD_SIZE == 4:
                self.param.sysexit = self.param.sysexit + delta
        if self.WORD_SIZE == 4:
            self.param.iretd = self.param.iretd + delta
            self.param.page_fault = self.param.page_fault + delta
            self.param.syscall_compute = self.param.syscall_compute + delta

            ''' This value seems to get adjusted the other way.  TBD why? '''
            self.lgr.debug('syscall_jump was 0x%x' % self.param.syscall_jump)
            self.param.syscall_jump = self.param.syscall_jump - delta
            self.lgr.debug('syscall_jump adjusted to 0x%x' % self.param.syscall_jump)

        if self.param.sys_entry is not None and self.param.sys_entry != 0 and self.WORD_SIZE==4:
            self.lgr.debug('sys_entry was to 0x%x' % self.param.sys_entry)
            self.param.sys_entry = self.param.sys_entry + delta
            self.lgr.debug('sys_entry adjusted to 0x%x' % self.param.sys_entry)
        

    def getCurrentTask(self, cpu):
        retval = None 
        if self.WORD_SIZE == 4 and cpu.architecture == 'arm':
            retval = self.getCurrentTaskARM(self.param, cpu)
        else:
            if self.WORD_SIZE == 4:
                param_xs_base = self.param.fs_base
                new_xs_base = cpu.ia32_fs_base
            else:
                param_xs_base = self.param.gs_base
                new_xs_base = cpu.ia32_gs_base
            if param_xs_base is None:
                cur_ptr = self.getCurrentTaskX86(self.param, cpu)
                retval = cur_ptr
            else:
                ''' TBD generalize this, will it always be such? '''
                if new_xs_base != 0 and new_xs_base != 0x10000:
                    ''' TBD, this seems the wrong way around, but runs of getKernelParams shows delta is the same, but for the sign.'''
                    '''
                    current_task is the offset into the FS segment
                    '''
                    if self.param.delta is None:
                        self.param.delta = param_xs_base - new_xs_base
                        self.lgr.debug('getCurrentTask param.xs_base 0x%x new_xs_base 0x%x delta is 0x%x, current_task was 0x%x' % (param_xs_base, 
                              new_xs_base, self.param.delta, self.param.current_task))
                        self.adjustParam(self.param.delta)
                        self.lgr.debug('getCurrentTask now 0x%x' % self.param.current_task)
                    cpl = getCPL(cpu)
                    #current_task = self.param.current_task + self.param.delta
                    if self.WORD_SIZE == 4:
                        ct_addr = new_xs_base + (self.param.current_task-self.param.kernel_base)
                    else:
                        va = cpu.ia32_gs_base + self.param.current_task
                        ct_addr = self.v2p(cpu, va)
                    try:
                        retval = SIM_read_phys_memory(cpu, ct_addr, self.WORD_SIZE)
                    except:
                        self.lgr.error('memUtils getCurrentTask failed to read phys address 0x%x' % ct_addr)
                        retval = None
                    if retval == 0:
                        self.lgr.error('retval is zero reading 0x%x' % ct_addr)
                        return -1
                    if retval is None or retval == 0:
                        self.param.delta = None
                    else:
                        self.lgr.debug('getCurrentTask cpl: %d  adjusted current_task: 0x%x xs_base: 0x%x phys of ct_addr(phys) is 0x%x retval: 0x%x  ' % (cpl, 
                              self.param.current_task, new_xs_base, ct_addr, retval))
  

        return retval

    def kernel_v2p(self, param, cpu, vaddr):
        cpl = getCPL(cpu)
        pc = self.getRegValue(cpu, 'pc')
        try:
            phys_block = cpu.iface.processor_info.logical_to_physical(vaddr, Sim_Access_Read)
        except:
            return None

        if phys_block.address != 0:
            #self.lgr.debug('kernel_v2p, cpl: %d pc: 0x%x got phys block, get unsigned of of phys 0x%x' % (cpl, pc, phys_block.address))
            return self.getUnsigned(phys_block.address)
        else:
            retval =  vaddr - param.kernel_base + param.ram_base
            #self.lgr.debug('kernel_v2p cpl: %d pc: 0x%x phys block zero, use kernel and ram base got 0x%x' % (cpl, pc, retval))
            return retval

    def getCurrentTaskARM(self, param, cpu):
        reg_num = cpu.iface.int_register.get_number("sp")
        sup_sp = cpu.gprs[1][reg_num]
        #self.lgr.debug('getCurrentTaskARM sup_sp 0x%x' % sup_sp)
        if sup_sp == 0:
            return None
        ts = sup_sp & ~(param.thread_size - 1)
        #self.lgr.debug('getCurrentTaskARM ts 0x%x' % ts)
        if ts == 0:
            return None
        if ts < param.kernel_base:
            ts += param.kernel_base
            #self.lgr.debug('getCurrentTaskARM ts adjusted by base now 0x%x' % ts)
        task_struct = ts + 12
        ct_addr = self.kernel_v2p(param, cpu, task_struct) 
        #self.lgr.debug('ts: 0x%x  task_struct: 0x%x  phys: 0x%x' % (ts, task_struct, ct_addr))
        try:
            ct = SIM_read_phys_memory(cpu, ct_addr, self.WORD_SIZE)
        except:
            #self.lgr.debug('getCurrentTaskARM ct_addr 0x%x not mapped? kernel_base 0x%x ram_base 0x%x' % (ct_addr, param.kernel_base, param.ram_base))
            pass

     
            return None
        #self.lgr.debug('getCurrentTaskARM ct_addr 0x%x ct 0x%x' % (ct_addr, ct))
        return ct


    def getCurrentTaskX86(self, param, cpu):
        cpl = getCPL(cpu)
        if cpl == 0:
            tr_base = cpu.tr[7]
            esp = self.readPtr(cpu, tr_base + 4)
            if esp is None:
                return None
            #self.lgr.debug('getCurrentTaskX86 kernel mode, esp is 0x%x, tr_base was 0x%x' % (esp, tr_base))
        else:
            esp = self.getRegValue(cpu, 'esp')
            #self.lgr.debug('getCurrentTaskX86 user mode, esp is 0x%x' % esp)
        ptr = esp - 1 & ~(param.stack_size - 1)
        #self.lgr.debug('getCurrentTaskX86 ptr is 0x%x' % ptr)
        ret_ptr = self.readPtr(cpu, ptr)
        if ret_ptr is not None:
            #self.lgr.debug('getCurrentTaskX86 ret_ptr is 0x%x' % ret_ptr)
            check_val = self.readPtr(cpu, ret_ptr)
            if check_val == 0xffffffff:
                return None
        return ret_ptr

    def getBytes(self, cpu, num_bytes, addr, phys_in=False):
        '''
        Get a tuple of bytes of length num_bytes from the given address using Simics physical memory reads, which return tuples.
        '''
        done = False
        curr_addr = addr
        bytes_to_go = num_bytes
        retbytes = ()
        #print 'in getBytes for 0x%x bytes' % (num_bytes)
        while not done and bytes_to_go > 0 and curr_addr is not None:
            bytes_to_read = bytes_to_go
            remain_in_page = pageUtils.pageLen(curr_addr, pageUtils.PAGE_SIZE)
            #print 'remain is 0x%x  bytes to go is 0x%x  cur_addr is 0x%x end of page would be 0x%x' % (remain_in_page, bytes_to_read, curr_addr, end)
            if remain_in_page < bytes_to_read:
                bytes_to_read = remain_in_page
            if bytes_to_read > 1024:
                bytes_to_read = 1024
            #phys_block = cpu.iface.processor_info.logical_to_physical(curr_addr, Sim_Access_Read)
            if phys_in:
                phys = curr_addr
            else:
                phys = self.v2p(cpu, curr_addr)
            if phys is None:
                self.lgr.error('memUtils v2p for 0x%x returned None' % curr_addr)
                #SIM_break_simulation('bad phys memory mapping at 0x%x' % curr_addr) 
                return None, None
            #self.lgr.debug('read (bytes_to_read) 0x%x bytes from 0x%x ' % (bytes_to_read, curr_addr))
            try:
                #read_data = readPhysBytes(cpu, phys_block.address, bytes_to_read)
                read_data = readPhysBytes(cpu, phys, bytes_to_read)
            except ValueError:
            #except:
                #print 'trouble reading phys bytes, address %x, num bytes %d end would be %x' % (phys_block.address, bytes_to_read, phys_block.address + bytes_to_read - 1)
                print('trouble reading phys bytes, address %x, num bytes %d end would be %x' % (phys, bytes_to_read, phys + bytes_to_read - 1))
                print('bytes_to_go %x  bytes_to_read %d' % (bytes_to_go, bytes_to_read))
                self.lgr.error('bytes_to_go %x  bytes_to_read %d' % (bytes_to_go, bytes_to_read))
                return retbytes
            holder = ''
            count = 0
            for v in read_data:
                count += 1
                holder = '%s%02x' % (holder, v)
                #self.lgr.debug('add v of %2x holder now %s' % (v, holder))
            retbytes = retbytes+read_data
            del read_data
            bytes_to_go = bytes_to_go - bytes_to_read
            #self.lgr.debug('0x%x bytes of data read from %x bytes_to_go is %d' % (count, curr_addr, bytes_to_go))
            curr_addr = curr_addr + bytes_to_read
        return retbytes

    def getBytesHex(self, cpu, num_bytes, addr, phys_in=False):
        '''
        Get a hex string of num_bytes from the given address using Simics physical memory reads, which return tuples.
        '''
        done = False
        curr_addr = addr
        bytes_to_go = num_bytes
        retval = ''
        #print 'in getBytes for 0x%x bytes' % (num_bytes)
        while not done and bytes_to_go > 0 and curr_addr is not None:
            bytes_to_read = bytes_to_go
            remain_in_page = pageUtils.pageLen(curr_addr, pageUtils.PAGE_SIZE)
            #print 'remain is 0x%x  bytes to go is 0x%x  cur_addr is 0x%x end of page would be 0x%x' % (remain_in_page, bytes_to_read, curr_addr, end)
            if remain_in_page < bytes_to_read:
                bytes_to_read = remain_in_page
            if bytes_to_read > 1024:
                bytes_to_read = 1024
            #phys_block = cpu.iface.processor_info.logical_to_physical(curr_addr, Sim_Access_Read)
            if phys_in:
                phys = curr_addr
            else:
                phys = self.v2p(cpu, curr_addr)
            if phys is None:
                self.lgr.error('memUtils v2p for 0x%x returned None' % curr_addr)
                #SIM_break_simulation('bad phys memory mapping at 0x%x' % curr_addr) 
                return None, None
            #self.lgr.debug('read (bytes_to_read) 0x%x bytes from 0x%x ' % (bytes_to_read, curr_addr))
            try:
                #read_data = readPhysBytes(cpu, phys_block.address, bytes_to_read)
                read_data = readPhysBytes(cpu, phys, bytes_to_read)
            except ValueError:
            #except:
                #print 'trouble reading phys bytes, address %x, num bytes %d end would be %x' % (phys_block.address, bytes_to_read, phys_block.address + bytes_to_read - 1)
                print('trouble reading phys bytes, address %x, num bytes %d end would be %x' % (phys, bytes_to_read, phys + bytes_to_read - 1))
                print('bytes_to_go %x  bytes_to_read %d' % (bytes_to_go, bytes_to_read))
                self.lgr.error('bytes_to_go %x  bytes_to_read %d' % (bytes_to_go, bytes_to_read))
                return retval
            holder = ''
            count = 0
            for v in read_data:
                count += 1
                holder = '%s%02x' % (holder, v)
                #self.lgr.debug('add v of %2x holder now %s' % (v, holder))
            del read_data
            retval = '%s%s' % (retval, holder)
            bytes_to_go = bytes_to_go - bytes_to_read
            #self.lgr.debug('0x%x bytes of data read from %x bytes_to_go is %d' % (count, curr_addr, bytes_to_go))
            curr_addr = curr_addr + bytes_to_read
        return retval

    def writeWord(self, cpu, address, value):
        #phys_block = cpu.iface.processor_info.logical_to_physical(address, Sim_Access_Read)
        phys = self.v2p(cpu, address)
        #SIM_write_phys_memory(cpu, phys_block.address, value, self.WORD_SIZE)
        SIM_write_phys_memory(cpu, phys, value, self.WORD_SIZE)

    def writeByte(self, cpu, address, value):
        #phys_block = cpu.iface.processor_info.logical_to_physical(address, Sim_Access_Read)
        phys = self.v2p(cpu, address)
        #SIM_write_phys_memory(cpu, phys_block.address, value, self.WORD_SIZE)
        SIM_write_phys_memory(cpu, phys, value, 1)

    def writeWord32(self, cpu, address, value):
        phys = self.v2p(cpu, address)
        SIM_write_phys_memory(cpu, phys, value, 4)

    def writeBytes(self, cpu, address, byte_tuple):
        ''' TBD functionally different from writeString? '''
        if len(byte_tuple) == 0:
            self.lgr.error('memUtils writeBytes got empty byte_tuple')
            return
        cur_addr = address
        for b in byte_tuple:
            phys = self.v2p(cpu, cur_addr)
            if phys is not None:
                SIM_write_phys_memory(cpu, phys, b, 1)
            else:
                self.lgr.error('Failed to get phys addr for 0x%x' % cur_addr)
            cur_addr = cur_addr + 1

    def getGSCurrent_task_offset(self, cpu):
        gs_base = cpu.ia32_gs_base
        retval = gs_base + self.param.cur_task_offset_into_gs
        self.lgr.debug('getGSCurrent_task_offset cell %s gs base is 0x%x, plus current_task offset is 0x%x' % (self.cell_name, gs_base, retval))
        return retval

    def writeString(self, cpu, address, string):
        #self.lgr.debug('writeString len %d adress: 0x%x %s' % (len(string), address, string))

        lcount = int(len(string)/4)
        carry = len(string) % 4
        if carry != 0:
            lcount += 1
        
        sindex = 0
        for i in range(lcount):
            eindex = min(sindex+4, len(string))
            if sys.version_info[0] > 2 and type(string) != bytearray and type(string) != bytes:
                sub = string[sindex:eindex].encode('utf-8','ignore') 
            else:
                sub = string[sindex:eindex]
            count = len(sub)
            #sub = sub.zfill(4)
            sub = sub.ljust(4, b'0')
            #print('sub is %s' % sub)
            #value = int(sub.encode('hex'), 16)
            value = struct.unpack("<L", sub)[0]
            sindex +=4
            #phys_block = cpu.iface.processor_info.logical_to_physical(address, Sim_Access_Read)
            phys = self.v2p(cpu, address)
            if phys is None:
                self.lgr.error('writeString got None as phys addr for 0x%x' % address)
                return
            #SIM_write_phys_memory(cpu, phys_block.address, value, count)
            try:
                SIM_write_phys_memory(cpu, phys, value, count)
                #self.lgr.debug('writeString wrote %d bytes' % count)
            except TypeError:
                self.lgr.error('writeString failed writing to phys 0x%x (vert 0x%x), value %s' % (phys, address, value))
                return
            address += 4

    def getCallNum(self, cpu):
        if not self.param.arm_svc:
            callnum = self.getRegValue(cpu, 'syscall_num')
        else:
            lr = self.getRegValue(cpu, 'lr')
            val = self.readWord(cpu, lr-4)
            callnum = val & 0xfff
        return callnum

    def isKernel(self, v):
        if v >= self.param.kernel_base:
            return True
        else:
            return False

    def saveKernelCR3(self, cpu):
        reg_num = cpu.iface.int_register.get_number("cr3")
        self.kernel_saved_cr3 = cpu.iface.int_register.read(reg_num)
        self.lgr.debug('memUtils saveKernelCR3 saved cr3 to 0x%x' % (self.kernel_saved_cr3))

    def getKernelSavedCR3(self):
        return self.kernel_saved_cr3
