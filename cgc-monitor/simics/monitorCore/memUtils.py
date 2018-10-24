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
MACHINE_WORD_SIZE = 8

def readPhysBytes(cpu, paddr, len):
    try:
        return cpu.iface.processor_info_v2.get_physical_memory().iface.memory_space.read(cpu, paddr, len, 0)
    except:
        return None

def getCPL(cpu):
    reg_num = cpu.iface.int_register.get_number("cs")
    cs = cpu.iface.int_register.read(reg_num)
    mask = 3
    return cs & mask

def testBit(int_value, bit):
    mask = 1 << bit
    return(int_value & mask)

def bitRange(value, start, end):
    shifted = value >> start
    num_bits = (end - start) + 1 
    mask = 2**num_bits - 1
    retval = shifted & mask
    return retval

class memUtils():
    def __init__(self, word_size, param):
        self.WORD_SIZE = word_size
        self.param = param
        ia32_regs = ["eax", "ebx", "ecx", "edx", "ebp", "edi", "esi", "eip", "esp"]
        ia64_regs = ["rax", "rbx", "rcx", "rdx", "rbp", "rdi", "rsi", "rip", "rsp"]
        self.regs = {}
        i=0
        for ia32_reg in ia32_regs:
            self.regs[ia32_reg] = ia32_reg
            if self.WORD_SIZE == 8:
                self.regs[ia32_reg] = ia64_regs[i]
            i+=1    

    def v2p(self, cpu, v):
        try:
            phys_block = cpu.iface.processor_info.logical_to_physical(v, Sim_Access_Read)
            if phys_block.address != 0:
                return phys_block.address
            else:
                if v < self.param.kernel_base:
                    phys_addr = v & ~self.param.kernel_base 
                    return phys_addr
                else:
                    return 0
                    
        except:
            return None

    def readByte(self, cpu, vaddr):
        phys = self.v2p(cpu, vaddr)
        if phys is not None:
            return SIM_read_phys_memory(cpu, self.v2p(cpu, vaddr), 1)
        else:
            return None
    '''
        Read a block of maxlen bytes, and return the null-terminated string
        found at the start of the block. (If there is no zero byte in the
        block, return a string that covers the entire block.)
    '''
    def readString(self, cpu, vaddr, maxlen):
        s = ''
        try:
            phys_block = cpu.iface.processor_info.logical_to_physical(vaddr, Sim_Access_Read)
        except:
            print('memUtils, readString, could not read 0x%x' % vaddr)
            return None
        if phys_block.address == 0:
            return None
        read_data = readPhysBytes(cpu, phys_block.address, maxlen)
        for v in read_data:
            if v == 0:
                del read_data
                return s
            s += chr(v)
    
        return None
    
    def readWord32(self, cpu, vaddr):
        return SIM_read_phys_memory(cpu, self.v2p(cpu, vaddr), 4)
    

    def readPtr(self, cpu, vaddr):
        phys = self.v2p(cpu, vaddr)
        if phys is not None:
            try:
                return SIM_read_phys_memory(cpu, self.v2p(cpu, vaddr), self.WORD_SIZE)
            except:
                return None
        else:
            return None

    def readWord(self, cpu, vaddr):
        phys = self.v2p(cpu, vaddr)
        if phys is not None:
            return SIM_read_phys_memory(cpu, self.v2p(cpu, vaddr), self.WORD_SIZE)
        else:
            return None

    def getRegValue(self, cpu, reg):
        reg_num = cpu.iface.int_register.get_number(self.regs[reg])
        reg_value = cpu.iface.int_register.read(reg_num)
        return reg_value

    def getESP(self):
        if self.WORD_SIZE == 32:
            return 'esp'
        else:
            return 'rsp'

    def getSigned(self, val):
        if self.WORD_SIZE == 32:
            if(val & 0x80000000):
                val = -0x100000000 + val
        else:
            if(val & 0x8000000000000000):
                val = -0x10000000000000000 + val
        return val

    def getUnsigned(self, val):
        if self.WORD_SIZE == 32:
            return val & 0xFFFFFFFF
        else:
            return val & 0xFFFFFFFFFFFFFFFF

    def getEIP(self):
        if self.WORD_SIZE == 32:
            return 'eip'
        else:
            return 'rip'

    def getCurrentTask(self, param, cpu):
        cpl = getCPL(cpu)
        if cpl == 0:
            tr_base = cpu.tr[7]
            esp = self.readPtr(cpu, tr_base + 4)
            #print('kernel mode, esp is 0x%x' % esp)
        else:
            esp = self.getRegValue(cpu, 'esp')
            #print('user mode, esp is 0x%x' % esp)
        ptr = esp - 1 & ~(param.stack_size - 1)
        #print('ptr is 0x%x' % ptr)
        ret_ptr = self.readPtr(cpu, ptr)
        #print('ret_ptr is 0x%x' % ret_ptr)

        return ret_ptr
