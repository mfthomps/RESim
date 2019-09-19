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
import struct
from simics import *
MACHINE_WORD_SIZE = 8
class ValueError(Exception):
    pass
def readPhysBytes(cpu, paddr, count):
    try:
        return cpu.iface.processor_info_v2.get_physical_memory().iface.memory_space.read(cpu, paddr, count, 0)
    except:
        raise ValueError('failed to read %d bytes from 0x%x' % (count, paddr))

def getCPL(cpu):
    #print('arch %s' % cpu.architecture)
    if cpu.architecture == 'arm':
        ''' TBD FIX this! '''
        reg_num = cpu.iface.int_register.get_number("pc")
        pc = cpu.iface.int_register.read(reg_num)
        print('pc is 0x%x' % pc)
        if pc > 0xc0000000:
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

def bitRange(value, start, end):
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

class memUtils():
    def __init__(self, word_size, param, lgr, arch='x86-64', cell_name='unknown'):
        self.WORD_SIZE = word_size
        self.param = param
        self.cell_name = cell_name
        self.lgr = lgr
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
                    self.regs[ia32_reg] = self.ia64_regs[i]
                i+=1    
            self.regs['syscall_num'] = self.regs['eax']
            self.regs['syscall_ret'] = self.regs['eax']
            self.regs['pc'] = self.regs['eip']
        elif arch == 'arm':
            for i in range(13):
                r = 'R%d' % i
                self.regs[r] = r
            self.regs['sp'] = 'sp'
            self.regs['pc'] = 'pc'
            self.regs['cpsr'] = 'cpsr'
            self.regs['syscall_num'] = 'r7'
            self.regs['syscall_ret'] = 'r0'
            self.regs['eip'] = 'pc'
            self.regs['esp'] = 'sp'
        else: 
            self.lgr.error('memUtils, unknown architecture %s' % arch)
            
    def v2p(self, cpu, v):
        try:
            phys_block = cpu.iface.processor_info.logical_to_physical(v, Sim_Access_Read)
        except:
            return None

        if phys_block.address != 0:
            #self.lgr.debug('get unsigned of of phys 0x%x' % phys_block.address)
            return self.getUnsigned(phys_block.address)

        else:
            ptable_info = pageUtils.findPageTable(cpu, v, self.lgr)
            if v < self.param.kernel_base and not ptable_info.page_exists:
                self.lgr.debug('phys addr for 0x%x not mapped per page tables' % (v))
                return None
            #self.lgr.debug('phys addr for 0x%x return 0' % (v))
            if cpu.architecture == 'arm':
                phys_addr = v - (self.param.kernel_base - self.param.ram_base)
                return self.getUnsigned(phys_addr)
            else:
                mode = cpu.iface.x86_reg_access.get_exec_mode()
                if v < self.param.kernel_base and mode == 8:
                #if v < self.param.kernel_base:
                    phys_addr = v & ~self.param.kernel_base 
                    #self.lgr.debug('get unsigned of 0x%x mode %d' % (v, mode))
                    return self.getUnsigned(phys_addr)
                else:
                    phys_addr = v & ~self.param.kernel_base 
                    #self.lgr.debug('memUtils v2p  32-bit Mode?  mode %d  kernel addr base 0x%x  v 0x%x  phys 0x%x' % (mode, self.param.kernel_base, v, phys_addr))
                    return phys_addr
                    

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
    def readStringNOT(self, cpu, vaddr, maxlen):
        s = ''
        try:
            phys_block = cpu.iface.processor_info.logical_to_physical(vaddr, Sim_Access_Read)
        except:
            print('memUtils, readString, could not read 0x%x' % vaddr)
            return None
        if phys_block.address == 0:
            return None
        return self.readStringPhys(cpu, phys_block.address, maxlen)

    def readString(self, cpu, vaddr, maxlen):
        retval = None
        ps = self.v2p(cpu, vaddr)
        if ps is not None:
            #self.lgr.debug('readString vaddr 0x%x ps is 0x%x' % (vaddr, ps))
            remain_in_page = pageUtils.pageLen(ps, pageUtils.PAGE_SIZE)
            if remain_in_page < maxlen:
                #self.lgr.debug('remain_in_page %d' % remain_in_page)
                first_read = self.readStringPhys(cpu, ps, remain_in_page)
                if first_read is not None and len(first_read) == remain_in_page:
                    ''' get the rest ''' 
                    ps = self.v2p(cpu, vaddr+remain_in_page)
                    #self.lgr.debug('first read %s new ps 0x%x' % (first_read, ps))
                    second_read = self.readStringPhys(cpu, ps, maxlen - remain_in_page)
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
        read_data = readPhysBytes(cpu, paddr, maxlen)
        for v in read_data:
            if v == 0:
                del read_data
                return s
            s += chr(v)
        if len(s) > 0:
            return s
        else: 
            return None
    
    def readWord32(self, cpu, vaddr):
        paddr = self.v2p(cpu, vaddr) 
        if paddr is None:
            #self.lgr.error('readWord32 phys of 0x%x is none' % vaddr)
            return None
        try:
            value = SIM_read_phys_memory(cpu, paddr, 4)
        except:
            self.lgr.error('readWord32 could not read content of %s' % str(paddr))
            value = None
        return value

    def readWord16(self, cpu, vaddr):
        return SIM_read_phys_memory(cpu, self.v2p(cpu, vaddr), 2)
    
    def readWord16le(self, cpu, vaddr):
        hi = SIM_read_phys_memory(cpu, self.v2p(cpu, vaddr), 1)
        lo = SIM_read_phys_memory(cpu, self.v2p(cpu, vaddr+1), 1)
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
                self.lgr.debug('except for %s' % reg)
                ''' Hack, regs contaminated with aliases, e.g., syscall_num '''
                continue
            reg_values[reg] = reg_value
        
        s = json.dumps(reg_values)
        print s
    
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
                return self.getUnsigned(SIM_read_phys_memory(cpu, self.v2p(cpu, vaddr), size))
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
        if reg in self.regs:
            reg_num = cpu.iface.int_register.get_number(self.regs[reg])
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

    def getCurrentTask(self, param, cpu):
      
        if self.WORD_SIZE == 4:
            if cpu.architecture == 'arm':
                return self.getCurrentTaskARM(param, cpu)
            else:
                return self.getCurrentTaskX86(param, cpu)
        elif self.WORD_SIZE == 8:
            gs_b700 = self.getGSCurrent_task_offset(cpu)
            #phys_addr = self.v2p(cpu, gs_b700)
            #self.current_task[cpu] = phys_addr
            #self.current_task_virt[cpu] = gs_b700
            ct_addr = self.v2p(cpu, gs_b700)
            if ct_addr is None:
                self.lgr.debug('getCurrentTask finds no phys for 0x%x' % gs_b700)
                return None
            self.lgr.debug('memUtils getCurrentTask cell %s gs_b700 is 0x%x phys is 0x%x' % (self.cell_name, gs_b700, ct_addr))
            try:
                ct = SIM_read_phys_memory(cpu, ct_addr, self.WORD_SIZE)
            except:
                self.lgr.debug('getCurrentTaskARM ct_addr 0x%x not mapped?' % ct_addr)
                return None
            self.lgr.debug('getCurrentTask ct_addr 0x%x ct 0x%x' % (ct_addr, ct))
            return ct
        else:
            print('unknown word size %d' % self.WORD_SIZE)
            return None

    def kernel_v2p(self, param, cpu, vaddr):
        return vaddr - param.kernel_base + param.ram_base

    def getCurrentTaskARM(self, param, cpu):
        reg_num = cpu.iface.int_register.get_number("sp")
        sup_sp = cpu.gprs[1][reg_num]
        self.lgr.debug('getCurrentTaskARM sup_sp 0x%x' % sup_sp)
        if sup_sp == 0:
            return None
        ts = sup_sp & ~(param.thread_size - 1)
        #self.lgr.debug('getCurrentTaskARM ts 0x%x' % ts)
        if ts == 0:
            return None
        if ts < param.kernel_base:
            ts += param.kernel_base
        ct_addr = self.kernel_v2p(param, cpu, ts) + 12
        try:
            ct = SIM_read_phys_memory(cpu, ct_addr, self.WORD_SIZE)
        except:
            self.lgr.debug('getCurrentTaskARM ct_addr 0x%x not mapped?' % ct_addr)
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
            #self.lgr.debug('getCurrentTaskX86 kernel mode, esp is 0x%x' % esp)
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

    def getBytes(self, cpu, num_bytes, addr):
        '''
        Get a hex string of num_bytes from the given address using Simics physical memory reads, which return tuples.
        '''
        done = False
        curr_addr = addr
        bytes_to_go = num_bytes
        retval = ''
        retbytes = ()
        #print 'in getBytes for 0x%x bytes' % (num_bytes)
        while not done and bytes_to_go > 0:
            bytes_to_read = bytes_to_go
            remain_in_page = pageUtils.pageLen(curr_addr, pageUtils.PAGE_SIZE)
            #print 'remain is 0x%x  bytes to go is 0x%x  cur_addr is 0x%x end of page would be 0x%x' % (remain_in_page, bytes_to_read, curr_addr, end)
            if remain_in_page < bytes_to_read:
                bytes_to_read = remain_in_page
            if bytes_to_read > 1024:
                bytes_to_read = 1024
            #phys_block = cpu.iface.processor_info.logical_to_physical(curr_addr, Sim_Access_Read)
            phys = self.v2p(cpu, curr_addr)
            if phys is None:
                self.lgr.error('memUtils v2p for 0x%x returned None' % curr_addr)
                #SIM_break_simulation('bad phys memory mapping at 0x%x' % curr_addr) 
                return None, None
            #print 'read (bytes_to_read) 0x%x bytes from 0x%x phys:%x ' % (bytes_to_read, curr_addr, phys_block.address)
            try:
                #read_data = readPhysBytes(cpu, phys_block.address, bytes_to_read)
                read_data = readPhysBytes(cpu, phys, bytes_to_read)
            except ValueError:
            #except:
                #print 'trouble reading phys bytes, address %x, num bytes %d end would be %x' % (phys_block.address, bytes_to_read, phys_block.address + bytes_to_read - 1)
                print 'trouble reading phys bytes, address %x, num bytes %d end would be %x' % (phys, bytes_to_read, phys + bytes_to_read - 1)
                print 'bytes_to_go %x  bytes_to_read %d' % (bytes_to_go, bytes_to_read)
                self.lgr.error('bytes_to_go %x  bytes_to_read %d' % (bytes_to_go, bytes_to_read))
                return retval, retbytes
            holder = ''
            count = 0
            for v in read_data:
                count += 1
                holder = '%s%02x' % (holder, v)
                #self.lgr.debug('add v of %2x holder now %s' % (v, holder))
            retbytes = retbytes+read_data
            del read_data
            retval = '%s%s' % (retval, holder)
            bytes_to_go = bytes_to_go - bytes_to_read
            #self.lgr.debug('0x%x bytes of data read from %x bytes_to_go is %d' % (count, curr_addr, bytes_to_go))
            curr_addr = curr_addr + bytes_to_read
        return retval, retbytes

    def writeWord(self, cpu, address, value):
        #phys_block = cpu.iface.processor_info.logical_to_physical(address, Sim_Access_Read)
        phys = self.v2p(cpu, address)
        #SIM_write_phys_memory(cpu, phys_block.address, value, self.WORD_SIZE)
        SIM_write_phys_memory(cpu, phys, value, self.WORD_SIZE)

    def getGSCurrent_task_offset(self, cpu):
        gs_base = cpu.ia32_gs_base
        retval = gs_base + self.param.cur_task_offset_into_gs
        self.lgr.debug('getGSCurrent_task_offset cell %s gs base is 0x%x, plus current_task offset is 0x%x' % (self.cell_name, gs_base, retval))
        return retval

    def writeString(self, cpu, address, string):
        #self.lgr.debug('writeString 0x%x %s' % (address, string))

        lcount = len(string)/4
        carry = len(string) % 4
        if carry != 0:
            lcount += 1
        print lcount
        sindex = 0
        for i in range(lcount):
            eindex = min(sindex+4, len(string))
            sub = string[sindex:eindex] 
            count = len(sub)
            #sub = sub.zfill(4)
            sub = sub.ljust(4, '0')
            #print('sub is %s' % sub)
            #value = int(sub.encode('hex'), 16)
            value = struct.unpack("<L", sub)[0]
            sindex +=4
            #phys_block = cpu.iface.processor_info.logical_to_physical(address, Sim_Access_Read)
            phys = self.v2p(cpu, address)
            #SIM_write_phys_memory(cpu, phys_block.address, value, count)
            SIM_write_phys_memory(cpu, phys, value, count)
            address += 4

