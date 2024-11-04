from simics import *
import memUtils
import json
import sys
class VxKMemUtils():
    def __init__(self, lgr):
        self.lgr = lgr
        self.WORD_SIZE = 4
        self.arm_regs = []
        for i in range(13):
            r = 'r%d' % i
            self.arm_regs.append(r)
        self.arm_regs.append('sp')
        self.arm_regs.append('pc')
        self.arm_regs.append('lr')
        self.SIZE_MASK = 0xffffffff

    def readPtr(self, cpu, addr):
        return self.readWord32(cpu, addr)

    def readWord(self, cpu, addr):
        return self.readWord32(cpu, addr)

    def readWord32(self, cpu, addr):
        retval = None
        try:
            retval = SIM_read_phys_memory(cpu, addr, 4)
        except:
            self.lgr.debug('vxMemUtils readWord32 could not read content of 0x%x' % (addr))
            SIM_break_simulation('remove this')
        return retval

    def readWord16(self, cpu, addr):
        retval = None
        try:
            retval = SIM_read_phys_memory(cpu, addr, 2)
        except:
            self.lgr.debug('vxMemUtils readWord16 could not read content of 0x%x' % (addr))
            SIM_break_simulation('remove this')
        return retval

    def readWord16le(self, cpu, addr):
        hi = None
        lo = None
        try:
            hi = SIM_read_phys_memory(cpu, addr, 1)
        except:
            self.lgr.debug('vxMemUtils readWord16le could not read content of 0x%x' % (addr))
        addrplus = addr+1
        try:
            lo = SIM_read_phys_memory(cpu, addrplus, 1)
        except:
            self.lgr.debug('vxMemUtils readWord16le could not read content of 0x%x' % (addrplus))
        if hi is not None and lo is not None:
            retval = hi << 8 | lo
        return retval


    def getRegValue(self, cpu, reg):
        if reg in ['eip']:
            reg_num = cpu.iface.int_register.get_number('pc')
        elif reg == 'syscall_ret':
            reg_num = cpu.iface.int_register.get_number('r0')
        else:
            reg_num = cpu.iface.int_register.get_number(reg)
        reg_value = cpu.iface.int_register.read(reg_num)
        return reg_value

    def setRegValue(self, cpu, reg, value):
        reg_num = cpu.iface.int_register.get_number(reg)
        cpu.iface.int_register.write(reg_num, value)

    def wordSize(self, cpu):
        return 4

    def isKernel(self, addr):
        return False

    def readString(self, cpu, paddr, maxlen):
        s = ''
        try:
            read_data = memUtils.readPhysBytes(cpu, paddr, maxlen)
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

    def printRegJson(self, cpu, word_size=None):
        if word_size is None:
            word_size = self.WORD_SIZE
        if cpu.architecture == 'arm':
            #self.lgr.debug('printRegJson is arm regs is %s' % (str(self.regs)))
            regs = self.arm_regs
        elif cpu.architecture == 'arm64':
            regs = self.arm64_regs
        elif word_size == 8:
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

    def getBytes(self, cpu, num_bytes, addr):
        read_data = memUtils.readPhysBytes(cpu, addr, num_bytes)
        return read_data

    def readBytes(self, cpu, addr, count):
        return self.getBytes(cpu, count, addr)

    def readByte(self, cpu, addr):
        return SIM_read_phys_memory(cpu, addr, 1)

    def readMemory(self, cpu, addr, size):
        return SIM_read_phys_memory(cpu, addr, size)

    def readAppPtr(self, cpu, addr, size=4):
        return SIM_read_phys_memory(cpu, addr, size)

    def getCallRetReg(self, cpu):
        return 'r0'

    def getSigned(self, val):
        if(val & 0x80000000):
            val = -0x100000000 + val
        return val

    def writeWord(self, cpu, address, value):
        SIM_write_phys_memory(cpu, address, value, self.WORD_SIZE)

    def writeByte(self, cpu, address, value):
        SIM_write_phys_memory(cpu, address, value, 1)

    def writeWord32(self, cpu, address, value):
        if value is None:
            self.lgr.error('vxKMemUtils writeWord32 value given is None')
            return
        SIM_write_phys_memory(cpu, address, value, 4)

    def writeBytes(self, cpu, address, byte_tuple):
        if len(byte_tuple) == 0:
            self.lgr.error('vxKMemUtils writeBytes got empty byte_tuple')
            return
        cur_addr = address
        for b in byte_tuple:
            SIM_write_phys_memory(cpu, cur_addr, b, 1)
            cur_addr = cur_addr + 1

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
            if len(sub) < 4:
                self.lgr.error('writeString failed writing sub %s, len less than 4?' % (str(sub)))
                continue
            try:
                value = struct.unpack("<L", sub)[0]
            except:
                self.lgr.error('writeString failed unpacking sub %s,???' % (str(sub)))
                sindex +=4
                address += 4
                continue
            sindex +=4
            try:
                SIM_write_phys_memory(cpu, address, value, count)
                #self.lgr.debug('writeString wrote %d bytes' % count)
            except TypeError:
                self.lgr.error('writeString failed writing to address 0x%x, value %s' % (address, value))
                return
            address += 4

    def v2p(self, cpu, v, use_pid=None):
        return v
