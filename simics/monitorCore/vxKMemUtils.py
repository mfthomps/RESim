from simics import *
import memUtils
import json
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
