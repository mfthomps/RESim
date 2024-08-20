from simics import *
class VxKMemUtils():
    def __init__(self, lgr):
        self.lgr = lgr
        self.WORD_SIZE = 4
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
