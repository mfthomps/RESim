from simics import *
import os
class Jumpers():
    def __init__(self, top, context_manager, cpu, lgr):
        self.top = top
        self.lgr = lgr
        self.cpu = cpu
        self.context_manager = context_manager
        self.fromto = {}
        self.hap = {}
        self.breakpoints = {}
        self.reverse_enabled = True

    def noReverse(self):
        self.lgr.debug('jumper noReverse')
        self.reverse_enabled = False

    def setJumper(self, from_addr, to_addr):
        self.fromto[from_addr] = to_addr
        self.setOneBreak(from_addr)

    def setOneBreak(self, addr):
            phys_block = self.cpu.iface.processor_info.logical_to_physical(addr, Sim_Access_Execute)
            if phys_block.address == 0 or phys_block.address is None:
                self.lgr.error('jumper setOneBreak, memory not yet mapped.  No jumper set.')
                return
            self.breakpoints[addr] = SIM_breakpoint(self.cpu.physical_memory, Sim_Break_Physical, Sim_Access_Execute, phys_block.address, 1, 0)
            self.hap[addr] = SIM_hap_add_callback_index("Core_Breakpoint_Memop", self.doJump, addr, self.breakpoints[addr])

            #proc_break = self.context_manager.genBreakpoint(None, Sim_Break_Linear, Sim_Access_Execute, addr, 1, 0)
            #self.hap[addr] = self.context_manager.genHapIndex("Core_Breakpoint_Memop", self.doJump, None, proc_break, 'jumper')
            self.lgr.debug('jumper setBreaks set break on addr 0x%x' % addr)

    def setBreaks(self):
        for f in self.fromto:
            self.setOneBreak(f)
    
    def doJump(self, addr, third, forth, memory):
        #print('doJump')
        #self.lgr.debug('doJump')
        ''' callback when jumper breakpoint is hit'''
        #curr_addr = memory.logical_address 
        #self.lgr.debug('doJump addr is 0x%x' % addr)
        if addr not in self.hap:
            self.lgr.debug('jumper doJump addr 0x%x not in haps' % addr)
            return
        if self.reverse_enabled:
            self.top.writeRegValue('eip', self.fromto[addr], alone=True)
        else:
            if self.cpu.architecture != 'arm':
                reg_num = self.cpu.iface.int_register.get_number('eip')
            else:
                reg_num = self.cpu.iface.int_register.get_number('pc')
            self.cpu.iface.int_register.write(reg_num, self.fromto[addr])
        #self.lgr.debug('jumper doJump from 0x%x to 0x%x' % (addr, self.fromto[addr]))

    def clearBreaks(self):
        for f in self.fromto:
            #self.context_manager[self.target].genDeleteHap(hap[f])
            SIM_delete_breakpoint(self.breakpoints[f])
            SIM_hap_delete_callback_id('Core_Breakpoint_Memop', self.hap[f])

    def removeBreaks(self):
        self.clearBreak()
        self.hap = {}
        self.breakpoints = {}

    def loadJumpers(self, fname):
        from_addr = None
        to_addr = None
        if not os.path.isfile(fname):
            self.lgr.error('No jumper file found at %s' % fname)
        else:
            with open(fname) as fh:
                for line in fh:
                    if line.strip().startswith('#'):
                        continue
                    try:
                        from_addr, to_addr = line.strip().split()
                        from_addr = int(from_addr, 16)
                        to_addr = int(to_addr, 16)
                    except:
                        raise Exception("Error reading %s from %s, bad jumper" % (line, fname))
                        return
                    self.setJumper(from_addr, to_addr) 
