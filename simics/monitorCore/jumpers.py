from simics import *
import os
class Jumpers():
    def __init__(self, top, context_manager, cpu, lgr):
        self.top = top
        self.lgr = lgr
        self.cpu = cpu
        self.context_manager = context_manager
        self.fromto = {}
        self.comm_name = {}
        self.temp = []
        self.hap = {}
        self.breakpoints = {}
        self.reverse_enabled = None
        self.physical = True
        self.break_simulation = []

    def setJumper(self, from_addr, to_addr, comm=None):
        self.fromto[from_addr] = to_addr
        if comm is not None:
            self.comm_name[from_addr] = comm
        self.setOneBreak(from_addr)

    def setOneBreak(self, addr):
            if self.physical:
                phys_block = self.cpu.iface.processor_info.logical_to_physical(addr, Sim_Access_Execute)
                if phys_block.address == 0 or phys_block.address is None:
                    self.lgr.error('jumper setOneBreak, memory not yet mapped.  No jumper set.')
                    return
                self.breakpoints[addr] = SIM_breakpoint(self.cpu.physical_memory, Sim_Break_Physical, Sim_Access_Execute, phys_block.address, 1, 0)
                self.hap[addr] = SIM_hap_add_callback_index("Core_Breakpoint_Memop", self.doJump, addr, self.breakpoints[addr])
            else:
                proc_break = self.context_manager.genBreakpoint(None, Sim_Break_Linear, Sim_Access_Execute, addr, 1, 0)
                self.hap[addr] = self.context_manager.genHapIndex("Core_Breakpoint_Memop", self.doJump, addr, proc_break, 'jumper')
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
        if addr in self.comm_name:
            cpu, comm, pid = self.top.getCurrentProc()
            if comm != self.comm_name[addr]:
                self.lgr.debug('doJump comm %s does not match jumper comm of %s' % (comm, self.comm_name[addr]))
                return
        if self.reverse_enabled is None:
            self.reverse_enabled = self.top.reverseEnabled()
            self.lgr.debug('jumpers doJump setting reverse_enabled to %r' % self.reverse_enabled)
        if self.reverse_enabled:
            self.top.writeRegValue('eip', self.fromto[addr], alone=True)
        else:
            if self.cpu.architecture != 'arm':
                reg_num = self.cpu.iface.int_register.get_number('eip')
            else:
                reg_num = self.cpu.iface.int_register.get_number('pc')
            self.cpu.iface.int_register.write(reg_num, self.fromto[addr])
        #if addr in self.comm_name:
        #    self.lgr.debug('jumper doJump from 0x%x to 0x%x in comm %s' % (addr, self.fromto[addr], self.comm_name[addr]))
        #else:
        #    self.lgr.debug('jumper doJump from 0x%x to 0x%x' % (addr, self.fromto[addr]))
        if addr in self.break_simulation:
            SIM_break_simulation('Jumper request')

    def removeOneBreak(self, addr):
        if addr not in self.hap:
            self.lgr.debug('jumpers removeOneBreak but addr 0x%x not in dict.' % addr)
            return
        if not self.physical:
            self.context_manager[self.target].genDeleteHap(self.hap[addr])
        else:
            SIM_delete_breakpoint(self.breakpoints[addr])
            SIM_hap_delete_callback_id('Core_Breakpoint_Memop', self.hap[addr])

    def removeBreaks(self):
        for f in self.fromto:
            self.removeOneBreak(addr)
        self.hap = {}
        self.breakpoints = {}

    def loadJumpers(self, fname, physical=True):
        self.physical = physical
        from_addr = None
        to_addr = None
        self.lgr.debug('jumpers loadJumper, physical: %r' % (physical))
        if not os.path.isfile(fname):
            self.lgr.error('No jumper file found at %s' % fname)
        else:
            with open(fname) as fh:
                for line in fh:
                    if line.strip().startswith('#'):
                        continue
                    parts = line.strip().split()
                    if len(parts) < 2:
                        self.lgr.error("jumpers Error reading %s from %s, bad jumper" % (line, fname))
                        raise Exception("jumpers Error reading %s from %s, bad jumper" % (line, fname))
                        return
                    try:
                        from_addr = int(parts[0], 16)
                        to_addr = int(parts[1], 16)
                    except:
                        self.lgr.error("jumpers Error reading %s from %s, bad jumper" % (line, fname))
                        raise Exception("jumpers Error reading %s from %s, bad jumper" % (line, fname))
                        return
                    comm = None
                    if len(parts) > 2:
                        comm = parts[2]
                    if len(parts) > 3 and parts[3] == 'break':
                        self.break_simulation.append(from_addr)
                    self.setJumper(from_addr, to_addr, comm) 

