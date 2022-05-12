from simics import *
import os
class Jumpers():
    def __init__(self, top, context_manager, lgr):
        self.top = top
        self.lgr = lgr
        self.context_manager = context_manager
        self.fromto = {}
        self.hap = {}

    def setJumper(self, from_addr, to_addr):
        self.fromto[from_addr] = to_addr
        self.setOneBreak(from_addr)

    def setOneBreak(self, addr):
            proc_break = self.context_manager.genBreakpoint(None, Sim_Break_Linear, Sim_Access_Execute, addr, 1, 0)
            self.hap[addr] = self.context_manager.genHapIndex("Core_Breakpoint_Memop", self.doJump, None, proc_break, 'jumper')
            self.lgr.debug('jumper setBreaks set break on addr 0x%x' % addr)

    def setBreaks(self):
        for f in self.fromto:
            self.setOneBreak(f)
    
    def doJump(self, dumb, third, forth, memory):
        print('doJump')
        self.lgr.debug('doJump')
        ''' callback when jumper breakpoint is hit'''
        curr_addr = memory.logical_address 
        self.lgr.debug('doJump curr_addr is 0x%x' % curr_addr)
        if curr_addr not in self.hap:
            self.lgr.debug('jumper doJump addr 0x%x not in haps' % curr_addr)
            return
        self.top.writeRegValue('eip', self.fromto[curr_addr], alone=True)
        self.lgr.debug('jumper doJump from 0x%x to 0x%x' % (curr_addr, self.fromto[curr_addr]))

    def clearBreaks(self):
        for f in self.fromto:
            self.context_manager[self.target].genDeleteHap(hap[f])

    def removeBreaks(self):
        self.clearBreak()
        self.hap = {}

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
