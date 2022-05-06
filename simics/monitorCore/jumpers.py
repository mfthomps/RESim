from simics import *
class Jumpers():
    def __init__(self, top, context_manager, lgr):
        self.top = top
        self.lgr = lgr
        self.context_manager = context_manager
        self.fromto = {}
        self.hap = {}

    def setJumper(self, from_addr, to_addr):
        self.fromto[from_addr] = to_addr
        self.setBreaks()

    def setBreaks(self):
        for f in self.fromto:
            proc_break = self.context_manager.genBreakpoint(None, Sim_Break_Linear, Sim_Access_Execute, f, 1, 0)
            self.hap[f] = self.context_manager.genHapIndex("Core_Breakpoint_Memop", self.doJump, None, proc_break, 'jumper')
            self.lgr.debug('jumper setBreaks set break on addr 0x%x' % f)

    
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
