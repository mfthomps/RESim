from simics import *
class LoopN():
    def __init__(self, top, iterations, mem_utils, context_manager, lgr):
        self.top = top
        self.iterations = iterations
        self.count = 0
        self.mem_utils = mem_utils
        self.context_manager = context_manager
        self.lgr = lgr
        self.eip = self.top.getEIP()
        self.loop_hap = None
        self.go()

    def doBreaks(self):
        if self.loop_hap is None:
            proc_break = self.context_manager.genBreakpoint(None, Sim_Break_Linear, Sim_Access_Execute, self.eip, 1, 0)
            self.loop_hap = self.context_manager.genHapIndex("Core_Breakpoint_Memop", self.loopHap, None, proc_break, 'loopN')
            self.lgr.debug('loopN doBreaks set break on 0x%x' % self.eip)
        else:
            self.lgr.debug('loopN doBreaks, break already set')

    def rmBreaks(self):
        if self.loop_hap is not None:
            hap = self.loop_hap
            self.context_manager.genDeleteHap(hap)
            self.loop_hap = None

    def go(self):
        self.lgr.debug('loopN loopHap go')
        self.count = 0
        self.doBreaks()
        SIM_continue(0)
    
    def loopHap(self, dumb, the_object, the_break, memory):
        if self.loop_hap is None:
            return
        self.count = self.count + 1
        self.lgr.debug('loopN loopHap count now %d' % self.count)
        if self.count >= self.iterations:
            self.lgr.debug('loopN loopHap hit limit')
            self.rmBreaks()
            self.top.stopAndGo(self.top.skipAndMail)

