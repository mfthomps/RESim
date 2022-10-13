from idaapi import *
import colorBlocks
class DBGHooks(DBG_Hooks):
    def __init__(self):
        self.idasim = None
        DBG_Hooks.__init__(self)

    def setRESim(self, idasim):
        self.idasim = idasim

    def dbg_run_to(self, pid, tid, ea):
        #print('dbg_run_to')
        self.idasim.signalClient()
    def dbg_step_into(self):
        #print('dbg_step_into')
        self.idasim.signalClient()
    
    def dbg_process_attach(self, one,two,three,four,five,six):
        print('dbg_process_attach') 

    def dbg_process_start(self, one,two,three,four,five,six):
        print('dbg_process_started')
        #colorBlocks.colorBlocks()
