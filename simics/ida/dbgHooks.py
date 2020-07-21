from idaapi import *
class DBGHooks(DBG_Hooks):
    def __init__(self, idasim):
        self.idasim = idasim
        DBG_Hooks.__init__(self)

    def dbg_run_to(self, pid, tid, ea):
        print('dbg_run_to')
        self.idasim.signalClient()
    def dbg_step_into(self):
        print('dbg_step_into')
        self.idasim.signalClient()
    
