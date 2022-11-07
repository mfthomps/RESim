from idaapi import *
import colorBlocks
import reHooks
import rev
class DBGHooks(DBG_Hooks):
    def __init__(self):
        self.idasim = None
        self.idb_hooks = None
        self.re_hooks = None
        DBG_Hooks.__init__(self)
         
    def setIdbHooks(self, idb_hooks):
        self.idb_hooks = idb_hooks

    def setReHooks(self, re_hooks):
        self.re_hooks = re_hooks

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
        #re_hooks = reHooks.Hooks()
        #re_hooks.hook()
        rev.RESimClient(self.re_hooks, self, self.idb_hooks)
