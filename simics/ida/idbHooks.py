from idaapi import *
class IDBHooks(IDB_Hooks):
    def __init__(self):
        self.idasim = None
        IDB_Hooks.__init__(self)
    def setRESim(self, idasim):
        self.idasim = idasim
    def auto_empty(self, dumb):
        print('in auto_empty*****************************************************************************')
    def auto_empty_finally(self, dumb):
        print('in auto_empty finally*****************************************************************************')

