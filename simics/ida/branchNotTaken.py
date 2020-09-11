import idaapi
import idc
import idaversion
from idaapi import simplecustviewer_t
import gdbProt
import json
import os
import time
class BranchNotTaken(simplecustviewer_t):
    def __init__(self):
        self.isim = None

    class datawatch_handler(idaapi.action_handler_t):
        def __init__(self, callback):
            idaapi.action_handler_t.__init__(self)
            self.callback = callback
        def activate(self, ctx):
            self.callback()

        def update(self, ctx):
            return idaapi.AST_ENABLE_ALWAYS


    def Create(self, isim):
        self.isim = isim
        title = "BNT"
        if not simplecustviewer_t.Create(self, title):
            print("failed create of BNT viewer")
            return False
        else:
            print("created BNT")
        self.Show()
        return True

    def register(self):

        pass


    def updateList(self, branches):
        print "in updateList"
        #self.Close()
        #self.Create()
        #print('did create')
        retval = []
        self.ClearLines()
        for b in branches:
            cline = '0x%x' % b
            self.AddLine(cline)

        return None

    '''
    def OnDblClick(self, shift):
        line = self.GetCurrentLine()
        line = idaapi.tag_remove(line)
        print('line is %s' % line)
        parts = line.split()
        index = None
        try:
            index = int(parts[0])
        except:
            print('no index found in %s' % line)
            return
        command = '@cgc.goToDataMark(%d)' % index
        print('cmd is %s' % command)
        simicsString = gdbProt.Evalx('SendGDBMonitor("%s");' % command)
        eip = gdbProt.getEIPWhenStopped()
        self.isim.signalClient()
        return True
    '''

    def OnKeydown(self, vkey, shift):
        if vkey == 27:
            print('esc does nothing')
        else:
            return False
        return True

          
