import idaapi
import idc
import idaversion
import ida_kernwin
from idaapi import simplecustviewer_t
import gdbProt
import getEdges
import json
import os
import time
class BranchNotTaken(simplecustviewer_t):
    def __init__(self):
        self.isim = None

    class bnt_handler(idaapi.action_handler_t):
        def __init__(self, callback):
            idaapi.action_handler_t.__init__(self)
            self.callback = callback
        def activate(self, ctx):
            self.callback()

        def update(self, ctx):
            return idaapi.AST_ENABLE_ALWAYS

    def getOffset(self):
        retva = None
        fname = idaapi.get_root_filename()
        command = "@cgc.getSOFromFile('%s')" % fname
        simicsString = gdbProt.Evalx('SendGDBMonitor("%s");' % command)
        print('so stuff: %s' % simicsString) 
        if ':' in simicsString:
            adders = simicsString.split(':')[1]
            start = adders.split('-')[0]
            try:
                retval = int(start,16)
            except ValueError:
                print('could not get hex from %s' % start)
        return retval 

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

        form = idaversion.get_current_widget()
        the_name = "refresh_bnt"
        idaapi.register_action(idaapi.action_desc_t(the_name, "refresh BNT list", self.bnt_handler(self.updateList)))
        idaapi.attach_action_to_popup(form, None, the_name)


    def updateList(self):
        branches = getEdges.getEdges()
        print "in updateList"
        offset = self.getOffset()
        if branches is None:
            print('Branch Not Taken list is None')
            return
        retval = []
        self.ClearLines()
        for b in branches:
            f = idc.get_func_name(b)
            to_val = b + offset
            from_val = branches[b]+offset
            cline = 'to 0x%x from 0x%x %s' % (to_val, from_val, f)
            self.AddLine(cline)

        return None

    def OnDblClick(self, shift):
        line = self.GetCurrentLine()
        line = idaapi.tag_remove(line)
        #print('line is %s' % line)
        parts = line.split()
        branch_from  = None
        try:
            branch_from  = int(parts[3], 16)
        except:
            print('branch from not found in %s' % line)
            return
        command = '@cgc.goToBasicBlock(0x%x)' % branch_from
        #print('cmd is %s' % command)
        simicsString = gdbProt.Evalx('SendGDBMonitor("%s");' % command)
        if 'not in blocks' in simicsString:
            ida_kernwin.jumpto(branch_from)
        else:
            eip = gdbProt.getEIPWhenStopped()
            if eip is not None:
                self.isim.signalClient()
        return True

    def OnKeydown(self, vkey, shift):
        if vkey == 27:
            print('esc does nothing')
        else:
            return False
        return True

          
