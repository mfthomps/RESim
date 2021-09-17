import idaapi
import idc
from idaapi import simplecustviewer_t
import gdbProt
import json
import os
import reHooks
import idaversion
class WriteWatch(simplecustviewer_t):
    def __init__(self):
        self.isim = None

    class writewatch_handler(idaapi.action_handler_t):
        def __init__(self, callback):
            idaapi.action_handler_t.__init__(self)
            self.callback = callback
        def activate(self, ctx):
            self.callback()

        def update(self, ctx):
            return idaapi.AST_ENABLE_ALWAYS


    def Create(self, isim, title):
        self.isim = isim
        if not simplecustviewer_t.Create(self, title):
            print("failed create of writeWatch viewer")
            return False
        else:
            print("created writeWatch")
        self.Show()
        return True

    def register(self):

        form = idaversion.get_current_widget()
        the_name = "refresh_write_data"
        idaapi.register_action(idaapi.action_desc_t(the_name, "refresh data", self.writewatch_handler(self.updateWriteWatch)))
        idaapi.attach_action_to_popup(form, None, the_name)
        print('write watch did register')


    def updateWriteWatch(self):
        print "in updateWriteWatch"
        #self.Close()
        #self.Create()
        #print('did create')
        retval = []
        self.ClearLines()
        #self.Refresh()
        #print('did refresh of clear')
        command = '@cgc.getWriteMarks()'
        simicsString = gdbProt.Evalx('SendGDBMonitor("%s");' % command)
        if type(simicsString) is int:
            print('updateStackTrace got an int?  %d' % simicsString)
            return
        try:
            data_json = json.loads(simicsString)
        except:
            print('could not get json from %s' % simicsString)
            return
        index = 0
        for entry in data_json:
            instruct = idc.GetDisasm(entry['ip'])
            uline = '%3d 0x%08x %s' % (index, entry['ip'], entry['msg'])
            line = uline.encode('ascii', 'replace')
            cline = str(line)
            #print("added %s" % line)
            retval.append(str(line))
            self.AddLine(cline)
            index += 1
        self.Refresh()
        #self.Show()
        return retval

    def OnDblClick(self, shift):
        line = self.GetCurrentLine()
        line = idaapi.tag_remove(line)
        #print('line is %s' % line)
        parts = line.split()
        index = None
        try:
            index = int(parts[0])
        except:
            print('no index found in %s' % line)
            return
        command = '@cgc.goToWriteMark(%d)' % index
        #print('cmd is %s' % command)
        simicsString = gdbProt.Evalx('SendGDBMonitor("%s");' % command)
        eip = gdbProt.getEIPWhenStopped()
        self.isim.signalClient()
        return True

    def OnKeydown(self, vkey, shift):
        if vkey == 27:
            print('esc does nothing')
        else:
            return False
        return True

          
