import idaapi
import idc
from idaapi import simplecustviewer_t
import gdbProt
import json
import reHooks
class StackTrace(simplecustviewer_t):
    def __init__(self):
        self.isim = None

    class stacktrace_handler(idaapi.action_handler_t):
        def __init__(self, callback):
            idaapi.action_handler_t.__init__(self)
            self.callback = callback
        def activate(self, ctx):
            #print("set stacktrace ")
            self.callback()

        def update(self, ctx):
            return idaapi.AST_ENABLE_ALWAYS

    def revTo(self):
        highlighted = idaapi.get_highlighted_identifier()
        addr = reHooks.getHex(highlighted)
        command = '@cgc.revToAddr(0x%x, extra_back=0)' % (addr)
        #print('cmd: %s' % command)
        simicsString = gdbProt.Evalx('SendGDBMonitor("%s");' % command)
        eip = gdbProt.getEIPWhenStopped()
        self.isim.signalClient()

    def Create(self, isim):
        self.isim = isim
        title = "stack trace"
        if not simplecustviewer_t.Create(self, title):
            print("failed create of stacktrace viewer")
            return False
        else:
            print("created stacktrace")
        self.Show()
        return True

    def register(self):

        form = idaapi.get_current_tform()
        the_name = "reverse to"
        idaapi.register_action(idaapi.action_desc_t(the_name, "reverse to", self.stacktrace_handler(self.revTo)))
        idaapi.attach_action_to_popup(form, None, the_name)
        the_name = "refresh_stack"
        idaapi.register_action(idaapi.action_desc_t(the_name, "refresh stack", self.stacktrace_handler(self.updateStackTrace)))
        idaapi.attach_action_to_popup(form, None, the_name)
        #self.Show()

    def updateStackTrace(self):
        #print "in updateStackTrace"
        #self.Close()
        #self.Create()
        #print('did create')
        retval = []
        self.ClearLines()
        #self.Refresh()
        #print('did refresh of clear')
        command = '@cgc.getStackTrace()'
        simicsString = gdbProt.Evalx('SendGDBMonitor("%s");' % command)
        if type(simicsString) is int:
            print('updateStackTrace got an int?  %d' % simicsString)
            return
        try:
            st_json = json.loads(simicsString)
        except:
            print('could not get json from %s' % simicsString)
            return
        for entry in st_json:
            instruct = idc.GetDisasm(entry['ip'])
            #print('instruct is %s' % str(instruct))
            #line = '0x%x %-20s %s' % (entry['ip'], entry['fname'], entry['instruct'])
            fun = idc.GetFunctionName(entry['ip'])
            line = '0x%08x %-15s %-10s %s' % (entry['ip'], str(entry['fname']), fun, str(instruct))
            #print("added %s" % line)
            retval.append(str(line))
            self.AddLine(str(line))
        self.Refresh()
        #self.Show()
        return retval

    def OnDblClick(self, shift):
        line = self.GetCurrentLine()
        #print('line is %s' % line)
        parts = line.split()
        try:
            addr = int(parts[0], 16)
        except:
            print('no address found in %s' % line)
            return
        idc.Jump(addr) 
