import idaapi
import idc
import idaversion
from idaapi import simplecustviewer_t
import gdbProt
import json
import os
import time
import resimUtils
class DataWatch(simplecustviewer_t):
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


    def Create(self, isim, title):
        self.isim = isim
        if not simplecustviewer_t.Create(self, title):
            print("failed create of datawatch viewer")
            return False
        else:
            print("created datawatch")
        self.Show()
        return True

    def register(self):

        form = idaversion.get_current_widget()
        the_name = "refresh_data"
        idaapi.register_action(idaapi.action_desc_t(the_name, "refresh data", self.datawatch_handler(self.updateDataWatch)))
        idaapi.attach_action_to_popup(form, None, the_name)

        iterator_name = "tag_iterator"
        idaapi.register_action(idaapi.action_desc_t(iterator_name, "Tag function as iterator", self.datawatch_handler(self.tagIterator)))
        idaapi.attach_action_to_popup(form, None, iterator_name)

        watch_name = "next_watch_mark"
        idaapi.register_action(idaapi.action_desc_t(watch_name, "Next watch mark", self.datawatch_handler(self.nextWatchMark)))
        idaapi.attach_action_to_popup(form, None, watch_name)

        offset_name = "get_offset"
        idaapi.register_action(idaapi.action_desc_t(offset_name, "Get offset from original buffer", self.datawatch_handler(self.getOffset)))
        idaapi.attach_action_to_popup(form, None, offset_name)
        #self.Show()

    def tagIterator(self):
        line = self.GetCurrentLine()
        if line is not None:
            parts = line.split()
            if len(parts) > 2:
                index = None
                try:
                    index = int(parts[0])
                except ValueError:
                    print('Failed to get index from %s' % line)
                    return
                command = '@cgc.tagIterator(%d)' % index
                simicsString = gdbProt.Evalx('SendGDBMonitor("%s");' % command)
                time.sleep(1)
                self.updateDataWatch()

    def getOffset(self):
        self.isim.getBacktraceAddr()

    def nextWatchMark(self):
        command = '@cgc.nextWatchMark()'
        simicsString = gdbProt.Evalx('SendGDBMonitor("%s");' % command)
        try:
            index = int(simicsString)
        except:
            print('%s' % simicsString)
            return
        index = index - 1
        #print('nextWatchMark decremented index to %d' % index)
        self.Jump(index)

    def updateDataWatch(self):
        print("in updateDataWatch")
        #self.Close()
        #self.Create()
        #print('did create')
        retval = []
        self.ClearLines()
        #self.Refresh()
        print('did refresh of clear')
        command = '@cgc.getWatchMarks()'
        simicsString = gdbProt.Evalx('SendGDBMonitor("%s");' % command)
        if type(simicsString) is int:
            print('updateStackTrace got an int?  %d' % simicsString)
            return
        if simicsString.startswith('None'):
            simicsString=simicsString[5:]

        try:
            data_json = json.loads(simicsString)
        except:
            print('could not get json from %s' % simicsString)
            return
        index = 1
        for entry in data_json:
            instruct = idc.GetDisasm(entry['ip'])
            uline = '%3d 0x%08x 0x%08x %s pid:%d' % (index, entry['ip'], entry['cycle'], entry['msg'], entry['pid'])
            line = uline.encode('ascii', 'replace')
            #print('do %s' % line)
            if 'return from' in str(line):
                cline = idaapi.COLSTR(str(line), idaapi.SCOLOR_DREF)
            elif 'closed FD' in str(line):
                cline = idaapi.COLSTR(str(line), idaapi.SCOLOR_DREF)
            else:
                cline = str(line)
            #print("added %s" % line)
            retval.append(str(line))
            self.AddLine(cline)
            index += 1
        self.Refresh()
        command = '@cgc.nextWatchMark()'
        simicsString = gdbProt.Evalx('SendGDBMonitor("%s");' % command)
        try:
            index = int(simicsString)
        except:
            print('%s' % simicsString)
            return
        self.Jump(index)
            
        #self.Show()
        return retval

    def OnDblClick(self, shift):
        line = self.GetCurrentLine()
        line = idaapi.tag_remove(line)
        #print('line is %s' % line)
        parts = line.split()
        #print('parts0 is %s' % parts[0])
        index = None
        try:
            index = int(parts[0])
        except:
            print('no index found in %s' % line)
            return
        command = '@cgc.goToDataMark(%d)' % index
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

          
