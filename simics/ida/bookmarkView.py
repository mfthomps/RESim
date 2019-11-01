'''
 * This software was created by United States Government employees
 * and may not be copyrighted.
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
 * ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
'''
import idaapi
import idc
from ida_kernwin import simplecustviewer_t
import gdbProt
import bpUtils

BT = 'backtrack '
START = 'START'


class bookmarkView(simplecustviewer_t):
    def __init__(self):
        self.isim = None

    class AddBookmarkHandler(idaapi.action_handler_t):
        def __init__(self, bookmark_view):
            idaapi.action_handler_t.__init__(self)
            self.bookmark_view = bookmark_view

        def activate(self, ctx):
            self.bookmark_view.askSetBookmark()
            return 1
        def update(self, ctx):
            return idaapi.AST_ENABLE_ALWAYS

    def Create(self, isim):
        self.isim = isim
        title = "Bookmarks"
        if not simplecustviewer_t.Create(self, title):
            print("failed create of bookmarks viewer")
            return False
        else:
            print("created bookmarkView")
        self.Show()


    def register(self):
        add_bookmark_action = idaapi.action_desc_t(
            'add_bookmark:action',
            'Add bookmark', 
            self.AddBookmarkHandler(self), 
            None)
        idaapi.register_action(add_bookmark_action)
        form = idaapi.get_current_widget()
        idaapi.attach_action_to_popup(form, None, 'add_bookmark:action')
        self.Show()

    def runToUserSpace(self):
        simicsString = gdbProt.Evalx('SendGDBMonitor("@cgc.runToUserSpace()");') 
        eip = gdbProt.getEIPWhenStopped()
        print('runtoUserSpace, stopped at eip 0x%x, then stepwait.' % eip)
        #gdbProt.stepWait()

    def goToBookmarkRefresh(self, mark):
        if mark != 'origin' and mark != '<None>':
            simicsString = gdbProt.goToBookmark(mark)
            if simicsString == "reverse disabled":
                print('Reverse execution is disabled')
                return
            eip = gdbProt.getEIPWhenStopped()
            #gdbProt.stepWait()
            print('Now at bookmark: %s' % mark)
        else:
            ''' monitor goToFirst will now handle missing page, and it starts in user space '''
            ''' TBD will end up at second instruction '''
            print('goToBookmarkRefresh, is start_1, goToFirst')
            #simicsString = gdbProt.Evalx('SendGDBMonitor("@cgc.goToFirst()");') 
            simicsString = gdbProt.Evalx('SendGDBMonitor("@cgc.goToOrigin()");') 
            eip = gdbProt.getEIPWhenStopped()
            
            #gdbProt.stepWait()


            #print('eip when stopped is 0x%x' % eip)
            #self.runToUserSpace()
            #self.runToUserSpace()
            print('Now at bookmark: %s' % mark)
        self.isim.showSimicsMessage()

    def goToOrigin(self):
        simicsString = gdbProt.Evalx('SendGDBMonitor("@cgc.goToOrigin()");') 
        eip = gdbProt.getEIPWhenStopped()
        if eip is not None:
            print('goToOrigin eip when stopped is 0x%x' % eip)
            #gdbProt.stepWait()
            #print('did step wait')
        else:
            print('goToOrigin, getEIPWhenStopped returned None')

    def updateBookmarkView(self):
        #print "in updateBookmarkView"
        #self.Close()
        #self.Create()
        #print('did create')
        retval = []
        self.ClearLines()
        #self.Refresh()
        #print('did refresh of clear')
        command = '@cgc.listBookmarks()'
        simicsString = gdbProt.Evalx('SendGDBMonitor("%s");' % command)
        if type(simicsString) is int or type(simicsString) is long:
            print('listBookmarks got an int?  %d' % simicsString)
            return
        lines = simicsString.split('\n')
        for l in lines:
            if ':' in l:
                #print l
                num, bm = l.split(':',1)
                entry = bm.strip()
                if entry.startswith(BT) and START not in entry:
                    entry = '<<<'+entry[len(BT):]
                self.AddLine(str(entry))
                #print("added %s" % entry)
                retval.append(entry)
        self.Refresh()
        #self.Show()
        return retval

    def OnDblClick(self, shift):
        line = self.GetCurrentLine()
        if not line: line = "<None>"
        if line.startswith('<<<'):
           line = line.replace('<<<',BT)
        self.goToBookmarkRefresh(line.strip())
        self.isim.signalClient()
        return True

    def setBookmark(self, mark):
        command = "@cgc.setDebugBookmark('%s')" % (mark)
        simicsString = gdbProt.Evalx('SendGDBMonitor("%s");' % command)
    
    def askSetBookmark(self):
        #print('askSetBookmark')
        addr = idc.get_reg_value(self.isim.PC)
        instruct = idc.GetDisasm(addr)
        if ';' in instruct:
            instruct, dumb = instruct.rsplit(';', 1)
            #print('instruct is %s' % instruct)
            instruct = instruct.strip()
    
        #print('eip %x  instruct: %s' % (addr, instruct))
        default = '0x%x: %s' % (addr, instruct) 
        mark = idc.AskStr(default, 'Name of new bookmark:')
        if mark != 0 and mark != 'None':
            self.setBookmark(mark)
            self.updateBookmarkView()

    def printBookmarks(self):
        #print('printBookmarks')
        try:
            x1, y1, x2, y2 = self.GetSelection()
        except:
            print 'nothing selected'
            for lineno in range(0, 99999):
                try:
                    line = self.GetLine(lineno)[0]
                except:
                    return
                if line is not None:
                    print line
                else:
                    return
            return
        #print('%d %d %d %d' % (x1, y1, x2, y2)) 
        for lineno in range(y1, y2+1):
            print self.GetLine(lineno)[0]

    def OnKeydown(self, vkey, shift):
        if vkey == 27:
            print('esc does nothing')
        else:
            return False
        return True
