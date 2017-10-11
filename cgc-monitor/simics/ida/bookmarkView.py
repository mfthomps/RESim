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
from idaapi import simplecustviewer_t
import gdbProt
class bookmarkView(simplecustviewer_t):

    class bookmark_handler(idaapi.action_handler_t):
        def __init__(self, callback):
            idaapi.action_handler_t.__init__(self)
            self.callback = callback
        def activate(self, ctx):
            print("set bookmark ")
            self.callback()
        def update(self, ctx):
            return idaapi.AST_ENABLE_ALWAYS

    def Create(self):
        title = "Bookmarks"
        if not simplecustviewer_t.Create(self, title):
            print("failed create of bookmarks viewer")
            return False
        else:
            print("created bookmarkView")
        tcc = self.GetTCustomControl()
        the_name = "the_name"
        idaapi.register_action(idaapi.action_desc_t(the_name, "add bookmark", self.bookmark_handler(self.askSetBookmark)))
        idaapi.attach_action_to_popup(tcc, None, the_name)
        self.Show()

    def runToUserSpace(self):
        simicsString = gdbProt.Evalx('SendGDBMonitor("@cgc.runToUserSpace()");') 
        eip = gdbProt.getEIPWhenStopped()
        print('runtoUserSpace, stopped at eip 0x%x, then stepwait.' % eip)
        gdbProt.stepWait()
        print('runtoUserSpace')

    def goToBookmarkRefresh(self, mark):
        if mark != '_start+1':
            gdbProt.goToBookmark(mark)
            eip = gdbProt.getEIPWhenStopped()
            gdbProt.stepWait()
            print('Now at bookmark: %s' % mark)
        else:
            ''' monitor goToFirst will now handle missing page, and it starts in user space '''
            ''' TBD will end up at second instruction '''
            print('goToBookmarkRefresh, is start_1, goToFirst')
            simicsString = gdbProt.Evalx('SendGDBMonitor("@cgc.goToFirst()");') 
            eip = gdbProt.getEIPWhenStopped()
            gdbProt.stepWait()
            #print('eip when stopped is 0x%x' % eip)
            #self.runToUserSpace()
            #self.runToUserSpace()
            print('Now at bookmark: %s' % mark)

    def goToOrigin(self):
        simicsString = gdbProt.Evalx('SendGDBMonitor("@cgc.goToOrigin()");') 
        eip = gdbProt.getEIPWhenStopped()
        if eip is not None:
            print('gotoOrigin eip when stopped is 0x%x' % eip)
            gdbProt.stepWait()
            print('did step wait')
        else:
            print('gotToOrigin, getEIPWhenStopped returned None')

    def updateBookmarkView(self):
        print "in updateBookmarkView"
        retval = []
        self.ClearLines()
        command = '@cgc.listBookmarks()'
        simicsString = gdbProt.Evalx('SendGDBMonitor("%s");' % command)
        lines = simicsString.split('\n')
        for l in lines:
            if ':' in l:
                #print l
                num, bm = l.split(':',1)
                self.AddLine(bm.strip())
                print("added %s" % bm.strip())
                retval.append(bm.strip())
        self.Refresh()
        return retval

    def OnDblClick(self, shift):
        line = self.GetCurrentLine()
        if not line: line = "<None>"
        self.goToBookmarkRefresh(line.strip())
        return True

    def setBookmark(self, mark):
        command = "@cgc.setDebugBookmark('%s')" % (mark)
        simicsString = gdbProt.Evalx('SendGDBMonitor("%s");' % command)
    
    def askSetBookmark(self):
        print('askSetBookmark')
        addr = idc.GetRegValue("EIP")
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
