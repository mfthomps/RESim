import time
import json
import idaapi
import idc
import idautils
import idaversion
import bpUtils
import gdbProt
import origAnalysis
import resimUtils
import regFu
import ida_kernwin
no_rev = 'reverse execution disabled'
class IdaSIM():
    def __init__(self, stack_trace, bookmark_view, data_watch, branch_not_taken, write_watch, kernel_base, reg_list):
        self.stack_trace = stack_trace
        self.data_watch = data_watch
        self.branch_not_taken = branch_not_taken
        self.write_watch = write_watch
        self.bookmark_view = bookmark_view
        self.just_debug = False
        self.recent_bookmark = 1
        self.recent_fd = '1'
        self.kernel_base = kernel_base
        self.reg_list = reg_list
        self.origAnalysis = origAnalysis.OrigAnalysis(idaversion.get_input_file_path())
        proc_info = idaapi.get_inf_structure()
        #print('********************************** procname %s' % proc_info.procname)
        if proc_info.procname == 'ARM':
            self.PC='pc'
            self.SP='sp'
        elif proc_info.procname == 'PPC':
            self.PC='PC'
            self.SP='R1'
        else:
            self.PC='eip'
            self.SP='esp'

    def getOrigAnalysis(self):
        return self.origAnalysis

    def checkNoRev(self, ss):
        if type(ss) is str:
            if ss.startswith(no_rev):
                print('Reverse execution is disabled')
                return False
        return True 

    def doRevToCursor(self):
        cursor = idaversion.get_screen_ea()
        curAddr = idaversion.get_reg_value(self.PC)
        if cursor == curAddr:
            print('attempt to go back to where you are ignored')
            return
        #doRevToAddr(cursor)
        command = '@cgc.revToAddr(0x%x, extra_back=%d)' % (cursor, 0)
        simicsString = gdbProt.Evalx('SendGDBMonitor("%s");' % command)
        print('simicsString <%s>' % simicsString)
        if self.checkNoRev(simicsString):
            print('simicsString call geteip when stopped')
            eip = gdbProt.getEIPWhenStopped()
            print('simicsString back from geteip when stopped')
            self.signalClient()
            print('simicsString back from signalClient')

    def doRunToCursor(self):
        cursor = idaversion.get_screen_ea()
        curAddr = idaversion.get_reg_value(self.PC)
        #doRevToAddr(cursor)
        command = '@cgc.doBreak(0x%x, run=True)' % (cursor)
        print('command <%s>' % command)
        simicsString = gdbProt.Evalx('SendGDBMonitor("%s");' % command)
        print('simicsString <%s>' % simicsString)
        print('simicsString call geteip when stopped')
        eip = gdbProt.getEIPWhenStopped()
        print('simicsString back from geteip when stopped')
        self.signalClient()
        print('simicsString back from signalClient')

    def signalClient(self, norev=False):
        start_eip = idaversion.get_reg_value(self.PC)
            #print('signalClient eip was at 0x%x, then after rev 1 0x%x call setAndDisable string is %s' % (start_eip, eip, simicsString))
        #print('signalClient start_eip 0x%x' % start_eip)
        if norev:
            idaversion.step_into()
            idaversion.wait_for_next_event(idc.WFNE_SUSP, -1)
        simicsString = gdbProt.Evalx('SendGDBMonitor("@cgc.printRegJson()");')
        #print('signalClient load json')
        try:
            regs = json.loads(simicsString)
        except:
            try:
                simicsString = gdbProt.Evalx('SendGDBMonitor("@cgc.printRegJson()");')
                regs = json.loads(simicsString)
            except:
                print('failed to get regs from %s' % simicsString)
                return
        #print('signalClient update regs')
        for reg in regs:
            r = str(reg.upper())
            if r == 'EFLAGS':
                r = 'EFL'
            elif r == 'CPSR':
                r = 'PSR'
            elif r == 'SP_EL0':
                r = 'SP'
            elif r == 'SP_EL1':
                continue
            #print('set %s to 0x%x' % (r, regs[reg]))
            idaversion.set_reg_value(r, regs[reg])
        #print('signalClient refresh memory')
        idaversion.refresh_debugger_memory()
        #print('signalClient back from refresh memory')

        new_eip = idaversion.get_reg_value(self.PC)
        if new_eip >= self.kernel_base:
            print('in kernel, run to user')
        #self.updateStackTrace()
        #print('signalClient back from update stack')


    '''
        reverse-step-instruction, but within current process, return new eip
    '''
    def reverseStepInstruction(self, num=1):
    
        command = "@cgc.reverseStepInstruction(%d)" % num
        simicsString = gdbProt.Evalx('SendGDBMonitor("%s");' % command)
        if self.checkNoRev(simicsString):
            eip = gdbProt.getEIPWhenStopped()
            self.signalClient()
    
    def doRevStepOver(self):
        #print 'in doRevStepOver'
        curAddr = idaversion.get_reg_value(self.PC)
        prev_eip = idaversion.prev_head(curAddr)
        eip = None
        #simicsString = gdbProt.Evalx('SendGDBMonitor("@cgc.reverseToCallInstruction(False)");')
        print('doRevStepOver prev_eip 0x%x' % prev_eip) 
        if prev_eip == idaapi.BADADDR:
            prev_eip = None
            simicsString = gdbProt.Evalx('SendGDBMonitor("@cgc.reverseToCallInstruction(False)");')
        else:
            #print('cur is 0x%x prev is 0x%x' % (curAddr, prev_eip))
            simicsString = gdbProt.Evalx('SendGDBMonitor("@cgc.reverseToCallInstruction(False, prev=0x%x)");' % prev_eip)
        print('doRevStepOver %s' % simicsString) 
        if self.checkNoRev(simicsString):
            eip = gdbProt.getEIPWhenStopped()
            self.signalClient()
        return eip
    
    def doRevStepInto(self):
        #print 'in doRevStepInto'
        #eip = reverseStepInstruction()
        curAddr = idaversion.get_reg_value(self.PC)
        prev_eip = idaversion.prev_head(curAddr)
        eip = None
        simicsString = gdbProt.Evalx('SendGDBMonitor("@cgc.reverseToCallInstruction(True)");')
        '''
        if prev_eip == idaapi.BADADDR:
            prev_eip = None
            simicsString = gdbProt.Evalx('SendGDBMonitor("@cgc.reverseToCallInstruction(True)");')
        else:
            #print('cur is 0x%x prev is 0x%x' % (curAddr, prev_eip))
            simicsString = gdbProt.Evalx('SendGDBMonitor("@cgc.reverseToCallInstruction(True, prev=0x%x)");' % prev_eip)
        '''
        if self.checkNoRev(simicsString):
            eip = gdbProt.getEIPWhenStopped()
            self.signalClient()
        return eip
    
    def doRevFinish(self):
        #print 'doRevFinish'
        #doRevCommand('uncall-function')
        cur_addr = idaversion.get_reg_value(self.PC)
        #f = idc.GetFunctionAttr(cur_addr, idc.FUNCATTR_START)
        f = idc.get_func_attr(cur_addr, idc.FUNCATTR_START)
        if f != idaapi.BADADDR: 
            print('doRevFinish got function start at 0x%x, go there, and further back 1' % f) 
            self.doRevToAddr(f, extra_back=1)
        else:
            print('use monitor uncall function')
            simicsString = gdbProt.Evalx('SendGDBMonitor("@cgc.uncall()");')
            if self.checkNoRev(simicsString):
                eip = gdbProt.getEIPWhenStopped()
                self.signalClient()
    
    '''
        Issue the Simics "rev" command via GDB and then move forward the actual breakpoint
    '''
    def doReverse(self, extra_back=None):
        print('in doReverse')
        curAddr = idaversion.get_reg_value(self.PC)
        #goNowhere()
        #print('doReverse, back from goNowhere curAddr is %x' % curAddr)
        isBpt = idaversion.check_bpt(curAddr)
        # if currently at a breakpoint, we need to back an instruction to so we don't break
        # here
        if isBpt > 0:
            print('curAddr is %x, it is a breakpoint, do a rev step over' % curAddr)
            addr = self.doRevStepOver()
            if addr is None:
                return None
            print('in doReverse, did RevStepOver got addr of %x' % addr)
            isBpt = idaversion.check_bpt(addr)
            if isBpt > 0:
                # back up onto a breakpoint, we are done
                print('doReverse backed to breakpoint, we are done')
            return addr
    
        #print 'do reverse'
        param = ''
        if extra_back is not None:
            param = extra_back
        command = '@cgc.doReverse(%s)' % param
        simicsString = gdbProt.Evalx('SendGDBMonitor("%s");' % command)
        addr = None
        if self.checkNoRev(simicsString):
            addr = gdbProt.getEIPWhenStopped()
            self.signalClient()
    
        return addr
    
    def doRevToAddr(self, addr, extra_back=0):
        command = '@cgc.revToAddr(0x%x, extra_back=%d)' % (addr, extra_back)
        simicsString = gdbProt.Evalx('SendGDBMonitor("%s");' % command)
        if self.checkNoRev(simicsString):
            eip = gdbProt.getEIPWhenStopped()
            self.signalClient()
        
    '''
    Run backwards until we find the most recent write to the current SP
    '''
    def wroteToSP(self):
        sp = idaversion.get_reg_value(self.SP)
        print('Running backwards to previous write to ESP:0x%x' % sp)
        self.wroteToAddress(sp)
     
                        
    def getMailbox(self):    
        msg = gdbProt.Evalx('SendGDBMonitor("@cgc.emptyMailbox()");')
        lines = msg.split('\n')
        if len(lines) > 1:
            msg = lines[0]
        print('got mailbox message: <%s>' % msg)
        return msg
    
    def getUIAddress(self, prompt):    
        value = self.registerMath()
        if value is None:
            value = idaversion.get_reg_value(self.SP)
        target_addr = idaversion.ask_addr(value, prompt)
        return target_addr
    
    def writeWord(self):
        print('Write Word')
        addr = idaversion.ask_addr(0, 'Address to modify')
        value = idaversion.ask_addr(0, 'Value')
        command = '@cgc.writeWord(0x%x, 0x%x)' % (addr, value)
        simicsString = gdbProt.Evalx('SendGDBMonitor("%s");' % command)
    
    def wroteToAddressPrompt(self, num_bytes=None):
        addr = self.getUIAddress('Run backwards until this address is modified')
        print('Running backwards to find write to address 0x%x' % addr)
        self.wroteToAddress(addr, num_bytes=num_bytes)
    
    def trackAddressPrompt(self, prompt=None, num_bytes=None):
        if prompt is None:
            prompt = 'Run backwards to find source of data at this address'
        addr = self.getUIAddress(prompt)
        if addr is not None:
            print('%s 0x%x' % (prompt, addr))
            self.trackAddress(addr, num_bytes=num_bytes)
            self.showSimicsMessage()
            bookmark_list = self.bookmark_view.updateBookmarkView()
    
    def wroteToAddress(self, target_addr, num_bytes=None):
        disabledSet = bpUtils.disableAllBpts(None)
        command = '@cgc.stopAtKernelWrite(0x%x)' % (target_addr)
        simicsString = gdbProt.Evalx('SendGDBMonitor("%s");' % command)
        if self.checkNoRev(simicsString):
            eip = gdbProt.getEIPWhenStopped()
            self.signalClient()
        else:
            return
        bpUtils.enableBpts(disabledSet)
        if eip >=  self.kernel_base:
            print('previous syscall wrote to address 0x%x' % target_addr)
        else:
            curAddr = idaversion.get_reg_value(self.PC)
            #print('Current instruction (0x%x) wrote to 0x%x' % (curAddr, target_addr))
            print('Previous instruction  wrote to 0x%x' % (target_addr))
        self.bookmark_list = self.bookmark_view.updateBookmarkView()
    
    def trackAddress(self, target_addr, num_bytes=None):
        disabledSet = bpUtils.disableAllBpts(None)
        num_bytes_string = 'None'
        if num_bytes is not None:
            num_bytes_string = '%d' % num_bytes
        command = '@cgc.revTaintAddr(0x%x, num_bytes=%s)' % (target_addr, num_bytes_string)
        simicsString = gdbProt.Evalx('SendGDBMonitor("%s");' % command)
        if self.checkNoRev(simicsString):
            eip = gdbProt.getEIPWhenStopped()
            self.signalClient()
        else:
            return
        bpUtils.enableBpts(disabledSet)
        if eip is None:
            print('Failed to get eip from RESim.  ERROR')
        elif eip >=  self.kernel_base:
            print('previous is as far back as we can trace content of address 0x%x' % target_addr)
        else:
            curAddr = idaversion.get_reg_value(self.PC)
            print('Current instruction (0x%x) is as far back as we can trace 0x%x' % (curAddr, target_addr))
        self.bookmark_list = self.bookmark_view.updateBookmarkView()
    
    def showSimicsMessage(self):
        command = '@cgc.idaMessage()' 
        simics_string = gdbProt.Evalx('SendGDBMonitor("%s");' % command)
        print(simics_string)
       
        if type(simics_string) is str:
           if 'Simics got lost' in simics_string:
              idc.Warning(simics_string)
           elif 'Just debug' in simics_string:
              self.just_debug = True
        return simics_string
    
           
    def wroteToRegister(self): 
        highlighted = idaversion.getHighlight()

        if highlighted is None  or not self.isReg(highlighted):
           print('%s not in reg list' % highlighted)
           highlighted = idaversion.ask_str('Wrote to register:', 'Which register?')

        print('Looking for a write to %s...' % highlighted)
        command = "@cgc.revToModReg('%s')" % highlighted
        simicsString = gdbProt.Evalx('SendGDBMonitor("%s");' % command)
        eip = None
        if self.checkNoRev(simicsString):
            eip = gdbProt.getEIPWhenStopped()
            self.signalClient()
        else:
            return
        curAddr = idaversion.get_reg_value(self.PC)
        print('Current instruction (0x%x) wrote to reg %s' % (curAddr, highlighted))
        return eip
        
    def trackRegister(self): 
        highlighted = idaversion.getHighlight()
        if highlighted is None  or not self.isReg(highlighted):
           print('%s not in reg list' % highlighted)
           print('%s' % str(self.reg_list))
           highlighted = idaversion.ask_str('Track register:', 'Which register?')
        print('backtrack to source of to %s...' % highlighted)
        command = "@cgc.revTaintReg('%s')" % highlighted
        simicsString = gdbProt.Evalx('SendGDBMonitor("%s");' % command)
        print('trackRegister got simicsString %s' % simicsString)
        eip = None
        if self.checkNoRev(simicsString):
            eip = gdbProt.getEIPWhenStopped()
            self.signalClient()
        else:
            return
        curAddr = idaversion.get_reg_value(self.PC)
        print('Current instruction (0x%x) is as far back as we can trace reg %s' % (curAddr, highlighted))
        self.showSimicsMessage()
        bookmark_list = self.bookmark_view.updateBookmarkView()
        return eip

    def satisfyCondition(self): 
        cursor = idaversion.get_screen_ea()
        print('Satisfy condition at instruction 0x%x' % cursor)
        command = "@cgc.satisfyCondition(0x%x)" % cursor
        simicsString = gdbProt.Evalx('SendGDBMonitor("%s");' % command)
        print('satisfyCondition got simicsString %s' % simicsString)
        eip = None
        if self.checkNoRev(simicsString):
            eip = gdbProt.getEIPWhenStopped()
            self.signalClient()
        else:
            return
        curAddr = idaversion.get_reg_value(self.PC)
        self.showSimicsMessage()
        bookmark_list = self.bookmark_view.updateBookmarkView()
        return eip
     
    def chooseBookmark(self): 
        c=idaapi.Choose([], "select a bookmark", 1, deflt=self.recent_bookmark)
        c.width=50
        command = '@cgc.listBookmarks()'
        simicsString = gdbProt.Evalx('SendGDBMonitor("%s");' % command)
        #print lines
        lines = simicsString.split('\n')
        for l in lines:
            if ':' in l:
                #print l
                num, bm = l.split(':',1)
                c.list.append(bm.strip())
        chose = c.choose()
        if chose != 0:
            self.recent_bookmark = chose
            self.goToBookmarkRefresh(c.list[chose-1])
        else:
            print('user canceled')
         
    def askGoToBookmark(self):
        mark = idaversion.ask_str('myBookmark', 'Name of bookmark to jump to:')
        if mark is not None and mark != 0:
            self.goToBookmarkRefresh(mark)
    
    
    def highlightedBookmark(self): 
        highlighted = idaapi.get_output_selected_text()
        if highlighted is not None:
            self.goToBookmarkRefresh(highlighted)
    
    def listBookmarks(self):
        print('Bookmarks (highlight & alt-shift-b to go there)')
        command = '@cgc.listBookmarks()' 
        simicsString = gdbProt.Evalx('SendGDBMonitor("%s");' % command)
        print(simicsString)
        self.bookmark_view.updateBookmarkView()
       
       
    def goToBegin(self):
        '''
        NOT USED
        Send simics back to the earliest recorded eip 
        '''
        print('goToBegin')
        #simicsString = gdbProt.Evalx('SendGDBMonitor("@cgc.goToFirst()");') 
        #eip = getEIPWhenStopped()
        #stepWait()
        #runToUserSpace()
        self.goToBookmarkRefresh('_start+1')
        # trusting there is a first breakpoint
        #print('goToBegin got back from goToBookmarkRefresh now run to first break?')
        #GetDebuggerEvent(WFNE_SUSP | WFNE_CONT, -1)
        #GetDebuggerEvent(WFNE_SUSP | WFNE_CONT, -1)
        #print('back from goToBegin')
    
    def goToBookmarkRefresh(self, mark):
        self.bookmark_view.goToBookmarkRefresh(mark)
        self.signalClient()
    
    def goToOrigin(self):
        '''
        Send simics back to the eip where simics had stopped for debugging
        '''
        print('goToOrigin')
        self.bookmark_view.goToOrigin()
        #signalClient()
        #goToBookmarkRefresh('origin')
    
    def setBreakAtStart(self):
        ''' keep from reversing past start of process '''
        addr = LocByName("_start")
        if addr is not None:
            bptEnabled = idaversion.check_bpt(addr)
            if bptEnabled < 0:
                print('breakAtStart bpt set at 0x%x' % addr)
                idaversion.add_bpt(addr)
        else:
            print('setBreakAtStart, got no loc for _start')
        return addr
    
    def goNowhere(self):
        '''
        Force ida to send server the current breakpoints
        '''
        #print('in goNowhere')
        #curAddr = idaversion.get_reg_value("EIP")
        #print('in goNowhere back from getReg')
        #bptEnabled, disabledSet = setAndDisable(curAddr)
        #simicsString = gdbProt.Evalx('SendGDBMonitor("@cgc.skipAndMail()");') 
        #eip = gdbProt.getEIPWhenStopped()
        #gdbProt.stepWait()
        self.signalClient()
        #print('goNowhere after stepInto')
        #GetDebuggerEvent(WFNE_SUSP | WFNE_CONT, -1)
        #reEnable(curAddr, bptEnabled, disabledSet)
    
    def runToUserSpace(self):
        #self.bookmark_view.runToUserSpace()
        #time.sleep(3)
        print('runToUser do resynch')
        v = ida_kernwin.get_current_viewer()
        r = ida_kernwin.get_view_renderer_type(v)
        dotoggle = False
        ''' work around ida bug "nrect(26)" error '''
        if r == ida_kernwin.TCCRT_GRAPH:
            dotoggle = True
            ida_kernwin.process_ui_action("ToggleRenderer")
        print('resynch to server')
        simicsString = gdbProt.Evalx('SendGDBMonitor("@cgc.resynch()");')
        time.sleep(1)
        eip = gdbProt.getEIPWhenStopped()
        print('resynch got eip 0x%x now sig client' % eip)
        if dotoggle:
            ida_kernwin.process_ui_action("ToggleRenderer")
        self.signalClient()
    
    def runToSyscall(self):
            value = idaversion.ask_long(0, "Syscall number?")
            print('run to syscall of %d' % value)
            if value == 0:
                simicsString = gdbProt.Evalx('SendGDBMonitor("@cgc.runToSyscall()");') 
            else:
                simicsString = gdbProt.Evalx('SendGDBMonitor("@cgc.runToSyscall(%s)");' % value) 
               
            eip = gdbProt.getEIPWhenStopped(kernel_ok=True)
            #print('runtoSyscall, stopped at eip 0x%x, now run to user space.' % eip)
            self.showSimicsMessage()
            simicsString = gdbProt.Evalx('SendGDBMonitor("@cgc.runToUserSpace()");') 
            eip = gdbProt.getEIPWhenStopped()
            #print('runtoSyscall, stopped at eip 0x%x, then stepwait.' % eip)
            #gdbProt.stepWait()
            self.signalClient(norev=True)
            eax = idaversion.get_reg_value("EAX")
            print('Syscall result: %d' % int(eax))
            #print('runtoSyscall rev over')
            #doRevStepOver()
            #print('runtoSyscall done')
    
    def revToSyscall(self):
        simicsString = gdbProt.Evalx('SendGDBMonitor("@cgc.revToSyscall()");') 
        if self.checkNoRev(simicsString):
            eip = gdbProt.getEIPWhenStopped()
            self.signalClient()
        else:
            return
        simicsString = gdbProt.Evalx('SendGDBMonitor("@cgc.runToUserSpace()");') 
        eip = gdbProt.getEIPWhenStopped()
        self.signalClient()
        print('revtoSyscall done')
    
    def revBlock(self):
        cur_addr = idaversion.get_reg_value(self.PC)
        f = idaapi.get_func(cur_addr)
        if f is None:
            print('Ida analysis sees no function, cannot perform this function')
            return
        fc = idaapi.FlowChart(f)
        block_start = None
        prev_addr = None
        prev_block = None
        for block in fc:
            block_start = block.startEA
            #print('block_start 0x%x, cur_addr is 0x%x' % (block_start, cur_addr))
            if block_start > cur_addr:
                break
            prev_addr = block_start
            prev_block = block
    
        if prev_addr == cur_addr:
            self.doRevStepInto()
        elif prev_addr is not None:
            next_addr = idaversion.next_head(prev_addr)
            if next_addr == cur_addr:
                ''' reverse two to get there? '''
                print('revBlock rev two?')
                self.doRevStepInto()
                self.doRevStepInto()
            else:
                print('revBlock rev to 0x%x' % prev_addr)
                self.doRevToAddr(prev_addr, extra_back=0)
        else:
            print('must have been top, uncall')
            self.doRevFinish()
   
    def watchData(self):
        command = "@cgc.watchData()" 
        print('called %s' % command)
        simicsString = gdbProt.Evalx('SendGDBMonitor("%s");' % command)
        print('watchData got back %s' % simicsString) 
        time.sleep(1)
        eip = gdbProt.getEIPWhenStopped()
        if eip != 0:
            self.signalClient()
        self.showSimicsMessage()
        
    def runToIO(self):
        print('runToIO')
        result = idaversion.ask_str(self.recent_fd, 'FD ?')
        if result is None:
            return
        self.recent_fd = result
        fd = int(result)
        command = "@cgc.runToIO(%d)" % fd
        print('command is %s' % command)
        simicsString = gdbProt.Evalx('SendGDBMonitor("%s");' % command)
        time.sleep(1)
        eip = gdbProt.getEIPWhenStopped()
        print('runToIO %s, ended at eip 0x%x' % (result, eip))
        self.signalClient(norev=True)
        self.showSimicsMessage()

    def runToAccept(self):
        print('runToAccept')
        result = idaversion.ask_str(self.recent_fd, 'FD ?')
        if result is None:
            return
        self.recent_fd = result
        fd = int(result)
        command = "@cgc.runToAccept(%d)" % fd
        print('command is %s' % command)
        simicsString = gdbProt.Evalx('SendGDBMonitor("%s");' % command)
        time.sleep(1)
        eip = gdbProt.getEIPWhenStopped()
        print('runToAccept %s, ended at eip 0x%x' % (result, eip))
        self.signalClient(norev=True)
        self.showSimicsMessage()
    
    def runToOpen(self):
        print('runToOpen')
        result = idaversion.ask_str('?', 'filename substring')
        if result is None:
            return
        command = "@cgc.runToOpen('%s')" % result
        print('command is %s' % command)
        simicsString = gdbProt.Evalx('SendGDBMonitor("%s");' % command)
        eip = gdbProt.getEIPWhenStopped()
        print('runToOpen %s, ended at eip 0x%x' % (result, eip))
        self.signalClient(norev=True)
        self.showSimicsMessage()

    def runToWrite(self):
        print('runToWrite')
        result = idaversion.ask_str('?', 'String')
        if result is None:
            return
        command = "@cgc.runToWrite('%s')" % result
        print('command is %s' % command)
        simicsString = gdbProt.Evalx('SendGDBMonitor("%s");' % command)
        eip = gdbProt.getEIPWhenStopped()
        print('runToWrite %s, ended at eip 0x%x' % (result, eip))
        self.signalClient(norev=True)
        self.showSimicsMessage()

    def runToConnect(self):
        print('runToConnect')
        result = idaversion.ask_str('?', 'Network address as ip:port (or regex)')
        if result is None:
            return
        #result = '192.168.31.52:20480'
        command = "@cgc.runToConnect('%s')" % result
        print('command is %s' % command)
        simicsString = gdbProt.Evalx('SendGDBMonitor("%s");' % command)
        eip = gdbProt.getEIPWhenStopped()
        print('runToConnect %s, ended at eip 0x%x' % (result, eip))
        self.signalClient(norev=True)
        self.showSimicsMessage()
    
    def runToBind(self):
        print('runToBind')
        result = idaversion.ask_str('?', 'Network address as ip\:port (or regex)')
        if result is None:
            return
        #result = '192.168.31.52:20480'
        command = "@cgc.runToBind('%s')" % result
        print('command is %s' % command)
        simicsString = gdbProt.Evalx('SendGDBMonitor("%s");' % command)
        eip = gdbProt.getEIPWhenStopped()
        print('runToBind %s, ended at eip 0x%x' % (result, eip))
        self.signalClient(norev=True)
        self.showSimicsMessage()
    
    # Ida does not believe their is a debugger until you do something, so break at current eip
    def primePump(self):
        addr = setBreakAtStart()
        if addr is not None:
            self.goNowhere()
    
    def updateBookmarkView(self):
        bookmark_list = self.bookmark_view.updateBookmarkView()

    def rebuildBookmarkView(self):
        print('rebuilding bookmark view')
        self.bookmark_view.Create(self)
        bookmark_list = self.bookmark_view.updateBookmarkView()
    
    def updateStackTrace(self):
        stack_trace_results = self.stack_trace.updateStackTrace()

    def updateDataWatch(self):
        data_watch_results = self.data_watch.updateDataWatch()

    def updateBNT(self):
        self.branch_not_taken.updateList()
    
    def updateWriteWatch(self):
        write_watch_results = self.write_watch.updateWriteWatch()
    
    def rebuildStackTrace(self):
        print('rebuilding stack trace')
        self.stack_trace.Create(self)
        stack_trace_results = self.stack_trace.updateStackTrace()
    
    def runToClone(self):
        simicsString = gdbProt.Evalx('SendGDBMonitor("@cgc.clone()");') 
        eip = gdbProt.getEIPWhenStopped()
        self.signalClient()
    
    def recordText(self):
        for seg_ea in idautils.Segments():
            print('seg: %s' % idaversion.get_segm_name(seg_ea))
            if idaversion.get_segm_name(seg_ea) == '.text':
                start = idaversion.get_segm_attr(seg_ea, idc.SEGATTR_START)
                end = idaversion.get_segm_attr(seg_ea, idc.SEGATTR_END)
                print('text at 0x%x - 0x%x' % (start, end))
                gdbProt.Evalx('SendGDBMonitor("@cgc.recordText(0x%x, 0x%x)");' % (start, end)) 
                break
    
    def doStepInto(self):
        print('in doInto')
        proc_info = idaapi.get_inf_structure()
        if proc_info.procname == 'PPC':
            cur_addr = idaversion.get_reg_value(self.PC)
            instruct = idc.generate_disasm_line(cur_addr, 0)
            print('is ppc, instruct %s' % instruct)
            if instruct.startswith('bl '):
                print('is ppc do step')
                gdbProt.Evalx('SendGDBMonitor("@cgc.stepN(1)");')
                eip = gdbProt.getEIPWhenStopped()
                self.signalClient()
            else: 
                idaversion.step_into()
                idaversion.wait_for_next_event(idc.WFNE_SUSP, -1)
        else:
            idaversion.step_into()
            idaversion.wait_for_next_event(idc.WFNE_SUSP, -1)
        cur_addr = idaversion.get_reg_value(self.PC)
        #print('cur_addr is 0x%x kernel_base 0x%x' % (cur_addr, self.kernel_base))
        if cur_addr > self.kernel_base:
            print('doStepInto run to user space')
            self.runToUserSpace()
   
    def doStepOver(self):
        print('in doStepOver')

        proc_info = idaapi.get_inf_structure()
        if proc_info.procname == 'PPC':
            cur_addr = idaversion.get_reg_value(self.PC)
            instruct = idc.generate_disasm_line(cur_addr, 0)
            print('is ppc, instruct %s' % instruct)
            if instruct.startswith('b') and not instruct.startswith('bl '):
                print('is ppc b, do step')
                gdbProt.Evalx('SendGDBMonitor("@cgc.stepN(1)");')
                eip = gdbProt.getEIPWhenStopped()
                self.signalClient()
            else: 
                idaversion.step_over()
                idaversion.wait_for_next_event(idc.WFNE_SUSP, -1)
        else:
            idaversion.step_over()
            idaversion.wait_for_next_event(idc.WFNE_SUSP, -1)

        #print('back getDebuggerEvent')
        cur_addr = idaversion.get_reg_value(self.PC)
        #print('cur_addr is 0x%x' % cur_addr)
        if cur_addr > self.kernel_base:
            print('doStepOver in kernel run to user space')
            self.runToUserSpace()
        else:
            #print('doStepOver signal client')
            self.signalClient()
        
    
    def exitIda(self):
        goToOrigin()
        simicsString = gdbProt.Evalx('SendGDBMonitor("@cgc.idaDone()");')
        print("Telling gdb server we are exiting")
        time.sleep(2)
        idaapi.qexit(0)
    
    def resynch(self):
        '''
        print('resynch to server')
        simicsString = gdbProt.Evalx('SendGDBMonitor("@cgc.resynch()");')
        time.sleep(1)
        eip = gdbProt.getEIPWhenStopped()
        print('resynch got eip 0x%x now sig client' % eip)
        '''
        print('Not calling monitor -- simply doing a register refresh.')
        self.signalClient()
    
    def runToText(self):
        simicsString = gdbProt.Evalx('SendGDBMonitor("@cgc.runToText()");')
        time.sleep(1)
        eip = gdbProt.getEIPWhenStopped()
        self.signalClient()
    
    def revToText(self):
        simicsString = gdbProt.Evalx('SendGDBMonitor("@cgc.revToText()");')
        time.sleep(1)
        if self.checkNoRev(simicsString):
            eip = gdbProt.getEIPWhenStopped()
            self.signalClient()
    
    def exitMaze(self):
        simicsString = gdbProt.Evalx('SendGDBMonitor("@cgc.exitMaze(debugging=True)");')
        time.sleep(1)
        eip = gdbProt.getEIPWhenStopped()
        self.signalClient()
     
    def showCycle(self):
        simicsString = gdbProt.Evalx('SendGDBMonitor("@cgc.showCycle()");')
        print(simicsString)
    
    def refreshBookmarks(self):
        self.bookmark_view.updateBookmarkView()
    
    def continueForward(self):
        simicsString = gdbProt.Evalx('SendGDBMonitor("@cgc.continueForward()");')
        #while True:
        #    simicsString = gdbProt.Evalx('SendGDBMonitor("@cgc.getEIPWhenStopped(%s)");' % 'True')
        #    time.sleep(2)
        #idc.PauseProcess()
        eip = gdbProt.getEIPWhenStopped()
        print('continueForward got eip 0x%x' % eip)
        self.signalClient()
        self.bookmark_list = self.bookmark_view.updateBookmarkView()
   
    def isReg(self, reg): 
        ''' TBD must be better way to get list of registers from ida '''
        retval = False
        if reg is not None:
            if len(reg) == 3 and reg.startswith('e'):
                reg = reg[1:]
            if reg in self.reg_list:
                retval = True 
        return retval

    def registerMath(self): 
        retval = None
        if regFu.isHighlightedEffective():
            retval = regFu.getOffset()
        else:
            #regs =['eax', 'ebx', 'ecx', 'edx', 'esi', 'edi', 'ebp']
            highlighted = idaversion.getHighlight()
            retval = None
            if highlighted is not None:
                print('highlighted is %s' % highlighted)
                if self.isReg(highlighted):
                    retval = idaversion.get_reg_value(highlighted)
                else:
                    try:
                        retval = int(highlighted, 16)
                    except:
                        pass
                    if retval is None:
                        ''' TBD this is broken, manually manage register list? '''
                        for reg in self.reg_list:
                            if highlighted.startswith(reg):
                                rest = highlighted[len(reg):]
                                value = None
                                try:
                                    value = int(rest[1:])
                                except:
                                    pass
                                if value is not None:
                                    if rest.startswith('+'):
                                        regvalue = idaversion.get_reg_value(reg)
                                        retval = regvalue + value
                                    elif rest.startswith('-'):
                                        regvalue = idaversion.get_reg_value(reg)
                                        retval = regvalue - value
        return retval
    def reBase(self):
        fname = idaversion.get_root_filename()
        command = "@cgc.getSOFromFile('%s')" % fname
        simicsString = gdbProt.Evalx('SendGDBMonitor("%s");' % command)
        print('so stuff: %s' % simicsString) 
        adders = simicsString.split(':')[1]
        start = adders.split('-')[0]
        try:
            start_hex = int(start,16)
        except ValueError:
            print('could not get hex from %s' % start)
            return 
        idaversion.rebase_program(start_hex, 0) 

    def trackIO(self):
        result = idaversion.ask_str(self.recent_fd, 'FD ?', hist=2)
        if result is None:
            return
        self.recent_fd = result
        fd = int(result)
        simicsString = gdbProt.Evalx('SendGDBMonitor("@cgc.trackIO(%d)");' % fd)
        time.sleep(1)
        eip = gdbProt.getEIPWhenStopped()
        self.signalClient()
        self.updateDataWatch()

    def retrack(self):
        simicsString = gdbProt.Evalx('SendGDBMonitor("@cgc.retrack()");')
        time.sleep(1)
        eip = gdbProt.getEIPWhenStopped()
        self.signalClient()
        self.updateDataWatch()

    def getBacktraceAddr(self):
        highlighted = idaversion.getHighlight()
        addr = resimUtils.getHex(highlighted)
        if addr is None:
            print('Highlighted is not an address')
            return
        command = '@cgc.backtraceAddr(0x%x, None)' % (addr)
        print('cmd: %s' % command)
        simicsString = gdbProt.Evalx('SendGDBMonitor("%s");' % command)
        print(simicsString)
