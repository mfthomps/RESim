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
'''
Manage bookmarks.  the __bookmarks key is the text of the bookmark
'''
from simics import *
from collections import OrderedDict
import memUtils
import sys
class bookmarkMgr():
    __bookmarks = OrderedDict()
    __kernel_marks = []
    __origin_bookmark = 'origin'
    __back_marks = {}
    __mark_msg = {}
    def __init__(self, top, context_mgr, lgr):
        self.top = top
        self.context_mgr = context_mgr
        self.lgr = lgr
        self.track_num = 0
        self.ida_funs = None

    def setTrackNum(self):
        self.track_num += 1
        return self.track_num

    def setIdaFuns(self, ida_funs):
        self.ida_funs = ida_funs

    def clearMarks(self):
        self.lgr.debug('bookmarkMgr, clearMarks')
        self.__bookmarks = OrderedDict()
        self.__kernel_marks = []
        self.__back_marks = {}
        self.__mark_msg = {}

    def hasBookmarkDelta(self, delta):
        for mark in self.__bookmarks:
            delta_str = "cycle:%x" % delta
            if mark.strip().endswith(delta_str):
                return True
        return False

    def setBacktrackBookmark(self, mark, cpu=None, cycles=None, eip=None, steps=None, msg=None):
        mark = 'backtrack %d %s' % (self.track_num, mark)
        self.setDebugBookmark(mark, cpu=cpu, cycles=cycles, eip=eip, steps=steps, msg=msg)

    def setDebugBookmark(self, mark, cpu=None, cycles=None, eip=None, steps=None, msg=None):
        self.lgr.debug('setDebugBookmark mark: %s' % mark)
        if cpu is None: 
            dum, cpu = self.context_mgr.getDebugPid() 
        cell_name = self.top.getTopComponentName(cpu)
        steps = None
        if cycles is None:
            #current = SIM_cycle_count(cpu)
            #steps = SIM_step_count(cpu)
            current = cpu.cycles
            steps = cpu.steps
        else:
            current = cycles
            steps = steps
        #SIM_run_command('set-bookmark %s' % mark)
        #if not mark.startswith('protected_memory') and not mark.startswith('_start+1'):
     
        if eip is None: 
            eip = self.top.getEIP(cpu)

        if not mark.startswith('origin'):
            start_cycle = self.getCycle('origin')
            if start_cycle is None:
                self.lgr.debug('setDebugBookmark no origin')
                return
            delta = current - start_cycle
            if mark.startswith('protected_memory:') and self.hasBookmarkDelta(delta):
                self.lgr.debug('setDebugBookmark protected memory, return')
                return
            if self.ida_funs is not None:
                fun = self.ida_funs.getFunName(eip)
                if fun is not None:
                    mark = mark +" %s " % fun
            mark = mark+" cycle:%x" % delta
        cpl = memUtils.getCPL(cpu)
        if cpl == 0:
            self.__kernel_marks.append(mark)
            self.lgr.debug('setDebugBookmark, cpl0 for mark %s' % mark)
        elif mark in self.__kernel_marks:
            ''' replace kernel protected memory mark with one at syscall '''
            if mark.startswith('protected_memory'):
                self.__kernel_marks.remove(mark)
                del self.__bookmarks[mark]
            else:
                self.lgr.debug('setDebugBookmark %s already exists, do nothing' % mark)
                return
         
        self.__bookmarks[mark] = self.top.cycleRecord(current, steps, eip)
        self.__mark_msg[mark] = msg
        instruct = SIM_disassemble_address(cpu, eip, 1, 0)
        if not mark.startswith('protected_memory'):
            self.lgr.debug('setDebugBookmark %s cycle on %s is %x step:0x%x eip: %x %s' % (mark, cell_name, current, steps, eip, instruct[1]))
        self.lgr.debug('setDebugBookmark return')
        return mark

    def getCurrentCycle(self, cpu):
        start_cycle = self.getCycle('origin')
        if start_cycle is None:
            self.lgr.debug('setDebugBookmark no origin')
            return None
        delta = cpu.cycles - start_cycle
        return delta

    def getCycle(self, mark):
        real_mark = self.getDebugBookmark(mark)
        if real_mark is not None:
            return self.__bookmarks[real_mark].cycles
        else:
            return None

    def getStep(self, mark):
        if mark in self.__bookmarks:
            return self.__bookmarks[mark].steps
        else:
            return None

    def getEIP(self, mark):
        if mark in self.__bookmarks:
            return self.__bookmarks[mark].eip
        else:
            return None

    def isKernel(self, mark):
        if mark in self.__kernel_marks:
            return True
        else:
            return False

    def hasDebugBookmark(self, mark):
        got = self.getDebugBookmark(mark)
        if got is not None:
            return True
        else:
            return False

    def getDebugBookmark(self, mark):
        if mark in self.__bookmarks:
            return mark
        elif mark.startswith('protected_memory'):
            ''' special case to ignore cycle count in these bookmarks '''
            for bm in self.__bookmarks:
                if bm.startswith(mark):
                    return bm
            self.lgr.debug('getDebugBookmark, no mark starts with <%s>' % mark)
            return None
        else:
            return None

    def clearOtherBookmarksXX(self, keep_mark):
        prefix, suffix = keep_mark.split(':')
        if prefix is None or len(prefix) == 0:
            self.lgr.debug('clearOtherBookmarks called with bad prefix %s' % keep_mark)
            return
        copy = list(self.__bookmarks)
        for mark in copy:
            if mark != keep_mark and ':' in mark:
                t_prefix, dum = mark.split(':')
                if t_prefix == prefix: 
                    del self.__bookmarks[mark]

    def clearOtherBookmarks(self, prefix, keep_mark=None):
        copy = list(self.__bookmarks)
        for mark in copy:
            #if mark != keep_mark and ':' in mark:
            if mark.startswith(prefix): 
                if keep_mark is None or not mark.startswith(keep_mark):
                    del self.__bookmarks[mark]
            else:
                self.lgr.debug('clearOtherBookmarks skipping %s prefix %s keep %s' % (mark, prefix, keep_mark))

    def getSorted(self):
        retval = []
        d = OrderedDict()
        for mark in self.__bookmarks:
            d[self.__bookmarks[mark].cycles] = mark
        for cycle in sorted(d):
            retval.append(d[cycle])
            #print('%s 0x%x' % (d[cycle], cycle))

        return retval

    def listBookmarks(self):
        i = 0
        marks = self.getSorted()
        #for mark in self.__bookmarks:
        for mark in marks:
            #for mark in self.__bookmarks:
            i += 1
            print('%d : %s' % (i, mark))
        self.lgr.debug('listBookmarks done')
        print("<end of bookmarks>")

    def getBookmarks(self):
        return self.__bookmarks

    def goToDebugBookmark(self, mark):
        if type(mark) == int:
            self.lgr.debug('goToDebugBookmark skip to debug bookmark: %d' % mark)
            marks = self.getSorted()
            i = 0
            for the_mark in marks:
                i += 1
                if i == mark:
                    self.goToDebugBookmark(the_mark)
                    return 
        self.lgr.debug('goToDebugBookmark skip to debug bookmark: %s' % mark)
        if mark not in self.__bookmarks:
            self.lgr.error('goToDebugBookmark could not find cycle for mark %s' % mark)
            return
        sys.stderr = open('err.txt', 'w')
        dum, cpu = self.context_mgr.getDebugPid() 
        self.context_mgr.clearExitBreaks()
        start_cycle = self.getCycle('_start+1')
        done = False
        if self.top.SIMICS_BUG:
          while not done:
            SIM_run_command('pselect %s' % cpu.name)
            SIM_run_command('skip-to cycle = 0x%x' % start_cycle)
            cycles = SIM_cycle_count(cpu)
            self.lgr.debug('goToDebugBookmark, did skip to start at cycle %x, expected %x ' % (cycles, start_cycle))
            cycle = self.__bookmarks[mark].cycles
            self.lgr.debug("goToDebugBookmark, pslect then skip to 0x%x" % cycle)
            SIM_run_command('pselect %s' % cpu.name)
            SIM_run_command('skip-to cycle=%d' % cycle)
            eip = self.top.getEIP(cpu)
            current = SIM_cycle_count(cpu)
            step = SIM_step_count(cpu)
            self.lgr.debug('goToDebugBookmark skipped to cycle %x step: %x eip: %x, wanted cycle: %x step: %x eip: %x' % (current, step, eip, cycle, self.__bookmarks[mark].steps, self.__bookmarks[mark].eip))
            if current != cycle or eip != self.__bookmarks[mark].eip:
                self.lgr.error('goToDebugBookmark, simicsError skipped to cycle %x eip: %x, BUT WE wanted %x eip: 0x%x' % (current, eip, cycle, self.__bookmarks[mark].eip))
                ''' play simics ping pong until cycles match eip '''
                
            else:
                done = True
        else:
            cycle = self.__bookmarks[mark].cycles
            self.lgr.debug("goToDebugBookmark, pslect then skip to 0x%x" % cycle)
            SIM_run_command('pselect %s' % cpu.name)
            try:
                SIM_run_command('skip-to cycle=%d' % cycle)
            except:
                print('reverse disabled')
                return 'reverse disabled'
            eip = self.top.getEIP(cpu)
            current = SIM_cycle_count(cpu)
            step = SIM_step_count(cpu)
            if cycle is not None and self.__bookmarks[mark].steps is not None:
                self.lgr.debug('goToDebugBookmark skipped to cycle %x step: %x eip: %x, wanted cycle: %x step: %x eip: %x' % (current, step, eip, cycle, self.__bookmarks[mark].steps, self.__bookmarks[mark].eip))
            if current != cycle or eip != self.__bookmarks[mark].eip:
                self.lgr.error('goToDebugBookmark, simicsError skipped to cycle %x eip: %x, BUT WE wanted %x eip: 0x%x' % (current, eip, cycle, self.__bookmarks[mark].eip))
            

        self.context_mgr.setExitBreaks()
        self.context_mgr.resetBackStop()
        self.top.gdbMailbox('0x%x' % eip)
        self.lgr.debug('goToDebugBookmark set mbox to %x' % eip)
        return self.__mark_msg[mark]

    def goToOrigin(self):
        self.goToDebugBookmark(self.__origin_bookmark)
        return self.__mark_msg[self.__origin_bookmark]

    def skipToOrigin(self):
        dum, cpu = self.context_mgr.getDebugPid() 
        origin = self.__bookmarks[self.__origin_bookmark].cycles
        SIM_run_command('pselect %s' % cpu.name)
        SIM_run_command('skip-to cycle=%d' % origin)
        current = SIM_cycle_count(cpu)
        eip = self.top.getEIP(cpu)
        instruct = SIM_disassemble_address(cpu, eip, 1, 0)
        self.lgr.debug('skipToOrigin skip %x landed at %x, eip: %x %s' % (origin, current, eip, instruct[1]))

    def getFirstCycle(self):
        return self.__bookmarks['origin'].cycles

    def skipToFirst(self, cpu=None):
        # TBD NOT USED
        if cpu is None:
            dum, cpu = self.context_mgr.getDebugPid() 
        first = self.__bookmarks['_start+1'].cycles
        SIM_run_command('pselect %s' % cpu.name)
        SIM_run_command('skip-to cycle=%d' % first)
        current = SIM_cycle_count(cpu)
        step = SIM_step_count(cpu)
        eip = self.top.getEIP(cpu)
        instruct = SIM_disassemble_address(cpu, eip, 1, 0)
        self.lgr.debug('skipToFirst skip %x landed at %x step: 0x%x, eip: %x %s' % (first, current, step, 
            eip, instruct[1]))

    def setOrigin(self, cpu, msg=None):
        ''' Remove all other bookmarks and set the origin '''
        self.lgr.debug('bookmarkMgr setOrigin')
        self.clearMarks()
        self.__origin_bookmark = 'origin'
        im = self.context_mgr.getIdaMessage()
        if im is not None and '[' in im:
            self.__origin_bookmark = im[im.find('[')+1:im.find(']')]        
        self.__origin_bookmark = self.setDebugBookmark(self.__origin_bookmark, cpu=cpu, msg=msg)

    def mapOrigin(self, origin):
        for mark in self.__bookmarks:
            if mark.startswith(origin):
                self.__origin_bookmark = mark
                self.lgr.debug('bookmarkMgr mapOrigin now: %s' % mark)
                break 

    def getROPAddr(self):
        retval = None
        for mark in self.__bookmarks:
            if mark.strip().startswith('ROP'):
                pc_str = mark.strip().split()[6]
                retval = int(pc_str, 16)
                break
        return retval 

    def getSEGVAddr(self):
        retval = None
        for mark in self.__bookmarks:
            if mark.strip().startswith('SEGV'):
                addr_str =  mark.strip().split()[3]
                self.lgr.debug('bookmarks getSEGVAddr addr got %s' % addr_str)
                retval =  int(addr_str, 16)
                break
        return retval 

    def getFaultAddr(self):
        retval = None
        for mark in self.__bookmarks:
            if mark.strip().startswith('Unhandled fault'):
                addr_str =  mark.strip().split()[7]
                self.lgr.debug('bookmarks Unhandled fault addr got %s' % addr_str)
                retval =  int(addr_str, 16)
                break
        return retval 
