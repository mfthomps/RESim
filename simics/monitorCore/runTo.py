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
from simics import *
from resimHaps import *
import cli
import soMap
import stopFunction
import hapCleaner
import resimUtils
import memUtils
import glob
import os
''' TBD extend for multiple concurrent threads and multiple skip SO files '''
class Prec():
    def __init__(self, cpu, proc, tid=None, who=None):
        self.cpu = cpu
        self.proc = proc
        self.tid = tid
        self.who = who
        self.debugging = False
class RunTo():
    def __init__(self, top, cpu, cell, cell_name, task_utils, mem_utils, context_manager, so_map, trace_mgr, param, lgr):
        self.top = top
        self.cell = cell
        self.cell_name = cell_name
        self.cpu = cpu
        self.task_utils = task_utils
        self.mem_utils = mem_utils
        self.context_manager = context_manager
        self.so_map = so_map
        self.trace_mgr = trace_mgr
        self.param = param
        self.lgr = lgr
        self.stop_hap = None
        self.stop_action = None
        self.hap_list = []
        self.skip_list = []
        self.skip_dll = None
        self.skip_dll_others = []
        self.skip_dll_section = None
        self.skip_dll_other_section = []
        
        self.loadSkipList()
        
        self.cur_task_hap = None
        self.cur_task_break = None
        self.debug_group = False
        self.write_hap = None
        # just a cheap global used to reflect we are interested in any thread within the proc
        self.threads = False
        # for SO tracing
        self.want_tid = None
        self.so_haps = {}

    def stopHap(self, dumb, one, exception, error_string):
        if self.stop_hap is not None:
            eip = self.top.getEIP(self.cpu)
            self.lgr.debug('runTo stopHap ip: 0x%x stop_action %s' % (eip, str(self.stop_action)))
            hap = self.stop_hap
            self.top.RES_delete_stop_hap_run_alone(hap)
            self.stop_hap = None
            if self.stop_action is not None:
                self.stop_action.run()
            else:
                self.top.skipAndMail()

            '''

            if self.debug_group:
                self.context_manager.watchTasks(set_debug_tid=True)
            self.top.skipAndMail()
            self.top.RES_delete_stop_hap(self.stop_hap)
            self.stop_hap = None
            self.top.show()
            '''

    def rmHaps(self, and_then):
        if len(self.hap_list) > 0:
            self.lgr.debug('runTo rmHaps')
            for hap in self.hap_list:
                self.context_manager.genDeleteHap(hap, immediate=True)
            del self.hap_list[:]
            if and_then is not None:
                and_then()
                self.lgr.debug('runTo rmHaps back from and_then')

    def stopIt(self, dumb=None):
        self.lgr.debug('runTo stopIt')
        self.rmHaps(None)
        self.stop_hap = self.top.RES_add_stop_callback(self.stopHap, None)
        SIM_break_simulation('soMap')

    def knownHap(self, tid, the_obj, break_num, memory):
        if len(self.hap_list) > 0:
            cpu, comm, cur_tid = self.task_utils.curThread() 
            right_tid = False
            if self.threads:
                group_tids = self.task_utils.getGroupTids(tid)
                if cur_tid in group_tids: 
                    right_tid = True
            else:
                if cur_tid == tid:
                    right_tid = True
            if right_tid:
                value = memory.logical_address
                fname, start, end = self.so_map.getSOInfo(value)
                if fname is not None and start is not None:
                    self.lgr.debug('soMap knownHap tid:%s memory 0x%x %s start:0x%x end:0x%x' % (cur_tid, value, fname, start, end))
                else:
                    self.lgr.debug('soMap knownHap tid:%s memory 0x%x NO mapping file %s' % (cur_tid, value, fname))

                SIM_run_alone(self.stopIt, None)
            #else:
            #    self.lgr.debug('soMap knownHap wrong tid, wanted %d got %d' % (tid, cur_tid))

    def traceHap(self, start, the_obj, break_num, memory):
        if start not in self.so_haps or self.so_haps[start] is None:
            self.lgr.debug('runTo traceHap start 0x%x not in so_haps,bail' % start)
        else:
            cpu, comm, cur_tid = self.task_utils.curThread() 
            #self.lgr.debug('runTo traceHap start 0x%x addr 0x%x tid:%s want_tid:%s' % (start, memory.logical_address, cur_tid, self.want_tid))
            right_tid = False
            if self.threads:
                group_tids = self.task_utils.getGroupTids(self.want_tid)
                if cur_tid in group_tids: 
                    right_tid = True
            else:
                if cur_tid == self.want_tid:
                    right_tid = True
            if right_tid:
                value = memory.logical_address
                fname, start, end = self.so_map.getSOInfo(value)
                if fname is not None and start is not None:
                    if start not in self.so_haps:
                        self.lgr.debug('runTo traceHap start 0x%x not in so_haps' % start)
                    elif self.so_haps[start] is None:
                        self.lgr.debug('runTo traceHap start 0x%x in so_haps as None' % start)
                   
                    else:
                        self.lgr.debug('soMap traceHap tid:%s memory 0x%x %s start:0x%x end:0x%x' % (cur_tid, value, fname, start, end))
                        self.context_manager.genDeleteHap(self.so_haps[start])
                        self.so_haps[start] = None
                    
                else:
                    self.lgr.debug('soMap traceHap tid:%s memory 0x%x NO mapping file %s' % (cur_tid, value, fname))
            else:
                #self.lgr.debug('soMap traceHap tid:%s is not the right tid %s' % (cur_tid, self.want_tid))
                pass

        
    def runToKnown(self, skip=None, reset=False, threads=False):        
       self.threads = threads
       if reset:
           self.skip_list = []
       cpu, comm, cur_tid = self.task_utils.curThread() 
       code_section_list = self.so_map.getCodeSections(cur_tid)
       self.lgr.debug('runTo runToKnown tid:%s got %d code sections' % (cur_tid, len(code_section_list)))
       for section in code_section_list:
           if section.addr in self.skip_list:
               continue
           end = section.addr+section.size
           if skip is None or not (skip >= section.addr and skip <= end):
               proc_break = self.context_manager.genBreakpoint(None, Sim_Break_Linear, Sim_Access_Execute, section.addr, section.size, 0)
               self.hap_list.append(self.context_manager.genHapIndex("Core_Breakpoint_Memop", self.knownHap, cur_tid, proc_break, 'runToKnown'))
               self.lgr.debug('runTo runToKnown set break on 0x%x size 0x%x' % (section.addr, section.size))
           else:
               self.skip_list.append(section.addr)
               self.lgr.debug('soMap runToKnow, skip 0x%x' % (skip))
                
       if len(self.hap_list) > 0:  
           return True
       else:
           return False

    def loadSkipList(self):
        dll_skip = self.top.getCompDict(self.cell_name, 'DLL_SKIP')
        if dll_skip is not None:
            with open(dll_skip) as fh:
                for line in fh:
                    if line.startswith('#'):
                        continue
                    if self.skip_dll is None:
                        self.skip_dll = line.strip()
                    else:
                        self.skip_dll_others.append(line.strip())
            self.lgr.debug('runTo loadSkipList loaded %s with %d others' % (dll_skip, len(self.skip_dll_others)))
            print('Will attempt to skip syscalls from DLLs defined in %s' % (dll_skip))

    def watchSO(self):
        ''' Intended to be called prior to trace all starting in order to disable tracing of
            system calls made while still in a skipped dll '''
        self.lgr.debug('runTo watchSO')
        self.lgr.debug('watch SO trace_mgr is %s' % str(self.trace_mgr))
        self.trace_mgr.write('watching SO for skip dlls\n')
        if self.skip_dll is not None:
            self.so_map.addSOWatch(self.skip_dll, self.soLoadCallback)
            for dll in self.skip_dll_others:
                self.so_map.addSOWatch(dll, self.soLoadCallback)
           
    def soLoadCallback(self, section):
        ''' called by soMap or winDLLMap when a watched code file is loaded '''
        self.lgr.debug('runTo soLoadCallback fname: %s addr: 0x%x size 0x%x current_context %s' % (section.fname, section.load_addr, section.size, str(self.cpu.current_context)))
        if section.fname.endswith(self.skip_dll):
            self.skip_dll_section = soMap.CodeSection(section.load_addr, section.size, section.fname)
            self.breakOnSkip()
        else:
            other_section = soMap.CodeSection(section.load_addr, section.size, section.fname)
            self.skip_dll_other_section.append(other_section)


    def breakOnSkip(self):
        ''' Set breakpoint range on the DLL whose syscalls are to be skipped '''
        if self.skip_dll_section is not None:
           tid = self.task_utils.curTID()
           proc_break = self.context_manager.genBreakpoint(self.cpu.current_context, Sim_Break_Linear, Sim_Access_Execute, self.skip_dll_section.addr, self.skip_dll_section.size, 0)
           self.hap_list.append(self.context_manager.genHapIndex("Core_Breakpoint_Memop", self.skipHap, tid, proc_break, 'breakOnSkip'))
           self.lgr.debug('runTo breakOnSkip tid: %s breakOnSkip set break on main skip dll addr 0x%x current_context %s' % (tid, self.skip_dll_section.addr,
               str(self.cpu.current_context)))
        
    def skipHap(self, tid, the_obj, break_num, memory):
        ''' Hit the DLL whose syscalls are to be skipped '''
        if len(self.hap_list) > 0:
            cur_tid = self.task_utils.curTID()
            if cur_tid == tid:
                self.lgr.debug('runTo skipHap tid %s current_context %s' % (tid, str(self.cpu.current_context)))
                ''' remove haps and then set the breaks on all DLLs except the skip list '''
                SIM_run_alone(self.rmHaps, self.setSkipBreaks) 

    def setSkipBreaks(self):
        ''' Set breaks on all DLLs except unknown and ones whose syscalls are to be skipped
            and suspend the watch. '''
        self.skip_list = []
        self.skip_list.append(self.skip_dll_section.addr) 
        for other in self.skip_dll_other_section:
            self.skip_list.append(other.addr) 
        tid = self.task_utils.curTID()
        cpu, comm, cur_tid = self.task_utils.curThread() 
        code_section_list = self.so_map.getCodeSections(cur_tid)
        self.lgr.debug('runTo setSkipBreaks tid:%s got %d code sections current context: %s' % (tid, len(code_section_list), str(self.cpu.current_context)))
        self.context_manager.addSuspendWatch()
        msg = 'tid:%s (%s) Suspending syscall trace per dll_skip file current context %s\n' % (tid, comm, str(self.cpu.current_context))
        self.lgr.debug(msg)
        self.lgr.debug('trace_mgr is %s' % str(self.trace_mgr))
        self.trace_mgr.write(msg)
        self.trace_mgr.flush()
        context = self.cpu.current_context
        for section in code_section_list:
           if section.addr in self.skip_list:
               continue
           if section.fname == 'unknown':
               continue
           if section.size is None:
               self.lgr.debug('runto setSkipList size of section %s is None' % section.fname)
           elif section.addr is None:
               self.lgr.debug('runto setSkipList addr of section %s is None' % section.fname)
           else:
               end = section.addr+section.size
               proc_break = self.context_manager.genBreakpoint(context, Sim_Break_Linear, Sim_Access_Execute, section.addr, section.size, 0)
               self.hap_list.append(self.context_manager.genHapIndex("Core_Breakpoint_Memop", self.skipBreakoutHap, tid, proc_break, 'runToKnown'))
               self.lgr.debug('runTo setSkiplist set break on 0x%x size 0x%x context %s' % (section.addr, section.size, str(context)))

    def skipBreakoutHap(self, tid, the_obj, break_num, memory):
        ''' We hit a DLL whose syscalls are not to be skipped.  Restore debug context.  TBD modify to handle non-debug case as well
            perhaps using the ignore context?'''
        if len(self.hap_list) > 0:
            cur_tid = self.task_utils.curTID()
            self.lgr.debug('runTo skipBreakoutHap cur_tid %s' % cur_tid)
            if tid == cur_tid:
                eip = self.top.getEIP(self.cpu)
                self.lgr.debug('runTo skipBreakoutHap eip: 0x%x' % eip)
                self.context_manager.rmSuspendWatch()
                msg = 'tid:%s Restarting suspended syscall trace per dll_skip file\n' % (tid)
                self.trace_mgr.write(msg)
                self.trace_mgr.flush()
                self.lgr.debug(msg)
                SIM_run_alone(self.rmHaps, self.breakOnSkip)


    def inFlist(self, fun_list, the_list):
        for stop_fun in the_list:
            for fun in fun_list:
                if stop_fun.fun == fun:
                    return True
        return False

    def toRunningProc(self, proc, want_tid_list, flist, debug_group=False, final_fun=None):
        ''' intended for use when process is already running '''
        self.debug_group = debug_group
        cpu, comm, tid  = self.task_utils.curThread()
        ''' if already in proc, just attach debugger '''
        if want_tid_list is not None:
            self.lgr.debug('runTo toRunningProc, proc: %s run to tid_list %s, current tid:%s <%s>' % (proc, str(want_tid_list), tid, comm))
        else:
            self.lgr.debug('runTo toRunningProc, look for <%s>, current tid:%s <%s>' % (proc, tid, comm))
        if flist is not None and self.inFlist([self.top.debug, self.top.debugGroup], flist): 
            if not self.task_utils.isExitTid(tid):
                if proc is not None and proc == comm:
                    self.lgr.debug('runTo toRunningProc Already at proc %s, done' % proc)
                    hap_clean = hapCleaner.HapCleaner(cpu)
                    stop_action = hapCleaner.StopAction(hap_clean, flist=flist)
                    stop_action.run()
                    return
                elif want_tid_list is not None and tid in want_tid_list:
                    ''' TBD FIXME '''
                    self.lgr.debug('runTo toRunningProc already at tid:%s, done' % tid)
                    hap_clean = hapCleaner.HapCleaner(cpu)
                    if final_fun is not None:
                        f3 = stopFunction.StopFunction(final_fun, [], nest=False)
                        flist.append(f3)
                    stop_action = hapCleaner.StopAction(hap_clean, flist=flist)
                    stop_action.run()
                    return

        # *** SEE returns above ****
        ''' Set breakpoint on current_task to watch task switches '''
        prec = Prec(cpu, proc, want_tid_list)
        phys_current_task = self.task_utils.getPhysCurrentTask()
        self.cur_task_break = SIM_breakpoint(cpu.physical_memory, Sim_Break_Physical, Sim_Access_Write, 
                             phys_current_task, self.mem_utils.WORD_SIZE, 0)
        self.cur_task_hap = RES_hap_add_callback_index("Core_Breakpoint_Memop", self.runToProc, prec, self.cur_task_break)
        self.lgr.debug('runTo toRunningProc  want tids %s set break %d at 0x%x hap %d' % (str(want_tid_list), self.cur_task_break, phys_current_task,
            self.cur_task_hap))
        
        hap_clean = hapCleaner.HapCleaner(cpu)
        self.stop_action = hapCleaner.StopAction(hap_clean, breakpoints=[self.cur_task_break], flist=flist)

        status = self.top.is_monitor_running.isRunning()
        if not status:
            try:
                self.lgr.debug('runTo toRunningProc try continue')
                SIM_continue(0)
                pass
            except SimExc_General as e:
                print('ERROR... try continue?')
                self.lgr.error('runTo ERROR in toRunningProc  try continue? %s' % str(e))
                SIM_continue(0)
        else:
            self.lgr.debug('runTo toRunningProc thinks it is already running')
      
    def stopAlone(self, dumb=None): 
        self.stop_hap = self.top.RES_add_stop_callback(self.stopHap, None)
        SIM_run_alone(self.cleanToProcHaps, None)
        SIM_break_simulation('runTo stopAlone')

    def runToProc(self, prec, the_obj, break_num, memory):
        ''' callback when current_task is updated.  new value is in memory parameter '''
        if self.cur_task_hap is None:
            return

        cur_thread = memUtils.memoryValue(self.cpu, memory)
        self.lgr.debug('runToProc cur_thread 0x%x' % cur_thread)
        tid, comm = self.task_utils.getTidCommFromThreadRec(cur_thread)
        # prec_tid is a list
        self.lgr.debug('runToProc look for prec.proc %s prec.tid %s, the current tid is %s cycle: 0x%x' % (prec.proc, prec.tid, tid, self.cpu.cycles))
        if tid is not None and tid != 0:
            if (prec.tid is not None and tid in prec.tid) or (prec.tid is None and comm == prec.proc):
                self.lgr.debug('runTo runToProc got proc %s tid is %s  prec.tid is %s' % (comm, tid, prec.tid))
                SIM_run_alone(self.cleanToProcHaps, None)
                #SIM_run_alone(self.toUserAlone, tid)
                SIM_run_alone(self.top.stopAndCall, self.doStopAction)
            else:
                #self.proc_list[self.target][tid] = comm
                #self.lgr.debug('runToProc tid: %d proc: %s' % (tid, comm))
                pass

    def doStopAction(self, dumb=None):
        if self.stop_action is not None:
            flist = self.stop_action.flist
        if flist is not None and len(flist) > 0: 
            self.lgr.debug('runToProc doStopAction has flist')
            first_item = flist[0]
            if first_item.fun == self.top.toUser:
                self.top.toUser(flist = flist[1:])
            else: 
                for fun_item in flist:
                    self.lgr.debug('runToProc doStopAction fun %s' % fun_item.fun)
                    if len(fun_item.args) ==  0:
                        fun_item.fun()
                    else:
                        fun_item.fun(fun_item.args)
        else:
            self.lgr.debug('runToProc doStopAction NO flist, just run to user?')
            tid, comm = self.task_utils.getTidCommFromThreadRec(cur_thread)
            self.top.toUser(flist=None, want_tid=tid)


    def toUserAlone(self, tid):
        flist = None
        if self.stop_action is not None:
            flist = self.stop_action.flist
        self.top.toUser(flist=flist, want_tid=tid)
            
    def cleanToProcHaps(self, dumb):
        self.lgr.debug('cleantoProcHaps')
        if self.cur_task_break is not None:
            RES_delete_breakpoint(self.cur_task_break)
            self.cur_task_break = None
        if self.cur_task_hap is not None:
            RES_hap_delete_callback_id("Core_Breakpoint_Memop", self.cur_task_hap)
            self.cur_task_hap = None

    def isRunningTo(self):
        if self.cur_task_hap is not None:
            return True
        else:
            return False

    def setOriginWhenStopped(self):
        f1 = stopFunction.StopFunction(self.top.resetOrigin, [], nest=False)
        self.lgr.debug('runTo setOriginWhenStopped')
        self.stop_action.addFun(f1)

    def traceSO(self, threads=True):
        cpu, comm, cur_tid = self.task_utils.curThread() 
        self.lgr.debug('runTo traceSO tid:%s (%s)' % (cur_tid, comm))
        code_section_list = self.so_map.getCodeSections(cur_tid)
        self.want_tid = cur_tid
        for section in code_section_list:
            addr = section.addr
            proc_break = self.context_manager.genBreakpoint(None, Sim_Break_Linear, Sim_Access_Execute, addr, section.size, 0)
            hap = self.context_manager.genHapIndex("Core_Breakpoint_Memop", self.traceHap, section.addr, proc_break, 'traceSO')
            self.so_haps[section.addr] = hap
        self.lgr.debug('runTo traceSO set %d section breaks' % len(code_section_list))

    def runToMainSO(self, threads=False):
        self.lgr.debug('runTo runToMainSO thread: %r' % threads)
        main_dll_file = self.top.getCompDict(self.cell_name, 'MAIN_LIBS')
        if main_dll_file is not None:
            if os.path.isfile(main_dll_file):
                cpu, comm, cur_tid = self.task_utils.curThread() 
                main_dll_list = []
                with open(main_dll_file) as fh:
                    for line in fh:
                        main_dll_list.append(line.strip())
                self.lgr.debug('runTo runToMainSO got %d dlls in list' % len(main_dll_list))
                code_section_list = self.so_map.getCodeSections(cur_tid)
                dll_section_list = []
                for section in code_section_list:
                    if section.fname in main_dll_list: 
                        dll_section_list.append(section)
                self.setRunToSOBreak(dll_section_list)
                SIM_continue(0)
            else:
                self.lgr.error('runTo runToMainSO, no file at %s' % main_dll_file)
                

    def setRunToSOBreak(self, section_list):
       cpu, comm, cur_tid = self.task_utils.curThread() 
       hap_clean = hapCleaner.HapCleaner(self.cpu)
       f1 = stopFunction.StopFunction(self.top.skipAndMail, [], nest=False)
       self.stop_action = hapCleaner.StopAction(hap_clean, flist=[f1])
       for section in section_list:
           addr = section.addr
           proc_break = self.context_manager.genBreakpoint(None, Sim_Break_Linear, Sim_Access_Execute, addr, section.size, 0)
           self.hap_list.append(self.context_manager.genHapIndex("Core_Breakpoint_Memop", self.knownHap, cur_tid, proc_break, 'runToKnown'))

    def runToSO(self, fname, threads=False):        
       ''' run until the give SO/DLL file.  if not loaded, use soMap/winDLL to call us back when it is loaded'''
       ''' TBD need to update soMap.py'''
       self.threads = threads
       cpu, comm, cur_tid = self.task_utils.curThread() 
       code_section_list = self.so_map.getCodeSections(cur_tid)
       self.lgr.debug('runTo runToSO tid:%s got %d code sections' % (cur_tid, len(code_section_list)))
       got_one = False
       if threads:
           print('WARNING: this is a thread-local function.  If the application does an accept/fork you will miss it')
       for section in code_section_list:
           if section.addr in self.skip_list:
               continue
           if section.fname.lower().endswith(fname.lower()):
               #self.setRunToSOBreak(section.addr, section.size)
               self.setRunToSOBreak([section])
               self.lgr.debug('runTo runToSO set break on 0x%x size 0x%x' % (section.addr, section.size))
               got_one = True
               SIM_continue(0)
               break
       if not got_one:
           self.lgr.debug('runTo runToSO did not find SO %s, addSOWatch' % fname)
           self.so_map.addSOWatch(fname, self.soLoaded)    
           SIM_continue(0)
                
       if len(self.hap_list) > 0:  
           return True
       else:
           return False

    def soLoadedAlone(self, section):
        if type(section) is int:
            load_addr = section
            cpu, comm, cur_tid = self.task_utils.curThread() 
            code_section_list = self.so_map.getCodeSections(cur_tid)
            for this_section in code_section_list:
                if this_section.addr == load_addr:
                    section = this_section
                    break
            if type(section) is int:
                self.lgr.error('runTo soLoadedAlone sectoin stil int...')
             
        self.lgr.debug('runto soLoadedAlone file %s, call setRuntoSOBreak' % section.fname)
        self.setRunToSOBreak([section])
     
    def soLoaded(self, section):
        SIM_run_alone(self.soLoadedAlone, section)

    def runTo32(self):
        self.lgr.debug('runTo runto32')
        done = False
        if self.cpu.architecture != 'x86-64':
            self.lgr.error('runTo runTo32 only supported on x86-64')
            return
        max_loops = 10000
        loops = 0
        while not done:
            loops += 1
            ws = self.mem_utils.wordSize(self.cpu)
            if ws == 4:
                self.lgr.debug('runTo runTo32 ws is 4, done')
                print('Now in 32 bit mode')
                self.top.show()
                break
            else:
                cpl = memUtils.getCPL(self.cpu)
                if cpl == 0:
                    self.lgr.debug('runTo runTo32 in kernel, run to user')
                    f1 = stopFunction.StopFunction(self.runTo32, [], nest=False)
                    self.top.toUser([f1])
                    done = True
                else:
                    #next_cycle = self.cpu.cycles+1  
                    #self.lgr.debug('runTo runTo32 skip to 0x%x' % next_cycle)
                    #resimUtils.skipToTest(self.cpu, next_cycle, self.lgr)
                    cli.quiet_run_command('si')
            if loops > max_loops:
                self.lgr.error('runTo32 exceeded max of %d loops' % max_loops)
                break

    def runToWriteNotZero(self, addr):
       cpu, comm, cur_tid = self.task_utils.curThread() 
       proc_break = self.context_manager.genBreakpoint(None, Sim_Break_Linear, Sim_Access_Write, addr, 1, 0)
       self.write_hap = self.context_manager.genHapIndex("Core_Breakpoint_Memop", self.writeHap, cur_tid, proc_break, 'runToWrite')
       self.lgr.debug('runTo runToWriteNotZero set break on 0x%x' % addr)

    def writeHap(self, tid, the_obj, break_num, memory):
        if self.write_hap is not None:
            cpu, comm, cur_tid = self.task_utils.curThread() 
            if tid == cur_tid: 
                value = memUtils.memoryValue(self.cpu, memory)
                self.lgr.debug('runTo writeHap saw write, value 0x%x' % value)
                if value != 0:
                    SIM_break_simulation('writeHap')
                    hap = self.write_hap
                    SIM_run_alone(self.context_manager.genDeleteHap, hap)
                    self.lgr.debug('runTo writeHap did break simulation')
                    self.write_hap = None
