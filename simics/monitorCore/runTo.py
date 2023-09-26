from simics import *
from resimHaps import *
import soMap
import stopFunction
import hapCleaner
import resimUtils
import memUtils
import glob
''' TBD extend for multiple concurrent threads and multiple skip SO files '''
class Prec():
    def __init__(self, cpu, proc, tid=None, who=None):
        self.cpu = cpu
        self.proc = proc
        self.tid = tid
        self.who = who
        self.debugging = False
class RunTo():
    def __init__(self, top, cpu, cell, task_utils, mem_utils, context_manager, so_map, trace_mgr, param, lgr):
        self.top = top
        self.cell = cell
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

    def delStopHap(self, dumb):
        if self.stop_hap is not None:
            RES_hap_delete_callback_id("Core_Simulation_Stopped", self.stop_hap)
            self.stop_hap = None

    def stopHap(self, dumb, one, exception, error_string):
        if self.stop_hap is not None:
            eip = self.top.getEIP(self.cpu)
            self.lgr.debug('runTo stopHap ip: 0x%x' % eip)
            SIM_run_alone(self.delStopHap, None)
            if self.stop_action is not None:
                self.stop_action.run()
            else:
                self.top.skipAndMail()

            '''

            if self.debug_group:
                self.context_manager.watchTasks(set_debug_tid=True)
            self.top.skipAndMail()
            RES_hap_delete_callback_id("Core_Simulation_Stopped", self.stop_hap)
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
        self.stop_hap = RES_hap_add_callback("Core_Simulation_Stopped", 
            	     self.stopHap, None)
        SIM_break_simulation('soMap')

    def knownHap(self, tid, third, forth, memory):
        if len(self.hap_list) > 0:
            cpu, comm, cur_tid = self.task_utils.curThread() 
            if tid == cur_tid: 
                value = memory.logical_address
                fname, start, end = self.so_map.getSOInfo(value)
                if fname is not None and start is not None:
                    self.lgr.debug('soMap knownHap tid:%s memory 0x%x %s start:0x%x end:0x%x' % (tid, value, fname, start, end))
                else:
                    self.lgr.debug('soMap knownHap tid:%s memory 0x%x NO mapping file %s' % (tid, value, fname))

                SIM_run_alone(self.stopIt, None)
            #else:
            #    self.lgr.debug('soMap knownHap wrong tid, wanted %d got %d' % (tid, cur_tid))
        
    def runToKnown(self, skip=None, reset=False):        
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
               #self.lgr.debug('runTo runToKnown set break on 0x%x size 0x%x' % (section.addr, section.size))
           else:
               self.skip_list.append(section.addr)
               self.lgr.debug('soMap runToKnow, skip 0x%x' % (skip))
                
       if len(self.hap_list) > 0:  
           return True
       else:
           return False

    def loadSkipList(self):
        ''' TBD move to ini env variable '''
        flist = glob.glob('*.dll_skip')
        if len(flist) > 1:
            self.lgr.error('Found multiple dll_skip files, only one supported')
        elif len(flist) == 1:
            with open(flist[0]) as fh:
                for line in fh:
                    if line.startswith('#'):
                        continue
                    if self.skip_dll is None:
                        self.skip_dll = line.strip()
                    else:
                        self.skip_dll_others.append(line.strip())
            self.lgr.debug('runTo loadSkipList loaded %s with %d others' % (flist[0], len(self.skip_dll_others)))
            print('Will attempt to skip syscalls from DLLs defined in %s' % (flist[0]))

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
        self.lgr.debug('runTo soLoadCallback fname: %s addr: 0x%x size 0x%x current_context %s' % (section.fname, section.addr, section.size, str(self.cpu.current_context)))
        if section.fname.endswith(self.skip_dll):
            self.skip_dll_section = soMap.CodeSection(section.addr, section.size)
            self.breakOnSkip()
        else:
            other_section = soMap.CodeSection(section.addr, section.size)
            self.skip_dll_other_section.append(other_section)


    def breakOnSkip(self):
        ''' Set breakpoint range on the DLL whose syscalls are to be skipped '''
        if self.skip_dll_section is not None:
           tid = self.task_utils.curTID()
           proc_break = self.context_manager.genBreakpoint(self.cpu.current_context, Sim_Break_Linear, Sim_Access_Execute, self.skip_dll_section.addr, self.skip_dll_section.size, 0)
           self.hap_list.append(self.context_manager.genHapIndex("Core_Breakpoint_Memop", self.skipHap, tid, proc_break, 'breakOnSkip'))
           self.lgr.debug('runTo breakOnSkip tid: %s breakOnSkip set break on main skip dll addr 0x%x current_context %s' % (tid, self.skip_dll_section.addr,
               str(self.cpu.current_context)))
        
    def skipHap(self, tid, third, forth, memory):
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
           else:
               end = section.addr+section.size
               proc_break = self.context_manager.genBreakpoint(context, Sim_Break_Linear, Sim_Access_Execute, section.addr, section.size, 0)
               self.hap_list.append(self.context_manager.genHapIndex("Core_Breakpoint_Memop", self.skipBreakoutHap, tid, proc_break, 'runToKnown'))
               self.lgr.debug('runTo setSkiplist set break on 0x%x size 0x%x context %s' % (section.addr, section.size, str(context)))

    def skipBreakoutHap(self, tid, third, forth, memory):
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
            self.lgr.debug('runTo toRunningProc, run to tid_list %s, current tid:%s <%s>' % (str(want_tid_list), tid, comm))
        else:
            self.lgr.debug('runTo toRunningProc, look for <%s>, current tid:%s <%s>' % (proc, tid, comm))
        if flist is not None and self.inFlist([self.top.debug, self.top.debugGroup], flist): 
            if tid != self.task_utils.getExitTid():
                if proc is not None and proc == comm:
                    self.lgr.debug('runTo toRunningProc Already at proc %s, done' % proc)
                    hap_clean = hapCleaner.HapCleaner(cpu)
                    stop_action = hapCleaner.StopAction(hap_clean, [], flist)
                    stop_action.run()
                    return
                elif want_tid_list is not None and tid in want_tid_list:
                    ''' TBD FIXME '''
                    self.lgr.debug('runTo toRunningProc already at tid:%s, done' % tid)
                    hap_clean = hapCleaner.HapCleaner(cpu)
                    if final_fun is not None:
                        f3 = stopFunction.StopFunction(final_fun, [], nest=False)
                        flist.append(f3)
                    stop_action = hapCleaner.StopAction(hap_clean, [], flist)
                    stop_action.run()
                    return
        ''' Set breakpoint on current_task to watch task switches '''
        prec = Prec(cpu, proc, want_tid_list)
        phys_current_task = self.task_utils.getPhysCurrentTask()
        self.cur_task_break = SIM_breakpoint(cpu.physical_memory, Sim_Break_Physical, Sim_Access_Write, 
                             phys_current_task, self.mem_utils.WORD_SIZE, 0)
        self.cur_task_hap = RES_hap_add_callback_index("Core_Breakpoint_Memop", self.runToProc, prec, self.cur_task_break)
        self.lgr.debug('runTo toRunningProc  want tids %s set break %d at 0x%x hap %d' % (str(want_tid_list), self.cur_task_break, phys_current_task,
            self.cur_task_hap))
        
        hap_clean = hapCleaner.HapCleaner(cpu)
        self.stop_action = hapCleaner.StopAction(hap_clean, [], flist)

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
      
    def stopAlone(self, prec): 
        self.stop_hap = RES_hap_add_callback("Core_Simulation_Stopped", 
        	     self.stopHap, None)
        SIM_run_alone(self.cleanToProcHaps, None)
        SIM_break_simulation('found %s' % prec.proc)

    def runToProc(self, prec, third, forth, memory):
        ''' callback when current_task is updated.  new value is in memory parameter '''
        if self.cur_task_hap is None:
            return

        tid, comm = self.task_utils.getTidCommFromThreadRec(cur_task_rec)
        #self.lgr.debug('runToProc look for %s tid is %d cycle: 0x%x' % (prec.proc, tid, self.cpu.cycles))
        if tid is not None and tid != 0:
            if (prec.tid is not None and tid in prec.tid) or (prec.tid is None and comm == prec.proc):
                self.lgr.debug('runTo runToProc got proc %s tid is %s  prec.tid is %s' % (comm, tid, str(prec.tid)))
                SIM_run_alone(self.stopAlone, prec)
            else:
                #self.proc_list[self.target][tid] = comm
                #self.lgr.debug('runToProc tid: %d proc: %s' % (tid, comm))
                pass
            
    def cleanToProcHaps(self, dumb):
        self.lgr.debug('cleantoProcHaps')
        if self.cur_task_break is not None:
            RES_delete_breakpoint(self.cur_task_break)
        if self.cur_task_hap is not None:
            RES_hap_delete_callback_id("Core_Breakpoint_Memop", self.cur_task_hap)
            self.cur_task_hap = None

    def isRunningTo(self):
        if self.cur_task_hap is not None:
            return True
        else:
            return False

    def setOriginWhenStopped(self):
        f1 = stopFunction.StopFunction(self.top.setOrigin, [], nest=False)
        self.lgr.debug('runTo setOriginWhenStopped')
        self.stop_action.addFun(f1)

    def setRunToSOBreak(self, addr, size):
       cpu, comm, cur_tid = self.task_utils.curThread() 
       hap_clean = hapCleaner.HapCleaner(self.cpu)
       f1 = stopFunction.StopFunction(self.top.skipAndMail, [], nest=False)
       self.stop_action = hapCleaner.StopAction(hap_clean, [], [f1])
       end = addr+size
       proc_break = self.context_manager.genBreakpoint(None, Sim_Break_Linear, Sim_Access_Execute, addr, size, 0)
       self.hap_list.append(self.context_manager.genHapIndex("Core_Breakpoint_Memop", self.knownHap, cur_tid, proc_break, 'runToKnown'))

    def runToSO(self, fname):        
       ''' run until the give SO/DLL file.  if not loaded, use soMap/winDLL to call us back when it is loaded'''
       ''' TBD need to update soMap.py'''
       cpu, comm, cur_tid = self.task_utils.curThread() 
       code_section_list = self.so_map.getCodeSections(cur_tid)
       self.lgr.debug('runTo runToSO tid:%s got %d code sections' % (cur_tid, len(code_section_list)))
       got_one = False
       for section in code_section_list:
           if section.addr in self.skip_list:
               continue
           if section.fname.endswith(fname):
               self.setRunToSOBreak(section.addr, section.size)
               self.lgr.debug('runTo runToSO set break on 0x%x size 0x%x' % (section.addr, section.size))
               got_one = True
               SIM_continue(0)
               break
       if not got_one:
           self.so_map.addSOWatch(fname, self.soLoaded)    
           SIM_continue(0)
                
       if len(self.hap_list) > 0:  
           return True
       else:
           return False

    def soLoadedAlone(self, section):
        self.lgr.debug('runto soLoadedAlone file %s, call setRuntoSOBreak' % section.fname)
        self.setRunToSOBreak(section.addr, section.size)
     
    def soLoaded(self, section):
        SIM_run_alone(self.soLoadedAlone, section)

    def runTo32(self):
        self.lgr.debug('runTo runto32')
        done = False
        if self.cpu.architecture != 'x86-64':
            self.lgr.error('runTo runTo32 only supported on x86-64')
            return
        while not done:
            ws = self.mem_utils.wordSize(self.cpu)
            if ws == 4:
                self.lgr.debug('runTo runTo32 ws is 4, done')
                break
            cpl = memUtils.getCPL(self.cpu)
            if cpl == 0:
                self.lgr.debug('runTo runTo32 in kernel, run to user')
                f1 = stopFunction.StopFunction(self.runTo32, [], nest=False)
                self.top.toUser([f1])
                done = True
            else:
                next_cycle = self.cpu.cycles+1  
                #self.lgr.debug('runTo runTo32 skip to 0x%x' % next_cycle)
                resimUtils.skipToTest(self.cpu, next_cycle, self.lgr)
                

    def runToWriteNotZero(self, addr):
       cpu, comm, cur_tid = self.task_utils.curThread() 
       proc_break = self.context_manager.genBreakpoint(None, Sim_Break_Linear, Sim_Access_Write, addr, 1, 0)
       self.write_hap = self.context_manager.genHapIndex("Core_Breakpoint_Memop", self.writeHap, cur_tid, proc_break, 'runToWrite')
       self.lgr.debug('runTo runToWriteNotZero set break on 0x%x' % addr)

    def writeHap(self, tid, third, forth, memory):
        if self.write_hap is not None:
            cpu, comm, cur_tid = self.task_utils.curThread() 
            if tid == cur_tid: 
                value = SIM_get_mem_op_value_le(memory)
                self.lgr.debug('runTo writeHap saw write, value 0x%x' % value)
                if value != 0:
                    SIM_break_simulation('writeHap')
                    hap = self.write_hap
                    SIM_run_alone(self.context_manager.genDeleteHap, hap)
                    self.lgr.debug('runTo writeHap did break simulation')
                    self.write_hap = None
