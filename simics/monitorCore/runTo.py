from simics import *
from resimHaps import *
import soMap
import stopFunction
import hapCleaner
import glob
''' TBD extend for multiple concurrent threads and multiple skip SO files '''
class Prec():
    def __init__(self, cpu, proc, pid=None, who=None):
        self.cpu = cpu
        self.proc = proc
        self.pid = pid
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
        self.hap_list = []
        self.skip_list = []
        self.skip_dll = None
        self.skip_dll_others = []
        self.skip_dll_section = None
        self.skip_dll_other_section = []
        
        self.loadSkipList()
        
        self.cur_task_hap = None
        self.cur_task_break = None

    def stopHap(self, dumb, one, exception, error_string):
        if self.stop_hap is not None:
            eip = self.top.getEIP(self.cpu)
            self.lgr.debug('soMap stopHap ip: 0x%x' % eip)
            self.top.skipAndMail()
            RES_hap_delete_callback_id("Core_Simulation_Stopped", self.stop_hap)
            self.stop_hap = None
            self.top.show()

    def rmHaps(self, and_then):
        if len(self.hap_list) > 0:
            self.lgr.debug('soMap rmHapsAlone')
            for hap in self.hap_list:
                self.context_manager.genDeleteHap(hap)
            del self.hap_list[:]
            if and_then is not None:
                and_then()

    def stopIt(self, dumb=None):
        SIM_run_alone(self.rmHaps, None)
        self.stop_hap = RES_hap_add_callback("Core_Simulation_Stopped", 
            	     self.stopHap, self.cpu)
        SIM_break_simulation('soMap')

    def knownHap(self, pid, third, forth, memory):
        if len(self.hap_list) > 0:
            cpu, comm, cur_pid = self.task_utils.curProc() 
            if pid == cur_pid: 
                value = memory.logical_address
                fname, start, end = self.so_map.getSOInfo(value)
                if fname is not None and start is not None:
                    self.lgr.debug('soMap knownHap pid:%d memory 0x%x %s start:0x%x end:0x%x' % (pid, value, fname, start, end))
                else:
                    self.lgr.debug('soMap knownHap pid:%d memory 0x%x NO mapping file %s' % (pid, value, fname))

                self.stopIt(None)                
            #else:
            #    self.lgr.debug('soMap knownHap wrong pid, wanted %d got %d' % (pid, cur_pid))
        
    def runToKnown(self, skip=None, reset=False):        
       if reset:
           self.skip_list = []
       cpu, comm, cur_pid = self.task_utils.curProc() 
       code_section_list = self.so_map.getCodeSections(cur_pid)
       self.lgr.debug('runTo runToKnown pid:%d got %d code sections' % (cur_pid, len(code_section_list)))
       for section in code_section_list:
           if section.addr in self.skip_list:
               continue
           end = section.addr+section.size
           if skip is None or not (skip >= section.addr and skip <= end):
               proc_break = self.context_manager.genBreakpoint(None, Sim_Break_Linear, Sim_Access_Execute, section.addr, section.size, 0)
               self.hap_list.append(self.context_manager.genHapIndex("Core_Breakpoint_Memop", self.knownHap, cur_pid, proc_break, 'runToKnown'))
               #self.lgr.debug('runTo runToKnown set break on 0x%x size 0x%x' % (section.addr, section.size))
           else:
               self.skip_list.append(section.addr)
               self.lgr.debug('soMap runToKnow, skip 0x%x' % (skip))
                
       if len(self.hap_list) > 0:  
           return True
       else:
           return False

    def loadSkipList(self):
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
        self.lgr.debug('runTo loadSkipList loaded %d others' % len(self.skip_dll_others))

    def watchSO(self):
        ''' Intended to be called prior to trace all starting in order to disable tracing of
            system calls made while still in a skipped dll '''
        self.lgr.debug('runToIO watchSO')
        if self.skip_dll is not None:
            self.so_map.addSOWatch(self.skip_dll, self.soLoadCallback)
            for dll in self.skip_dll_others:
                self.so_map.addSOWatch(dll, self.soLoadCallback)
           
    def soLoadCallback(self, fname, addr, size):
        ''' called by soMap or winDLLMap when a watched code file is loaded '''
        self.lgr.debug('runToIO soLoadCallback fname: %s addr: 0x%x size 0x%x' % (fname, addr, size))
        if fname.endswith(self.skip_dll):
            self.skip_dll_section = soMap.CodeSection(addr, size)
            self.breakOnSkip()
        else:
            other_section = soMap.CodeSection(addr, size)
            self.skip_dll_other_section.append(other_section)


    def breakOnSkip(self):
        ''' Set breakpoint range on the DLL whose syscalls are to be skipped '''
        if self.skip_dll_section is not None:
           pid_and_thread = self.task_utils.getPidAndThread()
           proc_break = self.context_manager.genBreakpoint(self.cpu.current_context, Sim_Break_Linear, Sim_Access_Execute, self.skip_dll_section.addr, self.skip_dll_section.size, 0)
           self.hap_list.append(self.context_manager.genHapIndex("Core_Breakpoint_Memop", self.skipHap, pid_and_thread, proc_break, 'breakOnSkip'))
           self.lgr.debug('runToIO pid-thread: %s breakOnSkip set break on main skip dll addr 0x%x' % (pid_and_thread, self.skip_dll_section.addr))
        
    def skipHap(self, pid_and_thread, third, forth, memory):
        ''' Hit the DLL whose syscalls are to be skipped '''
        if len(self.hap_list) > 0:
            if self.task_utils.matchPidThread(pid_and_thread):
                value = memory.logical_address
                ''' remove haps and then set the breaks on all DLLs except the skip list '''
                SIM_run_alone(self.rmHaps, self.setSkipBreaks) 

    def setSkipBreaks(self):
        ''' Set breaks on all DLLs except unknown and ones whose syscalls are to be skipped
            and suspend the watch. '''
        self.skip_list = []
        self.skip_list.append(self.skip_dll_section.addr) 
        for other in self.skip_dll_other_section:
            self.skip_list.append(other.addr) 
        pid_and_thread = self.task_utils.getPidAndThread()
        cpu, comm, cur_pid = self.task_utils.curProc() 
        code_section_list = self.so_map.getCodeSections(cur_pid)
        self.lgr.debug('runTo setSkipBreaks pid-thread:%s got %d code sections' % (pid_and_thread, len(code_section_list)))
        self.context_manager.addSuspendWatch()
        msg = 'pid:%s (%s) Suspending syscall trace per dll_skip file\n' % (pid_and_thread, comm)
        self.trace_mgr.write(msg)
        for section in code_section_list:
           if section.addr in self.skip_list:
               continue
           if section.fname == 'unknown':
               continue
           end = section.addr+section.size
           proc_break = self.context_manager.genBreakpoint(self.cpu.current_context, Sim_Break_Linear, Sim_Access_Execute, section.addr, section.size, 0)
           self.hap_list.append(self.context_manager.genHapIndex("Core_Breakpoint_Memop", self.skipBreakoutHap, pid_and_thread, proc_break, 'runToKnown'))
           #self.lgr.debug('runTo setSkiplist set break on 0x%x size 0x%x' % (section.addr, section.size))

    def skipBreakoutHap(self, pid_and_thread, third, forth, memory):
        ''' We hit a DLL whose syscalls are not to be skipped.  Restore debug context.  TBD modify to handle non-debug case as well
            perhaps using the ignore context?'''
        if len(self.hap_list) > 0:
            if self.task_utils.matchPidThread(pid_and_thread):
                eip = self.top.getEIP(self.cpu)
                self.lgr.debug('runTo skipBreakoutHap eip: 0x%x' % eip)
                self.context_manager.rmSuspendWatch()
                msg = 'pid:%s Restarting suspended syscall trace per dll_skip file\n' % (pid_and_thread)
                self.trace_mgr.write(msg)
                SIM_run_alone(self.rmHaps, self.breakOnSkip)


    def inFlist(self, fun_list, the_list):
        for stop_fun in the_list:
            for fun in fun_list:
                if stop_fun.fun == fun:
                    return True
        return False

    def toRunningProc(self, proc, want_pid_list, flist, debug_group=False, final_fun=None):
        ''' intended for use when process is already running '''
        cpu, comm, pid  = self.task_utils.curProc()
        ''' if already in proc, just attach debugger '''
        if want_pid_list is not None:
            self.lgr.debug('toRunningProc, run to pid_list %s, current pid %d <%s>' % (str(want_pid_list), pid, comm))
        else:
            self.lgr.debug('toRunningProc, look for <%s>, current pid %d <%s>' % (proc, pid, comm))
        if flist is not None and self.inFlist([self.top.debug, self.top.debugGroup], flist): 
            if pid != self.task_utils.getExitPid():
                if proc is not None and proc == comm:
                    self.lgr.debug('toRunningProc Already at proc %s, done' % proc)
                    f1 = stopFunction.StopFunction(self.top.debugExitHap, [], nest=False)
                    f2 = stopFunction.StopFunction(self.top.debug, [debug_group], nest=False)
                    self.toUser([f2, f1])
                    #self.debug()
                    return
                elif want_pid_list is not None and pid in want_pid_list:
                    ''' TBD FIXME '''
                    self.lgr.debug('toRunningProc already at pid %d, done' % pid)
                    f1 = stopFunction.StopFunction(self.top.debugExitHap, [], nest=False)
                    f2 = stopFunction.StopFunction(self.top.debug, [debug_group], nest=False)
                    if final_fun is not None:
                        f3 = stopFunction.StopFunction(final_fun, [], nest=False)
                        self.toUser([f2, f1, f3])
                    else:
                        self.toUser([f2, f1])
                    #self.debugGroup()
                    return
        ''' Set breakpoint on current_task to watch task switches '''
        prec = Prec(cpu, proc, want_pid_list)
        phys_current_task = self.task_utils.getPhysCurrentTask()
        self.cur_task_break = SIM_breakpoint(cpu.physical_memory, Sim_Break_Physical, Sim_Access_Write, 
                             phys_current_task, self.mem_utils.WORD_SIZE, 0)
        self.cur_task_hap = RES_hap_add_callback_index("Core_Breakpoint_Memop", self.runToProc, prec, self.cur_task_break)
        self.lgr.debug('toRunningProc  want pids %s set break %d at 0x%x hap %d' % (str(want_pid_list), self.cur_task_break, phys_current_task,
            self.cur_task_hap))
        
        hap_clean = hapCleaner.HapCleaner(cpu)
        #hap_clean.add("Core_Breakpoint_Memop", self.cur_task_hap)
        #stop_action = hapCleaner.StopAction(hap_clean, [self.cur_task_break], flist)
        stop_action = hapCleaner.StopAction(hap_clean, [], flist)
        self.stop_hap = RES_hap_add_callback("Core_Simulation_Stopped", 
        	     self.stopHap, stop_action)

        status = self.top.is_monitor_running.isRunning()
        if not status:
            try:
                self.lgr.debug('toRunningProc try continue')
                SIM_continue(0)
                pass
            except SimExc_General as e:
                print('ERROR... try continue?')
                self.lgr.error('ERROR in toRunningProc  try continue? %s' % str(e))
                SIM_continue(0)
        else:
            self.lgr.debug('toRunningProc thinks it is already running')
       

    def runToProc(self, prec, third, forth, memory):
        ''' callback when current_task is updated.  new value is in memory parameter '''
        if self.cur_task_hap is None:
            return
        cpu = prec.cpu
        cur_task_rec = SIM_get_mem_op_value_le(memory)

        win_thread = None
        if self.top.isWindows():
            win_thread = cur_task_rec
            ptr = cur_task_rec + self.param.proc_ptr
            cur_task_rec = self.mem_utils.readPtr(self.cpu, ptr)

        pid = self.mem_utils.readWord32(cpu, cur_task_rec + self.param.ts_pid)
        self.lgr.debug('runToProc look for %s pid is %d cycle: 0x%x' % (prec.proc, pid, self.cpu.cycles))
        if pid != 0:
            comm = self.mem_utils.readString(cpu, cur_task_rec + self.param.ts_comm, 16)
            if (prec.pid is not None and pid in prec.pid) or (prec.pid is None and comm == prec.proc):
                self.lgr.debug('got proc %s pid is %d  prec.pid is %s' % (comm, pid, str(prec.pid)))
                SIM_run_alone(self.cleanToProcHaps, None)
                SIM_break_simulation('found %s' % prec.proc)
            else:
                #self.proc_list[self.target][pid] = comm
                #self.lgr.debug('runToProc pid: %d proc: %s' % (pid, comm))
                pass
            
    def cleanToProcHaps(self, dumb):
        self.lgr.debug('cleantoProcHaps')
        if self.cur_task_break is not None:
            RES_delete_breakpoint(self.cur_task_break)
        if self.cur_task_hap is not None:
            RES_hap_delete_callback_id("Core_Breakpoint_Memop", self.cur_task_hap)
            self.cur_task_hap = None
