from simics import *
from resimHaps import *
import soMap
import glob
''' TBD extend for multiple concurrent threads and multiple skip SO files '''
class RunTo():
    def __init__(self, top, cpu, cell, task_utils, context_manager, so_map, lgr):
        self.top = top
        self.cell = cell
        self.cpu = cpu
        self.task_utils = task_utils
        self.context_manager = context_manager
        self.so_map = so_map
        self.lgr = lgr
        self.stop_hap = None
        self.hap_list = []
        self.skip_list = []
        self.skip_dll = None
        self.skip_dll_others = []
        self.skip_dll_section = None
        self.skip_dll_other_section = []
        
        self.loadSkipList()
        

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
        self.lgr.debug('runToIO soLoadCallback fname: %s addr: 0x%x size 0x%x' % (fname, addr, size))
        if fname.endswith(self.skip_dll):
            self.skip_dll_section = soMap.CodeSection(addr, size)
            self.breakOnSkip()
        else:
            other_section = soMap.CodeSection(addr, size)
            self.skip_dll_other_section.append(other_section)


    def breakOnSkip(self):
        if self.skip_dll_section is not None:
           pid_and_thread = self.task_utils.getPidAndThread()
           proc_break = self.context_manager.genBreakpoint(None, Sim_Break_Linear, Sim_Access_Execute, self.skip_dll_section.addr, self.skip_dll_section.size, 0)
           self.hap_list.append(self.context_manager.genHapIndex("Core_Breakpoint_Memop", self.skipHap, pid_and_thread, proc_break, 'breakOnSkip'))
           self.lgr.debug('runToIO pid-thread: %s breakOnSkip set break on main skip dll addr 0x%x' % (pid_and_thread, self.skip_dll_section.addr))
        
    def skipHap(self, pid_and_thread, third, forth, memory):
        if len(self.hap_list) > 0:
            if self.task_utils.matchPidThread(pid_and_thread):
                value = memory.logical_address
                ''' remove haps and then set the breaks on all DLLs except the skip list '''
                SIM_run_alone(self.rmHaps, self.setSkipBreaks) 

    def setSkipBreaks(self):
        self.skip_list = []
        self.skip_list.append(self.skip_dll_section.addr) 
        for other in self.skip_dll_other_section:
            self.skip_list.append(other.addr) 
        pid_and_thread = self.task_utils.getPidAndThread()
        cpu, comm, cur_pid = self.task_utils.curProc() 
        code_section_list = self.so_map.getCodeSections(cur_pid)
        self.lgr.debug('runTo setSkipBreaks pid-thread:%s got %d code sections' % (pid_and_thread, len(code_section_list)))
        self.context_manager.addSuspendWatch()
        for section in code_section_list:
           if section.addr in self.skip_list:
               continue
           if section.fname == 'unknown':
               continue
           end = section.addr+section.size
           proc_break = self.context_manager.genBreakpoint(None, Sim_Break_Linear, Sim_Access_Execute, section.addr, section.size, 0)
           self.hap_list.append(self.context_manager.genHapIndex("Core_Breakpoint_Memop", self.skipBreakoutHap, pid_and_thread, proc_break, 'runToKnown'))
           self.lgr.debug('runTo setSkiplist set break on 0x%x size 0x%x' % (section.addr, section.size))

    def skipBreakoutHap(self, pid_and_thread, third, forth, memory):
        if len(self.hap_list) > 0:
            if self.task_utils.matchPidThread(pid_and_thread):
                eip = self.top.getEIP(self.cpu)
                self.lgr.debug('runTo skipBreakoutHap eip: 0x%x' % eip)
                self.context_manager.rmSuspendWatch()
                SIM_run_alone(self.rmHaps, self.breakOnSkip)
