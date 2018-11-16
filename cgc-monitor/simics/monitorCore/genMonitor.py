
from simics import *
import os
import utils
import linuxParams
import memUtils
#import kernelInfo
#import linuxProcessUtils
import taskUtils
import genContextMgr
import bookmarkMgr
import isMonitorRunning
import reverseToCall
import reverseToAddr
import pFamily
import traceOpen
import pageFaultGen
import hapCleaner
import reverseToUser
import findKernelWrite
import syscall
import traceProcs
import cloneChild
import soMap
import elfText

target = 'VDR'
class cellConfig():
    cells = {}
    cell_cpu = {}
    cell_cpu_list = {}
    cell_context = {}
    def __init__(self):
        self.loadCellObjects()

    def loadCellObjects(self):
        first_box = target 
        self.cells[first_box] = 'vdr host'
        for cell_name in self.cells:
            obj = SIM_get_object(cell_name)
            self.cell_context[cell_name] = obj.cell_context

        for cell_name in self.cells:
            cmd = '%s.get-processor-list' % cell_name
            proclist = SIM_run_command(cmd)
            self.cell_cpu[cell_name] = SIM_get_object(proclist[0])
            self.cell_cpu_list[cell_name] = []
            for proc in proclist:
                self.cell_cpu_list[cell_name].append(SIM_get_object(proc))
    def cpuFromCell(self, cell_name):
        ''' simplification for single-core sims '''
        return self.cell_cpu[cell_name]

class Prec():
    def __init__(self, cpu, proc, pid=None):
        self.cpu = cpu
        self.proc = proc
        self.pid = pid
        self.debugging = False

class GenMonitor():
    SIMICS_BUG=False
    PAGE_SIZE = 4096
    def __init__(self):
        self.param = None
        self.mem_utils = None
        #self.os_p_utils = None
        self.task_utils = None
        self.cur_task = {}
        self.bs = []
        self.proc_hap = None
        self.stop_proc_hap = None
        self.proc_break = None
        self.gdb_mailbox = None
        self.stop_hap = None
        self.log_dir = '/tmp/'
        self.mode_hap = None
        self.hack_list = []
        self.genInit()
        self.traceOpen = None
        self.sysenter_cycles = []
        self.trace_fh = None
        self.so_map = None
        self.call_traces = {}

    def genInit(self):
        '''
        remove all previous breakpoints.  
        '''
        self.lgr = utils.getLogger('noname', os.path.join(self.log_dir, 'monitors'))
        self.is_monitor_running = isMonitorRunning.isMonitorRunning(self.lgr)
        SIM_run_command("delete -all")
        self.cell_config = cellConfig()
        self.lgr.debug('New log, in genInit')
        self.param = linuxParams.linuxParams()
        self.mem_utils = memUtils.memUtils(4, self.param)
        OS_TYPE = os.getenv('CGC_OS_TYPE')

    def getTopComponentName(self, cpu):
         if cpu is not None:
             names = cpu.name.split('.')
             return names[0]
         else:
             return None

    def modeChanged(self, cpu, one, old, new):
        cpl = memUtils.getCPL(cpu)
        eip = self.mem_utils.getRegValue(cpu, 'eip')
        self.lgr.debug('mode changed cpl reports %d trigger_obj is %s old: %d  new: %d  eip: 0x%x' % (cpl, str(one), old, new, eip))
        SIM_break_simulation('mode changed, break simulation')
        
    def stopHap(self, stop_action, one, exception, error_string):
        if stop_action is None or stop_action.hap_clean is None:
            print('stopHap error, stop_action None?')
            return 
        self.lgr.debug('stopHap cycle: 0x%x' % stop_action.hap_clean.cpu.cycles)
        for hc in stop_action.hap_clean.hlist:
            if hc.hap is not None:
                if hc.htype == 'GenContext':
                    self.lgr.debug('will delete GenContext hap %s' % str(hc.hap))
                    self.context_manager.genDeleteHap(hc.hap)
                else:
                    self.lgr.debug('will delete hap %s' % str(hc.hap))
                    SIM_hap_delete_callback_id(hc.htype, hc.hap)
                hc.hap = None
        if self.stop_hap is not None:
            self.lgr.debug('will delete hap %s' % str(self.stop_hap))
            SIM_hap_delete_callback_id("Core_Simulation_Stopped", self.stop_hap)
            self.stop_hap = None
            for bp in stop_action.breakpoints:
                SIM_delete_breakpoint(bp)
            ''' check functions in list '''
            if len(stop_action.flist) > 0:
                fun = stop_action.flist.pop(0)
                fun(stop_action.flist) 

    def run2Kernel(self, cpu):
        cpl = memUtils.getCPL(cpu)
        if cpl != 0:
            self.lgr.debug('run2Kernel in user space (%d), set hap' % cpl)
            self.mode_hap = SIM_hap_add_callback_obj("Core_Mode_Change", cpu, 0, self.modeChanged, cpu)
            hap_clean = hapCleaner.HapCleaner(cpu)
            hap_clean.add("Core_Mode_Change", self.mode_hap)
            stop_action = hapCleaner.StopAction(hap_clean, None)
            self.stop_hap = SIM_hap_add_callback("Core_Simulation_Stopped", 
        	     self.stopHap, stop_action)
            SIM_continue(0)
        else:
            self.lgr.debug('run2Kernel, already in kernel')

    def run2User(self, cpu, flist=None):
        cpl = memUtils.getCPL(cpu)
        if cpl == 0:
            self.lgr.debug('run2User in kernel space (%d), set hap' % cpl)
            self.mode_hap = SIM_hap_add_callback_obj("Core_Mode_Change", cpu, 0, self.modeChanged, cpu)
            hap_clean = hapCleaner.HapCleaner(cpu)
            hap_clean.add("Core_Mode_Change", self.mode_hap)
            stop_action = hapCleaner.StopAction(hap_clean, None, flist)
            self.stop_hap = SIM_hap_add_callback("Core_Simulation_Stopped", 
        	     self.stopHap, stop_action)
            SIM_run_alone(SIM_run_command, 'continue')
        else:
            self.lgr.debug('run2User, already in user')
            if flist is not None and len(flist) == 1:
                flist[0]()

    def findCurrentTaskAddr(self, cpu, cur_task):
        ''' Look for the Linux data address corrsponding to the current_task symbol 
            Use the current task as determined by stack-fu, and then look for that
            starting at 0xc2000000.  Empirical results suggest the second such address
            is the first one to be updated on a task switch.
        '''
        #self.run2Kernel(cpu)
        start = 0xc2000000
        addr = start
        got_count = 0
        for i in range(8000000):
            val = self.mem_utils.readPtr(cpu, addr)
            if val is None:
                return None
            if val == cur_task:
                self.lgr.debug('got match at addr: 0x%x' % addr)
                got_count += 1
                break
            if got_count == 2:
                break
            #print('got 0x%x from 0x%x' % (val, addr))
            addr += 4
        self.lgr.debug('final addr is 0x%x' % addr)
        return addr
        
    def doInit(self):
        cpu = self.cell_config.cpuFromCell(target)
        ''' get cur_task_rec using stack fu '''
        pid = 0
        while pid == 0: 
            ''' run until we get something sane '''
            cur_task_rec = self.mem_utils.getCurrentTask(self.param, cpu)
            while cur_task_rec is None:
                cur_task_rec = self.mem_utils.getCurrentTask(self.param, cpu)
                if cur_task_rec is None:
                    #print('nope, continue')
                    SIM_continue(900000000)
                else:
                    SIM_break_simulation('Enough boot to get cur_task_rec')
                
            pid = self.mem_utils.readWord32(cpu, cur_task_rec + self.param.ts_pid)
            if pid == 0:
                print('pid was zero, try again')
                SIM_continue(900000000)
        
        if self.param.current_task is None:    
            comm = self.mem_utils.readString(cpu, cur_task_rec + self.param.ts_comm, 16)
            self.lgr.debug('doInit find current task symbol, curr_task_rec is 0x%x comm: %s' % (cur_task_rec, comm))
            ''' use brute force to get the current_task symbol address '''
            current_task = self.findCurrentTaskAddr(cpu, cur_task_rec)
        else:
            current_task = self.param.current_task
        if current_task is None:
            print('Could not read kernel memory looking for current_task')
            return
        else: 
            self.cur_task[cpu] = current_task
        self.lgr.debug('cur_task for cpu %s is 0x%x' % (cpu.name, self.cur_task[cpu]))

        my_cur_task_rec = self.mem_utils.readPtr(cpu, self.cur_task[cpu])
        self.lgr.debug('stack based rec was 0x%x  mine is 0x%x' % (cur_task_rec, my_cur_task_rec))

        self.task_utils = taskUtils.TaskUtils(cpu, self.param, self.mem_utils, current_task, self.lgr)
        self.context_manager = genContextMgr.GenContextMgr(self, self.task_utils, self.lgr) 
        #self.bookmarks = bookmarkMgr.bookmarkMgr(self, self.context_manager, self.lgr)
        self.bookmarks = {}
        ''' hack os_utils fu '''
        os_p_utils = {}
        os_p_utils[target] = self.task_utils 
        self.rev_to_call = reverseToCall.reverseToCall(self, self.param, os_p_utils,
                 self.PAGE_SIZE, self.context_manager, 'revToCall', self.is_monitor_running, None, self.log_dir)
        #self.os_p_utils = linuxProcessUtils.linuxProcessUtils(self, 'thrower', self.param,
        #            self.cell_config, None, None, self.cur_task[cpu], self.mem_utils, self.lgr, False)
        self.pfamily = pFamily.Pfamily(target, self.param, self.cell_config, self.mem_utils, self.task_utils, self.lgr)
        self.page_faults = pageFaultGen.PageFaultGen(target, self.param, self.cell_config, self.mem_utils, self.task_utils, self.lgr)
        cell = self.cell_config.cell_context[target]
        self.traceOpen = traceOpen.TraceOpen(self.param, self.mem_utils, self.task_utils, cpu, cell, self.lgr)
        self.traceProcs = traceProcs.TraceProcs(self.lgr)
        self.soMap = soMap.SOMap(self.lgr)
        
    def tasks(self):
        tasks = self.task_utils.getTaskStructs()
        for t in tasks:
            print('pid: %d taks_rec: 0x%x  comm: %s children 0x%x 0x%x' % (tasks[t].pid, t, tasks[t].comm, tasks[t].children[0], tasks[t].children[1]))


    def setDebugBookmark(self, mark, cpu=None, cycles=None, eip=None, steps=None):
        pid, cell_name, cpu = self.context_manager.getDebugPid() 
        self.bookmarks[pid].setDebugBookmark(mark, cpu=cpu, cycles=cycles, eip=eip, steps=steps)

    def debug(self, dumb=None):
        self.stopTrace()    
        pid, cell_name, cpu = self.context_manager.getDebugPid() 
        if pid is None:
            ''' Our first debug '''
            port = 9123 
            cpu, comm, pid = self.task_utils.curProc() 
            self.lgr.debug('debug for cpu %s port will be %d.  Pid is %d' % (cpu.name, port, pid))
            self.context_manager.setDebugPid(pid, target, cpu)
            cmd = 'new-gdb-remote cpu=%s architecture=x86 port=%d' % (cpu.name, port)
            SIM_run_command(cmd)
            cmd = 'enable-reverse-execution'
            SIM_run_command(cmd)
            self.bookmarks[pid] = bookmarkMgr.bookmarkMgr(self, self.context_manager, self.lgr)
            self.setDebugBookmark('_start+1', cpu)
            self.bookmarks[pid].setOrigin(cpu)
            ''' tbd read elf and pass executable pages? NO, would not determine other executable pages '''
            self.rev_to_call.setup(cpu, [], bookmarks=self.bookmarks[pid])
            self.context_manager.watchTasks()
        else:
            ''' already debugging.  change to current process '''
            cpu, comm, pid = self.task_utils.curProc() 
            self.lgr.debug('debug, already debugging, change process pid to %d' % pid)
            self.context_manager.setDebugPid(pid, target, cpu)
            if pid not in self.bookmarks:
                self.bookmarks[pid] = bookmarkMgr.bookmarkMgr(self, self.context_manager, self.lgr)
                self.bookmarks[pid].setOrigin(cpu)
            self.rev_to_call.setup(cpu, [], bookmarks=self.bookmarks[pid])
            self.context_manager.watchTasks()


    def show(self):
        cpu, comm, pid = self.task_utils.curProc() 
        cpl = memUtils.getCPL(cpu)
        eip = self.getEIP(cpu)
        print('cpu.name is %s PL: %d pid: %d(%s) EIP: 0x%x   current_task symbol at 0x%x' % (cpu.name, cpl, pid, comm, eip, self.cur_task[cpu]))
        pfamily = self.pfamily.getPfamily()
        tabs = ''
        while len(pfamily) > 0:
            prec = pfamily.pop()
            print('%s%5d  %s' % (tabs, prec.pid, prec.proc))
            tabs += '\t'



    def signalHap(self, signal_info, one, exception_number):
        cpu, comm, pid = self.task_utils.curProc() 
        if signal_info.callnum is None:
            if exception_number in self.hack_list:
                return
            else:
               self.hack_list.append(exception_number)
        if signal_info.pid is not None:
            if pid == signal_info.pid:
                SIM_break_simulation('signal %d' % exception_number)
                self.lgr.debug('signalHap from %d (%s) signal 0x%x at 0x%x' % (pid, comm, exception_number, self.getEIP(cpu)))
        else: 
           SIM_break_simulation('signal %d' % exception_number)
           self.lgr.debug('signalHap from %d (%s) signal 0x%x at 0x%x' % (pid, comm, exception_number, self.getEIP(cpu)))
         

    def int80Hap(self, cpu, one, exception_number):
        cpu, comm, pid = self.task_utils.curProc()
        eax = self.mem_utils.getRegValue(cpu, 'eax')
        self.lgr.debug('int80Hap in proc %d (%s), eax: 0x%x' % (pid, comm, eax))
        self.lgr.debug('syscall 0x%d from %d (%s) at 0x%x ' % (eax, pid, comm, self.getEIP(cpu)))
        SIM_break_simulation('syscall')
        print('use si to get address of syscall entry, and further down look for computed call')

    def runToSyscall80(self):
        cpu = self.cell_config.cpuFromCell(target)
        self.lgr.debug('runToSyscall80') 
        self.scall_hap = SIM_hap_add_callback_obj_index("Core_Exception", cpu, 0,
                 self.int80Hap, cpu, 0x180) 
        hap_clean = hapCleaner.HapCleaner(cpu)
        hap_clean.add("Core_Exception", self.scall_hap)
        stop_action = hapCleaner.StopAction(hap_clean, [], None)
        self.stop_hap = SIM_hap_add_callback("Core_Simulation_Stopped", 
        	     self.stopHap, stop_action)
        status = self.is_monitor_running.isRunning()
        if not status:
            SIM_run_command('c')

    def runToSignal(self, signal=None, pid=None):
        cpu = self.cell_config.cpuFromCell(target)
        self.lgr.debug('runToSignal, signal given is %s' % str(signal)) 

        sig_info = syscall.SyscallInfo(cpu, pid, signal)
        #max_intr = 31
        max_intr = 1028
        if signal is None:
            sig_hap = SIM_hap_add_callback_obj_range("Core_Exception", cpu, 0,
                     self.signalHap, sig_info, 0, max_intr) 
        else:
            sig_hap = SIM_hap_add_callback_obj_index("Core_Exception", cpu, 0,
                     self.signalHap, sig_info, signal) 

        hap_clean = hapCleaner.HapCleaner(cpu)
        hap_clean.add("Core_Exception", sig_hap)
        stop_action = hapCleaner.StopAction(hap_clean, [], None)
        self.stop_hap = SIM_hap_add_callback("Core_Simulation_Stopped", 
        	     self.stopHap, stop_action)
        status = self.is_monitor_running.isRunning()
        if not status:
            SIM_run_command('c')

    def execToText(self, flist=None):
        ''' assuming we are in an exec system call, run until execution enters the
            the .text section per the elf header in the file that was execed.'''
        cpu, comm, pid  = self.task_utils.curProc()
        prog_name, dumb = self.task_utils.getProgName(pid) 
        full_path = os.path.join(self.param.root_prefix, prog_name[1:])
        self.lgr.debug('execToText, prefix is %s progname is %s  full: %s' % (self.param.root_prefix, prog_name, full_path))
        text_s, size_s = elfText.getText(full_path)
        text = int(text_s, 16)
        size = int(size_s, 16)
        self.lgr.debug('text 0x%x size 0x%x' % (text, size))       
        self.context_manager.recordText(text, text+size)
        self.runToText(flist)

    def debugProc(self, proc):
        plist = self.task_utils.getPidsForComm(proc)
        if len(plist) > 0:
            self.lgr.debug('debugProc process %s found, run until some instance is scheduled' % proc)
            flist = [self.toUser, self.debug]
            self.toProc(proc, None, flist)
        else:
            self.lgr.debug('debugProc no process %s found, run until execve' % proc)
            #flist = [self.toUser, self.debug]
            flist = [self.execToText, self.debug]
            self.toExecve(proc, flist=flist)

    def debugPid(self, pid):
        self.lgr.debug('debugPid for %d' % pid)
        flist = [self.toUser, self.debug]
        self.toProc(None, pid, flist)

    def changedThread(self, cpu, third, forth, memory):
        cur_task_rec = self.mem_utils.readPtr(cpu, self.cur_task[cpu])
        pid = self.mem_utils.readWord32(cpu, cur_task_rec + self.param.ts_pid)
        if pid != 0:
            print('changedThread')
            self.show()

    def runToProc(self, prec, third, forth, memory):
        ''' callback when current_task is updated.  new value is in memory parameter '''
        cpu = prec.cpu
        #cur_task_rec = self.mem_utils.readPtr(cpu, self.cur_task[cpu])
        cur_task_rec = SIM_get_mem_op_value_le(memory)
        pid = self.mem_utils.readWord32(cpu, cur_task_rec + self.param.ts_pid)
        if pid != 0:
            if prec.pid is not None:
                self.lgr.debug('runToProc pid is %d, look for %d' % (pid, prec.pid))
            comm = self.mem_utils.readString(cpu, cur_task_rec + self.param.ts_comm, 16)
            if (prec.pid is not None and prec.pid == pid) or (prec.pid is None and comm == prec.proc):
                self.lgr.debug('got proc %s pid is %d' % (comm, pid))
                SIM_break_simulation('found %s' % prec.proc)
            else:
                if comm not in self.bs:
                    self.bs.append(comm)
                    print('pid: %d proc: %s' % (pid, comm))
            
       
    def toUser(self, flist=None): 
        cpu = self.cell_config.cpuFromCell(target)
        self.run2User(cpu, flist)

    def runToUserSpace(self):
        self.lgr.debug('runToUserSpace')
        self.is_monitor_running.setRunning(True)
        flist = [self.skipAndMail]
        self.toUser(flist)

    def toKernel(self): 
        cpu = self.cell_config.cpuFromCell(target)
        self.run2Kernel(cpu)

    def toProcPid(self, pid):
        self.toProc(None, pid, None)

    def toProc(self, proc, want_pid=None, flist=None):
        cpu, comm, pid  = self.task_utils.curProc()
        ''' if already in proc, just attach debugger '''
        if self.debug in flist: 
            if proc is not None and proc == comm:
                self.lgr.debug('Already at proc %s, done' % proc)
                self.debug()
                return
            elif want_pid is not None and pid == want_pid:
                self.lgr.debug('Already at pid %d, done' % want_pid)
                self.debug()
                return
        self.lgr.debug('toProc current_task is 0x%x  pid %s ' % (self.cur_task[cpu], str(want_pid)))
        cell = self.cell_config.cell_context[target]
        prec = Prec(cpu, proc, want_pid)
        if want_pid is not None:
            self.lgr.debug('toProc, pid %d prec.pid %d' % (want_pid, prec.pid))
        else:
            self.lgr.debug('pid is None')
        proc_break = SIM_breakpoint(cell, Sim_Break_Linear, Sim_Access_Write, self.cur_task[cpu], self.mem_utils.WORD_SIZE, 0)
        self.proc_hap = SIM_hap_add_callback_index("Core_Breakpoint_Memop", self.runToProc, prec, proc_break)
        
        hap_clean = hapCleaner.HapCleaner(cpu)
        hap_clean.add("Core_Breakpoint_Memop", self.proc_hap)
        stop_action = hapCleaner.StopAction(hap_clean, [proc_break], flist)
        #self.stop_proc_hap = SIM_hap_add_callback("Core_Simulation_Stopped", 
        #	     self.stoppedToProc, fun_list)
        self.stop_hap = SIM_hap_add_callback("Core_Simulation_Stopped", 
        	     self.stopHap, stop_action)
        status = self.is_monitor_running.isRunning()
        if not status:
            SIM_run_command('c')
       
    def setCurTaskHap(self):
        cpu = self.cell_config.cpuFromCell(target)
        self.lgr.debug('setBreaks current_task is 0x%x   ' % (self.cur_task[cpu]))
        cell = self.cell_config.cell_context[target]
        code_break_num = SIM_breakpoint(cell, Sim_Break_Linear, Sim_Access_Write, self.cur_task[cpu], self.mem_utils.WORD_SIZE, 0)
        cb_num = SIM_hap_add_callback_index("Core_Breakpoint_Memop", 
               self.changedThread, cpu, code_break_num)

    def getEIP(self, cpu=None):
        if cpu is None:
            dum, dum2, cpu = self.context_manager.getDebugPid() 
            if cpu is None:
                cpu = self.cell_config.cpuFromCell(target)
        eip = self.mem_utils.getRegValue(cpu, 'eip')
        return eip
        
    class cycleRecord():
        def __init__(self, cycles, steps, eip):
            self.cycles = cycles
            self.steps = steps
            self.eip = eip
        def toString(self):
            if self.steps is not None:
                return 'cycles: 0x%x steps: 0x%x eip: 0x%x' % (self.cycles, self.steps, self.eip)
            else:
                return 'cycles: 0x%x (no steps recorded) eip: 0x%x' % (self.cycles, self.eip)

    def gdbMailbox(self, msg):
        self.gdb_mailbox = msg
        self.lgr.debug('in gdbMailbox msg set to <%s>' % msg)
        print('gdbMailbox:%s' % msg)

    def emptyMailbox(self):
        if self.__gdb_mailbox is not None and self.__gdb_mailbox != "None":
            print self.__gdb_mailbox
            self.lgr.debug('emptying mailbox of <%s>' % self.__gdb_mailbox)
            self.__gdb_mailbox = None

    def runSkipAndMailAlone(self, cycles): 
        pid, dum2, cpu = self.context_manager.getDebugPid() 
        if cpu is None:
            self.lgr.error("no cpu in runSkipAndMailAlone")
            return
        current = cpu.cycles
        eip = self.getEIP(cpu)
        instruct = SIM_disassemble_address(cpu, eip, 1, 0)
        self.lgr.debug('skipAndMailAlone current cycle is %x eip: %x %s requested %d cycles' % (current, eip, instruct[1], cycles))
        if cycles > 0:
            previous = current - cycles 
            start = self.bookmarks[pid].getCycle('_start+1')
            if previous > start:
                self.context_manager.clearExitBreak()
                count = 0
                while current != previous:
                    SIM_run_command('pselect cpu-name = %s' % cpu.name)
                    SIM_run_command('skip-to cycle=%d' % previous)
                    eip = self.getEIP(cpu)
                    current = cpu.cycles
                    instruct = SIM_disassemble_address(cpu, eip, 1, 0)
                    if current != previous:
                        self.lgr.debug('runSkipAndMailAlone, have not yet reached previous %x %x eip: %x' % (current, previous, eip))
                        time.sleep(1)
                    count += 1
                    if count > 3:
                        self.lgr.debug('skipAndMailAlone, will not reach previous, bail')
                        break
                self.lgr.debug('skipAndMailAlone went to previous, cycle now is %x eip: %x %s' % (current, eip, instruct[1]))
                self.context_manager.resetBackStop()
                self.context_manager.setExitBreak(cpu)
            else:
                self.lgr.debug('skipAndRunAlone was asked to back up before start of recording')
        self.is_monitor_running.setRunning(False)
        self.lgr.debug('setRunning to false, now set mbox to 0x%x' % eip)
        self.gdbMailbox('0x%x' % eip)
        print('Monitor done')

    def skipAndMail(self, cycles=1):

        dum, dum2, cpu = self.context_manager.getDebugPid() 
        if cpu is None:
            self.lgr.error("no cpu in runSkipAndMail")
            return
        #current = SIM_cycle_count(cpu)
        eip = self.getEIP(cpu)
        #instruct = SIM_disassemble_address(cpu, eip, 1, 0)
        cycles =- 1
        if cycles <= 0:
            self.lgr.debug('skipAndMail, set running false, and update mbox directly')
            self.is_monitor_running.setRunning(False)
            self.gdbMailbox('0x%x' % eip)
        else:
            '''
            Reverse one instruction via skip-to, set the mailbox to the new eip.
            Expect the debugger script to forward one instruction
            '''
            self.lgr.debug('skipAndMail, run it alone')
            SIM_run_alone(self.runSkipAndMailAlone, cycles)

    def goToOrigin(self):
        pid, dum2, cpu = self.context_manager.getDebugPid() 
        self.lgr.debug('goToOrigin for pid %d' % pid)
        self.bookmarks[pid].goToOrigin()

    def goToDebugBookmark(self, mark):
        self.lgr.goToDebugBookmark('goToDebugBookmark %s' % mark)
        mark = mark.replace('|','"')
        pid, dum2, cpu = self.context_manager.getDebugPid() 
        self.bookmarks[pid].goToDebugBookmark(mark)

    def listBookmarks(self):
        pid, dum2, cpu = self.context_manager.getDebugPid() 
        self.bookmarks[pid].listBookmarks()

    def getBookmarks(self):
        pid, dum2, cpu = self.context_manager.getDebugPid() 
        return self.bookmarks[pid].getBookmarks()

    def doReverse(self, extra_back=0):
        dum, dum2, cpu = self.context_manager.getDebugPid() 
        self.lgr.debug('doReverse entered, extra_back is %s' % str(extra_back))
        self.context_manager.clearExitBreak()
        reverseToWhatever.reverseToWhatever(self, self.context_manager, cpu, self.lgr, extra_back=extra_back)
        self.lgr.debug('doReverse, back from reverseToWhatever init')
        self.context_manager.setExitBreak(cpu)

    def printCycle(self):
        dum, dum2, cpu = self.context_manager.getDebugPid() 
        cell_name = self.getTopComponentName(cpu)
        current = cpu.cycles
        print 'current cycle for %s is %x' % (cell_name, current)

    ''' more experiments '''
    def reverseStepInstruction(self, num=1):
        dum, dum2, cpu = self.context_manager.getDebugPid() 
        cell_name = self.getTopComponentName(cpu)
        dum_cpu, comm, pid  = self.task_utils.curProc()
        eip = self.getEIP()
        self.lgr.debug('reservseStepInstruction starting at %x' % eip)
        my_args = procInfo.procInfo(comm, cpu, pid, None, False)
        self.stopped_reverse_instruction_hap = SIM_hap_add_callback("Core_Simulation_Stopped", 
		    self.stoppedReverseInstruction, my_args)
        self.lgr.debug('reverseStepInstruction, added stop hap')
        SIM_run_alone(SIM_run_command, 'reverse-step-instruction %d' % num)

    def stoppedReverseInstruction(self, my_args, one, exception, error_string):
        cell_name = self.getTopComponentName(my_args.cpu)
        cpu, comm, pid  = self.task_utils.curProc()
        if pid == my_args.pid:
            eip = self.getEIP()
            self.lgr.debug('stoppedReverseInstruction at %x' % eip)
            print 'stoppedReverseInstruction stopped at ip:%x' % eip
            self.gdbMailbox('0x%x' % eip)
            SIM_hap_delete_callback_id("Core_Simulation_Stopped", self.stopped_reverse_instruction_hap)
        else:
            self.lgr.debug('stoppedReverseInstruction in wrong pid (%d), try again' % pid)
            SIM_run_alone(SIM_run_command, 'reverse-step-instruction')
    
    def reverseToCallInstruction(self, step_into, prev=None):
        dum, dum2, cpu = self.context_manager.getDebugPid() 
        cell_name = self.getTopComponentName(cpu)
        self.context_manager.clearExitBreak()
        self.lgr.debug('reverseToCallInstruction, step_into: %r  on entry, gdb_mailbox: %s' % (step_into, self.gdb_mailbox))
        if prev is not None:
            instruct = SIM_disassemble_address(cpu, prev, 1, 0)
            self.lgr.debug('reverseToCallInstruction instruct is %s at prev: 0x%x' % (instruct[1], prev))
            if instruct[1] == 'int 128' or (not step_into and instruct[1].startswith('call')):
                self.revToAddr(prev)
            else:
                self.rev_to_call.doRevToCall(step_into, prev)
        else:
            self.lgr.debug('prev is none')
            self.rev_to_call.doRevToCall(step_into, prev)
        self.lgr.debug('reverseToCallInstruction back from call to reverseToCall ')

    def uncall(self):
        dum, dum2, cpu = self.context_manager.getDebugPid() 
        cell_name = self.getTopComponentName(cpu)
        dum_cpu, cur_addr, comm, pid = self.task_utils.currentProcessInfo(cpu)
        self.context_manager.clearExitBreak()
        self.lgr.debug('cgcMonitor, uncall')
        self.rev_to_call.doUncall()
   
    def getInstance(self):
        return INSTANCE
 
    def revToModReg(self, reg):
        self.lgr.debug('revToModReg for reg %s' % reg)
        self.context_manager.clearExitBreak()
        self.rev_to_call.doRevToModReg(reg)

    def revToAddr(self, address, extra_back=0):
        pid, cell_name, cpu = self.context_manager.getDebugPid() 
        self.lgr.debug('revToAddr 0x%x, extra_back is %d' % (address, extra_back))
        self.context_manager.clearExitBreak()
        reverseToAddr.reverseToAddr(address, self.context_manager, self.is_monitor_running, self, cpu, self.lgr, extra_back=extra_back)
        self.lgr.debug('back from reverseToAddr')

    ''' intended for use by gdb, if stopped return the eip.  checks for mailbox messages'''
    def getEIPWhenStopped(self, kernel_ok=False):
        #status = SIM_simics_is_running()
        status = self.is_monitor_running.isRunning()
        if not status:
            debug_pid, dum2, cpu = self.context_manager.getDebugPid() 
            if cpu is None:
                print('no cpu defined in context manager')
                return
            cell_name = self.getTopComponentName(cpu)
            dum_cpu, comm, pid  = self.task_utils.curProc()
            self.lgr.debug('getEIPWhenStopped, pid %d' % (pid)) 
            eip = self.getEIP(cpu)
            if self.gdb_mailbox is not None:
                self.lgr.debug('getEIPWhenStopped mbox is %s pid is %d (%s) cycle: 0x%x' % (self.gdb_mailbox, pid, comm, cpu.cycles))
                retval = 'mailbox:%s' % self.gdb_mailbox
                print retval
                return retval
            else:
                self.lgr.debug('getEIPWhenStopped, mbox must be empty?')
            cpl = memUtils.getCPL(cpu)
            if cpl == 0 and not kernel_ok:
                self.lgr.debug('getEIPWhenStopped in kernel pid:%d (%s) eip is %x' % (pid, comm, eip))
                retval = 'in kernel'
                print retval
                return retval
            self.lgr.debug('getEIPWhenStopped pid:%d (%s) eip is %x' % (pid, comm, eip))
            if debug_pid != pid:
                self.lgr.debug('getEIPWhenStopped wrong process pid:%d (%s) eip is %x' % (pid, comm, eip))
                retval = 'wrong process'
                print retval
                return retval
            SIM_run_command('pselect cpu-name = %s' % cpu.name)
            retval = 'mailbox:0x%x' % eip
            print retval
            #print 'cmd is %s' % cmd
            #SIM_run_command(cmd)
        else:
            self.lgr.debug('call to getEIPWhenStopped, not stopped')
            print 'not stopped'
            retval = 'not stopped'
        return retval

    def idaMessage(self):
        self.context_manager.showIdaMessage()

    def resynch(self):
        debug_pid, debug_cell, debug_cpu = self.context_manager.getDebugPid() 
        cpu, comm, pid = self.task_utils.curProc() 
        self.lgr.debug('resynch to pid: %d' % debug_pid)
        #self.is_monitor_running.setRunning(True)
        if pid == debug_pid:
            self.lgr.debug('rsynch, already in proc')
            flist = [self.skipAndMail]
            self.toUser(flist) 
        else:
            flist = [self.toUser, self.skipAndMail]
            self.lgr.debug('rsynch, call toProc for pid %d' % debug_pid)
            self.toProc(None, debug_pid, flist)

    def traceExecve(self, comm=None):
        self.pfamily.traceExecve(comm)

    def watchPageFaults(self):
        self.page_faults.watchPageFaults()

    def traceOpenSyscall(self):
        self.lgr.debug('about to call traceOpen')
        self.traceOpen.traceOpenSyscall()

    def getCell(self):
        return self.cell_config.cell_context[target]

    def getCPU(self):
        return self.cell_config.cpuFromCell(target)

    def reverseToUser(self):
        cpu = self.cell_config.cpuFromCell(target)
        cell = self.cell_config.cell_context[target]
        rtu = reverseToUser.ReverseToUser(self.param, self.lgr, cpu, cell)

    def getDebugFirstCycle(self):
        print('start_cycle:%x' % self.bookmarks.getFirstCycle())

    def getFirstCycle(self):
        pid, dum2, cpu = self.context_manager.getDebugPid() 
        return self.bookmarks[pid].getFirstCycle()

    def stopAtKernelWrite(self, addr, rev_to_call=None, num_bytes = 1):
        '''
        Runs backwards until a write to the given address is found.
        '''
        self.context_manager.clearExitBreak()
        pid, dum2, cpu = self.context_manager.getDebugPid() 
        cell_name = self.getTopComponentName(cpu)
        self.lgr.debug('stopAtKernelWrite, call findKernelWrite for 0x%x' % addr)
        self.find_kernel_write = findKernelWrite.findKernelWrite(self, cpu, addr, self.task_utils, self.task_utils,
            self.context_manager, self.param, self.bookmarks[pid], self.lgr, rev_to_call, num_bytes) 

    def revTaintAddr(self, addr):
        '''
        back track the value at a given memory location, where did it come from?
        '''
        self.lgr.debug('revTaintAddr for 0x%x' % addr)
        pid, dum2, cpu = self.context_manager.getDebugPid() 
        cell_name = self.getTopComponentName(cpu)
        eip = self.getEIP(cpu)
        instruct = SIM_disassemble_address(cpu, eip, 1, 0)
        value = self.mem_utils.readWord32(cpu, addr)
        bm='backtrack START:0x%x inst:"%s" track_addr:0x%x track_value:0x%x' % (eip, instruct[1], addr, value)
        self.bookmarks[pid].setDebugBookmark(bm)
        self.lgr.debug('BT add bookmark: %s' % bm)
        self.context_manager.setIdaMessage('')
        self.stopAtKernelWrite(addr, self.rev_to_call)

    def revTaintReg(self, reg):
        ''' back track the value in a given register '''
        self.lgr.debug('revTaintReg for %s' % reg)
        pid, dum2, cpu = self.context_manager.getDebugPid() 
        cell_name = self.getTopComponentName(cpu)
        eip = self.getEIP(cpu)
        instruct = SIM_disassemble_address(cpu, eip, 1, 0)
        reg_num = cpu.iface.int_register.get_number(reg)
        value = cpu.iface.int_register.read(reg_num)
        self.lgr.debug('revTaintReg for reg value %x' % value)
        bm='backtrack START:0x%x inst:"%s" track_reg:%s track_value:0x%x' % (eip, instruct[1], reg, value)
        self.bookmarks[pid].setDebugBookmark(bm)
        self.context_manager.setIdaMessage('')
        self.rev_to_call.doRevToModReg(reg, True)

    def rev1(self):
        dum, dum2, cpu = self.context_manager.getDebugPid() 
        new_cycle = cpu.cycles - 1
         
        start_cycles = self.rev_to_call.getStartCycles()
        if new_cycle >= start_cycles:
            result = SIM_run_command('skip-to cycle=0x%x' % new_cycle)
            self.lgr.debug('rev1 result %s' % result)
        else:
            self.lgr.debug('rev1, already at first cycle 0x%x' % new_cycle)
            self.skipAndMail()

    def test1(self):
        
        pid, cell_name, cpu = self.context_manager.getDebugPid() 
        cycles = cpu.cycles
        print('first skip-to cycle=0x%x' % cycles)
        for i in range(200):
            cycles = cycles - 1
            cycles = cycles & 0xFFFFFFFFFFFFFFFF
            print('this skip-to cycle=0x%x' % cycles)
            SIM_run_command('skip-to cycle=0x%x' % cycles)
            eip = self.getEIP(cpu)
            cpl = memUtils.getCPL(cpu)
            instruct = SIM_disassemble_address(cpu, eip, 1, 0)
            print('0x%x pl:%s  %s' % (eip, cpl, instruct[1]))
             
    def runToSyscall(self, callnum = None):
        cell = self.cell_config.cell_context[target]
        self.is_monitor_running.setRunning(True)
        if callnum == 0:
            callnum = None
        self.lgr.debug('runToSyscall for callnumm %s' % callnum)
        my_syscall = syscall.Syscall(self, cell, self.param, self.mem_utils, self.task_utils, self.context_manager, None, self.lgr, callnum=callnum)

    def traceSyscall(self, callnum=None, soMap=None):
        cell = self.cell_config.cell_context[target]
        self.is_monitor_running.setRunning(True)
        if callnum == 0:
            callnum = None
        self.lgr.debug('runToSyscall for callnumm %s' % callnum)
        my_syscall = syscall.Syscall(self, cell, self.param, self.mem_utils, self.task_utils, 
                           self.context_manager, self.traceProcs, self.lgr, callnum=callnum, trace=True, trace_fh = self.trace_fh, soMap=soMap)
        return my_syscall

    def traceProcesses(self):
        call_list = ['vfork','clone','execve','open','pipe','pipe2','close','dup','dup2','socketcall']
        calls = ' '.join(s for s in call_list)
        print('tracing these system calls: %s' % calls)
        self.trace_fh = open('/tmp/syscall_trace.txt', 'w')
        for call in call_list: 
            if call == 'open':
                self.call_traces[call] = self.traceSyscall(callnum=self.task_utils.syscallNumber(call), soMap=self.soMap)
            else:
                self.call_traces[call] = self.traceSyscall(callnum=self.task_utils.syscallNumber(call))

    def stopTrace(self):
        for call in self.call_traces:
            self.call_traces[call].stopTrace()
        self.call_traces.clear()   

    def traceAll(self):
        cell = self.cell_config.cell_context[target]
        self.trace_fh = open('/tmp/syscall_trace.txt', 'w')
        my_syscall = syscall.Syscall(self, cell, self.param, self.mem_utils, self.task_utils, 
                           self.context_manager, self.traceProcs, self.lgr, callnum=None, trace=True, trace_fh = self.trace_fh)

    def noDebug(self):
        cmd = 'disable-reverse-execution'
        SIM_run_command(cmd)
        self.rev_to_call.noWatchSysenter()

    def showProcTrace(self):
        pid_comm_map = self.task_utils.getPidCommMap()
        precs = self.traceProcs.getPrecs()
        for prec in precs:
            if prec.prog is None:
                precs.prog = 'comm: %s' % (pid_comm_map[prec.pid])
        self.traceProcs.showAll()
 
    def toExecve(self, comm, flist=None):
        cell = self.cell_config.cell_context[target]
        callnum=self.task_utils.syscallNumber('execve')
        my_syscall = syscall.Syscall(self, cell, self.param, self.mem_utils, self.task_utils, 
                           self.context_manager, self.traceProcs, self.lgr, callnum=callnum, 
                           trace=False, trace_fh = None, break_on_execve=comm, flist_in = flist)

    def clone(self):
        cell = self.cell_config.cell_context[target]
        eh = cloneChild.CloneChild(self, cell, self.param, self.mem_utils, self.task_utils, self.context_manager, self.lgr)
        SIM_run_command('c')

    def recordText(self, start, end):
        self.lgr.debug('.text IDA is 0x%x - 0x%x' % (start, end))
        self.context_manager.recordText(start, end)

    def textHap(self, prec, third, forth, memory):
        ''' callback when current_task is updated.  new value is in memory parameter '''
        if self.proc_hap is None:
            return
        cpu, comm, pid = self.task_utils.curProc() 
        if cpu != prec.cpu or pid != prec.pid:
            self.lgr.debug('text hap, wrong something %d' % pid)
            return
        #cur_eip = SIM_get_mem_op_value_le(memory)
        eip = self.getEIP(cpu)
        self.lgr.debug('text hap, must be in text eip is 0x%x' % eip)
        SIM_break_simulation('text hap')
        if prec.debugging:
            self.context_manager.genDeleteHap(self.proc_hap)
            self.proc_hap = None
            self.skipAndMail()

    def runToText(self, flist = None):
        ''' run until within the currently defined text segment '''
        self.is_monitor_running.setRunning(True)
        start, end = self.context_manager.getText()
        if start is None:
            print('No text segment defined, has IDA been started with the rev plugin?')
            return
        count = end - start
        cell = self.cell_config.cell_context[target]
        self.lgr.debug('runToText range 0x%x 0x%x' % (start, end))
        proc_break = self.context_manager.genBreakpoint(cell, Sim_Break_Linear, Sim_Access_Execute, start, count, 0)
        pid, cell_name, cpu = self.context_manager.getDebugPid() 
        if cpu is None:
            self.lgr.debug('runToText, not debugging yet, assume current process')
            cpu, comm, pid = self.task_utils.curProc() 
        prec = Prec(cpu, None, pid)
        if flist is None:
            prec.debugging = True
        else:
            self.call_traces['open'] = self.traceSyscall(callnum=self.task_utils.syscallNumber('open'), soMap=self.soMap)

        self.proc_hap = self.context_manager.genHapIndex("Core_Breakpoint_Memop", self.textHap, prec, proc_break)
        self.lgr.debug('hap set, now run')

        hap_clean = hapCleaner.HapCleaner(cpu)
        hap_clean.add("GenContext", self.proc_hap)
        stop_action = hapCleaner.StopAction(hap_clean, None, flist)
        self.stop_hap = SIM_hap_add_callback("Core_Simulation_Stopped", 
          self.stopHap, stop_action)
        SIM_run_alone(SIM_run_command, 'continue')

    def showSOMap(self, pid):
        self.soMap.showSO(pid)

    def getSOFile(self, pid, addr):
        fname = self.soMap.getSOFile(pid, addr)
        print(fname)

if __name__=="__main__":        
    print('instantiate the GenMonitor') 
    cgc = GenMonitor()
