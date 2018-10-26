
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
import pageFaultGen
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


class StopAction():
    def __init__(self, hap_cleaner, breakpoints, flist):
        self.hap_clean = hap_cleaner
        if breakpoints is not None:
            self.breakpoints = breakpoints
        else:
            self.breakpoints = []
        if flist is not None:
            self.flist = flist
        else:
            self.flist = []

class HapCleaner():
    hlist = None 
    def __init__(self):
        self.hlist = []

    class HapType():
        def __init__(self, htype, hap):
            self.htype = htype
            self.hap = hap

    def add(self, htype, hap):
        ht = self.HapType(htype, hap)
        self.hlist.append(ht)

class SyscallInfo():
    def __init__(self, cpu, pid, callnum):
        self.cpu = cpu
        self.pid = pid
        self.callnum = callnum

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
        self.lgr.debug('modeChanged now %d' % cpl)
        self.lgr.debug('mode changed cpl reports %d trigger_obj is %s old: %d  new: %d' % (cpl, str(one), old, new))
        SIM_break_simulation('mode changed, break simulation')
        
    def stopHap(self, stop_action, one, exception, error_string):
        self.lgr.debug('stopHap')
        for hc in stop_action.hap_clean.hlist:
            if hc.hap is not None:
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
            hap_clean = HapCleaner()
            hap_clean.add("Core_Mode_Change", self.mode_hap)
            stop_action = StopAction(hap_clean, None)
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
            hap_clean = HapCleaner()
            hap_clean.add("Core_Mode_Change", self.mode_hap)
            stop_action = StopAction(hap_clean, None, flist)
            self.stop_hap = SIM_hap_add_callback("Core_Simulation_Stopped", 
        	     self.stopHap, stop_action)
            SIM_run_alone(SIM_run_command, 'continue')
        else:
            self.lgr.debug('run2User, already in user')

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
        self.bookmarks = bookmarkMgr.bookmarkMgr(self, self.context_manager, self.lgr)
        ''' hack os_utils fu '''
        os_p_utils = {}
        os_p_utils[target] = self.task_utils 
        self.rev_to_call = reverseToCall.reverseToCall(self, self.param, os_p_utils,
                 self.PAGE_SIZE, self.context_manager, 'nobody', self.is_monitor_running, self.bookmarks, self.log_dir)
        #self.os_p_utils = linuxProcessUtils.linuxProcessUtils(self, 'thrower', self.param,
        #            self.cell_config, None, None, self.cur_task[cpu], self.mem_utils, self.lgr, False)
        self.pfamily = pFamily.Pfamily(target, self.param, self.cell_config, self.mem_utils, self.task_utils, self.lgr)
        self.page_faults = pageFaultGen.PageFaultGen(target, self.param, self.cell_config, self.mem_utils, self.task_utils, self.lgr)
        
    def tasks(self):
        tasks = self.task_utils.getTaskStructs()
        for t in tasks:
            print('pid: %d comm: %s' % (tasks[t].pid, tasks[t].comm))


    def setDebugBookmark(self, mark, cpu=None, cycles=None, eip=None, steps=None):
        self.bookmarks.setDebugBookmark(mark, cpu=cpu, cycles=cycles, eip=eip, steps=steps)

    def debug(self, dumb=None):
        port = 9123 
        cpu, comm, pid = self.task_utils.curProc() 
        self.lgr.debug('debug for cpu %s port will be %d.  Pid is %d' % (cpu.name, port, pid))
        self.context_manager.setDebugPid(pid, target, cpu)
        cmd = 'new-gdb-remote cpu=%s architecture=x86 port=%d' % (cpu.name, port)
        SIM_run_command(cmd)
        cmd = 'enable-reverse-execution'
        SIM_run_command(cmd)
        self.setDebugBookmark('_start+1', cpu)
        self.bookmarks.setOrigin(cpu)
        ''' tbd read elf and pass executable pages? '''
        self.rev_to_call.setup(cpu, [])


    def show(self):
        cpu = self.cell_config.cpuFromCell(target)
        cpl = memUtils.getCPL(cpu)
        eip = self.getEIP(cpu)
        print('cpu.name is %s PL: %d EIP: 0x%x   current_task symbol at 0x%x' % (cpu.name, cpl, eip, self.cur_task[cpu]))
        pfamily = self.pfamily.getPfamily()
        tabs = ''
        while len(pfamily) > 0:
            prec = pfamily.pop()
            print('%s%5d  %s' % (tabs, prec.pid, prec.proc))
            tabs += '\t'


    def syscallHap(self, syscall_info, third, forth, memory):
        cpu = SIM_current_processor()
        if cpu != syscall_info.cpu:
            self.lgr.debug('syscallHap, wrong cpu %s %s' % (cpu.name, syscall_info.cpu.name))
            return
        cpu, comm, pid = self.task_utils.curProc() 
        eax = self.mem_utils.getRegValue(syscall_info.cpu, 'eax')
        self.lgr.debug('syscallHap in proc %d (%s), eax: 0x%x  look for %s' % (pid, comm, eax, str(syscall_info.callnum)))
        if syscall_info.pid is None or syscall_info.pid == pid: 
            eax = self.mem_utils.getRegValue(syscall_info.cpu, 'eax')
            if syscall_info.callnum is not None:
                eax = self.mem_utils.getRegValue(syscall_info.cpu, 'eax')
                if eax == syscall_info.callnum:
                    self.lgr.debug('syscall 0x%d from %d (%s) at 0x%x ' % (eax, pid, comm, self.getEIP(syscall_info.cpu)))
                    SIM_break_simulation('syscall')
            else:
                self.lgr.debug('syscall 0x%d from %d (%s) at 0x%x ' % (eax, pid, comm, self.getEIP(syscall_info.cpu)))
                SIM_break_simulation('syscall')


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
        hap_clean = HapCleaner()
        hap_clean.add("Core_Exception", self.scall_hap)
        stop_action = StopAction(hap_clean, [], None)
        self.stop_hap = SIM_hap_add_callback("Core_Simulation_Stopped", 
        	     self.stopHap, stop_action)
        status = self.is_monitor_running.isRunning()
        if not status:
            SIM_run_command('c')

    def runToSignal(self, signal=None, pid=None):
        cpu = self.cell_config.cpuFromCell(target)
        self.lgr.debug('runToSignal, signal given is %s' % str(signal)) 

        sig_info = SyscallInfo(cpu, pid, signal)
        #max_intr = 31
        max_intr = 1028
        if signal is None:
            sig_hap = SIM_hap_add_callback_obj_range("Core_Exception", cpu, 0,
                     self.signalHap, sig_info, 0, max_intr) 
        else:
            sig_hap = SIM_hap_add_callback_obj_index("Core_Exception", cpu, 0,
                     self.signalHap, sig_info, signal) 

        hap_clean = HapCleaner()
        hap_clean.add("Core_Exception", sig_hap)
        stop_action = StopAction(hap_clean, [], None)
        self.stop_hap = SIM_hap_add_callback("Core_Simulation_Stopped", 
        	     self.stopHap, stop_action)
        status = self.is_monitor_running.isRunning()
        if not status:
            SIM_run_command('c')

    def debugProc(self, proc):
        self.lgr.debug('debugProc for %s' % proc)
        flist = [self.toUser, self.debug]
        self.toProc(proc, flist=flist)

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
        self.toUser()

    def toKernel(self): 
        cpu = self.cell_config.cpuFromCell(target)
        self.run2Kernel(cpu)

    def toProc(self, proc, pid=None, flist=None):
        cpu = self.cell_config.cpuFromCell(target)
        self.lgr.debug('toProc current_task is 0x%x   ' % (self.cur_task[cpu]))
        cell = self.cell_config.cell_context[target]
        prec = Prec(cpu, proc, pid)
        proc_break = SIM_breakpoint(cell, Sim_Break_Linear, Sim_Access_Write, self.cur_task[cpu], self.mem_utils.WORD_SIZE, 0)
        self.proc_hap = SIM_hap_add_callback_index("Core_Breakpoint_Memop", self.runToProc, prec, proc_break)
        
        hap_clean = HapCleaner()
        hap_clean.add("Core_Breakpoint_Memop", self.proc_hap)
        stop_action = StopAction(hap_clean, [proc_break], flist)
        #self.stop_proc_hap = SIM_hap_add_callback("Core_Simulation_Stopped", 
        #	     self.stoppedToProc, fun_list)
        self.stop_hap = SIM_hap_add_callback("Core_Simulation_Stopped", 
        	     self.stopHap, stop_action)
        status = self.is_monitor_running.isRunning()
        if not status:
            SIM_run_command('c')
       
    def runToSyscall(self, callnum=None): 
        self.lgr.debug('runToSyscall callnum is %s' % str(callnum)) 
        cell = self.cell_config.cell_context[target]
        proc_break = SIM_breakpoint(cell, Sim_Break_Linear, Sim_Access_Execute, self.param.sys_entry, self.mem_utils.WORD_SIZE, 0)
        pid, cell_name, cpu = self.context_manager.getDebugPid() 
        syscall_info = SyscallInfo(cpu, pid, callnum)
        proc_hap = SIM_hap_add_callback_index("Core_Breakpoint_Memop", self.syscallHap, syscall_info, proc_break)
        hap_clean = HapCleaner()
        hap_clean.add("Core_Breakpoint_Memop", proc_hap)
        stop_action = StopAction(hap_clean, [proc_break], None)
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
            dum, dum2, cpu = self.__context_manager.getDebugPid() 
        cell_name = self.getTopComponentName(cpu)
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
        dum, dum2, cpu = self.context_manager.getDebugPid() 
        if cpu is None:
            self.lgr.error("no cpu in runSkipAndMailAlone")
            return
        current = cpu.cycles
        eip = self.getEIP(cpu)
        instruct = SIM_disassemble_address(cpu, eip, 1, 0)
        self.lgr.debug('skipAndMailAlone current cycle is %x eip: %x %s requested %d cycles' % (current, eip, instruct[1], cycles))
        if cycles > 0:
            previous = current - cycles 
            start = self.bookmarks.getCycle('_start+1')
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
        cycles -= 1
        if cycles <= 0:
            self.gdbMailbox('0x%x' % eip)
        else:
            '''
            Reverse one instruction via skip-to, set the mailbox to the new eip.
            Expect the debugger script to forward one instruction
            '''
            self.lgr.debug('skipAndMail, run it alone')
            SIM_run_alone(self.runSkipAndMailAlone, cycles)

    def goToOrigin(self):
        self.bookmarks.goToOrigin()

    def goToDebugBookmark(self, mark):
        mark = mark.replace('|','"')
        self.bookmarks.goToDebugBookmark(mark)

    def listBookmarks(self):
        self.bookmarks.listBookmarks()

    def getBookmarks(self):
        return self.bookmarks.getBookmarks()

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
            self.lgr.debug('reverseToCallInstruction instruct is %s, prev: 0x%x' % (instruct[1], prev))
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
                self.lgr.debug('getEIPWhenStopped mbox is %s pid is %d (%s)' % (self.gdb_mailbox, pid, comm))
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
        pid, cell, cpu = self.context_manager.getDebugPid() 
        self.lgr.debug('resynch to pid: %d' % pid)
        flist = [self.toUser]
        self.toProc(None, pid=pid, flist=flist)

    def traceExecve(self):
        self.pfamily.traceExecve()

    def watchPageFaults(self):
        self.page_faults.watchPageFaults()

if __name__=="__main__":        
    print('instantiate the GenMonitor') 
    cgc = GenMonitor()
