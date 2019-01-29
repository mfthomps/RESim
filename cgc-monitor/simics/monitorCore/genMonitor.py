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
Use Simics to monitor processes.  The is the top level module for RESim,
derived from cgcMonitor, which was developed for the DARPA Cyber Grand Challenge.
'''
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
import stopFunction
import trackThreads
import dataWatch
import traceFiles
import stackTrace
import exitMaze
import net
import sharedSyscall

import pickle

class cellConfig():
    '''
    Manage the Simics simulation cells (boxes), CPU's (processor cores).
    TBD -- clean up once multi-box strategy evolves, e.g., could there be
    multiple CPUs per cell?  
    '''
    cells = {}
    cell_cpu = {}
    cell_cpu_list = {}
    cell_context = {}
    def __init__(self, target):
        self.loadCellObjects(target)

    def loadCellObjects(self, target):
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
    ''' Top level RESim class '''
    SIMICS_BUG=False
    PAGE_SIZE = 4096
    def __init__(self):
        self.param = None
        self.mem_utils = None
        #self.os_p_utils = None
        self.task_utils = None
        self.cur_task = {}
        self.proc_list = {}
        self.proc_hap = None
        self.stop_proc_hap = None
        self.proc_break = None
        self.gdb_mailbox = None
        self.stop_hap = None
        self.log_dir = '/tmp/'
        self.mode_hap = None
        self.hack_list = []
        self.traceOpen = None
        self.sysenter_cycles = []
        self.trace_fh = None
        self.soMap = None
        ''' dict of syscall.SysCall keyed on call number '''
        self.call_traces = {}
        self.trace_all = None
        self.track_threads = None
        self.exit_group_syscall = None
        self.dataWatch = None
        self.debug_breaks_set = True
        self.target = None
        self.unistd32 = '/mnt/ubuntu_img/linux-2.6.32/linux-2.6.32/arch/x86/include/asm/unistd_32.h'
        self.root_prefix = os.getenv('RESIM_ROOT_PREFIX')
        if self.root_prefix is None:
            self.root_prefix = '/mnt/vdr_img/rootfs'
        self.netInfo = None
        self.stack_base = None
        self.maze_exits = []
        self.exit_maze = None
        self.rev_execution_enabled = False
        self.run_from_snap = None

        self.genInit()

    def genInit(self):
        '''
        remove all previous breakpoints.  
        '''
        self.lgr = utils.getLogger('noname', os.path.join(self.log_dir, 'monitors'))
        self.is_monitor_running = isMonitorRunning.isMonitorRunning(self.lgr)
        SIM_run_command("delete -all")
        self.target = os.getenv('RESIM_TARGET')
        print('using target of %s' % self.target)
        self.cell_config = cellConfig(self.target)
        self.lgr.debug('New log, in genInit')
        param_file = os.getenv('RESIM_PARAM')
        if param_file is not None:
            print('Using params from %s' % param_file)
            self.lgr.debug('Using params from %s' % param_file)
            self.param = pickle.load( open(param_file, 'rb') ) 
            self.lgr.debug(self.param.getParamString())
            #print('param next %s  comm %s' % (str(self.param.ts_next), str(self.param.ts_comm)))
        else:
            self.param = linuxParams.linuxParams()
        self.mem_utils = memUtils.memUtils(4, self.param, self.lgr)
        self.netInfo = net.NetAddresses(self.lgr)
        self.run_from_snap = os.getenv('RUN_FROM_SNAP')
        if self.run_from_snap is not None:
            plist_file = os.path.join('./', self.run_from_snap, 'proc_list.pickle')
            if os.path.isfile(plist_file):
                self.proc_list = pickle.load( open(plist_file, 'rb') ) 
            net_file = os.path.join('./', self.run_from_snap, 'net_list.pickle')
            self.netInfo.loadfile(net_file)

    def getTopComponentName(self, cpu):
         if cpu is not None:
             names = cpu.name.split('.')
             return names[0]
         else:
             return None

    def modeChanged(self, want_pid, one, old, new):
        cpu, comm, this_pid = self.task_utils.curProc() 
        cpl = memUtils.getCPL(cpu)
        if want_pid != this_pid:
            self.lgr.debug('mode changed wrong pid, wanted %d got %d' % (want_pid, this_pid))
            return
        eip = self.mem_utils.getRegValue(cpu, 'eip')
        self.lgr.debug('mode changed cpl reports %d trigger_obj is %s old: %d  new: %d  eip: 0x%x' % (cpl, str(one), old, new, eip))
        SIM_break_simulation('mode changed, break simulation')
        
    def stopHap(self, stop_action, one, exception, error_string):
        if stop_action is None or stop_action.hap_clean is None:
            print('stopHap error, stop_action None?')
            return 
        cpu, comm, pid = self.task_utils.curProc() 
        eip = self.getEIP(cpu)
        self.lgr.debug('stopHap pid %d eip 0x%x cycle: 0x%x' % (pid, eip, stop_action.hap_clean.cpu.cycles))
        for hc in stop_action.hap_clean.hlist:
            if hc.hap is not None:
                if hc.htype == 'GenContext':
                    self.lgr.debug('will delete GenContext hap %s' % str(hc.hap))
                    self.context_manager.genDeleteHap(hc.hap)
                else:
                    #self.lgr.debug('stopHap will delete hap %s' % str(hc.hap))
                    SIM_hap_delete_callback_id(hc.htype, hc.hap)
                hc.hap = None
        if self.stop_hap is not None:
            self.lgr.debug('stopHap will delete hap %s' % str(self.stop_hap))
            SIM_hap_delete_callback_id("Core_Simulation_Stopped", self.stop_hap)
            self.stop_hap = None
            for bp in stop_action.breakpoints:
                SIM_delete_breakpoint(bp)
            ''' check functions in list '''
            self.lgr.debug('stopHap now run actions %s' % str(stop_action.flist))
            stop_action.run()
            self.lgr.debug('back from stop_action.run')

    def run2Kernel(self, cpu):
        cpl = memUtils.getCPL(cpu)
        if cpl != 0:
            cpu, comm, pid = self.task_utils.curProc() 
            self.lgr.debug('run2Kernel in user space (%d), set hap' % cpl)
            self.mode_hap = SIM_hap_add_callback_obj("Core_Mode_Change", pid, 0, self.modeChanged, cpu)
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
            cpu, comm, pid = self.task_utils.curProc() 
            self.lgr.debug('run2User pid %d in kernel space (%d), set hap' % (pid, cpl))
            self.mode_hap = SIM_hap_add_callback_obj("Core_Mode_Change", cpu, 0, self.modeChanged, pid)
            hap_clean = hapCleaner.HapCleaner(cpu)
            hap_clean.add("Core_Mode_Change", self.mode_hap)
            stop_action = hapCleaner.StopAction(hap_clean, None, flist)
            self.stop_hap = SIM_hap_add_callback("Core_Simulation_Stopped", 
        	     self.stopHap, stop_action)
            SIM_run_alone(SIM_run_command, 'continue')
        else:
            self.lgr.debug('run2User, already in user')
            if flist is not None and len(flist) == 1:
                flist[0].fun(flist[0].args)

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
        self.lgr.debug('genMonitor doInit target is %s' % self.target)
        cpu = self.cell_config.cpuFromCell(self.target)
        SIM_run_command('pselect cpu-name = %s' % cpu.name)
        ''' get cur_task_rec using stack fu '''
        pid = 0
        cur_task_rec = None
        #while pid == 0: 
        while cur_task_rec is None:
            ''' run until we get something sane '''
            cur_task_rec = self.mem_utils.getCurrentTask(self.param, cpu)
            while cur_task_rec is None:
                cur_task_rec = self.mem_utils.getCurrentTask(self.param, cpu)
                if cur_task_rec is None:
                    print('Current task not yet defined, continue')
                    SIM_continue(900000000)
                else:
                    SIM_break_simulation('Booted enough to get cur_task_rec')
            self.lgr.debug('doInit out of loop with cur_task_rec of 0x%x' % cur_task_rec)
                
        self.task_utils = taskUtils.TaskUtils(cpu, self.param, self.mem_utils, self.unistd32, self.run_from_snap, self.lgr)
 
        tu_cur_task_rec = self.task_utils.getCurTaskRec()
        if tu_cur_task_rec is None:
            self.lgr.error('could not read tu_cur_task_rec from taskUtils')
            return

        self.lgr.debug('stack based rec was 0x%x  mine is 0x%x' % (cur_task_rec, tu_cur_task_rec))

        self.context_manager = genContextMgr.GenContextMgr(self, self.task_utils, self.param, self.lgr) 
        #self.bookmarks = bookmarkMgr.bookmarkMgr(self, self.context_manager, self.lgr)
        self.bookmarks = {}
        ''' hack os_utils fu '''
        os_p_utils = {}
        os_p_utils[self.target] = self.task_utils 
        self.page_faults = pageFaultGen.PageFaultGen(self, self.target, self.param, self.cell_config, self.mem_utils, 
               self.task_utils, self.context_manager, self.lgr)
        self.rev_to_call = reverseToCall.reverseToCall(self, self.param, os_p_utils, 
                 self.PAGE_SIZE, self.context_manager, 'revToCall', self.is_monitor_running, None, self.log_dir)
        self.pfamily = pFamily.Pfamily(self.target, self.param, self.cell_config, self.mem_utils, self.task_utils, self.lgr)
        cell = self.cell_config.cell_context[self.target]
        self.traceOpen = traceOpen.TraceOpen(self.param, self.mem_utils, self.task_utils, cpu, cell, self.lgr)
        self.traceProcs = traceProcs.TraceProcs(self.lgr, self.proc_list)
        self.soMap = soMap.SOMap(self.context_manager, self.root_prefix, self.run_from_snap, self.lgr)
        self.dataWatch = dataWatch.DataWatch(self, cpu, self.PAGE_SIZE, self.context_manager, self.lgr)
        self.traceFiles = traceFiles.TraceFiles(self.lgr)
        self.sharedSyscall = sharedSyscall.SharedSyscall(self, cpu, cell, self.param, self.mem_utils, self.task_utils, 
                  self.context_manager, self.traceProcs, self.traceFiles, self.soMap, self.dataWatch, self.lgr)
        
    def tasks(self):
        self.lgr.debug('tasks')
        tasks = self.task_utils.getTaskStructs()
        plist = {}
        for t in tasks:
            plist[tasks[t].pid] = t 
        for pid in sorted(plist):
            t = plist[pid]
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

            self.context_manager.setDebugPid(pid, self.target, cpu)

            cmd = 'new-gdb-remote cpu=%s architecture=x86 port=%d' % (cpu.name, port)
            SIM_run_command(cmd)
            cmd = 'enable-reverse-execution'
            SIM_run_command(cmd)
            self.rev_execution_enabled = True
            self.bookmarks[pid] = bookmarkMgr.bookmarkMgr(self, self.context_manager, self.lgr)
            self.setDebugBookmark('_start+1', cpu)
            self.bookmarks[pid].setOrigin(cpu)
            ''' tbd read elf and pass executable pages? NO, would not determine other executable pages '''
            self.rev_to_call.setup(cpu, [], bookmarks=self.bookmarks[pid], page_faults = self.page_faults)

            self.context_manager.watchTasks()
            cell = self.cell_config.cell_context[self.target]

            ''' keep track of threads within our process that are created during debug session '''
            self.track_threads = trackThreads.TrackThreads(cpu, cell, pid, self.context_manager, self.task_utils, self.mem_utils, self.lgr)

            self.lgr.debug('debug set exit_group break')
            self.exit_group_syscall = syscall.Syscall(self, cell, self.param, self.mem_utils, self.task_utils, 
                           self.context_manager, None, self.sharedSyscall, self.lgr, callnum_list=[self.task_utils.syscallNumber('exit_group')], continue_simulation=False)
            self.watchPageFaults(pid)
            self.sharedSyscall.setDebugging(True)
        else:
            ''' already debugging.  change to current process '''
            cpu, comm, pid = self.task_utils.curProc() 


    def show(self):
        cpu, comm, pid = self.task_utils.curProc() 
        cpl = memUtils.getCPL(cpu)
        eip = self.getEIP(cpu)
        print('cpu.name is %s PL: %d pid: %d(%s) EIP: 0x%x   current_task symbol at 0x%x (use FS: %r)' % (cpu.name, cpl, pid, 
               comm, eip, self.param.current_task, self.param.current_task_fs))
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
                self.lgr.error('signalHap from %d (%s) signal 0x%x at 0x%x' % (pid, comm, exception_number, self.getEIP(cpu)))
                SIM_break_simulation('signal %d' % exception_number)
        else: 
           SIM_break_simulation('signal %d' % exception_number)
           self.lgr.debug('signalHap from %d (%s) signal 0x%x at 0x%x' % (pid, comm, exception_number, self.getEIP(cpu)))
         
    def readStackFrame(self):
        cpu, comm, pid = self.task_utils.curProc()
        stack_frame = self.task_utils.frameFromStackSyscall()
        frame_string = taskUtils.stringFromFrame(stack_frame)
        print(frame_string)

    def int80Hap(self, cpu, one, exception_number):
        cpu, comm, pid = self.task_utils.curProc()
        eax = self.mem_utils.getRegValue(cpu, 'eax')
        self.lgr.debug('int80Hap in proc %d (%s), eax: 0x%x' % (pid, comm, eax))
        self.lgr.debug('syscall 0x%d from %d (%s) at 0x%x ' % (eax, pid, comm, self.getEIP(cpu)))
        if eax != 5:
            return
        SIM_break_simulation('syscall')
        print('use si to get address of syscall entry, and further down look for computed call')

    def runToSyscall80(self):
        cpu = self.cell_config.cpuFromCell(self.target)
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
        cpu = self.cell_config.cpuFromCell(self.target)
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
        if self.root_prefix is not None:
            full_path = os.path.join(self.root_prefix, prog_name[1:])
            self.lgr.debug('execToText, prefix is %s progname is %s  full: %s' % (self.root_prefix, prog_name, full_path))
            text_segment = elfText.getText(full_path)
            if text_segment is not None:
                self.lgr.debug('execToText 0x%x - 0x%x' % (text_segment.start, text_segment.start+text_segment.size))       
                self.context_manager.recordText(text_segment.start, text_segment.start+text_segment.size)
                self.soMap.addText(text_segment.start, text_segment.size, prog_name)
                self.runToText(flist)
                return
            else:
                self.lgr.debug('execToText missing binary, just run to user')
                self.toUser(flist)
                return
        self.lgr.debug('execToText no information about the text segment')
        ''' If here, then no info about the text segment '''
        if flist is not None:
            stopFunction.allFuns(flist)
        

    def watchProc(self, proc):
        ''' TBD remove?  can just use debugProc and then disable reverse-exectution?  Highlight on/off on IDA '''
        plist = self.task_utils.getPidsForComm(proc)
        if len(plist) > 0:
            self.lgr.debug('watchProc process %s found, run until some instance is scheduled' % proc)
            f1 = stopFunction.StopFunction(self.toUser, [], True)
            flist = [f1]
            self.toRunningProc(proc, plist, flist)
        else:
            self.lgr.debug('watchProc no process %s found, run until execve' % proc)
            #flist = [self.toUser, self.debug]
            ''' run to the execve, then start recording shared object mmaps and run
                until we enter the text segment so we get the SO map '''
            f1 = stopFunction.StopFunction(self.execToText, [], True)
            flist = [f1]
            self.toExecve(proc, flist=flist)

    def cleanToProcHaps(self):
        SIM_delete_breakpoint(self.proc_break)
        SIM_hap_delete_callback_id("Core_Breakpoint_Memop", self.proc_hap)

    def toProc(self, proc):
        plist = self.task_utils.getPidsForComm(proc)
        if len(plist) > 0:
            self.lgr.debug('toProc process %s found, run until some instance is scheduled' % proc)
            print('%s is running.  Will continue until some instance of it is scheduled' % proc)
            f1 = stopFunction.StopFunction(self.toUser, [], True)
            flist = [f1]
            self.toRunningProc(proc, plist, flist)
        else:
            self.lgr.debug('toProc no process %s found, run until execve' % proc)
            cpu = self.cell_config.cpuFromCell(self.target)
            prec = Prec(cpu, proc, None)
            phys_current_task = self.task_utils.getPhysCurrentTask()
            self.proc_break = SIM_breakpoint(cpu.physical_memory, Sim_Break_Physical, Sim_Access_Write, 
                             phys_current_task, self.mem_utils.WORD_SIZE, 0)
            self.lgr.debug('toProc  set break at 0x%x' % (phys_current_task))
            self.proc_hap = SIM_hap_add_callback_index("Core_Breakpoint_Memop", self.runToProc, prec, self.proc_break)
        
            f1 = stopFunction.StopFunction(self.cleanToProcHaps, [], False)
            self.toExecve(proc, [f1])

    def setStackBase(self):
        ''' debug cpu not yet set.  TBD align with debug cpu selection strategy '''
        cpu = self.cell_config.cpuFromCell(self.target)
        esp = self.mem_utils.getRegValue(cpu, 'esp')
        eip = self.mem_utils.getRegValue(cpu, 'eip')
        self.stack_base = esp
        self.lgr.debug('setStackBase to 0x%x eip is 0x%x' % (esp, eip))

    def debugProc(self, proc):
        plist = self.task_utils.getPidsForComm(proc)
        if len(plist) > 0:
            self.lgr.debug('debugProc process %s found, run until some instance is scheduled' % proc)
            print('%s is running.  Will continue until some instance of it is scheduled' % proc)
            f1 = stopFunction.StopFunction(self.toUser, [], True)
            f2 = stopFunction.StopFunction(self.debug, [], False)
            flist = [f1, f2]
            self.toRunningProc(proc, plist, flist)
        else:
            self.lgr.debug('debugProc no process %s found, run until execve' % proc)
            #flist = [self.toUser, self.debug]
            ''' run to the execve, then start recording shared object mmaps and run
                until we enter the text segment so we get the SO map '''
            f1 = stopFunction.StopFunction(self.execToText, [], True)
            f2 = stopFunction.StopFunction(self.setStackBase, [], False)
            f3 = stopFunction.StopFunction(self.debug, [], False)
            flist = [f1, f2, f3]
            self.toExecve(proc, flist=flist)

    def debugPid(self, pid):
        self.lgr.debug('debugPid for %d' % pid)
        f1 = stopFunction.StopFunction(self.toUser, [], True)
        f2 = stopFunction.StopFunction(self.debug, [], False)
        flist = [f1, f2]
        self.toRunningProc(None, [pid], flist)

    def changedThread(self, cpu, third, forth, memory):
        cur_addr = SIM_get_mem_op_value_le(memory)
        pid = self.mem_utils.readWord32(cpu, cur_addr + self.param.ts_pid)
        if pid != 0:
            print('changedThread')
            self.show()

    def runToProc(self, prec, third, forth, memory):
        ''' callback when current_task is updated.  new value is in memory parameter '''
        cpu = prec.cpu
        cur_task_rec = SIM_get_mem_op_value_le(memory)
        pid = self.mem_utils.readWord32(cpu, cur_task_rec + self.param.ts_pid)
        #self.lgr.debug('runToProc look for %s' % prec.proc)
        if pid != 0:
            comm = self.mem_utils.readString(cpu, cur_task_rec + self.param.ts_comm, 16)
            if (prec.pid is not None and pid in prec.pid) or (prec.pid is None and comm == prec.proc):
                self.lgr.debug('got proc %s pid is %d' % (comm, pid))
                SIM_break_simulation('found %s' % prec.proc)
            else:
                self.proc_list[pid] = comm
                #self.lgr.debug('runToProc pid: %d proc: %s' % (pid, comm))
            
      
    def addProcList(self, pid, comm):
        self.proc_list[pid] = comm
 
    def toUser(self, flist=None): 
        self.lgr.debug('toUser')
        cpu = self.cell_config.cpuFromCell(self.target)
        self.run2User(cpu, flist)

    def runToUserSpace(self):
        self.lgr.debug('runToUserSpace')
        self.is_monitor_running.setRunning(True)
        flist = [self.skipAndMail]
        f1 = stopFunction.StopFunction(self.skipAndMail, [], False)
        self.toUser([f1])

    def toKernel(self): 
        cpu = self.cell_config.cpuFromCell(self.target)
        self.run2Kernel(cpu)

    def toProcPid(self, pid):
        self.toRunningProc(None, [pid], None)

    def inFlist(self, fun, the_list):
        for stop_fun in the_list:
            if stop_fun.fun == fun:
                return True
        return False

    def toRunningProc(self, proc, want_pid=None, flist=None):
        ''' intended for use when process is already running '''
        cpu, comm, pid  = self.task_utils.curProc()
        ''' if already in proc, just attach debugger '''
        self.lgr.debug('toRunningProc, look for <%s> current <%s>' % (proc, comm))
        if flist is not None and self.inFlist(self.debug, flist): 
            if proc is not None and proc == comm:
                self.lgr.debug('Already at proc %s, done' % proc)
                f1 = stopFunction.StopFunction(self.debug, [], False)
                self.toUser([f1])
                #self.debug()
                return
            elif want_pid is not None and pid in want_pid:
                self.lgr.debug('Already at pid %d, done' % pid)
                self.debug()
                return
        prec = Prec(cpu, proc, want_pid)
        phys_current_task = self.task_utils.getPhysCurrentTask()
        proc_break = SIM_breakpoint(cpu.physical_memory, Sim_Break_Physical, Sim_Access_Write, 
                             phys_current_task, self.mem_utils.WORD_SIZE, 0)
        self.lgr.debug('toRunningProc  pid %s set break at 0x%x' % (str(want_pid), phys_current_task))
        self.proc_hap = SIM_hap_add_callback_index("Core_Breakpoint_Memop", self.runToProc, prec, proc_break)
        
        hap_clean = hapCleaner.HapCleaner(cpu)
        hap_clean.add("Core_Breakpoint_Memop", self.proc_hap)
        stop_action = hapCleaner.StopAction(hap_clean, [proc_break], flist)
        self.stop_hap = SIM_hap_add_callback("Core_Simulation_Stopped", 
        	     self.stopHap, stop_action)

        status = self.is_monitor_running.isRunning()
        if not status:
            SIM_run_command('c')
       

    def getEIP(self, cpu=None):
        if cpu is None:
            dum, dum2, cpu = self.context_manager.getDebugPid() 
            if cpu is None:
                cpu = self.cell_config.cpuFromCell(self.target)
        eip = self.mem_utils.getRegValue(cpu, 'eip')
        return eip

    def getReg(self, reg, cpu):
        value = self.mem_utils.getRegValue(cpu, reg)
        self.lgr.debug('debugGetReg for %s is %x' % (reg, value))
        return value

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
        #self.lgr.debug('in gdbMailbox msg set to <%s>' % msg)
        print('gdbMailbox:%s' % msg)

    def emptyMailbox(self):
        if self.gdb_mailbox is not None and self.gdb_mailbox != "None":
            print self.gdb_mailbox
            #self.lgr.debug('emptying mailbox of <%s>' % self.gdb_mailbox)
            self.gdb_mailbox = None

    def runSkipAndMailAlone(self, cycles): 
        pid, dum2, cpu = self.context_manager.getDebugPid() 
        if cpu is None:
            self.lgr.debug("no cpu in runSkipAndMailAlone")
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
            self.lgr.debug("no cpu in runSkipAndMail")
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

        #self.stopTrace()
        self.restoreDebugBreaks()

    def goToOrigin(self):
        pid, dum2, cpu = self.context_manager.getDebugPid() 
        self.lgr.debug('goToOrigin for pid %d' % pid)
        self.bookmarks[pid].goToOrigin()

    def goToDebugBookmark(self, mark):
        self.lgr.debug('goToDebugBookmark %s' % mark)
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
        self.removeDebugBreaks()
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
        self.removeDebugBreaks()
        dum, dum2, cpu = self.context_manager.getDebugPid() 
        cell_name = self.getTopComponentName(cpu)
        self.removeDebugBreaks()
        self.context_manager.clearExitBreak()
        self.lgr.debug('reverseToCallInstruction, step_into: %r  on entry, gdb_mailbox: %s' % (step_into, self.gdb_mailbox))
        self.context_manager.showHaps()
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
        self.removeDebugBreaks()
        self.rev_to_call.doUncall()
   
    def getInstance(self):
        return INSTANCE
 
    def revToModReg(self, reg):
        self.lgr.debug('revToModReg for reg %s' % reg)
        self.removeDebugBreaks()
        self.context_manager.clearExitBreak()
        self.rev_to_call.doRevToModReg(reg)

    def revToAddr(self, address, extra_back=0):
        pid, cell_name, cpu = self.context_manager.getDebugPid() 
        self.lgr.debug('revToAddr 0x%x, extra_back is %d' % (address, extra_back))
        self.removeDebugBreaks()
        self.context_manager.clearExitBreak()
        reverseToAddr.reverseToAddr(address, self.context_manager, self.is_monitor_running, self, cpu, self.lgr, extra_back=extra_back)
        self.lgr.debug('back from reverseToAddr')

    ''' intended for use by gdb, if stopped return the eip.  checks for mailbox messages'''
    def getEIPWhenStopped(self, kernel_ok=False):
        #status = SIM_simics_is_running()
        status = self.is_monitor_running.isRunning()
        debug_pid, dum2, cpu = self.context_manager.getDebugPid() 
        if not status:
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
            eip = self.getEIP(cpu)
            self.lgr.debug('call to getEIPWhenStopped, not stopped at 0x%x' % eip)
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
        if self.context_manager.amWatching(pid):
            self.lgr.debug('rsynch, already in proc')
            f1 = stopFunction.StopFunction(self.skipAndMail, [], False)
            self.toUser([f1])
        else:
            f1 = stopFunction.StopFunction(self.toUser, [], True)
            f2 = stopFunction.StopFunction(self.skipAndMail, [], False)
            flist = [f1, f2]
            self.lgr.debug('rsynch, call toRunningProc for pid %d' % debug_pid)
            pid_list = self.context_manager.getThreadPids()
            self.toRunningProc(None, pid_list, flist)

    def traceExecve(self, comm=None):
        self.pfamily.traceExecve(comm)

    def watchPageFaults(self, debugging=None):
        self.page_faults.watchPageFaults(debugging)

    def stopWatchPageFaults(self, pid=None):
        self.page_faults.stopWatchPageFaults(pid)

    def catchCorruptions(self):
        self.watchPageFaults()

    def traceOpenSyscall(self):
        self.lgr.debug('about to call traceOpen')
        self.traceOpen.traceOpenSyscall()

    def getCell(self):
        return self.cell_config.cell_context[self.target]

    def getCPU(self):
        return self.cell_config.cpuFromCell(self.target)

    def reverseToUser(self):
        self.removeDebugBreaks()
        cpu = self.cell_config.cpuFromCell(self.target)
        cell = self.cell_config.cell_context[self.target]
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
        self.removeDebugBreaks()
        pid, dum2, cpu = self.context_manager.getDebugPid() 
        cell_name = self.getTopComponentName(cpu)
        self.lgr.debug('stopAtKernelWrite, call findKernelWrite for 0x%x num bytes %d' % (addr, num_bytes))
        cell = self.cell_config.cell_context[self.target]
        self.find_kernel_write = findKernelWrite.findKernelWrite(self, cpu, cell, addr, self.task_utils, self.task_utils,
            self.context_manager, self.param, self.bookmarks[pid], self.lgr, rev_to_call, num_bytes) 

    def revTaintAddr(self, addr):
        '''
        back track the value at a given memory location, where did it come from?
        '''
        self.lgr.debug('revTaintAddr for 0x%x' % addr)
        self.removeDebugBreaks()
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
        self.removeDebugBreaks()
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
        if self.rev_execution_enabled:
            self.removeDebugBreaks()
            dum, dum2, cpu = self.context_manager.getDebugPid() 
            new_cycle = cpu.cycles - 1
         
            start_cycles = self.rev_to_call.getStartCycles()
            if new_cycle >= start_cycles:
                self.is_monitor_running.setRunning(True)
                result = SIM_run_command('skip-to cycle=0x%x' % new_cycle)
                self.lgr.debug('rev1 result from skipt to 0x%x  is %s' % (new_cycle, result))
                self.skipAndMail()
            else:
                self.lgr.debug('rev1, already at first cycle 0x%x' % new_cycle)
                self.skipAndMail()
        else:
            print('reverse execution disabled')
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
            
    def revOver(self): 
        self.reverseToCallInstruction(False)

    def revInto(self): 
        self.reverseToCallInstruction(True)

    def revToWrite(self, addr):
        self.stopAtKernelWrite(addr)

    def runToSyscall(self, callnum = None):
        cell = self.cell_config.cell_context[self.target]
        self.is_monitor_running.setRunning(True)
        if callnum == 0:
            callnum = None
        self.lgr.debug('runToSyscall for callnumm %s' % callnum)
        my_syscall = syscall.Syscall(self, cell, self.param, self.mem_utils, self.task_utils, self.context_manager, None, self.sharedSyscall, self.lgr, callnum_list=[callnum])

    def traceSyscall(self, callnum=None, soMap=None, call_params=[], trace_procs = False):
        cell = self.cell_config.cell_context[self.target]
        # TBD only set if debugging?
        self.is_monitor_running.setRunning(True)
        if callnum == 0:
            callnum = None
        self.lgr.debug('traceSyscall for callnumm %s' % callnum)
        if trace_procs:
            tp = self.traceProcs
        else:
            tp = None
        my_syscall = syscall.Syscall(self, cell, self.param, self.mem_utils, self.task_utils, 
                           self.context_manager, tp, self.sharedSyscall, self.lgr, callnum_list=[callnum], trace=True, trace_fh = self.trace_fh, soMap=soMap, call_params=call_params)
        return my_syscall

    def traceProcesses(self):
        call_list = ['vfork','fork', 'clone','execve','open','pipe','pipe2','close','dup','dup2','socketcall', 'exit', 'exit_group']
        calls = ' '.join(s for s in call_list)
        print('tracing these system calls: %s' % calls)
        self.trace_fh = open('/tmp/syscall_trace.txt', 'w')
        self.sharedSyscall.setTrace(self.trace_fh)
        for call in call_list: 
            '''
            if call == 'open':
                self.call_traces[call] = self.traceSyscall(callnum=self.task_utils.syscallNumber(call), soMap=self.soMap, trace_procs=True)
            else:
                self.call_traces[call] = self.traceSyscall(callnum=self.task_utils.syscallNumber(call))
            '''
            self.call_traces[call] = self.traceSyscall(self.task_utils.syscallNumber(call), trace_procs=True)

    def stopTrace(self):
        self.lgr.debug('stopTrace from genMonitor')
        for call in self.call_traces:
            callnum=self.task_utils.syscallNumber(call)
            self.lgr.debug('stopTrace of call %s' % call)
            self.call_traces[call].stopTrace(immediate=True)
        self.call_traces.clear()   
        if self.trace_all is not None:
            self.trace_all.stopTrace(immediate=True)
            self.trace_all = None

    def traceFile(self, path):
        outfile = os.path.join('/tmp', os.path.basename(path))
        self.traceFiles.watchFile(path, outfile)

    def traceFD(self, fd):
        outfile = '/tmp/output-fd-%d.log' % fd
        self.traceFiles.watchFD(fd, outfile)

    def traceAll(self):
        ''' trace all system calls. if a program selected for debugging, watch only that program '''
        self.lgr.debug('traceAll begin')
        cell = self.cell_config.cell_context[self.target]
        self.trace_fh = open('/tmp/syscall_trace.txt', 'w')
        self.sharedSyscall.setTrace(self.trace_fh)
        #call_list = ['vfork','clone','execve','open','pipe','pipe2','close','dup','dup2','socketcall']
        #call_list = ['vfork', 'clone']
        #calls = ' '.join(s for s in call_list)
        #print('tracing these system calls: %s' % calls)
        #callnum_list = []
        #for call in call_list:
        #    callnum_list.append(self.task_utils.syscallNumber(call))

        #my_syscall = syscall.Syscall(self, cell, self.param, self.mem_utils, self.task_utils, 
        #                   self.context_manager, self.traceProcs, self.lgr, callnum_list=callnum_list, 
        #                   trace=True, trace_fh = self.trace_fh, traceFiles=self.traceFiles)
        self.trace_all = syscall.Syscall(self, cell, self.param, self.mem_utils, self.task_utils, 
                           self.context_manager, self.traceProcs, self.sharedSyscall, self.lgr, callnum_list=None, 
                           trace=True, trace_fh = self.trace_fh, traceFiles=self.traceFiles)

    def noDebug(self):
        self.lgr.debug('noDebug')
        cmd = 'disable-reverse-execution'
        SIM_run_command(cmd)
        self.rev_execution_enabled = False
        self.removeDebugBreaks()
        self.sharedSyscall.setDebugging(False)

    def restartDebug(self):
        cmd = 'enable-reverse-execution'
        SIM_run_command(cmd)
        self.rev_execution_enabled = True
        self.restoreDebugBreaks()
        self.sharedSyscall.setDebugging(True)

    def stopThreadTrack(self):
        self.lgr.debug('stopThreadTrack')
        self.track_threads.stopTrack()

    def showProcTrace(self):
        pid_comm_map = self.task_utils.getPidCommMap()
        precs = self.traceProcs.getPrecs()
        for pid in precs:
            if precs[pid].prog is None and pid in pid_comm_map:
                precs[pid].prog = 'comm: %s' % (pid_comm_map[pid])
        for pid in precs:
            if precs[pid].prog is None and pid in self.proc_list:
                precs[pid].prog = 'comm: %s' % (self.proc_list[pid])
        
        self.traceProcs.showAll()
 
    def toExecve(self, comm, flist=None):
        cell = self.cell_config.cell_context[self.target]
        callnum=self.task_utils.syscallNumber('execve')
        my_syscall = syscall.Syscall(self, cell, self.param, self.mem_utils, self.task_utils, 
                           self.context_manager, self.traceProcs, self.sharedSyscall, self.lgr, callnum_list=[callnum], 
                           trace=False, trace_fh = None, break_on_execve=comm, flist_in = flist, netInfo=self.netInfo)

    def clone(self, nth=1):
        ''' Run until we are in the child of the Nth clone of the current process'''
        cell = self.cell_config.cell_context[self.target]
        eh = cloneChild.CloneChild(self, cell, self.param, self.mem_utils, self.task_utils, self.context_manager, nth, self.lgr)
        SIM_run_command('c')

    def recordText(self, start, end):
        ''' record IDA's view of text segment, unless we recorded from our own parse of the elf header '''
        self.lgr.debug('.text IDA is 0x%x - 0x%x' % (start, end))
        s, e = self.context_manager.getText()
        if s is None:
            self.context_manager.recordText(start, end)
            self.soMap.addText(start, end-start, 'tbd')

    def textHap(self, prec, third, forth, memory):
        ''' callback when text segment is executed '''
        if self.proc_hap is None:
            return
        cpu, comm, pid = self.task_utils.curProc() 
        if cpu != prec.cpu or pid not in prec.pid:
            self.lgr.debug('text hap, wrong something %d prec pid list %s' % (pid, str(prec.pid)))
            return
        #cur_eip = SIM_get_mem_op_value_le(memory)
        eip = self.getEIP(cpu)
        self.lgr.debug('textHap, must be in text eip is 0x%x' % eip)
        SIM_break_simulation('text hap')
        if prec.debugging:
            self.context_manager.genDeleteHap(self.proc_hap)
            self.proc_hap = None
            self.skipAndMail()
 
    def restoreDebugBreaks(self, dumb=None):
        if not self.debug_breaks_set:
            self.lgr.debug('restoreDebugBreaks')
            pid, cell_name, cpu = self.context_manager.getDebugPid() 
            if pid is not None:
                self.context_manager.watchTasks()
                prec = Prec(cpu, None, pid)
                self.rev_to_call.watchSysenter(prec)
                if self.track_threads is not None:
                    self.track_threads.startTrack()
            cell = self.cell_config.cell_context[self.target]
            self.exit_group_syscall = syscall.Syscall(self, cell, self.param, self.mem_utils, self.task_utils, 
                           self.context_manager, None, self.sharedSyscall, self.lgr, callnum_list=[self.task_utils.syscallNumber('exit_group')], continue_simulation=False)
            self.debug_breaks_set = True


    def noWatchSysEnter(self):
        self.rev_to_call.noWatchSysenter()

    def removeDebugBreaks(self):
        self.lgr.debug('removeDebugBreaks')
        pid, cell_name, cpu = self.context_manager.getDebugPid() 
        self.stopWatchPageFaults(pid)
        self.context_manager.stopWatchTasks()
        self.rev_to_call.noWatchSysenter()
        if self.track_threads is not None:
            self.track_threads.stopTrack()
        if self.exit_group_syscall is not None:
            self.exit_group_syscall.stopTrace()
            self.exit_group_syscall = None
        self.debug_breaks_set = False

    def revToText(self):
        self.is_monitor_running.setRunning(True)
        start, end = self.context_manager.getText()
        if start is None:
            print('No text segment defined, has IDA been started with the rev plugin?')
            return
        self.removeDebugBreaks()
        count = end - start
        self.lgr.debug('revToText 0x%x - 0x%x count: 0x%x' % (start, end, count))
        cell = self.cell_config.cell_context[self.target]
        cpu, comm, pid = self.task_utils.curProc() 
        self.rev_to_call.setBreakRange(self.target, pid, start, count, cpu, comm, False)
        f1 = stopFunction.StopFunction(self.skipAndMail, [], False)
        f2 = stopFunction.StopFunction(self.rev_to_call.rmBreaks, [], False)
        flist = [f1, f2]
        hap_clean = hapCleaner.HapCleaner(cpu)
        stop_action = hapCleaner.StopAction(hap_clean, None, flist)
        self.stop_hap = SIM_hap_add_callback("Core_Simulation_Stopped", 
          self.stopHap, stop_action)
        self.lgr.debug('hap set, now reverse')
        SIM_run_command('rev')

    def getSyscall(self, callname):
        if callname in self.call_traces:
            return self.call_traces[callname]
        elif self.trace_all is not None:
            return self.trace_all
        else:
            self.lgr.error('getSyscall, not able to return instance for call %s len self.call_traces %d' % (callname, len(self.call_traces)))

    def runToText(self, flist = None):
        ''' run until within the currently defined text segment '''
        self.is_monitor_running.setRunning(True)
        start, end = self.context_manager.getText()
        if start is None:
            print('No text segment defined, has IDA been started with the rev plugin?')
            return
        count = end - start
        cell = self.cell_config.cell_context[self.target]
        self.lgr.debug('runToText range 0x%x 0x%x' % (start, end))
        proc_break = self.context_manager.genBreakpoint(cell, Sim_Break_Linear, Sim_Access_Execute, start, count, 0)
        pid, cell_name, cpu = self.context_manager.getDebugPid() 
        if cpu is None:
            self.lgr.debug('runToText, not debugging yet, assume current process')
            cpu, comm, pid = self.task_utils.curProc() 
            prec = Prec(cpu, None, [pid])
        else:
            pid_list = self.context_manager.getThreadPids()
            prec = Prec(cpu, None, pid_list)
        if flist is None:
            prec.debugging = True
            f1 = stopFunction.StopFunction(self.skipAndMail, [], False)
            flist = [f1]
        else:
            self.call_traces['open'] = self.traceSyscall(callnum=self.task_utils.syscallNumber('open'), soMap=self.soMap)

        self.proc_hap = self.context_manager.genHapIndex("Core_Breakpoint_Memop", self.textHap, prec, proc_break, 'text_hap')

        hap_clean = hapCleaner.HapCleaner(cpu)
        hap_clean.add("GenContext", self.proc_hap)
        stop_action = hapCleaner.StopAction(hap_clean, None, flist)
        self.stop_hap = SIM_hap_add_callback("Core_Simulation_Stopped", 
          self.stopHap, stop_action)
        self.lgr.debug('hap set, now run')
        SIM_run_alone(SIM_run_command, 'continue')

    def runToConnect(self, addr, nth=None):
        #addr = '192.168.31.52:20480'
        self.is_monitor_running.setRunning(True)
        call_params = syscall.CallParams('CONNECT', addr, break_simulation=True)        
        call_params.nth = nth
        cell = self.cell_config.cell_context[self.target]
        self.lgr.debug('runToConnect to %s' % addr)
        self.call_traces['socketcall'] = syscall.Syscall(self, cell, self.param, self.mem_utils, self.task_utils, 
                               self.context_manager, None, self.sharedSyscall, self.lgr, 
                               callnum_list=[self.task_utils.syscallNumber('socketcall')], call_params=[call_params], continue_simulation=False)
        self.lgr.debug('back from runToConnect to %s' % addr)
        SIM_run_command('c')

    def runToWrite(self, substring):
        self.is_monitor_running.setRunning(True)
        call_params = syscall.CallParams('write', substring, break_simulation=True)        
        cell = self.cell_config.cell_context[self.target]
        self.lgr.debug('runToWrite to %s' % substring)
        self.call_traces['write'] = syscall.Syscall(self, cell, self.param, self.mem_utils, self.task_utils, 
                               self.context_manager, None, self.sharedSyscall, self.lgr, 
                               callnum_list=[self.task_utils.syscallNumber('write')], call_params=[call_params], continue_simulation=False)
        SIM_run_command('c')
    def runToBind(self, addr):
        #addr = '192.168.31.52:20480'
        self.is_monitor_running.setRunning(True)
        call_params = syscall.CallParams('BIND', addr, break_simulation=True)        
        cell = self.cell_config.cell_context[self.target]
        self.lgr.debug('runToBind to %s' % addr)
        self.call_traces['socketcall'] = syscall.Syscall(self, cell, self.param, self.mem_utils, self.task_utils, 
                               self.context_manager, None, self.sharedSyscall, self.lgr, 
                               callnum_list=[self.task_utils.syscallNumber('socketcall')], call_params=[call_params], continue_simulation=False)
        SIM_run_command('c')
    def runToIO(self, fd):
        self.is_monitor_running.setRunning(True)
        call_params = syscall.CallParams(None, fd, break_simulation=True)        
        cell = self.cell_config.cell_context[self.target]
        self.lgr.debug('runToIO to read %d' % fd)
        calls = ['read', 'write', '_llseek', 'socketcall', 'close' ]
        callnums = []
        for call in calls:
            callnum=self.task_utils.syscallNumber(call)
            callnums.append(callnum)

        the_syscall = syscall.Syscall(self, cell, self.param, self.mem_utils, self.task_utils, 
                               self.context_manager, None, self.sharedSyscall, self.lgr, 
                               callnums, call_params=[call_params], 
                               continue_simulation=False)
        for call in calls:
            self.call_traces[call] = the_syscall
        SIM_run_command('c')


    def getCurrentSO(self):
        cpu, comm, pid = self.task_utils.curProc() 
        eip = self.getEIP(cpu)
        retval = self.getSO(eip)
        return retval

    def getSO(self, eip):
        cpu, comm, pid = self.task_utils.curProc() 
        fname = self.getSOFile(pid, eip)
        self.lgr.debug('getCurrentSO fname for eip 0x%x is %s' % (eip, fname))
        retval = None
        if fname is not None:
            text_seg  = self.soMap.getSOAddr(pid, fname) 
            base = text_seg.start
            if base is not None:
                end = base+text_seg.size
                print('%s:0x%x-0x%x' % (fname, base, end))
                retval = ('%s:0x%x-0x%x' % (fname, base, end))
            else:
                print('None')
        else:
            print('None')
        return retval
     
    def showSOMap(self, pid=None):
        self.lgr.debug('showSOMap')
        if pid is None:
            cpu, comm, pid = self.task_utils.curProc() 
        self.lgr.debug('showSOMap pid %d' % pid)
        self.soMap.showSO(pid)

    def getSOFile(self, pid, addr):
        fname = self.soMap.getSOFile(pid, addr)
        return fname

    def showThreads(self):
        pid, cell_name, cpu = self.context_manager.getDebugPid() 
        thread_recs = self.context_manager.getThreadRecs()
        for rec in thread_recs:
            pid = self.mem_utils.readWord32(cpu, rec + self.param.ts_pid)
            state = self.mem_utils.readWord32(cpu, rec)
            self.lgr.debug('thread pid: %d state: 0x%x rec: 0x%x' % (pid, state, rec)) 
            print('thread pid: %d state: 0x%x rec: 0x%x' % (pid, state, rec)) 
            

    def traceRoutable(self):
        call_list = ['vfork','fork', 'clone','execve','socketcall']
        call_params = {}
        call_params['socketcall'] = []
        cp = syscall.CallParams('CONNECT', None)
        cp.param_flags.append(syscall.ROUTABLE)
        call_params['socketcall'].append(cp)

        calls = ' '.join(s for s in call_list)
        print('tracing these system calls: %s' % calls)
        self.trace_fh = open('/tmp/syscall_trace.txt', 'w')
        self.sharedSyscall.setTrace(self.trace_fh)
        for call in call_list: 
            this_call_params = []
            if call in call_params:
                this_call_params = call_params[call]
            self.call_traces[call] = self.traceSyscall(callnum=self.task_utils.syscallNumber(call), call_params=this_call_params, trace_procs=True)

    def traceListen(self):
        ''' generate a syscall trace of processes that bind to an IP address/port '''
        call_list = ['vfork','fork', 'clone','execve','socketcall']
        call_params = {}
        call_params['socketcall'] = []
        cp = syscall.CallParams('BIND', None)
        cp.param_flags.append(syscall.AF_INET)
        call_params['socketcall'].append(cp)

        calls = ' '.join(s for s in call_list)
        print('tracing these system calls: %s' % calls)
        self.trace_fh = open('/tmp/syscall_trace.txt', 'w')
        self.sharedSyscall.setTrace(self.trace_fh)
        for call in call_list: 
            this_call_params = []
            if call in call_params:
                this_call_params = call_params[call]
            self.call_traces[call] = self.traceSyscall(callnum=self.task_utils.syscallNumber(call), call_params=this_call_params, trace_procs=True)

    def showBinders(self):
        if 'socketcall' in self.call_traces:
            ''' is of class Binders '''
            binders = self.call_traces['socketcall'].getBinders()
            binders.showAll('/tmp/binder.txt')
            binders.dumpJson('/tmp/binder.json')

    def dumpBinders(self):
        if 'socketcall' in self.call_traces:
            ''' is of class Binders '''
            binders = self.call_traces['socketcall'].getBinders()
            binders.dumpJson('/tmp/binder.json')

    def showConnectors(self):
        if 'socketcall' in self.call_traces:
            ''' is of class Connectors '''
            connectors = self.call_traces['socketcall'].getConnectors()
            connectors.showAll('/tmp/connector.txt')
            connectors.dumpJson('/tmp/connector.json')

    def dumpConnectors(self):
        if 'socketcall' in self.call_traces:
            ''' is of class Connectors '''
            connectors = self.call_traces['socketcall'].getConnectors()
            connectors.dumpJson('/tmp/connector.json')

    def stackTrace(self):
        cpu, comm, pid = self.task_utils.curProc() 
        st = stackTrace.StackTrace(self, cpu, pid, self.soMap, self.mem_utils, self.task_utils, self.stack_base, self.lgr)
        st.printTrace()

    def getStackTrace(self):
        self.lgr.debug('getStackTrace')
        cpu, comm, pid = self.task_utils.curProc() 
        st = stackTrace.StackTrace(self, cpu, pid, self.soMap, self.mem_utils, self.task_utils, self.stack_base, self.lgr)
        j = st.getJson() 
        self.lgr.debug(j)
        print j

    def writeRegValue(self, reg, value):
        cpu, comm, pid = self.task_utils.curProc() 
        reg_num = cpu.iface.int_register.get_number(reg)
        cpu.iface.int_register.write(reg_num, value)
        self.lgr.debug('writeRegValue %s, %x regnum %d' % (reg, value, reg_num))

    def writeWord(self, address, value):
        cpu, comm, pid = self.task_utils.curProc() 
        phys_block = cpu.iface.processor_info.logical_to_physical(address, Sim_Access_Read)
        SIM_write_phys_memory(cpu, phys_block.address, value, 4)

    def watchData(self, start=None, length=None):
        if start is not None:
            self.lgr.debug('watchData 0x%x count %d' % (start, length))
            self.dataWatch.setRange(start, length) 
        self.is_monitor_running.setRunning(True)
        if self.dataWatch.watch():
            SIM_run_command('c')
        else: 
            print('no data being watched')

    def isProtectedMemory(self, addr):
        ''' compat with CGC version '''
        return False 

    def showHaps(self):
        self.context_manager.showHaps()

    def addMazeExit(self):
        ''' Intended for use if it seems a maze exit is nested -- will cause the most recent breakout
            address to be ignored when setting maze exit breakpoints '''
        if self.exit_maze is not None:
            eip = self.exit_maze.getBreakout()
            if eip is not None:
                self.lgr.debug('addMazeExit adding 0x%x to exits' % eip)
                self.maze_exits.append(eip)

    def getMazeExits(self):
        return self.maze_exits

    def exitMaze(self, debugging=False):
        cpu, comm, pid = self.task_utils.curProc() 
        cpl = memUtils.getCPL(cpu)
        if cpl == 0:
            print('Must first run to user space.')
            return
        cell = self.cell_config.cell_context[self.target]
        self.is_monitor_running.setRunning(True)
        tod_track = self.trace_all
        if tod_track is None:
            tod_track = syscall.Syscall(self, cell, self.param, self.mem_utils, self.task_utils, 
                           self.context_manager, None, self.sharedSyscall, self.lgr, callnum_list=[self.task_utils.syscallNumber('gettimeofday')], 
                           continue_simulation=False)
        self.exit_maze = exitMaze.ExitMaze(self, cpu, cell, pid, tod_track, self.context_manager, self.task_utils, self.mem_utils, debugging, self.lgr)
        self.exit_maze.run()
        #self.exit_maze.showInstructs()

    def plantBreaks(self):
        if self.exit_maze is not None:
            self.exit_maze.plantBreaks() 
        print('Maze exit breaks planted')

    def plantCmpBreaks(self):
        if self.exit_maze is not None:
            self.exit_maze.plantCmpBreaks() 
            print('Maze pruning breaks planted')

    def showParams(self):
        self.param.printParams()

    def writeConfig(self, name):
        cmd = 'write-configuration %s' % name 
        SIM_run_command(cmd)
        plist_file = os.path.join('./', name, 'proc_list.pickle')
        pickle.dump( self.proc_list, open( plist_file, "wb" ) )
        net_file = os.path.join('./', name, 'net_list.pickle')
        self.netInfo.pickleit(net_file)
        self.task_utils.pickleit(name)
        self.soMap.pickleit(name)

    def continueForward(self):
        self.lgr.debug('continueForward')
        self.is_monitor_running.setRunning(True)
        SIM_run_command('c')

    def showNets(self):
        net_commands = self.netInfo.getCommands()
        if len(net_commands) > 0:
           print('Network definition commands:')
        for c in net_commands:
            print c

    def notRunning(self):
        status = self.is_monitor_running.isRunning()
        if status:   
            print('Was running, set to not running')
            self.is_monitor_running.setRunning(False)
    
if __name__=="__main__":        
    print('instantiate the GenMonitor') 
    cgc = GenMonitor()
    cgc.doInit()
