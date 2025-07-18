import os
import binascii
import re
from simics import *
import hapCleaner
import taskUtils
import net
import ipc
import memUtils
import stopFunction
import pageUtils
import dmod
import resimUtils
import syscall
import sys
import copy
import ntpath
import winProg
import winSocket
import winFile
import winNTSTATUS
import net
import winDelay
import doInUser
from resimHaps import *
from resimSimicsUtils import rprint
PROC_CREATE_INFO_OFFSET=0x58
PROG_NAME_OFFSET=0x18
def paramOffPtrUtil(pnum, offset_list, frame, word_size, cpu, mem_utils, lgr):
        param = 'param%d' % pnum
        pval = frame[param]
        #lgr.debug('paramOffPtr word size %d starting pval is 0x%x' % (word_size, pval))
        for offset in offset_list:
            ptr = pval + offset
            #lgr.debug('paramOffPtr param%d offset 0x%x from pval 0x%x ptr 0x%x' % (pnum, offset, pval, ptr))
            if word_size == 8:
                pval = mem_utils.readWord(cpu, ptr)
            elif word_size == 4: 
                pval = mem_utils.readWord32(cpu, ptr)
            if pval is not None:
                #lgr.debug('paramOffPtr got new pval 0x%x by reading ptr 0x%x' % (pval, ptr))
                pass
            else:
                lgr.error('paramOffPtr got new pval is None reading from ptr 0x%x' % ptr)
                break
        return pval

class WinSyscall():

    def __init__(self, top, cell_name, cell, param, mem_utils, task_utils, context_manager, traceProcs, sharedSyscall, lgr, 
                   traceMgr, dataWatch, call_list=None, trace = False, flist_in=None, soMap = None, 
                   call_params=[], connectors=None, stop_on_call=False, targetFS=None, skip_and_mail=True, linger=False,
                   background=False, name=None, record_fd=False, callback=None, swapper_ok=False, kbuffer=None, no_gui=False): 
        self.lgr = lgr
        self.traceMgr = traceMgr
        self.mem_utils = mem_utils
        self.task_utils = task_utils
        self.dataWatch = dataWatch
        self.context_manager = context_manager
        ''' mostly a test if we are debugging (if tid is not none). not very clean '''
        tid, cpu = context_manager.getDebugTid()
        self.debugging = False
        self.stop_on_call = stop_on_call
        if tid is not None:
            self.debugging = True
            #self.lgr.debug('winSyscall is debugging cell %s' % cell_name)
        self.cpu = cpu
        ''' Note cell may be None, leaving it up to the context manager '''
        self.cell_name = cell_name
        self.cell = cell
        if cell is not None:
            self.lgr.debug('syscall _init_ cell_name %s, name: %s, param: %s cell is not none, cell.name: %s' % (cell_name, name, str(call_params), cell.name))
        else:
            self.lgr.debug('syscall _init_ cell_name %s, name: %s, param: %s cell is none.' % (cell_name, name, str(call_params)))
        self.top = top
        self.param = param
        self.sharedSyscall = sharedSyscall
        self.traceProcs = traceProcs
        self.stop_hap = None
        self.finish_hap = {}
        self.finish_break = {}
        self.finish_hap_page = {}
        self.finish_hap_table = {}
        self.first_mmap_hap = {}
        self.soMap = soMap
        self.proc_hap = []
        self.timeofday_count = {}
        self.timeofday_start_cycle = {}
        self.call_list = call_list
        self.trace = trace
        if call_params is None:
            self.call_params = []
        else:
            self.call_params = call_params
        self.stop_action = None
        self.stop_maze_hap = None
        self.targetFS = targetFS
        self.linger = linger
        self.linger_cycles = []
        self.background_break = None
        self.background_hap = None
        self.name = name
        self.watch_first_mmap = None
        self.mmap_fname = None
        self.comm_cache = {}
        self.record_fd = record_fd
        self.syscall_info = None
        self.alt_syscall_info = None
        self.callback = callback
        ''' normally ignore syscalls made by swapper '''
        self.swapper_ok = swapper_ok

        ''' catch dual invocation of syscallHap.  TBD, find root cause and yank it out '''
        self.hack_cycle = 0

        self.sockwatch = syscall.SockWatch()

        self.ignore_progs = context_manager.getIgnoredProgs()
        # see syscall.py
        self.flist_in = flist_in

        if trace is None and self.traceMgr is not None:
            tf = 'logs/syscall_trace.txt'
            #self.traceMgr.open(tf, cpu, noclose=True)
            self.traceMgr.open(tf, cpu)
        ''' track kernel buffers '''
        self.kbuffer = kbuffer

        ''' And one for tracking epoll info '''
        self.epolls = {}
      
        self.syscall_context = None 
        self.background = background
        break_list, break_addrs = self.doBreaks(background)

        self.break_simulation = False
        for call in self.call_params:
            if call is not None and call.break_simulation:
                self.break_simulation = True
                break 
 
        if flist_in is not None:
            ''' Given function list to use after syscall completes '''
            hap_clean = hapCleaner.HapCleaner(cpu)
            #for ph in self.proc_hap:
            #    self.lgr.debug('winSyscall proc hap %s adding to hap cleander' % str(ph))
            #    hap_clean.add("GenContext", ph)
            self.stop_action = hapCleaner.StopAction(hap_clean, flist=flist_in, break_addrs = break_addrs)
            self.lgr.debug('winSyscall cell %s stop action includes given flist_in.  stop_on_call is %r linger: %r name: %s' % (self.cell_name, stop_on_call, self.linger, name))
        elif (self.break_simulation or self.debugging) and not self.breakOnProg() and not trace and skip_and_mail:
            hap_clean = hapCleaner.HapCleaner(cpu)
            #for ph in self.proc_hap:
            #    hap_clean.add("GenContext", ph)
            #f1 = stopFunction.StopFunction(self.top.skipAndMail, [], nest=False)
            f1 = stopFunction.StopFunction(self.top.stepN, [1], nest=False)
            flist = [f1]
            self.stop_action = hapCleaner.StopAction(hap_clean, flist=flist, break_addrs = break_addrs)
            self.lgr.debug('winSyscall cell %s stop action includes stepN in flist. SOMap exists: %r linger: %r name: %s' % (self.cell_name, (soMap is not None), self.linger, name))
        elif not self.linger:
            hap_clean = hapCleaner.HapCleaner(cpu)
            #for ph in self.proc_hap:
            #    hap_clean.add("GenContext", ph)
            self.stop_action = hapCleaner.StopAction(hap_clean, break_addrs = break_addrs)
            self.lgr.debug('winSyscall cell %s stop action includes NO flist linger: %r name: %s' % (self.cell_name, self.linger, name))
        else:
            self.lgr.debug('winSyscall cell %s name: %s linger is true, and no flist or other reason to stop, so no stop action' % (name, self.cell_name))

        self.exit_calls = ['TerminateProcess', 'TerminateThread']
        
        ''' TBD '''
        self.stop_on_exit = False

        ''' Used when finding newly created tasks '''
        self.cur_task_break = None
        self.cur_task_hap = None
        self.current_tasks = []

        self.ioctl_op_map = winSocket.getOpMap()

        self.word_size_cache = {}
        self.default_app_word_size = 8
        env_word_size = os.getenv('DEFAULT_APP_WORD_SIZE')
        if env_word_size is not None:
            self.default_app_word_size = int(env_word_size)
            self.lgr.debug('winSyscall using default application word size from env: %d' % self.default_app_word_size)
        else:
            self.lgr.debug('winSyscall using default application word size of 8')

        ''' when stophap it, remove these parameters '''
        self.rm_param_queue = []
        ''' Detect orphen winDelays '''
        self.win_delays = {}
        self.no_gui = no_gui

        ''' catch syscall calling syscall '''
        self.pending_calls = {}


    def breakOnProg(self):
        for call in self.call_params:
            if call is not None and call.subcall == 'CreateUserProcess' and call.break_simulation:
                self.lgr.debug('winSyscall breakOnProg return true')
                return True
        return False

    def doBreaks(self, background):
        break_list = []
        break_addrs = []
        self.timeofday_count = {}
        self.timeofday_start_cycle = {}
        self.lgr.debug('winSyscall cell_name %s doBreaks.  reset timeofdaycount' % (self.cell_name))
        if self.call_list is None:
            ''' trace all calls '''
            self.lgr.debug('winSyscall doBreaks trace all')
            self.syscall_info = syscall.SyscallInfo(self.cpu, None, None, self.trace)
            if self.cpu.architecture.startswith('arm'):
                #phys = self.mem_utils.v2p(self.cpu, self.param.arm_entry)
                #self.lgr.debug('winSyscall arm no callnum, set break at 0x%x ' % (self.param.arm_entry))
                proc_break = self.context_manager.genBreakpoint(self.cell, Sim_Break_Linear, Sim_Access_Execute, self.param.arm_entry, 1, 0)
                if self.syscall_context is None:
                    self.syscall_context = self.context_manager.getBPContext(proc_break)
                    #self.lgr.debug('syscall, setting syscall_context to %s' % self.syscall_context)
                #proc_break = self.context_manager.genBreakpoint(self.cpu.physical_memory, Sim_Break_Physical, Sim_Access_Execute, phys, 1, 0)
                break_addrs.append(self.param.arm_entry)
                self.proc_hap.append(self.context_manager.genHapIndex("Core_Breakpoint_Memop", self.syscallHap, self.syscall_info, proc_break, 'syscall'))
            else:
                if self.param.sysenter is not None:
                    proc_break = self.context_manager.genBreakpoint(self.cell, Sim_Break_Linear, Sim_Access_Execute, self.param.sysenter, 1, 0)
                    break_addrs.append(self.param.sysenter)
                    break_list.append(proc_break)
                    if self.param.sys_entry is not None and self.param.sys_entry != 0:
                        ''' Has sys_entry as well. '''
                        #self.lgr.debug('winSyscall no callnum, set sysenter and sys_entry break at 0x%x & 0x%x' % (self.param.sysenter, self.param.sys_entry))
                        self.lgr.debug('winSyscall doBreaks no callnum, set sys_entry break at 0x%x ' % (self.param.sys_entry))
                        proc_break1 = self.context_manager.genBreakpoint(self.cell, Sim_Break_Linear, Sim_Access_Execute, self.param.sys_entry, 1, 0)
                        break_addrs.append(self.param.sys_entry)
                        break_list.append(proc_break1)
                        self.proc_hap.append(self.context_manager.genHapRange("Core_Breakpoint_Memop", self.syscallHap, self.syscall_info, proc_break, proc_break1, 'syscall'))
                    else:
                        self.lgr.debug('winSyscall no callnum, set sysenter break at 0x%x ' % (self.param.sysenter))
                        self.proc_hap.append(self.context_manager.genHapIndex("Core_Breakpoint_Memop", self.syscallHap, self.syscall_info, proc_break, 'syscall'))
                elif self.param.sys_entry is not None and self.param.sys_entry != 0:
                        #self.lgr.debug('winSyscall no callnum, set sys_entry break at 0x%x' % (self.param.sys_entry))
                        proc_break1 = self.context_manager.genBreakpoint(self.cell, Sim_Break_Linear, Sim_Access_Execute, self.param.sys_entry, 1, 0)
                        break_addrs.append(self.param.sys_entry)
                        break_list.append(proc_break1)
                        self.proc_hap.append(self.context_manager.genHapIndex("Core_Breakpoint_Memop", self.syscallHap, self.syscall_info, proc_break1, 'syscall'))
                else:
                    self.lgr.debug('SysCall no call list, no breaks set.  parms: %s' % self.param.getParamString())
        
        else:
            if self.syscall_info is None:
                self.syscall_info = syscall.SyscallInfo(self.cpu, None, True, self.trace)
            ''' will stop within the kernel at the computed entry point '''
            did_callnum = []
            self.lgr.debug('winSyscall doBreaks computed')
            for call in self.call_list:
                callnum = self.task_utils.syscallNumber(call)
                if callnum in did_callnum:
                    continue
                else:
                    did_callnum.append(callnum)
                if callnum is not None:
                    self.lgr.debug('SysCall doBreaks call: %s  num: %d' % (call, callnum))
                if callnum is not None and callnum < 0:
                    self.lgr.error('winSyscall bad call number %d for call <%s>' % (callnum, call))
                    return None, None
                if callnum is None:
                    self.lgr.error('Failed to get call number for call %s' % call)
                    return None, None
                entry = self.task_utils.getSyscallEntry(callnum)
                self.lgr.debug('winSyscall call addCall for callnum %d' % callnum)
                self.syscall_info.addCall(callnum, entry, False)
                if entry is None:
                    self.lgr.error('Failed to get entry for callnum %d' % callnum)
                    return None, None
                #phys = self.mem_utils.v2p(cpu, entry)
                #proc_break = self.context_manager.genBreakpoint(self.cpu.physical_memory, Sim_Break_Physical, Sim_Access_Execute, phys, 1, 0)
                debug_tid, dumb = self.context_manager.getDebugTid() 
                if not background or debug_tid is not None:
                    self.lgr.debug('winSyscall callnum %s name %s entry 0x%x call_params %s' % (callnum, call, entry, str(self.syscall_info)))
                    proc_break = self.context_manager.genBreakpoint(self.cell, Sim_Break_Linear, Sim_Access_Execute, entry, 1, 0)
                    proc_break1 = None
                    break_list.append(proc_break)
                    break_addrs.append(entry)
                    self.proc_hap.append(self.context_manager.genHapIndex("Core_Breakpoint_Memop", self.syscallHap, None, proc_break, call))
                if background:
                    dc = self.context_manager.getDefaultContext()
                    self.lgr.debug('winSyscall doBreaks set background breaks at 0x%x' % entry)
                    self.background_break = SIM_breakpoint(dc, Sim_Break_Linear, Sim_Access_Execute, entry, 1, 0)
                    self.background_hap = RES_hap_add_callback_index("Core_Breakpoint_Memop", self.syscallHap, None, self.background_break)

        return break_list, break_addrs

    def syscallHap(self, dumb, context, break_num, memory):
        ''' Invoked when syscall is detected.  May set a new breakpoint on the
            return to user space so as to collect remaining parameters, or to stop
            the simulation as part of a debug session '''
        ''' NOTE Does not track Tar syscalls! '''
        if self.context_manager.isReverseContext():
            return
        if self.syscall_info.callnum is None and self.callback is not None:
            # only used syscall to set breaks, we'll take it from here.
            self.lgr.debug('winSyscall syscallHap call callback %s' % str(self.callback))
            self.callback()
            return
        cpu, comm, tid = self.task_utils.curThread() 
        #self.lgr.debug('winSyscall syscallHap tid:%s (%s) %s context %s break_num %s cpu is %s t is %s cycle: 0x%x' % (tid, comm, self.name, str(context), str(break_num), str(memory.ini_ptr), type(memory.ini_ptr), self.cpu.cycles))
        #self.lgr.debug('memory.ini_ptr.name %s' % (memory.ini_ptr.name))
        if tid is None:
            return
        if tid.startswith('4-'):
            # TBD allow switch to override?
            return

        break_eip = self.mem_utils.getRegValue(self.cpu, 'pc')
        if self.syscall_info.cpu != cpu:
            self.lgr.error('syscallHap wrong cell, cur: %s, expected %s' % (cpu.name, self.syscall_info.cpu.name))
            return

        self.comm_cache[tid] = comm
        if self.linger:
            if cpu.cycles in self.linger_cycles:
                #self.lgr.debug('syscalHap for lingering call we already made.')
                return
            else:
                self.linger_cycles.append(cpu.cycles)
        else:
            ''' for example, rec calls rec_from '''
            if self.hack_cycle+20 >= cpu.cycles:
                self.lgr.debug('syscallHap tid:%s skip back-to-back calls within 10 cycles. TBD fix this for cases where cycles match?.' % tid)
                return
            else:
                self.hack_cycle = cpu.cycles

        if self.syscall_info.callnum is None:
           callnum = self.mem_utils.getCallNum(cpu)
           #self.lgr.debug('syscallHap callnum %d' % callnum)
           if callnum == 9999:
               SIM_break_simulation('0x4254, is that you?')
               reutrn
           ''' tracing all'''
           if self.no_gui and self.task_utils.isGUICall(callnum):
               return
           callname = self.task_utils.syscallName(callnum)
           if callname is None:
               self.lgr.debug('winSyscallHap tracing all bad callnum')
               return
           if self.record_fd and (callname not in record_fd_list or comm in skip_proc_list):
               self.lgr.debug('winSyscallHap not in record_fd list: %s' % callname)
               return
           syscall_instance = self.top.getSyscall(self.cell_name, callname) 
           if syscall_instance is not None and syscall_instance != self and syscall_instance.isBackground() == self.isBackground() and callname != 'exit_group' and syscall_instance.getContext() == self.cell:
               #self.lgr.debug(str(syscall_instance))
               #self.lgr.debug(str(self))
               self.lgr.debug('winSyscallHap tracing all tid:%s callnum %d name %s found more specific syscall hap, so ignore this one' % (tid, callnum, callname))
               return
           if callname == 'mmap' and tid in self.first_mmap_hap:
               return
        else:
           ''' not callnum from reg may not be the real callnum, Use syscall_info.callnum.
               Also, this is a cacluated entry....'''
           callnum = self.syscall_info.getCall(break_eip, False)
           if callnum is None:
               break_handle = self.context_manager.getBreakHandle(break_num)
               self.lgr.debug('winSyscallHap name: %s break eip 0x%x not in syscall_info break_num 0x%x handle: 0x%x  Assume computed break set is not applicable to this process' % (self.name, break_eip, break_num, break_handle))
               return
           callname = self.task_utils.syscallName(callnum) 
           self.lgr.debug('winSyscallHap, here callname %s' % callname)
           if callname is None:
               self.lgr.debug('winSyscallHap tracing selected callnumbers, bad call number %d  ?????' % (callnum))
               return
           if self.record_fd and (callname not in record_fd_list or comm in skip_proc_list):
               return
           if tid == 1 and callname in ['open', 'mmap', 'mmap2']:
               ''' ad-hoc noise reduction '''
               return
        ''' call 0 is read in 64-bit '''
        if callnum == 0 and self.mem_utils.WORD_SIZE==4:
            self.lgr.debug('winSyscallHap callnum is zero')
            return
        if callname == 'sppsvc.exe':
            ''' windows licensing service. RESim will crash if computed entry because it does not seem to run in the same context as other apps.  runs in kernel?'''
            return
        if not self.cpu.architecture.startswith('arm'):
            rax = self.mem_utils.getRegValue(self.cpu, 'rax')
            if self.mem_utils.isKernel(rax):
                # this is just an assumption.  TBD better way to determine if the call is internel, e.g., FlushKey resulting in WriteFile
                self.lgr.debug('syscallHap tid:%s rax is kernel, assume internal kernel use of syscall')
                return
        else:
            # TBD not yet handled
            pass
        value = memory.logical_address
        self.lgr.debug('syscallHap cell %s context %sfor tid:%s (%s) at 0x%x (memory 0x%x) callnum %d callname: %s hap name: %s cycle: 0x%x' % (self.cell_name, str(context), 
             tid, comm, break_eip, value, callnum, callname, self.name, self.cpu.cycles))
           
        if not self.swapper_ok and comm == 'swapper/0' and tid == 1:
            self.lgr.debug('syscallHap, skipping call from init/swapper')
            return

        if len(self.proc_hap) == 0 and self.background_break is None:
            self.lgr.debug('syscallHap entered for tid:%s after hap deleted' % tid)
            return
        if self.syscall_info.cpu is not None and cpu != self.syscall_info.cpu:
            self.lgr.debug('syscallHap, wrong cpu %s %s' % (cpu.name, self.syscall_info.cpu.name))
            return

        ''' catch stray calls from wrong tid.  Allow calls if the syscall instance's cell is not None, which means it is not up to the context manager
            to watch or not.  TBD needed for windows?'''
        if self.debugging and not self.context_manager.amWatching(tid) and self.syscall_info.callnum is not None and self.background_break is None and self.cell is None:
            self.lgr.debug('syscallHap name: %s tid:%s missing from context manager.  Debugging and specific syscall watched. callnum: %d' % (self.name, 
                 tid, self.syscall_info.callnum))
            return


        if tid == 0:
            value = memory.logical_address
            ''' TBD debug simics?  seems broken '''
            self.lgr.debug('syscallHap tid 0, unexpected break_ip 0x%x memory says 0x%x len of haps is %d' % (break_eip, value, len(self.proc_hap)))
            return

        word_size = self.getWordSize(tid)
        #self.lgr.debug('winSyscall syscallHap get frame and exit addresses.  word size %d, cycles: 0x%x' % (word_size, self.cpu.cycles))    
        frame, exit_eip1, exit_eip2, exit_eip3 = self.getExitAddrs(break_eip, self.syscall_info, word_size)
        if frame is None:
            value = memory.logical_address
            ''' TBD Simics broken???? occurs due to a mov dword ptr fs:[0xc149b454],ebx '''
            self.lgr.debug('syscallHap tid:%s unexpected break_ip 0x%x memory says 0x%x len of haps is %d' % (tid, break_eip, value, len(self.proc_hap)))
            #SIM_break_simulation('unexpected break eip 0x%x' % break_eip)
            return
        

        if callnum > 0x1400:
            self.lgr.warning('syscallHap callnum is too big')
            return
        
        if self.sharedSyscall.isPendingExecve(tid):
            ''' TBD fix for windows '''
            if callname == 'close':
                self.lgr.debug('syscallHap must be a close on exec? tid:%s' % tid)
                return
            elif callname == 'CreateUserProcess':
                self.lgr.debug('syscallHap must be a CreateUserProcess in CreateUserProcess? tid:%s' % tid)
                return
            elif callname == 'exit_group':
                self.lgr.debug('syscallHap exit_group called from within execve %d' % tid)
                return
            elif callname == 'uname':
                self.lgr.debug('syscallHap uname called from within execve %d' % tid)
                return
            else:
                self.lgr.error('fix this, syscall within exec? tid:%s call: %s' % (tid, callname))
                SIM_break_simulation('fix this')
                return

        if self.name is None:
            exit_info_name = '%s-exit' % (callname)
        else:
            exit_info_name = '%s-%s-exit' % (callname, self.name)

        if tid in self.pending_calls:
            self.lgr.debug('winSyscall tid %s has pending call %s, bail' % (tid, self.pending_calls[tid]))
            return
        if callname in self.exit_calls:
            self.context_manager.tidExit(tid)
            self.lgr.debug('winSyscall %s call %s exit of tid:%s stop_on_exit: %r' % (self.name, callname, tid, self.stop_on_exit))
            ida_msg = '%s tid:%s (%s)' % (callname, tid, comm)
            if callname == 'TerminateProcess':
                who = frame['param1']
                self.lgr.debug('winSyscall %s process who: 0x%x' % (callname, who))
                if who == 0xffffffffffffffff:
                    self.lgr.debug('winSyscall %s process will exit' % callname)
                    self.handleTerminateProcess(tid, ida_msg)
                    if self.stop_on_exit and self.top.debugging():
                        self.lgr.debug('syscall break simulation for stop_on_exit')
                        SIM_break_simulation(ida_msg)
                    return
            elif callname == 'TerminateThread':
                self.lgr.debug('winSyscall %s call stopWatchTid' % callname)
                self.context_manager.stopWatchTid(tid)

        ''' Set exit breaks '''
        #self.lgr.debug('syscallHap in proc %d (%s), callnum: 0x%x  EIP: 0x%x' % (tid, comm, callnum, break_eip))
        #self.lgr.debug('syscallHap frame: %s' % frame_string)
        #frame_string = taskUtils.stringFromFrame(frame)
        #self.lgr.debug('syscallHap frame: %s' % frame_string)


        if self.syscall_info.callnum is not None:
            # computed syscall

            if frame['param6'] is None:
                self.lgr.debug('syscallHap param6 is None, assume internal kernel call')
                return
            #self.lgr.debug('syscallHap cell %s callnum %d self.syscall_info.callnum %d stop_on_call %r' % (self.cell_name, 
            #     callnum, self.syscall_info.callnum, self.stop_on_call))
            if True:
                exit_info = self.syscallParse(callnum, callname, frame, cpu, tid, comm, self.syscall_info)
                if exit_info is not None:
                    if comm != 'tar':
                            ''' watch syscall exit unless call_params narrowed a search failed to find a match '''
                            tracing_all = False 
                            if self.top is not None:
                                tracing_all = self.top.tracingAll(self.cell_name, tid)
                            if self.callback is None:
                                if not syscall.hasParamMatchRequest(self.call_params) or len(exit_info.call_params) >0 or tracing_all or self.trackingSO(callname, self.syscall_info):

                                    if self.stop_on_call:
                                        if exit_info.matched_param is None or exit_info.matched_param.name != 'runToCall':
                                            cp = syscall.CallParams('stop_on_call', None, None, break_simulation=True)
                                            exit_info.call_params.append(cp)
                                    self.lgr.debug('exit_info.call_params tid:%s is %s' % (tid, str(exit_info.call_params)))

                                    if self.dataWatch is not None and not self.dataWatch.disabled and callname not in self.exit_calls:
                                        self.lgr.debug('winSyscall calling dataWatch to stop watch to ignore kernel fiddle with data')
                                        self.dataWatch.stopWatch()
                                    #self.lgr.debug('winSyscall call sharedSyscall.addExit')
                                    self.sharedSyscall.addExitHap(self.cpu.current_context, tid, exit_eip1, exit_eip2, exit_eip3, exit_info, exit_info_name)
                                    self.pending_calls[tid] = callname
                                    #if callname == 'Close': 
                                    #    SIM_break_simulation('is close')
                                    #    return
                                else:
                                    #self.lgr.debug('did not add exitHap')
                                    pass
                            else:
                                self.lgr.debug('syscall invoking callback')
                                self.callback()
                    else:
                        self.lgr.debug('syscallHap skipping tar %s, no exit' % comm)
                else:
                    #self.lgr.debug('syscallHap exitInfo is None')
                    pass
            else:
                self.lgr.debug('syscallHap call num does not match?')
                
        else:
            ''' tracing all syscalls, or watching for any syscall, e.g., during debug '''
            exit_info = self.syscallParse(callnum, callname, frame, cpu, tid, comm, self.syscall_info)
            #self.lgr.debug('syscall looking for any, got %d from %d (%s) at 0x%x ' % (callnum, tid, comm, break_eip))

            if exit_info is not None:
                if comm != 'tar':
                    name = callname+'-exit' 
                    #self.lgr.debug('syscallHap call to addExitHap for tid:%s' % tid)
                    if self.stop_on_call:
                        cp = syscall.CallParams('stop_on_call', None, None, break_simulation=True)
                        exit_info.call_params.append(cp)
                    #self.lgr.debug('syscallHap tid:%s call addExitHap' % tid)
                    self.sharedSyscall.addExitHap(self.cell, tid, exit_eip1, exit_eip2, exit_eip3, exit_info, name)
                    self.pending_calls[tid] = callname
                else:
                    self.lgr.debug('syscallHap tid:%s skip exitHap for tar' % tid)
            else:
                self.lgr.debug('winSyscall syscallHap tid:%s trace all got exit_info of none' % tid)

    def trackingSO(self, callname, syscall_info):
        retval = False
        if callname in ['CreateSection', 'MapViewOfSection']:
            for param in self.call_params:
                if param.name == 'trackSO':
                    retval = True
        return retval

    def syscallParse(self, callnum, callname, frame, cpu, tid, comm, syscall_info, quiet=False):
        '''
        Parse a system call using many if blocks.  Note that setting exit_info to None prevents the return from the
        syscall from being observed (which is useful if this turns out to be not the exact syscall you were looking for.
        '''
        exit_info = syscall.ExitInfo(self, cpu, tid, comm, callnum, callname, None, frame)
        exit_info.syscall_entry = self.mem_utils.getRegValue(self.cpu, 'pc')
        trace_msg = None
        frame_string = taskUtils.stringFromFrame(frame)

        # variable to determine if we are going to be doing 32 or 64 bit syscall
        if tid in self.word_size_cache:
            word_size = self.word_size_cache[tid]
            #self.lgr.debug('winSyscall syscallParse tid %s in cache word size %d' % (tid, word_size))
        else: 
            word_size = self.default_app_word_size
            somap_size = self.soMap.wordSize(tid)
            if somap_size is None:
                #self.lgr.debug('winSyscall syscallParse tid %s got somap_size none' % (tid))
                pass
            else:
                #self.lgr.debug('winSyscall syscallParse tid %s not in cache somap_size %d' % (tid, somap_size))
                word_size = somap_size
            self.word_size_cache[tid] = word_size
        exit_info.word_size = word_size
        #user_sp = frame['sp']
        #if user_sp > 0xffffffff:
        #    word_size = 8
        #else:
        #    word_size = 4
        #self.lgr.debug('hacky sp is 0x%x ws %d' % (user_sp, word_size))

        #self.lgr.debug('syscallParse syscall name: %s tid:%s callname <%s> params: %s' % (self.name, tid, callname, str(self.call_params)))
        for call_param in self.call_params:
            if call_param.match_param.__class__.__name__ == 'TidFilter':
                if tid != call_param.match_param.tid:
                    self.lgr.debug('syscall syscallParse, tid filter did not match')
                    return
                else:
                    syscall.addParam(exit_info, call_param)
                    self.lgr.debug('syscall syscallParse %s, tid filter matched, added call_param' % callname)
            elif call_param.match_param.__class__.__name__ == 'Dmod' and len(self.call_params) == 1:
                if call_param.match_param.comm is not None and call_param.match_param.comm != comm:
                    #self.lgr.debug('syscall syscallParse, Dmod %s does not match comm %s, return' % (call_param.match_param.comm, comm))
                    self.lgr.debug('winSyscall syscallParse, Dmod does not match comm %s, return' % (comm))
                    return
            elif call_param.name == 'runToCall':
                self.lgr.debug('winSyscall syscallParse is runToCall callname %s' % callname)
                alter_callname = callname
                if callname == 'DeviceIoControlFile' and frame['param6'] is not None:
                    operation = frame['param6'] & 0xffffffff
                    self.lgr.debug('winSyscall syscallParse operation 0x%x' % operation)
                    if operation in self.ioctl_op_map:
                        alter_callname = self.ioctl_op_map[operation]
                    else:
                        self.lgr.debug('winSyscall syscallParse operation 0x%x NOT IN op map' % operation)
                if self.call_list is not None and alter_callname not in self.call_list:
                    self.lgr.debug('syscall syscallParse, runToCall %s not in call list' % alter_callname)
                    return
                elif self.call_list is None and call_param.subcall != alter_callname:
                    self.lgr.debug('syscall syscallParse, runToCall %s not the subcall %s and call list is none' % (alter_callname, call_param.subcall))
                    return
                else:
                    if self.stop_on_call and not self.linger:
                        self.lgr.debug('syscall syscallParse %s, runToCall call matched, breaking simulation' % callname)
                        SIM_break_simulation(callname)
                        self.top.rmSyscall(call_param.name)
                    else:
                        syscall.addParam(exit_info, call_param)
                        self.lgr.debug('syscall syscallParse %s, runToCall, call match linger or not stop_on_call, added call_param' % alter_callname)

        frame_string = taskUtils.stringFromFrame(frame)
        #trace_msg = 'tid:%s (%s) %s %s' % (tid, comm, callname, frame_string)
        #self.lgr.debug('winSyscall syscallParse '+trace_msg)
        trace_msg = 'tid:%s (%s) %s' % (tid, comm, callname)
        if callname == 'CreateUserProcess':
            ''' TBD move offsets into param '''
            rsp = frame['sp']
            ptr = rsp + PROC_CREATE_INFO_OFFSET
            base = self.mem_utils.readPtr(self.cpu, ptr)
            if base is not None:
                ptr2 = base + PROG_NAME_OFFSET
                ptr3 = self.mem_utils.readPtr(self.cpu, ptr2)
                if ptr3 is None:
                    self.lgr.debug('winSyscall syscallParse cup %s ptr3 is None' % (trace_msg))
                else:
                    prog = self.mem_utils.readWinString(self.cpu, ptr3, 200)
                    if prog is None:
                        self.lgr.warning('winSyscall failed to read program name for CreateUserProcess.  TBD Add callback for when program name is mapped to memory')
                        return
                    trace_msg = trace_msg+' prog: %s frame: %s' % (prog, frame_string)
                    self.lgr.debug('winSyscall syscallParse cup %s' % trace_msg)
                    want_to_debug = False
                    if self.name == 'CreateUserProcess': 
                        ''' TBD section needs cleanup.  criteria for debugging seems hazy'''
                        ''' checkProg will initiate debug sequence '''
                        want_to_debug = self.checkProg(prog, tid, exit_info)
                        if want_to_debug:
                            ''' remove param, no more syscall processing here '''
                            self.lgr.debug('winSyscall cup wants to debug?  do not add call_param')
                        else:
                            for param in self.call_params:
                                if param.name == 'toCreateProc':
                                    exit_info.call_params.append(param)
                    if not want_to_debug:
                        self.lgr.debug('winSyscall cup add %s as pending proc' % prog)
                        self.soMap.addPendingProc(prog)
                        base = ntpath.basename(prog)
                        if self.top.trackingThreads(): 
                            want_comm = base[:taskUtils.COMM_SIZE-1]
                            self.lgr.debug('winSyscall is tracking threads base %s' % want_comm)
                            self.context_manager.callWhenFirstScheduled(want_comm, self.recordLoadAddr)
                        # TBD need to record stack ???
                        #if base.startswith(comm):
                        #    ''' creating another process for same program '''
                        #    self.lgr.debug('winSyscall syscallParase cup of same program')
                        #    self.context_manager.callWhenFirstScheduled(comm, self.recordStack)
            else:
                trace_msg = trace_msg + ' base read from 0x%x was none' % ptr
                self.lgr.debug(trace_msg)
                SIM_break_simulation(trace_msg)
       

        # Handle JUST first parameter for a bunch of functions that have Handle as their first, then break out into more params for some
        elif callname in ['MapViewOfSection', 'WaitForSingleObject', 'QueryKey', 'QueryMultipleValueKey', 'QuerySection', 'QueryInformationFile', 'SetInformationFile', 'QueryInformationToken', 'QueryValueKey', 'Close','RequestWaitReplyPort', 'ClearEvent', 'NotifyChangeKey', 'EnumerateValueKey']:
            exit_info.old_fd = frame['param1']
            trace_msg = trace_msg+' Handle: 0x%x' % (exit_info.old_fd)
            if callname in ['QueryValueKey', 'EnumerateValueKey']:
                info_class = frame['param3']
                iclass = 'Unknown'
                if info_class in winNTSTATUS.keyval_info_class_map:
                    iclass = winNTSTATUS.keyval_info_class_map[info_class]

                exit_info.retval_addr = frame['param4']
                exit_info.count = self.stackParam(1, frame) & 0xffffffff  #length of return buffer
                if callname == 'QueryValueKey':
                    exit_info.fname_addr = self.paramOffPtr(2, [8], frame, word_size)
                    exit_info.fname = self.mem_utils.readWinString(self.cpu, exit_info.fname_addr, 100)
                    trace_msg = trace_msg + ' name addr: 0x%x ValueName: %s information_class: %d (%s) ReturnBuffer: 0x%x BufferLength: %d' % (exit_info.fname_addr, 
                        exit_info.fname, info_class, iclass, exit_info.retval_addr, exit_info.count)
                else:
                    exit_info.fname = frame['param2']
                    trace_msg = trace_msg + ' subkey Index: %d information_class: %d (%s) ReturnBuffer: 0x%x BufferLength: %d' % ( exit_info.fname, 
                        info_class, iclass, exit_info.retval_addr, exit_info.count)
                for call_param in self.call_params:
                    self.lgr.debug('winSyscall %s call_param.subcall %s type %s' % (callname, call_param.subcall, type(call_param.match_param)))
                    if type(call_param.match_param) is int and call_param.match_param == exit_info.old_fd and \
                             (call_param.proc is None or call_param.proc == self.comm_cache[tid]):
                        syscall.addParam(exit_info, call_param)
                        self.lgr.debug('winSyscall %s found match', callname)
                        break

            elif callname == 'RequestWaitReplyPort':
                exit_info.retval_addr = frame['param3']
                exit_info.fname_addr = frame['param2']
                trace_msg = trace_msg + ' LPCRequestAddr: 0x%x LPCReplyAddr: 0x%x' % (exit_info.fname_addr, exit_info.retval_addr)
           
            elif callname == 'QueryInformationFile':
                info_class = self.stackParam(1, frame) & 0xFF # all values are under 80
                exit_info.retval_addr = frame['param3']
                buf_size = frame['param4']
                io_status_block = frame['param2']
                trace_msg = trace_msg + ' information_class: %s return_buf: 0x%x buf_size: 0x%x IoStatusBlock_addr: 0x%x' % (winFile.file_information_class[info_class], exit_info.retval_addr, buf_size, io_status_block)

            elif callname == 'SetInformationFile':
                info_class = self.stackParam(1, frame) & 0xFF # all values are under 80
                exit_info.retval_addr = frame['param2']
                buf_size = frame['param4']
                buf_addr = frame['param3']
                max_read = min(1000, buf_size) 
                buf_contents = self.mem_utils.readBytes(self.cpu, buf_addr, max_read)
                buf_hx = None
                if buf_contents is not None:
                    buf_hx = binascii.hexlify(buf_contents)

                trace_msg = trace_msg + ' information_class: %s buf_addr: 0x%x buf_size: 0x%x buf_contents: %s' % (winFile.file_information_class[info_class], buf_addr, buf_size, buf_hx)
                if (winFile.file_information_class[info_class] == "FileDispositionInformation") and (buf_hx != b'00'):
                    trace_msg = trace_msg + ' - FILE BEING FLAGGED FOR DELETION AFTER CLOSE'

            elif callname == 'Close':
                self.lgr.debug(trace_msg)
                for call_param in self.call_params:
                    self.lgr.debug('winSyscall %s call_param.subcall %s type %s value %s call_param.proc %s' % (callname, call_param.subcall, 
                               type(call_param.match_param), str(call_param.match_param), call_param.proc))
                    if call_param.match_param == exit_info.old_fd and (call_param.proc is None or call_param.proc == self.comm_cache[tid]):
                        syscall.addParam(exit_info, call_param)
                        if not self.linger:
                            self.lgr.debug('winSyscall closed fd 0x%x, stop trace' % exit_info.old_fd)
                            self.stopTrace()
                            break 
                    elif call_param.match_param.__class__.__name__ == 'Dmod' and call_param.match_param.tid == tid and exit_info.old_fd == call_param.match_param.fd:
                        self.lgr.debug('winSyscall close Dmod, tid and fd match')
                        exit_info.call_params.append(call_param)

            elif callname == 'MapViewOfSection':
                self.lgr.debug('MapViewOfSection word_size %d' % word_size)
                load_address = self.paramOffPtr(3, [0], frame, word_size)
                size = self.stackParamPtr(3, 0, frame) 
                if load_address is not None and size is not None:
                    trace_msg = trace_msg+' load_address 0x%x size 0x%x' % (load_address, size)
                self.lgr.debug(trace_msg)
                
        # Handle other functions specifically
        elif callname == 'QuerySystemInformation':
            exit_info.retval_addr = frame['param2']
            exit_info.count = frame['param3']
            info_class = frame['param1']
            iclass = "Uknown"
            if info_class in winNTSTATUS.system_info_class_map:
                iclass = winNTSTATUS.system_info_class_map[info_class]

            trace_msg = trace_msg + ' information_class: %d (%s) return_buf: 0x%x buf_size: %d' % (info_class, iclass, exit_info.retval_addr, exit_info.count)
 
        elif callname == 'ReadFile':
            exit_info.old_fd = frame['param1']
            # data buffer address
            exit_info.retval_addr = self.stackParam(2, frame)
            # the return count address --> this is where kernel will store count ACTUALLY sent/received
            #if word_size == 4:
            #    exit_info.fname_addr = self.paramOffPtr(5, [0], frame, word_size) + word_size
            #else:
            #    exit_info.fname_addr = frame['param5'] + word_size
            if word_size == 4:
                exit_info.count_addr = frame['param5'] + 8
            else:
                exit_info.count_addr = frame['param5'] 
            exit_info.delay_count_addr = exit_info.count_addr
            exit_info.count = self.stackParam(3, frame) & 0xFFFFFFFF 
             
            trace_msg = trace_msg+' Handle: 0x%x buf_addr: 0x%x RetCount_addr: 0x%x requested_count: %d' % (exit_info.old_fd, exit_info.retval_addr, exit_info.delay_count_addr, exit_info.count) 
            self.lgr.debug('ReadFile %s' % trace_msg)
            #SIM_break_simulation('starting Read')
            skip_this = False
            for call_param in self.call_params:
                ''' look for matching FD '''
                if type(call_param.match_param) is int:
                    if call_param.match_param == exit_info.old_fd and (call_param.proc is None or call_param.proc == self.comm_cache[tid]):

                        if call_param.nth is not None:
                            call_param.count = call_param.count + 1
                            self.lgr.debug('winSyscall read call_param.nth not none, is %d, count is %d' % (call_param.nth, call_param.count))
                            if call_param.count >= call_param.nth:
                                self.lgr.debug('count >= param, set it')
                                syscall.addParam(exit_info, call_param)
                                if self.kbuffer is not None and exit_info.count > 0:
                                    self.lgr.debug('syscall read kbuffer for addr 0x%x' % exit_info.retval_addr)
                                    self.kbuffer.read(exit_info.retval_addr, exit_info.count, exit_info.old_fd)
                        else:
                            self.lgr.debug('winSyscall read, call_param.nth is none, call it matched')
                            syscall.addParam(exit_info, call_param)
                            if self.kbuffer is not None and exit_info.count > 0:
                                self.lgr.debug('winSyscall read kbuffer for addr 0x%x' % exit_info.retval_addr)
                                self.kbuffer.read(exit_info.retval_addr, exit_info.count, exit_info.old_fd)
                        break
                    else:
                        self.lgr.debug('winSyscall read match_param was int, no match?')
                        skip_this = True
            if not skip_this:
                if exit_info.count > 0:
                    self.lgr.debug('winSyscall ReadFile set asynch_handler')
                    exit_info.asynch_handler = winDelay.WinDelay(self.top, self.cpu, tid, comm, exit_info, None,
                            self.mem_utils, self.context_manager, self.traceMgr, callname, self.kbuffer, exit_info.old_fd, exit_info.count, self.stop_action, self.lgr)
                    if self.watchData(exit_info):
                        self.lgr.debug('winSyscall ReadFile doing win_delay.setDataWatch')
                        exit_info.asynch_handler.setDataWatch(self.dataWatch, exit_info.syscall_instance.linger) 


        elif callname == 'WriteFile':
            #self.lgr.debug('WriteFile')
            exit_info.old_fd = frame['param1']
            exit_info.retval_addr = self.stackParam(1, frame)
            val = self.stackParam(3, frame) 
            write_string = None
            buffer_addr = None
            if val is not None:
                count = val & 0x00000000FFFFFFFF
                buffer_addr = self.stackParam(2, frame)
                max_count = min(1000, count)
                write_string = self.mem_utils.readWinString(self.cpu, buffer_addr, max_count)
                trace_msg = trace_msg+' Handle: 0x%x retval_addr: 0x%x buf_addr: 0x%x buf_size: %d buf_contents: %s' % (exit_info.old_fd, exit_info.retval_addr, buffer_addr, count, repr(write_string))

            for call_param in self.call_params:
                if type(call_param.match_param) is int and call_param.match_param == frame['param1'] and (call_param.proc is None or call_param.proc == self.comm_cache[tid]):
                    self.lgr.debug('winSyscall call param found %d, matches %d' % (call_param.match_param, frame['param1']))
                    syscall.addParam(exit_info, call_param)
                    break
                elif type(call_param.match_param) is str: 
                    if write_string is not None and call_param.match_param in write_string:
                        self.lgr.debug('winSyscall write match param for tid:%s is string %s, add to exit info' % (tid, write_string))
                        exit_info.call_params.append(call_param)
                        exit_info.append_msg = 'String from address 0x%x' % buffer_addr
                        break
                    else:
                        self.lgr.debug('winSyscall WriteFile match param is string but we read %s' % write_string)
                elif call_param.match_param.__class__.__name__ == 'Dmod':
                    if count < 4028:
                        self.lgr.debug('syscall write check dmod count %d' % count)
                        mod = call_param.match_param
                        if mod.checkString(self.cpu, frame['param2'], count):
                            if mod.getCount() == 0:
                                self.lgr.debug('syscall write found final dmod %s' % mod.getPath())
                                if not self.remainingDmod(call_param.name):
                                    #self.top.stopTrace(cell_name=self.cell_name, syscall=self)
                                    self.top.rmSyscall(call_param.name)
                                    if not self.top.remainingCallTraces(cell_name=self.cell_name) and SIM_simics_is_running():
                                        self.top.notRunning(quiet=True)
                                        SIM_break_simulation('dmod done on cell %s file: %s' % (self.cell_name, mod.getPath()))
                                    else:
                                        print('%s performed' % mod.getPath())
                                else:
                                    self.syscall_info.callparams.remove(call_param)
                else:
                    #self.lgr.debug('syscall write call_param match_param is type %s' % (call_param.match_param.__class__.__name__))
                    pass
        elif callname == 'CreateFile':
            if self.mem_utils.isKernel(frame['param1']):
                self.lgr.debug('winSyscall CreateFile internel to kernel')
            else:
                #SIM_break_simulation('create')

                str_size_addr = self.paramOffPtr(3, [0x10], frame, word_size) 
                str_size = self.mem_utils.readWord16(self.cpu, str_size_addr)
                exit_info.fname_addr = self.paramOffPtr(3, [0x10, 8], frame, word_size)
                
                if exit_info.fname_addr is None:
                    trace_msg = trace_msg+' fname address is None' 
                    self.lgr.debug(trace_msg)
                else:
                    param_callname = callname 
                    max_count = min(1000, str_size)
                    exit_info.fname = self.mem_utils.readWinString(self.cpu, exit_info.fname_addr, max_count)
                    # TBD better approach?
                    exit_info.retval_addr = frame['param1']

                    trace_msg = trace_msg+' fname: %s fname_addr: 0x%x retval_addr: 0x%x' % (exit_info.fname, exit_info.fname_addr, exit_info.retval_addr)
                    # Permissions
                    accesses = []
                    access_mask = frame['param2']
                    for flag, name in winFile.access_mask_map.items():
                        if access_mask & flag:
                            accesses.append(name)
    
                    attributes = []
                    file_attributes = self.stackParam(2, frame) & 0xffffffff
                    if file_attributes == 0x0:
                       attributes.append('NONE')

                    for attrib, name in winFile.file_attribute_map.items():
                        if file_attributes & attrib:
                            attributes.append(name)
                   
                    share = []
                    share_access = self.stackParam(3, frame) & 0xffffffff
                    if share_access == 0x0:
                        share.append('NONE')

                    for ac, name in winFile.share_access_map.items():
                        if share_access & ac:
                            share.append(name)

                    create_disposition = self.stackParam(4, frame) & 0xffffffff
                    disposition = 'UNKNOWN'
                    if create_disposition in winFile.disposition_map:
                        disposition = winFile.disposition_map[create_disposition]
                        if disposition.startswith('FILE_OPEN'):
                            param_callname = 'OpenFile'

                    trace_msg = trace_msg+' access: 0x%x (%s) file_attributes: 0x%x (%s) share_access: 0x%x (%s) create_disposition: 0x%x (%s)' % (access_mask, ', '.join(accesses), file_attributes, ', '.join(attributes), share_access, ', '.join(share), create_disposition, disposition)

                    if exit_info.fname.endswith('Endpoint'):
                        extended_size = self.stackParam(7, frame)
                        if extended_size is not None:
                            extended_size = min(extended_size, 200)
                            extended_addr = self.stackParam(6, frame)
                            if extended_addr is not None:
                                '''
                                Observations running tcp and udp servers
                                9th byte string
                                25th byte tcp 0  udp 11
                                33rd byte tcp 2  udp 2
                                37th byte tcp 1  udp 2 
                                '''
                                str_ptr = extended_addr + 8 
                                sock_str= self.mem_utils.readWinString(self.cpu, str_ptr, 20)
                                extended = self.mem_utils.readBytes(self.cpu, extended_addr, extended_size)
                                if extended is not None:
                                    exit_info.sock_struct = extended
                                    b24 = extended[24]
                                    b32 = extended[32]
                                    b36 = extended[36]
                                    self.lgr.debug('winSyscall endpoint extended_addr 0x%x socket string %s b24 0x%x b32 0x%x b36 0x%x' % (extended_addr, sock_str, b24, b32, b36))
                                    extended_hx = binascii.hexlify(extended)
                                    sock_type = net.socktype[b36]
                                    trace_msg = trace_msg + ' - socket() call socket type: %s\n AFD extended: %s' % (sock_type, extended_hx)
                            else:
                                self.lgr.debug('winSyscall endpoint, but extended addr is None')
                        else:
                            self.lgr.debug('winSyscall endpoint, but extended size is None')
                    elif exit_info.fname.endswith('AsyncConnectHlp'):
                        ''' will be used with connect calls that name a bind ''' 
                        self.lgr.debug('winSyscall is AsnycConnect, record this in winCallExit')
                    
                    exit_info = self.genericCallParams(syscall_info, exit_info, param_callname)

        elif callname == 'QueryAttributesFile':
            object_attr = frame['param1']
            str_size_addr = self.paramOffPtr(1, [0x10], frame, word_size)
            str_size = self.mem_utils.readWord16(self.cpu, str_size_addr)
            if str_size is not None:
                self.lgr.debug('winSyscall QueryAttributesFile str_size_addr: 0x%x size: %d' % (str_size_addr, str_size))
                
                exit_info.fname_addr = self.paramOffPtr(1, [0x10, 8], frame, word_size)
                exit_info.retval_addr = frame['param2']
                max_count = min(1000, str_size)
                exit_info.fname = self.mem_utils.readWinString(self.cpu, exit_info.fname_addr, max_count)
                trace_msg = trace_msg+' fname: %s fname_addr: 0x%x retval_addr: 0x%x' % (exit_info.fname, exit_info.fname_addr, exit_info.retval_addr)


        elif callname in ['OpenFile', 'OpenKeyEx', 'OpenKey', 'OpenSection']:
            object_attr = frame['param3']
            str_size_addr = self.paramOffPtr(3, [0x10], frame, word_size) 
            str_size = self.mem_utils.readWord16(self.cpu, str_size_addr)
              
            if str_size is not None:
                self.lgr.debug('winSyscall %s str_size_addr: 0x%x size: %d' % (callname, str_size_addr, str_size))

                exit_info.fname_addr = self.paramOffPtr(3, [0x10, 8], frame, word_size)
                exit_info.retval_addr = frame['param1']
                max_count = min(1000, str_size)
                exit_info.fname = self.mem_utils.readWinString(self.cpu, exit_info.fname_addr, max_count)
                trace_msg = trace_msg+' fname: %s fname_addr: 0x%x retval_addr: 0x%x (handle addr)' % (exit_info.fname, exit_info.fname_addr, exit_info.retval_addr)
                self.lgr.debug(trace_msg) 
                # Permissions
                accesses = []
                access_mask = frame['param2']
                for flag, name in winFile.access_mask_map.items():
                   if access_mask & flag:
                       accesses.append(name)
                trace_msg = trace_msg + ' access: 0x%x (%s)' % (access_mask, ', '.join(accesses))

                if callname == 'OpenFile':
                    share = []
                    value = self.stackParam(1, frame) 
                    if value is not None:
                        share_access = value & 0xffffffff
                        if share_access == 0x0:
                            share.append('NONE')
                        for ac, name in winFile.share_access_map.items():
                            if share_access & ac:
                                share.append(name)
                        trace_msg = trace_msg+' share_access: 0x%x (%s)' % (share_access, ', '.join(share)) 
                    else:
                        trace_msg = trace_msg + 'failed reading stack param 1 '

                
                exit_info = self.genericCallParams(syscall_info, exit_info, callname)
            #SIM_break_simulation('string at 0x%x' % exit_info.fname_addr)
  
        elif callname == 'DeviceIoControlFile':
            callname, trace_msg = self.parseDeviceIoCall(tid, comm, exit_info, trace_msg, frame, word_size)
        elif callname in ['CreateEvent', 'OpenProcess']:
            exit_info.retval_addr = frame['param1']
            trace_msg = trace_msg + ' Handle_addr: 0x%x' % (exit_info.retval_addr)

        elif callname == 'OpenProcessToken':
            process_handle = frame['param1']
            if process_handle == 0xffffffffffffffff:
                trace_msg = trace_msg + ' for_process: %s (this one)' % (tid)
            else:
                trace_msg = trace_msg+' for_process: 0x%x' % (process_handle)
            
            exit_info.retval_addr = frame['param3']
            trace_msg = trace_msg+' Handle_addr: 0x%x' % (exit_info.retval_addr)

        elif callname in ['WaitForMultipleObjects32']:
            count = frame['param1'] & 0xffff
            for i in range(count):
                #addr = frame['param2']+i*self.mem_utils.wordSize(self.cpu)
                addr = frame['param2']+i*4
                handle = self.mem_utils.readWord32(self.cpu, addr)
                trace_msg = trace_msg + " Handle[%d]: 0x%x" % (i, handle)
 
        elif callname in ['AlpcSendWaitReceivePort']:
            exit_info.old_fd = frame['param1']
            # contains size and will contain returned size
            exit_info.retval_addr = frame['param3']
            exit_info.count = self.mem_utils.readWord16(self.cpu, exit_info.retval_addr)
            if exit_info.count is not None:
                buf_start = frame['param3']+5*self.mem_utils.wordSize(self.cpu) 
                limit_count = min(exit_info.count, 100)
                buf = self.mem_utils.readBytes(self.cpu, buf_start, limit_count)
                trace_msg = trace_msg+' Handle: 0x%x count: 0x%x data: %s' % (exit_info.old_fd, exit_info.count, binascii.hexlify(buf))
            else:
                trace_msg = trace_msg+' Handle: 0x%x count is None' % (exit_info.old_fd)

        elif callname == 'ConnectPort':
            exit_info.fname_addr = self.paramOffPtr(2, [8], frame, word_size)
            str_size_addr = frame['param2']
            str_size = self.mem_utils.readWord16(self.cpu, str_size_addr)
            max_count = min(1000, str_size)
            exit_info.fname = self.mem_utils.readWinString(self.cpu, exit_info.fname_addr, max_count)
            exit_info.retval_addr = frame['param1']
            trace_msg = trace_msg+' fname: %s fname_addr: 0x%x retval_addr: 0x%x (handle addr)' % (exit_info.fname, exit_info.fname_addr, exit_info.retval_addr)

        elif callname == 'AlpcConnectPort':
            exit_info.fname_addr = self.paramOffPtr(2, [8], frame, word_size)
            str_size_addr = frame['param2']
            str_size = self.mem_utils.readWord16(self.cpu, str_size_addr)
            max_count = min(1000, str_size)
            exit_info.fname = self.mem_utils.readWinString(self.cpu, exit_info.fname_addr, max_count)
            exit_info.retval_addr = frame['param1']
            trace_msg = trace_msg+' fname: %s fname_addr: 0x%x retval_addr: 0x%x (handle addr)' % (exit_info.fname, exit_info.fname_addr, exit_info.retval_addr)
        
        elif callname == 'Continue':
            pass
        
            #if comm == 'TeamViewer_Ser':
            #    SIM_break_simulation('team viewer')

        elif callname == 'CreateSection':
            exit_info.old_fd = self.stackParam(3, frame) 
            if exit_info.old_fd is not None:
                trace_msg = trace_msg+' Handle: 0x%x' % (exit_info.old_fd)
            else:
                trace_msg = trace_msg+' Handle: None'

        elif callname in ['CreateThread', 'CreateThreadEx']:
            exit_info.retval_addr = frame['param1']
            trace_msg = trace_msg+' retval_addr: 0x%x (handle addr)' % (exit_info.retval_addr)

        elif callname in ['AllocateVirtualMemory', 'FreeVirtualMemory', 'QueryVirtualMemory', 'UnmapViewOfSection']:
            who = frame['param1']
            if who == 0xffffffffffffffff:
                trace_msg = trace_msg + ' for_process: %s (this one)' % (tid)
            else:
                trace_msg = trace_msg+' for_process: 0x%x' % (who)
            
            if callname == 'AllocateVirtualMemory':
                # Base addr pointer 
                exit_info.retval_addr = frame['param2']
                # Size pointer 
                exit_info.fname_addr = frame['param4']
                exit_info.count = self.paramOffPtr(4, [0], frame, word_size)     
       
                alloc_type = self.stackParam(1, frame)
                atype = "Uknown mapping"
                if alloc_type in winFile.allocation_type_map:
                    atype = winFile.allocation_type_map[alloc_type]

                trace_msg = trace_msg+' base_addr_ptr: 0x%x size_ptr: 0x%x size_requested: 0x%x alloc_type: 0x%x (%s)' % (exit_info.retval_addr, exit_info.fname_addr, exit_info.count, alloc_type, atype)
               
            elif callname == 'FreeVirtualMemory':
                exit_info.retval_addr = frame['param2'] #pointer to base addr
                exit_info.fname_addr = frame['param3'] # pointer to region size
                
                free_type = frame['param4']
                ftype = "Unknown mapping"
                if free_type in winFile.allocation_type_map:
                    ftype = winFile.allocation_type_map[free_type]

                trace_msg = trace_msg + ' base_addr_ptr: 0x%x size_ptr: 0x%x free_type: 0x%x (%s)' % (exit_info.retval_addr, exit_info.fname_addr, free_type, ftype)

                base = self.paramOffPtr(2, [0], frame, word_size)
                if base is not None:
                    trace_msg = trace_msg + ' base_addr_to_free: 0x%x' % (base)

                size = self.paramOffPtr(3, [0], frame, word_size)
                if size is not None:
                    trace_msg = trace_msg + ' size: 0x%x' % (size)
 
            elif callname == 'QueryVirtualMemory':
                base_addr = frame['param2']
                if base_addr is not None:
                    trace_msg = trace_msg + ' base_addr: 0x%x' % (base_addr)

                exit_info.retval_addr = frame['param4']
                buf_size = self.stackParam(1, frame)
                trace_msg = trace_msg + ' return_buf: 0x%x return_buf_size: %d' % (exit_info.retval_addr, buf_size)

            elif callname == 'UnmapViewOfSection':
                base_addr = frame['param2']
                if base_addr is not None:
                    trace_msg = trace_msg + ' base_addr: 0x%x' % (base_addr)
 
        elif callname == 'TerminateProcess':
            who = frame['param1']
            trace_msg = trace_msg+' who: 0x%x' % (who)
            if who == 0xffffffffffffffff:
                trace_msg = trace_msg+' (this process)'
            if tid in self.word_size_cache:
                del self.word_size_cache[tid]

        elif callname == 'DuplicateObject':
            exit_info.old_fd = frame['param2']
            exit_info.retval_addr = frame['param4']
            trace_msg = trace_msg+' Handle: 0x%x  reval_addr: 0x%x' % (exit_info.old_fd, exit_info.retval_addr)
            for call_param in self.call_params:
                self.lgr.debug('syscall DuplicateObject subcall %s call_param.match_param is %s fd is %d' % (call_param.subcall, 
                     str(call_param.match_param), exit_info.old_fd))
                if type(call_param.match_param) is int:
                    if (call_param.subcall == 'accept' or self.name=='runToIO') and (call_param.match_param < 0 or call_param.match_param == exit_info.old_fd):
                        syscall.addParam(exit_info, call_param)
                        self.lgr.debug('syscall DuplicateObject set call param to handle in exit')
                        break

        elif callname == 'QueryInformationProcess':
            who = frame['param1']
            if who == 0xffffffffffffffff:
                trace_msg = trace_msg + ' Process: %s (this one)' % (tid)
            else:
                trace_msg = trace_msg+' Process: 0x%x' % (who)

            info_class = frame['param2']
            iclass = "Uknown"
            if info_class in winNTSTATUS.process_info_class_map:
                iclass = winNTSTATUS.process_info_class_map[info_class]
            
            exit_info.retval_addr = frame['param3']
            exit_info.count = frame['param4']
            trace_msg = trace_msg + ' information_class: %d (%s) return_buf: 0x%x return_buf_size: %d' % (info_class, iclass, exit_info.retval_addr, exit_info.count)
        #    entry = self.task_utils.getSyscallEntry(callnum)
        #    SIM_break_simulation('query information process computed 0x%x' % entry)
        elif callname in ['FindAtom', 'AddAtom']:
            str_addr = frame['param1']
            length = frame['param2']
            max_count = min(1000, length)
            atom_str = self.mem_utils.readWinString(self.cpu, str_addr, max_count)
            exit_info.retval_addr = frame['param3']
            trace_msg = trace_msg + ' atom string: %s, length: %d' % (atom_str, length)
           
        else:
            #self.lgr.debug(trace_msg)
            pass
        self.lgr.debug('winSyscall syscallParse %s cycles:0x%x' % (trace_msg, self.cpu.cycles))
        #else:
        #    self.lgr.debug('Windows syscallParse, not looking for <%s>, remove exit info.' % callname)
        #    exit_info = None
        if exit_info is not None:
            exit_info.trace_msg = trace_msg
        if trace_msg is not None and not quiet:
            #self.lgr.debug(trace_msg.strip()) 
            
            self.dataWatch.markTrace(trace_msg.strip())
            #if trace_msg is not None and self.traceMgr is not None and (len(self.call_params) == 0 or exit_info.call_params is not None):
            if trace_msg is not None and self.traceMgr is not None:
                if len(trace_msg.strip()) > 0:
                    self.traceMgr.write(trace_msg+'\n'+frame_string+'\n')
                     

        if exit_info.asynch_handler is not None:
            # catch orphan winDelays'
            if tid not in self.win_delays:
                self.win_delays[tid] = {}
            if exit_info.old_fd not in self.win_delays[tid]:
                self.win_delays[tid][exit_info.old_fd] = exit_info.asynch_handler
            else:
                # hacky catch of what should have been already removed
                self.win_delays[tid][exit_info.old_fd].remove()
                self.win_delays[tid][exit_info.old_fd] = exit_info.asynch_handler
                


        return exit_info
        #
        # end of syscallParse
        #

    def stackParam(self, pnum, frame):
        rsp = frame['sp']
        offset = 0x20 + (pnum * self.mem_utils.WORD_SIZE)
        ptr = rsp + offset
        value = self.mem_utils.readPtr(self.cpu, ptr)
        return value

    def stackParamPtr(self, pnum, ptr_offset, frame):
        value = None
        rsp = frame['sp']
        offset = 0x20 + (pnum * self.mem_utils.WORD_SIZE)
        ptr = rsp + offset
        #self.lgr.debug('stackParamPtr rsp 0x%x ptr 0x%x' % (rsp, ptr))
        ptr_value = self.mem_utils.readPtr(self.cpu, ptr)
        if ptr_value is not None:
            new_ptr = ptr_value++ptr_offset
            #self.lgr.debug('stackParamPtr new_ptr 0x%x' % new_ptr)
            value = self.mem_utils.readWord(self.cpu, new_ptr) 
        return value
        
    def paramOffPtr(self, pnum, offset_list, frame, word_size):
        return paramOffPtrUtil(pnum, offset_list, frame, word_size, self.cpu, self.mem_utils, self.lgr)

    def getExitAddrs(self, break_eip, syscall_info, word_size, frame = None):
        exit_eip1 = None
        exit_eip2 = None
        exit_eip3 = None
        frame = None 
        #self.lgr.debug('winSyscall getExitAddrs break_eip 0x%x' % break_eip)
        if break_eip == self.param.sysenter:
            ''' caller frame will be in regs'''
            if frame is None:
                frame = self.task_utils.frameFromRegs()
                frame_string = taskUtils.stringFromFrame(frame)
            exit_eip1 = self.param.sysexit
            ''' catch interrupt returns such as wait4 '''
            exit_eip2 = self.param.iretd
            try:
                exit_eip3 = self.param.sysret64
                #self.lgr.debug('syscall getExitAddrs has sysret64 exit1 0x%x 2 0x%x 3 0x%x' % (exit_eip1, exit_eip2, exit_eip3))
            except AttributeError:
                exit_eip3 = None
                #self.lgr.debug('syscall getExitAddrs no sysret64 exit1 0x%x 2 0x%x ' % (exit_eip1, exit_eip2))
        elif False and break_eip == self.param.arm_entry:
            exit_eip1 = self.param.arm_ret
            exit_eip2 = self.param.arm_ret2
            if frame is None:
                frame = self.task_utils.frameFromRegsComputed()
                frame_string = taskUtils.stringFromFrame(frame)
                #SIM_break_simulation(frame_string)
        elif syscall_info.calculated:
            #self.lgr.debug('getExitAddress is computed')
            ''' Note EIP in stack frame is unknown '''
            #frame['eax'] = syscall_info.callnum
            if self.cpu.architecture.startswith('arm'):
                if frame is None:
                    frame = self.task_utils.frameFromRegsComputed()
                exit_eip1 = self.param.arm_ret
                exit_eip2 = self.param.arm_ret2
                exit_eip2 = None
                #exit_eip3 = self.param.sysret64
            elif self.mem_utils.WORD_SIZE == 8:
                if frame is None:
                    frame = self.task_utils.frameFromRegsComputed()
                    frame_string = taskUtils.stringFromFrame(frame)
                    #self.lgr.debug('frame computed string %s' % frame_string)
                exit_eip1 = self.param.sysexit
                exit_eip2 = self.param.iretd
                exit_eip3 = self.param.sysret64
            else:
                self.lgr.error('syscallHap calculated, bad word size?') 
            #if frame is not None:     
            #    frame_string = taskUtils.stringFromFrame(frame)
            #    self.lgr.debug('frame string %s' % frame_string)
        return frame, exit_eip1, exit_eip2, exit_eip3

    def checkProg(self, prog_string, tid, exit_info):
        ''' return True if we think the syscall params indicate we want to debug this'''
        retval = True
        self.lgr.debug('checkProg syscall %s  prog: %s' % (self.name, prog_string))
        cp = None
        for call in self.call_params:
            #self.lgr.debug('checkProg call %s' % call)
            if call.subcall == 'CreateUserProcess':
                cp = call
                break
        if cp is None:
            for call in self.call_params:
                self.lgr.debug('checkProg traceall call %s' % call)
                if call.subcall == 'CreateUserProcess':
                    cp = call
                    break
            
        if cp is not None: 
            if cp.match_param is None:
                retval = False
            elif cp.match_param.__class__.__name__ == 'Dmod':
               self.task_utils.modExecParam(tid, self.cpu, cp.match_param)
            else: 

                retval = False
                if '\\' in cp.match_param:
                    ''' compare full path '''
                    base = prog_string
                else:
                    base = ntpath.basename(prog_string)
                self.lgr.debug('checkProg base %s against %s' % (base, cp.match_param))
                if base.startswith(cp.match_param):
                    ''' is program file we are looking for.  do we care if it is a binary? '''
                    self.lgr.debug('matches base')
                    wrong_type = False
                    '''
                    TBD fix for Windows
                    if self.traceProcs is not None:
                        ftype = self.traceProcs.getFileType(tid)
                        if ftype is None:
                            full_path = self.targetFS.getFull(prog_string, self.lgr)
                            if full_path is not None and os.path.isfile(full_path):
                                ftype = magic.from_file(full_path)
                                if ftype is None:
                                    self.lgr.error('checkProg failed to find file type for %s tid:%s' % (prog_string, tid))
                                    return
                        if ftype is not None and 'binary' in cp.param_flags and 'elf' not in ftype.lower():
                            wrong_type = True
                    '''
                    if not wrong_type:
                        ''' Obscure criteria for not looking to debug.  Debug will set break_simulation to false.'''
                        if cp.break_simulation:
                            retval = False
                            self.top.rmSyscall('toCreateProc')
                            self.lgr.debug('checkProg CreateUserProc of %s call runToUserSpace' % prog_string)
                            SIM_run_alone(self.top.runToUserSpace, None)
                            
                        else:
                            self.lgr.debug('checkProg CreateUserProc of %s call toNewProc' % prog_string)
                            retval = True
                            #exit_info.call_params = cp 
                            #exit_info.call_params = None
                            win_prog = winProg.WinProg(self.top, self.cpu, self.mem_utils, self.task_utils, self.context_manager, self.soMap, self.stop_action, self.param, self.lgr)
                            SIM_run_alone(win_prog.toNewProc, prog_string)
                            #SIM_run_alone(self.stopAlone, 'CreateUserProc of %s' % prog_string)
                    else:
                        self.lgr.debug('checkProg, got %s when looking for binary %s, skip' % (ftype, prog_string))
        else:
            retval = False
        return retval

    def stopAlone(self, msg):
        ''' NOTE: this is also called by sharedSyscall/winCallExit '''
        eip = self.top.getEIP()
        if self.stop_action is not None:
            self.stop_action.setExitAddr(eip)
        self.stop_hap = self.top.RES_add_stop_callback(self.stopHap, msg)
        self.lgr.debug('winSyscall stopAlone cell %s added stopHap %d Now stop. msg: %s' % (self.cell_name, self.stop_hap, msg))
        SIM_break_simulation(msg)

    def stopHap(self, msg, one, exception, error_string):
        '''  Invoked when a syscall (or more typically its exit back to user space) triggers
             a break in the simulation
        '''
        if self.stop_hap is not None:
            self.top.RES_delete_stop_hap(self.stop_hap)
            self.stop_hap = None
            eip = self.mem_utils.getRegValue(self.cpu, 'pc')
            if self.stop_action is not None:
                self.lgr.debug('syscall stopHap name: %s cycle: 0x%x eip: 0x%x exception %s error %s linger: %r' % (self.name, self.stop_action.hap_clean.cpu.cycles, eip, str(exception), str(error_string), self.linger))
            else:
                self.lgr.debug('syscall stopHap, no stop_action') 
            if not self.linger:
                break_list = self.stop_action.getBreaks()
                if eip not in break_list and eip != self.stop_action.getExitAddr():
                    self.lgr.debug('syscall stopHap 0x%x not in break list, not our stop %s' % (eip, ' '.join(hex(x) for x in break_list)))
                    #self.top.skipAndMail()
                    return
       
                for hc in self.stop_action.hap_clean.hlist:
                    if hc.hap is not None:
                        #self.lgr.debug('will delete hap %s' % str(hc.hap))
                        self.context_manager.genDeleteHap(hc.hap)
                        hc.hap = None
                self.lgr.debug('syscall stopHap will delete hap %s' % str(self.stop_hap))
                ''' check functions in list '''
                self.lgr.debug('winSyscall stopHap call to rmExitHap')
                self.sharedSyscall.rmExitHap(None)

                ''' TBD do this as a stop function? '''
                cpu, comm, tid = self.task_utils.curThread() 
                self.sharedSyscall.rmPendingExecve(tid)

                ''' TBD when would we want to close it?'''
                if self.traceMgr is not None:
                    self.traceMgr.flush()
                #self.top.idaMessage() 
                ''' Run the stop action, which is a hapCleaner class '''
                funs = self.stop_action.listFuns()
                self.lgr.debug('syscall stopHap run stop_action, funs: %s' % funs)
                self.stop_action.run(cb_param=msg)

                # TBD remove when call traces finally trashed
                if self.call_list is not None:
                    for callname in self.call_list:
                        #self.top.rmCallTrace(self.cell_name, callname)
                        self.top.rmCallTrace(self.cell_name, self.name)
                # mftmft TBD
                for param in self.rm_param_queue:
                    self.lgr.debug('syscall stopHap call top.rmSyscall for %s' % param)
                    self.top.rmSyscall(param)
                self.rm_param_queue = []
            else:
                self.lgr.debug('syscall will linger and catch next occurance')
                self.top.skipAndMail()

    def setExits(self, frames, origin_reset=False, context_override=None):
        ''' set exits for a list of frames, intended for tracking when syscall has already been made and the process is waiting '''
        for tid in frames:
            self.lgr.debug('setExits frame of tid:%s is %s' % (tid, taskUtils.stringFromFrame(frames[tid])))
            if frames[tid] is None:
                continue
            pc = frames[tid]['pc']
            callnum = frames[tid]['syscall_num']
            syscall_info = syscall.SyscallInfo(self.cpu, None, pc, self.trace)
            callname = self.task_utils.syscallName(callnum, syscall_info.compat32) 
            word_size = self.getWordSize(tid)
            frame, exit_eip1, exit_eip2, exit_eip3 = self.getExitAddrs(pc, syscall_info, word_size, frame=frames[tid])

            exit_info = syscall.ExitInfo(self, self.cpu, tid, comm, callnum, callname, syscall_info.compat32, frame)
            exit_info.retval_addr = frames[tid]['param2']
            exit_info.count = frames[tid]['param3']
            exit_info.old_fd = frames[tid]['param1']
            self.lgr.debug('setExits set count to parm3 now 0x%x' % exit_info.count)

            the_callname = callname
            ''' TBD need to evaluate syscall params against call params to know if we care about this call'''
            # See if there is a call param that matches the syscall
            for cp in self.call_params:
                if type(cp.match_param) is int:
                    if cp.match_param == exit_info.old_fd:
                        self.lgr.debug('setExits found call param as integer set call params to %s' % str(cp))
                        exit_info.call_params.append(cp)
                        exit_info.matched_param = cp
                 
                else:
                    exit_info.call_params.append(cp)
            if len(exit_info.call_params) > 0:
                exit_info.origin_reset = origin_reset
                if exit_info.retval_addr is not None:
                    self.lgr.debug('setExits almost done for tid:%s call %d retval_addr is 0x%x' % (tid, callnum, exit_info.retval_addr))
                else:
                    self.lgr.debug('setExits almost done for tid:%s call %d retval_addr is None' % (tid, callnum))
                exit_info_name = '%s-%s-exit' % (the_callname, self.name)
                self.sharedSyscall.addExitHap(self.cell, tid, exit_eip1, exit_eip2, exit_eip3, exit_info, exit_info_name, context_override=context_override)
                self.pending_calls[tid] = callname
            else:
                self.lgr.debug('setExits call_param is none')

    def stopTrace(self, immediate=False):
        self.lgr.debug('Winsyscall stopTrace call_list %s immediate: %r' % (str(self.call_list), immediate))
        proc_copy = list(self.proc_hap)
        for ph in proc_copy:
            #self.lgr.debug('syscall stopTrace, delete self.proc_hap %d' % ph)
            self.context_manager.genDeleteHap(ph, immediate=immediate)
            self.proc_hap.remove(ph)

        #self.lgr.debug('winSyscall do call to stopTraceAlone alone')
        if immediate:
            self.stopTraceAlone(None)
        else:
            SIM_run_alone(self.stopTraceAlone, None)
        #self.lgr.debug('did call to alone')
        if self.top is not None and not self.top.remainingCallTraces(cell_name=self.cell_name):
            self.sharedSyscall.stopTrace()

        for tid in self.first_mmap_hap:
            #self.lgr.debug('syscall stopTrace, delete mmap hap tid:%s' % tid)
            self.context_manager.genDeleteHap(self.first_mmap_hap[tid], immediate=immediate)
        self.first_mmap_hap = {}

        ''' Remove from syscall lists managed by genMonitor '''
        if self.top is not None and self.call_list is not None:
            for callname in self.call_list:
                #self.lgr.debug('winSyscall stopTrace call top rmCallTrace for call_list item %s' % callname)
                self.top.rmCallTrace(self.cell_name, callname)
            ''' and try removing based on the syscall name '''
            #self.lgr.debug('winSyscall stopTrace call top rmCallTrace for %s' % self.name)
            self.top.rmCallTrace(self.cell_name, self.name)
        ''' reset SO map tracking ''' 
        self.sharedSyscall.trackSO(True)
        self.bang_you_are_dead = True
        #self.lgr.debug('winSyscall stopTrace return for %s' % self.name)

    def stopTraceAlone(self, dumb):
        #self.lgr.debug('winSyscall stopTraceAlone')
        if self.stop_hap is not None:
            RES_hap_delete_callback_id(self.stop_hap)
            self.stop_hap = None

        #self.lgr.debug('winSyscall stopTraceAlone2')
        if self.background_break is not None:
            #self.lgr.debug('winSyscall stopTraceAlone delete background_break %d' % self.background_break)
            RES_delete_breakpoint(self.background_break)
            RES_hap_delete_callback_id("Core_Breakpoint_Memop", self.background_hap)
            self.background_break = None
            self.background_hap = None
        self.lgr.debug('winSyscall stopTraceAlone, call to remove exit')
        self.sharedSyscall.rmExitBySyscallName(self.name, self.cell, immediate=True)

        if self.cur_task_hap is not None:
            rmNewProcHap(self.cur_task_hap)
            self.cur_task_hap = None
        #self.lgr.debug('stopTraceAlone done')

    def resetTimeofdayCount(self, tid):
        self.timeofday_count[tid] = 0

    def getTimeofdayCount(self, tid):
        return self.timeofday_count[tid]

    def stopMazeHap(self, syscall, one, exception, error_string):
        if self.stop_maze_hap is not None:
            SIM_run_alone(self.top.exitMaze, syscall)
            self.top.RES_delete_stop_hap(self.stop_maze_hap)
            self.stop_maze_hap = None

    def stopForMazeAlone(self, syscall):
        self.stop_maze_hap = self.top.RES_add_stop_callback(self.stopMazeHap, syscall)
        self.lgr.debug('winSyscall added stopMazeHap Now stop, syscall: %s' % (syscall))
        SIM_break_simulation('automaze')

    def checkMaze(self, syscall):
        cpu, comm, tid = self.task_utils.curThread() 
        self.lgr.debug('winSyscall checkMaze tid:%s in timer loop' % tid)
        #maze_exit = self.top.checkMazeReturn()
        #if False and maze_exit is not None:
        #    self.lgr.debug('mazeExit checkMaze tid:%s found existing maze exit that matches' % tid)
        #    maze_exit.mazeReturn(True)
        #else:
        if True:
            if self.top.getAutoMaze():
                SIM_run_alone(self.stopForMazeAlone, syscall)
            else:
                rprint("Tid %s seems to be in a timer loop.  Try exiting the maze? Use @cgc.exitMaze('%s').  \nOr autoMaze() to always exit. \n or noExitMaze() to disable loop checking." % (tid, syscall))
                SIM_break_simulation('timer loop?')
   
 
    def modeChanged(self, fun_arg, one, old, new):
        the_fun, arg = fun_arg
        if self.mode_hap is None:
            return
        self.lgr.debug('syscall modeChanged old %d new %d' % (old, new))
        if old == Sim_CPU_Mode_Supervisor:
            RES_hap_delete_callback_id("Core_Mode_Change", self.mode_hap)
            self.mode_hap = None
            SIM_run_alone(the_fun, arg)
            

    def checkTimeLoop(self, callname, tid):
        if self.cpu.architecture.startswith('arm'):
            return
        limit = 800
        delta_limit = 0x12a05f200
        if tid not in self.timeofday_count:
            self.timeofday_count[tid] = 0
        self.lgr.debug('checkTimeLoop tid:%s timeofday_count: %d' % (tid, self.timeofday_count[tid]))
        ''' crude measure of whether we are in a delay loop '''
        if self.timeofday_count[tid] == 0:
            self.timeofday_start_cycle[tid] = self.cpu.cycles
        self.timeofday_count[tid] = self.timeofday_count[tid] + 1
        if self.timeofday_count[tid] >= limit:
            now = self.cpu.cycles
            delta = now - self.timeofday_start_cycle[tid]
            self.lgr.debug('timeofday tid:%s count is %d, now 0x%x was 0x%x delta 0x%x' % (tid, self.timeofday_count[tid], now, self.timeofday_start_cycle[tid], delta))
            #if delta < 0x2540be40:
            if delta < delta_limit:
                self.timeofday_count[tid] = 0
                self.mode_hap = RES_hap_add_callback_obj("Core_Mode_Change", self.cpu, 0, self.modeChanged, (self.checkMaze, callname))
            else:
                self.timeofday_count[tid] = 0
                self.lgr.debug('checkTimeLoop tid:%s reset tod count' % tid)

    def stopOnExit(self):
        self.stop_on_exit=True
        self.lgr.debug('syscall stopOnExit')

    def handleExit(self, tid, ida_msg, killed=False, retain_so=False, exit_group=False):
        self.lgr.debug('winSyscall handleExit tid:%s  TBD, just call handleTerminateProcess for now' % tid)
        self.handleTerminateProcess(tid, ida_msg)

    def handleTerminateProcess(self, tid_in, ida_msg):
        proc_part = tid_in.split('-')[0]
        thread_dict = self.task_utils.findThreads()
        self.lgr.debug(ida_msg)
        if self.traceMgr is not None:
            self.traceMgr.write(ida_msg+'\n')
        self.context_manager.setIdaMessage(ida_msg)
        self.task_utils.setExitTid(proc_part)
        self.sharedSyscall.stopTrace()
        for thread_id in thread_dict:
            tid = '%s-%s' % (proc_part, thread_id) 
            if self.traceProcs is not None:
                self.traceProcs.exit(tid)
            self.context_manager.stopWatchTid(tid)
        if self.top.debugging():
            print('exit process :%s' % proc_part)
            SIM_run_alone(self.stopAlone, 'Terminate Process :%s' % proc_part)

    def addCallParams(self, call_params):
        gotone = False
        for call in call_params:
            if call not in self.call_params:
                self.lgr.debug('winSyscall addCallParams added call %s' % call.toString())
                self.call_params.append(call)
                gotone = True
        ''' TBD inconsistent stop actions????'''
        if gotone:
            if self.stop_action is None:
                f1 = stopFunction.StopFunction(self.top.skipAndMail, [], nest=False)
                flist = [f1]
                hap_clean = hapCleaner.HapCleaner(self.cpu)
                self.stop_action = hapCleaner.StopAction(hap_clean, flist=flist)
            self.lgr.debug('winSyscall addCallParams added params')
        else:
            pass
            #self.lgr.debug('syscall addCallParams, no new params')

    def isRecordFD(self):
        return self.record_fd

    def setRecordFD(self, tof):
        self.record_fd = tof

    def getContext(self):
        return self.cell

    def rmCallParam(self, call_param):
        if call_param in self.call_params: 
            self.call_params.remove(call_param)
        else: 
            self.lgr.error('sycall rmCallParam, but param does not exist?')

    def rmCallParamName(self, call_param_name):
        return_list = []
        rm_list = []
        for cp in self.call_params:
            if cp.name == call_param_name:
                rm_list.append(cp)
            else:
                return_list.append(cp)
        for cp in rm_list:
            self.call_params.remove(cp)
        return return_list

    def getCallParams(self):
        return self.call_params

    def remainingDmod(self):
        for call_param in self.call_params:
            if call_param.match_param.__class__.__name__ == 'Dmod':
                 return True
        return False

    def hasCallParam(self, param_name):
        retval = False
        for call_param in self.call_params:
            if call_param.name == param_name:
                retval = True
                break 
        return retval

    def getDmods(self):
        retval = []
        for call_param in self.call_params:
            if call_param.match_param.__class__.__name__ == 'Dmod':
                 dmod = call_param.match_param
                 if dmod not in retval:
                     retval.append(dmod)
        return retval

    def rmDmods(self):
        params_copy = list(self.call_params)
        rm_list = []
        for call_param in params_copy:
            if call_param.match_param.__class__.__name__ == 'Dmod':
                self.lgr.debug('syscall rmDmods, removing dmod %s' % call_param.match_param.path)
                rm_list.append(call_param)

        for call_param in rm_list:
            self.rmCallParam(call_param)
        if len(self.call_params) == 0:
            self.lgr.debug('syscall rmDmods, no more call_params, remove syscall')
            self.stopTrace()

    def getCallList(self):
        return self.call_list

    def callListContains(self, call_list):
        retval = True
        if self.call_list is not None and len(self.call_list)>0:
            for call in call_list:
                if call not in self.call_list:
                    retval = False
                    break
        else:
           retval = False
        return retval 

    def callListIntersects(self, call_list):
        retval = False
        if self.call_list is not None and len(self.call_list)>0:
            for call in call_list:
                #self.lgr.debug('syscall compare %s to %s' % (call, str(self.call_list)))
                if call in self.call_list:
                    retval = True
                    break
        return retval 

    def recordStack(self, tid):
        # TBD not used yet?
        self.lgr.debug('winSyscall recordStack tid:%s' % tid)
        self.top.recordStackClone(tid, -1)

    def watchData(self, exit_info):
        if (self.break_simulation or self.linger) and self.dataWatch is not None:
            #self.lgr.debug('winSyscall watchData True')
            return True
        else:
            #self.lgr.debug('winSyscall watchData False break_sim %r  linger %r' % (self.break_simulation, self.linger))
            return False

    def genericCallParams(self, syscall_info, exit_info, callname):
        retval = exit_info
        got_something = False
        ignore_if_not_got_something = False
        for call_param in self.call_params:
            self.lgr.debug('winSyscall genericCallparams got param name: %s type %s subcall: %s' % (call_param.name, type(call_param.match_param), call_param.subcall))
            if call_param.match_param.__class__.__name__ == 'Dmod':
                 ignore_if_not_got_something = True
                 mod = call_param.match_param
                 #self.lgr.debug('is dmod, mod.getMatch is %s' % mod.getMatch())
                 #if mod.fname_addr is None:
                 if mod.getMatch() == exit_info.fname:
                     self.lgr.debug('syscallParse, dmod match on fname %s, cell %s' % (exit_info.fname, self.cell_name))
                     exit_info.call_params.append(call_param)
                     got_something = True
                     break
            if type(call_param.match_param) is str: 
                if ((call_param.subcall is None or call_param.subcall.startswith(callname) or callname.startswith(call_param.subcall)) \
                         and (call_param.proc is None or call_param.proc == self.comm_cache[tid])):
                    if call_param.subcall in ['OpenFile', 'CreateFile'] and exit_info.fname is not None and ntpath.basename(exit_info.fname) != call_param.match_param:
                        self.lgr.debug('winSyscall genericCallParams, fname found but does not match string param')
                        ignore_if_not_got_something = True
                        continue
                    self.lgr.debug('syscall %s, found match_param %s param.subcall %s' % (callname, call_param.match_param, call_param.subcall))
                    syscall.addParam(exit_info, call_param)
                    break
                elif call_param.name == 'trackSO':
                    syscall.addParam(exit_info, call_param)
                    got_something = True
                else:
                    self.lgr.debug('winSyscall genericCallParams match_param is str, no match, set retval to None')
                    ignore_if_not_got_something = True
            elif call_param.name == 'trackSO':
                got_something = True
                exit_info.call_params.append(call_param)
        if not got_something and ignore_if_not_got_something:
            exit_info = None 
        return retval

    def resetHackCycle(self):
        self.hack_cycle= 0

    def appendRmParam(self, param):
        self.rm_param_queue.append(param)

    def rmRmParam(self, param):
        retval = False
        if param in self.rm_param_queue: 
            self.rm_param_queue.remove(param)
            retval = True
        return retval

    def parseDeviceIoCall(self, tid, comm, exit_info, trace_msg, frame, word_size):
        exit_info.old_fd = frame['param1']

        event_handle = frame['param2']
        operation = frame['param6'] & 0xffffffff
        if operation in self.ioctl_op_map:
            op_cmd = self.ioctl_op_map[operation]
            trace_msg = trace_msg + ' ' + op_cmd
            exit_info.socket_callname = op_cmd
        else:
            op_cmd = 'DeviceIOControlFile'

        pdata_addr = frame['param7']
        len_pdata = frame['param8'] & 0xFFFFFFFF
        size = min(len_pdata, 200)
        pdata = self.mem_utils.readBytes(self.cpu, pdata_addr, size)
        pdata_hx = None
        if pdata is not None:
            pdata_hx = binascii.hexlify(pdata)
        
        exit_info.retval_addr = self.stackParam(5, frame)
        exit_info.count = self.stackParam(6, frame) & 0xFFFFFFFF

        trace_msg = trace_msg+' Handle: 0x%x Operation: 0x%x Event_Handle: 0x%x' % (exit_info.old_fd, operation, event_handle)
        #self.lgr.debug('%s  cycle 0x%x' % (trace_msg, self.cpu.cycles))
        if pdata is not None and len_pdata > 0:
            trace_msg = trace_msg+' pdata: %s' % pdata_hx
 
        do_async_io = False

        if op_cmd == 'BIND':
            #sock_addr = pdata_addr+self.mem_utils.wordSize(self.cpu)
            sock_addr = pdata_addr+4
            self.lgr.debug('winSyscall %s pdata_addr: 0x%x  sock_addr: 0x%x' % (op_cmd, pdata_addr, sock_addr))
            sock_struct = net.SockStruct(self.cpu, sock_addr, self.mem_utils, exit_info.old_fd)
            exit_info.sock_struct = sock_struct
            to_string = sock_struct.getString()
            trace_msg = trace_msg + ' ' + to_string
            if not self.checkMatchParams('BIND', sock_struct, exit_info): 
                return None, None

        elif op_cmd == 'CONNECT':

            sock_addr = pdata_addr+12

            '''
            if word_size == 8:
                # TBD not right yet. fix this
                sock_addr = self.paramOffPtr(7, [16], frame, word_size) 
            else:
                sock_addr = self.paramOffPtr(7, [8], frame, word_size) 
            #sock_addr = pdata_addr+self.mem_utils.wordSize(self.cpu)
            '''
            sock_type = self.sharedSyscall.win_call_exit.getSockType(tid, exit_info.old_fd)
            if sock_type is not None:
                self.lgr.debug('pdata_addr: 0x%x  sock_addr: 0x%x sock_type: 0x%x word_size %d' % (pdata_addr, sock_addr, sock_type, word_size))
            else:
                #sock_addr = pdata_addr+12
                self.lgr.debug('pdata_addr: 0x%x  sock_addr: 0x%x sock_type unknown word_size %d ' % (pdata_addr, sock_addr, word_size))
            sock_struct = net.SockStruct(self.cpu, sock_addr, self.mem_utils, exit_info.old_fd, sock_type=sock_type)
            to_string = sock_struct.getString()
            exit_info.sock_struct = sock_struct
            trace_msg = trace_msg+' '+to_string
            if not self.checkMatchParams('CONNECT', sock_struct, exit_info): 
                return None, None
        elif op_cmd == 'SUPER_CONNECT' or op_cmd == 'SUPER_CONNECT2':

            sock_addr = pdata_addr+10

            '''
            if word_size == 8:
                # TBD not right yet. fix this
                sock_addr = self.paramOffPtr(7, [16], frame, word_size) 
            else:
                sock_addr = self.paramOffPtr(7, [8], frame, word_size) 
            #sock_addr = pdata_addr+self.mem_utils.wordSize(self.cpu)
            '''
            sock_type = self.sharedSyscall.win_call_exit.getSockType(tid, exit_info.old_fd)
            if sock_type is not None:
                self.lgr.debug('pdata_addr: 0x%x  sock_addr: 0x%x sock_type: 0x%x word_size %d' % (pdata_addr, sock_addr, sock_type, word_size))
            else:
                #sock_addr = pdata_addr+12
                self.lgr.debug('pdata_addr: 0x%x  sock_addr: 0x%x sock_type unknown word_size %d ' % (pdata_addr, sock_addr, word_size))
            sock_struct = net.SockStruct(self.cpu, sock_addr, self.mem_utils, exit_info.old_fd, sock_type=sock_type)
            to_string = sock_struct.getString()
            trace_msg = trace_msg+' '+to_string

        if op_cmd in ['ACCEPT', '12083_ACCEPT']:
            if op_cmd == '12083_ACCEPT':
                exit_info.new_fd = self.paramOffPtr(7, [4], frame, word_size)
                trace_msg = trace_msg+'New_Handle: 0x%x' % (exit_info.new_fd)
            else:
                handle_addr = pdata_addr+self.mem_utils.wordSize(self.cpu)
                exit_info.new_fd = self.mem_utils.readWord32(self.cpu, handle_addr)
            trace_msg = trace_msg + " Bind_Handle: 0x%x  Connect_Handle: 0x%x" % (exit_info.old_fd, exit_info.new_fd)
            self.lgr.debug(trace_msg)
            for call_param in self.call_params:
                #self.lgr.debug('syscall accept subcall %s call_param.match_param is %s fd is %d' % (call_param.subcall, str(call_param.match_param), exit_info.old_fd))
                if type(call_param.match_param) is int:
                    if (call_param.subcall == 'accept' or self.name=='runToIO') and (call_param.match_param < 0 or call_param.match_param == exit_info.old_fd):
                        self.lgr.debug('did accept match')
                        syscall.addParam(exit_info, call_param)
                        self.context_manager.setIdaMessage(trace_msg)
                        break

        elif op_cmd in ['RECV', 'RECV_DATAGRAM', 'SEND', 'SEND_DATAGRAM']:
            # TBD Seems to vary.  Needs much testing.  Offsets dependent on other params?  API version IDs?
            if exit_info.count > 0:
                trace_msg = trace_msg + ' OutputBuffer: 0x%x OutputBufferLength: %d' % (exit_info.retval_addr, exit_info.count)
       
            # data buffer address
            self.lgr.debug('winSyscall op_cmd <%s>' % op_cmd)

            exit_info.retval_addr = self.paramOffPtr(7, [0, word_size], frame, word_size)

            frame_string = taskUtils.stringFromFrame(frame)
            if exit_info.retval_addr is not None:
                self.lgr.debug('winSyscall %s word_size %d retval_addr 0x%x' % (op_cmd, word_size, exit_info.retval_addr))
            else:
                self.lgr.error('winSyscall %s word_size %d retval_addr None' % (op_cmd, word_size))
            #SIM_break_simulation('in send/recv') 
            #if op_cmd in ['SEND'] and word_size == 8:
            #    count_value = self.paramOffPtr(7, [0, 8], frame, word_size) 
            #else:
            #    count_value = self.paramOffPtr(7, [0, 0], frame, word_size) 
            count_value = self.paramOffPtr(7, [0, 0], frame, word_size) 
            if count_value == 0 and op_cmd in ['SEND']:
                count_value = self.paramOffPtr(7, [0, 8], frame, word_size) 
                exit_info.retval_addr = self.paramOffPtr(7, [0, 0xc], frame, word_size)
                self.lgr.debug('%s %s was zero HACK adjust offsets so now count_value 0x%x' % (op_cmd, comm, count_value))
            if count_value is not None:
                send_string = ''
                exit_info.count = count_value & 0xFFFFFFFF
                self.lgr.debug('%s %s count_value 0x%x' % (op_cmd, comm, count_value))

                if op_cmd == 'SEND_DATAGRAM':
                    if word_size == 8:
                        #sock_addr = self.paramOffPtr(7, [0], frame, word_size) + 0x68
                        exit_info.sock_addr = self.paramOffPtr(7, [0x60], frame, word_size) 
                    else:
                        exit_info.sock_addr = self.paramOffPtr(7, [0x34], frame, word_size) 
                    self.lgr.debug('SEND_DATAGRAM sock_addr: 0x%x count_value %d' % (exit_info.sock_addr, count_value))
                    sock_struct = net.SockStruct(self.cpu, exit_info.sock_addr, self.mem_utils, exit_info.old_fd)
                    send_string = sock_struct.getString()
                    ## TBD UDP has different params than TCP?
                elif op_cmd == 'RECV_DATAGRAM':
                    if word_size == 8:
                        exit_info.sock_addr = self.paramOffPtr(7, [0x18], frame, word_size) 
                    else:
                        exit_info.sock_addr = self.paramOffPtr(7, [0x10], frame, word_size) 
                    
                    self.lgr.debug('RECV_DATAGRAM sock_addr: 0x%x count_value %d' % (exit_info.sock_addr, count_value))
                    # TBD UDP has different params than TCP?
                    sock_struct = net.SockStruct(self.cpu, exit_info.sock_addr, self.mem_utils, exit_info.old_fd)
                    to_string = sock_struct.getString()
                    #self.lgr.debug('winSyscall sock %s' % to_string)
                    #frame_string = taskUtils.stringFromFrame(frame)
                    #SIM_break_simulation(trace_msg+' '+to_string+ ' '+frame_string)

                # TBD count_addr vs delay_count_addr
                # REMOVE THIS
                exit_info.count_addr = frame['param5'] + 8
                #exit_info.delay_count_addr = exit_info.count_addr
                
                if word_size == 4:
                    param_val = self.paramOffPtr(5, [0], frame, word_size) 
                    if param_val is None:
                        self.lgr.debug('winSyscall tid:%s failed to get delay_count_addr from stack2, count_addr is 0x%x set delay_count to none' % (tid, exit_info.count_addr))
                        exit_info.delay_count_addr = None
                    else:
                        exit_info.delay_count_addr = param_val + word_size
                else:
                    exit_info.delay_count_addr = self.stackParam(1, frame) + word_size
               
                if exit_info.delay_count_addr is not None:
                    self.lgr.debug('winSyscall tid:%s %s returned delay_count_addr 0x%x' % (tid, op_cmd, exit_info.delay_count_addr))
                else:
                    self.lgr.debug('winSyscall tid:%s %s returned delay count addr is None' % (tid, op_cmd))
                if exit_info.retval_addr is None:
                    self.lgr.error('winSyscall retval_addr None')
                elif exit_info.count is None:
                    self.lgr.error('winSyscall count None')
                elif exit_info.count_addr is None:
                    self.lgr.error('winSyscall count_addr None')
                elif exit_info.delay_count_addr is None:
                    trace_msg = trace_msg + ' data_buf_addr: 0x%x count_requested: 0x%x count_addr: 0x%x delay_count_addr is None  %s' %  (exit_info.retval_addr, 
                            exit_info.count, exit_info.count_addr, send_string)
                else: 
                    trace_msg = trace_msg + ' data_buf_addr: 0x%x count_requested: 0x%x count_addr: 0x%x delay_count_addr: 0x%x %s' %  (exit_info.retval_addr, 
                            exit_info.count, exit_info.count_addr, exit_info.delay_count_addr, send_string)
                self.lgr.debug(trace_msg)
                frame_string = taskUtils.stringFromFrame(frame)
                self.lgr.debug(frame_string)
                do_async_io = True

            else:
                trace_msg = trace_msg + ' failed to read count'
                exit_info.count=0
                self.lgr.debug(trace_msg)

        elif op_cmd in ['GET_PEER_NAME']:
            self.lgr.debug(trace_msg)
        #elif op_cmd == 'TCP_FASTOPEN':
        #    trace_msg = trace_msg+' '+to_string

        #self.lgr.debug('winSyscall socket check call params')
        for call_param in self.call_params:
            #self.lgr.debug('winSyscall %s op_cmd: %s subcall is %s handle is %s match_param is %s call_param.name is %s call_list: %s' % (self.name, op_cmd, call_param.subcall, str(exit_info.old_fd), str(call_param.match_param), call_param.name, str(self.call_list)))
            if self.call_list is not None and (op_cmd in self.call_list or call_param.subcall == op_cmd)  and type(call_param.match_param) is int and \
                         (call_param.match_param == -1 or call_param.match_param == exit_info.old_fd) and \
                         (call_param.proc is None or call_param.proc == self.comm_cache[tid]):
                self.lgr.debug('winSyscall socket first if block satisfied')
                if call_param.nth is not None:
                    call_param.count = call_param.count + 1
                    self.lgr.debug('winSyscall parse socket %s call_param.nth not none, is %d, count incremented to  %d' % (op_cmd, call_param.nth, call_param.count))
                    if call_param.count >= call_param.nth:
                        self.lgr.debug('count >= param, set exit_info.call_params to catch return')
                        syscall.addParam(exit_info, call_param)
                        if self.kbuffer is not None and exit_info.count > 0:
                            self.lgr.debug('winSyscall read kbuffer for addr 0x%x' % exit_info.retval_addr)
                            self.kbuffer.read(exit_info.retval_addr, exit_info.count, exit_info.old_fd)
                        break
                else:
                    self.lgr.debug('call_param.nth is none, call it matched')
                    syscall.addParam(exit_info, call_param)
                    if self.kbuffer is not None and exit_info.count > 0:
                        self.lgr.debug('syscall read kbuffer for addr 0x%x' % exit_info.retval_addr)
                        self.kbuffer.read(exit_info.retval_addr, exit_info.count, exit_info.old_fd)
                break
            elif call_param.name == 'runToReceive' and op_cmd in ['RECV', 'RECV_DATAGRAM']:
                self.lgr.debug('winSyscall parse socket call %s is runToReceive append call_param.match_param %s' % (op_cmd, call_param.match_param))
                exit_info.call_params.append(call_param)
            elif call_param.name == 'runToSend' and op_cmd in ['SEND', 'SEND_DATAGRAM']:
                self.lgr.debug('winSyscall parse socket call %s is runToReceive append call_param.match_param %s' % (op_cmd, call_param.match_param))
                exit_info.call_params.append(call_param)
            elif call_param.name == 'runToIO' and type(call_param.match_param) is int:
                exit_info = None
            elif call_param.name == 'runToCall':
                if self.call_list is not None and (op_cmd not in self.call_list):
                    self.lgr.debug('winSyscall parse socket call %s, but not what we think is a runToCall.' % op_cmd)
                    exit_info = None
                elif self.call_list is None and op_cmd != call_param.subcall:
                    self.lgr.debug('winSyscall parse socket call %s, but not what we think is a runToCall with call_list of none.' % op_cmd)
                    exit_info = None
                else:
                    self.lgr.debug('winSyscall parse socket call %s, add call_param to exit_info' % op_cmd)
                    syscall.addParam(exit_info, call_param)
                    if self.stop_on_call and not self.linger:
                        frame_string = taskUtils.stringFromFrame(frame)
                        self.lgr.debug(frame_string)
                        self.lgr.debug('winSyscall stop_on_call')
                        SIM_break_simulation('stop_on_call') 
        
        if do_async_io and exit_info is not None: 
            if exit_info.count > 0:
                exit_info.asynch_handler = winDelay.WinDelay(self.top, self.cpu, tid, comm, exit_info, exit_info.sock_addr,
                      self.mem_utils, self.context_manager, self.traceMgr, exit_info.socket_callname, self.kbuffer, 
                      exit_info.old_fd, exit_info.count, self.stop_action, self.lgr)
                if self.watchData(exit_info):
                    self.lgr.debug('doing winDelay.setDataWatch, maybe')
                    exit_info.asynch_handler.setDataWatch(self.dataWatch, exit_info.syscall_instance.linger) 
        return op_cmd, trace_msg

    def checkMatchParams(self, call_name, sock_struct, exit_info):
            retval = True
            for call_param in self.call_params:
                #self.lgr.debug('winSyscall subcall %s call_param.proc %s' % (call_param.subcall, call_param.proc))
                if call_param.subcall == call_name and (call_param.proc is None or call_param.proc == self.comm_cache[tid]):
                     if call_param.match_param is not None:
                         #self.lgr.debug('winSyscall match_param is %s' % str(call_param.match_param))
                         go = None
                         if sock_struct.port is not None:
                             #self.lgr.debug('winSyscall sock_struct.port %s' % sock_struct.port)
                             ''' look to see if this address matches a given pattern '''
                             s = sock_struct.dottedPort()
                             pat = call_param.match_param
                             try:
                                 go = re.search(pat, s, re.M|re.I)
                             except:
                                 self.lgr.error('invalid expression: %s' % pat)
                                 return False
                         
                             #self.lgr.debug('socketParse look for match %s %s' % (pat, s))
                         if len(call_param.match_param.strip()) == 0 or go or call_param.match_param == sock_struct.sa_data: 
                             self.lgr.debug('socketParse found match %s' % (call_param.match_param))
                             syscall.addParam(exit_info, call_param)
                             if go:
                                 ida_msg = '%s to %s, FD: %d' % (call_name, s, sock_struct.fd)
                             else:
                                 ida_msg = '%s to %s, FD: %d' % (call_name, call_param.match_param, sock_struct.fd)
                             self.context_manager.setIdaMessage(ida_msg)
                             break
                     
                     if call_name == 'BIND' and syscall.AF_INET in call_param.param_flags and sock_struct.sa_family == net.AF_INET:
                         syscall.addParam(exit_info, call_param)
                         self.sockwatch.bind(tid, sock_struct.fd, call_param)
            return retval


    def getWordSize(self, tid):
        # determine if we are going to be doing 32 or 64 bit syscall
        if tid in self.word_size_cache:
            word_size = self.word_size_cache[tid]
            #self.lgr.debug('winSyscall syscallParse tid %s in cache word size %d' % (tid, word_size))
        else: 
            word_size = self.default_app_word_size
            somap_size = self.soMap.wordSize(tid)
            if somap_size is None:
                #self.lgr.debug('winSyscall syscallParse tid %s got somap_size none' % (tid))
                pass
            else:
                #self.lgr.debug('winSyscall syscallParse tid %s not in cache somap_size %d' % (tid, somap_size))
                word_size = somap_size
            self.word_size_cache[tid] = word_size
        return word_size


    def recordLoadAddr(self, tid):
        # use doInUser to ensure record is paged in
        comm = self.task_utils.getCommFromTid(tid) 
        self.lgr.debug('recordLoadAddr tid:%s (%s) do it in user space' % (tid, comm))
        doInUser.DoInUser(self.top, self.cpu, self.doRecordLoadAddr, tid, self.task_utils, self.mem_utils, self.lgr, tid=tid)

    def doRecordLoadAddr(self, tid):
        # WARNING this is a contextManager callback on a reschedule.  The task info is not yet loaded
        comm = self.task_utils.getCommFromTid(tid) 
        eproc = self.task_utils.getProcRecForTid(tid)
        self.lgr.debug('winSyscall doRecordLoad addr tid:%s (%s) eproc 0x%x' % (tid, comm, eproc))
        load_addr = winProg.getLoadAddress(self.cpu, self.mem_utils, eproc, comm, self.lgr)
        if load_addr is None:
            self.lgr.error('winSyscall doRecordLoad failed to get load addess for %s' % tid)
            return
        prog = self.soMap.findPendingProg(comm)
        if prog is None:
            self.lgr.error('winSyscall doRecordLoad failed to get pending prog for %s (%s)' % (tid, comm))
            return
        full_path = self.top.getFullPath(fname=prog)
        size, machine, image_base, text_offset = winProg.getSizeAndMachine(full_path, self.lgr)
        if size is None:
            self.lgr.debug('winSyscall doRecordLoad unable to get size.  Maybe executable is not in the local file system.  Otherwise, is path to executable defined in the ini file RESIM_root_prefix? Useing full_path %s')
            return 
        text_addr = load_addr + text_offset
        self.soMap.addText(prog, tid, load_addr, size, machine, image_base, text_offset, full_path)
        sp = self.mem_utils.getRegValue(self.cpu, 'sp')
        # stack base found via hurestic, windows libs manage it.
        #self.top.recordStackBase(tid, sp)
        self.lgr.debug('winSyscall doRecordLoadAddr runToText got size 0x% sp 0x%xx' % (size, sp))

    def rmPendingCall(self, tid):
        if tid in self.pending_calls:
            del self.pending_calls[tid]

