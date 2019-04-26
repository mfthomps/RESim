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
#import mftHap
import sys
import os
import gc
import signal
try:
    from pympler import asizeof
except:
    pass
from itertools import cycle

OS_TYPE = os.getenv('CGC_OS_TYPE')
DEVEL = os.getenv('CGC_DEVEL')
SIMICS_VER = os.getenv('SIMICS_VER')
INSTANCE = os.getenv('INSTANCE')
ONE_BOX = os.getenv('ONE_BOX')
if INSTANCE is None:
    INSTANCE = '0'

#SIM_SCRIPTS = '/mnt/cgc/simics/simicsScripts'

PY_SHARED = '/usr/share/pyshared'
CORE = None
if DEVEL is not None and DEVEL == 'YES':
    CORE = '/mnt/cgcsvn/cgc/trunk/cgc-monitor/simics/monitorCore'
else:
    CORE = os.path.join(PY_SHARED, 'monitorCore')
if CORE not in sys.path:
    print("using CORE of %s" % CORE)
    sys.path.append(CORE)
if PY_SHARED not in sys.path:
    sys.path.append(PY_SHARED)

from monitorLibs import configMgr
from monitorLibs import configMgr

# default to 4.8
lib = configMgr.sim_lib_path

if lib not in sys.path:
    sys.path.append(lib)


#if SIM_SCRIPTS not in sys.path:
#    sys.path.append(SIM_SCRIPTS)
import ConfigParser
import osUtils
import getSymbol
import time
import ropCop
import notCode
import hapManager
import startDebugging
import startDebugging2
import procInfo
import debugInfo
import contextManager
import cgcEvents
import noX
import protectedMemory
import kernelInfo
import cellConfig
import masterConfig
import watchKernel
import watchUID
import pageUtils
import pageFaults
import otherFaults
import targetLog
import bsdProcessUtils
import bsdParams
import bsd64Params
import linux64Params
import linuxProcessUtils
import memUtils
import watchLinuxCreds
import callLog
import tracing
import socket
import StringIO
import findKernelWrite
import taintManager
import chainHap
import reverseToCall
import runToUserSpace
import debugSignal
import stopHap
import stopHapCallback
import reverseToWhatever
import codeCoverage
import keepAlive
import negotiatePoV
import debugType2
import bookmarkMgr
import bsdUnexpected
import returnToUserHap
import runToSyscall
import isMonitorRunning
import decode
import reverseToAddr
import AutoAnalysis
from monitorLibs import programSections
from monitorLibs import utils
from monitorLibs import szk
from monitorLibs import forensicEvents
#import putPackages
#import trackSetup
cgc = None
'''
Report on syscalls to CGCOS made by decendents of a server process,
i.e., cb-server and by  decendents of a replay master that creates
replay processes.  Also report on signals and memory accesses to a 
selected address range.  And execution of non-executable code and
returns that don't correspond to calls.
TBD: currently assumes single processor models.
TBD: clean up memory callbacks/breakpoints on sigterm, etc.
'''
class cgcMonitor():
    SIMICS_BUG=False
    NO_TRACK = True
    #NO_TRACK = False
    # Offsets and such read from a parameters file
    __param = {} 

    # 
    __rop_cop = None
    __keep_alive = None
    __noX = None
    __non_code = None
    __protected_memory = None
    __context_manager = None
    __taint_manager = None
    # next three python module instances are one per cell_name
    __os_p_utils = {} 
    __mem_utils = {} 
    __watch_uid = {} 
    __kernel_info = {} 
    __watch_kernel = None
    __cell_config = None
    __zk = None
    __master_config = None
    target_log = None
    __negotiate = None
 

    ''' The following have dictionary entries per cell (per host) '''
    __sysenter_break = {}
    # Map PID to syscall numbers so we know what we are returning from
    __syscall_entries = {}
    __unmapped_eips = {}
    __return_to_cycle = {}

    __server_hap = {}

    __watch_non_code = {}
    __pending_signals = {}
    __did_track_setup = {}
    # The PID of the server process.  We only record syscalls by decendents of the server
    __server_pid = {}

    __last_ret_eip = {}
    __watching = {}
    __num_calls = {}
    __bytes_wrote = {}
    __bytes_read = {}

    __reg_frame = {}

    __replay_file_name = {}
    __rules_file_name = {}
    __cb_file_name = {}

    #watching_current_syscalls = {}
    __previous_pid_cycle = {}
    __pid_cycles = {}
    __previous_pid_user_cycle = {}
    __pid_user_cycles = {}
    
    __pid_wallclock_start = {}
    __call_log = {}
    __prog_sections = {}

    __ret_exec_break = {}
    __ret_exec_hap = {}

    __num_cb_binaries = 0

    __mode_changed = {}

    __player_hap = None
    __player_break = None
    __player_offset = None
    __player_monitor = False

    __fd_set_size = None

    __find_kernel_write = None
    __gdb_mailbox = None
    __rev_to_call = None
    __signal_cycle = None

    __first_eip = {}
    __x_pages = {}
    continuation_hap = None
    stopped_reverse_instruction_hap = None

    __errored_syscalls = {}

    __manager_pid = None
    __replay_pid = None
    __player_pid = None
    __pov_manager_pid = None
    __cfe_poller_pid = None
    __ids_pid = []
    __ids_cell_name = None
    __code_coverage = None

    __pid_structs_to_clean = {}
    __pid_contexts_to_clean = {}

    debug_syscall_break = {}
    debug_syscall_hap = {}

    __cr3 = {}
    __cr4 = {}

    __rop_pending = {}

    __have_returned_from = []

    __auto_analysis = None
    __recent_throw_id = None
    # CGCOS syscall numbers
    SYS_EXIT = 1
    SYS_WRITE = 2
    SYS_READ = 3
    SYS_FDWAIT = 4
    SYS_ALLOCATE = 5
    SYS_DEALLOCATE = 6
    SYS_RANDOM = 7

    PROT_EXEC = 4
    PROT_NONE = 0
    PAGE_SIZE = 4096
    EXEC_PATH_LENGTH = 64
    TRANSMIT_FD = 1
    RECEIVE_FD = 0
    NEGOTIATE_FD = 3
 

    def __init__(self):
        #self.alloc_count=0
        #self.free_count=0
        SIM_run_command("set-memory-limit 1000")
        self.always_watch_calls = False
        if SIMICS_VER == '4.8':
            # TBD should be able to run wihtout tracking?
            #print 'setting NO_TRACK to true'
            #self.NO_TRACK = True
            pass
        ''' Which cells perform which functions (e.g., server, thrower) '''
        num_boxes = 3
        if ONE_BOX == 'YES':
            num_boxes = 1
        self.__cell_config = cellConfig.cellConfig(num_boxes, OS_TYPE)
        self.__cell_config.loadCellObjects()
        # dictionaries keyed on cell_name
        self.__os_params = osUtils.getOSParams(self.__cell_config.os_type)
        ''' not to be confused with master.cfg, the configMgr includes directories and such for 
            the monitor and is also used by  simulated targets
        '''
        self.cfg = configMgr.configMgr(self.__cell_config.os_type)
        ''' Initialize zookeeper module, zk functions have own log, see szk.log ''' 
        hostname = socket.gethostname() 
        self.__zk = szk.szk(hostname, self.cfg, INSTANCE, local_logging=False)
        instance = INSTANCE
        if instance is None:
            instance = 'x'
        my_name = 'monitor_'+instance
        self.lgr = utils.getLogger(my_name, os.path.join(self.cfg.logdir, 'monitors'))
        ''' What to monitor, kernel section addresses, etc. '''
        self.__master_config = masterConfig.masterConfig(self, self.__cell_config, self.__zk)
        if not self.__master_config.load(lgr=self.lgr):
            print 'error reading master.cfg (from zk) '
            self.lgr.error("error reading master.cfg (from zk) exiting")
            exit(1)
        log_level = self.__master_config.logLevel()
        self.lgr.setLevel(log_level)
        self.sys_cfg = self.getConfigCode()
        self.lgr.debug('cgcMonitor got system config code %s' % self.sys_cfg)
        self.lgr.debug('cgcMonitor zk client_id is 0x%x' % self.__zk.zk.client_id[0])

        ''' 
        Someone has to record the master configuration file used in this run 
        This is for the initial case of monitors starting up with no replays to handle.
        Functions that enqueue replays will also make sure the config is recorded
        TBD: would require sql clients in all targets.  Just record via enqueuing
        '''
        #got_lock, has_lock = self.__zk.getHouseKeepingLock(self.__master_config.checksum)
        #if got_lock:
        #    self.__master_config.recordConfig()
        #else:
        #    self.lgr.debug('housekeeping lock was taken by %s' % has_lock)

        self.log_sys_calls = self.__master_config.logSysCalls()

        self.is_monitor_running = isMonitorRunning.isMonitorRunning(self.lgr)
        ''' __param is Kernel offsets, e.g., where is the comm field in a proc record? '''
        for cell_name in self.__cell_config.os_type:
            if self.__cell_config.os_type[cell_name] == osUtils.LINUX:
                settings, p_file = osUtils.loadParameters(os.path.join(self.cfg.os_params_dir, 
                   self.__os_params[cell_name]))
                self.lgr.info('Loaded parameters from %s (%s) for OS type: %s' % (self.__os_params[cell_name], 
                   p_file, self.__cell_config.os_type[cell_name]))
                self.lgr.info('system map: %s' % self.cfg.system_map[cell_name])
                print('system map: %s' % self.cfg.system_map[cell_name])

                self.__param[cell_name] = linuxParams.linuxParams()
                self.__mem_utils[cell_name] = memUtils.memUtils(4, self.__param[cell_name])
            elif self.__cell_config.os_type[cell_name] == osUtils.LINUX64:
                self.__param[cell_name] = linux64Params.linux64Params()
                self.__mem_utils[cell_name] = memUtils.memUtils(8, self.__param[cell_name])
                self.lgr.debug('loaded linux64')
            elif self.__cell_config.os_type[cell_name] == osUtils.FREE_BSD64:
                self.__param[cell_name] = bsd64Params.bsd64Params()
                self.__mem_utils[cell_name] = memUtils.memUtils(8, self.__param[cell_name])
                self.lgr.debug('loaded bsd64Params')
            elif self.__cell_config.os_type[cell_name] == osUtils.FREE_BSD:
                self.__param[cell_name] = bsdParams.bsdParams()
                self.__mem_utils[cell_name] = memUtils.memUtils(4, self.__param[cell_name])
                self.lgr.debug('loaded bsdParams')
            else:
                self.lgr.error('on %s, unknown os type %s' % (cell_name, self.__cell_config.os_type[cell_name]))
        #print self.__param.stack_size

        if not self.cfg.no_monitor:
            ''' children of replay master that we don't care about '''
            self.__exempt_comms = ['sh', 'scp', 'ssh', 'mkdir', 'rm']
            #self.hapTrack()
            self.target_log = targetLog.targetLog(self, self.__zk, self.cfg, self.__master_config, self.sys_cfg, self.lgr)
            self.lgr.debug('back from targetLog init, done with init')
            self.__negotiate = negotiatePoV.negotiatePoV(self, self.cfg, self.__master_config, self.target_log, self.lgr)
            self.doInit()
            self.lgr.debug('back from doInit')
        else:
            self.lgr.debug('no monitoring, set status & reset and do nothing else')
            self.zkStatusAndReset()

        self.hack_break = None
        self.hack_hap = None

    def getCR3(self, cpu):
        if cpu in self.__cr3:
            # must be a re-init, ignore.
            return
        done = True
        cell_name = self.getTopComponentName(cpu)
        while SIM_processor_privilege_level(cpu) != 0:
            print('not in pl0, fiddle some')
            SIM_continue(100000000)
        reg_num = cpu.iface.int_register.get_number("cr3")
        self.__cr3[cpu] = cpu.iface.int_register.read(reg_num)
        print('***************************************************got cr3 value of 0x%x' % self.__cr3[cpu])
        reg_num = cpu.iface.int_register.get_number("cr4")
        self.__cr4[cpu] = cpu.iface.int_register.read(reg_num)
        addr_extend = memUtils.testBit(self.__cr4[cpu], 5)
        print('got cr4 value of 0x%x, addr_extend is %d' % (self.__cr4[cpu], addr_extend))
        self.lgr.debug('getCR3 on %s, cr3: 0x%x  cr4: 0x%x' % (cell_name, self.__cr3[cpu], self.__cr4[cpu]))

    def forceWatchReturn(self, cpu, cell_name, comm, pid):
        cell = self.__cell_config.cell_context[cell_name]
        self.lgr.debug('cgcMonitor forceWatchReturn %s %d   watch calls: %r' %  (comm, pid, self.__master_config.watchCalls(cell_name, comm)))
        self.doKernelSysCalls(cpu, cell_name, comm, pid, force=True)
        '''
        if not self.__master_config.watchCalls(cell_name, comm) and self.__code_coverage is not None: 
            doKernelSysCalls(self, cpu, cell_name, comm, pid, force=True)
            #ret_callback = self.__hap_manager.kernelSysCall(cpu, cell_name, cell, self.__kernel_info[cell_name].userret_offset, self.ret_callback)
            #self.lgr.debug('cgcMonitor, forceWatchRreturn did kernelSysCall for userret_offset hap %d comm is %s' % (ret_callback, comm))
        else:
            self.lgr.debug('cgcMonitor forceWatchReturn did not call doKernelSyscalls for %s %d' % (comm, pid))
        '''

    def getConfigCode(self):
        code = ''
        sixtyfour=''
        for cell_name in self.__cell_config.os_type:
            if self.__cell_config.os_type[cell_name].startswith(osUtils.FREE_BSD):
                code=code+'k'
                if self.__cell_config.os_type[cell_name] == osUtils.FREE_BSD64:
                    sixtyfour = '64'
            elif self.__cell_config.os_type[cell_name] == osUtils.LINUX64:
                code=code+'l'
            elif self.__cell_config.os_type[cell_name] == osUtils.LINUX:
                code=code+'d'
            else:
                code = code+'?'
                self.lgr.debug('getConfigCode, os_type %s unknown' % self.__cel_config.os_type[cell_name])
        code = code+sixtyfour    
        return code

    def watching_current_syscalls(self, cell_name, pid):
        return self.__hap_manager.watchingCurrentSyscalls(cell_name, pid)

    def forceKernelSysCalls(self, cpu, cell_name):
        doKernelSysCalls(self, cpu, cell_name, None, 0, force=True)
        self.lgr.debug('forceKernelSysCalls')
        return
        '''
        self.watching_current_syscalls[cpu] = True
        cell = self.__cell_config.cell_context[cell_name]
        self.lgr.debug('forceKernelSysCalls watching kernel syscalls')
        self.__hap_manager.kernelSysCall(cpu, cell_name, cell, self.__kernel_info[cell_name].syscall_offset, self.sys_callback)

        # linux has many ways to enter the kernel for non-CGCOS processes
        if self.__kernel_info[cell_name].sysentry_offset is not None:
            self.__sysenter_break[cell_name] = self.__hap_manager.kernelSysCall(cpu, cell_name, 
                                                   cell, self.__kernel_info[cell_name].sysentry_offset, self.sys_callback)
            self.lgr.debug('forceKernelSysCalls break for sysentry_offset is %d' % self.__sysenter_break[cell_name])

        ret_callback = self.__hap_manager.kernelSysCall(cpu, cell_name, cell, self.__kernel_info[cell_name].userret_offset, self.ret_callback)
        self.lgr.debug('forceKernelSysCalls break for userret_offset is %d' % ret_callback)

        if self.__kernel_info[cell_name].sysenter_exit is not None:
            self.__hap_manager.kernelSysCall(cpu, cell_name, cell, self.__kernel_info[cell_name].sysenter_exit, self.sysenter_exit_callback)

        if self.__kernel_info[cell_name].syscall_exit is not None:
            self.__hap_manager.kernelSysCall(cpu, cell_name, cell, self.__kernel_info[cell_name].syscall_exit, self.syscall_exit_callback)
        '''



    ''' set breakpoint/callbacks for kernel system calls and user space returns, intended to be called while in a process we
        are watching.
        Note we take comm as a param vice from getPinfo because the latter may be a pre-exec program name
    '''
    def doKernelSysCalls(self, cpu, cell_name, comm, pid, force=False):
        dumcpu, cur_addr, dum_comm, pid = self.__os_p_utils[cell_name].getPinfo(cpu)
        self.lgr.debug('doKernelSysCalls doing Calls on %s for %d (%s)' % (cell_name, pid, comm))
        if self.__hap_manager.watchingCurrentSyscalls(cell_name, pid):
            self.lgr.debug('doKernelSyscalls, already watching for %s %d' % (cell_name, pid))
            return
        #self.watching_current_syscalls[cell_name] = True
        cell = self.__cell_config.cell_context[cell_name]
        if force or self.__master_config.watchCalls(cell_name, comm): 
            self.lgr.debug('doKernelSysCalls watching kernel syscalls for %d (%s) %s' % (pid, comm, str(cpu)))
            self.__hap_manager.kernelSysCall(cpu, cell_name, cell, self.__kernel_info[cell_name].syscall_offset, self.sys_callback)

            # linux has many ways to enter the kernel for non-CGCOS processes
            #isNetworkHost = self.__cell_config.cells[cell_name] == 'network host'
            #if self.__kernel_info.sysentry_offset is not None and not isNetworkHost:
            if self.__kernel_info[cell_name].sysentry_offset is not None:
                self.__sysenter_break[cell_name] = self.__hap_manager.kernelSysCall(cpu, cell_name, 
                                                       cell, self.__kernel_info[cell_name].sysentry_offset, self.sys_callback)
                self.lgr.debug('doKernelSysCalls break for sysentry_offset is %d' % self.__sysenter_break[cell_name])

            ret_callback = self.__hap_manager.kernelSysCall(cpu, cell_name, cell, self.__kernel_info[cell_name].userret_offset, self.ret_callback)
            #self.lgr.debug('doKernelSysCalls break for userret_offset is %d' % ret_callback)

            if self.__kernel_info[cell_name].sysenter_exit is not None:
                self.__hap_manager.kernelSysCall(cpu, cell_name, cell, self.__kernel_info[cell_name].sysenter_exit, self.sysenter_exit_callback)

            if self.__kernel_info[cell_name].syscall_exit is not None:
                self.__hap_manager.kernelSysCall(cpu, cell_name, cell, self.__kernel_info[cell_name].syscall_exit, self.syscall_exit_callback)
        self.__hap_manager.incKernelSysCalls(cell_name, pid)

    def doDumbBreak(self, sym, cpu):
        phys_block = cpu.iface.processor_info.logical_to_physical(sym, Sim_Access_Read)
        dum_break = SIM_breakpoint(cpu.physical_memory, Sim_Break_Physical, Sim_Access_Execute, phys_block.address, 1, 0)
        self.lgr.debug('doIinitCell dumb break %d set at %x phys: %x' % (dum_break, sym, phys_block.address))
        dum_hap = SIM_hap_add_callback_index("Core_Breakpoint_Memop", 
		self.doExitCallback, cpu, dum_break)

    ''' Initialization for a specific cell, i.e., one computer in the simulated network '''
    def doInitCell(self, cell_name):
        #if cell_name == 'server':
        #    self.hack_breaks(cell_name)
        self.lgr.info('in doInitCell for cell %s' % cell_name)
        ''' Set breaks and haps on syscall, userret entry and signals.  '''        
        cpu = self.__cell_config.cpuFromCell(cell_name)
        if self.always_watch_calls:
            self.forceKernelSysCalls(cpu, cell_name)
        cell = self.__cell_config.cell_context[cell_name]

        # kernel syscalls now managed in the os_p_utils module.  Enable/Disable based on current task
        #self.doKernelSysCalls(cpu, cell_name)
        if self.__kernel_info[cell_name].execve_offset is not None:
            #phys_block = cpu.iface.processor_info.logical_to_physical(self.__kernel_info[cell_name].execve_offset, Sim_Access_Read)
            #self.lgr.debug('doInitCell phys addr for exeve is %x' % phys_block.address)
            #execve_break = SIM_breakpoint(cpu.physical_memory, Sim_Break_Physical, Sim_Access_Execute, 
            #    phys_block.address, 1, 0)
            self.__hap_manager.breakLinear(cell_name, self.__kernel_info[cell_name].execve_offset, Sim_Access_Execute, self.execve_callback, 'execve')

            #execve_break = SIM_breakpoint(cell, Sim_Break_Linear, Sim_Access_Execute, 
            #    self.__kernel_info[cell_name].execve_offset, 1, 0)
            #execve_hap = SIM_hap_add_callback_index("Core_Breakpoint_Memop", 
	    #	self.execve_callback, cpu, execve_break)
            #self.__hap_manager.addBreak(cell_name, None, execve_break, None)
            #self.__hap_manager.addHap(cpu, cell_name, None, execve_hap, None)
            #self.lgr.debug('doInitCell for %s execve break %d set at %x' % (cell_name, execve_break, self.__kernel_info[cell_name].execve_offset))
        else:
            self.lgr.error('no execve_offset for %s' % cell_name)
        if self.__kernel_info[cell_name].sys_clone is not None:
            self.__hap_manager.breakLinear(cell_name, self.__kernel_info[cell_name].sys_clone, Sim_Access_Execute, self.sys_clone_callback, 'sys_clone')
            #clone_break = SIM_breakpoint(cell, Sim_Break_Linear, Sim_Access_Execute, 
            #    self.__kernel_info[cell_name].sys_clone, 1, 0)
            #clone_hap = SIM_hap_add_callback_index("Core_Breakpoint_Memop", 
	    #	self.sys_clone_callback, cpu, clone_break)
            #self.__hap_manager.addBreak(cell_name, None, clone_break, None)
            #self.__hap_manager.addHap(cpu, cell_name, None, clone_hap, None)
            #self.lgr.debug('doInitCell for %s sys_clone break %d set at %x' % (cell_name, clone_break, self.__kernel_info[cell_name].sys_clone))

            self.__hap_manager.breakLinear(cell_name, self.__kernel_info[cell_name].ret_from_fork, Sim_Access_Execute, self.ret_from_fork_callback, 'ret_from_fork')
            #clone_break = SIM_breakpoint(cell, Sim_Break_Linear, Sim_Access_Execute, 
            #    self.__kernel_info[cell_name].ret_from_fork, 1, 0)
            #clone_hap = SIM_hap_add_callback_index("Core_Breakpoint_Memop", 
	    #	self.ret_from_fork_callback, cpu, clone_break)
            #self.__hap_manager.addBreak(cell_name, None, clone_break, None)
            #self.__hap_manager.addHap(cpu, cell_name, None, clone_hap, None)
        for cpu in self.__cell_config.cell_cpu_list[cell_name]:
            self.getCR3(cpu)

      
        '''
        sym = self.__kernel_info[cell_name].do_exit
        self.doDumbBreak(sym, cpu)
        sym = self.__kernel_info[cell_name].do_group_exit
        self.doDumbBreak(sym, cpu)

        sym = self.__kernel_info[cell_name].exit_range_min 
        self.doDumbBreak(sym, cpu)

        sym = self.__kernel_info[cell_name].exit_range_max
        self.doDumbBreak(sym, cpu)
        '''
        # catch process exit, needed for replay when CB's fail validation
        sym = self.__kernel_info[cell_name].do_exit
        #phys_block = cpu.iface.processor_info.logical_to_physical(sym, Sim_Access_Read)
        #exit_break = SIM_breakpoint(cpu.physical_memory, Sim_Break_Physical, Sim_Access_Execute, phys_block.address, 1, 0)
        self.__hap_manager.breakLinear(cell_name, sym, Sim_Access_Execute, self.doExitCallback, 'do_exit')
        #cell = self.__cell_config.cell_context[cell_name]
        #exit_break = SIM_breakpoint(cell, Sim_Break_Linear, Sim_Access_Execute, sym, 4, 0)
        #self.lgr.debug('doIinitCell do_exit break %d set at %x ' % (exit_break, sym))
        #exit_hap = SIM_hap_add_callback_index("Core_Breakpoint_Memop", 
	#	self.doExitCallback, cpu, exit_break)
        #self.__hap_manager.addBreak(cell_name, None, exit_break, None)
        #self.__hap_manager.addHap(cpu, cell_name, None, exit_hap, None)

        #phys_block = cpu.iface.processor_info.logical_to_physical(self.__kernel_info[cell_name].sig_offset, Sim_Access_Read)
        #sig_break = SIM_breakpoint(cpu.physical_memory, Sim_Break_Physical, Sim_Access_Execute, phys_block.address, 1, 0)
        self.__hap_manager.breakLinear(cell_name, self.__kernel_info[cell_name].sig_offset, Sim_Access_Execute, self.sig_callback, 'sig_break')
        #sig_break = SIM_breakpoint(cell, Sim_Break_Linear, Sim_Access_Execute, self.__kernel_info[cell_name].sig_offset, 4, 0)
        #self.lgr.debug('doIinitCell sig_break break %d set at %x ' % (sig_break, self.__kernel_info[cell_name].sig_offset))
        #sig_hap = SIM_hap_add_callback_index("Core_Breakpoint_Memop", 
	#	self.sig_callback, cpu, sig_break)
        #self.__hap_manager.addBreak(cell_name, None, sig_break, None)
        #self.__hap_manager.addHap(cpu, cell_name, None, sig_hap, None)

        if self.__cell_config.os_type[cell_name] == osUtils.LINUX:
            #phys_block = cpu.iface.processor_info.logical_to_physical(self.__kernel_info[cell_name].sig_seccomp, Sim_Access_Read)
            #sig_break = SIM_breakpoint(cpu.physical_memory, Sim_Break_Physical, Sim_Access_Execute, phys_block.address, 1, 0)
            sig_break = SIM_breakpoint(cell, Sim_Break_Linear, Sim_Access_Execute, self.__kernel_info[cell_name].sig_seccomp, 4, 0)
            self.lgr.debug('doIinitCell sig_seccomp break %d set at %x' % (sig_break, self.__kernel_info[cell_name].sig_seccomp))
            sig_hap = SIM_hap_add_callback_index("Core_Breakpoint_Memop", 
    		self.sig_seccomp_callback, cpu, sig_break)
            self.__hap_manager.addBreak(cell_name, None, sig_break, None)
            self.__hap_manager.addHap(cpu, cell_name, None, sig_hap, None)

        self.__ret_exec_break[cell_name] = {}
        self.__ret_exec_hap[cell_name] = {}
        '''
        if self.__kernel_info[cell_name].sig_user is not None:
            sig_break = SIM_breakpoint(cell, Sim_Break_Linear, Sim_Access_Execute, self.__kernel_info[cell_name].sig_user, 1, 0)
            sig_hap = SIM_hap_add_callback_index("Core_Breakpoint_Memop", 
		self.sig2_callback, cpu, sig_break)
            self.__hap_manager.addBreak(cell_name, None, sig_break, None)
            self.__hap_manager.addHap(cpu, cell_name, None, sig_hap, None)
        '''
        #self.debugSysCalls(cpu)
        self.__errored_syscalls[cell_name] = 0

    '''
        A "server" is either the cb-server, launcher or the replay process.  In the case of local replays, there is only the 
        latter.
    '''
    def getServerPid(self, cell_name, cpu):
        kind = self.getKind(cell_name)
        server_pid = []
        if kind == 'network host':
            server_pid = self.__os_p_utils[cell_name].getPidByName(self.__master_config.server_name)
        elif kind == 'pov thrower':
            server_pid = self.__os_p_utils[cell_name].getPidByName(self.__master_config.replay_name)
        else:
            print 'unknown host type in cellConfig %s' % kind
        return server_pid

    def checkTaintProcessRunning(self, cpu, cell_name):
            if self.__master_config.taint_process is not None:
                pid_list = self.__os_p_utils[cell_name].getPidByName(self.__master_config.taint_process) 
                if len(pid_list) > 0:
                    pid = pid_list[0]
                    #print 'start taint'
                    ''' program we are to taint tracking is already running. '''
                    self.__watching[cell_name].append(pid)
                    task_addr = self.__os_p_utils[cell_name].getTaskAddrByPid(pid)
                    self.monitorForPid(cell_name, pid, self.__master_config.taint_process, cpu)
                    self.__taint_manager = taintManager.taintManager(self, self.__master_config, self.__context_manager, 
                        self.__hap_manager, self.__os_p_utils[cell_name], self.__param[cell_name], self.lgr)
                    self.lgr.debug('checkTaintProcessRunning created taintManager for %s:%d (%s)' % (cell_name, 
                                    pid, self.__master_config.taint_process))

    def getReplayFileName(self, pid, cell_name):
        if cell_name is None:
            return None
        seed = self.target_log.findSeed(pid, cell_name)
        try:
            return self.__replay_file_name[seed]
        except KeyError:
            self.lgr.debug('getReplayFileName, no seed for %s %d' % (cell_name, pid))
            return None

    def checkDebugProcessRunning(self, cpu, cell_name):
            if self.__master_config.debug_process is not None:
                pid_list = self.__os_p_utils[cell_name].getPidByName(self.__master_config.debug_process) 
                if len(pid_list) > 0:
                    pid = pid_list[0]
                    #print 'start debug'
                    ''' program we are to debug is already running. '''
                    seed = self.target_log.findSeed(pid, cell_name)
                    self.__watching[cell_name].append(pid)
                    task_addr = self.__os_p_utils[cell_name].getTaskAddrByPid(pid)
                    self.monitorForPid(cell_name, pid, self.__master_config.debug_process)
                    self.__call_log[cell_name][pid] = callLog.callLog(self, self.__os_p_utils[cell_name], 
                        self.__param[cell_name], pid, 
                        self.__master_config.debug_process, self.__replay_file_name[seed], self.__zk, self.lgr, self.cfg.logdir,
                        self.__kernel_info[cell_name].cgc_bytes_offset)
                    self.lgr.debug('checkDebugProcessRunning created call_log for %s:%d (%s)' % (cell_name, 
                                    pid, self.__master_config.debug_process))

    def checkTracedProcessRunning(self, cpu, cell_name):
            if self.__master_config.trace_target is not None:
                pid_list = self.__os_p_utils[cell_name].getPidByName(self.__master_config.trace_target) 
                if len(pid_list) > 0:
                    pid = pid_list[0]
                    #print 'start trace'
                    ''' program we are to trace is already running. '''
                    self.__tracing.startTrace(self.__master_config.trace_target, pid, cpu)
                    self.__watching[cell_name].append(pid)
                    seed = self.target_log.findSeed(pid, cell_name)
                    task_addr = self.__os_p_utils[cell_name].getTaskAddrByPid(pid)
                    self.monitorForPid(cell_name, pid, self.__master_config.trace_target, cpu)
                    self.__call_log[cell_name][pid] = callLog.callLog(self, self.__os_p_utils[cell_name], self.__param[cell_name], pid, 
                        self.__master_config.trace_target, self.__replay_file_name[seed], self.__zk, self.lgr, self.cfg.logdir,
                        self.__kernel_info[cell_name].cgc_bytes_offset)
                    self.lgr.debug('checkTracedProcessRunning created call_log for %s:%d (%s)' % (cell_name, 
                                    pid, self.__master_config.trace_target))

    '''
        Global initialization, also some more stuff that is per-cell
    '''
    def doInit(self):
        '''
        remove all previous breakpoints.  
        '''
        SIM_run_command("delete -all")
        for cell_name in self.__cell_config.os_type:
            self.__kernel_info[cell_name] = kernelInfo.kernelInfo(self.lgr, self.__cell_config.os_type[cell_name], self.__param[cell_name],
                self.cfg.system_map[cell_name], self.cfg.cgc_bytes) 

        self.__num_cb_binaries = 0
        self.__fd_set_size = self.fdSetSize()


        ''' Classes used to monitor different kinds of behavior '''
        self.__noX = noX.noX(self.PAGE_SIZE, self.__cell_config.cells, self.lgr)
        self.__hap_manager = hapManager.hapManager(self, self.__cell_config, 
                               self.lgr, self.always_watch_calls)
        ''' Instantiate an os_process_utils for each box (cell) '''
        for cell_name in self.__cell_config.os_type:
            if self.__cell_config.os_type[cell_name].startswith(osUtils.LINUX):
                self.__os_p_utils[cell_name] = linuxProcessUtils.linuxProcessUtils(self, cell_name, self.__param[cell_name], 
                    self.__cell_config, self.__master_config, self.__hap_manager, 
                    self.__kernel_info[cell_name].current_task, self.__mem_utils[cell_name], self.lgr, 
                    self.always_watch_calls)
                self.__watch_uid[cell_name] = watchLinuxCreds.watchLinuxCreds(self, cell_name, self.__param[cell_name], 
                    self.__cell_config, self.__os_p_utils[cell_name], self.lgr)
            elif self.__cell_config.os_type[cell_name].startswith(osUtils.FREE_BSD):
                self.__os_p_utils[cell_name] = bsdProcessUtils.bsdProcessUtils(self, cell_name, self.__param[cell_name], 
                    self.__cell_config, self.__master_config, self.__hap_manager, self.__watch_kernel, 
                    self.__mem_utils[cell_name], self.lgr)
                self.__watch_uid[cell_name] = watchUID.watchUID(self, cell_name, self.__param[cell_name], self.__cell_config, self.__os_p_utils[cell_name], self.lgr)
            else:
                print 'unknown os: %s' % self.__cell_config.os_type[cell_name]


        self.__context_manager = contextManager.contextManager(self, self.__cell_config, 
            self.__hap_manager, self.__master_config, self.__os_p_utils, self.__param[cell_name], self.__zk, 
            self.target_log, self.lgr)

        self.__tracing = tracing.tracing(self, self.__master_config, self.__os_p_utils, self.__zk, self.cfg, 
            self.lgr, self.cfg.logdir)
        self.__replay_file_name = {}
        self.__cb_file_name = {}
 
        if self.__master_config.code_coverage:
            self.__code_coverage = codeCoverage.codeCoverage(self.cfg, self.lgr)

        for cell_name in self.__cell_config.cells:
            self.lgr.debug('doInit loop for cell %s' % cell_name)
            cpu = self.__cell_config.cpuFromCell(cell_name)
 

            #exception_hap= SIM_hap_add_callback_obj_range("Core_Exception", cpu, 0,
            #'         self.exceptionCallback, cpu, 0, 13)
            #exception_hap= SIM_hap_add_callback_obj_range("Core_Exception", cpu, 0,
            #         self.exceptionCallback, cpu, 15, 256)
            #self.__mode_changed[cpu] = SIM_hap_add_callback_obj("Core_Mode_Change", cpu, 0,
            #        self.modeChanged, cpu)
            self.__syscall_entries[cell_name] = {}
            self.__unmapped_eips[cell_name] = {}
            self.__return_to_cycle[cell_name] = {}

            self.__last_ret_eip[cell_name] = {}
            self.__num_calls[cell_name] = {}
            self.__bytes_wrote[cell_name] = {}
            self.__bytes_read[cell_name] = {}
            self.__reg_frame[cell_name] = {}
            self.__pid_cycles[cell_name] = {}
            self.__pid_user_cycles[cell_name] = {}
            self.__pid_wallclock_start[cell_name] = {}
            self.__call_log[cell_name] = {}
            self.__prog_sections[cell_name] = {}
            self.__first_eip[cell_name] = {}

            self.__watch_non_code[cell_name] = []
            self.__pending_signals[cell_name] = []
            self.__did_track_setup[cell_name] = []
            self.__watching[cell_name] = []
            self.__x_pages[cell_name] = {}
            self.__sysenter_break[cell_name] = None
            self.__rop_pending[cell_name] = False
            if not self.NO_TRACK:
                load_command = '%s.software.load-parameters %s' % (cell_name, self.__os_params)
                SIM_run_command(load_command)
            #NOTE server_pid is a list
            server_list = self.getServerPid(cell_name, cpu)
            print 'len of server_list is %d' % len(server_list)
            self.__server_pid[cell_name] = list(server_list)
            if len(self.__server_pid[cell_name]) > 0:
                name = self.getServerName(cell_name)
    	        self.lgr.info('doInit for cell %s server %s, got %d server pids, first is %d' % \
                    (cell_name, name, len(self.__server_pid[cell_name]), 
                    self.__server_pid[cell_name][0]))

            self.__master_config.loadKSections(cell_name, self.lgr)
            self.doInitCell(cell_name)

            #self.watching_current_syscalls[cell_name] = False

            self.checkTracedProcessRunning(cpu, cell_name)
            self.checkDebugProcessRunning(cpu, cell_name)
            self.checkTaintProcessRunning(cpu, cell_name)


        ''' additional classes that need the classes instatiated above '''

        ''' unexpected execution regions '''
        unx_regions = {}        
        for cell_name in self.__cell_config.os_type:
            unx_regions[cell_name] = bsdUnexpected.bsdUnexpected(self.cfg.system_map[cell_name], self.__cell_config.os_type[cell_name], self.lgr).getRegions()

        self.__watch_kernel = watchKernel.watchKernel(self, self.__param, self.__cell_config, 
            self.__master_config, self.__hap_manager, self.__os_p_utils, 
            self.__kernel_info, self.PAGE_SIZE, unx_regions, self.__cr3, self.__cr4, self.lgr)
            #self.__kernel_info[cell_name].default_se_exit, self.PAGE_SIZE, unx_regions, self.__cr3, self.__cr4, self.lgr)

        for cell_name in self.__cell_config.os_type:
            self.__os_p_utils[cell_name].setKernelWatch(self.__watch_kernel)

        self.__non_code = notCode.notCode(self, self.__param, 
            self.__master_config, self.__hap_manager, self.__context_manager, 
            self.__os_p_utils, self.__master_config.stack_size, self.__master_config.ps_strings,  
            self.PAGE_SIZE, self.lgr) 

        self.__rop_cop = ropCop.ropCop(self, self.__cell_config, 
            self.__param, self.__master_config, self.__hap_manager, self.__context_manager, self.__noX, 
            self.__os_p_utils, self.PAGE_SIZE, self.lgr) 

        self.__keep_alive = keepAlive.keepAlive(self, self.cfg, self.lgr)

        self.__other_faults = otherFaults.otherFaults(self, self.__master_config, self.__cell_config, self.__os_p_utils, self.lgr)

        self.__protected_memory = protectedMemory.protectedMemory(self, self.__cell_config.cells,
            self.__param, self.__master_config.stop_on_memory, self.__hap_manager, 
            self.__context_manager, self.__os_p_utils, self.PAGE_SIZE, 
            self.__negotiate, self.__other_faults, self.lgr, track_access=self.__master_config.server_protected_memory)
        self.lgr.debug('track_protected_access is %r' % self.__master_config.track_protected_access)
        self.lgr.debug('server_protected_memory is %r' % self.__master_config.server_protected_memory)

        self.__page_faults = pageFaults.pageFaults(self, self.__master_config, self.__cell_config,  
            self.__context_manager, self.__protected_memory, self.__noX, self.__non_code, self.__os_p_utils, self.__param, 
            True, self.lgr)   

        # reverseToCall gets its own log
        instance = INSTANCE
        if instance is None:
            instance = 'x'
        my_name = 'reverseToCall_'+instance
        log_dir = os.path.join(self.cfg.logdir, 'monitors')
        self.__bookmarks = bookmarkMgr.bookmarkMgr(self, self.__context_manager, self.lgr)
        self.__rev_to_call = reverseToCall.reverseToCall(self, self.__param, self.__os_p_utils, 
                 self.PAGE_SIZE, self.__context_manager, my_name, self.is_monitor_running, self.__bookmarks, log_dir)


        self.getPlayerOffset()
        self.zkStatusAndReset()

    def zkStatusAndReset(self):
        ''' note to zookeeper that this monitor slave is up, recording the checksum of of the configuration 
            file that we'll work off of.  Set watch to re-init if the node is deleted.
        '''
        current_time = time.time()
        self.__zk.deleteOurReset()
        self.recordOurReset(str(current_time))
        ''' and the node watched by targetWatcher to determine if monitor is dead '''
        self.__zk.deleteOurStatus()
        if not self.__zk.recordOurStatus(str(current_time), True):
            self.lgr.error('fatal error from recordOurStatus')
            exit(1)
        self.lgr.debug('recorded our status to zk node, config checksum is %s' % self.__master_config.checksum)

    def recordOurReset(self, timestamp):
        self.lgr.debug('recordOurReset called')
        record = self.__master_config.checksum+' '+timestamp
        if not self.__zk.recordOurReset(record, True, self.reInitAlone, self.lgr):
            self.lgr.error('fatal error from recordOurReset')
            exit(1)
        self.lgr.debug('recorded our reset to zk node, config checksum is %s, timestr is %s' % (self.__master_config.checksum, timestamp))

    def exceptionCallback(self, cpu, one, exception_number):
        cell_name = self.getTopComponentName(cpu)
        dumcpu, cur_addr, comm, pid = self.__os_p_utils[cell_name].getPinfo(cpu)
        self.lgr.debug('exception %d from %d (%s)' % (exception_number, pid, comm))
   

    def modeChanged(self, pinfo, one, old, new):
        if new == Sim_CPU_Mode_Supervisor:
            cell_name = self.getTopComponentName(pinfo.cpu)
            dumcpu, cur_addr, comm, pid = self.__os_p_utils[cell_name].getPinfo(cpu)
            if pid == pinfo.pid:
                eip = self.getEIP(pinfo.cpu)
                cell_name = self.getTopComponentName(pinfo.cpu)
                self.lgr.debug('mode change exec is %s:%d (%s) eip  %x' % (cell_name,
                    pid, comm, eip))
                #mftHap.mftHap('si', pinfo.cpu, self.lgr)
        pass


    '''
        Determine if we should track memory and syscalls for this process
    '''
    def watchProcess(self, cell_name, cpu, cur_addr, comm, pid):
        if len(self.__server_pid[cell_name]) is 0:
           # no server yet running on this cell, nothing to watch
           #self.lgr.debug('no server yet, could not be parent of %s on %s' % (comm, cell_name))
           return False
        decended = self.__os_p_utils[cell_name].isDecended(self.__server_pid[cell_name], cur_addr, comm, pid)
        #self.lgr.debug('is %d (%s) on %s a child of %d (%s), os says: %r' % (pid, 
        #     comm, cell_name, self.__server_pid[cell_name][0], server_name, decended))
        if decended:
                if pid not in self.__server_pid[cell_name]:
                    return True
                else:
                    return False
        else:
            return False
   
    def watchRop(self, cell_name, comm, pid):
        '''
        Only watch Rop when requested, and then if the player, only if it is a PoV
        '''
        retval = False
        if self.isPlayer(comm): 
            if self.isPoV(pid, cell_name): 
                if self.__master_config.watchRop(cell_name, comm):
                    retval = True
        elif self.__master_config.watchRop(cell_name, comm):
            retval = True
        return retval

    '''
        Set memory access Haps, intended to be called when a process is about to first return to
        user mode after an exec.
    '''
    def cbMemory(self, comm, cell_name, pid):
        #print 'in cbMemory'
        self.lgr.debug('in cbMemory for %s:%d (%s)' % (cell_name, pid, comm))
        self.__watch_non_code[cell_name].append(pid)
        #self.__prog_sections[cell_name][pid] = ConfigParser.ConfigParser()
        self.__prog_sections[cell_name][pid] = programSections.programSections()
        seed = self.target_log.findSeed(pid, cell_name)
        cb_name = self.target_log.findCBName(seed)
        cb_config = self.__zk.getCBConfig(comm, cb_name) 
        if cb_config is not None:    
            #self.lgr.debug('cfg for %s is \n%s' % (comm, cb_config))
            self.__prog_sections[cell_name][pid].load(cb_config)
        else:
            self.lgr.error('No config file for comm %s cbname %s' % (comm, cb_name))
            print('!!!!  No config file for %s, will not monitor !!!!!!' % comm)
            return
        ps = self.__prog_sections[cell_name][pid]

        for text in ps.text_sections:
             self.lgr.debug('%s text start: %x  end: %x' % (comm, text[0], text[1]))
        for data in ps.data_sections:
             self.lgr.debug('%s data start: %x  end: %x' % (comm, data[0], data[1]))
        if len(ps.text_sections) > 0 and len(ps.data_sections) > 0:
            # only for linux text/data mapped to same physical page
            self.__hap_manager.setTextStart(cell_name, pid, 
                pageUtils.pageStart((ps.text_sections[0][0]+ps.text_sections[0][1]), self.PAGE_SIZE))

            self.__hap_manager.setDataEnd(cell_name, pid, 
                 pageUtils.pageStart(ps.data_sections[0][0], self.PAGE_SIZE))

        if self.__master_config.watchNoX(cell_name, comm):
            for section in ps.data_sections:            
                self.__noX.add(cell_name, pid, section[0], section[1])
            start = self.__master_config.ps_strings - self.__master_config.stack_size
            self.__noX.add(cell_name, pid, start, self.__master_config.stack_size)


        cpu = self.__cell_config.cpuFromCell(cell_name)
        cell = cpu.physical_memory
        if self.__master_config.watchNoX(cell_name, comm):
            for section in ps.data_sections:
                # TBD top page of text and bottom of data share a page? eh?
                end = section[0] + section[1]
                self.lgr.debug('adding nocode breakpoints for data %x through %x' % (section[0], end))
                self.__non_code.nonCodeBreakRange(cell_name, pid, cpu, section[0], section[1], True)
            start = self.__master_config.ps_strings - self.__master_config.stack_size
            self.lgr.debug('adding nocode breakpoints for stack %x of size %x' % (start, 
                  self.__master_config.stack_size))
            self.__non_code.nonCodeBreakRange(cell_name, pid, cpu, start, self.__master_config.stack_size, True)

        if self.watchRop(cell_name, comm, pid):
            for section in reversed(ps.text_sections):
                self.lgr.debug('set ropCopBreakRange for cgc binary text from loader.  pid: %s:%d  start address: %x' %\
                    (cell_name, pid, section[0]))
                self.__rop_cop.ropCopBreakRange(cell_name, pid, section[0], section[1], cpu, comm, from_loader=True)

        if self.isCB(comm) and self.__master_config.code_coverage:
            self.lgr.debug('setting code coverage breaks for %s' % comm)
            self.__code_coverage.setBreaks(comm, cpu, comm)

        if self.cfg.protected_start is None:
            ''' no memory haps to do, we are done '''
            #print 'no memory haps to do, done'
            self.lgr.info('%s %d (%s) no memory haps to do, done' % (cell_name, pid, comm))
        elif self.cfg.protected_length is None:
            print 'missing protected_length value from config file for %s?' % comm
            self.lgr.error('missing protected_length value from config file for %s?' % comm)
	    SIM_break_simulation("stopping error in config file")
        elif self.__master_config.protectedMemory(cell_name, comm): 
            #self.__protected[pid] = protectedInfo.protectedInfo(start, length, self.PAGE_SIZE)
            end = self.cfg.protected_start + self.cfg.protected_length
            self.lgr.debug('do protected break range between %x and %x' % (self.cfg.protected_start, end))
            self.__protected_memory.protectedBreakRange(self.cfg.protected_start, end, cpu, cell_name, pid, comm)

        if self.__master_config.stopOnSomething(): 
            if pid not in self.__x_pages[cell_name]:
                self.__x_pages[cell_name][pid] = []
            for section in ps.text_sections:
                self.lgr.debug('cgcMonitor cbMemory add to x_pages %s %d (%s) addr: %x  len: %x' % (cell_name, pid, comm, 
                    section[0], section[1]))
                self.__x_pages[cell_name][pid].append(self.addressAndLength(section[0], section[1]))
    '''
        Set memory access Haps, intended to be called when a process is about to first return to
        user mode after an exec.
    '''
    def elfMemory(self, comm, cell_name, pid):
        #print 'in elfMemory'
        self.lgr.debug('in elfMemory for %s:%d (%s)' % (cell_name, pid, comm))
        self.__watch_non_code[cell_name].append(pid)
        self.__prog_sections[cell_name][pid] = ConfigParser.ConfigParser()
        if self.isCB(comm):
            # get the program sections from a zk node
            cb_config = self.__zk.getCBConfig(comm) 
            if cb_config is not None:    
                #self.lgr.debug('cfg for %s is \n%s' % (comm, cb_config))
                cb_file = StringIO.StringIO(cb_config)
                self.__prog_sections[cell_name][pid].readfp(cb_file)
            else:
                self.lgr.debug('No config file for %s' % comm)
        else:
            cb_file = os.path.join(self.cfg.maps_dir, '%s.cfg' % comm)
            if not os.path.exists(cb_file):
                print('no .cfg file for %s at %s' % (comm, cb_file))
                self.lgr.info('no .cfg file for %s at %s' % (comm, cb_file))
                return False
            # TBD HACK note prog_sections is a configParser when not a CB
            self.__prog_sections[cell_name][pid].read(cb_file)
            self.lgr.debug('elfMemory, got config file: %s ' % cb_file)
        elf_data = None
        elf_data_size = 0
        try:

            elf_text = int(self.__prog_sections[cell_name][pid].get("elf", "text"), 16)
            elf_text_size = int(self.__prog_sections[cell_name][pid].get("elf", "text_size"), 16)
            # only for linux text/data mapped to same physical page
            self.__hap_manager.setTextStart(cell_name, pid, 
                pageUtils.pageStart((elf_text+elf_text_size), self.PAGE_SIZE))
        except ConfigParser.NoSectionError:
            print 'error reading elf values from config file %s.cfg' % comm 
            self.lgr.info('error reading elf values from config file for %s' % comm)
	    #SIM_break_simulation("stopping error reading config file") 
            return False
        except ConfigParser.ParsingError:
            self.lgr.info('parsing error reading elf values from config file for %s' % comm)
            pass
        try:
            elf_data = int(self.__prog_sections[cell_name][pid].get("elf", "data"), 16)
            elf_data_size = int(self.__prog_sections[cell_name][pid].get("elf", "data_size"), 16)
            # only for linux text/data mapped to same physical page
            self.__hap_manager.setDataEnd(cell_name, pid, 
                 pageUtils.pageStart(elf_data, self.PAGE_SIZE))
        except ConfigParser.NoOptionError:
            pass

        elf_bss_size = 0
        try:
            elf_bss_size = int(self.__prog_sections[cell_name][pid].get("elf", "bss_size"), 16)
        except: pass

        # TBD top page of text and bottom of data share a page? 
        if self.__master_config.watchNoX(cell_name, comm):
            if True or self.__cell_config.os_type[cell_name] != osUtils.LINUX:
                if elf_data is not None:
                    self.__noX.add(cell_name, pid, elf_data, elf_data_size + elf_bss_size)
            start = self.__master_config.ps_strings - self.__master_config.stack_size
            self.__noX.add(cell_name, pid, start, self.__master_config.stack_size)

        cpu = self.__cell_config.cpuFromCell(cell_name)
        cell = cpu.physical_memory
        if self.__master_config.watchNoX(cell_name, comm):
            if True or self.__cell_config.os_type[cell_name] != osUtils.LINUX:
                if elf_data is not None:
                    # TBD top page of text and bottom of data share a page? eh?
                    end = elf_data + elf_data_size
                    self.lgr.debug('adding nocode breakpoints for data %x through %x' % (elf_data, end))
                    self.__non_code.nonCodeBreakRange(cell_name, pid, cpu, elf_data, 
                        elf_data_size + elf_bss_size, True)
            start = self.__master_config.ps_strings - self.__master_config.stack_size
            self.lgr.debug('adding nocode breakpoints for stack %x of size %x' % (start, 
                  self.__master_config.stack_size))
            self.__non_code.nonCodeBreakRange(cell_name, pid, cpu, start, self.__master_config.stack_size, True)

        if self.watchRop(cell_name, comm, pid):
            self.lgr.debug('set ropCopBreakRange for elf text.  pid: %s:%d  start address: %x' %\
                (cell_name, pid, elf_text))
            self.__rop_cop.ropCopBreakRange(cell_name, pid, elf_text, elf_text_size, cpu, comm, from_loader=True)

        if self.__master_config.stopOnSomething(): 
            self.lgr.debug('cgcMonitor elfMemory add to x_pages %d (%s) addr: %x  len: %x' % (pid, comm, elf_text, 
                    elf_text_size))
            if pid not in self.__x_pages[cell_name]:
                self.__x_pages[cell_name][pid] = []
            self.__x_pages[cell_name][pid].append(self.addressAndLength(elf_text, elf_text_size))


    # TBD this looks grim; more efficient translation to hex characters?
    def getBytesPhys(self, cpu, num_bytes, addr):
        '''
        Get a hex string of num_bytes from the given address
        '''
        done = False
        curr_addr = addr
        bytes_to_go = num_bytes
        retval = ''
        #print 'in getBytes for 0x%x bytes' % (num_bytes)
        while not done and bytes_to_go > 0:
            bytes_to_read = bytes_to_go
            if bytes_to_read > 1024:
                bytes_to_read = 1024
            #print 'read (bytes_to_read) 0x%x bytes from 0x%x phys:%x ' % (bytes_to_read, curr_addr, phys_block.address)
            try:
                read_data = memUtils.readPhysBytes(cpu, addr, bytes_to_read)
            except:
                print 'trouble reading phys bytes, address %x, num bytes %d end would be %x' % (addr, bytes_to_read, addr + bytes_to_read - 1)
                print 'bytes_to_go %x  bytes_to_read %d' % (bytes_to_go, bytes_to_read)
                self.lgr.error('bytes_to_go %x  bytes_to_read %d' % (bytes_to_go, bytes_to_read))
                SIM_break_simulation('error in getBytes')
                return retval
            holder = ''
            count = 0
            for v in read_data:
                count += 1
                holder = '%s%02x' % (holder, v)
                #self.lgr.debug('add v of %2x holder now %s' % (v, holder))
            del read_data
            retval = '%s%s' % (retval, holder)
            bytes_to_go = bytes_to_go - bytes_to_read
            #self.lgr.debug('0x%x bytes of data read from %x bytes_to_go is %d' % (count, curr_addr, bytes_to_go))
            curr_addr = curr_addr + bytes_to_read
        return retval

    # TBD this looks grim; more efficient translation to hex characters?
    def getBytes(self, cpu, num_bytes, addr):
        '''
        Get a hex string of num_bytes from the given address
        '''
        done = False
        curr_addr = addr
        bytes_to_go = num_bytes
        retval = ''
        #print 'in getBytes for 0x%x bytes' % (num_bytes)
        while not done and bytes_to_go > 0:
            bytes_to_read = bytes_to_go
            remain_in_page = pageUtils.pageLen(curr_addr, self.PAGE_SIZE)
            #print 'remain is 0x%x  bytes to go is 0x%x  cur_addr is 0x%x end of page would be 0x%x' % (remain_in_page, bytes_to_read, curr_addr, end)
            if remain_in_page < bytes_to_read:
                bytes_to_read = remain_in_page
            if bytes_to_read > 1024:
                bytes_to_read = 1024
            phys_block = cpu.iface.processor_info.logical_to_physical(curr_addr, Sim_Access_Read)
            #print 'read (bytes_to_read) 0x%x bytes from 0x%x phys:%x ' % (bytes_to_read, curr_addr, phys_block.address)
            try:
                read_data = memUtils.readPhysBytes(cpu, phys_block.address, bytes_to_read)
            except:
                print 'trouble reading phys bytes, address %x, num bytes %d end would be %x' % (phys_block.address, bytes_to_read, phys_block.address + bytes_to_read - 1)
                print 'bytes_to_go %x  bytes_to_read %d' % (bytes_to_go, bytes_to_read)
                self.lgr.error('bytes_to_go %x  bytes_to_read %d' % (bytes_to_go, bytes_to_read))
                SIM_break_simulation('error in getBytes')
                return retval
            holder = ''
            count = 0
            for v in read_data:
                count += 1
                holder = '%s%02x' % (holder, v)
                #self.lgr.debug('add v of %2x holder now %s' % (v, holder))
            del read_data
            retval = '%s%s' % (retval, holder)
            bytes_to_go = bytes_to_go - bytes_to_read
            #self.lgr.debug('0x%x bytes of data read from %x bytes_to_go is %d' % (count, curr_addr, bytes_to_go))
            curr_addr = curr_addr + bytes_to_read
        return retval

    def cleanupAllAlone(self, dum=None):
        '''
        '''
        for cell_name in self.__cell_config.cells:
            self.lgr.debug('cleanupAllAlone for cell_name %s' % cell_name)
            
            cpu = self.__cell_config.cpuFromCell(cell_name)
            self.__watch_kernel.clearCalls(cpu)
            #self.__os_p_utils.processExiting()
            for pid in self.__watching[cell_name]:
                comm = self.__os_p_utils[cell_name].getCommByPid(pid)
                self.lgr.debug('cleanupAllAlone for pid %d  %s' % (pid, comm))
                cp = self.cellpid(cell_name, pid, comm)
                self.cleanupPidAlone(cp)
                #self.cleanupPid(cell_name, pid, comm)
                seed = self.target_log.findSeed(pid, cell_name)
                if seed in self.__pid_structs_to_clean:
                    self.__pid_structs_to_clean[seed].append(procInfo.procInfo(comm, cpu, pid))
                else:
                    print('cleanupAllAlone, missing seed %s from pid_structs_to_clean' % seed)
                
            self.__watching[cell_name] = []
        self.__hap_manager.removeKernelBreaks(True)
        self.__page_faults.cleanAll()
        for cell_name in self.__cell_config.os_type:
            self.__os_p_utils[cell_name].cleanAll() 
            #self.lgr.debug('os_p_utils %s size: 0x%x' % (cell_name, asizeof.asizeof(self.__os_p_utils[cell_name])))
        #self.lgr.debug('watchKernel size: 0x%x' % (asizeof.asizeof(self.__watch_kernel)))
        #self.lgr.debug('hapManager size: 0x%x' % (asizeof.asizeof(self.__hap_manager)))
        #self.lgr.debug('cgcMonitor size: 0x%x' % (asizeof.asizeof(self)))
        self.__other_faults.cleanAll()
        self.debug_syscall_break = {}
        self.debug_syscall_hap = {}
        if self.hack_break is not None:
            SIM_delete_breakpoint(self.hack_break)
            SIM_hap_delete_callback_id("Core_Breakpoint_Memop", self.hack_hap)
            self.hack_break = None
            self.hack_hap = None



    def cleanupAll(self):
        self.lgr.debug('cleanupAll')
        SIM_run_alone(self.cleanupAllAlone, None)

    class cellpid():
        def __init__(self, cell_name, pid, comm):
            self.cell_name = cell_name
            self.pid = pid
            self.comm = comm

    def cleanupPid(self, cell_name, pid, comm):
        cp = self.cellpid(cell_name, pid, comm)
        SIM_run_alone(self.cleanupPidAlone, cp)

    def cleanWaitingPidContexts(self, pid, cell_name):
        seed = self.target_log.findSeed(pid, cell_name)
        if seed not in self.__pid_contexts_to_clean:
            return
        self.lgr.debug('cleanWaitingPidContexts for %d processes' % len(self.__pid_contexts_to_clean[seed]))
        for item in self.__pid_contexts_to_clean[seed]:
            cell_name = self.getTopComponentName(item.cpu)
            self.__context_manager.cleanPID(cell_name, item.pid)
        self.__pid_contexts_to_clean.pop(seed)

    def cleanWaitingPidStructs(self, pid, cell_name):
        seed = self.target_log.findSeed(pid, cell_name)
        seed = self.target_log.findSeed(pid, cell_name)
        if seed not in self.__pid_structs_to_clean:
            return
        self.lgr.debug('cleanWaitingPidStructs for %d processes' % len(self.__pid_structs_to_clean[seed]))
        for item in self.__pid_structs_to_clean[seed]:
            cell_name = self.getTopComponentName(item.cpu)
            self.cleanPidStructs(cell_name, item.pid)
        self.__pid_structs_to_clean.pop(seed)

    def cleanPidStructs(self, cell_name, pid):
        self.lgr.debug('cleanPidStructs for %d' % pid)
        if pid in self.__syscall_entries[cell_name]:
            del self.__syscall_entries[cell_name][pid]
        if pid in self.__did_track_setup[cell_name]:
            self.__did_track_setup[cell_name].remove(pid)
        if pid in self.__pending_signals[cell_name]:
            self.__pending_signals[cell_name].remove(pid)
        if pid in self.__watch_non_code[cell_name]:
            self.__watch_non_code[cell_name].remove(pid)
        if pid in self.__prog_sections[cell_name]:
            del self.__prog_sections[cell_name][pid]
        #if pid in self.__protected:
        #   del(self.__protected[pid])
        if pid in self.__unmapped_eips[cell_name]:
            del(self.__unmapped_eips[cell_name][pid])
        if pid in self.__num_calls[cell_name]:
            del(self.__num_calls[cell_name][pid])
        if pid in self.__bytes_wrote[cell_name]:
            del(self.__bytes_wrote[cell_name][pid])
        if pid in self.__bytes_read[cell_name]:
            del(self.__bytes_read[cell_name][pid])
        if pid in self.__first_eip[cell_name]:
            del(self.__first_eip[cell_name][pid])
        if pid in self.__call_log[cell_name]:
            self.lgr.debug('closed call_log for %s:%d' % (cell_name, pid))
            self.__call_log[cell_name][pid].doneCallLog()
            del(self.__call_log[cell_name][pid])
        self.__rop_cop.clear(cell_name, pid)
        self.__noX.clear(cell_name, pid)
        self.__protected_memory.clear(cell_name, pid)

        if pid in self.__watching[cell_name]:
            self.cleanupPid(cell_name, pid, 'do not know')
            self.__watching[cell_name].remove(pid)
        cpu = self.__cell_config.cpuFromCell(cell_name)
        if pid in self.__pid_cycles[cell_name]:
            del self.__pid_cycles[cell_name][pid]
        if pid in self.__pid_user_cycles[cell_name]:
            del self.__pid_user_cycles[cell_name][pid]
        if pid in self.__pid_wallclock_start[cell_name]:
            del self.__pid_wallclock_start[cell_name][pid]

        if pid in self.__return_to_cycle[cell_name]:
            del self.__return_to_cycle[cell_name][pid]
        if pid in self.__x_pages[cell_name]:
            del self.__x_pages[cell_name][pid]
        if pid in self.__ret_exec_break[cell_name]:
            del self.__ret_exec_break[cell_name][pid]
        if pid in self.__ret_exec_hap[cell_name]:
            del self.__ret_exec_hap[cell_name][pid]

    def cleanupPidAlone(self, cp):
        cell_name = cp.cell_name
        pid = cp.pid
        self.lgr.debug('cleanupPidAlone, do clean pid for %d' % pid)
        if type(cp.comm) == str:
            if self.isPlayer(cp.comm):
                self.__player_monitor = False
                if self.__player_hap is not None: 
                    self.lgr.debug('cleanupPidAlone for %d' % pid)
                    SIM_delete_breakpoint(self.__player_break)
                    SIM_hap_delete_callback_id("Core_Breakpoint_Memop", self.__player_hap)
                    self.__player_hap = None
                    self.__player_break = None
            elif self.isCB(cp.comm):
                if self.__code_coverage is not None:
                    self.__code_coverage.reset()
        self.__hap_manager.clear(cell_name, pid)
        cpu = self.__cell_config.cpuFromCell(cell_name)
        self.__page_faults.cleanPid(cell_name, cpu, pid)
        self.__watch_uid[cell_name].cleanPid(pid)

    '''  NOT USED AT THE MOMENT, syscall_call and sysentry goes to sys_callback '''
    def sysentry_callback(self, cell_name, third, forth, fifth):
        #cell_name = self.getTopComponentName(cpu)
        cpu = SIM_current_processor()
        dumcpu, cur_addr, comm, pid = self.__os_p_utils[utils].getPinfo(cpu)
        frame = self.__os_p_utils[cell_name].frameFromRegs(cpu)
        if comm == 'replay_master' and frame['eax'] == self.__os_p_utils[cell_name].EXEC_SYS_CALL:
            self.lgr.debug('sysentry_callback %d (%s) frame: %s' % (pid, comm, self.__os_p_utils[cell_name].stringFromFrame(frame)))
            #SIM_break_simulation('debug exec syscall')
        if comm == 'player':
            eax = self.__os_p_utils[cell_name].mem_utils.getRegValue(cpu, 'eax')
            if pid in self.__watching[cell_name]:
                   self.lgr.debug('sysentry_callback player %d eax is %x frame %s' % (pid, eax, self.__os_p_utils[cell_name].stringFromFrame(frame)))
            else:
                   self.lgr.debug('NOT WATCH sysentry_callback player %d eax is %x frame %s' % (pid, eax, self.__os_p_utils[cell_name].stringFromFrame(frame)))

    '''
        Handle log updates for a watched process that is about to die
        Return true if this closes out the session.
    '''
    def updateLogs(self, comm, pid, cell_name, cpu, debug_event=False, do_done_item=False, force=False):
        retval = False
        self.__watch_kernel.getRetAddrs()
        self.lgr.debug('updateLogs for %s:%d (%s)' % (cell_name, pid, comm))
        prefix = 'cb'
        if self.isPlayer(comm):
            prefix = 'replay'
            # for long player xml validation watched by rop cop
            if not self.isPoVcb(comm):
                self.__keep_alive.cancelEvent()

        if self.__code_coverage is not None and self.isCB(comm):
            num_blocks, untouched_blocks = self.__code_coverage.getResults(comm)
            if num_blocks is not None:
                self.target_log.appendLog('untouched_blocks', '%d' % untouched_blocks, comm, pid, cell_name)
                touched_blocks = self.__code_coverage.getBitArrayTouched(comm)
                self.target_log.appendLog('touched_blocks', '%s' % touched_blocks, comm, pid, cell_name)
                self.lgr.debug('updateLogs code coverge for %s failed to hit %d of %d touched: %s' % (comm, 
                    untouched_blocks, num_blocks, touched_blocks))
            else:
                self.lgr.error('updateLogs failed to get code coverage info for %s' % comm)

        if pid in self.__num_calls[cell_name]:
            self.target_log.appendLog(prefix+'_sys_calls', '%d' % self.__num_calls[cell_name][pid], comm, pid, cell_name)
            self.lgr.debug('updateLogs got %d calls for  %s:%d (%s)' % (self.__num_calls[cell_name][pid], 
                cell_name, pid, comm))
        if pid in self.__bytes_wrote[cell_name]:
            self.target_log.appendLog(prefix+'_bytes_wrote', '%d' % self.__bytes_wrote[cell_name][pid], comm, pid, cell_name)
            self.lgr.debug('updateLogs got %d bytes_wrote for  %s:%d (%s)' % (self.__bytes_wrote[cell_name][pid], 
                cell_name, pid, comm))
        if pid in self.__bytes_read[cell_name]:
            self.target_log.appendLog(prefix+'_bytes_read', '%d' % self.__bytes_read[cell_name][pid], comm, pid, cell_name)
            self.lgr.debug('updateLogs got %d bytes_read for  %s:%d (%s)' % (self.__bytes_read[cell_name][pid], 
                cell_name, pid, comm))
        else:
            self.lgr.debug('updateLogs NO SYSCALLS FOR %s:%d (%s)' % (cell_name, pid, comm))

        if pid in self.__pid_cycles[cell_name]:
            cycles = self.__pid_cycles[cell_name][pid]
            self.target_log.appendLog(prefix+'_cycles', '%d' % cycles, comm, pid, cell_name)
        else:
            self.lgr.debug('updateLogs NO CYCLES FOR %s:%d (%s)' % (cell_name, pid, comm))

        if pid in self.__pid_user_cycles[cell_name]:
            self.lgr.debug('updateLogs got %d user_cycles for %s:%d (%s)' % (self.__pid_user_cycles[cell_name][pid], cell_name, pid, comm))
            cycles = self.__pid_user_cycles[cell_name][pid]
            self.target_log.appendLog(prefix+'_user_cycles', '%d' % cycles, comm, pid, cell_name)
        else:
            self.lgr.debug('updateLogs NO USER CYCLES FOR %s:%d (%s)' % (cell_name, pid, comm))

        fault_count = self.__page_faults.getFaultCount(cell_name, pid)
        if fault_count is not None:
            self.target_log.appendLog(prefix+'_faults', '%d' % fault_count, comm, pid, cell_name)
        else:
            self.lgr.debug('updateLogs NO PAGE FAULTS FOR %s:%d (%s)' % (cell_name, pid, comm))

        if pid in self.__pid_wallclock_start[cell_name]:
            wallclock_duration = self.getWallSeconds(cpu) - self.__pid_wallclock_start[cell_name][pid]
            self.target_log.appendLog(prefix+'_wallclock_duration', '%.2f' % wallclock_duration,
                comm, pid, cell_name)
        #if not self.isPoller(comm) and (self.__cell_config.os_type[cell_name] == osUtils.LINUX or do_done_item):
        self.lgr.debug('updateLogs, is poller? %r' % self.isPoller(comm))
        if not self.isPoller(comm) or do_done_item:
            # do the player's "doneItem" in doExitCallback since player may have died before all CBs were created
            # on bsd, closed out in doExitCallback
            if pid in self.__watching[cell_name]:
                self.cleanupPid(cell_name, pid, comm)
                self.__watching[cell_name].remove(pid)
                self.lgr.debug('updateLogs, check doneItem %s %d %s' % (cell_name, pid, comm))
                if self.target_log.doneItem(self.__master_config.stopOnSomething(), debug_event, self.isPlayer(comm), cell_name, pid, comm, 
                       force=force):
                    retval = True
                    if not debug_event:
                        if self.__master_config.auto_analysis:
                            self.lgr.debug('back from targetLog done item, no event in auto analysis, break simulation')
                            throw_id = self.__recent_throw_id
                            #print('AutoAnalysis No Event throw_id:%s' % throw_id)
                            msg = 'AutoAnalysis No Event throw_id:%s\n' % throw_id
                            #SIM_break_simulation(msg)
                            SIM_run_alone(SIM_break_simulation, msg)
                            self.__zk.deleteOurStatus()
                            self.__zk.setLatestLocalPackageDone(self.lgr)
                            SIM_break_simulation(msg)
                            status = SIM_simics_is_running()
                            self.lgr.debug('simulation should be stopped? is it running? %r' % status)
                            self.autoAnalysisNoEvent()
                        else:
                            self.lgr.debug('updateLogs for %s:%d (%s), done all items, close out process' % (cell_name, pid, comm))
                            self.closeOutProcess(pid, cell_name)
                    else:
                        self.lgr.debug('updateLogs for %s:%d (%s), is a debug event' % (cell_name, pid, comm))
            else:
                self.lgr.debug('updateLogs, not watching %s:%d (%s)' % (cell_name, pid, comm))
               
        return retval 

    def closeOutProcess(self, pid, cell_name):
        '''
        intended to be called when the suite of watched processes have exited.
        '''
        seed = self.target_log.findSeed(pid, cell_name)
        self.__tracing.closeTrace(pid, cell_name)
        if seed in self.__replay_file_name:
           self.__replay_file_name.pop(seed)
        if seed in self.__cb_file_name:
            self.__cb_file_name.pop(seed)
        self.cleanWaitingPidStructs(pid, cell_name)
        self.cleanWaitingPidContexts(pid, cell_name)
        self.__other_faults.newCB()
        num_items = gc.collect()
        self.lgr.debug('closeOutProcess gc got %d items' % num_items)
        for pid in self.__ids_pid:
            if pid in self.__watching[self.__ids_cell_name]:
                self.cleanupPid(cell_name, pid, 'ids-com')
                self.__watching[self.__ids_cell_name].remove(pid)
        self.__ids_pid = []
        self.__keep_alive.cancelEvent()

        for cell_name in self.__cell_config.cells:
            self.__syscall_entries[cell_name] = {}
        self.__negotiate.clearValues(seed)

    def debugSysCalls(self, cpu):
        self.lgr.debug('debug_sys_calls')
        pcell = cpu.physical_memory
        phys_block = cpu.iface.processor_info.logical_to_physical(self.__kernel_info[cell_name].syscall_offset, Sim_Access_Read)
        self.debug_syscall_break[cpu] = SIM_breakpoint(pcell, Sim_Break_Physical, Sim_Access_Execute, 
                phys_block.address, 1, 0)
        #syscall_break = SIM_breakpoint(cell, Sim_Break_Linear, Sim_Access_Execute, 
        #    address, 1, 0)
        self.debug_syscall_hap[cpu] = SIM_hap_add_callback_index("Core_Breakpoint_Memop", 
	    self.debug_sys_callback, cpu, self.debug_syscall_break[cpu])
    '''
    debug Report a syscall
    '''
    def debug_sys_callback(self, cpu, third, breakpoint, fifth):
        cell_name = self.getTopComponentName(cpu)
        dumcpu, cur_addr, comm, pid = self.__os_p_utils[cell_name].getPinfo(cpu)
        if self.__cell_config.os_type[cell_name] != osUtils.LINUX:
            frame = self.__os_p_utils[cell_name].frameFromStack(cpu)
            eax = frame['eax']
            ebx = frame['ebx']
        else:
            eax = self.__os_p_utils[cell_name].mem_utils.getRegValue('eax')
            ebx = self.__os_p_utils[cell_name].mem_utils.getRegValue('ebx')
        self.lgr.debug('debug_sys_callback %s:%d (%s) eax: %d ebx: %d' % (cell_name, pid, comm, eax, ebx))
           
    '''
    Report a syscall
    '''
    def sys_callback(self, cell_name, third, breakpoint, fifth):
        cpu = SIM_current_processor()
        #if cpu != cur_cpu:
        #    self.lgr.debug('sys_callback, not same cpu, ignore')
        #    return
        if not self.__cell_config.os_type[cell_name].startswith(osUtils.LINUX):
            frame = self.__os_p_utils[cell_name].frameFromStack(cpu)
            eax = frame['eax']
            edx = frame['edx']
        else:
            eax = self.__os_p_utils[cell_name].mem_utils.getRegValue(cpu, 'eax')
            edx = self.__os_p_utils[cell_name].mem_utils.getRegValue(cpu, 'edx')
        dumcpu, cur_addr, comm, pid = self.__os_p_utils[cell_name].getPinfo(cpu)
        #self.lgr.debug('sys_callback %s:%d (%s) eax: %d edx: %d cpu: %s' % (cell_name, pid, comm, eax, edx, str(cpu)))
        conf_type = SIM_get_mem_op_initiator(fifth)
        #self.lgr.debug('third: %s  fifth: %s, initiator: %s' % (str(third), str(fifth),  conf_type))
        if not self.__hap_manager.watchingCurrentSyscalls(cell_name, pid):
            eip = self.getEIP(cpu)
            self.lgr.debug('not watching that!, eip: 0x%x return' % eip)
            xcpu, cur_addr, comm, pid = self.__os_p_utils[cell_name].currentProcessInfo(cpu)
            self.lgr.debug('sys_callback again %s:%d (%s) cur_addr 0x%x ' % (cell_name, pid, comm, cur_addr))
            conf_type = SIM_get_mem_op_initiator(fifth)
            self.lgr.debug('initiator is %s' % str(conf_type))
            thread_addr = self.__os_p_utils[cell_name].getPhysAddrOfCurrentThread(cpu)
            gs_base = cpu.ia32_gs_base
            self.lgr.debug('gs_base is 0x%x  thread_addr: 0x%x' % (gs_base, thread_addr))
            
            #SIM_break_simulation('stop here?')
            return
        if self.__rop_pending[cell_name]:
            if eax != self.SYS_EXIT:
                self.__rop_pending[cell_name] = False
                cell = self.__cell_config.cell_context[cell_name]
                self.__watch_kernel.doRop(cell, cpu, pid, comm)
            else:
                self.__rop_pending[cell_name] = False
        if pid in self.__pid_user_cycles[cell_name] and pid not in self.__syscall_entries[cell_name]:
            # update the user space cycles for this process
            current = cpu.cycles
            delta = current - self.__previous_pid_user_cycle[cell_name]
            #self.lgr.debug('sys_callback user cycles %s:%d (%s) was %x previous value is %x  current %d delta: %d' % (cell_name, 
            #    pid, comm, self.__pid_user_cycles[cpu][pid], self.__previous_pid_user_cycle[cpu], current, delta))
            self.__pid_user_cycles[cell_name][pid] += delta
        '''
        if eax == self.__os_p_utils.EXEC_SYS_CALL:
            # save reg frame til return to user space, by then arguments will be mapped to phys memory
            frame = self.__os_p_utils.frameFromRegs(cpu)
            self.__reg_frame[cell_name][pid] = frame
        '''
        server_name = self.getServerName(cell_name)

        ''' If in debug mode, then syscall breakpoint should be deleted.  But may have been
            recreated to catch the death of the process we were watching so we can reInit.
        '''
        if self.__context_manager.getDebugging():
        
            if self.__os_p_utils[cell_name].isSysExit(eax):
                debug_pid, dumb, debug_cpu = self.__context_manager.getDebugPid() 
                if debug_pid == pid and debug_cpu == cpu:
                    self.lgr.debug('sys_callback Exiting the process we were debugging, do reinit')
                    self.__hap_manager.removeKernelBreaks(True)
                    self.reInit()
                    self.__context_manager.detach()
            return
        my_args = procInfo.procInfo(comm, cpu, pid, None, False)
        if pid not in self.__watching[cell_name] and not \
                self.watchProcess(cell_name, cpu, cur_addr, comm, pid):
            self.lgr.debug('sys_callback not watching %d' % pid)
            if self.__os_p_utils[cell_name].isSysExit(eax) and (server_name == comm):
                # the replay master or cb-server is exiting
                if pid not in self.__server_pid[cell_name]:
                    self.lgr.debug('sys_callback reschedule ? %s on %s pid: %d' % (self.__cell_config.cells[cell_name], 
                        cell_name, pid))
                    return
                self.lgr.debug('sys_callback Exiting %s proc: %s:%d (%s)' % (self.__cell_config.cells[cell_name], cell_name,
                   pid, comm))
                self.__server_pid[cell_name].remove(pid)
                self.__os_p_utils[cell_name].cleanPid(pid)
                #self.__watching[cell_name].remove(pid)

            elif eax == self.__os_p_utils[cell_name].EXEC_SYS_CALL:
                # we might be execing a server, so record the call number
                #self.lgr.debug('sys_callback exec by %s:%d (%s)' % (cell_name, pid, comm))
                self.__syscall_entries[cell_name][pid] = eax
                #print 'args is %s look for %s' % (args, self.__master_config.replay_name)
                #if comm == 'replay_master':
                #    self.lgr.info('Exec from %s:%d (%s) frame: %s' % (cell_name, pid, comm, self.__os_p_utils.stringFromFrame(frame)))
                #    SIM_break_simulation('debug exeve in syscall')
                
            return

        ''' Don't monitor sh, scp, etc '''
        if comm in self.__exempt_comms:
           return
	#print "in sys_callback from pid %d comm: %s " % (pid, comm) 
        if pid in self.__watching[cell_name]:
            self.__watch_kernel.clearCalls(cpu)
            # add this back when mode hap is not longer used
            #if pid not in self.__syscall_entries[cell_name]:
            #    self.__tracing.intoKernel(comm, pid)
            #    return

        if self.__os_p_utils[cell_name].isSysExit(eax):
            ''' record process exit information in the monitoring log ''' 
            seed = self.target_log.findSeed(pid, cell_name)
            if self.isCB(comm) or self.isPlayer(comm):
                self.updateLogs(comm, pid, cell_name, cpu)
                if seed in self.__pid_contexts_to_clean:
                    self.__pid_contexts_to_clean[seed].append(procInfo.procInfo(comm, cpu, pid))
                self.closeOutTrace(comm, pid, cell_name)

            '''exiting process.  clean up haps, breakpoints and dictionary entries'''
            self.lgr.debug('sys_callback, is sysExit call')
            self.cleanupPid(cell_name, pid, comm)
            if seed in self.__pid_structs_to_clean:
                self.__pid_structs_to_clean[seed].append(procInfo.procInfo(comm, cpu, pid))
            self.__os_p_utils[cell_name].processExiting(cpu)
            if self.__sysenter_break[cell_name] == breakpoint:
                #frame = self.__os_p_utils.frameFromRegs(cpu)
                frame = self.__os_p_utils[cell_name].frameFromThread(cpu)
            else:
                frame = self.__os_p_utils[cell_name].frameFromStack(cpu)

            self.lgr.info('Exit from %s:%d (%s) break_num was %d frame: %s' % (cell_name, pid, comm, 
                breakpoint, self.__os_p_utils[cell_name].stringFromFrame(frame)))
            return
        elif self.__os_p_utils[cell_name].isTimer(eax): 
            self.lgr.info("got timer %s:%d (%s) call %d" % (cell_name, pid, comm, eax))
            # not expecting a return  TBD, record return to signal handler?
            pass
            
        elif eax != self.__os_p_utils[cell_name].EXEC_SYS_CALL:
            ''' make sure we are not here as the result of a reschedule '''
            if pid in self.__syscall_entries[cell_name]:
                if self.__syscall_entries[cell_name][pid] == eax:
                    self.lgr.debug('sys_callback maybe reschedule of %s:%d (%s)' % (cell_name, pid, comm))
                    return
                else:
                    if self.__cell_config.os_type[cell_name].startswith(osUtils.LINUX):
                        self.lgr.debug("sys_callback two system calls from %s:%d with no return? entry is %d" % (cell_name, pid,
                           self.__syscall_entries[cell_name][pid]))
                        del self.__syscall_entries[cell_name][pid]
                    else:
                        self.lgr.error("two system calls from %s:%d with no return? entry is %d" % (cell_name, pid,
                           self.__syscall_entries[cell_name][pid]))
                        #SIM_break_simulation("two system calls from %s:%d with no return? entry is %d" % (cell_name, pid,
                        #   self.__syscall_entries[cell_name][pid]))
                   
                        return
            if not self.cfg.cfe and (pid not in self.__did_track_setup[cell_name]):
                ''' We should watch this process, but we are not watching yet.  E.g., a player that has
                    not yet received its signal '''
                return
            ''' record the syscall number of use in the return handler '''
            #self.lgr.debug('not exec syscall pid %s:%d (%s) ' % (cell_name, pid, comm))
            self.__syscall_entries[cell_name][pid] = eax
            if pid not in self.__num_calls[cell_name]:
                #TBD why are we here if not tracking syscalls?  Should be initialized elsewhere
                self.__num_calls[cell_name][pid] = 0
            self.__num_calls[cell_name][pid] += 1
            #if eax == 120:
            #    #TBD OB what a hack
            #    self.__syscall_entries[cell_name][pid+1] = eax
            #    self.__num_calls[cell_name][pid+1] += 1
        

        else:
            ''' Exec syscall '''
            self.lgr.debug('sys_callback Exec syscall pid %s:%d ' % (cell_name, pid))
            self.__syscall_entries[cell_name][pid] = eax
            return
 
        if comm != server_name:
            if self.__sysenter_break[cell_name] == breakpoint:
                ''' came in via sysenter '''
                frame = self.__os_p_utils[cell_name].frameFromThread(cpu)
                self.lgr.info('syscall via sysenter from %s:%d (%s) frame: %s param is %d' % (cell_name, pid, comm, 
                    self.__os_p_utils[cell_name].stringFromFrame(frame), breakpoint))
            else:
                '''  came in via syscall_call '''
                frame = self.__os_p_utils[cell_name].frameFromStack(cpu)
                self.lgr.info('syscall via syscall from %s:%d (%s) frame: %s param is %d' % (cell_name, pid, comm, 
                    self.__os_p_utils[cell_name].stringFromFrame(frame), breakpoint))
                if self.isCB(comm) and eax not in range(1,8):
                    self.addLogEvent(cell_name, pid, comm, forensicEvents.USER_BAD_SYSCALL, 'Bad CGC syscall number %d from eip: %x' % \
                       (eax, frame['eip']), low_priority=True)
                    
        else:
            self.lgr.info('should not get here as server name %s comm %s' % (server_name, comm))
            #SIM_break_simulation('in sys_callback, should not get here')

        #if cell_name not in self.__have_returned_from:
        #    # hack to reset syscall breakpoints as physical, optimization to avoid breaks in address space of procs that don't use 32-bit api
        #    self.__have_returned_from.append(cell_name)
        #    self.__hap_manager.clearKernelSysCalls(cell_name, pid)
        #    self.doKernelSysCalls(cpu, cell_name, comm, pid)

            
    def doTransmitReceive(self, frame, call_num, cpu, comm, cell_name, pid):
        retval = True
        name = "receive"
        if call_num is self.SYS_WRITE:
            name = "transmit"
        if self.log_sys_calls and call_num is self.SYS_WRITE:
            self.__call_log[cell_name][pid].doTransmit(frame, cpu)
        elif self.log_sys_calls:
            self.__call_log[cell_name][pid].doReceive(frame, cpu)
        num_bytes = self.__os_p_utils[cell_name].sysCallNumBytes(self.__kernel_info[cell_name].cgc_bytes_offset, cpu)
        if num_bytes < 0:
           self.lgr.info('doTransmitReceive %s return from %s:%d (%s) call#: %d frame: %s UNKNOWN number of bytes  ' % (name, 
               cell_name, pid, comm, call_num, self.__os_p_utils[cell_name].stringFromFrame(frame)))
        else:
           if num_bytes > 0:
               buf = self.getBytes(cpu, num_bytes, frame['ecx'])
               self.lgr.info('doTransmitReceive %s return from %s:%d (%s) call#: %d frame: %s size: %d call_count: %d buffer(ecx): %s' % (name, 
                   cell_name, pid, comm, call_num, self.__os_p_utils[cell_name].stringFromFrame(frame), num_bytes, 
                   self.__num_calls[cell_name][pid], buf))
               if frame['ebx'] == self.NEGOTIATE_FD and self.isPoVcb(comm):
                   #SIM_break_simulation('debug nego')
                   address = self.__negotiate.recordNegotiate(call_num, buf, pid, cell_name)
                   if address is not None:
                       bm = 'protected_memory:0x%x' % address
                       # TBD somehow tell ida user the original address, i.e., first byte of the leak
                       orig_address = address
                       if not self.__bookmarks.hasDebugBookmark(bm):
                           # may have been split between two reads.  still not reliable?
                           address = address - 1
                           bm = 'protected_memory:0x%x' % (address)
                      
                       if self.__bookmarks.hasDebugBookmark(bm):
                           self.__bookmarks.clearOtherBookmarks('protected_memory:', bm)
                           self.lgr.debug('doTransmitReceive netgotiate, bookmark %s found' % bm)
                           pinfo = self.__protected_memory.findAddressReader(address)
                           cb_cell_name = self.getTopComponentName(pinfo.cpu)
                           bm_here = 'where we were when pover offered proof'
                           ''' TBD this will break in multithreading because of a cross cell reference '''
                           self.setDebugBookmark(bm_here, cpu=pinfo.cpu)
                           dbi = debugInfo.debugInfo(self.__context_manager, self.__hap_manager, 
                               pinfo.pid, pinfo.comm, None, cgcEvents.CGCEventType.protected_read, 0, 
                               'dum cb', 'dum pov', cb_cell_name, pinfo.cpu, None, 0, self.lgr,  auto_analysis=self.__master_config.auto_analysis)
                           #dbi.cycle = self.__bookmarks[bm] - 1
                           dbi.cycle = self.__bookmarks.getCycle(bm)
                           if dbi.cycle is None:
                               self.lgr.error('type 2 negotation, could not find cycle for bookmark %s' % bm)
                               
                           self.__tracing.closeTrace(pid, cell_name)
                           dbi.command = 'skip-to cycle = %d ' % dbi.cycle
                           self.lgr.debug('doTransmitReceive call start debugging to set a stop-hap with command: %s (0x%x) and then break_simulation' % (dbi.command, dbi.cycle))
                           debugType2.debugType2(self, self.__bookmarks, dbi, self.__param[cell_name], self.__os_p_utils[cell_name], address)
	                   SIM_break_simulation('stopping in doTransmitReceive, pov negotiation')
                       else:
                           self.lgr.debug('doTransmitReceive netgotiate, bookmark %s NOT found, page follows:' % bm)
                           self.lgr.debug(self.__negotiate.returnPage(pid, cell_name))

               else:
                   if frame['ebx'] == self.TRANSMIT_FD:
                       #self.lgr.debug('doTransmitReceive HERE')
                       if pid not in self.__bytes_wrote[cell_name]:
                           self.__bytes_wrote[cell_name][pid] = 0
                       self.__bytes_wrote[cell_name][pid] += num_bytes
                       if self.isCB(comm):
                           recent_protected, address = self.__protected_memory.getRecent()
                           #if recent_protected is None:
                           #    self.lgr.debug('recent protected is None')
                           if recent_protected is not None:
                              recent_string = '%x' % recent_protected
                              #self.lgr.debug('recent string: <%s>  buf <%s>' % (recent_string, buf))
                              if len (recent_string) > 2 and recent_string in buf:
                                  ''' don't wait for negotiate, declare type 2 here.  add bookmark for the transmit, retain the one for the read '''
                                  buf_addr = frame['ecx']
                                  offset = buf.index(recent_string)/2
                                  data_addr = buf_addr + offset 
                                  self.lgr.debug('doTransmitReceive detects protected memory wrote via transmit %x from memory: 0x%x' % (recent_protected, data_addr))
                                  entry = 'Type 2 POV, value: %s' % recent_string
                                  self.addLogEvent(cell_name, pid, comm, forensicEvents.POV_2, entry)

                                  bm = 'protected_memory:0x%x' % (address)
                          
                                  if not self.__bookmarks.hasDebugBookmark(bm):
                                      self.lgr.debug('doTransmitReceive, did not have bm for %s, adding it for receive?  error?' % bm)
                                      self.setDebugBookmark(bm, cpu=cpu)
                                  else: 
                                      self.lgr.debug('doTransmitReceive netgotiate, bookmark %s found' % bm)

                                  ''' set bookmark for the transmit '''
                                  cycles, eip = self.__other_faults.getCycles(cell_name, pid)
                                  if cycles is None:
                                      self.lgr.error('doTransmitReceive failed to find cycle of int80 from otherFaults')
                                      return
                                  trans_bm = 'CB transmit protected value:%s from memory:0x%x' % (recent_string, data_addr)
                                  self.setDebugBookmark(trans_bm, cpu=cpu, cycles=cycles, eip=eip)
                                  self.lgr.debug('doTransmitReceive, add bookmark for transmit protected memory from CB %s' % trans_bm)

                                  '''
                                  self.__bookmarks.clearOtherBookmarks(bm)
                                  dbi = debugInfo.debugInfo(self.__context_manager, self.__hap_manager, 
                                      pid, comm, None, cgcEvents.CGCEventType.protected_read, 0, 
                                      'dum cb', 'dum pov', cell_name, cpu, None, 0, self.lgr)
                                  #dbi.cycle = self.__bookmarks[bm] - 1
                                  dbi.cycle = self.__bookmarks.getCycle(bm)
                                  #dbi.cycle = self.__bookmarks[bm] 
                                  dbi.command = 'skip-to cycle = %d ' % dbi.cycle
                                  self.lgr.debug('doTransmitReceive call start debugging to set a stop-hap with command: %s (0x%x) and then break_simulation' % (dbi.command, dbi.cycle))
                                  debugType2.debugType2(self, self.__bookmarks, dbi, self.__param[cell_name], self.__os_p_utils[cell_name], address)
                                  SIM_break_simulation('stopping in doTransmitReceive, transmitted protected')
                                  '''


                   elif frame['ebx'] == self.RECEIVE_FD:
                       if pid not in self.__bytes_read[cell_name]:
                           self.__bytes_read[cell_name][pid] = 0
                       self.__bytes_read[cell_name][pid] += num_bytes
                           
           else:
               self.lgr.info('doTransmitReceive %s return from %s:%d (%s) call#: %d frame: %s ZERO BYTES' % (name, 
                   cell_name, pid, comm, call_num, self.__os_p_utils[cell_name].stringFromFrame(frame)))
               retval = False
        return retval

    '''
        Handle returns from the random system call
    '''
    def doRandom(self, frame, call_num, cpu, comm, cell_name, pid):
        rnd_bytes = self.__os_p_utils[cell_name].sysCallNumBytes(self.__kernel_info[cell_name].cgc_bytes_offset, cpu)
        if rnd_bytes is not 0:
            rnd_string = self.getBytes(cpu, rnd_bytes, frame['ebx'])
            self.lgr.info('random return from %s:%d (%s) call#: %d frame: %s size: %d buffer(ecx): %s' % (cell_name, pid, comm, call_num, self.__os_p_utils[cell_name].stringFromFrame(frame), rnd_bytes, rnd_string))
        else:
            self.lgr.info('random return from %s:%d (%s) call#: %d frame: %s ZERO BYTES' % (cell_name, pid, comm, call_num, self.__os_p_utils[cell_name].stringFromFrame(frame)))
        if self.log_sys_calls:
            self.__call_log[cell_name][pid].doRandom(frame, cpu)

    '''
        Handle returns from the allocate system call
    '''
    def doAllocate(self, frame, call_num, cpu, comm, cell_name, pid):
        length = frame['ebx']
        prot = frame['ecx']
        address = frame['edx']
        ret_address = self.__mem_utils[cell_name].readWord32(cpu, address)
        self.lgr.info('allocate return from %s:%d (%s) call#: %d frame: %s length: %d prot: %d : address is %x, new memory at %x' % (cell_name, pid, comm, call_num, self.__os_p_utils[cell_name].stringFromFrame(frame), length, prot, address, ret_address))
        if prot is self.PROT_NONE:
           ''' set breaks to catch execution of pages in the range '''
           if pid in self.__watch_non_code:
               self.lgr.info('Allocated memory not executable, set breaks on it from %x len %x' % (ret_address, length))
               self.__non_code.nonCodeBreakRange(cell_name, pid, cpu, ret_address, length)
           else:
               self.lgr.info('doAllocate no non_code module for pid %d' % pid)
           self.__noX.add(cell_name, pid, ret_address, length)
        else:
           if self.watchRop(cell_name, comm, pid):
               self.lgr.info('doAllocate is rop, set breaks from %x len %x' % (ret_address, length))
               self.__rop_cop.ropCopBreakRange(cell_name, pid, ret_address, length, cpu, comm)
        if self.log_sys_calls:
            self.__call_log[cell_name][pid].doAllocate(frame, cpu)
        if self.__master_config.stopOnSomething():
            self.lgr.debug('cgcMonitor doAllocate add to x_pages %d (%s) addr: %x  len: %x' % (pid, comm, ret_address, 
                    length))
            try:
                self.__x_pages[cell_name][pid].append(self.addressAndLength(ret_address, length))
            except KeyError:
                self.lgr.error('cgcMonitor doAllocate, pid %d not in x_pages for %s?'% (pid, cell_name))

    class addressAndLength():
        def __init__(self, a, l):
            self.address = a
            self.length = l
           
    '''
        Handle returns from the fdwait system call
    '''
    def doFdwait(self, frame, call_num, cpu, comm, cell_name, pid):
        nfds = frame['ebx']
        fd_set_ptr = frame['ecx']
        fd_set = self.getBytes(cpu, self.__fd_set_size, fd_set_ptr)
        timeval_sec = 0
        timeval_usec = 0
        timeval_ptr = frame['edx']
        if timeval_ptr != 0:
            timeval_sec = self.__mem_utils[cell_name].readWord32(cpu, timeval_ptr)
            timeval_usec = self.__mem_utils[cell_name].readWord32(cpu, timeval_ptr+self.__mem_utils[cell_name].WORD_SIZE)
        readyfds_ptr = frame['esi']
        readyfds = 0
        if readyfds_ptr != 0:
            readyfds = self.__mem_utils[cell_name].readWord32(cpu, readyfds_ptr)
        self.lgr.info('fdwait return from %s:%d (%s) call#: %d frame: %s nfds is %d fd_set_ptr: %x set: %s timeval: %d.%6d readyfds: %d' % \
            (cell_name, pid, comm, call_num, self.__os_p_utils[cell_name].stringFromFrame(frame), nfds, fd_set_ptr, fd_set,
             timeval_sec, timeval_usec, readyfds))
        if self.log_sys_calls:
            self.__call_log[cell_name][pid].doFdWait(frame, cpu, self.__fd_set_size)
    
    '''
        Handle returns from the deallocate system call
        TBD remove executable breaks (rop)
    '''
    def doDeallocate(self, frame, call_num, cpu, comm, cell_name, pid):
        address = frame['ebx']
        length = frame['ecx']
        self.lgr.info('deallocate return from %s:%d (%s) call#: %d frame: %s address is %x length: %d' % (cell_name, pid, comm, call_num, self.__os_p_utils[cell_name].stringFromFrame(frame), address, length))
        if pid in self.__watch_non_code:
            self.__non_code.nonCodeRangeRemove(cell_name, pid, cpu, address, length)
        else:
           self.lgr.info('doDeallocate no non_code module for pid %d' % pid)
        self.__noX.remove(cell_name, pid, address, length)

        if self.log_sys_calls:
            self.__call_log[cell_name][pid].doDeallocate(frame, cpu)

    def doStateAssertion(self, cpu_name):
            SIM_run_command('disable-vmp')
            #SIM_run_command('load-module state-assertion')
            #SIM_run_command('state-assertion-create-file compression = gz file = /tmp/test.sa')

            #SIM_run_command('sa0.add obj = %s steps = 1000000' % cpu_name)
            SIM_run_command('sa0.start')

    '''
        Enable software tracking & OS awareness 
    '''
    def trackSetup(self, my_args):
        cell_name = self.getTopComponentName(my_args.cpu)
        if not my_args.enabled_tracking and not self.NO_TRACK:
            enable_command = '%s.software.enable-tracker' % cell_name
            SIM_run_command(enable_command)
            self.lgr.debug('trackSetup software.enable-tracker')

        self.lgr.debug('in trackSetup for %s:%d (%s)' % (cell_name, my_args.pid, my_args.comm))
        if not self.__context_manager.has(cell_name, my_args.comm, my_args.pid):
            context = None
            if not self.NO_TRACK:
                track_cmd = "%s.software.track %s" % (cell_name, my_args.comm)
                self.lgr.debug('track_cmd is %s' % track_cmd)
                context = SIM_run_command(track_cmd)
            else:
                track_cmd = "new-context %s" % (my_args.comm)
                self.lgr.debug('NO_TRACK track_cmd is %s' % track_cmd)
                try:
                    SIM_run_command(track_cmd)
                except:
                    pass
                context = my_args.comm
            self.lgr.debug( 'trackSetup context is %s' % context)
            self.__context_manager.add(context, cell_name, my_args.pid, my_args.comm)

        if (self.__master_config.debug_cb and self.isCB(my_args.comm)) or \
           (my_args.comm == self.__master_config.debug_process) or \
           (self.__master_config.debug_pov and self.isPoVcb(my_args.comm)):
            
            # no monitoring, go to debugger as soon as the process gets to user space
            cmd = []
            #cmd.append('%s.run-until-activated' % context)
            cmd.append('to-user-space')
            #cmd.append('enable-reverse-execution')
            #  enable-reverse will be done as part of do-debug
            cmd.append('do-debug')
            self.lgr.debug('trackSetup go right to debugger for %s %d %s' % (cell_name, my_args.pid, my_args.comm))
            dbi = debugInfo.debugInfo(self.__context_manager, self.__hap_manager, 
                    my_args.pid, my_args.comm, cmd, None, None, 
                    'dum cb', 'dum pov', cell_name, my_args.cpu, None, None, self.lgr)
            self.cleanupAll()
            #startDebugging2.startDebugging2(dbi)
            self.__context_manager.setIdaMessage('Just debug, no analysis')
            self.__bookmarks.mapOrigin("_start+1") 
            chainHap.chainHap(self, dbi, self.__os_p_utils[cell_name], self.__param[cell_name])
            print 'break it now'
            SIM_break_simulation('trackSetup stop for CB debugging')
        elif not my_args.enabled_tracking:
            self.lgr.debug('enabling reverse execution')
            #SIM_run_alone(SIM_run_command, "set-bookmark 'assert_test'")
            #SIM_run_alone(self.doStateAssertion, my_args.cpu.name)
            #SIM_run_alone(run_command, 'rexec-limit %d %d' % (self.__master_config.reverse_size, self.__master_config.reverse_steps))
            #run_command('log-setup -overwrite log.txt')
            #run_command('log-level 4')
            
            # tbd, set to next cycle so we can back up? eh?
            #plus_1 = SIM_cycle_count(my_args.cpu)+1
            #self.setDebugBookmark('_start+1', my_args.cpu, plus_1)
            dum_cpu, cur_addr, dum, pid = self.__os_p_utils[cell_name].currentProcessInfo(my_args.cpu)
            self.lgr.debug('trackSetup set first bookmark pid is %d' % pid)
            self.setDebugBookmark('_start+1', my_args.cpu)
            stopHap.stopHap('enable-reverse-execution', self.lgr)
            #SIM_run_alone(run_command, 'enable-reverse-execution')
            self.lgr.debug('back from stopHap, does not mean it has run yet')
   
    ''' TBD not yet used '''
    #def trackTareDown(self):
    #    run_command("disable-reverse-execution")

    def monitorForPid(self, cell_name, pid, comm, cpu):
       '''
       Set up memory monitoring for the given process
       '''
       if pid not in self.__did_track_setup[cell_name]:
           self.lgr.info('monitorForPid %s:pid %d (%s)' % (cell_name, pid, comm))
           ''' assume this is the exec return to user mode for this process '''
           if self.isCB(comm):
               self.cbMemory(comm, cell_name, pid)
           else:
               self.elfMemory(comm, cell_name, pid)
              
           if (self.__master_config.stopOnSomething() and self.isCB(comm) and not self.__master_config.debug_pov) or \
              (self.__master_config.debug_pov and self.isPoVcb(comm)) or self.__master_config.debug_process is not None:
               ''' We are doing analysis, so enable software tracking, which will slow
                   simics down quite a bit.  If only monitoring is desired, turn off all
                   of the stop_on's'''
               #SIM_break_simulation("stopping to do track setup")
               self.lgr.debug('monitorForPid, set up rev execution')
               enabled_tracking = len(self.__did_track_setup[cell_name]) > 1
               my_args = procInfo.procInfo(comm, cpu, pid, self.__context_manager,
                   enabled_tracking)
               SIM_run_alone(self.trackSetup, my_args)
           self.__did_track_setup[cell_name].append(pid)
           self.__num_calls[cell_name][pid] = 1
           self.lgr.debug('monitorForPid returning')
           SIM_break_simulation("here");
           '''
           if self.isCB(comm):
            hack_addr = 0xbaaaf18
            phys_block = cpu.iface.processor_info.logical_to_physical(hack_addr, Sim_Access_Read)
            if True or phys_block.address != 0:
                #pcell = cpu.physical_memory
                #self.hack_break = SIM_breakpoint(pcell, Sim_Break_Physical, Sim_Access_Write, phys_block.address, 1, 0)
                cell = self.__cell_config.cell_context[cell_name]
                self.hack_break = SIM_breakpoint(cell, Sim_Break_Linear, Sim_Access_Write, hack_addr, 1, 0)
                self.hack_hap= SIM_hap_add_callback_index("Core_Breakpoint_Memop", self.hack_callback, procInfo.procInfo(None, cpu, pid), self.hack_break)
                self.lgr.debug('HACK installed hap for phys addr 0x%x' % phys_block.address)
            else:
                self.lgr.debug('HACK could not install hap, address not mapped')
           '''

    def updateStructs(self, cell_name, pid, comm):
           '''
           Create per-process lists.  
           TBD find such lists scattered about and put here.
           
           '''
           if pid not in self.__x_pages[cell_name]:
               self.__x_pages[cell_name][pid] = []
           else:
               self.lgr.error('updateStructs, x_pages for %d already exists' % pid)
               
    def watchThisProcess(self, cell_name, pid, comm):
        self.lgr.debug('watchThisProcess %s %d (%s)' % (cell_name, pid, comm))
        self.__watching[cell_name].append(pid)

    def prepForIDS(self, program, cpu, cell_name, pid, args):
        #self.lgr.debug('prepForIDS num args is %d  sixth is %s' % (len(args), args[6]))
        self.__rules_file_name = None
        running = True
        if len(args) == 0:
            self.lgr.debug('Starting IDS on %s pid: %d program: %s but have no params in 64bit' % (cell_name, pid, program))
            return False
        licycle = cycle(args)
        next_item = licycle.next()
        retval = True
        self.lgr.debug('Starting IDS on %s pid: %d program: %s ' % (cell_name, pid, program))
        panic = 100
        i=0
        while running:
            try:
                this_item, next_item = next_item, licycle.next()
            except:
                running = False
                self.lgr.error('prepForIDS unable to find rules %s %d (%s)' % (cell_name, pid, program))
            if this_item == '-rules':
                self.__rules_file_name = next_item
                self.lgr.debug('prepForIDS found rules file: %s' % self.__rules_file_name)
                running = False
            if i > panic:
                self.lgr.error('prepForIDS fatal loop looking at args %s' % str(args))
                running = False
            i += 1
        if self.__rules_file_name is None or self.__rules_file_name.endswith('no_filter.rules'):
            self.lgr.debug('prepForIDS no rules file')
            self.__rules_file_name = None
            retval = False
        else:
            self.target_log.setRules(self.__rules_file_name)
        return retval

    def prepForPlayer(self, program, cpu, cell_name, pid, args):
            ''' pov launcher for CFE  or poller for cqe'''
            cell = self.__cell_config.cell_context[cell_name]
            #if not self.__master_config.watchSysCalls():
                # no syscalls, so log may go quiet, add keep-alive messages so we don't appear to be dead
            #    self.__keep_alive.postEvent(cpu)
            # thanks NRFIN 68, you pig!
            self.__keep_alive.postEvent(cpu)
            if self.__master_config.watchPlayer() and not self.isPoller(program):

                # If not  monitoring syscalls, set break on return so that
                # we can then set break on when player starts consuming user data
                if not self.__master_config.watchCalls(cell_name, program): 
                    if not self.cfg.cfe:
                        self.__hap_manager.kernelSysCall(cpu, cell_name, cell, self.__kernel_info[cell_name].userret_offset, self.ret_callback)
                else: 
                    #self.doKernelSysCalls(cpu, cell_name, program)
                    pass
                if self.__master_config.stopOnSomething(): 
                    self.updateStructs(cell_name, pid, program)
            #player_break = 9999
            self.lgr.debug('prepForPlayer call getParent')
            parent_pid, parent_comm = self.__os_p_utils[cell_name].getParent(pid, cpu)
            #g_parent_pid, g_parent_comm = self.__os_p_utils[cell_name].getParent(parent_pid)
            self.lgr.debug('prepForPlayer, manager pid is %d (%s)' % (parent_pid, parent_comm))
            self.__manager_pid = parent_pid
            pid_for_target_log = parent_pid
            seed = 'some_poller'
            if self.cfg.cfe:
                if self.__rules_file_name is not None:
                    ''' watch ids processes '''
                    for ids_pid in self.__ids_pid:
                        self.lgr.debug('prepForPlayer, start watching IDS %d on %s ' %  (ids_pid, cell_name))
                        self.__watching[cell_name].append(ids_pid)
                if program.endswith('.pov'):
                    replay_file = program
                    #replay_file = os.path.splitext(os.path.basename(self.__replay_file_name))[0]
                    #the_args = ''
                    #for arg in args:
                    #    the_args = the_args+' '+arg 
                    #self.lgr.debug('pov args: %s' % the_args)
                    ''' This is the pov seed, not the CB seed, make assignment so not equal to "some_poller" '''
                    seed = utils.getTagValue(args, 'seed', '=')            
                    pid_for_target_log = pid
                    tmp_replay_file_name = program
                else:
                    ''' A poll '''
                    the_args = ''
                    for arg in args:
                        the_args = the_args+' '+arg 
                    self.lgr.debug('poller args: %s' % the_args)
                    #findex = 12
                    #if self.__cell_config.os_type[cell_name].startswith(osUtils.LINUX):
                    #    findex = 11 
                    #self.lgr.debug("num args %d findex is %d" % (len(args), findex))
                    #if len(args) <= findex:
                    #    SIM_break_simulation("num args too small %d findex is %d" % (len(args), findex))
                    #    return
                    #if args[findex] == '-s':
                    #    findex = findex+2
                    num_args = len(args)
                    tmp_replay_file_name = args[num_args-1]
                    self.lgr.debug('prepForPlayer cfe poll, replay_file_name is : %s ' % (args[num_args-1]))
                    replay_file = os.path.splitext(os.path.basename(tmp_replay_file_name))[0]
                self.lgr.debug('prepForPlayer, call newReplay for %s' % replay_file)
                seed = self.target_log.newReplay(replay_file, watch_player=self.__master_config.watchPlayer(),
                        debug_binary=self.__master_config.stopOnSomething(), seed=seed, pid=pid_for_target_log, cell_name=cell_name)
                if program.endswith('.pov'):
                    self.__negotiate.newPoV(program, pid, cpu, cell_name, self.__master_config)
                if seed not in self.__cb_file_name:
                    self.__cb_file_name[seed] = None
                if seed not in self.__pid_structs_to_clean:
                    self.__pid_structs_to_clean[seed] = []
                    self.__pid_contexts_to_clean[seed] = []
                self.__replay_file_name[seed] = tmp_replay_file_name
                self.__os_p_utils[cell_name].setCommMap(pid, program, cpu)
            else: 
                ''' NOT CFE, retain for future cqe-type processing '''
                try:
                    #common = os.path.splitext(os.path.basename(self.__replay_file_name))[0].split('_', 1)[1]
                    just_file = os.path.splitext(os.path.basename(self.__cb_file_name[seed]))[0]
                except:
                    self.lgr.error('prepForPlayer bad replay file name, could not get common from it %s' % self.__cb_file_name)
                    return
                common = utils.getCommonName(just_file)
                if not self.target_log.newPair(common, self.__master_config.watchPlayer(), pid, cell_name):
                    self.lgr.error('prepForPlayer multiple CBs running at same time? %s:%d (%s)' % (cell_name, pid, common))
                    return
                replay_file_name[seed] = args[num_args-1]
                root, ext = os.path.splitext(self.__replay_file_name[seed])
                self.target_log.newReplay(os.path.basename(root))

            self.lgr.debug('prepForPlayer Starting player %s on %s pid: %d program: %s replay: %s cb: %s. Parent: %d' % \
                 (program, cell_name, pid, program, self.__replay_file_name[seed], self.__cb_file_name[seed], parent_pid))
            self.__cfe_poller_pid = parent_pid
            #self.__watching[cell_name].append(pid)
            #self.doKernelSysCalls(cpu, cell_name)
            # remove this
            #SIM_break_simulation('make chkpt here')
            if self.__master_config.trace_target == program:
                self.__tracing.startTrace(program, pid, cpu, self.__replay_file_name[seed])
            if self.__code_coverage is not None:
                self.__code_coverage.reset()

    def prepForCB(self, program, cpu, cell_name, pid, args):
            #parent_pid, parent_comm = self.__os_p_utils.getParent(pid, self.__param[cell_name])
            #g_parent_pid, g_parent_comm = self.__os_p_utils.getParent(parent_pid, self.__param[cell_name])
            self.lgr.debug('Starting CB %s on %s pid: %d program: %s ' % (program, cell_name, pid, program))
            the_args = ''
            for arg in args:
                the_args = the_args+' '+arg 
            self.lgr.debug('CB args: %s' % the_args)
            seed = utils.getTagValue(args, 'seed', '=')

            if not self.target_log.newCB(program, self.__master_config.watchPlayer(), seed, pid, cell_name, self.__rules_file_name):
                self.lgr.error('prepForCB multiple CBs running at same time? %s:%d (%s)' % (cell_name, pid, program))
                return
            # new targetLog replay
            if program.startswith(utils.TEST_DUCK_NAME+'_'+utils.TEST_DUCK_TEAM_ID):
                self.addLogEvent(cell_name, pid, program, forensicEvents.DUCK_NAME_TEST, 'Test of CGC monitoring EICAR-equivalent')

            # map program to pid, COMM string length not long enough
            self.__os_p_utils[cell_name].setCommMap(pid, program, cpu)
            #self.doKernelSysCalls(cpu, cell_name, program)
              
            if self.__master_config.stopOnSomething(): 
                self.updateStructs(cell_name, pid, program)

            #SIM_run_alone(SIM_run_command, 'list-breakpoints')
            replay_file = None 
            if seed not in self.__pid_structs_to_clean:
                self.__pid_structs_to_clean[seed] = []
                self.__pid_contexts_to_clean[seed] = []
            if seed in self.__replay_file_name:
                try:
                    replay_file = os.path.splitext(os.path.basename(self.__replay_file_name[seed]))[0]
                except:
                    self.lgr.error('cgcMonitor prepForCB bad replay filename %s' % self.__replay_file_name[seed])
                    return
            if self.log_sys_calls:
                self.__call_log[cell_name][pid] = callLog.callLog(self, self.__os_p_utils[cell_name], self.__param[cell_name], pid, program,
                    replay_file, self.__zk, self.lgr, self.cfg.logdir,
                        self.__kernel_info[cell_name].cgc_bytes_offset)
                self.lgr.debug('created call_log for %s:%d (%s)' % (cell_name, pid, program))
            #if self.__tracing.isTraced(program):
            #    self.__tracing.startTrace(program, pid, cpu)
            #    self.lgr.debug('cgcMonitor finishExecParams Will trace CB: %s' % program)
            if self.__master_config.trace_cb:
                tmp_replay = None
                if seed in self.__replay_file_name:
                    tmp_replay = self.__replay_file_name[seed]
                #else:
                #    tmp_replay = self.target_log.getLatestPOV()
                throw_id = None
                if self.__master_config.auto_analysis:
                    package = self.__zk.getLatestLocalPackage(self.lgr)
                    self.__context_manager.setLatestPackage(package)
                    throw_id_element = package.find('throw_id')
                    if throw_id_element is not None:
                        throw_id = throw_id_element.text
                        self.__recent_throw_id = throw_id
                        throw_id = os.path.join('/tmp',throw_id+'-trace.log') 
                        try:
                           os.remove(throw_id)
                        except:
                           pass 
                self.__tracing.startTrace(program, pid, cpu, tmp_replay, use_outfile=throw_id)
                self.lgr.debug('cgcMonitor prepForCB trace all CBs, this CB: %s for replay: %s throw_id: %s' % (program, 
                   tmp_replay, throw_id))
            elif not self.__master_config.watchSysCalls() and self.__master_config.stopOnSomething():
                self.lgr.debug('Want debug, but not monitoring sys calls %d (%s)' % (pid, program))
                self.monitorForPid(cell_name, pid, program, cpu)
                self.watchThisProcess(cell_name, pid, program) 
            if self.__master_config.stop_on_memory or self.__master_config.track_protected_access:
                self.__protected_memory.newCB(cpu)


            
    def hack_callback(self, pinfo, third, forth, memory):
        dumcpu, cur_addr, comm, pid = self.__os_p_utils[cell_name].getPinfo(cpu)
        if dumcpu != pinfo.cpu or pid != pinfo.pid:
            self.lgr.debug('HACK hack_callback wrong process %d' % pid)
        else:
            self.lgr.debug('HACK %d wrote to 0xbaaaf18, at cycle 0x%x' % (pinfo.pid, pinfo.cpu.cycle))

    '''
        May also be invoked from os_p_utils if program name not in mapped memory during first read
        TBD: very brittle and depends on replay invocation from the replay_master
    '''
    def finishExecParams(self, cpu, pid, program, args, cur_addr):
        if program is None:
            self.lgr.debug('finishExecParams, Unexpected None value for program %d' % pid)
            return
        program = os.path.basename(program)
        cell_name = self.getTopComponentName(cpu)
        server_name = self.getServerName(cell_name)
        parent_addr, parent_pid = self.__os_p_utils[cell_name].getParentPid(cur_addr, cpu) 

        #self.lgr.debug('finishExecParams for %s %d <%s> server_name is %s. parent pid %d' % (cell_name, pid, program, server_name, parent_pid))
        #if self.isCB(program) or self.isPoVcb(program) or self.isIDS(program):
        # TBD don't have a userret_offset for 64 bit
        #if self.isCB(program) or self.isPoVcb(program):
        if self.isCB(program) or self.isPoVcb(program) or self.isIDS(program):
            #phys_block = cpu.iface.processor_info.logical_to_physical(self.__kernel_info[cell_name].userret_offset, Sim_Access_Read)
            #pcell = cpu.physical_memory
            #the_break = SIM_breakpoint(pcell, Sim_Break_Physical, Sim_Access_Execute, phys_block.address, 1, 0)
            cell = self.__cell_config.cell_context[cell_name]
            the_break = SIM_breakpoint(cell, Sim_Break_Linear, Sim_Access_Execute, self.__kernel_info[cell_name].userret_offset, 1, 0)
            self.__ret_exec_break[cell_name][pid] = the_break
            self.__ret_exec_hap[cell_name][pid] = SIM_hap_add_callback_index("Core_Breakpoint_Memop", self.ret_exec_callback, procInfo.procInfo(program, cpu, pid), the_break)
            self.lgr.debug('finishExecParams on %s %d (%s) set ret_exec_break, break # %d and hap # %d' % (cell_name, pid, program, the_break, 
               self.__ret_exec_hap[cell_name][pid]))
   
        if program == server_name:
            self.__server_pid[cell_name].append(pid)
            self.lgr.debug('finishExecParams Starting service on %s (%s) pid: %d program: %s  args is %s' % \
                 (self.__cell_config.cells[cell_name], cell_name, pid, program, str(args)))
            if program == 'launcher':
                got_e = False
                cb_name = None
                for arg in args:
                    if got_e:
                        cb_name = arg
                        break
                    if arg == '-e':
                        got_e = True
                if cb_name is not None:
                    ''' for use if launcher exits before exec '''
                    self.target_log.setHackedCB(os.path.basename(cb_name))
               
        if program == 'pov-manager':
            self.lgr.debug('Starting service pov-manager') 
            self.pov_manager_pid = pid

        if self.isCB(program):
            self.prepForCB(program, cpu, cell_name, pid, args)

        elif self.isPlayer(program) and program != self.__master_config.debug_process:
            self.prepForPlayer(program, cpu, cell_name, pid, args)

        elif self.isIDS(program):
            self.prepForIDS(program, cpu, cell_name, pid, args)

        elif self.__tracing.isTraced(program, pid):
            ''' Instruction/data trace required for arbitrary program, track it like a CB '''
            self.lgr.debug('finishExecParams Found program to trace: %s' % program)
            self.__tracing.startTrace(program, pid, cpu)
            self.monitorForPid(cell_name, pid, program, cpu)
            self.watchThisProcess(cell_name, pid, program) 
            self.__call_log[cell_name][pid] = callLog.callLog(self, self.__os_p_utils[cell_name], self.__param[cell_name], pid, program,
                None, self.__zk, self.lgr, self.cfg.logdir,
                        self.__kernel_info[cell_name].cgc_bytes_offset)
            self.lgr.debug('finishExecParams created call_log for %s:%d (%s)' % (cell_name, pid, program))
        elif program == self.__master_config.debug_process:
            ''' debug arbitrary program.  TBD awkward, we instrument just to then tear it all down to enter 
            debugging.  Easiest way is using common mechanism.'''
            self.lgr.debug('finishExecParams, will debug %s' % program)
            self.monitorForPid(cell_name, pid, program, cpu)
            if self.__master_config.stopOnSomething(): 
                self.updateStructs(cell_name, pid, program)
        elif program == self.__master_config.taint_process:
            self.monitorForPid(cell_name, pid, program, cpu)
        ''' for debugging
        elif program == 'replay':
            self.lgr.debug('Found replay : %s  %d' % (program, pid))
            self.__watching[cell_name].append(pid)
            self.doKernelSysCalls(cpu, cell_name, program)
        '''
    '''
        Get offset of address in player of the code whose execution indicates
        the player is about to consume untrusted data.  This is a file written
        by the target.
    '''    
    def getPlayerOffset(self):
        self.__player_offset = 0x0804a480
        try:
           player_offset_file = os.path.join(self.cfg.maps_dir, 'playerOffset.txt')
           pf = open(player_offset_file)
           self.__player_offset = int(pf.read(), 16)
           pf.close()
           print 'using player offset from target: %d' % self.__player_offset
        except:
           print 'did not find playerOffset.xt'
           pass
    
    def player_ready_callback(self, pid, third, breakpoint, fifth):
        # only used in old cqe, all on one machine
        cpu = SIM_current_processor()
        cell_name = self.getTopComponentName(cpu)
        cpu, cur_addr, comm, this_pid = self.__os_p_utils[cell_name].getPinfo(cpu)
        if pid == this_pid:
            comm = self.__os_p_utils[cell_name].updateComm(pid, cpu)
            self.lgr.debug('player_ready_callback %s:%d (%s) thinks player is ready' % \
               (cell_name, pid, comm))
            print 'player is ready'
            self.__keep_alive.postEvent(cpu)
            self.__player_monitor = True
            SIM_delete_breakpoint(breakpoint)
            SIM_hap_delete_callback_id("Core_Breakpoint_Memop", self.__player_hap)
            self.__player_hap = None
            #self.__watching[cell_name].append(pid)
            self.monitorForPid(cell_name, pid, comm, cpu)
            fname = self.__replay_file_name['some_poller']
            if fname is None:
                self.lgr.error('could not get thrower arguments')
                SIM_break_simulation('could not get thrower arguments')
                return
            self.lgr.debug('player_ready_callback for %s:%d (%s) throw file: %s' % \
                   (cell_name,pid, comm, fname))
            #root, ext = os.path.splitext(fname)
            #self.target_log.newReplay(os.path.basename(root))

    def sys_clone_callback(self, cell_name, third, forth, memory):
        #cell_name = self.getTopComponentName(cpu)
        cpu = SIM_current_processor()
        dumcpu, cur_addr, comm, pid = self.__os_p_utils[cell_name].getPinfo(cpu)
        if self.isIDS(comm):
            self.lgr.debug('sys_clone_callback %s %d (%s)' % (cell_name, pid, comm))

    def ret_from_fork_callback(self, cell_name, third, forth, memory):
        #cell_name = self.getTopComponentName(cpu)
        cpu = SIM_current_processor()
        dumcpu, cur_addr, comm, pid = self.__os_p_utils[cell_name].getPinfo(cpu)
        if self.isIDS(comm):
            self.lgr.debug('ret_from_fork_callback %s %d (%s)' % (cell_name, pid, comm))
            self.__ids_pid.append(pid)
            self.__ids_cell_name = cell_name

    def execve_callback(self, cell_name, third, forth, memory):
        '''
        Invoked when Linux enters the kernel exeve function.
        use finishExecParams to record start of programs of interest
        Also, read process arguments so they are stored in the os_p_utils for this process
        '''   
        cpu = SIM_current_processor()
        cell_name = self.getTopComponentName(cpu)
        #self.lgr.debug('execve_callback %s ' % (cell_name))
        dumcpu, cur_addr, comm, pid = self.__os_p_utils[cell_name].getPinfo(cpu)
        if pid in self.__syscall_entries[cell_name] and self.__syscall_entries[cell_name][pid] == self.__os_p_utils[cell_name].EXEC_SYS_CALL:
            self.lgr.debug('execve_callback %s %d (%s) already has EXEC_SYS_CALL in syscall_entries bail' % (cell_name, pid, comm))
            return
        if pid is None:
            self.lgr.debug('execve_callback %s with no pid' % cell_name)
            return
        self.lgr.debug('execve_callback %s %d (%s)' % (cell_name, pid, comm))
        ''' not needed because we now use the returnToUser hap? '''
        #self.__syscall_entries[cell_name][pid] = self.__os_p_utils[cell_name].EXEC_SYS_CALL
        '''
        tell the os_p_utils what function to call if it can't read program name 
        until a page is mapped
        '''
        program, args_list = self.__os_p_utils[cell_name].getProcArgsFromStack(pid, self.finishExecParams, cpu)
        if program is not None:
            #self.lgr.debug('cgcMonitor execve_callback from %s %d (%s), call finishExecParams program: %s' % (cell_name, pid, comm, program))
            self.finishExecParams(cpu, pid, program, args_list, cur_addr)
        else:
            if comm is not None:
                self.lgr.debug('execve_callback cell %s found no program, not yet mapped, should now be a callback to finishExecParams %d %s' % \
                    (cell_name, pid, comm))
            else:
                self.lgr.debug('execve_callback cell %s found no program, not yet mapped, should now be a callback to finishExecParams %d comm None' % (cell_name, pid))

    def syscall_exit_callback(self, cell_name, third, forth, memory):
        '''
        Invoked on Linux syscall_exit.  All Exec handling occurs in ret_callback
        CBs now hit this breakpoint, so don't delete EXEC from syscall_entries.
        ''' 
        #cell_name = self.getTopComponentName(cpu)
        cpu = SIM_current_processor()
        dumcpu, cur_addr, comm, pid = self.__os_p_utils[cell_name].getPinfo(cpu)
        frame = self.__os_p_utils[cell_name].frameFromStack(cpu)
        #self.lgr.debug( 'syscall_exit_callback got %d (%s) frame: %s' % (pid, comm, self.__os_p_utils[cell_name].stringFromFrame(frame)))
        call_num = None
        # TBD when mode hap removed for tracing, put this back, but no return?
        #if self.__tracing.returnTo(comm, pid):
        #    return
        try:
            call_num = self.__syscall_entries[cell_name][pid]
            ''' remove the entry for the syscall for which we are returning '''
            if not (self.isCB(comm) or self.isPoVcb(comm)) or call_num is not self.__os_p_utils[cell_name].EXEC_SYS_CALL:
                del self.__syscall_entries[cell_name][pid]
            else:
                self.lgr.debug('sysexit_callback found EXEC, not removed from syscall_entries for %d (%s)' % (pid, comm))
        except KeyError:
            return

        if comm not in self.__exempt_comms:
            self.recordOnReturn(frame, call_num, cell_name, cpu, pid, comm)
            self.lgr.debug( 'sysexit_callback got bck from recordOnReturn %d' % pid)

    def sysenter_exit_callback(self, cpu, third, forth, memory):
        '''
        Invoked on Linux sysenter_exit .  All Exec handling occurs in ret_callback
        CBs now hit this breakpoint, so don't delete EXEC from syscall_entries.
        ''' 
        cell_name = self.getTopComponentName(cpu)
        dumcpu, cur_addr, comm, pid = self.__os_p_utils[cell_name].getPinfo(cpu)
        frame = self.__os_p_utils[cell_name].frameFromStack(cpu)
        #self.lgr.debug( 'sysenter_exit_callback got %d (%s) frame: %s' % (pid, comm, self.__os_p_utils[cell_name].stringFromFrame(frame)))
        call_num = None
        # TBD when mode hap removed for tracing, put this back, but no return?
        #if self.__tracing.returnTo(comm, pid):
        #    return
        try:
            call_num = self.__syscall_entries[cell_name][pid]
            ''' remove the entry for the syscall for which we are returning '''
            if not self.isCB(comm) or call_num is not self.__os_p_utils[cell_name].EXEC_SYS_CALL:
                del self.__syscall_entries[cell_name][pid]
            else:
                self.lgr.debug('sysenter_callback found EXEC, not removed from syscall_entries')
        except KeyError:
            return

        if comm not in self.__exempt_comms:
            self.recordOnReturn(frame, call_num, cell_name, cpu, pid, comm)
            self.lgr.debug( 'sysenter_callback got bck from recordOnReturn %d' % pid)

    '''
        Record system call values when about to return from a system call
    '''
    def recordOnReturn(self, frame, call_num, cell_name, cpu,pid, comm):
        # success value in eax 
        retval = self.__os_p_utils[cell_name].mem_utils.getSigned(frame['eax'])
        #self.lgr.debug('userret call num %d retval of %d for %s:%d' % (call_num, retval, cell_name,pid))
        syscall_ok = True
        if self.isCB(comm) or (self.cfg.cfe and self.isPoV(pid, cell_name)):
            if retval is 0:
                if call_num is self.SYS_READ or call_num is self.SYS_WRITE:
                    syscall_ok = self.doTransmitReceive(frame, call_num, cpu, comm, cell_name, pid)
                elif call_num is self.SYS_RANDOM:
                    self.doRandom(frame, call_num, cpu, comm, cell_name, pid)
                elif call_num is self.SYS_ALLOCATE:
                    self.doAllocate(frame, call_num, cpu, comm, cell_name, pid)
                elif call_num is self.SYS_DEALLOCATE:
                    self.doDeallocate(frame, call_num, cpu, comm, cell_name, pid)
                elif call_num is self.SYS_FDWAIT:
                    self.doFdwait(frame, call_num, cpu, comm, cell_name, pid)
 
                else:
                    self.lgr.info('TBD return from %s:%d (%s) call#: %d frame: %s ' % (cell_name, pid, comm, call_num, self.__os_p_utils[cell_name].stringFromFrame(frame)))
          
            else:
                self.lgr.info('Error return from %s:%d (%s) call#: %d frame: %s error: %d ' % (cell_name,
                     pid, comm, call_num, self.__os_p_utils[cell_name].stringFromFrame(frame), retval))
                syscall_ok = False
            # mark cycles for tracking user space cycles
            self.__previous_pid_user_cycle[cell_name] = cpu.cycles
            #self.lgr.debug('recordOnReturn ret_callback set previous_pid_user_cycle to %x' % SIM_cycle_count(cpu))
            if self.__master_config.bail_on_failed_calls > 0: 
                if syscall_ok and not (self.isPoVcb(comm) and call_num is self.SYS_RANDOM) and not call_num == self.SYS_FDWAIT:
                    ''' reset error counter, unless it is a pov and call to random, ad-hoc avoidance of pov burning time or fdwait '''
                    self.__errored_syscalls[cell_name] = 0
                elif not syscall_ok:
                    self.__errored_syscalls[cell_name] += 1
                    self.lgr.info('recordOnReturn errored syscalls for %d (%s) is %d' % (pid, comm, self.__errored_syscalls[cell_name]))                    
                    if self.__errored_syscalls[cell_name] > self.__master_config.bail_on_failed_calls:
                        self.lgr.info('recordOnReturn found too many syscall failures, stop watching process %d (%s)' % (pid, comm))                    
                        self.addLogEvent(cell_name, pid, comm, forensicEvents.ERRORED_SYSCALLS, 'Too many syscall errors %d' % (self.__errored_syscalls[cell_name]))
                        self.updateLogs(comm, pid, cell_name, cpu)
                        self.__context_manager.cleanPID(cell_name, pid)
                        self.closeOutTrace(comm, pid, cell_name)
                        self.cleanupPid(cell_name, pid, comm)
                        seed = self.target_log.findSeed(pid, cell_name)
                        if seed in self.__pid_structs_to_clean:
                            self.__pid_structs_to_clean[seed].append(procInfo.procInfo(comm, cpu, pid))
                        else:
                            self.lgr.debug('recordOnReturn, did not find pid_structs_to_clean for seed %s' % seed)
                        self.__os_p_utils[cell_name].processExiting(cpu, force=True)
                        if pid in self.__watching[cell_name]:
                            self.__watching[cell_name].remove(pid)
           
        else:
             # not cgcos, TBD track interesting system calls more closely?
             self.lgr.info('recordOnReturn return from %s:%d (%s) frame: %s ' % (cell_name, 
                 pid, comm, self.__os_p_utils[cell_name].stringFromFrame(frame)))

        if self.log_sys_calls and comm == self.__master_config.trace_target and not self.isCB(comm):
            if call_num is self.__os_p_utils[cell_name].READ_SYSCALL:
                self.__call_log[cell_name][pid].doLinuxRead(frame, cpu)
            if call_num is self.__os_p_utils[cell_name].WRITE_SYSCALL:
                self.__call_log[cell_name][pid].doLinuxWrite(frame, cpu)
            if call_num is self.__os_p_utils[cell_name].BRK:
                self.__call_log[cell_name][pid].doLinuxBrk(frame, cpu)
            if call_num is self.__os_p_utils[cell_name].MMAP:
                self.__call_log[cell_name][pid].doLinuxMmap(frame, cpu)
            if call_num is self.__os_p_utils[cell_name].MUNMAP:
                self.__call_log[cell_name][pid].doLinuxUnMap(frame, cpu)
            if call_num is self.__os_p_utils[cell_name].SOCKET:
                self.__call_log[cell_name][pid].doLinuxSocket(frame, cpu)

        if comm is not None and comm == self.__master_config.taint_process:
            #if call_num is self.__os_p_utils[cell_name].READ_SYSCALL:
            #    self.__taint_manager.didRead(cpu, cell_name, pid, comm, frame['ecx'], frame['edx'])
            if self.__taint_manager is not None and call_num is self.__os_p_utils[cell_name].WRITE_SYSCALL:
                self.__taint_manager.didWrite(cpu, cell_name, pid, comm, frame['ecx'], frame['edx'])

        self.__keep_alive.resetKillCount()
           
    def r2UserCallback(self, pinfo):
        cell_name = self.getTopComponentName(pinfo.cpu)
        self.lgr.debug('in r2UserCallback %s %d (%s)' % (cell_name, pinfo.pid, pinfo.comm))
        if self.__master_config.watchUID(cell_name, pinfo.comm):
            self.lgr.debug('r2UserCallback watch UID %s:%d (%s)' % (cell_name, pinfo.pid, pinfo.comm))
            self.__watch_uid[cell_name].addPid(pinfo.pid, pinfo.comm, pinfo.cur_addr, pinfo.cpu)
        if not self.isIDS(pinfo.comm):
            ''' ids watch management tied to running of some replay. '''
            self.watchThisProcess(cell_name, pinfo.pid, pinfo.comm) 
        if self.isPoVcb(pinfo.comm) and self.__master_config.watchPlayer():
            self.__player_pid = pinfo.pid
        elif self.isCB(pinfo.comm):
           self.__pid_cycles[cell_name][pinfo.pid] = 0
           self.__pid_user_cycles[cell_name][pinfo.pid] = 0
           self.__previous_pid_cycle[cell_name] = pinfo.cpu.cycles
           self.__previous_pid_user_cycle[cell_name] = pinfo.cpu.cycles
           now = self.getWallSeconds(pinfo.cpu)
           self.__pid_wallclock_start[cell_name][pinfo.pid] = now
           self.lgr.debug('r2UserCallback start for %s:%d is %d' % (cell_name, pinfo.pid, now))
           self.lgr.debug('r2UserCallback set Init cycle counters and previous_pid_cycle for %s:%d (%s) to %x' % (cell_name, 
               pinfo.pid, pinfo.comm, self.__previous_pid_cycle[cell_name]))

        if self.__master_config.watchCalls(cell_name, pinfo.comm):
            self.lgr.debug('r2UserCallback init num_calls on %s for %d (%s)' % (cell_name, pinfo.pid, pinfo.comm))
            self.__num_calls[cell_name][pinfo.pid] = 1
        self.monitorForPid(cell_name, pinfo.pid, pinfo.comm, pinfo.cpu)
        self.doKernelSysCalls(pinfo.cpu, cell_name, pinfo.comm, pinfo.pid)
        #if self.isIDS(pinfo.comm):
        #    self.__mode_changed[cpu] = SIM_hap_add_callback_obj("Core_Mode_Change", pinfo.cpu, 0,
        #            self.modeChanged, pinfo)
 
    def ret_exec_callback(self, pinfo, third, forth, memory):
        cpu = SIM_current_processor()
        cell_name = self.getTopComponentName(cpu)
        dumcpu, cur_addr, comm, pid = self.__os_p_utils[cell_name].getPinfo(cpu)
        if pid == pinfo.pid:
            if cell_name not in self.__ret_exec_break or pid not in self.__ret_exec_break[cell_name]:
                self.lgr.error('ret_exec_callb ack %d (%s) pid or cell not in ret_exec_break') 
                return
            if self.__ret_exec_break[cell_name][pid] == None:
                self.lgr.debug('ret_exec_callback %d (%s) after hap deleted, ignore' % (pinfo.pid, pinfo.comm))
                return
            self.lgr.debug('ret_exec_callback %s:%d (%s) curaddr is %x cpu: %s' % (cell_name, pinfo.pid, pinfo.comm, cur_addr, str(cpu)))
            #self.lgr.debug('ret_exec_callback third: %s fourth %s, will delete breakpoint # %d hap # %d' % (third, forth, self.__ret_exec_break[cell_name][pid],
            #    self.__ret_exec_hap[cell_name][pid]))
            SIM_hap_delete_callback_id("Core_Breakpoint_Memop", self.__ret_exec_hap[cell_name][pid])
            SIM_delete_breakpoint(self.__ret_exec_break[cell_name][pid])
            del self.__ret_exec_break[cell_name][pid]
            del self.__ret_exec_hap[cell_name][pid]

            if ((self.isIDS(pinfo.comm) and self.__rules_file_name is not None)) or self.isCB(pinfo.comm) or (self.isPoVcb(pinfo.comm) and self.__master_config.watchPlayer()):
                self.lgr.debug('ret_exec_callback, do returnToUserHap')
                cpu_list = self.__cell_config.cell_cpu_list[cell_name]
                returnToUserHap.returnToUserHap(self, cpu, cpu_list, pinfo.pid, pinfo.comm, self.r2UserCallback, 
                    self.__os_p_utils[cell_name], self.is_monitor_running, self.lgr)
            elif self.isIDS(pinfo.comm) and self.__rules_file_name is None:
                self.lgr.debug('ret_exec_callback, ids, no rules do not monitor')
            

    '''
    Handle a return to user space.  In freeBSD, this handles all returns.
    In Linux, it is invoked when resume_userspace is hit.  But that is not always hit, so see sysexit_callback above
    Also handles unmapped eips, i.e., those we tried to set breakpoints on, but could not because they were not yet mapped.
    '''
    def ret_callback(self, cell_name, third, forth, memory):
        #cell_name = self.getTopComponentName(cpu)
        cpu = SIM_current_processor()
        if self.__watch_kernel.doingRop(cpu):
            self.__rop_pending[cell_name] = True
            self.__watch_kernel.undoRop(cpu)
        dumcpu, cur_addr, comm, pid = self.__os_p_utils[cell_name].getPinfo(cpu)
		
        if pid in self.__syscall_entries[cell_name]:
            call_num = self.__syscall_entries[cell_name][pid]
            #self.lgr.debug('ret_callback call_num %d' % call_num)
            if call_num is self.__os_p_utils[cell_name].EXEC_SYS_CALL:
                # update the comm
                comm = self.__os_p_utils[cell_name].updateComm(pid, cpu)
        #self.lgr.debug('ret_callback %s:%d (%s) curaddr is %x cpu: %s' % (cell_name, pid, comm, cur_addr, str(cpu)))
        if pid in self.__ret_exec_break[cell_name] and self.__ret_exec_break[cell_name] is not None:
            ''' simics does not always hit all haps if breakpoints are repeated, e.g., linear & phys '''
            self.lgr.debug('ret_callback instead of ret_exec_callback, reroute, simics damage?')
            self.ret_exec_callback(procInfo.procInfo(comm, cpu, pid), third, forth, memory)
            return

        if not self.__master_config.watchCalls(cell_name, comm) and not self.isPlayer(comm) \
                and self.__code_coverage is None: 
            # we are only here to watch the player until it starts consuming user data, or to update a comm?
            if pid in self.__syscall_entries[cell_name]:
                del self.__syscall_entries[cell_name][pid]
            return

        if self.__tracing.returnTo(comm, pid):
            return
        if pid in self.__unmapped_eips[cell_name]:
            # this process had a breakpoint to set on an eip that was not yet mapped.
            eip = self.__unmapped_eips[cell_name][pid]
            phys_block = cpu.iface.processor_info.logical_to_physical(eip, Sim_Access_Read)
            if phys_block.address != 0:
                # eip is now mapped.
                if self.isPlayer(comm) and self.__player_hap is None:
                    #self.lgr.debug('ret_callback player, unmapped eip %x' % eip)
                    if eip == self.__player_offset:
                        self.setPlayerBreak(phys_block.address, cell_name, pid) 
                        del self.__unmapped_eips[cell_name][pid]
                        if not self.__master_config.watchCalls(cell_name, comm): 
                            # not watching syscalls, here just to do the above, remove the callback for user space returns
                            self.__hap_manager.clearKernelSysCalls(cell_name, pid)
                    return
                # TBD remove False if switched back to use of physical breakpoints for user space rop
                if False and self.watchRop(cell_name, comm, pid):
                    if self.isCB(comm):
                        self.lgr.debug('ret_callback add rop cop break range resulting from page fault, pid: %s:%d address: %x physical: %x' % \
                            (cell_name, pid, eip, phys_block.address))
                        self.__rop_cop.ropCopBreakRange(cell_name, pid, eip, 1, cpu, comm)
                        
                    else:
                        elf_text = int(self.__prog_sections[cell_name][pid].get("elf", "text"), 16)
                        elf_text_size = int(self.__prog_sections[cell_name][pid].get("elf", "text_size"), 16)
                        if (eip >= elf_text and eip <= (elf_text + elf_text_size)) or not self.isPlayer(comm):
                        # TBD avoid setting rop on player library code, it hangs the system
                            self.lgr.debug('ret_callback add rop cop break range for pov resulting from page fault, pid: %s:%d address: %x physical: %x' % \
                                (cell_name, pid, eip, phys_block.address))
                            self.__rop_cop.ropCopBreakRange(cell_name, pid, eip, 1, cpu, comm)
                if self.__master_config.code_coverage:
                    self.lgr.debug('updating code coverage breaks for %s' % comm)
                    self.__code_coverage.updateBreaks(comm, cpu, pid)
                del self.__unmapped_eips[cell_name][pid]
                del self.__return_to_cycle[cell_name][pid]
                self.__previous_pid_user_cycle[cell_name] = cpu.cycles
                self.lgr.debug('ret_callback return from unmapped code in %s, set previous_pid_user_cycle to %x' % (comm, cpu.cycles))
            elif not self.isPlayer(comm):
                self.lgr.debug('in ret_callback with unmapped eip for %s:%d, eip %x is still unmapped' % (cell_name, pid, eip))
            return

        server_name = self.getServerName(cell_name)

        ''' see if we are trying to re-init after a debug session '''
        if self.__context_manager.getDebugging():
           debug_pid, dumb, debug_cpu = self.__context_manager.getDebugPid() 
           if debug_cpu == cpu and debug_pid == pid:
               self.lgr.error('In return during debug')
               #TBD what to do here?
               #SIM_run_alone(self.install_stop_hap, None)
               #SIM_break_simulation('Doing reinit after debug')
           return

        ''' Don't monitor sh, scp, etc '''
        if comm in self.__exempt_comms:
           return


        #if comm != 'replay_master':
        #   return

        #self.lgr.debug('#######ret_callback %s:%d (%s) curaddr is %x' % (cell_name, pid, comm, cur_addr))
        if not self.__cell_config.os_type[cell_name].startswith(osUtils.LINUX):
            frame = self.__os_p_utils[cell_name].frameFromThread(cpu)
        else:
            frame = self.__os_p_utils[cell_name].frameFromStack(cpu)
        ''' get the syscall number recorded on entry for this pid 
        '''
        call_num = None
        try:
            call_num = self.__syscall_entries[cell_name][pid]
            ''' remove the entry for the syscall for which we are returning '''
            del self.__syscall_entries[cell_name][pid]
        except KeyError:
           if pid in self.__watching[cell_name]:
               # are we expecting a return after a page fixup?
               if not self.__page_faults.expecting(cell_name, pid):
                   self.__last_ret_eip[cell_name][pid] = frame['eip']
                   #self.lgr.info('unrelated user return without call for pid %s:%d (%s), last_ret_eip to %x' % \
                   #    (cell_name, pid, comm, frame['eip']))
                   self.__previous_pid_user_cycle[cell_name] = cpu.cycles
                   ''' TBD better basis for knowing first return to user space ? '''
                   '''
                   if self.isCB(comm) and pid not in self.__pid_user_cycles[cpu]:
                       self.__pid_cycles[cpu][pid] = 0
                       self.__pid_user_cycles[cpu][pid] = 0
                       self.__previous_pid_cycle[cpu] = cpu.cycles
                       self.__previous_pid_user_cycle[cpu] = cpu.cycles
                       now = self.getWallSeconds(cpu)
                       self.__pid_wallclock_start[cpu][pid] = now
                       self.lgr.debug('wallclock start for %s:%d is %d' % (cell_name, pid, now))
                       self.lgr.debug('ret_callback set Init cycle counters and previous_pid_cycle for %s:%d (%s) to %x' % (cell_name, 
                           pid, comm, self.__previous_pid_cycle[cpu]))
                   '''
                   self.lgr.debug('ret_callback unknown (reschedule?) %s %d (%s) set previous_pid_user_cycle to %x' % (cell_name, pid, comm, cpu.cycles))
                           
           return

        isNetworkHost = self.__cell_config.cells[cell_name] == 'network host'
        if call_num is self.__os_p_utils[cell_name].EXEC_SYS_CALL:
            self.__first_eip[cell_name][pid] = frame['eip']
            if pid not in self.__watching[cell_name] \
                     and not self.watchProcess(cell_name, cpu, cur_addr, comm, pid):
                # not interested
                return
            #elif isNetworkHost:
            elif self.isCB(comm):
                eip = self.getEIP(cpu)
                self.lgr.debug('ret_callback exec return eip is %x for %s:%d (%s) frame eip is %x cycle: 0x%x' % (eip, cell_name,pid,
                     comm, frame['eip'], cpu.cycles))
                self.monitorForPid(cell_name, pid, comm, cpu)
            else:
                if self.isPlayer(comm):
                    # starting the player, get the pov file name stored back when the replay
                    # process was created
                    # TBD why entry zero ???
                    '''
                    fname = self.__replay_file_name
                    if fname is None:
                        SIM_break_simulation('could not get thrower arguments')
                        return
                    self.lgr.debug('ret_callback exec return for %s:%d (%s) throw file: %s' % \
                           (cell_name,pid, comm, fname))
                    root, ext = os.path.splitext(fname)
                    self.target_log.newReplay(os.path.basename(root))
                    '''
                    # MFTX
                    eip = self.getEIP(cpu)
                    self.lgr.debug('ret_callback player exec return eip is %x for %s:%d (%s)' % (eip, cell_name,pid,
                     comm))
                    if self.cfg.cfe:
                        if not self.isPoller(comm):
                            self.monitorForPid(cell_name, pid, comm, cpu)
                        else:
                            return
                    else:
                        phys_block = cpu.iface.processor_info.logical_to_physical(self.__player_offset, Sim_Access_Read)
                        if phys_block.address != 0:
                            self.setPlayerBreak(phys_block.address, cell_name, pid)
                        else:
                            # code containing doDoc not mapped, catch it in ret_callback
                            self.lgr.debug('player offset %x not yet mapped, add to unmapped eips' % self.__player_offset)
                            self.__unmapped_eips[cell_name][pid] = self.__player_offset
            
            # NOTE returns above, only watch throwers and CBs
            self.lgr.debug('ret_callback now watching pid %s:%d (%s)' % (cell_name, pid, comm))
            if self.isCB(comm) and pid not in self.__prog_sections[cell_name]:
                self.lgr.error('no program sections for %s:%d (%s), fatal. ' % (cell_name, 
                   pid, comm))
                SIM_break_simulation('did not find program sections for %s' % comm)
                return
            if self.log_sys_calls and pid in self.__call_log[cell_name]:
                self.__call_log[cell_name][pid].execReturn(frame, cpu, self.__prog_sections[cell_name][pid])

        self.recordOnReturn(frame, call_num, cell_name, cpu, pid, comm)
        #self.lgr.debug('ret_callback back from recordOnReturn pid %s:%d (%s)' % (cell_name, pid, comm))

    '''
        Set break at point at which player starts to consume user data
    ''' 
    def setPlayerBreak(self, address, cell_name, pid):   
        #cell = self.__cell_config.cell_context[cell_name]
        cpu = self.__cell_config.cpuFromCell(cell_name)
        cell = cpu.physical_memory
        self.lgr.debug('setPlayerBreak set break at %x' % address)
        self.__player_break = SIM_breakpoint(cell, Sim_Break_Physical, Sim_Access_Execute, address, 1, 0)
        #player_break = SIM_breakpoint(cell, Sim_Break_Linear, Sim_Access_Execute, 
        #    self.__player_offset, 1, 0)
        if self.__player_break is None:
            print 'player break is none\n'
            self.lgr.critical('setPlayerBreak player break is none for pid %d' % pid)
            return 
        self.__player_hap = SIM_hap_add_callback_index("Core_Breakpoint_Memop", 
             self.player_ready_callback, pid, self.__player_break)
   
        self.lgr.debug('setPlayerBreak pid: %d player_break is %d replay: %s' % \
             (pid, self.__player_break, self.__replay_file_name)['some_poller'])

    ''' TBD hit by linux IPC signals, used to init monitoring of the player '''
    # REMOVE, no longer used
    def sig2_callback(self, cpu, third, forth, fifth):
        cell_name = self.getTopComponentName(cpu)
        dumcpu, cur_addr, comm, pid = self.__os_p_utils[cell_name].getPinfo(cpu)
        sig_val = self.__os_p_utils[cell_name].mem_utils.getRegValue(cpu, 'eax')
        #self.lgr.debug('sig2_callback saw %d for %s:%d (%s)' % (sig_val, cell_name, pid, comm))
        if not self.watchProcess(cell_name, cpu, cur_addr, comm, pid):
           return
        self.lgr.debug('sig2_callback saw signal %d from %d (%s), ignore' % (sig_val, pid, comm))
        return
        if sig_val == self.__os_p_utils[cell_name].REPLAY_USER_SIG:
            # Assume player got signal from parent, commence monitoring
            comm = self.__os_p_utils[cell_name].updateComm(pid, cpu)
            self.lgr.debug('sig2_callback %s:%d (%s) thinks player got SIG from from parent' % \
               (cell_name, pid, comm))
            self.watchThisProcess(cell_name, pid, comm) 
            self.monitorForPid(cell_name, pid, comm, cpu)
            fname = self.__replay_file_name['some_poller']
            if fname is None:
                self.lgr.error('could not get thrower arguments')
                SIM_break_simulation('could not get thrower arguments')
                return
            self.lgr.debug('ret_callback exec return for %s:%d (%s) throw file: %s' % \
                   (cell_name,pid, comm, fname))
            root, ext = os.path.splitext(fname)
            self.target_log.newReplay(os.path.basename(root))

    def getSignalCycle(self):
        return self.__signal_cycle

    def signalCleanup(self, comm, pid, cell_name, cpu):
        self.lgr.debug('signalCleanup %s %d (%s)' % (cell_name, pid, comm))
        self.__context_manager.cleanPID(cell_name, pid)
        self.closeOutTrace(comm, pid, cell_name)

        '''exiting process.  clean up haps, breakpoints and dictionary entries'''
        self.cleanupPid(cell_name, pid, comm)
        self.cleanPidStructs(cell_name, pid)
        if self.isPlayer(comm):
            self.__player_pid = None
        elif self.isIDS(comm):
            self.cleanIDS()

    def cleanIDS(self):
        if self.__ids_cell_name is not None and len(self.__ids_pid)>0:
            self.__os_p_utils[self.__ids_cell_name].clearPinfo()
            for pid in self.__ids_pid:
                self.lgr.debug('cleanIDS clearPinfo & cleanup for ids %s %d' % (self.__ids_cell_name, pid))
                self.cleanupPid(self.__ids_cell_name, pid, "IDS")
                if pid in self.__watching[self.__ids_cell_name]:
                    self.__watching[self.__ids_cell_name].remove(pid)
            self.__ids_pid = []
            self.__ids_cell_name = None

    def doExitCallback(self, cell_name, third, forth, fifth):
        #cell_name = self.getTopComponentName(cpu)
        cpu = SIM_current_processor()
        dumcpu, cur_addr, comm, pid = self.__os_p_utils[cell_name].getPinfo(cpu)
        if dumcpu is None:
            self.lgr.debug('doExitCallback after pinfo cleared on %s' % cell_name)
            return
        if pid == self.__cfe_poller_pid:
            esp = self.__os_p_utils[cell_name].mem_utils.getRegValue(cpu, 'esp')
            param = esp + 2*self.__mem_utils[cell_name].WORD_SIZE
            exit_code = self.__mem_utils[cell_name].readWord32(cpu, param)
            if exit_code != 0:
                self.lgr.debug('doExitCallback for cfe_poller %d %s exit_code %d' % (pid, comm, exit_code))
                self.target_log.appendLog('poll_fail', '%d' % exit_code, comm, pid, cell_name)
            self.__cfe_poller_pid = None
            if  self.target_log.doneItem(self.__master_config.stopOnSomething(), False, True, cell_name, pid, comm):
                self.closeOutProcess(pid, cell_name)
            return
        self.lgr.debug('doExitCallback %s %d (%s) ' % (cell_name, pid, comm))
        #if pid not in self.__watching[cell_name]:
        #    #self.lgr.debug('doExitCallback, not watching %d on %s' % (pid, cell_name))
        #    return
        if comm is not None:
            if pid == self.__replay_pid or (self.cfg.cfe and self.isPoVcb(comm) and self.__player_pid is not None):
                self.lgr.debug('doExitCallback for replay (or pov) %s %d (%s) ' % (cell_name, pid, comm))
                if self.__player_pid is not None:
                    self.signalCleanup(self.__master_config.player_name, self.__player_pid, cell_name, cpu)
                # do the player's "doneItem" call here since player may have died before all CBs were created
                if  self.__master_config.watchPlayer() and self.target_log.doneItem(self.__master_config.stopOnSomething(), False, True, cell_name, pid, comm):
                    self.closeOutProcess(pid, cell_name)
                    self.__tracing.closeTrace(pid, cell_name)
                    if pid in self.__watching[cell_name]:
                        self.lgr.debug('doExitCallback replay or POV %d %s checked doneItem' % (pid, comm))
                        self.cleanupPid(cell_name, pid, comm)
                        self.__watching[cell_name].remove(pid)
                    self.cleanWaitingPidStructs(pid, cell_name)
                    self.cleanWaitingPidContexts(pid, cell_name)
                    self.__other_faults.newCB()
                if not self.cfg.cfe:
                    self.target_log.replayExits(pid, cell_name)
                self.__os_p_utils[cell_name].clearPinfo()
            elif pid == self.__manager_pid:
                esp = self.__os_p_utils[cell_name].mem_utils.getRegValue(cpu, 'esp')
                param = esp + self.__mem_utils[cell_name].WORD_SIZE
                exit_code = self.__mem_utils[cell_name].readWord32(cpu, param)
                self.lgr.debug('doExitCallback for manager %d %s exit_code %d' % (pid, comm, exit_code))
                #self.watching_current_syscalls[cell_name] = self.__hap_manager.clearKernelSysCalls(cell_name)
                self.__hap_manager.clearKernelSysCalls(cell_name, pid)
                self.cleanIDS()
            elif self.cfg.cfe and self.isCB(comm):
                #esp = self.__os_p_utils[cell_name].mem_utils.getRegValue(cpu, 'esp')
                #phys_block = cpu.iface.processor_info.logical_to_physical(esp, Sim_Access_Read)
                #ret_adr = SIM_read_phys_memory(cpu, phys_block.address, self.__mem_utils[cell_name].WORD_SIZE)
                #self.lgr.debug('doExitCallback for CB %d %s ret_adr is 0x%x' % (pid, comm, ret_adr))
                self.lgr.debug('doExitCallback for CB %d %s' % (pid, comm))
                if pid in self.__watching[cell_name]:
                    self.lgr.debug('doExitCallback for CB %d %s check doneItem' % (pid, comm))
                    self.cleanupPid(cell_name, pid, comm)
                    self.__watching[cell_name].remove(pid)
                    if self.target_log.doneItem(self.__master_config.stopOnSomething(), False, False, cell_name, pid, comm):
                        self.__keep_alive.cancelEvent()
                else:
                    self.lgr.debug('doExitCallback for CB %d %s was not watching the pid' % (pid, comm))

                dbi = debugInfo.debugInfo(self.__context_manager, self.__hap_manager, 
                    pid, comm, None, cgcEvents.CGCEventType.signal, None,
                    'dum cb', 'dum pov', cell_name, cpu, None, None, self.lgr, None, auto_analysis=self.__master_config.auto_analysis)
                dbi.cycle, dum = self.__other_faults.getCycles(cell_name, pid)
                if dbi.cycle is None:
                    self.lgr.debug('doExitCallback, cycle is none, why am I here, should hap be gone?')
                    return
                dbi.command = 'skip-to cycle = %d ' % dbi.cycle

                if not self.__master_config.watchSysCalls():
                    self.updateLogs(comm, pid, cell_name, cpu)
                    self.cleanupPid(cell_name, pid, comm)
                self.__os_p_utils[cell_name].clearPinfo()
                ''' TOGGLE to enter debugger on process exit.   TBD, make it a package boolean via oneThrow argument '''
                if False:
                        #dbi.command = 'reverse-to cycle = %d ' % dbi.cycle
                        self.lgr.debug('in sig_callback sigsegv for pid: %s:%d going to reverse to cycle %x which is NOT 1 cycle prior to recorded' % (cell_name, pid, dbi.cycle ))
                        print 'would do %s' % dbi.command
                        self.lgr.debug('call start debugging to set a stop-hap with command: %s and then break_simulation' % dbi.command)
                        debugSignal.debugSignal(self, dbi, self.__param[cell_name], self.__os_p_utils[cell_name], self.__bookmarks)
       	                SIM_break_simulation('stopping in do_exit')

                #self.watching_current_syscalls[cpu] = self.__hap_manager.clearKernelSysCalls(cell_name)
                self.__hap_manager.clearKernelSysCalls(cell_name, pid)
                self.cleanIDS()
            elif self.cfg.cfe and ((pid not in self.__server_pid[cell_name]) and comm == 'launcher'):
                ''' launcher post fork pre-exec failure, likely TLV '''
                esp = self.__os_p_utils[cell_name].mem_utils.getRegValue(cpu, 'esp')
                param = esp + 2*self.__mem_utils[cell_name].WORD_SIZE
                exit_code = self.__mem_utils[cell_name].readWord32(cpu, param)
                self.lgr.debug('doExitCallback for launcher %d %s exit_code %d' % (pid, comm, exit_code))
                if exit_code != 0:
                    self.lgr.critical('doExitCallback for launcher %d %s exit_code %d' % (pid, comm, exit_code))
                    if not self.target_log.appendLog('launcher_fail', '%d' % exit_code, comm, pid, cell_name):
                        ''' was not replay recorded.  so we don't know which replay node to mark as done. '''
                        self.target_log.launcherExitsNoReplay(cell_name, pid, comm)
                    else:
                        event_type = forensicEvents.LAUNCH_ERROR
                        self.addLogEvent(cell_name, pid, comm, event_type, 'launcher post fork pre-exec failure TLV?')
                    self.closeOutProcess(pid, cell_name)
            return
            
    def sig_seccomp_callback(self, cpu, third, forth, fifth):
        cell_name = self.getTopComponentName(cpu)
        dumcpu, cur_addr, comm, pid = self.__os_p_utils[cell_name].getPinfo(cpu)
        if comm is not None and (self.isPlayer(comm) or self.isReplay(comm) or self.isCB(comm)):
            esp = self.__os_p_utils[cell_name].mem_utils.getRegValue(cpu, 'esp')
            phys_block = cpu.iface.processor_info.logical_to_physical(esp, Sim_Access_Read)
            ret_adr = SIM_read_phys_memory(cpu, phys_block.address, self.__mem_utils[cell_name].WORD_SIZE)
            if not self.__kernel_info[cell_name].isExit(ret_adr):
                event_type = forensicEvents.USER_SIGOTHER
                self.addLogEvent(cell_name, pid, comm, event_type, 'sig_seccomp_callback event ')
                self.lgr.critical('sig_seccomp send sigsys called from %d (%s) ret_adr is %x' % (pid, comm, ret_adr))
                #SIM_break_simulation('debug it')

    '''
    Report a signal
    '''
    def sig_callback(self, cell_name, third, forth, fifth):
        #stop_for = [1, 2, 3, 4, 6, 8, 9, 11, 13, 15]
        #cell_name = self.getTopComponentName(cpu)
        cpu = SIM_current_processor()
        stop_for = self.__os_p_utils[cell_name].getStopFor()
        dumcpu, cur_addr, comm, pid = self.__os_p_utils[cell_name].getPinfo(cpu)
        #self.lgr.info('sig_callback for %s:%d (%s) frame at postsig in kerne' % \
        #     (cell_name, pid, comm))
        if not self.isReplay(comm) and not self.isWatching(cell_name, pid):
            return

        #print("got signal breakbreak %s %s %s" % (type(third), type(forth), type(fifth)))
        if self.__context_manager.getDebugging():
           return

        # TBD do not set bookmarks via run alone!
        #if self.__master_config.stop_on_signal:
        #    # so we can return to the scene of the signal to expidite exit when done w/ analysis
        self.__signal_cycle = cpu.cycles
        sig_val = None
        ret_adr = 0
        if self.__cell_config.os_type[cell_name] == osUtils.FREE_BSD64:
            sig_val = self.__os_p_utils[cell_name].mem_utils.getRegValue(cpu, 'edi')
        else:
       	    # Read the first parameter on the stack, this is sig for bsd and linux do_exit
            esp = self.__os_p_utils[cell_name].mem_utils.getRegValue(cpu, 'esp')
            phys_block = cpu.iface.processor_info.logical_to_physical(esp, Sim_Access_Read)
            #sig_val = SIM_read_phys_memory(cpu, phys_block.address+self.__mem_utils[cell_name].WORD_SIZE, self.__mem_utils[cell_name].WORD_SIZE)
            sig_val = SIM_read_phys_memory(cpu, phys_block.address+self.__mem_utils[cell_name].WORD_SIZE, 4)
            # ret_adr only used for linux, TBD remove for bsd
            ret_adr = SIM_read_phys_memory(cpu, phys_block.address, self.__mem_utils[cell_name].WORD_SIZE)
        retval = self.__os_p_utils[cell_name].mem_utils.getSigned(sig_val)
        #print 'sig_val is %d' % sig_val
        self.lgr.info('sig_callback for %s:%d (%s) signal: %d  ret_adr is %x in do_exit in kernel' % \
             (cell_name, pid, comm, sig_val, ret_adr))
        #if self.isReplay(comm):
        if pid == self.__replay_pid:
            if self.__kernel_info[cell_name].isSysExit(ret_adr):
                self.lgr.debug('isReplay signal called from from sys_exit, val was %d,   cb failed validation?' % sig_val)
                self.target_log.replayExits(pid, cell_name)
            else:
                self.lgr.debug('signal caught in %d (%s), may just be postsig garbage?' % (pid, comm))
                return
        elif self.isReplay(comm):
            if self.__kernel_info[cell_name].isSysExit(ret_adr):
                self.lgr.debug('some child of replay (the manager?) entered do_signal from sys_exit, pid %d ' % pid)


        if pid in self.__pid_wallclock_start[cell_name]:
            now =  self.getWallSeconds(cpu)
            wallclock_duration = now - self.__pid_wallclock_start[cell_name][pid]
            self.lgr.debug('wallclock end for %s:%d is %d' % (cell_name, pid, now))
            self.lgr.debug('process ran for %.2f seconds' % wallclock_duration)

        ''' is this a process exit? '''
        # TBD, hack based on observation that syscall exists seem to have do_group_exit's (or related) first address as their ret?
        if not self.__master_config.watchSysCalls() and self.__kernel_info[cell_name].isSysExit(ret_adr) and (self.isCB(comm) or self.isPlayer(comm)):
        #if self.__kernel_info.isExit(ret_adr) and (self.isCB(comm) or self.isPlayer(comm)):
            self.lgr.debug('sig_callback signal %d (garbage, ignore),  not watching syscalls, so this seems to be a process exit' % sig_val)
            self.updateLogs(comm, pid, cell_name, cpu)
            self.signalCleanup(comm, pid, cell_name, cpu)
            if self.isPoVcb(comm):
                if  self.__master_config.watchPlayer() and self.target_log.doneItem(self.__master_config.stopOnSomething(), False, True, cell_name, pid, comm):
                    self.closeOutProcess(pid, cell_name)
                    self.__tracing.closeTrace(pid, cell_name)
                    self.cleanWaitingPidStructs(pid, cell_name)
                    self.cleanWaitingPidContexts(pid, cell_name)
                    self.__other_faults.newCB()
            return

        elif self.isPlayer(comm) and self.__kernel_info[cell_name].isExit(ret_adr):
            # TBD fix, should catch & report player signals
            #self.lgr.debug('signal from player %d, signal number may be nonsense, handle exit' % sig_val)
            self.lgr.debug('signal from player %d, part of an exit, signal number may be nonsense, assume exiting' % sig_val)
            self.updateLogs(comm, pid, cell_name, cpu)
            self.signalCleanup(comm, pid, cell_name, cpu)
            return
        elif self.isReplay(comm):
            self.lgr.debug('signal from %s %d (%s), ignore and see what else happens %x' % (cell_name, pid, comm, sig_val))
            return
        elif sig_val in stop_for or self.isCB(comm) or self.isPoVcb(comm) or comm == self.__master_config.trace_target \
         or (sig_val == 0 and self.isPlayer(comm)):
            if self.__kernel_info[cell_name].isSysExit(ret_adr) or (self.__kernel_info[cell_name].isExit(ret_adr) and self.isPlayer(comm)):
                # TBD why would a system call not be detected prior to this?
                if self.__hap_manager.pidHasEntries(cell_name, pid):
                    self.lgr.debug('signal called from sys_exit, exit value was %d,   ignoring, assume normal exit?' % sig_val)
                    self.updateLogs(comm, pid, cell_name, cpu)
                    self.signalCleanup(comm, pid, cell_name, cpu)
                    return
                else:
                    self.lgr.debug('signal, hap manager indicates process already cleaned up, just more sig processing of a dying proc')
                    return
            dum_calls = self.__master_config.watchSysCalls()
            frame = self.__os_p_utils[cell_name].frameFromThread(cpu)
            text_frame = self.__os_p_utils[cell_name].stringFromFrame(frame)
	    self.lgr.info('In sig_callback(in kernel, in postsig or do_exit function), sig %d issued to %s:%d (%s) frame: %s watching calls: %r' % \
                  (sig_val, cell_name, pid, comm, text_frame, dum_calls))
            ''' record process exit information in the monitoring log, ignore sigkill ''' 
            #if not ((self.isPlayer(comm) or self.isReplay(comm)) and sig_val == self.__os_p_utils[cell_name].SIGKILL):
            negotiate_result = None
            if sig_val == self.__os_p_utils[cell_name].SIGKILL:
                if self.isReplay(comm):
                    # did not expect replay to get this signal, note error in log
                    self.lgr.debug('signal %d in %d (%s) at %x' % (sig_val, pid, comm, frame['eip'])) 
                    return 
            elif sig_val == self.__os_p_utils[cell_name].SIGINT and (self.isPlayer(comm) or self.isIDS(comm)):
                self.lgr.debug('signal %d in %d (%s) at %x, interrupt?, continue' % (sig_val, pid, comm, frame['eip'])) 
                return 
            elif sig_val == self.__os_p_utils[cell_name].SIGHUP and self.isIDS(comm):
                self.lgr.debug('signal %d in %d (%s) at %x, sighup, exit' % (sig_val, pid, comm, frame['eip'])) 
                self.signalCleanup(comm, pid, cell_name, cpu)
                return 
            else:
                if sig_val != 0 and sig_val != self.__os_p_utils[cell_name].SIGUSR1:
                    event_type = self.eventTypeFromSignal(sig_val, comm, cell_name)
                    self.addLogEvent(cell_name, pid, comm, event_type, 'Signal %d at eip: %x ' % \
                       (sig_val, frame['eip']))
                    if sig_val != self.__os_p_utils[cell_name].SIGALRM:
                        negotiate_result = self.__negotiate.checkType1(frame, pid, cell_name)

            force_closeout_process = False

            thrower_gone = self.updateLogs(comm, pid, cell_name, cpu, debug_event=True, do_done_item=True, force=force_closeout_process)
            
            #SIM_break_simulation('debug')
            ''' are we configured to do analysis? '''
            if self.__master_config.stop_on_signal and sig_val != self.__os_p_utils[cell_name].SIGALRM:
              self.__tracing.closeTrace(pid, cell_name)
              seed = self.target_log.findSeed(pid, cell_name)
              is_type_2 = self.__negotiate.isType2(seed)
              ''' if type 2, may need to keep running after segv to wait for pov to report to negotiator '''
              ''' stop here if thrower is gone, (or not type 2) or not auto analysis '''
              ''' TOGGLE '''
              #if True or not is_type_2: 
              #if not is_type_2: 
              if thrower_gone or not self.__master_config.auto_analysis or not is_type_2: 
                '''
                See if we hit the page fault as part of memory monitoring.  
                Delete the hap, & breakpoint.  New hap set in debugging
                '''
                #self.__page_faults.cleanPid(cell_name, cpu, pid)
                        
                ''' 
                Run the simulation backwards. 
                The SIM_break_simulation function is asychronous to this HAP.  So we
                add another HAP that gets invoked when the simulation actually
                stops.  
                ''' 
                ''' collect parameters to pass to the haps, include eip of segv '''
                self.lgr.debug('generate debugInfo, auto_analysis is %r' % self.__master_config.auto_analysis)
                dbi = debugInfo.debugInfo(self.__context_manager, self.__hap_manager, 
                    pid, comm, None, cgcEvents.CGCEventType.signal, frame['eip'], 
                    'dum cb', 'dum pov', cell_name, cpu, frame, sig_val, self.lgr, negotiate_result, auto_analysis=self.__master_config.auto_analysis)
                self.lgr.debug('generate debugInfo, auto_analysis is %r in dbi %r' % (self.__master_config.auto_analysis, dbi.auto_analysis))
                if pid in self.__unmapped_eips[cell_name]:
                    '''
                    Signal resulted from a bad eip.  When entering debug, first return to the cycle
                    at which the fault occurred.
                    '''
                    self.lgr.debug('in sig_callback for pid: %s:%d with unmapped eip: %x, we have met the enemy' % \
                         (cell_name, pid, self.__unmapped_eips[cell_name][pid]))
                    dbi.cycle = self.__return_to_cycle[cell_name][pid].cycles
                    dbi.command = 'skip-to cycle = %d ' % dbi.cycle
                    #dbi.command = 'reverse-to cycle = %d ' % dbi.cycle
                    dbi.unmapped_eip = True
                    self.lgr.debug('will reverse to cycle %x which is IS the recorded, so rev one from there (set dbi.unmapped_eip)' % dbi.cycle)
                elif sig_val == self.__os_p_utils[cell_name].SIGSEGV:
                    #TBD assuming segv?
                    if pid not in self.__return_to_cycle[cell_name]:
                        self.lgr.error('sig_callback missing return_to_cycle for pid %d, cannot debug signals if not monitoring process' % (pid))
                        print('sig_callback missing return_to_cycle for pid %d, cannot debug signals if not monitoring process' % (pid))
                        return
                    #dbi.cycle = self.__return_to_cycle[cell_name][pid] -1
                    dbi.cycle = self.__return_to_cycle[cell_name][pid].cycles
                    if pid in self.__syscall_entries[cell_name]:
                        self.lgr.debug("sig_callback, was a syscall")
                        dbi.cycle, dum = self.__other_faults.getCycles(cell_name, pid)
                    dbi.command = 'skip-to cycle = %d ' % dbi.cycle
                    #dbi.command = 'reverse-to cycle = %d ' % dbi.cycle
                    self.lgr.debug('in sig_callback sigsegv for pid: %s:%d going to reverse to cycle %x which is NOT 1 cycle prior to recorded' % (cell_name, pid, dbi.cycle ))
                    print 'would do %s' % dbi.command
                self.lgr.debug('call start debugging to set a stop-hap with command: %s and then break_simulation' % dbi.command)
                self.cleanupAll()
                if not is_type_2:
                    self.__bookmarks.clearOtherBookmarks('protected_memory:')
                    self.lgr.debug('cleared other bookmarks')
                debugSignal.debugSignal(self, dbi, self.__param[cell_name], self.__os_p_utils[cell_name], self.__bookmarks)
	        SIM_break_simulation('stopping in sig_callback')

              elif self.__master_config.auto_analysis and is_type_2:
                  ''' we don't know what/where things were when fault happened '''
                  cycle = cpu.cycles
                  bm='SEGV of %s at 0x%x' % (comm, frame['eip'])
                  self.setDebugBookmark(bm, cpu=cpu, cycles=cycle)

            else:
                ''' set flag to supress side effects of impending crash, e.g., core dump reading of protected 
                    memory '''
                self.__pending_signals[cell_name].append(pid)
                self.cleanupPid(cell_name, pid, comm)
                self.cleanPidStructs(cell_name, pid)
                self.__os_p_utils[cell_name].processExiting(cpu)
                self.lgr.debug("Cleaned up for pid %s:%d, we are done with that pid." % (cell_name, pid))
                self.closeOutTrace(comm, pid, cell_name)

    def closeOutTrace(self, comm, pid, cell_name):
      # TBD this is broken for multi-binary CB's
      if False:
        if self.isCB(comm) and self.__tracing.isTraced(comm, pid):
            seed = self.target_log.findSeed(pid, cell_name)
            replay = os.path.basename(self.__replay_file_name[seed])
            self.lgr.debug('call copyTrace for %s' % replay)
            self.__tracing.copyTrace(replay)

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

    def recordReturnToCycle(self, cpu, cell_name, pid):
       cpl = memUtils.getCPL(cpu)
       eip = self.getEIP(cpu)
       if cpl == 0:
           precall_cycle, dum = self.__other_faults.getCycles(cell_name, pid)
           if precall_cycle is not None:
  
               self.__return_to_cycle[cell_name][pid] = self.cycleRecord(precall_cycle, None, eip)
               #self.lgr.debug('recordReturnToCycle %s %d is in kernel, use pre-call cycle instead: 0x%x' % (cell_name, pid, precall_cycle))
           else:
               self.lgr.error('recordReturnToCycle, in kernel but no precall_cycle %s %d' % (cell_name, pid))
       else:
           cycle = cpu.cycles
           step = SIM_step_count(cpu)
           cr = self.cycleRecord(cycle, step, eip)
           self.__return_to_cycle[cell_name][pid] = cr
           self.lgr.debug('recordReturnToCycle %s %d %s' % (cell_name, pid, cr.toString()))
       

    def handleEipFault(self, cpu, cell_name, pid, eip, comm): 
       ''' 
       eip is not mapped.  Record the unmapped eip so the rop cop can be fixed up.  
       Of course the eip can be on mars.  In case it is on mars, record the current 
       simulation cycle so we can come back to it during analysis.
       ''' 
       #self.lgr.debug('in handleEipFault , pid %s:%d with unmapped eip %x' % (cell_name, 
       #    pid, eip))
       # skip if we are only watching, but not yet monitoring, the player
       if not (self.isPlayer(comm) and not self.__player_monitor):
           cell = self.__cell_config.cell_context[cell_name]
           self.__unmapped_eips[cell_name][pid] = eip
           self.recordReturnToCycle(cpu, cell_name, pid)
           self.lgr.debug('handleEipFault , recorded returnToCycle for pid %s:%d with unmapped eip %x' % (cell_name, 
               pid, eip))

    def getTopComponentName(self, cpu):
         if cpu is not None:
             names = cpu.name.split('.')
             return names[0]
         else:
             return None

    def cellHasServer(self, cell_name):
        if len(self.__server_pid[cell_name]) is 0:
            return False
        else:
            return True

    def hasPendingSignal(self, cell_name, pid):
        if pid in self.__pending_signals[cell_name]:
           return True
        return False

    def list_contexts(self):
        self.__context_manager.list()

    def idaMessage(self):
        self.__context_manager.showIdaMessage()

    def getServerName(self, cell_name):
        kind = self.getKind(cell_name)
        if kind == 'network host':
           return self.__master_config.server_name
        elif kind == 'pov thrower':
           return self.__master_config.replay_name
        elif kind == 'ids':
           return self.__master_config.ids_name
        else:
           print 'unknown kind in getServerName %s' % kind
        return None

    def getLastRetEIP(self, cell_name, pid):
        retval = None
        try:
            retval = self.__last_ret_eip[cell_name][pid]
        except KeyError:
            pass
        return retval

    def isWatching(self, cell_name, pid):
        if cell_name in self.__watching and pid in self.__watching[cell_name]:
            return True
        else:
            return False

    def watchSysCalls(self, cell_name, pid, comm):
        if not self.isWatching(cell_name, pid):
            return False
        if pid in self.__ids_pid and self.__rules_file_name is None:
            return False
        elif self.isIDS(comm) and pid not in self.__ids_pid:
            return False
        elif self.__master_config.watchCalls(cell_name, comm):
            return True
        return False

    def isPoV(self, pid, cell_name):
        retval = False
        seed = self.target_log.findSeed(pid, cell_name)
        if seed in self.__replay_file_name:
            base = os.path.basename(self.__replay_file_name[seed])
            if base.startswith('POV') or base.endswith('.pov'):
                retval = True
        return retval

    def isPoVcb(self, comm):
        if comm is not None and comm.endswith('.pov'):
            return True
        else:
            return False

    def isCB(self, comm):
        if comm is not None and (comm.startswith('CB') or comm.endswith('.rcb')):
            return True
        else:
            return False

    def isPoller(self, comm):
        if comm is not None and comm == self.__master_config.player_name:
           return True
        else:
           return False

    def isIDS(self, comm):
        #self.lgr.debug('isIDS test <%s> against <%s>' % (self.__master_config.ids_name, comm))
        if comm is not None and comm == self.__master_config.ids_name:
            #self.lgr.debug('IS TRUE')
            return True
        else:
            return False

    def isPlayer(self, comm):
        '''
        Return true if the given comm is the player (for cqe), or
        if it is a POV (for cfe).
        '''
        if self.cfg.cfe:
            if comm is not None and comm.endswith('.pov'):
                return True
        # CFE polls, and in CQE, player is player 
        #self.lgr.debug('isPlayer compare %s to %s' % (comm, self.__master_config.player_name))
        if comm is not None and comm == self.__master_config.player_name:
           return True
        else:
           return False

    def isReplay(self, comm):
        if comm is not None and comm == self.__master_config.replay_name:
           return True
        else:
           return False

    ''' TBD remove, no longer needed now that replay does not use signals to wake player 
        Was used in freeBSD due to signal code kernel stampts at top of stack'''
    def isReplaySignalCode(self, cell_name, eip):
        #self.lgr.debug('in isReplaySignalCode for %s at %x' % (cell_name, eip))
        if self.__cell_config.cells[cell_name] != 'network host':
            if eip >= 0xbfbff000:
                return True
        return False

    def idaDone(self):
        self.lgr.debug('cgcMonitor idaDone')
        
        pid, cell_name, cpu = self.__context_manager.getDebugPid()
        if cell_name is not None:
            seed = self.target_log.findSeed(pid, cell_name)
            if seed in self.__replay_file_name:
                self.target_log.doneDebug(self.__replay_file_name[seed]) 
            else:
                self.lgr.debug('idaDone, no replay_file_name for seed %s' % seed)
                self.target_log.doneDebug('no replay, deleted?')
            self.goToOrigin()
            self.__bookmarks.clearMarks()
        self.__context_manager.idaDone()
        if cell_name is not None:
            self.closeOutProcess(pid, cell_name)

    def reInit(self, event=None):
        if event is None:
            self.lgr.debug('reInit called, event is none')
        else:
            self.lgr.debug('reInit called, event is path is %s' % event.path)
        if self.cfg.no_monitor:
            return
        self.cleanupAllAlone()
        for cell_name in self.__cell_config.os_type:
            self.__os_p_utils[cell_name].reInit()
        if event is None:
            self.lgr.debug('reInit after cleanupAllAlone, not from watcher')
        else:
            self.lgr.debug('reInit after cleanupAllAlone, eventpath is %s' % event.path)
        if not self.__master_config.load(lgr=self.lgr):
            print 'reInit error reading master.cfg (from zk) exiting'
            self.lgr.error("reInit error reading master.cfg (from zk) exiting")
            exit(1)
        
        for cell_name in self.__cell_config.cells:
            self.doInitCell(cell_name)
            for pid in self.__did_track_setup[cell_name]:
                self.lgr.error('reInit, pid left in did_track_setup %d' % pid)
            self.__did_track_setup[cell_name] = []
            self.__rop_pending[cell_name] = False
            cpu = self.__cell_config.cpuFromCell(cell_name)
            self.__watch_kernel.undoRop(cpu)
            self.__syscall_entries[cell_name] = {}

        SIM_run_alone(SIM_run_command, 'disable-reverse-execution')
        SIM_run_alone(SIM_run_command, 'enable-vmp')
        self.lgr.debug('reInit disabled reverse execution')
        self.__context_manager.setDebugging(False)
        self.__page_faults.cleanAll()
        self.__page_faults.reInit()
        self.__other_faults.reInit(self.__master_config)
        # reset node deleted to get us to reinit.  Or we deleted it.  Recreate it
        timestamp = self.__zk.getOurStatus()
        if timestamp is None:
            self.lgr.error('reInit failed to get our status, fatal')
            return
        self.recordOurReset(timestamp)
        if self.__master_config.code_coverage and self.__code_coverage is None:
            self.__code_coverage = codeCoverage.codeCoverage(self.cfg, self.lgr)
        self.log_sys_calls = self.__master_config.logSysCalls()
        self.__protected_memory.reInit(self.__master_config.stop_on_memory, self.__master_config.server_protected_memory)
        self.__bookmarks.clearMarks()
        self.__negotiate.clearAllValues()


    def reInitAlone(self, event):
        '''
        called as a zookeeper watcher when the monitor's reset node is deleted.
        Reinitialize the cgcMonitor for the new master configuration
        '''
        status = SIM_simics_is_running()
        if not status and self.__context_manager.getDebugging():
            # TBD if simulation broke for debug, don't kill it
            self.lgr.debug('reInitAlone but simulation not running?, with event of path %s' % event.path)
            return
        if event is not None:
            self.lgr.debug('reInitAlone call reInit, with event of path %s' % event.path)
        else:
            self.lgr.debug('reInitAlone call reInit')
        SIM_run_alone(self.reInit, event)

    def pageFaultUpdateCycles(self, cell_name, cpu, pid, comm):
        '''
        experimental, will need to use mode haps to get any accuracy
        '''
        if pid in self.__pid_user_cycles[cell_name] and pid not in self.__syscall_entries[cell_name]:
            cur_cycle = cpu.cycles
            delta = cur_cycle - self.__previous_pid_user_cycle[cell_name]
            #self.lgr.debug('pageFaultsUpdateCycles for %s:%d (%s) user cycles was %d previous value is %d  current %d delta: %d' % \
            #    (cell_name, pid, comm, self.__pid_user_cycles[cpu][pid], 
            #     self.__previous_pid_user_cycle[cpu], cur_cycle, delta))
            self.__pid_user_cycles[cell_name][pid] += delta

    def getPidCycles(self, cell_name, pid):
        retval = 0
        delta = cpu.cycles - self.__previous_pid_cycle[cell_name]
        if pid in self.__pid_cycles[cell_name]:
            retval = self.__pid_cycles[cell_name][pid] + delta
            self.lgr.debug('getPidCycles, tot 0x%x  delta 0x%x' % (retval, delta))
        return retval

    def switchedPid(self, cpu, pid, new_comm):
        '''
        called by os_p_utils whenever the current task changes
        Do accounting on cycles per process
        '''
        cell_name = self.getTopComponentName(cpu)
        if self.__os_p_utils[cell_name] is None:
            self.lgr.debug('switchedPid called before __os_p_utils initialized')
            return
        dum_cpu, cur_addr, old_comm, old_pid = self.__os_p_utils[cell_name].getPinfo(cpu)
        if old_pid is not None:
            #self.lgr.debug('switchedPid to %s:%d from %d' % (cell_name, pid, old_pid))
            pass
        #if old_pid is not None and self.isWatching(cell_name, old_pid):
        if old_pid is not None and old_pid in self.__pid_cycles[cell_name]:
            # watching previous process, update its cycles
            cur_cycle = cpu.cycles
            delta = cur_cycle - self.__previous_pid_cycle[cell_name]
            #self.lgr.debug('switchedPid was watching %s:%d (%s) will switch to %d (%s) pid cycles was %d previous: %d delta: %d' % \
            #   (cell_name, old_pid, old_comm, pid, new_comm, self.__pid_cycles[cpu][old_pid], 
            #   self.__previous_pid_cycle[cpu], delta))
            self.__pid_cycles[cell_name][old_pid] += delta
            # don't charge user space with cycles if within a syscall
            if old_pid in self.__pid_user_cycles[cell_name] and old_pid not in self.__syscall_entries[cell_name]:
                delta = cur_cycle - self.__previous_pid_user_cycle[cell_name]
                #self.lgr.debug('switchedPid was watching %s:%d (%s) user cycles was %d previous value is %d  current %d delta: %d' % \
                #    (cell_name, old_pid, old_comm, self.__pid_user_cycles[cpu][old_pid], 
                #     self.__previous_pid_user_cycle[cpu], cur_cycle, delta))
                self.__pid_user_cycles[cell_name][old_pid] += delta
        if self.isWatching(cell_name, pid) and self.isCB(new_comm):
            # watching new process, mark current cycles
            cur_cycle = cpu.cycles
            self.__previous_pid_cycle[cell_name] = cur_cycle
            if pid not in self.__syscall_entries[cell_name]:
                self.__previous_pid_user_cycle[cell_name] = cur_cycle
            #self.lgr.debug('switchedPid now watching %s:%d (%s) previous cycle now %d' % (cell_name, pid, new_comm, cur_cycle))

    def setRopPending(self, cell_name):
        self.__rop_pending[cell_name] = True

    ''' Not python logging, log entry for monitoring events, log will be written to a zk node '''
    def addLogEvent(self, cell_name, pid, comm, event_type, entry, low_priority=False):
        self.target_log.addLogEvent(cell_name, pid, comm, event_type, entry, low_priority)

    def addProtectedAccess(self, record, pid, cell_name):
        self.target_log.addProtectedAccess(record, pid, cell_name)

    # debugging to see when haps are created.  Hint, enable reverse creates squads of em.
    def hapHapCallback(self, data, obj, num, low, high):
        print 'added hap %d low: %d  high: %d' % (num, low, high)
        print obj

    def hapTrack(self):
        hap_hap = SIM_hap_add_callback("Core_Hap_Callback_Installed", 
		self.hapHapCallback, None)

    def getKind(self, cell_name):
        return self.__cell_config.cells[cell_name]

    def getNumCalls(self, cell_name, pid):
        return self.__num_calls[cell_name][pid]

    def showCurrent(self):
        print 'current process:'
        dum, dum2, cpu = self.__context_manager.getDebugPid() 
        cell_name = self.getTopComponentName(cpu)
        cpu, cur_addr, comm, pid = self.__os_p_utils[cell_name].getPinfo(cpu)
        print '%s:%d (%s)' % (cell_name, pid, comm)

    def getWallSeconds(self, cpu):
        time = SIM_time(cpu)
        return time

    def getReplayFileNameFromSeed(self, seed):
        if seed in self.__replay_file_name:
            return self.__replay_file_name[seed]
        else:
            return None

    def getCBFileNameFromSeed(self, seed):
        if seed in self.__cb_file_name:
            return self.__cb_file_name[seed]
        else:
            return None

    def fdSetSize(self):
        _NFDBITS = 8*self.__mem_utils[cell_name].WORD_SIZE
        FD_SETSIZE = 1024
        array_size = FD_SETSIZE / _NFDBITS
        return array_size        

    def eventTypeFromSignal(self, sigval, comm, cell_name):
        if self.isPlayer(comm): 
            if sigval == self.__os_p_utils[cell_name].SIGSEGV:
                return forensicEvents.PLAYER_SIGSEGV
            elif sigval == self.__os_p_utils[cell_name].SIGILL:
                return forensicEvents.PLAYER_SIGILL
            elif sigval == self.__os_p_utils[cell_name].SIGALRM:
                return forensicEvents.PLAYER_SIGALRM
            elif sigval == self.__os_p_utils[cell_name].SIGKILL:
                return forensicEvents.PLAYER_SIGKILL
            else:
                return forensicEvents.PLAYER_SIGOTHER
        elif self.isReplay(comm):
            if sigval == self.__os_p_utils[cell_name].SIGSEGV:
                return forensicEvents.REPLAY_SIGSEGV
            elif sigval == self.__os_p_utils[cell_name].SIGILL:
                return forensicEvents.REPLAY_SIGILL
            elif sigval == self.__os_p_utils[cell_name].SIGALRM:
                return forensicEvents.REPLAY_SIGALRM
            elif sigval == self.__os_p_utils[cell_name].SIGKILL:
                return forensicEvents.REPLAY_SIGKILL
            else:
                return forensicEvents.REPLAY_SIGOTHER
        else:
            if sigval == self.__os_p_utils[cell_name].SIGSEGV:
                return forensicEvents.USER_SIGSEGV
            elif sigval == self.__os_p_utils[cell_name].SIGILL:
                return forensicEvents.USER_SIGILL
            elif sigval == self.__os_p_utils[cell_name].SIGTRAP:
                return forensicEvents.USER_SIGTRAP
            elif sigval == self.__os_p_utils[cell_name].SIGFPE:
                return forensicEvents.USER_SIGFPE
            elif sigval == self.__os_p_utils[cell_name].SIGALRM:
                return forensicEvents.USER_SIGALRM
            elif sigval == self.__os_p_utils[cell_name].SIGKILL:
                return forensicEvents.USER_SIGKILL
            else:
                return forensicEvents.USER_SIGOTHER

    def clgr(self, record):
        self.lgr.critical(record)
        self.__zk.logCritical(record)

    def elgr(self, record):
        self.lgr.error(record)
        self.__zk.logCritical(record)

    def readyDebug(self, cell_name, cpu, pid, comm, manual):
        '''
        intitialize modules to support human analysis
        TBD move findKernelWrite here
        '''
        #if not manual:
        #    self.__bookmarks.setOrigin(cpu)
        instance = INSTANCE
        if instance is None:
            instance = 'x'
        log_dir = os.path.join(self.cfg.logdir, 'monitors')
        self.lgr.debug('readyDebug, %s %d (%s)' % (cell_name, pid, comm))
        if pid not in self.__x_pages[cell_name]:
            self.lgr.error('readyDebug, %d not in x_pages for %s' % (pid, cell_name))
            return
        self.__rev_to_call.setup(cpu, self.__x_pages[cell_name][pid])
        
        my_name = 'runToUser'+instance
        cell = self.__cell_config.cell_context[cell_name]
        self.__run_to_user_space = runToUserSpace.runToUserSpace(self, self.__param[cell_name], 
                 self.__os_p_utils[cell_name], self.__x_pages[cell_name][pid],
                 self.PAGE_SIZE, self.__context_manager, comm, cell_name, cell, 
                 cpu, pid, self.__other_faults, my_name, self.is_monitor_running, log_dir)

    def runToUserSpace(self):
        self.lgr.debug('cgcMonitor runToUserSpace')
        #cpl = memUtils.getCPL(cpu)
        #if cpl == 0:
        pid, cell_name, cpu = self.__context_manager.getDebugPid() 
        self.__run_to_user_space.runToUser(cpu, cell_name, pid)
        #else:
        #    self.lgr.debug('runToUserSpacealready in user space?')
        
    def revToUserSpace(self):
        self.lgr.debug('cgcMonitor revToUserSpace')
        self.__run_to_user_space.revToUser()
    
    def revTaintAddr(self, addr):
        '''
        back track the value at a given memory location, where did it come from?
        '''
        self.lgr.debug('revTaintAddr for 0x%x' % addr)
        dum, dum2, cpu = self.__context_manager.getDebugPid() 
        cell_name = self.getTopComponentName(cpu)
        eip = self.getEIP(cpu)
        instruct = SIM_disassemble_address(cpu, eip, 1, 0)
        value = self.__os_p_utils[cell_name].getMemUtils().readWord32(cpu, addr)
        bm='backtrack START:0x%x inst:"%s" track_addr:0x%x track_value:0x%x' % (eip, instruct[1], addr, value)
        self.__bookmarks.setDebugBookmark(bm)
        self.lgr.debug('BT add bookmark: %s' % bm)
        self.__context_manager.setIdaMessage('')
        self.stopAtKernelWrite(addr, self.__rev_to_call)

    def revTaintReg(self, reg):
        ''' back track the value in a given register '''
        self.lgr.debug('revTaintReg for %s' % reg)
        dum, dum2, cpu = self.__context_manager.getDebugPid() 
        cell_name = self.getTopComponentName(cpu)
        eip = self.getEIP(cpu)
        instruct = SIM_disassemble_address(cpu, eip, 1, 0)
        reg_num = cpu.iface.int_register.get_number(reg)
        value = cpu.iface.int_register.read(reg_num)
        self.lgr.debug('revTaintReg for reg value %x' % value)
        bm='backtrack START:0x%x inst:"%s" track_reg:%s track_value:0x%x' % (eip, instruct[1], reg, value)
        self.__bookmarks.setDebugBookmark(bm)
        self.__context_manager.setIdaMessage('')
        self.__rev_to_call.doRevToModReg(reg, True)


    def stopAtKernelWrite(self, addr, rev_to_call=None, num_bytes = 1):
        '''
        Runs backwards until a write to the given address is found.
        '''
        self.__context_manager.clearExitBreak()
        dum, dum2, cpu = self.__context_manager.getDebugPid() 
        cell_name = self.getTopComponentName(cpu)
        self.lgr.debug('stopAtKernelWrite, call findKernelWrite for 0x%x' % addr)
        self.__find_kernel_write = findKernelWrite.findKernelWrite(self, cpu, addr, self.__os_p_utils[cell_name], self.__os_p_utils[cell_name], 
            self.__context_manager, self.__param[cell_name], self.__bookmarks, self.lgr, rev_to_call, num_bytes) 

    def cleanupKernelWrite(self):
        self.__find_kernel_write.cleanup(True)

    def emptyMailbox(self):
        if self.__gdb_mailbox is not None and self.__gdb_mailbox != "None":
            print self.__gdb_mailbox
            self.lgr.debug('emptying mailbox of <%s>' % self.__gdb_mailbox)
            self.__gdb_mailbox = None

    ''' not currently used '''
    def getCurrentPid(self):
        dum, dum2, cpu = self.__context_manager.getDebugPid() 
        if cpu is None:
            cpu = SIM_current_processor()
        cell_name = self.getTopComponentName(cpu)
        cpu, cur_addr, comm, pid = self.__os_p_utils[cell_name].currentProcessInfo(cpu)
        self.lgr.debug('getCurrentPid, return %d' % pid)
        retval = '%s %s %d' % (cell_name, comm, pid)
        print retval
        return retval

    ''' intended for use by gdb client to set bookmark for returning to the correct context '''
    def setDebugBookmark(self, mark, cpu=None, cycles=None, eip=None, steps=None):
        self.__bookmarks.setDebugBookmark(mark, cpu=cpu, cycles=cycles, eip=eip, steps=steps)

    def printAllCurrentThreads(self, cell_name):
        for cpu in self.__cell_config.cell_cpu_list[cell_name]:
            dum_cpu, cur_addr, comm, pid = self.__os_p_utils[cell_name].currentProcessInfo(cpu)
            threads = self.__os_p_utils[cell_name].getThreads(cpu, cur_addr)
            print('%s  pid: %d  comm: %s  oncpu: 0x%x' % (str(cpu), pid, comm, threads[0].cpu))
        
    def getEIP(self, cpu=None):
        if cpu is None:
            dum, dum2, cpu = self.__context_manager.getDebugPid() 
        cell_name = self.getTopComponentName(cpu)
        eip = self.__os_p_utils[cell_name].mem_utils.getRegValue(cpu, 'eip')
        return eip

    def getReg(self, reg, cpu):
        cell_name = self.getTopComponentName(cpu)
        value = self.__os_p_utils[cell_name].mem_utils.getRegValue(cpu, reg)
        self.lgr.debug('debugGetReg for %s is %x' % (reg, value))
        return value

    def debugGetReg(self, reg):
        dum, dum2, cpu = self.__context_manager.getDebugPid() 
        cell_name = self.getTopComponentName(cpu)
        value = self.__os_p_utils[cell_name].mem_utils.getRegValue(cpu, reg)
        self.lgr.debug('debugGetReg for %s is %x' % (reg, value))
        print('%s:0x%x' % (reg, value))
        return value

    def getDebugReplay(self):
        pid, dum2, cpu = self.__context_manager.getDebugPid() 
        cell_name = self.getTopComponentName(cpu)
        if cell_name is not None:
            fname = self.getReplayFileName(pid, cell_name)
        else:
            fname = 'unknown'
        comm = self.__context_manager.getDebugComm() 
        print('%s vs %s' % (os.path.basename(fname), comm))

    def getDebugFirstCycle(self):
        print('start_cycle:%x' % self.__bookmarks.getFirstCycle())
    
    def isProtectedMemory(self, address):
        retval = False
        end = self.cfg.protected_start + self.cfg.protected_length
        if address >= self.cfg.protected_start and address <= end:
            retval = True
        return retval

    def runSkipAndMailAlone(self, cycles): 
        dum, dum2, cpu = self.__context_manager.getDebugPid() 
        if cpu is None:
            self.lgr.error("no cpu in runSkipAndMailAlone")
            return
        current = cpu.cycles
        eip = self.getEIP(cpu)
        instruct = SIM_disassemble_address(cpu, eip, 1, 0)
        self.lgr.debug('skipAndMailAlone current cycle is %x eip: %x %s requested %d cycles' % (current, eip, instruct[1], cycles))
        if cycles > 0:
            previous = current - cycles 
            start = self.__bookmarks.getCycle('_start+1')
            if previous > start:
                self.__context_manager.clearExitBreak()
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
                self.__context_manager.resetBackStop()
                self.__context_manager.setExitBreak(cpu)
            else:
                self.lgr.debug('skipAndRunAlone was asked to back up before start of recording')
        self.gdbMailbox('0x%x' % eip)
        print('Monitor done')

    def skipAndMail(self, cycles=1):

        dum, dum2, cpu = self.__context_manager.getDebugPid() 
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
   

    def getFirstCycle(self):
        return self.__bookmarks.getFirstCycle()

    def r2UserNext(self, cpu):
        eip = self.getEIP(cpu)
        cell_name = self.getTopComponentName(cpu)
        if eip > self.__param[cell_name].kernel_base:
            self.lgr.debug('r2UserNext eip %x still kernel after mode hap, as expected step one' % (eip))
            SIM_continue(1)
        eip = self.getEIP(cpu)
        self.lgr.debug('r2UserNext eip now 0x%x' % eip)
        phys_block = cpu.iface.processor_info.logical_to_physical(eip, Sim_Access_Read)
        instruct = SIM_disassemble_address(cpu, eip, 1, 0)
        if phys_block.address == 0 or 'illegal' in instruct[1]:
            self.lgr.debug('r2UserNext, still not mapped %s' % instruct[1])
            SIM_continue(4)
            stopHapCallback.stopHapCallback(self.skipAndMail, 1, self.lgr)
        else: 
            self.lgr.debug('r2UserNext, eip is mapped phys: %x' % phys_block.address)
            instruct = SIM_disassemble_address(cpu, eip, 1, 0)
            self.lgr.debug('r2UserNext eip: %x %s' % (eip, instruct[1]))
            self.skipAndMail()

    def r2UserStart(self, pinfo):
        self.lgr.debug('r2UserStart, use stopHapCallback to skipAndMail')
        #stopHapCallback.stopHapCallback(self.skipAndMail, 1, self.lgr)
        stopHapCallback.stopHapCallback(self.r2UserNext, pinfo.cpu, self.lgr)

    def goToFirst(self, cpu=None, pid=None):
        self.__context_manager.clearExitBreak()
        self.__bookmarks.skipToFirst(cpu)
        ''' we are now in user space, but likely the code is not paged in '''
        #self.__run_to_user_space.runToUser() 
        if cpu is None:
            pid, cell_name, cpu = self.__context_manager.getDebugPid() 
        else:
            cell_name = self.getTopComponentName(cpu)
        eip = self.getEIP(cpu)
        #eip = self.getEIP(cpu)+6
        phys_block = cpu.iface.processor_info.logical_to_physical(eip, Sim_Access_Read)
        self.lgr.debug('goToFirst, did skip, eip is 0x%x, phys is %x' % (eip, phys_block.address))
        if phys_block.address == 0:
            ''' page not mapped, use mode hap to get to user space.  We can do this because we are going forward. '''
            SIM_continue(4)
            current = cpu.cycles
            eip = self.getEIP(cpu)
            self.lgr.debug('goToFirst, after continue to get to kernel, eip is 0x%x cycle 0x%x' % (eip, current))
            #cpu_list = self.__cell_config.cell_cpu_list[cell_name]
            #returnToUserHap.returnToUserHap(self, cpu, cpu_list, pid, 'debugged process',  self.r2UserStart, self.__os_p_utils[cell_name], 
            #    self.is_monitor_running, self.lgr)
            #SIM_continue(0)
            self.runToUserSpace()
            #self.lgr.debug('gotToFirst, not paged in, use pipe to continue')
            #f = open('./simics.stdin', 'w')
            #f.write('c\n')
            #f.close()
        else:
            self.lgr.debug('gotToFirst, is already paged in')
            #self.gdbMailbox('0x%x' % eip)
            self.skipAndMail()

    def goToOrigin(self):
        self.__bookmarks.goToOrigin()

    def goToDebugBookmark(self, mark):
        mark = mark.replace('|','"')
        self.__bookmarks.goToDebugBookmark(mark)

    def listBookmarks(self):
        self.__bookmarks.listBookmarks()

    def getBookmarks(self):
        return self.__bookmarks.getBookmarks()
       
    def doReverse(self, extra_back=0):
        dum, dum2, cpu = self.__context_manager.getDebugPid() 
        self.lgr.debug('doReverse entered, extra_back is %s' % str(extra_back))
        self.__context_manager.clearExitBreak()
        reverseToWhatever.reverseToWhatever(self, self.__context_manager, cpu, self.lgr, extra_back=extra_back)
        self.lgr.debug('doReverse, back from reverseToWhatever init')
        self.__context_manager.setExitBreak(cpu)

    ''' intended for use by gdb, if stopped return the eip.  checks for mailbox messages'''
    def getEIPWhenStopped(self, kernel_ok=False):
        #status = SIM_simics_is_running()
        status = self.is_monitor_running.isRunning()
        if not status:
            debug_pid, dum2, cpu = self.__context_manager.getDebugPid() 
            if cpu is None:
                print('no cpu defined in context manager')
                return
            cell_name = self.getTopComponentName(cpu)
            dum_cpu, cur_addr, dum, pid = self.__os_p_utils[cell_name].currentProcessInfo(cpu)
            self.lgr.debug('getEIPWhenStopped, look for comm for pid %d' % (pid)) 
            comm = self.__os_p_utils[cell_name].getCommByPid(pid)
            eip = self.getEIP(cpu)
            if self.__gdb_mailbox is not None:
                self.lgr.debug('getEIPWhenStopped mbox is %s pid is %d (%s)' % (self.__gdb_mailbox, pid, comm))
                retval = 'mailbox:%s' % self.__gdb_mailbox
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
            #if comm != self.__context_manager.comm_being_debugged:
            if debug_pid != pid:
                self.lgr.debug('getEIPWhenStopped wrong process pid:%d (%s) eip is %x' % (pid, comm, eip))
                retval = 'wrong process'
                print retval
                return retval
            SIM_run_command('pselect cpu-name = %s' % cpu.name)
            retval = 'mailbox:0x%x' % eip
            print retval
            #cmd = '%s.symtable symtable = %s' % (self.__context_manager.get(cell_name, pid), comm)
            #print 'cmd is %s' % cmd
            #SIM_run_command(cmd)
        else:
            self.lgr.debug('call to getEIPWhenStopped, not stopped')
            print 'not stopped'
            retval = 'not stopped'
        return retval

    def gdbMailbox(self, msg):
        self.__gdb_mailbox = msg
        self.lgr.debug('in gdbMailbox msg set to <%s>' % msg)
        print('gdbMailbox:%s' % msg)

    def watchTaint(self):
        self.__taint_manager.watchTaint()

    def printCycle(self):
        dum, dum2, cpu = self.__context_manager.getDebugPid() 
        cell_name = self.getTopComponentName(cpu)
        current = cpu.cycles
        print 'current cycle for %s is %x' % (cell_name, current)

    ''' more experiments '''
    def reverseStepInstruction(self, num=1):
        dum, dum2, cpu = self.__context_manager.getDebugPid() 
        cell_name = self.getTopComponentName(cpu)
        dum_cpu, cur_addr, comm, pid = self.__os_p_utils[cell_name].currentProcessInfo(cpu)
        eip = self.getEIP()
        self.lgr.debug('reservseStepInstruction starting at %x' % eip)
        my_args = procInfo.procInfo(comm, cpu, pid, None, False)
        self.stopped_reverse_instruction_hap = SIM_hap_add_callback("Core_Simulation_Stopped", 
		    self.stoppedReverseInstruction, my_args)
        self.lgr.debug('reverseStepInstruction, added stop hap')
        SIM_run_alone(SIM_run_command, 'reverse-step-instruction %d' % num)

    def stoppedReverseInstruction(self, my_args, one, exception, error_string):
        cell_name = self.getTopComponentName(my_args.cpu)
        cpu, cur_addr, comm, pid = self.__os_p_utils[cell_name].currentProcessInfo(my_args.cpu)
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
        dum, dum2, cpu = self.__context_manager.getDebugPid() 
        cell_name = self.getTopComponentName(cpu)
        self.__context_manager.clearExitBreak()
        self.lgr.debug('reverseToCallInstruction, step_into: %r' % step_into)
        if prev is not None:
            instruct = SIM_disassemble_address(cpu, prev, 1, 0)
            self.lgr.debug('reverseToCallInstruction instruct is %s, prev: 0x%x' % (instruct[1], prev))
            if instruct[1] == 'int 128' or (not step_into and instruct[1].startswith('call')):
                self.revToAddr(prev)
            else:
                self.__rev_to_call.doRevToCall(step_into, prev)
        else:
            self.lgr.debug('prev is none')
            self.__rev_to_call.doRevToCall(step_into, prev)
        self.lgr.debug('reverseToCallInstruction back from call to reverseToCall ')

    def uncall(self):
        dum, dum2, cpu = self.__context_manager.getDebugPid() 
        cell_name = self.getTopComponentName(cpu)
        dum_cpu, cur_addr, comm, pid = self.__os_p_utils[cell_name].currentProcessInfo(cpu)
        self.__context_manager.clearExitBreak()
        self.lgr.debug('cgcMonitor, uncall')
        #self.__rev_to_call.doRevToCall(True, False)
        self.__rev_to_call.doUncall()
   
    def getInstance(self):
        return INSTANCE
 
    def revToModReg(self, reg):
        #dum, dum2, cpu = self.__context_manager.getDebugPid() 
        self.lgr.debug('revToModReg for reg %s' % reg)
        #cell_name = self.getTopComponentName(cpu)
        #dum_cpu, cur_addr, comm, pid = self.__os_p_utils[cell_name].currentProcessInfo(cpu)
        self.__context_manager.clearExitBreak()
        self.__rev_to_call.doRevToModReg(reg)

    def revToAddr(self, address, extra_back=0):
        pid, cell_name, cpu = self.__context_manager.getDebugPid() 
        self.lgr.debug('revToAddr 0x%x, extra_back is %d' % (address, extra_back))
        self.__context_manager.clearExitBreak()
        reverseToAddr.reverseToAddr(address, self.__context_manager, self.is_monitor_running, self, cpu, self.lgr, extra_back=extra_back)
        self.lgr.debug('back from reverseToAddr')

    def runToSyscall(self):
        pid, cell_name, cpu = self.__context_manager.getDebugPid() 
        cell = self.__cell_config.cell_context[cell_name]
        self.lgr.debug('runToSyscall')
        self.__context_manager.clearExitBreak()
        runToSyscall.runToSyscall(self, self.__os_p_utils[cell_name], cpu, pid, True, self.__kernel_info[cell_name].syscall_offset, cell, 
              self.is_monitor_running, self.lgr)

    def revToSyscall(self):
        pid, cell_name, cpu = self.__context_manager.getDebugPid() 
        cell = self.__cell_config.cell_context[cell_name]
        self.lgr.debug('revToSyscall')
        self.__context_manager.clearExitBreak()
        runToSyscall.runToSyscall(self, self.__os_p_utils[cell_name], cpu, pid, False, self.__kernel_info[cell_name].syscall_offset, cell, 
              self.is_monitor_running, self.lgr)
        self.lgr.debug('back')
       
    def autoAnalysis(self, cell_name, pid, comm, cpu, manual, backstop_cycles=None):
        throw_id = self.__context_manager.getThrowId()
        print('AutoAnalysis ready for throw_id:%s' % throw_id)

    def autoAnalysisNoEvent(self):
        '''  no throw_id in context manager, because no debugging.  get what we recorded from tracing '''
        throw_id = self.__recent_throw_id
        print('AutoAnalysis No Event throw_id:%s' % throw_id)

    def analysisFirstROP(self):
        self.__auto_analysis.goFirstROP()

    ''' functions below experimental for getting Ida to refresh registers '''
    def reverseStep(self):
        dum, dum2, cpu = self.__context_manager.getDebugPid() 
        cell_name = self.getTopComponentName(cpu)
        dum_cpu, cur_addr, comm, pid = self.__os_p_utils[cell_name].currentProcessInfo(cpu)
        my_args = procInfo.procInfo(comm, cpu, pid, None, False)
        SIM_run_alone(self.addContinuationHap, my_args)
        self.lgr.debug('reverseStep, added continuation hap')

    def addStopHapForSignalClient(self, my_args):
        self.stop_signal_client_hap = SIM_hap_add_callback("Core_Simulation_Stopped", 
		    self.stopSignalClient, my_args)

    def stopSignalClient(self, my_args, one, exception, error_string):
        self.cleanup()
        self.__context_manager.signalClient()

    def signalClient(self):
        self.__context_manager.signalClient()
     
    def addContinuationHap(self, my_args):
        self.continuation_hap = SIM_hap_add_callback("Core_Continuation", 
		    self.continuation, my_args)

    def continuation(self, my_args, one):
        '''
        reversing = SIM_run_command('simulation-reversing')
        if not reversing:
            self.lgr.debug('in continuation hap')
            SIM_break_simulation('stop instead of continue')
            SIM_hap_delete_callback_id("Core_Continuation", self.continuation_hap)
            self.__context_manager.signalClient()
        '''
        if self.continuation_hap is not None:
            SIM_break_simulation('stop here from continuation hap')
            SIM_hap_delete_callback_id("Core_Continuation", self.continuation_hap)
            self.continuation_hap = None

    ''' close the call logs, intended for use from simics command line, e.g., when doing trace without
        any debugging events '''
    def closeCallLog(self):
        if self.log_sys_calls:
            for cell_name in self.__call_log:
                for pid in self.__call_log[cell_name]:
                    self.__call_log[cell_name][pid].doneCallLog()

    def checkLogStatus(self):
         self.lgr.debug('checkLogStatus num log handles is %d' % len(self.lgr.handlers))

    def printProcList(self):
         dum, dum2, cpu = self.__context_manager.getDebugPid() 
         if cpu is None:
             cpu = SIM_current_processor() 
         cell_name = self.getTopComponentName(cpu)
         pinfo = self.__os_p_utils[cell_name].getProcList()
         print('cell_name: %s' % cell_name)
         current_cpu = None
         for p in pinfo:
             if p.cpu != current_cpu:
                 print('%s' % str(p.cpu))
                 current_cpu = p.cpu
             #print('\tproc: %s  %d' % (p.comm, p.pid))
             if p.tlist is not None:
                 for t in p.tlist:
                     print('proc: %s pid %d  single: 0x%x  thread %s %d  cpu:0x%x  my_addr: 0x%x' % (p.comm, p.pid, p.task_ptr, t.comm, t.pid, t.cpu, t.task_ptr))

    #def gdbSend(self, packet):
    #    self.__context_manager.gdbSendPacket(packet)

    def continueSimulation(self):
         self.lgr.debug('continueSimulation')
         SIM_continue(0)

    def clearProtectedBookmarks(self):
        ''' delete protected memory bookmarks, e.g., if we stop for debugging at first sign of rop or nox '''
        self.__bookmarks.clearOtherBookmarks('protected_memory:')

    def forceQuitReplay(self):
        '''
        Hard coded to stop monitoring what is on the server cell.
        '''
        for cell_name in self.__cell_config.cells:
            cpu = self.__cell_config.cpuFromCell(cell_name)
            for pid in self.__watching[cell_name]:
                comm = self.__os_p_utils[cell_name].getCommByPid(pid)
                self.addLogEvent(cell_name, pid, comm, forensicEvents.FORCED_QUIT, 'forced quit monitor of replay')
                self.updateLogs(comm, pid, cell_name, cpu)
                self.__context_manager.cleanPID(cell_name, pid)
                self.closeOutTrace(comm, pid, cell_name)
                self.cleanupPid(cell_name, pid, comm)
                seed = self.target_log.findSeed(pid, cell_name)
                if seed in self.__pid_structs_to_clean:
                    self.__pid_structs_to_clean[seed].append(procInfo.procInfo(comm, cpu, pid))
                else:
                    self.lgr.debug('forceQuitReplay, did not find pid_structs_to_clean for seed %s' % seed)
            self.__os_p_utils[cell_name].processExiting(cpu)

    def writeWord(self, address, value):
        dum, dum2, cpu = self.__context_manager.getDebugPid() 
        phys_block = cpu.iface.processor_info.logical_to_physical(address, Sim_Access_Read)
        SIM_write_phys_memory(cpu, phys_block.address, value, 4)
 
    '''
    def mempool_alloc_cb(self, cpu, third, forth, fifth):
         self.alloc_count += 1
         self.lgr.debug('kmalloc  %d  %d' % (self.alloc_count, self.free_count))

    def mempool_re_alloc_cb(self, cpu, third, forth, fifth):
         self.alloc_count += 1
         self.lgr.debug('kmalloc_slab  %d  %d' % (self.alloc_count, self.free_count))

    def mempool_free_cb(self, cpu, third, forth, fifth):
         self.free_count += 1
         self.lgr.debug('kfree %d %d' % (self.alloc_count, self.free_count))

    def hack_breaks(self, cell_name):
         cell = self.__cell_config.cell_context[cell_name]
         cpu = self.__cell_config.cpuFromCell(cell_name)
         fname= self.cfg.system_map[cell_name]

         mempool_addr = getSymbol.getSymbol(fname, '__kmalloc', True)
         mempool_break = SIM_breakpoint(cell, Sim_Break_Linear, Sim_Access_Execute, mempool_addr, 1, 0)
         self.lgr.debug('set kmalloc break at 0x%x' % mempool_addr)
         dum_hap = SIM_hap_add_callback_index("Core_Breakpoint_Memop", 
		self.mempool_alloc_cb, cpu, mempool_break)

         mempool_re_addr = getSymbol.getSymbol(fname, 'kmalloc_slab', True)
         mempool_re_break = SIM_breakpoint(cell, Sim_Break_Linear, Sim_Access_Execute, mempool_re_addr, 1, 0)
         self.lgr.debug('set kmalloc_slab break at 0x%x' % mempool_re_addr)
         dum_hap = SIM_hap_add_callback_index("Core_Breakpoint_Memop", 
		self.mempool_re_alloc_cb, cpu, mempool_re_break)

         mempool_free_addr = getSymbol.getSymbol(fname, 'kfree', True)
         mempool_free_break = SIM_breakpoint(cell, Sim_Break_Linear, Sim_Access_Execute, mempool_free_addr, 1, 0)
         dum_hap = SIM_hap_add_callback_index("Core_Breakpoint_Memop", 
		self.mempool_free_cb, cpu, mempool_free_break)

    '''

    '''
    def signal_handler(self, signal, frame):
         print 'cgcMonitor in signal handler'
         self.lgr.debug('signal handler called, delete config file to force copy of target log')
         # delete config node to force log copy back to host from simulated target
         self.__zk.deleteReplayCFG()
         print 'deleted config file, sleep 4'
         self.lgr.debug('signal handler called, deleted config sleep 4')
         time.sleep(4)
         #os.abort()
    '''

''' turn off simics messages we can't do anything about '''
SIM_run_command("log-type -sub unimpl")
#run_command("service_node_cmp0.log-level 0")
cgc = cgcMonitor()
