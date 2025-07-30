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

Initialization of RESim proceeds as follows:
    The launchRESim program
    The standard python __init__ defines a set of module data and calls self.genInit(comp_dict), passing
    in the dictionary provided by launcheRESim
    genInit initializes a set of modules.
    The launchRESim then calls doInit, whose functions depend on whether a snapshot is run or not.
    If not a snapshot, the doInit runs the simulation until it finds the current task record.
    Finally, the runScripts function runs the INIT_SCRIPT from the ini, if any, and the onedone
    script if defined in the environment variables, e.g., for runAFL.

'''
from simics import *
import cli
import os
import sys
import errno
import struct
import resimUtils
import resimSimicsUtils
from resimSimicsUtils import rprint
import memUtils
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
import ipc
import sharedSyscall
import idaFuns
import traceMgr
import binder
import connector
import dmod
import targetFS
import winTargetFS
import cellConfig
import trackFunctionWrite
import pageUtils
import ropCop
import coverage
import taskSwitches
import traceMalloc
import backStop
import fuzz
import afl
import playAFL
import replayAFL
import reportCrash
import reportExit
import injectIO
import instructTrace
import aflPath
import trackAFL
import prepInject
import prepInjectWatch
import injectToBB
import injectToWM
import traceMarks
import userBreak
import magicOrigin
from resimHaps import *
import reverseTrack
import jumpers
import kbuffer
import funMgr
import readReplace
import regSet
import syscallManager
import testSnap
import winTaskUtils
import winMonitor
import winDLLMap
import runTo
import winProg
import stackFrameManager
import traceBuffer
import dmodMgr
import runToReturn
import recordLogEvents
import pageCallbacks
import loopN
import spotFuzz
import disassemble
import vxKMonitor
import vxKMemUtils
import vxParam
import vxKTaskUtils
import vxKModules
import findRefs
import findText
import recordEntry
import reverseMgr
import skipToMgr
import defaultConfig
import watchWrite
import doInUser

#import fsMgr
import json
import pickle
import re
import shutil
try:
    import importlib
except:
    ''' must be py 2.7 '''
    import imp 
    pass
import glob
import inspect


class Prec():
    def __init__(self, cpu, proc, tid=None, who=None):
        self.cpu = cpu
        self.proc = proc
        self.tid = tid
        self.who = who
        self.debugging = False


class GenMonitor():
    ''' Top level RESim class '''
    SIMICS_BUG=False
    PAGE_SIZE = 4096
    def __init__(self, comp_dict, link_dict, cfg_file, conf=None):
        self.comp_dict = comp_dict
        self.link_dict = link_dict
        # The param structure is shared by many modules.  It may be altered by the memUtils to account for ASLR
        self.param = {}
        self.mem_utils = {}
        self.task_utils = {}
        self.context_manager = {}
        #self.proc_list = {}
        self.cur_task_hap = None
        self.cur_task_break = None
        self.proc_hap = None
        self.stop_proc_hap = None
        self.proc_break = None
        self.gdb_mailbox = None
        self.stop_hap = None
        self.snap_warn_hap = None
        #self.log_dir = '/tmp/'
        self.log_dir = os.path.join(os.getcwd(), 'logs')
        try:
            os.mkdir(self.log_dir)
        except:
            pass
        self.mode_hap = None
        self.hack_list = []
        self.traceOpen = {}
        self.traceMgr = {}
        self.soMap = {}
        self.page_faults = {}
        self.rev_to_call = {}
        self.pfamily = {}
        self.traceProcs = {}
        self.dataWatch = {}
        self.trackFunction = {}
        self.traceFiles = {}
        self.sharedSyscall = {}
        self.ropCop = {}
        self.back_stop = {}
        self.reverseTrack = {}
        self.kbuffer = {}

        self.syscallManager = {}
        ''' dict of dict of syscall.SysCall keyed cell and context'''
        ''' TBD remove these '''
        self.call_traces = {}
        self.trace_all = {}

        self.run_to = {}

        self.stackFrameManager = {}

        self.unistd = {}
        self.unistd32 = {}
        self.targetFS = {}
        self.track_threads = {}
        self.exit_group_syscall = {}
        self.debug_breaks_set = True
        self.target = None
        self.netInfo = {}
        ''' for compatability, remove after old snapshots updated '''
        self.stack_base = {}

        self.maze_exits = {}
        self.exit_maze = []
        self.rev_execution_enabled = False
        self.run_from_snap = None
        self.ida_funs = None
        self.user_iterators = None
        self.auto_maze=False

        self.bookmarks = None

        self.reg_list = None

        self.is_compat32 = False

        self.relocate_funs = {}
        self.coverage = None
        self.real_script = None
        self.trace_malloc = None
        ''' full path of program being debugged '''
        self.full_path = None

        self.aflPlay = None
        ''' What to call when a command completes from skipAndMail (if anything '''
        self.command_callback = None
        self.command_callback_param = None
        ''' Command to run when debug commences '''
        self.debug_callback = None
        self.dubug_callback_param = None

        ''' TBD safe to reuse this?  helps when detecting iterative changes in address value '''
        self.find_kernel_write = None

        self.fun_mgr = None
       
        self.win_trace = None  

        self.one_done_module = None
        self.conf = conf
        self.lgr = resimUtils.getLogger('resim', os.path.join(self.log_dir, 'monitors'))
        one_done_script = os.getenv('ONE_DONE_SCRIPT')
        if one_done_script is not None:
            if one_done_script.startswith('/'):
                abs_path = one_done_script
            if os.path.isfile('./'+one_done_script):
                abs_path = os.path.abspath(('./%s' % one_done_script))
            else:
                abs_path = os.path.join(os.path.dirname(__file__), one_done_script)

            if os.path.isfile(abs_path):
                self.one_done_module = resimUtils.doLoad(one_done_script, abs_path)
                #self.one_done_module = imp.load_source(one_done_script, abs_path)
                self.lgr.debug('onedone found at %s' % abs_path)
            else:
                self.lgr.error('no onedone found for %s' % one_done_script)
        else:
            self.lgr.debug('No ONE_DONE_SCRIPT, must be interactive session.')

        self.injectIOInstance = None
        ''' retrieved from snapshot pickle, not necessarily current, used for debugSnap '''
        self.debug_info = None
        ''' Target attached by gdb client, e.g., IDA.  Only supports one at a time.  TBD allow multiple clients 
            with some way to name them.  '''
        self.debugger_target = None
  
        ''' once disabled, cannot go back ''' 
        self.disable_reverse = False

        self.gdb_port = 9123

        self.replayInstance = None
    
        self.cfg_file = cfg_file

        self.did_debug = False

        self.quit_when_done = False
        self.snap_start_cycle = {}
        self.instruct_trace = None
        self.user_break = None
        ''' Manage reset of origin based on execution of magic instruction 99 '''
        self.magic_origin = {}

        ''' Control flow jumpers '''
        self.jumper_dict = {}

        ''' Get valid FS base values for locating current task '''
        self.fs_mgr = None

        ''' ReadReplace module if any '''
        self.read_replace = {}

        ''' RegSet module if any '''
        self.reg_set = {}

        self.os_type = {}

        ''' catch-all for windows monitoring commands '''
        self.winMonitor = {}

        ''' catch-all for vxWorks DKM monitoring commands '''
        self.vxKMonitor = {}

        ''' Once data tracking seems to have completed, e.g., called goToDataMark,
            do not set debug related haps
        '''
        self.track_started = False
        self.track_finished = False

        self.dmod_mgr = {}

        self.stop_on_exit = {}

        self.no_gdb = False

        self.afl_instance= None

        self.page_callbacks = {}

        self.trace_buffers = {}

        self.resim_version = 25
        self.snap_version = 0

        self.report_crash = None
        self.loop_n = {}

        self.disassemble_instruct = {}
        self.max_marks = None
        self.no_reset = False
        self.record_entry = {}
        self.reverse_mgr = {}
        self.skip_to_mgr = {}
        # ad hoc watch for exits
        self.watchingExitTIDs = []
        self.SIMICS_VER = resimSimicsUtils.version()
        # for diagnostics
        self.pending_stop_hap = None

        ''' **** NO init data below here**** '''
        self.lgr.debug('genMonitor call genInit')
        self.genInit(comp_dict)
        exit_hap = RES_hap_add_callback("Core_At_Exit", self.simicsQuitting, None)

        ''' ****NO init data here**** '''

    def genInit(self, comp_dict):
        self.is_monitor_running = isMonitorRunning.isMonitorRunning(self.lgr)
        SIM_run_command("bp.delete -all")
        self.target = os.getenv('RESIM_TARGET')
        print('using target of %s' % self.target)
        self.cell_config = cellConfig.CellConfig(list(comp_dict.keys()), self.lgr)
        target_cpu = self.cell_config.cpuFromCell(self.target)
        self.lgr.debug('New log, in genInit')
        self.run_from_snap = os.getenv('RUN_FROM_SNAP')
        self.binders = binder.Binder(self.lgr)
        self.connectors = connector.Connector(self.lgr)
        try:
            os.remove('.driver_server_version')
        except:
            pass
        if self.run_from_snap is not None:
            self.lgr.debug('genInit running from snapshot %s' % self.run_from_snap)
            version_file = os.path.join('./', self.run_from_snap, 'version.pickle')
            if os.path.isfile(version_file):
                self.snap_version = pickle.load( open(version_file, 'rb') )

            ''' Restore link naming for convenient connect / disconnect '''
            net_link_file = os.path.join('./', self.run_from_snap, 'net_link.pickle')
            if os.path.isfile(net_link_file):
                self.link_dict = pickle.load( open(net_link_file, 'rb') )
                for target in self.link_dict:
                    for link in self.link_dict[target]:
                        cmd = '%s = %s' % (self.link_dict[target][link].name, self.link_dict[target][link].obj)
                        self.lgr.debug('genInit link cmd is %s' % cmd)
                        SIM_run_command(cmd)

            ''' TBD compatability, remove this '''
            stack_base_file = os.path.join('./', self.run_from_snap, 'stack_base.pickle')
            if os.path.isfile(stack_base_file):
                self.stack_base = pickle.load( open(stack_base_file, 'rb') )

            debug_info_file = os.path.join('./', self.run_from_snap, 'debug_info.pickle')
            if os.path.isfile(debug_info_file):
                self.debug_info = pickle.load( open(debug_info_file, 'rb') )
                self.lgr.debug('genInit loaded debug_info %s' % str(self.debug_info))
            driver_version_file = os.path.join('./', self.run_from_snap, 'driver_version.pickle')
            if os.path.isfile(driver_version_file):
                self.lgr.debug('genInit found driver_version_file pickle')
                # for driver-driver to find version of driver-server that was pickled
                driver_version = pickle.load( open(driver_version_file, 'rb') )
                current_version_file = os.path.join('./', '.driver_server_version')
                with open(current_version_file, 'w') as fh:
                    fh.write(driver_version) 
                    self.lgr.debug('genInit wrote %s to %s' % (driver_version, current_version_file))
                    fh.close()
            else:
                # assume the snapshot was not created by RESim
                self.recordDriverServerVersion()
            connector_file = os.path.join('./', self.run_from_snap, 'connector.json')
            if os.path.isfile(connector_file):
                self.connectors.loadJson(connector_file)
            binder_file = os.path.join('./', self.run_from_snap, 'binder.json')
            if os.path.isfile(binder_file):
                self.binders.loadJson(binder_file)
            self.lgr.debug('genInit rand from snap loop through targets in comp_dict')
            for cell_name in comp_dict:
                self.lgr.debug('genInit snapshot load target %s' % cell_name)
                param_file = os.path.join('./', self.run_from_snap, cell_name, 'param.pickle')
                # Ignore pickle file for vxworks (for now anyway)
                if 'OS_TYPE' in comp_dict[cell_name] and comp_dict[cell_name]['OS_TYPE'].startswith('VXW'):
                    self.param[cell_name] = vxParam.VxParam()
                elif os.path.isfile(param_file):
                    self.param[cell_name] = pickle.load(open(param_file, 'rb'))
                    self.lgr.debug('Loaded params for cell %s from pickle' % cell_name)

                    # TBD more hackary
                    if self.param[cell_name].kernel_base == 0xffffffff80000000:
                        self.param[cell_name].kernel_base = 0xffff800000000000
                        self.lgr.debug('genInit hacked kernel base to 0x%x' % self.param[cell_name].kernel_base)
                    if self.param[cell_name].sys_entry == 0:
                        self.param[cell_name].sys_entry = None

                    self.lgr.debug(self.param[cell_name].getParamString())
                else:
                    self.lgr.debug('No param pickle at %s' % param_file)
        else:                 
            self.recordDriverServerVersion()
        self.lgr.debug('genInit each target in comp_dict (%d targets)' % len(comp_dict))
        for cell_name in comp_dict:
            if 'OS_TYPE' not in comp_dict[cell_name]:
                self.lgr.debug('Cell %s does not have an os type. Params from snapshot, but missing from ini file.  not tracked' % cell_name)
                continue
            self.lgr.debug('genInit for cell %s' % (cell_name))
            if 'RESIM_PARAM' in comp_dict[cell_name] and cell_name not in self.param and comp_dict[cell_name]['RESIM_PARAM'].lower() != 'none':
                param_file = comp_dict[cell_name]['RESIM_PARAM']
                print('Cell %s using params from %s' % (cell_name, param_file))
                self.lgr.debug('Cell %s using params from %s' % (cell_name, param_file))
                if not os.path.isfile(param_file):
                    if cell_name != self.target:
                        print('Could not find param file at %s -- it will not be monitored' % param_file)
                        self.lgr.debug('Could not find param file at %s -- it will not be monitored' % param_file)
                        continue
                    else:
                        self.lgr.error('Could not find param file for TARGET at %s -- Cannot continue.' % param_file)
                        self.quit()
                self.param[cell_name] = pickle.load( open(param_file, 'rb') ) 
                ''' add new attributes of kParam here for compat with old param files '''
                if not hasattr(self.param[cell_name], 'compat32_entry'):
                    self.param[cell_name].compat_32_entry = None
                    self.param[cell_name].compat_32_int128 = None
                    self.param[cell_name].compat_32_compute = None
                    self.param[cell_name].compat_32_jump = None
                if not hasattr(self.param[cell_name], 'data_abort'):
                    self.param[cell_name].data_abort = None
                    self.param[cell_name].prefetch_abort = None
                if not hasattr(self.param[cell_name], 'arm_ret2'):
                    self.param[cell_name].arm_ret2 = None
                if not hasattr(self.param[cell_name], 'arm_svc'):
                    self.param[cell_name].arm_svc = False
                if not hasattr(self.param[cell_name], 'delta'):
                    self.param[cell_name].delta = None
                if not hasattr(self.param[cell_name], 'fs_base'):
                    self.param[cell_name].fs_base = None
                if not hasattr(self.param[cell_name], 'current_task_gs'):
                    self.param[cell_name].current_task_gs = False
                if not hasattr(self.param[cell_name], 'gs_base'):
                    self.param[cell_name].gs_base = None
                if 'OS_TYPE' in comp_dict[cell_name] and comp_dict[cell_name]['OS_TYPE'].startswith('WIN'):
                    if not hasattr(self.param[cell_name], 'page_table'):
                        # TBD remove hack after old snapshots cycle out
                        self.param[cell_name].page_table = 0x28

                ''' always true? TBD '''
                self.param[cell_name].ts_state = 0
                # TBD fix hack
                if self.param[cell_name].sys_entry == 0:
                    self.param[cell_name].sys_entry = None

                self.lgr.debug(self.param[cell_name].getParamString())
            elif 'OS_TYPE' in comp_dict[cell_name] and comp_dict[cell_name]['OS_TYPE'].startswith('VXW'):
                self.lgr.debug('No params for vxworks yet.')
                self.param[cell_name] = None
            elif cell_name not in self.param:
                print('Cell %s missing params, it will not be monitored. ' % (cell_name))
                self.lgr.debug('Cell %s missing params ' % (cell_name))
                continue 
            word_size = 4
            if 'OS_TYPE' in comp_dict[cell_name]:
                self.os_type[cell_name] = comp_dict[cell_name]['OS_TYPE']
                if self.os_type[cell_name] == 'LINUX64' or self.os_type[cell_name].startswith('WIN'):
                    word_size = 8
                self.lgr.debug('Cell %s os type %s' % (cell_name, self.os_type[cell_name]))

            cpu = self.cell_config.cpuFromCell(cell_name)
            if self.isVxDKM(cpu=cpu):
                self.mem_utils[cell_name] = vxKMemUtils.VxKMemUtils(self.lgr)
                self.lgr.debug('genInit set memUtils for VxDKM cell %s' % cell_name)
            else:
                self.mem_utils[cell_name] = memUtils.MemUtils(self, word_size, self.param[cell_name], self.lgr, arch=cpu.architecture, cell_name=cell_name)
            if cell_name not in self.os_type:
                # TBD move os type into params file so it need not be in the ini file?
                self.lgr.error('Missing OS_TYPE for cell %s' % cell_name)
                self.quit()
                return
            if self.os_type[cell_name].startswith('LINUX'):
                if 'RESIM_UNISTD' not in comp_dict[cell_name]:
                    if cell_name == 'driver':
                        print('Driver missing RESIM_UNISTD, will not be analyzed')
                        continue
                    print('Target is missing RESIM_UNISTD path')
                    self.lgr.error('Target is missing RESIM_UNISTD path')
                    self.quit()
                    return
                self.unistd[cell_name] = comp_dict[cell_name]['RESIM_UNISTD']
                self.lgr.debug('RESIM_UNISTD for cell %s' % cell_name)
                if 'RESIM_UNISTD_32' in comp_dict[cell_name]:
                    self.unistd32[cell_name] = comp_dict[cell_name]['RESIM_UNISTD_32']
                if 'RESIM_ROOT_PREFIX' not in comp_dict[cell_name]:
                    if cell_name == 'driver':
                        print('Driver missing RESIM_ROOT_PREFIX, will not be analyzed')
                        continue
                    print('Target missing RESIM_ROOT_PREFIX path')
                    self.lgr.error('Target missing RESIM_ROOT_PREFIX path')
                    self.quit()
                    return;
            try:
                root_prefix = comp_dict[cell_name]['RESIM_ROOT_PREFIX']
            except:
                self.lgr.error('RESIM_ROOT_PREFIX for cell %s is either not defined, or the path is wrong.' % cell_name)
                self.quit()
                return
            root_subdirs = []
            if 'RESIM_ROOT_SUBDIRS' in comp_dict[cell_name]:
                sub_dirs = comp_dict[cell_name]['RESIM_ROOT_SUBDIRS']
                parts = sub_dirs.split(';')
                for sd in parts:
                    root_subdirs.append(sd.strip()) 
            if self.isWindows(cell_name):
                self.targetFS[cell_name] = winTargetFS.TargetFS(self, root_prefix, root_subdirs, self.lgr)
            else:
                self.targetFS[cell_name] = targetFS.TargetFS(self, root_prefix, root_subdirs)
            self.lgr.debug('targetFS for %s is %s' % (cell_name, self.targetFS[cell_name]))

            self.netInfo[cell_name] = net.NetAddresses(self.lgr)
            self.call_traces[cell_name] = {}
            #self.proc_list[cell_name] = {}
            #self.stack_base[cell_name] = {}
            if self.run_from_snap is not None:
                net_file = os.path.join('./', self.run_from_snap, cell_name, 'net_list.pickle')
                if os.path.isfile(net_file):
                    self.netInfo[cell_name].loadfile(net_file)
                    self.lgr.debug('loaded net_list from %s' % net_file)

            if 'ARM_SVC' in comp_dict[cell_name]:
                if comp_dict[cell_name]['ARM_SVC'].lower() in ['false', 'no']:
                    self.param[cell_name].arm_svc = False 
        self.lgr.debug('genInit finished')

    def runPreScripts(self):
        ''' run the PRE_INIT_SCRIPT, if any'''
        init_script = os.getenv('PRE_INIT_SCRIPT')
        if init_script is not None:
            cmd = 'run-command-file %s' % init_script
            SIM_run_command(cmd)
            self.lgr.debug('ran PRE_INIT_SCRIPT %s' % init_script)

    def runScripts(self):
        ''' run the INIT_SCRIPT and the one_done module, if any '''
        self.lgr.debug('runScripts')
        init_script = os.getenv('INIT_SCRIPT')
        if init_script is not None:
            self.lgr.debug('run INIT_SCRIPT %s' % init_script)
            cmd = 'run-command-file %s' % init_script
            SIM_run_command(cmd)
            self.lgr.debug('ran INIT_SCRIPT %s' % init_script)
        if self.one_done_module is not None:
            #self.one_done_module.onedone(self)
            self.lgr.debug('one_done_module defined, call it')
            self.one_done_module.onedone(self)
            #SIM_run_alone(self.one_done_module.onedone, self)

    def getTopComponentName(self, cpu):
         if cpu is not None:
             names = cpu.name.split('.')
             return names[0]
         else:
             return None

    def stopModeChanged(self, stop_action, one, exception, error_string):
        cpu, comm, this_tid = self.task_utils[self.target].curThread() 
        eip = self.mem_utils[self.target].getRegValue(cpu, 'eip')
        instruct = SIM_disassemble_address(cpu, eip, 1, 0)
        cpl = memUtils.getCPL(cpu)
        if cpl == 0:
            reason = None
            if eip == self.param[self.target].sysenter:
                reason = "sysenter"
            elif eip == self.param[self.target].sys_entry:
                reason = "sys_entry"
            elif cpu.architecture.startswith('arm') and eip == self.param[self.target].arm64_entry:
                reason = "sys_entry"
            elif eip == self.param[self.target].page_fault:
                reason = "page_fault"
            call_info = ''
            if reason is not None and reason != 'page_fault':
                callnum = self.mem_utils[self.target].getRegValue(cpu, 'syscall_num')
                callname = self.task_utils[self.target].syscallName(callnum, self.is_compat32)
                call_info = 'callnum %d (%s)  compat32: %r' % (callnum, callname, self.is_compat32)
            self.lgr.debug('\tstopModeChanged entered kernel, eip 0x%x %s reason: %s %s tid:%s' % (eip, instruct[1], reason, call_info, this_tid))
        self.lgr.debug('stopModeChanged, continue')
        SIM_run_alone(SIM_continue, 0)

    def modeChangeReport(self, want_tid, one, old, new):
        cpu, comm, this_tid = self.task_utils[self.target].curThread() 
        if want_tid != this_tid:
            #self.lgr.debug('mode changed wrong tid, wanted %d got %d' % (want_tid, this_tid))
            return
        if new == Sim_CPU_Mode_Supervisor:
            new_mode = 'kernel'
        elif new == Sim_CPU_Mode_User:
            new_mode = 'user'
        else:
            new_mode = 'hypervisor'
        eip = self.mem_utils[self.target].getRegValue(cpu, 'eip')
        phys = self.mem_utils[self.target].v2p(cpu, eip)
        callnum = self.mem_utils[self.target].getRegValue(cpu, 'syscall_num')
        self.lgr.debug('modeChangeReport new mode: %s get phys of eip: 0x%x eax: 0x%x tid:%s cycle: 0x%x' % (new_mode, eip, callnum, this_tid, cpu.cycles))
        if phys is not None:
            instruct = SIM_disassemble_address(cpu, phys, 0, 0)
            if new_mode == 'user':
                reason = None
                if eip == self.param[self.target].iretd:
                    reason = "iretd"
                elif eip == self.param[self.target].sysret64:
                    reason = "sysret64"
                elif eip == self.param[self.target].sysexit:
                    reason = "sysexit"
                self.lgr.debug('modeChangeReport returned to user from eip 0x%x %s reason: %s' % (eip, instruct[1], reason))
            elif new_mode == 'kernel':
                self.lgr.debug('modeChangeReport entering kernel from eip 0x%x %s ' % (eip, instruct[1]))
            else:
                self.lgr.debug('modeChangeReport entering hypervisor from eip 0x%x %s ' % (eip, instruct[1]))
                
        else:
            self.lgr.debug('modeChangeReport new mode: %s  eip 0x%x eax 0x%x  Failed getting phys for eip' % (new_mode, eip, callnum))


        SIM_break_simulation('mode changed')

    def modeChanged(self, tid_list, one, old, new):
        cpu = self.cell_config.cpuFromCell(self.target)
        cpl = memUtils.getCPL(cpu)
        eip = self.mem_utils[self.target].getRegValue(cpu, 'pc')
        if new == Sim_CPU_Mode_Hypervisor or old == Sim_CPU_Mode_Hypervisor:
            return
        elif new == Sim_CPU_Mode_Supervisor: 
            mode = 0
        elif new == Sim_CPU_Mode_User:
            mode = 1
            #if cpu.architecture == 'arm64' and cpu.in_aarch64:
            #    self.lgr.debug('modeChanged arm64 in user space with aarch64, not yet handled, bail')
            #    return
        dumb, comm, this_tid = self.task_utils[self.target].curThread() 
        ''' note may both be None due to failure of getProc '''
        if this_tid not in tid_list:
            ''' or just want may be None if debugging some windows dead zone '''
            #if want_tid is None and this_tid is not None:
            #    SIM_break_simulation('mode changed, tid was None, now is not none.')
            if this_tid is not None:            
                self.lgr.debug('mode changed to %d wrong tid, wanted %s got %s' % (mode, str(tid_list), this_tid))
                alive = False
                for tid in tid_list:
                    rec = self.task_utils[self.target].getRecAddrForTid(tid)
                    if rec is not None:
                        alive = True
                        break
                if not alive:
                    self.lgr.debug('modeChanged no recs for tids %s, assume dead' % str(tid_list))
                    print('modeChanged no recs for tids %s, assume dead' % str(tid_list))
                    self.context_manager[self.target].setIdaMessage('Process gone')
                    SIM_break_simulation('mode changed, tid %s threads all gone' % str(tid_list))
                    
                return
            else:
                self.lgr.error('mode changed wrong tid, wanted %s got NONE, will break here' % (str(tid_list)))
        instruct = SIM_disassemble_address(cpu, eip, 0, 0)
        self.lgr.debug('modeChanged tid:%s cpl reports %d hap reports %d  trigger_obj is %s old: %d  new: %d  eip: 0x%x ins: %s' % (this_tid, cpl, 
                mode, str(one), old, new, eip, instruct[1]))
        SIM_break_simulation('mode changed, break simulation')
        
    def stopHap(self, stop_action, one, exception, error_string):
        self.lgr.debug('stopHap')
        if self.stop_hap is not None:
            SIM_run_alone(self.stopHapAlone, stop_action)

    def stopHapAlone(self, stop_action):
        if stop_action is None or stop_action.hap_clean is None:
            print('stopHap error, stop_action None?')
            self.lgr.error('stopHapAlone error, stop_action None?')
            return 
        if stop_action.prelude is not None:
            stop_action.prelude()
        dumb, comm, tid = self.task_utils[self.target].curThread() 
        ''' note, curThread may fail, best effort for debugging why it failed.'''
        cpu = self.cell_config.cpuFromCell(self.target)
        wrong_tid = False
        if stop_action.tid is not None and tid != stop_action.tid:
            ''' likely some other tid in our group '''
            wrong_tid = True
        eip = self.getEIP(cpu)
        self.lgr.debug('genMonitor stopHap tid %s eip 0x%x cycle: 0x%x wrong_tid: %r' % (tid, eip, stop_action.hap_clean.cpu.cycles, wrong_tid))
        for hc in stop_action.hap_clean.hlist:
            if hc.hap is not None:
                if hc.htype == 'GenContext':
                    self.lgr.debug('genMonitor stopHap stopAction delete GenContext hap %s' % str(hc.hap))
                    self.context_manager[self.target].genDeleteHap(hc.hap)
                else:
                    self.lgr.debug('genMonitor stopHap stopAction will delete hap %s type %s' % (str(hc.hap), str(hc.htype)))
                    RES_hap_delete_callback_id(hc.htype, hc.hap)
                hc.hap = None

        for bp in stop_action.breakpoints:
            RES_delete_breakpoint(bp)
        del stop_action.breakpoints[:]

        if self.stop_hap is not None:
            self.lgr.debug('genMonitor stopHap will delete hap %s' % str(self.stop_hap))
            self.RES_delete_stop_hap(self.stop_hap)
            self.stop_hap = None
        self.is_compat32 = self.compat32()
        ''' check functions in list '''
        self.lgr.debug('stopHap compat32 is %r now run actions %s wrong_tid %r' % (self.is_compat32, stop_action.listFuns(), wrong_tid))
        stop_action.run(wrong_tid=wrong_tid)
        self.is_monitor_running.setRunning(False)
        self.lgr.debug('stopAlone back from stop_action.run')

        if stop_action.tid is not None and tid != stop_action.tid:
            self.lgr.debug('stopHap wrong tid:%s expected %d reverse til we find tid ' % (tid, stop_action.tid))
            ''' set up for revToTid, set function to the wrong_tid_action '''
            hap_clean = hapCleaner.HapCleaner(cpu)
            f1 = stopFunction.StopFunction(stop_action.wrong_tid_action, [], nest=False, match_tid=True)
            new_stop_action = hapCleaner.StopAction(hap_clean, tid=stop_action.tid, wrong_tid_action=stop_action.wrong_tid_action)
            SIM_run_alone(self.revToTid, stop_action)
        else:
            self.lgr.debug('genMonitor stopHap enable-vmp')
            SIM_run_command('enable-vmp')

    def revToTid(self, tid):
        cpu, comm, cur_tid = self.task_utils[self.target].curThread() 
        phys_current_task = self.task_utils[self.target].getPhysCurrentTask()
        self.proc_break = SIM_breakpoint(cpu.physical_memory, Sim_Break_Physical, Sim_Access_Write, 
                             phys_current_task, self.mem_utils[self.target].WORD_SIZE, 0)
        hap_clean = hapCleaner.HapCleaner(cpu)
        ''' when we stop, rev 1 to revert the current task value '''
        stop_action = hapCleaner.StopAction(hap_clean, breakpoints=[self.proc_break], tid=tid, prelude=self.rev1NoMail)
        self.stop_hap = self.RES_add_stop_callback(self.stopHap, stop_action)
        self.lgr.debug('revToTid hap set, break on 0x%x now reverse' % phys_current_task)
        SIM_run_command('rev')

    def stopAndAction(self, stop_action):
        self.lgr.debug('stopAndAction')
        self.stop_hap = RES_hap_add_callback(self.stopHap, stop_action)
        self.lgr.debug('stopAndAction set stop_hap is now %d  now stop' % self.stop_hap)
        SIM_break_simulation('stopAndAction')

    def run2Kernel(self, cpu, flist=None):
        cpl = memUtils.getCPL(cpu)
        if cpl != 0:
            dumb, comm, tid = self.task_utils[self.target].curThread() 
            self.lgr.debug('run2Kernel in user space (%d), set hap' % cpl)
            self.mode_hap = RES_hap_add_callback_obj("Core_Mode_Change", cpu, 0, self.modeChanged, [tid])
            hap_clean = hapCleaner.HapCleaner(cpu)
            hap_clean.add("Core_Mode_Change", self.mode_hap)
            stop_action = hapCleaner.StopAction(hap_clean, flist=flist)
            self.stop_hap = self.RES_add_stop_callback(self.stopHap, stop_action)
            SIM_continue(0)
        else:
            self.lgr.debug('run2Kernel, already in kernel')
            if flist is not None: 
                #if len(flist) == 1:
                for fun_item in flist:
                    if len(fun_item.args) ==  0:
                        fun_item.fun()
                    else:
                        fun_item.fun(fun_item.args)

    def run2User(self, cpu, flist=None, want_tid=None):
        cpl = memUtils.getCPL(cpu)
        if cpl == 0:
            tid = self.task_utils[self.target].curTID() 
            self.lgr.debug('run2User want_tid %s tid:%s' % (want_tid, tid))
            ''' use debug process if defined, otherwise default to current process '''
            if want_tid is not None:
                want_tid = str(want_tid)
                self.lgr.debug('run2User has want_tid of %s' % want_tid)
                tid_list = [want_tid]
            else:
                tid_list = self.context_manager[self.target].getThreadTids()
                if len(tid_list) == 0:
                    tid_list.append(tid)
                    self.lgr.debug('run2User tidlist from context_manager empty, add self %s' % tid)
                else:
                    self.lgr.debug('run2User tidlist from context_manager is %s' % tid_list)
            #if debug_tid is not None:
            #    if debug_tid != tid:
            #        self.lgr.debug('debug_tid:%s  tid %s' % (debug_tid, tid))
            #        ''' debugging, but not this tid.  likely a clone '''
            #        if not self.context_manager[self.target].amWatching(tid):
            #            ''' stick with original debug tid '''
            #            tid = debug_tid
                    
            self.mode_hap = RES_hap_add_callback_obj("Core_Mode_Change", cpu, 0, self.modeChanged, tid_list)
            self.lgr.debug('run2User tid %s in kernel space (%d), set mode hap %d' % (str(tid_list), cpl, self.mode_hap))
            hap_clean = hapCleaner.HapCleaner(cpu)
            # fails when deleted? 
            hap_clean.add("Core_Mode_Change", self.mode_hap)
            stop_action = hapCleaner.StopAction(hap_clean, flist=flist)
            self.stop_hap = self.RES_add_stop_callback(self.stopHap, stop_action)
            self.lgr.debug('run2User added stop_hap of %d' % self.stop_hap)
            simics_status = SIM_simics_is_running()
            if not simics_status:
                self.lgr.debug('run2User continue')
                #SIM_run_alone(SIM_continue, 0)
                SIM_run_alone(self.continueForward, None)
            else:
                self.lgr.debug('run2User would continue, but already running?')
        else:
            self.lgr.debug('run2User, already in user')
            if flist is not None: 
                #if len(flist) == 1:
                for fun_item in flist:
                    if len(fun_item.args) ==  0:
                        fun_item.fun()
                    else:
                        fun_item.fun(fun_item.args)

    def finishInit(self, cell_name):
        
            if cell_name not in self.param or cell_name not in self.targetFS: 
                return
            cpu = self.cell_config.cpuFromCell(cell_name)
            cell = self.cell_config.cell_context[cell_name]
            self.lgr.debug('finishInit for cell %s, cell.name: %s' % (cell_name, cell.name))
            #self.task_utils[cell_name] = taskUtils.TaskUtils(cpu, cell_name, self.param[cell_name], self.mem_utils[cell_name], 
            #      self.unistd[cell_name], self.run_from_snap, self.lgr)
            if not self.isVxDKM(target=cell_name): 
                tu_cur_task_rec = self.task_utils[cell_name].getCurThreadRec()
                if tu_cur_task_rec is None:
                    self.lgr.error('could not read tu_cur_task_rec from taskUtils')
                    return
            self.traceMgr[cell_name] = traceMgr.TraceMgr(self.lgr)
            #if self.param[cell_name].fs_base is None:
            #    cur_task_rec = self.mem_utils[cell_name].getCurrentTask(cpu)
            #    #self.lgr.debug('stack based rec was 0x%x  mine is 0x%x' % (cur_task_rec, tu_cur_task_rec))

            ''' manages setting haps/breaks based on context swtiching.  TBD will be one per cpu '''
            self.context_manager[cell_name] = genContextMgr.GenContextMgr(self, cell_name, self.task_utils[cell_name], self.param[cell_name], cpu, self.lgr) 
            if cell_name != 'driver': 
                self.page_faults[cell_name] = pageFaultGen.PageFaultGen(self, cell_name, self.param[cell_name], self.cell_config, self.mem_utils[cell_name], 
                       self.task_utils[cell_name], self.context_manager[cell_name], self.lgr)
            self.record_entry[cell_name] = recordEntry.RecordEntry(self, cpu, cell_name, self.mem_utils[cell_name], self.task_utils[cell_name], self.context_manager[cell_name], 
                                           self.param[cell_name], self.is_compat32, self.run_from_snap, self.lgr)

            self.reverse_mgr[cell_name] = reverseMgr.ReverseMgr(self.conf, cpu, self.lgr, top=self)
            self.rev_to_call[cell_name] = reverseToCall.reverseToCall(self, cell_name, self.param[cell_name], self.task_utils[cell_name], self.mem_utils[cell_name],
                 self.PAGE_SIZE, self.context_manager[cell_name], 'revToCall', self.is_monitor_running, None, self.log_dir, self.is_compat32, self.run_from_snap, self.record_entry[cell_name], self.reverse_mgr[cell_name])
            self.pfamily[cell_name] = pFamily.Pfamily(self, cell, self.param[cell_name], cpu, self.mem_utils[cell_name], self.task_utils[cell_name], self.lgr)
            self.traceOpen[cell_name] = traceOpen.TraceOpen(self.param[cell_name], self.mem_utils[cell_name], self.task_utils[cell_name], cpu, cell, self.lgr)
            #self.traceProcs[cell_name] = traceProcs.TraceProcs(cell_name, self.lgr, self.proc_list[cell_name], self.run_from_snap)
            self.traceProcs[cell_name] = traceProcs.TraceProcs(cell_name, self.context_manager[cell_name], self.task_utils[cell_name], self.lgr, run_from_snap = self.run_from_snap)
            if self.isWindows(target=cell_name):
                self.soMap[cell_name] = winDLLMap.WinDLLMap(self, cpu, cell_name, self.mem_utils[cell_name], self.task_utils[cell_name], 
                          self.context_manager[cell_name], self.run_from_snap, self.lgr)
            elif self.isVxDKM(target=cell_name):
                self.soMap[cell_name] = vxKModules.VxKModules(self, cell_name, cpu, self.mem_utils[cell_name], self.task_utils[cell_name], 
                          self.targetFS[cell_name], self.comp_dict[cell_name], self.lgr)
            else:
                self.soMap[cell_name] = soMap.SOMap(self, cell_name, cell, cpu, self.context_manager[cell_name], self.task_utils[cell_name], self.targetFS[cell_name], self.run_from_snap, self.lgr)
            self.disassemble_instruct[cell_name] = disassemble.Disassemble(self, cpu, self.soMap[cell_name], self.lgr)
            ''' ugly circular dependency'''
            self.context_manager[cell_name].setSOMap(self.soMap[cell_name])
            self.back_stop[cell_name] = backStop.BackStop(self, cpu, self.lgr)
            self.dataWatch[cell_name] = dataWatch.DataWatch(self, cpu, cell_name, self.PAGE_SIZE, self.context_manager[cell_name], 
                  self.mem_utils[cell_name], self.task_utils[cell_name], self.rev_to_call[cell_name], self.param[cell_name], 
                  self.run_from_snap, self.back_stop[cell_name], self.is_compat32, self.comp_dict[cell_name], self.soMap[cell_name], self.reverse_mgr[cell_name], self.lgr)
            self.trackFunction[cell_name] = trackFunctionWrite.TrackFunctionWrite(cpu, cell, self.param[cell_name], self.mem_utils[cell_name], 
                  self.task_utils[cell_name], 
                  self.context_manager[cell_name], self.lgr)
            self.traceFiles[cell_name] = traceFiles.TraceFiles(self, self.traceProcs[cell_name], self.lgr, cpu)
            self.sharedSyscall[cell_name] = sharedSyscall.SharedSyscall(self, cpu, cell, cell_name, self.param[cell_name], 
                  self.mem_utils[cell_name], self.task_utils[cell_name], 
                  self.context_manager[cell_name], self.traceProcs[cell_name], self.traceFiles[cell_name], 
                  self.soMap[cell_name], self.dataWatch[cell_name], self.traceMgr[cell_name], self.lgr)

            self.syscallManager[cell_name] = syscallManager.SyscallManager(self, cpu, cell_name, self.param[cell_name], self.mem_utils[cell_name], self.task_utils[cell_name],
                                     self.context_manager[cell_name], self.traceProcs[cell_name], self.sharedSyscall[cell_name], self.lgr, self.traceMgr[cell_name], self.soMap[cell_name], 
                                     self.dataWatch[cell_name], self.is_compat32, self.targetFS[cell_name], self.os_type[cell_name])

            self.reverseTrack[cell_name] = reverseTrack.ReverseTrack(self, self.dataWatch[cell_name], self.context_manager[cell_name], 
                  self.mem_utils[cell_name], self.rev_to_call[cell_name], self.lgr)

            self.run_to[cell_name] = runTo.RunTo(self, cpu, cell, cell_name, self.task_utils[cell_name], self.mem_utils[cell_name], self.context_manager[cell_name], 
                                        self.soMap[cell_name], self.traceMgr[cell_name], self.param[cell_name], self.lgr)
            self.stackFrameManager[cell_name] = stackFrameManager.StackFrameManager(self, cpu, cell_name, self.task_utils[cell_name], self.mem_utils[cell_name], 
                                        self.context_manager[cell_name], self.soMap[cell_name], self.targetFS[cell_name], self.run_from_snap, self.disassemble_instruct[cell_name], self.lgr)

            if self.isWindows(target=cell_name):
                self.winMonitor[cell_name] = winMonitor.WinMonitor(self, cpu, cell_name, self.param[cell_name], self.mem_utils[cell_name], self.task_utils[cell_name], 
                                               self.syscallManager[cell_name], self.traceMgr[cell_name], self.traceProcs[cell_name], self.context_manager[cell_name], 
                                               self.soMap[cell_name], self.sharedSyscall[cell_name], self.run_from_snap, self.rev_to_call[cell_name], self.lgr)
            elif self.isVxDKM(target=cell_name):
                self.vxKMonitor[cell_name] = vxKMonitor.VxKMonitor(self, cpu, cell_name, self.mem_utils[cell_name], self.task_utils[cell_name], 
                                               self.soMap[cell_name], self.syscallManager[cell_name], self.context_manager[self.target], 
                                               self.run_from_snap, self.comp_dict[cell_name], self.lgr)

            self.page_callbacks[cell_name] = pageCallbacks.PageCallbacks(self, cpu, self.mem_utils[cell_name], self.lgr)
            self.dmod_mgr[cell_name] = dmodMgr.DmodMgr(self, self.comp_dict[cell_name], cell_name, self.run_from_snap, self.syscallManager[cell_name], 
                                  self.context_manager[cell_name], self.mem_utils[cell_name], self.task_utils[cell_name], self.lgr)
            self.skip_to_mgr[cell_name] = skipToMgr.SkipToMgr(self.reverse_mgr[cell_name], cpu, self.lgr)


            load_jumpers = self.getCompDict(cell_name, 'LOAD_JUMPERS')
            if load_jumpers is not None and (load_jumpers.lower() == 'yes' or load_jumpers.lower() == 'true'):
                self.loadJumpersTarget(cell_name)
            

    def getBootCycleChunk(self):
        run_cycles = None
        for cell_name in self.cell_config.cell_context:
            if cell_name in self.task_utils:
                continue
            if 'FIRST_BOOT_CHUNK' in self.comp_dict[cell_name]:
               new = self.comp_dict[cell_name]['FIRST_BOOT_CHUNK']
               del self.comp_dict[cell_name]['FIRST_BOOT_CHUNK']
               run_cycles = int(new)
               self.lgr.debug('getBootCycleChunk, found FIRST_BOOT_CHUNK is %d' % (run_cycles))
            elif 'BOOT_CHUNKS' in self.comp_dict[cell_name]:
               new = self.comp_dict[cell_name]['BOOT_CHUNKS']
               new = int(new)
               self.lgr.debug('getBootCycleChunk, yes new is %d run_cycles %s' % (new, run_cycles))
               if run_cycles is None:
                   run_cycles = new
               else:
                   run_cycles = min(run_cycles, new)
        if run_cycles is None:
            run_cycles =  900000000
        self.lgr.debug('getBootCycle return %d' % run_cycles)
        return run_cycles
   
    def snapInit(self):
            ''' Running from a snapshot '''
            tfile = os.path.join('./', self.run_from_snap, 'debug_info.pickle')
            if os.path.isfile(tfile):
                self.warnSnapshot()
            for cell_name in self.cell_config.cell_context:
                if cell_name not in self.param:
                    ''' not monitoring this cell, no param file '''
                    continue
                if cell_name not in self.os_type:
                    ''' not monitoring this cell, no os_type means sections missing from ini file'''
                    continue
                if cell_name in self.task_utils:
                    ''' already got taskUtils for this cell '''
                    continue
                cpu = self.cell_config.cpuFromCell(cell_name)
                self.snap_start_cycle[cpu] = cpu.cycles
                if self.os_type[cell_name].startswith('LINUX'):
                    if cell_name not in self.unistd:
                        self.lgr.error('Component %s missing unistd path' % cell_name)
                        self.quit()
                        return
                    unistd32 = None
                    if cell_name in self.unistd32:
                        unistd32 = self.unistd32[cell_name]
                    task_utils = taskUtils.TaskUtils(cpu, cell_name, self.param[cell_name], self.mem_utils[cell_name], 
                        self.unistd[cell_name], unistd32, self.run_from_snap, self.lgr)
                    self.task_utils[cell_name] = task_utils
                elif self.isWindows(target=cell_name):
                    self.task_utils[cell_name] = winTaskUtils.WinTaskUtils(cpu, cell_name, self.param[cell_name],self.mem_utils[cell_name], self.run_from_snap, self.lgr) 
                elif self.isVxDKM(target=cell_name):
                    self.task_utils[cell_name] = vxKTaskUtils.VxKTaskUtils(cpu, cell_name, self.mem_utils[cell_name], self.comp_dict[cell_name], self.run_from_snap, self.lgr) 
                else:
                    self.lgr.error('snapInit unknown os type %s for cell %s' % (self.os_type[cell_name], cell_name))
                    return
                self.lgr.debug('snapInit for cell %s, now call to finishInit' % cell_name)
                self.finishInit(cell_name)
                # see if context manager needs to make some callbacks due the current process being scheduled
                cpu, comm, tid = self.task_utils[cell_name].curThread() 
                proc_rec = self.task_utils[cell_name].getCurProcRec()
                prog = self.traceProcs[cell_name].getProg(tid)
                self.lgr.debug('snapInit for cell %s, call checkFirstSchedule for tid:%s (%s) rec: 0x%x prog: %s' % (cell_name, tid, comm, proc_rec, prog))
                if prog is not None:
                     comm = os.path.basename(prog) 
                self.context_manager[cell_name].checkFirstSchedule(proc_rec, tid, comm, first=True)

 
    def doInit(self):
        ''' Entry point from launchRESim '''
        self.lgr.debug('genMonitor doInit')
        if self.run_from_snap is not None:
            self.snapInit()
            self.runScripts()
            return
        self.runPreScripts()
        #self.fs_mgr = fsMgr.FSMgr(self.cell_config.cell_context, self.param, self.cell_config, self.lgr)
        self.initCells()

    def initCells(self, dumb=None):
        done = False
        run_cycles = self.getBootCycleChunk()
        hack_count = 0
        while not done:
            done = True
            for cell_name in self.cell_config.cell_context:
                self.lgr.debug('genMonitor initCells cell_name %s' % cell_name)
                if cell_name not in self.param:
                    ''' not monitoring this cell, no param file '''
                    continue
                if cell_name in self.task_utils:
                    ''' already got taskUtils for this cell '''
                    self.lgr.debug('already got %s' % cell_name)
                    continue
                cpu = self.cell_config.cpuFromCell(cell_name)
                if self.isVxDKM(target=cell_name):
                    self.task_utils[cell_name] = vxKTaskUtils.VxKTaskUtils(cpu, cell_name, self.mem_utils[cell_name], self.comp_dict[cell_name], None, self.lgr) 
                    self.finishInit(cell_name)
                    continue 
                ''' run until we get something sane '''
                eip = self.getEIP(cpu)
                cpl = memUtils.getCPL(cpu)
                if cpl == 0 and not self.mem_utils[cell_name].isKernel(eip):
                    stall_time = cpu.stall_time
                    self.lgr.debug('doInit cell %s cpl 0 but not in kernel code yet eip 0x%x cycles: 0x%x stall_time 0x%x' % (cell_name, eip, cpu.cycles, stall_time))
                    if False and stall_time != 0:
                        #TBD this should not happen.  If it does, might cause other cells to get to far ahead?
                        if memUtils.cpuWordSize(cpu) == 4:
                            count = 0xffffffff - self.param[cell_name].kernel_base
                        else:
                            count = 0xffffffffffffffff - self.param[cell_name].kernel_base
                        self.proc_bp = SIM_breakpoint(cpu.current_context, Sim_Break_Linear, Sim_Access_Execute, self.param[cell_name].kernel_base, count, 0)
                        self.proc_hap = RES_hap_add_callback_index("Core_Breakpoint_Memop", self.kernelCodeHap, cpu, self.proc_bp)
                        self.lgr.debug('initCell, stalling, run to kernel')
                        SIM_continue(0)
                        return 
                    done = False
                    continue
                self.lgr.debug('doInit cell %s get current task from mem_utils eip: 0x%x cpl: %d' % (cell_name, eip, cpl))
                cur_task_rec = None
                cur_task_rec = self.mem_utils[cell_name].getCurrentTask(cpu)
                if cur_task_rec == 0xdeadbeef:
                    self.lgr.debug('doInit cell hack count %d' % hack_count)
                    if hack_count > 10:
                        SIM_break_simulation('remove this')
                        done = True
                    else:
                        hack_count = hack_count+1
                        done = False
                elif cur_task_rec is None or cur_task_rec == 0:
                    #print('Current task not yet defined, continue')
                    self.lgr.debug('doInit Current task for %s not yet defined, continue' % cell_name)
                    done = False
                elif cur_task_rec == -1:
                    self.lgr.error('debugging')
                    SIM_break_simulation('remove this') 
                else:
                    tid = self.mem_utils[cell_name].readWord32(cpu, cur_task_rec + self.param[cell_name].ts_pid)
                    if tid is None:
                        self.lgr.debug('doInit cell %s cur_task_rec 0x%x tid None ' % (cell_name, cur_task_rec))
                        done = False
                        continue
                    if True:
                        if self.isWindows(cell_name):
                            task_utils = winTaskUtils.WinTaskUtils(cpu, cell_name, self.param[cell_name],self.mem_utils[cell_name], self.run_from_snap, self.lgr) 
                            swapper = task_utils.getSystemProcRec()
                        else: 
                            unistd32 = None
                            if cell_name in self.unistd32:
                                unistd32 = self.unistd32[cell_name]
                            task_utils = taskUtils.TaskUtils(cpu, cell_name, self.param[cell_name], self.mem_utils[cell_name], 
                                self.unistd[cell_name], unistd32, self.run_from_snap, self.lgr)
                            swapper = task_utils.findSwapper()
                        if swapper is None:
                            self.lgr.debug('doInit cell %s taskUtils failed to get swapper, hack harder' % cell_name)
                            done = False
                            #SIM_break_simulation('remove this')
                            #done = True
                        else: 
                            tasks = task_utils.getTaskStructs()
                            if len(tasks) == 1:
                                self.lgr.debug('doInit cell %s taskUtils got swapper, but no other process, hack harder' % cell_name)
                                done = False
                        
                            else:
                                saved_cr3 = self.mem_utils[cell_name].getKernelSavedCR3()
                                if saved_cr3 is not None and self.isWindows(cell_name):
                                    self.lgr.debug('doInit %s saved_cr3 is 0x%x' % (cell_name, saved_cr3))
                                    reg_num = cpu.iface.int_register.get_number("cr3")
                                    current_cr3 = cpu.iface.int_register.read(reg_num)
                                    if saved_cr3 != current_cr3:
                                        self.lgr.debug('doInit saved_cr3 of 0x%x is not the current cr3 value 0x%x.  Not done yet' % (saved_cr3, cr3_val, current_cr3))
                                        done = False
                                        continue
                                    else:
                                        task_utils.savePhysCR3Addr()
                                self.task_utils[cell_name] = task_utils
                                if self.isWindows(cell_name):
                                    self.task_utils[cell_name].setSystemProcessRec()
                                # adjust kernel params for aslr
                                self.mem_utils[cell_name].adjustParam(cpu)
                                self.lgr.debug('doInit Booted enough to get cur_task_rec for cell %s, now call to finishInit' % cell_name)
                                self.finishInit(cell_name)
                                run_cycles = self.getBootCycleChunk()
                    else:
                        self.lgr.debug('doInit cell %s taskUtils got task rec of zero' % cell_name)
                        done = False
            if not done:
                ''' Tried each cell, still not done, advance forward '''
                self.lgr.debug('Tried each, now continue %d cycles' % run_cycles)
                ''' using the most recently selected cpu, continue specified number of cycles '''
                cmd = 'pselect %s' % cpu.name
                dumb, ret = cli.quiet_run_command(cmd)
                cmd = 'c %s cycles' % run_cycles
                #dumb, ret = cli.quiet_run_command(cmd)
                SIM_continue(run_cycles)
                self.lgr.debug('back from continue dumb %s ret %s' % (dumb, ret))
                run_cycles = self.getBootCycleChunk()
            else: 
                self.lgr.debug('doInit done, call runScripts')
        self.runScripts()

    def kernelCodeHap(self, cpu, the_obj, the_break, memory):
        eip = self.getEIP(cpu)
        self.lgr.debug('kernelCodeHap eip 0x%x' % eip)
        RES_delete_breakpoint(self.proc_bp)
        hap = self.proc_hap
        self.proc_hap = None
        self.proc_bp = None
        SIM_run_alone(self.rmKernelCodeHap, hap)
        SIM_run_alone(self.stopAndCall, self.initCells)

    def rmKernelCodeHap(self, hap):
        self.lgr.debug('rmKernelCodeHap')
        RES_hap_delete_callback_id("Core_Breakpoint_Memop", hap)


    def getDbgFrames(self):
        ''' Get stack frames from kernel entries as recorded by the reverseToCall module. 
            If debugging, get all debug threads.  If not debugging, get whatever is recorded.
            NOT this will only get frames that were recorded.
        '''
        self.lgr.debug('getDbgFrames') 
        retval = {}
        if self.isWindows():
            retval = self.winMonitor[self.target].getDbgFrames()
        elif self.isVxDKM():
            pass
        elif not self.debugging():
            self.lgr.debug('getDbgFrames task not debugging. force setup of reverseToCall to get entry frames.')
            cpu = self.cell_config.cpuFromCell(self.target)
            self.rev_to_call[self.target].setup(cpu, [])
            tasks = self.task_utils[self.target].getTaskStructs()
            for t in sorted(tasks):
                tid = str(tasks[t].pid)
                #self.lgr.debug('getDbgFrames task for tid:%s state %d' % (tid, tasks[t].state))
                frame, cycles = self.record_entry[self.target].getRecentCycleFrame(tid)
                if frame is not None:
                    #self.lgr.debug('getDbgFrames add frame for tid:%s' % (tid))
                    retval[tid] = frame
        else:
            plist = {}
            tid_list = self.context_manager[self.target].getThreadTids()
            tasks = self.task_utils[self.target].getTaskStructs()
            self.lgr.debug('getDbgFrames tid_list %s' % str(tid_list))
            plist = {}
            for t in tasks:
                tid = str(tasks[t].pid)
                if tid in tid_list:
                    plist[tid] = t 
        
            self.lgr.debug('getDbgFrames plist %s' % str(plist))
            for tid in sorted(plist):
                t = plist[tid]
                self.lgr.debug('getDbgFrames task for tid:%s state %d' % (tid, tasks[t].state))
                ''' TBD do we care about windows task state?'''
                if True or tasks[t].state > 0:
                    frame, cycles = self.record_entry[self.target].getRecentCycleFrame(tid)
                    if frame is not None:
                        retval[tid] = frame
            self.lgr.debug('getDbgFrames return %d frames' % len(retval))
        return retval 

    def getRecentEnterCycle(self, tid=None):
        ''' return latest cycle in which the kernel was entered for this TID 
            regardless of the current cycle.  '''
        if tid is None:
            cpu, comm, tid = self.task_utils[self.target].curThread() 
        frame, cycles = self.record_entry[self.target].getRecentCycleFrame(tid)
        return frame, cycles

    def getPreviousEnterCycle(self, tid=None):
        ''' return most recent cycle in which the kernel was entered for this TID 
            relative to the current cycle.  '''
        if tid is None:
            cpu, comm, tid = self.task_utils[self.target].curThread() 
        frame, cycles = self.record_entry[self.target].getPreviousCycleFrame(tid)
        return frame, cycles

    def getPrevSyscallInfo(self, tid=None):
        if tid is None:
            cpu, comm, tid = self.task_utils[self.target].curThread() 
        frame, cycles = self.getPreviousEnterCycle(tid=tid)
        call = self.task_utils[self.target].syscallName(frame['syscall_num'], self.is_compat32)
        retval = ''
        #if call == 'socketcall' or call.upper() in net.callname:
        if call == 'socketcall':
            if 'ss' in frame:
                ss = frame['ss']
                socket_callnum = frame['param1']
                socket_callname = net.callname[socket_callnum].lower()
                retval = ('\ttid: %s syscall %s %s fd: %d sp: 0x%x pc: 0x%x cycle: 0x%x' % (tid, 
                     call, socket_callname, ss.fd, frame['sp'], frame['pc'], cycles))
            else:
                retval = ('\ttid: %s socketcall but no ss in frame?' % tid)
        else:
            retval = ('\ttid: %s syscall %s param1: %d sp: 0x%x pc: 0x%x cycle: 0x%x' % (tid, 
                 call, frame['param1'], frame['sp'], frame['pc'], cycles))
        return retval

    def revToSyscall(self):
        frame, cycles = self.getPreviousEnterCycle()
        self.lgr.debug('revToSyscal got cycles 0x%x' % cycles)
        cpu, comm, tid = self.task_utils[self.target].curThread() 
        prev = cycles-1
        self.skip_to_mgr[self.target].skipToTest(prev)
        print('Reversed to previous syscall:') 
        self.lgr.debug('Reversed to previous syscall:') 
        call = self.task_utils[self.target].syscallName(frame['syscall_num'], self.is_compat32)
        if call == 'socketcall' or call.upper() in net.callname:
            if 'ss' in frame:
                ss = frame['ss']
                socket_callnum = frame['param1']
                socket_callname = net.callname[socket_callnum].lower()
                print('\ttid: %s syscall %s %s fd: %d sp: 0x%x pc: 0x%x cycle: 0x%x' % (tid, 
                     call, socket_callname, ss.fd, frame['sp'], frame['pc'], cycles))
            else:
                print('\ttid: %s socketcall but no ss in frame?' % tid)
        else:
            print('\ttid: %s syscall %s param1: %d sp: 0x%x pc: 0x%x cycle: 0x%x' % (tid, 
                 call, frame['param1'], frame['sp'], frame['pc'], cycles))

    def tasksDBG(self, tid=None):
        cpu, cur_comm, cur_tid = self.task_utils[self.target].curThread() 
        plist = {}
        tid_list = self.context_manager[self.target].getThreadTids()
        force_cpu = None
        if tid is None:
            tid = cur_tid
        if len(tid_list) == 0:
            tid_list.append(id)
            force_cpu = cpu
        tasks = self.task_utils[self.target].getTaskStructs()
        self.lgr.debug('tasksDBG, tid_list is %s' % str(tid_list))
        print('Status of debugging threads')
        plist = {}
        for t in tasks:
            tid = str(tasks[t].pid)
            if tid in tid_list:
                plist[tid] = t 
        for tid in sorted(plist):
            this_in_kernel = False
            if tid == cur_tid:
                cpl = memUtils.getCPL(cpu)
                if cpl == 0:
                    this_in_kernel = True   
            t = plist[tid]
            if this_in_kernel or (tasks[t].state > 0 and tasks[t].state != 64):
                frame, cycles = self.record_entry[self.target].getPreviousCycleFrame(tid, cpu=force_cpu)
                if frame is None:
                    print('Nothing in previous, try recent loaded from pickle')
                    frame, cycles = self.record_entry[self.target].getRecentCycleFrame(tid)
                if frame is None:
                    #frame, cycles = self.rev_to_call[self.target].getRecentCycleFrame(tid)
                    print('frame for %s was none' % tid)
                    continue
                call = self.task_utils[self.target].syscallName(frame['syscall_num'], self.is_compat32)
                if call == 'socketcall' or call.upper() in net.callname:
                    if 'ss' in frame:
                        ss = frame['ss']
                        socket_callnum = frame['param1']
                        socket_callname = net.callname[socket_callnum].lower()
                        print('tid: %s syscall %s %s fd: %d task_addr: 0x%x sp: 0x%x pc: 0x%x cycle: 0x%x state: %d' % (tid, 
                             call, socket_callname, ss.fd, tasks[t].addr, frame['sp'], frame['pc'], cycles, tasks[t].state))
                    else:
                        print('tid: %s socketcall but no ss in frame?' % tid)
                else:
                    print('tid: %s syscall %s param1: %d task_addr: 0x%x sp: 0x%x pc: 0x%x cycle: 0x%x state: %d' % (tid, 
                         call, frame['param1'], tasks[t].addr, frame['sp'], frame['pc'], cycles, tasks[t].state))
            else:
                print('tid: %s in user space?' % tid)

    def getThreads(self):
        ''' Return a json rep of tasksDBG '''
        plist = {}
        tid_list = self.context_manager[self.target].getThreadTids()
        tasks = self.task_utils[self.target].getTaskStructs()
        self.lgr.debug('getThreads, tid_list is %s' % str(tid_list))
        plist = {}
        for t in tasks:
            tid = str(tasks[t].pid)
            if tid in tid_list:
                plist[tid] = t 
        retval = []
        for tid in sorted(plist):
            tid_state = {} 
            tid_state['tid'] = tid
            t = plist[tid]
            if tasks[t].state > 0:
                frame, cycles = self.record_entry[self.target].getRecentCycleFrame(tid)
                if frame is None:
                    #print('frame for %s was none' % tid)
                    continue
                call = self.task_utils[self.target].syscallName(frame['syscall_num'], self.is_compat32)
                if call == 'socketcall' or call.upper() in net.callname:
                    if 'ss' in frame:
                        ss = frame['ss']
                        socket_callnum = frame['param1']
                        socket_callname = net.callname[socket_callnum].lower()
                        tid_state['call'] = socket_callname
                        tid_state['fd'] = ss.fd
                        tid_state['sp'] = frame['sp']
                        tid_state['pc'] = frame['pc']
                        tid_state['cycles'] = cycles
                        tid_state['state'] = tasks[t].state
                        #print('tid: %s syscall %s %s fd: %d task_addr: 0x%x sp: 0x%x pc: 0x%x cycle: 0x%x state: %d' % (tid, 
                        #     call, socket_callname, ss.fd, tasks[t].addr, frame['sp'], frame['pc'], cycles, tasks[t].state))
                    else:
                        print('tid: %s socketcall but no ss in frame?' % tid)
                else:
                    #print('tid: %s syscall %s param1: %d task_addr: 0x%x sp: 0x%x pc: 0x%x cycle: 0x%x state: %d' % (tid, 
                    #     call, frame['param1'], tasks[t].addr, frame['sp'], frame['pc'], cycles, tasks[t].state))
                    tid_state['call'] = call
                    tid_state['param1'] = frame['param1']
                    tid_state['sp'] = frame['sp']
                    tid_state['pc'] = frame['pc']
                    tid_state['cycles'] = cycles
                    tid_state['state'] = tasks[t].state
            else:
                tid_state['call'] = None
                #print('tid: %s in user space?' % tid)
            retval.append(tid_state)
        print(json.dumps(retval))

    def tasks(self, target=None, filter=None, file=None, verbose=False):
        self.lgr.debug('tasks')
        if target is None:
            target = self.target
        if file is not None:
            fh = open(file, 'w')
        else:
            fh = None
        print('Tasks on cell %s' % target)
        if fh is not None:
            fh.write('Tasks on cell %s\n' % target)

        if self.isWindows():
            self.winMonitor[target].tasks(filter=filter, file=file)
        else:
            tasks = self.task_utils[target].getTaskStructs()
            plist = {}
            for t in tasks:
                plist[tasks[t].pid] = t 
            for tid in sorted(plist):
                t = plist[tid]
                if filter is None or filter in tasks[t].comm:
                    uid, e_uid = self.task_utils[target].getCred(t)
                    if uid is not None:
                        id_str = 'uid: %d  euid: %d' % (uid, e_uid)        
                    else:
                        id_str = ''
                    if verbose:
                        name = self.getProgName(tid)
                        '''
                        prog = self.soMap[self.target].getProg(tid)
                        if prog is None:
                            if self.target in self.traceProcs:
                                prog = self.traceProcs[self.target].getProg(tid)
                        if prog is not None:
                            name = os.path.basename(prog)
                        else:
                            name = tasks[t].comm
                        '''
                    else:
                        name = tasks[t].comm
                    # catch garbage
                    if type(tasks[t].next) is not int:
                        print('Error getting task info at task rec 0x%x' % t)
                        break
                    print('tid: %d taks_rec: 0x%x  comm: %s state: %d next: 0x%x leader: 0x%x parent: 0x%x tgid: %d %s' % (tasks[t].pid, t, 
                        name, tasks[t].state, tasks[t].next, tasks[t].group_leader, tasks[t].real_parent, tasks[t].tgid, id_str))
                    if fh is not None:
                        fh.write('tid: %d taks_rec: 0x%x  comm: %s state: %d next: 0x%x leader: 0x%x parent: 0x%x tgid: %d %s\n' % (tasks[t].pid, t, 
                            tasks[t].comm, tasks[t].state, tasks[t].next, tasks[t].group_leader, tasks[t].real_parent, tasks[t].tgid, id_str))
            

    def setDebugBookmark(self, mark, cpu=None, cycles=None, eip=None, steps=None):
        if self.bookmarks is not None:
            self.lgr.debug('setDebugBookmark')
            if not self.rev_execution_enabled:
                self.lgr.warning('setDebugBookmark called, but reverse not enabled, will ignore')
            else:
                tid, cpu = self.context_manager[self.target].getDebugTid() 
                self.bookmarks.setDebugBookmark(mark, cpu=cpu, cycles=cycles, eip=eip, steps=steps, msg=self.context_manager[self.target].getIdaMessage())
        else:
            self.lgr.debug('setDebugBookmark, but self.bookmarks is None')

    def debugGroup(self):
        self.debug(group=True)

    def doDebugCmd(self, tid = None):
        ''' Note, target may not be currently scheduled '''
        cpu, comm, this_tid = self.task_utils[self.target].curThread() 
        if tid is None:
            tid = this_tid 
        machine_size = self.soMap[self.target].getMachineSize(tid)
        self.lgr.debug('doDebugCmd for cpu %s arch: %s port will be %d.  Tid is %s compat32 %r machine size %s' % (cpu.name, cpu.architecture, self.gdb_port, tid, self.is_compat32, machine_size))
        if cpu.architecture == 'arm':
            cmd = 'new-gdb-remote cpu=%s architecture=arm port=%d' % (cpu.name, self.gdb_port)
        elif cpu.architecture == 'arm64':
            if machine_size == 32:
                cmd = 'new-gdb-remote cpu=%s architecture=arm port=%d' % (cpu.name, self.gdb_port)
            else:
                cmd = 'new-gdb-remote cpu=%s architecture=arm64 port=%d' % (cpu.name, self.gdb_port)
        if cpu.architecture == 'ppc32':
            cmd = 'new-gdb-remote cpu=%s architecture=ppc32 port=%d' % (cpu.name, self.gdb_port)
        #elif self.mem_utils[self.target].WORD_SIZE == 8 and not self.is_compat32:
        elif self.isWindows(self.target):
            machine_size = self.soMap[self.target].getMachineSize(tid)
            self.lgr.debug('doDebugCmd machine_size got %s' % machine_size)
            if machine_size is None:
                ''' hack for compatability with older windows tests. remove after all saved SOMaps have machine '''
                dumb, machine, dumb2, dumb3 = winProg.getSizeAndMachine(self.full_path, self.lgr)
                if machine is None:
                    self.lgr.error('doDebugCmd failed to get machine value from %s' % self.full_path)
                    machine_size = 64
                elif 'I386' in machine:
                    machine_size = 32
                elif 'AMD64' in machine:
                    machine_size = 64
            if machine_size == 32:
                cmd = 'new-gdb-remote cpu=%s architecture=x86 port=%d' % (cpu.name, self.gdb_port)
            elif machine_size == 64:
                cmd = 'new-gdb-remote cpu=%s architecture=x86-64 port=%d' % (cpu.name, self.gdb_port)
            else:
                self.lgr.error('doDebugCmd failed to get windows machine type')
                return None 

        elif self.mem_utils[self.target].WORD_SIZE == 8 and not self.is_compat32:
            cmd = 'new-gdb-remote cpu=%s architecture=x86-64 port=%d' % (cpu.name, self.gdb_port)
        else:
            cmd = 'new-gdb-remote cpu=%s architecture=x86 port=%d' % (cpu.name, self.gdb_port)
        self.lgr.debug('cmd: %s' % cmd)
        try:
            SIM_run_command(cmd)
        #except simics.SimExc_General:
        except SimExc_General as e:
            self.lgr.debug('doDebugCmd new-gdb-remote failed, likely running runTrack? %s' % e.toString())

    def setPathToProg(self, tid):
        local_path = self.soMap[self.target].getLocalPath(tid)
        if local_path is None:
            prog_name = self.getProgName(tid)
            if self.targetFS[self.target] is not None and prog_name is not None:
                full_path = self.targetFS[self.target].getFull(prog_name, self.lgr)
                self.full_path = full_path
                self.lgr.debug('setPathToProg tid:%s set full_path to %s' % (tid, full_path))
        else:
            self.full_path = local_path
            self.lgr.debug('setPathToProg tid:%s set full_path to local path gotten from SO map %s' % (tid, local_path))

    def debug(self, group=False):
        '''
        Called when process is ready to be debugged, often as the last item in a hap chain.  The process
        has likely populated its shared libraries and has just returned back to its text segment.
         
        '''
        if group is not None and type(group) == str:
            print('Did you mean debugProc?')
            return
    
        self.lgr.debug('genMonitor debug group is %r' % group)
        #self.stopTrace()    
        cpu = self.cell_config.cpuFromCell(self.target)
        cell_name = self.getTopComponentName(cpu)
        if self.target not in self.magic_origin:
            if resimSimicsUtils.serviceNodeConnected('driver_service_node', lgr=self.lgr):
                self.magic_origin[self.target] = magicOrigin.MagicOrigin(self, cpu, self.bookmarks, self.lgr)
        if not self.did_debug:
            ''' Our first debug '''
            cpu, comm, tid = self.task_utils[self.target].curThread() 
            if self.full_path is None:
                ''' This will set full_path'''
                self.setPathToProg(tid)
                self.lgr.debug('debug called setPathToProg for tid %s full_path now %s' % (tid, self.full_path))
            # TBD already called in debugTidList.  Does a group==True cover it?
            if not group or self.bookmarks is None:
                if not self.no_gdb and self.bookmarks is None:
                    self.lgr.debug('genMonitor debug call doDebugCmd')
                    self.doDebugCmd()
                if self.bookmarks is None:
                    self.bookmarks = bookmarkMgr.bookmarkMgr(self, self.context_manager[self.target], self.lgr)
                    self.bookmarks.setOrigin(cpu)
                    self.debugger_target = self.target
            self.did_debug=True
            if not self.rev_execution_enabled:
                self.lgr.debug('debug enable reverse execution')
                ''' only exception is AFL coverage on target that differs from consumer of injected data '''
                self.reverse_mgr[self.target].enableReverse()
                self.rev_execution_enabled = True
                #self.setDebugBookmark('origin', cpu)
                self.bookmarks.setOrigin(cpu)
            ''' tbd, this is likely already set by some other action, no harm '''
            self.context_manager[self.target].watchTasks()
            self.context_manager[self.target].setDebugTid()
            self.recordEntry()
            #self.lgr.debug('debug restore RESim context')
            # this is already done in setDebugTid???
            #self.context_manager[self.target].restoreDebugContext()
            self.debug_breaks_set = True

            if group:
                leader_tid = self.task_utils[self.target].getGroupLeaderTid(tid)
                tid_list = self.task_utils[self.target].getGroupTids(leader_tid)
                self.lgr.debug('genManager debug, will debug entire process group under leader %s %s' % (leader_tid, str(tid_list)))
                for tmp_tid in tid_list:
                    self.context_manager[self.target].addTask(tmp_tid)

            ''' keep track of threads within our process that are created during debug session '''
            cpl = memUtils.getCPL(cpu)
            if cpl == 0:
                self.lgr.warning('debug: not in user space, x86 32-bit compat mode may miss clones')

            if not self.isVxDKM(cpu=cpu):
                self.syscallManager[self.target].rmSyscall('runToText', immediate=True)
                self.lgr.debug('genMonitor debug removed open/mmap syscall, now track threads')

                if self.track_threads is not None:
                    # cheesy hack of setting dict to None if we don't want to track threads
                    self.lgr.debug('genMonitor debug call trackThreads becuase the hack is not None')
                    self.trackThreads()
                    ''' By default, no longer watch for new SO files '''
                    self.track_threads[self.target].stopSOTrack()

                self.watchPageFaults(tid)

                self.sharedSyscall[self.target].setDebugging(True)
            prog_name = self.getProgName(tid)
            if self.targetFS[self.target] is not None and prog_name is not None:
                sindex = 0
                if self.full_path is not None:
                    self.lgr.debug('debug, set target fs, progname is %s  full: %s' % (prog_name, self.full_path))
                    real_path = resimUtils.realPath(self.full_path)
                    ''' this is not actually the text segment, it is the entire range of main program sections ''' 
                    if self.isWindows(self.target):
                        ''' Assumes winProg has already populated soMap'''
                        # Note this call will add the text section after getting the load address from the peb
                        load_info = self.soMap[self.target].getLoadInfo()
                    elif self.isVxDKM(target=self.target):
                        load_info = self.soMap[self.target].getModuleInfo(prog_name)
                    else:
                        load_info = self.soMap[self.target].addText(real_path, prog_name, tid)
                    if load_info is not None and load_info.addr is not None:
                        root_prefix = self.comp_dict[self.target]['RESIM_ROOT_PREFIX']
                        self.fun_mgr = funMgr.FunMgr(self, cpu, cell_name, self.mem_utils[self.target], self.lgr)
                        if self.isWindows():
                            image_base = self.soMap[self.target].getImageBase(prog_name)
                            offset = load_info.addr - image_base
                            self.fun_mgr.getIDAFuns(self.full_path, root_prefix, offset)
                        elif self.isVxDKM():
                            module_info = self.soMap[self.target].getModuleInfo(prog_name)
                            offset = module_info.addr
                            self.fun_mgr.getIDAFuns(self.full_path, root_prefix, offset)
                        else:
                            if self.soMap[self.target].isDynamic(prog_name):
                                image_base = self.soMap[self.target].getImageBase(prog_name)
                                offset = load_info.addr - image_base
                                self.lgr.debug('debug is dynamic, use load address as offset 0x%x image_base 0x%x' % (offset, image_base))
                            else:
                                offset = 0
                            self.fun_mgr.getIDAFuns(self.full_path, root_prefix, offset)
                        ''' TBD alter stackTrace to use this and buid it out'''
                        #self.context_manager[self.target].recordText(elf_info.address, elf_info.address+elf_info.size)
                        self.soMap[self.target].setFunMgr(self.fun_mgr, tid)
                        self.bookmarks.setFunMgr(self.fun_mgr)
                        self.dataWatch[self.target].setFunMgr(self.fun_mgr)
                        self.lgr.debug('ropCop instance for %s' % self.target)
                        self.ropCop[self.target] = ropCop.RopCop(self, cpu, cell_name, self.context_manager[self.target],  self.mem_utils[self.target],
                             load_info.addr, load_info.size, self.bookmarks, self.task_utils[self.target], self.lgr)
                    elif load_info is not None:
                        self.lgr.error('debug, text segment missing load address for %s.  Perhaps program was running before being debugged?' % self.full_path)
                  
                    else:
                        self.lgr.error('debug, text segment None for %s' % self.full_path)
                    self.lgr.debug('create coverage module')
                    ida_path = self.getIdaData(self.full_path)
                    if ida_path is not None and self.target in self.soMap:
                        analysis_path = self.soMap[self.target].getAnalysisPath(self.full_path)
                        if analysis_path is None:
                            analysis_path = self.full_path
                            self.lgr.debug('coverage, no analysis path, revert to full_path')
                        self.lgr.debug('debug, create Coverage ida_path %s, analysis path: %s' % (ida_path, analysis_path))
                        
                        self.coverage = coverage.Coverage(self, prog_name, analysis_path, ida_path, self.context_manager[self.target], 
                           cell_name, self.soMap[self.target], self.mem_utils[self.target], cpu, self.run_from_snap, self.lgr)
                        if self.coverage is None:
                            self.lgr.error('debug: Coverage is None!')
                        else:
                            self.lgr.debug('debug: Coverage %s' % str(coverage))
                    if self.coverage is None:
                        self.lgr.debug('Coverage is None!')
                else:
                    print('Warning, no program file for %s relative to root prefix.' % prog_name)
                    self.lgr.debug('debug Failed to get full path for %s' % prog_name)
            rprint('Now debugging %s' % prog_name)
            if self.fun_mgr is None:
                self.lgr.debug('Warning no fun_mgr is defined.  Do not know what we are debugging?')
            elif not self.fun_mgr.hasIDAFuns(comm=comm):
                self.lgr.debug('Warning program functions not found.  Dump functions from IDA or Ghidra')
                rprint('Warning program functions not found.  Dump functions from IDA or Ghidra')
            if self.debug_callback is not None:
                self.lgr.debug('debug do callback to %s' % str(self.debug_callback))
                cb = self.debug_callback
                param = self.debug_callback_param
                SIM_run_alone(cb, param)
                self.debug_callback = None
                self.debug_callback_param = None
        else:
            ''' already debugging as current process '''
            self.lgr.debug('genMonitor debug, already debugging')
            self.context_manager[self.target].setDebugTid()

        if not self.disable_reverse:
            self.lgr.debug('debug call rev_to_call.setup with bookmarks %s' % self.bookmarks)
            self.rev_to_call[self.target].setup(cpu, [], bookmarks=self.bookmarks, page_faults = self.page_faults[self.target])
        self.task_utils[self.target].clearExitTid()
        ''' Otherwise not cleared when pageFaultGen is stopped/started '''
        self.page_faults[self.target].clearFaultingCycles()
        self.record_entry[self.target].clearEnterCycles()
        self.is_monitor_running.setRunning(False)

        jumper_file = os.getenv('EXECUTION_JUMPERS')
        if jumper_file is not None:
            self.lgr.error('Please remove EXECUTION_JUMPERS from ENV section.  Place them in target sections.')

        self.loadJumpersTarget(self.target)

        if self.target in self.reg_set:
             self.reg_set[self.target].swapContext()

    def trackThreads(self):
        self.lgr.debug('trackThreads') 
        if self.track_threads is None:
            # undo hack
            self.track_threads = {}
        if self.target not in self.track_threads:
            self.checkOnlyIgnore()
            cpu, comm, tid = self.task_utils[self.target].curThread() 
            self.track_threads[self.target] = trackThreads.TrackThreads(self, cpu, self.target, tid, self.context_manager[self.target], 
                    self.task_utils[self.target], self.mem_utils[self.target], self.param[self.target], self.traceProcs[self.target], 
                    self.soMap[self.target], self.targetFS[self.target], self.sharedSyscall[self.target], self.syscallManager[self.target], self.is_compat32, self.lgr)
        else:
            self.track_threads[self.target].checkContext()
            self.lgr.debug('trackThreads already tracking for %s' % self.target)
            print('trackThreads already tracking for %s' % self.target)

    def show(self):
        cpu, comm, tid = self.task_utils[self.target].curThread() 
        if cpu is None:
            cpu = self.cell_config.cpuFromCell(self.target)
            self.lgr.error('show failed to get cpu from taskUtils curThread.  target cpu is %s %s' % (cpu.name, str(cpu.current_context)))
            return
        cpl = memUtils.getCPL(cpu)
        eip = self.getEIP(cpu)
        sp = self.mem_utils[self.target].getRegValue(cpu, 'sp')
        so_file = self.soMap[self.target].getSOFile(eip)
        context = SIM_object_name(cpu.current_context)
        if self.isWindows():
            cur_thread_rec = self.task_utils[self.target].getCurThreadRec()
            if cur_thread_rec is None:
                self.lgr.error('show cur_thread_rec is None')
                return
            cur_proc_rec = self.task_utils[self.target].getCurProcRec()
            if cur_proc_rec is None:
                self.lgr.error('show cur_proc_rec is None')
                return
            print('cpu.name is %s context: %s PL: %d tid: %s(%s) EIP: 0x%x SP: 0x%x code file: %s eproc: 0x%x ethread: 0x%x' % (cpu.name, context,
                   cpl, tid, comm, eip, sp, so_file, cur_proc_rec, cur_thread_rec))
        elif self.isVxDKM(): 
            print('cpu.name is %s context: %s PL: %d tid: %s(%s) EIP: 0x%x SP: 0x%x code file: %s' % (cpu.name, context,
                   cpl, tid, comm, eip, sp, so_file))
        else: 
            line = ('cpu.name is %s context: %s PL: %d tid: %s(%s) EIP: 0x%x SP: 0x%x  current_task symbol at 0x%x (use FS: %r)' % (cpu.name, context, 
                   cpl, tid, comm, eip, sp, self.param[self.target].current_task, self.param[self.target].current_task_fs))
            print(line)
            # needed for testing
            self.lgr.debug(line)
            pfamily = self.pfamily[self.target].getPfamily()
            tabs = ''
            while len(pfamily) > 0:
                prec = pfamily.pop()
                print('%s%5s  %s' % (tabs, prec.tid, prec.proc))
                tabs += '\t'

    def signalHap(self, signal_info, one, exception_number):
        cpu, comm, tid = self.task_utils[self.target].curThread() 
        if signal_info.callnum is None:
            if exception_number in self.hack_list:
                return
            else:
               self.hack_list.append(exception_number)
        if signal_info.tid is not None:
            if tid == signal_info.tid:
                self.lgr.error('signalHap from %s (%s) signal 0x%x at 0x%x' % (tid, comm, exception_number, self.getEIP(cpu)))
                SIM_break_simulation('signal %d' % exception_number)
        else: 
           SIM_break_simulation('signal %d' % exception_number)
           self.lgr.debug('signalHap from %s (%s) signal 0x%x at 0x%x' % (tid, comm, exception_number, self.getEIP(cpu)))
         
    def readStackFrame(self):
        cpu, comm, tid = self.task_utils[self.target].curThread()
        stack_frame = self.task_utils[self.target].frameFromStackSyscall()
        frame_string = taskUtils[self.target].stringFromFrame(stack_frame)
        print(frame_string)

    def int80Hap(self, cpu, one, exception_number):
        cpu, comm, tid = self.task_utils[self.target].curThread()
        eax = self.mem_utils[self.target].getRegValue(cpu, 'eax')
        self.lgr.debug('int80Hap in proc %s (%s), eax: 0x%x' % (tid, comm, eax))
        self.lgr.debug('syscall 0x%d from %s (%s) at 0x%x ' % (eax, tid, comm, self.getEIP(cpu)))
        if eax != 5:
            return
        SIM_break_simulation('syscall')
        print('use si to get address of syscall entry, and further down look for computed call')

    def runToSyscall80(self):
        cpu = self.cell_config.cpuFromCell(self.target)
        self.lgr.debug('runToSyscall80') 
        self.scall_hap = RES_hap_add_callback_obj_index("Core_Exception", cpu, 0,
                 self.int80Hap, cpu, 0x180) 
        hap_clean = hapCleaner.HapCleaner(cpu)
        hap_clean.add("Core_Exception", self.scall_hap)
        stop_action = hapCleaner.StopAction(hap_clean)
        self.stop_hap = self.RES_add_stop_callback(self.stopHap, stop_action)
        status = self.is_monitor_running.isRunning()
        if not status:
            SIM_continue(0)

    def runToSignal(self, signal=None, tid=None):
        cpu = self.cell_config.cpuFromCell(self.target)
        self.lgr.debug('runToSignal, signal given is %s' % str(signal)) 

        sig_info = syscall.SyscallInfo(cpu, tid, signal)
        #max_intr = 31
        max_intr = 1028
        if signal is None:
            sig_hap = RES_hap_add_callback_obj_range("Core_Exception", cpu, 0,
                     self.signalHap, sig_info, 0, max_intr) 
        else:
            sig_hap = RES_hap_add_callback_obj_index("Core_Exception", cpu, 0,
                     self.signalHap, sig_info, signal) 

        hap_clean = hapCleaner.HapCleaner(cpu)
        hap_clean.add("Core_Exception", sig_hap)
        stop_action = hapCleaner.StopAction(hap_clean)
        self.stop_hap = self.RES_add_stop_callback(self.stopHap, stop_action)
        status = self.is_monitor_running.isRunning()
        if not status:
            SIM_continue(0)
   
    def execToText(self, flist=None):
        ''' assuming we are in an exec system call, run until execution enters the
            the .text section per the elf header in the file that was execed.'''
        cpu, comm, tid  = self.task_utils[self.target].curThread()
        prog_name, dumb = self.task_utils[self.target].getProgName(tid) 
        self.lgr.debug('execToText debug set exit_group break')
        self.debugExitHap()
                       
        if self.targetFS[self.target] is not None:
            sindex = 0
            full_path = self.targetFS[self.target].getFull(prog_name, self.lgr)
            self.lgr.debug('execToText, progname is %s  full: %s' % (prog_name, full_path))
            if full_path is None:
                self.lgr.warning('execToText failed to get full_path for %s' % prog_name)
            else:
                prog_info = self.soMap[self.target].addText(full_path, prog_name, tid)
                if prog_info is not None:
                    if prog_info.addr is None:
                        self.lgr.debug('execToText found file %s, but address is None? Assume dynamic' % full_path)
                        #stopFunction.allFuns(flist)
                        #return
                    else:
                        self.lgr.debug('execToText %s 0x%x - 0x%x' % (prog_name, prog_info.addr, prog_info.end))
                    self.runToText(flist, this_tid=True)
                    return
                else:
                    self.lgr.debug('execToText text segment, just run to user flist')
                    self.toUser(flist)
                    return
        self.lgr.debug('execToText no information about the text segment')
        ''' If here, then no info about the text segment '''
        if flist is not None:
            stopFunction.allFuns(flist)
        

    def watchProc(self, proc):
        ''' SEE watchTasks '''
        ''' TBD remove?  can just use debugProc and then disable reverse-exectution?  Highlight on/off on IDA '''
        plist = self.task_utils[self.target].getTidsForComm(proc)
        if len(plist) > 0:
            self.lgr.debug('watchProc process %s found, run until some instance is scheduled' % proc)
            f1 = stopFunction.StopFunction(self.toUser, [], nest=True)
            flist = [f1]
            self.run_to[self.target].toRunningProc(proc, plist, flist)
        else:
            self.lgr.debug('watchProc no process %s found, run until execve' % proc)
            #flist = [self.toUser, self.debug]
            ''' run to the execve, then start recording shared object mmaps and run
                until we enter the text segment so we get the SO map '''
            f1 = stopFunction.StopFunction(self.execToText, [], nest=True)
            flist = [f1]
            self.toExecve(prog=proc, flist=flist)


    def toProc(self, proc, binary=False, run=True, new=False):
        self.rmDebugWarnHap()
        plist = self.task_utils[self.target].getTidsForComm(proc, ignore_exits=True)
        if not new and len(plist) > 0 and not (len(plist)==1 and self.task_utils[self.target].isExitTid(plist[0])):
            self.lgr.debug('toProc process %s found, run until some instance is scheduled' % proc)
            print('%s is running as %s.  Will continue until some instance of it is scheduled' % (proc, plist[0]))
            f1 = stopFunction.StopFunction(self.toUser, [], nest=True)
            flist = [f1]
            self.run_to[self.target].toRunningProc(proc, plist, flist)
        else:
            cpu = self.cell_config.cpuFromCell(self.target)
        
            #f1 = stopFunction.StopFunction(self.cleanToProcHaps, [], False)
            if self.isWindows():
                if new:
                    self.lgr.debug('toProc want new process %s, run until CreateUserProcess' % proc)
                else:
                    self.lgr.debug('toProc no process %s found, run until CreateUserProcess' % proc)
                self.winMonitor[self.target].toCreateProc(comm=proc, run=run)
            else:
                if new:
                    self.lgr.debug('toProc want new process %s, run until execve cycles now 0x%x' % (proc, cpu.cycles))
                else:
                    self.lgr.debug('toProc no process %s found, run until execve' % proc)
                self.toExecve(prog=proc, flist=[], binary=binary, any_exec=True)

        
    def debugProc(self, proc, final_fun=None, pre_fun=None, track_threads=True, new=False, not_to_user=False):
        if not track_threads:
            # TBD fix this hack.  confusing since track_threads is a dict
            self.lgr.debug('genMonitor debugProc track_threads set to None')
            self.track_threads = None
        if self.isWindows():
            self.rmDebugWarnHap()
            self.winMonitor[self.target].debugProc(proc, final_fun, pre_fun, new=new)
            return

        if type(proc) is not str:
            print('Need a proc name as a string')
            return
        self.lgr.debug('genMonitor debugProc')
        #if len(proc) > 15:
        #    proc = proc[:16]
        #    print('Process name truncated to %s to match Linux comm name' % proc)
        self.rmDebugWarnHap()
        #self.stopTrace()
        plist = []
        if not new:
            plist = self.task_utils[self.target].getTidsForComm(proc, ignore_exits=True)
        else:
            self.lgr.debug('genMonitor debugProc is new, stop debug and stop tracking')
            self.stopDebug()
            self.stopTracking()
        if self.target not in self.magic_origin:
            if resimSimicsUtils.serviceNodeConnected('driver_service_node', lgr=self.lgr):
                cpu = self.cell_config.cpuFromCell(self.target)
                self.magic_origin[self.target] = magicOrigin.MagicOrigin(self, cpu, self.bookmarks, self.lgr)
        if not new and len(plist) > 0 and not (len(plist)==1 and self.task_utils[self.target].isExitTid(plist[0])):
            self.lgr.debug('debugProc plist len %d plist[0] %s  exittid:%s proc: %s' % (len(plist), plist[0], self.task_utils[self.target].getExitTid(), proc))
            if proc.startswith('/') and self.target in self.soMap:
                prog_name = self.soMap[self.target].getProg(plist[0])
                self.lgr.debug('debugProc prog_name %s' % prog_name)
                if prog_name is None:
                    print('\n*** Warning *** Requested debug of %s, which is already running, but it has no SO Map entries\n')
                    local_path = self.getFullPath(fname=proc)
                    self.soMap[self.target].addText(local_path, proc, plist[0])
                    self.lgr.debug('debugProc %s add to soMap' % proc)

            self.lgr.debug('debugProc process %s found, run until some instance is scheduled' % proc)
            flist = []
            print('%s is running.  Will continue until some instance of it is scheduled' % proc)
            if not not_to_user: 
                flist.append(stopFunction.StopFunction(self.toUser, [], nest=True))
            else:
                self.lgr.debug('debugProc will run to %s scheduled, but not to user' % proc)
            flist.append(stopFunction.StopFunction(self.debugExitHap, [], nest=False))
            flist.append(stopFunction.StopFunction(self.debug, [True], nest=False))
            if final_fun is not None:
                flist.append(stopFunction.StopFunction(final_fun, [], nest=False))
            if pre_fun is not None:
                fp = stopFunction.StopFunction(pre_fun, [], nest=False)
                flist.insert(0, fp)
            ''' If not yet loaded SO files, e.g., we just did a toProc, then execToText ''' 
            if self.soMap[self.target].getSOTid(plist[0]) is None:
                self.lgr.debug('debugProc, no so yet, run to text for proc %s.' % proc)
                rtt = stopFunction.StopFunction(self.execToText, [], nest=True)
                flist.insert(1, rtt)
            self.run_to[self.target].toRunningProc(proc, plist, flist)
        else:
            if not new:
                self.lgr.debug('debugProc no process %s found, run until execve' % proc)
            else:
                self.lgr.debug('debugProc run until NEW execve of %s' % proc)
            #flist = [self.toUser, self.debug]
            ''' run to the execve, then start recording shared object mmaps and run
                until we enter the text segment so we get the SO map '''
            f1 = stopFunction.StopFunction(self.toUser, [], nest=True)
            f2 = stopFunction.StopFunction(self.execToText, [], nest=True)
            f3 = stopFunction.StopFunction(self.stackFrameManager[self.target].setStackBase, [], nest=False)
            f4 = stopFunction.StopFunction(self.debug, [], nest=False)
            flist = [f1, f2, f3, f4]
            if track_threads:
                watch_exit = True
            else:
                watch_exit = False
            self.toExecve(prog=proc, flist=flist, binary=True, watch_exit=watch_exit)
       

    def listHasDebug(self, flist):
        for f in flist:
            if f.fun == self.debug: 
                return True
        return False

    def debugThis(self):
        ''' Intended for use while debugging a process that clones and you want to only watch 
            the current clone '''
        self.context_manager[self.target].watchOnlyThis()
        print('now debugging only:')
        self.lgr.debug('debugThis')
        self.show()

    def debugAll(self):
        self.context_manager[self.target].watchAll()
        self.lgr.debug('debugAll')
        print('watching all threads')
 
    def debugTid(self, tid):
        self.rmDebugWarnHap()
        self.debugTidList([tid], self.debug)

    def debugTidGroup(self, tid, final_fun=None, to_user=True, track_threads=True):
        if not track_threads:
            self.track_threads = None
        self.lgr.debug('debugTidGroup tid:%s' % tid)
        leader_tid = self.task_utils[self.target].getGroupLeaderTid(tid)
        if leader_tid is None:
            self.lgr.error('debugTidGroup leader_tid is None, asked about %s' % tid)
            return
    
        tid_dict = self.task_utils[self.target].getGroupTids(leader_tid)
        tid_list = list(tid_dict.keys())
        leader_prog = self.soMap[self.target].getProg(leader_tid)
        copy_list = list(tid_list)
        for l_tid in copy_list:
            prog = self.soMap[self.target].getProg(l_tid)
            if prog != leader_prog:
                self.lgr.debug('debugTidGroup prog %s does not match leader %s, remove it' % (prog, leader_prog))
                tid_list.remove(l_tid)
      
        self.lgr.debug('debugTidGroup cell %s tid:%s found leader %s and %d tids' % (self.target, tid, leader_tid, len(tid_list)))
        if len(tid_list) == 0:
            self.lgr.error('debugTidGroup tid:%s not on current target?' % tid)
        else: 
            self.debugTidList(tid_list, self.debugGroup, final_fun=final_fun, to_user=to_user)

    def debugTidList(self, tid_list, debug_function, final_fun=None, to_user=True):
        #self.stopTrace()
        if len(tid_list) == 0:
            self.lgr.error('debugTidList with empty list')
            return
        cpu = self.cell_config.cpuFromCell(self.target)
        if self.target not in self.magic_origin:
            if resimSimicsUtils.serviceNodeConnected('driver_service_node', lgr=self.lgr):
                self.magic_origin[self.target] = magicOrigin.MagicOrigin(self, cpu, self.bookmarks, self.lgr)
        #if not self.isWindows():
        #    self.soMap[self.target].setContext(tid_list)
        self.lgr.debug('debugTidList cell %s tid_list: %s' % (self.target, str(tid_list)))
        if to_user:
            f1 = stopFunction.StopFunction(self.toUser, [], nest=True)
        f2 = stopFunction.StopFunction(self.debugExitHap, [], nest=False)
        f3 = stopFunction.StopFunction(debug_function, [], nest=False)
        if to_user:
            flist = [f1, f3, f2]
        else:
            flist = [f3, f2]
        if final_fun is not None:
            f4 = stopFunction.StopFunction(final_fun, [], nest=False)
            flist.append(f4)
        debug_group = False
        if debug_function == self.debugGroup:
            debug_group = True

        ''' enable reversing now so we can rev to events prior to scheduling, e.g., arrival of data at kernel '''
        self.reverse_mgr[self.target].enableReverse()
        self.rev_execution_enabled = True
        if self.full_path is None:
            self.lgr.debug('debugTidList full_path is None, set it')
            self.setPathToProg(tid_list[0])
        if not self.no_gdb and self.bookmarks is None:
            self.lgr.debug('genMonitor debug call doDebugCmd')
            self.doDebugCmd(tid_list[0])
        if self.bookmarks is None:
            self.bookmarks = bookmarkMgr.bookmarkMgr(self, self.context_manager[self.target], self.lgr)
            self.debugger_target = self.target
        #self.setDebugBookmark('origin', cpu)
        self.bookmarks.setOrigin(cpu)
        # reset jumpers and read replace which may have been disabled by stopDebug
        self.lgr.debug('debugTidList restoring jumpers and readReplace')
        self.jumperEnable()
        self.enableOtherBreaks()

        self.run_to[self.target].toRunningProc(None, tid_list, flist, debug_group=True, final_fun=final_fun)

    def enableOtherBreaks(self):
        if self.target in self.read_replace:
            self.read_replace[self.target].enableBreaks()
        if self.target in self.trace_buffers:
            self.trace_buffers[self.target].restoreHaps()
        if self.target in self.page_callbacks:
            self.page_callbacks[self.target].enableBreaks()

    def changedThread(self, cpu, third, forth, memory):
        cur_addr = memUtils.memoryValue(self.cpu, memory)
        tid = self.mem_utils[self.target].readWord32(cpu, cur_addr + self.param[self.target].ts_pid)
        if tid != 0:
            print('changedThread')
            self.show()

    #def addProcList(self, tid, comm):
    #    #self.lgr.debug('addProcList %s %s' % (tid, comm))
    #    self.proc_list[self.target][tid] = comm
 
    def toUser(self, flist=None, want_tid=None):
        self.rmDebugWarnHap()
        self.lgr.debug('toUser want_tid %s' % want_tid)
        cpu = self.cell_config.cpuFromCell(self.target)
        if self.isVxDKM(cpu=cpu):
            self.vxKMonitor[self.target].toModule()
        else:
            self.run2User(cpu, flist, want_tid=want_tid)

    def runToUserSpace(self, dumb=None):
        self.lgr.debug('runToUserSpace')
        self.is_monitor_running.setRunning(True)
        f1 = stopFunction.StopFunction(self.skipAndMail, [], nest=False)
        self.toUser([f1])

    def toKernel(self, flist=None): 
        self.rmDebugWarnHap()
        cpu = self.cell_config.cpuFromCell(self.target)
        self.run2Kernel(cpu, flist=flist)

    def toProcTid(self, tid):
        self.lgr.debug('toProcTid %s' % tid)
        f1 = stopFunction.StopFunction(self.toUser, [], nest=True)
        f2 = stopFunction.StopFunction(self.skipAndMail, [], nest=False)
        flist = [f1, f2]
        self.run_to[self.target].toRunningProc(None, [str(tid)], flist)


    def getEIP(self, cpu=None):
        if cpu is None:
            dum, cpu = self.context_manager[self.target].getDebugTid() 
            if cpu is None:
                cpu = self.cell_config.cpuFromCell(self.target)
        target = self.cell_config.cpu_cell[cpu]
        eip = self.mem_utils[target].getRegValue(cpu, 'pc')
        return eip

    def getReg(self, reg, cpu=None):
        if cpu is None:
            cpu = self.cell_config.cpuFromCell(self.target)
            target = self.target
        else:
            target = self.cell_config.cpu_cell[cpu]
        value = self.mem_utils[target].getRegValue(cpu, reg)
        #self.lgr.debug('debugGetReg for %s is %x' % (reg, value))
        return value

    def is_ascii(s):
        return all(ord(c) < 128 for c in s)

    def gdbMailbox(self, msg):
        self.gdb_mailbox = msg
        self.lgr.debug('in gdbMailbox msg set to <%s>' % msg)
        #amsg = msg.encode("ascii", "ignore")
        print('gdbMailbox:%s' % msg)

    def emptyMailbox(self):
        if self.gdb_mailbox is not None and self.gdb_mailbox != "None":
            print(self.gdb_mailbox)
            #self.lgr.debug('emptying mailbox of <%s>' % self.gdb_mailbox)
            self.gdb_mailbox = None

    def runSkipAndMailAlone(self, cycles): 
        tid, cpu = self.context_manager[self.target].getDebugTid() 
        if cpu is None:
            self.lgr.debug("no cpu in runSkipAndMailAlone")
            return
        current = cpu.cycles
        eip = self.getEIP(cpu)
        instruct = SIM_disassemble_address(cpu, eip, 1, 0)
        self.lgr.debug('skipAndMailAlone current cycle is %x eip: %x %s requested %d cycles' % (current, eip, instruct[1], cycles))
        if cycles > 0:
            previous = current - cycles 
            start = self.bookmarks.getCycle('_start+1')
            if previous > start:
                count = 0
                while current != previous:
                    self.skipToCyle(previous)
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
                self.context_manager[self.target].resetBackStop()
            else:
                self.lgr.debug('skipAndRunAlone was asked to back up before start of recording')
        self.is_monitor_running.setRunning(False)
        self.lgr.debug('setRunning to false, now set mbox to 0x%x' % eip)
        self.gdbMailbox('0x%x' % eip)
        print('Monitor done')

    def skipAndMail(self, cycles=1, restore_debug=True):
        self.lgr.debug('skipAndMail restore_debug %r' % restore_debug)
        dum, cpu = self.context_manager[self.target].getDebugTid() 
        if cpu is None:
            self.lgr.debug("no cpu in runSkipAndMail")
            return
        if self.quit_when_done:
            self.lgr.debug("skipAndMail quit_when_done true, bail")
            self.quit()
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
        if self.coverage is not None:
            
            self.lgr.debug('skipAndMail call saveCoverage')
            self.coverage.saveCoverage()
            # Cannot delete because we may wish to save block coverage
            #self.coverage = None
            self.coverage.disableCoverage()
        if self.command_callback is not None:
            self.lgr.debug('skipAndMail do callback to %s' % str(self.command_callback))
            cb = self.command_callback
            param = self.command_callback_param
            SIM_run_alone(cb, param)
            self.command_callback = None
            self.command_callback_param = None
        else:
            cpl = memUtils.getCPL(cpu)
            self.lgr.debug('skipAndMail, cpl %d' % cpl)
            if cpl == 0:
                #SIM_run_alone(self.skipBackToUser, 1)
                #self.lgr.debug('skipAndMail, back from call to skip (but it ran alone)')
                # TBD skipping back to prior to call makes no sense
                self.lgr.debug('skipAndMail left in kernel')
                
            if self.debugging() and restore_debug:
                self.lgr.debug('skipAndMail, restoreDebugBreaks')
                SIM_run_alone(self.restoreDebugBreaks, False)

    def goToOrigin(self, debugging=True):
        if self.bookmarks is None:
            self.lgr.debug('genMonitor goToOrigin, no bookmarks do nothing')
            return
        cpu, comm, tid  = self.task_utils[self.target].curThread()
        if self.getFirstCycle() == cpu.cycles:
            self.lgr.debug('genMonitor goToOrigin already there, do nothing')
            return
        if debugging:
            self.removeDebugBreaks(immediate=True)
            self.lgr.debug('goToOrigin am debugging, call stopTrackIO')
            self.stopTrackIO(immediate=True)
        self.lgr.debug('goToOrigin tid was is %s' % tid)
        msg = self.bookmarks.goToOrigin()
        cpu, comm, tid  = self.task_utils[self.target].curThread()
        #self.lgr.debug('goToOrigin tid now is %s' % tid)
        if debugging:
            self.context_manager[self.target].setIdaMessage(msg)
            self.restoreDebugBreaks(was_watching=True)
            self.lgr.debug('goToOrigin call stopWatchTasks')
            self.context_manager[self.target].stopWatchTasksAlone(None)
            self.context_manager[self.target].watchTasks(set_debug_tid=True)

    def goToDebugBookmark(self, mark):
        context_was_watching = self.context_manager[self.target].watchingThis()
        self.lgr.debug('goToDebugBookmark %s' % mark)
        self.removeDebugBreaks()
        self.stopTrackIO()
        if self.syscallManager[self.target].rmAllSyscalls():
            self.lgr.debug('Syscall traces were active -- they were deleted before jumping to bookmarks ')
            print('\n\n*** Syscall traces are active -- were deleted before jumping to bookmarks ***')
        '''
        if len(self.call_traces[self.target]) > 0: 
            self.lgr.debug('Syscall traces were active -- they were deleted before jumping to bookmarks ')
            print('\n\n*** Syscall traces are active -- were deleted before jumping to bookmarks ***')
            #self.stopTrace()
            self.lgr.debug('Syscall traces are active -- they will be deleted before jumping to bookmarks ')
            #self.showHaps()
            #for call in self.call_traces[self.target]:
            #    self.lgr.debug('remaining trace %s' % call)
            #return
        '''
        if type(mark) != int:
            mark = mark.replace('|','"')
        msg = self.bookmarks.goToDebugBookmark(mark)
        self.context_manager[self.target].setIdaMessage(msg)
        self.restoreDebugBreaks(was_watching=True)
        self.context_manager[self.target].watchTasks()
        if not context_was_watching:
            self.context_manager[self.target].setAllHap()

    def showCallTraces(self):
        for call in self.call_traces[self.target]:
            self.lgr.debug('remaining trace %s' % call)

    def listBookmarks(self):
        if self.bookmarks is not None:
            self.bookmarks.listBookmarks()
        else:
            print('Bookmarks not created')

    def getBookmarks(self):
        if self.bookmarks is not None:
            return self.bookmarks.getBookmarks()
        else:
            return None

    def getBookmarksInstance(self):
        return self.bookmarks

    def getBookmarksJson(self):
        the_json = self.bookmarks.getBookmarksJson()
        sorted_list = sorted(the_json)
        sorted_json = []
        for delta in sorted_list:
            for entry in the_json[delta]:
                entry['rel_cycle'] = delta
                sorted_json.append(entry)
        print(json.dumps(sorted_json, indent=4))

    def doReverse(self, extra_back=0):
        if self.reverseEnabled():
            dum, cpu = self.context_manager[self.target].getDebugTid() 
            self.lgr.debug('doReverse entered, extra_back is %s' % str(extra_back))
            self.removeDebugBreaks()
            reverseToWhatever.reverseToWhatever(self, self.context_manager[self.target], cpu, self.lgr, extra_back=extra_back)
            self.lgr.debug('doReverse, back from reverseToWhatever init')
        else:
            print('reverse execution disabled')
            self.skipAndMail()

    def printCycle(self):
        dum, cpu = self.context_manager[self.target].getDebugTid() 
        cell_name = self.getTopComponentName(cpu)
        current = cpu.cycles
        print('current cycle for %s is %x' % (cell_name, current))

    ''' more experiments '''
    def reverseStepInstruction(self, num=1):
        dum, cpu = self.context_manager[self.target].getDebugTid() 
        cell_name = self.getTopComponentName(cpu)
        dum_cpu, comm, tid  = self.task_utils[self.target].curThread()
        eip = self.getEIP()
        self.lgr.debug('reservseStepInstruction starting at %x' % eip)
        my_args = procInfo.procInfo(comm, cpu, tid, None, False)
        self.stopped_reverse_instruction_hap = self.RES_add_stop_callback(self.stoppedReverseInstruction, my_args)
        self.lgr.debug('reverseStepInstruction, added stop hap')
        SIM_run_alone(SIM_run_command, 'reverse-step-instruction %d' % num)

    def stoppedReverseInstruction(self, my_args, one, exception, error_string):
        cell_name = self.getTopComponentName(my_args.cpu)
        cpu, comm, tid  = self.task_utils[self.target].curThread()
        if tid == my_args.tid:
            eip = self.getEIP()
            self.lgr.debug('stoppedReverseInstruction at %x' % eip)
            print('stoppedReverseInstruction stopped at ip:%x' % eip)
            self.gdbMailbox('0x%x' % eip)
            self.RES_delete_stop_hap(self.stopped_reverse_instruction_hap)
        else:
            self.lgr.debug('stoppedReverseInstruction in wrong tid (%s), try again' % tid)
            SIM_run_alone(SIM_run_command, 'reverse-step-instruction')

    def revStepOver(self):
        self.reverseToCallInstruction(False)

    def revStepInto(self):
        self.reverseToCallInstruction(True)
 
    def reverseToCallInstruction(self, step_into, prev=None):
        if self.reverseEnabled():
            dum, cpu = self.context_manager[self.target].getDebugTid() 
            cell_name = self.getTopComponentName(cpu)
            self.lgr.debug('reverseToCallInstruction, step_into: %r  on entry, gdb_mailbox: %s' % (step_into, self.gdb_mailbox))
            self.removeDebugBreaks()
            #self.context_manager[self.target].showHaps()
            if prev is not None:
                instruct = SIM_disassemble_address(cpu, prev, 1, 0)
                self.lgr.debug('reverseToCallInstruction instruct is %s at prev: 0x%x' % (instruct[1], prev))
                if instruct[1] == 'int 128' or (not step_into and (instruct[1].startswith('call') or instruct[1].startswith('blr'))):
                    self.revToAddr(prev)
                else:
                    self.rev_to_call[self.target].doRevToCall(step_into, prev)
            else:
                self.lgr.debug('prev is none')
                self.rev_to_call[self.target].doRevToCall(step_into, prev)
            self.lgr.debug('reverseToCallInstruction back from call to reverseToCall ')
        else:
            print('reverse execution disabled')
            self.lgr.debug('reverseToCallInstruction reverse execution disabled')
            self.skipAndMail()

    def uncall(self):
        dum, cpu = self.context_manager[self.target].getDebugTid() 
        cell_name = self.getTopComponentName(cpu)
        self.lgr.debug('cgcMonitor, uncall')
        self.removeDebugBreaks()
        self.rev_to_call[self.target].doUncall()
   
    def getInstance(self):
        return INSTANCE

    def revToModReg(self, reg, kernel=False):
        if not self.debugging():
            cpu = self.cell_config.cpuFromCell(self.target)
            self.rev_to_call[self.target].setup(cpu, [])
        reg = reg.lower()
        self.lgr.debug('revToModReg for reg %s kernel: %r' % (reg, kernel))
        self.removeDebugBreaks()
        self.rev_to_call[self.target].doRevToModReg(reg, kernel=kernel)

    def revToAddr(self, address, extra_back=0):
        if self.reverseEnabled():
            tid, cpu = self.context_manager[self.target].getDebugTid() 
            self.lgr.debug('revToAddr 0x%x, extra_back is %d' % (address, extra_back))
            self.removeDebugBreaks(immediate=True)
            self.stopTrackIO(immediate=True)
            reverseToAddr.reverseToAddr(address, self.context_manager[self.target], self.task_utils[self.target], self.is_monitor_running, self, cpu, 
                           self.reverse_mgr[self.target], self.lgr, extra_back=extra_back)
            self.lgr.debug('back from reverseToAddr')
        else:
            print('reverse execution disabled')
            self.lgr.debug('reverse execution disabled')
            self.skipAndMail()

    ''' intended for use by gdb, if stopped return the eip.  checks for mailbox messages'''
    def getEIPWhenStopped(self, kernel_ok=False):
        self.lgr.debug('getEIP when stopped')
        simics_status = SIM_simics_is_running()
        resim_status = self.is_monitor_running.isRunning()
        debug_tid, cpu = self.context_manager[self.target].getDebugTid() 
        ''' TBD fix this race condition? '''
        #if debug_tid is None:
        #    debug_tid = self.context_manager[self.target].getSavedDebugTid()
        eip = self.getEIP(cpu)
        retval = None
        if not resim_status and debug_tid is None:
            retval = 'mailbox:exited'
            self.lgr.debug('getEIPWhenStopped debug_tid is gone, return %s' % retval)
            print(retval)

        elif resim_status and not simics_status:
            self.lgr.debug('getEIPWhenStopped Simics not running, RESim thinks it is running.  Perhaps gdb breakpoint?')
            tid, cpu = self.context_manager[self.target].getDebugTid() 
            SIM_run_command('pselect %s' % cpu.name)
            self.context_manager[self.target].setIdaMessage('Stopped at debugger breakpoint?')
            retval = 'mailbox:0x%x' % eip
            self.is_monitor_running.setRunning(False)

        elif not resim_status:
            if cpu is None:
                self.lgr.error('no cpu defined in context manager')
            else: 
                dum_cpu, comm, tid  = self.task_utils[self.target].curThread()
                self.lgr.debug('getEIPWhenStopped, tid %s' % (tid)) 
                if self.gdb_mailbox is not None:
                    self.lgr.debug('getEIPWhenStopped mbox is %s tid is %s (%s) cycle: 0x%x' % (self.gdb_mailbox, tid, comm, cpu.cycles))
                    retval = 'mailbox:%s' % self.gdb_mailbox
                    print(retval)
                else:
                    self.lgr.debug('getEIPWhenStopped, mbox must be empty?')
                    cpl = memUtils.getCPL(cpu)
                    if cpl == 0 and not kernel_ok:
                        self.lgr.debug('getEIPWhenStopped in kernel tid:%s (%s) eip is %x' % (tid, comm, eip))
                        retval = 'in kernel'
                        print(retval)
                    else:
                        self.lgr.debug('getEIPWhenStopped tid:%s (%s) eip is %x' % (tid, comm, eip))
                        if not self.context_manager[self.target].amWatching(tid):
                            self.lgr.debug('getEIPWhenStopped not watching process tid:%s (%s) eip is %x' % (tid, comm, eip))
                            retval = 'wrong process'
                            print(retval)
                        else:
                            retval = 'mailbox:0x%x' % eip
                            print(retval)
        else:
            self.lgr.debug('call to getEIPWhenStopped, not stopped at 0x%x' % eip)
            print('not stopped')
            retval = 'not stopped'
        return retval

    def reMessage(self):
        self.context_manager[self.target].showIdaMessage()

    def idaMessage(self):
        self.context_manager[self.target].showIdaMessage()

    def getIdaMessage(self):
        return self.context_manager[self.target].getIdaMessage()

    def resynch(self):
        ''' poor name? If not in user space of one of the thread group, go there '''
        debug_tid, debug_cpu = self.context_manager[self.target].getDebugTid() 
        cur_tid = self.task_utils[self.target].curTID() 
        self.lgr.debug('resynch to debug_tid:%s' % debug_tid)
        #self.is_monitor_running.setRunning(True)
        if self.context_manager[self.target].amWatching(cur_tid):
            self.lgr.debug('rsynch, already in proc')
            f1 = stopFunction.StopFunction(self.skipAndMail, [], nest=False)
            self.toUser([f1])
        else:
            f1 = stopFunction.StopFunction(self.toUser, [], nest=True)
            f2 = stopFunction.StopFunction(self.skipAndMail, [], nest=False)
            flist = [f1, f2]
            self.lgr.debug('rsynch, call toRunningProc for tid:%s' % debug_tid)
            tid_list = self.context_manager[self.target].getThreadTids()
            self.run_to[self.target].toRunningProc(None, tid_list, flist)

    def traceExecve(self, comm=None):
        ''' TBD broken '''
        self.pfamily[self.target].traceExecve(comm)

    def watchPageFaults(self, tid=None, target=None, afl=False):
        if not self.isVxDKM(target=target):
            if target is None:
                target = self.target
            if tid is None:
                tid, cpu = self.context_manager[target].getDebugTid() 
            self.lgr.debug('genMonitor watchPageFaults tid %s' % tid)
            self.page_faults[target].watchPageFaults(tid=tid, compat32=self.is_compat32, afl=afl)
            #self.lgr.debug('genMonitor watchPageFaults back')

    def stopWatchPageFaults(self, tid=None, target=None, immediate=False):
        if target is None:
            target = self.target
        self.lgr.debug('genMonitor stopWatchPageFaults')
        if target in self.page_faults:
            self.page_faults[target].stopWatchPageFaults(tid, immediate=immediate)
            self.page_faults[target].stopPageFaults()

    def catchCorruptions(self):
        self.watchPageFaults()

    def traceOpenSyscall(self):
        #self.lgr.debug('about to call traceOpen')
        self.traceOpen[self.target].traceOpenSyscall()

    def getCell(self, cell_name=None):
        if cell_name is None:
            return self.cell_config.cell_context[self.target]
        elif cell_name in self.cell_config.cell_context:
            return self.cell_config.cell_context[cell_name]
        else: 
            self.lgr.error('getCell, name %s not found' % cell_name)
            return None

    def getTarget(self):
        return self.target

    def getCPU(self, cell_name=None):
        if cell_name is None:
            target = self.target
        else:
            target = cell_name
        return self.cell_config.cpuFromCell(target)

    def getTID(self, target=None):
        if target is None:
            target = self.target
        cpu, comm, this_tid = self.task_utils[target].curThread() 
        return this_tid

    def getComm(self, target=None):
        if target is None:
            target = self.target
        cpu, comm, this_tid = self.task_utils[target].curThread() 
        return comm

    def getCurrentProc(self, target_cpu=None):
        if target_cpu is None:
            target = self.target
        else:
            target = self.cell_config.cellFromCPU(target_cpu)
        cpu, comm, tid = self.task_utils[target].curThread() 
        return cpu, comm, tid

    def getCPL(self): 
        cpu, comm, this_tid = self.task_utils[self.target].curThread() 
        cpl = memUtils.getCPL(cpu)

    def skipBackToUser(self, extra=0):
        if self.reverseEnabled():
            self.lgr.debug('skipBackToUser')
            self.removeDebugBreaks(keep_watching=False, keep_coverage=False, immediate=True)
            cpu, comm, tid = self.task_utils[self.target].curThread() 
            self.rev_to_call[self.target].jumpOverKernel(tid)
        else:
            self.lgr.debug('skipBackToUser but reverse execution not enabled.')
            print('reverse execution not enabled.')

    def reverseToUser(self, force=False):
        if not force:
            print('Try using skipBackToUser instead.  Or force=True if you insist, but it may not return and may end in the wrong tid.')
            return
        ''' Note: may not stop in current tid, see skipBacktoUser '''
        self.removeDebugBreaks()
        cell = self.cell_config.cell_context[self.target]
        cpu = self.cell_config.cpuFromCell(self.target)
        rtu = reverseToUser.ReverseToUser(self.param[self.target], self.lgr, cpu, cell)

    def getDebugFirstCycle(self):
        print('start_cycle:%x' % self.bookmarks.getFirstCycle())

    def getFirstCycle(self):
        return self.bookmarks.getFirstCycle()

    def stopAtKernelWrite(self, addr, rev_to_call=None, num_bytes = 1, satisfy_value=None, kernel=False, prev_buffer=False, track=False):
        '''
        Runs backwards until a write to the given address is found.
        Default is 1 byte since that tells us where the write occurred, regardless of the quantity of bytes written.
        '''
        if self.reverseEnabled():
            #self.context_manager[self.target].showHaps();
            self.removeDebugBreaks(immediate=True)
            tid, cpu = self.context_manager[self.target].getDebugTid() 
            value = self.mem_utils[self.target].readMemory(cpu, addr, num_bytes)
            if value is None:
                self.lgr.error('stopAtKernelWrite failed to read from addr 0x%x' % addr)
                self.skipAndMail()
                return
            self.lgr.debug('stopAtKernelWrite, call findKernelWrite of 0x%x to address 0x%x num bytes %d rev_to_call %s track %r cycles: 0x%x' % (value, addr, num_bytes, str(rev_to_call), track, cpu.cycles))
            cell = self.cell_config.cell_context[self.target]
            '''
            TBD breaks.  check for HAPs that have not been deleted or hidden.  ROP hap?
            here = cpu.cycles
            phys = self.mem_utils[self.target].v2p(cpu, addr)
            orig_cycle = self.bookmarks.getFirstCycle()
            self.lgr.debug('stopAtKernelWrite at cycle 0x%x, skip to origin 0x%x to test if value changed' % (cpu.cycles, orig_cycle))
            self.skipToCycle(orig_cycle) 
            value_origin = SIM_read_phys_memory(cpu, phys, num_bytes)
            if value_origin == value:
                print('Value 0x%x at address 0x%x unchanged at origin.' % (value, addr))
                self.lgr.debug('stopAtKernelWRite 0x%x at address 0x%x unchanged at origin.' % (value, addr))
            elif value_origin is None:
                print('Address 0x%x not mapped at origin.' % (addr))
                self.lgr.debug('stopAtKernelWrite Address 0x%x not mapped at origin.' % (addr))
            else:
                self.skipToCycle(here) 
                self.lgr.debug('stopAtKernelWrite Address 0x%x differs from that at origin. Skipped to saved cycle? 0x%x' % (addr, cpu.cycles))
            '''
            if True:
                if self.find_kernel_write is None:
                    self.find_kernel_write = findKernelWrite.findKernelWrite(self, cpu, cell, addr, self.task_utils[self.target], self.mem_utils[self.target],
                        self.context_manager[self.target], self.param[self.target], self.bookmarks, self.dataWatch[self.target], self.reverse_mgr[self.target], 
                        self.lgr, rev_to_call=rev_to_call, 
                        num_bytes=num_bytes, satisfy_value=satisfy_value, kernel=kernel, prev_buffer=prev_buffer, track=track)
                else:
                    self.lgr.debug('stopAtKernelWrite Address found existing find_kernel_write, use it for addr 0x%x num_bytes %d' % (addr, num_bytes))
                    self.find_kernel_write.go(addr, num_bytes=num_bytes, track=track, rev_to_call=rev_to_call)
        else:
            print('reverse execution disabled')
            self.skipAndMail()

    def revTaintSP(self):
        cpu = self.cell_config.cpuFromCell(self.target)
        value = self.mem_utils[self.target].getRegValue(cpu, 'sp')
        self.lgr.debug('revTaintSP')
        self.revTaintAddr(value)
        
    def revTaintAddr(self, addr, kernel=False, prev_buffer=False, callback=None, num_bytes=None):
        '''
        back track the value at a given memory location, where did it come from?
        prev_buffer of True causes tracking to stop when an address holding the
        value is found, e.g., as a souce buffer.
        The callback is used with prev_buffer=True, which always assumes the
        find will occur in the reverseToCall module.
        '''
        if num_bytes is None:
            num_bytes = self.getWordSize() 
        self.lgr.debug('revTaintAddr for 0x%x' % addr)
        if self.reverseEnabled():
            self.lgr.debug('revTaintAddr disable vmp')
            SIM_run_command('disable-vmp')
            self.removeDebugBreaks()
            tid, cpu = self.context_manager[self.target].getDebugTid() 
            cell_name = self.getTopComponentName(cpu)
            eip = self.getEIP(cpu)
            instruct = SIM_disassemble_address(cpu, eip, 1, 0)
            if num_bytes == 1:
                value = self.mem_utils[self.target].readByte(cpu, addr)
            elif num_bytes == 2:
                value = self.mem_utils[self.target].readWord16(cpu, addr)
            elif num_bytes == 4:
                value = self.mem_utils[self.target].readWord32(cpu, addr)
            else:
                value = self.mem_utils[self.target].readWord(cpu, addr)
            if value is None:
                print('Could not get value from address 0x%x' % addr)
                self.skipAndMail()
                return
            track_num = self.bookmarks.setTrackNum()
            bm='backtrack START:%d 0x%x inst:"%s" track_addr:0x%x track_value:0x%x' % (track_num, eip, instruct[1], addr, value)
            self.bookmarks.setDebugBookmark(bm)
            self.lgr.debug('BT add bookmark: %s' % bm)
            self.context_manager[self.target].setIdaMessage('')
            if callback is not None:
                self.rev_to_call[self.target].setCallback(callback)
            self.stopAtKernelWrite(addr, rev_to_call=self.rev_to_call[self.target], kernel=kernel, 
                 prev_buffer=prev_buffer, num_bytes=num_bytes, track=True)
        else:
            print('reverse execution disabled')
            self.skipAndMail()

    def revRegSrc(self, reg, kernel=False, callback=None, taint=False):
        ''' NOT yet used, see revTainReg'''
        self.rev_to_call[self.target].setCallback(callback)
        self.rev_to_call[self.target].doRevToModReg(reg, kernel=kernel, taint=taint)

    def revTaintReg(self, reg, kernel=False, no_increments=False):
        ''' back track the value in a given register '''
        self.lgr.debug('revTaintReg disable vmp')
        SIM_run_command('disable-vmp')
        self.reverseTrack[self.target].revTaintReg(reg, self.bookmarks, kernel=kernel, no_increments=no_increments)

    def satisfyCondition(self, pc):
        ''' Assess a simple condition, modify input data to satisfy it '''
        if self.reverseEnabled():
            self.removeDebugBreaks()
            tid, cpu = self.context_manager[self.target].getDebugTid() 
            eip = self.getEIP(cpu)
            instruct = SIM_disassemble_address(cpu, eip, 1, 0)
            self.lgr.debug('satisfyCondition pc 0x%x' % pc)
            # TBD, backtrack bookmarks only for debugging, they are meaningless after the retrack
            track_num = self.bookmarks.setTrackNum()
            bm='backtrack START:%d 0x%x inst:"%s" satsify condition' % (track_num, eip, instruct[1])
            self.bookmarks.setDebugBookmark(bm)
            self.context_manager[self.target].setIdaMessage('')
            if not self.rev_to_call[self.target].satisfyCondition(pc):
                self.restoreDebugBreaks(was_watching=True)
        else:
            print('reverse execution disabled')
            self.skipAndMail()

    def rev1NoMail(self):
        self.lgr.debug('rev1NoMail')
        dum, cpu = self.context_manager[self.target].getDebugTid() 
        new_cycle = cpu.cycles - 1
        self.skipToCycle(new_cycle)
        self.lgr.debug('rev1NoMail skipped to 0x%x  cycle is 0x%x' % (new_cycle, cpu.cycles))
        SIM_run_command('disassemble')

    def rev1(self):
        if self.reverseEnabled():
            self.removeDebugBreaks()
            dum, cpu = self.context_manager[self.target].getDebugTid() 
            new_cycle = cpu.cycles - 1
         
            start_cycles = self.getStartCycle()
            if new_cycle >= start_cycles:
                self.is_monitor_running.setRunning(True)
                self.skipToCycle(new_cycle)
                #try:
                #    result = SIM_run_command('skip-to cycle=0x%x' % new_cycle)
                #except: 
                #    print('Reverse execution disabled?')
                #    self.skipAndMail()
                #    return
                self.lgr.debug('rev1 result from skip to 0x%x  is %s cycle now 0x%x' % (new_cycle, result, cpu.cycles))
                self.skipAndMail()
            else:
                self.lgr.debug('rev1, already at first cycle 0x%x' % new_cycle)
                self.skipAndMail()
        else:
            print('reverse execution disabled')
            self.skipAndMail()

    def test1(self):
        
        tid, cpu = self.context_manager[self.target].getDebugTid() 
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

    def runToCall(self, callname, tid=None, subcall=None, run=True, stop_on_call=False, linger=False, trace=False):
        cell = self.cell_config.cell_context[self.target]
        self.is_monitor_running.setRunning(True)
        self.lgr.debug('runToCall')
        self.checkOnlyIgnore()
        if tid is not None:
            tid_match = syscall.TidFilter(tid)
            tid_param = syscall.CallParams('runToCall', callname, tid_match, break_simulation=True) 
            call_params = [tid_param]
            self.lgr.debug('runToCall %s set tid filter' % callname)
        elif subcall is not None:
            if callname == 'ipc':
                if subcall in ipc.call_name:
                    ipc_call = syscall.IPCFilter(ipc.call_name[subcall])
                    ipc_param = syscall.CallParams('runToCall', callname, ipc_call, break_simulation=True) 
                    call_params = [ipc_param]
                    self.lgr.debug('runToCall %s set tid filter' % callname)
                else:
                    self.lgr.error('syscall runToCall, subcall %s unknown' % subcall)
                    return
            else:
                self.lgr.error('syscall runTocall subcall %s not handled for call %s' % (subcall, callname))
                return
        else:
            self.lgr.debug('runToCall set no_param to break on this call')
            no_param = syscall.CallParams('runToCall', callname, None, break_simulation=True) 
            call_params = [no_param]

        self.lgr.debug('runToCall %s %d params' % (callname, len(call_params)))
        if trace:
            tf = 'logs/runToCall_%s.trace' % callname
            cpu = self.cell_config.cpuFromCell(self.target)
            self.traceMgr[self.target].open(tf, cpu)
        self.syscallManager[self.target].watchSyscall(None, [callname], call_params, callname, stop_on_call=stop_on_call, linger=linger)
        if run: 
            SIM_continue(0)

    def runToSyscall(self, callnum = None):
        cell = self.cell_config.cell_context[self.target]
        self.is_monitor_running.setRunning(True)
        if callnum is not None:
            # TBD fix 32-bit compat
            callname = self.task_utils[self.target].syscallName(callnum, False)
            self.lgr.debug('runToSyscall for  %s' % callname)
            #call_params = [syscall.CallParams(callname, None, break_simulation=True)]        
            call_params = []

            if callnum == 120:
                print('Disabling thread tracking for clone')
                self.stopThreadTrack()
            self.syscallManager[self.target].watchSyscall(None, [callname], call_params, callname)

        else:
            ''' watch all syscalls '''
            self.lgr.debug('runToSyscall for any system call')
            self.trace_all[self.target] = self.syscallManager[self.target].watchAllSyscalls(None, 'runToSyscall')
     
        self.lgr.debug('runToSyscall now continue')
        SIM_continue(0)

    def traceSyscall(self, callname=None, soMap=None, call_params=[], trace_procs = False, swapper_ok=False):
        ''' TBD clean up or remove '''
        cell = self.cell_config.cell_context[self.target]
        # TBD only set if debugging?
        self.is_monitor_running.setRunning(True)
        self.lgr.debug('traceSyscall for call %s' % callname)
        if trace_procs:
            tp = self.traceProcs[self.target]
        else:
            tp = None
        my_syscall = syscall.Syscall(self, self.target, None, self.param[self.target], self.mem_utils[self.target], self.task_utils[self.target], 
                           self.context_manager[self.target], tp, self.sharedSyscall[self.target], self.lgr, self.traceMgr[self.target],call_list=[callname], 
                           trace=True, soMap=soMap, call_params=call_params, 
                           binders=self.binders, connectors=self.connectors, targetFS=self.targetFS[self.target], swapper_ok=swapper_ok)
        return my_syscall

    def traceProcesses(self, new_log=True, swapper_ok=False):
        ''' TBD clean up or remove '''
        cpu, comm, tid = self.task_utils[self.target].curThread() 
        call_list = ['vfork','fork', 'clone','execve','open','openat','pipe','pipe2','close','dup','dup2','socketcall', 
                     'exit', 'exit_group', 'waitpid', 'ipc', 'read', 'write', 'gettimeofday', 'mmap', 'mmap2']
        #             'exit', 'exit_group', 'waittid', 'ipc', 'read', 'write', 'gettimeofday', 'mmap', 'mmap2']
        if (cpu.architecture == 'arm' and not self.param[self.target].arm_svc) or self.mem_utils[self.target].WORD_SIZE == 8:
            call_list.remove('socketcall')
            call_list.remove('mmap2')
            for scall in net.callname[1:]:
                call_list.append(scall.lower())
        if self.mem_utils[self.target].WORD_SIZE == 8:
            call_list.remove('ipc')
            call_list.remove('send')
            call_list.remove('recv')
            call_list.remove('waitpid')
            call_list.append('waitid')

        calls = ' '.join(s for s in call_list)
        print('tracing these system calls: %s' % calls)
        if new_log:
            self.traceMgr[self.target].open('logs/syscall_trace.txt', cpu)
        for call in call_list: 
            #TBD fix 32-bit compat
            self.call_traces[self.target][call] = self.traceSyscall(callname=call, trace_procs=True, soMap=self.soMap[self.target], swapper_ok=swapper_ok)

    def rmSyscall(self, call_param_name, context=None, cell_name=None, all_contexts=False):
        self.lgr.debug('rmSyscall call_param_name %s, cell_name %s context: %s all_contexts: %r' % (call_param_name, cell_name, context, all_contexts))
        if cell_name is None:
            cell_name = self.target 
        if not all_contexts:
            self.syscallManager[self.target].rmSyscall(call_param_name, context=context)
        else:
            context_list = self.context_manager[self.target].getContexts()
            for context in context_list:
                self.syscallManager[self.target].rmSyscall(call_param_name, context=context)
   
    def rmAllSyscalls(self, cell_name=None):
        if cell_name is None:
            cell_name = self.target
        self.syscallManager[cell_name].rmAllSyscalls()
 
 
    def stopTrace(self):
        self.lgr.debug('stopTrace')
        self.syscallManager[self.target].rmAllSyscalls()

    def rmCallTrace(self, cell_name, callname):
        #TBD remove this?
        ''' remove a call trace and all of its aliases '''
        #self.lgr.debug('genMonitor rmCallTrace %s' % callname)
        if callname in self.call_traces[cell_name]:
            the_call = self.call_traces[cell_name][callname]
            rm_list = []
            #self.lgr.debug('genMonitor rmCallTrace will delete %s' % callname)
            del self.call_traces[cell_name][callname]
            for call in self.call_traces[cell_name]:
                if self.call_traces[cell_name][call] == the_call:
                    rm_list.append(call)
            for call in rm_list:
                del self.call_traces[cell_name][call]

        else:
            #self.lgr.debug('rmCallTrace callname %s not in call_traces for cell %s' % (callname, cell_name))
            pass

    def traceFile(self, path):
        ''' Create mirror of reads/write to the given file.'''
        self.lgr.debug('traceFile %s' % path)
        outfile = os.path.join('logs/', os.path.basename(path))
        self.traceFiles[self.target].watchFile(path, outfile)
        ''' TBD reduce to only track open/write/close? '''
        if self.target not in self.trace_all:
            self.traceAll()

    def traceFD(self, fd, raw=False, web=False, all=False, comm=None):
        ''' Create mirror of reads/write to the given FD.  Use raw to avoid modifications to the data. '''
        self.lgr.debug('traceFD %d target is %s' % (fd, self.target))
        outfile = 'logs/output-fd-%d.log' % fd
        self.traceFiles[self.target].watchFD(fd, outfile, raw=raw, web=web, all=all, comm=comm)

    def exceptHap(self, cpu, one, exception_number):
        cpu, comm, tid = self.task_utils[self.target].curThread() 
        call = self.mem_utils[self.target].getRegValue(cpu, 'r7')
        self.lgr.debug('exeptHap except: %d  tid:%s call %d' % (exception_number, tid, call))

    def copyCallParams(self, syscall):
        ''' TBD replace with new syscallManager'''
        ''' Copy the call parameters from all other syscalls to the given syscall.  TBD why?  Cannot we hit twice on a call, once at entry and once at jump table destination?'''
        #self.lgr.debug('copyCallParams for syscall %s' % syscall.name)
        the_calls = syscall.getCallList()
        for other_call in self.call_traces[self.target]:
            if (the_calls is None or len(the_calls)==0) or self.call_traces[self.target][other_call].callListIntersects(the_calls):
                #self.lgr.debug('copyCallParams found a syscall with intersecting calls (or syscall was traceAll), copy its params')
                params = self.call_traces[self.target][other_call].getCallParams()
                syscall.addCallParams(params) 
       
    def checkOnlyIgnore(self):
        ''' Load ignore list or only list if defined '''
        self.lgr.debug('checkOnlyIgnore')
        retval = False
        if not self.debugging():
            retval = self.ignoreProgList() 
            if not retval:
                retval = self.onlyProgList() 
            self.ignoreThreadList()
        return retval
 
    def traceAll(self, target=None, record_fd=False, swapper_ok=False, call_params_list=[], track_threads=True, trace_file=None, no_gui=False):
        if target is None:
            target = self.target

        if not track_threads:
            self.track_threads = None 
        ''' trace all system calls. if a program selected for debugging, watch only that program '''
        self.lgr.debug('traceAll target %s begin track_threads %r' % (target, track_threads))
        if target not in self.cell_config.cell_context:
            print('Unknown target %s' % target)
            return
        if self.checkOnlyIgnore():
            self.rmDebugWarnHap()

        if self.context_manager[self.target].didListLoad():
            self.lgr.debug('Will preserve syscall exits')
            self.sharedSyscall[self.target].preserveExit()

        self.traceBufferTarget(target, msg='traceAll')

        if target in self.trace_all:
            self.trace_all[target].setRecordFD(record_fd)
            print('Was tracing.  Limit to FD recording? %r' % (record_fd))
            self.lgr.debug('traceAll Was tracing.  Limit to FD recording? %r' % (record_fd))
        else:
            if self.isWindows():
                self.trace_all[target]= self.winMonitor[target].traceAll(record_fd=record_fd, swapper_ok=swapper_ok, no_gui=no_gui)
                self.lgr.debug('traceAll back from winMonitor trace_all set to %s' % self.trace_all[target])
                self.run_to[target].watchSO()
                if track_threads:
                    self.trackThreads()
                return
            elif self.isVxDKM():
                self.trace_all[target]= self.vxKMonitor[target].traceAll(record_fd=record_fd)

            context = self.context_manager[target].getDefaultContext()
            cell = self.cell_config.cell_context[target]
            tid, cpu = self.context_manager[target].getDebugTid() 
            if tid is not None:
                self.lgr.debug('traceAll, tid back from getDebugTid is %s' % tid)
                #tf = '/tmp/syscall_trace-%s-%s.txt' % (target, tid)
                if trace_file is None:
                    tf = 'logs/syscall_trace-%s-%s.txt' % (target, tid)
                else:
                    tf = trace_file
                context = self.context_manager[target].getRESimContext()
            else:
                self.lgr.debug('traceAll, no tid')
                if trace_file is None:
                    tf = 'logs/syscall_trace-%s.txt' % target
                else:
                    tf = trace_file

            if not self.isVxDKM(target=target) and track_threads:
                cpu, comm, tid = self.task_utils[target].curThread() 
                self.lgr.debug('traceAll trackThreads')
                self.trackThreads()

            self.traceMgr[target].open(tf, cpu)
            if not self.isVxDKM(target=target) and not self.isWindows(target=target):
                if not self.context_manager[self.target].watchingTasks() and track_threads:
                    self.traceProcs[target].watchAllExits()
                self.lgr.debug('traceAll, create syscall hap')
                self.trace_all[target] = self.syscallManager[self.target].watchAllSyscalls(None, 'traceAll', trace=True, binders=self.binders, connectors=self.connectors,
                                          record_fd=record_fd, linger=True, netInfo=self.netInfo[self.target], swapper_ok=swapper_ok, call_params_list=call_params_list)
    
                frames = self.getDbgFrames()
                if self.run_from_snap is not None and self.snap_start_cycle[cpu] == cpu.cycles:
                    ''' running from snap, fresh from snapshot.  see if we recorded any calls waiting in kernel '''
                    self.lgr.debug('traceAll running from snap, starting cycle')
                    p_file = os.path.join('./', self.run_from_snap, target, 'sharedSyscall.pickle')
                    if os.path.isfile(p_file):
                        exit_info_list = pickle.load(open(p_file, 'rb'))
                        if exit_info_list is None:
                            self.lgr.error('traceAll No sharedSyscall pickle data found in %s' % p_file)
                        else:
                            self.lgr.debug('traceAll got sharedSyscall pickle len of exit_info %d' % len(exit_info_list))
                            ''' TBD rather crude determination of context.  Assuming if debugging, then all from pickle should be resim context. '''
                            #self.trace_all[target].setExits(exit_info_list, context_override = context)
                            self.trace_all[target].setExits(frames, context_override = context)
                    
    
                self.lgr.debug('traceAll, call to setExits %d frames context %s' % (len(frames), context))
                self.trace_all[target].setExits(frames, context_override=context)


    def stopDebug(self, rev=False):
        ''' stop all debugging.  called by injectIO and debugProc (with new=True) and user when process dies and we know it will be recreated '''
        self.lgr.debug('stopDebug')
        if not rev and self.rev_execution_enabled:
            self.reverse_mgr[self.target].disableReverse()
            self.rev_execution_enabled = False
        self.removeDebugBreaks(keep_watching=False, keep_coverage=False, immediate=True)
        self.sharedSyscall[self.target].setDebugging(False)
        self.syscallManager[self.target].rmAllSyscalls()
        #self.stopTrace()
        if self.target in self.magic_origin:
            self.magic_origin[self.target].deleteMagicHap() 
            del self.magic_origin[self.target]
            self.lgr.debug('stopDebug deleted magic origin ')
        self.noWatchSysEnter()
        self.context_manager[self.target].stopDebug()
        # DO NOT call stopTracking here, breaks restoreDebug function.

    def restartDebug(self):
        self.lgr.debug('restartDebug')
        self.reverse_mgr[self.target].enableReverse()
        self.rev_execution_enabled = True
        self.restoreDebugBreaks(was_watching=True)
        self.sharedSyscall[self.target].setDebugging(True)
        self.recordEntry()

    def startThreadTrack(self):
        if self.track_threads is not None:
            for cell_name in self.track_threads:
                self.lgr.debug('startThreadTrack for %s' % cell_name)
                self.track_threads[cell_name].startTrack()
        
    def stopThreadTrack(self, immediate=False):
        if self.track_threads is not None:
            self.lgr.debug('stopThreadTrack ')
            for cell_name in self.track_threads:
                self.lgr.debug('stopThreadTrack for %s' % cell_name)
                self.track_threads[cell_name].stopTrack(immediate=immediate)
            self.track_threads = {}

    def showProcTrace(self):
        ''' TBD this looks like a hack, why are the precs none?'''
        tid_comm_map = self.task_utils[self.target].getTidCommMap()
        precs = self.traceProcs[self.target].getPrecs()
        for tid in precs:
            if precs[tid].prog is None and tid in tid_comm_map:
                precs[tid].prog = 'comm: %s' % (tid_comm_map[tid])
        #for tid in precs:
        #    if precs[tid].prog is None and tid in self.proc_list[self.target]:
        #        precs[tid].prog = 'comm: %s' % (self.proc_list[self.target][tid])
        
        self.traceProcs[self.target].showAll()

    def trackExecve(self):
        self.toExecve(any_exec=True, run=False, linger=True) 
    def toExecve(self, prog=None, flist=None, binary=False, watch_exit=False, any_exec=False, run=True, linger=False):
        cell = self.cell_config.cell_context[self.target]
        if prog is not None:    
            params = syscall.CallParams('toExecve', 'execve', prog, break_simulation=True) 
            if binary:
                params.param_flags.append('binary')
            if any_exec:
                params.param_flags.append('any_exec')
            call_params = [params]
        else:
            call_params = []
            cpu = self.cell_config.cpuFromCell(self.target)
            self.traceMgr[self.target].open('logs/execve.txt', cpu)
        call_list = ['execve']
        if watch_exit:
            call_list.append('exit_group')
            call_list.append('exit')
        scall_name = 'execve'
        # alter name so syscall knows difference between toProc and debugProc
        if flist is not None:
            for f in flist:
                self.lgr.debug('toExecve flist fun str(%s)' % f.getFun())
                if f.getFun() == self.debug:
                    scall_name = 'execve_debug'
                    self.lgr.debug('toExecve found debug, set scall_name to execve_debug')
                    break
        self.syscallManager[self.target].watchSyscall(None, call_list, call_params, scall_name, flist=flist, linger=linger)
        if run:
            SIM_continue(0)

    def clone(self, nth=1):
        ''' Run until we are in the child of the Nth clone of the current process'''
        #cell = self.cell_config.cell_context[self.target]
        #eh = cloneChild.CloneChild(self, cell, self.param[self.target], self.mem_utils[self.target], self.task_utils[self.target], self.context_manager[self.target], nth, self.lgr)
        #SIM_run_command('c')
        self.runToClone(nth)

    #def recordText(self, start, end):
    #    ''' record IDA's view of text segment, unless we recorded from our own parse of the elf header '''
    #    self.lgr.debug('.text IDA is 0x%x - 0x%x' % (start, end))
    #    s, e = self.context_manager[self.target].getText()
    #    if s is None:
    #        self.lgr.debug('genMonitor recordText, no text from contextManager, use from IDA')
    #        cpu, comm, tid = self.task_utils[self.target].curThread() 
    #        self.context_manager[self.target].recordText(start, end)
    #        self.soMap[self.target].addText(start, end-start, 'tbd', tid)

    def textHap(self, prec, the_object, the_break, memory):
        ''' callback when text segment is executed '''
        if self.proc_hap is None:
            return
        cpu, comm, tid = self.task_utils[self.target].curThread() 
        if cpu != prec.cpu or tid not in prec.tid:
            self.lgr.debug('%s hap, wrong something tid:%s prec tid list %s' % (prec.who, tid, str(prec.tid)))
            #SIM_break_simulation('remove this')
            return

        eip = self.getEIP(cpu)
        load_info = self.soMap[self.target].getLoadInfo()
        if load_info.addr is None:
            self.lgr.debug('textHap load_info addr is None, assume dynamic? eip 0x%x' % eip)
            self.soMap[self.target].setProgStart()
        #cur_eip = SIM_get_mem_op_value_le(memory)
        self.lgr.debug('textHap eip is 0x%x' % eip)
        self.is_monitor_running.setRunning(False)
        SIM_break_simulation('text hap')
        if prec.debugging:
            self.context_manager[self.target].genDeleteHap(self.proc_hap)
            self.proc_hap = None
            self.skipAndMail()

    def debugExitHap(self, flist=None, context=None): 
        ''' intended to stop simulation if the threads we are debugging all exit '''
        retval = None
        if self.isWindows():
            self.winMonitor[self.target].debugExitHap(flist, context=context)
        elif self.isVxDKM():
            self.lgr.debug('debugExitHap, TBD for vxDKM')
        else:
            if self.target not in self.exit_group_syscall:
                somap = None
                if self.target in self.soMap:
                    somap = self.soMap[self.target]
                else:
                    self.lgr.debug('debugExitHap no so map for %s' % self.target)
       
                if context is None: 
                    context=self.context_manager[self.target].getRESimContextName()

                exit_calls = ['exit_group', 'tgkill', 'exit']
                self.exit_group_syscall[self.target] = self.syscallManager[self.target].watchSyscall(context, exit_calls, [], 'debugExit')
                retval = self.exit_group_syscall[self.target]
                #self.lgr.debug('debugExitHap')
        return retval

    def rmDebugExitHap(self):
        ''' Intended to be called if a SEGV or other cause of death occurs, in which case we assume that is caught by
            the contextManager and we do not want this rudundant stopage. '''
        if self.isWindows():
            self.winMonitor[self.target].rmDebugExitHap()
        elif self.isVxDKM():
            self.lgr.debug('rmDebugExitHap, TBD for vxDKM')
        elif self.target in self.exit_group_syscall:
            self.lgr.debug('rmDebugExit')
            self.syscallManager[self.target].rmSyscall('debugExit')
            #self.exit_group_syscall[self.target].stopTrace()
            del self.exit_group_syscall[self.target]

    def stopOnExit(self, stop=True, target=None):
        if target is None:
            target = self.target
        self.lgr.debug('stopOnExit target %s is %r' % (target, stop))
        self.stop_on_exit[target] = stop 
        
    def getStopOnExit(self, target=None):
        retval = False
        if target is None:
            target = self.target
        if target in self.stop_on_exit and self.stop_on_exit[target] == True:
            retval = True
        return retval
       
    def noReverse(self, watch_enter=True):
        self.reverse_mgr[self.target].disableReverse()
        if not watch_enter:
            self.noWatchSysEnter()
        self.rev_execution_enabled = False
        self.lgr.debug('genMonitor noReverse')

    def allowReverse(self):
        if self.rev_execution_enabled:
            print('Reverse execution already enabled')
            return
        self.reverse_mgr[self.target].enableReverse()
        tid, cpu = self.context_manager[self.target].getDebugTid() 
        prec = Prec(cpu, None, tid)
        if tid is not None:
            self.lgr.debug('genMonitor allowReverse tid from getDebugTid is %s' % tid)
            self.recordEntry()
        if self.bookmarks is None:
            self.bookmarks = bookmarkMgr.bookmarkMgr(self, self.context_manager[self.target], self.lgr)
            self.bookmarks.setOrigin(cpu)
        self.rev_execution_enabled = True
        self.lgr.debug('genMonitor allowReverse done')
        print('Reverse execution enabled.')
 
    def restoreDebugBreaks(self, was_watching=False):
         
        cpu, comm, cur_tid = self.task_utils[self.target].curThread() 
        self.lgr.debug('restoreDebugBreaks cur tid:%s  but may not be the debug tid cycles: 0x%x' % (cur_tid, cpu.cycles))
        self.context_manager[self.target].resetWatchTasks() 
        if not self.debug_breaks_set and not self.track_finished:
            self.lgr.debug('restoreDebugBreaks breaks not set and not track finished')
            #self.context_manager[self.target].restoreDebug() 
            tid, cpu = self.context_manager[self.target].getDebugTid() 
            if tid is not None:
                if not was_watching:
                    self.context_manager[self.target].watchTasks()
                if self.rev_execution_enabled:
                    prec = Prec(cpu, None, tid)
                    self.recordEntry()
                    if self.track_threads is not None and self.target in self.track_threads:
                        self.track_threads[self.target].startTrack()
                    if self.target in self.ropCop:
                        self.ropCop[self.target].setHap()
            self.debugExitHap()
            self.context_manager[self.target].setExitBreaks()
            self.debug_breaks_set = True
            self.watchPageFaults()
            #self.lgr.debug('restoreDebugBreaks back page')
            if self.trace_malloc is not None:
                self.trace_malloc.setBreaks()
            #self.lgr.debug('restoreDebugBreaks back  malloc')
            if self.injectIOInstance is not None:
                self.injectIOInstance.restoreCallHap()
            #self.lgr.debug('restoreDebugBreaks back  inject')
            if self.user_break is not None:
                self.user_break.doBreak()
            #self.lgr.debug('restoreDebugBreaks back  break')
            if self.target in self.magic_origin:
                self.lgr.debug('restoreDebugBreaks set magic?')
                self.magic_origin[self.target].setMagicHap()
            #self.lgr.debug('restoreDebugBreaks return')
            self.jumperEnable()
            if self.target in self.read_replace:
                self.read_replace[self.target].enableBreaks()
            if self.target in self.trace_buffers:
                self.trace_buffers[self.target].restoreHaps()

    def noWatchSysEnter(self):
        self.lgr.debug('noWatchSysEnter')
        self.record_entry[self.target].noWatchSysenter()

    def stopWatchTasks(self, target=None, immediate=False):
        if target is None:
            target = self.target
        if immediate:   
           self.context_manager[target].stopWatchTasksAlone(None)
        else:
           self.context_manager[target].stopWatchTasks()

    def watchGroupExits(self, target=None): 
        if target is None:
            target = self.target
        self.context_manager[target].watchGroupExits()

    def removeDebugBreaks(self, keep_watching=False, keep_coverage=True, immediate=False):
        ''' return true if breaks were set and we removed them '''
        self.lgr.debug('genMon removeDebugBreaks was set: %r immediate: %r' % (self.debug_breaks_set, immediate))
        if not keep_watching:
            if immediate:
                self.context_manager[self.target].stopWatchTasksAlone(None)
            else:
                self.context_manager[self.target].stopWatchTasks()
        if self.debug_breaks_set:
            retval = True
            tid, cpu = self.context_manager[self.target].getDebugTid() 
            self.stopWatchPageFaults(tid, immediate=immediate)
            self.noWatchSysEnter()
            if self.track_threads is not None and self.target in self.track_threads:
                self.track_threads[self.target].stopTrack(immediate=immediate)
            if self.isWindows():
                self.winMonitor[self.target].rmDebugExitHap(immediate=immediate, context=self.context_manager[self.target].getRESimContextName()) 
            elif self.target in self.exit_group_syscall:
                self.syscallManager[self.target].rmSyscall('debugExit', immediate=immediate, context=self.context_manager[self.target].getRESimContextName())
                self.lgr.debug('genMon removeDebugBreaks removed debugExit')
                #self.exit_group_syscall[self.target].stopTrace(immediate=immediate)
                del self.exit_group_syscall[self.target]
            if self.target in self.ropCop:
                self.ropCop[self.target].clearHap()
            self.context_manager[self.target].clearExitBreaksAlone(None)
            self.debug_breaks_set = False
            if self.coverage is not None and not keep_coverage:
                self.coverage.stopCover(keep_hits=True)
            if self.trace_malloc is not None:
                #self.lgr.debug('genMon removeDebugBreaks trace_malloc')
                self.trace_malloc.stopTrace()
            if self.injectIOInstance is not None:
                #self.lgr.debug('genMon removeDebugBreaks inject delcallhap')
                self.injectIOInstance.delCallHap()
            if self.user_break is not None:
                self.user_break.stopBreak()
            if self.target in self.magic_origin:
                self.lgr.debug('genMon removeDebugBreaks magic')
                self.magic_origin[self.target].deleteMagicHap()
            self.jumperDisable()
            self.disableOtherBreaks()
        else:
            retval = False
        return retval

    def disableOtherBreaks(self):
        if self.target in self.read_replace:
            self.read_replace[self.target].disableBreaks()
        if self.target in self.trace_buffers:
            self.trace_buffers[self.target].rmAllHaps(immediate=immediate)
        if self.target in self.page_callbacks:
            self.page_callbacks[self.target].disableBreaks()

    def revToText(self):
        self.is_monitor_running.setRunning(True)
        #start, end = self.context_manager[self.target].getText()
        load_info = self.soMap[self.target].getLoadInfo()
        if load_info is None:
            print('No text segment defined, has IDA been started with the rev plugin?')
            return
        self.removeDebugBreaks()
        start = load_info.addr
        end = load_info.end
        count = end - start
        self.lgr.debug('revToText 0x%x - 0x%x count: 0x%x' % (start, end, count))
        cell = self.cell_config.cell_context[self.target]
        cpu, comm, tid = self.task_utils[self.target].curThread() 
        self.rev_to_call[self.target].setBreakRange(self.target, tid, start, count, cpu, comm, False)
        f1 = stopFunction.StopFunction(self.rev_to_call[self.target].rmBreaks, [], nest=False)
        f2 = stopFunction.StopFunction(self.skipAndMail, [], nest=False, match_tid=True)
        flist = [f1, f2]
        hap_clean = hapCleaner.HapCleaner(cpu)
        ''' if we land in the wrong tid, rev to the right tid and then revToText again...'''
        stop_action = hapCleaner.StopAction(hap_clean, flist=flist, tid=tid, wrong_tid_action=self.revToText)
        self.stop_hap = self.RES_add_stop_callback(self.stopHap, stop_action)
        self.lgr.debug('hap set, now reverse')
        SIM_run_command('rev')

    def getSyscall(self, cell_name, callname):
        ''' find the most specific syscall for the given callname '''
        retval = None
        if self.isWindows(target=cell_name):
            retval = self.winMonitor[cell_name].getSyscall(callname)
        else:
            if cell_name in self.exit_group_syscall and callname == 'exit_group':
                #self.lgr.debug('is exit group')
                retval = self.exit_group_syscall[cell_name]
            elif cell_name in self.call_traces: 
                if callname in self.call_traces[cell_name]:
                    #self.lgr.debug('is given callname %s' % callname)
                    retval = self.call_traces[cell_name][callname]
                elif cell_name in self.trace_all:
                    #self.lgr.debug('is trace all')
                    retval = self.trace_all[cell_name]
                else:
                    self.lgr.debug('genMonitor getSyscall, not able to return instance for call %s len self.call_traces %d' % (callname, 
                               len(self.call_traces[cell_name])))
        return retval

    def tracingAll(self, cell_name, tid=None):
        ''' are we tracing all syscalls for the given tid? '''
        retval = False
        #self.lgr.debug('tracingAll cell_name %s len of self.trace_all is %d' % (cell_name, len(self.trace_all))) 
        if cell_name in self.trace_all:
            #self.lgr.debug('tracingAll %s in trace_all' % cell_name) 
            debug_tid, dumb1 = self.context_manager[self.target].getDebugTid() 
            if debug_tid is None:
                #self.lgr.debug('tracingAll tid none, return true')
                retval = True
            else:
                #self.lgr.debug('tracingAll debug_tid:%s' % debug_tid)
                if self.context_manager[self.target].amWatching(tid):
                    #self.lgr.debug('tracingAll watching tid:%s' % tid)
                    retval = True
                else:
                    #self.lgr.debug('tracingAll not watching debug_tid:%s' % debug_tid)
                    pass
        return retval
            

    def runToText(self, flist = None, this_tid=False):
        ''' run until within the currently defined text segment '''
        self.is_monitor_running.setRunning(True)
        #start, end = self.context_manager[self.target].getText()
        load_info = self.soMap[self.target].getLoadInfo()
        if this_tid:
            cpu, comm, tid = self.task_utils[self.target].curThread() 
        else:
            tid, cpu = self.context_manager[self.target].getDebugTid() 
        if load_info is None:
            print('No text load info for current process?')
            return
        loader_load_info = None
        if load_info.interp is not None:
            ip = self.getEIP() 
            loader_load_info = self.soMap[self.target].addLoader(tid, load_info.interp, ip)

        if load_info.addr is not None:
            start = load_info.addr
            end = load_info.end
            count = end - start
            self.lgr.debug('runToText range 0x%x 0x%x' % (start, end))
        else:
            if loader_load_info is not None:
                # assume dynamic load.  Set break on zero to start of loader
                start = 0
                count = loader_load_info.addr 
                self.lgr.debug('runToText dynamic load break on range 0x%x 0x%x tid:%s' % (start, count, tid))
            else:
                self.lgr.error('runToText dynamic load but no load info for the loader itself')
                return
            
        self.context_manager[self.target].watchTasks()
        if flist is not None and self.listHasDebug(flist):
            ''' We will be debugging.  Set debugging context now so that any reschedule does not 
                cause false hits in the text block '''
            self.context_manager[self.target].setDebugTid()

        proc_break = self.context_manager[self.target].genBreakpoint(None, Sim_Break_Linear, Sim_Access_Execute, start, count, 0)
        if tid is None or this_tid:
            cpu, comm, tid = self.task_utils[self.target].curThread() 
            prec = Prec(cpu, None, [tid], who='to text')
        else:
            tid_list = self.context_manager[self.target].getThreadTids()
            prec = Prec(cpu, None, tid_list, who='to text')
        prec.debugging = True
        ''' NOTE obscure use of flist to determine if SO files are tracked '''
        prec.debugging = True
        if flist is None:
            f1 = stopFunction.StopFunction(self.skipAndMail, [], nest=False)
            flist = [f1]
        #else:
        #    #self.call_traces[self.target]['open'] = self.traceSyscall(callname='open', soMap=self.soMap)
        if not self.isWindows():
            call_list = ['open', 'mmap']
            if self.mem_utils[self.target].WORD_SIZE == 4 or self.is_compat32: 
                call_list.append('mmap2')

            self.syscallManager[self.target].watchSyscall(None, call_list, [], 'runToText')

            self.lgr.debug('debug watching open syscall and mmap')

            hap_clean = hapCleaner.HapCleaner(cpu)
            hap_clean.add("GenContext", self.proc_hap)
            stop_action = hapCleaner.StopAction(hap_clean, flist=flist)
            self.stop_hap = self.RES_add_stop_callback(self.stopHap, stop_action)
            self.lgr.debug('runToText hap set, now run. flist in stophap is %s breakpoint set on 0x%x' % (stop_action.listFuns(), start))

        self.proc_hap = self.context_manager[self.target].genHapIndex("Core_Breakpoint_Memop", self.textHap, prec, proc_break, 'text_hap')

        SIM_continue(0)

    def undoDebug(self, dumb):
        self.lgr.debug('undoDebug')
        if self.cur_task_hap is not None:
            RES_hap_delete_callback_id("Core_Breakpoint_Memop", self.cur_task_hap)
            RES_delete_breakpoint(self.cur_task_break)
            self.cur_task_hap = None
        if self.proc_hap is not None:
            self.context_manager[self.target].genDeleteHap(self.proc_hap)
            self.proc_hap = None
        if self.stop_hap is not None:
            self.RES_delete_stop_hap(self.stop_hap)
            self.stop_hap = None
        self.lgr.debug('undoDebug done')
            

    def remainingCallTraces(self, cell_name=None, exception=None):
        if cell_name is None:
            cell_name = self.target
        return self.syscallManager[cell_name].remainingCallTraces(exception=exception)


    def runTo(self, call_list, call_params, cell_name=None, cell=None, run=True, linger_in=False, background=False, 
              ignore_running=False, name=None, flist=None, callback = None, all_contexts=False):
        retval = None
        self.lgr.debug('runTo call_list %s' % str(call_list))
        if not ignore_running and self.checkOnlyIgnore():
            self.rmDebugWarnHap()

        ''' call_list is a list '''
        if not ignore_running and self.is_monitor_running.isRunning():
            print('Monitor is running, try again after it pauses')
            self.lgr.debug('runTo Monitor is running, try again after it pauses')
            return
        if cell_name is None:
            cell_name = self.target
        ''' qualify call with name, e.g, for multiple dmod on reads '''
        call_name = call_list[0]
        if name is not None:
            #call_name = '%s-%s' % (call[0], name)
            call_name = name
        if cell is None:
            self.lgr.debug('genMonitor runTo cellname %s call_name %s compat32 %r' % (cell_name, call_name, self.is_compat32))
        else:
            self.lgr.debug('genMonitor runTo cellname %s cell: %s call_name %s compat32 %r' % (cell_name, cell.name, call_name, self.is_compat32))
        call_param_name = call_name
        if call_params is None:
            call_params_list = []
        else:
            call_params_list = [call_params]
            call_param_name = call_params.name
        if not linger_in:
            if flist is None:
                flist = []
            f1 = stopFunction.StopFunction(self.syscallManager[self.target].rmSyscall, [call_param_name], nest=False)
            f2 = stopFunction.StopFunction(self.skipAndMail, [], nest=False)
            flist.append(f1)
            flist.append(f2)
        the_syscall = None
        if self.isVxDKM():
            if 'fopen' not in call_list:
                call_list.append('fopen')
            if 'ioctl' not in call_list:
                call_list.append('ioctl')
        if all_contexts:
            for context in self.context_manager[self.target].getContexts():
                self.syscallManager[cell_name].watchSyscall(context, call_list, call_params_list, name, linger=linger_in, background=background, flist=flist, 
                           callback=callback)
 
        else:
            context = self.context_manager[self.target].getContextName(cell)
            the_syscall = self.syscallManager[cell_name].watchSyscall(context, call_list, call_params_list, name, linger=linger_in, background=background, flist=flist, 
                   callback=callback)
        if the_syscall is not None:
            ''' find processes that are in the kernel on IO calls '''
            frames = self.getDbgFrames()
            for tid in list(frames):
                if frames[tid] is None:
                    self.lgr.error('frame for tid %s is none?' % tid)
                    continue
                call = self.task_utils[self.target].syscallName(frames[tid]['syscall_num'], self.is_compat32) 
                self.lgr.debug('runTo found %s in kernel for tid:%s' % (call, tid))
                #if call == 'socketcall': 
                #    if 'ss' in frames[tid]:
                #        ss = frames[tid]['ss']
                #        socket_callnum = frames[tid]['param1']
                #        call = net.callname[socket_callnum].lower()
                #        self.lgr.debug('runTo socketcall, set call to %s' % call)
                if call not in call_list:
                   self.lgr.debug('runTo socketcall call %s not in call_list %s' % (call, str(call_list)))
                   del frames[tid]
            self.lgr.debug('runTo, %d frames after all that' % len(frames))
            if len(frames) > 0:
                cpu = self.cell_config.cpuFromCell(self.target)
                eip = self.getEIP(cpu=cpu)
                self.lgr.debug('runTo, %d frames eip 0x%x' % (len(frames), eip))
                if not self.mem_utils[self.target].isKernel(eip) and self.bookmarks is not None:
                    first_cycle  = self.getFirstCycle() 
                    current_cycle = cpu.cycles
                    self.lgr.debug('runTo, not in kernel first_cycle: 0x%x current: 0x%x' % (first_cycle, current_cycle))
                    if self.reverseEnabled() and self.getFirstCycle() != cpu.cycles:
                        self.lgr.debug('runTo, not in kernel, rev enabled, have frames, try rev 2 before tracking syscalls')
                        prev_cycle = cpu.cycles - 2
                        self.skipToCycle(prev_cycle, cpu=cpu)
                self.lgr.debug('runTo, call to setExits')
                the_syscall.setExits(frames, context_override=self.context_manager[self.target].getRESimContext()) 


        self.lgr.debug('genMonitor runTo done setting, check if running')
        if run and not self.is_monitor_running.isRunning():
            self.lgr.debug('genMonitor runTo run set but is not running, do continue')
            self.is_monitor_running.setRunning(True)
            SIM_continue(0)
        self.lgr.debug('genMonitor runTo now return')
        return retval

    def runToClone(self, nth=1):
        self.lgr.debug('runToClone to %s' % str(nth))
        call_params = syscall.CallParams('runToClone', 'clone', None, break_simulation=True)        
        call_params.nth = nth
        self.runTo(['clone'], call_params, name='clone')

    def runToConnect(self, addr, proc=None, nth=None):
        #addr = '192.168.31.52:20480'
        self.lgr.debug('runToConnect to %s  proc: %s   nth: %s' % (addr, str(proc), str(nth)))
        try:
            test = re.search(addr, 'nothing', re.M|re.I)
        except:
            self.lgr.error('invalid pattern: %s' % addr)
            return
        ''' NOTE: socketCallName returns "socket" for x86 '''

        if self.isWindows(self.target):
            cname = 'CONNECT'
            call = ['CONNECT']
        else:
            cname = 'CONNECT'
            call = self.task_utils[self.target].socketCallName('connect', self.is_compat32)
        call_params = syscall.CallParams('runToConnect', cname, addr, break_simulation=True, proc=proc)        
        call_params.nth = nth
        self.runTo(call, call_params, name='connect')

    def runToDmod(self, dfile, cell_name=None, background=False, comm=None, break_simulation=False):
        if cell_name is None:
            cell_name = self.target
            run = True
        else:
            run = False
        self.dmod_mgr[cell_name].runToDmod(dfile, run=run, background=False, comm=None, break_simulation=False)


    def runToWrite(self, substring):
        call_params = syscall.CallParams('runToWrite', 'write', substring, break_simulation=True)        
        cell = self.cell_config.cell_context[self.target]
        if self.isWindows():
            call_list = ['WriteFile']
        else:
            call_list = ['write', 'writev']
        self.lgr.debug('runToWrite to %s' % substring)
        self.runTo(call_list, call_params, name='write')

    def runToOpen(self, substring, run=True):
        #if self.track_threads is not None and self.target in self.track_threads:
        #    self.track_threads[self.target].stopSOTrack()
        #else:
        #    ''' do not hook mmap calls to track SO maps '''
        #    self.sharedSyscall[self.target].trackSO(False)
        #print('warning, SO tracking has stopped')
        if self.isWindows():
            # TBD distinguish true creates from windows hacked overload of create file
            open_call_list = ['OpenFile', 'CreateFile']
        elif self.isVxDKM():
            open_call_list = ['fopen']
        else:
            open_call_list = ['open']
        call_params = syscall.CallParams('runToOpen', open_call_list[0], substring, break_simulation=True)
        self.lgr.debug('runToOpen to %s' % substring)
        self.runTo(open_call_list, call_params, name='open', run=run)

    def runToOpenKey(self, substring):
        if self.isWindows():
            open_call_list = ['OpenKey', 'OpenKeyEx']
        else:
            self.lgr.error('runToOpenKey not available on Linux')
            return
        call_params = syscall.CallParams('runToOpenKey', open_call_list[0], substring, break_simulation=True)
        self.lgr.debug('runToOpenKey to %s' % substring)
        self.runTo(open_call_list, call_params, name='open')

    def runToCreate(self, substring):
        if self.track_threads is not None and self.target in self.track_threads:
            self.track_threads[self.target].stopSOTrack()
        else:
            ''' do not hook mmap calls to track SO maps '''
            self.sharedSyscall[self.target].trackSO(False)
        print('warning, SO tracking has stopped')
        if self.isWindows():
            open_call_name = 'CreateFile'
        else:
            open_call_name = 'create'
        call_params = syscall.CallParams('runToCreate', open_call_name, substring, break_simulation=True)
        self.lgr.debug('runToCreate to %s' % substring)
        self.runTo([open_call_name], call_params, name='create')

    # TBD redo all these runTo's to not rely on subcalls
    def runToSend(self, substring):
        if not self.isWindows():
            call = self.task_utils[self.target].socketCallName('send', self.is_compat32)
        else:
            call = ['SEND']
        call_params = syscall.CallParams('runToSend', 'send', substring, break_simulation=True)        
        self.lgr.debug('runToSend to %s' % substring)
        self.runTo(call, call_params, name='send')

    def runToSendTo(self, substring):
        call = self.task_utils[self.target].socketCallName('sendto', self.is_compat32)
        call_params = syscall.CallParams('runToSend', 'send', substring, break_simulation=True)        
        self.lgr.debug('runToSend to %s' % substring)
        self.runTo(call, call_params, name='send')

    def runToSendPort(self, port):
        call = self.task_utils[self.target].socketCallName('sendto', self.is_compat32)
        call_params = syscall.CallParams('runtoSendPort', 'sendto', port, break_simulation=True)        
        call_params.param_flags.append(syscall.DEST_PORT)
        self.lgr.debug('runToSendPort to port %s' % port)
        self.runTo(call, call_params, name='sendport')

    def runToReceive(self, substring):
        if self.isWindows():
            call_params = syscall.CallParams('runToReceive', 'RECV', substring, break_simulation=True)        
            call = ['RECV']
        else:
            # socketCallName returns a list
            call = self.task_utils[self.target].socketCallName('recv', self.is_compat32)
            if 'socketcall' in call:
                call_params = syscall.CallParams('runToReceive', 'recv', substring, break_simulation=True)        
            else:
                call_params = syscall.CallParams('runToReceive', None, substring, break_simulation=True)        
        self.lgr.debug('runToReceive call %s substring %s' % (call, substring))
        self.runTo(call, call_params, name='recv')

    def runToReceiveMsg(self, substring):
        # socketCallName returns a list
        call = self.task_utils[self.target].socketCallName('recvmsg', self.is_compat32)
        if 'socketcall' in call:
            call_params = syscall.CallParams('runToReceiveMsg', 'recvmsg', substring, break_simulation=True)        
        else:
            call_params = syscall.CallParams('runToReceiveMsg', None, substring, break_simulation=True)        
        self.lgr.debug('runToReceive call %s substring %s' % (call, substring))
        self.runTo(call, call_params, name='recv')

    def runToRead(self, substring, ignore_running=False):
        call_params = syscall.CallParams('runToRead', 'read', substring, break_simulation=True)        
        self.lgr.debug('runToRead to %s' % str(substring))
        self.runTo(['read', 'clone', 'execve'], call_params, name='read', ignore_running=ignore_running)

    def runToAccept(self, fd, flist=None, proc=None, run=True, linger=False):
        if not self.isWindows():
            call = self.task_utils[self.target].socketCallName('accept', self.is_compat32)
        else:
            call = ['ACCEPT', '12083_ACCEPT', 'DuplicateObject']
        call_params = syscall.CallParams('runToAccept', 'accept', fd, break_simulation=True, proc=proc)        
           
        self.lgr.debug('runToAccept on FD: %d call is: %s linger %r' % (fd, str(call), linger))
        #if flist is None and not self.isWindows():
        #    linger = True
        #else:
        #    linger = False
        self.runTo(call, call_params, linger_in=linger, flist=flist, name='accept', run=run)
        
    def runToBind(self, addr, proc=None, run=True):
        #addr = '192.168.31.52:20480'
        if type(addr) is int:
            addr = '.*:%d$' % addr
        try:
            test = re.search(addr, 'nothing', re.M|re.I)
        except:
            self.lgr.error('invalid pattern: %s' % addr)
            return
        if self.isWindows(self.target):
            cname = 'BIND'
            call = ['BIND']
        else:
            cname = 'BIND'
            call = self.task_utils[self.target].socketCallName('bind', self.is_compat32)

        call_params = syscall.CallParams('runToBind', cname, addr, break_simulation=True, proc=proc)        
        self.lgr.debug('runToBind to %s ' % (addr))
        self.runTo(call, call_params, name='bind', run=run)

    def runToIO(self, fd, linger=False, break_simulation=True, count=1, flist_in=None, origin_reset=False, 
                run_fun=None, proc=None, run=True, kbuf=False, call_list=None, sub_match=None, target=None, just_input=False):
        if target is None:
            target = self.target
        if self.isWindows(target):
            if kbuf:
                kbuffer = self.kbuffer[target]
            else:
                kbuffer = None
            self.winMonitor[target].runToIO(fd, linger, break_simulation, count, flist_in, origin_reset, 
                   run_fun, proc, run, kbuffer, call_list, sub_match=sub_match, just_input=just_input)
            return
        elif self.isVxDKM(target=target):
            if kbuf:
                kbuffer = self.kbuffer[target]
            else:
                kbuffer = None
            self.vxKMonitor[target].runToIO(fd, linger, break_simulation, count, flist_in, origin_reset, 
                   run_fun, proc, run, kbuffer, call_list, sub_match=sub_match, just_input=just_input)
            return
        
        ''' Run to any IO syscall.  Used for trackIO.  Also see runToInput for use with prepInject '''
        #call_params = syscall.CallParams('runToIO', None, fd, break_simulation=break_simulation, proc=proc)        
        call_params = syscall.CallParams('runToIO', None, fd, break_simulation=break_simulation, proc=proc)        
        ''' nth occurance of syscalls that match params '''
        call_params.nth = count
       
        if 'runToIO' in self.call_traces[target]:
            self.lgr.debug('runToIO already in call_traces, add param')
            self.call_traces[target]['runToIO'].addCallParams([call_params])
        else:
            cell = self.cell_config.cell_context[target]
            self.lgr.debug('runToIO on FD %s just_input %r' % (str(fd), just_input))
            tid, cpu = self.context_manager[target].getDebugTid() 
            if tid is None:
                cpu, comm, tid = self.task_utils[target].curThread() 
    
            if not just_input:
                # add open to catch Dmods for open_replace
                calls = ['open', 'read', 'write', '_llseek', 'socketcall', 'close', 'ioctl', 'select', 'pselect6', '_newselect']
                accept_call = self.task_utils[target].socketCallName('accept', self.is_compat32)
                for c in accept_call:
                    calls.append(c)
                # note hack for identifying old arm kernel
                if (cpu.architecture == 'arm' and not self.param[target].arm_svc) or self.mem_utils[target].WORD_SIZE == 8:
                    calls.remove('socketcall')
                    for scall in net.callname[1:]:
                        #self.lgr.debug('runToIO adding call <%s>' % scall.lower())
                        calls.append(scall.lower())
                if self.mem_utils[target].WORD_SIZE == 8:
                    self.lgr.debug('runToIO not just input remove calls not in 64 bit apps')
                    #calls.remove('recv')
                    calls.remove('_llseek')
                    calls.remove('_newselect')
                    calls.remove('select')
                    calls.append('lseek')
                    calls.remove('send')
                    calls.remove('recv')
 
                    for c in accept_call:
                        if c in calls:
                            calls.remove(c)
            else:
                # TBD fix all this to reflect machine size of target binary
                self.lgr.debug('runToIO just input') 
                if (cpu.architecture == 'arm' and not self.param[target].arm_svc):
                    calls = ['read', 'close', 'ioctl', 'select', 'pselect6', '_newselect', 'poll']
                    for call in net.readcalls:
                        calls.append(call.lower())
                elif self.mem_utils[target].WORD_SIZE == 8:
                    self.lgr.debug('runToIO just input wordisize 8') 
                    calls = ['read', 'close', 'ioctl', 'pselect6', 'ppoll']
                    for call in net.readcalls:
                        calls.append(call.lower())
                    calls.remove('recv')
                else: 
                    calls = ['read', 'close', 'socketcall', 'ioctl', 'select', 'pselect6', '_newselect']
                accept_call = self.task_utils[target].socketCallName('accept', self.is_compat32)
                for c in accept_call:
                    calls.append(c)

            calls.append('clone')
            calls.append('execve')
            if self.mem_utils[target].WORD_SIZE == 8:
                calls.append('dup3')
            else:
                calls.append('dup2')
            skip_and_mail = True
            if flist_in is not None:
                ''' Given callback functions, use those instead of skip_and_mail '''
                skip_and_mail = False
            self.lgr.debug('runToIO, add new syscall')
            kbuffer_mod = None
            if kbuf:
                kbuffer_mod = self.kbuffer[target] 
                self.sharedSyscall[target].setKbuffer(kbuffer_mod)
            the_syscall = self.syscallManager[target].watchSyscall(None, calls, [call_params], 'runToIO', linger=linger, flist=flist_in, 
                             skip_and_mail=skip_and_mail, kbuffer=kbuffer_mod)
            ''' find processes that are in the kernel on IO calls '''
            frames = self.getDbgFrames()
            skip_calls = ['select', 'pselect6', '_newselect']
            for tid in list(frames):
                if frames[tid] is None:
                    self.lgr.error('frames[%s] is None' % tid)
                    continue
                call = self.task_utils[target].syscallName(frames[tid]['syscall_num'], self.is_compat32) 
                self.lgr.debug('runToIO found %s in kernel for tid:%s' % (call, tid))
                if call not in calls or call in skip_calls:
                   del frames[tid]
                else:
                   self.lgr.debug('kept frames for tid:%s' % tid)
            if len(frames) > 0:
                self.lgr.debug('runToIO, call to setExits')
                the_syscall.setExits(frames, origin_reset=origin_reset, context_override=self.context_manager[target].getRESimContext()) 
            #self.copyCallParams(the_syscall)
    
    
            if run_fun is not None:
                SIM_run_alone(run_fun, None) 
            if run:
                self.lgr.debug('runToIO now run, context is %s' % str(cpu.current_context))
                self.continueForward()
                #SIM_continue(0)

    def runToInput(self, fd, linger=False, break_simulation=True, count=1, flist_in=None, ignore_waiting=False, sub_match=None):
        ''' Track syscalls that consume inputs.  Intended for use by prepInject functions '''
        ''' Also see runToIO for more general tracking '''
        input_calls = ['read', 'recv', 'recvfrom', 'recvmsg', 'select']
        call_param_list = []
        for call in input_calls:
            call_param = syscall.CallParams('runToInput', call, fd, break_simulation=break_simulation)        
            call_param.nth = count
            call_param.sub_match = sub_match
            call_param_list.append(call_param)

        cpu, comm, cur_tid = self.task_utils[self.target].curThread() 
        self.lgr.debug('runToInput on FD %d cycle: 0x%x count: %d sub_match: %s' % (fd, cpu.cycles, count, sub_match))
        calls = ['read', 'socketcall', 'select', '_newselect', 'pselect6']
        if (cpu.architecture == 'arm' and not self.param[self.target].arm_svc) or self.mem_utils[self.target].WORD_SIZE == 8:
            calls.remove('socketcall')
            for scall in net.readcalls:
                calls.append(scall.lower())
        if self.mem_utils[self.target].WORD_SIZE == 8:
            calls.remove('recv')
            calls.remove('_newselect')
            calls.remove('select')
        skip_and_mail = True
        if flist_in is not None:
            ''' Given callback functions, use those instead of skip_and_mail '''
            skip_and_mail = False

        # TBD Name of call syscall is checked elsewhere for runToIO ?
        the_syscall = self.syscallManager[self.target].watchSyscall(None, calls, call_param_list, 'runToIO', linger=linger, flist=flist_in, 
                                 skip_and_mail=skip_and_mail)
        for call in calls:
            self.call_traces[self.target][call] = the_syscall
        self.call_traces[self.target]['runToIO'] = the_syscall
        if not ignore_waiting:
            ''' find processes that are in the kernel on IO calls '''
            frames = self.getDbgFrames()
            self.lgr.debug('runToInput found %d frames in kernel' % len(frames))
            for tid in list(frames):
                if frames[tid] is None:
                    self.lgr.error('frame for tid %s is none?' % tid)
                    continue
                call = self.task_utils[self.target].syscallName(frames[tid]['syscall_num'], self.is_compat32) 
                self.lgr.debug('runToInput found %s in kernel for tid:%s ' % (call, tid))
                if call not in calls:
                    del frames[tid]
                   
            if len(frames) > 0:
                eip = self.getEIP(cpu=cpu)
                self.lgr.debug('runToInput, %d frames eip 0x%x' % (len(frames), eip))
                if not self.mem_utils[self.target].isKernel(eip):
                    first_cycle  = self.getFirstCycle() 
                    current_cycle = cpu.cycles
                    self.lgr.debug('runToInput, not in kernel first_cycle: 0x%x current: 0x%x' % (first_cycle, current_cycle))
                    if self.reverseEnabled() and self.getFirstCycle() != cpu.cycles:
                        self.lgr.debug('runToInput, not in kernel, rev enabled, have frames, try rev 2 before tracking syscalls')
                        prev_cycle = cpu.cycles - 2
                        self.skipToCycle(prev_cycle, cpu=cpu)
                    
                self.lgr.debug('runToInput, call to setExits')
                the_syscall.setExits(frames, context_override=self.context_manager[self.target].getRESimContext()) 
            elif cpu in self.snap_start_cycle and self.snap_start_cycle[cpu] == cpu.cycles:
                self.lgr.warning('runToInput, NO FRAMES found for threads waiting in the kernel.  May miss returns, e.g., from select or read.')
                print('WARNING: runToInput found NO FRAMES for threads waiting in the kernel.  May miss returns, e.g., from select or read.')
        
        self.continueForward()
        #SIM_continue(0)

    def getCurrentSO(self):
        cpu, comm, tid = self.task_utils[self.target].curThread() 
        eip = self.getEIP(cpu)
        retval = self.getSO(eip)
        return retval

    def origProgAddr(self, eip):
        return self.getSO(eip, show_orig=True)

    def getLoadSize(self, fname):
        start, size = self.soMap[self.target].getLoadAddrSize(fname)
        self.lgr.debug('getLoadSize for %s got 0x%x, 0x%x' % (fname, start, size))
        return start, size

    def getSO(self, eip, show_orig=False, target_cpu=None, just_name=False):
        retval = None
        if target_cpu is None:
            target = self.target
        else:
            target = self.cell_config.cellFromCPU(target_cpu)
        fname, start, end = self.soMap[target].getSOInfo(eip)
        if fname is None:
            self.lgr.debug('getSO no library found for 0x%x' % eip)
        else:
            if show_orig:
                cpu, comm, tid = self.task_utils[target].curThread() 
                image_base = self.soMap[target].getImageBase(fname)
                delta = eip - start
                orig = image_base+delta  
                self.lgr.debug('getSO eip 0x%x start 0x%x image_base 0x%x' % (eip, start, image_base))
                orig_str = ' orig address: 0x%x' % orig
                retval = ('%s:0x%x-0x%x %s' % (fname, start, end, orig_str))
            elif just_name:
                retval = ('%s' % (fname))
            else:
                retval = ('%s:0x%x-0x%x' % (fname, start, end))

        return retval
     
    def showSOMap(self, tid=None, filter=None, save=False):
        self.lgr.debug('showSOMap')
        self.soMap[self.target].showSO(tid, filter=filter, save=save)

    def listSOMap(self, filter=None):
        self.lgr.debug('listSOMap for cell %s' % self.target)
        self.soMap[self.target].listSO(filter=filter)

    def getSOMap(self, quiet=False):
        return self.soMap[self.target].getSO(quiet=quiet)

    def getSOFile(self, addr):
        fname = self.soMap[self.target].getSOFile(addr)
        return fname


    def traceExternal(self):
        call_list = ['vfork','fork', 'clone','execve','socketcall']
        call_params = {}
        call_params['socketcall'] = []
        cp = syscall.CallParams('traceExternal', 'connect', None)
        cp.param_flags.append(syscall.EXTERNAL)
        call_params['socketcall'].append(cp)

        calls = ' '.join(s for s in call_list)
        print('tracing these system calls: %s' % calls)
        cpu, comm, tid = self.task_utils[self.target].curThread() 
        self.traceMgr[self.target].open('logs/syscall_trace.txt', cpu)
        for call in call_list: 
            this_call_params = []
            if call in call_params:
                this_call_params = call_params[call]
            self.call_traces[self.target][call] = self.traceSyscall(callname=call, call_params=this_call_params, trace_procs=True)

    def traceListen(self):
        ''' generate a syscall trace of processes that bind to an IP address/port '''
        call_list = ['vfork','fork', 'clone','execve','socketcall']
        call_params = {}
        call_params['socketcall'] = []
        cp = syscall.CallParams('traceListen', 'bind', None)
        cp.param_flags.append(syscall.AF_INET)
        call_params['socketcall'].append(cp)

        calls = ' '.join(s for s in call_list)
        print('tracing these system calls: %s' % calls)
        cpu, comm, tid = self.task_utils[self.target].curThread() 
        self.traceMgr[self.target].open('logs/syscall_trace.txt', cpu)
        for call in call_list: 
            this_call_params = []
            if call in call_params:
                this_call_params = call_params[call]
            self.call_traces[self.target][call] = self.traceSyscall(callname=call, call_params=this_call_params, trace_procs=True)

    def showBinders(self):
            self.binders.showAll('logs/binder.txt')
            self.binders.dumpJson('logs/binder.json')

    def showConnectors(self):
            self.connectors.showAll('logs/connector.txt')
            self.connectors.dumpJson('logs/connector.json')

    def saveTraces(self):
        self.showBinders()
        self.showConnectors()
        self.showProcTrace()
        self.showNets()
        print('Traces saved in ./logs.  Move them to artifact repo and run postScripts')

    def stackTrace(self, verbose=False, in_tid=None, use_cache=True, stop_after_clib=False):
        self.stackFrameManager[self.target].stackTrace(verbose=verbose, in_tid=in_tid, use_cache=use_cache, stop_after_clib=stop_after_clib)

    def getStackTraceQuiet(self, max_frames=None, max_bytes=None, skip_recurse=False, stop_after_clib=False):
        return self.stackFrameManager[self.target].getStackTraceQuiet(max_frames=max_frames, max_bytes=max_bytes, skip_recurse=skip_recurse, stop_after_clib=stop_after_clib)

    def getStackTrace(self):
        return self.stackFrameManager[self.target].getStackTrace()

    def recordStackBase(self, tid, sp):
        self.stackFrameManager[self.target].recordStackBase(tid, sp)

    def recordStackClone(self, tid, parent):
        self.stackFrameManager[self.target].recordStackClone(tid, parent)
 
    def resetOrigin(self, cpu=None):
        self.lgr.debug('resetOrigin')
        ''' could be called with tid as the parameter. '''
        if cpu is None or type(cpu) is str:
            tid, cpu = self.context_manager[self.target].getDebugTid() 
            self.lgr.debug('resetOrigin from context_manager cpu %s' % str(cpu))
        self.reverse_mgr[self.target].disableReverse()
        self.lgr.debug('reset Origin rev ex disabled')
        self.reverse_mgr[self.target].enableReverse(two_step=True)
        self.lgr.debug('reset Origin rev ex enabled')
        self.rev_execution_enabled = True
        if self.bookmarks is not None:
            self.bookmarks.setOrigin(cpu, self.context_manager[self.target].getIdaMessage())
        else:
            self.lgr.debug('genMonitor resetOrigin without bookmarks, assume you will use bookmark0')

    def clearBookmarks(self, reuse_msg=False):
        if self.reverseEnabled():
            tid, cpu = self.context_manager[self.target].getDebugTid() 
            self.lgr.debug('genMonitor clearBookmarks')
            if tid is None:
                #print('** Not debugging?? **')
                self.lgr.debug('clearBookmarks, Not debugging?? **')
                return False
       
            self.bookmarks.clearMarks()
            SIM_run_alone(self.resetOrigin, cpu)
            #self.resetOrigin(cpu)
            self.dataWatch[self.target].resetOrigin(cpu.cycles, reuse_msg=reuse_msg, record_old=True)
            cpu, comm, tid = self.task_utils[self.target].curThread() 
            #self.stopTrackIO()
            self.lgr.debug('genMonitor clearBookmarks call clearWatches')
        else:
            self.lgr.debug('genMonitor clearBookmarks reverse not enabled')
            pass
        return True

    def writeRegValue(self, reg, value, alone=False, reuse_msg=False, target_cpu=None):
        if self.no_reset:
            SIM_break_simulation('no reset')
            print('Would reset origin, bail')
            return
        if target_cpu is None:
            target = self.target
            target_cpu = self.cell_config.cpuFromCell(self.target)
        else:
            target = self.cell_config.cellFromCPU(target_cpu)
        self.mem_utils[target].setRegValue(target_cpu, reg, value)
        #self.lgr.debug('writeRegValue %s, %x ' % (reg, value))
        if alone:
            SIM_run_alone(self.clearBookmarks, reuse_msg) 
        else:
            self.clearBookmarks(reuse_msg=reuse_msg)

    def writeWord(self, address, value, target_cpu=None, word_size=None):
        if self.no_reset:
            SIM_break_simulation('no reset')
            print('Would reset origin, bail')
            return
        ''' NOTE: wipes out bookmarks! '''
        if target_cpu is None:
            target = self.target
            target_cpu = self.cell_config.cpuFromCell(self.target)
        else:
            target = self.cell_config.cellFromCPU(target_cpu)
        if target_cpu is None:
            self.lgr.error('writeWord, cpu is None')
            return
        if word_size is None:
            word_size = self.mem_utils[target].wordSize(target_cpu)
        if word_size == 4:
            self.mem_utils[target].writeWord32(target_cpu, address, value)
        else:
            self.mem_utils[target].writeWord(target_cpu, address, value)
        self.lgr.debug('writeWord(0x%x, 0x%x), disable reverse execution to clear bookmarks, then set origin' % (address, value))
        self.clearBookmarks()

    def writeByte(self, address, value, target_cpu=None):
        if self.no_reset:
            SIM_break_simulation('no reset')
            print('Would reset origin, bail')
            return
        ''' NOTE: wipes out bookmarks! '''
        if target_cpu is None:
            target = self.target
        else:
            target = self.cell_config.cellFromCPU(target_cpu)
        cpu, comm, tid = self.task_utils[target].curThread() 
        self.mem_utils[target].writeByte(cpu, address, value)
        #phys_block = cpu.iface.processor_info.logical_to_physical(address, Sim_Access_Read)
        #SIM_write_phys_memory(cpu, phys_block.address, value, 4)
        self.lgr.debug('writeByte(0x%x, 0x%x), disable reverse execution to clear bookmarks, then set origin' % (address, value))
        self.clearBookmarks()

    def writeString(self, address, string, target_cpu=None):
        if self.no_reset:
            SIM_break_simulation('no reset')
            print('Would reset origin, bail')
            return
        if target_cpu is None:
            target = self.target
        else:
            target = self.cell_config.cellFromCPU(target_cpu)
        if target in self.task_utils:
            ''' NOTE: wipes out bookmarks! '''
            cpu, comm, tid = self.task_utils[target].curThread() 
            self.lgr.debug('writeString 0x%x %s' % (address, string))
            self.mem_utils[target].writeString(cpu, address, string)
            self.lgr.debug('writeString, disable reverse execution to clear bookmarks, then set origin')
            self.clearBookmarks()

    def writeBytes(self, cpu, address, bstring, target_cpu=None):
        if self.no_reset:
            SIM_break_simulation('no reset')
            print('Would reset origin, bail')
            return
        if target_cpu is None:
            target = self.target
        else:
            target = self.cell_config.cellFromCPU(target_cpu)
        if target in self.task_utils:
            ''' NOTE: wipes out bookmarks! '''
            cpu, comm, tid = self.task_utils[target].curThread() 
            self.mem_utils[target].writeBytes(cpu, address, bstring)
            self.lgr.debug('writeBytes, disable reverse execution to clear bookmarks, then set origin')
            self.clearBookmarks()

    def stopDataWatch(self, immediate=False, leave_backstop=False):
        self.lgr.debug('genMonitor stopDataWatch immediate %r leave_backstop %r' % (immediate, leave_backstop))
        self.dataWatch[self.target].stopWatch(break_simulation=True, immediate=immediate, leave_backstop=leave_backstop)

    def showDataWatch(self):
        self.dataWatch[self.target].showWatch()

    def addDataWatch(self, start, length):
        self.lgr.debug('genMonitory watchData 0x%x count %d' % (start, length))
        msg = "User range 0x%x count %d" % (start, length)
        cpu = self.cell_config.cpuFromCell(self.target)
        self.dataWatch[self.target].enable()
        self.dataWatch[self.target].resetOrigin(cpu.cycles)
        self.dataWatch[self.target].setRange(start, length, msg) 
        self.dataWatch[self.target].setBreakRange()
        self.dataWatch[self.target].watch(break_simulation=False)
        self.dataWatch[self.target].setCallback(self.resetTrackIOBackstop)

    def watchData(self, start=None, length=None, show_cmp=False):
        self.lgr.debug('genMonitor watchData')
        if start is not None:
            self.lgr.debug('genMonitory watchData 0x%x count %d' % (start, length))
            msg = "User range 0x%x count %d" % (start, length)
            self.dataWatch[self.target].setRange(start, length, msg) 
        self.is_monitor_running.setRunning(True)
        if self.dataWatch[self.target].watch(show_cmp):
            self.continueForward()
            #SIM_continue(0)
        else: 
            print('no data being watched')
            self.lgr.debug('genMonitor watchData no data being watched')
            self.is_monitor_running.setRunning(False)

    def isProtectedMemory(self, addr):
        ''' compat with CGC version '''
        return False 

    def showHaps(self, filter=None):
        for cell_name in self.context_manager:
            print('Cell: %s' % cell_name)
            self.context_manager[cell_name].showHaps(filter=filter)

    def addMazeExit(self):
        ''' Intended for use if it seems a maze exit is nested -- will cause the most recent breakout
            address to be ignored when setting maze exit breakpoints '''
        if len(self.exit_maze) > 0:
            eip = self.exit_maze[-1].getBreakout()
            if eip is not None:
                self.lgr.debug('addMazeExit adding 0x%x to exits' % eip)
                if self.exit_maze[-1] not in self.maze_exits:
                    self.maze_exists[self.exit_maze[-1]] = []
                self.maze_exits[self.exit_maze[-1]].append(eip)

    def getMaze(self):
        maze = self.exit_maze[-1].getMaze()
        
        jmaze = json.dumps(maze)
        print(jmaze)

    def getMazeExits(self):
        if len(self.exit_maze) > 0:
            if self.exit_maze[-1] in self.maze_exits:
                return self.maze_exits[self.exit_maze[-1]]
        return []

    def doMazeReturn(self):
        if len(self.exit_maze) > 0:
            self.exit_maze[-1].mazeReturn()

    def checkMazeReturn(self):
        for me in self.exit_maze:
            if me.checkJustReturn():
                return me
        return None

    def autoMaze(self):
        self.auto_maze = not self.auto_maze
        self.lgr.debug('auto_maze now %r, run again to toggle.' % self.auto_maze)
        print('auto_maze now %r, run again to toggle.' % self.auto_maze)

    def getAutoMaze(self):
        return self.auto_maze

    def exitMaze(self, syscallname, debugging=False):
        self.lgr.debug('exitMaze call %s' % syscallname)
        cpu, comm, tid = self.task_utils[self.target].curThread() 
        cpl = memUtils.getCPL(cpu)
        if cpl == 0:
            print('Must first run to user space.')
            return
        self.is_monitor_running.setRunning(True)
        name = 'exitMaze_%s' % syscallname
        tod_track = self.syscallManager[self.target].watchSyscall(None, [syscallname], [], name)
        #tod_track = None
        #if self.target in self.trace_all:
        #    self.lgr.debug('exitMaze, trace_all is %s' % str(self.trace_all[self.target]))
        #    tod_track = self.trace_all[self.target]
        #    self.lgr.debug('genMonitor exitMaze, using traceAll syscall')
        #if tod_track is None: 
        #    if syscallname in self.call_traces:
        #        self.lgr.debug('genMonitor exitMaze tid:%s, using syscall defined for %s' % (tid, syscallname))
        #        tod_track = self.call_traces[self.target][syscallname]
        #    else:
        #        self.lgr.debug('genMonitor exitMaze tid:%s, using new syscall for %s' % (tid, syscallname))
        #        tod_track = syscall.Syscall(self, self.target, None, self.param[self.target], self.mem_utils[self.target], self.task_utils[self.target], 
        #                   self.context_manager[self.target], None, self.sharedSyscall[self.target], self.lgr,self.traceMgr, 
        #                   call_list=[syscallname])
        one_proc = False
        dbgtid, dumb1 = self.context_manager[self.target].getDebugTid() 
        if dbgtid is not None:
            one_proc = True
        em = exitMaze.ExitMaze(self, cpu, tid, tod_track, self.context_manager[self.target], self.task_utils[self.target], self.mem_utils[self.target], debugging, one_proc, self.lgr)
        self.exit_maze.append(em)
        em.run()
        #self.exit_maze.showInstructs()

    def plantBreaks(self):
        if len(self.exit_maze) > 0:
            self.exit_maze[-1].plantBreaks() 
        print('Maze exit breaks planted')

    def plantCmpBreaks(self):
        if len(self.exit_maze) > 0:
            self.exit_maze[-1].plantCmpBreaks() 
            print('Maze pruning breaks planted')

    def showMazeStatus(self):
        print('maze status')
        for m in self.exit_maze:
            tid, planted, broke = m.getStatus()
            print('%s planted: %d  broke: %d' % (tid, planted, broke))
        no_watch_list = self.context_manager[self.target].getNoWatchList()
        cpu = self.cell_config.cpuFromCell(self.target)
        print('No watch list:')
        for rec in no_watch_list:
            tid = self.mem_utils[self.target].readWord32(cpu, rec + self.param[self.target].ts_pid)
            print('  %s' % tid)
        

    def showParams(self):
        self.param.printParams()

    #def inProcList(self, tid):
    #    if tid in self.proc_list[self.target]:
    #        return True
    #    else:
    #        return False

    #def myTasks(self):
    #    print('Current proc_list for %s' % self.target)
    #    for tid in self.proc_list[self.target]:
    #        print('%d %s' % (tid, self.proc_list[self.target][tid]))


    def showDmods(self):
        for target in self.context_manager:
            self.syscallManager[target].showDmods()

    def rmAllDmods(self):
        for target in self.context_manager:
            self.syscallManager[target].rmAllDmods()
            self.dmod_mgr[target].rmAllDmods()

    def rmDmod(self, cell_name, path):
        self.dmod_mgr[cell_name].rmDmod(path)

    def writeConfig(self, name):
        if '-' in name:
            print('Avoid use of - in snapshot names.')
            return
        cmd = 'write-configuration %s' % name 
        SIM_run_command(cmd)
        self.lgr.debug('writeConfig %s' % cmd)
        for cell_name in self.cell_config.cell_context:
            if cell_name in self.netInfo:
                ''' netInfo stands in for all cell_name-based dictionaries ''' 
                net_file = os.path.join('./', name, cell_name, 'net_list.pickle')
                try:
                    os.mkdir(os.path.dirname(net_file))
                except OSError as exc:
                    if exc.errno != errno.EEXIST:
                        raise
                    pass
                self.netInfo[cell_name].pickleit(net_file)
                self.task_utils[cell_name].pickleit(name)
                self.soMap[cell_name].pickleit(name)
                self.traceProcs[cell_name].pickleit(name)
                self.record_entry[cell_name].pickleit(name, cell_name)
                self.dataWatch[cell_name].pickleit(name)
                self.stackFrameManager[cell_name].pickleit(name)
                if self.run_from_snap is not None:
                    old_afl_file = os.path.join('./', self.run_from_snap, cell_name, 'afl.pickle')
                    if os.path.isfile(old_afl_file):
                        new_afl_file = os.path.join('./', name, cell_name, 'afl.pickle')
                        shutil.copyfile(old_afl_file, new_afl_file)
                p_file = os.path.join('./', name, cell_name, 'sharedSyscall.pickle')
                exit_info_list = self.sharedSyscall[cell_name].getExitList('traceAll')
                self.lgr.debug('writeConfig saved %d exit_info records' % len(exit_info_list))
                pickle.dump(exit_info_list, open(p_file, 'wb'))

                param_file = os.path.join('./', name, cell_name, 'param.pickle')
                pickle.dump(self.param[cell_name], open(param_file, 'wb'))
                if cell_name in self.read_replace:
                    self.read_replace[cell_name].pickleit(name)
                self.dmod_mgr[cell_name].pickleit(name)
                
        net_link_file = os.path.join('./', name, 'net_link.pickle')
        pickle.dump( self.link_dict, open( net_link_file, "wb" ) )

        version_file = os.path.join('./', name, 'version.pickle')
        pickle.dump( self.resim_version, open(version_file, "wb" ) )
      
        if self.target in self.stackFrameManager: 
            self.stackFrameManager[self.target].pickleit(name) 

        debug_info_file = os.path.join('./', name, 'debug_info.pickle')
        debug_info = {}
        debug_tid, debug_cpu = self.context_manager[self.target].getDebugTid()
        self.lgr.debug('writeConfig got from contextManager debug_tid %s cpu %s' % (debug_tid, debug_cpu.name))
        if debug_tid is not None:
            debug_info['tid'] = debug_tid
            debug_info['cpu'] = debug_cpu.name
            self.lgr.debug('writeConfig debug_tid:%s cpu %s' % (debug_tid, debug_cpu.name))
        elif self.debug_info is not None:
            debug_info = self.debug_info
        else:
            self.lgr.debug('writeConfig no debug_tid found from context manager')
        pickle.dump( debug_info, open(debug_info_file, "wb" ) )

        if self.connectors is not None:
            connector_file = os.path.join('./', name, 'connector.json')
            self.connectors.dumpJson(connector_file)
        if self.binders is not None:
            binder_file = os.path.join('./', name, 'binder.json')
            self.binders.dumpJson(binder_file)

        if os.path.isfile('.driver_server_version'):
            with open('.driver_server_version') as fh:
                dsv = fh.read()
                version_file = os.path.join('./', name, 'driver_version.pickle')
                pickle.dump(dsv, open(version_file, "wb" ) )

        self.lgr.debug('writeConfig done to %s' % name)

    def showCycle(self, target=None):
        if target is None:
            target = self.target
        cpu = self.cell_config.cpuFromCell(target)
        if self.bookmarks is None:
            print ('cpu cycles for cell %s 0x%x' % (target, cpu.cycles))
        else:
            cycles = self.bookmarks.getCurrentCycle(cpu)
            if cycles is not None:
                print ('cpu cycles on cell %s since _start: 0x%x absolute cycle: 0x%x' % (target, cycles, cpu.cycles))
            else:
                print ('cpu cycles on cell %s 0x%x -- bookmarks return nothing.' % (target, cpu.cycles))
        
    def continueForward(self, dumb=None):
        if not self.isRunning():
            self.lgr.debug('continueForward')
            self.is_monitor_running.setRunning(True)
            SIM_continue(0)
        else:
            self.lgr.debug('continueForward, already running')

    def showNets(self):
        net_commands = self.netInfo[self.target].getCommands()
        if len(net_commands) > 0:
           print('Network definition commands:')
        else:
           print('No exec of ip addr or ifconfig found')
        for c in net_commands:
            print(c)
        with open('logs/networks.txt', 'w') as fh:
            for c in net_commands:
                fh.write(c+'\n')   

    def isRunning(self):
        status = self.is_monitor_running.isRunning()
        return status

    def notRunning(self, quiet=False):
        status = self.is_monitor_running.isRunning()
        if status:   
            if not quiet:
                print('Was running, set to not running')
            self.is_monitor_running.setRunning(False)

    def getMemoryValue(self, addr):
        tid, cpu = self.context_manager[self.target].getDebugTid() 
        value = self.mem_utils[self.target].readWord32(cpu, addr)
        print('0x%x' % value)

    def printRegJson(self):
        ''' TBD For now, we need self.target to match the gdb client's expectations.
            So leverage the fact that client calls this often, and switch target if needed.'''
        if self.debugger_target is not None and self.target != self.debugger_target:
            self.setTarget(self.debugger_target)
        tid, cpu = self.context_manager[self.target].getDebugTid() 
        word_size = self.mem_utils[self.target].wordSize(cpu)
        prog_machine_size = self.soMap[self.target].getMachineSize(tid)
        #self.lgr.debug('printRegJson prog_machine_size %s' % prog_machine_size)
        if prog_machine_size is not None:
            if prog_machine_size == 64:
                word_size = 8
            else:
                word_size = 4
           
        self.mem_utils[self.target].printRegJson(cpu, word_size=word_size)

    def flushTrace(self):
        if self.target in self.traceMgr:
            self.traceMgr[self.target].flush()
        if self.target in self.winMonitor:
            self.winMonitor[self.target].flushTrace()

    def getCurrentThreadLeaderTid(self):
        tid = self.task_utils[self.target].getCurrentThreadLeaderTid()
        print(tid)        

    def getGroupTids(self, in_tid, quiet=False):
        leader_tid = self.task_utils[self.target].getGroupLeaderTid(in_tid)
        plist = self.task_utils[self.target].getGroupTids(leader_tid)
        if plist is None:
            print('Could not find leader %s' % leader_tid)
            return
        if not quiet:
            for tid in plist:
                print(tid)
        
    def reportMode(self):
        self.rmDebugWarnHap()
        tid, cpu = self.context_manager[self.target].getDebugTid() 
        if tid is None:
            cpu, comm, tid = self.task_utils[self.target].curThread() 
        
        self.lgr.debug('reportMode for tid:%s' % tid)
        self.mode_hap = RES_hap_add_callback_obj("Core_Mode_Change", cpu, 0, self.modeChangeReport, tid)
        self.stop_hap = self.RES_add_stop_callback(self.stopModeChanged, None)

    def setTarget(self, target):
        if target not in self.cell_config.cell_context:
            print('Unknown target: %s' % target)
            self.lgr.error('Unknown target: %s' % target)
            return
        self.target = target  
        print('Target is now: %s' % target)
        self.lgr.debug('setTarget, target is now: %s' % target)

    def showTargets(self):
        print('Targets:')
        for target in self.context_manager:
            if target == self.target:
                print('\t'+target+' --current')
            else:
                print('\t'+target)

    def reverseEnabled(self):
        # TBD Simics VT_revexec_active is broken.  Often gives the wrong answer
        #return True
        if self.disable_reverse: 
            #self.lgr.debug('reverseEnabled disable_reverse is True')
            return False
        else:
            #self.lgr.debug('reverseEnabled disable_reverse is False, call reverse mgr')
            if not self.reverse_mgr[self.target].nativeReverse():
                return self.reverse_mgr[self.target].reverseEnabled()
            else:
                return VT_revexec_active()
        ''' 
        cmd = 'sim.status'
        #cmd = 'sim.info.status'
        dumb, ret = cli.quiet_run_command(cmd)
        rev = ret.find('Reverse Execution')
        after = ret[rev:]
        parts = after.split(':', 1)
        if parts[1].strip().startswith('Enabled'):
            return True
        else:
            self.context_manager[self.target].setIdaMessage('Reverse execution disabled')
            return False
        ''' 
       
    def v2p(self, addr, use_pid=None, force_cr3=None):
        cpu = self.cell_config.cpuFromCell(self.target)
        value = self.mem_utils[self.target].v2p(cpu, addr, use_pid=use_pid, force_cr3=force_cr3, do_log=True)
        if value is not None:
            print('0x%x' % value)
        else:
            print('got None doing v2p from 0x%x' % addr)

    def allWrite(self):
        self.sharedSyscall[self.target].startAllWrite() 
        call = 'write'
        self.call_traces[self.target][call] = self.traceSyscall(callname=call)

    def compat32(self):
        cpu = self.cell_config.cpuFromCell(self.target)
        if cpu.architecture.lower().startswith('x8'):
            mode = self.task_utils[self.target].getExecMode()
            if mode == 3:
                return True
        return False

    def readString(self, addr, size=256):
        cpu = self.cell_config.cpuFromCell(self.target)
        fname = self.mem_utils[self.target].readString(cpu, addr, size)
        print(fname) 

    def retrack(self, clear=True, callback=None, use_backstop=True, run=False):
        self.lgr.debug('retrack')
        if callback is None:
            callback = self.stopTrackIO
        ''' Use existing data watches to track IO.  Clears later watch marks '''
        cpu = self.cell_config.cpuFromCell(self.target)
        eip = self.getEIP(cpu)
        self.lgr.debug('retrack cycle: 0x%x eip: 0x%x callback %s context: %s' % (cpu.cycles, eip, str(callback), cpu.current_context))
        if clear:
            cpu = self.cell_config.cpuFromCell(self.target)
            origin = self.bookmarks.getFirstCycle()
            if origin == cpu.cycles:
                self.dataWatch[self.target].clearWatches(-1)
            else:
                prev_cycle = cpu.cycles - 1
                self.dataWatch[self.target].clearWatches(prev_cycle)
        self.dataWatch[self.target].watch(break_simulation=False)
        self.dataWatch[self.target].setCallback(callback)
        self.dataWatch[self.target].rmBackStop()
        self.dataWatch[self.target].setRetrack(True, use_backstop)
        if self.coverage is not None:
            self.coverage.doCoverage()
        self.context_manager[self.target].watchTasks()
        if run:
            self.lgr.debug('retrack now continue')
            try:
                SIM_continue(0)
                pass
            except SimExc_General as e:
                print('ERROR... try continue?')
                self.lgr.error('ERROR in retrack  try continue? %s' % str(e))
                if 'already running' in str(e):
                    self.lgr.debug('thinks it is already running?')
                else:
                    SIM_continue(0)

    def trackRecv(self, fd, max_marks=None, kbuf=False, commence=None):
        call_list = ['RECV', 'RECV_DATAGRAM']
        if commence is not None:
            self.dataWatch[self.target].commenceWith(commence)
        self.trackIO(fd, call_list=call_list, max_marks=max_marks, kbuf=kbuf)

    def trackKbuf(self, fd):
        # hack used for testing
        self.trackIO(fd, kbuf=True, max_marks=10)

    def resetTrackIOBackstop(self):
        self.dataWatch[self.target].rmBackStop()
        print('Track IO has stopped at a backstop or max marks.  Use continue if you expect more data, or goToDataWatch to begin analysis at a watch mark.')

    def trackIO(self, fd, origin_reset=False, callback=None, run_fun=None, max_marks=None, count=1, 
                quiet=False, mark_logs=False, kbuf=False, call_list=None, run=True, commence=None, 
                offset=None, length=None, commence_offset=0, track_calls=False, backstop_cycles=None):
        if max_marks is None:
            max_marks = self.max_marks
        self.lgr.debug('trackIO fd: 0x%x max_marks %s count %d' % (fd, max_marks, count)) 
        if self.bookmarks is None:
            self.lgr.error('trackIO called but no debugging session exists.')
            return
        if not self.reverseEnabled() and not kbuf:
            print('Reverse execution must be enabled.')
            return
        if self.fun_mgr is None:
            print('No funManager loaded, debugging?')
            return

        debug_tid, dumb = self.context_manager[self.target].getDebugTid() 
        if debug_tid is None:
            self.lgr.error('trackIO called with no debug tid?')
            return
        comm = self.task_utils[self.target].getCommFromTid(debug_tid)
        if not self.fun_mgr.hasIDAFuns(comm=comm):
            print('No functions defined for comm %s, needs IDA or Ghidra analysis.' % comm)
            return

        clib_ok = self.soMap[self.target].checkClibAnalysis(debug_tid)
        if not clib_ok:
            print('*********** MISSING analysis for one or more clib-type libraries; tracking may fail')
           
        if commence is not None:
            self.dataWatch[self.target].commenceWith(commence, offset=commence_offset)
        if track_calls:
            self.dataWatch[self.target].markCallTrace()
        self.track_started = True
        self.stopTrackIOAlone(immediate=True, check_crash=False)
        cpu = self.cell_config.cpuFromCell(self.target)
        self.clearWatches(cycle=cpu.cycles)
        self.restoreDebugBreaks()
        if callback is None:
            done_callback = self.resetTrackIOBackstop
        elif callback == 'skipAndMail':
            # we want to do command callback.
            done_callback = self.stopAndMail
        else:
            done_callback = callback
        self.lgr.debug('trackIO stopped track and cleared watches current context %s' % str(cpu.current_context))
        if kbuf:
            self.kbuffer[self.target] = kbuffer.Kbuffer(self, cpu, self.context_manager[self.target], self.mem_utils[self.target], 
                self.dataWatch[self.target], self.lgr)
            self.lgr.debug('trackIO using kbuffer')

        self.dataWatch[self.target].trackIO(fd, done_callback, self.is_compat32, max_marks, quiet=quiet, offset=offset, length=length, backstop_cycles=backstop_cycles)
        self.lgr.debug('trackIO back from dataWatch, now run to IO')

        if self.coverage is not None:
            self.coverage.doCoverage()

        if mark_logs:
            self.traceFiles[self.target].markLogs(self.dataWatch[self.target])
            if self.target in self.trace_buffers:
                self.trace_buffers[self.target].markLogs(self.dataWatch[self.target])

        self.runToIO(fd, linger=True, break_simulation=False, origin_reset=origin_reset, run_fun=run_fun, count=count, kbuf=kbuf,
                     call_list=call_list, run=run, just_input=True)

   
    def stopTrackIO(self, immediate=False, check_crash=True):
        self.lgr.debug('stopTrackIO immediate %r' % immediate)
        if immediate:
            self.stopTrackIOAlone(immediate=immediate, check_crash=check_crash)
        else:
            SIM_run_alone(self.stopTrackIOAlone, immediate)

    def pendingFault(self, target=None):
        retval = False
        if target is None:
            target = self.target
        thread_tids = self.context_manager[target].getThreadTids()
        self.lgr.debug('pendingFault got %d thread_tids' % (len(thread_tids)))
        for tid in thread_tids:
            prec =  self.page_faults[target].getPendingFault(tid)
            if prec is not None:
                comm = self.task_utils[target].getCommFromTid(tid)
                if prec.page_fault:
                    print('Tid %s (%s) has pending page fault, may be crashing. Cycle %s' % (tid, comm, prec.cycles))
                    self.lgr.debug('pendingFault tid:%s (%s) has pending page fault, may be crashing.' % (tid, comm))
                    leader = self.task_utils[target].getGroupLeaderTid(tid)
                    self.page_faults[target].handleExit(tid, leader)
                    retval = True 
                else:
                    print('Tid %s (%s) has pending fault %s Cycle %s' % (tid, comm, prec.name, prec.cycles))
                    self.lgr.debug('pendingFault tid:%s (%s) has pending fault %s Cycle %s' % (tid, comm, prec.name, prec.cycles))
        return retval

    def stopTrackIOAlone(self, immediate=False, check_crash=True, target=None):
        if target is None:
            target = self.target
        crashing = False 
        if check_crash:
            crashing = self.pendingFault(target=target)               
        self.syscallManager[target].rmSyscall('runToIO', context=self.context_manager[target].getRESimContextName(), rm_all=crashing, immediate=immediate) 
        #if 'runToIO' in self.call_traces[self.target]:
        #    self.stopTrace(syscall = self.call_traces[self.target]['runToIO'])
        #    print('Tracking complete.')
        self.lgr.debug('stopTrackIO, call stopDataWatch...')

        #self.removeDebugBreaks(immediate=immediate)

        self.stopDataWatch(immediate=immediate)
        self.dataWatch[target].rmBackStop()
        self.dataWatch[target].setRetrack(False)
        self.dataWatch[target].removeExternalHaps(immediate=immediate)
        if self.coverage is not None:
            self.coverage.saveCoverage()
        if self.injectIOInstance is not None:
            SIM_run_alone(self.injectIOInstance.delCallHap, None)
        self.dataWatch[target].pickleFunEntries(self.run_from_snap)

        #self.jumperStop()
        self.lgr.debug('stopTrackIO return')

    def clearWatches(self, cycle=None):
        self.dataWatch[self.target].clearWatches(cycle=cycle)

    def showWatchMarks(self, old=False, verbose=False):
        self.dataWatch[self.target].showWatchMarks(old=old, verbose=verbose)

    def saveWatchMarks(self, fpath):
        self.dataWatch[self.target].saveWatchMarks(fpath)

    def saveWatchMarksJson(self, fpath):
        self.dataWatch[self.target].saveJson(fpath)


    def getWatchMarks(self):
        self.lgr.debug('getWatchMarks')
        watch_marks = self.dataWatch[self.target].getWatchMarks()
        try:
            jmarks = json.dumps(watch_marks)
            print(jmarks)
        except Exception as e:
            self.lgr.debug('getWatchMarks, json dumps failed on %s' % str(watch_marks))
            self.lgr.debug('error %s' % str(e))
            with open('logs/badjson.txt', 'w') as fh:
                fh.write(str(watch_marks))
                #print(str(watch_marks))
            for bad in watch_marks:
                try:
                    badstring = json .dumps(bad)
                except Exception as e:
                    self.lgr.debug('getWatchMarks, json dumps failed on %s' % str(bad))
        self.lgr.debug('getWatchMarks done')

    def getWriteMarks(self):
        self.lgr.debug('genMonitor getWritemarks')
        watch_marks = self.trackFunction[self.target].getWatchMarks()
        try:
            jmarks = json.dumps(watch_marks)
            print(jmarks)
        except Exception as e:
            self.lgr.debug('getWriteMarks, json dumps failed on %s' % str(watch_marks))
            self.lgr.debug('error %s' % str(e))

    def stopTracking(self, keep_watching=False, keep_coverage=False):
        self.lgr.debug('stopTracking')
        self.stopTrackIO(immediate=True, check_crash=False)
        if self.dataWatch[self.target].didSomething():
            self.disableOtherBreaks()
            self.rmAllDmods()
        self.dataWatch[self.target].removeExternalHaps(immediate=True)
        self.dataWatch[self.target].disable()

        self.stopThreadTrack(immediate=True)
        self.noWatchSysEnter()

        self.removeDebugBreaks(immediate=True, keep_watching=keep_watching, keep_coverage=keep_coverage)
        self.track_finished = True

    def goToWatchMark(self, index):
        return self.goToDataMark(index)
    def goToDataMark(self, index):
        if index is None:
            print('goToDataMark called with no index, perhaps that mark does not exist?')
            return None
        was_watching = self.context_manager[self.target].watchingThis()
        self.lgr.debug('goToDataMark(%d)' % index)

        ''' Assume that this is the first thing done after a track.
            Remove all haps that might interfer with reversing. '''
        self.stopTracking()
        cycle = self.dataWatch[self.target].goToMark(index)
        if cycle is not None:
            self.context_manager[self.target].watchTasks(set_debug_tid=True)
            if not was_watching:
                self.context_manager[self.target].setAllHap()
        else:
            print('Index %d does not have an associated data mark.' % index)
        return cycle

    def goToWriteMark(self, index):
        was_watching = self.context_manager[self.target].watchingThis()
        cycle = self.trackFunction[self.target].goToMark(index)
        if cycle is not None:
            self.context_manager[self.target].watchTasks(set_debug_tid=True)
            if not was_watching:
                self.context_manager[self.target].setAllHap()
        return cycle

    def goToBasicBlock(self, addr):
        self.lgr.debug('goToBasicBlock 0x%x' % addr)
        self.removeDebugBreaks()
        cycle = self.coverage.goToBasicBlock(addr)
        self.restoreDebugBreaks(was_watching=True)
        if cycle is not None:
            self.context_manager[self.target].watchTasks(set_debug_tid=True)
        else:
            print('address 0x%x not in blocks hit' % addr)
            self.lgr.debug('address 0x%x not in blocks hit' % addr)
            self.gdbMailbox('address %s not in blocks hit.' % addr)
        return cycle
       
    
    def addProc(self, tid, leader_tid, comm, clone=False):    
        self.traceProcs[self.target].addProc(tid, leader_tid, comm=comm, clone=clone)

    def traceInject(self, dfile):
        ''' DEPRECATED, remove '''
        self.lgr.debug('traceInject %s' % dfile)
        if not os.path.isfile(dfile):
            print('File not found at %s\n\n' % dfile)
            return
        addr = None
        afl_file = os.path.join('./', self.run_from_snap, self.target, 'afl.pickle')
        if os.path.isfile(afl_file):
            self.lgr.debug('afl pickle from %s' % afl_file)
            so_pickle = pickle.load( open(afl_file, 'rb') ) 
            #print('start %s' % str(so_pickle['text_start']))
            call_ip = so_pickle['call_ip']
            return_ip = so_pickle['return_ip']
            if 'addr' in so_pickle:
                addr = so_pickle['addr']
                self.lgr.debug('traceInject pickle addr 0x%x ' % (addr))
        cpu = self.cell_config.cpuFromCell(self.target)
        ''' Add memUtil function to put byte array into memory '''
        byte_string = None
        with open(dfile, 'rb') as fh:
            byte_string = fh.read()
        
        self.dataWatch[self.target].goToRecvMark()
        lenreg = None
        lenreg2 = None
        if addr is None:
            addr = self.dataWatch[self.target].firstBufferAddress()
        if addr is None:
            self.lgr.error('traceInject, no firstBufferAddress found')
            return
        if cpu.architecture == 'arm':
            lenreg = 'r0'
        else:
            lenreg = 'eax'
        prev_len = self.mem_utils[self.target].getRegValue(cpu, lenreg)
        self.lgr.debug('traceInject prev_len is %s' % prev_len)
        if len(byte_string) > prev_len:
            '''
            if sys.version_info[0] == 3:
                a = input('Warning: your injection is %d bytes; previous reads was only %d bytes.  Continue?' % (len(byte_string), prev_len))
            else:
                a = raw_input('Warning: your injection is %d bytes; previous reads was only %d bytes.  Continue?' % (len(byte_string), prev_len))
            if a.lower() != 'y':
                return
            '''
            self.lgr.warning('your injection is %d bytes; previous reads was only %d bytes?' % (len(byte_string), prev_len))
        self.lgr.debug('traceInject Addr: 0x%x length: %d byte_string is %s' % (addr, len(byte_string), str(byte_string)))
        self.mem_utils[self.target].writeString(cpu, addr, byte_string) 
        self.writeRegValue(lenreg, len(byte_string))
        if lenreg2 is not None:
            self.writeRegValue(lenreg2, len(byte_string))
        self.lgr.debug('traceInject from file %s. Length register %s set to 0x%x' % (dfile, lenreg, len(byte_string))) 
        self.traceAll()
        SIM_continue(0)
       

    def injectIO(self, dfile, stay=False, keep_size=False, callback=None, n=1, cpu=None, 
            sor=False, cover=False, target=None, targetFD=None, trace_all=False, 
            save_json=None, limit_one=False, no_rop=False, go=True, max_marks=None, instruct_trace=False, mark_logs=False,
            break_on=None, no_iterators=False, only_thread=False, no_track=False, no_reset=False, count=1, no_page_faults=False, 
            no_trace_dbg=False, run=True, reset_debug=True, src_addr=None, malloc=False, trace_fd=None, fname=None):
        ''' Inject data into application or kernel memory.  This function assumes you are at a suitable execution point,
            e.g., created by prepInject or prepInjectWatch.  '''
        ''' Use go=False and then go yourself if you are getting the instance for your own use, otherwise
            the instance is not defined until it is done.
            use no_reset True to stop the tracking if RESim would need to reset the origin.'''
        self.track_started = True
        self.lgr.debug('injectIO dfile: %s max_marks %s' % (dfile, max_marks))
        if 'coverage/id' in dfile or 'trackio/id' in dfile:
            print('Modifying a coverage or injectIO file name to a queue file name for injection into application memory')
            self.lgr.debug('Modifying a coverage or injectIO file name to a queue file name for injection into application memory')
            if 'coverage/id' in dfile:
                dfile = dfile.replace('coverage', 'queue')
            else:
                dfile = dfile.replace('trackio', 'queue')
        if type(save_json) is bool:
            if save_json:
                save_json = 'logs/track.json'
            else:
                save_json = None

        if save_json:
            # hacky logic for turning off gdb server when running parallel trackIOs
            self.no_gdb = True
        if self.bookmarks is not None:
            self.goToOrigin()

        ''' See if the target cell or/and process differs from the current process into which data will be injected '''
        target_cell, target_prog, target_cpu, this_cpu = self.parseTarget(target)
        if cpu is None:
            cpu = this_cpu
        ''' Record any debuggerish buffers that were specified in the ini file '''
        if trace_all:
            self.traceBufferTarget(target_cell, msg='injectIO traceAll')

        cell_name = self.getTopComponentName(cpu)
        if no_track:
            self.dataWatch[target_cell].disable()
        else:
            self.dataWatch[target_cell].resetWatch()
        if max_marks is not None:
            self.dataWatch[target_cell].setMaxMarks(max_marks) 
        if target_prog is None:
            self.page_faults[target_cell].stopWatchPageFaults()
            tid = self.getTID()
            # may be wrong tid, e.g., prepInjectWatch
            self.watchPageFaults(tid)
        if mark_logs or trace_fd is not None:
            self.traceFiles[self.target].markLogs(self.dataWatch[target_cell])
        self.rmDebugWarnHap()
        self.checkOnlyIgnore()
        self.lgr.debug('genMonitor injectIO create instance')
        self.injectIOInstance = injectIO.InjectIO(self, cpu, cell_name, self.back_stop[self.target], dfile, self.dataWatch[target_cell], self.bookmarks, 
                  self.mem_utils[self.target], self.context_manager[self.target], self.soMap[self.target], self.lgr, 
                  self.run_from_snap, stay=stay, keep_size=keep_size, callback=callback, packet_count=n, stop_on_read=sor, coverage=cover, 
                  target_cell=target_cell, target_prog=target_prog, targetFD=targetFD, trace_all=trace_all, 
                  save_json=save_json, limit_one=limit_one, no_track=no_track,  no_reset=no_reset, no_rop=no_rop, instruct_trace=instruct_trace, 
                  break_on=break_on, mark_logs=mark_logs, no_iterators=no_iterators, only_thread=only_thread, count=count, no_page_faults=no_page_faults,
                  no_trace_dbg=no_trace_dbg, run=run, reset_debug=reset_debug, src_addr=src_addr, malloc=malloc, trace_fd=trace_fd, fname=fname)

        if go:
            self.injectIOInstance.go()
        return self.injectIOInstance
   
    def aflInject(self, target, index, instance=None, cover=False, save_json=False):
        afl_file = aflPath.getAFLPath(target, index, instance)
        save_json_file = None
        if save_json:
            save_json_file = 'logs/trackio.json' 
        if afl_file is not None:
            self.injectIO(afl_file, cover=cover, save_json=save_json_file)

    def aflInjectTCP(self, target, index, instance=None, cover=False, save_json=False):
        afl_file = aflPath.getAFLPath(target, index, instance)
        if afl_file is not None:
            if save_json:
                self.injectIO(afl_file, cover=cover, n=-1, save_json='logs/track.json')
            else:
                self.injectIO(afl_file, cover=cover, n=-1)
        else:
            print('no file found at %s' % afl_file)

    def doudp(self, dumb):
        port = os.getenv('TARGET_PORT')
        cmd = './doudp.sh %s' % port
        #cmd = 'bash -c "cat /tmp/sendudp > /dev/udp/localhost/%s"' % (port)
        print('cmd is: %s' % cmd)
        os.system(cmd)
        print('back from command')

    def aflTrack(self, target, index, FD, port, instance = None):
        afl_file = aflPath.getAFLPath(target, index, instance)
        if afl_file is not None:
            shutil.copyfile(afl_file, 'logs/sendudp')
            self.trackIO(FD, run_fun=self.doudp)
            print('tracking %s' % afl_file)
 
    def tagIterator(self, index):    
        ''' User driven identification of an iterating function -- will collapse many watch marks into one '''
        self.dataWatch[self.target].tagIterator(index)

    def addIterator(self, addr):
        fun_addr = self.fun_mgr.getFun(addr)
        if fun_addr is not None:
            self.fun_mgr.addIterator(fun_addr)

    def runToKnown(self, go=True):
        self.soMap[self.target].runToKnown()
        if go:
            SIM_continue(0)

    def runToOther(self, go=True, threads=False):
        ''' Continue execution until a different library is entered, or main text is returned to '''
        cpu = self.cell_config.cpuFromCell(self.target)
        eip = self.mem_utils[self.target].getRegValue(cpu, 'eip')

        if self.isWindows():
            self.lgr.debug('runToOther eip 0x%x' % eip)
            self.run_to[self.target].runToKnown(eip, threads=threads)
        else:
            self.soMap[self.target].runToKnown(eip, threads=threads)
        if go:
           SIM_continue(0)

    def modFunction(self, fun, offset, word):
        ''' write a given word at the offset of a start of a function.  Intended to force a return
            of a specific value.  Assumes you provide proper machine code. '''
        addr, end = self.fun_mgr.getAddr(fun)
        cpu = self.cell_config.cpuFromCell(self.target)
        if addr is not None:
            new_addr = addr+offset
            self.mem_utils[self.target].writeWord32(cpu, new_addr, word)
            self.lgr.debug('modFunction wrote 0x%x to 0x%x' % (word, new_addr))
            self.lgr.debug('modFunction, disable reverse execution to clear bookmarks, then set origin')
            self.clearBookmarks()
        else:
            self.lgr.error('modFunction, no address found for %s' % (fun))

    def trackFunctionWrite(self, fun, show_compare=False):
        ''' When the given function is entered, begin tracking memory addresses that are written to.
            Stop on exit of the function. '''
        self.track_started = True
        self.lgr.debug('genMonitor trackFunctionWrite %s' % fun)
        tid, cpu = self.context_manager[self.target].getDebugTid() 

        read_watch_marks = self.dataWatch[self.target].getWatchMarks()
        self.trackFunction[self.target].trackFunction(tid, fun, self.fun_mgr, read_watch_marks, show_compare)

    def saveMemory(self, addr, size, fname):
        cpu = self.cell_config.cpuFromCell(self.target)
        byte_array = self.mem_utils[self.target].readBytes(cpu, addr, size)
        with open(fname, 'wb') as fh:
            fh.write(byte_array)
        self.lgr.debug('saveMemory wrote %d bytes from 0x%x to file %s' % (size, addr, fname))

    def pinfo(self, addr, force_cr3=None):
        cpu = self.cell_config.cpuFromCell(self.target)
        ptable_info = pageUtils.findPageTable(cpu, addr, self.lgr, force_cr3=force_cr3)
        if ptable_info is not None:
            print(ptable_info.valueString())

    def pageInfo(self, addr, quiet=False, cr3=None):
        cpu = self.cell_config.cpuFromCell(self.target)
        if cr3 is None:
            use_cr3 = self.mem_utils[self.target].getKernelSavedCR3()
        else:
            use_cr3 = cr3
        task_cr3 = memUtils.getCR3(cpu)
        print('current task cr3 0x%x' % (task_cr3))
        if use_cr3 is not None:
            print('Using cr3 0x%x' % (use_cr3))

        ptable_info = pageUtils.findPageTable(cpu, addr, self.lgr, force_cr3=use_cr3)
        if not quiet:
            print(ptable_info.valueString())
        cpu = self.cell_config.cpuFromCell(self.target)
        if cpu.architecture == 'ppc32':
            if ptable_info is not None:
                print(ptable_info.valueString())
        elif ptable_info.entry is not None:
            pei = pageUtils.PageEntryInfo(ptable_info.entry, cpu.architecture)
            if not quiet:
                print('writable? %r' % pei.writable)
        else:
            print('page table entry is None')
        return ptable_info

    def toTid(self, tid, callback = None, run=True):
        ''' advance to the given tid.  default callback is toUser.  If tid is -1, then advance to any tid.
            If tid is -2, then advance to any non-zero tid and there is no default callback'''
        if type(tid) is int:
            tid = str(tid)
        self.lgr.debug('genMonitor toTid %s' % tid)
        if callback is None and tid != '-2' and tid !='0':
            callback = self.toUser
        if tid == '-1':
            cpu, comm, cur_tid = self.task_utils[self.target].curThread() 
            self.lgr.debug('genMonitor toTid run to any tid that we are watching. cur_tid %s' % cur_tid)
            if self.amWatching(cur_tid):
                self.lgr.debug('genMonitor toTid watching cur tid, just do callback')
                callback() 
            else:
                self.context_manager[self.target].catchTid(tid, callback)
        else:
            self.context_manager[self.target].catchTid(tid, callback)
        if run:
            SIM_continue(0)

    def cleanMode(self, dumb):
        if self.mode_hap is not None:
            #print('mode_hap was lingering, delete it')
            RES_hap_delete_callback_id("Core_Mode_Change", self.mode_hap)
            self.mode_hap = None

    def watchROP(self, watching=True, callback=None, addr=None, size=None):
        self.lgr.debug('watchROP')
        for t in self.ropCop:
            self.lgr.debug('ropcop instance %s' % t)
        if self.target in self.ropCop:
            self.ropCop[self.target].watchROP(watching=watching, callback=callback, addr=addr, size=size)

    def enableCoverage(self, fname=None, backstop_cycles=None, report_coverage=False, dead_zone=False):
        ''' Enable code coverage '''
        ''' Intended for use with trackIO, playAFL, etc '''
        if self.coverage is not None:
            analysis_path = self.getAnalysisPath(fname)
            tid, cpu = self.context_manager[self.target].getDebugTid() 
            self.coverage.enableCoverage(tid, fname=analysis_path, backstop = self.back_stop[self.target], backstop_cycles=backstop_cycles, 
              report_coverage=report_coverage, create_dead_zone=dead_zone)
            self.coverage.doCoverage()
        else:
            self.lgr.error('enableCoverage, no coverage defined')

    def mapCoverage(self, fname=None, backstop=False, dead_zone=False):
        ''' Enable code coverage and do mapping '''
        ''' Not intended for use with trackIO, use enableCoverage for that '''
        if fname is not None:
            analysis_path = self.soMap[self.target].getAnalysisPath(fname)
        else:
            analysis_path = None
        self.lgr.debug('mapCoverage file (None means use prog name): %s' % analysis_path)
        if self.coverage is None and fname is not None:
            cell = self.cell_config.cell_context[self.target]
            cpu = self.cell_config.cpuFromCell(self.target)
            if analysis_path is not None:
                ida_path = self.getIdaData(analysis_path)
                self.lgr.debug('mapCoverage, no coveage defined, create one. ida_path is %s' % ida_path)
                self.coverage = coverage.Coverage(self, analysis_path, ida_path, self.context_manager[self.target], 
                   cell, self.soMap[self.target], self.mem_utils[self.target], cpu, self.run_from_snap, self.lgr)
            else:
                self.lgr.error('mapCoverage, could not get analysis path from fname %s' % fname)
        backstop_cycles = None
        if backstop:
            backstop_cycles = defaultConfig.backstopCycles()      
        self.enableCoverage(fname=analysis_path, backstop_cycles=backstop_cycles, report_coverage=backstop, dead_zone=dead_zone)

    def showCoverage(self):
        self.coverage.showCoverage()
        self.coverage.saveCoverage()

    def saveCoverage(self):
        self.coverage.saveCoverage()

    def stopCoverage(self):
        self.lgr.debug('stopCoverage')
        if self.coverage is not None:
            self.coverage.stopCover()

    def runToStack(self):
        ''' 3 pages for now? '''
        tid, cpu = self.context_manager[self.target].getDebugTid() 
        esp = self.mem_utils[self.target].getRegValue(cpu, 'esp')
        base = esp & 0xffffff000
        proc_break = self.context_manager[self.target].genBreakpoint(None, Sim_Break_Linear, Sim_Access_Execute, base, 0x3000, 0)
        tid_list = self.context_manager[self.target].getThreadTids()
        prec = Prec(cpu, None, tid_list, who='to stack')
        prec.debugging = True
        f1 = stopFunction.StopFunction(self.skipAndMail, [], nest=False)
        flist = [f1]

        self.proc_hap = self.context_manager[self.target].genHapIndex("Core_Breakpoint_Memop", self.textHap, prec, proc_break, 'stack_hap')

        hap_clean = hapCleaner.HapCleaner(cpu)
        hap_clean.add("GenContext", self.proc_hap)
        stop_action = hapCleaner.StopAction(hap_clean, flist=flist)
        self.stop_hap = self.RES_add_stop_callback(self.stopHap, stop_action)

        self.context_manager[self.target].watchTasks()
        self.lgr.debug('runToStack hap set, now run. flist in stophap is %s' % stop_action.listFuns())
        SIM_run_alone(SIM_continue, 0)
    
    def rmBackStop(self):
        self.lgr.debug('rmBackStop')
        self.dataWatch[self.target].rmBackStop()    

    def saveHits(self, fname):
        self.lgr.debug('saveHits %s' % fname)
        self.coverage.saveHits(fname)

    def difCoverage(self, fname):
        ''' TBD not used'''
        self.coverage.difCoverage(fname)

    def precall(self, tid=None):
        if tid is None:
            cpu, comm, tid = self.task_utils[self.target].curThread() 
        cycle_list = self.record_entry[self.target].getEnterCycles(tid)
        self.lgr.debug('precall tid:%s len of cycle_list %d' % (tid, len(cycle_list)))
        if cycle_list is None:
            print('No cycles for tid:%s' % tid)
            return
        else:
            ''' find latest cycle that preceeds current cycle '''
            cpu = self.cell_config.cpuFromCell(self.target)
            prev_cycle = None
            for cycle in reversed(cycle_list):
                if cycle < cpu.cycles:
                    prev_cycle = cycle
                    break
            if prev_cycle is None:
                print('No cycle found for tid:%s that is earlier than current cycle 0x%x' % (tid, cpu.cycles))  
                self.lgr.debug('precall No cycle found for tid:%s that is earlier than current cycle 0x%x' % (tid, cpu.cycles))  
            else:
                did_remove = self.removeDebugBreaks()
                SIM_run_command('pselect %s' % cpu.name)
                previous = prev_cycle-1
                self.skipToCycle(previous)
                eip = self.getEIP()
                self.lgr.debug('precall skipped to cycle 0x%x eip: 0x%x' % (cpu.cycles, eip))
                if cpu.cycles != previous:
                    self.lgr.error('precall Cycle not as expected, wanted 0x%x got 0x%x' % (previous, cpu.cycles))
                else:
                    cpl = memUtils.getCPL(cpu)
                    if cpl == 0: 
                        # TBD Simics edge case?
                        previous = prev_cycle-2
                        self.lgr.debug('precall landed in kernel, try going back 1 more to 0x%x' % previous)
                        self.skipToCycle(previous)
                        cpl = memUtils.getCPL(cpu)
                        if cpl == 0: 
                            self.lgr.error('precall ended up in kernel, quit')
                            #self.quit()
                if did_remove:
                    self.restoreDebugBreaks(was_watching=True)

    def taskSwitches(self):
        cpu = self.cell_config.cpuFromCell(self.target)
        ts = taskSwitches.TaskSwitches(cpu, self.mem_utils[self.target], self.task_utils[self.target], self.param[self.target], self.lgr)

    ''' not yet used, maybe never '''
    def setReal(self, script):
        if not os.path.isfile(script):
            print('Could not find %s' % script)
            return
        self.real_script = script
    def realScript(self):
        if self.real_script is not None:
            cmd = ('run-command-file %s' % self.real_script)
            SIM_run_command(cmd)
        else:
            self.lgr.debug('real script, no script to run')

   
    def swapSOTid(self, old, new):
        self.lgr.debug('genMonitor swapSOTid')
        retval = self.soMap[self.target].swapTid(old, new)
        if retval:
            self.task_utils[self.target].swapExecTid(old, new)
        return retval

    def getCoverageFile(self):
        if self.coverage is not None:
            return self.coverage.getCoverageFile()
        else:
            return None

    def getCoverage(self):
        return self.coverage

    def startDataSessions(self):
        if self.coverage is not None:
            SIM_run_alone(self.coverage.startDataSessions, None)

    def nextWatchMark(self):
        n = self.dataWatch[self.target].nextWatchMark()
        if n is not None:
            print(n)
        else:
            print('No watch marks after current cycle')

    def showContext(self):
        cpu = self.cell_config.cpuFromCell(self.target)
        print('context for cell %s is  %s' % (self.target, str(cpu.current_context)))

    def traceMalloc(self):
        self.lgr.debug('genMonitor traceMalloc')
        cpu = self.cell_config.cpuFromCell(self.target)
        cell = self.cell_config.cell_context[self.target]
        self.trace_malloc = traceMalloc.TraceMalloc(self, self.fun_mgr, self.context_manager[self.target], 
               self.mem_utils[self.target], self.task_utils[self.target], cpu, cell, self.dataWatch[self.target], self.lgr)

    def showMalloc(self):
        self.trace_malloc.showList()

    def stopTraceMalloc(self):
        if self.trace_malloc is not None:
            self.trace_malloc.stopTrace()
        self.trace_malloc = None

    def trackXMLFile(self, substring):
        ''' track access to XML file access '''
        self.lgr.debug('trackXMLFile') 
        self.track_started = True
        self.stopTrackIO(immediate=True)
        self.clearWatches()
        self.lgr.debug('trackXMLFile stopped track and cleared watchs')
        self.dataWatch[self.target].trackFile(self.stopTrackIO, self.is_compat32)
        self.lgr.debug('trackXMLFile back from dataWatch, now run to IO')
        if self.coverage is not None:
            self.coverage.doCoverage()
        self.runToOpen(substring)    

    def fuzz(self, path, n=1, fname=None):
        ''' TBD not used.  See runAFL '''
        cpu, comm, tid = self.task_utils[self.target].curThread() 
        cell_name = self.getTopComponentName(cpu)
        self.debugTidGroup(tid, to_user=False)
        full_path = None
        if fname is not None:
            full_path = self.targetFS[self.target].getFull(fname, lgr=self.lgr)
            if full_path is None:
                self.lgr.error('unable to get full path from %s' % fname)
                return
        fuzz_it = fuzz.Fuzz(self, cpu, cell_name, path, self.coverage, self.back_stop[self.target], self.mem_utils[self.target], self.run_from_snap, self.lgr, n, full_path)
        fuzz_it.trim()

    def checkUserSpace(self, cpu):
        retval = True
        ''' TBD remove all this?'''
        return retval
        cpl = memUtils.getCPL(cpu)
        if cpl == 0:
            self.lgr.warning('The snapshot from prepInject left us in the kernel, try forward 1')
            SIM_run_command('pselect %s' % cpu.name)
            SIM_run_command('si')
            cpl = memUtils.getCPL(cpu)
            if cpl == 0:
                self.lgr.error('checkUserSpace Still in kernel, cannot work from here.  Check your prepInject snapshot. Exit.')
                retval = False
        return retval

    def aflTCP(self, sor=False, fname=None, linear=False, port=8765, dead=False):
        # TBD not used.  remove?
        ''' note hack of n = -1 to indicate tcp '''
        self.afl(n=-1, sor=sor, fname=fname, port=port, dead=dead)

    def afl(self,n=1, sor=False, fname=None, linear=False, target=None, targetFD=None, count=1, dead=None, port=8765, 
            one_done=False, test_file=None, commence_params=None):
        ''' sor is stop on read; target names process other than consumer; if dead is True,it 
            generates list of breakpoints to later ignore because they are hit by some other thread over and over. Stored in checkpoint.dead.
            fname is to fuzz a library'''
        self.lgr.debug('genMonitor afl')
        self.rmDebugWarnHap()
        target_cell, target_proc, target_cpu, this_cpu = self.parseTarget(target)
        cell_name = self.getTopComponentName(this_cpu)
        ''' prevent use of reverseToCall.  TBD disable other modules as well?'''
        self.disable_reverse = True
        if target is None:
            if not self.checkUserSpace(target_cpu):
                return
            # keep gdb 9123 port free
            self.gdb_port = 9124
            #self.debugTidGroup(tid, to_user=False)
        '''
        TBD remove this?
        full_path = None
        if fname is not None and target is None:
            self.lgr.debug('afl get full for %s' % fname)
            full_path = self.targetFS[self.target].getFull(fname, lgr=self.lgr)
            self.lgr.debug('afl back from get full for %s' % fname)
            if full_path is None:
                self.lgr.error('unable to get full path from %s' % fname)
                return
        else: 
            full_path=fname
        '''
        full_path=fname
        self.afl_instance = afl.AFL(self, this_cpu, cell_name, self.coverage, self.back_stop[target_cell], self.mem_utils[self.target], 
            self.run_from_snap, self.context_manager[target_cell], self.page_faults[target_cell], self.lgr, packet_count=n, stop_on_read=sor, fname=full_path, 
            linear=linear, target_cell=target_cell, target_proc=target_proc, targetFD=targetFD, count=count, create_dead_zone=dead, port=port, 
            one_done=one_done, test_file=test_file, commence_params=commence_params)
        if target is None:
            self.noWatchSysEnter()
            self.afl_instance.goN(0)

    # TBD unused?
    def aflFD(self, fd, snap_name, count=1):
        self.prepInject(fd, snap_name, count=count)

    def prepInject(self, fd, snap_name, count=1, commence=None):
        ''' 
            Prepare a system checkpoint for fuzzing or injection by running until IO on some FD.
            fd -- will runToIOish on that FD and will record the buffer address for use by injectIO or fuzzing.
            snap_name -- will writeConfig to that snapshot.  Use that snapshot for fuzz and afl commands. '''
        if self.reverseEnabled():
            if '-' in snap_name:
               print('Avoid use of - in snapshot names.')
               return
            if os.path.exists(snap_name):
               print('%s already exists, pick a new snapshot name.' % snap_name)
               return
            cpu = self.cell_config.cpuFromCell(self.target)
            cell_name = self.getTopComponentName(cpu)
            debug_tid, dumb = self.context_manager[self.target].getDebugTid() 
            if debug_tid is None:
                cpu, comm, tid = self.task_utils[self.target].curThread() 
                self.debugTidGroup(tid)
            print('fd is %d (0x%x)' % (fd, fd))
            prepInject.PrepInject(self, cpu, cell_name, fd, snap_name, count, self.mem_utils[self.target], 
                 self.lgr, commence=commence) 
        else:
            print('Reverse execution must be enabled to run prepInject')

    def prepInjectWatch(self, watch_mark, snap_name):
        ''' Like prepInject, but goes to given watchmark records the kernel buffers identified by using trackIO(kbuf=True) '''
        if self.reverseEnabled():
            if '-' in snap_name:
               print('Avoid use of - in snapshot names.')
               return
            cpu = self.cell_config.cpuFromCell(self.target)
            cell_name = self.getTopComponentName(cpu)
            self.lgr.debug('prepInjectWatch')
            kbuf_module = None
            if self.target in self.kbuffer:
                kbuf_module = self.kbuffer[self.target]
            self.lgr.debug('prepInjectWatch, kbuffer: %s' % str(kbuf_module))
            prep_inject = prepInjectWatch.PrepInjectWatch(self, cpu, cell_name, self.mem_utils[self.target], self.dataWatch[self.target], 
                              self.context_manager[self.target], kbuf_module, self.lgr) 
            prep_inject.doInject(snap_name, watch_mark)
        else:
            print('prepInjectWatch requires reverse execution.')

    def prepInjectAddr(self, addr, snap_name):
        ''' Variant of prepInject that uses current execution point and records the given address as the application buffer '''
        self.lgr.debug('prepInjectAddr  begin')
        self.writeConfig(snap_name)
        pickDict = {}
        pickDict['addr'] = addr
        afl_file = os.path.join('./', snap_name, self.target, 'afl.pickle')
        pickle.dump( pickDict, open( afl_file, "wb") ) 
        print('Configuration file saved to %s, ok to quit.' % afl_file)

    def hasBookmarks(self):
        return self.bookmarks is not None

    def setDisableReverse(self):
        ''' Once set, cannot go back '''
        self.disable_reverse = True


    def playAFL(self, dfile, n=1, sor=False, linear=False, dead=False, afl_mode=False, no_cover=False, crashes=False, 
            parallel=False, only_thread=False, target=None, trace_all=False, repeat=False, fname=None, targetFD=None, count=1, 
            no_page_faults=False, show_new_hits=False, diag_hits=False, search_list=None, commence_params=None, watch_rop=False):
        ''' replay one or more input files, e.g., all AFL discovered paths for purposes of updating BNT in code coverage 
            Use fname to name a binary such as a library.
        '''

        ''' See if the target cell or/and process differs from the current process into which data will be injected '''
        target_cell, target_proc, target_cpu, this_cpu = self.parseTarget(target)
        cell_name = self.getTopComponentName(this_cpu)
        #if not self.checkUserSpace(cpu):
        #    return
        #
        # 

        if no_cover:
            bb_coverage = None
        self.rmDebugWarnHap()
        if parallel:
            self.no_gdb = True
        if afl_mode:
            self.disable_reverse = True
        play = playAFL.PlayAFL(self, this_cpu, cell_name, self.back_stop[target_cell], no_cover,
              self.mem_utils[self.target], dfile, self.run_from_snap, self.context_manager[target_cell],
              self.cfg_file, self.lgr, packet_count=n, stop_on_read=sor, linear=linear, create_dead_zone=dead, afl_mode=afl_mode, 
              crashes=crashes, parallel=parallel, only_thread=only_thread, target_cell=target_cell, target_proc=target_proc, 
              repeat=repeat, fname=fname, targetFD=targetFD, count=count, trace_all=trace_all, no_page_faults=no_page_faults,
              show_new_hits=show_new_hits, diag_hits=diag_hits, search_list=search_list, commence_params=commence_params, watch_rop=watch_rop)
        if play is not None and target_proc is None:
            self.lgr.debug('playAFL now go')
            #if trace_all: 
            #    self.traceAll()
            #    #self.trace_all = True
            play.go()
        elif play is None:
            print('playAFL failed?')

    def findBB(self, target, bb):
        afl_output = aflPath.getAFLOutput()
        target_dir = os.path.join(afl_output, target)
        #flist = os.listdir(target_dir)
        flist = glob.glob(target_dir+'/resim_*/')
        #print('flist is %s' % str(flist))
        if len(flist) == 0:
            ''' is not parallel fuzzing '''
            coverage_dir = os.path.join(target_dir, 'coverage')
            queue_dir = os.path.join(target_dir, 'queue')
            hit_files = os.listdir(coverage_dir)
            
            for f in hit_files:
                path = os.path.join(coverage_dir, f)
                hit_list = json.load(open(path))
                if bb in hit_list:
                    qfile = os.path.join(queue_dir, f)
                    print('found 0x%x in %s' % (bb, qfile))
        else: 
            ''' is parallel fuzzing '''
            print('is parallel')
            for drone in flist:
                coverage_dir = os.path.join(drone, 'coverage')
                queue_dir = os.path.join(drone, 'queue')
                hit_files = os.listdir(coverage_dir)
                for f in hit_files:
                    path = os.path.join(coverage_dir, f)
                    hit_list = json.load(open(path))
                    if bb in hit_list:
                        qfile = os.path.join(queue_dir, f)
                        print('found 0x%x in %s' % (bb, qfile))
    
    def bbAFL(self, target, bb, n=1, sor=False):
        ''' replay all AFL discovered paths for purposes of discovering which data files hit a given BB '''
        cpu, comm, tid = self.task_utils[self.target].curThread() 
        cell_name = self.getTopComponentName(cpu)
        if self.aflPlay is None:
            self.debugTidGroup(tid, to_user=False)
            self.aflPlay = playAFL.PlayAFL(self, cpu, cell_name, self.back_stop[self.target], self.coverage,
                  self.mem_utils[self.target], self.dataWatch[self.target], target, self.run_from_snap, self.context_manager[self.target], 
                  self.lgr, packet_count=n, stop_on_read=sor)
        if self.aflPlay is not None:
            self.aflPlay.go(findbb=bb)

    def replayAFL(self, target, index, targetFD, instance=None, cover=False, trace=False): 
        ''' replay a specific AFL data file using a driver listening on localhost 4022 '''
        self.replay_instance = replayAFL.ReplayAFL(self, target, index, targetFD, self.lgr, instance=instance, cover=cover, trace=trace) 

    def replayAFLTCP(self, target, index, targetFD, instance=None, cover=False, trace=False): 
        self.replay_instance = replayAFL.ReplayAFL(self, target, index, targetFD, self.lgr, instance=instance, tcp=True, cover=cover, trace=trace) 

    def crashReport(self, fname, n=1, one_done=False, report_index=None, target=None, targetFD=None, trackFD=None, report_dir=None):
        ''' generate crash reports for all crashes in a given AFL target diretory -- or a given specific file '''
        self.lgr.debug('crashReport %s' % fname)
        cpu, comm, tid = self.task_utils[self.target].curThread() 
        self.report_crash = reportCrash.ReportCrash(self, cpu, tid, self.dataWatch[self.target], self.mem_utils[self.target], fname, n, one_done, report_index, self.lgr, 
              target=target, targetFD=targetFD, trackFD=trackFD, report_dir=report_dir)
        self.report_crash.go()

    def exitReport(self, fname, n=1, one_done=False, report_index=None, report_dir=None):
        ''' generate exit reports for all exits in a given AFL target diretory -- or a given specific file '''
        self.lgr.debug('exitReport %s' % fname)
        cpu, comm, tid = self.task_utils[self.target].curThread() 
        self.report_exit = reportExit.ReportExit(self, cpu, tid, self.mem_utils[self.target], fname, n, one_done, report_index, self.lgr, 
              report_dir=report_dir)
        self.report_exit.go()

    def trackAFL(self, target):
        track_afl = trackAFL.TrackAFL(self, target, self.lgr)
        track_afl.go()

    def getSEGVAddr(self):
        if self.bookmarks is not None:
            return self.bookmarks.getSEGVAddr()
        else:
            return None

    def getROPAddr(self):
        return self.bookmarks.getROPAddr()
   
    def getFaultAddr(self):
        return self.bookmarks.getFaultAddr()
   
    def setCommandCallback(self, callback):
        self.lgr.debug('setCommandCallback to %s' % str(callback))
        self.command_callback = callback 

    def setCommandCallbackParam(self, param):
        self.command_callback_param = param 

    def doCommandCallback(self):
        if self.command_callback is not None:
            self.lgr.debug('doCommandCallback')
            self.command_callback(self.command_callback_param)

    def setDebugCallback(self, callback):
        self.lgr.debug('setDebugCallback to %s' % str(callback))
        self.debug_callback = callback 

    def setDebugCallbackParam(self, param):
        self.debug_callback_param = param 

    def getCommandCallback(self):
        return self.command_callback 

    def findBNT(self, hits, fun_blocks):
        for bb in fun_blocks['blocks']:
            for bb_hit in hits:
                if bb_hit == bb['start_ea']:
                    for branch in bb['succs']:
                        if branch not in hits:
                            print('function: %s branch 0x%x from 0x%x not in hits' % (fun_blocks['name'], branch, bb_hit))

    def aflBNT(self, target, fun_name=None):
        ida_path = self.getIdaData(self.full_path)
        if ida_path is not None:
            if target is None:
                fname = '%s.hits' % ida_path
            else:
                fname = '%s.%s.hits' % (ida_path, target)
            ''' hits are now just flat lists without functoins '''
            hits = json.load(open(fname))
            block_file = self.full_path+'.blocks'
            blocks = json.load(open(block_file))
            print('aflBNT found %d hits and %d blocks' % (len(hits), len(blocks)))
            if fun_name is None:
                for fun in blocks:
                    self.findBNT(hits, blocks[fun]) 
            else:
                for fun in blocks:
                    if blocks[fun]['name'] == fun_name:
                        self.findBNT(hits, blocks[fun]) 
                        break
    def quitAlone(self, dumb): 
        sys.stderr.write('user requested quit')
        self.lgr.debug('quitAlone')
        SIM_run_command('q')
   
    def quit(self, cycles=None):
        SIM_run_alone(self.quitAlone, cycles)

    def quitWhenDone(self):
        self.lgr.debug('quitWhenDone set true')
        self.quit_when_done = True

    def getMatchingExitInfo(self):
        return self.sharedSyscall[self.target].getMatchingExitInfo()

    def getDefaultContext(self):
        return self.context_manager[self.target].getDefaultContext()

    def getRESimContext(self):
        return self.context_manager[self.target].getRESimContext()

    def restoreRESimContext(self):
        self.context_manager[self.target].restoreWatchTasks()
        self.context_manager[self.target].watchTasks()

    def preCallFD(self, fd):
        self.rev_to_call[self.target].preCallFD(fd)

    def alterConfig(self, fname, fd):
        ''' run a given simics script while managing reverse execution state '''
        ''' If debugging thread is in the kernel on this FD, roll back to precall '''
        self.preCallFD(fd)
        ''' modify the configuration '''
        cmd = 'run-command-file %s' % fname
        SIM_run_command(cmd)
        ''' Establish a new origin since the above has messed up reverse execution state '''
        self.resetOrigin()

    def addJumper(self, from_bb, to_bb):
        ''' Add a jumper for use in code coverage and AFL, e.g., to skip a CRC '''
        ida_path = self.getIdaData(self.full_path)
        jname = ida_path+'.jumpers'
        if os.path.isfile(jname):
            with open(jname) as fh:
                jumpers = json.load(fh)
        else:
            jumpers = {}
        if from_bb in jumpers:
            print('from_bb 0x%x already in jumpers for %s' % (from_bb, jname))
            return
        else:
            jumpers[from_bb] = to_bb
        with open(jname, 'w') as fh:
            fh.write(json.dumps(jumpers))
        print('add 0x%x => 0x%x to %s' % (from_bb, to_bb, jname))
    
    def getFullPath(self, fname=None):
        # get the full local path.
        if fname is not None:
            retval = self.targetFS[self.target].getFull(fname, lgr=self.lgr)
            self.lgr.debug('getFullPath from targetFS got %s' % retval)
        else:
            retval =  self.full_path
        return retval 

    def frameFromRegs(self):
        reg_frame = self.task_utils[self.target].frameFromRegs()
        return reg_frame

    def getTidsForComm(self, comm):
        plist = self.task_utils[self.target].getTidsForComm(comm)
        return plist

    def resetBookmarks(self):
        self.bookmarks = None

    def instructTrace(self, fname, all_proc=False, kernel=False, just_kernel=False, watch_threads=False, just_tid=None):
        self.instruct_trace = instructTrace.InstructTrace(self, self.lgr, fname, all_proc=all_proc, kernel=kernel, 
                        just_kernel=just_kernel, watch_threads=watch_threads, just_tid=just_tid)
        cpu = self.cell_config.cpuFromCell(self.target)
        cpl = memUtils.getCPL(cpu)
        if cpl != 0 or kernel:
            self.instruct_trace.start() 

    def stopInstructTrace(self):
        self.instruct_trace.endTrace()
        self.instruct_trace = None

    def debugIfNot(self):
        ''' warning, assumes current tid is the one to be debugged. '''
        self.lgr.debug('debugIfNot')
        self.rmDebugWarnHap()
        if self.bookmarks is None:
            cpu, comm, this_tid = self.task_utils[self.target].curThread() 
            print('Will debug tid: %s (%s)' % (this_tid, comm))
            self.lgr.debug('debugIfNot Will debug tid: %s (%s)' % (this_tid, comm))
            self.debug(group=True)
        else:
            print('Already debugging.')

    def debugSnap(self, final_fun=None):
        retval = True
        self.rmDebugWarnHap()
        if self.debug_info is not None and 'pid' in self.debug_info:
            self.debug_info['tid'] = str(self.debug_info['pid'])
        if self.debug_info is not None and 'tid' in self.debug_info:
            self.lgr.debug('debugSnap call debugTidGroup for tid:%s cpu name %s current target %s' % (self.debug_info['tid'], self.debug_info['cpu'], self.target))
            self.debugTidGroup(self.debug_info['tid'], to_user=False, final_fun=final_fun)
            self.lgr.debug('debugSnap did debugTidGroup for tid:%s' % self.debug_info['tid'])
        else:
            self.lgr.error('debugSnap, no debug_info read from snapshot, try using debugIfNot')
            retval = False
        return retval

    def saveDeadCoverage(self):
        ''' force the current dead zone coverage basic blocks to be saved to a file, and quit '''
        self.coverage.saveDeadFile()

    def mergeCover(self, target=None):
        self.debugIfNot()
        self.coverage.mergeCover(target=target)

    def setBreak(self, addr):
        resim = self.getRESimContext()
        #bp = SIM_breakpoint(resim, Sim_Break_Linear, Sim_Access_Execute, addr, self.mem_utils[self.target].WORD_SIZE, 0)
        bp = SIM_breakpoint(resim, Sim_Break_Linear, Sim_Access_Execute, addr, 1, 0)
        print('set execution break at 0x%x bp %d' % (addr, bp))

    def setWriteBreak(self, addr):
        resim = self.getRESimContext()
        bp = SIM_breakpoint(resim, Sim_Break_Linear, Sim_Access_Write, addr, self.mem_utils[self.target].WORD_SIZE, 0)
        print('set write break at 0x%x bp %d' % (addr, bp))


    def showSyscallExits(self):
        exit_list = self.sharedSyscall[self.target].getExitList('traceAll')
        for tid in exit_list:
            frame = exit_list[tid]
            call = self.task_utils[self.target].syscallName(frame['syscall_num'], self.is_compat32)
            self.lgr.debug('showSyscallExits tid:%s  syscall %s' % (tid, call))
            print('tid:%s  syscall %s' % (tid, call))

    def watchTasks(self):
        ''' watch this task and its threads, will append to others if already watching 
        NOTE assumes it is in execve and we want to track SO files
        '''
        self.context_manager[self.target].watchTasks(set_debug_tid=True)
        ''' flist of other than None causes watch of open/mmap for SO tracking '''
        self.execToText(flist=[])

    def watchExit(self):
        tid = self.getTID()
        self.watchingExitTIDs.append(tid)
        self.context_manager[self.target].watchExit(tid=tid)
        self.context_manager[self.target].setExitCallback(self.procExitCallback)

    def procExitCallback(self):
        SIM_break_simulation('proc exit')

    def ni(self):
        eip = self.getEIP()
        cpu = self.cell_config.cpuFromCell(self.target)
        instruct = SIM_disassemble_address(cpu, eip, 1, 0)
        next_ip = eip + instruct[0]
        self.goAddr(next_ip)

    def goAddr(self, addr):
        ''' Run to a given address'''
        cpu = self.cell_config.cpuFromCell(self.target)
        cell = cpu.current_context
        bp = SIM_breakpoint(cell, Sim_Break_Linear, Sim_Access_Execute, addr, self.mem_utils[self.target].WORD_SIZE, 0)
        self.lgr.debug('goAddr break set on 0x%x cell %s' % (addr, cell))
        hap_clean = hapCleaner.HapCleaner(cpu)
        stop_action = hapCleaner.StopAction(hap_clean, [bp])
        self.stop_hap = self.RES_add_stop_callback(self.stopHap, stop_action)
        SIM_continue(0)

    def stopAndMail(self):
        self.stopAndGo(self.skipAndMail)

    def stopAndGo(self, callback):
        ''' Will stop simulation and invoke the given callback once stopped.
            It also calls our stopHap, which 
        '''
        cpu, comm, this_tid = self.task_utils[self.target].curThread() 
        self.lgr.debug('stopAndGo tid %s cycle 0x%x' % (this_tid, cpu.cycles))
        SIM_run_alone(self.stopAndGoAlone, callback)

    def stopAndGoAlone(self, callback, param=None):
        cpu, comm, this_tid = self.task_utils[self.target].curThread() 
        self.lgr.debug('stopAndGoAlone tid %s cycle 0x%x' % (this_tid, cpu.cycles))
        cpu = self.cell_config.cpuFromCell(self.target)
        if param is None:
            call_params = []
        else:
            call_params = [param]
        f1 = stopFunction.StopFunction(callback, call_params, nest=False)
        flist = [f1]
        hap_clean = hapCleaner.HapCleaner(cpu)
        stop_action = hapCleaner.StopAction(hap_clean, flist=flist)
        self.stop_hap = self.RES_add_stop_callback(self.stopHap, stop_action)
        self.lgr.debug('stopAndGoAlone, hap set now stop it')
        SIM_break_simulation('Stopping simulation')

    def stopAndCall(self, callback):
        self.lgr.debug('stopAndCall')
        self.stop_hap = self.RES_add_stop_callback(self.stopAndCallHap, callback)
        SIM_break_simulation('stopAndCall')

    def stopAndCallHap(self, callback, one, exception, error_string):
        if self.stop_hap is not None:
            self.lgr.debug('stopAndCallHap callback is %s' % str(callback))
            hap = self.stop_hap
            self.RES_delete_stop_hap_run_alone(hap)
            self.stop_hap = None
            SIM_run_alone(callback, None)

    def foolSelect(self, fd):
        self.sharedSyscall[self.target].foolSelect(fd)

    def log(self, string):
        rprint(string)

    def injectToBB(self, bb, target=None, targetFD=None, fname=None):
        ibb = injectToBB.InjectToBB(self, bb, self.lgr, target_prog=target, targetFD=targetFD, fname=fname)

    def injectToWM(self, addr, target=None, targetFD=None, max_marks=None, no_reset=False, ws=None):
        iwm = injectToWM.InjectToWM(self, addr, self.dataWatch[self.target], self.lgr, target_prog=target, targetFD=targetFD, max_marks=max_marks, no_reset=no_reset, ws=ws)

    def getParam(self):
        return self.param[self.target]

    def syscallName(self, callnum):
        #self.lgr.debug('syscallName %d' % callnum)
        return self.task_utils[self.target].syscallName(callnum, self.is_compat32) 

    def showLinks(self):
        for computer in self.link_dict:
            print('computer %s' % computer)
            for link in self.link_dict[computer]:
                print('\tlink %s  %s' % (link, self.link_dict[computer][link].name))

    def backtraceAddr(self, addr, cycles):
        ''' Look at watch marks to find source of a given address by backtracking through watchmarks '''
        retval = None
        self.lgr.debug('backtraceAddr %x cycles: 0x%x' % (addr, cycles))
        tm = traceMarks.TraceMarks(self.dataWatch[self.target], self.lgr)
        cpu = self.cell_config.cpuFromCell(self.target)
        if cycles is None:
            cycles = cpu.cycles
        orig, offset = tm.getOrigRead(addr, cycles)
        if orig is None:
            ''' not an original read buffer, find the original via the refs '''
            ref = tm.findRef(addr, cycles)
            if ref is not None:     
                
                self.lgr.debug('backtraceAddr addr 0x%x found in ref %s' % (addr, ref.toString()))
                offset = ref.getOffset(addr) 
                tot_offset = offset + ref.orig_read.prior_bytes_read
                msg = 'The value at 0x%x originated at offset %d into origin within %s' % (addr, offset, ref.toString())
                msg = msg+('\nTotal offset into file is %d (0x%x)' % (tot_offset, tot_offset))
                print(msg)
                self.context_manager[self.target].setIdaMessage(msg)
                self.lgr.debug(msg)
                retval = msg
            else:
                msg = 'Orig buffer not found for addr 0x%x' % addr
                self.lgr.debug(msg)
                self.context_manager[self.target].setIdaMessage(msg)
                print(msg)
        else:
            offset = orig.offset(addr)
            tot_offset = offset + orig.prior_bytes_read
            msg = 'The value at 0x%x is in an original read, offset %d into %s'  % (addr, offset, orig.toString())
            msg = msg+('\nTotal offset into file is %d (0x%x)' % (tot_offset, tot_offset))
            print(msg)
            self.context_manager[self.target].setIdaMessage(msg)
            self.lgr.debug(msg)
            retval = msg
        if self.report_crash is not None:
            self.report_crash.addMsg('Backtrace summary: \n %s' % msg)
        return retval

    def amWatching(self, tid):
        return self.context_manager[self.target].amWatching(tid)

    def doBreak(self, addr, count=1, run=False):
        ''' Set a breakpoint and optional count and stop when it is reached.  The stopTrack function will be invoked.'''
        self.context_manager[self.target].setIdaMessage('')
        cpu = self.cell_config.cpuFromCell(self.target)
        self.user_break = userBreak.UserBreak(self, cpu, addr, count, self.context_manager[self.target], self.lgr)
        self.lgr.debug('doBreak context %s' % cpu.current_context)
        if run:
            SIM_continue(0)

    def delUserBreak(self):
        self.user_break = None

    def didMagicOrigin(self):
        ''' Was the origin ever reset due to executing a magic instruction?'''
        retval = False
        if self.target in self.magic_origin:
            retval = self.magic_origin[self.target].didMagic()
        return retval

    def magicStop(self):
        if self.target not in self.magic_origin:
            cpu = self.cell_config.cpuFromCell(self.target)
            self.magic_origin[self.target] = magicOrigin.MagicOrigin(self, cpu, self.bookmarks, self.lgr)
        self.magic_origin[self.target].magicStop()

    def blackListTid(self, tid):
        self.context_manager[self.target].noWatch(tid)

    def jumper(self, from_addr, to_addr):
        ''' Set a control flow jumper '''
        if self.target not in self.jumper_dict:
            cpu = self.cell_config.cpuFromCell(self.target)
            self.jumper_dict[self.target] = jumpers.Jumpers(self, self.context_manager[self.target], self.soMap[self.target], self.mem_utils[self.target], 
                  self.task_utils[self.target], cpu, self.lgr)
        self.jumper_dict[self.target].setJumper(from_addr, to_addr)
        self.lgr.debug('jumper set')

    def jumperStop(self, target=None):
        self.lgr.debug('jumperStop')
        if target is None:
            target = self.target
        if target in self.jumper_dict:
            self.jumper_dict[target].removeBreaks(immediate=True)

    def jumperDisable(self, target=None):
        if target is None:
            target = self.target
        if target in self.jumper_dict:
            self.jumper_dict[target].disableBreaks()

    def jumperEnable(self, target=None):
        if target is None:
            target = self.target
        if target in self.jumper_dict:
            self.jumper_dict[target].enableBreaks()

    def simicsQuitting(self, one, two):
        print('Simics quitting.')
        self.flushTrace()

    def getFunMgr(self):
        return self.fun_mgr

    def stopStepN(self, dumb, one, exception, error_string):
        if self.stop_hap is not None:
            self.lgr.debug('stopStepN delete stop_hap %d' % self.stop_hap)
            self.RES_delete_stop_hap(self.stop_hap)
            self.stop_hap = None
            self.lgr.debug('stopStepN call skipAndMail')
            self.skipAndMail()

    def stepN(self, n):
        ''' Used by runToSyscall to step out of kernel. '''
        self.lgr.debug('stepN %d' % n)
        flist = [self.skipAndMail]
        f1 = stopFunction.StopFunction(self.skipAndMail, [], nest=False)
        self.stop_hap = self.RES_add_stop_callback(self.stopStepN, None)
        cmd = 'c %d' % n
        SIM_run_alone(SIM_run_command, cmd)
        self.lgr.debug('stepN ran command %s' % cmd)

    def getProgName(self, tid, target=None):
        if target is None:
            target = self.target
        if tid is None:
            self.lgr.debug('genMonitor getProgName tid is none')
            return None
        prog_name = None
        if target in self.soMap:
            prog_name = self.soMap[target].getProg(tid)
        if prog_name is None:
            prog_name = self.traceProcs[target].getProg(tid)
            self.lgr.debug('genMonitor called traceProcs to  getProgName for tid:%s, returned progname is %s' % (tid, prog_name))
        if prog_name is None or prog_name == 'unknown' or prog_name == '<clone>':
            #prog_name = self.soMap[target].getProg(tid)
            #if True or prog_name is None:
            self.lgr.debug('getProgName call to get from traceProcs failed, try taskUtils')
            prog_name, dumb = self.task_utils[target].getProgName(tid) 
            self.lgr.debug('genMonitor getProgName tid:%s NOT in traceProcs task_utils got %s' % (tid, prog_name))
            if prog_name is None:
                comm = self.task_utils[target].getCommFromTid(tid) 
                if comm is None:
                    self.lgr.error('genMonitor getProgName tid:%s on target %s got None' % (tid, target))
                else: 
                    prog_name = self.task_utils[target].getProgNameFromComm(comm) 
                    if prog_name is None:
                        if target in self.soMap:
                            # TBD dependency loop
                            prog_name = self.soMap[target].getFullPath(comm)
                            self.lgr.debug('genMonitor getProgName tid:%s call soMap with comm from getCommFromTid, got %s' % (tid, prog_name))
                        if prog_name is None:
                            prog_name = comm
                            self.lgr.debug('genMonitor getProgName tid:%s reverted to getCommFromTid, got %s' % (tid, prog_name))
                self.traceProcs[target].setName(tid, prog_name, None)
        return prog_name
 
    def getSharedSyscall(self):
        return self.syscallManager[self.target].getSharedSyscall()

    def showDataRange(self, addr):
        self.dataWatch[self.target].showRange(addr)

    def ignoreProg(self, prog):
        self.context_manager[self.target].ignoreProg(prog)

    def runToCycle(self, cycle):
        self.rmDebugWarnHap()
        cpu = self.cell_config.cpuFromCell(self.target)
        if cycle < cpu.cycles:
            print('Cannot use this function to run backwards.')
            return
        delta = cycle - cpu.cycles
        print('will run forward 0x%x cycles' % delta)
        cmd = 'run count = 0x%x unit = cycles' % (delta)
        self.lgr.debug('runToCycle 0x%x cmd %s' % (cycle, cmd))
        SIM_run_command(cmd)
        print('Done, at cycle 0x%x.' % cpu.cycles)

    def runToSeconds(self, seconds):
        self.rmDebugWarnHap()
        cpu = self.cell_config.cpuFromCell(self.target)
        now_string, ret = cli.quiet_run_command('ptime -t')
        #print('now_string is %s ret is %s' % (now_string, ret))
        now = float(now_string)
        want = float(seconds)
        if now > want:
            print('Cannot use this function to run backwards.')
            return
        print('now %.2f  want %.2f' % (now, want))
        delta = want - now
        ms = delta * 1000
        
        print('will run forward %d ms' % int(ms))
        self.lgr.debug('runToSeconds.  Now %s, want %s Will run forward %d ms' % (now, seconds, int(ms)))
        cmd = 'run count = %d unit = ms' % (int(ms))
        SIM_run_command(cmd)
        
    def loadJumpers(self):    
        for target in self.context_manager:
            self.loadJumpersTarget(target)

    def loadJumpersTarget(self, target):    
        if 'EXECUTION_JUMPERS' in self.comp_dict[target]:
            jumper_file = self.comp_dict[target]['EXECUTION_JUMPERS']
            if jumper_file is not None:
                if target not in self.jumper_dict:
                    cpu = self.cell_config.cpuFromCell(target)
                    self.jumper_dict[target] = jumpers.Jumpers(self, self.context_manager[target], self.soMap[target], self.mem_utils[target], 
                             self.task_utils[self.target], cpu, self.lgr)
                    self.jumper_dict[target].loadJumpers(jumper_file)
                    print('Loaded jumpers from %s' % jumper_file)
                else:
                    print('Jumpers for %s already loaded' % target)
            else:
                print('No jumper file defined though ENV set for target %s.' % target)
        else:
            self.lgr.debug('LoadJumpersTarget No EXECUTION_JUMPERS defined for %s' % target)

    def getSyscallEntry(self, callname):
        retval = None
        callnum = self.task_utils[self.target].syscallNumber(callname, self.is_compat32)
        #self.lgr.debug('SysCall doBreaks call: %s  num: %d' % (call, callnum))
        if callnum is not None and callnum < 0:
            self.lgr.error('getSyscallEntry bad call number %d for call <%s>' % (callnum, callname))
        elif callnum is not None:
            retval = self.task_utils[self.target].getSyscallEntry(callnum, self.is_compat32)
        else:
            self.lgr.error('getSyscallEntry got no call number for %s' % callname)
            
        return retval

    def isCode(self, addr, tid=None, target=None):
        if target is None:
            target = self.target
        if tid is None:
            tid = self.getTID()
        return self.soMap[target].isCode(addr, tid)

    def getTargetPlatform(self):
        platform = None
        if 'PLATFORM' in self.comp_dict[self.target]:
            platform = self.comp_dict[self.target]['PLATFORM']
        return platform

    def getTargetEnv(self, name):
        retval = None
        if name in self.comp_dict[self.target]:
            retval = self.comp_dict[self.target][name]
        return retval

    def getReadAddr(self):
        return self.syscallManager[self.target].getReadAddr()

    def showSyscalls(self):
        for cell_name in self.syscallManager:
            print('The syscalls for cell %s:' % cell_name)
            self.syscallManager[cell_name].showSyscalls()

    def showSyscallTraces(self):
        for call in self.call_traces[self.target]:
            print('%s  -- %s' % (call, self.call_traces[self.target][call].name))

    # also see pendingFault
    def hasPendingPageFault(self, tid, target=None):
        if target is None:
            target = self.target
        if tid is None:
            self.lgr.error('hasPendingFault called with tid of None')
            return
        tid_list = self.task_utils[target].getGroupTids(tid)
        self.lgr.debug('hasPendingFault tid %s got list of %d tids' % (tid, len(tid_list))) 
        for t in tid_list:
            fault = self.page_faults[target].hasPendingPageFault(t)
        
            if fault:
                return True
        return False

    def getCred(self):
        return self.task_utils[self.target].getCred()

    def trackProgArgs(self):
        ''' Assuming the process is at start, track references to its argsv '''
        self.dataWatch[self.target].watchArgs()
    def trackCGIArgs(self):
        ''' Assuming the process is at start, track references to its argsv '''
        self.dataWatch[self.target].watchCGIArgs()

    def hasProcHap(self):
        if self.proc_hap is None:
            return False
        else:
            return True

    def showFuns(self, search=None):
        if self.fun_mgr is not None:
            self.fun_mgr.showFuns(search = search)
        else:
            print('No IDA functions loaded.')

    def showRelocate(self, search=None):
        self.fun_mgr.showRelocate(search=search)

    def showMangle(self, search=None):
        if self.fun_mgr is not None:
            self.fun_mgr.showMangle(search = search)
        else:
            print('No IDA functions loaded.')

    def isFun(self, addr):
        if self.fun_mgr.isFun(addr):
            print('Yes, 0x%x is a function' % addr)
        else:
            print('No, 0x%x is not a function' % addr)

    def getFunName(self, addr):
        retval = None
        if self.fun_mgr is None:
            self.lgr.error('getFunName No function manager yet, are you debugging?')
        else:
            retval = self.fun_mgr.getFunName(addr)
        return retval

    def getFun(self, addr):
        #fname = self.fun_mgr.getFunName(addr)
        if self.fun_mgr is None:
            print('No function manager yet, are you debugging?')
            return
        fun_name = self.fun_mgr.funFromAddr(addr)
        if fun_name is not None:
            entry = self.fun_mgr.getFunEntry(fun_name)
            print('Function for address 0x%x is %s, entry 0x%x' % (addr, fun_name, entry))
        elif self.isVxDKM():
            fun_name = self.task_utils[self.target].getGlobalSym(addr)
            print('Function for address 0x%x is VxWorks symbol %s' % (addr, fun_name))
            
        if fun_name is None:
            so = self.soMap[self.target].getSOInfo(addr)
            if so is not None:
                print('No function for 0x%x (perhaps no analysis?).  Program is %s' % (addr, so))
            else:
                print('No function or program found for address 0x%x' % addr)

    def rmDebugWarnHap(self):
        if self.snap_warn_hap is not None:
            self.rmWarnHap(self.snap_warn_hap)
            self.snap_warn_hap = None

    def rmWarnHap(self, hap):
        RES_hap_delete_callback_id("Core_Continuation", hap)

    def warnSnapshotHap(self, stop_action, one):
        #self.lgr.debug('warnSnapShot')
        if self.snap_warn_hap is None:
            return
        if not self.context_manager[self.target].didListLoad():
            debug_tid, dumb = self.context_manager[self.target].getDebugTid() 
            if debug_tid is None and self.debug_info is not None and 'tid' in self.debug_info:
                print('Warning snapshot exists but not debugging.  Running will lose state (e.g., threads waiting in the kernel.')
                print('Continue again to go on.  Will not be warned again this session.')
                SIM_break_simulation('stopped')
        SIM_run_alone(self.rmWarnHap, self.snap_warn_hap)
        self.snap_warn_hap = None

    def warnSnapshot(self):
        #self.snap_warn_hap = RES_hap_add_callback("Core_Continuation", self.warnSnapshotHap, None)
        # TBD RESTORE THIS
        pass

    def overrideBackstopCallback(self, callback):
        self.lgr.debug('overrideBackstopCallback with %s' % str(callback))
        self.back_stop[self.target].overrideCallback(callback)

    def restoreBackstopCallback(self):
        self.back_stop[self.target].restoreCallback()

    def findKernelEntry(self):
        self.found_entries = []
        cpu = self.cell_config.cpuFromCell(self.target)
        self.mode_hap = RES_hap_add_callback_obj("Core_Mode_Change", cpu, 0, self.modeChangeFindEntry, None)
        self.stop_hap = self.RES_add_stop_callback(self.stopFindEntry, None)

    def modeChangeFindEntry(self, dumb, one, old, new):
        target_cpu = self.cell_config.cpuFromCell(self.target)
        cpu, comm, tid = self.task_utils[self.target].curThread() 
        if new == Sim_CPU_Mode_Supervisor:
            SIM_break_simulation('mode changed')

    def stopFindEntry(self, stop_action, one, exception, error_string):
        cpu, comm, tid = self.task_utils[self.target].curThread() 
        eip = self.getEIP()
        if eip in self.found_entries:
            SIM_run_alone(SIM_continue, 0)
            return
        self.found_entries.append(eip)
        instruct = SIM_disassemble_address(cpu, eip, 1, 0)
        if eip not in [self.param[self.target].arm_entry, self.param[self.target].arm_svc, self.param[self.target].data_abort, self.param[self.target].page_fault]:
            self.lgr.debug('stopFindEntry tid:%s eip 0x%x %s' % (tid, eip, instruct[1]))
            print('stopFindEntry tid:%s eip 0x%x %s' % (tid, eip, instruct[1]))
        else:
            SIM_run_alone(SIM_continue, 0)

    def isMainText(self, address):
        return self.soMap[self.target].isMainText(address)
   
    def setPacketNumber(self, packet_number):
        if self.coverage is not None:
            self.coverage.setPacketNumber(packet_number)

    def getPhys(self, linear):
        cpu, comm, tid = self.task_utils[self.target].curThread() 
        phys_block = cpu.iface.processor_info.logical_to_physical(linear, Sim_Access_Read)
        print('0x%x' % phys_block.address)

    def readReplace(self, fname, cell_name=None, snapshot=None):
        if not os.path.isfile(fname):
            return False
        if cell_name is None:
            cell_name = self.target
        self.lgr.debug('readReplace %s' % fname)
        cpu, comm, tid = self.task_utils[cell_name].curThread() 
        self.read_replace[cell_name] = readReplace.ReadReplace(self, cpu, cell_name, fname, self.soMap[cell_name], self.mem_utils[cell_name], self.lgr, snapshot=snapshot)
        return True

    def regSet(self, fname, cell_name=None, snapshot=None):
        if not os.path.isfile(fname):
            return False
        if cell_name is None:
            cell_name = self.target
        self.lgr.debug('regSet %s' % fname)
        cpu, comm, tid = self.task_utils[cell_name].curThread() 
        self.reg_set[cell_name] = regSet.RegSet(self, cpu, cell_name, fname, self.mem_utils[self.target], self.soMap[cell_name], self.lgr, snapshot=snapshot)
        return True

    def testSnap(self):
        self.debugSnap()
        ts = testSnap.TestSnap(self, self.coverage, self.back_stop[self.target], self.lgr) 
        ts.go()
        self.lgr.debug('done')
        print('done')

    def curTaskTest(self):
        if self.param[self.target].current_task_fs:
            cpu, comm, tid = self.task_utils[self.target].curThread() 
            phys = cpu.ia32_fs_base + (self.param[self.target].current_task-self.param[self.target].kernel_base)
            print('current task phys addr is 0x%x' % phys)

    def getIdaData(self, path, target=None):
        if target is None:
            target = self.target
        self.lgr.debug('getIdaData path %s' % path)
        root_prefix = self.comp_dict[target]['RESIM_ROOT_PREFIX']
        ida_path = resimUtils.getIdaData(path, root_prefix, lgr=self.lgr)
        return ida_path

    def isWindows(self, target=None, cpu=None):
        retval = False
        if cpu is not None:
            target = self.getTopComponentName(cpu)
        elif target is None:
            target = self.target
        #self.lgr.debug('isWindows os type of %s is %s' % (target, self.os_type[target]))
        if self.os_type[target].startswith('WIN'):
            retval = True
        return retval

    def isVxDKM(self, target=None, cpu=None):
        retval = False
        if cpu is not None:
            target = self.getTopComponentName(cpu)
        elif target is None:
            target = self.target
        if self.os_type[target].startswith('VXWORKS_DKM'):
            retval = True
        return retval

    def getWin7CallParams(self, stop_on=None, only=None, only_proc=None, track_params=False, this_tid=False):
        ''' Use breakpoints set on the user space to identify call parameter 
            Optional stop_on will stop on exit from call'''
        if self.target in self.winMonitor:
            self.rmDebugWarnHap()
            self.checkOnlyIgnore()
            self.winMonitor[self.target].getWin7CallParams(stop_on, only, only_proc, track_params, this_tid=this_tid)

    def rmCallParamBreaks(self):
        self.lgr.debug('rmCallparamBreaks (genMonitor)')
        self.winMonitor[self.target].rmCallParamBreaks()

    def isIA32E(self):
        target_cpu = self.cell_config.cpuFromCell(self.target)
        isit = pageUtils.isIA32E(target_cpu)
        print('isIA32E: %r' % isit)

    def listRegNames(self):
        target_cpu = self.cell_config.cpuFromCell(self.target)
        for i in range(200):
            reg_name = target_cpu.iface.int_register.get_name(i)
            print('%d %s' % (i, reg_name))

    def wordSize(self, tid, target=None):
        if target is None:
            target = self.target
        retval = self.soMap[target].wordSize(tid)
        return retval

    def wordSizexx(self):
        target_cpu = self.cell_config.cpuFromCell(self.target)
        ws = self.mem_utils[self.target].wordSize(target_cpu)
        print('word size: %d' % ws)
        reg_num = target_cpu.iface.int_register.get_number("cs_limit")
        cs = target_cpu.iface.int_register.read(reg_num)
        print('cs 0x%x' % cs)

    def findThreads(self):
        thread_dict = self.task_utils[self.target].findThreads(quiet=False)
        return thread_dict

    def showThreads(self):
        self.task_utils[self.target].showThreads()

    def showTidsForComm(self, comm_in):
        self.task_utils[self.target].showTidsForComm(comm_in)

    def isReverseExecutionEnabled(self):
        return self.rev_execution_enabled

    def traceWindows(self, track_threads=True):
        if self.target in self.trace_all:
            print('Already tracing windows')
            return
        tid, cpu = self.context_manager[self.target].getDebugTid() 
        self.traceBufferTarget(self.target)
        if tid is None:
            self.checkOnlyIgnore()
        self.trace_all[self.target]=self.winMonitor[self.target].traceWindows()
        if track_threads:
            self.trackThreads()
        self.lgr.debug('traceWindows set trace_all[%s] to %s' % (self.target, str(self.trace_all[self.target])))

    ''' Hack to catch erzat syscall from application with 9999 as syscall number for purpose of locating program text section load address'''
    def catchEnter(self):
        cpu = self.cell_config.cpuFromCell(self.target)
        self.mode_hap = RES_hap_add_callback_obj("Core_Mode_Change", cpu, 0, self.catchEnterHap, None)
        self.traceWindows()
        self.allowReverse() 

    def catchEnterHap(self, dumb, one, old, new):
        self.lgr.debug('catchEnterHap new mode: %s' % str(new))
        if new == Sim_CPU_Mode_Supervisor:
            cpu = self.cell_config.cpuFromCell(self.target)
            callnum = self.mem_utils[self.target].getRegValue(cpu, 'syscall_num')
            if callnum == 9999:
                SIM_break_simulation('0x4254, is that you?')
                SIM_run_alone(self.cleanMode, None)
                self.syscallManager[self.target].rmAllSyscalls()

    def setFullPath(self, full_path):
        self.full_path = full_path
        self.lgr.debug('setFullPath to %s' % full_path)

    def ignoreProgList(self):
        retval = False
        if 'SKIP_PROGS' in self.comp_dict[self.target]: 
            sfile = self.comp_dict[self.target]['SKIP_PROGS']
            retval = self.context_manager[self.target].loadIgnoreList(sfile)
            if retval:
                print('Loaded list of programs to ignore from %s' % sfile)
        return retval

    def ignoreThreadList(self):
        retval = False
        if 'SKIP_THREADS' in self.comp_dict[self.target]: 
            sfile = self.comp_dict[self.target]['SKIP_THREADS']
            retval = self.context_manager[self.target].loadIgnoreThreadList(sfile)
            if retval:
                print('Loaded list of threads to ignore from %s' % sfile)
        return retval

    def onlyProgList(self):
        retval = False
        if 'ONLY_PROGS' in self.comp_dict[self.target]: 
            sfile = self.comp_dict[self.target]['ONLY_PROGS']
            retval = self.context_manager[self.target].loadOnlyList(sfile)
            if retval:
                print('Loaded list of programs to watch from %s (all others will be ignored).' % sfile)
        return retval

    def getCompDict(self, target, item):
        retval = None
        if target in self.comp_dict and item in self.comp_dict[target]: 
            retval = self.comp_dict[target][item]
        return retval

    def didDebug(self):
        return self.did_debug

    def isRunningTo(self):
        return self.run_to[self.target].isRunningTo()

    def setOriginWhenStopped(self):
        self.run_to[self.target].setOriginWhenStopped()

    def up(self):
        self.stackFrameManager[self.target].up()

    def down(self):
        self.stackFrameManager[self.target].down()

    def dumpStack(self, count=80, fname=None):
        self.stackFrameManager[self.target].dumpStack(count, fname=fname)

    def tracking(self):
        return self.track_started

    def runToSO(self, file, threads=False):
        self.rmDebugWarnHap()
        tid_list = None
        self.run_to[self.target].runToSO(file, threads=threads)

    def runToMainSO(self, threads=True):
        self.rmDebugWarnHap()
        tid_list = None
        self.run_to[self.target].runToMainSO(threads=threads)
  
    def traceSO(self, threads=True):
        if self.checkOnlyIgnore():
            self.rmDebugWarnHap()
        tid_list = None
        self.run_to[self.target].traceSO(threads=threads)

    def skipToCycle(self, cycle, cpu=None, disable=False):
        if cpu is None:
            cpu = self.cell_config.cpuFromCell(self.target)
            # assumption called by user, so reset watches
            self.stopTracking()
            self.lgr.debug('skipToCycle did stopTracking')
        self.context_manager[self.target].setReverseContext()
        if disable:
            self.context_manager[self.target].disableAll()
        else:
            # assume user invoked, make sure we are not tracking, or that will mess things up
            self.stopTracking()
            self.lgr.debug('skipToCycle assume user invoked did stopTracking')
        retval = self.skip_to_mgr[self.target].skipToTest(cycle)
        self.context_manager[self.target].clearReverseContext()
        if disable:
            self.context_manager[self.target].enableAll()
        self.lgr.debug('skipToCycle done wanted cycle 0x%x' % cycle)
        return retval

    def cutRealWorld(self):
        self.lgr.debug('cutRealWorld')
        print('Cutting links to real networks')
        if self.target in self.magic_origin:
            self.magic_origin[self.target].deleteMagicHap() 
        resimSimicsUtils.cutRealWorld()

    def runTo32(self):
        self.run_to[self.target].runTo32()

    def getWordSize(self):
        cpu, comm, tid = self.task_utils[self.target].curThread() 
        retval = self.soMap[self.target].wordSize(tid)
        return retval

    def runToWriteNotZero(self, addr):
        self.run_to[self.target].runToWriteNotZero(addr)

    def getAnalysisPath(self, fname):
        if fname is not None:
            analysis_path = self.soMap[self.target].getAnalysisPath(fname)
            if analysis_path is None:
                self.lgr.debug('getAnalysisPath failed to get path from soMap for %s' % fname)
        else:
            analysis_path = None
        return analysis_path

    def traceBuffer(self):
        for target in self.context_manager:
            self.traceBufferTarget(target)

    def traceBufferTarget(self, target, msg=None):
        if 'TRACE_BUFFERS' in self.comp_dict[target]:
            trace_buffer_file = self.comp_dict[target]['TRACE_BUFFERS']
            if trace_buffer_file is not None and target not in self.trace_buffers:
                cpu= self.cell_config.cpuFromCell(target)
                self.trace_buffers[target] = traceBuffer.TraceBuffer(self, trace_buffer_file, cpu, target, self.mem_utils[target], self.context_manager[target], self.soMap[target], self.lgr, msg=msg)
                return self.trace_buffers[target]
        return None

    def traceBufferMarks(self, target=None):
        if target is None:
            target = self.target
        if target in self.trace_buffers:
            self.lgr.debug('traceBufferMarks for target %s.' % target)
            self.trace_buffers[target].markLogs(self.dataWatch[target])
        else:
            self.lgr.debug('traceBufferMarks target %s not in trace_buffers' % target)

    def toRunningProc(self, proc, plist, flist):
        self.run_to[self.target].toRunningProc(proc, plist, flist)
    
    def parseTarget(self, target):
        self.lgr.debug('parseTarget %s' % target) 
        target_cell = self.target
        target_proc = None
        if target is not None:
            if ':' in target:
                parts = target.rsplit(':',1)
                target_cell = parts[0]
                target_proc = parts[1]
            else:
                target_proc = target
            self.lgr.debug('parseTarget target_cell %s target_proc %s' % (target_cell, target_proc))

        this_cpu, comm, tid = self.task_utils[self.target].curThread() 
        if target_cell != self.target:
            target_cpu = self.cell_config.cpuFromCell(target_cell)
            if target_cpu is None:
                self.lgr.error('Component %s not found' % target_cell)
                self.quit()
        else:
            target_cpu = this_cpu

        return target_cell, target_proc, target_cpu, this_cpu

    def setTargetToDebugger(self):
        self.lgr.debug('setTargetToDebugger %s' % self.debugger_target)
        self.setTarget(self.debugger_target)

    def getBytes(self, target, cpu, count, addr):
        return self.mem_utils[target].getBytes(cpu, count, addr)

    def addPageProbe(self, addr, target=None):
        if target is None:
            target = self.target
        if target in self.page_faults:
            self.page_faults[target].addProbe(addr)
            self.lgr.debug('addPageProbe cell %s addr 0x%x' % (target, addr))

    def toFun(self, fun_name):
        addr = self.getFunEntry(fun_name)
        if addr is not None:
            self.lgr.debug('toFun %s 0x%x' % (fun_name, addr))
            self.goAddr(addr)

    def showFunEntries(self, fun_name):
        self.fun_mgr.showFunAddrs(fun_name)

    def getFunEntry(self, fun_name):
        ''' get the entry of a given function name, with preference to the largest function '''
        if self.fun_mgr is None:
            self.lgr.error('getFunEntry, no function manager')
            return None
        return self.fun_mgr.getFunEntry(fun_name)


    def curThreadRec(self):
        cur_thread_rec = self.task_utils[self.target].getCurThreadRec()
        phys_current_task = self.task_utils[self.target].getPhysCurrentTask()

        cpu = self.cell_config.cpuFromCell(self.target)
        mem_cur_task = self.mem_utils[self.target].getCurrentTask(cpu)
        print('cur_thread_rec 0x%x  phys_current_task 0x%x mem_cur_task: 0x%x' % (cur_thread_rec, phys_current_task, mem_cur_task))

    def debugging(self):
        retval = False
        debug_tid, dumb = self.context_manager[self.target].getDebugTid() 
        if debug_tid is None:
            debug_tid = self.context_manager[self.target].getSavedDebugTid() 
            self.lgr.debug('genMonitor debugging ? context manager returned None for getDebugTid, tried getting saved and got %s' % (debug_tid))
        if debug_tid is not None:
            retval = True
        return retval

    def haltCoverage(self):
        if self.coverage is not None:
            self.coverage.haltCoverage()

    def brokenAFL(self):
        self.lgr.debug('brokenAFL')
        if self.afl_instance is not None:
            self.afl_instance.saveThisData()
            self.quit() 

    def curThread(self, target_cpu=None):
        if target_cpu is None:
            target = self.target
        else:
            target = self.cell_config.cellFromCPU(target_cpu)
        cpu, comm, this_tid = self.task_utils[target].curThread() 
        return cpu, comm, this_tid

    def runToReturn(self):
        cpu = self.cell_config.cpuFromCell(self.target)
        rtr = runToReturn.RunToReturn(self, cpu, self.task_utils[self.target], 
                     self.param[self.target].kernel_base, self.context_manager[self.target], self.lgr)
        self.lgr.debug('runToReturn breaks set now continue')
        SIM_continue(0)

    def recordLogEvents(self, obj):
        fname = 'logs/%s.log' % obj
        cpu = self.cell_config.cpuFromCell(self.target)
        rle = recordLogEvents.RecordLogEvents(fname, obj, 4, cpu, self.lgr)

    def pageCallback(self, addr, callback, name=None, use_pid=None, writable=True):
        # TBD pass cell name and set for any target!
        if self.target in self.page_callbacks:
            self.page_callbacks[self.target].setCallback(addr, callback, name=name, use_pid=use_pid, writable=writable)
        else:
            self.lgr.error('pageCallback called, but no page_callbacks are set')

    def getTIB(self):
        return self.task_utils[self.target].getTIB()

    def getThraedRec(self):
        if self.target in self.task_utils:
            rec = self.task_utils[self.target].getCurThreadRec()
            print('thread rec is 0x%x' % rec)

    def getCurProcRec(self):
        if self.target in self.task_utils:
            return self.task_utils[self.target].getCurProcRec()
        else:
            return None

    def getProcRecForTid(self, cpu, tid):
        cell_name = self.getTopComponentName(cpu)
        return self.task_utils[cell_name].getProcRecForTid(tid)
         
    def hasUserPageTable(self, cpu=None):
        retval = False
        if cpu is None:
            cell_name = self.target
        else:
            cell_name = self.getTopComponentName(cpu)
        if self.isWindows(cell_name):
            #if hasattr(self.param[cell_name], 'page_table') and self.param[cell_name].page_table is not None:
            retval = True
        else:
            if hasattr(self.param[cell_name], 'mm_struct') and self.param[cell_name].mm_struct is not None:
                retval = True
        return retval

    def getSnapVersion(self):
        return self.snap_version
  
    def trackingThreads(self):
        if self.track_threads is None or self.target not in self.track_threads:
            return False
        else:
            return True

    def hasAFL(self):
        if self.afl_instance is None:
            return False
        else:
            return True

    def getFunWithin(self, fun_name, start, end):
        return self.fun_mgr.getFunWithin(fun_name, start, end)

    def getSnapProg(self):
        ''' get the program that was being debugged when the snapshot was made'''
        retval = None
        if self.debug_info is not None and 'tid' in self.debug_info:
            tid = self.debug_info['tid']
            leader_tid = self.task_utils[self.target].getGroupLeaderTid(tid)
            if leader_tid is None:
                self.lgr.error('getSnapProg leader_tid is None, asked about %s' % tid)
            else: 
                retval = self.soMap[self.target].getProg(leader_tid)
        return retval

    def getProgPath(self, prog_in, target=None):
        retval = None
        if target is None:
            target = self.target
        self.lgr.debug('getProgPath cell %s for %s' % (target, prog_in))
        if prog_in is not None:
            retval = self.soMap[target].getFullPath(prog_in)
            if retval is None:
                retval = self.getFullPath(fname=prog_in)
        else:
            self.lgr.debug('getProgPath for None')
        return retval

    def findBytes(self, byte_string):
        byte_array = bytes.fromhex(byte_string)
        print('len of byte_array %d' % len(byte_array))
        load_info = self.soMap[self.target].getLoadInfo()
        base = load_info.addr
        print('start at 0x%x' % base)
        cpu = self.cell_config.cpuFromCell(self.target)
        for i in range(2000000):
            running = ''
            offset=0
            got_one = True
            for b in byte_array:
                mem_byte = self.mem_utils[self.target].readByte(cpu, base+i+offset)
                #print('compare b 0x%x to mem 0x%x' % (b, mem_byte))
                if b != mem_byte:
                    got_one = False
                    break
                else:
                    hexval = '%2x' % b
                    running = running + hexval
                    if offset > 0:
                        print('matched %s offset %d' % (running, offset))
                    offset = offset + 1
            if got_one:
                print('got one at 0x%x' % (base+i))
                break

    def loopN(self, count):
        if self.target not in self.loop_n:
            self.loop_n[self.target] = loopN.LoopN(self, count, self.mem_utils[self.target], self.context_manager[self.target], self.lgr)
        else:
            self.loop_n[self.target].go()

    def isLibc(self, addr, target_cpu=None):
        if target_cpu is None:
            target = self.target
        else:
            target = self.cell_config.cellFromCPU(target_cpu)
        return self.soMap[target].isLibc(addr)

    def spotFuzz(self, fuzz_addr, break_at, data_length=4, reg=None, fail_break=None):
        self.rmDebugWarnHap()
        cpu = self.cell_config.cpuFromCell(self.target)
        spotFuzz.SpotFuzz(self, cpu, self.mem_utils[self.target], self.context_manager[self.target], self.back_stop[self.target], 
             fuzz_addr, break_at, self.lgr, reg=reg, data_length=data_length, fail_break=fail_break)

    def clearExitTid(self):
        self.task_utils[self.target].clearExitTid()
    
    def diagHits(self):
        self.coverage.diagHits()    

    def getSyscallManager(self):
        return self.syscallManager[self.target]

    def disassembleAddress(self, cpu, addr):
        target = self.cell_config.cellFromCPU(cpu)
        return self.disassemble_instruct[target].getDisassemble(addr)

    def traceFuns(self):
        self.fun_mgr.traceFuns()
  
    def showOrig(self, pc): 
        if self.isVxDKM():
            self.vxKMonitor[self.target].origOffset()

    def trackFile(self, substring):
        ''' track access to a file'''
        self.lgr.debug('trackFile') 
        self.setCommandCallback(self.trackIO)
        self.runToOpen(substring)    

    def watchHack(self):
        self.vxKMonitor[self.target].watchHack()
   
    def maxMarks(self, max_marks):
        self.max_marks = max_marks 

    def noReset(self):
        self.no_reset = True

    def findRefs(self, offset):
        marks = self.dataWatch[self.target].getAllJson()
        refs = findRefs.FindRefs(offset, marks, self.lgr)

    def rev1(self):
        cpu = self.cell_config.cpuFromCell(self.target)
        back_one = cpu.cycles - 1
        self.skipToCycle(back_one, cpu=cpu)

    def findText(self):
        cpu = self.cell_config.cpuFromCell(self.target)
        findText.FindText(self, cpu, self.mem_utils[self.target], self.soMap[self.target], self.lgr)

    def stackAdjust(self, fun_name):
        adjust = self.fun_mgr.stackAdjust(fun_name)
        print('adjust 0x%x' % adjust)

    def traceWrite(self, msg):
        if self.target in self.traceMgr:
            self.traceMgr[self.target].write(msg)

    def recordEntry(self, dumb=None):
        ''' record syscall entries '''
        if self.reverseEnabled():
            self.lgr.debug('recordEntry')
            self.record_entry[self.target].watchSysenter()
        else:
            print('Reverse execution is not enabled.')

    def enableReverse(self):
        self.reverse_mgr[self.target].enableReverse()

    def disableReverse(self):
        self.reverse_mgr[self.target].disableReverse()

    def skipTo(self, cycle):
        self.reverse_mgr[self.target].skipToCycle(cycle)

    def reverse(self):
        self.reverse_mgr[self.target].reverse()

    def revOne(self):
        self.lgr.debug('revOne')
        self.context_manager[self.target].disableAll()
        self.context_manager[self.target].setReverseContext()
        self.reverse_mgr[self.target].revOne()
        self.context_manager[self.target].enableAll()
        self.context_manager[self.target].clearReverseContext()
        self.lgr.debug('revOne done')

    def timer(self, cycles):
        target_cpu = self.cell_config.cpuFromCell(self.target)
        delta_time, delta_sim_time, ram_use = resimSimicsUtils.timer(target_cpu, cycles)
        slowdown = delta_time / delta_sim_time
        storage = self.reverse_mgr[self.target].snapSize()
        span = self.reverse_mgr[self.target].getSpan()
        print('Timer 0x%x cycles in %f.3 seconds; slowdown %f.2  snapshot storage: %s ram use: %s span 0x%x' % (cycles, delta_time, 
              slowdown, f"{storage:,}", f"{ram_use:,}", span))

    def snapSize(self):
        storage = self.reverse_mgr[self.target].snapSize()
        print('Snapshot storage using %s bytes' % f"{storage:,}")

    def recordDriverServerVersion(self):
        resim_dir = os.getenv('RESIM_DIR')
        driver_version = os.path.join(resim_dir, 'simics', 'bin', 'driver_server_version')
        current_version = os.path.join('./', '.driver_server_version')
        shutil.copyfile(driver_version, current_version)

    def runCommandFile(self, fname):
        cmd = 'run-command-file %s' % fname
        SIM_run_command(cmd)

    def shutUpConsole(self):
        for cell in self.conf.sim.cell_list:
            object_cell = cell.name.split('.')[0]
            self.lgr.debug('shutUpConsole cell %s' % object_cell)
            cmd = '%s.serconsole.con.disable-cmd-line-output' % object_cell
            SIM_run_command(cmd)

    def version(self):
        return self.reverse_mgr[self.target].version()
    def nativeReverse(self, target=None):
        if target is None:
            target = self.target
        return self.reverse_mgr[target].nativeReverse()
    def takeSnapshot(self, name, target=None):
        if target is None:
            target = self.target
        return self.reverse_mgr[target].takeSnapshot(name)
    def restoreSnapshot(self, name, target=None):
        if target is None:
            target = self.target
        return self.reverse_mgr[target].restoreSnapshot(name)

    def watchWrite(self, start, count):
        target_cpu = self.cell_config.cpuFromCell(self.target)
        self.watch_write = watchWrite.WatchWrite(self, target_cpu, self.context_manager[self.target], self.lgr)
        self.watch_write.watchRange(start, count)

    def noExitMaze(self):
        if self.target in self.trace_all:
            self.trace_all[self.target].noExitMaze()

    def getTraceFiles(self):
        if self.target in self.traceFiles:
            return self.traceFiles[self.target]
        else:
            return None

    def watchingExitTid(self, tid):
        if tid in self.watchingExitTIDs:
            return True
        else:
            return False

    def noPrep(self):
        # TBD fix to look for afl.pickle instead of naming convention
        if self.run_from_snap is not None and ('prep_' in self.run_from_snap or '_prep' in self.run_from_snap):
            print('Current snapshot looks like a prep inject.  Exiting.')
            self.lgr.debug('Current snapshot looks like a prep inject, bail.')
            self.quit()

    def adjustParams(self):
        for cell_name in self.cell_config.cell_context:
            if cell_name in self.mem_utils:
                cpu = self.cell_config.cpuFromCell(cell_name)
                self.mem_utils[cell_name].adjustParam(cpu)

    def doInUser(self, callback, param, tid=None, target=None):
        if target is None:
            target = self.target
        cpu = self.cell_config.cpuFromCell(target)
        self.lgr.debug('doInUser')
        doInUser.DoInUser(self, cpu, callback, param, self.task_utils[target], self.mem_utils[target], self.lgr, tid=tid)

    def RES_delete_stop_hap(self, hap):
        self.pending_stop_hap = None
        SIM_hap_delete_callback_id('Core_Simulation_Stopped', hap)
        self.lgr.debug('RES_delete_stop_hap')

    def RES_delete_stop_hap_run_alone(self, hap):
        # race condition of 2 stop haps existing?
        self.pending_stop_hap = None
        self.lgr.debug('RES_delete_stop_hap_run_alone')
        SIM_run_alone(RES_delete_stop_hap, hap)

    def RES_add_stop_callback(self, callback, param):
        retval = None
        if self.pending_stop_hap is not None:
            self.lgr.error('RES_add_stop_callback called for %s, but already pending stop with callback %s!' % (str(callback), str(self.pending_stop_hap)))
            self.quit()
        else:
            retval = SIM_hap_add_callback('Core_Simulation_Stopped', callback, param)
            self.pending_stop_hap = callback
            self.lgr.debug('RES_add_stop_callback for %s' % str(callback))
        return retval

    def stepOver(self):
        cpu = self.cell_config.cpuFromCell(self.target)
        eip = self.getEIP()
        instruct = SIM_disassemble_address(cpu, eip, 1, 0)
        if instruct[1].startswith('call') or instruct[1].startswith('bl '):
            next_eip = eip + instruct[0]
            self.doBreak(next_eip)
            SIM_continue(0)
        else:
            self.stepN(1)


if __name__=="__main__":        
    print('instantiate the GenMonitor') 
    cgc = GenMonitor()
    cgc.doInit()
    print('Done with initialization')
