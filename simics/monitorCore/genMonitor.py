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
from resimUtils import rprint
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
import userIterators
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
import syscallManager
import testSnap
import winTaskUtils
import winMonitor
import winDLLMap
import runTo
import winProg
import stackFrameManager

#import fsMgr
import json
import pickle
import re
import shutil
import imp
import glob
import inspect


class Prec():
    def __init__(self, cpu, proc, pid=None, who=None):
        self.cpu = cpu
        self.proc = proc
        self.pid = pid
        self.who = who
        self.debugging = False


class GenMonitor():
    ''' Top level RESim class '''
    SIMICS_BUG=False
    PAGE_SIZE = 4096
    def __init__(self, comp_dict, link_dict, cfg_file):
        self.comp_dict = comp_dict
        self.link_dict = link_dict
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
                self.one_done_module = imp.load_source(one_done_script, abs_path)
                self.lgr.debug('onedone found at %s' % abs_path)
            else:
                self.lgr.error('no onedone found for %s' % one_done_script)
        else:
            self.lgr.debug('No ONE_DONE_SCRIPT, must be interactive session.')

        self.injectIOInstance = None
        ''' retrieved from snapshot pickle, not necessarily current '''
        self.debug_info = None
  
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

        self.os_type = {}

        ''' catch-all for windows monitoring commands '''
        self.winMonitor = {}

        ''' Once data tracking seems to have completed, e.g., called goToDataMark,
            do not set debug related haps
        '''
        self.track_started = False
        self.track_finished = False

        ''' ****NO init data below here**** '''
        self.lgr.debug('genMonitor call genInit')
        self.genInit(comp_dict)
        exit_hap = RES_hap_add_callback("Core_At_Exit", self.simicsQuitting, None)

        ''' ****NO init data here**** '''

    def genInit(self, comp_dict):
        self.is_monitor_running = isMonitorRunning.isMonitorRunning(self.lgr)
        SIM_run_command("bp.delete -all")
        self.target = os.getenv('RESIM_TARGET')
        print('using target of %s' % self.target)
        self.cell_config = cellConfig.CellConfig(list(comp_dict.keys()))
        target_cpu = self.cell_config.cpuFromCell(self.target)
        self.lgr.debug('New log, in genInit')
        self.run_from_snap = os.getenv('RUN_FROM_SNAP')
        self.binders = binder.Binder(self.lgr)
        self.connectors = connector.Connector(self.lgr)
        if self.run_from_snap is not None:
            self.lgr.debug('genInit running from snapshot %s' % self.run_from_snap)
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
            connector_file = os.path.join('./', self.run_from_snap, 'connector.json')
            if os.path.isfile(connector_file):
                self.connectors.loadJson(connector_file)
            binder_file = os.path.join('./', self.run_from_snap, 'binder.json')
            if os.path.isfile(binder_file):
                self.binders.loadJson(binder_file)
            for cell_name in comp_dict:
                param_file = os.path.join('./', self.run_from_snap, cell_name, 'param.pickle')
                if os.path.isfile(param_file):
                    self.param[cell_name] = pickle.load(open(param_file, 'rb'))
                    self.lgr.debug('Loaded params for cell %s from pickle' % cell_name)
                    self.lgr.debug(self.param[cell_name].getParamString())
                else:
                    self.lgr.debug('No param pickle at %s' % param_file)
                         
        for cell_name in comp_dict:
            self.lgr.debug('genInit for cell %s' % (cell_name))
            if 'RESIM_PARAM' in comp_dict[cell_name] and cell_name not in self.param:
                param_file = comp_dict[cell_name]['RESIM_PARAM']
                print('Cell %s using params from %s' % (cell_name, param_file))
                self.lgr.debug('Cell %s using params from %s' % (cell_name, param_file))
                if not os.path.isfile(param_file):
                    print('Could not find param file at %s -- it will not be monitored' % param_file)
                    self.lgr.debug('Could not find param file at %s -- it will not be monitored' % param_file)
                    continue
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

                ''' always true? TBD '''
                self.param[cell_name].ts_state = 0

                self.lgr.debug(self.param[cell_name].getParamString())
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
            self.mem_utils[cell_name] = memUtils.memUtils(word_size, self.param[cell_name], self.lgr, arch=cpu.architecture, cell_name=cell_name)
            if self.os_type[cell_name].startswith('LINUX'):
                if 'RESIM_UNISTD' not in comp_dict[cell_name]:
                    print('Target is missing RESIM_UNISTD path')
                    self.quit()
                    return
                self.unistd[cell_name] = comp_dict[cell_name]['RESIM_UNISTD']
                if 'RESIM_UNISTD_32' in comp_dict[cell_name]:
                    self.unistd32[cell_name] = comp_dict[cell_name]['RESIM_UNISTD_32']
                if 'RESIM_ROOT_PREFIX' not in comp_dict[cell_name]:
                    print('Target missing RESIM_ROOT_PREFIX path')
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
                self.targetFS[cell_name] = winTargetFS.TargetFS(self, root_prefix, root_subdirs)
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

    def runPreScripts(self):
        ''' run the PRE_INIT_SCRIPT and the one_done module, if any '''
        init_script = os.getenv('PRE_INIT_SCRIPT')
        if init_script is not None:
            cmd = 'run-command-file %s' % init_script
            SIM_run_command(cmd)
            self.lgr.debug('ran PRE_INIT_SCRIPT %s' % init_script)
    def runScripts(self):
        ''' run the INIT_SCRIPT and the one_done module, if iany '''
        init_script = os.getenv('INIT_SCRIPT')
        if init_script is not None:
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
        cpu, comm, this_pid = self.task_utils[self.target].curProc() 
        eip = self.mem_utils[self.target].getRegValue(cpu, 'eip')
        instruct = SIM_disassemble_address(cpu, eip, 1, 0)
        self.lgr.debug('stopModeChanged eip 0x%x %s' % (eip, instruct[1]))
        #SIM_run_alone(SIM_continue, 0)

    def modeChangeReport(self, want_pid, one, old, new):
        cpu, comm, this_pid = self.task_utils[self.target].curProc() 
        if want_pid != this_pid:
            #self.lgr.debug('mode changed wrong pid, wanted %d got %d' % (want_pid, this_pid))
            return
        new_mode = 'user'
        eip = self.mem_utils[self.target].getRegValue(cpu, 'eip')
        callnum = self.mem_utils[self.target].getRegValue(cpu, 'syscall_num')
        #self.lgr.debug('modeChangeReport new mode: %s get phys of eip: 0x%x' % (new_mode, eip))
        phys = self.mem_utils[self.target].v2p(cpu, eip)
        if phys is not None:
            instruct = SIM_disassemble_address(cpu, phys, 0, 0)
            self.lgr.debug('modeChangeReport new mode: %s  eip 0x%x %s --  eax 0x%x' % (new_mode, eip, instruct[1], callnum))
        else:
            self.lgr.debug('modeChangeReport new mode: %s  eip 0x%x eax 0x%x  Failed getting phys for eip' % (new_mode, eip, callnum))
        if new == Sim_CPU_Mode_Supervisor:
            new_mode = 'kernel'
            SIM_break_simulation('mode changed')

    def modeChanged(self, want_pid, one, old, new):
        dumb, comm, this_pid = self.task_utils[self.target].curProc() 
        cpu = self.cell_config.cpuFromCell(self.target)
        ''' note may both be None due to failure of getProc '''
        if want_pid != this_pid:
            ''' or just want may be None if debugging some windows dead zone '''
            if want_pid is None and this_pid is not None:
                SIM_break_simulation('mode changed, pid was None, now is not none.')
                
            self.lgr.debug('mode changed wrong pid, wanted %d got %d' % (want_pid, this_pid))
            return
        cpl = memUtils.getCPL(cpu)
        eip = self.mem_utils[self.target].getRegValue(cpu, 'eip')
        mode = 1
        if new == Sim_CPU_Mode_Supervisor:
            mode = 0
        phys = self.mem_utils[self.target].v2p(cpu, eip)
        if phys is None:
            self.lgr.debug('modeChanged failed to get phys addr for 0x%x' % eip)
            SIM_break_simulation('bad phys')
            return
        instruct = SIM_disassemble_address(cpu, phys, 0, 0)
        self.lgr.debug('mode changed cpl reports %d hap reports %d  trigger_obj is %s old: %d  new: %d  eip: 0x%x ins: %s' % (cpl, 
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
        dumb, comm, pid = self.task_utils[self.target].curProc() 
        ''' note, curProc may fail, best effort for debugging why it failed.'''
        cpu = self.cell_config.cpuFromCell(self.target)
        wrong_pid = False
        if stop_action.pid is not None and pid != stop_action.pid:
            ''' likely some other pid in our group '''
            wrong_pid = True
        eip = self.getEIP(cpu)
        self.lgr.debug('genMonitor stopHap pid %s eip 0x%x cycle: 0x%x wrong_pid: %r' % (pid, eip, stop_action.hap_clean.cpu.cycles, wrong_pid))
        for hc in stop_action.hap_clean.hlist:
            if hc.hap is not None:
                if hc.htype == 'GenContext':
                    self.lgr.debug('genMonitor stopHap stopAction delete GenContext hap %s' % str(hc.hap))
                    self.context_manager[self.target].genDeleteHap(hc.hap)
                else:
                    self.lgr.debug('genMonitor stopHap stopAction will delete hap %s type %s' % (str(hc.hap), str(hc.htype)))
                    RES_hap_delete_callback_id(hc.htype, hc.hap)
                hc.hap = None
        if self.stop_hap is not None:
            self.lgr.debug('genMonitor stopHap will delete hap %s' % str(self.stop_hap))
            RES_hap_delete_callback_id("Core_Simulation_Stopped", self.stop_hap)
            self.stop_hap = None
        for bp in stop_action.breakpoints:
            RES_delete_breakpoint(bp)
        del stop_action.breakpoints[:]
        self.is_compat32 = self.compat32()
        ''' check functions in list '''
        self.lgr.debug('stopHap compat32 is %r now run actions %s wrong_pid %r' % (self.is_compat32, stop_action.listFuns(), wrong_pid))
        stop_action.run(wrong_pid=wrong_pid)
        self.is_monitor_running.setRunning(False)
        self.lgr.debug('stopAlone back from stop_action.run')

        if stop_action.pid is not None and pid != stop_action.pid:
            self.lgr.debug('stopHap wrong pid %d expected %d reverse til we find pid ' % (pid, stop_action.pid))
            ''' set up for revToPid, set function to the wrong_pid_action '''
            hap_clean = hapCleaner.HapCleaner(cpu)
            f1 = stopFunction.StopFunction(stop_action.wrong_pid_action, [], nest=False, match_pid=True)
            new_stop_action = hapCleaner.StopAction(hap_clean, None, pid=stop_action.pid, wrong_pid_action=stop_action.wrong_pid_action)
            SIM_run_alone(self.revToPid, stop_action)
            return

    def revToPid(self, pid):
        cpu, comm, cur_pid = self.task_utils[self.target].curProc() 
        phys_current_task = self.task_utils[self.target].getPhysCurrentTask()
        self.proc_break = SIM_breakpoint(cpu.physical_memory, Sim_Break_Physical, Sim_Access_Write, 
                             phys_current_task, self.mem_utils[self.target].WORD_SIZE, 0)
        hap_clean = hapCleaner.HapCleaner(cpu)
        ''' when we stop, rev 1 to revert the current task value '''
        stop_action = hapCleaner.StopAction(hap_clean, [self.proc_break], pid=pid, prelude=self.rev1NoMail)
        self.stop_hap = RES_hap_add_callback("Core_Simulation_Stopped", self.stopHap, stop_action)
        self.lgr.debug('revToPid hap set, break on 0x%x now reverse' % phys_current_task)
        SIM_run_command('rev')

    def stopAndAction(self, stop_action):
        self.lgr.debug('stopAndAction')
        self.stop_hap = RES_hap_add_callback("Core_Simulation_Stopped", 
        	     self.stopHap, stop_action)
        self.lgr.debug('stopAndAction set stop_hap is now %d  now stop' % self.stop_hap)
        SIM_break_simulation('stopAndAction')

    def run2Kernel(self, cpu):
        cpl = memUtils.getCPL(cpu)
        if cpl != 0:
            dumb, comm, pid = self.task_utils[self.target].curProc() 
            self.lgr.debug('run2Kernel in user space (%d), set hap' % cpl)
            self.mode_hap = RES_hap_add_callback_obj("Core_Mode_Change", cpu, 0, self.modeChanged, pid)
            hap_clean = hapCleaner.HapCleaner(cpu)
            hap_clean.add("Core_Mode_Change", self.mode_hap)
            stop_action = hapCleaner.StopAction(hap_clean, None)
            self.stop_hap = RES_hap_add_callback("Core_Simulation_Stopped", 
        	     self.stopHap, stop_action)
            SIM_continue(0)
        else:
            self.lgr.debug('run2Kernel, already in kernel')

    def run2User(self, cpu, flist=None):
        cpl = memUtils.getCPL(cpu)
        if cpl == 0:
            dumb, dumb, pid = self.task_utils[self.target].curProc() 
            ''' use debug process if defined, otherwise default to current process '''
            debug_pid, dumb = self.context_manager[self.target].getDebugPid() 
            if debug_pid is not None:
                if debug_pid != pid:
                    self.lgr.debug('debug_pid %d  pid %d' % (debug_pid, pid))
                    ''' debugging, but not this pid.  likely a clone '''
                    if not self.context_manager[self.target].amWatching(pid):
                        ''' stick with original debug pid '''
                        pid = debug_pid
                    
            self.mode_hap = RES_hap_add_callback_obj("Core_Mode_Change", cpu, 0, self.modeChanged, pid)
            self.lgr.debug('run2User pid %d in kernel space (%d), set mode hap %d' % (pid, cpl, self.mode_hap))
            hap_clean = hapCleaner.HapCleaner(cpu)
            # fails when deleted? 
            hap_clean.add("Core_Mode_Change", self.mode_hap)
            stop_action = hapCleaner.StopAction(hap_clean, None, flist)
            self.stop_hap = RES_hap_add_callback("Core_Simulation_Stopped", 
        	     self.stopHap, stop_action)
            self.lgr.debug('run2User added stop_hap of %d' % self.stop_hap)
            simics_status = SIM_simics_is_running()
            if not simics_status:
                SIM_run_alone(SIM_continue, 0)
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
 
            tu_cur_task_rec = self.task_utils[cell_name].getCurTaskRec()
            if tu_cur_task_rec is None:
                self.lgr.error('could not read tu_cur_task_rec from taskUtils')
                return
            self.traceMgr[cell_name] = traceMgr.TraceMgr(self.lgr)
            #if self.param[cell_name].fs_base is None:
            #    cur_task_rec = self.mem_utils[cell_name].getCurrentTask(cpu)
            #    #self.lgr.debug('stack based rec was 0x%x  mine is 0x%x' % (cur_task_rec, tu_cur_task_rec))

            ''' manages setting haps/breaks based on context swtiching.  TBD will be one per cpu '''
        
            self.context_manager[cell_name] = genContextMgr.GenContextMgr(self, cell_name, self.task_utils[cell_name], self.param[cell_name], cpu, self.lgr) 
            self.page_faults[cell_name] = pageFaultGen.PageFaultGen(self, cell_name, self.param[cell_name], self.cell_config, self.mem_utils[cell_name], 
                   self.task_utils[cell_name], self.context_manager[cell_name], self.lgr)
            self.rev_to_call[cell_name] = reverseToCall.reverseToCall(self, cell_name, self.param[cell_name], self.task_utils[cell_name], self.mem_utils[cell_name],
                 self.PAGE_SIZE, self.context_manager[cell_name], 'revToCall', self.is_monitor_running, None, self.log_dir, self.is_compat32, self.run_from_snap)
            self.pfamily[cell_name] = pFamily.Pfamily(cell, self.param[cell_name], cpu, self.mem_utils[cell_name], self.task_utils[cell_name], self.lgr)
            self.traceOpen[cell_name] = traceOpen.TraceOpen(self.param[cell_name], self.mem_utils[cell_name], self.task_utils[cell_name], cpu, cell, self.lgr)
            #self.traceProcs[cell_name] = traceProcs.TraceProcs(cell_name, self.lgr, self.proc_list[cell_name], self.run_from_snap)
            self.traceProcs[cell_name] = traceProcs.TraceProcs(cell_name, self.context_manager[cell_name], self.task_utils[cell_name], self.lgr, run_from_snap = self.run_from_snap)
            if self.isWindows():
                self.soMap[cell_name] = winDLLMap.WinDLLMap(self, cpu, cell_name, self.mem_utils[cell_name], self.task_utils[cell_name], self.run_from_snap, self.lgr)
            else:
                self.soMap[cell_name] = soMap.SOMap(self, cell_name, cell, cpu, self.context_manager[cell_name], self.task_utils[cell_name], self.targetFS[cell_name], self.run_from_snap, self.lgr)
            self.back_stop[cell_name] = backStop.BackStop(self, cpu, self.lgr)
            self.dataWatch[cell_name] = dataWatch.DataWatch(self, cpu, cell_name, self.PAGE_SIZE, self.context_manager[cell_name], 
                  self.mem_utils[cell_name], self.task_utils[cell_name], self.rev_to_call[cell_name], self.param[cell_name], 
                  self.run_from_snap, self.back_stop[cell_name], self.is_compat32, self.lgr)
            self.trackFunction[cell_name] = trackFunctionWrite.TrackFunctionWrite(cpu, cell, self.param[cell_name], self.mem_utils[cell_name], 
                  self.task_utils[cell_name], 
                  self.context_manager[cell_name], self.lgr)
            self.traceFiles[cell_name] = traceFiles.TraceFiles(self.traceProcs[cell_name], self.lgr)
            self.sharedSyscall[cell_name] = sharedSyscall.SharedSyscall(self, cpu, cell, cell_name, self.param[cell_name], 
                  self.mem_utils[cell_name], self.task_utils[cell_name], 
                  self.context_manager[cell_name], self.traceProcs[cell_name], self.traceFiles[cell_name], 
                  self.soMap[cell_name], self.dataWatch[cell_name], self.traceMgr[cell_name], self.lgr)

            self.syscallManager[cell_name] = syscallManager.SyscallManager(self, cpu, cell_name, self.param[cell_name], self.mem_utils[cell_name], self.task_utils[cell_name],
                                     self.context_manager[cell_name], self.traceProcs[cell_name], self.sharedSyscall[cell_name], self.lgr, self.traceMgr[cell_name], self.soMap[cell_name], 
                                     self.is_compat32, self.targetFS[cell_name], self.os_type[cell_name])

            self.reverseTrack[cell_name] = reverseTrack.ReverseTrack(self, self.dataWatch[cell_name], self.context_manager[cell_name], 
                  self.mem_utils[cell_name], self.rev_to_call[cell_name], self.lgr)

            self.run_to[cell_name] = runTo.RunTo(self, cpu, cell, self.task_utils[cell_name], self.mem_utils[cell_name], self.context_manager[self.target], 
                                        self.soMap[self.target], self.traceMgr[self.target], self.param[self.target], self.lgr)
            self.stackFrameManager[cell_name] = stackFrameManager.StackFrameManager(self, cpu, cell_name, self.task_utils[cell_name], self.mem_utils[cell_name], 
                                        self.context_manager[self.target], self.soMap[self.target], self.targetFS[cell_name], self.run_from_snap, self.lgr)
            ''' TBD compatability remove this'''
            if self.stack_base is not None and cell_name in self.stack_base:
                self.stackFrameManager[cell_name].initStackBase(self.stack_base[cell_name])

            #self.track_threads[self.target] = trackThreads.TrackThreads(self, cpu, self.target, None, self.context_manager[self.target], 
            #        self.task_utils[self.target], self.mem_utils[self.target], self.param[self.target], self.traceProcs[self.target], 
            #        self.soMap[self.target], self.targetFS[self.target], self.sharedSyscall[self.target], self.syscallManager[self.target], self.is_compat32, self.lgr)

            if self.isWindows():
                self.winMonitor[cell_name] = winMonitor.WinMonitor(self, cpu, cell_name, self.param[cell_name], self.mem_utils[cell_name], self.task_utils[cell_name], 
                                               self.syscallManager[cell_name], self.traceMgr[cell_name], self.traceProcs[cell_name], self.context_manager[cell_name], 
                                               self.soMap[self.target], self.sharedSyscall[self.target], self.run_from_snap, self.lgr)
            self.lgr.debug('finishInit is done for cell %s' % cell_name)
            if self.run_from_snap is not None:
                dmod_file = os.path.join('./', self.run_from_snap, 'dmod.pickle')
                if os.path.isfile(dmod_file):
                    dmod_dict = pickle.load( open(dmod_file, 'rb') )
                    for dmod_path in dmod_dict[cell_name]:
                        self.runToDmod(dmod_path, cell_name=cell_name)
            self.handleMods(cell_name)
            


    def getBootCycleChunk(self):
        run_cycles =  900000000
        for cell_name in self.cell_config.cell_context:
            if cell_name in self.task_utils:
                continue
            if 'BOOT_CHUNKS' in self.comp_dict[cell_name]:
               new = self.comp_dict[cell_name]['BOOT_CHUNKS']
               new = int(new)
               self.lgr.debug('getBootCycleChunk, yes new is %d' % new)
               run_cycles = min(run_cycles, new)
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
                if cell_name in self.task_utils:
                    ''' already got taskUtils for this cell '''
                    continue
                cpu = self.cell_config.cpuFromCell(cell_name)
                self.snap_start_cycle[cpu] = cpu.cycles
                if self.os_type[cell_name].startswith('LINUX'):
                    unistd32 = None
                    if cell_name in self.unistd32:
                        unistd32 = self.unistd32[cell_name]
                    task_utils = taskUtils.TaskUtils(cpu, cell_name, self.param[cell_name], self.mem_utils[cell_name], 
                        self.unistd[cell_name], unistd32, self.run_from_snap, self.lgr)
                    self.task_utils[cell_name] = task_utils
                elif self.isWindows():
                    self.task_utils[cell_name] = winTaskUtils.WinTaskUtils(cpu, cell_name, self.param[cell_name],self.mem_utils[cell_name], self.run_from_snap, self.lgr) 
                else:
                    self.lgr.error('snapInit unknown os type %s' % self.os_type)
                    return
                self.lgr.debug('snapInit for cell %s, now call to finishInit' % cell_name)
                self.finishInit(cell_name)

 
    def doInit(self):
        ''' Entry point from launchRESim '''
        self.lgr.debug('genMonitor doInit')
        if self.run_from_snap is not None:
            self.snapInit()
            self.runScripts()
            return
        run_cycles = self.getBootCycleChunk()
        done = False
        self.runPreScripts()
        #self.fs_mgr = fsMgr.FSMgr(self.cell_config.cell_context, self.param, self.cell_config, self.lgr)
        while not done:
            done = True
            for cell_name in self.cell_config.cell_context:
                if cell_name not in self.param:
                    ''' not monitoring this cell, no param file '''
                    continue
                if cell_name in self.task_utils:
                    ''' already got taskUtils for this cell '''
                    self.lgr.debug('already got %s' % cell_name)
                    continue
                cpu = self.cell_config.cpuFromCell(cell_name)
                ''' run until we get something sane '''
                eip = self.getEIP(cpu)
                cpl = memUtils.getCPL(cpu)
                if cpl == 0 and not self.mem_utils[cell_name].isKernel(eip):
                    self.lgr.debug('doInit cell %s cpl 0 but not in kernel code yet eip 0x%x cycles: 0x%x' % (cell_name, eip, cpu.cycles))
                    done = False
                    continue
                self.lgr.debug('doInit cell %s get current task from mem_utils eip: 0x%x cpl: %d' % (cell_name, eip, cpl))
                cur_task_rec = None
                cur_task_rec = self.mem_utils[cell_name].getCurrentTask(cpu)
                if cur_task_rec is None or cur_task_rec == 0:
                    #print('Current task not yet defined, continue')
                    self.lgr.debug('doInit Current task for %s not yet defined, continue' % cell_name)
                    done = False
                elif cur_task_rec == -1:
                    self.lgr.error('debugging')
                    SIM_break_simulation('remove this') 
                else:
                    pid = self.mem_utils[cell_name].readWord32(cpu, cur_task_rec + self.param[cell_name].ts_pid)
                    if pid is None:
                        #self.lgr.debug('doInit cell %s cur_task_rec 0x%x pid None ' % (cell_name, cur_task_rec))
                        done = False
                        continue
                    ''' TBD clean this up '''
                    self.lgr.debug('doInit cell %s pid is %d' % (cell_name, pid))
                    '''
                    phys = self.mem_utils[cell_name].v2p(cpu, self.param[cell_name].current_task)
                    tu_cur_task_rec = self.mem_utils[cell_name].readPhysPtr(cpu, phys)
                    if tu_cur_task_rec is None:
                        self.lgr.debug('doInit cell %s cur_task_rec 0x%x pid %d but None from task_utils ' % (cell_name, cur_task_rec, pid))
                        done = False
                        continue
                    self.lgr.debug('doInit cell %s cur_task_rec 0x%x pid %d from task_utils 0x%x   current_task: 0x%x (0x%x)' % (cell_name, 
                           cur_task_rec, pid, tu_cur_task_rec, self.param[cell_name].current_task, phys))
                    if tu_cur_task_rec != 0:
                        if cur_task_rec != tu_cur_task_rec:
                            self.lgr.debug('doInit memUtils getCurrentTaskRec does not match found at para.current_task, try again')
                            pid = self.mem_utils[cell_name].readWord32(cpu, cur_task_rec + self.param[cell_name].ts_pid)
                            tu_pid = self.mem_utils[cell_name].readWord32(cpu, tu_cur_task_rec + self.param[cell_name].ts_pid)
                            self.lgr.debug('pid %s  tu_pid %s' % (str(pid), str(tu_pid)))
                            #SIM_break_simulation('no match')
                            done = False
                            continue
                    '''
                    if True:
                        unistd32 = None
                        if cell_name in self.unistd32:
                            unistd32 = self.unistd32[cell_name]
                        task_utils = taskUtils.TaskUtils(cpu, cell_name, self.param[cell_name], self.mem_utils[cell_name], 
                            self.unistd[cell_name], unistd32, self.run_from_snap, self.lgr)
                        swapper = task_utils.findSwapper()
                        if swapper is None:
                            self.lgr.debug('doInit cell %s taskUtils failed to get swapper, hack harder' % cell_name)
                            done = False
                        else: 
                            tasks = task_utils.getTaskStructs()
                            if len(tasks) == 1:
                                self.lgr.debug('doInit cell %s taskUtils got swapper, but no other process, hack harder' % cell_name)
                                done = False
                        
                            else:
                                self.task_utils[cell_name] = task_utils
                                saved_cr3 = self.mem_utils[cell_name].getKernelSavedCR3()
                                if saved_cr3 is not None:
                                    self.lgr.debug('doInit saved_cr3 is 0x%x' % saved_cr3)
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
                dumb, ret = cli.quiet_run_command(cmd)
                #self.lgr.debug('back from continue')
        self.runScripts()

    def handleMods(self, cell_name):
        ''' Load DMODs.  Snapshot contains dmod state, so only load if not a snapshot '''
        if self.run_from_snap is None and 'DMOD' in self.comp_dict[cell_name]:
            self.is_monitor_running.setRunning(False)
            dlist = self.comp_dict[cell_name]['DMOD'].split(';')
            for dmod in dlist:
                dmod = dmod.strip()
                if self.runToDmod(dmod, cell_name=cell_name):
                    print('Dmod %s pending for cell %s, need to run forward' % (dmod, cell_name))
                else:
                    print('Dmod is missing, cannot continue.')
                    self.quit()
        ''' Load readReplace items. '''
        if 'READ_REPLACE' in self.comp_dict[cell_name]:
            self.is_monitor_running.setRunning(False)
            dlist = self.comp_dict[cell_name]['READ_REPLACE'].split(';')
            for read_replace in dlist:
                read_replace = read_replace.strip()
                if self.readReplace(read_replace, cell_name=cell_name, snapshot=self.run_from_snap):
                    print('ReadReplace %s set for cell %s' % (read_replace, cell_name))
                else:
                    print('ReadReplace file %s is missing, cannot continue.' % read_replace)
                    self.quit()
       
    def getDbgFrames(self):
        retval = {}
        plist = {}
        pid_list = self.context_manager[self.target].getThreadPids()
        tasks = self.task_utils[self.target].getTaskStructs()
        self.lgr.debug('getDbgFrames')
        plist = {}
        for t in tasks:
            if tasks[t].pid in pid_list:
                plist[tasks[t].pid] = t 
        for pid in sorted(plist):
            t = plist[pid]
            if tasks[t].state > 0:
                frame, cycles = self.rev_to_call[self.target].getRecentCycleFrame(pid)
                if frame is not None:
                    retval[pid] = frame
        return retval 

    def getRecentEnterCycle(self):
        ''' return latest cycle in which the kernel was entered for this PID 
            regardless of the current cycle.  '''
        cpu, comm, pid = self.task_utils[self.target].curProc() 
        frame, cycles = self.rev_to_call[self.target].getRecentCycleFrame(pid)
        return frame, cycles

    def getPreviousEnterCycle(self):
        ''' return most recent cycle in which the kernel was entered for this PID 
            relative to the current cycle.  '''
        cpu, comm, pid = self.task_utils[self.target].curProc() 
        frame, cycles = self.rev_to_call[self.target].getPreviousCycleFrame(pid)
        return frame, cycles

    def revToSyscall(self):
        frame, cycles = self.getPreviousEnterCycle()
        self.lgr.debug('revToSyscal got cycles 0x%x' % cycles)
        cpu, comm, pid = self.task_utils[self.target].curProc() 
        prev = cycles-1
        resimUtils.skipToTest(cpu, prev, self.lgr)
        print('Reversed to previous syscall:') 
        self.lgr.debug('Reversed to previous syscall:') 
        call = self.task_utils[self.target].syscallName(frame['syscall_num'], self.is_compat32)
        if call == 'socketcall' or call.upper() in net.callname:
            if 'ss' in frame:
                ss = frame['ss']
                socket_callnum = frame['param1']
                socket_callname = net.callname[socket_callnum].lower()
                print('\tpid: %d syscall %s %s fd: %d sp: 0x%x pc: 0x%x cycle: 0x%x' % (pid, 
                     call, socket_callname, ss.fd, frame['sp'], frame['pc'], cycles))
            else:
                print('\tpid: %d socketcall but no ss in frame?' % pid)
        else:
            print('\tpid: %d syscall %s param1: %d sp: 0x%x pc: 0x%x cycle: 0x%x' % (pid, 
                 call, frame['param1'], tasks[t].addr, frame['sp'], frame['pc'], cycles))

    def tasksDBG(self):
        plist = {}
        pid_list = self.context_manager[self.target].getThreadPids()
        tasks = self.task_utils[self.target].getTaskStructs()
        self.lgr.debug('tasksDBG, pid_list is %s' % str(pid_list))
        print('Status of debugging threads')
        plist = {}
        for t in tasks:
            if tasks[t].pid in pid_list:
                plist[tasks[t].pid] = t 
        for pid in sorted(plist):
            t = plist[pid]
            if tasks[t].state > 0:
                frame, cycles = self.rev_to_call[self.target].getRecentCycleFrame(pid)
                if frame is None:
                    print('frame for %d was none' % pid)
                    continue
                call = self.task_utils[self.target].syscallName(frame['syscall_num'], self.is_compat32)
                if call == 'socketcall' or call.upper() in net.callname:
                    if 'ss' in frame:
                        ss = frame['ss']
                        socket_callnum = frame['param1']
                        socket_callname = net.callname[socket_callnum].lower()
                        print('pid: %d syscall %s %s fd: %d task_addr: 0x%x sp: 0x%x pc: 0x%x cycle: 0x%x state: %d' % (pid, 
                             call, socket_callname, ss.fd, tasks[t].addr, frame['sp'], frame['pc'], cycles, tasks[t].state))
                    else:
                        print('pid: %d socketcall but no ss in frame?' % pid)
                else:
                    print('pid: %d syscall %s param1: %d task_addr: 0x%x sp: 0x%x pc: 0x%x cycle: 0x%x state: %d' % (pid, 
                         call, frame['param1'], tasks[t].addr, frame['sp'], frame['pc'], cycles, tasks[t].state))
            else:
                print('pid: %d in user space?' % pid)

    def getThreads(self):
        ''' Return a json rep of tasksDBG '''
        plist = {}
        pid_list = self.context_manager[self.target].getThreadPids()
        tasks = self.task_utils[self.target].getTaskStructs()
        self.lgr.debug('getThreads, pid_list is %s' % str(pid_list))
        plist = {}
        for t in tasks:
            if tasks[t].pid in pid_list:
                plist[tasks[t].pid] = t 
        retval = []
        for pid in sorted(plist):
            pid_state = {} 
            pid_state['pid'] = pid
            t = plist[pid]
            if tasks[t].state > 0:
                frame, cycles = self.rev_to_call[self.target].getRecentCycleFrame(pid)
                if frame is None:
                    #print('frame for %d was none' % pid)
                    continue
                call = self.task_utils[self.target].syscallName(frame['syscall_num'], self.is_compat32)
                if call == 'socketcall' or call.upper() in net.callname:
                    if 'ss' in frame:
                        ss = frame['ss']
                        socket_callnum = frame['param1']
                        socket_callname = net.callname[socket_callnum].lower()
                        pid_state['call'] = socket_callname
                        pid_state['fd'] = ss.fd
                        pid_state['sp'] = frame['sp']
                        pid_state['pc'] = frame['pc']
                        pid_state['cycles'] = cycles
                        pid_state['state'] = tasks[t].state
                        #print('pid: %d syscall %s %s fd: %d task_addr: 0x%x sp: 0x%x pc: 0x%x cycle: 0x%x state: %d' % (pid, 
                        #     call, socket_callname, ss.fd, tasks[t].addr, frame['sp'], frame['pc'], cycles, tasks[t].state))
                    else:
                        print('pid: %d socketcall but no ss in frame?' % pid)
                else:
                    #print('pid: %d syscall %s param1: %d task_addr: 0x%x sp: 0x%x pc: 0x%x cycle: 0x%x state: %d' % (pid, 
                    #     call, frame['param1'], tasks[t].addr, frame['sp'], frame['pc'], cycles, tasks[t].state))
                    pid_state['call'] = call
                    pid_state['param1'] = frame['param1']
                    pid_state['sp'] = frame['sp']
                    pid_state['pc'] = frame['pc']
                    pid_state['cycles'] = cycles
                    pid_state['state'] = tasks[t].state
            else:
                pid_state['call'] = None
                #print('pid: %d in user space?' % pid)
            retval.append(pid_state)
        print(json.dumps(retval))

    def tasks(self, target=None):
        self.lgr.debug('tasks')
        if target is None:
            target = self.target
        print('Tasks on cell %s' % target)

        if self.isWindows():
            self.winMonitor[target].tasks()
        else:
            tasks = self.task_utils[target].getTaskStructs()
            plist = {}
            for t in tasks:
                plist[tasks[t].pid] = t 
            for pid in sorted(plist):
                t = plist[pid]
                uid, e_uid = self.task_utils[target].getCred(t)
                if uid is not None:
                    id_str = 'uid: %d  euid: %d' % (uid, e_uid)        
                else:
                    id_str = ''
                print('pid: %d taks_rec: 0x%x  comm: %s state: %d next: 0x%x leader: 0x%x parent: 0x%x tgid: %d %s' % (tasks[t].pid, t, 
                    tasks[t].comm, tasks[t].state, tasks[t].next, tasks[t].group_leader, tasks[t].real_parent, tasks[t].tgid, id_str))
            

    def setDebugBookmark(self, mark, cpu=None, cycles=None, eip=None, steps=None):
        self.lgr.debug('setDebugBookmark')
        SIM_run_command('enable-reverse-execution')
        pid, cpu = self.context_manager[self.target].getDebugPid() 
        self.bookmarks.setDebugBookmark(mark, cpu=cpu, cycles=cycles, eip=eip, steps=steps, msg=self.context_manager[self.target].getIdaMessage())

    def debugGroup(self):
        self.debug(group=True)

    def doDebugCmd(self, pid = None):
            ''' Note, target may not be currently scheduled '''
            cpu, comm, this_pid = self.task_utils[self.target].curProc() 
            if pid is None:
                pid = this_pid 
            self.lgr.debug('doDebugCmd for cpu %s port will be %d.  Pid is %d compat32 %r' % (cpu.name, self.gdb_port, pid, self.is_compat32))
            if self.bookmarks is None:
                if cpu.architecture == 'arm':
                    cmd = 'new-gdb-remote cpu=%s architecture=arm port=%d' % (cpu.name, self.gdb_port)
                #elif self.mem_utils[self.target].WORD_SIZE == 8 and not self.is_compat32:
                elif self.isWindows:
                    machine_size = self.soMap[self.target].getMachineSize(pid)
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
                SIM_run_command(cmd)
                self.bookmarks = bookmarkMgr.bookmarkMgr(self, self.context_manager[self.target], self.lgr)

    def setPathToProg(self, pid):
        prog_name = self.getProgName(pid)
        if self.targetFS[self.target] is not None and prog_name is not None:
            full_path = self.targetFS[self.target].getFull(prog_name, self.lgr)
            self.full_path = full_path
            self.lgr.debug('setPathToProg pid:%d set full_path to %s' % (pid, full_path))

    def debug(self, group=False):
        '''
        Called when process is ready to be debugged, often as the last item in a hap chain.  The process
        has likely populated its shared libraries and has just returned back to its text segment.
         
        '''
    
        self.lgr.debug('genMonitor debug group is %r' % group)
        #self.stopTrace()    
        cell = self.cell_config.cell_context[self.target]
        cpu = self.cell_config.cpuFromCell(self.target)
        if self.target not in self.magic_origin:
            self.magic_origin[self.target] = magicOrigin.MagicOrigin(self, cpu, self.bookmarks, self.lgr)
        if not self.disable_reverse:
            self.rev_to_call[self.target].setup(cpu, [], bookmarks=self.bookmarks, page_faults = self.page_faults[self.target])
        if not self.did_debug:
            ''' Our first debug '''
            cpu, comm, pid = self.task_utils[self.target].curProc() 
            self.setPathToProg(pid)
            self.lgr.debug('genMonitor debug call doDebugCmd')
            self.doDebugCmd()
            self.did_debug=True
            if not self.rev_execution_enabled:
                self.lgr.debug('debug enable reverse execution')
                ''' only exception is AFL coverage on target that differs from consumer of injected data '''
                cmd = 'enable-reverse-execution'
                SIM_run_command(cmd)
                self.rev_execution_enabled = True
                #self.setDebugBookmark('origin', cpu)
                self.bookmarks.setOrigin(cpu)
            ''' tbd, this is likely already set by some other action, no harm '''
            self.context_manager[self.target].watchTasks()
            self.context_manager[self.target].setDebugPid()
            self.context_manager[self.target].restoreDebugContext()
            self.debug_breaks_set = True

            if group:
                leader_pid = self.task_utils[self.target].getGroupLeaderPid(pid)
                pid_list = self.task_utils[self.target].getGroupPids(leader_pid)
                self.lgr.debug('genManager debug, will debug entire process group under leader %d %s' % (leader_pid, str(pid_list)))
                for pid in pid_list:
                    self.context_manager[self.target].addTask(pid)

            ''' keep track of threads within our process that are created during debug session '''
            cpl = memUtils.getCPL(cpu)
            if cpl == 0:
                self.lgr.warning('debug: not in user space, x86 32-bit compat mode may miss clones')


            self.syscallManager[self.target].rmSyscall('runToText')
            #if 'open' in self.call_traces[self.target]:
            #    self.stopTrace(syscall = self.call_traces[self.target]['open'])
            self.lgr.debug('genMonitor debug removed open/mmap syscall, now track threads')

            self.trackThreads()
            ''' By default, no longer watch for new SO files '''
            self.track_threads[self.target].stopSOTrack()

            self.watchPageFaults(pid)

            self.sharedSyscall[self.target].setDebugging(True)
            prog_name = self.getProgName(pid)
            if self.targetFS[self.target] is not None and prog_name is not None:
                sindex = 0
                if self.full_path is not None:
                    self.lgr.debug('debug, set target fs, progname is %s  full: %s' % (prog_name, self.full_path))
                    real_path = resimUtils.realPath(self.full_path)
                    ''' this is not actually the text segment, it is the entire range of main program sections ''' 
                    if self.isWindows():
                        ''' Assumes winProg has already populated soMap'''
                        elf_info = self.soMap[self.target].getText(pid)
                    else:
                        elf_info = self.soMap[self.target].addText(real_path, prog_name, pid)
                    if elf_info is not None:
                        root_prefix = self.comp_dict[self.target]['RESIM_ROOT_PREFIX']
                        #self.getIDAFuns(self.full_path, elf_info.address)
                        self.fun_mgr = funMgr.FunMgr(self, cpu, self.mem_utils[self.target], self.lgr)
                        if self.isWindows():
                            offset = elf_info.address - elf_info.image_base
                            self.fun_mgr.getIDAFuns(self.full_path, root_prefix, offset)
                        else:
                            self.fun_mgr.getIDAFuns(self.full_path, root_prefix, 0)
                        ''' TBD alter stackTrace to use this and buid it out'''
                        self.context_manager[self.target].recordText(elf_info.address, elf_info.address+elf_info.size)
                        self.soMap[self.target].setFunMgr(self.fun_mgr, pid)
                        self.bookmarks.setFunMgr(self.fun_mgr)
                        self.dataWatch[self.target].setFunMgr(self.fun_mgr)
                        self.lgr.debug('ropCop instance for %s' % self.target)
                        self.ropCop[self.target] = ropCop.RopCop(self, cpu, cell, self.context_manager[self.target],  self.mem_utils[self.target],
                             elf_info.address, elf_info.size, self.bookmarks, self.task_utils[self.target], self.lgr)
                    else:
                        self.lgr.error('debug, text segment None for %s' % self.full_path)
                    self.lgr.debug('create coverage module')
                    ida_path = self.getIdaData(self.full_path)
                    if ida_path is not None:
                        self.lgr.debug('debug, create Coverage ida_path %s' % ida_path)
                        self.coverage = coverage.Coverage(self, self.full_path, ida_path, self.context_manager[self.target], 
                           cell, self.soMap[self.target], cpu, self.run_from_snap, self.lgr)
                    if self.coverage is None:
                        self.lgr.debug('Coverage is None!')
                else:
                    self.lgr.error('Failed to get full path for %s' % prog_name)
            rprint('Now debugging %s' % prog_name)
            if not self.fun_mgr.hasIDAFuns():
                self.lgr.debug('Warning program functions not found.  Dump functions from IDA or Ghidra')
                rprint('Warning program functions not found.  Dump functions from IDA or Ghidra')
            if self.debug_callback is not None:
                self.lgr.debug('debug do callback to %s' % str(self.command_callback))
                SIM_run_alone(self.debug_callback, self.debug_callback_param)
        else:
            ''' already debugging as current process '''
            self.lgr.debug('genMonitor debug, already debugging')
            self.context_manager[self.target].setDebugPid()
        self.task_utils[self.target].clearExitPid()
        ''' Otherwise not cleared when pageFaultGen is stopped/started '''
        self.page_faults[self.target].clearFaultingCycles()
        self.rev_to_call[self.target].clearEnterCycles()
        self.is_monitor_running.setRunning(False)
        jumper_file = os.getenv('EXECUTION_JUMPERS')
        if jumper_file is not None:
            if self.target not in self.jumper_dict:
                self.jumper_dict[self.target] = jumpers.Jumpers(self, self.context_manager[self.target], cpu, self.lgr)
                self.jumper_dict[self.target].loadJumpers(jumper_file)
        if self.target in self.read_replace:
             self.read_replace[self.target].swapContext()

    def trackThreads(self):
        if self.target not in self.track_threads:
            self.checkOnlyIgnore()
            cpu, comm, pid = self.task_utils[self.target].curProc() 
            self.track_threads[self.target] = trackThreads.TrackThreads(self, cpu, self.target, pid, self.context_manager[self.target], 
                    self.task_utils[self.target], self.mem_utils[self.target], self.param[self.target], self.traceProcs[self.target], 
                    self.soMap[self.target], self.targetFS[self.target], self.sharedSyscall[self.target], self.syscallManager[self.target], self.is_compat32, self.lgr)
        else:
            self.track_threads[self.target].checkContext()
            self.lgr.debug('trackThreads already tracking for %s' % self.target)
            print('trackThreads already tracking for %s' % self.target)

    def show(self):
        cpu, comm, pid = self.task_utils[self.target].curProc() 
        if cpu is None:
            cpu = self.cell_config.cpuFromCell(self.target)
            self.lgr.error('show failed to get cpu from taskUtils curProc.  target cpu is %s %s' % (cpu.name, str(cpu.current_context)))
            return
        cpl = memUtils.getCPL(cpu)
        eip = self.getEIP(cpu)
        so_file = self.soMap[self.target].getSOFile(eip)
        context = SIM_object_name(cpu.current_context)
        if self.isWindows():
            cur_thread = self.task_utils[self.target].getCurThread()
            cur_thread_rec = self.task_utils[self.target].getCurThreadRec()
            cur_proc_rec = self.task_utils[self.target].getCurTaskRec()
            print('cpu.name is %s context: %s PL: %d pid: %d(%s) EIP: 0x%x thread: 0x%x  code file: %s eproc: 0x%x ethread: 0x%x' % (cpu.name, context,
                   cpl, pid, comm, eip, cur_thread, so_file, cur_proc_rec, cur_thread_rec))
        
        else: 
            print('cpu.name is %s context: %s PL: %d pid: %d(%s) EIP: 0x%x   current_task symbol at 0x%x (use FS: %r)' % (cpu.name, context, 
                   cpl, pid, comm, eip, self.param[self.target].current_task, self.param[self.target].current_task_fs))
            pfamily = self.pfamily[self.target].getPfamily()
            tabs = ''
            while len(pfamily) > 0:
                prec = pfamily.pop()
                print('%s%5d  %s' % (tabs, prec.pid, prec.proc))
                tabs += '\t'



    def signalHap(self, signal_info, one, exception_number):
        cpu, comm, pid = self.task_utils[self.target].curProc() 
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
        cpu, comm, pid = self.task_utils[self.target].curProc()
        stack_frame = self.task_utils[self.target].frameFromStackSyscall()
        frame_string = taskUtils[self.target].stringFromFrame(stack_frame)
        print(frame_string)

    def int80Hap(self, cpu, one, exception_number):
        cpu, comm, pid = self.task_utils[self.target].curProc()
        eax = self.mem_utils[self.target].getRegValue(cpu, 'eax')
        self.lgr.debug('int80Hap in proc %d (%s), eax: 0x%x' % (pid, comm, eax))
        self.lgr.debug('syscall 0x%d from %d (%s) at 0x%x ' % (eax, pid, comm, self.getEIP(cpu)))
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
        stop_action = hapCleaner.StopAction(hap_clean, [])
        self.stop_hap = RES_hap_add_callback("Core_Simulation_Stopped", 
        	     self.stopHap, stop_action)
        status = self.is_monitor_running.isRunning()
        if not status:
            SIM_continue(0)

    def runToSignal(self, signal=None, pid=None):
        cpu = self.cell_config.cpuFromCell(self.target)
        self.lgr.debug('runToSignal, signal given is %s' % str(signal)) 

        sig_info = syscall.SyscallInfo(cpu, pid, signal)
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
        stop_action = hapCleaner.StopAction(hap_clean, [])
        self.stop_hap = RES_hap_add_callback("Core_Simulation_Stopped", 
        	     self.stopHap, stop_action)
        status = self.is_monitor_running.isRunning()
        if not status:
            SIM_continue(0)
   
    def execToText(self, flist=None):
        ''' assuming we are in an exec system call, run until execution enters the
            the .text section per the elf header in the file that was execed.'''
        cpu, comm, pid  = self.task_utils[self.target].curProc()
        prog_name, dumb = self.task_utils[self.target].getProgName(pid) 
        self.lgr.debug('execToText debug set exit_group break')
        self.debugExitHap()
                       
        if self.targetFS[self.target] is not None:
            sindex = 0
            full_path = self.targetFS[self.target].getFull(prog_name, self.lgr)
            self.lgr.debug('execToText, progname is %s  full: %s' % (prog_name, full_path))

            elf_info = self.soMap[self.target].addText(full_path, prog_name, pid)
            if elf_info is not None:
                if elf_info.address is None:
                    self.lgr.error('execToText found file %s, but address is None?' % full_path)
                    stopFunction.allFuns(flist)
                    return
                self.lgr.debug('execToText %s 0x%x - 0x%x' % (prog_name, elf_info.address, elf_info.address+elf_info.size))       
                self.context_manager[self.target].recordText(elf_info.address, elf_info.address+elf_info.size)
                self.runToText(flist)
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
        plist = self.task_utils[self.target].getPidsForComm(proc)
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
            self.toExecve(comm=proc, flist=flist)


    def toProc(self, proc, binary=True):
        plist = self.task_utils[self.target].getPidsForComm(proc)
        if len(plist) > 0 and not (len(plist)==1 and plist[0] == self.task_utils[self.target].getExitPid()):
            self.lgr.debug('toProc process %s found, run until some instance is scheduled' % proc)
            print('%s is running as %d.  Will continue until some instance of it is scheduled' % (proc, plist[0]))
            f1 = stopFunction.StopFunction(self.toUser, [], nest=True)
            flist = [f1]
            self.run_to[self.target].toRunningProc(proc, plist, flist)
        else:
            self.lgr.debug('toProc no process %s found, run until execve' % proc)
            cpu = self.cell_config.cpuFromCell(self.target)
            '''
            prec = Prec(cpu, proc, None)
            phys_current_task = self.task_utils[self.target].getPhysCurrentTask()
            self.proc_break = SIM_breakpoint(cpu.physical_memory, Sim_Break_Physical, Sim_Access_Write, 
                             phys_current_task, self.mem_utils[self.target].WORD_SIZE, 0)
            self.lgr.debug('toProc  set break at 0x%x' % (phys_current_task))
            self.proc_hap = RES_hap_add_callback_index("Core_Breakpoint_Memop", self.runToProc, prec, self.proc_break)
            '''
        
            #f1 = stopFunction.StopFunction(self.cleanToProcHaps, [], False)
            self.toExecve(comm=proc, flist=[], binary=binary)

        
    def debugProc(self, proc, final_fun=None, pre_fun=None):
        if self.isWindows():
            self.winMonitor[self.target].debugProc(proc, final_fun, pre_fun)
            return

        if type(proc) is not str:
            print('Need a proc name as a string')
            return
        self.lgr.debug('genMonitor debugProc')
        if len(proc) > 15:
            proc = proc[:16]
            print('Process name truncated to %s to match Linux comm name' % proc)
        self.rmDebugWarnHap()
        #self.stopTrace()
        plist = self.task_utils[self.target].getPidsForComm(proc)
        if len(plist) > 0 and not (len(plist)==1 and plist[0] == self.task_utils[self.target].getExitPid()):
            self.lgr.debug('debugProc plist len %d plist[0] %d  exitpid %d' % (len(plist), plist[0], self.task_utils[self.target].getExitPid()))

            self.lgr.debug('debugProc process %s found, run until some instance is scheduled' % proc)
            print('%s is running.  Will continue until some instance of it is scheduled' % proc)
            f1 = stopFunction.StopFunction(self.toUser, [], nest=True)
            f2 = stopFunction.StopFunction(self.debugExitHap, [], nest=False)
            f3 = stopFunction.StopFunction(self.debug, [], nest=False)
            flist = [f1, f3, f2]
            if final_fun is not None:
                f4 = stopFunction.StopFunction(final_fun, [], nest=False)
                flist.append(f4)
            if pre_fun is not None:
                fp = stopFunction.StopFunction(pre_fun, [], nest=False)
                flist.insert(0, fp)
            ''' If not yet loaded SO files, e.g., we just did a toProc, then execToText ''' 
            if self.soMap[self.target].getSOPid(plist[0]) is None:
                self.lgr.debug('debugProc, no so yet, run to text.')
                rtt = stopFunction.StopFunction(self.execToText, [], nest=True)
                flist.insert(1, rtt)
            self.run_to[self.target].toRunningProc(proc, plist, flist)
        else:
            self.lgr.debug('debugProc no process %s found, run until execve' % proc)
            #flist = [self.toUser, self.debug]
            ''' run to the execve, then start recording shared object mmaps and run
                until we enter the text segment so we get the SO map '''
            f1 = stopFunction.StopFunction(self.toUser, [], nest=True)
            f2 = stopFunction.StopFunction(self.execToText, [], nest=True)
            f3 = stopFunction.StopFunction(self.stackFrameManager[self.target].setStackBase, [], nest=False)
            f4 = stopFunction.StopFunction(self.debug, [], nest=False)
            flist = [f1, f2, f3, f4]
            self.toExecve(comm=proc, flist=flist, binary=True)
       

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
 
    def debugPid(self, pid):
        self.rmDebugWarnHap()
        self.debugPidList([pid], self.debug)

    def debugPidGroup(self, pid, final_fun=None, to_user=True):
        leader_pid = self.task_utils[self.target].getGroupLeaderPid(pid)
        if leader_pid is None:
            self.lgr.error('debugPidGroup leader_pid is None, asked about %d' % pid)
            return
        pid_dict = self.task_utils[self.target].getGroupPids(leader_pid)
        pid_list = list(pid_dict.keys())
        self.lgr.debug('debugPidGroup cell %s pid %d found leader %d and %d pids' % (self.target, pid, leader_pid, len(pid_list)))
        self.debugPidList(pid_list, self.debugGroup, final_fun=final_fun, to_user=to_user)

    def debugPidList(self, pid_list, debug_function, final_fun=None, to_user=True):
        #self.stopTrace()
        cpu = self.cell_config.cpuFromCell(self.target)
        if self.target not in self.magic_origin:
            self.magic_origin[self.target] = magicOrigin.MagicOrigin(self, cpu, self.bookmarks, self.lgr)
        if not self.isWindows():
            self.soMap[self.target].setContext(pid_list)
        self.lgr.debug('debugPidList cell %s pid_list: %s' % (self.target, str(pid_list)))
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
        cmd = 'enable-reverse-execution'
        SIM_run_command(cmd)
        self.rev_execution_enabled = True
        self.setPathToProg(pid_list[0])
        self.doDebugCmd(pid_list[0])
        #self.setDebugBookmark('origin', cpu)
        self.bookmarks.setOrigin(cpu)

        self.run_to[self.target].toRunningProc(None, pid_list, flist, debug_group=True, final_fun=final_fun)

    def changedThread(self, cpu, third, forth, memory):
        cur_addr = SIM_get_mem_op_value_le(memory)
        pid = self.mem_utils[self.target].readWord32(cpu, cur_addr + self.param[self.target].ts_pid)
        if pid != 0:
            print('changedThread')
            self.show()

    #def addProcList(self, pid, comm):
    #    #self.lgr.debug('addProcList %d %s' % (pid, comm))
    #    self.proc_list[self.target][pid] = comm
 
    def toUser(self, flist=None): 
        self.lgr.debug('toUser')
        cpu = self.cell_config.cpuFromCell(self.target)
        self.run2User(cpu, flist)

    def runToUserSpace(self):
        self.lgr.debug('runToUserSpace')
        self.is_monitor_running.setRunning(True)
        flist = [self.skipAndMail]
        f1 = stopFunction.StopFunction(self.skipAndMail, [], nest=False)
        self.toUser([f1])

    def toKernel(self): 
        cpu = self.cell_config.cpuFromCell(self.target)
        self.run2Kernel(cpu)

    def toProcPid(self, pid):
        self.lgr.debug('toProcPid %d' % pid)
        self.run_to[self.target].toRunningProc(None, [pid], None)


    def getEIP(self, cpu=None):
        if cpu is None:
            dum, cpu = self.context_manager[self.target].getDebugPid() 
            if cpu is None:
                cpu = self.cell_config.cpuFromCell(self.target)
        target = self.cell_config.cpu_cell[cpu]
        eip = self.mem_utils[target].getRegValue(cpu, 'eip')
        return eip

    def getReg(self, reg, cpu):
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
        pid, cpu = self.context_manager[self.target].getDebugPid() 
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
                    SIM_run_command('pselect %s' % cpu.name)
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
                self.context_manager[self.target].resetBackStop()
            else:
                self.lgr.debug('skipAndRunAlone was asked to back up before start of recording')
        self.is_monitor_running.setRunning(False)
        self.lgr.debug('setRunning to false, now set mbox to 0x%x' % eip)
        self.gdbMailbox('0x%x' % eip)
        print('Monitor done')

    def skipAndMail(self, cycles=1):
        self.lgr.debug('skipAndMail...')
        dum, cpu = self.context_manager[self.target].getDebugPid() 
        if cpu is None:
            self.lgr.debug("no cpu in runSkipAndMail")
            return
        if self.quit_when_done:
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
        if self.command_callback is not None:
            self.lgr.debug('skipAndMail do callback to %s' % str(self.command_callback))
            SIM_run_alone(self.command_callback, self.command_callback_param)
        else:
            cpl = memUtils.getCPL(cpu)
            self.lgr.debug('skipAndMail, cpl %d' % cpl)
            if cpl == 0:
                #SIM_run_alone(self.skipBackToUser, 1)
                #self.lgr.debug('skipAndMail, back from call to skip (but it ran alone)')
                # TBD skipping back to prior to call makes no sense
                self.lgr.debug('skipAndMail left in kernel')
                
            self.lgr.debug('skipAndMail, restoreDebugBreaks')
            SIM_run_alone(self.restoreDebugBreaks, False)

    def goToOrigin(self, debugging=True):
        if self.bookmarks is None:
            self.lgr.debug('genMonitor goToOrigin, no bookmarks do nothing')
            return
        if debugging:
            self.removeDebugBreaks()
            self.lgr.debug('goToOrigin am debugging, call stopTrackIO')
            self.stopTrackIO()
        cpu, comm, pid  = self.task_utils[self.target].curProc()
        #self.lgr.debug('goToOrigin pid was is %d' % pid)
        msg = self.bookmarks.goToOrigin()
        cpu, comm, pid  = self.task_utils[self.target].curProc()
        #self.lgr.debug('goToOrigin pid now is %d' % pid)
        if debugging:
            self.context_manager[self.target].setIdaMessage(msg)
            self.restoreDebugBreaks(was_watching=True)
            self.lgr.debug('goToOrigin call stopWatchTasks')
            self.context_manager[self.target].stopWatchTasksAlone(None)
            self.context_manager[self.target].watchTasks(set_debug_pid=True)

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
            dum, cpu = self.context_manager[self.target].getDebugPid() 
            self.lgr.debug('doReverse entered, extra_back is %s' % str(extra_back))
            self.removeDebugBreaks()
            reverseToWhatever.reverseToWhatever(self, self.context_manager[self.target], cpu, self.lgr, extra_back=extra_back)
            self.lgr.debug('doReverse, back from reverseToWhatever init')
        else:
            print('reverse execution disabled')
            self.skipAndMail()

    def printCycle(self):
        dum, cpu = self.context_manager[self.target].getDebugPid() 
        cell_name = self.getTopComponentName(cpu)
        current = cpu.cycles
        print('current cycle for %s is %x' % (cell_name, current))

    ''' more experiments '''
    def reverseStepInstruction(self, num=1):
        dum, cpu = self.context_manager[self.target].getDebugPid() 
        cell_name = self.getTopComponentName(cpu)
        dum_cpu, comm, pid  = self.task_utils[self.target].curProc()
        eip = self.getEIP()
        self.lgr.debug('reservseStepInstruction starting at %x' % eip)
        my_args = procInfo.procInfo(comm, cpu, pid, None, False)
        self.stopped_reverse_instruction_hap = RES_hap_add_callback("Core_Simulation_Stopped", 
		    self.stoppedReverseInstruction, my_args)
        self.lgr.debug('reverseStepInstruction, added stop hap')
        SIM_run_alone(SIM_run_command, 'reverse-step-instruction %d' % num)

    def stoppedReverseInstruction(self, my_args, one, exception, error_string):
        cell_name = self.getTopComponentName(my_args.cpu)
        cpu, comm, pid  = self.task_utils[self.target].curProc()
        if pid == my_args.pid:
            eip = self.getEIP()
            self.lgr.debug('stoppedReverseInstruction at %x' % eip)
            print('stoppedReverseInstruction stopped at ip:%x' % eip)
            self.gdbMailbox('0x%x' % eip)
            RES_hap_delete_callback_id("Core_Simulation_Stopped", self.stopped_reverse_instruction_hap)
        else:
            self.lgr.debug('stoppedReverseInstruction in wrong pid (%d), try again' % pid)
            SIM_run_alone(SIM_run_command, 'reverse-step-instruction')

    def revStepOver(self):
        self.reverseToCallInstruction(False)

    def revStepInto(self):
        self.reverseToCallInstruction(True)
 
    def reverseToCallInstruction(self, step_into, prev=None):
        if self.reverseEnabled():
            dum, cpu = self.context_manager[self.target].getDebugPid() 
            cell_name = self.getTopComponentName(cpu)
            self.lgr.debug('reverseToCallInstruction, step_into: %r  on entry, gdb_mailbox: %s' % (step_into, self.gdb_mailbox))
            self.removeDebugBreaks()
            #self.context_manager[self.target].showHaps()
            if prev is not None:
                instruct = SIM_disassemble_address(cpu, prev, 1, 0)
                self.lgr.debug('reverseToCallInstruction instruct is %s at prev: 0x%x' % (instruct[1], prev))
                if instruct[1] == 'int 128' or (not step_into and instruct[1].startswith('call')):
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
        dum, cpu = self.context_manager[self.target].getDebugPid() 
        cell_name = self.getTopComponentName(cpu)
        dum_cpu, cur_addr, comm, pid = self.task_utils[self.target].currentProcessInfo(cpu)
        self.lgr.debug('cgcMonitor, uncall')
        self.removeDebugBreaks()
        self.rev_to_call[self.target].doUncall()
   
    def getInstance(self):
        return INSTANCE

    def revToModReg(self, reg):
        reg = reg.lower()
        self.lgr.debug('revToModReg for reg %s' % reg)
        self.removeDebugBreaks()
        self.rev_to_call[self.target].doRevToModReg(reg)

    def revToAddr(self, address, extra_back=0):
        if self.reverseEnabled():
            pid, cpu = self.context_manager[self.target].getDebugPid() 
            self.lgr.debug('revToAddr 0x%x, extra_back is %d' % (address, extra_back))
            self.removeDebugBreaks()
            self.stopTrackIO()
            reverseToAddr.reverseToAddr(address, self.context_manager[self.target], self.task_utils[self.target], self.is_monitor_running, self, cpu, 
                           self.lgr, extra_back=extra_back)
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
        debug_pid, cpu = self.context_manager[self.target].getDebugPid() 
        eip = self.getEIP(cpu)
        retval = None
        if not resim_status and debug_pid is None:
            retval = 'mailbox:exited'
            self.lgr.debug('getEIPWhenStopped debug_pid is gone, return %s' % retval)
            print(retval)

        elif resim_status and not simics_status:
            self.lgr.debug('getEIPWhenStopped Simics not running, RESim thinks it is running.  Perhaps gdb breakpoint?')
            pid, cpu = self.context_manager[self.target].getDebugPid() 
            SIM_run_command('pselect %s' % cpu.name)
            self.context_manager[self.target].setIdaMessage('Stopped at debugger breakpoint?')
            retval = 'mailbox:0x%x' % eip

        elif not resim_status:
            if cpu is None:
                self.lgr.error('no cpu defined in context manager')
            else: 
                dum_cpu, comm, pid  = self.task_utils[self.target].curProc()
                self.lgr.debug('getEIPWhenStopped, pid %d' % (pid)) 
                if self.gdb_mailbox is not None:
                    self.lgr.debug('getEIPWhenStopped mbox is %s pid is %d (%s) cycle: 0x%x' % (self.gdb_mailbox, pid, comm, cpu.cycles))
                    retval = 'mailbox:%s' % self.gdb_mailbox
                    print(retval)
                else:
                    self.lgr.debug('getEIPWhenStopped, mbox must be empty?')
                    cpl = memUtils.getCPL(cpu)
                    if cpl == 0 and not kernel_ok:
                        self.lgr.debug('getEIPWhenStopped in kernel pid:%d (%s) eip is %x' % (pid, comm, eip))
                        retval = 'in kernel'
                        print(retval)
                    else:
                        self.lgr.debug('getEIPWhenStopped pid:%d (%s) eip is %x' % (pid, comm, eip))
                        if not self.context_manager[self.target].amWatching(pid):
                            self.lgr.debug('getEIPWhenStopped not watching process pid:%d (%s) eip is %x' % (pid, comm, eip))
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
        debug_pid, debug_cpu = self.context_manager[self.target].getDebugPid() 
        cpu, comm, pid = self.task_utils[self.target].curProc() 
        self.lgr.debug('resynch to pid: %d' % debug_pid)
        #self.is_monitor_running.setRunning(True)
        if self.context_manager[self.target].amWatching(pid):
            self.lgr.debug('rsynch, already in proc')
            f1 = stopFunction.StopFunction(self.skipAndMail, [], nest=False)
            self.toUser([f1])
        else:
            f1 = stopFunction.StopFunction(self.toUser, [], nest=True)
            f2 = stopFunction.StopFunction(self.skipAndMail, [], nest=False)
            flist = [f1, f2]
            self.lgr.debug('rsynch, call toRunningProc for pid %d' % debug_pid)
            pid_list = self.context_manager[self.target].getThreadPids()
            self.run_to[self.target].toRunningProc(None, pid_list, flist)

    def traceExecve(self, comm=None):
        ''' TBD broken '''
        self.pfamily[self.target].traceExecve(comm)

    def watchPageFaults(self, pid=None):

        if pid is None:
            pid, cpu = self.context_manager[self.target].getDebugPid() 
        #self.lgr.debug('genMonitor watchPageFaults pid %s' % pid)
        self.page_faults[self.target].watchPageFaults(pid=pid, compat32=self.is_compat32)
        #self.lgr.debug('genMonitor watchPageFaults back')

    def stopWatchPageFaults(self, pid=None):
        self.lgr.debug('genMonitor stopWatchPageFaults')
        self.page_faults[self.target].stopWatchPageFaults(pid)
        self.page_faults[self.target].stopPageFaults()

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

    def getPID(self):
        cpu, comm, this_pid = self.task_utils[self.target].curProc() 
        return this_pid

    def getCurrentProc(self, target_cpu=None):
        if target_cpu is None:
            target = self.target
        else:
            target = self.cell_config.cellFromCPU(target_cpu)
        cpu, comm, pid = self.task_utils[target].curProc() 
        return cpu, comm, pid

    def getCPL(self): 
        cpu, comm, this_pid = self.task_utils[self.target].curProc() 
        cpl = memUtils.getCPL(cpu)

    def skipBackToUser(self, extra=0):
        if self.reverseEnabled():
            self.lgr.debug('skipBackToUser')
            cpu, comm, pid = self.task_utils[self.target].curProc() 
            self.rev_to_call[self.target].jumpOverKernel(pid)
        else:
            self.lgr.debug('skipBackToUser but reverse execution not enabled.')
            print('reverse execution not enabled.')

    def reverseToUser(self, force=False):
        if not force:
            print('Try using skipBackToUser instead.  Or force=True if you insist, but it may not return and may end in the wrong pid.')
            return
        ''' Note: may not stop in current pid, see skipBacktoUser '''
        self.removeDebugBreaks()
        cell = self.cell_config.cell_context[self.target]
        cpu = self.cell_config.cpuFromCell(self.target)
        rtu = reverseToUser.ReverseToUser(self.param[self.target], self.lgr, cpu, cell)

    def getDebugFirstCycle(self):
        print('start_cycle:%x' % self.bookmarks.getFirstCycle())

    def getFirstCycle(self):
        return self.bookmarks.getFirstCycle()

    def stopAtKernelWrite(self, addr, rev_to_call=None, num_bytes = 1, satisfy_value=None, kernel=False, prev_buffer=False):
        '''
        Runs backwards until a write to the given address is found.
        '''
        if self.reverseEnabled():
            #self.context_manager[self.target].showHaps();
            self.removeDebugBreaks()
            pid, cpu = self.context_manager[self.target].getDebugPid() 
            value = self.mem_utils[self.target].readMemory(cpu, addr, num_bytes)
            if value is None:
                self.lgr.error('stopAtKernelWrite failed to read from addr 0x%x' % addr)
                self.skipAndMail()
                return
            self.lgr.debug('stopAtKernelWrite, call findKernelWrite of 0x%x to address 0x%x num bytes %d cycles: 0x%x' % (value, addr, num_bytes, cpu.cycles))
            cell = self.cell_config.cell_context[self.target]
            if self.find_kernel_write is None:
                self.find_kernel_write = findKernelWrite.findKernelWrite(self, cpu, cell, addr, self.task_utils[self.target], self.mem_utils[self.target],
                    self.context_manager[self.target], self.param[self.target], self.bookmarks, self.dataWatch[self.target], self.lgr, rev_to_call, 
                    num_bytes, satisfy_value=satisfy_value, kernel=kernel, prev_buffer=prev_buffer) 
            else:
                self.find_kernel_write.go(addr)
        else:
            print('reverse execution disabled')
            self.skipAndMail()

    def revTaintSP(self):
        cpu = self.cell_config.cpuFromCell(self.target)
        value = self.mem_utils[self.target].getRegValue(cpu, 'sp')
        self.revTaintAddr(value)
        
    def revTaintAddr(self, addr, kernel=False, prev_buffer=False, callback=None):
        '''
        back track the value at a given memory location, where did it come from?
        prev_buffer of True causes tracking to stop when an address holding the
        value is found, e.g., as a souce buffer.
        The callback is used with prev_buffer=True, which always assumes the
        find will occur in the reverseToCall module.
        '''
        self.lgr.debug('revTaintAddr for 0x%x' % addr)
        if self.reverseEnabled():
            self.removeDebugBreaks()
            pid, cpu = self.context_manager[self.target].getDebugPid() 
            cell_name = self.getTopComponentName(cpu)
            eip = self.getEIP(cpu)
            instruct = SIM_disassemble_address(cpu, eip, 1, 0)
            value = self.mem_utils[self.target].readWord32(cpu, addr)
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
            self.stopAtKernelWrite(addr, self.rev_to_call[self.target], kernel=kernel, prev_buffer=prev_buffer)
        else:
            print('reverse execution disabled')
            self.skipAndMail()

    def revRegSrc(self, reg, kernel=False, callback=None, taint=False):
        ''' NOT yet used, see revTainReg'''
        self.rev_to_call[self.target].setCallback(callback)
        self.rev_to_call[self.target].doRevToModReg(reg, kernel=kernel, taint=taint)

    def revTaintReg(self, reg, kernel=False):
        ''' back track the value in a given register '''
        self.reverseTrack[self.target].revTaintReg(reg, self.bookmarks, kernel=kernel)

    def satisfyCondition(self, pc):
        ''' Assess a simple condition, modify input data to satisfy it '''
        if self.reverseEnabled():
            self.removeDebugBreaks()
            pid, cpu = self.context_manager[self.target].getDebugPid() 
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
        dum, cpu = self.context_manager[self.target].getDebugPid() 
        new_cycle = cpu.cycles - 1
        SIM_run_command('pselect %s' % cpu.name)
        SIM_run_command('skip-to cycle = %d' % new_cycle)
        self.lgr.debug('rev1NoMail skipped to 0x%x  cycle is 0x%x' % (new_cycle, cpu.cycles))

    def rev1(self):
        if self.reverseEnabled():
            self.removeDebugBreaks()
            dum, cpu = self.context_manager[self.target].getDebugPid() 
            new_cycle = cpu.cycles - 1
         
            start_cycles = self.rev_to_call[self.target].getStartCycles()
            if new_cycle >= start_cycles:
                self.is_monitor_running.setRunning(True)
                try:
                    result = SIM_run_command('skip-to cycle=0x%x' % new_cycle)
                except: 
                    print('Reverse execution disabled?')
                    self.skipAndMail()
                    return
                self.lgr.debug('rev1 result from skip to 0x%x  is %s cycle now 0x%x' % (new_cycle, result, cpu.cycles))
                self.skipAndMail()
            else:
                self.lgr.debug('rev1, already at first cycle 0x%x' % new_cycle)
                self.skipAndMail()
        else:
            print('reverse execution disabled')
            self.skipAndMail()

    def test1(self):
        
        pid, cpu = self.context_manager[self.target].getDebugPid() 
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

    def runToCall(self, callname, pid=None, subcall=None):
        cell = self.cell_config.cell_context[self.target]
        self.is_monitor_running.setRunning(True)
        self.lgr.debug('runToCall')
        self.checkOnlyIgnore()
        if pid is not None:
            pid_match = syscall.PidFilter(pid)
            pid_param = syscall.CallParams('runToCall', callname, pid_match, break_simulation=True) 
            call_params = [pid_param]
            self.lgr.debug('runToCall %s set pid filter' % callname)
        elif subcall is not None:
            if callname == 'ipc':
                if subcall in ipc.call_name:
                    ipc_call = syscall.IPCFilter(ipc.call_name[subcall])
                    ipc_param = syscall.CallParams('runToCall', callname, ipc_call, break_simulation=True) 
                    call_params = [ipc_param]
                    self.lgr.debug('runToCall %s set pid filter' % callname)
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
        self.syscallManager[self.target].watchSyscall(None, [callname], call_params, callname, stop_on_call=True)
      
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
            self.syscallManager[self.target].watchSyscall(None, [callname], call_params, callname, stop_on_call=True)

        else:
            ''' watch all syscalls '''
            self.lgr.debug('runToSyscall for any system call')
            self.trace_all[self.target] = self.syscallManager[self.target].watchAllSyscalls(None, 'runToSyscall', stop_on_call=True)
     
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
        cpu, comm, pid = self.task_utils[self.target].curProc() 
        call_list = ['vfork','fork', 'clone','execve','open','openat','pipe','pipe2','close','dup','dup2','socketcall', 
                     'exit', 'exit_group', 'ipc', 'read', 'write', 'gettimeofday', 'mmap', 'mmap2']
        #             'exit', 'exit_group', 'waitpid', 'ipc', 'read', 'write', 'gettimeofday', 'mmap', 'mmap2']
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
            self.traceMgr[self.target].open('/tmp/syscall_trace.txt', cpu)
        for call in call_list: 
            #TBD fix 32-bit compat
            self.call_traces[self.target][call] = self.traceSyscall(callname=call, trace_procs=True, soMap=self.soMap[self.target], swapper_ok=swapper_ok)

    def rmSyscall(self, call_param_name, context=None, cell_name=None):
        if cell_name is None:
            cell_name = self.target 
        self.syscallManager[self.target].rmSyscall(call_param_name, context=context)
   
    def rmAllSyscalls(self, cell_name=None):
        if cell_name is None:
            cell_name = self.target
        self.syscallManager[cell_name].rmAllSyscalls()
 
 
    def stopTrace(self, cell_name=None, syscall=None):
        ''' TBD remove not used'''
        if cell_name is None:
            cell_name = self.target
 
        self.syscallManager[cell_name].stopTrace(syscall=syscall)
        #if syscall is not None:
        #    self.lgr.debug('genMonitor stopTrace from genMonitor cell %s given syscall %s' % (cell_name, syscall.name))
        #else:
        #    self.lgr.debug('genMonitor stopTrace from genMonitor cell %s no given syscall' % (cell_name))

        '''
        dup_traces = self.call_traces[cell_name].copy()
        for call in dup_traces:
            syscall_trace = dup_traces[call]
            if syscall is None or syscall_trace == syscall: 
                #self.lgr.debug('genMonitor stopTrace cell %s of call %s' % (cell_name, call))
                syscall_trace.stopTrace(immediate=True)
                #self.lgr.debug('genMonitor back from stopTrace')
                self.rmCallTrace(cell_name, call)

        #if syscall is None or syscall_trace == syscall: 
        #    self.call_traces[cell_name].clear()   
        if cell_name in self.trace_all and (syscall is None or self.trace_all[cell_name]==syscall):
            self.lgr.debug('call stopTrace for trace_all')
            self.trace_all[cell_name].stopTrace(immediate=False)
            del self.trace_all[cell_name]

            for exit in self.exit_maze:
                exit.rmAllBreaks()
        if cell_name not in self.trace_all and len(self.call_traces[cell_name]) == 0:
            self.traceMgr[cell_name].close()

        #if self.instruct_trace is not None:
        #    self.stopInstructTrace()
        '''

    def rmCallTrace(self, cell_name, callname):
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
        outfile = os.path.join('/tmp', os.path.basename(path))
        self.traceFiles[self.target].watchFile(path, outfile)
        ''' TBD reduce to only track open/write/close? '''
        if self.target not in self.trace_all:
            self.traceAll()

    def traceFD(self, fd, raw=False):
        ''' Create mirror of reads/write to the given FD.  Use raw to avoid modifications to the data. '''
        self.lgr.debug('traceFD %d' % fd)
        outfile = '/tmp/output-fd-%d.log' % fd
        self.traceFiles[self.target].watchFD(fd, outfile, raw=raw)

    def exceptHap(self, cpu, one, exception_number):
        cpu, comm, pid = self.task_utils[self.target].curProc() 
        call = self.mem_utils[self.target].getRegValue(cpu, 'r7')
        self.lgr.debug('exeptHap except: %d  pid %d call %d' % (exception_number, pid, call))

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
        pid, cpu = self.context_manager[self.target].getDebugPid() 
        retval = False
        if pid is None:
            retval = self.ignoreProgList() 
            if not retval:
                retval = self.onlyProgList() 
        return retval
 
    def traceAll(self, target=None, record_fd=False, swapper_ok=False):
        if target is None:
            target = self.target

        ''' trace all system calls. if a program selected for debugging, watch only that program '''
        self.lgr.debug('traceAll target %s begin' % target)
        if target not in self.cell_config.cell_context:
            print('Unknown target %s' % target)
            return

        if self.checkOnlyIgnore():
            self.rmDebugWarnHap()

        if self.isWindows():
            self.trace_all[target]= self.winMonitor[target].traceAll(record_fd=record_fd, swapper_ok=swapper_ok)
            self.lgr.debug('traceAll back from winMonitor trace_all set to %s' % self.trace_all[target])
            self.run_to[target].watchSO()
            return

        if target in self.trace_all:
            self.trace_all[target].setRecordFD(record_fd)
            print('Was tracing.  Limit to FD recording? %r' % (record_fd))
            self.lgr.debug('traceAll Was tracing.  Limit to FD recording? %r' % (record_fd))
        else:
            context = self.context_manager[target].getDefaultContext()
            cell = self.cell_config.cell_context[target]
            pid, cpu = self.context_manager[target].getDebugPid() 
            if pid is not None:
                tf = '/tmp/syscall_trace-%s-%d.txt' % (target, pid)
                context = self.context_manager[target].getRESimContext()
            else:
                tf = '/tmp/syscall_trace-%s.txt' % target
                cpu, comm, pid = self.task_utils[target].curProc() 

            self.traceMgr[target].open(tf, cpu)
            if not self.context_manager[self.target].watchingTasks():
                self.traceProcs[target].watchAllExits()
            self.lgr.debug('traceAll, create syscall hap')
            self.trace_all[target] = self.syscallManager[self.target].watchAllSyscalls(None, 'traceAll', trace=True, binders=self.binders, connectors=self.connectors,
                                      record_fd=record_fd, linger=True, netInfo=self.netInfo[self.target], swapper_ok=swapper_ok)

            if self.run_from_snap is not None and self.snap_start_cycle[cpu] == cpu.cycles:
                ''' running from snap, fresh from snapshot.  see if we recorded any calls waiting in kernel '''
                p_file = os.path.join('./', self.run_from_snap, target, 'sharedSyscall.pickle')
                if os.path.isfile(p_file):
                    exit_info_list = pickle.load(open(p_file, 'rb'))
                    if exit_info_list is None:
                        self.lgr.error('No data found in %s' % p_file)
                    else:
                        ''' TBD rather crude determination of context.  Assuming if debugging, then all from pickle should be resim context. '''
                        self.trace_all[target].setExits(exit_info_list, context_override = context)

            frames = self.getDbgFrames()
            self.lgr.debug('traceAll, call to setExits')
            self.trace_all[target].setExits(frames, context_override=self.context_manager[self.target].getRESimContext()) 
            ''' TBD not handling calls made prior to trace all without debug?  meaningful?'''

    def noDebug(self, dumb=None):
        self.lgr.debug('noDebug')
        cmd = 'disable-reverse-execution'
        SIM_run_command(cmd)
        self.rev_execution_enabled = False
        self.removeDebugBreaks(keep_watching=True, keep_coverage=False)
        self.sharedSyscall[self.target].setDebugging(False)
        self.noWatchSysEnter()

    def stopDebug(self):
        ''' stop all debugging '''
        self.lgr.debug('stopDebug')
        if self.rev_execution_enabled:
            cmd = 'disable-reverse-execution'
            SIM_run_command(cmd)
            self.rev_execution_enabled = False
        self.removeDebugBreaks(keep_watching=False, keep_coverage=False)
        self.sharedSyscall[self.target].setDebugging(False)
        self.syscallManager[self.target].rmAllSyscalls()
        #self.stopTrace()
        if self.target in self.magic_origin:
            del self.magic_origin[self.target]

    def restartDebug(self):
        self.lgr.debug('restartDebug')
        cmd = 'enable-reverse-execution'
        SIM_run_command(cmd)
        self.rev_execution_enabled = True
        self.restoreDebugBreaks(was_watching=True)
        self.sharedSyscall[self.target].setDebugging(True)

    def startThreadTrack(self):
        for cell_name in self.track_threads:
            self.lgr.debug('startThreadTrack for %s' % cell_name)
            self.track_threads[cell_name].startTrack()
        
    def stopThreadTrack(self, immediate=False):
        self.lgr.debug('stopThreadTrack ')
        for cell_name in self.track_threads:
            self.lgr.debug('stopThreadTrack for %s' % cell_name)
            self.track_threads[cell_name].stopTrack(immediate=immediate)

    def showProcTrace(self):
        ''' TBD this looks like a hack, why are the precs none?'''
        pid_comm_map = self.task_utils[self.target].getPidCommMap()
        precs = self.traceProcs[self.target].getPrecs()
        for pid in precs:
            if precs[pid].prog is None and pid in pid_comm_map:
                precs[pid].prog = 'comm: %s' % (pid_comm_map[pid])
        #for pid in precs:
        #    if precs[pid].prog is None and pid in self.proc_list[self.target]:
        #        precs[pid].prog = 'comm: %s' % (self.proc_list[self.target][pid])
        
        self.traceProcs[self.target].showAll()
 
    def toExecve(self, comm=None, flist=None, binary=False):
        cell = self.cell_config.cell_context[self.target]
        if comm is not None:    
            params = syscall.CallParams('toExecve', 'execve', comm, break_simulation=True) 
            if binary:
                params.param_flags.append('binary')
            call_params = [params]
        else:
            call_params = []
            cpu = self.cell_config.cpuFromCell(self.target)
            self.traceMgr[self.target].open('/tmp/execve.txt', cpu)

        self.syscallManager[self.target].watchSyscall(None, ['execve'], call_params, 'execve', flist=flist)
        SIM_continue(0)

    def clone(self, nth=1):
        ''' Run until we are in the child of the Nth clone of the current process'''
        #cell = self.cell_config.cell_context[self.target]
        #eh = cloneChild.CloneChild(self, cell, self.param[self.target], self.mem_utils[self.target], self.task_utils[self.target], self.context_manager[self.target], nth, self.lgr)
        #SIM_run_command('c')
        self.runToClone(nth)

    def recordText(self, start, end):
        ''' record IDA's view of text segment, unless we recorded from our own parse of the elf header '''
        self.lgr.debug('.text IDA is 0x%x - 0x%x' % (start, end))
        s, e = self.context_manager[self.target].getText()
        if s is None:
            self.lgr.debug('genMonitor recordText, no text from contextManager, use from IDA')
            cpu, comm, pid = self.task_utils[self.target].curProc() 
            self.context_manager[self.target].recordText(start, end)
            self.soMap[self.target].addText(start, end-start, 'tbd', pid)

    def textHap(self, prec, third, forth, memory):
        ''' callback when text segment is executed '''
        if self.proc_hap is None:
            return
        cpu, comm, pid = self.task_utils[self.target].curProc() 
        if cpu != prec.cpu or pid not in prec.pid:
            self.lgr.debug('%s hap, wrong something pid:%d prec pid list %s' % (prec.who, pid, str(prec.pid)))
            return
        #cur_eip = SIM_get_mem_op_value_le(memory)
        eip = self.getEIP(cpu)
        self.lgr.debug('textHap eip is 0x%x' % eip)
        self.is_monitor_running.setRunning(False)
        SIM_break_simulation('text hap')
        if prec.debugging:
            self.context_manager[self.target].genDeleteHap(self.proc_hap)
            self.proc_hap = None
            self.skipAndMail()

    def debugExitHap(self, flist=None): 
        ''' intended to stop simultion if the threads we are debugging all exit '''
        if self.isWindows():
            ''' TBD fix for windows '''
            pass
        else:
            if self.target not in self.exit_group_syscall:
                somap = None
                if self.target in self.soMap:
                    somap = self.soMap[self.target]
                else:
                    self.lgr.debug('debugExitHap no so map for %s' % self.target)
        
                context=self.context_manager[self.target].getRESimContextName()

                exit_calls = ['exit_group', 'tgkill']
                self.exit_group_syscall[self.target] = self.syscallManager[self.target].watchSyscall(context, exit_calls, [], 'debugExit')
                #self.lgr.debug('debugExitHap')


    def rmDebugExitHap(self):
        ''' Intended to be called if a SEGV or other cause of death occurs, in which case we assume that is caught by
            the contextManager and we do not want this rudundant stopage. '''
        if self.target in self.exit_group_syscall:
            self.lgr.debug('rmDebugExit')
            self.syscallManager[self.target].rmSyscall('debugExit')
            #self.exit_group_syscall[self.target].stopTrace()
            del self.exit_group_syscall[self.target]

    def stopOnExit(self):
        if self.target in self.exit_group_syscall:
            self.exit_group_syscall[self.target].stopOnExit()
        else:
            print('stopOnExit, no exit_group_syscall, are you debugging?')
       
    def noReverse(self, watch_enter=True):
        cmd = 'disable-reverse-execution'
        SIM_run_command(cmd)
        if not watch_enter:
            self.noWatchSysEnter()
        self.rev_execution_enabled = False
        self.lgr.debug('genMonitor noReverse')

    def allowReverse(self):
        cmd = 'enable-reverse-execution'
        SIM_run_command(cmd)
        pid, cpu = self.context_manager[self.target].getDebugPid() 
        prec = Prec(cpu, None, pid)
        if pid is not None:
            self.rev_to_call[self.target].watchSysenter(prec)
        self.rev_execution_enabled = True
        self.lgr.debug('genMonitor allowReverse')
 
    def restoreDebugBreaks(self, was_watching=False):
         
        self.lgr.debug('restoreDebugBreaks')
        self.context_manager[self.target].resetWatchTasks() 
        if not self.debug_breaks_set and not self.track_finished:
            self.lgr.debug('restoreDebugBreaks breaks not set and not track finished')
            #self.context_manager[self.target].restoreDebug() 
            pid, cpu = self.context_manager[self.target].getDebugPid() 
            if pid is not None:
                if not was_watching:
                    self.context_manager[self.target].watchTasks()
                if self.rev_execution_enabled:
                    prec = Prec(cpu, None, pid)
                    self.rev_to_call[self.target].watchSysenter(prec)
                    if self.target in self.track_threads:
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
                #self.lgr.debug('restoreDebugBreaks set magic?')
                self.magic_origin[self.target].setMagicHap()
            #self.lgr.debug('restoreDebugBreaks return')

    def noWatchSysEnter(self):
        self.lgr.debug('noWatchSysEnter')
        self.rev_to_call[self.target].noWatchSysenter()

 
    def removeDebugBreaks(self, keep_watching=False, keep_coverage=True, immediate=False):
        ''' return true if breaks were set and we removed them '''
        self.lgr.debug('genMon removeDebugBreaks was set: %r' % self.debug_breaks_set)
        if self.debug_breaks_set:
            retval = True
            if not keep_watching:
                if immediate:
                    self.context_manager[self.target].stopWatchTasksAlone(None)
                else:
                    self.context_manager[self.target].stopWatchTasks()
            pid, cpu = self.context_manager[self.target].getDebugPid() 
            self.stopWatchPageFaults(pid)
            self.rev_to_call[self.target].noWatchSysenter()
            if self.target in self.track_threads:
                self.track_threads[self.target].stopTrack(immediate=immediate)
            if self.target in self.exit_group_syscall:
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
                #self.lgr.debug('genMon removeDebugBreaks magic')
                self.magic_origin[self.target].deleteMagicHap()
        else:
            retval = False
        return retval

    def revToText(self):
        self.is_monitor_running.setRunning(True)
        start, end = self.context_manager[self.target].getText()
        if start is None:
            print('No text segment defined, has IDA been started with the rev plugin?')
            return
        self.removeDebugBreaks()
        count = end - start
        self.lgr.debug('revToText 0x%x - 0x%x count: 0x%x' % (start, end, count))
        cell = self.cell_config.cell_context[self.target]
        cpu, comm, pid = self.task_utils[self.target].curProc() 
        self.rev_to_call[self.target].setBreakRange(self.target, pid, start, count, cpu, comm, False)
        f1 = stopFunction.StopFunction(self.rev_to_call[self.target].rmBreaks, [], nest=False)
        f2 = stopFunction.StopFunction(self.skipAndMail, [], nest=False, match_pid=True)
        flist = [f1, f2]
        hap_clean = hapCleaner.HapCleaner(cpu)
        ''' if we land in the wrong pid, rev to the right pid and then revToText again...'''
        stop_action = hapCleaner.StopAction(hap_clean, None, flist, pid=pid, wrong_pid_action=self.revToText)
        self.stop_hap = RES_hap_add_callback("Core_Simulation_Stopped", 
          self.stopHap, stop_action)
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

    def tracingAll(self, cell_name, pid):
        ''' are we tracing all syscalls for the given pid? '''
        retval = False
        #self.lgr.debug('tracingAll cell_name %s len of self.trace_all is %d' % (cell_name, len(self.trace_all))) 
        if cell_name in self.trace_all:
            #self.lgr.debug('tracingAll %s in trace_all' % cell_name) 
            debug_pid, dumb1 = self.context_manager[self.target].getDebugPid() 
            if debug_pid is None:
                #self.lgr.debug('tracingAll pid none, return true')
                retval = True
            else:
                #self.lgr.debug('tracingAll debug_pid %d' % debug_pid)
                if self.context_manager[self.target].amWatching(pid):
                    #self.lgr.debug('tracingAll watching pid %d' % pid)
                    retval = True
                else:
                    #self.lgr.debug('tracingAll not watching debug_pid %d' % debug_pid)
                    pass
        return retval
            

    def runToText(self, flist = None, this_pid=False):
        ''' run until within the currently defined text segment '''
        self.is_monitor_running.setRunning(True)
        start, end = self.context_manager[self.target].getText()
        if start is None:
            print('No text segment defined, has IDA been started with the rev plugin?')
            return
        count = end - start
        self.lgr.debug('runToText range 0x%x 0x%x' % (start, end))

        self.context_manager[self.target].watchTasks()
        if flist is not None and self.listHasDebug(flist):
            ''' We will be debugging.  Set debugging context now so that any reschedule does not 
                cause false hits in the text block '''
            self.context_manager[self.target].setDebugPid()

        proc_break = self.context_manager[self.target].genBreakpoint(None, Sim_Break_Linear, Sim_Access_Execute, start, count, 0)
        if this_pid:
            cpu, comm, pid = self.task_utils[self.target].curProc() 
        else:
            pid, cpu = self.context_manager[self.target].getDebugPid() 
        if pid is None or this_pid:
            cpu, comm, pid = self.task_utils[self.target].curProc() 
            prec = Prec(cpu, None, [pid], who='to text')
        else:
            pid_list = self.context_manager[self.target].getThreadPids()
            prec = Prec(cpu, None, pid_list, who='to text')
        prec.debugging = True
        ''' NOTE obscure use of flist to determine if SO files are tracked '''
        prec.debugging = True
        if flist is None:
            f1 = stopFunction.StopFunction(self.skipAndMail, [], nest=False)
            flist = [f1]
        #else:
        #    #self.call_traces[self.target]['open'] = self.traceSyscall(callname='open', soMap=self.soMap)
        call_list = ['open', 'mmap']
        if self.mem_utils[self.target].WORD_SIZE == 4 or self.is_compat32: 
            call_list.append('mmap2')

        self.syscallManager[self.target].watchSyscall(None, call_list, [], 'runToText')

        self.lgr.debug('debug watching open syscall and mmap')

        hap_clean = hapCleaner.HapCleaner(cpu)
        hap_clean.add("GenContext", self.proc_hap)
        stop_action = hapCleaner.StopAction(hap_clean, None, flist)
        self.stop_hap = RES_hap_add_callback("Core_Simulation_Stopped", 
          self.stopHap, stop_action)
        self.lgr.debug('runToText hap set, now run. flist in stophap is %s' % stop_action.listFuns())

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
            RES_hap_delete_callback_id("Core_Simulation_Stopped", self.stop_hap)
            self.stop_hap = None
        self.lgr.debug('undoDebug done')
            

    def remainingCallTraces(self, cell_name=None, exception=None):
        if cell_name is None:
            cell_name = self.target
        return self.syscallManager[cell_name].remainingCallTraces(exception=exception)

    def remainingCallTracesXXXXXXXXX(self, exception=None):
        for cell_name in self.call_traces:
            if len(self.call_traces[cell_name]) > 0:
                #for ct in self.call_traces[cell_name]:
                #    self.lgr.debug('remainingCallTraces found remain for cell %s call %s' % (cell_name, ct))
                if len(self.call_traces[cell_name]) == 1 and exception in self.call_traces[cell_name]:
                    self.lgr.debug('remainingCallTraces ignoring exception %s' % exception)
                    pass
                else:
                    return True
        return False


    def runTo(self, call, call_params, cell_name=None, cell=None, run=True, linger_in=False, background=False, 
              ignore_running=False, name=None, flist=None, callback = None, all_contexts=False):
        retval = None
        self.lgr.debug('runTo')
        if self.checkOnlyIgnore():
            self.rmDebugWarnHap()

        ''' call is a list '''
        if not ignore_running and self.is_monitor_running.isRunning():
            print('Monitor is running, try again after it pauses')
            return
        if cell_name is None:
            cell_name = self.target
        ''' qualify call with name, e.g, for multiple dmod on reads '''
        call_name = call[0]
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
        if all_contexts:
            for context in self.context_manager[self.target].getContexts():
                self.syscallManager[cell_name].watchSyscall(context, call, call_params_list, name, linger=linger_in, background=background, flist=flist, 
                           callback=callback)
 
        else:
            self.syscallManager[cell_name].watchSyscall(None, call, call_params_list, name, linger=linger_in, background=background, flist=flist, 
                   callback=callback)
        if run and not self.is_monitor_running.isRunning():
            self.is_monitor_running.setRunning(True)
            SIM_continue(0)
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
        call = self.task_utils[self.target].socketCallName('connect', self.is_compat32)
        call_params = syscall.CallParams('runToConnect', 'connect', addr, break_simulation=True, proc=proc)        
        call_params.nth = nth
        self.runTo(call, call_params, name='connect')

    def runToDmod(self, dfile, cell_name=None, background=False, comm=None, break_simulation=False):
        retval = True
        if not os.path.isfile(dfile):
            print('No file found at %s' % dfile)
            return False
        if cell_name is None:
            cell_name = self.target
        mod = dmod.Dmod(self, dfile, self.mem_utils[cell_name], cell_name, self.lgr, comm=comm)
        operation = mod.getOperation()
        call_params = syscall.CallParams(dfile, operation, mod, break_simulation=break_simulation)        
        if cell_name is None:
            cell_name = self.target
            run = True
        else:
            run = False
        operation = mod.getOperation()
        self.lgr.debug('runToDmod file %s cellname %s operation: %s' % (dfile, cell_name, operation))
        name = 'dmod-%s' % operation
        self.runTo([operation], call_params, cell_name=cell_name, run=run, background=background, name=name, all_contexts=True)
        #self.runTo(operation, call_params, cell_name=cell_name, run=run, background=False)
        return retval

    def runToWrite(self, substring):
        call_params = syscall.CallParams('runToWrite', 'write', substring, break_simulation=True)        
        cell = self.cell_config.cell_context[self.target]
        self.runTo(['write'], call_params, name='write')
        self.lgr.debug('runToWrite to %s' % substring)

    def runToOpen(self, substring):
        if self.target in self.track_threads:
            self.track_threads[self.target].stopSOTrack()
        else:
            ''' do not hook mmap calls to track SO maps '''
            self.sharedSyscall[self.target].trackSO(False)
        print('warning, SO tracking has stopped')
        if self.isWindows():
            open_call_name = 'OpenFile'
        else:
            open_call_name = 'open'
        call_params = syscall.CallParams('runToOpen', open_call_name, substring, break_simulation=True)
        self.lgr.debug('runToOpen to %s' % substring)
        self.runTo([open_call_name], call_params, name='open')

    def runToSend(self, substring):
        call = self.task_utils[self.target].socketCallName('send', self.is_compat32)
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
        call = self.task_utils[self.target].socketCallName('recvmsg', self.is_compat32)
        call_params = syscall.CallParams('runToReceive', 'recvmsg', substring, break_simulation=True)        
        self.lgr.debug('runToReceive to %s' % substring)
        self.runTo(call, call_params, name='recv')

    def runToRead(self, substring, ignore_running=False):
        call_params = syscall.CallParams('runToRead', 'read', substring, break_simulation=True)        
        self.lgr.debug('runToRead to %s' % str(substring))
        self.runTo(['read'], call_params, name='read', ignore_running=ignore_running)

    def runToAccept(self, fd, flist=None, proc=None):
        if not self.isWindows():
            call = self.task_utils[self.target].socketCallName('accept', self.is_compat32)
        else:
            call = ['ACCEPT', '12083_ACCEPT', 'DuplicateObject']
        call_params = syscall.CallParams('runToAccept', 'accept', fd, break_simulation=True, proc=proc)        
           
        self.lgr.debug('runToAccept on FD: %d call is: %s' % (fd, str(call)))
        if flist is None and not self.isWindows():
            linger = True
        else:
            linger = False
        self.runTo(call, call_params, linger_in=linger, flist=flist, name='accept')
        
    def runToBind(self, addr, proc=None):
        #addr = '192.168.31.52:20480'
        if type(addr) is int:
            addr = '.*:%d' % addr
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
        self.runTo(call, call_params, name='bind')

    def runToIO(self, fd, linger=False, break_simulation=True, count=1, flist_in=None, origin_reset=False, 
                run_fun=None, proc=None, run=True, kbuf=False, call_list=None):
        if self.isWindows(self.target):
            self.winMonitor[self.target].runToIO(fd, linger, break_simulation, count, flist_in, origin_reset, 
                   run_fun, proc, run, kbuf, call_list)
            return
        ''' Run to any IO syscall.  Used for trackIO.  Also see runToInput for use with prepInject '''
        call_params = syscall.CallParams('runToIO', None, fd, break_simulation=break_simulation, proc=proc)        
        ''' nth occurance of syscalls that match params '''
        call_params.nth = count
       
        if 'runToIO' in self.call_traces[self.target]:
            self.lgr.debug('runToIO already in call_traces, add param')
            self.call_traces[self.target]['runToIO'].addCallParams([call_params])
        else:
            cell = self.cell_config.cell_context[self.target]
            self.lgr.debug('runToIO on FD %s' % str(fd))
            pid, cpu = self.context_manager[self.target].getDebugPid() 
            if pid is None:
                cpu, comm, pid = self.task_utils[self.target].curProc() 
    
            if True or self.target not in self.trace_all or self.trace_all[self.target] is None:
                accept_call = self.task_utils[self.target].socketCallName('accept', self.is_compat32)
                # add open to catch Dmods for open_replace
                calls = ['open', 'read', 'write', '_llseek', 'socketcall', 'close', 'ioctl', 'select', 'pselect6', '_newselect', 'bind']
                # but remove the open if there is already a syscall, e.g., open-dmod in the current context
                #for call in self.call_traces[self.target]:
                #    self.lgr.debug('runToIO check call %s' % call)
                #    if self.call_traces[self.target][call].callListContains(['open']):
                #        self.lgr.debug('runToIO found syscall %s contains open' % self.call_traces[self.target][call].name)
                #        if self.call_traces[self.target][call].syscall_context == cpu.current_context:
                #            self.lgr.debug('runToIO contexts match will remove open and add param to existing %s call' % call)
                #            calls.remove('open')
                #            self.call_traces[self.target][call].addCallParams([call_params])
                #        else:
                #            self.lgr.debug('runToIO contexts differ will leave open call')


                for c in accept_call:
                    calls.append(c)
                # note hack for identifying old arm kernel
                if (cpu.architecture == 'arm' and not self.param[self.target].arm_svc) or self.mem_utils[self.target].WORD_SIZE == 8:
                    calls.remove('socketcall')
                    for scall in net.callname[1:]:
                        #self.lgr.debug('runToIO adding call <%s>' % scall.lower())
                        calls.append(scall.lower())
                if self.mem_utils[self.target].WORD_SIZE == 8:
                    calls.remove('_llseek')
                    calls.remove('_newselect')
                    calls.append('lseek')
                    calls.remove('send')
                    calls.remove('recv')
                    for c in accept_call:
                        calls.remove(c)
                skip_and_mail = True
                if flist_in is not None:
                    ''' Given callback functions, use those instead of skip_and_mail '''
                    skip_and_mail = False
                self.lgr.debug('runToIO, add new syscall')
                kbuffer_mod = None
                if kbuf:
                    kbuffer_mod = self.kbuffer[self.target] 
                    self.sharedSyscall[self.target].setKbuffer(kbuffer_mod)
                the_syscall = self.syscallManager[self.target].watchSyscall(None, calls, [call_params], 'runToIO', linger=linger, flist=flist_in, 
                                 skip_and_mail=skip_and_mail, kbuffer=kbuffer_mod)
                ''' find processes that are in the kernel on IO calls '''
                frames = self.getDbgFrames()
                skip_calls = ['select', 'pselect6', '_newselect']
                for pid in list(frames):
                    if frames[pid] is None:
                        self.lgr.error('frames[%d] is None' % pid)
                        continue
                    call = self.task_utils[self.target].syscallName(frames[pid]['syscall_num'], self.is_compat32) 
                    self.lgr.debug('runToIO found %s in kernel for pid:%d' % (call, pid))
                    if call not in calls or call in skip_calls:
                       del frames[pid]
                    else:
                       self.lgr.debug('kept frames for pid %d' % pid)
                if len(frames) > 0:
                    self.lgr.debug('runToIO, call to setExits')
                    the_syscall.setExits(frames, origin_reset=origin_reset, context_override=self.context_manager[self.target].getRESimContext()) 
                #self.copyCallParams(the_syscall)
            else:
                # TBD REMOVE, not reached
                #self.trace_all[self.target].addCallParams([call_params])
                #self.lgr.debug('runToIO added parameters rather than new syscall')
                pass
    
    
            if run_fun is not None:
                SIM_run_alone(run_fun, None) 
            if run:
                self.lgr.debug('runToIO now run')
                SIM_continue(0)

    def runToInput(self, fd, linger=False, break_simulation=True, count=1, flist_in=None):
        ''' Track syscalls that consume inputs.  Intended for use by prepInject functions '''
        ''' Also see runToIO for more general tracking '''
        input_calls = ['read', 'recv', 'recvfrom', 'recvmsg', 'select']
        call_param_list = []
        for call in input_calls:
            call_param = syscall.CallParams('runToIO', call, fd, break_simulation=break_simulation)        
            call_param.nth = count
            call_param_list.append(call_param)

        self.lgr.debug('runToInput on FD %d' % fd)
        cpu, comm, pid = self.task_utils[self.target].curProc() 
        calls = ['read', 'socketcall', 'select', '_newselect', 'pselect6']
        if (cpu.architecture == 'arm' and not self.param[self.target].arm_svc) or self.mem_utils[self.target].WORD_SIZE == 8:
            calls.remove('socketcall')
            for scall in net.readcalls:
                calls.append(scall.lower())
        if self.mem_utils[self.target].WORD_SIZE == 8:
            calls.remove('recv')
        skip_and_mail = True
        if flist_in is not None:
            ''' Given callback functions, use those instead of skip_and_mail '''
            skip_and_mail = False

        the_syscall = self.syscallManager[self.target].watchSyscall(None, calls, call_param_list, 'runToIO', linger=linger, flist=flist_in, 
                                 skip_and_mail=skip_and_mail)
        for call in calls:
            self.call_traces[self.target][call] = the_syscall
        self.call_traces[self.target]['runToIO'] = the_syscall

        ''' find processes that are in the kernel on IO calls '''
        frames = self.getDbgFrames()
        for pid in list(frames):
            if frames[pid] is None:
                self.lgr.error('frame for pid %d is none?' % pid)
                continue
            call = self.task_utils[self.target].syscallName(frames[pid]['syscall_num'], self.is_compat32) 
            self.lgr.debug('runToInput found %s in kernel for pid:%d' % (call, pid))
            if call not in calls:
               del frames[pid]
        if len(frames) > 0:
            self.lgr.debug('runToInput, call to setExits')
            the_syscall.setExits(frames, context_override=self.context_manager[self.target].getRESimContext()) 
       
        
        SIM_continue(0)

    def getCurrentSO(self):
        cpu, comm, pid = self[self.target].task_utils[self.target].curProc() 
        eip = self.getEIP(cpu)
        retval = self.getSO(eip)
        return retval

    def getSOAddr(self, fname, pid):
        elf_info  = self.soMap[self.target].getSOAddr(fname, pid=pid) 
        return elf_info

    def getSOFromFile(self, fname):
        retval = ''
        self.lgr.debug('getSOFromFile %s' % fname)
        pid, cpu = self.context_manager[self.target].getDebugPid() 
        if pid is None:
           self.lgr.error('gotSOFromFile, no debug pid defined')
           return retval
        self.lgr.debug('getSOFromFile pid:%d fname %s' % (pid, fname))
        elf_info  = self.soMap[self.target].getSOAddr(fname, pid=pid) 
        if elf_info is None:
            self.lgr.error('getSO no map for %s' % fname)
            return retval
        if elf_info.address is not None:
            if elf_info.locate is not None:
                start = elf_info.locate+elf_info.offset
                end = start + elf_info.size
            else:
                # TBD fix this, assume text segment, no offset (fix for relocatable mains)
                start = 0
                end = elf_info.address + elf_info.size
            retval = ('%s:0x%x-0x%x' % (fname, start, end))
            print(retval)
        else:
            #print('None')
            pass
        return retval

    def getSO(self, eip):
        fname = self.getSOFile(eip)
        #self.lgr.debug('getCurrentSO fname for eip 0x%x is %s' % (eip, fname))
        retval = None
        if fname is not None:
            elf_info  = self.soMap[self.target].getSOAddr(fname) 
            if elf_info is None:
                self.lgr.error('getSO no map for %s' % fname)
                return
            if elf_info.address is not None:
                if elf_info.locate is not None:
                    start = elf_info.locate+elf_info.offset
                    end = start + elf_info.size
                else:
                    start = elf_info.address
                    end = elf_info.address + elf_info.size
                retval = ('%s:0x%x-0x%x' % (fname, start, end))
            else:
                #print('None')
                pass
        else:
            #print('None')
            pass
        return retval

     
    def showSOMap(self, pid=None):
        self.lgr.debug('showSOMap')
        self.soMap[self.target].showSO(pid)

    def listSOMap(self):
        self.soMap[self.target].listSO()

    def getSOMap(self, quiet=False):
        return self.soMap[self.target].getSO(quiet=quiet)

    def getSOFile(self, addr):
        fname = self.soMap[self.target].getSOFile(addr)
        return fname

    def showThreads(self):
        self.tasksDBG()
        '''
        pid, cpu = self.context_manager[self.target].getDebugPid() 
        if pid is None:
            self.lgr.error('showThreads debug pid from context manager is none?')
            return
        self.lgr.debug('showThreads for pid %d' % pid)
        thread_recs = self.context_manager[self.target].getThreadRecs()
        for rec in thread_recs:
            pid = self.mem_utils[self.target].readWord32(cpu, rec + self.param[self.target].ts_pid)
            state = self.mem_utils[self.target].readWord32(cpu, rec)
            self.lgr.debug('thread pid: %d state: 0x%x rec: 0x%x' % (pid, state, rec)) 
            print('thread pid: %d state: 0x%x rec: 0x%x' % (pid, state, rec)) 
        '''
            

    def traceExternal(self):
        call_list = ['vfork','fork', 'clone','execve','socketcall']
        call_params = {}
        call_params['socketcall'] = []
        cp = syscall.CallParams('traceExternal', 'connect', None)
        cp.param_flags.append(syscall.EXTERNAL)
        call_params['socketcall'].append(cp)

        calls = ' '.join(s for s in call_list)
        print('tracing these system calls: %s' % calls)
        cpu, comm, pid = self.task_utils[self.target].curProc() 
        self.traceMgr[self.target].open('/tmp/syscall_trace.txt', cpu)
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
        cpu, comm, pid = self.task_utils[self.target].curProc() 
        self.traceMgr[self.target].open('/tmp/syscall_trace.txt', cpu)
        for call in call_list: 
            this_call_params = []
            if call in call_params:
                this_call_params = call_params[call]
            self.call_traces[self.target][call] = self.traceSyscall(callname=call, call_params=this_call_params, trace_procs=True)

    def showBinders(self):
            self.binders.showAll('/tmp/binder.txt')
            self.binders.dumpJson('/tmp/binder.json')

    def showConnectors(self):
            self.connectors.showAll('/tmp/connector.txt')
            self.connectors.dumpJson('/tmp/connector.json')

    def saveTraces(self):
        self.showBinders()
        self.showConnectors()
        self.showProcTrace()
        self.showNets()
        print('Traces saved in /tmp.  Move them to artifact repo and run postScripts')

    def stackTrace(self, verbose=False, in_pid=None):
        self.stackFrameManager[self.target].stackTrace(verbose=verbose, in_pid=in_pid)

    def getStackTraceQuiet(self, max_frames=None, max_bytes=None):
        return self.stackFrameManager[self.target].getStackTraceQuiet(max_frames=max_frames, max_bytes=max_bytes)

    def getStackTrace(self):
        return self.stackFrameManager[self.target].getStackTrace()

    def recordStackBase(self, pid, sp):
        self.stackFrameManager[self.target].recordStackBase(pid, sp)

    def recordStackClone(self, pid, parent):
        self.stackFrameManager[self.target].recordStackClone(pid, parent)
 
    def resetOrigin(self, cpu=None):
        self.lgr.debug('resetOrigin')
        if cpu is None:
            pid, cpu = self.context_manager[self.target].getDebugPid() 
        cmd = 'disable-reverse-execution'
        SIM_run_command(cmd)
        self.lgr.debug('reset Origin rev ex disabled')
        cmd = 'enable-reverse-execution'
        SIM_run_command(cmd)
        self.lgr.debug('reset Origin rev ex enabled')
        self.rev_execution_enabled = True
        if self.bookmarks is not None:
            self.bookmarks.setOrigin(cpu, self.context_manager[self.target].getIdaMessage())
        else:
            self.lgr.debug('genMonitor resetOrigin without bookmarks, assume you will use bookmark0')

    def clearBookmarks(self, reuse_msg=False):
        pid, cpu = self.context_manager[self.target].getDebugPid() 
        self.lgr.debug('genMonitor clearBookmarks')
        if pid is None:
            #print('** Not debugging?? **')
            self.lgr.debug('clearBookmarks, Not debugging?? **')
            return False
       
        self.bookmarks.clearMarks()
        SIM_run_alone(self.resetOrigin, cpu)
        #self.resetOrigin(cpu)
        self.dataWatch[self.target].resetOrigin(cpu.cycles, reuse_msg=reuse_msg, record_old=True)
        cpu, comm, pid = self.task_utils[self.target].curProc() 
        #self.stopTrackIO()
        self.lgr.debug('genMonitor clearBookmarks call clearWatches')
        self.rev_to_call[self.target].resetStartCycles()
        return True

    def writeRegValue(self, reg, value, alone=False, reuse_msg=False, target_cpu=None):
        if target_cpu is None:
            target = self.target
        else:
            target = self.cell_config.cellFromCPU(target_cpu)
        cpu, comm, pid = self.task_utils[target].curProc() 
        self.mem_utils[target].setRegValue(cpu, reg, value)
        #self.lgr.debug('writeRegValue %s, %x ' % (reg, value))
        if self.reverseEnabled():
            if alone:
                SIM_run_alone(self.clearBookmarks, reuse_msg) 
            else:
                self.clearBookmarks(reuse_msg=reuse_msg)

    def writeWord(self, address, value, target_cpu=None):
        ''' NOTE: wipes out bookmarks! '''
        if target_cpu is None:
            target = self.target
        else:
            target = self.cell_config.cellFromCPU(target_cpu)
        cpu, comm, pid = self.task_utils[target].curProc() 
        self.mem_utils[target].writeWord(cpu, address, value)
        #phys_block = cpu.iface.processor_info.logical_to_physical(address, Sim_Access_Read)
        #SIM_write_phys_memory(cpu, phys_block.address, value, 4)
        if self.reverseEnabled():
            self.lgr.debug('writeWord(0x%x, 0x%x), disable reverse execution to clear bookmarks, then set origin' % (address, value))
            self.clearBookmarks()

    def writeByte(self, address, value, target_cpu=None):
        ''' NOTE: wipes out bookmarks! '''
        if target_cpu is None:
            target = self.target
        else:
            target = self.cell_config.cellFromCPU(target_cpu)
        cpu, comm, pid = self.task_utils[target].curProc() 
        self.mem_utils[target].writeByte(cpu, address, value)
        #phys_block = cpu.iface.processor_info.logical_to_physical(address, Sim_Access_Read)
        #SIM_write_phys_memory(cpu, phys_block.address, value, 4)
        if self.reverseEnabled():
            self.lgr.debug('writeByte(0x%x, 0x%x), disable reverse execution to clear bookmarks, then set origin' % (address, value))
            self.clearBookmarks()

    def writeString(self, address, string, target_cpu=None):
        if target_cpu is None:
            target = self.target
        else:
            target = self.cell_config.cellFromCPU(target_cpu)
        if target in self.task_utils:
            ''' NOTE: wipes out bookmarks! '''
            cpu, comm, pid = self.task_utils[target].curProc() 
            self.lgr.debug('writeString 0x%x %s' % (address, string))
            self.mem_utils[target].writeString(cpu, address, string)
            if self.reverseEnabled():
                self.lgr.debug('writeString, disable reverse execution to clear bookmarks, then set origin')
                self.clearBookmarks()
            else:
                self.lgr.debug('writeString reverse execution was not enabled.')

    def stopDataWatch(self, immediate=False):
        self.lgr.debug('genMonitor stopDataWatch')
        self.dataWatch[self.target].stopWatch(break_simulation=True, immediate=immediate)

    def showDataWatch(self):
        self.dataWatch[self.target].showWatch()

    def addDataWatch(self, start, length):
        self.lgr.debug('genMonitory watchData 0x%x count %d' % (start, length))
        msg = "User range 0x%x count %d" % (start, length)
        self.dataWatch[self.target].setRange(start, length, msg) 

    def watchData(self, start=None, length=None, show_cmp=False):
        self.lgr.debug('genMonitor watchData')
        if start is not None:
            self.lgr.debug('genMonitory watchData 0x%x count %d' % (start, length))
            msg = "User range 0x%x count %d" % (start, length)
            self.dataWatch[self.target].setRange(start, length, msg) 
        self.is_monitor_running.setRunning(True)
        if self.dataWatch[self.target].watch(show_cmp):
            SIM_continue(0)
        else: 
            print('no data being watched')
            self.lgr.debug('genMonitor watchData no data being watched')
            self.is_monitor_running.setRunning(False)

    def isProtectedMemory(self, addr):
        ''' compat with CGC version '''
        return False 

    def showHaps(self):
        for cell_name in self.context_manager:
            print('Cell: %s' % cell_name)
            self.context_manager[cell_name].showHaps()

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
        cpu, comm, pid = self.task_utils[self.target].curProc() 
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
        #        self.lgr.debug('genMonitor exitMaze pid:%d, using syscall defined for %s' % (pid, syscallname))
        #        tod_track = self.call_traces[self.target][syscallname]
        #    else:
        #        self.lgr.debug('genMonitor exitMaze pid:%d, using new syscall for %s' % (pid, syscallname))
        #        tod_track = syscall.Syscall(self, self.target, None, self.param[self.target], self.mem_utils[self.target], self.task_utils[self.target], 
        #                   self.context_manager[self.target], None, self.sharedSyscall[self.target], self.lgr,self.traceMgr, 
        #                   call_list=[syscallname])
        one_proc = False
        dbgpid, dumb1 = self.context_manager[self.target].getDebugPid() 
        if dbgpid is not None:
            one_proc = True
        em = exitMaze.ExitMaze(self, cpu, pid, tod_track, self.context_manager[self.target], self.task_utils[self.target], self.mem_utils[self.target], debugging, one_proc, self.lgr)
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
            pid, planted, broke = m.getStatus()
            print('%d planted: %d  broke: %d' % (pid, planted, broke))
        no_watch_list = self.context_manager[self.target].getNoWatchList()
        cpu = self.cell_config.cpuFromCell(self.target)
        print('No watch list:')
        for rec in no_watch_list:
            pid = self.mem_utils[self.target].readWord32(cpu, rec + self.param[self.target].ts_pid)
            print('  %d' % pid)
        

    def showParams(self):
        self.param.printParams()

    #def inProcList(self, pid):
    #    if pid in self.proc_list[self.target]:
    #        return True
    #    else:
    #        return False

    #def myTasks(self):
    #    print('Current proc_list for %s' % self.target)
    #    for pid in self.proc_list[self.target]:
    #        print('%d %s' % (pid, self.proc_list[self.target][pid]))

    def getDmodPaths(self):
        dmod_dict = {}
        for target in self.context_manager:
            dmod_dict[target] = [] 
            for call in self.call_traces[target]:
                dmod_list = self.call_traces[target][call].getDmods()
                for dmod in dmod_list:
                    path = dmod.getPath()
                    if path not in dmod_dict[target]:
                        dmod_dict[target].append(path)
        return dmod_dict

    def showDmods(self):
        for target in self.context_manager:
            for call in self.call_traces[target]:
                dmod_list = self.call_traces[target][call].getDmods()
                for dmod in dmod_list:
                    path = dmod.getPath()
                    print('%s %s %s' % (target, call, path))                    

    def rmAllDmods(self):
        for target in self.context_manager:
            call_copy = list(self.call_traces[target])
            for call in call_copy:
                self.call_traces[target][call].rmDmods()
                    

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
                self.rev_to_call[cell_name].pickleit(name, cell_name)
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
                
        net_link_file = os.path.join('./', name, 'net_link.pickle')
        pickle.dump( self.link_dict, open( net_link_file, "wb" ) )
       
        self.stackFrameManager[self.target].pickleit(name) 

        debug_info_file = os.path.join('./', name, 'debug_info.pickle')
        debug_info = {}
        debug_pid, debug_cpu = self.context_manager[self.target].getDebugPid()
        self.lgr.debug('writeConfig got from contextManager debug_pid %s cpu %s' % (debug_pid, debug_cpu.name))
        if debug_pid is not None:
            debug_info['pid'] = debug_pid
            debug_info['cpu'] = debug_cpu.name
            self.lgr.debug('writeConfig debug_pid %d cpu %s' % (debug_pid, debug_cpu.name))
        elif self.debug_info is not None:
            debug_info = self.debug_info
        else:
            self.lgr.debug('writeConfig no debug_pid found from context manager')
        pickle.dump( debug_info, open(debug_info_file, "wb" ) )

        if self.connectors is not None:
            connector_file = os.path.join('./', name, 'connector.json')
            self.connectors.dumpJson(connector_file)
        if self.binders is not None:
            binder_file = os.path.join('./', name, 'binder.json')
            self.binders.dumpJson(binder_file)

        dmod_file = os.path.join('./', name, 'dmod.pickle')
        dmod_dict = self.getDmodPaths()
        pickle.dump(dmod_dict, open(dmod_file, "wb"))

        self.lgr.debug('writeConfig done to %s' % name)

    def showCycle(self):
        cpu = self.cell_config.cpuFromCell(self.target)
        if self.bookmarks is None:
            print ('cpu cycles  0x%x' % (cpu.cycles))
        else:
            cycles = self.bookmarks.getCurrentCycle(cpu)
            print ('cpu cycles since _start: 0x%x absolute cycle: 0x%x' % (cycles, cpu.cycles))
        
    def continueForward(self):
        self.lgr.debug('continueForward')
        self.is_monitor_running.setRunning(True)
        SIM_continue(0)

    def showNets(self):
        net_commands = self.netInfo[self.target].getCommands()
        if len(net_commands) > 0:
           print('Network definition commands:')
        else:
           print('No exec of ip addr or ifconfig found')
        for c in net_commands:
            print(c)
        with open('/tmp/networks.txt', 'w') as fh:
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
        pid, cpu = self.context_manager[self.target].getDebugPid() 
        value = self.mem_utils[self.target].readWord32(cpu, addr)
        print('0x%x' % value)

    def printRegJson(self):
        self.lgr.debug('printRegJson')
        pid, cpu = self.context_manager[self.target].getDebugPid() 
        self.mem_utils[self.target].printRegJson(cpu)

    def flushTrace(self):
        if self.target in self.traceMgr:
            self.traceMgr[self.target].flush()
        if self.target in self.winMonitor:
            self.winMonitor[self.target].flushTrace()

    def getCurrentThreadLeaderPid(self):
        pid = self.task_utils[self.target].getCurrentThreadLeaderPid()
        print(pid)        

    def getGroupPids(self, in_pid):
        leader_pid = self.task_utils[self.target].getGroupLeaderPid(in_pid)
        plist = self.task_utils[self.target].getGroupPids(leader_pid)
        if plist is None:
            print('Could not find leader %d' % leader_pid)
            return
        for pid in plist:
            print(pid)
        
    def reportMode(self):
        pid, cpu = self.context_manager[self.target].getDebugPid() 
        if pid is None:
            cpu, comm, pid = self.task_utils[self.target].curProc() 
        
        self.lgr.debug('reportMode for pid %d' % pid)
        self.mode_hap = RES_hap_add_callback_obj("Core_Mode_Change", cpu, 0, self.modeChangeReport, pid)
        self.stop_hap = RES_hap_add_callback("Core_Simulation_Stopped", self.stopModeChanged, None)

    def setTarget(self, target):
        if target not in self.cell_config.cell_context:
            print('Unknown target: %s' % target)
            return
        self.target = target  
        print('Target is now: %s' % target)
        self.lgr.debug('Target is now: %s' % target)

    def showTargets(self):
        print('Targets:')
        for target in self.context_manager:
            print('\t'+target)

    def reverseEnabled(self):
        # TBD Simics VT_revexec_active is broken.  Often gives the wrong answer
        #return True
        if self.disable_reverse: 
            return False
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
       

    def v2p(self, addr):
        cpu = self.cell_config.cpuFromCell(self.target)
        value = self.mem_utils[self.target].v2p(cpu, addr)
        print('0x%x' % value)

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

    def retrack(self, clear=True, callback=None, use_backstop=True):
        self.lgr.debug('retrack')
        if callback is None:
            callback = self.stopTrackIO
        ''' Use existing data watches to track IO.  Clears later watch marks '''
        cpu = self.cell_config.cpuFromCell(self.target)
        eip = self.getEIP(cpu)
        self.lgr.debug('retrack cycle: 0x%x eip: 0x%x callback %s' % (cpu.cycles, eip, str(callback)))
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

    def trackRecv(self, fd, max_marks=None):
        call_list = ['RECV']
        self.trackIO(fd, call_list=call_list, max_marks=max_marks)

    def trackKbuf(self, fd):
        self.trackIO(fd, kbuf=True)

    def trackIO(self, fd, origin_reset=False, callback=None, run_fun=None, max_marks=None, count=1, 
                quiet=False, mark_logs=False, kbuf=False, call_list=None):
        self.lgr.debug('trackIO') 
        if self.bookmarks is None:
            self.lgr.error('trackIO called but no debugging session exists.')
            return
        if not self.reverseEnabled() and not kbuf:
            print('Reverse execution must be enabled.')
            return
        self.track_started = True
        self.stopTrackIOAlone()
        cpu = self.cell_config.cpuFromCell(self.target)
        self.clearWatches(cycle=cpu.cycles)
        self.restoreDebugBreaks()
        if callback is None:
            done_callback = self.stopTrackIO
        else:
            done_callback = callback
        self.lgr.debug('trackIO stopped track and cleared watches current context %s' % str(cpu.current_context))
        if kbuf:
            self.kbuffer[self.target] = kbuffer.Kbuffer(self, cpu, self.context_manager[self.target], self.mem_utils[self.target], self.lgr)
            self.lgr.debug('trackIO using kbuffer')

        self.dataWatch[self.target].trackIO(fd, done_callback, self.is_compat32, max_marks, quiet=quiet)
        self.lgr.debug('trackIO back from dataWatch, now run to IO')

        if self.coverage is not None:
            self.coverage.doCoverage()

        if mark_logs:
            self.traceFiles[self.target].markLogs(self.dataWatch[self.target])

        self.runToIO(fd, linger=True, break_simulation=False, origin_reset=origin_reset, run_fun=run_fun, count=count, kbuf=kbuf,
                     call_list=call_list)

   
    def stopTrackIO(self, immediate=False):
        SIM_run_alone(self.stopTrackIOAlone, immediate)

    def stopTrackIOAlone(self, immediate=False):
        thread_pids = self.context_manager[self.target].getThreadPids()
        self.lgr.debug('stopTrackIO got %d thread_pids' % len(thread_pids))
        crashing = False 
        for pid in thread_pids:
            if self.page_faults[self.target].hasPendingPageFault(pid):
                comm = self.task_utils[self.target].getCommFromPid(pid)
                cycle = self.page_faults[self.target].getPendingFaultCycle(pid)
                print('Pid %d (%s) has pending page fault, may be crashing. Cycle %s' % (pid, comm, cycle))
                self.lgr.debug('stopTrackIO Pid %d (%s) has pending page fault, may be crashing.' % (pid, comm))
                leader = self.task_utils[self.target].getGroupLeaderPid(pid)
                self.page_faults[self.target].handleExit(pid, leader)
                crashing = True 
               
        self.syscallManager[self.target].rmSyscall('runToIO', context=self.context_manager[self.target].getRESimContextName(), rm_all=crashing) 
        #if 'runToIO' in self.call_traces[self.target]:
        #    self.stopTrace(syscall = self.call_traces[self.target]['runToIO'])
        #    print('Tracking complete.')
        self.lgr.debug('stopTrackIO, call stopDataWatch...')

        #self.removeDebugBreaks(immediate=immediate)

        self.stopDataWatch(immediate=immediate)
        self.dataWatch[self.target].rmBackStop()
        self.dataWatch[self.target].setRetrack(False)
        if self.coverage is not None:
            self.coverage.saveCoverage()
        if self.injectIOInstance is not None:
            SIM_run_alone(self.injectIOInstance.delCallHap, None)
        self.dataWatch[self.target].pickleFunEntries(self.run_from_snap)

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
            with open('/tmp/badjson.txt', 'w') as fh:
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
        self.stopTrackIO(immediate=True)
        self.dataWatch[self.target].removeExternalHaps(immediate=True)

        self.stopThreadTrack(immediate=True)
        self.noWatchSysEnter()

        self.removeDebugBreaks(immediate=True, keep_watching=keep_watching, keep_coverage=keep_coverage)
        self.track_finished = True

    def goToDataMark(self, index):
        was_watching = self.context_manager[self.target].watchingThis()
        self.lgr.debug('goToDataMark(%d)' % index)

        ''' Assume that this is the first thing done after a track.
            Remove all haps that might interfer with reversing. '''
        self.stopTracking()
        cycle = self.dataWatch[self.target].goToMark(index)
        if cycle is not None:
            self.context_manager[self.target].watchTasks(set_debug_pid=True)
            if not was_watching:
                self.context_manager[self.target].setAllHap()
        else:
            print('Index %d does not have an associated data mark.' % index)
        return cycle

    def goToWriteMark(self, index):
        was_watching = self.context_manager[self.target].watchingThis()
        cycle = self.trackFunction[self.target].goToMark(index)
        if cycle is not None:
            self.context_manager[self.target].watchTasks(set_debug_pid=True)
            if not was_watching:
                self.context_manager[self.target].setAllHap()
        return cycle

    def goToBasicBlock(self, addr):
        self.lgr.debug('goToBasicBlock 0x%x' % addr)
        self.removeDebugBreaks()
        cycle = self.coverage.goToBasicBlock(addr)
        self.restoreDebugBreaks(was_watching=True)
        if cycle is not None:
            self.context_manager[self.target].watchTasks(set_debug_pid=True)
        else:
            print('address 0x%x not in blocks hit' % addr)
            self.lgr.debug('address 0x%x not in blocks hit' % addr)
            self.gdbMailbox('address %s not in blocks hit.' % addr)
        return cycle
       
    def mft4(self, pid): 
        want =  0xdf953b00
        wantX = 0xdf950000
        ts_next = self.param[self.target].ts_next
        cpu = self.cell_config.cpuFromCell(self.target)
        tr = self.task_utils[self.target].getRecAddrForPid(pid)
        ts_group_lead = self.param[self.target].ts_group_leader
        print('group lead 0x%x' % ts_group_lead)
        group_head = ts_group_lead + 0xe*4
        ts_group_head = self.param[self.target].ts_thread_group_list_head
        print('group head 0x%x ts_group_head 0x%x' % (group_head, ts_group_head))
        group_tr = self.mem_utils[self.target].readPtr(cpu, tr+group_head) - group_head
        lh = self.task_utils[self.target].read_list_head(cpu, group_tr, group_head)

        s = self.task_utils[self.target].readTaskStruct(group_tr-group_head, cpu)
        print('pid %d' % s.pid)
        print('pid: %d tr: 0x%x group_head: %d group_tr: 0x%x head_pid: %d' % (pid, tr, group_head, group_tr, s.pid))

        print('lh next 0x%x' % lh.next)


    def mft3(self, pid): 
        want =  0xdf953b00
        wantX = 0xdf950000
        ts_next = self.param[self.target].ts_next
        cpu = self.cell_config.cpuFromCell(self.target)
        tr = self.task_utils[self.target].getRecAddrForPid(pid)
        ts_group_lead = self.param[self.target].ts_group_leader
        group_head = ts_group_lead + 17*4
        print('group head 0x%x' % group_head)
        for i in range(0, 120, 4):
            offset = ts_group_lead + i
            '''
            value = self.mem_utils[self.target].readPtr(cpu, tr+offset)
            masked = value & 0xffff0000
            print('got 0x%x offset 0x%x ' % (value, offset))
            if masked == wantX:
                print('got#### 0x%x offset 0x%x ' % (value, offset))
            
            '''
            lh = self.task_utils[self.target].read_list_head(cpu, tr, offset)
            #if lh is not None and lh.next == want:
            if lh is not None and lh.next is not None:
                masked = lh.next and 0xffff0000
                try:
                    value = self.mem_utils[self.target].readPtr(cpu, tr+offset)
                    s = self.task_utils[self.target].readTaskStruct(value-offset, cpu)
                except:
                    continue
                if s is not None:
                    print('value 0x%x got 0x%x offset 0x%x pid: %d' % (value, lh.next, i/4, s.pid))
                


        '''
        group_head = ts_group_lead + 17*4
        value = self.mem_utils[self.target].readPtr(cpu, tr+group_head) 
        print('tr 0x%x  tr_group head is 0x%x' % (tr, tr+group_head))
        print('leader 0x%x  group_head 0x%x   value there is 0x%x' % (ts_group_lead, group_head, value))
        #ts_childr = self.param[self.target].ts_thread_group_list_head
        ts_childr = group_head
        lh = self.task_utils[self.target].read_list_head(cpu, tr, ts_childr)
        print('list head next 0x%x  list head prev 0x%x' % (lh.next, lh.prev))
        '''
        
    def mft2(self, pid):
        ts_next = self.param[self.target].ts_next
        ts_prev = self.param[self.target].ts_prev
        ts_thread = self.param[self.target].ts_thread_group_list_head
        ts_childr = self.param[self.target].ts_children_list_head
        print('ts_next %d  ts_prev %d  thread_group %d child_list %d' % (ts_next, ts_prev, ts_thread, ts_childr))
        ts_parent = self.param[self.target].ts_parent
        ts_real_parent = self.param[self.target].ts_real_parent
        cpu = self.cell_config.cpuFromCell(self.target)
        leader_pid = self.task_utils[self.target].getGroupLeaderPid(pid)
        print('leader of %d is %d' % (pid, leader_pid))

        tr = self.task_utils[self.target].getRecAddrForPid(pid)
        s = self.task_utils[self.target].readTaskStruct(tr, cpu)
        print('tr is 0x%x  pid %d ' % (tr, pid))
        prev_trx = self.mem_utils[self.target].readPtr(cpu, tr+ts_prev) 
        prev_tr = prev_trx - ts_next
        prev_s = self.task_utils[self.target].readTaskStruct(prev_tr, cpu)

        next_trx = self.mem_utils[self.target].readPtr(cpu, tr+ts_next)
        next_tr = next_trx - ts_next
        next_s = self.task_utils[self.target].readTaskStruct(next_tr, cpu)

        childr_trx = self.mem_utils[self.target].readPtr(cpu, tr+ts_childr)
        childr_tr = childr_trx 
        childr_s = self.task_utils[self.target].readTaskStruct(childr_tr, cpu)

        print('prev trx 0x%x prev rec 0x%x pid: %d' % (prev_trx, prev_tr, prev_s.pid))
        print('next trx 0x%x next rec 0x%x pid: %d' % (next_trx, next_tr, next_s.pid))
        print('childr trx 0x%x childr rec 0x%x pid: %d' % (childr_trx, childr_tr, childr_s.pid))
        ''' 
        print('pid %d  comm %s group_leader 0x%x prev 0x%x next 0x%x' % (s.pid, s.comm, s.group_leader, (s.next-ts_next), (s.prev-ts_prev)))
        clh = self.param[self.target].ts_children_list_head
        if clh is not None:
            val = self.mem_utils[self.target].readPtr(cpu, tr+clh) - clh
            print('child list head is 0x%x' % val)
            child = self.task_utils[self.target].readTaskStruct(val, cpu)
            print('child pid %d' % child.pid)
        slh = self.param[self.target].ts_sibling_list_head
        if slh is not None:
            val = self.mem_utils[self.target].readPtr(cpu, tr+slh) - slh
            print('sib list head is 0x%x' % val)
            sib = self.task_utils[self.target].readTaskStruct(val, cpu)
            print('sib pid %d' % sib.pid)
        ''' 

    
    def addProc(self, pid, leader_pid, comm, clone=False):    
        self.traceProcs[self.target].addProc(pid, leader_pid, comm=comm, clone=clone)

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
            sor=False, cover=False, fname=None, target=None, targetFD=None, trace_all=False, 
            save_json=None, limit_one=False, no_rop=False, go=True, max_marks=None, instruct_trace=False, mark_logs=False,
            break_on=None, no_iterators=False, only_thread=False, no_track=False, no_reset=False):
        ''' Inject data into application or kernel memory.  This function assumes you are at a suitable execution point,
            e.g., created by prepInject or prepInjectWatch.  '''
        ''' Use go=False and then go yourself if you are getting the instance for your own use, otherwise
            the instance is not defined until it is done.
            use no_reset True to stop the tracking if RESim would need to reset the origin.'''
        self.track_started = True
        if 'coverage/id' in dfile or 'trackio/id' in dfile:
            print('Modifying a coverage or injectIO file name to a queue file name for injection into application memory')
            if 'coverage/id' in dfile:
                dfile = dfile.replace('coverage', 'queue')
            else:
                dfile = dfile.replace('trackio', 'queue')
        if type(save_json) is bool:
            save_json = '/tmp/track.json'
        if self.bookmarks is not None:
            self.goToOrigin()
        this_cpu, comm, pid = self.task_utils[self.target].curProc() 
        if cpu is None:
            cpu = this_cpu
        self.lgr.debug('genMonitor injectIO pid %d' % pid)
        cell_name = self.getTopComponentName(cpu)
        self.dataWatch[self.target].resetWatch()
        if max_marks is not None:
            self.dataWatch[self.target].setMaxMarks(max_marks) 
        self.page_faults[self.target].stopWatchPageFaults()
        self.watchPageFaults(pid)
        if mark_logs:
            self.traceFiles[self.target].markLogs(self.dataWatch[self.target])
        self.rmDebugWarnHap()
        self.injectIOInstance = injectIO.InjectIO(self, cpu, cell_name, pid, self.back_stop[self.target], dfile, self.dataWatch[self.target], self.bookmarks, 
                  self.mem_utils[self.target], self.context_manager[self.target], self.lgr, 
                  self.run_from_snap, stay=stay, keep_size=keep_size, callback=callback, packet_count=n, stop_on_read=sor, coverage=cover, fname=fname,
                  target=target, targetFD=targetFD, trace_all=trace_all, save_json=save_json, limit_one=limit_one, no_track=no_track,  no_reset=no_reset, 
                  no_rop=no_rop, instruct_trace=instruct_trace, break_on=break_on, mark_logs=mark_logs, no_iterators=no_iterators, only_thread=only_thread)

        if go:
            self.injectIOInstance.go()
        return self.injectIOInstance
   
    def aflInject(self, target, index, instance=None, cover=False, save_json=False):
        afl_file = aflPath.getAFLPath(target, index, instance)
        save_json_file = None
        if save_json:
            save_json_file = '/tmp/trackio.json' 
        if afl_file is not None:
            self.injectIO(afl_file, cover=cover, save_json=save_json_file)

    def aflInjectTCP(self, target, index, instance=None, cover=False, save_json=False):
        afl_file = aflPath.getAFLPath(target, index, instance)
        if afl_file is not None:
            if save_json:
                self.injectIO(afl_file, cover=cover, n=-1, save_json='/tmp/track.json')
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
            shutil.copyfile(afl_file, '/tmp/sendudp')
            self.trackIO(FD, run_fun=self.doudp)
            print('tracking %s' % afl_file)
 
    def tagIterator(self, index):    
        ''' User driven identification of an iterating function -- will collapse many watch marks into one '''
        self.dataWatch[self.target].tagIterator(index)

    def runToKnown(self, go=True):
        self.soMap[self.target].runToKnown()
        if go:
            SIM_continue(0)

    def runToOther(self, go=True):
        ''' Continue execution until a different library is entered, or main text is returned to '''
        cpu = self.cell_config.cpuFromCell(self.target)
        eip = self.mem_utils[self.target].getRegValue(cpu, 'eip')

        if self.isWindows():
            self.lgr.debug('runToOther eip 0x%x' % eip)
            self.run_to[self.target].runToKnown(eip)
        else:
            self.soMap[self.target].runToKnown(eip)
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
        pid, cpu = self.context_manager[self.target].getDebugPid() 

        read_watch_marks = self.dataWatch[self.target].getWatchMarks()
        self.trackFunction[self.target].trackFunction(pid, fun, self.fun_mgr, read_watch_marks, show_compare)

    def saveMemory(self, addr, size, fname):
        cpu = self.cell_config.cpuFromCell(self.target)
        byte_array = self.mem_utils[self.target].readBytes(cpu, addr, size)
        with open(fname, 'wb') as fh:
            fh.write(byte_array)

    def pageInfo(self, addr, quiet=False):
        cpu = self.cell_config.cpuFromCell(self.target)
        ptable_info = pageUtils.findPageTable(cpu, addr, self.lgr, force_cr3=self.mem_utils[self.target].getKernelSavedCR3())
        if not quiet:
            print(ptable_info.valueString())
        cpu = self.cell_config.cpuFromCell(self.target)
        if ptable_info.entry is not None:
            pei = pageUtils.PageEntryInfo(ptable_info.entry, cpu.architecture)
            if not quiet:
                print('writable? %r' % pei.writable)
        return ptable_info

    def toPid(self, pid, callback = None):
        self.lgr.debug('genMonitor toPid %d' % pid)
        if callback is None:
            callback = self.toUser
        self.context_manager[self.target].catchPid(pid, callback)
        SIM_continue(0)

    def cleanMode(self, dumb):
        if self.mode_hap is not None:
            #print('mode_hap was lingering, delete it')
            RES_hap_delete_callback_id("Core_Mode_Change", self.mode_hap)
            self.mode_hap = None

    def watchROP(self, watching=True):
        self.lgr.debug('watchROP')
        for t in self.ropCop:
            self.lgr.debug('ropcop instance %s' % t)
        if self.target in self.ropCop:
            self.ropCop[self.target].watchROP(watching=watching)

    def enableCoverage(self, fname=None, physical=False, backstop_cycles=None):
        ''' Enable code coverage '''
        ''' Intended for use with trackIO '''
        if self.coverage is not None:
            if fname is not None:
                full_path = self.targetFS[self.target].getFull(fname)
            else:
                full_path = None
            pid, cpu = self.context_manager[self.target].getDebugPid() 
            self.coverage.enableCoverage(pid, fname=full_path, backstop = self.back_stop[self.target], backstop_cycles=backstop_cycles)
            self.coverage.doCoverage(physical=physical)
        else:
            self.lgr.error('enableCoverage, no coverage defined')

    def mapCoverage(self, fname=None):
        ''' Enable code coverage and do mapping '''
        ''' Not intended for use with trackIO, use enableCoverage for that '''
        if fname is not None:
            full_path = self.targetFS[self.target].getFull(fname, self.lgr)
        else:
            full_path = None
        self.lgr.debug('mapCoverage file (None means use prog name): %s' % full_path)
        self.enableCoverage(fname=full_path)

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
        pid, cpu = self.context_manager[self.target].getDebugPid() 
        esp = self.mem_utils[self.target].getRegValue(cpu, 'esp')
        base = esp & 0xffffff000
        proc_break = self.context_manager[self.target].genBreakpoint(None, Sim_Break_Linear, Sim_Access_Execute, base, 0x3000, 0)
        pid_list = self.context_manager[self.target].getThreadPids()
        prec = Prec(cpu, None, pid_list, who='to stack')
        prec.debugging = True
        f1 = stopFunction.StopFunction(self.skipAndMail, [], nest=False)
        flist = [f1]

        self.proc_hap = self.context_manager[self.target].genHapIndex("Core_Breakpoint_Memop", self.textHap, prec, proc_break, 'stack_hap')

        hap_clean = hapCleaner.HapCleaner(cpu)
        hap_clean.add("GenContext", self.proc_hap)
        stop_action = hapCleaner.StopAction(hap_clean, None, flist)
        self.stop_hap = RES_hap_add_callback("Core_Simulation_Stopped", 
          self.stopHap, stop_action)

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

    def precall(self, pid=None):
        if pid is None:
            cpu, comm, pid = self.task_utils[self.target].curProc() 
        self.lgr.debug('precall pid:%d' % pid)
        cycle_list = self.rev_to_call[self.target].getEnterCycles(pid)
        if cycle_list is None:
            print('No cycles for pid %d' % pid)
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
                print('No cycle found for pid %d that is earlier than current cycle 0x%x' % (pid, cpu.cycles))  
            else:
                did_remove = self.removeDebugBreaks()
                SIM_run_command('pselect %s' % cpu.name)
                previous = prev_cycle-1
                cmd='skip-to cycle=0x%x' % previous
                self.lgr.debug('precall cmd: %s' % cmd)
                SIM_run_command(cmd)
                if did_remove:
                    self.restoreDebugBreaks(was_watching=True)
                eip = self.getEIP()
                self.lgr.debug('precall skipped to cycle 0x%x eip: 0x%x' % (cpu.cycles, eip))
                if cpu.cycles != previous:
                    self.lgr.error('precall Cycle not as expected, wanted 0x%x got 0x%x' % (previous, cpu.cycles))
                else:
                    cpl = memUtils.getCPL(cpu)
                    if cpl == 0: 
                        self.lgr.error('precall ended up in kernel, quit')
                        self.quit()

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

   
    def swapSOPid(self, old, new):
        self.lgr.debug('genMonitor swapSOPid')
        retval = self.soMap[self.target].swapPid(old, new)
        if retval:
            self.task_utils[self.target].swapExecPid(old, new)
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
        print('context: %s' % (str(cpu.current_context)))

    def traceMalloc(self):
        self.lgr.debug('genMonitor traceMalloc')
        cpu = self.cell_config.cpuFromCell(self.target)
        cell = self.cell_config.cell_context[self.target]
        self.trace_malloc = traceMalloc.TraceMalloc(self.fun_mgr, self.context_manager[self.target], 
               self.mem_utils[self.target], self.task_utils[self.target], cpu, cell, self.dataWatch[self.target], self.lgr)

    def showMalloc(self):
        self.trace_malloc.showList()

    def stopTraceMalloc(self):
        if self.trace_malloc is not None:
            self.trace_malloc.stopTrace()
        self.trace_malloc = None

    def trackFile(self, substring):
        ''' track access to XML file access '''
        self.track_started = True
        self.stopTrackIO()
        self.clearWatches()
        self.lgr.debug('trackFile stopped track and cleared watchs')
        self.dataWatch[self.target].trackFile(self.stopTrackIO, self.is_compat32)
        self.lgr.debug('trackFile back from dataWatch, now run to IO')
        if self.coverage is not None:
            self.coverage.doCoverage()
        self.runToOpen(substring)    

    def fuzz(self, path, n=1, fname=None):
        cpu, comm, pid = self.task_utils[self.target].curProc() 
        cell_name = self.getTopComponentName(cpu)
        self.debugPidGroup(pid, to_user=False)
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
        ''' not hack of n = -1 to indicate tcp '''
        self.afl(n=-1, sor=sor, fname=fname, port=port, dead=dead)

    def afl(self,n=1, sor=False, fname=None, linear=False, target=None, dead=None, port=8765, one_done=False):
        ''' sor is stop on read; target names process other than consumer; if dead is True,it 
            generates list of breakpoints to later ignore because they are hit by some other thread over and over. Stored in checkpoint.dead.
            fname is to fuzz a library'''
        self.lgr.debug('genMonitor afl')
        cpu, comm, pid = self.task_utils[self.target].curProc() 
        cell_name = self.getTopComponentName(cpu)
        ''' prevent use of reverseToCall.  TBD disable other modules as well?'''
        self.disable_reverse = True
        if target is None:
            if not self.checkUserSpace(cpu):
                return
            # keep gdb 9123 port free
            self.gdb_port = 9124
            self.debugPidGroup(pid, to_user=False)
        full_path = None
        if fname is not None and target is None:
            full_path = self.targetFS[self.target].getFull(fname, lgr=self.lgr)
            if full_path is None:
                self.lgr.error('unable to get full path from %s' % fname)
                return
        else: 
            full_path=fname
        fuzz_it = afl.AFL(self, cpu, cell_name, self.coverage, self.back_stop[self.target], self.mem_utils[self.target], self.dataWatch[self.target], 
            self.run_from_snap, self.context_manager[self.target], self.page_faults[self.target], self.lgr, packet_count=n, stop_on_read=sor, fname=full_path, 
            linear=linear, target=target, create_dead_zone=dead, port=port, one_done=one_done)
        if target is None:
            self.noWatchSysEnter()
            fuzz_it.goN(0)

    def aflFD(self, fd, snap_name, count=1):
        self.prepInject(fd, snap_name, count=count)

    def prepInject(self, fd, snap_name, count=1):
        ''' 
            Prepare a system checkpoint for fuzzing or injection by running until IO on some FD.
            fd -- will runToIOish on that FD and will record the buffer address for use by injectIO or fuzzing.
            snap_name -- will writeConfig to that snapshot.  Use that snapshot for fuzz and afl commands. '''
        if self.reverseEnabled():
            if '-' in snap_name:
               print('Avoid use of - in snapshot names.')
               return
            cpu = self.cell_config.cpuFromCell(self.target)
            cell_name = self.getTopComponentName(cpu)
            debug_pid, dumb = self.context_manager[self.target].getDebugPid() 
            if debug_pid is None:
                cpu, comm, pid = self.task_utils[self.target].curProc() 
                self.debugPidGroup(pid)
            print('fd is %d' % fd)
            #fuzz_it = afl.AFL(self, cpu, cell_name, self.coverage, self.back_stop[self.target], self.mem_utils[self.target], 
            #   self.dataWatch[self.target], snap_name, self.context_manager[self.target], self.lgr, fd=fd, count=count)
            prepInject.PrepInject(self, cpu, cell_name, fd, snap_name, count, self.mem_utils[self.target], self.lgr) 
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
            prep_inject = prepInjectWatch.PrepInjectWatch(self, cpu, cell_name, self.mem_utils[self.target], self.dataWatch[self.target], kbuf_module, self.lgr) 
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

    def playAFLTCP(self, target, sor=False, linear=False, dead=False, afl_mode=False, crashes=False, parallel=False, only_thread=False, fname=None):
        self.playAFL(target,  n=-1, sor=sor, linear=linear, dead=dead, afl_mode=afl_mode, crashes=crashes, parallel=parallel, only_thread=only_thread, fname=fname)

    def playAFL(self, target, n=1, sor=False, linear=False, dead=False, afl_mode=False, no_cover=False, crashes=False, 
            parallel=False, only_thread=False, fname=None, trace_all=False, repeat=False):
        ''' replay all AFL discovered paths for purposes of updating BNT in code coverage '''
        cpu, comm, pid = self.task_utils[self.target].curProc() 
        cell_name = self.getTopComponentName(cpu)
        #if not self.checkUserSpace(cpu):
        #    return
        self.debugPidGroup(pid, to_user=False)
        bb_coverage = self.coverage
        if no_cover:
            bb_coverage = None
        self.rmDebugWarnHap()
        play = playAFL.PlayAFL(self, cpu, cell_name, self.back_stop[self.target], bb_coverage, 
              self.mem_utils[self.target], self.dataWatch[self.target], target, self.run_from_snap, self.context_manager[self.target], 
              self.cfg_file, self.lgr, packet_count=n, stop_on_read=sor, linear=linear, create_dead_zone=dead, afl_mode=afl_mode, 
              crashes=crashes, parallel=parallel, only_thread=only_thread, fname=fname, repeat=repeat)
        if play is not None:
            self.lgr.debug('playAFL now go')
            if trace_all: 
                self.traceAll()
                #self.trace_all = True
            play.go()
        else:
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
        cpu, comm, pid = self.task_utils[self.target].curProc() 
        cell_name = self.getTopComponentName(cpu)
        if self.aflPlay is None:
            self.debugPidGroup(pid, to_user=False)
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
        cpu, comm, pid = self.task_utils[self.target].curProc() 
        rc = reportCrash.ReportCrash(self, cpu, pid, self.dataWatch[self.target], self.mem_utils[self.target], fname, n, one_done, report_index, self.lgr, 
              target=target, targetFD=targetFD, trackFD=trackFD, report_dir=report_dir)
        rc.go()

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
        retval =  self.full_path
        if fname is not None:
            retval = self.targetFS[self.target].getFull(fname, lgr=self.lgr)
        return retval 

    def frameFromRegs(self):
        reg_frame = self.task_utils[self.target].frameFromRegs()
        return reg_frame

    def getPidsForComm(self, comm):
        plist = self.task_utils[self.target].getPidsForComm(comm)
        return plist

    def resetBookmarks(self):
        self.bookmarks = None

    def instructTrace(self, fname, all_proc=False, kernel=False, just_kernel=False, watch_threads=False, just_pid=None):
        self.instruct_trace = instructTrace.InstructTrace(self, self.lgr, fname, all_proc=all_proc, kernel=kernel, 
                        just_kernel=just_kernel, watch_threads=watch_threads, just_pid=just_pid)
        cpu = self.cell_config.cpuFromCell(self.target)
        cpl = memUtils.getCPL(cpu)
        if cpl != 0 or kernel:
            self.instruct_trace.start() 

    def stopInstructTrace(self):
        self.instruct_trace.endTrace()
        self.instruct_trace = None

    def debugIfNot(self):
        ''' warning, assumes current pid is the one to be debugged. '''
        if self.bookmarks is None:
            cpu, comm, this_pid = self.task_utils[self.target].curProc() 
            print('Will debug pid: %d (%s)' % (this_pid, comm))
            self.debug(group=True)
        else:
            print('Already debugging.')

    def debugSnap(self, final_fun=None):
        retval = True
        self.rmDebugWarnHap()
        if self.debug_info is not None and 'pid' in self.debug_info:
            self.lgr.debug('debugSnap call debugPidGroup for pid %d' % self.debug_info['pid'])
            self.debugPidGroup(self.debug_info['pid'], to_user=False, final_fun=final_fun)
            self.lgr.debug('debugSnap did debugPidGroup for pid %d' % self.debug_info['pid'])
        else:
            self.lgr.error('debugSnap, no debug_info read from snapshot')
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
        bp = SIM_breakpoint(resim, Sim_Break_Linear, Sim_Access_Write, addr, self.mem_utils[self.target].WORD_SIZE, 0)
        print('set execution break at 0x%x bp %d' % (addr, bp))


    def showSyscallExits(self):
        exit_list = self.sharedSyscall[self.target].getExitList('traceAll')
        for pid in exit_list:
            frame = exit_list[pid]
            call = self.task_utils[self.target].syscallName(frame['syscall_num'], self.is_compat32)
            self.lgr.debug('showSyscallExits pid %d  syscall %s' % (pid, call))
            print('pid %d  syscall %s' % (pid, call))

    def watchTasks(self):
        ''' watch this task and its threads, will append to others if already watching 
        NOTE assumes it is in execve and we want to track SO files
        '''
        self.context_manager[self.target].watchTasks(set_debug_pid=True)
        ''' flist of other than None causes watch of open/mmap for SO tracking '''
        self.execToText(flist=[])

    def watchExit(self):
        self.context_manager[self.target].watchExit()
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
        cpu = self.cell_config.cpuFromCell(self.target)
        cell = cpu.current_context
        bp = SIM_breakpoint(cell, Sim_Break_Linear, Sim_Access_Execute, addr, self.mem_utils[self.target].WORD_SIZE, 0)
        self.lgr.debug('goAddr break set on 0x%x cell %s' % (addr, cell))
        hap_clean = hapCleaner.HapCleaner(cpu)
        stop_action = hapCleaner.StopAction(hap_clean, [bp])
        self.stop_hap = RES_hap_add_callback("Core_Simulation_Stopped", 
        	     self.stopHap, stop_action)
        SIM_continue(0)

    def stopAndGo(self, callback):
        ''' Will stop simulation and invoke the given callback once stopped.'''
        SIM_run_alone(self.stopAndGoAlone, callback)

    def stopAndGoAlone(self, callback):
        self.lgr.debug('stopAndGoAlone')
        cpu = self.cell_config.cpuFromCell(self.target)
        f1 = stopFunction.StopFunction(callback, [], nest=False)
        flist = [f1]
        hap_clean = hapCleaner.HapCleaner(cpu)
        stop_action = hapCleaner.StopAction(hap_clean, None, flist)
        self.stop_hap = RES_hap_add_callback("Core_Simulation_Stopped", 
        	     self.stopHap, stop_action)
        self.lgr.debug('stopAndGoAlone, hap set now stop it')
        SIM_break_simulation('Stopping simulation')

    def foolSelect(self, fd):
        self.sharedSyscall[self.target].foolSelect(fd)

    def log(self, string):
        rprint(string)

    def injectToBB(self, bb, fname=None):
        ibb = injectToBB.InjectToBB(self, bb, self.lgr, fname=fname)

    def injectToWM(self, addr, fname=None):
        iwm = injectToWM.InjectToWM(self, addr, self.lgr, fname=fname)

    def getParam(self):
        return self.param[self.target]

    def syscallName(self, callnum):
        self.lgr.debug('syscallName %d' % callnum)
        return self.task_utils[self.target].syscallName(callnum, self.is_compat32) 

    def showLinks(self):
        for computer in self.link_dict:
            print('computer %s' % computer)
            for link in self.link_dict[computer]:
                print('\tlink %s  %s' % (link, self.link_dict[computer][link].name))

    def backtraceAddr(self, addr, cycles):
        ''' Look at watch marks to find source of a given address by backtracking through watchmarks '''
        self.lgr.debug('backtraceAddr %x' % addr)
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

    def amWatching(self, pid):
        return self.context_manager[self.target].amWatching(pid)

    def userBreakHap(self, dumb, third, forth, memory):
        self.lgr.debug('userBreakHap')
        self.stopAndGo(self.stopTrackIO) 

    def doBreak(self, addr, count=1, run=False):
        ''' Set a breakpoint and optional count and stop when it is reached.  The stopTrack function will be invoked.'''
        self.user_break = userBreak.UserBreak(self, addr, count, self.context_manager[self.target], self.lgr)
        cpu = self.cell_config.cpuFromCell(self.target)
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

    def blackListPid(self, pid):
        self.context_manager[self.target].noWatch(pid)

    def jumper(self, from_addr, to_addr):
        ''' Set a control flow jumper '''
        if self.target not in self.jummper_dict:
            cpu = self.cell_config.cpuFromCell(self.target)
            self.jumper_dict[self.target] = jumpers.Jumpers(self, self.context_manager[self.target], cpu, self.lgr)
        self.jumper_dict[self.target].setJumper(from_addr, to_addr)
        self.lgr.debug('jumper set')

    def jumperStop(self):
        self.jumper_dict[self.target].removeBreaks()

    def simicsQuitting(self, one, two):
        print('Simics quitting.')
        self.flushTrace()

    def getFunMgr(self):
        return self.fun_mgr

    def stopStepN(self, dumb, one, exception, error_string):
        if self.stop_hap is not None:
            self.lgr.debug('stopStepN delete stop_hap %d' % self.stop_hap)
            RES_hap_delete_callback_id("Core_Simulation_Stopped", self.stop_hap)
            self.stop_hap = None
            self.lgr.debug('stopStepN call skipAndMail')
            self.skipAndMail()

    def stepN(self, n):
        ''' Used by runToSyscall to step out of kernel. '''
        self.lgr.debug('stepN %d' % n)
        flist = [self.skipAndMail]
        f1 = stopFunction.StopFunction(self.skipAndMail, [], nest=False)
        self.stop_hap = RES_hap_add_callback("Core_Simulation_Stopped", self.stopStepN, None)
        cmd = 'c %d' % n
        SIM_run_alone(SIM_run_command, cmd)

    def getProgName(self, pid):
        prog_name = self.traceProcs[self.target].getProg(pid)
        self.lgr.debug('genMonitor getProgName pid %d progname is %s' % (pid, prog_name))
        if prog_name is None or prog_name == 'unknown':
            prog_name, dumb = self.task_utils[self.target].getProgName(pid) 
            self.lgr.debug('genMonitor getProgName pid %d NOT in traceProcs task_utils got %s' % (pid, prog_name))
            if prog_name is None:
                prog_name = self.task_utils[self.target].getCommFromPid(pid) 
                self.lgr.debug('genMonitor getProgName pid %d reverted to getCommFromPid, got %s' % (pid, prog_name))
        return prog_name
 
    def getSharedSyscall(self):
        return self.sharedSyscall[self.target]

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
        SIM_run_command(cmd)

    def runToSeconds(self, seconds):
        self.rmDebugWarnHap()
        cpu = self.cell_config.cpuFromCell(self.target)
        dumb, ret = cli.quiet_run_command('ptime -t')
        #print('dumb is %s ret is %s' % (dumb, ret))
        now = float(dumb)
        want = float(seconds)
        if now > want:
            print('Cannot use this function to run backwards.')
            return
        print('now %.2f  want %.2f' % (now, want))
        delta = want - now
        ms = delta * 1000
        
        print('will run forward %d ms' % int(ms))
        cmd = 'run count = %d unit = ms' % (int(ms))
        SIM_run_command(cmd)
        
    def loadJumpers(self):    
        jumper_file = os.getenv('EXECUTION_JUMPERS')
        if jumper_file is not None:
            if self.target not in self.jumper_dict:
                cpu = self.cell_config.cpuFromCell(self.target)
                self.jumper_dict[self.target] = jumpers.Jumpers(self, self.context_manager[self.target], cpu, self.lgr)
            self.jumper_dict[self.target].loadJumpers(jumper_file, physical=False)
            print('Loaded jumpers from %s' % jumper_file)
        else:
            print('No jumper file defined.')

    def getSyscallEntry(self, callname):
        callnum = self.task_utils[self.target].syscallNumber(callname, self.is_compat32)
        #self.lgr.debug('SysCall doBreaks call: %s  num: %d' % (call, callnum))
        if callnum is not None and callnum < 0:
            self.lgr.error('getSyscallEntry bad call number %d for call <%s>' % (callnum, callname))
            return None
        entry = self.task_utils[self.target].getSyscallEntry(callnum, self.is_compat32)
        return entry

    def setOrigin(self, dumb=None):
        ''' Reset the origin for the current target cpu '''
        pid = self.getPID()
        self.lgr.debug('setOrigin from genMonitor pid:%d' % pid)
        cpu = self.cell_config.cpuFromCell(self.target)
        self.bookmarks.setOrigin(cpu) 

    def isCode(self, addr):
        pid = self.getPID()
        return self.soMap[self.target].isCode(addr, pid)

    def getTargetPlatform(self):
        platform = None
        if 'PLATFORM' in self.comp_dict[self.target]:
            platform = self.comp_dict[self.target]['PLATFORM']
        return platform

    def getReadAddr(self):
        retval = None
        length = None
        cpu = self.cell_config.cpuFromCell(self.target)
        callnum = self.mem_utils[self.target].getCallNum(cpu)
        callname = self.task_utils[self.target].syscallName(callnum, self.is_compat32) 
        if callname is None:
            self.lgr.debug('getReadAddr bad call number %d' % callnum)
            return
        reg_frame = self.task_utils[self.target].frameFromRegs()
        if callname in ['read', 'recv', 'recfrom']:
            retval = reg_frame['param2']
            length = reg_frame['param3']
        elif callname == 'socketcall':
            retval = self.mem_utils[self.target].readWord32(self.cpu, frame['param2']+16)
            length = self.mem_utils[self.target].readWord32(self.cpu, frame['param2']+20)
        return retval, length

    def showSyscalls(self):
        for cell_name in self.syscallManager:
            print('The syscalls for cell %s:' % cell_name)
            self.syscallManager[cell_name].showSyscalls()

    def showSyscallTraces(self):
        for call in self.call_traces[self.target]:
            print('%s  -- %s' % (call, self.call_traces[self.target][call].name))

    def hasPendingPageFault(self, pid):
        return self.page_faults[self.target].hasPendingPageFault(pid)

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

    def showMangle(self, search=None):
        if self.fun_mgr is not None:
            self.fun_mgr.showMangle(search = search)
        else:
            print('No IDA functions loaded.')

    def getFun(self, addr):
        #fname = self.fun_mgr.getFunName(addr)
        fname = self.fun_mgr.funFromAddr(addr)
        print('fun for 0x%x is %s' % (addr, fname))

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
            debug_pid, dumb = self.context_manager[self.target].getDebugPid() 
            if debug_pid is None and self.debug_info is not None and 'pid' in self.debug_info:
                print('Warning snapshot exists but not debugging.  Running will lose state (e.g., threads waiting in the kernel.')
                print('Continue again to go on.  Will not be warned again this session.')
                SIM_break_simulation('stopped')
        SIM_run_alone(self.rmWarnHap, self.snap_warn_hap)
        self.snap_warn_hap = None

    def warnSnapshot(self):
        self.snap_warn_hap = RES_hap_add_callback("Core_Continuation", self.warnSnapshotHap, None)

    def overrideBackstopCallback(self, callback):
        self.lgr.debug('overrideBackstopCallback with %s' % str(callback))
        self.back_stop[self.target].overrideCallback(callback)

    def restoreBackstopCallback(self):
        self.back_stop[self.target].restoreCallback()

    def findKernelEntry(self):
        self.found_entries = []
        cpu = self.cell_config.cpuFromCell(self.target)
        self.mode_hap = RES_hap_add_callback_obj("Core_Mode_Change", cpu, 0, self.modeChangeFindEntry, None)
        self.stop_hap = RES_hap_add_callback("Core_Simulation_Stopped", self.stopFindEntry, None)

    def modeChangeFindEntry(self, dumb, one, old, new):
        target_cpu = self.cell_config.cpuFromCell(self.target)
        cpu, comm, pid = self.task_utils[self.target].curProc() 
        if new == Sim_CPU_Mode_Supervisor:
            SIM_break_simulation('mode changed')

    def stopFindEntry(self, stop_action, one, exception, error_string):
        cpu, comm, pid = self.task_utils[self.target].curProc() 
        eip = self.mem_utils[self.target].getRegValue(cpu, 'eip')
        if eip in self.found_entries:
            SIM_run_alone(SIM_continue, 0)
            return
        self.found_entries.append(eip)
        instruct = SIM_disassemble_address(cpu, eip, 1, 0)
        if eip not in [self.param[self.target].arm_entry, self.param[self.target].arm_svc, self.param[self.target].data_abort, self.param[self.target].page_fault]:
            self.lgr.debug('stopFindEntry pid: %d eip 0x%x %s' % (pid, eip, instruct[1]))
            print('stopFindEntry pid: %d eip 0x%x %s' % (pid, eip, instruct[1]))
        else:
            SIM_run_alone(SIM_continue, 0)

    def isMainText(self, address):
        return self.soMap[self.target].isMainText(address)
   
    def setPacketNumber(self, packet_number):
        if self.coverage is not None:
            self.coverage.setPacketNumber(packet_number)
    def getPhys(self, linear):
        cpu, comm, pid = self.task_utils[self.target].curProc() 
        phys_block = cpu.iface.processor_info.logical_to_physical(linear, Sim_Access_Read)
        print('0x%x' % phys_block.address)

    def readReplace(self, fname, cell_name=None, snapshot=None):
        if not os.path.isfile(fname):
            return False
        if cell_name is None:
            cell_name = self.target
        self.lgr.debug('readReplace %s' % fname)
        cpu, comm, pid = self.task_utils[cell_name].curProc() 
        self.read_replace[cell_name] = readReplace.ReadReplace(self, cpu, cell_name, fname, self.lgr, snapshot=snapshot)
        return True

    def testSnap(self):
        self.debugSnap()
        ts = testSnap.TestSnap(self, self.coverage, self.back_stop[self.target], self.lgr) 
        ts.go()
        self.lgr.debug('done')
        print('done')

    def curTaskTest(self):
        if self.param[self.target].current_task_fs:
            cpu, comm, pid = self.task_utils[self.target].curProc() 
            phys = cpu.ia32_fs_base + (self.param[self.target].current_task-self.param[self.target].kernel_base)
            print('current task phys addr is 0x%x' % phys)

    def getIdaData(self, path):
        #self.lgr.debug('getIdaData path %s' % path)
        root_prefix = self.comp_dict[self.target]['RESIM_ROOT_PREFIX']
        ida_path = resimUtils.getIdaData(path, root_prefix)
        return ida_path

    def isWindows(self, target=None):
        retval = False
        if target is None:
            target = self.target
        #self.lgr.debug('isWindows os type of %s is %s' % (target, self.os_type[target]))
        if self.os_type[target].startswith('WIN'):
            retval = True
        return retval

    def getWin7CallParams(self, stop_on=None, only=None, only_proc=None, track_params=False):
        ''' Use breakpoints set on the user space to identify call parameter 
            Optional stop_on will stop on exit from call'''
        if self.target in self.winMonitor:
            self.rmDebugWarnHap()
            self.checkOnlyIgnore()
            self.winMonitor[self.target].getWin7CallParams(stop_on, only, only_proc, track_params)

    def rmCallParamBreaks(self):
        self.lgr.debug('rmCallparamBreaks (genMonitor)')
        self.winMonitor[self.target].rmCallParamBreaks()

    def isIA32E(self):
        target_cpu = self.cell_config.cpuFromCell(self.target)
        isit = pageUtils.isIA32E(target_cpu)
        print('isIA32E: %r' % isit)

    def listRegNames(self):
        target_cpu = self.cell_config.cpuFromCell(self.target)
        for i in range(100):
            reg_name = target_cpu.iface.int_register.get_name(i)
            print('%d %s' % (i, reg_name))

    def wordSize(self):
        target_cpu = self.cell_config.cpuFromCell(self.target)
        ws = self.mem_utils[self.target].wordSize(target_cpu)
        print('word size: %d' % ws)
        reg_num = target_cpu.iface.int_register.get_number("cs_limit")
        cs = target_cpu.iface.int_register.read(reg_num)
        print('cs 0x%x' % cs)

    def findThreads(self):
        self.task_utils[self.target].findThreads()

    def isReverseExecutionEnabled(self):
        return self.rev_execution_enabled

    def traceWindows(self):
        pid, cpu = self.context_manager[self.target].getDebugPid() 
        if pid is None:
            self.ignoreProgList() 
            self.onlyProgList() 
        self.trace_all[self.target]=self.winMonitor[self.target].traceWindows()
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

    def onlyProgList(self):
        retval = False
        if 'ONLY_PROGS' in self.comp_dict[self.target]: 
            sfile = self.comp_dict[self.target]['ONLY_PROGS']
            retval = self.context_manager[self.target].loadOnlyList(sfile)
            if retval:
                print('Loaded list of programs to watch from %s (all others will be ignored).' % sfile)
        return retval

    def recordEnter(self):
        self.rev_to_call[self.target].sysenterHap(None, None, None, None)
 
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

    def dumpStack(self, count=80):
        self.stackFrameManager[self.target].dumpStack(count)

    def tracking(self):
        return self.track_started

if __name__=="__main__":        
    print('instantiate the GenMonitor') 
    cgc = GenMonitor()
    cgc.doInit()
