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
import cli
import os
import sys
import errno
import struct
import resim_utils
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
import sharedSyscall
import idaFuns
import traceMgr
import binder
import connector
import dmod
import targetFS
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
import writeData
import instructTrace
import aflPath
import trackAFL
import prepInject
import prepInjectWatch

import json
import pickle
import re
import shutil
import imp
import glob


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
        self.traceOpen = {}
        self.traceProcs = {}
        self.dataWatch = {}
        self.trackFunction = {}
        self.traceFiles = {}
        self.sharedSyscall = {}
        self.ropCop = {}
        self.back_stop = {}



        ''' dict of syscall.SysCall keyed on call number '''
        self.call_traces = {}
        self.unistd = {}
        self.unistd32 = {}
        self.targetFS = {}
        self.trace_all = {}
        self.track_threads = {}
        self.exit_group_syscall = {}
        self.debug_breaks_set = True
        self.target = None
        self.netInfo = {}
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

        ''' TBD safe to reuse this?  helps when detecting iterative changes in address value '''
        self.find_kernel_write = None

        self.one_done_module = None
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
            else:
                self.lgr.error('no onedone found for %s' % one_done_script)

        self.injectIOInstance = None
        ''' retrieved from snapshot pickle, not necessarily current '''
        self.debug_info = None
  
        ''' once disabled, cannot go back ''' 
        self.disable_reverse = False

        self.gdb_port = 9123

        self.replayInstance = None
    
        self.cfg_file = cfg_file

        ''' ****NO init data below here**** '''
        self.genInit(comp_dict)


    def genInit(self, comp_dict):
        '''
        remove all previous breakpoints.  
        '''
        self.lgr = resim_utils.getLogger('resim', os.path.join(self.log_dir, 'monitors'))
        self.is_monitor_running = isMonitorRunning.isMonitorRunning(self.lgr)
        SIM_run_command("delete -all")
        self.target = os.getenv('RESIM_TARGET')
        print('using target of %s' % self.target)
        self.cell_config = cellConfig.CellConfig(list(comp_dict.keys()))
        target_cpu = self.cell_config.cpuFromCell(self.target)
        self.lgr.debug('New log, in genInit')
        self.run_from_snap = os.getenv('RUN_FROM_SNAP')
        self.binders = binder.Binder(self.lgr)
        self.connectors = connector.Connector(self.lgr)
        if self.run_from_snap is not None:
            ''' Restore link naming for convenient connect / disconnect '''
            net_link_file = os.path.join('./', self.run_from_snap, 'net_link.pickle')
            if os.path.isfile(net_link_file):
                self.net_links = pickle.load( open(net_link_file, 'rb') )
                for target in self.net_links:
                    for link in self.net_links[target]:
                        cmd = '%s = %s' % (self.net_links[target][link].name, self.net_links[target][link].obj)
                        self.lgr.debug('genInit link cmd is %s' % cmd)
                        SIM_run_command(cmd)
            stack_base_file = os.path.join('./', self.run_from_snap, 'stack_base.pickle')
            if os.path.isfile(stack_base_file):
                self.stack_base = pickle.load( open(stack_base_file, 'rb') )
            debug_info_file = os.path.join('./', self.run_from_snap, 'debug_info.pickle')
            if os.path.isfile(debug_info_file):
                self.debug_info = pickle.load( open(debug_info_file, 'rb') )
            connector_file = os.path.join('./', self.run_from_snap, 'connector.json')
            if os.path.isfile(connector_file):
                self.connectors.loadJson(connector_file)
            binder_file = os.path.join('./', self.run_from_snap, 'binder.json')
            if os.path.isfile(binder_file):
                self.binders.loadJson(binder_file)
             

        for cell_name in comp_dict:
            if 'RESIM_PARAM' in comp_dict[cell_name]:
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

                ''' always true? TBD '''
                self.param[cell_name].ts_state = 0

                self.lgr.debug(self.param[cell_name].getParamString())
            else:
                print('Cell %s missing params, it will not be monitored. ' % (cell_name))
                self.lgr.debug('Cell %s missing params ' % (cell_name))
                continue 
            word_size = 4
            if 'OS_TYPE' in comp_dict[cell_name]:
                if comp_dict[cell_name]['OS_TYPE'] == 'LINUX64':
                    word_size = 8

            cpu = self.cell_config.cpuFromCell(cell_name)
            self.mem_utils[cell_name] = memUtils.memUtils(word_size, self.param[cell_name], self.lgr, arch=cpu.architecture, cell_name=cell_name)
            self.traceMgr[cell_name] = traceMgr.TraceMgr(self.lgr)

            self.unistd[cell_name] = comp_dict[cell_name]['RESIM_UNISTD']
            if 'RESIM_UNISTD_32' in comp_dict[cell_name]:
                self.unistd32[cell_name] = comp_dict[cell_name]['RESIM_UNISTD_32']
            root_prefix = comp_dict[cell_name]['RESIM_ROOT_PREFIX']
            self.targetFS[cell_name] = targetFS.TargetFS(root_prefix)
            self.lgr.debug('targetFS for %s is %s' % (cell_name, self.targetFS[cell_name]))

            self.netInfo[cell_name] = net.NetAddresses(self.lgr)
            self.call_traces[cell_name] = {}
            #self.proc_list[cell_name] = {}
            self.stack_base[cell_name] = {}
            if self.run_from_snap is not None:
                net_file = os.path.join('./', self.run_from_snap, cell_name, 'net_list.pickle')
                if os.path.isfile(net_file):
                    self.netInfo[cell_name].loadfile(net_file)

        init_script = os.getenv('INIT_SCRIPT')
        if init_script is not None:
            cmd = 'run-command-file %s' % init_script
            SIM_run_command(cmd)
            self.lgr.debug('ran INIT_SCRIPT %s' % init_script)
        if self.one_done_module is not None:
            #self.one_done_module.onedone(self)
            SIM_run_alone(self.one_done_module.onedone, self)

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
        SIM_run_alone(SIM_run_command, 'c')

    def modeChangeReport(self, want_pid, one, old, new):
        cpu, comm, this_pid = self.task_utils[self.target].curProc() 
        if want_pid != this_pid:
            #self.lgr.debug('mode changed wrong pid, wanted %d got %d' % (want_pid, this_pid))
            return
        new_mode = 'user'
        if new == Sim_CPU_Mode_Supervisor:
            new_mode = 'kernel'
            SIM_break_simulation('mode changed')
        eip = self.mem_utils[self.target].getRegValue(cpu, 'eip')
        callnum = self.mem_utils[self.target].getRegValue(cpu, 'syscall_num')
        phys = self.mem_utils[self.target].v2p(cpu, eip)
        instruct = SIM_disassemble_address(cpu, phys, 0, 0)
        self.lgr.debug('modeChangeReport new mode: %s  eip 0x%x %s --  eax 0x%x' % (new_mode, eip, instruct[1], callnum))

    def modeChanged(self, want_pid, one, old, new):
        cpu, comm, this_pid = self.task_utils[self.target].curProc() 
        if want_pid != this_pid:
            #self.lgr.debug('mode changed wrong pid, wanted %d got %d' % (want_pid, this_pid))
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
        if self.stop_hap is not None:
            SIM_run_alone(self.stopHapAlone, stop_action)

    def stopHapAlone(self, stop_action):
        if stop_action is None or stop_action.hap_clean is None:
            print('stopHap error, stop_action None?')
            return 
        if stop_action.prelude is not None:
            stop_action.prelude()
        cpu, comm, pid = self.task_utils[self.target].curProc() 
        wrong_pid = False
        if stop_action.pid is not None and pid != stop_action.pid:
            ''' likely some other pid in our group '''
            wrong_pid = True
        eip = self.getEIP(cpu)
        self.lgr.debug('genMonitor stopHap pid %d eip 0x%x cycle: 0x%x wrong_pid: %r' % (pid, eip, stop_action.hap_clean.cpu.cycles, wrong_pid))
        for hc in stop_action.hap_clean.hlist:
            if hc.hap is not None:
                if hc.htype == 'GenContext':
                    self.lgr.debug('genMonitor stopHap stopAction delete GenContext hap %s' % str(hc.hap))
                    self.context_manager[self.target].genDeleteHap(hc.hap)
                else:
                    self.lgr.debug('genMonitor stopHap stopAction will delete hap %s type %s' % (str(hc.hap), str(hc.htype)))
                    SIM_hap_delete_callback_id(hc.htype, hc.hap)
                hc.hap = None
        if self.stop_hap is not None:
            self.lgr.debug('genMonitor stopHap will delete hap %s' % str(self.stop_hap))
            SIM_hap_delete_callback_id("Core_Simulation_Stopped", self.stop_hap)
            self.stop_hap = None
            for bp in stop_action.breakpoints:
                SIM_delete_breakpoint(bp)
            del stop_action.breakpoints[:]
            self.is_compat32 = self.compat32()
            ''' check functions in list '''
            self.lgr.debug('stopHap compat32 is %r now run actions %s wrong_pid %r' % (self.is_compat32, stop_action.listFuns(), wrong_pid))
            stop_action.run(wrong_pid=wrong_pid)
            self.is_monitor_running.setRunning(False)
            self.lgr.debug('back from stop_action.run')

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
        self.stop_hap = SIM_hap_add_callback("Core_Simulation_Stopped", self.stopHap, stop_action)
        self.lgr.debug('revToPid hap set, break on 0x%x now reverse' % phys_current_task)
        SIM_run_command('rev')

    def run2Kernel(self, cpu):
        cpl = memUtils.getCPL(cpu)
        if cpl != 0:
            cpu, comm, pid = self.task_utils[self.target].curProc() 
            self.lgr.debug('run2Kernel in user space (%d), set hap' % cpl)
            self.mode_hap = SIM_hap_add_callback_obj("Core_Mode_Change", cpu, 0, self.modeChanged, pid)
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
                    
            self.mode_hap = SIM_hap_add_callback_obj("Core_Mode_Change", cpu, 0, self.modeChanged, pid)
            self.lgr.debug('run2User pid %d in kernel space (%d), set mode hap %d' % (pid, cpl, self.mode_hap))
            hap_clean = hapCleaner.HapCleaner(cpu)
            # fails when deleted? wtf?
            hap_clean.add("Core_Mode_Change", self.mode_hap)
            stop_action = hapCleaner.StopAction(hap_clean, None, flist)
            self.stop_hap = SIM_hap_add_callback("Core_Simulation_Stopped", 
        	     self.stopHap, stop_action)
            self.lgr.debug('run2User added stop_hap of %d' % self.stop_hap)
            SIM_run_alone(SIM_run_command, 'continue')
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
        
            self.lgr.debug('finishInit for cell %s' % cell_name)
            if cell_name not in self.param: 
                return
            cpu = self.cell_config.cpuFromCell(cell_name)
            cell = self.cell_config.cell_context[cell_name]
            #self.task_utils[cell_name] = taskUtils.TaskUtils(cpu, cell_name, self.param[cell_name], self.mem_utils[cell_name], 
            #      self.unistd[cell_name], self.run_from_snap, self.lgr)
 
            tu_cur_task_rec = self.task_utils[cell_name].getCurTaskRec()
            if tu_cur_task_rec is None:
                self.lgr.error('could not read tu_cur_task_rec from taskUtils')
                return

            cur_task_rec = self.mem_utils[cell_name].getCurrentTask(self.param[cell_name], cpu)
            #self.lgr.debug('stack based rec was 0x%x  mine is 0x%x' % (cur_task_rec, tu_cur_task_rec))
            ''' manages setting haps/breaks based on context swtiching.  TBD will be one per cpu '''
        
            self.context_manager[cell_name] = genContextMgr.GenContextMgr(self, cell_name, self.task_utils[cell_name], self.param[cell_name], cpu, self.lgr) 
            self.page_faults[cell_name] = pageFaultGen.PageFaultGen(self, cell_name, self.param[cell_name], self.cell_config, self.mem_utils[cell_name], 
                   self.task_utils[cell_name], self.context_manager[cell_name], self.lgr)
            self.rev_to_call[cell_name] = reverseToCall.reverseToCall(self, cell_name, self.param[cell_name], self.task_utils[cell_name], self.mem_utils[cell_name],
                 self.PAGE_SIZE, self.context_manager[cell_name], 'revToCall', self.is_monitor_running, None, self.log_dir, self.is_compat32, self.run_from_snap)
            self.pfamily[cell_name] = pFamily.Pfamily(cell, self.param[cell_name], self.cell_config, self.mem_utils[cell_name], self.task_utils[cell_name], self.lgr)
            self.traceOpen[cell_name] = traceOpen.TraceOpen(self.param[cell_name], self.mem_utils[cell_name], self.task_utils[cell_name], cpu, cell, self.lgr)
            #self.traceProcs[cell_name] = traceProcs.TraceProcs(cell_name, self.lgr, self.proc_list[cell_name], self.run_from_snap)
            self.traceProcs[cell_name] = traceProcs.TraceProcs(cell_name, self.context_manager[cell_name], self.task_utils[cell_name], self.lgr, run_from_snap = self.run_from_snap)
            self.soMap[cell_name] = soMap.SOMap(self, cell_name, cell, self.context_manager[cell_name], self.task_utils[cell_name], self.targetFS[cell_name], self.run_from_snap, self.lgr)
            self.back_stop[cell_name] = backStop.BackStop(cpu, self.lgr)
            self.dataWatch[cell_name] = dataWatch.DataWatch(self, cpu, cell_name, self.PAGE_SIZE, self.context_manager[cell_name], 
                  self.mem_utils[cell_name], self.task_utils[cell_name], self.rev_to_call[cell_name], self.param[cell_name], self.run_from_snap, self.back_stop[cell_name], self.lgr)
            self.trackFunction[cell_name] = trackFunctionWrite.TrackFunctionWrite(cpu, cell, self.param[cell_name], self.mem_utils[cell_name], 
                  self.task_utils[cell_name], 
                  self.context_manager[cell_name], self.lgr)
            self.traceFiles[cell_name] = traceFiles.TraceFiles(self.traceProcs[cell_name], self.lgr)
            self.sharedSyscall[cell_name] = sharedSyscall.SharedSyscall(self, cpu, cell, cell_name, self.param[cell_name], 
                  self.mem_utils[cell_name], self.task_utils[cell_name], 
                  self.context_manager[cell_name], self.traceProcs[cell_name], self.traceFiles[cell_name], 
                  self.soMap[cell_name], self.dataWatch[cell_name], self.traceMgr[cell_name], self.lgr)

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
            for cell_name in self.cell_config.cell_context:
                if cell_name not in self.param:
                    ''' not monitoring this cell, no param file '''
                    continue
                if cell_name in self.task_utils:
                    ''' already got taskUtils for this cell '''
                    continue
                cpu = self.cell_config.cpuFromCell(cell_name)
                unistd32 = None
                if cell_name in self.unistd32:
                    unistd32 = self.unistd32[cell_name]
                task_utils = taskUtils.TaskUtils(cpu, cell_name, self.param[cell_name], self.mem_utils[cell_name], 
                    self.unistd[cell_name], unistd32, self.run_from_snap, self.lgr)
                self.task_utils[cell_name] = task_utils
                self.lgr.debug('snapInit for cell %s, now call to finishInit' % cell_name)
                self.finishInit(cell_name)
 
    def doInit(self):
        self.lgr.debug('genMonitor doInit')
        if self.run_from_snap is not None:
            self.snapInit()
            return
        #SIM_run_command('pselect cpu-name = %s' % cpu.name)
        #run_cycles = 90000000
        #run_cycles =  9000000
        run_cycles = self.getBootCycleChunk()
        #run_cycles = 900000
        done = False
        while not done:
            done = True
            for cell_name in self.cell_config.cell_context:
                if cell_name not in self.param:
                    ''' not monitoring this cell, no param file '''
                    continue
                if cell_name in self.task_utils:
                    ''' already got taskUtils for this cell '''
                    continue
                cpu = self.cell_config.cpuFromCell(cell_name)
                ''' run until we get something sane '''
                #self.lgr.debug('doInit cell %s get current task from mem_utils' % cell_name)
                cur_task_rec = self.mem_utils[cell_name].getCurrentTask(self.param[cell_name], cpu)
                if cur_task_rec is None or cur_task_rec == 0:
                    #print('Current task not yet defined, continue')
                    #self.lgr.debug('doInit Current task for %s not yet defined, continue' % cell_name)
                    done = False
                else:
                    pid = self.mem_utils[cell_name].readWord32(cpu, cur_task_rec + self.param[cell_name].ts_pid)
                    if pid is None:
                        #self.lgr.debug('doInit cell %s cur_task_rec 0x%x pid None ' % (cell_name, cur_task_rec))
                        done = False
                        continue
                    #self.lgr.debug('doInit cell %s pid is %d' % (cell_name, pid))

                    phys = self.mem_utils[cell_name].v2p(cpu, self.param[cell_name].current_task)
                    tu_cur_task_rec = self.mem_utils[cell_name].readPhysPtr(cpu, phys)
                    if tu_cur_task_rec is None:
                        #self.lgr.debug('doInit cell %s cur_task_rec 0x%x pid %d but None from task_utils ' % (cell_name, cur_task_rec, pid))
                        done = False
                        continue
                    #self.lgr.debug('doInit cell %s cur_task_rec 0x%x pid %d from task_utils 0x%x   current_task: 0x%x (0x%x)' % (cell_name, 
                    #       cur_task_rec, pid, tu_cur_task_rec, self.param[cell_name].current_task, phys))
                    if tu_cur_task_rec != 0:
                        if cur_task_rec != tu_cur_task_rec:
                            #self.lgr.debug('doInit memUtils getCurrentTaskRec does not match found at para.current_task, try again')
                            pid = self.mem_utils[cell_name].readWord32(cpu, cur_task_rec + self.param[cell_name].ts_pid)
                            tu_pid = self.mem_utils[cell_name].readWord32(cpu, tu_cur_task_rec + self.param[cell_name].ts_pid)
                            self.lgr.debug('pid %s  tu_pid %s' % (str(pid), str(tu_pid)))
                            #SIM_break_simulation('no match')
                            done = False
                            continue
                        unistd32 = None
                        if cell_name in self.unistd32:
                            unistd32 = self.unistd32[cell_name]
                        task_utils = taskUtils.TaskUtils(cpu, cell_name, self.param[cell_name], self.mem_utils[cell_name], 
                            self.unistd[cell_name], unistd32, self.run_from_snap, self.lgr)
                        self.task_utils[cell_name] = task_utils
                        self.lgr.debug('doInit Booted enough to get cur_task_rec for cell %s, now call to finishInit' % cell_name)
                        self.finishInit(cell_name)
                        run_cycles = self.getBootCycleChunk()
                        if self.run_from_snap is None and 'DMOD' in self.comp_dict[cell_name]:
                            self.is_monitor_running.setRunning(False)
                            dlist = self.comp_dict[cell_name]['DMOD'].split(';')
                            for dmod in dlist:
                                dmod = dmod.strip()
                                self.runToDmod(dmod, cell_name=cell_name)
                                print('Dmod %s pending for cell %s, need to run forward' % (dmod, cell_name))
                    else:
                        #self.lgr.debug('doInit cell %s taskUtils got task rec of zero' % cell_name)
                        done = False
            if not done:
                #self.lgr.debug('continue %d cycles' % run_cycles)
                SIM_continue(run_cycles)
       
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
                retval[pid] = frame
        return retval 

    def getRecentEnterCycle(self):
        ''' return most recent cycle in which the kernel was entered for this PID '''
        cpu, comm, pid = self.task_utils[self.target].curProc() 
        frame, cycles = self.rev_to_call[self.target].getRecentCycleFrame(pid)
        return frame, cycles

    def tasksDBG(self):
        plist = {}
        pid_list = self.context_manager[self.target].getThreadPids()
        tasks = self.task_utils[self.target].getTaskStructs()
        self.lgr.debug('tasksDBG')
        print('Status of debugging threads')
        plist = {}
        for t in tasks:
            if tasks[t].pid in pid_list:
                plist[tasks[t].pid] = t 
        for pid in sorted(plist):
            t = plist[pid]
            if tasks[t].state > 0:
                frame, cycles = self.rev_to_call[self.target].getRecentCycleFrame(pid)
                call = self.task_utils[self.target].syscallName(frame['syscall_num'], self.is_compat32)
                print('pid: %d syscall %s param1: %d task_addr: 0x%x sp: 0x%x pc: 0x%x cycle: 0x%x' % (pid, 
                     call, frame['param1'], tasks[t].addr, frame['sp'], frame['pc'], cycles))
            else:
                print('pid: %d in user space?' % pid)

    def tasks(self):
        self.lgr.debug('tasks')
        print('Tasks on cell %s' % self.target)
        tasks = self.task_utils[self.target].getTaskStructs()
        plist = {}
        for t in tasks:
            plist[tasks[t].pid] = t 
        for pid in sorted(plist):
            t = plist[pid]
            print('pid: %d taks_rec: 0x%x  comm: %s state: %d next: 0x%x leader: 0x%x parent: 0x%x tgid: %d' % (tasks[t].pid, t, 
                tasks[t].comm, tasks[t].state, tasks[t].next, tasks[t].group_leader, tasks[t].real_parent, tasks[t].tgid))
            

    def setDebugBookmark(self, mark, cpu=None, cycles=None, eip=None, steps=None):
        SIM_run_command('enable-reverse-execution')
        pid, cpu = self.context_manager[self.target].getDebugPid() 
        self.bookmarks.setDebugBookmark(mark, cpu=cpu, cycles=cycles, eip=eip, steps=steps, msg=self.context_manager[self.target].getIdaMessage())

    def debugGroup(self):
        self.debug(group=True)

    def doDebugCmd(self):
            cpu, comm, pid = self.task_utils[self.target].curProc() 
            self.lgr.debug('debug for cpu %s port will be %d.  Pid is %d compat32 %r' % (cpu.name, self.gdb_port, pid, self.is_compat32))
            if self.bookmarks is None:
                if cpu.architecture == 'arm':
                    cmd = 'new-gdb-remote cpu=%s architecture=arm port=%d' % (cpu.name, self.gdb_port)
                elif self.mem_utils[self.target].WORD_SIZE == 8 and not self.is_compat32:
                    cmd = 'new-gdb-remote cpu=%s architecture=x86-64 port=%d' % (cpu.name, self.gdb_port)
                else:
                    cmd = 'new-gdb-remote cpu=%s architecture=x86 port=%d' % (cpu.name, self.gdb_port)
                self.lgr.debug('cmd: %s' % cmd)
                SIM_run_command(cmd)
                self.bookmarks = bookmarkMgr.bookmarkMgr(self, self.context_manager[self.target], self.lgr)
                if not self.disable_reverse:
                    self.rev_to_call[self.target].setup(cpu, [], bookmarks=self.bookmarks, page_faults = self.page_faults[self.target])
            return pid


    def debug(self, group=False):
        self.lgr.debug('genMonitor debug group is %r' % group)
        #self.stopTrace()    
        pid, cpu = self.context_manager[self.target].getDebugPid() 
        cell = self.cell_config.cell_context[self.target]
        if pid is None:
            ''' Our first debug '''
            pid = self.doDebugCmd()
            if not self.rev_execution_enabled:
                ''' only exception is AFL coverage on target that differs from consumer of injected data '''
                cmd = 'enable-reverse-execution'
                SIM_run_command(cmd)
                self.rev_execution_enabled = True
                self.setDebugBookmark('origin', cpu)
                self.bookmarks.setOrigin(cpu)
            ''' tbd, this is likely already set by some other action, no harm '''
            self.context_manager[self.target].watchTasks()
            self.context_manager[self.target].setDebugPid()

            if group:
                leader_pid = self.task_utils[self.target].getGroupLeaderPid(pid)
                self.lgr.debug('genManager debug, will debug entire process group under leader %d' % leader_pid)
                pid_list = self.task_utils[self.target].getGroupPids(leader_pid)
                for pid in pid_list:
                    self.context_manager[self.target].addTask(pid)

            ''' keep track of threads within our process that are created during debug session '''
            cpl = memUtils.getCPL(cpu)
            if cpl == 0:
                self.lgr.warning('debug: not in user space, x86 32-bit compat mode may miss clones')
            if 'open' in self.call_traces[self.target]:
                self.stopTrace(syscall = self.call_traces[self.target]['open'])
                self.lgr.debug('genMonitor debug removed open syscall, now track threads')
            self.track_threads[self.target] = trackThreads.TrackThreads(cpu, self.target, cell, pid, self.context_manager[self.target], 
                    self.task_utils[self.target], self.mem_utils[self.target], self.param[self.target], self.traceProcs[self.target], 
                    self.soMap[self.target], self.targetFS[self.target], self.sharedSyscall[self.target], self.is_compat32, self.lgr)


            self.watchPageFaults(pid)

            self.sharedSyscall[self.target].setDebugging(True)
 
            prog_name = self.traceProcs[self.target].getProg(pid)
            self.lgr.debug('genMonitor debug pid %d progname is %s' % (pid, prog_name))
            if prog_name is None or prog_name == 'unknown':
                prog_name, dumb = self.task_utils[self.target].getProgName(pid) 
                self.lgr.debug('genMonitor debug pid %d NOT in traceProcs task_utils got %s' % (pid, prog_name))
            if self.targetFS[self.target] is not None and prog_name is not None:
                sindex = 0
                full_path = self.targetFS[self.target].getFull(prog_name, self.lgr)
                self.full_path = full_path
                if full_path is not None:
                    self.lgr.debug('debug, set target fs, progname is %s  full: %s' % (prog_name, full_path))
                    self.getIDAFuns(full_path)
                    self.relocate_funs = elfText.getRelocate(full_path, self.lgr)
    
                    text_segment = elfText.getText(full_path, self.lgr)
                    if text_segment is not None:
                        self.context_manager[self.target].recordText(text_segment.address, text_segment.address+text_segment.size)
                        self.soMap[self.target].addText(text_segment.address, text_segment.size, prog_name, pid)
                        self.soMap[self.target].setIdaFuns(self.ida_funs)
                        self.rev_to_call[self.target].setIdaFuns(self.ida_funs)
                        self.dataWatch[self.target].setIdaFuns(self.ida_funs)
                        self.dataWatch[self.target].setUserIterators(self.user_iterators)
                        self.bookmarks.setIdaFuns(self.ida_funs)
                        self.dataWatch[self.target].setRelocatables(self.relocate_funs)
                        self.ropCop[self.target] = ropCop.RopCop(self, cpu, cell, self.context_manager[self.target],  self.mem_utils[self.target],
                             text_segment.address, text_segment.size, self.bookmarks, self.task_utils[self.target], self.lgr)
                    else:
                        self.lgr.error('debug, text segment None for %s' % full_path)
                    self.lgr.debug('create coverage module')
                    ida_path = self.getIdaData(full_path)
                    if ida_path is not None:
                        self.coverage = coverage.Coverage(self, full_path, ida_path, self.context_manager[self.target], 
                           cell, self.soMap[self.target], cpu, self.run_from_snap, self.lgr)
                    if self.coverage is None:
                        self.lgr.debug('Coverage is None!')
                else:
                    self.lgr.error('Failed to get full path for %s' % prog_name)
        else:
            ''' already debugging as current process '''
            self.lgr.debug('genMonitor debug, already debugging')
            pass
        self.task_utils[self.target].clearExitPid()
        ''' Otherwise not cleared when pageFaultGen is stopped/started '''
        self.page_faults[self.target].clearFaultingCycles()
        self.rev_to_call[self.target].clearEnterCycles()
        self.is_monitor_running.setRunning(False)

    def getIdaData(self, full_path):
        retval = None
        resim_ida_data = os.getenv('RESIM_IDA_DATA')
        if resim_ida_data is None:
            self.lgr.error('RESIM_IDA_DATA not defined')
        else: 
            base = os.path.basename(full_path)
            retval = os.path.join(resim_ida_data, base, base)
        return retval

    def show(self):
        cpu, comm, pid = self.task_utils[self.target].curProc() 
        cpl = memUtils.getCPL(cpu)
        eip = self.getEIP(cpu)
        #cur_task_rec = self.task_utils.getCurTaskRec()
        #addr = cur_task_rec+self.param.ts_group_leader
        #val = self.mem_utils.readPtr(cpu, addr)
        #print('current task 0x%x gl_addr 0x%x group_leader 0x%s' % (cur_task_rec, addr, val))
        print('cpu.name is %s PL: %d pid: %d(%s) EIP: 0x%x   current_task symbol at 0x%x (use FS: %r)' % (cpu.name, cpl, pid, 
               comm, eip, self.param[self.target].current_task, self.param[self.target].current_task_fs))
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
        self.scall_hap = SIM_hap_add_callback_obj_index("Core_Exception", cpu, 0,
                 self.int80Hap, cpu, 0x180) 
        hap_clean = hapCleaner.HapCleaner(cpu)
        hap_clean.add("Core_Exception", self.scall_hap)
        stop_action = hapCleaner.StopAction(hap_clean, [])
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
        stop_action = hapCleaner.StopAction(hap_clean, [])
        self.stop_hap = SIM_hap_add_callback("Core_Simulation_Stopped", 
        	     self.stopHap, stop_action)
        status = self.is_monitor_running.isRunning()
        if not status:
            SIM_run_command('c')
    
    def getIDAFuns(self, full_path):
        fun_path = full_path+'.funs'
        iterator_path = full_path+'.iterators'
        self.user_iterators = userIterators.UserIterators(iterator_path, self.lgr)
        if not os.path.isfile(fun_path):
            ''' No functions file, check for symbolic links '''
            if os.path.islink(full_path):
                actual = os.readlink(full_path)
                fun_path = actual+'.funs'
            
        if os.path.isfile(fun_path):
            self.ida_funs = idaFuns.IDAFuns(fun_path, self.lgr)
            self.lgr.debug('getIDAFuns using IDA function analysis from %s' % fun_path)
        else:
            self.lgr.warning('No IDA function file at %s' % fun_path)
 
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

            text_segment = elfText.getText(full_path, self.lgr)
            if text_segment is not None:
                if text_segment.address is None:
                    self.lgr.error('execToText found file %s, but address is None?' % full_path)
                    stopFunction.allFuns(flist)
                    return
                self.lgr.debug('execToText %s 0x%x - 0x%x' % (prog_name, text_segment.address, text_segment.address+text_segment.size))       
                self.context_manager[self.target].recordText(text_segment.address, text_segment.address+text_segment.size)
                self.soMap[self.target].addText(text_segment.address, text_segment.size, prog_name, pid)
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
            self.toRunningProc(proc, plist, flist)
        else:
            self.lgr.debug('watchProc no process %s found, run until execve' % proc)
            #flist = [self.toUser, self.debug]
            ''' run to the execve, then start recording shared object mmaps and run
                until we enter the text segment so we get the SO map '''
            f1 = stopFunction.StopFunction(self.execToText, [], nest=True)
            flist = [f1]
            self.toExecve(proc, flist=flist)

    def cleanToProcHaps(self, dumb):
        self.lgr.debug('cleantoProcHaps')
        if self.cur_task_break is not None:
            SIM_delete_breakpoint(self.cur_task_break)
        if self.cur_task_hap is not None:
            SIM_hap_delete_callback_id("Core_Breakpoint_Memop", self.cur_task_hap)
            self.cur_task_hap = None

    def toProc(self, proc):
        plist = self.task_utils[self.target].getPidsForComm(proc)
        if len(plist) > 0 and not (len(plist)==1 and plist[0] == self.task_utils[self.target].getExitPid()):
            self.lgr.debug('toProc process %s found, run until some instance is scheduled' % proc)
            print('%s is running as %d.  Will continue until some instance of it is scheduled' % (proc, plist[0]))
            f1 = stopFunction.StopFunction(self.toUser, [], nest=True)
            flist = [f1]
            self.toRunningProc(proc, plist, flist)
        else:
            self.lgr.debug('toProc no process %s found, run until execve' % proc)
            cpu = self.cell_config.cpuFromCell(self.target)
            '''
            prec = Prec(cpu, proc, None)
            phys_current_task = self.task_utils[self.target].getPhysCurrentTask()
            self.proc_break = SIM_breakpoint(cpu.physical_memory, Sim_Break_Physical, Sim_Access_Write, 
                             phys_current_task, self.mem_utils[self.target].WORD_SIZE, 0)
            self.lgr.debug('toProc  set break at 0x%x' % (phys_current_task))
            self.proc_hap = SIM_hap_add_callback_index("Core_Breakpoint_Memop", self.runToProc, prec, self.proc_break)
            '''
        
            #f1 = stopFunction.StopFunction(self.cleanToProcHaps, [], False)
            self.toExecve(proc, [])

    def setStackBase(self):
        ''' debug cpu not yet set.  TBD align with debug cpu selection strategy '''
        cpu = self.cell_config.cpuFromCell(self.target)
        esp = self.mem_utils[self.target].getRegValue(cpu, 'esp')
        eip = self.mem_utils[self.target].getRegValue(cpu, 'eip')
        cpu, comm, pid  = self.task_utils[self.target].curProc()
        self.stack_base[self.target][pid] = esp
        self.lgr.debug('setStackBase pid:%d to 0x%x init eip is 0x%x' % (pid, esp, eip))

    def modeChangeForStack(self, want_pid, one, old, new):
        if self.mode_hap is None:
            return
        cpu, comm, pid = self.task_utils[self.target].curProc() 
        self.lgr.debug('modeChangeForStack pid:%d wanted: %d old: %d new: %d' % (pid, want_pid, old, new))
        SIM_hap_delete_callback_id("Core_Mode_Change", self.mode_hap)
        self.mode_hap = None
        
        if new != Sim_CPU_Mode_Supervisor:
            self.setStackBase()

    def recordStackBase(self, pid, sp):
        self.lgr.debug('recordStackBase pid:%d 0x%x' % (pid, sp))
        self.stack_base[self.target][pid] = sp

    def recordStackClone(self, pid, parent):
        self.lgr.debug('recordStackClone pid: %d parent: %d' % (pid, parent))
        cpu = self.cell_config.cpuFromCell(self.target)
        self.mode_hap = SIM_hap_add_callback_obj("Core_Mode_Change", cpu, 0, self.modeChangeForStack, pid)
        '''
        if self.target not in self.track_threads:
            self.lgr.error('recordStackClone without track_threads loaded')
            return
        sp = self.track_threads[self.target].getChildStack(parent)
        self.stack_base[self.target][pid] = sp
        if sp is not None:
            self.lgr.debug('recordStackClone pid: %d 0x%x parent: %d' % (pid, sp, parent))
        else:
            self.lgr.debug('recordStackClone got no stack for parent %d' % parent)
        '''
        
    def debugProc(self, proc, final_fun=None, pre_fun=None):
        if type(proc) is not str:
            print('Need a proc name as a string')
            return
        self.lgr.debug('genMonitor debugProc')
        #self.stopTrace()
        plist = self.task_utils[self.target].getPidsForComm(proc)
        if len(plist) > 0 and not (len(plist)==1 and plist[0] == self.task_utils[self.target].getExitPid()):
            self.lgr.debug('debugProc plist len %d plist[0] %d  exitpid %d' % (len(plist), plist[0], self.task_utils[self.target].getExitPid()))

            self.lgr.debug('debugProc process %s found, run until some instance is scheduled' % proc)
            print('%s is running.  Will continue until some instance of it is scheduled' % proc)
            f1 = stopFunction.StopFunction(self.toUser, [], nest=True)
            f2 = stopFunction.StopFunction(self.debugExitHap, [], nest=False)
            f3 = stopFunction.StopFunction(self.debug, [], nest=False)
            flist = [f1, f2, f3]
            if final_fun is not None:
                f4 = stopFunction.StopFunction(final_fun, [], nest=False)
                flist.append(f4)
            if pre_fun is not None:
                fp = stopFunction.StopFunction(pre_fun, [], nest=False)
                flist.insert(0, fp)
            self.toRunningProc(proc, plist, flist)
        else:
            self.lgr.debug('debugProc no process %s found, run until execve' % proc)
            #flist = [self.toUser, self.debug]
            ''' run to the execve, then start recording shared object mmaps and run
                until we enter the text segment so we get the SO map '''
            f1 = stopFunction.StopFunction(self.toUser, [], nest=True)
            f2 = stopFunction.StopFunction(self.execToText, [], nest=True)
            f3 = stopFunction.StopFunction(self.setStackBase, [], nest=False)
            f4 = stopFunction.StopFunction(self.debug, [], nest=False)
            flist = [f1, f2, f3, f4]
            self.toExecve(proc, flist=flist, binary=True)

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
        self.debugPidList([pid], self.debug)

    def debugPidGroup(self, pid, final_fun=None, to_user=True):
        leader_pid = self.task_utils[self.target].getGroupLeaderPid(pid)
        if leader_pid is None:
            self.lgr.error('debugPidGroup leader_pid is None, asked about %d' % pid)
            return
        self.lgr.debug('debugPidGroup cell %s pid %d found leader %d' % (self.target, pid, leader_pid))
        pid_dict = self.task_utils[self.target].getGroupPids(leader_pid)
        pid_list = list(pid_dict.keys())
        self.debugPidList(pid_list, self.debugGroup, final_fun=final_fun, to_user=to_user)

    def debugPidList(self, pid_list, debug_function, final_fun=None, to_user=True):
        #self.stopTrace()
        self.soMap[self.target].setContext(pid_list)
        self.lgr.debug('debugPidList cell %s' % self.target)
        if to_user:
            f1 = stopFunction.StopFunction(self.toUser, [], nest=True)
        f2 = stopFunction.StopFunction(self.debugExitHap, [], nest=False)
        f3 = stopFunction.StopFunction(debug_function, [], nest=False)
        if to_user:
            flist = [f1, f2, f3]
        else:
            flist = [f2, f3]
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
        self.doDebugCmd()
        cpu = self.cell_config.cpuFromCell(self.target)
        self.setDebugBookmark('origin', cpu)
        self.bookmarks.setOrigin(cpu)

        self.toRunningProc(None, pid_list, flist, debug_group=True, final_fun=final_fun)

    def changedThread(self, cpu, third, forth, memory):
        cur_addr = SIM_get_mem_op_value_le(memory)
        pid = self.mem_utils[self.target].readWord32(cpu, cur_addr + self.param[self.target].ts_pid)
        if pid != 0:
            print('changedThread')
            self.show()

    def runToProc(self, prec, third, forth, memory):
        ''' callback when current_task is updated.  new value is in memory parameter '''
        if self.cur_task_hap is None:
            return
        cpu = prec.cpu
        cur_task_rec = SIM_get_mem_op_value_le(memory)
        pid = self.mem_utils[self.target].readWord32(cpu, cur_task_rec + self.param[self.target].ts_pid)
        #self.lgr.debug('runToProc look for %s pid is %d' % (prec.proc, pid))
        if pid != 0:
            comm = self.mem_utils[self.target].readString(cpu, cur_task_rec + self.param[self.target].ts_comm, 16)
            if (prec.pid is not None and pid in prec.pid) or (prec.pid is None and comm == prec.proc):
                self.lgr.debug('got proc %s pid is %d  prec.pid is %s' % (comm, pid, str(prec.pid)))
                SIM_run_alone(self.cleanToProcHaps, None)
                SIM_break_simulation('found %s' % prec.proc)
            else:
                #self.proc_list[self.target][pid] = comm
                #self.lgr.debug('runToProc pid: %d proc: %s' % (pid, comm))
                pass
            
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
        self.toRunningProc(None, [pid], None)

    def inFlist(self, fun_list, the_list):
        for stop_fun in the_list:
            for fun in fun_list:
                if stop_fun.fun == fun:
                    return True
        return False

    def toRunningProc(self, proc, want_pid_list=None, flist=None, debug_group=False, final_fun=None):
        ''' intended for use when process is already running '''
        cpu, comm, pid  = self.task_utils[self.target].curProc()
        ''' if already in proc, just attach debugger '''
        if want_pid_list is not None:
            self.lgr.debug('toRunningProc, run to pid_list %s, current pid %d <%s>' % (str(want_pid_list), pid, comm))
        else:
            self.lgr.debug('toRunningProc, look for <%s>, current pid %d <%s>' % (proc, pid, comm))
        if flist is not None and self.inFlist([self.debug, self.debugGroup], flist): 
            if pid != self.task_utils[self.target].getExitPid():
                if proc is not None and proc == comm:
                    self.lgr.debug('toRunningProc Already at proc %s, done' % proc)
                    f1 = stopFunction.StopFunction(self.debugExitHap, [], nest=False)
                    f2 = stopFunction.StopFunction(self.debug, [debug_group], nest=False)
                    self.toUser([f1, f2])
                    #self.debug()
                    return
                elif want_pid_list is not None and pid in want_pid_list:
                    ''' TBD FIXME '''
                    self.lgr.debug('toRunningProc already at pid %d, done' % pid)
                    f1 = stopFunction.StopFunction(self.debugExitHap, [], nest=False)
                    f2 = stopFunction.StopFunction(self.debug, [debug_group], nest=False)
                    if final_fun is not None:
                        f3 = stopFunction.StopFunction(final_fun, [], nest=False)
                        self.toUser([f1, f2, f3])
                    else:
                        self.toUser([f1, f2])
                    #self.debugGroup()
                    return
        ''' Set breakpoint on current_task to watch task switches '''
        prec = Prec(cpu, proc, want_pid_list)
        phys_current_task = self.task_utils[self.target].getPhysCurrentTask()
        self.cur_task_break = SIM_breakpoint(cpu.physical_memory, Sim_Break_Physical, Sim_Access_Write, 
                             phys_current_task, self.mem_utils[self.target].WORD_SIZE, 0)
        self.cur_task_hap = SIM_hap_add_callback_index("Core_Breakpoint_Memop", self.runToProc, prec, self.cur_task_break)
        self.lgr.debug('toRunningProc  want pids %s set break %d at 0x%x hap %d' % (str(want_pid_list), self.cur_task_break, phys_current_task,
            self.cur_task_hap))
        
        hap_clean = hapCleaner.HapCleaner(cpu)
        #hap_clean.add("Core_Breakpoint_Memop", self.cur_task_hap)
        #stop_action = hapCleaner.StopAction(hap_clean, [self.cur_task_break], flist)
        stop_action = hapCleaner.StopAction(hap_clean, [], flist)
        self.stop_hap = SIM_hap_add_callback("Core_Simulation_Stopped", 
        	     self.stopHap, stop_action)

        status = self.is_monitor_running.isRunning()
        if not status:
            try:
                self.lgr.debug('toRunningProc try continue')
                SIM_run_command('c')
                pass
            except SimExc_General as e:
                print('ERROR... try continue?')
                self.lgr.error('ERROR in toRunningProc  try continue? %s' % str(e))
                SIM_run_command('c')
        else:
            self.lgr.debug('toRunningProc thinks it is already running')
       

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
            self.coverage.saveCoverage()
        if self.command_callback is not None:
            self.lgr.debug('skipAndMail do callback to %s' % str(self.command_callback))
            SIM_run_alone(self.command_callback, None)
        else:
            self.restoreDebugBreaks()

    def goToOrigin(self, debugging=True):
        if self.bookmarks is None:
            self.lgr.debug('genMonitor goToOrigin, no bookmarks do nothing')
            return
        if debugging:
            self.removeDebugBreaks()
            self.stopTrackIO()
        cpu, comm, pid  = self.task_utils[self.target].curProc()
        self.lgr.debug('goToOrigin pid was is %d' % pid)
        msg = self.bookmarks.goToOrigin()
        cpu, comm, pid  = self.task_utils[self.target].curProc()
        self.lgr.debug('goToOrigin pid now is %d' % pid)
        if debugging:
            self.context_manager[self.target].setIdaMessage(msg)
            self.restoreDebugBreaks(was_watching=True)
            self.context_manager[self.target].watchTasks()

    def goToDebugBookmark(self, mark):
        self.lgr.debug('goToDebugBookmark %s' % mark)
        self.removeDebugBreaks()
        self.stopTrackIO()
        if len(self.call_traces[self.target]) > 0: 
            print('\n\n*** Syscall traces are active -- they must be deleted before jumping to bookmarks ***')
            self.lgr.debug('Syscall traces are active -- they must be deleted before jumping to bookmarks ')
            self.showHaps()
            #for call in self.call_traces[self.target]:
            #    self.lgr.debug('remaining trace %s' % call)
            return
        if type(mark) != int:
            mark = mark.replace('|','"')
        msg = self.bookmarks.goToDebugBookmark(mark)
        self.context_manager[self.target].setIdaMessage(msg)
        self.restoreDebugBreaks(was_watching=True)
        self.context_manager[self.target].watchTasks()

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
        self.stopped_reverse_instruction_hap = SIM_hap_add_callback("Core_Simulation_Stopped", 
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
            SIM_hap_delete_callback_id("Core_Simulation_Stopped", self.stopped_reverse_instruction_hap)
        else:
            self.lgr.debug('stoppedReverseInstruction in wrong pid (%d), try again' % pid)
            SIM_run_alone(SIM_run_command, 'reverse-step-instruction')
    
    def reverseToCallInstruction(self, step_into, prev=None):
        if self.reverseEnabled():
            dum, cpu = self.context_manager[self.target].getDebugPid() 
            cell_name = self.getTopComponentName(cpu)
            self.lgr.debug('reverseToCallInstruction, step_into: %r  on entry, gdb_mailbox: %s' % (step_into, self.gdb_mailbox))
            self.removeDebugBreaks()
            self.context_manager[self.target].showHaps()
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
        if not resim_status and debug_pid is None:
            retval = 'mailbox:exited'
            self.lgr.debug('getEIPWhenStopped debug_pid is gone, return %s' % retval)
            print(retval)
            return retval

        eip = self.getEIP(cpu)
        if resim_status and not simics_status:
            self.lgr.debug('getEIPWhenStopped Simics not running, RESim thinks it is running.  Perhaps gdb breakpoint?')
            pid, cpu = self.context_manager[self.target].getDebugPid() 
            SIM_run_command('pselect %s' % cpu.name)
            self.context_manager[self.target].setIdaMessage('Stopped at debugger breakpoint?')
            retval = 'mailbox:0x%x' % eip

        elif not resim_status:
            if cpu is None:
                self.lgr.error('no cpu defined in context manager')
                return
            cell_name = self.getTopComponentName(cpu)
            dum_cpu, comm, pid  = self.task_utils[self.target].curProc()
            self.lgr.debug('getEIPWhenStopped, pid %d' % (pid)) 
            if self.gdb_mailbox is not None:
                self.lgr.debug('getEIPWhenStopped mbox is %s pid is %d (%s) cycle: 0x%x' % (self.gdb_mailbox, pid, comm, cpu.cycles))
                retval = 'mailbox:%s' % self.gdb_mailbox
                print(retval)
                return retval
            else:
                self.lgr.debug('getEIPWhenStopped, mbox must be empty?')
            cpl = memUtils.getCPL(cpu)
            if cpl == 0 and not kernel_ok:
                self.lgr.debug('getEIPWhenStopped in kernel pid:%d (%s) eip is %x' % (pid, comm, eip))
                retval = 'in kernel'
                print(retval)
                return retval
            self.lgr.debug('getEIPWhenStopped pid:%d (%s) eip is %x' % (pid, comm, eip))
            #if debug_pid != pid:
            if not self.context_manager[self.target].amWatching(pid):
                self.lgr.debug('getEIPWhenStopped not watching process pid:%d (%s) eip is %x' % (pid, comm, eip))
                retval = 'wrong process'
                print(retval)
                return retval
            #SIM_run_command('pselect cpu-name = %s' % cpu.name)
            retval = 'mailbox:0x%x' % eip
            print(retval)
            #print 'cmd is %s' % cmd
            #SIM_run_command(cmd)
        else:
            self.lgr.debug('call to getEIPWhenStopped, not stopped at 0x%x' % eip)
            print('not stopped')
            retval = 'not stopped'
        return retval

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
            self.toRunningProc(None, pid_list, flist)

    def traceExecve(self, comm=None):
        self.pfamily.traceExecve(comm)

    def watchPageFaults(self, pid=None):

        self.lgr.debug('genMonitor watchPageFaults')
        if pid is None:
            pid, cpu = self.context_manager[self.target].getDebugPid() 
        self.page_faults[self.target].watchPageFaults(pid=pid, compat32=self.is_compat32)
        #self.page_faults[self.target].recordPageFaults()

    def stopWatchPageFaults(self, pid=None):
        self.lgr.debug('genMonitor stopWatchPageFaults')
        self.page_faults[self.target].stopWatchPageFaults(pid)
        self.page_faults[self.target].stopPageFaults()

    def catchCorruptions(self):
        self.watchPageFaults()

    def traceOpenSyscall(self):
        #self.lgr.debug('about to call traceOpen')
        self.traceOpen.traceOpenSyscall()

    def getCell(self):
        return self.cell_config.cell_context[self.target]

    def getCPU(self):
        return self.cell_config.cpuFromCell(self.target)

    def getPID(self):
        cpu, comm, this_pid = self.task_utils[self.target].curProc() 
        return this_pid

    def getCPL(self): 
        cpu, comm, this_pid = self.task_utils[self.target].curProc() 
        cpl = memUtils.getCPL(cpu)

    def skipBackToUser(self):
        cpu, comm, pid = self.task_utils[self.target].curProc() 
        self.rev_to_call[self.target].jumpOverKernel(pid)

    def reverseToUser(self):
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
            self.removeDebugBreaks()
            pid, cpu = self.context_manager[self.target].getDebugPid() 
            value = self.mem_utils[self.target].readMemory(cpu, addr, num_bytes)
            self.lgr.debug('stopAtKernelWrite, call findKernelWrite of 0x%x to address 0x%x num bytes %d' % (value, addr, num_bytes))
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

    def revTaintReg(self, reg, kernel=False):
        ''' back track the value in a given register '''
        reg = reg.lower()
        pid, cpu = self.context_manager[self.target].getDebugPid() 
        value = self.mem_utils[self.target].getRegValue(cpu, reg)
        self.lgr.debug('revTaintReg for %s value 0x%x' % (reg, value))
        if self.reverseEnabled():
            self.removeDebugBreaks()
            cell_name = self.getTopComponentName(cpu)
            eip = self.getEIP(cpu)
            instruct = SIM_disassemble_address(cpu, eip, 1, 0)
            reg_num = cpu.iface.int_register.get_number(reg)
            value = cpu.iface.int_register.read(reg_num)
            self.lgr.debug('revTaintReg for reg value %x' % value)
            track_num = self.bookmarks.setTrackNum()
            bm='backtrack START:%d 0x%x inst:"%s" track_reg:%s track_value:0x%x' % (track_num, eip, instruct[1], reg, value)
            self.bookmarks.setDebugBookmark(bm)
            self.context_manager[self.target].setIdaMessage('')
            self.rev_to_call[self.target].doRevToModReg(reg, taint=True, kernel=kernel)
        else:
            print('reverse execution disabled')
            self.skipAndMail()

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

    def runToSyscall(self, callnum = None):
        cell = self.cell_config.cell_context[self.target]
        self.is_monitor_running.setRunning(True)
        if callnum == 0:
            callname = None
        if callnum is not None:
            # TBD fix 32-bit compat
            callname = self.task_utils[self.target].syscallName(callnum, False)
            self.lgr.debug('runToSyscall for  %s' % callname)
            #call_params = [syscall.CallParams(callname, None, break_simulation=True)]        
            call_params = []

            if callnum == 120:
                print('Disabling thread tracking for clone')
                self.stopThreadTrack()
            self.call_traces[self.target][callname] = syscall.Syscall(self, self.target, None, self.param[self.target], 
                 self.mem_utils[self.target], self.task_utils[self.target], 
                 self.context_manager[self.target], None, self.sharedSyscall[self.target], self.lgr, self.traceMgr[self.target],call_list=[callname], 
                 call_params=call_params, stop_on_call=True, targetFS=self.targetFS[self.target])
        else:
            ''' watch all syscalls '''
            self.lgr.debug('runToSyscall for any system call')
            self.trace_all[self.target] = syscall.Syscall(self, self.target, None, self.param[self.target], 
                 self.mem_utils[self.target], self.task_utils[self.target], 
                 self.context_manager[self.target], None, self.sharedSyscall[self.target], self.lgr, self.traceMgr[self.target],
                 None, stop_on_call=True, targetFS=self.targetFS[self.target])
        SIM_run_command('c')

    def traceSyscall(self, callname=None, soMap=None, call_params=[], trace_procs = False):
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
                           binders=self.binders, connectors=self.connectors, targetFS=self.targetFS[self.target])
        return my_syscall

    def traceProcesses(self, new_log=True):
        cpu, comm, pid = self.task_utils[self.target].curProc() 
        call_list = ['vfork','fork', 'clone','execve','open','openat','pipe','pipe2','close','dup','dup2','socketcall', 
                     'exit', 'exit_group', 'waitpid', 'ipc', 'read', 'write', 'gettimeofday', 'mmap', 'mmap2']
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
            self.call_traces[self.target][call] = self.traceSyscall(callname=call, trace_procs=True, soMap=self.soMap[self.target])

    def stopTrace(self, cell_name=None, syscall=None):
        if cell_name is None:
            cell_name = self.target
        if syscall is not None:
            self.lgr.debug('genMonitor stopTrace from genMonitor cell %s given syscall %s' % (cell_name, syscall.name))
        else:
            self.lgr.debug('genMonitor stopTrace from genMonitor cell %s no given syscall' % (cell_name))

        dup_traces = self.call_traces[cell_name].copy()
        for call in dup_traces:
            syscall_trace = dup_traces[call]
            if syscall is None or syscall_trace == syscall: 
                #self.lgr.debug('genMonitor stopTrace cell %s of call %s' % (cell_name, call))
                syscall_trace.stopTrace(immediate=True)
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

    def rmCallTrace(self, cell_name, callname):
        #self.lgr.debug('genMonitor rmCallTrace %s' % callname)
        if callname in self.call_traces[cell_name]:
            #self.lgr.debug('genMonitor rmCallTrace will delete %s' % callname)
            del self.call_traces[cell_name][callname]

    def traceFile(self, path):
        self.lgr.debug('traceFile %s' % path)
        outfile = os.path.join('/tmp', os.path.basename(path))
        self.traceFiles[self.target].watchFile(path, outfile)

    def traceFD(self, fd):
        self.lgr.debug('traceFD %d' % fd)
        outfile = '/tmp/output-fd-%d.log' % fd
        self.traceFiles[self.target].watchFD(fd, outfile)

    def exceptHap(self, cpu, one, exception_number):
        cpu, comm, pid = self.task_utils[self.target].curProc() 
        call = self.mem_utils[self.target].getRegValue(cpu, 'r7')
        self.lgr.debug('exeptHap except: %d  pid %d call %d' % (exception_number, pid, call))
        
    def traceAll(self, target=None, record_fd=False):
        if target is None:
            target = self.target

        ''' trace all system calls. if a program selected for debugging, watch only that program '''
        self.lgr.debug('traceAll target %s begin' % target)
        if target not in self.cell_config.cell_context:
            print('Unknown target %s' % target)
            return
        if target in self.trace_all:
            self.trace_all[target].setRecordFD(record_fd)
            print('Was tracing.  Limit to FD recording? %r' % (record_fd))
        else:
            cell = self.cell_config.cell_context[target]
            pid, cpu = self.context_manager[target].getDebugPid() 
            if pid is not None:
                tf = '/tmp/syscall_trace-%s-%d.txt' % (target, pid)
            else:
                tf = '/tmp/syscall_trace-%s.txt' % target
                cpu, comm, pid = self.task_utils[target].curProc() 

            self.traceMgr[target].open(tf, cpu)
            if not self.context_manager[self.target].watchingTasks():
                self.traceProcs[target].watchAllExits()
            self.trace_all[target] = syscall.Syscall(self, target, None, self.param[target], self.mem_utils[target], self.task_utils[target], 
                           self.context_manager[target], self.traceProcs[target], self.sharedSyscall[target], self.lgr, self.traceMgr[target], call_list=None, 
                           trace=True, soMap=self.soMap[target], binders=self.binders, connectors=self.connectors, targetFS=self.targetFS[target], record_fd=record_fd,
                           name='traceAll', linger=True)

            if self.run_from_snap is not None:
                p_file = os.path.join('./', self.run_from_snap, target, 'sharedSyscall.pickle')
                if os.path.isfile(p_file):
                    exit_info_list = pickle.load(open(p_file, 'rb'))
                    if exit_info_list is None:
                        self.lgr.error('No data found in %s' % p_file)
                    else:
                        self.trace_all[target].setExits(exit_info_list)

    def noDebug(self, dumb=None):
        self.lgr.debug('noDebug')
        cmd = 'disable-reverse-execution'
        SIM_run_command(cmd)
        self.rev_execution_enabled = False
        self.removeDebugBreaks(keep_watching=True, keep_coverage=False)
        self.sharedSyscall[self.target].setDebugging(False)

    def stopDebug(self):
        ''' stop all debugging '''
        self.lgr.debug('stopDebug')
        if self.rev_execution_enabled:
            cmd = 'disable-reverse-execution'
            SIM_run_command(cmd)
            self.rev_execution_enabled = False
        self.removeDebugBreaks(keep_watching=False, keep_coverage=False)
        self.sharedSyscall[self.target].setDebugging(False)
        self.stopTrace()

    def restartDebug(self):
        cmd = 'enable-reverse-execution'
        SIM_run_command(cmd)
        self.rev_execution_enabled = True
        self.restoreDebugBreaks(was_watching=True)
        self.sharedSyscall[self.target].setDebugging(True)

    def startThreadTrack(self):
        for cell_name in self.track_threads:
            self.lgr.debug('startThreadTrack for %s' % cell_name)
            self.track_threads[cell_name].startTrack()
        
    def stopThreadTrack(self):
        for cell_name in self.track_threads:
            self.lgr.debug('stopThreadTrack for %s' % cell_name)
            self.track_threads[cell_name].stopTrack()

    def showProcTrace(self):
        pid_comm_map = self.task_utils[self.target].getPidCommMap()
        precs = self.traceProcs[self.target].getPrecs()
        for pid in precs:
            if precs[pid].prog is None and pid in pid_comm_map:
                precs[pid].prog = 'comm: %s' % (pid_comm_map[pid])
        #for pid in precs:
        #    if precs[pid].prog is None and pid in self.proc_list[self.target]:
        #        precs[pid].prog = 'comm: %s' % (self.proc_list[self.target][pid])
        
        self.traceProcs[self.target].showAll()
 
    def toExecve(self, comm, flist=None, binary=False):
        cell = self.cell_config.cell_context[self.target]
            
        call_params = syscall.CallParams('execve', comm, break_simulation=True)        
        if binary:
            call_params.param_flags.append('binary')

        ''' create own syscall instance if watching tasks or not tracing all calls '''
        if self.target not in self.trace_all or self.trace_all[self.target] is None or self.context_manager[self.target].watchingTasks():
            self.call_traces[self.target]['execve'] = syscall.Syscall(self, self.target, cell, self.param[self.target], self.mem_utils[self.target], 
                           self.task_utils[self.target], 
                           self.context_manager[self.target], self.traceProcs[self.target], self.sharedSyscall[self.target], self.lgr, 
                           self.traceMgr[self.target], call_list=['execve'], trace=False, flist_in = flist, 
                           netInfo=self.netInfo[self.target], targetFS=self.targetFS[self.target], call_params=[call_params], name='execve')
        else:
            ''' stuff the call params into existing traceall syscall module '''
            self.trace_all[self.target].addCallParams([call_params])
        SIM_run_command('c')

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
        self.exit_group_syscall[self.target].unsetDebuggingExit()
        SIM_break_simulation('text hap')
        if prec.debugging:
            self.context_manager[self.target].genDeleteHap(self.proc_hap)
            self.proc_hap = None
            self.skipAndMail()

    def debugExitHap(self, flist=None): 
        ''' intended to stop simultion if the threads we are debugging all exit '''
        cell = self.cell_config.cell_context[self.target]
        somap = None
        if self.target in self.soMap:
            somap = self.soMap[self.target]
        else:
            self.lgr.debug('debugExitHap no so map for %s' % self.target)
        
        self.exit_group_syscall[self.target] = syscall.Syscall(self, self.target, None, self.param[self.target], 
                       self.mem_utils[self.target], self.task_utils[self.target], 
                       self.context_manager[self.target], None, self.sharedSyscall[self.target], self.lgr, self.traceMgr[self.target], 
                       call_list=['exit_group'], soMap=somap, debugging_exit=True, compat32=self.is_compat32)
        self.lgr.debug('debugExitHap compat32: %r syscall is %s' % (self.is_compat32, str(self.exit_group_syscall[self.target])))

    def rmDebugExitHap(self):
        ''' Intended to be called if a SEGV or other cause of death occurs, in which case we assume that is caught by
            the contextManager and we do not want this rudundant stopage. '''
        if self.target in self.exit_group_syscall:
            self.lgr.debug('rmDebugExit')
            self.exit_group_syscall[self.target].stopTrace()
            del self.exit_group_syscall[self.target]
       
    def noReverse(self):
        self.noWatchSysEnter()
        cmd = 'disable-reverse-execution'
        SIM_run_command(cmd)
        self.noWatchSysEnter()
        self.lgr.debug('genMonitor noReverse')

    def allowReverse(self):
        cmd = 'enable-reverse-execution'
        SIM_run_command(cmd)
        pid, cpu = self.context_manager[self.target].getDebugPid() 
        prec = Prec(cpu, None, pid)
        if pid is not None:
            self.rev_to_call[self.target].watchSysenter(prec)
        self.lgr.debug('genMonitor allowReverse')
 
    def restoreDebugBreaks(self, dumb=None, was_watching=False):
        if not self.debug_breaks_set:
            #self.lgr.debug('restoreDebugBreaks')
            #self.context_manager[self.target].restoreDebug() 
            self.context_manager[self.target].resetWatchTasks() 
            pid, cpu = self.context_manager[self.target].getDebugPid() 
            if pid is not None:
                if not was_watching:
                    self.context_manager[self.target].watchTasks()
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
            if self.trace_malloc is not None:
                self.trace_malloc.setBreaks()
            if self.injectIOInstance is not None:
                self.injectIOInstance.setCallHap()

    def noWatchSysEnter(self):
        self.lgr.debug('noWatchSysEnter')
        self.rev_to_call[self.target].noWatchSysenter()

 
    def removeDebugBreaks(self, keep_watching=False, keep_coverage=True, immediate=False):
        self.lgr.debug('genMon removeDebugBreaks')
        pid, cpu = self.context_manager[self.target].getDebugPid() 
        self.stopWatchPageFaults(pid)
        if not keep_watching:
            self.context_manager[self.target].stopWatchTasks()
        self.rev_to_call[self.target].noWatchSysenter()
        if self.target in self.track_threads:
            self.track_threads[self.target].stopTrack(immediate=immediate)
        if self.target in self.exit_group_syscall:
            self.exit_group_syscall[self.target].stopTrace(immediate=immediate)
            del self.exit_group_syscall[self.target]
        if self.target in self.ropCop:
            self.ropCop[self.target].clearHap()
        self.context_manager[self.target].clearExitBreaks()
        self.debug_breaks_set = False
        if self.coverage is not None and not keep_coverage:
            self.coverage.stopCover(keep_hits=True)
        if self.trace_malloc is not None:
            self.trace_malloc.stopTrace()
        if self.injectIOInstance is not None:
            self.injectIOInstance.delCallHap()

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
        self.stop_hap = SIM_hap_add_callback("Core_Simulation_Stopped", 
          self.stopHap, stop_action)
        self.lgr.debug('hap set, now reverse')
        SIM_run_command('rev')

    def getSyscall(self, cell_name, callname):
        ''' find the most specific syscall for the given callname '''
        if cell_name in self.exit_group_syscall and callname == 'exit_group':
            #self.lgr.debug('is exit group')
            return self.exit_group_syscall[cell_name]
        elif cell_name in self.call_traces: 
            if callname in self.call_traces[cell_name]:
                #self.lgr.debug('is given callname %s' % callname)
                return self.call_traces[cell_name][callname]
            elif cell_name in self.trace_all:
                #self.lgr.debug('is trace all')
                return self.trace_all[cell_name]
            else:
                self.lgr.debug('genMonitor getSyscall, not able to return instance for call %s len self.call_traces %d' % (callname, 
                           len(self.call_traces[cell_name])))
        return None

    def tracingAll(self, cell_name, pid):
        ''' are we tracing all syscalls for the given pid? '''
        retval = False
        if cell_name in self.trace_all:
            debug_pid, dumb1 = self.context_manager[self.target].getDebugPid() 
            if debug_pid is None:
                self.lgr.debug('tracingAll pid none, return true')
                retval = True
            else:
                if self.context_manager[self.target].amWatching(pid):
                    self.lgr.debug('tracingAll watching pid %d' % pid)
                    retval = True
        return retval
            

    def runToText(self, flist = None):
        ''' run until within the currently defined text segment '''
        self.is_monitor_running.setRunning(True)
        start, end = self.context_manager[self.target].getText()
        if start is None:
            print('No text segment defined, has IDA been started with the rev plugin?')
            return
        count = end - start
        self.lgr.debug('runToText range 0x%x 0x%x' % (start, end))
        proc_break = self.context_manager[self.target].genBreakpoint(None, Sim_Break_Linear, Sim_Access_Execute, start, count, 0)
        pid, cpu = self.context_manager[self.target].getDebugPid() 
        if pid is None:
            self.lgr.debug('runToText, not debugging yet, assume current process')
            cpu, comm, pid = self.task_utils[self.target].curProc() 
            prec = Prec(cpu, None, [pid], who='to text')
        else:
            pid_list = self.context_manager[self.target].getThreadPids()
            prec = Prec(cpu, None, pid_list, who='to text')
        ''' NOTE obscure use of flist to determine if SO files are tracked '''
        if flist is None:
            prec.debugging = True
            f1 = stopFunction.StopFunction(self.skipAndMail, [], nest=False)
            flist = [f1]

        else:
            #self.call_traces[self.target]['open'] = self.traceSyscall(callname='open', soMap=self.soMap)
            call_list = ['open', 'mmap']
            if self.mem_utils[self.target].WORD_SIZE == 4 or self.is_compat32: 
                call_list.append('mmap2')
            cell = self.cell_config.cell_context[self.target]
            self.call_traces[self.target]['open']  = syscall.Syscall(None, self.target, None, self.param[self.target], self.mem_utils[self.target], self.task_utils[self.target], 
                           self.context_manager[self.target], None, self.sharedSyscall[self.target], self.lgr, None, call_list=call_list,
                           soMap=self.soMap, targetFS=self.targetFS, skip_and_mail=False, compat32=self.is_compat32)
            self.lgr.debug('debug watching open syscall and mmap')

        self.proc_hap = self.context_manager[self.target].genHapIndex("Core_Breakpoint_Memop", self.textHap, prec, proc_break, 'text_hap')

        hap_clean = hapCleaner.HapCleaner(cpu)
        hap_clean.add("GenContext", self.proc_hap)
        stop_action = hapCleaner.StopAction(hap_clean, None, flist)
        self.stop_hap = SIM_hap_add_callback("Core_Simulation_Stopped", 
          self.stopHap, stop_action)

        self.context_manager[self.target].watchTasks()
        self.lgr.debug('runToText hap set, now run. flist in stophap is %s' % stop_action.listFuns())
        SIM_run_alone(SIM_run_command, 'continue')

    def undoDebug(self, dumb):
        self.lgr.debug('undoDebug')
        if self.cur_task_hap is not None:
            SIM_hap_delete_callback_id("Core_Breakpoint_Memop", self.cur_task_hap)
            SIM_delete_breakpoint(self.cur_task_break)
            self.cur_task_hap = None
        if self.proc_hap is not None:
            self.context_manager[self.target].genDeleteHap(self.proc_hap)
            self.proc_hap = None
        if self.stop_hap is not None:
            SIM_hap_delete_callback_id("Core_Simulation_Stopped", self.stop_hap)
            self.stop_hap = None
        self.lgr.debug('undoDebug done')
            

    def remainingCallTraces(self):
        for cell_name in self.call_traces:
            if len(self.call_traces[cell_name]) > 0:
                #for ct in self.call_traces[cell_name]:
                #    self.lgr.debug('remainingCallTraces found remain for cell %s call %s' % (cell_name, ct))
                return True
        return False

    def runTo(self, call, call_params, cell_name=None, run=True, linger=False, background=False, ignore_running=False, name=None, flist=None):
        ''' call is a list '''
        if not ignore_running and self.is_monitor_running.isRunning():
            print('Monitor is running, try again after it pauses')
            return
        if cell_name is None:
            cell_name = self.target
        cell = self.cell_config.cell_context[cell_name]
        ''' qualify call with name, e.g, for multiple dmod on reads '''
        call_name = call[0]
        if name is not None:
            call_name = '%s-%s' % (call[0], name)
        self.lgr.debug('genMonitor runTo cellname %s call_name %s compat32 %r' % (cell_name, call_name, self.is_compat32))

        if cell_name not in self.trace_all or self.trace_all[cell_name] is None:
            self.call_traces[cell_name][call_name] = syscall.Syscall(self, cell_name, None, self.param[cell_name], self.mem_utils[cell_name], 
                               self.task_utils[cell_name], self.context_manager[cell_name], None, self.sharedSyscall[cell_name], 
                               self.lgr, self.traceMgr[cell_name],
                               call_list=call, call_params=[call_params], targetFS=self.targetFS[cell_name], linger=linger, 
                               background=background, name=name, flist_in=flist)
                               #compat32=self.is_compat32, background=background)
        else:
            ''' stuff the call params into existing traceall syscall module '''
            self.trace_all[cell_name].addCallParams([call_params])
            self.lgr.debug('runTo added parameters rather than new syscall')
        if run:
            self.is_monitor_running.setRunning(True)
            SIM_run_command('c')

    def runToClone(self, nth=1):
        self.lgr.debug('runToClone to %s' % str(nth))
        call_params = syscall.CallParams('clone', None, break_simulation=True)        
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
        call_params = syscall.CallParams('connect', addr, break_simulation=True, proc=proc)        
        call_params.nth = nth
        self.runTo(call, call_params, name='connect')

    def setDmod(self, dfile):
        self.runToDmod(dfile, cell_name = self.target)

    def runToDmod(self, dfile, cell_name=None, background=False):
        if not os.path.isfile(dfile):
            print('No file found at %s' % dfile)
            return
        if cell_name is None:
            cell_name = self.target
        mod = dmod.Dmod(self, dfile, self.mem_utils[self.target], cell_name, self.lgr)
        operation = mod.getOperation()
        call_params = syscall.CallParams(operation, mod, break_simulation=True)        
        if cell_name is None:
            cell_name = self.target
            run = True
        else:
            run = False
        operation = mod.getOperation()
        self.lgr.debug('runToDmod file %s cellname %s operation: %s' % (dfile, cell_name, operation))
        self.runTo([operation], call_params, cell_name=cell_name, run=run, background=background, name=dfile)
        #self.runTo(operation, call_params, cell_name=cell_name, run=run, background=False)

    def runToWrite(self, substring):
        call_params = syscall.CallParams('write', substring, break_simulation=True)        
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
        call_params = syscall.CallParams('open', substring, break_simulation=True)
        self.lgr.debug('runToOpen to %s' % substring)
        self.runTo(['open'], call_params, name='open')

    def runToSend(self, substring):
        call = self.task_utils[self.target].socketCallName('send', self.is_compat32)
        call_params = syscall.CallParams('send', substring, break_simulation=True)        
        self.lgr.debug('runToSend to %s' % substring)
        self.runTo(call, call_params, name='send')

    def runToSendPort(self, port):
        call = self.task_utils[self.target].socketCallName('sendto', self.is_compat32)
        call_params = syscall.CallParams('sendto', port, break_simulation=True)        
        call_params.param_flags.append(syscall.DEST_PORT)
        self.lgr.debug('runToSendPort to port %s' % port)
        self.runTo(call, call_params, name='sendport')

    def runToReceive(self, substring):
        call = self.task_utils[self.target].socketCallName('recvmsg', self.is_compat32)
        call_params = syscall.CallParams('recvmsg', substring, break_simulation=True)        
        self.lgr.debug('runToReceive to %s' % substring)
        self.runTo(call, call_params, name='recv')

    def runToRead(self, substring):
        call = self.task_utils[self.target].socketCallName('read', self.is_compat32)
        call_params = syscall.CallParams('read', substring, break_simulation=True)        
        self.lgr.debug('runToRead to %s' % substring)
        self.runTo(call, call_params, name='read')

    def runToAccept(self, fd, flist=None, proc=None):
        call = self.task_utils[self.target].socketCallName('accept', self.is_compat32)
        call_params = syscall.CallParams('accept', fd, break_simulation=True, proc=proc)        
        self.lgr.debug('runToAccept on FD: %d call is: %s' % (fd, str(call)))
        if flist is None:
            linger = True
        else:
            linger = False
        self.runTo(call, call_params, linger=linger, flist=flist, name='accept')
        
    def runToBind(self, addr, proc=None):
        #addr = '192.168.31.52:20480'
        if type(addr) is int:
            addr = '.*:%d' % addr
        try:
            test = re.search(addr, 'nothing', re.M|re.I)
        except:
            self.lgr.error('invalid pattern: %s' % addr)
            return
        call = self.task_utils[self.target].socketCallName('bind', self.is_compat32)
        call_params = syscall.CallParams('bind', addr, break_simulation=True, proc=proc)        
        self.lgr.debug('runToBind to %s ' % (addr))
        self.runTo(call, call_params, name='bind')

    def runToIO(self, fd, linger=False, break_simulation=True, count=1, flist_in=None, reset=False, run_fun=None, proc=None):
        call_params = syscall.CallParams(None, fd, break_simulation=break_simulation, proc=proc)        
        call_params.nth = count
        cell = self.cell_config.cell_context[self.target]
        self.lgr.debug('runToIO on FD %d' % fd)
        pid, cpu = self.context_manager[self.target].getDebugPid() 
        if pid is None:
            cpu, comm, pid = self.task_utils[self.target].curProc() 

        if self.target not in self.trace_all or self.trace_all[self.target] is None:
            calls = ['read', 'write', '_llseek', 'socketcall', 'close', 'ioctl', 'select', 'pselect6', '_newselect']
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
            skip_and_mail = True
            if flist_in is not None:
                ''' Given callback functions, use those instead of skip_and_mail '''
                skip_and_mail = False
    
            the_syscall = syscall.Syscall(self, self.target, None, self.param[self.target], self.mem_utils[self.target], self.task_utils[self.target], 
                                   self.context_manager[self.target], None, self.sharedSyscall[self.target], self.lgr, self.traceMgr[self.target],
                                   calls, call_params=[call_params], targetFS=self.targetFS[self.target], linger=linger, flist_in=flist_in, 
                                   skip_and_mail=skip_and_mail, name='runToIO')
            for call in calls:
                self.call_traces[self.target][call] = the_syscall
            ''' find processes that are in the kernel on IO calls '''
            frames = self.getDbgFrames()
            skip_calls = ['select', 'pselect', '_newselect']
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
                the_syscall.setExits(frames, reset=reset) 
        else:
            self.trace_all[self.target].addCallParams([call_params])
            self.lgr.debug('runToIO added parameters rather than new syscall')


        if run_fun is not None:
            SIM_run_alone(run_fun, None) 
        SIM_run_command('c')

    def runToInput(self, fd, linger=False, break_simulation=True, count=1, flist_in=None):
        call_params1 = syscall.CallParams('read', fd, break_simulation=break_simulation)        
        call_params1.nth = count
        call_params2 = syscall.CallParams('recv', fd, break_simulation=break_simulation)        
        call_params2.nth = count
        call_params3 = syscall.CallParams('recvfrom', fd, break_simulation=break_simulation)        
        call_params3.nth = count
        cell = self.cell_config.cell_context[self.target]
        self.lgr.debug('runToInput on FD %d' % fd)
        cpu, comm, pid = self.task_utils[self.target].curProc() 
        calls = ['read', 'socketcall']
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

        the_syscall = syscall.Syscall(self, self.target, None, self.param[self.target], self.mem_utils[self.target], self.task_utils[self.target], 
                               self.context_manager[self.target], None, self.sharedSyscall[self.target], self.lgr, self.traceMgr[self.target],
                               calls, call_params=[call_params1,call_params2,call_params3], targetFS=self.targetFS[self.target], linger=linger, flist_in=flist_in, 
                               skip_and_mail=skip_and_mail, name='runToInput')
        for call in calls:
            self.call_traces[self.target][call] = the_syscall
        ''' find processes that are in the kernel on IO calls '''
      
        frames = self.getDbgFrames()
        for pid in list(frames):
            call = self.task_utils[self.target].syscallName(frames[pid]['syscall_num'], self.is_compat32) 
            self.lgr.debug('runToInput found %s in kernel for pid:%d' % (call, pid))
            if call not in calls:
               del frames[pid]
        if len(frames) > 0:
            self.lgr.debug('runToIO, call to setExits')
            the_syscall.setExits(frames) 
       
        
        SIM_run_command('c')


    def getCurrentSO(self):
        cpu, comm, pid = self[self.target].task_utils[self.target].curProc() 
        eip = self.getEIP(cpu)
        retval = self.getSO(eip)
        return retval

    def getSOFromFile(self, fname):
        retval = ''
        self.lgr.debug('getSOFromFile %s' % fname)
        pid, cpu = self.context_manager[self.target].getDebugPid() 
        if pid is None:
           self.lgr.error('gotSOFromFile, no debug pid defined')
           return retval
        self.lgr.debug('getSOFromFile pid:%d fname %s' % (pid, fname))
        text_seg  = self.soMap[self.target].getSOAddr(fname, pid=pid) 
        if text_seg is None:
            self.lgr.error('getSO no map for %s' % fname)
            return retval
        if text_seg.address is not None:
            if text_seg.locate is not None:
                start = text_seg.locate+text_seg.offset
                end = start + text_seg.size
            else:
                # TBD fix this, assume text segment, no offset (fix for relocatable mains)
                start = 0
                end = text_seg.address + text_seg.size
            retval = ('%s:0x%x-0x%x' % (fname, start, end))
            print(retval)
        else:
            print('None')
        return retval

    def getSO(self, eip):
        fname = self.getSOFile(eip)
        #self.lgr.debug('getCurrentSO fname for eip 0x%x is %s' % (eip, fname))
        retval = None
        if fname is not None:
            text_seg  = self.soMap[self.target].getSOAddr(fname) 
            if text_seg is None:
                self.lgr.error('getSO no map for %s' % fname)
                return
            if text_seg.address is not None:
                if text_seg.locate is not None:
                    start = text_seg.locate+text_seg.offset
                    end = start + text_seg.size
                else:
                    start = text_seg.address
                    end = text_seg.address + text_seg.size
                retval = ('%s:0x%x-0x%x' % (fname, start, end))
            else:
                print('None')
        else:
            print('None')
        return retval
     
    def showSOMap(self, pid=None):
        self.lgr.debug('showSOMap')
        self.soMap[self.target].showSO(pid)

    def listSOMap(self):
        self.soMap[self.target].listSO()

    def getSOFile(self, addr):
        fname = self.soMap[self.target].getSOFile(addr)
        return fname

    def showThreads(self):
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
            

    def traceExternal(self):
        call_list = ['vfork','fork', 'clone','execve','socketcall']
        call_params = {}
        call_params['socketcall'] = []
        cp = syscall.CallParams('connect', None)
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
        cp = syscall.CallParams('bind', None)
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

    def dumpBinders(self):
            self.binders = self.call_traces[self.target]['socketcall'].getBinders()
            self.binders.dumpJson('/tmp/binder.json')

    def showConnectors(self):
            self.connectors.showAll('/tmp/connector.txt')
            self.connectors.dumpJson('/tmp/connector.json')

    def dumpConnectors(self):
            self.connectors = self.call_traces[self.target]['socketcall'].getConnectors()
            self.connectors.dumpJson('/tmp/connector.json')

    def stackTrace(self, verbose=False, in_pid=None):
        cpu, comm, cur_pid = self.task_utils[self.target].curProc() 
        if in_pid is not None:
            pid = in_pid
        else:
            pid = cur_pid
        if pid not in self.stack_base[self.target]:
            stack_base = None
        else:
            stack_base = self.stack_base[self.target][pid]
        if pid == cur_pid:
            reg_frame = self.task_utils[self.target].frameFromRegs(cpu)
        else:
            reg_frame, cycles = self.rev_to_call[self.target].getRecentCycleFrame(pid)
       
        st = stackTrace.StackTrace(self, cpu, pid, self.soMap[self.target], self.mem_utils[self.target], 
                 self.task_utils[self.target], stack_base, self.ida_funs, self.targetFS[self.target], 
                 self.relocate_funs, reg_frame, self.lgr)
        st.printTrace(verbose)

    def getStackTraceQuiet(self, max_frames=None, max_bytes=None):
        pid, cpu = self.context_manager[self.target].getDebugPid() 
        if pid is None:
            cpu, comm, pid = self.task_utils[self.target].curProc() 
        else:
            cpu, comm, cur_pid = self.task_utils[self.target].curProc() 
            if pid != cur_pid:
                if not self.context_manager[self.target].amWatching(cur_pid):
                    self.lgr.debug('getSTackTraceQuiet not in expected pid %d, current is %d' % (pid, cur_pid))
                    return None
                else:
                    pid = cur_pid
        if pid not in self.stack_base[self.target]:
            stack_base = None
        else:
            stack_base = self.stack_base[self.target][pid]
        reg_frame = self.task_utils[self.target].frameFromRegs(cpu)
        st = stackTrace.StackTrace(self, cpu, pid, self.soMap[self.target], self.mem_utils[self.target], 
                self.task_utils[self.target], stack_base, self.ida_funs, self.targetFS[self.target], self.relocate_funs, 
                reg_frame, self.lgr, max_frames=max_frames, max_bytes=max_bytes)
        return st

    def getStackTrace(self):
        ''' used by IDA client '''
        pid, cpu = self.context_manager[self.target].getDebugPid() 
        if pid is None:
            cpu, comm, pid = self.task_utils[self.target].curProc() 
        else:
            cpu, comm, cur_pid = self.task_utils[self.target].curProc() 
            if not self.context_manager[self.target].amWatching(cur_pid):
                self.lgr.debug('getSTackTrace not expected pid %d, current is %d  -- not a thread?' % (pid, cur_pid))
                return "{}"
            pid = cur_pid
        self.lgr.debug('genMonitor getStackTrace pid %d' % pid)
        if pid not in self.stack_base[self.target]:
            stack_base = None
        else:
            stack_base = self.stack_base[self.target][pid]
        reg_frame = self.task_utils[self.target].frameFromRegs(cpu)
        st = stackTrace.StackTrace(self, cpu, pid, self.soMap[self.target], self.mem_utils[self.target], 
                  self.task_utils[self.target], stack_base, self.ida_funs, self.targetFS[self.target], 
                  self.relocate_funs, reg_frame, self.lgr)
        j = st.getJson() 
        self.lgr.debug(j)
        #print j
        return j

    def resetOrigin(self, cpu=None):
        if cpu is None:
            pid, cpu = self.context_manager[self.target].getDebugPid() 
        cmd = 'disable-reverse-execution'
        SIM_run_command(cmd)
        cmd = 'enable-reverse-execution'
        SIM_run_command(cmd)
        self.rev_execution_enabled = True
        if self.bookmarks is not None:
            self.bookmarks.setOrigin(cpu, self.context_manager[self.target].getIdaMessage())
        else:
            self.lgr.debug('genMonitor resetOrigin without bookmarks, assume you will use bookmark0')

    def clearBookmarks(self):
        pid, cpu = self.context_manager[self.target].getDebugPid() 
        self.lgr.debug('genMonitor clearBookmarks')
        if pid is None:
            print('** Not debugging?? **')
            self.lgr.debug('clearBookmarks, Not debugging?? **')
            return False
        self.bookmarks.clearMarks()
        self.resetOrigin(cpu)
        self.dataWatch[self.target].clearWatchMarks()
        cpu, comm, pid = self.task_utils[self.target].curProc() 
        self.stopTrackIO()
        self.dataWatch[self.target].clearWatches(cpu.cycles)
        self.rev_to_call[self.target].resetStartCycles()
        return True

    def writeRegValue(self, reg, value):
        cpu, comm, pid = self.task_utils[self.target].curProc() 
        reg_num = cpu.iface.int_register.get_number(reg)
        cpu.iface.int_register.write(reg_num, value)
        self.lgr.debug('writeRegValue %s, %x regnum %d' % (reg, value, reg_num))
        self.clearBookmarks()

    def writeWord(self, address, value):
        ''' NOTE: wipes out bookmarks! '''
        cpu, comm, pid = self.task_utils[self.target].curProc() 
        self.mem_utils[self.target].writeWord(cpu, address, value)
        #phys_block = cpu.iface.processor_info.logical_to_physical(address, Sim_Access_Read)
        #SIM_write_phys_memory(cpu, phys_block.address, value, 4)
        self.lgr.debug('writeWord(0x%x, 0x%x), disable reverse execution to clear bookmarks, then set origin' % (address, value))
        self.clearBookmarks()

    def writeByte(self, address, value):
        ''' NOTE: wipes out bookmarks! '''
        cpu, comm, pid = self.task_utils[self.target].curProc() 
        self.mem_utils[self.target].writeByte(cpu, address, value)
        #phys_block = cpu.iface.processor_info.logical_to_physical(address, Sim_Access_Read)
        #SIM_write_phys_memory(cpu, phys_block.address, value, 4)
        self.lgr.debug('writeByte(0x%x, 0x%x), disable reverse execution to clear bookmarks, then set origin' % (address, value))
        self.clearBookmarks()

    def writeString(self, address, string):
        ''' NOTE: wipes out bookmarks! '''
        cpu, comm, pid = self.task_utils[self.target].curProc() 
        self.lgr.debug('writeString 0x%x %s' % (address, string))
        self.mem_utils[self.target].writeString(cpu, address, string)
        self.lgr.debug('writeString, disable reverse execution to clear bookmarks, then set origin')
        self.clearBookmarks()

    def stopDataWatch(self):
        self.lgr.debug('genMonitor stopDataWatch')
        self.dataWatch[self.target].stopWatch(break_simulation=True)

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
            SIM_run_command('c')
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

        tod_track = None
        if self.target in self.trace_all:
            self.lgr.debug('exitMaze, trace_all is %s' % str(self.trace_all[self.target]))
            tod_track = self.trace_all[self.target]
            self.lgr.debug('genMonitor exitMaze, using traceAll syscall')
        if tod_track is None: 
            if syscallname in self.call_traces:
                self.lgr.debug('genMonitor exitMaze pid:%d, using syscall defined for %s' % (pid, syscallname))
                tod_track = self.call_traces[self.target][syscallname]
            else:
                self.lgr.debug('genMonitor exitMaze pid:%d, using new syscall for %s' % (pid, syscallname))
                tod_track = syscall.Syscall(self, self.target, None, self.param[self.target], self.mem_utils[self.target], self.task_utils[self.target], 
                           self.context_manager[self.target], None, self.sharedSyscall[self.target], self.lgr,self.traceMgr, 
                           call_list=[syscallname])
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

    def writeConfig(self, name):
        cmd = 'write-configuration %s' % name 
        SIM_run_command(cmd)
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
                if self.run_from_snap is not None:
                    old_afl_file = os.path.join('./', self.run_from_snap, cell_name, 'afl.pickle')
                    if os.path.isfile(old_afl_file):
                        new_afl_file = os.path.join('./', name, cell_name, 'afl.pickle')
                        shutil.copyfile(old_afl_file, new_afl_file)
                p_file = os.path.join('./', name, cell_name, 'sharedSyscall.pickle')
                exit_info_list = self.sharedSyscall[cell_name].getExitList('traceAll')
                self.lgr.debug('writeConfig saved %d exit_info records' % len(exit_info_list))
                pickle.dump(exit_info_list, open(p_file, 'wb'))
                
        net_link_file = os.path.join('./', name, 'net_link.pickle')
        pickle.dump( self.link_dict, open( net_link_file, "wb" ) )
        
        stack_base_file = os.path.join('./', name, 'stack_base.pickle')
        pickle.dump( self.stack_base, open(stack_base_file, "wb" ) )

        debug_info_file = os.path.join('./', name, 'debug_info.pickle')
        debug_info = {}
        debug_pid, debug_cpu = self.context_manager[self.target].getDebugPid()
        if debug_pid is not None:
            debug_info['pid'] = debug_pid
            debug_info['cpu'] = debug_cpu.name
        pickle.dump( debug_info, open(debug_info_file, "wb" ) )


        if self.connectors is not None:
            connector_file = os.path.join('./', name, 'connector.json')
            self.connectors.dumpJson(connector_file)
        if self.binders is not None:
            binder_file = os.path.join('./', name, 'binder.json')
            self.binders.dumpJson(binder_file)

    def showCycle(self):
        pid, cpu = self.context_manager[self.target].getDebugPid() 
        cycles = self.bookmarks.getCurrentCycle(cpu)
        print ('cpu cycles since _start: 0x%x absolute cycle: 0x%x' % (cycles, cpu.cycles))
        
    def continueForward(self):
        self.lgr.debug('continueForward')
        self.is_monitor_running.setRunning(True)
        SIM_run_command('c')

    def showNets(self):
        net_commands = self.netInfo[self.target].getCommands()
        if len(net_commands) > 0:
           print('Network definition commands:')
        for c in net_commands:
            print(c)

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
        self.traceMgr[self.target].flush()

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
        self.mode_hap = SIM_hap_add_callback_obj("Core_Mode_Change", cpu, 0, self.modeChangeReport, pid)
        self.stop_hap = SIM_hap_add_callback("Core_Simulation_Stopped", self.stopModeChanged, None)

    def setTarget(self, target):
        if target not in self.cell_config.cell_context:
            print('Unknown target: %s' % target)
            return
        self.target = target  
        print('Target is now: %s' % target)
        self.lgr.debug('Target is now: %s' % target)

    def reverseEnabled(self):
        # TBD fix this after WR replies to question
        #return True
        #return VT_revexec_active()
        
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
        try:
            SIM_run_command('c')
            pass
        except SimExc_General as e:
            print('ERROR... try continue?')
            self.lgr.error('ERROR in retrack  try continue? %s' % str(e))
            if 'already running' in str(e):
                self.lgr.debug('thinks it is already running?')
            else:
                SIM_run_command('c')

    def trackIO(self, fd, reset=False, callback=None, run_fun=None, max_marks=None):
        if self.bookmarks is None:
            self.lgr.error('trackIO called but no debugging session exists.')
            return
        self.stopTrackIO()
        self.clearWatches()
        if callback is None:
            done_callback = self.stopTrackIO
        else:
            done_callback = callback
        self.lgr.debug('trackIO stopped track and cleared watchs')
        self.dataWatch[self.target].trackIO(fd, done_callback, self.is_compat32, max_marks)
        self.lgr.debug('trackIO back from dataWatch, now run to IO')

        if self.coverage is not None:
            self.coverage.doCoverage()
        self.runToIO(fd, linger=True, break_simulation=False, reset=reset, run_fun=run_fun)

    def stopTrackIO(self):
        self.lgr.debug('stopTrackIO')
        self.stopTrace()
        self.stopDataWatch()
        self.dataWatch[self.target].rmBackStop()
        self.dataWatch[self.target].setRetrack(False)
        if self.coverage is not None:
            self.coverage.saveCoverage()

    def clearWatches(self):
        self.dataWatch[self.target].clearWatches()

    def showWatchMarks(self):
        self.dataWatch[self.target].showWatchMarks()

    def saveWatchMarks(self, fpath):
        self.dataWatch[self.target].saveWatchMarks(fpath)

    def getWatchMarks(self):
        self.lgr.debug('getWatchMarks')
        watch_marks = self.dataWatch[self.target].getWatchMarks()
        try:
            jmarks = json.dumps(watch_marks)
            print(jmarks)
        except Exception as e:
            self.lgr.debug('getWatchMarks, json dumps failed on %s' % str(watch_marks))
            self.lgr.debug('error %s' % str(e))
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

    def goToDataMark(self, index):
        self.lgr.debug('goToDataMark(%d)' % index)
        self.stopTrackIO()
        cycle = self.dataWatch[self.target].goToMark(index)
        if cycle is not None:
            self.context_manager[self.target].watchTasks(set_debug_pid=True)
        return cycle

    def goToWriteMark(self, index):
        cycle = self.trackFunction[self.target].goToMark(index)
        if cycle is not None:
            self.context_manager[self.target].watchTasks(set_debug_pid=True)
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
        
    def mftx(self):
        SIM_run_command('disconnect $highlander_eth0 $highlander_switch0') 

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
                max_len = so_pickle['size']
                self.lgr.debug('traceInject pickle addr 0x%x len %d' % (addr, max_len))
        cpu = self.cell_config.cpuFromCell(self.target)
        ''' Add memUtil function to put byte array into memory '''
        byte_string = None
        with open(dfile) as fh:
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
        SIM_run_command('c')
       

    def injectIO(self, dfile, stay=False, keep_size=False, callback=None, n=1, cpu=None, 
            sor=False, cover=False, packet_size=None, target=None, targetFD=None, trace_all=False, 
            save_json=None, limit_one=False, no_rop=False, go=True, max_marks=None):
        ''' Use go=False and then go yourself if you are getting the instance for your own use, otherwise
            the instance is not defined until it is done.'''
        if type(save_json) is bool:
            save_json = '/tmp/track.json'
        if self.bookmarks is not None:
            self.goToOrigin()
        this_cpu, comm, pid = self.task_utils[self.target].curProc() 
        if cpu is None:
            cpu = this_cpu
        self.lgr.debug('genMonitor injectIO pid %d' % pid)
        cell_name = self.getTopComponentName(cpu)
        if max_marks is not None:
            self.dataWatch[self.target].setMaxMarks(max_marks) 
        self.injectIOInstance = injectIO.InjectIO(self, cpu, cell_name, pid, self.back_stop[self.target], dfile, self.dataWatch[self.target], self.bookmarks, 
                  self.mem_utils[self.target], self.context_manager[self.target], self.lgr, 
                  self.run_from_snap, stay=stay, keep_size=keep_size, callback=callback, packet_count=n, stop_on_read=sor, coverage=cover,
                  packet_size=packet_size, target=target, targetFD=targetFD, trace_all=trace_all, save_json=save_json, limit_one=limit_one,  
                  no_rop=no_rop)
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
            SIM_run_command('c')

    def runToOther(self, go=True):
        ''' Continue execution until a different library is entered, or main text is returned to '''
        cpu = self.cell_config.cpuFromCell(self.target)
        eip = self.mem_utils[self.target].getRegValue(cpu, 'eip')
        self.soMap[self.target].runToKnown(eip)
        if go:
            SIM_run_command('c')

    def modFunction(self, fun, offset, word):
        ''' write a given word at the offset of a start of a function.  Intended to force a return
            of a specific value.  Assumes you provide proper machine code. '''
        addr, end = self.ida_funs.getAddr(fun)
        cpu = self.cell_config.cpuFromCell(self.target)
        if addr is not None:
            new_addr = addr+offset
            self.mem_utils[self.target].writeWord32(cpu, new_addr, word)
            self.lgr.debug('modFunction wrote 0x%x to 0x%x' % (word, new_addr))
            self.lgr.debug('modFunction, disable reverse execution to clear bookmarks, then set origin')
            self.clearBookmarks()
        else:
            self.lgr.error('modFunction, no address found for %s' % (fun))

    def trackFunctionWrite(self, fun):
        ''' When the given function is entered, begin tracking memory addresses that are written to.
            Stop on exit of the function. '''
        self.lgr.debug('genMonitor trackFunctionWrite %s' % fun)
        pid, cpu = self.context_manager[self.target].getDebugPid() 

        read_watch_marks = self.dataWatch[self.target].getWatchMarks()
        self.trackFunction[self.target].trackFunction(pid, fun, self.ida_funs, read_watch_marks)

    def saveMemory(self, addr, size, fname):
        cpu = self.cell_config.cpuFromCell(self.target)
        byte_array = self.mem_utils[self.target].readBytes(cpu, addr, size)
        with open(fname, 'wb') as fh:
            fh.write(byte_array)

    def pageInfo(self, addr):
        cpu = self.cell_config.cpuFromCell(self.target)
        ptable_info = pageUtils.findPageTable(cpu, addr, self.lgr)
        print(ptable_info.valueString())
        cpu = self.cell_config.cpuFromCell(self.target)
        pei = pageUtils.PageEntryInfo(ptable_info.entry, cpu.architecture)
        print('writable? %r' % pei.writable)

    def toPid(self, pid):
        self.lgr.debug('genMonitor toPid')
        self.context_manager[self.target].catchPid(pid, self.toUser)
        SIM_run_command('c')

    def cleanMode(self):
        if self.mode_hap is not None:
            print('mode_hap was lingering, delete it')
            SIM_hap_delete_callback_id("Core_Mode_Change", self.mode_hap)
            self.mode_hap = None

    def watchROP(self, watching=True):
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
        self.stop_hap = SIM_hap_add_callback("Core_Simulation_Stopped", 
          self.stopHap, stop_action)

        self.context_manager[self.target].watchTasks()
        self.lgr.debug('runToStack hap set, now run. flist in stophap is %s' % stop_action.listFuns())
        SIM_run_alone(SIM_run_command, 'continue')
    
    def rmBackStop(self):
        self.lgr.debug('rmBackStop')
        self.dataWatch[self.target].rmBackStop()    

    def saveHits(self, fname):
        self.lgr.debug('saveHits %s' % fname)
        self.coverage.saveHits(fname)

    def difCoverage(self, fname):
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
                self.removeDebugBreaks()
                SIM_run_command('pselect %s' % cpu.name)
                previous = prev_cycle-1
                cmd='skip-to cycle=0x%x' % previous
                self.lgr.debug('precall cmd: %s' % cmd)
                SIM_run_command(cmd)
                self.restoreDebugBreaks(was_watching=True)
                self.lgr.debug('precall skipped to 0x%x' % cpu.cycles)
                if cpu.cycles != previous:
                    self.lgr.error('Cycle not as expected, wanted 0x%x got 0x%x' % (previous, cpu.cycles))

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
        self.trace_malloc = traceMalloc.TraceMalloc(self.ida_funs, self.context_manager[self.target], 
               self.mem_utils[self.target], self.task_utils[self.target], cpu, cell, self.dataWatch[self.target], self.lgr)

    def showMalloc(self):
        self.trace_malloc.showList()

    def stopTraceMalloc(self):
        if self.trace_malloc is not None:
            self.trace_malloc.stopTrace()
        self.trace_malloc = None

    def trackFile(self, substring):
        self.stopTrackIO()
        self.clearWatches()
        self.lgr.debug('trackFile stopped track and cleared watchs')
        self.dataWatch[self.target].trackFile(self.stopTrackIO, self.is_compat32)
        self.lgr.debug('trackIO back from dataWatch, now run to IO')
        if self.coverage is not None:
            self.coverage.doCoverage()
        self.runToOpen(substring)    

    def fuzz(self, path, n=1, fname=None):
        cpu, comm, pid = self.task_utils[self.target].curProc() 
        cell_name = self.getTopComponentName(cpu)
        self.debugPidGroup(pid)
        full_path = None
        if fname is not None:
            full_path = self.targetFS[self.target].getFull(fname, lgr=self.lgr)
            if full_path is None:
                self.lgr.error('unable to get full path from %s' % fname)
                return
        fuzz_it = fuzz.Fuzz(self, cpu, cell_name, path, self.coverage, self.back_stop[self.target], self.mem_utils[self.target], self.run_from_snap, self.lgr, n, full_path)
        fuzz_it.trim()

    def aflTCP(self, sor=False, fname=None, linear=False, port=8765):
        ''' not hack of n = -1 to indicate tcp '''
        self.afl(n=-1, sor=sor, fname=fname, port=port)

    def afl(self,n=1, sor=False, fname=None, linear=False, target=None, dead=None, port=8765, one_done=False):
        ''' sor is stop on read; target names process other than consumer; if dead is True,it 
            generates list of breakpoints to later ignore because they are hit by some other thread over and over. Stored in checkpoint.dead'''
        cpu, comm, pid = self.task_utils[self.target].curProc() 
        cell_name = self.getTopComponentName(cpu)
        ''' prevent use of reverseToCall.  TBD disable other modules as well?'''
        self.disable_reverse = True
        if target is None:
            # keep gdb 9123 port free
            self.gdb_port = 9124
            self.debugPidGroup(pid)
        full_path = None
        if fname is not None and target is None:
            full_path = self.targetFS[self.target].getFull(fname, lgr=self.lgr)
            if full_path is None:
                self.lgr.error('unable to get full path from %s' % fname)
                return
        else: 
            full_path=fname
        fuzz_it = afl.AFL(self, cpu, cell_name, self.coverage, self.back_stop[self.target], self.mem_utils[self.target], self.dataWatch[self.target], 
            self.run_from_snap, self.context_manager[self.target], self.lgr, packet_count=n, stop_on_read=sor, fname=full_path, 
            linear=linear, target=target, create_dead_zone=dead, port=port, one_done=one_done)
        if target is None:
            self.noWatchSysEnter()
            fuzz_it.goN(0)

    def aflFD(self, fd, snap_name, count=1):
        self.prepInject(fd, snap_name, count=count)

    def prepInject(self, fd, snap_name, count=1):
        ''' 
            Prepare a system checkpoint for fuzzing or injection by running until IO on some FD.
            fd -- will runToIOish on that FD
            snap_name -- will writeConfig to that snapshot.  Use that snapshot for fuzz and afl commands. '''
        if self.reverseEnabled():
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
            print('Reverse execution must be enabled to run aflFD')

    def prepInjectWatch(self, watch_mark, snap_name):
        if self.reverseEnabled():
            cpu = self.cell_config.cpuFromCell(self.target)
            cell_name = self.getTopComponentName(cpu)
            prep_inject = prepInjectWatch.PrepInjectWatch(self, cpu, cell_name, self.mem_utils[self.target], self.dataWatch[self.target], self.lgr) 
            prep_inject.doInject(snap_name, watch_mark)

    def hasBookmarks(self):
        return self.bookmarks is not None

    def playAFLTCP(self, target, sor=False, linear=False, dead=False, afl_mode=False):
        self.playAFL(target,  n=-1, sor=sor, linear=linear, dead=dead, afl_mode=afl_mode)

    def playAFL(self, target, n=1, sor=False, linear=False, dead=False, afl_mode=False, no_cover=False):
        ''' replay all AFL discovered paths for purposes of updating BNT in code coverage '''
        cpu, comm, pid = self.task_utils[self.target].curProc() 
        cell_name = self.getTopComponentName(cpu)
        self.debugPidGroup(pid)
        bb_coverage = self.coverage
        if no_cover:
            bb_coverage = None
        play = playAFL.PlayAFL(self, cpu, cell_name, self.back_stop[self.target], bb_coverage, 
              self.mem_utils[self.target], self.dataWatch[self.target], target, self.run_from_snap, self.context_manager[self.target], 
              self.cfg_file, self.lgr, 
              packet_count=n, stop_on_read=sor, linear=linear, create_dead_zone=dead, afl_mode=afl_mode)
        if play is not None:
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
            self.debugPidGroup(pid)
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

    def crashReport(self, fname, n=1, one_done=False, report_index=None, target=None, targetFD=None, trackFD=None):
        ''' generate crash reports for all crashes in a given AFL target diretory -- or a given specific file '''
        self.lgr.debug('crashReport %s' % fname)
        cpu, comm, pid = self.task_utils[self.target].curProc() 
        rc = reportCrash.ReportCrash(self, cpu, pid, self.dataWatch[self.target], self.mem_utils[self.target], fname, n, one_done, report_index, self.lgr, 
              target=target, targetFD=targetFD, trackFD=trackFD)
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
        self.command_callback = callback 


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
        sys.stderr.write('user rquested quit')
        SIM_run_command('q')
   
    def quit(self, cycles=None):
        SIM_run_alone(self.quitAlone, cycles)

    def getMatchingExitInfo(self):
        return self.sharedSyscall[self.target].getMatchingExitInfo()

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
    
    def getFullPath(self):
        return self.full_path

    def frameFromRegs(self, cpu):
        reg_frame = self.task_utils[self.target].frameFromRegs(cpu)
        return reg_frame

    def getPidsForComm(self, comm):
        plist = self.task_utils[self.target].getPidsForComm(comm)
        return plist

    def resetBookmarks(self):
        self.bookmarks = None

    def instructTrace(self, fname, all_proc=False, kernel=False):
        self.instruct_trace = instructTrace.InstructTrace(self, self.lgr, fname, all_proc=all_proc, kernel=kernel)
        pid = self.getPID()
        cpu = self.cell_config.cpuFromCell(self.target)
        cpl = memUtils.getCPL(cpu)
        if cpl != 0:
            self.instruct_trace.start() 

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
        if self.debug_info is not None and 'pid' in self.debug_info:
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
            print('pid %d  syscall %s' % (pid, call))

    def watchTasks(self):
        ''' watch this task and its threads, will append to others if already watching 
        NOTE assumes it is in execve and we want to track SO files
        '''
        self.context_manager[self.target].watchTasks(set_debug_pid=True)
        ''' flist of other than None causes watch of open/mmap for SO tracking '''
        self.execToText(flist=[])

    def ni(self):
        eip = self.getEIP()
        cpu = self.cell_config.cpuFromCell(self.target)
        instruct = SIM_disassemble_address(cpu, eip, 1, 0)
        next_ip = eip + instruct[0]
        cell = cpu.current_context
        bp = SIM_breakpoint(cell, Sim_Break_Linear, Sim_Access_Execute, next_ip, self.mem_utils[self.target].WORD_SIZE, 0)
        self.lgr.debug('ni eip 0x%x break set on 0x%x cell %s' % (eip, next_ip, cell))
        hap_clean = hapCleaner.HapCleaner(cpu)
        stop_action = hapCleaner.StopAction(hap_clean, [bp])
        self.stop_hap = SIM_hap_add_callback("Core_Simulation_Stopped", 
        	     self.stopHap, stop_action)
        SIM_run_command('c')

    def foolSelect(self, fd):
        self.sharedSyscall[self.target].foolSelect(fd)
    

if __name__=="__main__":        
    print('instantiate the GenMonitor') 
    cgc = GenMonitor()
    cgc.doInit()
