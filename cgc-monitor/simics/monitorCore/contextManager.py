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

import simics
from simics import *
import mod_software_tracker_commands as tr
import sys
import os
import subprocess
import backStop
sys.path.append("/home/mike/simics-4.6/simics-4.6.84/linux64/lib/") 
sys.path.append("/home/mike/simics-4.6/simics-4.6.84/linux64/lib/software-tracker")
from monitorLibs import throwMgr
'''
Manage simics contexts for remote debugging.  These functions are intended for
use as part of analysis, i.e., they play no role for basic monitoring.
'''

class contextManager():
    debugging = False
    ida_message = None
    context_list = {}
    comm_being_debugged = None
    def __init__(self, top, cell_config, hap_manager, master_config, os_p_utils, param, zk, target_log, lgr):
        for cell_name in cell_config.cells:
            self.context_list[cell_name] = {}
        self.current_debug_remote = None
        self.ida_message = "nothing "
        self.lgr = lgr
        self.cell_config = cell_config
        self.param = param
        self.debugging_pid = None
        self.debugging_comm = None
        self.debugging_cell = None
        self.debugging_cpu = None
        self.top = top
        self.hap_manager = hap_manager
        self.master_config = master_config
        self.stop_hap = None
        self.os_p_utils = os_p_utils
        self.zk = zk
        self.proc_info = None
        self.backstop = backStop.backStop(10, lgr)
        self.init_context = None
        self.exit_break_num = None
        self.throw_mgr = throwMgr.throwMgr(zk, lgr)
        self.debugging = False
        self.target_log = target_log
        ''' used for auto analysis file naming ''' 
        self.throw_id = None
        self.latest_package = None
        #SIM_run_command('set-context context = viper.cell_context')

    class context():
        context = None
        pid = []
        comm = None
        def __init__(self, con, cell_name, pid, comm):
            self.context = con
            self.comm = comm
            self.cell_name = cell_name
            self.pid = pid

    def setIdaMessage(self, message):
        self.ida_message = message

    def showIdaMessage(self):
        print 'cgcMonitor says: %s' % self.ida_message
        self.lgr.debug('cgcMonitor says: %s' % self.ida_message)

    def getIdaMessage(self):
        return self.ida_message

    def setDebugging(self, value):
        self.debugging = value;

    def getDebugging(self):
        return self.debugging

    def add(self, con, cell_name, pid, comm):
        self.context_list[cell_name][pid] = self.context(con, pid, cell_name, comm)

    def get(self, cell_name, pid):
        retval = None
        if pid in self.context_list[cell_name]:
            retval =  self.context_list[cell_name][pid].context
        return retval

    def has(self, cell_name, comm, pid):
        if pid in self.context_list[cell_name]:
            return True
        else:
            return False
 
            
    def printList(self):
        print 'in list'
        for cell_name in self.context_list:
            for pid in self.context_list[cell_name]:
                print  'context: %s  comm: %s  cell: %s pid: %d' % (self.context_list[cell_name][pid].context, 
                    self.context_list[cell_name][pid].comm, cell_name, pid)

    def detach(self):
        if self.current_debug_remote is not None:
            self.lgr.debug('in contextManager detach, disconnect existing remote')
            cmd = 'gdb%d.disconnect' % self.current_debug_remote
            SIM_run_command(cmd)
        else:
            print 'in contextManager detach, no current debug remote'

    def getDebugProcInfo(self):
        '''
        Returned pids are a set.  If PoV, then just that pid, if CB, then all pids of the CB,
        not just the one being debugged.
        '''
        return self.proc_info

    #def gdbSendPacket(self, packet):
    #    self.current_debug_remote.send_packet(packet)
 
    def setupSimicsDebug(self, cell_name, cpu, pid, comm, manual):
        if pid in self.context_list[cell_name]:
            reg_num = cpu.iface.int_register.get_number("eip")
            eip = cpu.iface.int_register.read(reg_num)
            self.lgr.debug('setupSimicsDebug in context_manager debug for cpu %s process: %d (%s) eip: %x' % (cpu.name, pid, comm, eip))
            self.comm_being_debugged = comm
            if self.current_debug_remote is not None:
                self.lgr.debug('in context_manager Disconnect existing remote, then debug for cpu %s' % cpu.name)
                cmd = 'gdb%d.disconnect' % self.current_debug_remote
                SIM_run_command(cmd)
                cmd = 'gdb%d.follow-context %s' % (self.current_debug_remote, 
                    self.context_list[cell_name][pid].context)
                SIM_run_command(cmd)
            else:
                #cmd = 'new-gdb-remote context = %s cpu = %s' % (self.context_list[pid].context,
                #      cpu.name)
                port = 9123 + int(self.top.getInstance())
                self.lgr.debug('in context_manager debug for cpu %s port will be %d' % (cpu.name, port))
                cmd = 'new-gdb-remote cpu=%s architecture=x86 port=%d' % (cpu.name, port)
                SIM_run_command(cmd)
                # !!!!! setting current_debug_remote breaks ability to detach from debugger, fix that before setting for experiments
                #self.current_debug_remote = SIM_run_command(cmd)
                #if self.current_debug_remote is None:
                #    self.lgr.debug('setupSimicsDebug, current_debug_remote is none, set it with a guess')
                #    #self.current_debug_remote = SIM_get_object('gdb0')
                #    self.current_debug_remote = 0
                #  TBD set to numeric so other functions, e.g., detach work?

                    
                self.lgr.debug('in context_manager ran %s' % cmd)
                self.lgr.debug('SET CONTEXT removed ******************')
                #cmd = 'set-context %s' % self.context_list[cell_name][pid].context
                #SIM_run_command(cmd)
                #self.lgr.debug('in context_manager after set context ran %s' % cmd)
            if not self.top.NO_TRACK:
                cmd = '%s.symtable symtable = %s' % (self.context_list[cell_name][pid].context, comm)
                print 'cmd is %s' % cmd
                SIM_run_command(cmd)
            #if manual:
            #    cmd = '%s.run-until-activated' % (self.context_list[cell_name][pid].context)
            #    SIM_run_alone(SIM_run_command, cmd)
        else:
            print 'context for pid %d not found' % pid

    def debugPoV(self, cell_name, pid, cpu, manual):


        ''' 
        setup the simics gdb server for a PoV 
        '''
        thrower_cell = cell_name
        thrower_pid = pid
        cb_cell = None
        cb_pid = None
        if len(self.cell_config.cells) > 1:
            for cn in self.cell_config.cells:
                if cn != cell_name:
                    cb_cell = cn
            if cb_cell is None or thrower_cell is None:
                print 'debugPoV trouble finding cb_cell or thrower cell.  cell_name is %s cell_config.cells follow:' % cell_name
                for cn in self.cell_config.cells:
                    print 'cn is %s' % cn
                return 
            if len(self.context_list[cb_cell]) > 1:
                print 'debugPoV not ready for multiple CBs on network host'
                return
            if len(self.context_list[thrower_cell]) > 1:
                print 'debugPoV not ready for multiple replayers on thrower'
                return
            for tpid in self.context_list[cb_cell]:
                cb_pid = tpid
            print 'debugPoV thrower_cell is %s  cell_name is %s' % (thrower_cell, cell_name) 
        else:
            cb_cell = cell_name
            cb_cpu = self.cell_config.cpuFromCell(cb_cell)
            for cpid in self.context_list[cb_cell]:
                comm = self.os_p_utils[cell_name].getCommByPid(cpid)
                if self.top.isCB(comm):
                    cb_pid = tpid
        cb_name = None
        
        if cb_pid is not None and cb_pid in self.context_list[cb_cell]: 
            cb_name = self.context_list[cb_cell][cb_pid].comm
        thrower_name =  self.context_list[thrower_cell][pid].comm
        thrower_cpu = self.cell_config.cpuFromCell(thrower_cell)
        parent_pid, dum = self.os_p_utils[thrower_cell].getParent(thrower_pid, cpu)
        thrower_file = self.top.getReplayFileName(pid, cell_name)
        print 'player pid is %d  its parent is %d thrower file : %s' % (thrower_pid, parent_pid, thrower_file)
        self.lgr.debug('thrower_file is %s'% thrower_file)
        thrower_file = os.path.basename(thrower_file).split('.')[0]
        self.lgr.debug('debugPov CB is: %s;  Thrower: %s  File: %s' % (cb_name, thrower_name, thrower_file))
 
        self.setupSimicsDebug(cell_name, cpu, pid, comm, manual)
        #self.zk.addThrow(cb_name, thrower_file, self.zk.getTargetName(), self.ida_message, 'POV')

    ''' start analyis for a challenge binary  (or pov in multibox)
        The pid is the process to be debugged.
        manual will prevent a backstop from being placed, e.g., if we go straight to the debugger
        Returns True if client dbgQueue request found and client is alive.
        TBD: easy way to force debug even if no client?  
    '''
    def debugCB(self, cell_name, pid, cpu, manual):
        if cell_name not in self.context_list or pid not in self.context_list[cell_name]:
            print 'in debugCB, cannot debug %s:%d, no context' % (cell_name, pid)
            return False
        cb_cell = cell_name
        thrower_pid = None
        thrower_cell = None
        thrower_file = None
        thrower_name = None
        if len(self.cell_config.cells) > 1:
            ''' more than one computer, assume remote replay '''
            self.lgr.debug('Multiple computers, assume remote replay')
            cb_cell = 'server'
            thrower_cell = 'thrower'
            if len(self.context_list[thrower_cell]) > 1:
                print 'not ready for multiple replayers on thrower'
                return False
            ''' assumes only one thrower '''
            seed = self.target_log.findSeed(pid, cell_name)
            thrower_file = self.top.getReplayFileNameFromSeed(seed)
            if cell_name == cb_cell:
                cb_name = self.context_list[cb_cell][pid].comm
            else:
                cb_name = self.top.getCBFileNameFromSeed(seed)
            if cb_name is None:
                if self.latest_package is None:
                    package = self.zk.getLatestLocalPackage(self.lgr)
                else:
                    package = self.latest_package
                if package is None:
                    self.lgr.debug('debugCB, no package and no cb file, bail')
                    return
                cb_element = package.find('cb_name')
                if cb_element is not None:
                    cb_name = cb_element.text
        else:
            ''' local replay, all processes on same cell.  '''
            thrower_cell = cell_name
            thrower_cpu = self.cell_config.cpuFromCell(thrower_cell)
            cb_name = self.context_list[cb_cell][pid].comm
            for tpid in self.context_list[thrower_cell]:
                comm = self.os_p_utils[thrower_cell].getCommByPid(tpid)
                if comm == self.master_config.player_name:
                    thrower_pid = tpid

            if thrower_pid is not None and thrower_pid in self.context_list[thrower_cell]:
                thrower_name =  self.context_list[thrower_cell][thrower_pid].comm
            thrower_file = self.top.getReplayFileName(pid, cell_name)
        if thrower_file is None:
            if self.latest_package is None:
                package = self.zk.getLatestLocalPackage(self.lgr)
            else:
                package = self.latest_package
            if package is None:
                self.lgr.debug('debugCB, no package and no thrower file, bail')
                return
            pov = package.find('pov')
            if pov is not None:
                thrower_file = pov.text
        else:
            print('before split CB is: %s;  Thrower: %s  File: %s' % (cb_name, thrower_name, thrower_file))
            self.lgr.debug('before split CB is: %s;  Thrower: %s  File: %s' % (cb_name, thrower_name, thrower_file))
        if thrower_file is not None:
            thrower_file = os.path.basename(thrower_file).split('.')[0]
            print('CB is: %s;  Thrower: %s  File: %s' % (cb_name, thrower_name, thrower_file))
            self.lgr.debug('debugCB CB is: %s;  Thrower: %s  File: %s' % (cb_name, thrower_name, 
                 thrower_file))
 
            #self.setupSimicsDebug(cell_name, cpu, pid, comm, manual)
            bin_type = 'CB'
            # hack, fix this hardcode
            if cell_name == 'thrower':
                bin_type = 'POV'
                self.setupSimicsDebug(cell_name, cpu, pid, thrower_file, manual)
            else:
                self.setupSimicsDebug(cell_name, cpu, pid, cb_name, manual)
            return self.throw_mgr.addThrow(cb_name, thrower_file, self.zk.getTargetName(), self.ida_message, bin_type,
                  watcher=self.myWatcher)
        else:
            self.lgr.error('debugCB, but no thrower file')
            return False


    class myProcInfo():
        pid = []
        def __init__(self, cpu, pid):
            self.cpu = cpu
            self.pid.append(pid)

    def getDebugPid(self):
        return self.debugging_pid, self.debugging_cell, self.debugging_cpu

    def getDebugComm(self):
        return self.debugging_comm

    '''
    NOT currently used
    '''
    def resetBackStop(self):
        self.backstop.resetCycle()

    '''
        Setup debugging/analysis of a PoV or a CB.
    '''
    def debug(self, cell_name, pid, comm, cpu, manual, backstop_cycles=None, auto_analysis=False):
        # save off the current context for restore when debug is done
        self.init_context = cpu.iface.context_handler.get_current_context() 
        # get monitor ready for debug session
        self.top.readyDebug(cell_name, cpu, pid, comm, manual)
        if not manual:
            if backstop_cycles is None:
                now = SIM_cycle_count(cpu)
                self.lgr.debug('contextManager debug set event_post_cycle at ten more than %x (%d)' % (now, now))
                self.backstop.setCycle(cpu, now)
            else:
                self.backstop.setCycle(cpu, backstop_cycles)
        self.proc_info = self.myProcInfo(cpu, pid)
        self.debugging_pid = pid
        self.debugging_comm = comm
        self.debugging_cell = cell_name
        self.debugging_cpu = cpu
        self.printList()
        self.lgr.debug('contextManager debug, for %s:%d (%s) player_name is %s replay file: %s' % (cell_name, pid, comm, 
            self.master_config.player_name, self.top.getReplayFileName(pid, cell_name)))
        if comm != self.master_config.player_name:
            '''
            Is a CB.  Get all CB pids so we know when they've died after debugging
            '''
            for m_pid in self.context_list[cell_name]:
                if self.top.isCB(self.context_list[cell_name][m_pid].comm):
                    if m_pid not in self.proc_info.pid:
                        self.proc_info.pid.append(m_pid)
            if not auto_analysis:
                if not self.debugCB(cell_name, pid, cpu, manual):
                    self.lgr.debug('contextManager debug, no debug client found, do not debug')
                #self.idaDone()
                #return
            else:
                if self.latest_package is None:
                    package = self.zk.getLatestLocalPackage(self.lgr)
                else:
                    package = self.latest_package
                throw_id_element = package.find('throw_id')
                if throw_id_element is not None:
                    self.throw_id = throw_id_element.text
        else:
            self.debugPoV(cell_name, pid, cpu, manual)
       
        self.setExitBreak(cpu) 
        
    def setExitBreak(self, cpu):
        ''' watch for exit of this process, to reinit monitoring '''    
        if self.exit_break_num is None:
            cell_name = self.top.getTopComponentName(cpu)
            cur_thread_addr = self.os_p_utils[cell_name].getPhysAddrOfCurrentThread(cpu)
            p_cell = cpu.physical_memory
            self.exit_break_num = SIM_breakpoint(p_cell, Sim_Break_Physical, 
                Sim_Access_Write, cur_thread_addr, 4, 0)
              
            self.exit_cb_num = SIM_hap_add_callback_index("Core_Breakpoint_Memop", 
                                                   self.changedThread, self.proc_info, self.exit_break_num)
            self.lgr.debug('contextManager setExitBreak set breakpoint %d' % self.exit_break_num)

    def clearExitBreak(self):
        if self.exit_break_num is not None:
            SIM_delete_breakpoint(self.exit_break_num)
            SIM_hap_delete_callback_id("Core_Breakpoint_Memop", self.exit_cb_num)
            self.lgr.debug('contextManager clearExitBreak removed breakpoint %d' % self.exit_break_num)
            self.exit_break_num = None
            self.exit_cb_num = None

    '''
        Called when kernel hits sigexit as the debugged process exits and it
        is safe to reinitialize the monitoring systes.
        NOT CURRENTLY USED (could not use os_p_utils here?)
        NOTE proc_info.pid is now a list, so this is broken anyway
    '''
    def sigexitCallback(self, my_args, third, forth, memory):
        ''' see if we are trying to re-init after a debug session '''
        cell_name = self.top.getTopComponentName(my_args.cpu)
        cpu, cur_addr, comm, pid = self.os_p_utils[cell_name].getPinfo(my_args.cpu)
        if self.getDebugging():
           if self.proc_info.cpu == cpu and self.proc_info.pid == pid:
               self.lgr.debug('In sigexitCallback during debug')
               SIM_run_alone(self.installStopHap, None)
               SIM_break_simulation('sigexitCallback doing reinit after debug in sigexitCallback')
               ''' get rid of this break/hap '''
               self.hap_manager.removeKernelBreaks()
               self.cleanContext()
        else:
           self.lgr.critical('unexpected hit of sysexit callback')
           return

    def pidsAllGone(self, proc_info):
        cell_name = self.top.getTopComponentName(proc_info.cpu)
        dum1, dum2, comm, tpid = self.os_p_utils[cell_name].getPinfo(proc_info.cpu)
        for pid in proc_info.pid:
            if (self.debugging_pid is not None and pid == tpid) or self.os_p_utils[cell_name].hasPid(pid):
                return False
            else:
                self.top.cleanPidStructs(cell_name, pid)
                proc_info.pid.remove(pid)
        self.lgr.debug('contextManager pids all gone, tpid %d comm %s' % (tpid, comm))
        return True


    '''
        Intended to be called when a debugging session analysis has completed.  The
        goal is to let the process exit (if it is still running) prior to re-initializing
        the monitoring functions (which have been gutted so as to not interfer with 
        analysis.)
    '''
    def idaDone(self):
        '''
          processing should vary by event.  signal should use continuation.
          nox, etc., should set breakpoint on exit
        '''
        self.lgr.debug('contextManager idaDone called')
        self.debugging_pid = None
        self.debugging_cell = None
        self.debugging_cpu = None
        self.backstop.clearCycle()
        self.ida_message = None
        #SIM_run_command('set-context default')
        #SIM_run_command('set-context context = viper.cell_context')
        #self.init_context = self.proc_info.cpu.iface.context_handler.set_current_context(self.init_context) 
        self.debugging = False
        if self.master_config.auto_analysis:
            self.zk.deleteOurStatus()
            self.zk.setLatestLocalPackageDone(self.lgr)
        elif not self.pidsAllGone(self.proc_info):
            self.proc_info.cpu.iface.context_handler.set_current_context(self.init_context) 
            cycle = SIM_cycle_count(self.proc_info.cpu)
            self.lgr.debug('Process being debugged still running, current cycle is %x' % cycle)
            # skip to where the fault occured so it does not take too long to finish
            signal_cycle = self.top.getSignalCycle()
            if signal_cycle is None:
                self.lgr.debug('idaDone, signal_cycle is none')
                return
            SIM_run_command('skip-to cycle=%d' % signal_cycle)
            cycle = SIM_cycle_count(self.proc_info.cpu)
            self.lgr.debug('after skip, current cycle is %x' % cycle)
            SIM_run_command('continue')
        else:
            self.proc_info.cpu.iface.context_handler.set_current_context(self.init_context) 
            for pid in self.proc_info.pid:
                self.lgr.debug('Already exited the process (%d) we were debugging, do reinit' % pid)
            cell_name = self.top.getTopComponentName(self.proc_info.cpu)
            self.detach()
            #self.top.reInit()
            #t cause monitor to reinit
            #if not self.master_config.auto_analysis:
            self.zk.deleteOurReset()
            #SIM_run_command('continue')

    def installStopHap(self, dum):
        self.stop_hap = SIM_hap_add_callback("Core_Simulation_Stopped", 
		    self.stopCallback, None)
        self.lgr.debug('contextManager installStopHap, stop hap added')

    def deleteCallback(self, dum):
        SIM_hap_delete_callback_id("Core_Simulation_Stopped", self.stop_hap)
        self.lgr.debug('contextManager deleteCallback, stop hap deleted')

    def stopCallback(self, dum, one, two, three):
        SIM_run_alone(self.deleteCallback, None)
        self.lgr.debug('in stopCallback for reinit disable-reverse-execution')
        # TBD big assumption that we want to reset the context list before reinit
        for cell_name in self.cell_config.cells:
            self.context_list[cell_name] = {}
        SIM_run_alone(SIM_run_command, 'disable-reverse-execution')
        SIM_run_alone(SIM_run_command, 'enable-vmp')
        cell_name = self.top.getTopComponentName(self.proc_info.cpu)
        for pid in self.proc_info.pid:
            self.top.cleanPidStructs(cell_name, pid)
        #SIM_run_alone(self.top.reInit, None)
        self.detach()
        #self.top.reInit()
        # cause monitor to reinit
        if not self.master_config.auto_analysis:
             self.zk.deleteOurReset()
        SIM_run_alone(SIM_continue, 0)

    def changedThread(self, proc_info, third, forth, memory):
        if len(proc_info.pid) > 0:
            #self.lgr.debug('In changedThread during debug seeing if %d exited' % proc_info.pid[0])
            pass
        if self.pidsAllGone(proc_info):
            self.lgr.debug('In changedThread during debug, all pids are gone')
            SIM_run_alone(self.installStopHap, None)
            SIM_break_simulation('changedThread doing reinit after debug and pids gone')
            ''' get rid of this break/hap '''
            self.hap_manager.removeKernelBreaks()
            self.clearExitBreak()

    def cleanContext(self):
        self.lgr.debug('contextManager cleanContext')
        for cell_name in self.context_list:
            self.context_list[cell_name] = {}
        self.debugging = False

    def cleanPID(self, cell_name, pid):
        self.lgr.debug('contextManager cleanPID for %s %d' % (cell_name, pid))
        if pid in self.context_list[cell_name]:
            del (self.context_list[cell_name][pid])
        
    def signalClient(self):
        cmd = 'gdb%s.signal 99' % self.current_debug_remote
        self.lgr.debug('signalClient command is %s' % cmd)
        SIM_run_alone(SIM_run_command, cmd)

    def myWatcher(self, event):
        '''
        called if client debugger node goes away.
        NOTE: syntax errors in here are not logged or displayed!!!!  
        '''
        self.lgr.debug('contextManager, myWatcher, client must have died, path: %s' % event.path)
        stat = self.zk.zk.exists(event.path)
        if stat is None: 
            if self.debugging_pid is not None:
                # NOTE simics cannot  handle commands from threads other than the main.  
                # We are a watch thread, so use a hacked fifo that simics reads from
                self.lgr.debug('contextManger, myWatcher, send ida done to the pipe')
                f = open('./simics.stdin', 'w')
                f.write('@cgc.idaDone()\n')
                f.close()
            else:
                self.lgr.debug('contextManger, myWatcher, debugging pid is None, tell simics to continue via pipe')
                f = open('./simics.stdin', 'w')
                f.write('c\n')
                f.close()
                #SIM_continue(0)
        else:
            self.lgr.debug('contextManger, myWatcher, path exists? %s' % event.path)
             
    def getThrowId(self):
        return self.throw_id

    def setLatestPackage(self, package):
        self.latest_package = package
