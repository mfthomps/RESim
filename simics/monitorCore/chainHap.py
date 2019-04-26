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
import memUtils
import mod_software_tracker_commands as tr
import sys
sys.path.append("/home/mike/simics-4.6/simics-4.6.84/linux64/lib/") 
sys.path.append("/home/mike/simics-4.6/simics-4.6.84/linux64/lib/software-tracker")
import logging
'''
   run a chain of commands the require simics to be stopped
'''
# TBD remove dbi use outside of init
class chainHap():
    stop_hap = None
    '''
    Run a command after the simulation has stopped
    '''
    def __init__(self, top, dbi, os_utils, param, final_call=None):
        print 'chainHap init'
        self.lgr = dbi.lgr
        self.lgr.debug('chainHap init') 
        SIM_run_alone(self.install_stop_hap, dbi)
        self.cmds = dbi.command
        self.os_utils = os_utils
        self.param = param
        self.top = top
        self.mode_changed_hap = None
        self.prev_command = None
        self.prev_cycles = SIM_cycle_count(dbi.cpu)
        self.final_call = final_call
        self.cpu = dbi.cpu
        self.pid = dbi.pid
        self.comm = dbi.comm
        self.cell_name = dbi.cell_name
        self.context_manager = dbi.context_manager
    def install_stop_hap(self, dbi):
        self.lgr.debug('chainHap install stop hap')
        self.stop_hap = SIM_hap_add_callback("Core_Simulation_Stopped", 
	    self.stop_callback, dbi)

    def stop_callback(self, dbi, one, two, three):
        print 'in chainHap stop_callback ' 
        self.lgr.debug('in chainHap stop_callback ')
        cycles = SIM_cycle_count(self.cpu)
        reg_num = self.cpu.iface.int_register.get_number("eip")
        eip = self.cpu.iface.int_register.read(reg_num)
        self.lgr.debug('chainHap in stop_callback, cycles is %x eip: %x' % (cycles, eip))
        if self.prev_cycles == cycles:
            self.lgr.error('chainHap got nowhere, rerun command?')
            #SIM_hap_delete_callback_id("UI_Run_State_Changed", self.stop_hap)
            #return
        self.prev_cycles = cycles
        cmd = self.cmds.pop(0)
        self.lgr.debug('chainHap stop_callback do cmd %s' % cmd)
        if cmd.startswith('skip-to'):
            self.lgr.debug('chainHap stop_callback found skip to %s' % cmd)
            SIM_run_command(cmd)
            cmd = self.cmds.pop(0)
            self.lgr.debug('chainHap stop_callback after skip-to command is %s' % cmd)
        if cmd == 'final-call':
            self.lgr.debug('chainHap final call')
            SIM_hap_delete_callback_id("Core_Simulation_Stopped", self.stop_hap)
            self.final_call()
        elif cmd == 'to-user-space':
            self.lgr.debug('chainHap to user space for pid %d' % self.pid)
            self.mode_changed_hap = SIM_hap_add_callback_obj("Core_Mode_Change", self.cpu, 0,
                    self.modeChangedToUserSpace, dbi)
            SIM_run_alone(SIM_run_command, 'continue')

        elif cmd != 'do-debug': 
            self.lgr.debug('chainHap not do-debug, is %s' % cmd)
            SIM_run_alone(SIM_run_command, cmd)
            if len(self.cmds) == 0:
                SIM_hap_delete_callback_id("Core_Simulation_Stopped", self.stop_hap)
                #SIM_hap_delete_callback_id("UI_Run_State_Changed", self.stop_hap)
        else:
            self.lgr.debug('chainHap do-debug eip is %x' % eip)
            self.top.setDebugBookmark('_start+1', self.cpu)
            SIM_run_alone(SIM_run_command, 'enable-reverse-execution')
            phys_block = self.cpu.iface.processor_info.logical_to_physical(eip, Sim_Access_Read)
            if phys_block.address == 0:
                # missing page, use mode hap to catch return.  Note mode hap will requeue the do-debug
                # command, so don't yet delete this stop hap
                self.lgr.debug('chainHap found missing page prior to do-debug')
                self.mode_changed_hap = SIM_hap_add_callback_obj("Core_Mode_Change", self.cpu, 0,
                    self.modeChangedPostFixup, dbi)
                SIM_run_alone(SIM_run_command, 'continue')
            else:
                if len(self.cmds) == 0:
                    SIM_hap_delete_callback_id("Core_Simulation_Stopped", self.stop_hap)
                    #SIM_hap_delete_callback_id("UI_Run_State_Changed", self.stop_hap)
                self.context_manager.debug(self.cell_name, self.pid, self.comm, self.cpu, True)

    def modeChangedToUserSpace(self, dbi, cpu, old, new):
        ''' TBD what if it dies before going to user space? '''
        cur_processor, cur_addr, comm, pid = self.os_utils.currentProcessInfo(self.cpu)
        self.lgr.debug('chainHap in modeChangedToUserSpace pid %d' % pid)
        if self.pid == pid:
            cpl = memUtils.getCPL(cpu)
            #if new != Sim_CPU_Mode_Supervisor:
            if cpl != 0:
                print('mode changed to user for pid %d' % self.pid)
                SIM_break_simulation('should be in user space')
                SIM_hap_delete_callback_id("Core_Mode_Change", self.mode_changed_hap)
                self.mode_changed_hap = None
      
    '''
        Intended to catch return to user space after a page fixup so the debugger can see code in memory
    ''' 
    def modeChangedPostFixup(self, dbi, cpu, old, new):
        cur_processor, cur_addr, comm, pid = self.os_utils.currentProcessInfo(cpu)
        self.lgr.debug('chainHap in modeChangedPostFixup pid %d' % pid)
        if self.pid == pid:
            cpl = memUtils.getCPL(cpu)
            if cpl != 0:
                reg_num = self.cpu.iface.int_register.get_number("eip")
                eip = self.cpu.iface.int_register.read(reg_num)
                phys_block = cpu.iface.processor_info.logical_to_physical(eip, Sim_Access_Read)
                if phys_block.address != 0:
                    # page is mapped, put do-debug back into chain of haps
                    self.lgr.debug('chainHap mode changed, page now mapped')
                    SIM_hap_delete_callback_id("Core_Mode_Change", self.mode_changed_hap)
                    self.cmds.append('do-debug')
                    SIM_break_simulation('chainHap page now mapped')
                else:
                    self.lgr.debug('chainHap mode changed, page STILL NOT MAPPED')
                    

