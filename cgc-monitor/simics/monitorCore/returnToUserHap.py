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
import procInfo
class returnToUserHap():
    '''
    Catch the initial return to user space.
    Intended to be called during execve return processing.
    The os could migrate the process, so need to set haps on all CPUs
    '''
    def __init__(self, top, cpu, cpu_list, pid, comm, callback, os_p_utils, is_monitor_running, lgr):
        self.the_hap = []
        self.callback = callback
        self.lgr = lgr
        self.cpu_list = cpu_list
        self.pid = pid
        self.cpu = cpu
        self.comm = comm
        self.top = top
        self.os_p_utils = os_p_utils
        self.is_monitor_running = is_monitor_running
        self.cell_name = self.top.getTopComponentName(cpu)
        cpl = memUtils.getCPL(cpu)
        if cpl != 0:
            self.lgr.debug('returnToUser init, but already in user space')
            return
        if pid is not None:
            self.lgr.debug('returnToUserHap %s:%d ' % (self.cell_name, pid))
            is_monitor_running.setRunning(True)
            SIM_run_alone(self.installModeHap, None)
    

    def installModeHap(self, dum):
        for cpu in self.cpu_list:
            hap = SIM_hap_add_callback_obj("Core_Mode_Change", cpu, 0, self.modeChanged, cpu)
            self.the_hap.append(hap)

            self.lgr.debug('returnToUserHap installModeHap, %s %d mode hap added %d haps (one per cpu)' % (self.cell_name, self.pid, len(self.the_hap)))

    #def deleteCallback(self, dum):
    #    self.lgr.debug('stopHap deleteCallback')
    #    SIM_hap_delete_callback_id("Core_Simulation_Stopped", self.the_hap)

    def runAlone(self, pinfo):
        self.lgr.debug('returnToUserHap runAlone, %d (%s) ' % (pinfo.pid, pinfo.comm))
        try:
            for hap in self.the_hap:
                SIM_hap_delete_callback_id("Core_Mode_Change", hap)
        except:
            self.lgr.error('wtf is this hap here or freaking not?')
        self.the_hap = []
        self.is_monitor_running.setRunning(False)
        self.callback(pinfo)

    def modeChanged(self, cpu, one, old, new):
        self.lgr.debug('returnToUserHap mode changed')
        if len(self.the_hap) == 0 or self.pid is None:
            self.lgr.error('returnToUserHap modeChanged, %s stop hap is gone, but here we are!' % (self.cell_name))
            return
        if cpu != self.cpu:
            self.lgr.debug('cpu in modeChange hap not same as starting cpu: %s %s' % (cpu.name, self.cpu.name))
        cpl = memUtils.getCPL(cpu)
        if cpl == 0:
            self.lgr.error('modeChanged says new but cpl is zero')
            return
        dumcpu, cur_addr, comm, pid = self.os_p_utils.getPinfo(cpu)
        if pid == self.pid:
            reg_num = cpu.iface.int_register.get_number("rip")
            eip = cpu.iface.int_register.read(reg_num)
            current = SIM_cycle_count(cpu)
            self.lgr.debug('returnToUserHap modeChanged %s:%d (%s) eip  %x cycle: 0x%x' % (self.cell_name, 
                pid, comm, eip, current))
            pinfo = procInfo.procInfo(self.comm, cpu, self.pid, cur_addr=cur_addr)
            self.pid = None
            SIM_run_alone(self.runAlone, pinfo)
        else:
            self.lgr.debug('returnToUserHap, modeChanged, expected pid %d got %d' % (self.pid, pid))
            status = SIM_simics_is_running()
            if not status:
                self.lgr.debug('modeChanged, simics not running, continue it')
                SIM_run_command('continue')

