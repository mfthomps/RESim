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
import resimHaps
import memUtils
class DoInUser():
    def __init__(self, top, cpu, callback, param, task_utils, mem_utils, lgr):
        self.top = top
        self.cpu = cpu
        self.callback = callback
        self.param = param
        self.task_utils = task_utils
        self.mem_utils = mem_utils
        self.lgr = lgr
        dum_cpu, comm, self.tid = self.task_utils.curThread()
        self.mode_hap = SIM_hap_add_callback_obj("Core_Mode_Change", self.cpu, 0, self.modeChanged, self.cpu)
        self.lgr.debug('doInUser mode hap set for tid:%s' % self.tid)

    def modeChanged(self, cpu, one, old, new):
        if self.mode_hap is None:
            return
        dum_cpu, comm, tid = self.task_utils.curThread()
        cell_name = self.top.getTopComponentName(self.cpu)
        ip = self.top.getEIP()
        #cpl = SIM_processor_privilege_level(self.cpu)
        cpl = memUtils.getCPL(cpu)
        self.lgr.debug('doInUser mode_changed %s %s (%s) look for %s, cpl is %d eip: 0x%x' % (cell_name, tid, comm, self.tid, cpl, ip))
        if new == Sim_CPU_Mode_User:
            if tid == self.tid:
                sp = self.mem_utils.getRegValue(self.cpu, 'sp')
                value = self.mem_utils.readWord(self.cpu, sp)
                self.lgr.debug('doInUser modeChanged sp 0x%x value 0x%x' % (sp, value))
                self.lgr.debug('doInUser mode_changed in user mode, do callback')
                SIM_run_alone(self.callback, self.param) 
                hap = self.mode_hap
                SIM_run_alone(resimHaps.RES_delete_mode_hap, hap)
                self.mode_hap = None

