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
Run to user mode or kernel mode.
'''
from simics import *
import hapCleaner
import memUtils
from resimHaps import *
class RunToModeChange():
    def __init__(self, top, task_utils, mem_utils, context_manager, lgr):
        self.top = top
        self.task_utils = task_utils
        self.mem_utils = mem_utils
        self.context_manager = context_manager
        self.lgr = lgr
        # stored for suspending mode hap until tid scheduled as an optimization.  Otherwise can take a long time
        self.tid_list = None
        self.cpu = None
        self.flist = None
        self.wrong_tid_count = 0

    def run2Kernel(self, cpu, flist=None):
        cpl = memUtils.getCPL(cpu)
        if cpl != 0:
            dumb, comm, tid = self.task_utils.curThread() 
            self.lgr.debug('run2Kernel in user space (%d), set hap' % cpl)
            self.mode_hap = RES_hap_add_callback_obj("Core_Mode_Change", cpu, 0, self.modeChanged, [tid])
            hap_clean = hapCleaner.HapCleaner(cpu)
            hap_clean.add("Core_Mode_Change", self.mode_hap)
            stop_action = hapCleaner.StopAction(hap_clean, flist=flist)
            self.top.RES_add_stop_callback(self.top.stopHap, stop_action, your_stop=True)
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
        self.flist = flist
        if cpl == 0:
            if self.tid_list is None:
                tid = self.task_utils.curTID() 
                self.lgr.debug('run2User want_tid %s tid:%s' % (want_tid, tid))
                ''' use debug process if defined, otherwise default to current process '''
                if want_tid is not None:
                    want_tid = str(want_tid)
                    self.lgr.debug('run2User has want_tid of %s' % want_tid)
                    self.tid_list = [want_tid]
                else:
                    self.tid_list = self.context_manager.getThreadTids()
                    if len(self.tid_list) == 0:
                        self.tid_list.append(tid)
                        self.lgr.debug('run2User tidlist from context_manager empty, add self %s' % tid)
                    else:
                        self.lgr.debug('run2User tidlist from context_manager is %s' % self.tid_list)
           
                    
            self.mode_hap = RES_hap_add_callback_obj("Core_Mode_Change", cpu, 0, self.modeChanged, self.tid_list)
            self.lgr.debug('run2User tid %s in kernel space (%d), set mode hap %d' % (str(self.tid_list), cpl, self.mode_hap))
            hap_clean = hapCleaner.HapCleaner(cpu)
            # fails when deleted? 
            hap_clean.add("Core_Mode_Change", self.mode_hap)
            stop_action = hapCleaner.StopAction(hap_clean, flist=flist)
            self.stop_hap = self.top.RES_add_stop_callback(self.top.stopHap, stop_action, your_stop=True)
            self.lgr.debug('run2User added stop_hap of %d' % self.stop_hap)
            simics_status = SIM_simics_is_running()
            if not simics_status:
                self.lgr.debug('run2User continue')
                #SIM_run_alone(SIM_continue, 0)
                SIM_run_alone(self.top.continueForward, None)
               
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

    def modeChanged(self, tid_list, one, old, new):
        cpu = self.top.cell_config.cpuFromCell(self.top.getTarget())
        cpl = memUtils.getCPL(cpu)
        eip = self.mem_utils.getRegValue(cpu, 'pc')
        if new == Sim_CPU_Mode_Hypervisor or old == Sim_CPU_Mode_Hypervisor:
            return
        elif new == Sim_CPU_Mode_Supervisor: 
            mode = 0
        elif new == Sim_CPU_Mode_User:
            mode = 1
            #if cpu.architecture == 'arm64' and cpu.in_aarch64:
            #    self.lgr.debug('modeChanged arm64 in user space with aarch64, not yet handled, bail')
            #    return
        dumb, comm, this_tid = self.task_utils.curThread() 
        ''' note may both be None due to failure of getProc '''
        bail = False
        if this_tid not in tid_list:
            ''' or just want may be None if debugging some windows dead zone '''
            #if want_tid is None and this_tid is not None:
            #    SIM_break_simulation('mode changed, tid was None, now is not none.')
            if this_tid is not None:            
                self.lgr.debug('modeChanged mode changed to %d wrong tid, wanted %s got %s (%s)' % (mode, str(tid_list), this_tid, comm))
                alive = False
                for tid in tid_list:
                    rec = self.task_utils.getRecAddrForTid(tid)
                    if rec is not None:
                        alive = True
                        break
                if not alive:
                    self.lgr.debug('modeChanged no recs for tids %s, assume dead' % str(tid_list))
                    print('modeChanged no recs for tids %s, assume dead' % str(tid_list))
                    self.context_manager.setIdaMessage('Process gone')
                    SIM_break_simulation('mode changed, tid %s threads all gone' % str(tid_list))
                bail = True
                self.wrong_tid_count += 1
                if self.wrong_tid_count > 4:
                    self.cpu = cpu
                    self.cpu = cpu
                    SIM_run_alone(self.suspend, None)
                    self.context_manager.catchTid(tid_list[0], self.restart)
            else:
                self.lgr.error('mode changed wrong tid, wanted %s got NONE, will break here' % (str(tid_list)))
        if not bail:
            instruct = SIM_disassemble_address(cpu, eip, 0, 0)
            self.lgr.debug('modeChanged tid:%s cpl reports %d hap reports %d  trigger_obj is %s old: %d  new: %d  eip: 0x%x ins: %s' % (this_tid, cpl, 
                    mode, str(one), old, new, eip, instruct[1]))
            SIM_break_simulation('mode changed, break simulation')
       
    def suspend(self, dumb):
        if self.stop_hap is not None: 
            hap = self.stop_hap
            self.top.RES_delete_stop_hap(hap, your_stop=True)
            self.lgr.debug('runToModeChange suspend deleted stop hap')
        if self.mode_hap is not None:
            RES_hap_delete_callback_id("Core_Mode_Change", self.mode_hap)
            self.lgr.debug('runToModeChange suspend deleted mode hap')
            self.mode_hap = None

    def restart(self, dumb):
        self.lgr.debug('runToModeChange restar')
        self.run2User(cpu = self.cpu, flist=self.flist)

