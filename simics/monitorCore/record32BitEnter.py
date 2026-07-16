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
Update a param file to include sysenter_32 and sys_entry parameters for calls from 
32 bit apps on a 64 bit x86 kernel.  Support as a separate step so that getKernelParams
need not spin until some 32 bit app runs.
'''
import pickle
from simics import *
from resimHaps import *
class Record32BitEnter():
    def __init__(self, top, cpu, target, current_param, want, lgr, save=True):
        self.top = top
        self.cpu = cpu
        self.target = target
        self.lgr = lgr
        self.save = save
        self.want = want
        # as originally constituted this is what we want to overwrite with new enter values
        fname = '%s.param' % self.target
        self.param = pickle.load(open( fname, "rb" ))

        self.enter_delta = current_param.sysenter - self.param.sysenter 
        self.lgr.debug('record32BitEnter enter_delta (current_param.sysenter (0x%x) - original.sysenter (0x%x) is 0x%x' % (current_param.sysenter, self.param.sysenter, self.enter_delta))
        # set to none for testing 
        if current_param.sys_entry is not None and self.param.sys_entry is not None and want == 'int 128':
            self.param.sys_entry = None
            self.lgr.debug('record32BitEnter original sys_entry was 0x%x, current 0x%x' % (self.param.sys_entry, current_param.sys_entry))
        if current_param.sysenter_32 is not None and self.param.sysenter_32 is not None and want == 'sysenter':
            self.param.sysenter_32 = None
            self.lgr.debug('record32BitEnter original sysenter_32 was 0x%x, current 0x%x' % (self.param.sysenter_32, current_param.sysenter_32))
        cpu, comm, tid =  self.top.getCurrentProc()
        if comm.startswith('('):
            # weird in kernel comm
            comm = comm[1:-1]
        self.comm = comm
        #self.doSysenter()
        self.lgr.debug('record32BitEnter set mode hap, want %s set self.comm to %s' % (self.want, self.comm))
        self.mode_hap = RES_hap_add_callback_obj("Core_Mode_Change", self.cpu, 0, self.modeHap, self.want)
        SIM_continue(0)

    #def doSysenter(self):
    #    self.lgr.debug('record32BitEnter doSysenter')
    #    self.mode_hap = RES_hap_add_callback_obj("Core_Mode_Change", self.cpu, 0, self.modeHap, 'sysenter')
    #    SIM_continue(0)

    #def doEntry(self):
    #    self.lgr.debug('record32BitEnter doEntry')
    #    self.mode_hap = RES_hap_add_callback_obj("Core_Mode_Change", self.cpu, 0, self.modeHap, 'int 128')
    #    SIM_continue(0)

    def doSysexit(self):
        self.lgr.debug('record32BitEnter doSyexit')
        self.mode_hap = RES_hap_add_callback_obj("Core_Mode_Change", self.cpu, 0, self.modeHap, 'sysexit')
        SIM_continue(0)

    def rmHap(self, hap):
        RES_hap_delete_callback_id("Core_Mode_Change", hap)

    def rmMode(self):
        if self.mode_hap is not None:
            hap = self.mode_hap
            self.mode_hap = None
            SIM_run_alone(self.rmHap, hap)

    def modeHap(self, want, the_obj, old, new):
        if self.mode_hap is None:
            return
        eip = self.top.getReg('rip')
        instruct = SIM_disassemble_address(self.cpu, eip, 1, 0)
        cpu, comm, tid =  self.top.getCurrentProc()
        self.lgr.debug('record32BitEnter modeHap new %d eip 0x%x instruct %s tid:%s (%s) self.comm %s want %s' % (new, eip, instruct[1], tid, comm, self.comm, want))
        if new == Sim_CPU_Mode_Supervisor:
            if instruct[1].startswith(want): 
                # is the syscall we want
                self.lgr.debug('record32BitEnter modeHap entering kernel eip 0x%x instruct %s tid:%s (%s)' % (eip, instruct[1], tid, comm))
                self.rmMode()
                if want == 'sysenter':
                    SIM_run_alone(self.top.stopAndCall, self.recordEnter32)
                else:
                    SIM_run_alone(self.top.stopAndCall, self.recordInt128)
        else:
            self.lgr.debug('record32BitEnter returning to user comm <%s> self.commm <%s>  want: <%s>' % (comm, self.comm, want))
            if want == 'sysexit' and comm == self.comm:
                self.rmMode()
                self.lgr.debug('record32BitEnter modeHap returning to user eip 0x%x instruct %s tid:%s (%s)'% (eip, instruct[1], tid, comm))
                self.top.stopAndGo(self.recordExit32Alone)

    def recordInt128(self, dumb):
        eip = self.top.getEIP()
        self.param.sys_entry = self.top.getEIP() + self.enter_delta
        self.lgr.debug('record32BitEnter recordInt128 eip: 0x%x set sys_entry to 0x%x enter_delta was 0x%x' % (eip, self.param.sys_entry, self.enter_delta))
        self.saveParams()

    def recordEnter32(self, dumb):
        eip = self.top.getEIP()
        self.param.sysenter_32 = eip + self.enter_delta
        self.lgr.debug('record32BitEnter recordEnter32 eip: 0x%x set sysenter_32 to 0x%x enter_delta was 0x%x' % (eip, self.param.sysenter_32, self.enter_delta))
        # we need to run to user return and then back up 1 to get the instruction and address
        self.top.allowReverse()
        self.doSysexit()

    def recordExit32Alone(self, dumb=None):
        cycle = self.cpu.cycles
        self.lgr.debug('record32BitEnter recordExit32Alone cycles: 0x%x' % cycle)
        prior = cycle - 1
        self.top.skipToCycle(prior)
        eip = self.top.getEIP()
        self.param.sysexit = eip - self.enter_delta
        self.lgr.debug('recorded sysexit as 0x%x' % self.param.sysexit)
        self.saveParams()

    def recordExit32(self, dumb):
        SIM_run_alone(self.recordExit32Alone, None)

    def saveParams(self):
        if self.save:
            self.lgr.debug(self.param.getParamString())
            self.lgr.debug('saveParam')
            fname = '%s.param' % self.target
            pickle.dump( self.param, open( fname, "wb" ) )
            self.param.printParams()
            print('Param file stored in %s current_task was 0x%x' % (fname, self.param.current_task))
