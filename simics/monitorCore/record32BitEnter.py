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
    def __init__(self, top, cpu, target, current_param, lgr, save=True):
        self.top = top
        self.cpu = cpu
        self.target = target
        self.lgr = lgr
        self.save = save
        # as originally constituted this is what we want to overwrite with new enter values
        fname = '%s.param' % self.target
        self.param = pickle.load(open( fname, "rb" ))

        self.enter_delta = current_param.sysenter - self.param.sysenter 
        self.lgr.debug('record32BitEnter enter_delta (current_param.sysenter (0x%x) - original.sysenter (0x%x) is 0x%x' % (current_param.sysenter, self.param.sysenter, self.enter_delta))
        self.mode_hap = RES_hap_add_callback_obj("Core_Mode_Change", cpu, 0, self.modeHap, None)
        # set to none for testing 
        if current_param.sys_entry is not None:
            self.lgr.debug('original sys_entry was 0x%x, current 0x%x' % (self.param.sys_entry, current_param.sys_entry))
            self.lgr.debug('original sysenter_32 was 0x%x, current 0x%x' % (self.param.sysenter_32, current_param.sysenter_32))
        self.param.sys_entry = None
        self.param.sysenter_32 = None

    def modeHap(self, dumb, the_obj, old, new):
        eip = self.top.getEIP()
        instruct = SIM_disassemble_address(self.cpu, eip, 1, 0)
        cpu, comm, tid =  self.top.getCurrentProc()
        if new == Sim_CPU_Mode_Supervisor:
            self.lgr.debug('record32BitEnter modeHap entering kernel eip 0x%x instruct %s tid:%s (%s)' % (eip, instruct[1], tid, comm))
            if instruct[1].startswith('int 128') and self.param.sys_entry is None:
                SIM_run_alone(self.top.stopAndCall, self.recordInt128)
            elif instruct[1] == 'sysenter' and self.param.sysenter_32 is None:
                SIM_run_alone(self.top.stopAndCall, self.recordEnter32)
        else:
            self.lgr.debug('record32BitEnter modeHap returning to user eip 0x%x instruct %s tid:%s (%s)'% (eip, instruct[1], tid, comm))

    def recordInt128(self, dumb):
        eip = self.top.getEIP()
        self.param.sys_entry = self.top.getEIP() - self.enter_delta
        self.lgr.debug('record32BitEnter recordInt128 eip: 0x%x set sys_entry to 0x%x enter_delta was 0x%x' % (eip, self.param.sys_entry, self.enter_delta))
        if self.param.sysenter_32 is None:
            SIM_continue(0)
        else:
            self.saveParams()

    def recordEnter32(self, dumb):
        eip = self.top.getEIP()
        self.param.sysenter_32 = eip - self.enter_delta
        self.lgr.debug('record32BitEnter recordEnter32 eip: 0x%x set sysenter_32 to 0x%x enter_delta was 0x%x' % (eip, self.param.sysenter_32, self.enter_delta))
        if self.param.sys_entry is None:
            SIM_continue(0)
        else:
            self.saveParams()

    def saveParams(self):
        if self.save:
            self.lgr.debug(self.param.getParamString())
            self.lgr.debug('saveParam')
            fname = '%s.param' % self.target
            pickle.dump( self.param, open( fname, "wb" ) )
            self.param.printParams()
            print('Param file stored in %s current_task was 0x%x' % (fname, self.param.current_task))
