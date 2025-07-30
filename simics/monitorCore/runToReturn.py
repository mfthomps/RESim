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
Run forward until a ret instruction is hit (adjusted by any calls).
NOTE: this is not reliable because compilers do not always have a return for every call.
And it does not cover much of arm

'''
from simics import *
class RunToReturn():
    def __init__(self, top, cpu, task_utils, kernel_base, context_manager, lgr):
        self.lgr = lgr
        self.top = top
        self.cpu = cpu
        self.task_utils = task_utils
        self.kernel_base = kernel_base
        self.context_manager = context_manager
        self.eip = top.getEIP()
        self.tid = top.getTID()
        self.call_hap = None
        self.ret_hap = None
        self.call_count = 1
        self.ret_count = 0 

        self.setBreaks()

    def setBreaks(self):
        self.lgr.debug('RunToReturn setBreaks eip 0x%x tid:%s' % (self.eip, self.tid))
        if self.cpu.architecture.startswith('arm') or self.cpu.architecture == 'ppc32':
            prefix = "bl"
        else:
            prefix = "call"
        call_break = self.context_manager.genBreakpoint(None, Sim_Break_Linear, Sim_Access_Execute, 0, self.kernel_base, 0, prefix=prefix)
        self.call_hap = self.context_manager.genHapIndex("Core_Breakpoint_Memop", self.callHap, None, call_break, 'run_to_return_call')

        if self.cpu.architecture == 'ppc32':
            prefix = 'blr'
        else:
            prefix = 'ret'
        ret_break = self.context_manager.genBreakpoint(None, Sim_Break_Linear, Sim_Access_Execute, 0, self.kernel_base, 0, prefix=prefix)
        self.ret_hap = self.context_manager.genHapIndex("Core_Breakpoint_Memop", self.retHap, None, ret_break, 'run_to_return_ret')


    def callHap(self, dumb, context, break_num, memory):
        if self.call_hap is None:
            return 
        tid = self.top.getTID()
        if tid != self.tid:
            return
        eip = self.top.getEIP()
        sp = self.top.getReg('sp', self.cpu)
        instruct = self.top.disassembleAddress(self.cpu, eip)
        if instruct[1].startswith('blr'):
            self.lgr.debug('RunToReturn callHap ppc32 BLR, so really a retHap handled elsewhere, skip') 
            #self.lgr.debug('RunToReturn callHap hacked BLR, so really a retHap calls:%d rets:%d  sp: 0x%x eip: 0x%x' % (self.call_count, self.ret_count, sp, eip))
            #self.ret_count = self.ret_count+1
            #if self.call_count == self.ret_count:
            #    SIM_run_alone(self.rmHaps, None)
            #    self.top.stopAndGo(self.stepOne)
        
        elif not instruct[1].startswith('blt') and not instruct[1].startswith('ble'):
            self.call_count = self.call_count+1
            if instruct[1].startswith('bl '):
                call_addr_s = instruct[1].split()[1]
                call_addr = None
                try:
                    call_addr = int(call_addr_s, 16)
                except:
                    self.lgr.error('fix remove this no hex for %s addr %s ??' % (instruct[1], call_addr_s))
                if call_addr is not None:
                    call_fun = self.top.getFunName(call_addr)
                    call_from_fun = self.top.getFunName(eip)
                    if call_fun is None and call_from_fun is None:
                        self.lgr.debug('RunToReturn eip: 0x%x call none from none, hack it down' % eip)
                        self.call_count = self.call_count - 1
                    else:
                        self.lgr.debug('RunToReturn callHap calls now:%d rets:%d eip: 0x%x %s call_fun %s from %s' % (self.call_count, self.ret_count, eip, instruct[1], call_fun, call_from_fun))

    def retHap(self, dumb, context, break_num, memory):
        if self.ret_hap is None:
            return 
        tid = self.top.getTID()
        if tid != self.tid:
            return
        sp = self.top.getReg('sp', self.cpu)
        eip = self.top.getEIP()
        instruct = self.top.disassembleAddress(self.cpu, eip)
        self.ret_count = self.ret_count+1
        if instruct[1].startswith('blr'):
            lr = self.top.getReg('lr', self.cpu)
            lr_fun = self.top.getFunName(lr)
            call_from_fun = self.top.getFunName(eip)
            self.lgr.debug('RunToReturn retHap calls:%d rets now:%d  sp: 0x%x eip: 0x%x %s lr 0x%x to fun %s from fun %s' % (self.call_count, self.ret_count, sp, eip, instruct[1], lr, lr_fun, call_from_fun))
             
        if self.call_count == self.ret_count:
            SIM_run_alone(self.rmHaps, None)
            self.top.stopAndGo(self.stepOne)

    def rmHaps(self, dumb):
        if self.call_hap is not None:
            self.context_manager.genDeleteHap(self.call_hap)
            self.call_hap = None
        if self.ret_hap is not None:
            self.context_manager.genDeleteHap(self.ret_hap)
            self.ret_hap = None

    def stepOne(self):
        SIM_run_alone(self.stepOneAlone, None)

    def stepOneAlone(self, dumb):
        self.lgr.debug('RunToReturn stepOneAlone')
        SIM_run_command('pselect %s' % self.cpu.name)
        SIM_run_command('si')
        self.top.show()
        print('done')
