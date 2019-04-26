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
'''
Reverse until some breakpoint is hit.  In theory, there will
be a breakpoint at the start of the process, to keep us from
flying past the recording.
'''
class reverseToWhatever():
    def __init__(self, top, context_manager, cpu, lgr, extra_back=0):
        self.top = top
        self.lgr = lgr
        self.extra_back = extra_back
        self.context_manager = context_manager
        self.lgr.debug('reverseToWhatever init')
        self.stop_hap = SIM_hap_add_callback("Core_Simulation_Stopped", 
	     self.stopHap, cpu)
        SIM_run_command('reverse')
        

    def stopHap(self, cpu, one, exception, error_string):
        eip = self.top.getEIP()
        self.lgr.debug('reverseToWhatever stopHap eip: %x' % eip)
        #self.top.gdbMailbox('0x%x' % eip)
        cycles = 1 + self.extra_back
        self.top.skipAndMail(cycles)
        self.context_manager.setExitBreak(cpu)
        SIM_hap_delete_callback_id("Core_Simulation_Stopped", self.stop_hap)
