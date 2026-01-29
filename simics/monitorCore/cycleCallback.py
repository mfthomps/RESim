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
Provide a callback service invoked after a given number of cycles.
The given callback is called with the given param.
Only instantiate one of these per name.
'''
from simics import *
class CycleCallback():
    def __init__(self, cpu, name, lgr):
        self.cycles = None
        self.callback = None
        self.cpu = cpu
        self.param = None
        self.lgr = lgr
        self.cycle_event = None
        use_name = '%s_cycle_callback' % name
        self.lgr.debug('cycleCallback register for name %s' % use_name)
        self.cycle_event = SIM_register_event(use_name, SIM_get_class("sim"), Sim_EC_Notsaved, self.cycle_handler, None, None, None, None)
        self.pending_event = False

    def setCallback(self, cycles, callback, param):
        self.cycles = cycles
        self.param = param
        self.callback = callback
        SIM_run_alone(self.setCycleHap, None)

    def setCycleHap(self, dumb=None):
        SIM_event_cancel_time(self.cpu, self.cycle_event, self.cpu, None, None)
        self.lgr.debug('cycleCallback setCycleHap did registercancel')
        commence_cycle = self.cpu.cycles + self.cycles
        self.lgr.debug('cycleCallback setCycleHap posted cycle of 0x%x cpu: %s look for cycle 0x%x (%d)' % (self.cycles, self.cpu.name, commence_cycle, commence_cycle))
        SIM_event_post_cycle(self.cpu, self.cycle_event, self.cpu, self.cycles, self.cycles)
        self.pending_event = True


    def cycle_handler(self, obj, cycles):
        if not self.pending_event: 
            return
        self.lgr.debug('cycleCallback cycle_handler') 
        self.lgr.debug('cycleCallback cycle_handler now do callback')
        SIM_run_alone(self.doCycleCallback, None)
        # TBD jumpers should match cycleCallback?  Two kinds: one for diagnostics and one for real control flow around crc's
        #self.top.jumperEnable(target=self.cell_name)

    def doCycleCallback(self, dumb):
        SIM_event_cancel_time(self.cpu, self.cycle_event, self.cpu, None, None)
        self.pending_event = False
        self.lgr.debug('cycleCallback doCycleCallback')
        self.callback(self.param)

    def cancel(self):
        SIM_event_cancel_time(self.cpu, self.cycle_event, self.cpu, None, None)
