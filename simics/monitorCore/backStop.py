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
from resimSimicsUtils import rprint
import logging
'''
Manage cycle events to limit how far a session can run without some intervening event.
'''
class BackStop():
    def cycle_handler(self, obj, cycles):
        ''' callback for hitting backstop cycle '''
        #self.lgr.debug("backStop, cycle_handler ")
        if self.back_stop_cycle is None:
            return
        if self.cpu is not None:
            if not self.top.hasAFL():
                self.lgr.debug('backStop cycle_handler going to break simuation cpu is %s cycles: 0x%x callback %s' % (self.cpu.name, self.cpu.cycles, str(self.callback)))
            self.clearCycle()
            SIM_break_simulation('hit final cycle')
            self.top.notRunning(quiet=True)
            '''
            cmd_callback = self.top.getCommandCallback()
            if cmd_callback is not None:
                self.lgr.debug('backStop cycle_handler, commandCallback takes precidence.')
                cmd_callback()
            '''
            if self.callback is not None:
                self.callback()
            if self.report_backstop:
                rprint('Backstop hit.')
        else: 
            rprint('backStop cycle_handler lingering after cpu set to None, ignore')
            SIM_continue(0)
        #SIM_run_alone(self.runalone_callback, None)
       
        #SIM_event_post_cycle(obj, cycle_event, obj, cycles, cycles)
 

    def __init__(self, top, cpu, lgr=None):
        if lgr is None:
            self.lgr = logging
        else:
            self.lgr = lgr
        self.cycle_event = None 
        ''' only hit if futureCycles never set '''
        self.hang_event = None 
        self.cpu = cpu
        self.top = top
        self.callback = None
        self.saved_callback = None
        self.hang_callback = None
        self.hang_cycles = None
        self.hang_cycles_delta = 0
        self.report_backstop = False
        self.delay = None
        self.lgr.debug('backStop init cpu %s' % self.cpu.name)

    def setCallback(self, callback):
        self.callback = callback

    def overrideCallback(self, callback):
        self.saved_callback = self.callback
        self.callback = callback

    def restoreCallback(self):
        self.callback = self.saved_callback

    def clearCycle(self):
        if self.cycle_event is not None:
            #self.lgr.debug('backStop clearCycle')
            #SIM_event_cancel_time(cpu, self.cycle_event, self.cpu, 0, None)
            SIM_event_cancel_time(self.cpu, self.cycle_event, self.cpu, None, None)
        self.back_stop_cycle = None

    def checkEvent(self):
        if self.cycle_event is None:
            print('backStop NO event') 
        else:
            print('backStop yes, has event') 

    def setFutureCycleAlone(self, cycles):
        if self.cycle_event is None:
            self.cycle_event = SIM_register_event("cycle event", SIM_get_class("sim"), Sim_EC_Notsaved, self.cycle_handler, None, None, None, None)
            #self.lgr.debug('backStop did register')
        else:
            SIM_event_cancel_time(self.cpu, self.cycle_event, self.cpu, None, None)
            #self.lgr.debug('backStop did registercancel')
        self.back_stop_cycle = self.cpu.cycles + cycles
        SIM_event_post_cycle(self.cpu, self.cycle_event, self.cpu, cycles, cycles)
        #self.lgr.debug('backStop setFutureCycleAlone, now: 0x%x  cycles: 0x%x should stop at 0x%x' % (self.cpu.cycles, cycles, self.back_stop_cycle))

    def setFutureCycle(self, cycles, now=False):
        #self.lgr.debug('backStop setFutureCycle')
        if self.hang_cycles is not None and self.cpu.cycles >= self.hang_cycles:
            #self.lgr.debug('backStop setFutureCycle hang cycles delta of 0x%x exceeded.  Cycles now 0x%x call hang_callback %s' % (self.hang_cycles_delta, self.cpu.cycles, str(self.hang_callback)))
            SIM_run_alone(self.hang_callback, self.cpu.cycles)
        else:
            if self.hang_cycles is None and self.hang_cycles_delta >0:
                # crude way to defer hang cycle watch until first data read
                self.lgr.debug('backStop setFutureCycle call setHangCallbackAlone')
                SIM_run_alone(self.setHangCallbackAlone, None)

            if self.delay is not None:
                self.delay = self.delay - 1
                if self.delay == 0:
                    self.delay = None
                else:
                    #self.lgr.debug('backStop setFuturecycle delay now %d, bail' % self.delay)
                    return
         
            if not now:
                SIM_run_alone(self.setFutureCycleAlone, cycles)
            else:
                self.setFutureCycleAlone(cycles)

        # TBD why was this being canceled?
        #if self.hang_event is not None:
        #    self.lgr.debug('setFutureCycle cancle hang_event')
        #    SIM_event_cancel_time(self.cpu, self.hang_event, self.cpu, None, None)
           

    def hang_handler(self, obj, cycles):
        if self.delay is not None:
            self.lgr.debug('backStop hang_handler but delay is 0x%x' % delay)
            return
        #self.lgr.debug('backStop hang_handler will call callback %s' % str(self.hang_callback))
        self.hang_callback(self.cpu.cycles)

    def setHangCallbackAlone(self, dumb):
        self.setHangCallback(self.hang_callback, self.hang_cycles_delta)

    def setHangCallback(self, callback, cycles, now=True):
        if self.delay is not None:
            return
        self.hang_cycles_delta = cycles
        self.hang_callback = callback
        if now:
            self.hang_cycles = self.cpu.cycles + cycles
            self.lgr.debug('backStop hang cycles 0x%x delta 0x%x setHangCallback to %s' % (self.hang_cycles, cycles, str(callback)))
            if self.hang_event is None:
                self.hang_event = SIM_register_event("hang event", SIM_get_class("sim"), Sim_EC_Notsaved, self.hang_handler, None, None, None, None)
            SIM_event_post_cycle(self.cpu, self.hang_event, self.cpu, cycles, cycles)

    def reportBackstop(self, report):
        self.report_backstop = report

    def setDelay(self, delay):
        self.lgr.debug('backStop setDelay 0x%x' % delay)
        self.delay = delay

if __name__ == "__main__":
    bs = backStop()
 
