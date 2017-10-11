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
class stopHapCallback():
    def __init__(self, callback, param, lgr):
        self.stop_hap = None
        self.callback = callback
        self.param = param
        self.lgr = lgr
        self.installStopHap()
        SIM_break_simulation('stopHapCallback init for command %s' % str(callback))

    class stopRec():
        def __init__(self, hap, callback):
            self.hap = hap
            self.callback = callback
        
    def installStopHap(self):
        self.stop_hap = SIM_hap_add_callback("Core_Simulation_Stopped", 
		    self.stopCallback, None)
        self.lgr.debug('stopHap installStopHap, stop hap added %d' % self.stop_hap)


    def stopCallback(self, dum, one, two, three):
        if self.stop_hap is None:
            self.lgr.debug('stopHapCallback, hap is none, but here we are')
            return
        self.lgr.debug('stopHap stopCallback stop hap is: %d make callback to : %s' % (self.stop_hap, str(self.callback)))
        SIM_hap_delete_callback_id("Core_Simulation_Stopped", self.stop_hap)
        self.stop_hap = None
        self.callback(self.param)
