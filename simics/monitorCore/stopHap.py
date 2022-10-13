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
class stopHap():
    def __init__(self, command, lgr):
        self.stop_hap = None
        self.command = command
        self.lgr = lgr
        self.installStopHap()
        SIM_break_simulation('stopHap init for command %s' % command) 

    class stopRec():
        def __init__(self, hap, command):
            self.hap = hap
            self.command = command
        
    def installStopHap(self):
        self.stop_hap = SIM_hap_add_callback("Core_Simulation_Stopped", 
		    self.stopCallback, None)
        self.lgr.debug('stopHap installStopHap, stop hap added %d' % self.stop_hap)

    #def deleteCallback(self, dum):
    #    self.lgr.debug('stopHap deleteCallback')
    #    SIM_hap_delete_callback_id("Core_Simulation_Stopped", self.stop_hap)

    def runAlone(self, stop_rec):
        self.lgr.debug('stopHap runAlone, stop hap is %d, command %s' % (stop_rec.hap,  stop_rec.command))
        #self.deleteCallback(None)
        SIM_hap_delete_callback_id("Core_Simulation_Stopped", stop_rec.hap)
        SIM_run_command(stop_rec.command)
        self.lgr.debug('stopHap back from %s' % stop_rec.command)
        if stop_rec.command == 'enable-reverse-execution':
            SIM_run_command('disconnect-real-network')
            SIM_run_command('disable-vmp')
            self.lgr.debug('stopHap disabled VMP & network')
        
        SIM_continue(0)
        self.lgr.debug('return from runAlone')

    def stopCallback(self, dum, one, two, three):
        self.lgr.debug('stopHap stopCallback stop hap is: %d command: %s' % (self.stop_hap, self.command))
        stop_rec = self.stopRec(self.stop_hap, self.command)
        SIM_run_alone(self.runAlone, stop_rec)
        '''
        SIM_run_alone(self.deleteCallback, None)
        SIM_run_alone(SIM_run_command, self.command)
        SIM_run_alone(SIM_run_command, 'continue')
        '''
