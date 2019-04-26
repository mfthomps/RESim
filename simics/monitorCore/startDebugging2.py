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
import mod_software_tracker_commands as tr
import sys
sys.path.append("/home/mike/simics-4.6/simics-4.6.84/linux64/lib/") 
sys.path.append("/home/mike/simics-4.6/simics-4.6.84/linux64/lib/software-tracker")
import logging
'''
   Use the contextManager to start debugging.  Optionally run a command.
   The debugInfo class is used to pass parameters.
   These commands will not run until Simics stops the simulation.
'''
class startDebugging2():
    __stop_hap = None
    '''
    Run a command after the simulation has stopped
    '''
    def __init__(self, dbi):
        print 'Debugging2 Init *****************************************'
        self.lgr = dbi.lgr
        self.lgr.debug('startDebugging2 init ****************')
        SIM_run_alone(self.install_stop_hap, dbi)

    def install_stop_hap(self, dbi):
        self.lgr.debug('startDebugging2 install stop hap')
        self.__stop_hap = SIM_hap_add_callback("Core_Simulation_Stopped", 
		    self.stop_callback, dbi)

    def stop_callback(self, dbi, one, two, three):
        print 'in startDebugging2 stop_callback'
        cycles = SIM_cycle_count(dbi.cpu)
        self.lgr.debug('startDebugging2 in stop_callback, cycles is %d' % cycles)
        #dbi.hap_manager.clear(dbi.cell_name, dbi.pid)
        if dbi.command is not None:
            print 'startDebugging2 stop_callback command will be %s' % dbi.command
            self.lgr.debug('startDebugging2 command will be %s' % dbi.command)
            SIM_run_alone(SIM_run_command, dbi.command)
        self.lgr.debug('startDebugging2 call to contextManager.debug')
        dbi.context_manager.debug(dbi.cell_name, dbi.pid, dbi.comm, dbi.cpu, False)

        SIM_hap_delete_callback_id("Core_Simulation_Stopped", self.__stop_hap)
        if dbi.del_breakpoint is not None:
            ''' remove the breakpoint set at the location of the signal '''
            SIM_delete_breakpoint(dbi.del_breakpoint)
        
