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
import sys
import logging
import startDebugging2
import chainHap
import cgcEvents
'''
    Do the simics-three-step: 
       Set a hap that fires when execution stops.  When that hap fires, set another
       hap that fires when the execution starts and then restart execution via 
       the given command, which must be one that will eventually lead to stopping
       the execution, e.g., 'reverse 1'.  The 2nd Hap installs a 3rd Hap that will
       fire when the execution again stops.  It is that 3rd Hap where we start
       debugging.
       MFT TBD: can this be simplified, e.g., using something like "SIM_run_unrestricted"?
'''
class startDebugging():
    __stop_hap = None
    __start_hap = None
    __page_hap = None
    __sig_hap = None
    __context_hap = None
    __param = None
    __page_break_breakpoint = None

    def __init__(self, dbi, param, os_utils):
        self.__param = param
        self.lgr = dbi.lgr
        self.os_utils = os_utils 
        self.lgr.debug('startDebugging init, install a stop hap')
        SIM_run_alone(self.install_stop_hap, dbi)

    def install_stop_hap(self, dbi):
        self.__stop_hap = SIM_hap_add_callback("Core_Simulation_Stopped", 
		    self.stop_callback, dbi)
        self.lgr.debug('startDebugging install_stop_hap, stop hap added')

    def delete_callback(self, dum):
        SIM_hap_delete_callback_id("Core_Simulation_Stopped", self.__stop_hap)
        print 'the startDebuggin hap has been deleted'

    def delete_page_callback(self, dum):
        SIM_hap_delete_callback_id("Core_Exception", self.__page_hap)
        print 'the page hap has been deleted'


    def install_start_hap(self, dbi):
        self.__start_hap = SIM_hap_add_callback("Core_Continuation", 
		    self.start_callback, dbi)

    def delete_start_hap(self, dum):
        SIM_hap_delete_callback_id("Core_Continuation", self.__start_hap)
        print 'the start hap has been deleted'

    def start_callback(self, dbi, one):
        SIM_run_alone(self.delete_start_hap, None)
        print 'in start callback startDebugging1x5'
        startDebugging2.startDebugging2(dbi)

    def stop_callback(self, dbi, one, two, three):
        if dbi.context_manager.getDebugging():
            print 'stop hap not yet deleted, but already debugging, just return'
            self.lgr.debug('stop hap not yet deleted, but already debugging, just return')
            return
        dbi.context_manager.setDebugging(True)
        SIM_run_alone(self.delete_callback, None)

        reg_num = dbi.cpu.iface.int_register.get_number("eip")
        eip = dbi.cpu.iface.int_register.read(reg_num)
        cycles = SIM_cycle_count(dbi.cpu)
        print 'in stop hap for startDebugging at cycle %x for pid %d eip: %x' % (cycles, dbi.pid, eip)
        self.lgr.debug('in stop callback for startDebugging at cycle %x for pid %d  eip: %x' % (cycles, dbi.pid, eip))
        #self.os_utils.printFrame(dbi.frame)
        #dbi.hap_manager.clear(dbi.cell_name, dbi.pid)
        if dbi.command.startswith('skip-to'):
            self.lgr.debug('is skip to, go there and debug, cmd %s' % dbi.command)
            SIM_run_alone(SIM_run_command, dbi.command)
            dbi.context_manager.debug(dbi.cell_name, dbi.pid, dbi.comm, dbi.cpu, False)
            return
        command = dbi.command
        dbi.command = None
        #TBD everything below is suspect 
        if dbi.event_type is cgcEvents.CGCEventType.signal:

            if dbi.cycle is None:          
                '''
                NOT USED, remove?
                The hap that caught the execution of kernel signal handling code passed us
                the eip from the thread's frame in dbi.sig_eip.  Set a break there and
                reverse.  Note we let that breakpoint break execution because Hap invokation
                is undefined while reversing.
                ''' 
                phys_block = dbi.cpu.iface.processor_info.logical_to_physical(dbi.sig_eip, 
                    Sim_Access_Read)
                cell = dbi.cpu.physical_memory
                dbi.del_breakpoint = SIM_breakpoint(cell, Sim_Break_Physical, 
                     Sim_Access_Execute, phys_block.address, 1, 0)
                self.lgr.debug('in stop hap breakpoint set break %d where signal occurred, at address %x, phys: %x' % \
                     (dbi.del_breakpoint, dbi.sig_eip, phys_block.address))
                #startDebugging2.startDebugging2(dbi)
            else:
                self.lgr.debug('in startDebug, have return to cycle, startDebug2 with reverse 1')
                #dbi.command = 'reverse 1'
                dbi.command = []
                dbi.command.append('reverse-step-instruction')
                dbi.command.append('step-instruction')
                dbi.command.append('reverse-step-instruction')
                dbi.command.append('do-debug')
                chainHap.chainHap(dbi, self.os_utils, self.__param)
                #startDebugging2.startDebugging2(dbi)

            #self._sig_sig_hap = SIM_hap_add_callback_index("Core_Breakpoint_Memop",
            #                    self.del_breakpoint_callback, dbi, self.__page_break_breakpoint)

            dbi.context_manager.setIdaMessage('Signal %d, thread frame from kernel:\n%s' \
                         % (dbi.event_value, self.os_utils.stringFromFrame(dbi.frame)))

        elif dbi.event_type is cgcEvents.CGCEventType.rop_cop:
            self.lgr.debug('Start debugging for rop cop')
            dbi.command = None
            startDebugging2.startDebugging2(dbi)
        else:
            self.lgr.debug('Not a signal, install start hap')
            SIM_run_alone(self.install_start_hap, dbi)
            if dbi.event_type is cgcEvents.CGCEventType.not_code:
                dbi.context_manager.setIdaMessage('Execution outside text region')
                self.lgr.debug('in stop_callback, execution outside of text region')

        print 'run command %s' % command
        self.lgr.debug('Done with stop callback in start Debbugging, will run command %s' % command)
        SIM_run_alone(SIM_run_command, command)
        
        
        
