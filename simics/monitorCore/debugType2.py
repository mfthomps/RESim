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
import memUtils
class debugType2():
    __stop_hap = None
    __param = None

    def __init__(self, top, bookmark_mgr, dbi, param, os_utils, address):
        self.__param = param
        self.lgr = dbi.lgr
        self.bookmark_mgr = bookmark_mgr
        self.os_utils = os_utils 
        self.top = top
        self.address = address
        self.lgr.debug('debugType2 init for read at 0x%x, install a stop hap' % address)
        SIM_run_alone(self.install_stop_hap, dbi)

    def install_stop_hap(self, dbi):
        self.__stop_hap = SIM_hap_add_callback("Core_Simulation_Stopped", 
		    self.stop_callback, dbi)
        self.lgr.debug('debugType2 install_stop_hap, stop hap added')

    def delete_callback(self, dum):
        SIM_hap_delete_callback_id("Core_Simulation_Stopped", self.__stop_hap)

    def runAlone(self, dbi):
        # record where the process is through, won't let debug past this point
        backstop_cycles = dbi.cpu.cycles

        bm = 'protected_memory:0x%x' % self.address
        self.bookmark_mgr.mapOrigin(bm)
        #self.bookmark_mgr.goToDebugBookmark(bm, internal=True, cpu=dbi.cpu)
        '''
        want_cycle = self.bookmark_mgr.getCycle(bm)
        want_step = self.bookmark_mgr.getStep(bm)
        want_eip = self.bookmark_mgr.getEIP(bm)
        done = False
        count = 0
        start_cycle = self.bookmark_mgr.getCycle('_start+1')
        while not done:
            SIM_run_command('pselect cpu-name = %s' % dbi.cpu.name)
            SIM_run_command('skip-to cycle = 0x%x' % start_cycle)
            cycles = SIM_cycle_count(dbi.cpu)
            self.lgr.debug('debugType2, did skip to start at cycle %x, expected %x ' % (cycles, start_cycle))
            SIM_run_command(dbi.command)
            cycles = SIM_cycle_count(dbi.cpu)
            eip = self.top.getEIP(dbi.cpu)
            steps = SIM_step_count(dbi.cpu)
            if want_step is not None:
                self.lgr.debug('debugType2, got cycle: %x step %x eip: %x, expected %x %x %x' % (cycles, steps, eip, want_cycle, want_step, want_eip))
            else:
                self.lgr.debug('debugType2, got cycle: %x step %x eip: %x, expected %x unknown %x' % (cycles, steps, eip, want_cycle, want_eip))
            if cycles != want_cycle or (want_step is not None and steps != want_step) or eip != want_eip:
                self.lgr.error('debugType2, simicsError, try again?')
            else:
                done = True
            
            count += 1
            if count > 4:
                self.lgr.error('debugType2 simics is hosed')
                done = True

        self.lgr.debug('debugType2 after command, cycles is 0x%x, backstop is 0x%x' % (cycles, backstop_cycles))
        '''
        dbi.context_manager.setIdaMessage('[Type 2 Pov read from 0x%x]' % self.address)
        # remove the previously added bookmark for protected memory
        #self.bookmark_mgr.clearOtherBookmarks('protected_memory:')
        self.bookmark_mgr.clearOtherBookmarks('protected_memory:', bm)
        if not dbi.auto_analysis:
            dbi.context_manager.debug(dbi.cell_name, dbi.pid, dbi.comm, dbi.cpu, False, backstop_cycles)
        else:
            self.lgr.debug('debugType2, call autoAnalysis')
            dbi.context_manager.debug(dbi.cell_name, dbi.pid, dbi.comm, dbi.cpu, False, backstop_cycles, auto_analysis=True)
            self.top.autoAnalysis(dbi.cell_name, dbi.pid, dbi.comm, dbi.cpu, False, backstop_cycles)
        cpl = memUtils.getCPL(dbi.cpu)
        if cpl == 0:
            # should not get here, cycles was adjusted when protected memory was read
            self.lgr.error('debugType2 found self in kernel space')
            #self.top.revToUserSpace()
            #self.lgr.debug('debugType2 reversed to user space, reset origin')
            #self.top.setDebugBookmark('origin', dbi.cpu)
        
    def stop_callback(self, dbi, one, two, three):
        if dbi.context_manager.getDebugging():
            print 'stop hap not yet deleted, but already debugging, just return'
            self.lgr.error('stop hap not yet deleted, but already debugging, just return')
            return
        dbi.context_manager.setDebugging(True)
        self.top.cleanupAllAlone(dbi.pid)
        SIM_run_alone(self.delete_callback, None)

        reg_num = dbi.cpu.iface.int_register.get_number("eip")
        eip = dbi.cpu.iface.int_register.read(reg_num)
        cycles = dbi.cpu.cycles
        print 'debugType2, stop_callback at cycle %x for pid %d eip: %x' % (cycles, dbi.pid, eip)
        self.lgr.debug('debugType2, stop_callback at cycle %x for pid %d  eip: %x' % (cycles, dbi.pid, eip))
        #dbi.hap_manager.clear(dbi.cell_name, dbi.pid)
        if dbi.command.startswith('skip-to'):
            self.lgr.debug('debugType2, stop_callback cmd is skip to, go there and debug, cmd %s' % (dbi.command))
            SIM_run_alone(self.runAlone, dbi)
        else:
            self.lgr.error('debugType2, stop callback missing skip-to command')
 
