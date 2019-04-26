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
class debugSignal():
    __stop_hap = None
    __stop_hap2 = None
    __param = None

    def __init__(self, top, dbi, param, os_utils, bookmarks):
        self.__param = param
        self.lgr = dbi.lgr
        self.top = top
        self.os_utils = os_utils 
        self.bookmarks = bookmarks
        self.lgr.debug('debugSignal init, install a stop hap, auto_analysis is %r' % dbi.auto_analysis)
        SIM_run_alone(self.install_stop_hap, dbi)

    def install_stop_hap(self, dbi):
        self.__stop_hap = SIM_hap_add_callback("Core_Simulation_Stopped", 
		    self.stop_callback, dbi)
        self.lgr.debug('debugSignal install_stop_hap, stop hap added')

    def delete_callback(self, dum):
        SIM_hap_delete_callback_id("Core_Simulation_Stopped", self.__stop_hap)
    
    def runAloneXXX(self, dbi):
        self.__stop_hap2 = SIM_hap_add_callback("Core_Simulation_Stopped", 
		    self.stop_callback2, dbi)
        self.lgr.debug('debugSignal install_stop_hap2, stop hap added')
        bm = 'bm_%x' % dbi.cycle
        self.lgr.debug('debugSignal, runAlone, real bookmark %s' % bm)
        cmd='skip-to %s' % bm
        self.lgr.debug('debugSignal, runAlone, added stop hap, no go to bookmark')
        SIM_run_alone( SIM_run_command, cmd)

    def stop_callback2(self, dbi, one, two, three):
        if self.__stop_hap2 is None:
            return
        SIM_hap_delete_callback_id("Core_Simulation_Stopped", self.__stop_hap2)
        self.__stop_hap2 = None
        cycles = dbi.cpu.cycles
        self.lgr.debug('debugSignal after skip to bookmark, cycles is %x' % cycles)
        new_want = cycles - 1
        if dbi.unmapped_eip:
            self.lgr.debug('stop_callback2, was unmapped, rev 1')
            SIM_run_command('pselect cpu-name = %s' % dbi.cpu.name)
            SIM_run_command('skip-to cycle = 0x%x' % new_want)
            cycles = dbi.cpu.cycles
            if cycles == new_want:
                cpl = memUtils.getCPL(dbi.cpu)
                if cpl == 0:
                    eip = self.top.getEIP(dbi.cpu)
                    self.lgr.debug('debugSignal stop_callback2, simicsError after rev, cycle is 0x%x  but eip is in kernel at %x, fail, try again' % (cycles, eip))
                    return
            else:
                self.lgr.debug('debugSignal, stop_callback2, simicsError after rev, cycle is 0x%x  expected it to be 0x%x' % (cycles, new_want))

        ida_msg = ''
        if dbi.frame is not None:
            ida_msg += 'Signal %d, thread frame from kernel:\n%s' \
                             % (dbi.event_value, self.os_utils.stringFromFrame(dbi.frame))
        if dbi.negotiate_result is not None:
            ida_msg +='\n[%s]' % dbi.negotiate_result 
        elif db.event_value is not None:
            ida_msg +='\n[Signal %d, failed negotiate]' % dbi.event_value
        dbi.context_manager.setIdaMessage(ida_msg)
        self.bookmarks.setOrigin(dbi.cpu)
        if not dbi.auto_analysis:
            dbi.context_manager.debug(dbi.cell_name, dbi.pid, dbi.comm, dbi.cpu, False, cycles)
        else:
            self.lgr.debug('debugSignal, call autoAnalysis')
            dbi.context_manager.debug(dbi.cell_name, dbi.pid, dbi.comm, dbi.cpu, False, cycles, auto_analysis=True)
            self.top.autoAnalysis(dbi.cell_name, dbi.pid, dbi.comm, dbi.cpu, False, cycles)
        

    def delete_callback(self, dum):
        SIM_hap_delete_callback_id("Core_Simulation_Stopped", self.__stop_hap)
    
    def runAloneXXXy(self, dbi):
        all_done = False
        expected = dbi.command.split('=')[1].strip()
        want_cycle = int(expected)
        simics_crap_counter = 0
        ida_msg = ''
        start_cycle = self.bookmarks.getCycle('_start+1')
        while not all_done:
            done = False
            while not done:
                SIM_run_command('pselect cpu-name = %s' % dbi.cpu.name)
                SIM_run_command('skip-to cycle = 0x%x' % start_cycle)
                cycles = dbi.cpu.cycles
                self.lgr.debug('debugSignal, did skip to start at cycle %x, expected %x counter %d' % (cycles, start_cycle, simics_crap_counter))

    def runAlone(self, dbi):
        all_done = False
        expected = dbi.command.split('=')[1].strip()
        want_cycle = int(expected)
        simics_crap_counter = 0
        ida_msg = ''
        start_cycle = self.bookmarks.getCycle('_start+1')
        if self.top.SIMICS_BUG:
          while not all_done:
            done = False
            while not done:
                SIM_run_command('pselect cpu-name = %s' % dbi.cpu.name)
                SIM_run_command('skip-to cycle = 0x%x' % start_cycle)
                cycles = dbi.cpu.cycles
                self.lgr.debug('debugSignal, did skip to start at cycle %x, expected %x counter %d' % (cycles, start_cycle, simics_crap_counter))
                
                #SIM_run_command('skip-to bookmark = bookmark0')
                #cycles = SIM_cycle_count(dbi.cpu)
                #self.lgr.debug('debugSignal, did skip to bookmark0, cycle now %x' % cycles)
                SIM_run_command('pselect cpu-name = %s' % dbi.cpu.name)
                SIM_run_command(dbi.command)
                cycles = dbi.cpu.cycles
                if dbi.command.startswith('skip-to'):
                    eip = self.top.getEIP(dbi.cpu)
                    if want_cycle != cycles or eip != dbi.sig_eip:
                        self.lgr.error('debugSignal, simicsError expected cycle %x (0x%x) eip:0x%x, got cycles %x eip:0x%x' % (want_cycle, dbi.cycle, dbi.sig_eip, cycles, eip))
                        SIM_run_command('pselect cpu-name = %s' % dbi.cpu.name)
                        SIM_run_command('skip-to cycle = 0x%x' % start_cycle)
                        
                    else:
                        self.lgr.debug('debugSignal, went where we expected, expected cycle %x (0x%x) eip: 0x%x, got cycles %x eip:0x%x counter: %d' % (want_cycle, dbi.cycle, dbi.sig_eip, cycles, eip, simics_crap_counter))
                done = True

            if dbi.unmapped_eip:
                new_want = want_cycle - 1
                # TBD debug, do one time
                simics_crap_counter_x = 0
                while all_done is False and simics_crap_counter_x < 1:
                    self.lgr.debug('debugSignal was unmapped eip, so rev 1 so we do not end up looking at dumb eip counter: %d' % simics_crap_counter_x)
                    SIM_run_command('pselect cpu-name = %s' % dbi.cpu.name)
                    SIM_run_command('skip-to cycle = 0x%x' % start_cycle)
                    cycles = dbi.cpu.cycles
                    self.lgr.debug('debugSignal, before doing rev, did skip to start at cycle %x, expected %x counter %d' % (cycles, start_cycle, simics_crap_counter))
                    SIM_run_command('pselect cpu-name = %s' % dbi.cpu.name)
                    SIM_run_command('skip-to cycle = 0x%x' % new_want)
                    cycles = dbi.cpu.cycles
                    if cycles == new_want:
                        cpl = memUtils.getCPL(dbi.cpu)
                        if cpl != 0:
                            all_done = True
                        else:
                            eip = self.top.getEIP(dbi.cpu)
                            self.lgr.debug('debugSignal, simicsError after rev, cycle is 0x%x  but eip is in kernel at %x, fail, try again' % (cycles, eip))
                            break
                    else:
                        self.lgr.debug('debugSignal, simicsError after rev, cycle is 0x%x  expected it to be 0x%x' % (cycles, new_want))
                        break
                    simics_crap_counter_x += 1
            else:
                all_done = True  
            simics_crap_counter += 1
            self.lgr.debug('inc counter to %d' % simics_crap_counter)
            if simics_crap_counter > 9:
                all_done = True
                self.lgr.error('debugSignal, simicsError simics has lost its way, TBD tell the idaClient user to try again later...')
                ida_msg += 'Simics got lost, what follows is wrong.  Suggest you quit and try again'
        else:
         SIM_run_command('pselect cpu-name = %s' % dbi.cpu.name)
         SIM_run_command(dbi.command)
         cycles = dbi.cpu.cycles
         if dbi.unmapped_eip:
             new_want = want_cycle - 1
             SIM_run_command('pselect cpu-name = %s' % dbi.cpu.name)
             SIM_run_command('skip-to cycle = 0x%x' % new_want)
             cycles = dbi.cpu.cycles

        self.lgr.debug('debugSignal after command, cycles is %x' % cycles)
        if dbi.frame is not None:
            ida_msg += 'Signal %d, thread frame from kernel:\n%s' \
                         % (dbi.event_value, self.os_utils.stringFromFrame(dbi.frame))
        if dbi.negotiate_result is not None:
            ida_msg +='\n[%s]' % dbi.negotiate_result 
        elif dbi.event_value is not None:
            ida_msg +='\n[Signal %d, failed negotiate]' % dbi.event_value
        dbi.context_manager.setIdaMessage(ida_msg)
        self.bookmarks.setOrigin(dbi.cpu)
        if not dbi.auto_analysis:
            dbi.context_manager.debug(dbi.cell_name, dbi.pid, dbi.comm, dbi.cpu, False, cycles)
        else:
            self.lgr.debug('debugSignal, call autoAnalysis')
            dbi.context_manager.debug(dbi.cell_name, dbi.pid, dbi.comm, dbi.cpu, False, cycles, auto_analysis=True)
            self.top.autoAnalysis(dbi.cell_name, dbi.pid, dbi.comm, dbi.cpu, False, cycles)
        
    def stop_callback(self, dbi, one, two, three):
        if dbi.context_manager.getDebugging():
            print 'stop hap not yet deleted, but already debugging, just return'
            self.lgr.error('stop hap not yet deleted, but already debugging, just return')
            return
        dbi.context_manager.setDebugging(True)
        SIM_run_alone(self.delete_callback, None)

        reg_num = dbi.cpu.iface.int_register.get_number("eip")
        eip = dbi.cpu.iface.int_register.read(reg_num)
        cycles = dbi.cpu.cycles
        print 'debugSignal, stop_callback at cycle %x for pid %d eip: %x' % (cycles, dbi.pid, eip)
        self.lgr.debug('debugSignal, stop_callback at cycle %x for pid %d  eip: %x' % (cycles, dbi.pid, eip))
        #dbi.hap_manager.clear(dbi.cell_name, dbi.pid)
        if dbi.command is not None and dbi.command.startswith('skip-to'):
            self.lgr.debug('debugSignal, stop_callback is skip to, go there and debug, cmd %s' % dbi.command)
            SIM_run_alone(self.runAlone, dbi)
        else:
            self.lgr.error('debugSigal, stop callback missing skip-to command')
 
