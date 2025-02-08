# * This software was created by United States Government employees
# * and may not be copyrighted.
# * Redistribution and use in source and binary forms, with or without
# * modification, are permitted provided that the following conditions
# * are met:
# * 1. Redistributions of source code must retain the above copyright
# *    notice, this list of conditions and the following disclaimer.
# * 2. Redistributions in binary form must reproduce the above copyright
# *    notice, this list of conditions and the following disclaimer in the
# *    documentation and/or other materials provided with the distribution.
# *
# * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
# * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
# * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
# * DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT,
# * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
# * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
# * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
# * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
# * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
# * ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
# * POSSIBILITY OF SUCH DAMAGE.
'''
Implement a subset of the deprecated Simics reverse execution functions, at
least those used by RESim.
'''
from simics import *
import os
import cli
class ReverseMgr():
    # TBD remove top and references after testing
    def __init__(self, top, cpu, lgr):
        self.cpu = cpu
        self.lgr = lgr
        self.top = top
        #self.cycle_span = 0x100000
        #self.span_mask = 0xfffffff00000
        self.cycle_span = 0x1000
        self.span_mask = 0xfffffff000
        self.callback = None
        self.cycle_event = None
        self.span_cycle_event = None
        self.delta_cycle_event = None
        self.origin_cycle = None
        self.latest_cycle = None
        self.bp_list = []
        self.sim_breakpoints = []
        self.reverse_from = None
        self.break_haps = []
        self.break_cycles = {}
        self.stop_hap = None
        self.SIMICS_VER = os.getenv('SIMICS_VER')

    def cancelSpanCycle(self, dumb):
        SIM_event_cancel_time(self.cpu, self.cycle_event, self.cpu, None, None)

    def setNextCycle(self):
        if self.cycle_event is None:
            self.cycle_event = SIM_register_event("reverse cycle event", SIM_get_class("sim"), Sim_EC_Notsaved, self.cycle_handler, None, None, None, None)
            masked = (self.origin_cycle & self.span_mask) 
            want_cycle = masked + self.cycle_span
            go_cycles = want_cycle - self.cpu.cycles
            self.lgr.debug('reverseMgr setNextCycle did register computed want_cycle as 0x%x go_cycles 0x%x' % (want_cycle, go_cycles))
        else:
            self.cancelSpanCycle(None)
            go_cycles = self.cycle_span
        SIM_event_post_cycle(self.cpu, self.cycle_event, self.cpu, go_cycles, go_cycles)

    def cycle_handler(self, obj, cycles):
        self.latest_cycle = self.cpu.cycles
        eip = self.top.getEIP()
        self.lgr.debug('reverseMgr cycle_handler cycles 0x%x now at 0x%x eip: 0x%x' % (cycles, self.latest_cycle, eip))
        SIM_run_alone(self.cycleHandlerAlone, cycles)

    def cycleHandlerAlone(self, cycles):
        self.latest_cycle = self.cpu.cycles
        eip = self.top.getEIP()
        self.lgr.debug('reverseMgr cycleHandlerAlone cycles now 0x%x at handler were 0x%x eip now 0x%x' % (self.cpu.cycles, self.latest_cycle, eip))
        cycle_mark = 'cycle_%x' % self.latest_cycle 
        SIM_take_snapshot(cycle_mark)
        self.setNextCycle()

    def enableReverse(self):
        print('SIMICS_VER is %s' % self.SIMICS_VER)
        if not self.SIMICS_VER.startswith('7'):
            cmd = 'enable-reverse-execution'
            SIM_run_command(cmd)
        else:
            self.origin_cycle = self.cpu.cycles
            self.lgr.debug('reverseMgr enableReverse starting cycle 0x%x' % self.origin_cycle)
            SIM_take_snapshot('origin')
            # TBD Simics bug?
            SIM_restore_snapshot('origin')
            self.setNextCycle()

    def disableReverse(self):
        if not self.SIMICS_VER.startswith('7'):
            cmd = 'disable-reverse-execution'
            SIM_run_command(cmd)
        else:
            self.cancelSpanCycle(None)
            self.origin_cycle = None
            snap_list = SIM_list_snapshots()
            for snap in snap_list:
                SIM_delete_snapshot(snap)
            self.lgr.debug('reverseMgr deleted %d snapshots' % len(snap_list))

    def reverseEnabled(self):
        if self.origin_cycle is not None:
            self.lgr.debug('reverseMgr reverseEnabled True')
            return True
        else:
            self.lgr.debug('reverseMgr reverseEnabled False')
            return False

    def skipToCycle(self, cycle):
        eip = self.top.getEIP()
        self.lgr.debug('reverseMgr skipToCycle 0x%x from cycle 0x%x eip 0x%x' % (cycle, self.cpu.cycles, eip))
        if self.origin_cycle is None:
            print('Reverse was not enabled')
            return False
        if cycle < self.origin_cycle:
            print('At oldest recorded cycle')
            return False
        current_cycle = self.cpu.cycles
        if current_cycle == cycle:
            print('Already at cycle 0x%x' % cycle)
            return True

        self.cancelSpanCycle(None)

        if self.latest_cycle is None:
            SIM_restore_snapshot('origin')
            self.lgr.debug('reverseMgr skipToCycle no latest cycle, restored origin, now just run to 0x%x' % cycle)
            self.runToCycle(cycle) 
        else:
            if cycle > self.latest_cycle:
                print('Cycle 0x%x is after last recorded cycle of 0x%x, will just run ahead' % (cycle, self.latest_cycle))
                self.runToCycle(cycle)
            else:
                recorded = cycle & self.span_mask
                self.lgr.debug('reverseMgr skipToCycle recorded (after mask) is 0x%x' % recorded)
                if recorded < self.origin_cycle:
                    SIM_restore_snapshot('origin')
                    self.runToCycle(cycle)
                    eip = self.top.getEIP()
                    self.lgr.debug('reverseMgr skipToCycle did restore origin and run forward to cycle 0x%x  cycle now 0x%x eip 0x%x' % (cycle, self.cpu.cycles, eip))
                else:
                    cycle_mark = 'cycle_%x' % recorded
                    SIM_restore_snapshot(cycle_mark)
                    eip = self.top.getEIP()
                    self.lgr.debug('reverseMgr skipToCycle restored 0x%x cycles now 0x%x eip 0x%x' % (recorded, self.cpu.cycles, eip))
                    if recorded != cycle:
                        self.lgr.debug('reverseMgr skipToCycle run to 0x%x' % cycle)
                        self.runToCycle(cycle)
        return True
            
          
    def runToCycle(self, cycle):
        if cycle < self.cpu.cycles:
            self.lgr.error('reverseMgr runToCycle 0x%x less than current 0x%x' % (cycle, self.cpu.cycles))
            return
        elif cycle == self.cpu.cycles:
            self.lgr.debug('reverseMgr runToCycle already at cycle 0x%x' % cycle)
            print('Already at cycle 0x%x' % cycle)
        else:
            #self.disableAll()
            self.setDeltaCycle(cycle)
            self.lgr.debug('reverseMgr runToCycle  0x%x now continue from cpu cycles 0x%x' % (cycle, self.cpu.cycles))
            count = 0
            while self.cpu.cycles != cycle:
                SIM_continue(0)
                self.lgr.debug('reverseMgr runToCycle 0x%x back from continue. Now,  cpu cycles 0x%x' % (cycle, self.cpu.cycles))
                count = count + 1
                if count > 10:
                    self.lgr.error('reverseMgr FIX this')
                    break

    def reverse(self):
        self.cancelSpanCycle(None)
        self.break_cycles = {}
        self.reverse_from = self.cpu.cycles
        self.lgr.debug('reverseMgr reverse from 0x%x' % self.reverse_from)
        cmd = 'bp.list'
        self.bp_list = SIM_run_command(cmd)
        self.bp_list.extend(self.sim_breakpoints)
        if len(self.bp_list) == 0:
            print('Warning reversing without any breakpoints, will hit origin')
            SIM_restore_snapshot('origin')
            self.lgr.debug('reverseMgr reverse without any breakpoints, just restore origin')
            return
        else:
            self.lgr.debug('reverseMgr reverse, bp list %s' % self.bp_list)
            self.tryForwardFrom(self.reverse_from)

    def tryForwardFrom(self, cycle):
        # skip back to previous snapshot and run forward
        self.current_span_end = cycle
        self.current_span_start = (cycle & self.span_mask) 
        if self.current_span_start == cycle:
            self.current_span_start = self.current_span_start - self.cycle_span
        if self.current_span_start < self.origin_cycle:
            self.lgr.debug('reverseMgr tryForwardFrom current_span start was less than origin, set it to origin')
            self.current_span_start = self.origin_cycle
        cycle_mark = 'cycle_%x' % self.current_span_start
        #self.disableAll()
        was_at = self.cpu.cycles
        SIM_restore_snapshot(cycle_mark)
        self.lgr.debug('reverseMgr tryForwardFrom was at 0x%x skipped back to 0x%x' % (was_at, self.current_span_start))
        #self.enableAll()
        self.setBreakHaps()
        self.setSpanCycle()
        self.lgr.debug('reverseMgr tryForwardFrom now continue')
        SIM_continue(0)
        
    def stopHap(self, param, one, exception, error_string):
        '''
        Entered when the cycle_handler hits the end of a span and breaks the simulation.

        If we have hit any breakpoints (per self.break_cycles) then skip to the most recent breakpoint
        and call it done.  Otherwise, skip back to the previous snapshot (span) and run forward again.
        '''
        self.lgr.debug('reverseMgr stopHap')
        if self.stop_hap is None:
            return
        self.lgr.debug('reverseMgr stopHap would do stuff len of break cycles is %d' % len(self.break_cycles))
        for hap in self.break_haps:
            SIM_run_alone(self.rmBreakHap, hap)
        self.break_haps = []
        hap = self.stop_hap
        SIM_run_alone(self.rmStopHap, hap)
        self.stop_hap = None
        SIM_run_alone(self.cancelRevSpanCycle, None)

        if len(self.break_cycles) == 0:
            next_span = self.current_span_start - self.cycle_span - 1
            self.lgr.debug('reverseMgr stopHap Failed to find any breaks, try forward from next span 0x%x' % next_span)
            SIM_run_alone(self.tryForwardFrom, next_span)
        else:
            cycle_list = list(self.break_cycles.keys())
            sorted_list = sorted(cycle_list)
            latest_cycle = sorted_list[-1]
            latest_bp = self.break_cycles[latest_cycle].bp
            self.lgr.debug('reverseMgr stopHap latest cycle 0x%x bp %d' % (latest_cycle, latest_bp))
            SIM_run_alone(self.skipAndCallback, latest_cycle)

    def skipAndCallback(self, latest_cycle):
        self.skipToCycle(latest_cycle)
        if self.callback is None:
            print('Reversing hit breakpoint %d at cycle 0x%x' % (latest_bp, latest_cycle))
            SIM_run_command('disassemble')
        else:
            memory = self.break_cycles[latest_cycle]
            self.callback(memory)
            self.lgr.debug('reverseMgr skipAndCallback done, called callback with memory') 

    def rmBreakHap(self, hap):
        SIM_hap_delete_callback_id('Core_Breakpoint_Memop', hap)

    def cancelRevSpanCycle(self, dumb):
        SIM_event_cancel_time(self.cpu, self.span_cycle_event, self.cpu, None, None)

    def setSpanCycle(self):
        '''
        Set a cycle Hap on the difference in cycles between the current and the current_span_end.

        Intended to be called when we've skipped back to the start of the previous span and now
        with to run forward to see if we hit any breakpoints.
        '''
        delta = self.current_span_end - self.cpu.cycles
        self.lgr.debug('reverseMgr setSpanCycle current_span_end 0x%x  current cycles 0x%x delta 0x%x' % (self.current_span_end, self.cpu.cycles, delta))
        if self.span_cycle_event is None:
            self.span_cycle_event = SIM_register_event("span cycle", SIM_get_class("sim"), Sim_EC_Notsaved, self.span_cycle_handler, None, None, None, None)
        else:
            self.cancelRevSpanCycle(None)
        SIM_event_post_cycle(self.cpu, self.span_cycle_event, self.cpu, delta, delta)

    def span_cycle_handler(self, obj, cycles):
        '''
        Entered after execution of the number of cycles set in setSpanCycle

        We will set a stop hap and break the simulation so that we can assess any breakpoints hit,
        or skip back again to the previous span cycle.
        '''
        self.lgr.debug('reverseMgr span_cycle_handler cpu cycles: 0x%x' % self.cpu.cycles)
        SIM_run_alone(self.spanHandleAlone, None)

    def spanHandleAlone(self, dumb):
        self.stop_hap = SIM_hap_add_callback("Core_Simulation_Stopped", self.stopHap, None)
        self.lgr.debug('span cycle handler cycle: 0x%x' % self.cpu.cycles)
        SIM_break_simulation('span cycle handler')

    def setBreakHaps(self):
        for bp in self.bp_list:
            self.lgr.debug('reverseMgr setBreakHaps set hap for bp %d' % bp)
            the_hap = SIM_hap_add_callback_index('Core_Breakpoint_Memop', self.breakCallback, None, bp)
            self.break_haps.append(the_hap) 

    class BreakInfo():
        def __init__(self, bp, memory):
            self.bp = bp
            self.logical_address = memory.logical_address
            self.physical_address = memory.physical_address

    def breakCallback(self, param, the_obj, the_break, memory):
        if len(self.break_haps) == 0:
            return
        eip = self.top.getEIP()
        instruct = SIM_disassemble_address(self.cpu, eip, 1, 0)
        value = SIM_get_mem_op_value_le(memory)
        self.lgr.debug('reverseMgr breakCallback break num %d memory addr 0x%x value: 0x%x cycles: 0x%x eip:0x%x  instruct %s' % (the_break, memory.logical_address, value, self.cpu.cycles, eip, instruct[1]))
        self.break_cycles[self.cpu.cycles] = self.BreakInfo(the_break, memory)
        #SIM_break_simulation('breakCallback')

    def rmStopHap(self, hap):
        SIM_hap_delete_callback_id("Core_Simulation_Stopped", hap)

    def revOne(self):
        if not self.SIMICS_VER.startswith('7'):
            cli.quiet_run_command('rev 1')
        else:
            cycle = self.cpu.cycles - 1
            self.skipToCycle(cycle)
            SIM_run_command('disassemble')


    def cancelDeltaCycle(self, dumb):
        SIM_event_cancel_time(self.cpu, self.delta_cycle_event, self.cpu, None, None)

    def setDeltaCycle(self, cycles):
        delta = cycles - self.cpu.cycles
        self.lgr.debug('reverseMgr setDeltaCycle delta 0x%x' % delta)
        if self.delta_cycle_event is None:
            self.delta_cycle_event = SIM_register_event("delta cycle", SIM_get_class("sim"), Sim_EC_Notsaved, self.delta_cycle_handler, None, None, None, None)
        else:
            self.cancelDeltaCycle(None)
        SIM_event_post_cycle(self.cpu, self.delta_cycle_event, self.cpu, delta, delta)

    def delta_cycle_handler(self, obj, cycles):
        self.lgr.debug('reverseMgr delta_cycle_handler')
        SIM_run_alone(self.deltaHandleAlone, None)

    def deltaHandleAlone(self, dumb):
        self.stop_hap = SIM_hap_add_callback("Core_Simulation_Stopped", self.deltaStopHap, None)
        SIM_break_simulation('delta cycle handler')

    def deltaStopHap(self, param, one, exception, error_string):
        self.lgr.debug('reverseMgr deltaStopHap')
        if self.stop_hap is None:
            return
        self.lgr.debug('reverseMgr deltaStopHap do what?')
        hap = self.stop_hap
        SIM_run_alone(self.rmStopHap, hap)
        self.stop_hap = None
        #self.enableAll()

    def SIM_breakpoint(self, the_object, the_type, the_mode, the_addr, the_count, the_flags):
        bp = SIM_breakpoint(the_object, the_type, the_mode, the_addr, the_count, the_flags)
        if bp is not None:
            self.sim_breakpoints.append(bp)
        return bp

    def SIM_delete_breakpoint(self, bp):
        SIM_delete_breakpoint(bp)
        if bp is not None:
            if bp in self.sim_breakpoints:
                self.sim_breakpoints.remove(bp)
            else:
                self.lgr.error('reverseMgr SIM_delete_breakpoint %d not in sim_breakpoints')

    # TBD NOT USED
    def disableAll(self):
        for bp in self.bp_list:
            #print('bp is %s' % bp)
            SIM_disable_breakpoint(bp)

    def enableAll(self):
        for bp in self.bp_list:
            #print('bp is %s' % bp)
            SIM_enable_breakpoint(bp)

    def setCallback(self, callback):
        self.callback = callback
