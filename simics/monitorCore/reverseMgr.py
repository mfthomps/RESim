from simics import *
import cli
class ReverseMgr():
    # TBD remove top and references after testing
    def __init__(self, top, cpu, lgr):
        self.cpu = cpu
        self.lgr = lgr
        self.top = top
        self.cycle_span = 0x100000
        self.span_mask = 0xfffffff00000
        self.cycle_event = None
        self.span_cycle_event = None
        self.delta_cycle_event = None
        self.starting_cycle = None
        self.latest_cycle = None
        self.bp_list = []
        self.reverse_from = None
        self.break_haps = []
        self.break_cycles = {}
        self.stop_hap = None

    def cancelSpanCycle(self, dumb):
        SIM_event_cancel_time(self.cpu, self.cycle_event, self.cpu, None, None)

    def setNextCycle(self):
        if self.cycle_event is None:
            self.cycle_event = SIM_register_event("cycle event", SIM_get_class("sim"), Sim_EC_Notsaved, self.cycle_handler, None, None, None, None)
            masked = (self.starting_cycle & self.span_mask) 
            want_cycle = masked + self.cycle_span
            go_cycles = want_cycle - self.cpu.cycles
            self.lgr.debug('reverseMgr setNextCycle did register computed want_cycle as 0x%x go_cycles 0x%x' % (want_cycle, go_cycles))
        else:
            self.cancelSpanCycle(None)
            go_cycles = self.cycle_span
        SIM_event_post_cycle(self.cpu, self.cycle_event, self.cpu, go_cycles, go_cycles)

    def cycle_handler(self, obj, cycles):
        SIM_run_alone(self.cycleHandlerAlone, cycles)

    def cycleHandlerAlone(self, cycles):
        self.latest_cycle = self.cpu.cycles
        self.lgr.debug('reverseMgr cycle_handler cycles 0x%x now at 0x%x' % (cycles, self.latest_cycle))
        cycle_mark = 'cycle_%x' % self.latest_cycle 
        VT_take_snapshot(cycle_mark)
        self.setNextCycle()

    def enableReverse(self):
        self.starting_cycle = self.cpu.cycles
        self.lgr.debug('reverseMgr enableReverse starting cycle 0x%x' % self.starting_cycle)
        VT_take_snapshot('origin')
        self.setNextCycle()

    def skipToCycle(self, cycle):
        if self.starting_cycle is None:
            print('Reverse was not enabled')
            return
        if cycle < self.starting_cycle:
            print('At oldest recorded cycle')
            return
        current_cycle = self.cpu.cycles
        if current_cycle == cycle:
            print('Already at cycle 0x%x' % cycle)
            return

        self.cancelSpanCycle(None)

        if self.latest_cycle is None:
            VT_restore_snapshot('origin')
            self.lgr.debug('reverseMgr skipToCycle no latest cycle, restored origin, now just run to 0x%x' % cycle)
            self.runToCycle(cycle) 
        else:
            if cycle > self.latest_cycle:
                print('Cycle 0x%x is after last recorded cycle of 0x%x, will just run ahead' % (cycle, self.latest_cycle))
                self.runToCycle(cycle)
            else:
                recorded = cycle & self.span_mask
                self.lgr.debug('reverseMgr skipToCycle recorded (after mask) is 0x%x' % recorded)
                if recorded < self.starting_cycle:
                    self.lgr.debug('reverseMgr skipToCycle restore origin and run forward')
                    VT_restore_snapshot('origin')
                    self.runToCycle(cycle)
                else:
                    cycle_mark = 'cycle_%x' % recorded
                    VT_restore_snapshot(cycle_mark)
                    self.lgr.debug('reverseMgr skipToCycle restored 0x%x cycles now 0x%x' % (recorded, self.cpu.cycles))
                    if recorded != cycle:
                        self.lgr.debug('reverseMgr skipToCycle run to 0x%x' % cycle)
                        self.runToCycle(cycle)
            
          
    def runToCycle(self, cycle):
        if cycle < self.cpu.cycles:
            self.lgr.error('reverseMgr runToCycle 0x%x less than current 0x%x' % (cycle, self.cpu.cycles))
            return
        self.disableAll()
        self.setDeltaCycle(cycle)
        self.lgr.debug('reverseMgr runToCycle  0x%x now continue' % cycle)
        SIM_continue(0)

    def disableAll(self):
        for bp in self.bp_list:
            #print('bp is %s' % bp)
            SIM_disable_breakpoint(bp)

    def enableAll(self):
        for bp in self.bp_list:
            #print('bp is %s' % bp)
            SIM_enable_breakpoint(bp)

    def reverse(self):
        self.cancelSpanCycle(None)
        self.reverse_from = self.cpu.cycles
        cmd = 'list-breakpoints'
        self.bp_list = SIM_run_command(cmd)
        if len(self.bp_list) == 0:
            print('Cannot reverse without any breakpoints')
            return
        self.lgr.debug(self.bp_list)
        self.tryForwardFrom(self.reverse_from)

    def tryForwardFrom(self, cycle):
        self.current_span_end = cycle
        self.current_span_start = (cycle & self.span_mask) 
        if self.current_span_start == cycle:
            self.current_span_start = self.current_span_start - self.cycle_span
        cycle_mark = 'cycle_%x' % self.current_span_start
        self.disableAll()
        was_at = self.cpu.cycles
        VT_restore_snapshot(cycle_mark)
        self.lgr.debug('reverseMgr tryForwardFrom was at 0x%x skipped back to 0x%x' % (was_at, self.current_span_start))
        self.enableAll()
        self.setBreakHaps()
        self.setSpanCycle()
        self.lgr.debug('reverseMgr tryForwardFrom now continue')
        SIM_continue(0)
        
    def stopHap(self, param, one, exception, error_string):
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
            latest_bp = self.break_cycles[latest_cycle]
            self.lgr.debug('reverseMgr stopHap latest cycle 0x%x bp %d' % (latest_cycle, latest_bp))
            SIM_run_alone(self.skipToCycle, latest_cycle)
            print('Reversing hit breakpoint %d at cycle 0x%x' % (latest_bp, latest_cycle))
            SIM_run_command('disassemble')

    def rmBreakHap(self, hap):
        SIM_hap_delete_callback_id('Core_Breakpoint_Memop', hap)

    def cancelRevSpanCycle(self, dumb):
        SIM_event_cancel_time(self.cpu, self.span_cycle_event, self.cpu, None, None)

    def setSpanCycle(self):
        delta = self.current_span_end - self.cpu.cycles
        self.lgr.debug('reverseMgr setSpanCycle current_span_end 0x%x  current cycles 0x%x delta 0x%x' % (self.current_span_end, self.cpu.cycles, delta))
        if self.span_cycle_event is None:
            self.span_cycle_event = SIM_register_event("span cycle", SIM_get_class("sim"), Sim_EC_Notsaved, self.span_cycle_handler, None, None, None, None)
        else:
            self.cancelRevSpanCycle(None)
        SIM_event_post_cycle(self.cpu, self.span_cycle_event, self.cpu, delta, delta)

    def span_cycle_handler(self, obj, cycles):
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

    def breakCallback(self, param, the_obj, the_break, memory):
        if len(self.break_haps) == 0:
            return
        eip = self.top.getEIP()
        instruct = SIM_disassemble_address(self.cpu, eip, 1, 0)

        self.lgr.debug('reverseMgr breakCallback break num %d memory 0x%x cycles: 0x%x eip:0x%x  instruct %s' % (the_break, memory.logical_address, self.cpu.cycles, eip, instruct[1]))
        self.break_cycles[self.cpu.cycles] = the_break
        #SIM_break_simulation('breakCallback')

    def rmStopHap(self, hap):
        SIM_hap_delete_callback_id("Core_Simulation_Stopped", hap)

    def revOne(self):
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
        self.enableAll()
