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
Implement a subset of the deprecated Simics reverse execution functions. 
The reversing functions are at least those used by RESim, along with
several CLI commands, e.g., enable-reverse-execution

Supported CLI functions include:
    enable-reverse-execution, will result in recording snapshots cycles for use in reverse and skip to functions
    disable-reverse-execution'
    rev [n] -- where n is cycles to reverse, default is to just reverse.
    skip-to-cycle cycle'

These functions behave in a manner similar to reversing functions available
in Simics 6.  As with Simics 6, reliable reversing requires adherence to some
constraints.  For the reverseMgr, these include:
    -- No Haps should be set while reversing.  See setCallback to simulate a Core_Simulation_Stopped hap
    -- Real networks and other external events should not be present.  
    -- Breakpoints set prior to reverse execution via the Simics SIM_breakpoint API
       must be altered to use the reverseMgr's SIM_breakpoint API.  

The stratgey is simple.  When reverse is enabled, we take in-memory snapshots
periodically (every cycle_span cycles, ensuring each snapshot falls on multiple of the span).
To reverse or skip, we restore snapshots and run forward to hit either
breakpoints or the requested number of cycles.  The choice of the cycle_span
value can have dramatic effects on performance, and should depend on your simulation.

The reverseMgr module could be instantiated for each target CPU (cell), however, only
one should be enabled at any time via enableReverse.   Each instance has a reference
cpu, whose cycles are associated with snapshots.  Breakpoints on any cell will be caught during reverse,
and the simulation will stop at the appropriate breakpoint.  Do not enable reversing on multiple instances.
A single reference cpu is employed to track time (its cycles).

As a convenience to support compatibility between Simics 6 and 7, some of the ReverseMgr functions will 
invoke native Simics reversing functions if running on Simics 6.

The reverseMgr can provide reversing functions on Simics 6 (instead of using native reversing).
This requires some additional logic because memory snapshots in the future are deleted as an effect
of restore-snapshot.

VMP will be disabled when reversing is enabled.

As with old Simics, a reverse that hits a read/write breakpoint will stop following execution of the instruction.
While one that hits an execute breakpoint will stop at the instruction (before execution).

The reverseMgr assumes on cycle per instruction.
'''
from simics import *
import os
import re
import traceback
import cli
import logging
NOUTILS = False
try:
    import resimSimicsUtils
except:
    NOUTILS = True
def getTokenValue(line, token):
    retval = None
    if token in line:
        rest = line.split(token)[1]
        #print('rest is %s' % rest)
        if ',' in rest:
            retval = rest.split(',', 1)[0]
        elif ')' in rest:
            retval = rest.split(')')[0]
        else:
            print('failed to get token value for %s from %s' % (token, line))
    else:
        print('token %s not in line %s' % (token, line))
    return retval

def getObject(line):
    rest = line.split('Object :')[1]
    retval = rest.split()[0]
    return retval

def isPhys(line):
    if ': phys-' in line:
        return True
    else:
        return False

def getBPList():
    ''' return a list of bp.memory breakpoints and pray the do not include SIM_breakpoint items.'''
    cmd = 'bp.list'
    dumb, result = cli.quiet_run_command(cmd)
    retval = []
    for line in result.splitlines():
        #print('line %s' % line)
        if 'bp.memory' in line:
            id_string = line.split('bp.memory')[0]
            id_val = int(id_string[1:-1])
            retval.append(id_val) 
    return retval
# helpers
def bp_type_to_str(t):
    return {
        0: "phys",
        1: "virt",
        2: "linear",
        3: "io"
    }.get(int(t), str(t))

def access_to_str(a):
    a = int(a)
    flags = []
    if a & 1:
        flags.append("R")
    if a & 2:
        flags.append("W")
    if a & 4:
        flags.append("X")
    return "".join(flags) if flags else "-"


def isEnabled(conf, bp):
    retval = False
    index = 0 
    for item in conf.sim.breakpoints:
        if item[0] == bp:
            if item[5]:
                retval = True
    return retval

def genBreakFromNewStyle(bp_values, lgr=None):
    #if lgr is not None:
    #    lgr.debug('genBreakFromNewStyle %s' % bp_values.toString())
    retval = SIM_breakpoint(bp_values.obj, bp_values.type, bp_values.access, bp_values.addr, bp_values.length, 0)
    if lgr is not None:
        lgr.debug('genBreakFromNewStyle got break num %d from %s' % (retval, bp_values.toString()))
    return retval

def transType(op_type):
    retval = 'unknown'
    if op_type == Sim_Trans_Load:
        retval = 'r'
    elif op_type == Sim_Trans_Store:
        retval = 'w'
    elif op_type == Sim_Trans_Instr_Fetch:
        retval = 'x'
    elif op_type == Sim_Trans_Pefetch:
        retval = 'x'
    elif op_type == Sim_Trans_Cache:
        retval = 'x'
    return retval

def getPselect():
    cpu, dumb = cli.quiet_run_command('pselect')
    retval = SIM_get_object(cpu) 
    return retval

def getRegValue(reg, cpu):
    reg_num = cpu.iface.int_register.get_number(reg)
    retval = cpu.iface.int_register.read(reg_num)
    return retval

class NewStyleBPValues():
    '''
    Record the values of a breakpoint created with bp.memory.break for use with SIM_breakpoint
    '''
    #def __init__(self, addr, length, access, obj, phys):
    def __init__(self, break_num):
        self.bp_num = break_num
        cmd = 'bp.show(%d)' % break_num
        line = cli.quiet_run_command(cmd)[1]
        addr = getTokenValue(line, 'addr=')
        length = getTokenValue(line, 'len=')
        access = getTokenValue(line, 'access=')
        obj = getObject(line)
        phys = isPhys(line)
        self.converted_bp_num = None
        self.addr = None
        try:
            self.addr = int(addr, 16)
        except:
            print('Failed to get addr from %s' % addr)
        self.length = int(length)
        self.access = 0
        if 'r' in access: 
            self.access = self.access | Sim_Access_Read
        if 'w' in access: 
            self.access = self.access | Sim_Access_Write
        if 'e' in access: 
            self.access = self.access | Sim_Access_Execute

        self.obj = SIM_get_object(obj)
        if phys:
            self.type = Sim_Break_Physical
        else:
            self.type = Sim_Break_Linear
        if "Enabled : True" in line:
            self.enabled = True
        else:
            self.enabled = False
        if "Oneshot : True" in line:
            self.oneshot = True
        else:
            self.oneshot = False

    def toString(self):
        #print('object %s addr 0x%x len %d access %s type: %d' % (self.obj, self.addr, self.length, self.access, self.type))
        retval = 'object %s addr 0x%x len %d access %s type: %d oneshot %r enabled: %r bp_num %d converted num %s' % (self.obj, self.addr, self.length, self.access, self.type, self.oneshot, self.enabled, self.bp_num, self.converted_bp_num)
        return retval

    def toDisplayString(self, break_info):
        # like: [ubuntu.cell_context] Breakpoint 1: ubuntu.cell_context 'x' access to v:0x80485cf len=4
        v_p = 'v'
        if self.type == Sim_Break_Physical:
            v_p = 'p'
        retval = "Breakpoint %d: %s '%s' access to %s:0x%x len=%d" % (self.bp_num, self.obj, transType(op_type), v_p, self.addr, length)
        return retval

class BPEnabler():
    '''
    Manage disabling and enabling breakpoints so we can skip without hitting them.
    '''
    def __init__(self, conf, sim_bp_list, lgr):
        self.sim_bp_list = sim_bp_list
        self.sim_did_disable = []
        self.newstyle_list = getBPList()            
        self.newstyle_values = []
        self.lgr = lgr
        self.conf = conf
        
        for bp in self.newstyle_list:
            bp_values = NewStyleBPValues(bp)
            self.newstyle_values.append(bp_values)
 
    def disableAll(self):
        #self.lgr.debug('BPEnabler disableAll')
        for bp in self.sim_bp_list:
            if bp in self.newstyle_list:
               # Name overload  TBD 
               print('TBD bp name overload')
            else:
                if isEnabled(self.conf, bp):
                    SIM_disable_breakpoint(bp)
                    self.sim_did_disable.append(bp)
        for bp_values in self.newstyle_values:
            if bp_values.enabled:
                cmd = 'bp.disable %d' % bp_values.bp_num                
                #self.lgr.debug('BPEnabler disable did bp %d' % bp_values.bp_num)
                cli.quiet_run_command(cmd)

    def enableAll(self):
        #self.lgr.debug('BPEnabler enable')
        for bp in self.sim_did_disable:
            SIM_enable_breakpoint(bp)
            #self.lgr.debug('BPEnabler enable did bp %d' % bp)
        for bp_values in self.newstyle_values:
            if bp_values.enabled:
                cmd = 'bp.enable %d' % bp_values.bp_num                
                cli.quiet_run_command(cmd)

class Performance():
    def __init__(self, cpu, sample_rate, do_log, lgr, top=None):
        self.sample_rate = sample_rate
        self.lgr = lgr
        self.do_log = do_log
        self.cpu = cpu
        self.time_stamps = {}
        self.lgr.debug('Performance begin, sample_rate %d do_log %r' % (sample_rate, do_log))

    def spanHit(self, cycle):
        if self.sample_rate == 1 or self.test_cycles > self.sample_rate:
            self.time_stamps[cycle] = time.perf_counter_ns()
            if self.do_log:
                size = self.snapSize()
                self.lgr.debug('reverseMgr cycleHandlerAlone cycles now 0x%x snapshot size %s' % (self.cpu.cycles, f"{size:,}"))
            self.test_cycles = 0
        self.test_cycles = self.test_cycles + 1

    def snapSize(self):
        '''
        Retun the total number of bytes consumed by snapshots
        '''
        retval = 0
        size_list = VT_snapshot_size_used()
        for item in size_list:
            #self.lgr.debug('size item %s' % str(item)) 
            retval = retval + item
        return retval

    def getSizeChanges(self):
        size_list = VT_snapshot_size_used()
        prev_size = None
        retval = {}
        index = 0
        for this_size in size_list:
            if prev_size is None:
                retval[index] = this_size
            else:
                if this_size != prev_size:
                    if abs(this_size - prev_size) > 32000:
                        retval[index] = this_size
            prev_size = this_size 
            index += 1
        return retval

    def showSizeChanges(self):
        size_changes = self.getSizeChanges()
        for index in size_changes:
            print('%d 0x%x' % (index, size_changes[index]))

class ReverseMgr():
    '''
    Initialize the ReverseMgr.

    Parameter conf: The Simics conf object
    Parameter cpu: The cpu that is to create snapshots as time goes by.  Note that memory breakpoints on any cell can be caught
    Parameter lgr: A python logging module
    Parameter top: Optional module that implements a "getEIP" function for debugging
    Parameter span: Optional span value.  Default is 0x100000
             
    '''
    def __init__(self, conf, cpu, arg, int_t, output_modes, lgr, top=None, span=None, force_new=False, report_performance=False):
        self.conf = conf
        self.cpu = cpu
        self.lgr = lgr
        self.top = top
        # we create a snapshot every cycle_span cycles
        #self.cycle_span = 0x100000
        if span is None:
            self.cycle_span = 0x100000
            #self.cycle_span =  0x1000000

        else:
            self.cycle_span = span
        self.force_new = force_new
        self.report_performance = report_performance
        self.output_modes = output_modes
        parts = cli.quiet_run_command('version')
        self.version_string = parts[0][0][2]
        if self.nativeReverse():
            self.lgr.debug('reverseMgr simics version %s native reverse' % (self.version_string))
        else:
            self.lgr.debug('reverseMgr simics version %s reverse cycle_span 0x%x' % (self.version_string, self.cycle_span))
        if self.oldSimics():
            cli.quiet_run_command('enable-unsupported-feature internals')

        # map cell names to cpu's for use if reverse finds break on some other cell
        self.our_cell = cpu.name.split('.')[0]
        #self.cpu_map = {}
        #self.mapCPUsToCell()
        self.cpu_list = self.getTheCPUs()
        # The event handler that takes a snapshot 
        self.cycle_event = None
        # what hapens when we reach the end of the current_span
        self.span_end_cycle_event = None
        self.delta_cycle_event = None
        # the event handler for when we reach the latest_span_end to snapshot and set the next span event
        self.recording_end_cycle_event = None

        # SEE declerations in reset
        self.reset()
        # breakpoints set via SIM_breakpoint
        self.sim_breakpoints = []
     
        self.performance = Performance(cpu, 1, True, self.lgr, None)
        if not self.nativeReverse():
            self.defineCommands(arg, int_t)

    def reset(self):
        # The current_span is the range of cycles over which we will run forward
        # intending to hit and record breakpoints
        self.current_span_start = None
        self.current_span_end = None
        # The latest_span_end is latest recorded snapshot
        self.latest_span_end = None
        self.span_record = {}
        self.callback = None
        # catch passing of cycle_span cycles
        self.origin_cycle = None
        self.recording = False
        # list of breakpoint values at the start of a reverse that were created with the bp.memory.break
        self.bp_values_from_cli = []
        self.disabled_new_style_breaks = []
        self.converted_breaks = []
        self.reverse_from = None
        self.break_haps = []
        self.break_cycles = {}
        self.stop_hap = None
        self.continuation_hap = None
        self.recording_end_event_set = False
        self.reverse_to =  None
        # hack for catching attempts to restore snapshots not net recorded due to runAlone
        self.snapshot_names = []
        self.was_at_reverse_point = False
        self.was_at_origin = False
        self.rev_done_msg = ''
        self.break_index = 0
        self.when_done_skip_index = None
        self.vmp_was_enabled = None

    def getBreakIndex(self):
        retval = self.break_index
        self.break_index += 1
        return retval
        
    def cancelSpanCycle(self):
        '''
        Cancel the event used to record execution of cycle_span cycles during recording
        '''
        if self.cycle_event is not None:
            #self.lgr.debug('reverseMgr cancelSpanCycle')
            SIM_event_cancel_time(self.cpu, self.cycle_event, self.cpu, None, None)
        self.recording = False

    def getMasked(self, cycle):
        ''' Return cycle - (cycle % cycle_span) 
        '''
        mod = cycle % self.cycle_span
        retval = cycle - mod
        return retval

    def setNextCycle(self, dumb=None):
        '''
        Register a cycle event to take a snapshot on reaching the next span during recording
        '''
        self.recording = True
        #self.lgr.debug('reverseMgr setNextCycle') 
        if self.cycle_event is None:
            self.cycle_event = SIM_register_event("reverse cycle event", SIM_get_class("sim"), Sim_EC_Notsaved, self.cycle_handler, None, None, None, None)
            masked = self.getMasked(self.origin_cycle)
            want_cycle = masked + self.cycle_span
            go_cycles = want_cycle - self.cpu.cycles
            #self.lgr.debug('reverseMgr setNextCycle did register computed want_cycle as 0x%x go_cycles 0x%x' % (want_cycle, go_cycles))
        elif self.latest_span_end is None:
            masked = self.getMasked(self.origin_cycle)
            want_cycle = masked + self.cycle_span
            go_cycles = want_cycle - self.cpu.cycles
            #self.lgr.debug('reverseMgr setNextCycle already registered but no latest_span_end, want_cycle as 0x%x go_cycles 0x%x' % (want_cycle, go_cycles))

        elif self.cpu.cycles == self.latest_span_end:
            self.cancelSpanCycle()
            go_cycles = self.cycle_span
            reach = self.cpu.cycles + go_cycles
            #self.lgr.debug('reverseMgr setNextCycle cpu.cycles 0x%x equals latest_span_end, did cancel go cycles will be 0x%x to reach 0x%x' % (self.cpu.cycles, go_cycles, reach))
        elif self.cpu.cycles > self.latest_span_end:
            self.cancelSpanCycle()
            go_cycles = self.cycle_span - (self.cpu.cycles % self.cycle_span)
            #self.lgr.debug('reverseMgr setNextCycle cpu.cycles 0x%x after latest_span_end go 0x%x cycles' % (self.cpu.cycles, go_cycles))
        else:
            # current cycles < latest_span_end
            self.cancelSpanCycle()
            if self.oldSimics():
                self.latest_span_end = self.getMasked(self.cpu.cycles)
                self.lgr.debug('reverseMgr setNextCycle old simics, reverted latest_span_end to 0x%x' % self.latest_span_end)
            want_cycle = self.latest_span_end + self.cycle_span
            go_cycles = want_cycle - self.cpu.cycles
            #self.lgr.debug('reverseMgr setNextCycle cpu.cycles 0x%x prior to latest_span_end go 0x%x cycles' % (self.cpu.cycles, go_cycles))
        SIM_event_post_cycle(self.cpu, self.cycle_event, self.cpu, go_cycles, go_cycles)

    def cycle_handler(self, obj, cycles):
        '''
        Entered when the next span is reached during recording.
        '''
        self.latest_span_end = self.cpu.cycles
        if self.report_performance and self.top is not None:
            eip = self.top.getEIP()
            self.lgr.debug('reverseMgr cycle_handler cycles 0x%x now at 0x%x eip: 0x%x' % (cycles, self.latest_span_end, eip))
        SIM_run_alone(self.cycleHandlerAlone, cycles)

    def takeSnapshot(self, name):
        if not self.version().startswith('7'):
            if self.oldSimics():
                #self.lgr.debug('reverseMgr 6.0.146 take %s' % name)
                cmd = 'save-snapshot %s' % name
                #SIM_run_alone(cli.quiet_run_command, cmd)
                cli.quiet_run_command(cmd)
            else:
                VT_take_snapshot(name)
        else:
            SIM_take_snapshot(name)
        self.snapshot_names.append(name)
        #self.lgr.debug('reverseMgr took snapshot %s' % name)

    def getPreviousName(self, name):
        retval = None
        if not name.startswith('cycle_'):
            self.lgr.error('reverseMgr getPreviousName given %s' % name)
        else:
            cycle_s = name[6:]
            cycle = int(cycle_s, 16)
            prev_cycle = cycle - self.cycle_span 
            retval = 'cycle_%x' % prev_cycle
        return retval

    def atOrigin(self):
        if self.origin_cycle is not None and self.cpu.cycles == self.origin_cycle:
            return True
        else:
            return False

    def restoreSnapshot(self, name, force=False):
        self.lgr.debug('reverseMgr restoreSnapshot %s' % name)
        bp_enabler = BPEnabler(self.conf, self.sim_breakpoints, self.lgr)
        bp_enabler.disableAll()
        #self.disableSimBreaks()
        
        if name == 'origin':
            self.was_at_origin = True
            if self.cpu.cycles == self.origin_cycle and not force:
                self.lgr.debug('reverseMgr restoreSnapshot to origin, already there')
                return
        elif name.startswith('cycle_'):
            want_cycle = int(name[6:], 16)
            if want_cycle == self.origin_cycle:
                #self.lgr.debug('reverseMgr restoreSnapshot %s was origin, rename it' % name)
                name = 'origin'
        if not self.version().startswith('7'):
            if self.oldSimics():
                go_forward = False
                if name.startswith('cycle_'):
                    want_cycle = int(name[6:], 16)
                    if want_cycle > self.cpu.cycles:
                        go_forward = True
                if go_forward:
                    self.lgr.debug('reverseMgr restoreSnapshot %s, is forward, old simics, run there' % name)
                    self.runToCycle(self.cpu, want_cycle)
                else:
                    #self.lgr.debug('reverseMgr 6.0.146 restore %s' % name)
                    cmd = 'restore-snapshot %s' % name
                    #SIM_run_alone(cli.quiet_run_command, cmd)
                    try:
                        cli.quiet_run_command(cmd)
                    except:
                        self.lgr.debug('reverseMgr restoreSnapshot %s race condition?' % name)
                        if name in self.snapshot_names:
                            # assume race due to runAlone
                            snap_list = self.getSnapList()
                            self.lgr.debug('snap_list %s' % str(snap_list))
                            cur_name = name
                            count = 0
                            while True:
                                count = count + 1
                                cur_name = self.getPreviousName(cur_name)
                                self.lgr.debug('reverseMgr restoreSnapshot got cur_name %s' % cur_name)
                                if cur_name is None:
                                    self.lgr.error('reverseMgr restoreSnapshot failed to find any snapshot to use')
                                    break
                                if cur_name in snap_list:
                                    self.lgr.debug('reverseMgr restoreSnapshot would use cur_name %s' % cur_name)
                                    cmd = 'restore-snapshot %s' % cur_name
                                    cli.quiet_run_command(cmd)
                                    self.lgr.debug('reverseMgr restoreSnapshot after restore to previous cycles now 0x%x' % self.cpu.cycles)
                                    cycles = self.cycle_span * count
                                    cmd = 'run-cycles 0x%x' % cycles
                                    cli.quiet_run_command(cmd)
                                    self.lgr.debug('reverseMgr restoreSnapshot took long way to get to cycle 0x%x after running ahead 0x%x cycles' % (self.cpu.cycles, cycles))
                                    break
                                if count > 30:
                                    self.lgr.error('reverseMgr restoreSnapshot, missing %d snapshots???' % count) 
                                    break
                        else:
                            self.lgr.error('reverseMgr restoreSnapshot ask %s, not in recorded names' % name)
 
                                 
            else:
                VT_restore_snapshot(name)
        else:
            
            #cli.quiet_run_command('disable-vmp')
            SIM_restore_snapshot(name)
            #cli.quiet_run_command('enable-vmp')
        #self.enableSimBreaks()
        bp_enabler.enableAll()
        #self.lgr.debug('reverseMgr restoreSnapshot done, cycle now 0x%x wanted %s' % (self.cpu.cycles, name))

    def cycleHandlerAlone(self, cycles):
        if self.latest_span_end != self.cpu.cycles:
            self.lgr.error('reverseMgr cycleHandlerAlone drifted cycles now 0x%x expected 0x%x' % (self.cpu.cycles, self.latest_span_end))
        cycle_mark = 'cycle_%x' % self.latest_span_end 
        self.takeSnapshot(cycle_mark)
        self.span_record[self.latest_span_end] = {}
        for cpu in self.cpu_list:
            self.span_record[self.latest_span_end][cpu] = cpu.cycles
        if self.report_performance:
            self.performance.spanHit(cycles)
        self.setNextCycle()

    def findCycleSpan(self, cpu, cycles):
        ''' Find the span cycles occuring before the given cycles for the given cpu '''
        retval = None
        recorded = self.getMasked(cycles)
        #self.lgr.debug('reverseMgr findCycleSpan for cpu %s cycles 0x%x recorded is 0x%x' % (cpu.name, cycles, recorded))
        if recorded < self.origin_cycle:
            # Are there any recorded cycles for this cpu that are less than the given cycles?
            for loop_cycle in self.span_record:
                self.lgr.debug('findCycleSpan recorded less than origin.  loop_cycle 0x%x, cpu cycles is 0x%x' % (loop_cycle, self.span_record[loop_cycle][cpu]))
                if self.span_record[loop_cycle][cpu] < cycles:
                    retval = loop_cycle
            if retval is None:
                self.lgr.debug('reverseMgr findCycleSpan recorded less than origin and no %s cycles less than cycles.' % cpu.name)
            else:
                self.lgr.debug('reverseMgr findCycleSpan recorded less than origin loop cycle 0x%x has 0x%x cycles for %s and that is less than given cycle' % (loop_cycle, 
                      self.span_record[loop_cycle][cpu], cpu.name))
        elif self.latest_span_end is None:
            # No recorded cycles, just use origin
            self.lgr.debug('reverseMgr findCycleSpan no recorded cycles, just use origin')
            retval = self.origin_cycle 
        elif self.span_record[recorded][cpu] == cycles:
                retval = recorded
        elif self.span_record[recorded][cpu] > cycles:
            # loop backwards to find a cpu cycle less than given
            loop_cycles = recorded
            while self.span_record[loop_cycles][cpu] > cycles and loop_cycles >= self.origin_cycle:
                loop_cycles = loop_cycles - self.cycle_span
                retval = loop_cycles
            #if retval is None:
            #    self.lgr.debug('reverseMgr findCycleSpan recorded cycles for cpu greater than given cycles, looped backward and did not find any less than given.')
            #else:
            #    self.lgr.debug('reverseMgr findCycleSpan recorded cycles for cpu greater than given cycles, looped backward and did found loop_cycles 0x%x with cpu cycles 0x%x' % (retval,
            #       self.span_record[retval][cpu]))
        else:
            # loop forward to find the greatest cpu cycle less than the given
            loop_cycles = recorded
            retval = recorded
            while self.span_record[loop_cycles][cpu] < cycles and loop_cycles != self.latest_span_end:
                retval = loop_cycles
                loop_cycles = loop_cycles + self.cycle_span
            #if retval is None:
            #    self.lgr.error('findCycleSpan recorded cycles for cpu less than given cycles, looped forward and did not find any less than given.')
            #else:
            #    self.lgr.debug('findCycleSpan recorded cycles for cpu less than given cycles, looped forward and did found loop_cycles 0x%x with cpu cycles 0x%x' % (retval,
            #       self.span_record[retval][cpu]))
        return retval
                

    def enableReverse(self, two_step=False):
        '''
        Enable reverse execution.  This should only be called for one instance of reverseMgr at a time.
        '''
        self.lgr.debug('reversMgr enableReverse')
        if self.nativeReverse():
            self.lgr.debug('enableReverse, use native')
            cmd = 'enable-reverse-execution'
            SIM_run_command(cmd)
        elif not self.reverseEnabled():
            self.setContinuationHap()
            self.origin_cycle = self.cpu.cycles
            self.takeSnapshot('origin')
            self.span_record[self.origin_cycle] = {}
            for cpu in self.cpu_list:
                self.span_record[self.origin_cycle][cpu] = cpu.cycles
            self.lgr.debug('reverseMgr enableReverse starting cycle 0x%x' % (self.origin_cycle))
            # TBD Simics bug?  DO NOT RESTORE, or you will disable real-network interfaces
            #self.restoreSnapshot('origin')
            dumb, status = cli.quiet_run_command('disable-vmp')
            if status == 'VMP already disabled.':
                self.vmp_was_enabled = False
            else:
                self.vmp_was_enabled = True

            if two_step:
                # Simics gets confused when restoring memory snapshots.  Doing an immediate restore often avoids
                # that confusion, however it can interere with real networks. Set two_step when calling due to real world cut. 
                self.skipToOrigin(force=True)
                self.lgr.debug('reverseMgr enableReverse did 2-step')
            self.setNextCycle()
        else:
            self.lgr.error('reverseMgr enableReverse, already enabled')


    def parselist(self, the_list):
        retval = []
        for line in the_list.splitlines():
            parts = line.split()
            i = None
            try:
                i = int(parts[0])
            except:
                pass
            if i is not None:
                name = parts[1]
                retval.append(name)
        return retval 

    def oldSimics(self):
        if self.cpu.architecture == 'ppc32' and self.version().startswith('6.0.146'):
            return True
        else:
            return False

    def disableReverse(self):
        '''
        Disable reverse execution and stop recording snapshots.
        '''
        if self.nativeReverse():
            cmd = 'disable-reverse-execution'
            SIM_run_command(cmd)
            self.lgr.debug('disableReverse is native, ran %s' % cmd)
        else:
            self.cancelSpanCycle()
            self.origin_cycle = None
         
            if self.oldSimics():
                snap_list = self.getSnapList()
                self.lgr.debug('disableReverse snap_list %s' % str(snap_list))
                for name in snap_list:
                    if '>' not in name:
                        cmd = 'delete-snapshot %s' % name
                        self.lgr.debug('disableReverse %s' % cmd)
                        SIM_run_command(cmd)
            elif not self.version().startswith('7'):
                snap_list = VT_list_snapshots()
                for snap in snap_list:
                    VT_delete_snapshot(snap)
            else:
                snap_list = SIM_list_snapshots()
                for snap in snap_list:
                    SIM_delete_snapshot(snap)
            self.lgr.debug('reverseMgr disableReverse deleted %d snapshots' % len(snap_list))
            self.rmContinuationHap()
            self.checkVMP()
            self.reset()

    def reverseEnabled(self):
        ''' Return True if reverse execution is enabled on Simics 7 '''
        if self.origin_cycle is not None:
            self.lgr.debug('reverseMgr reverseEnabled True')
            return True
        else:
            self.lgr.debug('reverseMgr reverseEnabled False')
            return False

    def skipToCycleFromCli(self, cycle):
        cpu = getPselect()
        #self.lgr.debug('reverseMgr skipToCycleFromCli cycle 0x%x cpu from pselect is %s' % (cycle, cpu.name))
        self.skipToCycle(cycle, cpu=cpu)

    def skipToCycle(self, cycle, cpu=None):
        '''  
        Skip to a given cycle.   
        Parameter cpu: The cpu.
        Parameter cycle: The cycle to skip to on the cpu
        '''
        if cpu is None:
            self.lgr.debug('reverseMgr skipToCycle cpu was None, using self')
            cpu = self.cpu
        self.lgr.debug('reverseMgr skipToCycle cpu %s cycle 0x%x' % (cpu.name, cycle))
        #if self.top is not None:
        #     eip = self.top.getEIP()
        #     self.lgr.debug('reverseMgr skipToCycle 0x%x from cycle 0x%x eip 0x%x use_cpu: %s' % (our_cycles, self.cpu.cycles, eip, use_cpu.name))
        if self.origin_cycle is None:
            print('Reverse was not enabled')
            self.lgr.debug('reverseMgr skipToCycle Reverse was not enabled')
            return False
        cycle_span = self.findCycleSpan(cpu, cycle)
        if cycle_span is None:
            # cycle prior to origin
            self.lgr.debug('skipToCycle, the cycle span is less than origin')
            self.when_done_skip_index = None
        elif self.span_record[cycle_span][cpu] == cycle:
            self.lgr.debug('skipToCycle, already at the requested cycle')
            self.when_done_skip_index = None
        else:
            # will need to skip to cycle_span and then run forward
            self.cancelSpanCycle()
            cycle_mark = 'cycle_%x' % cycle_span
            self.restoreSnapshot(cycle_mark)
            self.runToCycle(cpu, cycle)
        return True
            
          
    def runToCycle(self, cpu, cycle):
        '''
        Run forward to the given cycle.  Internal only, will disable breakpoints before running forward.  Uses a event hap.
        '''
        if cycle < cpu.cycles:
            self.lgr.error('reverseMgr runToCycle 0x%x less than current 0x%x' % (cycle, cpu.cycles))
            return
        elif cycle == cpu.cycles:
            self.lgr.debug('reverseMgr runToCycle already at cycle 0x%x' % cycle)
            print('Already at cycle 0x%x' % cycle)
        else:
            bp_enabler = BPEnabler(self.conf, self.sim_breakpoints, self.lgr)
            bp_enabler.disableAll()
            #self.disableAll()
            self.setDeltaCycle(cpu, cycle)
            delta = cycle - cpu.cycles
            #self.lgr.debug('reverseMgr runToCycle  0x%x. Now continue from cpu cycles 0x%x delta 0x%x' % (cycle, cpu.cycles, delta))
                
            SIM_continue(0)
            #SIM_continue(delta)
            #self.lgr.debug('reverseMgr runToCycle 0x%x back from continue. Now,  cpu cycles 0x%x' % (cycle, cpu.cycles))

            cmd = 'pselect %s' % cpu.name
            cli.quiet_run_command(cmd)
            if self.rev_done_msg is not None:
                print(self.rev_done_msg)
            SIM_run_command('disassemble')
            #self.enableAll()
            bp_enabler.enableAll()
            self.setNextCycle()
            self.whenDone()
            #self.lgr.debug('reverseMgr runToCycle back from whenDone')
        if self.oldSimics() and self.latest_span_end is not None and self.latest_span_end > cpu.cycles:
            # TBD should be self.cpu?  matter for old simics?
            self.latest_span_end =  self.getMasked(cpu.cycles)
            self.lgr.debug('reverseMgr runToCycle reverted latest_span_end to 0x%x' % self.latest_span_end)

    def rev(self, count):
        self.lgr.debug('rev count is %d' % count)
        if count == 0:
            self.reverse()
        else:
            current = self.cpu.cycles
            reverse_to = current - count
            self.reverse(reverse_to=reverse_to)

    def reverse(self, dumb=None, reverse_to=None, callback=None):
        '''
        Reverse until either a breakpoint is hit, or we hit the origin.  If multiple breakpoionts are set, execution
        is set at the most recent.
        Will return the stop hap if native reversing
        '''
        self.bp_values_from_cli = []
        self.lgr.debug('reverseMgr reverse')
        self.reverse_to =  reverse_to
        self.was_at_origin = False
        # stop hap if native reverse and callback given
        retval = None
        if self.nativeReverse():
            if callback is not None:
                retval = self.top.RES_add_stop_callback(callback, None, your_stop=True)
                
            if self.reverse_to is not None:
                cmd = 'reverse-to cycle=0x%x' % self.reverse_to
                self.lgr.debug('reverseMgr reverse is reverse_to, cmd %s' % cmd)
                SIM_run_command(cmd)
            else:
                SIM_run_command('reverse')
        else:
            if self.origin_cycle is None:
                self.lgr.error('reverseMgr reverse called but reverse is not enabled.')
                return
            if callback is not None:
                self.setCallback(callback)
            self.cancelSpanCycle()
            self.break_cycles = {}
            self.reverse_from = self.cpu.cycles
            self.lgr.debug('reverseMgr reverse from 0x%x' % self.reverse_from)
            if self.reverse_to is not None:
                self.lgr.debug('reverseMgr reverse will reverse to 0x%x' % self.reverse_to)
            newstyle_list = getBPList()            
            self.lgr.debug('reverseMgr reverse bp.memory.break breaks is %s' % str(newstyle_list))
            for bp in newstyle_list:
                self.lgr.debug('reverseMgr reverse get new style values for bp %d' % bp)
                bp_values = NewStyleBPValues(bp)
                self.bp_values_from_cli.append(bp_values)
            
            if len(self.sim_breakpoints) == 0 and len(newstyle_list) == 0 and self.reverse_to is None:
                print('Warning reversing without any breakpoints, will hit origin')
                self.skipToOrigin()
                self.lgr.debug('reverseMgr reverse without any breakpoints, just restore origin')
                return
            else:
                self.lgr.debug('reverseMgr reverse, SIM bp list %s' % str(self.sim_breakpoints))
                self.skipBackAndRunForward(True)
        return retval

    def hasSnapFor(self, cycles):
        cycle_mark = 'cycle_%x' % cycles
        snap_list = self.getSnapList()
        if cycle_mark in snap_list:
            return True
        else:
            return False

    def getLatestSnapCycle(self):
        retval = None
        snap_list = self.getSnapList()
        self.lgr.debug('reverseMgr getLatestSnapCycle snaplist has %d items' % len(snap_list))
        if len(snap_list)>1:
            name = snap_list[-1]
            try:
                retval = int(name[6:], 16)
            except:
                if name != 'origin':
                    self.lgr.error('reverseMgr getLatestSnapCycle failed on name %s' % name)
        return retval

    def skipBackAndRunForward(self, first_skip):
        '''
         Skip back to previous snapshot and run forward to see if we hit a breakpoint.

         Parameter first_skip: If false, we need to skip back two cycle spans.  Otherwise, we just skip back to previous span
        '''
        self.lgr.debug('reverseMgr skipBackAndRunForward first_skip %r, current cycle 0x%x origin_cycle 0x%x' % (first_skip, self.cpu.cycles, self.origin_cycle))
        missing_snapshots = False
        if first_skip:
            # Where do we skip back to before running forward?
            # NOTE for older simics with only cli for snapshots, the runAlones may not be recorded.
            self.current_span_start = self.getMasked(self.cpu.cycles)
            if not self.hasSnapFor(self.current_span_start): 
                self.lgr.debug('reverseMgr skipBackAndRunForward missing current_span_start 0x%x' % self.current_span_start)
                missing_snapshots = True
                recent = self.getLatestSnapCycle() 
                if recent is None:
                    # assume no snaps other than origin
                    self.current_span_start = self.origin_cycle
                    cycle_mark = 'origin'
                    self.lgr.debug('reverseMgr skipBackAndRunForward latest recorded snap is origin,') 
                else:
                    self.lgr.debug('reverseMgr skipBackAndRunForward wanted span start 0x%x, but not recorded, most recent is 0x%x' % (self.current_span_start, recent))
                    self.current_span_start = recent
                    cycle_mark = 'cycle_%x' % self.current_span_start
            # Where should we stop running forward?
            self.current_span_end = self.cpu.cycles
        else:
            # We may or may not be on a span boundary and must go back 2 spans from the boundary
            masked_current = self.getMasked(self.cpu.cycles)
            self.current_span_start = masked_current - (self.cycle_span)
            self.current_span_end = self.current_span_start + self.cycle_span - 1
            self.lgr.debug('reverseMgr skipBackAndRunForward current_span start set to 0x%x, cycle_span 0x%x masked_current was 0x%x' % (self.current_span_start, self.cycle_span, masked_current))
        if not missing_snapshots:
            if self.current_span_start <= self.origin_cycle:
                self.lgr.debug('reverseMgr skipBackAndRunForward current_span start was less than origin, set it to origin')
                self.current_span_start = self.origin_cycle
                cycle_mark = 'origin'
                self.current_span_end = self.current_span_start + self.cycle_span
            else:
                cycle_mark = 'cycle_%x' % self.current_span_start
    
        was_at = self.cpu.cycles
        self.restoreSnapshot(cycle_mark)
        self.lgr.debug('reverseMgr skipBackAndRunForward was at 0x%x restored snapshot %s, cycles now 0x%x (should match current_span_start)' % (was_at, cycle_mark, self.cpu.cycles))
        if self.cpu.cycles != self.current_span_start:
            self.lgr.error('reverseMgr skipBackAndRunForward restored %s but got 0x%x bail' % (cycle_mark, self.cpu.cycles)) 
            return
        if self.reverse_to is not None and self.reverse_to > self.current_span_start:
            delta = self.reverse_to - self.current_span_start
            if delta > self.cycle_span and not missing_snapshots:
                self.lgr.error('reverseMgr skipBackAndRunForward reached reverse_to 0x%x without hitting break, delta would have been 0x%x.' % (self.reverse_to, delta))
                self.skipToCycle(self.reverse_to)
                return

            self.lgr.debug('reverseMgr skipBackAndRunForward reverse_to of 0x%x greater than current span start 0x%x, run forward 0x%x cycles' % (self.reverse_to, 
                           self.current_span_start, delta))
            #self.reverse_to = None
            self.rmContinuationHap()
            bp_enabler = BPEnabler(self.conf, self.sim_breakpoints, self.lgr)
            bp_enabler.disableAll()
            #self.disableSimBreaks()
            expect = self.cpu.cycles + delta
            # TBD running steps vs cycles creates problems.  Where else does SIM_continue fail?
            cmd = 'r 0x%x cycles' % delta
            SIM_run_command(cmd)
            self.lgr.debug('reverseMgr skipBackAndRunForward cmd: %s' % cmd)
            #SIM_continue(delta)
            count = 0
            while self.cpu.cycles < expect:
                eip = self.top.getEIP()
                self.lgr.error('reverseMgr skipBackAndRunForward expected 0x%x but got 0x%x after running forward delta eip 0x%x' % (expect, self.cpu.cycles, eip))
                new_delta = expect - self.cpu.cycles
                #SIM_continue(new_delta)
                cmd = 'run-cycles 0x%x' % new_delta
                SIM_run_command(cmd)
                count = count + 1
                if count > 5:
                    self.lgr.error('reverseMgr skipBackAndRunForward too much, bail')
                    return
            if self.cpu.cycles > expect:
                too_far = self.cpu.cycles - expect
                self.lgr.error('reverseMgr skipBackAndRunForrward ran past the delta by 0x%x cycles, now at 0x%x?' % (too_far, self.cpu.cycles))
                return
            bp_enabler.enableAll()
            #self.enableSimBreaks()
            self.lgr.debug('reverseMgr skipBackAndRunForward ran forward to the reverse_to point so we can set breaks and run from there.  cycles now 0x%x' % self.cpu.cycles)
            self.was_at_reverse_point = True

        if self.current_span_end == self.cpu.cycles:
            self.lgr.debug('reverseMgr skipBackAndRunForward already at current_span_end of 0x%x, now what?' % self.current_span_end)
        else:
            self.lgr.debug('reverseMgr skipBackAndRunForward call setBreakHaps')
            self.setBreakHaps()
            self.setSpanEndCycle()
            self.lgr.debug('reverseMgr skipBackAndRunForward now continue')
            #print('remove this')
            #return
            self.rmContinuationHap()
            SIM_continue(0)
            self.setContinuationHap()
        
    def stopHap(self, param, one, exception, error_string):
        '''
        Entered when the cycle_handler hits the end of a span and breaks the simulation.

        If we have hit any breakpoints (per self.break_cycles) then skip to the most recent breakpoint
        and call it done.  Otherwise, skip back to the previous snapshot (span) and run forward again.
        '''
        self.lgr.debug('reverseMgr stopHap')
        if self.stop_hap is None:
            return
        self.lgr.debug('reverseMgr stopHap len of break cycles is %d current_cycle 0x%x' % (len(self.break_cycles), self.cpu.cycles))
        for hap in self.break_haps:
            SIM_run_alone(self.rmBreakHap, hap)
        self.rmConvertedBreaks()
        self.break_haps = []
        hap = self.stop_hap
        SIM_run_alone(self.rmStopHap, hap)
        self.stop_hap = None
        SIM_run_alone(self.enableDisabledNewStyle, None)

        SIM_run_alone(self.cancelSpanEndCycle, None)

        if len(self.break_cycles) == 0:
            if not self.was_at_reverse_point and not self.was_at_origin:
                self.lgr.debug('reverseMgr stopHap Failed to find any breaks, try forward from span prior to previous span ')
                SIM_run_alone(self.skipBackAndRunForward, False)
            else:
                if self.was_at_reverse_point:
                    self.lgr.debug('reverseMgr stopHap Failed to find any breaks and we ran forward from the reverse_to point')
                else:
                    self.lgr.debug('reverseMgr stopHap Failed to find any breaks and we ran forward from the origin')
                if self.callback is not None:
                    self.callback(0xbababa, None, None, None)
                    self.callback = None
                    self.lgr.debug('reverseMgr stopHap failed to find break, called callback')
                else:
                    if self.reverse_to is not None:
                        SIM_run_alone(self.skipToCycle, self.reverse_to)
                        self.lgr.debug('reverseMgr stopHap failed to find break, no callback, did skip to cycle 0x%x' % self.reverse_to)
                    else:
                        SIM_run_alone(self.skipToOrigin, False)
                        print('Stopped reversing at origin')
                        self.lgr.debug('reverseMgr stopHap failed to find break, no callback, skipped to origin')
                 
        else:
            cycle_list = list(self.break_cycles.keys())
            sorted_list = sorted(cycle_list)
            latest_index = sorted_list[-1]
            latest_break = self.break_cycles[latest_index]
            self.lgr.debug('reverseMgr stopHap latest_index 0x%x bp %d' % (latest_index, latest_break.bp))

            self.rev_done_msg = latest_break.toDisplayString()
            #for converted in self.bp_values_from_cli:
            #    self.lgr.debug('reverseMgr stopHap check converted bp_num %d against %d' % (converted.converted_bp_num, latest_break.bp))
            #    if converted.converted_bp_num == latest_break.bp:
            #        self.rev_done_msg = converted.toDisplayString(latest_break)
            #        self.lgr.debug('reverseMgr stopHap st rev_done_msg to %s' % self.rev_done_msg)
            #        break

            # NOTE latest_index is used to dereference the breakpoint info structure that tells us the cycle we want
            SIM_run_alone(self.skipAndCallback, latest_index)
        self.was_at_reverse_point = False


    def skipAndCallback(self, skip_index):
        '''
        We've run to where we started reversing, recording breaks and see we hit one.  
        Skip back to the given cycle and invoke the callback (if any).  
        NOTE the cell of the breakpoint may not be our cell.
        '''
        break_info = self.break_cycles[skip_index]
        self.lgr.debug('reverseMgr skipAndCallback current reference cpu cycle 0x%x, call skipToCycle for index %d interator_cycles 0x%x on cpu %s' % (self.cpu.cycles, skip_index,
             break_info.initiator_cycles, break_info.initiator_cpu.name))
        self.when_done_skip_index = skip_index
        cycles = break_info.initiator_cycles
        if break_info.op_type & 4:
            # Simics reversing stops on instruction following a read or write
            cycles = cycles - 1
        self.skipToCycle(cycles, cpu=break_info.initiator_cpu)

    def whenDone(self):
        self.lgr.debug('reverseMgr whenDone when_done_skip_index is %s' % self.when_done_skip_index)
        if self.when_done_skip_index is not None:
            self.setNextCycle()
            break_info = self.break_cycles[self.when_done_skip_index]
            self.rmIfOneShot(break_info.bp)
            if self.callback is not None:
                self.callback(break_info, None, None, None)
                self.callback = None
                self.lgr.debug('reverseMgr skipAndCallback done, called callback with memory with size %d' % (break_info.size)) 
            self.when_done_skip_index = None

    def checkVMP(self):
        if self.vmp_was_enabled:
            cli.quiet_run_command('enable-vmp')

    def rmIfOneShot(self, bp):
        self.lgr.debug('reverseMgr rmIfOneShot bp %d len of bp_values_from_cli is %d' % (bp, len(self.bp_values_from_cli)))
        for new_style in self.bp_values_from_cli:
            # TBD handle name conflicts
            self.lgr.debug('reverseMgr rmIfOneShot check new_style converted bp num %s against %d' % (new_style.converted_bp_num, bp))
            if new_style.converted_bp_num == bp: 
                self.lgr.debug('\tmatch %s' % new_style.toString())
                if new_style.oneshot:
                    cmd = 'bp.delete %d' % new_style.bp_num
                    cli.quiet_run_command(cmd)
                    self.lgr.debug('rmIfOneShot removed bp %d' % new_style.bp_num)

    def rmBreakHap(self, hap):
        SIM_hap_delete_callback_id('Core_Breakpoint_Memop', hap)

    def cancelSpanEndCycle(self, dumb):
        # cancel the event at the end of the current_span
        #self.lgr.debug('reverseMgr cancelSpanEndCycle')
        SIM_event_cancel_time(self.cpu, self.span_end_cycle_event, self.cpu, None, None)

    def setSpanEndCycle(self):
        '''
        Set a cycle Hap on the difference in cycles between the current cycle and the current_span_end.

        Intended to be called when we've skipped back to the start of the previous span and now
        with to run forward to see if we hit any breakpoints.
        '''
        delta = self.current_span_end - self.cpu.cycles
        self.lgr.debug('reverseMgr setSpanEndCycle current_span_end 0x%x  current cycles 0x%x delta 0x%x' % (self.current_span_end, self.cpu.cycles, delta))
        if self.span_end_cycle_event is None:
            self.span_end_cycle_event = SIM_register_event("span cycle", SIM_get_class("sim"), Sim_EC_Notsaved, self.span_end_cycle_handler, None, None, None, None)
        else:
            self.cancelSpanEndCycle(None)
        SIM_event_post_cycle(self.cpu, self.span_end_cycle_event, self.cpu, delta, delta)

    def span_end_cycle_handler(self, obj, cycles):
        '''
        Entered after execution of the number of cycles set in setSpanEndCycle

        We will set a stop hap and break the simulation so that we can assess any breakpoints hit,
        or skip back again to the previous span cycle.
        '''
        self.lgr.debug('reverseMgr span_end_cycle_handler cpu cycles: 0x%x' % self.cpu.cycles)
        SIM_run_alone(self.spanHandleAlone, None)

    def spanHandleAlone(self, dumb):
        self.stop_hap = SIM_hap_add_callback("Core_Simulation_Stopped", self.stopHap, None)
        self.lgr.debug('reverseMgr spanHandleAlone cycle: 0x%x set stop hap and stop simulation to assess if we hit breakpoints' % self.cpu.cycles)
        SIM_break_simulation('')

    def setBreakHaps(self):
        '''
        Set haps on all breakpoints so we can record their cycles
        '''
        self.lgr.debug('reverseMgr setBreakHaps') 
        for bp in self.sim_breakpoints:
            self.lgr.debug('reverseMgr setBreakHaps set hap for bp %d' % bp)
            the_hap = SIM_hap_add_callback_index('Core_Breakpoint_Memop', self.breakCallback, None, bp)
            self.lgr.debug('reverseMgr setBreakHaps did set hap on bp %d' % bp)
            self.break_haps.append(the_hap) 
        for new_style in self.bp_values_from_cli: 
            self.lgr.debug('reverseMgr setBreakHaps newstyle %s' % new_style.toString())
            if new_style.enabled:
                the_break = genBreakFromNewStyle(new_style, lgr=self.lgr)
                self.lgr.debug('reverseMgr setBreakHaps new style the_break is %d' % the_break)
                new_style.converted_bp_num = the_break
                self.converted_breaks.append(the_break)
                the_hap = SIM_hap_add_callback_index('Core_Breakpoint_Memop', self.breakCallback, None, the_break)
                self.lgr.debug('reverseMgr setBreakHaps did set hap on bp %d from new style bp %d' % (the_break, new_style.bp_num))
                self.break_haps.append(the_hap) 
                self.lgr.debug('reverseMgr setBreaks will disable new_style %d' % new_style.bp_num)
                cmd = 'bp.disable %d' % new_style.bp_num
                cli.quiet_run_command(cmd)
                self.disabled_new_style_breaks.append(new_style.bp_num)

    class BreakInfo():
        '''
        Internal class used to skip to the point at which a breakpoint occurred.
        '''
        def __init__(self, initiator_cpu, initiator_cycles, the_object, bp, memory, reference_cpu_cycles):
            self.initiator_cpu = initiator_cpu
            self.initiator_cycles = initiator_cycles
            self.the_object = the_object
            self.bp = bp
            self.logical_address = memory.logical_address
            self.physical_address = memory.physical_address
            self.size = memory.size
            self.op_type = SIM_get_mem_op_type(memory)
            self.reference_cpu_cycles = reference_cpu_cycles
        def toDisplayString(self):
            if self.physical_address is not None and self.physical_address != 0:
                v_p = 'p'
                addr = self.physical_address
            else:
                v_p = 'v'
                addr = self.logical_address
            retval = "Breakpoint %d: %s '%s' access to %s:0x%x len=%d" % (self.bp, self.the_object.name, transType(self.op_type), v_p, addr, self.size)
            return retval

    def breakCallback(self, param, the_obj, the_break, memory):
        '''
        HAP invoked when breakpoints are hit while reversing.  We record the cycle for use in identifying
        the most recent hap, from the perspective of the reference cpu, which may not be the initiator. 
        ''' 
        self.lgr.debug('reverseMgr breakCallback object:%s' % str(the_obj)) 
        initiator_cpu = SIM_get_mem_op_initiator(memory)
        if len(self.break_haps) == 0:
            return
        op_type = SIM_get_mem_op_type(memory)
        if op_type in [Sim_Trans_Load, Sim_Trans_Store]:
            break_after = True
        else:
            break_after = False
        if self.top is not None:
            # diagnostics
            eip = self.top.getEIP()
            instruct = SIM_disassemble_address(self.cpu, eip, 1, 0)
            if not NOUTILS:
                op_type_string = resimSimicsUtils.transType(op_type)

                if memory.logical_address == 0 and memory.physical_address is not None:
                    self.lgr.debug('reverseMgr breakCallback break num %d phys memory addr 0x%x cycles: 0x%x eip:0x%x  instruct %s op_type: %s' % (the_break, 
                            memory.physical_address, self.cpu.cycles, eip, instruct[1], op_type_string))
                else:
                    self.lgr.debug('reverseMgr breakCallback break num %d memory addr 0x%x cycles: 0x%x eip:0x%x  instruct %s op_type: %s' % (the_break, 
                            memory.logical_address, self.cpu.cycles, eip, instruct[1], op_type_string))
        #object_cycles = None 
        #object_cell = the_obj.name.split('.')[0]
        #if object_cell != self.our_cell:
        #    if object_cell not in self.cpu_map:
        #        self.lgr.error('reverseMgr breakCallback %s not in cpu map' % object_cell)
        #        return
        #    object_cycles = self.cpu_map[object_cell].cycles
        initiator_cycles = initiator_cpu.cycles
        if break_after:
            initiator_cycles = initiator_cycles + 1
        break_index = self.getBreakIndex()
        eip = getRegValue('eip', initiator_cpu)
        instruct = SIM_disassemble_address(initiator_cpu, eip, 1, 0)
        self.break_cycles[break_index] = self.BreakInfo(initiator_cpu, initiator_cycles, the_obj, the_break, memory, self.cpu.cycles)
        self.lgr.debug('reverseMgr breakCallback added break_cycles entry for index %d  op_type %d initiator_cycles 0x%x break_after %r eip: 0x%x %s' % (break_index, 
           op_type, initiator_cycles, break_after, eip, instruct[1]))
        #if the_break in self.bp_cli_list:
        #    self.lgr.debug('reverseMgr breakCallback from bp.memory.break breakpoint.  need to continue.  add a stop hap and...')
        #    print('reverseMgr breakCallback from bp.memory.break breakpoint.  need to continue.  add a stop hap and...')
        #    SIM_run_alone(self.addCliStopHap, None)

    def addCliStopHap(self, dumb):
        ''' 
        Used with bp.memory.break breakpoints so we can keep going.
        '''
        self.stop_hap = SIM_hap_add_callback("Core_Simulation_Stopped", self.cliStopHap, None)

    def cliStopHap(self, param, one, exception, error_string):
        ''' 
        Hit when a bp.memory.break causes Simics to stop (even though there is a HAP!)
        '''
        self.lgr.debug('cliStopHap')
        hap = self.stop_hap
        SIM_run_alone(self.rmStopHap, hap)
        self.stop_hap = None
        SIM_run_alone(SIM_continue, 0)

    def rmStopHap(self, hap):
        ''' Remove a stop hap.  Intended to be called from SIM_run_alone '''
        SIM_hap_delete_callback_id("Core_Simulation_Stopped", hap)

    def revOne(self):
        ''' Reverse a single cycle '''
        if self.nativeReverse():
            cli.quiet_run_command('rev 1')
        else:
            cpu = getPselect()
            cycle = cpu.cycles - 1
            self.skipToCycle(cycle, cpu=cpu)
            # TBD move to when done
            SIM_run_command('disassemble')

    def cancelDeltaCycle(self, use_cpu):
        SIM_event_cancel_time(use_cpu, self.delta_cycle_event, use_cpu, None, None)

    def setDeltaCycle(self, use_cpu, cycles):
        '''
        Used by runToCycle to enter a hap when cycles have been executed.
        '''
        delta = cycles - use_cpu.cycles
        self.lgr.debug('reverseMgr setDeltaCycle delta 0x%x' % delta)
        if self.delta_cycle_event is None:
            self.delta_cycle_event = SIM_register_event("delta cycle", SIM_get_class("sim"), Sim_EC_Notsaved, self.delta_cycle_handler, None, None, None, None)
        else:
            self.cancelDeltaCycle(use_cpu)
        SIM_event_post_cycle(use_cpu, self.delta_cycle_event, use_cpu, delta, delta)

    def delta_cycle_handler(self, obj, cycles):
        self.lgr.debug('reverseMgr delta_cycle_handler')
        SIM_run_alone(self.deltaHandleAlone, None)

    def deltaHandleAlone(self, dumb):
        self.stop_hap = SIM_hap_add_callback("Core_Simulation_Stopped", self.deltaStopHap, None)
        #SIM_break_simulation('Cycle now 0x%x' % self.cpu.cycles)
        SIM_break_simulation('Done')

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
        self.lgr.debug('reverseMgr set SIM_breakpoint %d' % bp)
        if bp is not None:
            self.sim_breakpoints.append(bp)
        return bp

    def SIM_delete_breakpoint(self, bp):
        SIM_delete_breakpoint(bp)
        if bp is not None:
            if bp in self.sim_breakpoints:
                self.sim_breakpoints.remove(bp)
                self.lgr.debug('reverseMgr SIM_delete_breakpoint removed %d from sim_breakpoints' % bp)
            else:
                self.lgr.error('reverseMgr SIM_delete_breakpoint %d not in sim_breakpoints')

    def disableSimBreaks(self):
        for bp in self.sim_breakpoints:
            SIM_disable_breakpoint(bp)

    def enableSimBreaks(self):
        for bp in self.sim_breakpoints:
            SIM_enable_breakpoint(bp)

    def setCallback(self, callback):
        '''
        Set a callback to be invoked after reverse finds a breakpoint.  The calling convention of the 
        callback should match a Core_Simulation_Stopped HAP.  Use this instead of setting a stop hap.
        The user parameter passed to the callback will be the memory value from the breakpoint hap.
        Use that to determine if your HAP is called by this module, or by Simics 6. 
        '''
        self.callback = callback

    def cancelRecordingEndCycle(self, dumb):
        SIM_event_cancel_time(self.cpu, self.recording_end_cycle_event, self.cpu, None, None)
        #self.lgr.debug('reverseMgr cancelRecordingEndCycle')
        self.recording_end_event_set = False

    def setRecordingEndCycle(self):
        '''
        Set a cycle Hap on the difference in cycles between the current and the latest_span_end

        Intended to be called when from a continuation hap when we are not recording or reversing/skipping
        '''
        if self.latest_span_end is not None:
            delta = self.latest_span_end - self.cpu.cycles
            if delta > 0:
                self.lgr.debug('reverseMgr setRecordingEndCycle  latest_span_end 0x%x  current cycles 0x%x delta 0x%x' % (self.latest_span_end, self.cpu.cycles, delta))
                if self.recording_end_cycle_event is None:
                    self.recording_end_cycle_event = SIM_register_event("recording end cycle", SIM_get_class("sim"), Sim_EC_Notsaved, self.recording_end_cycle_handler, None, None, None, None)
                else:
                    self.cancelRecordingEndCycle(None)
                SIM_event_post_cycle(self.cpu, self.recording_end_cycle_event, self.cpu, delta, delta)
                self.recording_end_event_set = True
            else:
                self.lgr.debug('reverseMgr setRecordingEndCycle  latest_span_end 0x%x  current cycles 0x%x match, just setNext cycle' % (self.latest_span_end, self.cpu.cycles))
                self.setNextCycle()
        else:
            self.lgr.debug('reverseMgr setRecordingEndCycle  NO latest span end. current cycles 0x%x, just setNext cycle' % (self.cpu.cycles))
            self.setNextCycle()

    def recording_end_cycle_handler(self, obj, cycles):
        '''
        Entered after execution of the number of cycles set in setRecordingEndCycle
        Will restart catching span cycle
        '''
        self.lgr.debug('reverseMgr recording_end_cycle_handler cpu cycles: 0x%x' % self.cpu.cycles)
        SIM_run_alone(self.setNextCycle, None)

    def rmContinuationHap(self):
        self.lgr.debug('reverseMgr rmContinuationHapAlone') 
        if self.continuation_hap is not None:
            hap = self.continuation_hap
            self.rmContinuationHapAlone(hap)
            self.continuation_hap = None

    def rmContinuationHapAlone (self, hap):
        self.lgr.debug('reverseMgr rmContinuationHapAlone %s' % hap)
        SIM_hap_delete_callback_id("Core_Continuation", hap)

    def setContinuationHap(self):
        '''
        Catch a continue so that we can record snapshots as we move past the latest span.
        '''
        self.lgr.debug('reverseMgr setContinuationHap, currrent cycle 0x%x' % self.cpu.cycles)
        self.continuation_hap = SIM_hap_add_callback("Core_Continuation", self.continuationHap, None)

    def continuationHap(self, dumb, one):
        '''
        Restart recording of snapshots if needed.
        '''
        if not self.recording_end_event_set:
            #self.lgr.debug('reverseMgr continuationHap cycles: 0x%x' % self.cpu.cycles)
            if not self.recording:
                #self.lgr.debug('reverseMgr continuationHap not recording, set recording end')
                self.setRecordingEndCycle()
            else:
                #self.lgr.debug('reverseMgr continuationHap am recording')
                pass
        else:
            #self.lgr.debug('reverseMgr continuationHap but recording_end_event_set')
            pass

    def getSpan(self):
        '''
        Return the cycle span
        '''
        return self.cycle_span

    def skipToOrigin(self, force=False):
        self.lgr.debug('reverseMgr skipToOrigin')
        self.restoreSnapshot('origin', force=force)
        if self.oldSimics():
            self.latest_span_end = None

    def reverseTo(self, cycle):
        '''
        Reverse to given cycle or breakpoint hit.
        '''
        self.lgr.debug('reverseMgr reverseTo cycle 0x%x' % cycle)
        self.reverse(reverse_to=cycle)

    def nativeReverse(self):
        ''' Does Simics itself support reversing? '''
        #TBD remove this
        #return False
        if not self.version().startswith('7') and not self.force_new:
           if self.oldSimics():
               return False
               #return True
           else:
               return True
        else:
           return False

    #def mapCPUsToCell(self):
    #    '''
    #    Populate the cpu map for use when the most recent breakpoint is not tied to our cell.
    #    Call this if cells are added or removed.
    #    '''
    #    for cell in self.conf.sim.cell_list:
    #        object_cell = cell.name.split('.')[0]
    #        self.lgr.debug('reverseMgr mapCPUsToCell cell %s' % object_cell)
    #        cmd = '%s.get-processor-list' % object_cell
    #        proclist = SIM_run_command(cmd)
    #        cpu = SIM_get_object(proclist[0])
    #        self.cpu_map[object_cell] = cpu
    def getTheCPUs(self):
        retval = []
        for cell in self.conf.sim.cell_list:
            object_cell = cell.name.split('.')[0]
            cmd = '%s.get-processor-list' % object_cell
            proclist = SIM_run_command(cmd)
            for cpu_name in proclist:
                cpu = SIM_get_object(cpu_name)
                retval.append(cpu)
        return retval

    def version(self):
        return self.version_string

    def getSnapList(self):
        if not self.version().startswith('7'):
            raw_list = cli.quiet_run_command('list-snapshots')[1]
            retval = self.parselist(raw_list)
        else:
            retval = SIM_list_snapshots()
            retval.sort()
        return retval

    def showSnapLen(self):
        snap_list = self.getSnapList()
        print('reverseManager has %d items in snap_list' % len(snap_list))

    def enableDisabledNewStyle(self, dumb):
        self.lgr.debug('enableDisabledNewStyle')
        for bp in self.disabled_new_style_breaks:
            cmd = 'bp.enable %d' % bp
            try:
                cli.quiet_run_command(cmd)
            except:
                # race condition
                pass

    def rmConvertedBreaks(self):
        for bp in self.converted_breaks:
            self.lgr.debug('rmConvertedBreaks removing break %d' % bp)
            SIM_delete_breakpoint(bp)
        self.converted_breaks = []

    def showSizeChanges(self):
        self.performance.showSizeChanges()

    def defineCommands(self, arg, int_t):
        cli.new_command(
            "enable-reverse-execution",
            self.enableReverse,
            [],
            short="Enable reverse execution",
            doc="""
           Enable reverse execution.
        """
        )
        cli.new_command(
            "disable-reverse-execution",
            self.disableReverse,
            [],
            short="Disable reverse execution",
            doc="""
           Disable reverse execution.
        """
        )
        cli.new_command(
            "rev",
            self.rev,
            [arg(int_t, 'steps', "?", 0)],
            short="Reverse [N] steps",
            doc="""
           Reverse.  If the optional N is provided, it will reverse that number of steps.
        """
        )
        cli.new_command(
            "skip-to-cycle",
            self.skipToCycleFromCli,
            [arg(int_t, 'cycle', "1")],
            short="Skip to the given cycle",
            doc="""
           Skip to the given cycle value.  The reverse manager assumes 1 cycle per instruction.
        """
        )
        cli.new_command(
            "list-all-breakpoints",
            self.listSimBreakpoints,
            [],
            short="List all breakpoints made via SIM_breakpoint calls",
            doc="""
               List all breakpoints made via SIM_breakpoint calls.
        """
        )
    def listSimBreakpoints(self):
            # Thanks Nick!
            # Parse bp.list   
            mem_addrs = set()
            #print('why am i here?')    
            #traceback.print_stack()
            try:
                result = cli.quiet_run_command( "bp.list", self.output_modes.formatted_text )
        
                # result = ([ids], formatted_string)
                txt = result[1] if isinstance(result, tuple) else str(result)
        
                # Extract ALL addr occurrences 
                for m in re.finditer(r"addr=0x([0-9a-fA-F]+)", txt):
                    mem_addrs.add(int(m.group(1), 16))
        
            except Exception as e:
                print("WARNING: bp.list parsing failed:", e)
        
            # iterate internal breakpoint table
            bps = self.conf.sim.breakpoints
            if len(bps) > 0: 
                print(
                    f"{'TYPE':<7} {'ACC':<4} {'ACT':<4} "
                    f"{'START':<18} {'END':<18} {'SIZE':<10} {'KIND':<6} "
                    f"{'ORIGIN':<18} {'OBJECT':<30} {'HANDLE'}"
                )
                print("-" * 150)
        
            # main loop
            for bp in bps:
                try:
                    bp_type = int(bp[1])
                    access  = int(bp[2])
                    active  = int(bp[5])
        
                    obj_field = bp[11]
                    handles   = bp[12]
        
                    # object resolution (string or object)
                    if isinstance(obj_field, str):
                        obj = getattr(self.conf, obj_field)
                        obj_name = obj_field
                    else:
                        obj = obj_field
                        obj_name = obj.name
        
                except Exception:
                    continue
        
                for h in handles:
                    try:
                        h_val = int(h)
        
                        bpx = obj.iface.breakpoint.get_breakpoint(h_val)
        
                        start = int(bpx.start)
                        end   = int(bpx.end)
        
                        size = end - start + 1
        
                        kind = "single" if start == end else "range"
        
                        origin = "bp.memory.break" if start in mem_addrs else "Other"
        
                        print(
                            f"{bp_type_to_str(bp_type):<7} "
                            f"{access_to_str(access):<4} "
                            f"{active:<4} "
                            f"{f'0x{start:016x}':<18} "
                            f"{f'0x{end:016x}':<18} "
                            f"{f'0x{size:x}':<10} "
                            f"{kind:<6} "
                            f"{origin:<18} "
                            f"{obj_name:<30} "
                            f"{h_val}"
                        )
        
                    except Exception:
        
                        continue
                
#Everything below is for use running directly from the Simics command prompt, e.g., for testing.
#Typically this module would be instantiated from some other Python module.
#

def getLogger(name, logdir, level=None):
    os.umask(000)
    try:
        os.makedirs(logdir)
    except:
        pass

    log_level = logging.DEBUG
    lgr = logging.getLogger(name)
    lgr.setLevel(log_level)
    fh = logging.FileHandler(logdir+'/%s.log' % name)
    fh.setLevel(log_level)
    frmt = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
    fh.setFormatter(frmt)
    lgr.addHandler(fh)
    lgr.info('Start of log from %s.py' % name)
    ch = logging.StreamHandler()
    ch.setLevel(logging.ERROR)
    ch.setFormatter(frmt)
    lgr.addHandler(ch)
    return lgr

def getCPU(conf):
    #cell = conf.sim.cell_list[0]
    #object_cell = cell.name.split('.')[0]
    #print('Loading ReverseMgr module for cell %s' % object_cell)
    #cmd = '%s.get-processor-list' % object_cell
    #proclist = SIM_run_command(cmd)
    #cpu = SIM_get_object(proclist[0])
    pselect_out = cli.quiet_run_command('pselect')[1]
    pselect = pselect_out.strip()[1:-1] 
    cpu = SIM_get_object(pselect)
    return cpu

if __name__ == '__main__':
    lgr = getLogger('reverseMgr', '/tmp/')
    cpu = getCPU(conf)
    spanenv = os.getenv('REVERSE_SPAN')
    if spanenv is not None:
        span = int(spanenv, 16)
    else:
        span = 0x1000000
    rev = ReverseMgr(conf, cpu, arg, int_t, output_modes, lgr, force_new=True, span=span, report_performance=True)
    print('ReverseMgr module loaded.  You may now use reversing commands including:')
    print('\tenable-reverse-execution, will result in Recording snapshots cycles on cpu %s every 0x%x cycles' % (cpu.name, span))
    print('\tdisable-reverse-execution')
    print('\trev [n] -- where n is cycles to reverse, default is to just reverse.')
    print('\tskip-to-cycle cycle')
    print('Logging to  /tmp/reverseMgr.log')

