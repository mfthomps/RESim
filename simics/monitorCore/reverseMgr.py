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
The reversing functions are at least those used by RESim.

Supported functions include:
    skipToCycle -- skip to any cycle within the recording span.
    reverse -- reverse execution and break per whatever breakpoints are set.

These functions behave in a manner similar to reversing functions available
in Simics 6.  As with Simics 6, reliable reversing requires adherence to some
constraints.  For the reverseMgr, these include:
    -- No Haps should be set while reversing.  See setCallback to simulate a Core_Simulation_Stopped hap
    -- Real networks and other external events should not be present.  
    -- Breakpoints set prior to reverse execution via the SIM_breakpoint API
       must be altered to use the reverseMgr's SIM_breakpoint API.  
       Do not use both SIM_breakpoint and bp.manager to set breakpoints.  Their
       returned values are not exclusive, so use one or the other.
    -- Breakpoints set prior to reverse execution are all enabled following a reverse,
       regardless of their state at the start of the reverse.  (This can be fixed with a bit of work.)

The stratgey is simple.  When reverse is enabled, we take in-memory snapshots
periodically (every cycle_span cycles, ensuring each snapshot falls on multiple of the span).
To reverse or skip, we restore snapshots and run forward to hit either
breakpoints or the requested number of cycles.

The reverseMgr module could be instantiated for each target CPU (cell), however, only
one should be enabled at any time via enableReverse.   Breakpoints on any cell will be caught during reverse,
and the simulation will stop at the appropriate breakpoint.
The choice of active CPU may not matter much, it is used to record the passing of cycles.  
Do not enable reversing on multiple instances.

As a convenience to support compatibility between Simics 6 and 7, some of the ReverseMgr functions will 
invoke native Simics reversing functions if running on Simics 6.

The reverseMgr can provide reversing functions on Simics 6 (instead of using native reverseing).
This requires some additional logic because memory snapshots in the future are deleted as an effect
of restore-snapshot.
 
'''
from simics import *
import os
import cli
import logging
import resimSimicsUtils
class ReverseMgr():
    '''
    Initialize the ReverseMgr.

    Parameter conf: The Simics conf object
    Parameter cpu: The cpu that is to create snapshots as time goes by.  Note that memory breakpoints on any cell can be caught
    Parameter lgr: A python logging module
    Parameter top: Optional module that implements a "getEIP" function for debugging
    Parameter span: Optional span value.  Default is 0x100000
             
    '''
    def __init__(self, conf, cpu, lgr, top=None, span=None):
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
        parts = cli.quiet_run_command('version')
        self.version_string = parts[0][0][2]
        self.lgr.debug('reverseMgr simics version %s' % self.version_string)
        if self.oldSimics():
            cli.quiet_run_command('enable-unsupported-feature internals')

        # map cell names to cpu's for use if reverse finds break on some other cell
        self.our_cell = cpu.name.split('.')[0]
        self.cpu_map = {}
        self.mapCPUsToCell()
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


    def reset(self):
        # The current_span is the range of cycles over which we will run forward
        # intending to hit and record breakpoints
        self.current_span_start = None
        self.current_span_end = None
        # The latest_span_end is latest recorded snapshot
        self.latest_span_end = None
        self.callback = None
        # catch passing of cycle_span cycles
        self.origin_cycle = None
        self.recording = False
        # list of breakpoints at the start of a reverse
        self.bp_list = []
        # list of breakpoints at the start of a reverse that were created with the bp.memory.break
        self.bp_cli_list = []
        self.reverse_from = None
        self.break_haps = []
        self.break_cycles = {}
        self.stop_hap = None
        self.continuation_hap = None
        self.recording_end_event_set = False
        self.reverse_to =  None
        # for debugging storage/performance
        self.test_cycles = 0
        # hack for catching attempts to restore snapshots not net recorded due to runAlone
        self.snapshot_names = []
        self.was_at_reverse_point = False
        self.was_at_origin = False

    def cancelSpanCycle(self):
        '''
        Cancel the event used to record execution of cycle_span cycles during recording
        '''
        if self.cycle_event is not None:
            self.lgr.debug('reverseMgr cancelSpanCycle')
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
        if self.top is not None:
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
        self.lgr.debug('reverseMgr took snapshot %s' % name)

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

    def restoreSnapshot(self, name):
        self.disableSimBreaks()
        if name == 'origin':
            self.was_at_origin = True
            if self.cpu.cycles == self.origin_cycle:
                self.lgr.debug('restoreSnapshot to origin, already there')
                return
        if not self.version().startswith('7'):
            if self.oldSimics():
                go_forward = False
                if name.startswith('cycle_'):
                    want_cycle = int(name[6:], 16)
                    if want_cycle > self.cpu.cycles:
                        go_forward = True
                if go_forward:
                    self.lgr.debug('reverseMgr restoreSnapshot %s, is forward, old simics, run there' % name)
                    self.runToCycle(want_cycle)
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
            SIM_restore_snapshot(name)
        self.enableSimBreaks()
        #self.lgr.debug('reverseMgr restoreSnapshot done, cycle now 0x%x wanted %s' % (self.cpu.cycles, name))

    def cycleHandlerAlone(self, cycles):
        if self.latest_span_end != self.cpu.cycles:
            self.lgr.error('reverseMgr cycleHandlerAlone drifted cycles now 0x%x expected 0x%x' % (self.cpu.cycles, self.latest_span_end))
        cycle_mark = 'cycle_%x' % self.latest_span_end 
        self.takeSnapshot(cycle_mark)
        if self.top is not None and self.test_cycles > 100:
            eip = self.top.getEIP()
            size = self.snapSize()
            self.lgr.debug('reverseMgr cycleHandlerAlone cycles now 0x%x at handler were 0x%x eip now 0x%x snapshot size %s' % (self.cpu.cycles, self.latest_span_end, eip, f"{size:,}"))
            self.test_cycles = 0
        self.test_cycles = self.test_cycles + 1
        self.setNextCycle()

    def snapSize(self):
        '''
        Retun the number of bytes consumed by snapshots
        '''
        retval = 0
        if self.oldSimics():
            pass
        else:
            size_list = VT_snapshot_size_used()
            for item in size_list:
                #self.lgr.debug('size item %s' % str(item)) 
                retval = retval + item
        return retval

    def enableReverse(self, two_step=False):
        '''
        Enable reverse execution.  This should only be called for one instance of reverseMgr at a time.
        '''
        self.lgr.debug('reversMgr enableReverse')
        if self.nativeReverse():
            cmd = 'enable-reverse-execution'
            SIM_run_command(cmd)
        elif not self.reverseEnabled():
            self.setContinuationHap()
            self.origin_cycle = self.cpu.cycles
            self.takeSnapshot('origin')
            size = self.snapSize()
            self.lgr.debug('reverseMgr enableReverse starting cycle 0x%x snapshot memory size 0x%x' % (self.origin_cycle, size))
            # TBD Simics bug?  DO NOT RESTORE, or you will disable real-network interfaces
            #self.restoreSnapshot('origin')
            if two_step:
                # Simics gets confused when restoring memory snapshots.  Doing an immediate restore often avoids
                # that confusion, however it can interere with real networks. Set two_step when calling due to real world cut. 
                self.skipToOrigin()
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
            self.reset()

    def reverseEnabled(self):
        ''' Return True if reverse execution is enabled on Simics 7 '''
        if self.origin_cycle is not None:
            self.lgr.debug('reverseMgr reverseEnabled True')
            return True
        else:
            self.lgr.debug('reverseMgr reverseEnabled False')
            return False

    def skipToCycle(self, our_cycles, use_cell=None, object_cycles=None):
        '''  
        Skip to a given cycle.   
        Parameter our_cycles: cycle on this cpu to skip to, unless use_cell is set as per below.
        Parameter use_cell: Not intended for external use.  Names a sell other than the cell of this cpu.
        Parameter object_cycles: The cycles on the use_cell cpu to be skipped to.

        The use_cell / object_cycles are intended for use internal to the module for skipping to the cycle
        of the most recent breakpoint when that breakpoint is not on our cell.  In such a case, the ReverseMgr
        will restore the span prior to our_cycles and then run forward to the object_cycles on the use_cell.
        NOTE: TBD not fully implemented for case where object_cycles is less than the previous span cycle.
        '''
        if self.top is not None:
             eip = self.top.getEIP()
             self.lgr.debug('reverseMgr skipToCycle 0x%x from cycle 0x%x eip 0x%x use_cell: %s' % (our_cycles, self.cpu.cycles, eip, use_cell))
        if self.origin_cycle is None:
            print('Reverse was not enabled')
            self.lgr.debug('reverseMgr skipToCycle Reverse was not enabled')
            return False
        if our_cycles < self.origin_cycle:
            print('At oldest recorded cycle')
            self.lgr.debug('reverseMgr At oldest recorded cycle')
            return False
        current_cycle = self.cpu.cycles
        if use_cell is None:
            if current_cycle == our_cycles:
                print('Already at cycle 0x%x' % current_cycle)
                self.lgr.debug('reverseMgr skipToCycle Already at cycle 0x%x' % current_cycle)
                return True
            object_cycles = our_cycles
        else:
            current_cycle == self.cpu_map[use_cell].cycles
            if object_cycles == current_cycle:
                print('Already at cycle 0x%x on cell %s' % (current_cycle, use_cell))
                self.lgr.debug('reverseMgr skipToCycle Already at cycle 0x%x on cell %s' % (current_cycle, use_cell))
                return True

        self.cancelSpanCycle()

        if self.latest_span_end is None:
            #self.lgr.error('reverseMgr skipToCycle, have not yet hit a single span.  Consider reducing the cycle span in reverseMgr.py.')
            self.skipToOrigin()
            if use_cell is None:
                self.lgr.debug('reverseMgr skipToCycle no latest cycle, restored origin 0x%x, now run to 0x%x' % (self.cpu.cycles, object_cycles))
            else:
                self.lgr.debug('reverseMgr skipToCycle no latest cycle, restored origin 0x%x on our cell, which is 0x%x on different cell %s, now run to 0x%x' % (self.cpu.cycles, 
                     current_cycle, use_cell,  object_cycles))
            self.runToCycle(object_cycles, use_cell=use_cell)
        else:
            if self.oldSimics() and our_cycles > current_cycle:
                self.lgr.debug('reverseMgr skipToCycle old simics, want cycle in future, just run to it')
                self.runToCycle(object_cycles, use_cell=use_cell)
            elif our_cycles > self.latest_span_end:
                #print('Cycle 0x%x is after last recorded cycle of 0x%x, will just run ahead' % (cycle, self.latest_span_end))
                self.lgr.debug('reverseMgr skipToCycle Cycle 0x%x is after last recorded cycle of 0x%x, will skip there and then run ahead' % (our_cycles, self.latest_span_end))

                missing_snapshots = False
                if not self.hasSnapFor(self.latest_span_end):
                    missing_snapshots = True
                    latest = self.getLatestSnapCycle()
                    if latest is not None:
                        cycle_mark = 'cycle_%x' % self.getLatestSnapCycle() 
                        self.lgr.debug('reverseMgr skipToCycle was missing, latest cycle mark %s' % cycle_mark)
                    else:
                        self.lgr.debug('reverseMgr skipToCycle was missing, latest cycle was none, set to latest_span_end 0x%x' % self.latest_span_end)
                        cycle_mark = 'cycle_%x' % self.latest_span_end
                else:
                    cycle_mark = 'cycle_%x' % self.latest_span_end

                self.restoreSnapshot(cycle_mark)
                self.lgr.debug('reverseMgr after restore %s cycle now 0x%x' % (cycle_mark, self.cpu.cycles))
                if not missing_snapshots and self.cpu.cycles != self.latest_span_end:
                    self.lgr.error('reverseMgr skipToCycle did restore to %s, but now at 0x%x' % (cycle_mark, self.cpu.cycles))
                    return False
                if use_cell is not None:
                    current_cycle = self.cpu_map[use_cell].cycles
                    self.lgr.debug('ReverseMgr skipToCycle different cell is %s, and his cycles are now 0x%x' % (use_cell, current_cycle))
                    if current_cycle >= object_cycles:
                        self.lgr.error('ReverseMgr skipToCycle different cell is %s, and his cycles are now 0x%x, which is beyond our goal of 0x%x' % (use_cell, current_cycle, object_cycles))
                self.runToCycle(object_cycles, use_cell=use_cell)
            else:
                recorded = self.getMasked(our_cycles)
                self.lgr.debug('reverseMgr skipToCycle recorded (after mask of want cycle) is 0x%x cpu.cycles is 0x%x origin was 0x%x' % (recorded, self.cpu.cycles, self.origin_cycle))
                if recorded < self.origin_cycle:
                    self.lgr.debug('reverseMgr skipToCycle masked value less than origin, skip to origin')
                    self.skipToOrigin()
                    if use_cell is None:
                        if self.top is not None:
                            eip = self.top.getEIP()
                            self.lgr.debug('reverseMgr skipToCycle did restore origin.  Now run forward to cycle 0x%x  cycle (origin) now 0x%x eip 0x%x' % (object_cycles, self.cpu.cycles, eip))
                    else:
                        current_cycle = self.cpu_map[use_cell].cycles
                        self.lgr.debug('reverseMgr skipToCycle did restore origin Now run forward to cycle 0x%x  cycle now 0x%x on our cell, different cell %s cycle 0x%x' % (object_cycles, self.cpu.cycles, current_cycles, use_cell))
                    self.runToCycle(object_cycles, use_cell=use_cell)
                elif recorded == self.cpu.cycles and use_cell is None:
                    self.runToCycle(object_cycles, use_cell=use_cell)
                    self.lgr.debug('reverseMgr skipToCycle recorded 0x%x same as current, just run forward to 0x%x' % (recorded, object_cycles))
                else:
                    cycle_mark = 'cycle_%x' % recorded
                    self.restoreSnapshot(cycle_mark)
                    if use_cell is None:
                        if self.top is not None:
                            eip = self.top.getEIP()
                            self.lgr.debug('reverseMgr skipToCycle restored 0x%x cycles now 0x%x eip 0x%x' % (recorded, self.cpu.cycles, eip))
                    else:
                        current_cycle = self.cpu_map[use_cell].cycles
                        self.lgr.debug('reverseMgr skipToCycle restored 0x%x cycles now 0x%x on our cpu and 0x%x on different cell %s' % (recorded, self.cpu.cycles, current_cyle, use_cell))
                    if recorded != current_cycle:
                        if self.cpu.cycles != object_cycles or use_cell is not None:
                            self.lgr.debug('reverseMgr skipToCycle run to 0x%x' % object_cycles)
                            self.runToCycle(object_cycles, use_cell=use_cell)
                        else:
                            self.setNextCycle()
        return True
            
          
    def runToCycle(self, cycle, use_cell=None):
        '''
        Run forward to the given cycle.  Internal only, will disable breakpoints before running forward.  Uses a event hap.
        '''
        if use_cell is None:
            use_cpu = self.cpu
        else:
            use_cpu = self.cpu_map[use_cell]
        if cycle < use_cpu.cycles:
            if use_cell is None:
                self.lgr.error('reverseMgr runToCycle 0x%x less than current 0x%x' % (cycle, use_cpu.cycles))
            else:
                self.lgr.error('reverseMgr runToCycle ON OTHER CELL %s 0x%x less than current 0x%x.  Maybe fix this by going back one more span?' % (use_cell, cycle, use_cpu.cycles))
            return
        elif cycle == use_cpu.cycles:
            self.lgr.debug('reverseMgr runToCycle already at cycle 0x%x' % cycle)
            print('Already at cycle 0x%x' % cycle)
        else:
            self.disableAll()
            self.setDeltaCycle(use_cpu, cycle)
            delta = cycle - use_cpu.cycles
            self.lgr.debug('reverseMgr runToCycle  0x%x. Now continue from cpu cycles 0x%x delta 0x%x' % (cycle, use_cpu.cycles, delta))
            if use_cell is not None:
                cmd = 'pselect %s' % use_cpu.name
                cli.quiet_run_command(cmd)
                
            SIM_continue(0)
            #SIM_continue(delta)
            self.lgr.debug('reverseMgr runToCycle 0x%x back from continue. Now,  cpu cycles 0x%x' % (cycle, use_cpu.cycles))
            self.enableAll()
            self.setNextCycle()
        if self.oldSimics() and self.latest_span_end is not None and self.latest_span_end > use_cpu.cycles:
            self.latest_span_end =  self.getMasked(use_cpu.cycles)
            self.lgr.debug('reverseMgr runToCycle reverted latest_span_end to 0x%x' % self.latest_span_end)

    def reverse(self, dumb=None, reverse_to=None, callback=None):
        '''
        Reverse until either a breakpoint is hit, or we hit the origin.  If multiple breakpoionts are set, execution
        is set at the most recent.
        Will return the stop hap if native reversing
        '''
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
            if callback is not None:
                self.setCallback(callback)
            self.cancelSpanCycle()
            self.break_cycles = {}
            self.reverse_from = self.cpu.cycles
            self.lgr.debug('reverseMgr reverse from 0x%x' % self.reverse_from)
            cmd = 'bp.list'
            self.bp_list = SIM_run_command(cmd)
            self.bp_cli_list = list(self.bp_list)
            if len(self.bp_list) > 0 and len(self.sim_breakpoints) > 0:
                self.lgr.error('reverseMgr reverse.  Do not set breakpoints with both SIM_breakpoint and bp.manager.  Fatal')
                self.top.quit()
                return
            if len(self.bp_list) == 0:
                self.bp_list = self.sim_breakpoints
            if len(self.bp_list) == 0:
                print('Warning reversing without any breakpoints, will hit origin')
                self.skipToOrigin()
                self.lgr.debug('reverseMgr reverse without any breakpoints, just restore origin')
                return
            else:
                self.lgr.debug('reverseMgr reverse, bp list %s' % self.bp_list)
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
            self.reverse_to = None
            self.rmContinuationHap()
            self.disableSimBreaks()
            expect = self.cpu.cycles + delta
            #print('would run forward 0x%x cycles. remove this' % delta)
            #return
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
                SIM_continue(new_delta)
                count = count + 1
                if count > 5:
                    self.lgr.error('reverseMgr skipBackAndRunForward too much, bail')
                    return
            if self.cpu.cycles > expect:
                too_far = self.cpu.cycles - expect
                self.lgr.error('reverseMgr skipBackAndRunForrward ran past the delta by 0x%x cycles, now at 0x%x?' % (too_far, self.cpu.cycles))
                return
            self.enableSimBreaks()
            self.lgr.debug('reverseMgr skipBackAndRunForward ran forward to the reverse_to point so we can set breaks and run from there.  cycles now 0x%x' % self.cpu.cycles)
            self.was_at_reverse_point = True

        #self.enableAll()
        if self.current_span_end == self.cpu.cycles:
            self.lgr.debug('reverseMgr skipBackAndRunForward already at current_span_end of 0x%x, now what?' % self.current_span_end)
        else:
            self.setBreakHaps()
            self.setSpanEndCycle()
            self.lgr.debug('reverseMgr skipBackAndRunForward now continue')
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
        self.break_haps = []
        hap = self.stop_hap
        SIM_run_alone(self.rmStopHap, hap)
        self.stop_hap = None
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
                    self.lgr.debug('reverseMgr stopHap failed to find break, no callback')
                    print('reverseMgr stopHap failed to find break, no callback')
                 
        else:
            cycle_list = list(self.break_cycles.keys())
            sorted_list = sorted(cycle_list)
            latest_cycle = sorted_list[-1]
            latest_bp = self.break_cycles[latest_cycle].bp
            self.lgr.debug('reverseMgr stopHap latest_cycle 0x%x bp %d' % (latest_cycle, latest_bp))

            SIM_run_alone(self.skipAndCallback, latest_cycle)
        self.was_at_reverse_point = False


    def skipAndCallback(self, skip_to_cycle):
        '''
        We've run to where we started reversing.  Skip back to the given cycle and invoke the callback (if any).  
        NOTE the cell of the breakpoint may not be our cell.
        '''
        self.lgr.debug('reverseMgr skipAndCallback current cycle 0x%x, call skipToCycle for 0x%x' % (self.cpu.cycles, skip_to_cycle))
        latest_bp = self.break_cycles[skip_to_cycle].bp
        use_cell = None
        object_cycles = self.break_cycles[skip_to_cycle].object_cycles
        if object_cycles is not None:
            use_cell = self.break_cycles[skip_to_cycle].the_object.name.split('.')[0]
            self.lgr.debug('reverseMgr skipAndCallback using different cell %s' % use_cell)
        self.skipToCycle(skip_to_cycle, use_cell=use_cell, object_cycles=object_cycles)

        self.setNextCycle()
        if self.callback is None:
            print('Reversing hit breakpoint %d at cycle 0x%x' % (latest_bp, skip_to_cycle))
            SIM_run_command('disassemble')
        else:
            memory = self.break_cycles[skip_to_cycle]
            self.callback(memory, None, None, None)
            self.callback = None
            self.lgr.debug('reverseMgr skipAndCallback done, called callback with memory') 

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
        SIM_break_simulation('span cycle handler')

    def setBreakHaps(self):
        '''
        Set haps on all breakpoints so we can record their cycles
        '''
        for bp in self.bp_list:
            self.lgr.debug('reverseMgr setBreakHaps set hap for bp %d' % bp)
            the_hap = SIM_hap_add_callback_index('Core_Breakpoint_Memop', self.breakCallback, None, bp)
            self.break_haps.append(the_hap) 

    class BreakInfo():
        '''
        Internal class used to skip to the point at which a breakpoint occurred.
        '''
        def __init__(self, the_object, bp, memory, object_cycles=None):
            self.the_object = the_object
            self.bp = bp
            self.logical_address = memory.logical_address
            self.physical_address = memory.physical_address
            self.size = memory.size
            self.object_cycles = object_cycles

    def breakCallback(self, param, the_obj, the_break, memory):
        '''
        HAP invoked when breakpoints are hit while reversing.  We record the cycle for use in identifying
        the most recent hap.  If the breakpoint is a bp.memory.breakpoint; then we force a continue since Simics
        will stop on those even if there is a HAP to handle it.
        ''' 
        if len(self.break_haps) == 0:
            return
        op_type = SIM_get_mem_op_type(memory)
        if op_type in [Sim_Trans_Load, Sim_Trans_Store]:
            break_after = True
        else:
            break_after = False
        if self.top is not None:
            eip = self.top.getEIP()
            instruct = SIM_disassemble_address(self.cpu, eip, 1, 0)
            op_type = SIM_get_mem_op_type(memory)
            op_type_string = resimSimicsUtils.transType(op_type)

            if memory.logical_address == 0 and memory.physical_address is not None:
                self.lgr.debug('reverseMgr breakCallback break num %d phys memory addr 0x%x cycles: 0x%x eip:0x%x  instruct %s op_type: %s' % (the_break, 
                        memory.physical_address, self.cpu.cycles, eip, instruct[1], op_type_string))
            else:
                self.lgr.debug('reverseMgr breakCallback break num %d memory addr 0x%x cycles: 0x%x eip:0x%x  instruct %s op_type: %s' % (the_break, 
                        memory.logical_address, self.cpu.cycles, eip, instruct[1], op_type_string))
        object_cycles = None 
        object_cell = the_obj.name.split('.')[0]
        if object_cell != self.our_cell:
            if object_cell not in self.cpu_map:
                self.lgr.error('reverseMgr breakCallback %s not in cpu map' % object_cell)
                return
            object_cycles = self.cpu_map[object_cell].cycles
            if break_after:
                object_cycles = object_cycles + 1
        if break_after:
            cpu_cycles = self.cpu.cycles+1
        else:
            cpu_cycles = self.cpu.cycles
        self.break_cycles[cpu_cycles] = self.BreakInfo(the_obj, the_break, memory, object_cycles=object_cycles)
        if the_break in self.bp_cli_list:
            self.lgr.debug('reverseMgr breakCallback from bp.memory.break breakpoint.  need to continue.  add a stop hap and...')
            print('reverseMgr breakCallback from bp.memory.break breakpoint.  need to continue.  add a stop hap and...')
            SIM_run_alone(self.addCliStopHap, None)

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
            cycle = self.cpu.cycles - 1
            self.skipToCycle(cycle)
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
        SIM_break_simulation('Cycle now 0x%x' % self.cpu.cycles)

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
                if bp in self.bp_list:
                    self.lgr.debug('reverseMgr SIM_delete_breakpoint removed %d from bp_list' % bp)
                    self.bp_list.remove(bp)
            else:
                self.lgr.error('reverseMgr SIM_delete_breakpoint %d not in sim_breakpoints')

    def disableSimBreaks(self):
        for bp in self.sim_breakpoints:
            SIM_disable_breakpoint(bp)

    def enableSimBreaks(self):
        for bp in self.sim_breakpoints:
            SIM_enable_breakpoint(bp)

    def disableAll(self):
        '''
        Disable all breakpoints
        '''
        self.rmContinuationHap()
        for bp in self.bp_list:
            #print('bp is %s' % bp)
            SIM_disable_breakpoint(bp)

    def enableAll(self):
        '''
        Enable all breakpoints
        '''
        self.lgr.debug('reverseMgr enableAll')
        self.setContinuationHap()
        for bp in self.bp_list:
            self.lgr.debug('reverseMgr enableAll bp is %s' % bp)
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
        self.lgr.debug('reverseMgr cancelRecordingEndCycle')
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
        if self.continuation_hap is not None:
            hap = self.continuation_hap
            self.rmContinuationHapAlone(hap)
            self.continuation_hap = None

    def rmContinuationHapAlone (self, hap):
        self.lgr.debug('reverseMgr rmContinuationHapAlone')
        SIM_hap_delete_callback_id("Core_Continuation", hap)

    def setContinuationHap(self):
        '''
        Catch a continue so that we can record snapshots as we move past the latest span.
        '''
        self.lgr.debug('reverseMgr setContinuationHap cycle 0x%x' % self.cpu.cycles)
        self.continuation_hap = SIM_hap_add_callback("Core_Continuation", self.continuationHap, None)

    def continuationHap(self, dumb, one):
        '''
        Restart recording of snapshots if needed.
        '''
        if not self.recording_end_event_set:
            self.lgr.debug('reverseMgr continuationHap cycles: 0x%x' % self.cpu.cycles)
            if not self.recording:
                self.lgr.debug('reverseMgr continuationHap not recording, set recording end')
                self.setRecordingEndCycle()
            else:
                self.lgr.debug('reverseMgr continuationHap am recording')
        else:
            self.lgr.debug('reverseMgr continuationHap but recording_end_event_set')

    def getSpan(self):
        '''
        Return the cycle span
        '''
        return self.cycle_span

    def skipToOrigin(self):
        self.lgr.debug('reverseMgr skipToOrigin')
        self.restoreSnapshot('origin')
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
        if not self.version().startswith('7'):
           if self.oldSimics():
               return False
               #return True
           else:
               return True
        else:
           return False

    def mapCPUsToCell(self):
        '''
        Populate the cpu map for use when the most recent breakpoint is not tied to our cell.
        Call this if cells are added or removed.
        '''
        for cell in self.conf.sim.cell_list:
            object_cell = cell.name.split('.')[0]
            self.lgr.debug('reverseMgr mapCPUsToCell cell %s' % object_cell)
            cmd = '%s.get-processor-list' % object_cell
            proclist = SIM_run_command(cmd)
            cpu = SIM_get_object(proclist[0])
            self.cpu_map[object_cell] = cpu

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

'''
Everything below is for use running directly from the Simics command prompt, e.g., for testing.
Typically this module would be instantiated from some other Python module.
'''

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
    cell = conf.sim.cell_list[0]
    object_cell = cell.name.split('.')[0]
    print('Loading ReverseMgr module for cell %s' % object_cell)
    cmd = '%s.get-processor-list' % object_cell
    proclist = SIM_run_command(cmd)
    cpu = SIM_get_object(proclist[0])
    return cpu
if __name__ == '__main__':
    lgr = getLogger('reverseMgr', '/tmp/')
    cpu = getCPU(conf)
    rev = ReverseMgr(conf, cpu, lgr)
    print('Usage: @rev.enableReverse() to enable reverse execution.')
    print('       @rev.reverse() to reverse to a breakpoint that you have separately set.')
    print('       @rev.skipToCycle(cycle) to skip to a cycle.')
    print('       @rev.disableReverse() disable reverse execution.')
    print('Logging to  /tmp/reverseMgr.log')
