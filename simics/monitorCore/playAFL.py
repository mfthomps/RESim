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
'''
Inject data and track code coverage in a manner similar to that performed with AFL.
The given "dfile" input can be either a single data file, or a name an AFL campaign, 
which results in playing all of the queue files found by AFL.
'''
from simics import *
import writeData
import aflPath
import resimUtils
import traceBuffer
import cli
import sys
import os
import glob
import pickle
import json
from resimUtils import rprint

class PlayAFL():
    def __init__(self, top, cpu, cell_name, backstop, no_cover, mem_utils, dfile,
             snap_name, context_manager, cfg_file, lgr, packet_count=1, stop_on_read=False, linear=False,
             create_dead_zone=False, afl_mode=False, crashes=False, parallel=False, only_thread=False, target_cell=None, target_proc=None,
             fname=None, repeat=False, targetFD=None, count=1, trace_all=False, no_page_faults=False):
        self.top = top
        self.backstop = backstop
        self.no_cover = no_cover
        self.coverage = None
        # mem_utils is instance for cell into which data gets injected
        self.mem_utils = mem_utils
        self.snap_name = snap_name
        self.cpu = cpu
        # mem_utils is instance for cell whose coverage is to be tracked
        self.context_manager = context_manager
        self.cell_name = cell_name
        self.lgr = lgr
        self.afl_mode = afl_mode
        self.findbb = None
        self.write_data = None
        self.orig_buffer = None
        self.cfg_file = cfg_file
        self.dfile = dfile
        self.trace_buffer = None
        self.target_proc = target_proc
        if target_cell is None:
            self.target_cell = cell_name
        else:
            self.target_cell = target_cell
        self.target_cpu = self.top.getCPU(self.target_cell)
        self.fname = fname
        self.afl_mode = afl_mode
        self.only_thread = only_thread
        self.create_dead_zone = create_dead_zone
        self.linear = linear
        self.targetFD = targetFD
        self.count = count
        self.trace_all = trace_all
        self.afl_dir = aflPath.getAFLOutput()
        self.all_hits = []
        self.afl_list = []
        self.commence_coverage = None
        self.commence_after_exits = None
        self.counter_bp = None
        self.counter_hap = None
        self.exit_counter = 0
        self.exit_eip = None
        self.stop_hap_cycle = None
        self.back_stop_cycle = None
        self.hang_cycles = 90000000
        hang = os.getenv('HANG_CYCLES')
        if hang is not None:
            self.hang_cycles = int(hang)
        self.cycle_event = None
        self.initial_cycle = self.target_cpu.cycles
        ''' for testing, replay same data file over and over. only works with single file '''
        self.repeat = repeat
        self.repeat_counter = 0
        ''' If parallel, the all_hits will not be tracked or written.  TBD to that separately.'''
        self.parallel = parallel
        ''' Only track current thread '''
        self.only_thread = only_thread
        pad_env = os.getenv('AFL_PAD') 
        if pad_env is not None:
            try:
                self.pad_to_size = int(pad_env)
            except:
                self.lgr.error('Bad AFL_PAD value %s' % pad_env)
                return
        else: 
            self.pad_to_size = 0
        self.stop_on_read =   stop_on_read
        if not self.stop_on_read:
            sor = os.getenv('AFL_STOP_ON_READ')
            if sor is not None and sor.lower() == 'true':
                self.stop_on_read = True
        self.udp_header = os.getenv('AFL_UDP_HEADER')
        if packet_count > 1 and not (self.udp_header is not None or self.pad_to_size > 0):
            self.lgr.error('Multi-packet requested but no pad or UDP header has been given in env variables')
            return None
        if os.path.isfile(dfile):
            ''' single file to play '''
            self.dfile = 'oneplay'
            relative = dfile[(len(self.afl_dir)+1):]
            if dfile.startswith(aflPath.getAFLOutput()) and len(relative.strip()) > 0:
                self.afl_list = [relative]
                self.lgr.debug('playAFL, single file, path relative to afl_dir is %s' % relative)
            else:
                self.afl_list = [dfile]
                self.lgr.debug('playAFL, single file, abs path is %s' % dfile)
        else:
            if not crashes:
                print('get dfile queue')
                self.lgr.debug('playAFL get queue for dfile %s' % dfile)
                self.afl_list = aflPath.getTargetQueue(dfile, get_all=True)
                if len(self.afl_list) == 0:
                    print('No queue files found for %s' % dfile)
                    self.lgr.debug('playAFL No queue files found for %s' % dfile)
                    return
            else:
                self.afl_list = aflPath.getTargetCrashes(dfile)
                if len(self.afl_list) == 0:
                    print('No crashes found for %s' % dfile)
                    return
            print('Playing %d sessions.  Please wait until that is reported.' % len(self.afl_list))
        tid = self.top.getTID()
        self.lgr.debug('playAFL afl list has %d items.  current context %s current tid:%s fname:%s' % (len(self.afl_list), self.target_cpu.current_context, tid, self.fname))
        self.initial_context = self.target_cpu.current_context
        self.index = -1
        self.stop_hap = None
        self.call_hap = None
        self.call_break = None
        self.addr = None
        self.in_data = None
        #self.backstop_cycles =   100000
        if self.afl_mode:
            if os.getenv('AFL_BACK_STOP_CYCLES') is not None:
                self.backstop_cycles =   int(os.getenv('AFL_BACK_STOP_CYCLES'))
                self.lgr.debug('afl AFL_BACK_STOP_CYCLES is %d' % self.backstop_cycles)
            else:
                self.lgr.warning('no AFL_BACK_STOP_CYCLES defined, using default of 100000')
                self.backstop_cycles =   1000000
        else:
            self.backstop_cycles =   900000
            bsc = os.getenv('BACK_STOP_CYCLES')
            if bsc is not None:
                self.backstop_cycles = int(bsc)
        self.packet_count = packet_count
        self.afl_packet_count = None
        self.current_packet = 0
        self.hit_total = 0

        self.filter_module = None
        packet_filter = os.getenv('AFL_PACKET_FILTER')
        if packet_filter is not None:
            self.filter_module = resimUtils.getPacketFilter(packet_filter, lgr)

        ''' replay file names that hit the given bb '''
        self.bnt_list = []
        self.tid = self.top.getTID()
        if target_proc is None:
            self.target_tid = self.tid
        else:
            self.target_tid = None
        self.stop_on_break = False
        self.exit_list = []
        if self.cpu.architecture == 'arm':
            lenreg = 'r0'
        else:
            lenreg = 'eax'
        self.len_reg_num = self.cpu.iface.int_register.get_number(lenreg)
        
        self.snap_name = snap_name
        self.no_page_faults = no_page_faults
        if not self.loadPickle(snap_name):
            print('No AFL data stored for cell %s in checkpoint %s, cannot play AFL.' % (self.cell_name, snap_name))
            return None

        if target_proc is None:
            self.top.debugTidGroup(tid, to_user=False)
            self.finishInit()
            self.disableReverse()
            self.initial_context = self.target_cpu.current_context
        else:
            ''' generate a bookmark so we can return here after setting coverage breakpoints on target'''
            self.lgr.debug('playAFL target_proc %s reset origin and set target to %s' % (target_proc, target_cell))
            self.top.resetOrigin()
            self.top.setTarget(target_cell)
            self.top.debugProc(target_proc, self.playInitCallback)

    def ranToIO(self, dumb):
        self.commence_coverage = self.target_cpu.cycles - self.initial_cycle
        self.lgr.debug('playAFL ran to IO cycles for commence coverage after: 0x%x cycles' % self.commence_coverage)
        self.top.rmSyscall('runToIO', cell_name=self.cell_name)

        # return to origin and run forward again, this time counting syscall exits
        self.exit_eip = self.top.getEIP(cpu=self.target_cpu)
        self.tid = self.top.getTID(target=self.target_cell)

        cmd = 'skip-to bookmark = bookmark0'
        cli.quiet_run_command(cmd)

        SIM_run_alone(self.setCycleHap, None)
        SIM_run_alone(self.setCounterHap, None)
        self.lgr.debug('ranToIO set counter hap and cycle hap now continue')
        SIM_run_alone(SIM_run_command, 'continue')

    def setCounterHap(self, dumb=None):
        self.exit_counter = 0
        self.lgr.debug('playAFL setCounterHap currentContext %s' % self.target_cpu.current_context)


        if self.commence_after_exits is None or self.dfile != 'oneplay' or self.repeat:
            context = self.target_cpu.current_context
        else:
            context = self.context_manager.getRESimContext()
        self.counter_bp = SIM_breakpoint(context, Sim_Break_Linear, Sim_Access_Execute, self.exit_eip, 1, 0)
        self.counter_hap = SIM_hap_add_callback_index("Core_Breakpoint_Memop", self.counterHap, None, self.counter_bp)

    def counterHap(self, dumb, third, break_num, memory):
        if self.counter_hap is None:
            return
        tid = self.top.getTID(target=self.target_cell)
        if tid != self.target_tid:
            self.lgr.debug('playAFL counterHap wrong tid:%s, wanted %d cycle: 0x%x' % (tid, self.target_tid, self.target_cpu.cycles))
            return
        self.exit_counter = self.exit_counter+1
        self.lgr.debug('playAFL counterHap, count now %d' % self.exit_counter)
        if self.commence_after_exits is not None and self.exit_counter == self.commence_after_exits:
            self.lgr.debug('alf counterHap reached desired count, enable coverage breaks')
            self.coverage.enableAll()
            SIM_run_alone(self.setHangCallback, None)
            hap = self.counter_hap
            SIM_run_alone(self.rmCounterHap, hap)
            self.counter_hap = None

    def setHangCallback(self, dumb):
        self.lgr.debug('playAFL setHangCallback')
        self.backstop.setHangCallback(self.hangCallback, self.hang_cycles)

    def playInitCallback(self):
        self.target_tid = self.top.getTID()
        ''' We are in the target process and completed debug setup including getting coverage module.  Go back to origin '''
        self.lgr.debug('playAFL playInitCallback. target tid: %d finish init to set coverage and such' % self.target_tid)
        self.trace_buffer = traceBuffer.TraceBuffer(self.top, self.target_cpu, self.mem_utils, self.context_manager, self.lgr, 'playAFL')
        self.initial_context = self.target_cpu.current_context
        if self.trace_all:
            self.top.traceAll()
        if len(self.trace_buffer.addr_info) == 0:
            self.trace_buffer = None
        if self.targetFD is not None and self.count > 0:
            ''' run to IO before finishing init '''
            self.top.jumperDisable(target=self.cell_name)
            self.top.setCommandCallback(self.ranToIO)
            self.top.runToIO(self.targetFD, count=self.count, break_simulation=True, target=self.target_cell)
        else:
            self.finishCallback()

    def finishCallback(self, dumb=None):
        ''' restore origin and go '''
        self.lgr.debug('playAFL finishCallback')
        self.finishInit()
        self.lgr.debug('playAFL finishCallback skip to bookmark')
        cmd = 'skip-to bookmark = bookmark0'
        # TBD this will break on repeat or playing multiple files
        cli.quiet_run_command(cmd)
        self.disableReverse()
        self.top.setTarget(self.cell_name)
        tid = self.top.getTID()
        self.lgr.debug('playAFL finishCallback, restored to original bookmark and reset target to %s tid: %d' % (self.cell_name, tid))
        self.go()

    def disableReverse(self):
        self.lgr.debug('playAFL disabling reverse execution')
        cli.quiet_run_command('disable-reverse-execution')
        self.top.setDisableReverse()
        cli.quiet_run_command('enable-unsupported-feature internals')
        cli.quiet_run_command('save-snapshot name = origin')

    def finishInit(self):
        self.lgr.debug('playAFL finishInit')
        if self.dfile != 'oneplay' or self.repeat:
            self.lgr.debug('playAFL finishInit call to remove debug breaks')
            self.top.removeDebugBreaks(keep_watching=False, keep_coverage=False, immediate=True)
        elif self.target_proc is None:
            self.lgr.debug('playAFL finishInit target_proc None, call resetOrigin')
            self.top.resetOrigin()
        if self.target_proc is None:
            # otherwise traceBuffer set up in playInitCallback
            self.trace_buffer = traceBuffer.TraceBuffer(self.top, self.target_cpu, self.mem_utils, self.context_manager, self.lgr, 'playAFL')
            if len(self.trace_buffer.addr_info) == 0:
                self.trace_buffer = None

        self.top.stopThreadTrack(immediate=True)

        if not self.no_cover:
            self.lgr.debug('playAFL finishInit call to get coverage')
            self.coverage = self.top.getCoverage()
            if self.coverage is None:
                self.lgr.error('playAFL finishInit failed getting coverage')
 

        self.physical=False
        if self.coverage is not None:
            full_path = None
            if self.fname is None:
                analysis_path = self.top.getAnalysisPath(self.target_proc)
            else:
                analysis_path = self.top.getAnalysisPath(self.fname)
            self.lgr.debug('playAFL call enableCoverage analysis_path is %s' % analysis_path)
            self.coverage.enableCoverage(self.target_tid, backstop=self.backstop, backstop_cycles=self.backstop_cycles, 
               afl=self.afl_mode, linear=self.linear, create_dead_zone=self.create_dead_zone, only_thread=self.only_thread, fname=analysis_path)
            self.lgr.debug('playAFL backfrom enableCoverage')
            self.physical = True
            if self.linear:
                self.physical = False
                self.lgr.debug('playAFL, linear use context manager to watch tasks')
                self.context_manager.restoreDebugContext()
                self.context_manager.watchTasks()
            self.coverage.doCoverage(no_merge=True, physical=self.physical)
            if self.commence_coverage is not None:
                self.coverage.disableAll()
            else:
                self.backstop.setHangCallback(self.coverage.recordHang, self.hang_cycles)

            if True:
                ''' TBD, multple writers?'''
                full_path = self.coverage.getFullPath()
                full_path = os.path.abspath(full_path)
    
                hits_path = self.coverage.getHitsPath()+'.prog'
                self.lgr.debug('create prog file at path: %s' % hits_path)
                parent = os.path.dirname(os.path.abspath(hits_path))
                print('parent is %s' % parent)
                try:
                    os.makedirs(parent)
                except:
                    pass
                try:
                    fh = open(hits_path, 'x')
                    fh.write(full_path+'\n')
                    fh.write(self.cfg_file+'\n')
                except:
                    self.lgr.debug('create failed (already exists?) at path: %s' % hits_path)
                    pass
                    #print('full_path is %s,  wrote that to %s' % (full_path, hits_path))
            #self.backstop.setCallback(self.whenDone)
        self.backstop.setCallback(self.backstopCallback)

    def go(self, findbb=None):
        if len(self.afl_list) == 0:
            print('Nothing in afl list')
            self.lgr.debug('Nothing in afl list')
            self.top.quit()
            return
        self.lgr.debug('playAFL go')
        self.bnt_list = []
        self.index = -1
        self.hit_total = 0
        self.findbb = findbb
        SIM_run_alone(self.goAlone, False)

    def backstopCallback(self):
        SIM_run_alone(self.backstopCallbackAlone, None)

    def backstopCallbackAlone(self, cycles):
        self.lgr.info('playAFL backstop detected')
        if self.stop_hap is None:
               self.stop_hap = SIM_hap_add_callback("Core_Simulation_Stopped", self.stopHap,  None)
        SIM_break_simulation('backstop')

    def hangCallback(self, cycles):
        SIM_run_alone(self.hangCallbackAlone, cycles)

    def hangCallbackAlone(self, cycles):
        self.lgr.info('playAFL hang detected')
        if self.stop_hap is None:
               self.stop_hap = SIM_hap_add_callback("Core_Simulation_Stopped", self.stopHap,  None)
        SIM_break_simulation('hang')

    def stopOnRead(self, counter):
        self.lgr.info('playAFL stopOnRead callback counter %d' % counter)
        if self.stop_hap is None:
               self.stop_hap = SIM_hap_add_callback("Core_Simulation_Stopped", self.stopHap,  None)
        SIM_break_simulation('stopOnRead')

    def goAlone(self, clear_hits):
        self.current_packet=1
        if not self.repeat:
            self.index += 1
        else:
            self.repeat_counter += 1
            if self.repeat_counter % 10 == 0:
                rprint(str(self.repeat_counter))
        self.target_cpu.current_context = self.initial_context 
        self.lgr.debug('playAFL goAlone, len of afl list is %d, index now %d context %s' % (len(self.afl_list), self.index, str(self.target_cpu.current_context)))
        done = False
        if self.dfile != 'oneplay':
            ''' skip files if already have coverage (or have been create by another drone in parallel'''
            while not done and self.index < len(self.afl_list):
                fname = self.getHitsPath(self.index)
                self.lgr.debug('playAFL goAlone file %s' % fname)
                ''' python 2 does not have FileExistsError,fly blind '''
                try:
                    os.open(fname, os.O_CREAT | os.O_EXCL)
                    done = True
                except:
                    self.lgr.debug('playAFL goAlone did not get exclusive create for file at %s' % fname)
                    if not self.parallel:
                        try:
                            hits_json = json.load(open(fname))
                        except:
                            done = True
                            continue
                        for hit in hits_json:
                            hit = int(hit)
                            if hit not in self.all_hits:
                                self.all_hits.append(hit)
                    self.index += 1
        if self.index < len(self.afl_list) or self.repeat:
            self.lgr.debug('playAFL goAlone index %d' % self.index)
            if self.commence_coverage is not None:
                self.coverage.disableAll()
            if self.dfile != 'oneplay' or self.repeat:
                cli.quiet_run_command('restore-snapshot name = origin')
            if self.commence_coverage is not None:
                self.lgr.debug('playAFL goAlone set counter hap')
                self.setCounterHap()
            if self.coverage is not None:
                if clear_hits and not self.repeat:
                    self.coverage.stopCover() 
                    self.coverage.doCoverage(no_merge=True, physical=self.physical) 
            #if self.orig_buffer is not None:
            #    #self.lgr.debug('playAFL restored %d bytes to original buffer at 0x%x' % (len(self.orig_buffer), self.addr))
            #    self.mem_utils.writeBytes(self.cpu, self.addr, self.orig_buffer) 
            self.lgr.info('playAFL try afl_list entry %s' % self.afl_list[self.index])
            if self.in_data is None or not self.repeat:
                full = os.path.join(self.afl_dir, self.afl_list[self.index])
                if not os.path.isfile(full):
                    self.lgr.debug('No file at %s, non-parallel file' % full)
                    full = os.path.join(self.afl_dir, self.dfile, 'queue', self.afl_list[self.index])
                if not os.path.isfile(full):
                    self.lgr.debug('No file at %s, try local file' % full)
                    full = self.afl_list[self.index]
                    if not os.path.isfile(full):
                        self.lgr.debug('No file at %s, try basename' % full)
                        full = os.path.basename(full)
                        if not os.path.isfile(full):
                            self.lgr.debug('No local file at %s, either, bail' % full)
                            print('Could not find file for %s' % full)
                            self.top.quit()
                            return
                    else:
                        self.lgr.debug('Using local file at: %s' % full)
                
                with open(full, 'rb') as fh:
                    if sys.version_info[0] == 2:
                        self.in_data = bytearray(fh.read())
                    else:
                        self.in_data = fh.read()
                self.lgr.debug('playAFL goAlone loaded %d bytes from file session %d of %d' % (len(self.in_data), self.index, len(self.afl_list)))
                self.afl_packet_count = self.packet_count
        
            #if self.orig_buffer is not None:
            #    ''' restore receive buffer to original condition in case injected data is smaller than original and poor code
            #        references data past the end of what is received. '''
            #    self.mem_utils.writeBytes(self.cpu, self.addr, self.orig_buffer) 
            #    self.lgr.debug('playAFL restored %d bytes to original buffer at 0x%x' % (len(self.orig_buffer), self.addr))
            #self.top.restoreRESimContext()
            #self.context_manager.restoreDebugContext()
            self.lgr.debug('playAFL here')
            if self.write_data is None:
                force_default_context = True
                if self.dfile == 'oneplay' and not self.repeat:
                    force_default_context = False
                self.lgr.debug('playAFL gen writeData')
                write_callback = None
                if self.stop_on_read:
                    write_callback = self.stopOnRead
                self.write_data = writeData.WriteData(self.top, self.cpu, self.in_data, self.afl_packet_count, 
                         self.mem_utils, self.context_manager, self.backstop, self.snap_name, self.lgr, udp_header=self.udp_header, 
                         pad_to_size=self.pad_to_size, backstop_cycles=self.backstop_cycles, force_default_context=force_default_context, 
                         filter=self.filter_module, stop_on_read=self.stop_on_read, write_callback=write_callback)
                         #filter=self.filter_module, stop_on_read=self.stop_on_read, shared_syscall=self.top.getSharedSyscall())
            else:
                self.write_data.reset(self.in_data, self.afl_packet_count, self.addr)
            eip = self.top.getEIP(self.cpu)
            self.lgr.debug('playAFL call writeData write')
            count = self.write_data.write()
            bp_count = self.coverage.bpCount()
            self.lgr.debug('playAFL goAlone tid:%s ip: 0x%x wrote %d bytes from file %s continue from cycle 0x%x %d cpu context: %s %d breakpoints set' % (self.tid, eip, count, self.afl_list[self.index], self.cpu.cycles, self.cpu.cycles, str(self.cpu.current_context), bp_count))
            # TBD just rely on coverage?
            #self.backstop.setFutureCycle(self.backstop_cycles, now=True)
            if self.trace_buffer is not None:
                self.trace_buffer.msg('playAFL from '+self.afl_list[self.index])

            if self.afl_mode: 
                if self.coverage is not None:
                    if self.repeat is False or self.repeat_counter > 1:
                        self.coverage.watchExits()
                else:
                    self.lgr.error('playAFL afl_mode but not coverage?')
                    return
            elif self.coverage is not None:
                self.coverage.watchExits(callback=self.reportExit, tid=self.target_tid)
            else:
                self.context_manager.watchGroupExits()
                self.context_manager.setExitCallback(self.reportExit)
            #if self.stop_hap is None:
            #    self.stop_hap = SIM_hap_add_callback("Core_Simulation_Stopped", self.stopHap,  None)

            self.lgr.debug('playAFL goAlone watch page faults for tid:%s cell %s' % (self.target_tid, self.target_cell))
            if not self.no_page_faults:
                self.top.watchPageFaults(tid=self.target_tid, target=self.target_cell)
            else:
                self.lgr.debug('playAFL goAlone will not watch page faults, will miss segv')
                self.top.stopWatchPageFaults()
            if self.dfile == 'oneplay' and not self.repeat and self.target_proc is None:
                self.lgr.debug('playAFL goAlone is onePlay and not repeat, not calling resetOrigin')
                #self.top.resetOrigin()

            self.lgr.debug('playAFL goAlone now continue')
            if self.repeat:
                #if self.repeat_counter > 20:
                #    return
                SIM_continue(0)
                self.lgr.debug('playAFL goAlone repeat set, did continue')
                pass
            else:
                SIM_continue(0)
                self.lgr.debug('playAFL goAlone repeat not set, did continue')
                pass
        else:
            self.lgr.info('playAFL did all sessions.')
            ''' did all sessions '''
            if self.coverage is not None and self.findbb is None and not self.afl_mode and not self.parallel:
                hits = self.coverage.getHitCount()
                self.lgr.info('All sessions done, save %d all_hits as %s' % (len(self.all_hits), self.dfile))
                hits_path = self.coverage.getHitsPath()
  
                s = json.dumps(self.all_hits)
                save_name = '%s.%s.hits' % (hits_path, self.dfile)
                try:
                    os.makedirs(os.path.dirname(hits_path))
                except:
                    pass
                try:
                    with open(save_name, 'w') as fh:
                        fh.write(s)
                        fh.flush()
                except:
                    self.lgr.error('Failed creating %s.  Is the directory correct?' % save_name)
                    return
                print('%d Hits file written to %s' % (len(self.all_hits), save_name))
                all_prev_hits_path = '%s.hits' % hits_path
                if os.path.isfile(all_prev_hits_path):
                    all_prev_hits = json.load(open(all_prev_hits_path))
                    count = 0
                    for hit in self.all_hits:
                        if hit not in all_prev_hits:
                            #print('New hit found at 0x%x' % hit)
                            gotone = True
                            count = count+1
                    if count == 0:
                        print('No new hits.')
                    else:
                        print('Found %d new hits that were not in %s' % (count, all_prev_hits_path))
                        
                else:
                    print('no hits file at %s ?' % all_prev_hits_path)
            elif self.parallel:
                self.top.quit()
            self.delStopHap(None)               
            if self.findbb is not None:
                for f, n in sorted(self.bnt_list):
                    print('%-30s  packet %d' % (f, n))
                print('Found %d sessions that hit address 0x%x' % (len(self.bnt_list), self.findbb))
            print('Played %d sessions' % len(self.afl_list))
            if len(self.exit_list)>0:
                print('%d Sessions that called exit:' % len(self.exit_list))
                for exit in sorted(self.exit_list):
                    print(exit)
                print('\n\n  Sessions that did not exit:')
        
                for item in sorted(self.afl_list):
                    if item not in self.exit_list:
                        print(item)
            if self.dfile != 'oneplay' or self.repeat:
                cli.quiet_run_command('restore-snapshot name = origin')
            else:
                self.top.stopCoverage() 
                

    def getHitsPath(self, index):
        queue_dir = os.path.dirname(self.afl_list[index])
        queue_parent = os.path.dirname(queue_dir)
        if os.path.basename(queue_dir) == 'manual_queue':
            coverage_dir = os.path.join(queue_parent, 'manual_coverage')
        else:
            coverage_dir = os.path.join(queue_parent, 'coverage')
        try:
            os.makedirs(coverage_dir)
        except:
            pass
        fname = os.path.join(coverage_dir, os.path.basename(self.afl_list[self.index])) 
        return fname

    def recordHits(self, hit_bbs):
        ''' hits will go in a "coverage" directory along side queue, etc. '''
        self.lgr.debug('playAFL recordHits %d' % len(hit_bbs))
        #hit_list = list(hit_bbs.keys())
        fname = self.getHitsPath(self.index)
        if not os.path.isfile(fname):
            self.lgr.debug('playAFL record hits, assume ad-hoc path')
            print('Assume ad-hoc path, hits stored in /tmp/playAFL.hits')
            fname = '/tmp/playAFL.hits'
        with open(fname, 'w') as fh:
            #json.dump(hit_list, fh) 
            json.dump(hit_bbs, fh) 
        #for hit in hit_list:
        for hit in hit_bbs:
            hit = int(hit)
            if hit not in self.all_hits:
                self.all_hits.append(hit)

    def stopHap(self, dumb, one, exception, error_string):
        self.lgr.debug('playAFL in stopHap')
        if self.target_cpu.cycles == self.initial_cycle:
            self.lgr.debug('playAFL stopHap, but did not get anywhere, continue?')
            SIM_run_alone(SIM_continue, 0)
            return
        if self.stop_hap is not None:
            if self.coverage is not None:
                num_packets = self.write_data.getCurrentPacket()
                self.lgr.debug('playAFL stopHap index %d, got %d hits, %d packets cycles: 0x%x' % (self.index, self.coverage.getHitCount(), 
                     num_packets, self.target_cpu.cycles))
                #self.backstop.checkEvent()
                self.backstop.clearCycle()
                hits = self.coverage.getHitCount()
                if hits > self.hit_total:
                    delta = hits - self.hit_total
                    self.hit_total = hits 
                    self.lgr.debug('Found %d new hits' % delta)
                hit_bbs = self.coverage.getBlocksHit()
                self.lgr.debug('playAFL stophap gtBlocksHit returned %d hits' % len(hit_bbs))
                if self.findbb is not None and self.index < len(self.afl_list):
                    self.lgr.debug('looking for bb 0x%x' % self.findbb)
                    if self.findbb in hit_bbs:
                        packet_num = self.write_data.getCurrentPacket()
                        self.bnt_list.append((self.afl_list[self.index], packet_num))
                elif not self.repeat:
                    self.recordHits(hit_bbs)
                    self.coverage.saveDeadFile()
                if self.coverage.didExit():
                    self.exit_list.append(self.afl_list[self.index])

                if self.top.hasPendingPageFault(self.tid):
                    print('TID %s has pending page fault' % self.tid)
                    self.lgr.debug('TID %s has pending page fault' % self.tid)
            else:
                self.lgr.debug('playAFL stopHap')
            SIM_run_alone(self.goAlone, True)


    def delStopHap(self, dumb):
        if self.stop_hap is not None:
            SIM_hap_delete_callback_id('Core_Simulation_Stopped', self.stop_hap)
            self.stop_hap = None

    def loadPickle(self, name):
        retval = False
        afl_file = os.path.join('./', name, self.cell_name, 'afl.pickle')
        if os.path.isfile(afl_file):
            retval = True
            self.lgr.debug('afl pickle from %s' % afl_file)
            so_pickle = pickle.load( open(afl_file, 'rb') ) 
            #print('start %s' % str(so_pickle['text_start']))
            if 'addr' in so_pickle:
                self.addr = so_pickle['addr']
            if 'orig_buffer' in so_pickle:
                self.orig_buffer = so_pickle['orig_buffer']
        return retval

    def reportExit(self):
        SIM_run_alone(self.reportExitAlone, None)

    def reportExitAlone(self, dumb):
        print('Process exit  cycles 0x%x' % self.target_cpu.cycles)
        if self.stop_hap is None:
               self.stop_hap = SIM_hap_add_callback("Core_Simulation_Stopped", self.stopHap,  None)
        SIM_break_simulation('process exit')
 
    def setCycleHap(self, dumb=None):
        if self.cycle_event is None:
            self.cycle_event = SIM_register_event("playAFL commence", SIM_get_class("sim"), Sim_EC_Notsaved, self.cycle_handler, None, None, None, None)
            self.lgr.debug('playAFL setCycleHap set playAFL commence')
        else:
            SIM_event_cancel_time(self.target_cpu, self.cycle_event, self.target_cpu, None, None)
            self.lgr.debug('playAFL setCycleHap did registercancel')
        commence_cycle = self.target_cpu.cycles + self.commence_coverage
        self.lgr.debug('playAFL setCycleHap posted cycle of 0x%x cpu: %s look for cycle 0x%x (%d)' % (self.commence_coverage, self.target_cpu.name, commence_cycle, commence_cycle))
        SIM_event_post_cycle(self.target_cpu, self.cycle_event, self.target_cpu, self.commence_coverage, self.commence_coverage)


    def cycle_handler(self, obj, cycles):
        if self.cycle_event is None:
            return
        self.lgr.debug('playAFL cycle_handler exit counter is %d' % self.exit_counter)
        self.commence_after_exits = self.exit_counter
        self.exit_counter = 0
        hap = self.counter_hap
        SIM_run_alone(self.rmCounterHap, hap)
        self.counter_hap = None
        self.lgr.debug('playAFL cycle_handler now set stopHapCycle and stop')
        SIM_run_alone(self.doCycleStop, None)
        # TBD jumpers should match playAFL?  Two kinds: one for diagnostics and one for real control flow around crc's
        #self.top.jumperEnable(target=self.cell_name)

    def doCycleStop(self, dumb):
        SIM_event_cancel_time(self.target_cpu, self.cycle_event, self.target_cpu, None, None)
        self.cycle_event = None
        self.lgr.debug('playAFL doCycleStop cycle_event set to None')
        self.stop_hap_cycle = SIM_hap_add_callback("Core_Simulation_Stopped", self.stopHapCycle,  None)
        SIM_break_simulation('playAFL cycle_handler')

    def rmCounterHap(self, hap):
        self.lgr.debug('playAFL rmCounterHap')
        SIM_hap_delete_callback_id('Core_Breakpoint_Memop', hap)
        SIM_delete_breakpoint(self.counter_bp)
        self.counter_bp = None

    def stopHapCycle(self, dumb, one, exception, error_string):
        if self.stop_hap_cycle is not None:
            SIM_run_alone(self.rmStopHapCycle, None)
            SIM_run_alone(self.finishCallback, None)

    def rmStopHapCycle(self, dumb):
        if self.stop_hap_cycle is not None:
            SIM_hap_delete_callback_id("Core_Simulation_Stopped", self.stop_hap_cycle)
            self.lgr.debug('playAFL stop_hap_cycle removed')
            self.stop_hap_cycle = None
