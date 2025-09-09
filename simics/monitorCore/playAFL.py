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
import memUtils
import cli
import sys
import os
import glob
import pickle
import json

class PlayAFL():
    def __init__(self, top, cpu, cell_name, backstop, no_cover, mem_utils, dfile,
             snap_name, context_manager, cfg_file, lgr, packet_count=1, stop_on_read=False, linear=False,
             create_dead_zone=False, afl_mode=False, crashes=False, parallel=False, only_thread=False, target_cell=None, target_proc=None,
             fname=None, repeat=False, targetFD=None, count=1, trace_all=False, no_page_faults=False, show_new_hits=False, diag_hits=False,
             search_list=None, commence_params=None, watch_rop=False, primer=None):
        if fname is not None and '/' in fname and fname[0] != '/':
            # needed for soMap lookups
            fname = '/'+fname
        lgr.debug('playAFL dfile: %s fname: %s' % (dfile, fname))
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
        self.show_new_hits = show_new_hits
        self.watch_rop = watch_rop
        self.primer = primer
        self.afl_dir = aflPath.getAFLOutput()
        self.all_hits = []
        self.afl_list = []
        self.commence_coverage = None
        self.commence_after_exits = None
        self.counter_bp = None
        self.counter_hap = None
        self.exit_counter = 0
        self.exit_eip = None
        self.commence_params = commence_params
        self.stop_hap_cycle = None
        self.back_stop_cycle = None
        self.hang_cycles = 90000000
        self.addr_of_count = None
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
        sioctl = os.getenv('IOCTL_COUNT_MAX')
        if sioctl is not None:
            self.ioctl_count_max = int(sioctl)
        else:
            self.ioctl_count_max = None
        select_s = os.getenv('SELECT_COUNT_MAX')
        if select_s is not None:
            self.select_count_max = int(select_s)
        else:
            self.select_count_max = None
        self.stop_on_read =   stop_on_read
        if not self.stop_on_read:
            sor = os.getenv('AFL_STOP_ON_READ')
            if sor is not None and sor.lower() in ['true', 'yes']:
                self.stop_on_read = True
        self.udp_header = os.getenv('AFL_UDP_HEADER')
        if packet_count > 1 and not (self.udp_header is not None or self.pad_to_size > 0):
            self.lgr.error('Multi-packet requested but no pad or UDP header has been given in env variables')
            return None
        self.one_off = False
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
            self.one_off = True
        elif os.path.isdir(dfile) and not os.path.isfile(os.path.join(dfile, 'version.pickle')):
            # avoid snapshot directories

            self.lgr.debug('playAFL, directory of input files')
            flist = os.listdir(dfile)
            if len(flist) == 0:
                self.lgr.debug('playAFL, no files in directory %s, leave' % dfile)
                return
            for f in sorted(flist):
                rfile = os.path.join(dfile, f)
                if os.path.isfile(rfile):
                    self.afl_list.append(rfile)
             
        else:
            if not crashes:
                print('get dfile queue for %s' % dfile)
                self.lgr.debug('playAFL get queue for dfile %s' % dfile)
                self.afl_list = aflPath.getTargetQueue(dfile, get_all=True)
                if len(self.afl_list) == 0:
                    print('No queue files found for %s' % dfile)
                    self.lgr.debug('playAFL No queue files found for %s' % dfile)
                    return
                self.top.noWatchSysEnter()
            else:
                self.afl_list = aflPath.getTargetCrashes(dfile)
                if len(self.afl_list) == 0:
                    print('No crashes found for %s' % dfile)
                    return
            print('Playing %d sessions.  Please wait until that is reported.' % len(self.afl_list))
            self.lgr.debug('Playing %d sessions.  Please wait until that is reported.' % len(self.afl_list))
        self.search_list = search_list
        tid = self.top.getTID()
        self.lgr.debug('playAFL afl list has %d items.  current context %s current tid:%s fname:%s search_list:%s' % (len(self.afl_list), self.target_cpu.current_context, tid, self.fname, search_list))
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
        
        if os.getenv('BACK_STOP_DELAY') is not None:
            self.backstop_delay =   int(os.getenv('BACK_STOP_DELAY'))
            self.lgr.debug('BACK_STOP_DELAY is %d' % self.backstop_delay)
        else:
            self.backstop_delay =   None
        self.packet_count = packet_count
        self.afl_packet_count = None
        self.current_packet = 0
        self.hit_total = 0
        self.diag_hits = diag_hits

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
        elif self.cpu.architecture == 'arm64':
            lenreg = 'x0'
        else:
            lenreg = 'eax'
        self.len_reg_num = self.cpu.iface.int_register.get_number(lenreg)
 
        if self.search_list is not None:
            self.no_cover = True
        self.search_found_eip = None
        
        self.snap_name = snap_name
        self.no_page_faults = no_page_faults
        if not self.loadPickle(snap_name):
            print('No AFL data stored for cell %s in checkpoint %s, cannot play AFL.' % (self.cell_name, snap_name))
            self.lgr.error('playAFL No AFL data stored for cell %s in checkpoint %s, cannot play AFL.' % (self.cell_name, snap_name))
            self.top.quit()
            return None
        self.lgr.debug('playAFL back from loadPickle')

        if target_proc is None:
            self.lgr.debug('playAFL call debugTidGroup')
            self.top.debugTidGroup(tid, to_user=False)
            self.lgr.debug('playAFL call finishInit')
            self.finishInit()

            if self.dfile != 'oneplay' or self.afl_mode or self.search_list is not None:
                self.disableReverse()
            self.initial_context = self.target_cpu.current_context
        else:
            if True or self.count > 1 or self.commence_params is not None:
                if self.commence_params is not None and os.path.isfile(self.commence_params):
                    self.loadCommenceParams()
                # assumes process is ready to injest data, e.g., a driver ready to read a json
                self.lgr.debug('playAFL will inject data so we can properly count exits prior to commence of coverage')
                self.loadInData(use_primer=True)
                count= self.doWriteData()
            ''' generate a bookmark so we can return here after setting coverage breakpoints on target.  Bookmark must be set after data inject above'''
            self.lgr.debug('playAFL target_proc %s reset origin and set target to %s.  cycle: 0x%x' % (target_proc, target_cell, self.cpu.cycles))
            self.top.resetOrigin()
            self.top.setTarget(target_cell)
            self.top.debugProc(target_proc, self.playInitCallback, not_to_user=False)
        self.did_exit = False

    def ranToIO(self, dumb):
        self.commence_coverage = self.target_cpu.cycles - self.initial_cycle
        self.top.rmSyscall('runToIO', cell_name=self.cell_name)

        # return to origin and run forward again, this time counting syscall exits
        eip = self.top.getEIP(cpu=self.target_cpu)
        self.exit_eip = self.mem_utils.v2p(self.target_cpu, eip)
        self.lgr.debug('playAFL ran to IO cycles for commence coverage after: 0x%x cycles current cycle: 0x%x exit_ip: 0x%x' % (self.commence_coverage, self.target_cpu.cycles, self.exit_eip))
        self.tid = self.top.getTID(target=self.target_cell)

        #cmd = 'skip-to bookmark = bookmark0'
        #cli.quiet_run_command(cmd)
        self.top.skipToCycle(self.initial_cycle, cpu=self.target_cpu, disable=True)
        SIM_run_alone(self.setHapsAndRun, None)

    def setHapsAndRun(self, dumb):
        self.top.stopTracking()
        self.context_manager.stopWatchTasksAlone()
        #self.context_manager.restoreDebugContext()
        self.setCycleHap(None)
        self.setCounterHap(None)
        self.lgr.debug(' <><><><><><><><><><><><><>ranToIO set counter hap and cycle hap now continue from cycle 0x%x <><><><><><><><><><><><><>' % self.target_cpu.cycles)
        #print('remove this target cpu context %s' % self.target_cpu.current_context)
        SIM_run_alone(SIM_run_command, 'continue')

    def setCounterHap(self, dumb=None):
        self.exit_counter = 0

        self.lgr.debug('playAFL setCounterHap set break on eip: 0x%x' % (self.exit_eip))
        #self.counter_bp = SIM_breakpoint(context, Sim_Break_Linear, Sim_Access_Execute, self.exit_eip, 1, 0)
        self.counter_bp = SIM_breakpoint(self.target_cpu.physical_memory, Sim_Break_Physical, Sim_Access_Execute, self.exit_eip, 1, 0)
        self.counter_hap = SIM_hap_add_callback_index("Core_Breakpoint_Memop", self.counterHap, None, self.counter_bp)

    def counterHap(self, dumb, third, break_num, memory):
        if self.counter_hap is None:
            self.lgr.debug('playAFL counter hap is none')
            return
        
        tid = self.top.getTID(target=self.target_cell)
        if tid != self.target_tid:
            #self.lgr.debug('playAFL counterHap wrong tid:%s, wanted %s cycle: 0x%x' % (tid, self.target_tid, self.target_cpu.cycles))
            return
        self.exit_counter = self.exit_counter+1
        #self.lgr.debug('playAFL counterHap, count now %d cycles: 0x%x memory: 0x%x' % (self.exit_counter, self.target_cpu.cycles, memory.physical_address))
        if self.commence_after_exits is not None and self.exit_counter == self.commence_after_exits:
            self.lgr.debug(' <><><><><><><><><><><><><>afl counterHap reached desired count, enable coverage breaks cycle 0x%x <><><><><><><><><><><><><>' % self.target_cpu.cycles)
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
        self.lgr.debug('playAFL playInitCallback. target tid: %s finish init to set coverage and such cycle: 0x%x' % (self.target_tid, self.cpu.cycles))
        self.trace_buffer = self.top.traceBufferTarget(self.target_cell, msg='playAFL')
        self.initial_context = self.target_cpu.current_context
        if self.trace_all:
            self.top.traceAll()
        # do not watch exit of consuming process, watch this one
        self.context_manager.clearExitBreaks() 
        self.context_manager.watchExit()
        if self.targetFD is not None and self.count > 1 and self.commence_after_exits is None:
            # run to IO before finishing init 
            self.top.jumperDisable(target=self.cell_name)
            self.top.setCommandCallback(self.ranToIO)
            self.top.runToIO(self.targetFD, count=self.count, break_simulation=True, target=self.target_cell)
        else:
            self.finishCallback()

    def finishCallback(self, dumb=None):
        ''' restore origin and go '''
        self.lgr.debug('playAFL finishCallback')
        self.finishInit()
        self.lgr.debug('playAFL finishCallback back from finishInit skip to bookmark')
        #cmd = 'skip-to bookmark = bookmark0'
        # TBD this will break on repeat or playing multiple files
        #cli.quiet_run_command(cmd)
        self.top.skipToCycle(self.initial_cycle, cpu=self.target_cpu, disable=True)
        self.disableReverse()
        self.top.setTarget(self.cell_name)
        tid = self.top.getTID()
        self.context_manager.stopWatchTasks()
        self.lgr.debug(' <><><><><><><><><><><><><>playAFL finishCallback, restored to original bookmark and reset target to %s tid: %s <><><><><><><><><><><><><>' % (self.cell_name, tid))
        self.go()

    def disableReverse(self):
        self.lgr.debug('playAFL disabling reverse execution and enabling internals')
        if not self.top.nativeReverse():
            self.top.disableReverse()
            self.top.takeSnapshot('origin')
        else:
            cli.quiet_run_command('disable-reverse-execution')
            #VT_take_snapshot('origin')
            cli.quiet_run_command('enable-unsupported-feature internals')
            cli.quiet_run_command('save-snapshot name = origin')

    def finishInit(self):
        self.lgr.debug('playAFL finishInit')
        if self.dfile != 'oneplay' or self.repeat:
            self.lgr.debug('playAFL finishInit call to remove debug breaks')
            self.top.removeDebugBreaks(keep_watching=False, keep_coverage=False, immediate=True)
            self.lgr.debug('playAFL finishInit call to restore watch of exits')
            self.exit_syscall = self.top.debugExitHap()
        elif self.target_proc is None:
            self.lgr.debug('playAFL finishInit target_proc None, call resetOrigin')
            self.top.resetOrigin()
        if self.target_proc is None:
            # otherwise traceBuffer set up in playInitCallback
            self.trace_buffer = self.top.traceBufferTarget(self.target_cell, msg='playAFL')
            #if len(self.trace_buffer.addr_info) == 0:
            #    self.trace_buffer = None

        self.top.stopThreadTrack(immediate=True)

        if not self.no_cover:
            self.lgr.debug('playAFL finishInit call to get coverage cycle: 0x%x' % self.cpu.cycles)
            self.coverage = self.top.getCoverage()
            if self.coverage is None:
                self.lgr.error('playAFL finishInit failed getting coverage')
 

        if self.coverage is not None:
            full_path = None
            analysis_path = None
            prog_path = None
            if self.fname is None:
                if self.target_proc is not None:
                    analysis_path = self.top.getAnalysisPath(self.target_proc)
                    if '/' not in self.target_proc:
                        prog_path = self.top.getProgPath(self.target_proc, target=self.target_cell)
                    else:
                        prog_path = self.target_proc
                    self.lgr.debug('playAFL finishInit fname is None, prog_path got %s' % prog_path)
            else:
                analysis_path = self.top.getAnalysisPath(self.fname)
                if '/' not in self.fname:
                    prog_path = self.top.getProgPath(self.fname)
                    print('Relative path given, guessing you mean %s' % prog_path)
                    self.lgr.debug('playAFL Relative path given, guessing you mean %s' % prog_path)
                else:
                    prog_path = self.fname
            self.lgr.debug('playAFL call enableCoverage analysis_path is %s prog_path = %s fname %s cycle: 0x%x' % (analysis_path, prog_path, self.fname, self.cpu.cycles))
            self.coverage.enableCoverage(self.target_tid, backstop=self.backstop, backstop_cycles=self.backstop_cycles, 
               afl=self.afl_mode, linear=self.linear, create_dead_zone=self.create_dead_zone, only_thread=self.only_thread, 
               fname=analysis_path, prog_path=prog_path, diag_hits=self.diag_hits)
            self.lgr.debug('playAFL backfrom enableCoverage')
            if self.linear:
                self.lgr.debug('playAFL, linear use context manager to watch tasks')
                self.context_manager.restoreDebugContext()
            #self.context_manager.watchTasks()
            self.coverage.doCoverage(no_merge=True)
            if self.commence_after_exits is not None:
                self.coverage.disableAll()
            else:
                self.lgr.debug('playAFL, call setHangCallback %d cycles' % self.hang_cycles)
                #self.backstop.setHangCallback(self.coverage.recordHang, self.hang_cycles)
                self.backstop.setHangCallback(self.hangCallback, self.hang_cycles)

            if False:
                ''' STOP USING prog file TBD'''
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
        if self.search_list is not None:
            self.lgr.debug('playAFL search_list at %s' % self.search_list)
            self.setSearch() 
        self.backstop.setCallback(self.backstopCallback)
        if self.watch_rop:
            load_addr, size = self.top.getLoadSize(self.fname)
            self.top.watchROP(addr=load_addr, size=size) 
            self.lgr.debug('playAFL watching rop for %s addr 0x%x size 0x%x' % (self.fname, load_addr, size))
        

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
        self.did_exit = False
        SIM_run_alone(self.goAlone, False)

    def backstopCallback(self):
        SIM_run_alone(self.backstopCallbackAlone, None)

    def backstopCallbackAlone(self, cycles):
        self.lgr.info('playAFL backstop detected')
        if self.stop_hap is None:
               self.stop_hap = self.top.RES_add_stop_callback(self.stopHap,  None)
        SIM_break_simulation('backstop')

    def hangCallback(self, cycles):
        SIM_run_alone(self.hangCallbackAlone, cycles)

    def hangCallbackAlone(self, cycles):
        self.lgr.info('playAFL hang detected')
        print('playAFL hang detected')
        if self.stop_hap is None:
               self.stop_hap = self.top.RES_add_stop_callback(self.stopHap,  None)
        SIM_break_simulation('hang')

    def stopOnRead(self, counter):
        self.lgr.info('playAFL stopOnRead callback counter %d' % counter)
        if self.stop_hap is None:
               self.stop_hap = self.top.RES_add_stop_callback(self.stopHap,  None)
        SIM_break_simulation('stopOnRead')

    def goAlone(self, clear_hits):
        self.write_data = None
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
                self.lgr.debug('playAFL goAlone hits path file %s' % fname)
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
            if self.commence_after_exits is not None:
                self.coverage.disableAll()
            if self.dfile != 'oneplay' or self.repeat:
                if not self.top.nativeReverse():
                    self.top.restoreSnapshot('origin')
                else:
                    cli.quiet_run_command('restore-snapshot name=origin')
            #VT_restore_snapshot('origin')
            if self.commence_after_exits is not None:
                self.lgr.debug('playAFL goAlone set counter hap')
                self.setCounterHap()
            if self.coverage is not None:
                if clear_hits and not self.repeat:
                    self.lgr.debug('playAfl goAlone already have coverage, re-enable all breakpoints')
                    self.coverage.resetCoverage()
            #        #self.coverage.stopCover() 
            #        #self.coverage.setBlockBreaks()
            #        #self.coverage.doCoverage(no_merge=True, physical=self.physical) 
            #if self.orig_buffer is not None:
            #    #self.lgr.debug('playAFL restored %d bytes to original buffer at 0x%x' % (len(self.orig_buffer), self.addr))
            #    self.mem_utils.writeBytes(self.cpu, self.addr, self.orig_buffer) 
            self.lgr.info('playAFL try afl_list entry %s' % self.afl_list[self.index])

            if self.in_data is None or not self.repeat:
                self.loadInData()
                self.lgr.debug('playAFL goAlone loaded %d bytes from file session %d of %d' % (len(self.in_data), self.index, len(self.afl_list)))
        
            #if self.orig_buffer is not None:
            #    ''' restore receive buffer to original condition in case injected data is smaller than original and poor code
            #        references data past the end of what is received. '''
            #    self.mem_utils.writeBytes(self.cpu, self.addr, self.orig_buffer) 
            #    self.lgr.debug('playAFL restored %d bytes to original buffer at 0x%x' % (len(self.orig_buffer), self.addr))
            #self.top.restoreRESimContext()
            #self.context_manager.restoreDebugContext()
            self.lgr.debug('playAFL here')
            if self.write_data is None:
                count= self.doWriteData()
            else:
                self.lgr.debug('playAFL goAlone **** write_data not None ***')
                count = 0

            if self.trace_all:
                self.write_data.tracingIO()
            eip = self.top.getEIP(self.cpu)
            if self.coverage is not None:
                bp_count = self.coverage.bpCount()
                self.lgr.debug('playAFL goAlone tid:%s ip: 0x%x wrote %d bytes from file %s continue from cycle 0x%x %d cpu context: %s %d breakpoints set' % (self.tid, eip, count, self.afl_list[self.index], self.target_cpu.cycles, self.target_cpu.cycles, str(self.target_cpu.current_context), bp_count))
            # TBD just rely on coverage?
            #self.backstop.setFutureCycle(self.backstop_cycles, now=True)
            if self.trace_buffer is not None:
                self.trace_buffer.msg('playAFL from '+self.afl_list[self.index])
            if self.trace_all:
                self.lgr.debug('playAFL goAlone call traceAll')
                self.top.traceAll()

            if self.afl_mode: 
                if self.coverage is not None:
                    if self.repeat is False or self.repeat_counter > 1:
                        self.coverage.watchExits(callback=self.reportExit, suspend_callback=self.reportSuspend, tid=self.target_tid)
                else:
                    self.lgr.error('playAFL afl_mode but not coverage?')
                    return
            elif self.coverage is not None:
                self.coverage.watchExits(callback=self.reportExit, suspend_callback=self.reportSuspend, tid=self.target_tid)
            else:
                self.context_manager.watchGroupExits()
                self.context_manager.setExitCallback(self.reportExit)
            self.lgr.debug('playAFL goAlone call watch tasks target tid %s' % self.target_tid)
            self.context_manager.watchTasks(tid=self.target_tid)
            #if self.stop_hap is None:
            #    self.stop_hap = self.top.RES_add_stop_callback(self.stopHap,  None)

            self.lgr.debug('playAFL goAlone watch page faults for tid:%s cell %s' % (self.target_tid, self.target_cell))
            if not self.no_page_faults:
                self.top.watchPageFaults(tid=self.target_tid, target=self.target_cell, afl=self.afl_mode)
            else:
                self.lgr.debug('playAFL goAlone will not watch page faults, will miss segv')
                self.top.stopWatchPageFaults()
            if self.dfile == 'oneplay' and not self.repeat and self.target_proc is None:
                self.lgr.debug('playAFL goAlone is onePlay and not repeat, not calling resetOrigin')
                #self.top.resetOrigin()

            if self.search_list is not None and self.backstop_cycles is not None and self.backstop_cycles > 0:
                self.backstop.setFutureCycle(self.backstop_cycles, now=False)

            if self.exit_syscall is not None:
                # syscall tracks cycle of recent entry to avoid hitting same hap for a single syscall.  clear that.
                self.exit_syscall.resetHackCycle()

            self.lgr.debug('playAFL goAlone now continue')
            if self.repeat:
                #if self.repeat_counter > 20:
                #    return
                self.lgr.debug('playAFL goAlone repeat set, do continue')
                SIM_continue(0)
                self.lgr.debug('playAFL goAlone repeat set, did continue')
                pass
            else:
                self.lgr.debug('playAFL goAlone repeat not set, do continue from cycle: 0x%x' % self.cpu.cycles)
                SIM_continue(0)
                self.lgr.debug('playAFL goAlone repeat not set, back from did continue')
                pass
        else:
            self.lgr.info('playAFL did all sessions.')
            ''' did all sessions '''
            if self.coverage is not None and self.findbb is None and not self.afl_mode and not self.parallel and not os.path.isdir(self.dfile):
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
                            if self.show_new_hits:
                                print('New hit found at 0x%x' % hit)
                            count = count+1
                    if count == 0:
                        print('No new hits.')
                    else:
                        print('Found %d new hits that were not in %s' % (count, all_prev_hits_path))
                        
                else:
                    print('no hits file at %s ?' % all_prev_hits_path)
            elif self.parallel:
                self.top.quit()
            if self.stop_hap is not None:
                hap = self.stop_hap
                self.top.RES_delete_stop_hap_run_alone(hap)
                self.stop_hap = None
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
                if not self.top.nativeReverse():
                    self.top.restoreSnapshot('origin')
                else:
                    cli.quiet_run_command('restore-snapshot name=origin')
            else:
                self.top.stopCoverage() 
               
    def doWriteData(self): 
        if self.write_data is None:
            force_default_context = False
            #force_default_context = True
            #if self.dfile == 'oneplay' and not self.repeat:
            #    force_default_context = False
            self.lgr.debug('playAFL gen writeData')
            write_callback = None
            if self.stop_on_read or self.ioctl_count_max is not None:
                write_callback = self.stopOnRead
            self.write_data = writeData.WriteData(self.top, self.cpu, self.in_data, self.afl_packet_count, 
                     self.mem_utils, self.context_manager, self.backstop, self.snap_name, self.lgr, udp_header=self.udp_header, 
                     pad_to_size=self.pad_to_size, backstop_cycles=self.backstop_cycles, force_default_context=force_default_context, 
                     #filter=self.filter_module, stop_on_read=self.stop_on_read, write_callback=write_callback)
                     filter=self.filter_module, stop_on_read=self.stop_on_read, shared_syscall=self.top.getSharedSyscall(), write_callback=write_callback,
                     ioctl_count_max=self.ioctl_count_max, select_count_max=self.select_count_max, backstop_delay=self.backstop_delay)
        else:
            self.write_data.reset(self.in_data, self.afl_packet_count, self.addr)
        count = self.write_data.write()
        self.lgr.debug('playAFL called writeData, wrote %d bytes' % count)
        if self.mem_utils.isKernel(self.addr):
            if self.addr_of_count is not None and not self.top.isWindows():
                self.lgr.debug('playAFL set ioctl wrote len in_data %d to 0x%x' % (count, self.addr_of_count))
                self.mem_utils.writeWord32(self.cpu, self.addr_of_count, count)
                self.write_data.watchIOCtl()
        return count

    def loadInData(self, use_primer=False):
        if use_primer and self.primer is not None:
            if not os.path.isfile(self.primer):
                self.lgr.error('playAFL loadInData primer file %s not found' % self.primer)
            with open(self.primer, 'rb') as fh:
                self.lgr.debug('playAFL loadInData from primer %s' % self.primer)
                if sys.version_info[0] == 2:
                    self.in_data = bytearray(fh.read())
                else:
                    self.in_data = fh.read()
            self.afl_packet_count = self.packet_count

        else:
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
                    self.lgr.debug('playAFL loadInData from %s' % full)
                    if sys.version_info[0] == 2:
                        self.in_data = bytearray(fh.read())
                    else:
                        self.in_data = fh.read()
                self.afl_packet_count = self.packet_count

    def getHitsPath(self, index):
        fname = None
        self.lgr.debug('playAFL getHitsPath index %d, len(afl_list) %d' % (index, len(self.afl_list)))
        if index < len(self.afl_list):
            queue_dir = os.path.dirname(self.afl_list[index])
            queue_parent = os.path.dirname(queue_dir)
            if self.search_list is None:
                if os.path.basename(queue_dir) == 'manual_queue':
                    coverage_dir = os.path.join(queue_parent, 'manual_coverage')
                else:
                    coverage_dir = os.path.join(queue_parent, 'coverage')
            else:
                if os.path.basename(queue_dir) == 'manual_queue':
                    coverage_dir = os.path.join(queue_parent, 'manual_search')
                else:
                    coverage_dir = os.path.join(queue_parent, 'search')
            try:
                os.makedirs(coverage_dir)
            except:
                pass
            fname = os.path.join(coverage_dir, os.path.basename(self.afl_list[self.index])) 
            self.lgr.debug('playAFL getHitsPath returning fname %s coverage_dir was %s' % (fname, coverage_dir))
        return fname

    def getExitsPath(self, index):
        queue_dir = os.path.dirname(self.afl_list[index])
        queue_parent = os.path.dirname(queue_dir)
        if os.path.basename(queue_dir) == 'manual_queue':
            exits_dir = os.path.join(queue_parent, 'manual_exits')
        else:
            exits_dir = os.path.join(queue_parent, 'exits')
        try:
            os.makedirs(exits_dir)
        except:
            pass
        fname = os.path.join(exits_dir, os.path.basename(self.afl_list[self.index])) 
        return fname

    def recordHits(self, hit_bbs):
        ''' Record coverage, including cycles.  File will go in a "coverage" directory along side queue, etc. unless it is a one-off'''
        self.lgr.debug('playAFL recordHits %d' % len(hit_bbs))
        #hit_list = list(hit_bbs.keys())
        if self.one_off:
            print('Assume ad-hoc path, coverage (hits & cycles) stored in /tmp/playAFL.coverage')
            fname = '/tmp/playAFL.coverage'
        else:
            fname = self.getHitsPath(self.index)
        self.lgr.debug('playAFL recordHits to file %s' % fname)
        with open(fname, 'w') as fh:
            #json.dump(hit_list, fh) 
            json.dump(hit_bbs, fh) 
        #for hit in hit_list:
        for hit in hit_bbs:
            hit = int(hit)
            if hit not in self.all_hits:
                self.all_hits.append(hit)
        if self.one_off:
            print('Hits list (for IDA) stored %d hits in /tmp/playAFL.hits' % len(self.all_hits))
            fname = '/tmp/playAFL.hits'
            with open(fname, 'w') as fh:
                json.dump(self.all_hits, fh) 
        else:
            base = os.path.basename(fname)
            print('%d hits in this play for %s.' % (len(hit_bbs), base))
        self.reportNewHits()

    def reportNewHits(self):
            prog_path = self.top.getProgName(self.target_tid, target=self.target_cell)
            if prog_path is not None:
                hits_path = self.top.getIdaData(prog_path, target=self.cell_name)
                self.lgr.debug('playAFL recordHits prog_path %s hits path from getIdaData %s' % (prog_path, hits_path))

                all_prev_hits_path = '%s.hits' % hits_path
                if os.path.isfile(all_prev_hits_path):
                    all_prev_hits = json.load(open(all_prev_hits_path))
                    count = 0
                    for hit in self.all_hits:
                        if hit not in all_prev_hits:
                            if self.show_new_hits:
                                print('New hit found at 0x%x' % hit)
                            count = count+1
                    if count == 0:
                        print('No new hits.')
                    else:
                        print('Found %d new hits that were not in %s' % (count, all_prev_hits_path))

    def recordExits(self, path):
        ''' exits will go in a "exits" directory along side queue, etc. '''
        self.lgr.debug('playAFL recordExits for %s' % path)
        if not self.one_off:
            fname = self.getExitsPath(self.index)
        else:
            fname = '/tmp/exit.msg'
        with open(fname, 'w') as fh:
            #json.dump(hit_list, fh) 
            msg = '%s : %s\n' % (path, self.context_manager.getIdaMessage())
            fh.write(msg)
            fh.flush()
            self.lgr.debug('playAFL recordExits msg: %s' % msg)

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
                delta = self.target_cpu.cycles - self.initial_cycle
                self.lgr.debug('playAFL stophap getBlocksHit returned %d hits over 0x%x cycles' % (len(hit_bbs), delta))
                if self.findbb is not None and self.index < len(self.afl_list):
                    self.lgr.debug('looking for bb 0x%x' % self.findbb)
                    if self.findbb in hit_bbs:
                        packet_num = self.write_data.getCurrentPacket()
                        self.bnt_list.append((self.afl_list[self.index], packet_num))
                #elif self.dfile == 'oneplay':
                elif not self.repeat:
                    self.recordHits(hit_bbs)
                    self.coverage.saveDeadFile()
                    if self.stop_hap is not None:
                        hap = self.stop_hap
                        self.top.RES_delete_stop_hap_run_alone(hap)
                        self.stop_hap = None
                    self.lgr.debug('playAFL stopHap, not repeat, should be done.')
                if self.coverage.didExit() or self.did_exit:
                    self.lgr.debug('playAFL stopHap coverage says didExit, add to exit_list')
                    self.exit_list.append(self.afl_list[self.index])
                    self.recordExits(self.afl_list[self.index])

                if self.top.hasPendingPageFault(self.target_tid, target=self.target_cell):
                    print('TID %s has pending page fault' % self.target_tid)
                    self.lgr.debug('TID %s has pending page fault' % self.target_tid)
            elif self.search_list is not None:
                self.lgr.debug('playAFL stopHap Search completed.')
            else:
                self.lgr.debug('playAFL stopHap, coverage not set and no search list')
            self.top.clearExitTid()
            if self.repeat or self.dfile != 'oneplay':
                self.context_manager.stopWatchTasks()
                SIM_run_alone(self.goAlone, True)

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
            if 'addr_of_count' in so_pickle and so_pickle['addr_of_count'] is not None: 
                self.addr_of_count = so_pickle['addr_of_count']
                self.lgr.debug('injectIO load addr_of_count 0x%x' % (self.addr_of_count))
        return retval

    def reportExit(self):
        self.did_exit = True
        SIM_run_alone(self.reportExitAlone, None)

    def reportExitAlone(self, dumb):
        print('Process exit  cycles 0x%x' % self.target_cpu.cycles)
        self.lgr.debug('playAFL reportExitAlone Process exit  cycles 0x%x' % self.target_cpu.cycles)
        if self.stop_hap is None:
               self.stop_hap = self.top.RES_add_stop_callback(self.stopHap,  None)
        SIM_break_simulation('process exit')
 
    def reportSuspend(self):
        self.did_suspend = True
        SIM_run_alone(self.reportSuspendAlone, None)

    def reportSuspendAlone(self, dumb):
        print('Process suspend, bail. cycles 0x%x' % self.target_cpu.cycles)
        self.lgr.debug('playAFL reportSuspendAlone Process suspend, bail. cycles 0x%x' % self.target_cpu.cycles)
        if self.stop_hap is None:
               self.stop_hap = self.top.RES_add_stop_callback(self.stopHap,  None)
        SIM_break_simulation('process suspend')
 
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
        self.lgr.debug('playAFL cycle_handler exit counter is %d cycle: 0x%x' % (self.exit_counter, self.target_cpu.cycles))
        self.write_data = None
        self.commence_after_exits = self.exit_counter
        if self.commence_params is not None:
            with open(self.commence_params, 'w') as fh:
                fh.write('0x%x\n' % self.exit_counter) 
                fh.write('0x%x\n' % self.exit_eip) 
                fh.write('%s\n' % self.target_tid) 
                self.lgr.debug('afl cycle_handler created commence params file %s' % self.commence_params)
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
        self.stop_hap_cycle = self.top.RES_add_stop_callback(self.stopHapCycle,  None)
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
            self.top.RES_delete_stop_hap(self.stop_hap_cycle)
            self.lgr.debug('playAFL stop_hap_cycle removed')
            self.stop_hap_cycle = None

    def setSearch(self):
        with open(self.search_list) as fh:
            for line in fh:
                line = line.strip()
                if line.startswith('#'):
                    continue
                addr = int(line, 16)
                context = self.target_cpu.current_context
                search_bp = SIM_breakpoint(context, Sim_Break_Linear, Sim_Access_Write, addr, 1, 0)
                self.search_hap = SIM_hap_add_callback_index("Core_Breakpoint_Memop", self.searchHap, None, search_bp)
                self.lgr.debug('playAFL set search break on 0x%x' % addr)

    def searchHap(self, dumb, third, break_num, memory):
        self.lgr.debug('searchHap hit mem 0x%x' % memory.logical_address)
        print('searchHap hit mem 0x%x' % memory.logical_address)
        eip = self.top.getEIP(cpu=self.target_cpu)
        value = memUtils.memoryValue(self.cpu, memory)
        self.recordSearchFind(memory.logical_address, eip, value)

    def recordSearchFind(self, addr, eip, value):
        ''' search finds will go in a "search" directory along side queue, etc. '''
        self.lgr.debug('playAFL recordSearchFinds')
        #hit_list = list(hit_bbs.keys())
        fname = self.getHitsPath(self.index)
        if fname is not None: 
            basename = os.path.basename(fname)
            self.lgr.debug('playAFL recordSearchFind record hit at eip 0x%x value 0x%x from %s' % (eip, value, basename))
            if not os.path.isfile(fname):
                self.lgr.debug('playAFL recordSearchFind, assume ad-hoc path')
            with open(fname, 'w') as fh:
                fh.write('addr:0x%x eip:0x%x value:0x%x' % (addr, eip, value))

    def loadCommenceParams(self): 
        with open(self.commence_params) as fh:
            self.commence_after_exits = int(fh.readline(), 16) 
            self.exit_eip = int(fh.readline(), 16) 
            self.target_tid = fh.readline()
            self.lgr.debug('afl loadCommenceParams loaded from %s' % self.commence_params)
