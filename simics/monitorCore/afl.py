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
Play AFL sessions, commencing at a snapshot generated via prepInject or
prepInjectWatch.
'''
import os
import stat
import shutil
import time
import socket
import sys
import pickle
import struct
import json
import cli
import stopFunction
import writeData
import resimUtils
import defaultConfig
#import tracemalloc
from simics import *
RESIM_MSG_SIZE=80
AFL_OK=0
AFL_CRASH=1
AFL_HANG=2
AFL_CLOSED=3
class AFL():
    def __init__(self, top, cpu, cell_name, coverage, backstop, mem_utils, snap_name, context_manager, page_faults, lgr,
                 packet_count=1, stop_on_read=False, fname=None, linear=False, target_cell=None, target_proc=None, targetFD=None,
                 count=1, create_dead_zone=False, port=8765, one_done=False, test_file=None, commence_params=None):
        pad_env = os.getenv('AFL_PAD') 
        self.lgr = lgr
        if pad_env is not None:
            try:
                self.pad_to_size = int(pad_env)
            except:
                self.lgr.error('Bad AFL_PAD value %s' % pad_env)
                return
        else: 
            self.pad_to_size = 0
        self.udp_header = os.getenv('AFL_UDP_HEADER')
        if packet_count > 1 and not (self.udp_header is not None or self.pad_to_size > 0):
            self.lgr.error('Multi-packet requested but no pad or UDP header has been given in env variables')
            return
        self.filter_module = None
        packet_filter = os.getenv('AFL_PACKET_FILTER')
        if packet_filter is not None:
            self.filter_module = resimUtils.getPacketFilter(packet_filter, lgr)

        self.pad_char = chr(0)
        self.cpu = cpu
        self.cell_name = cell_name
        self.top = top
        self.mem_utils = mem_utils
        self.stop_on_read = stop_on_read
        self.coverage = coverage
        self.context_manager = context_manager
        self.linear = linear
        # For multi-packet UDP.  afl_packet_count may be adjusted less than given packet count.
        self.packet_count = packet_count
        self.afl_packet_count = None
        self.current_packet = 0
        self.backstop = backstop
        self.stop_hap = None
        self.call_break = None
        self.call_hap = None
        self.in_data = None
        self.orig_in_data = None
        self.orig_data_length = 0
        self.write_data = None

        if target_cell is None:
            self.target_cell = cell_name
        else:
            self.target_cell = target_cell
        self.target_cpu = self.top.getCPU(self.target_cell)
        self.target_proc = target_proc
        self.targetFD = targetFD
        self.count = count
        self.cycle_event = None

        self.create_dead_zone = create_dead_zone
        self.backstop.setCallback(self.whenDone)
        self.port = port
        self.one_done = one_done
        self.page_faults = page_faults
        sor = os.getenv('AFL_STOP_ON_READ')
        if sor is not None and sor.lower() in ['true', 'yes']:
            self.stop_on_read = True
        # TBD why are sor and backstop mutually exclusive?
        if stop_on_read:
            self.backstop_cycles = 0
        else:
            self.backstop_cycles = defaultConfig.aflBackstopCycles()
            self.lgr.debug('afl AFL_BACK_STOP_CYCLES is %d' % self.backstop_cycles)

        if os.getenv('BACK_STOP_DELAY') is not None:
            self.backstop_delay =   int(os.getenv('BACK_STOP_DELAY'))
            self.lgr.debug('BACK_STOP_DELAY is %d' % self.backstop_delay)
        else:
            self.backstop_delay =  None 

        sioctl = os.getenv('IOCTL_COUNT_MAX')
        if sioctl is not None:
            self.ioctl_count_max = int(sioctl)
            self.lgr.debug('IOCTL_COUNT_MAX is %d' % self.ioctl_count_max)
        else:
            self.ioctl_count_max = None
        select_s = os.getenv('SELECT_COUNT_MAX')
        if select_s is not None:
            self.select_count_max = int(select_s)
        else:
            self.select_count_max = None

        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.settimeout(2)
        self.server_address = ('localhost', self.port)
        self.iteration = 1
        self.tid = self.top.getTID()
        if target_proc is None:
            self.target_tid = self.tid
        else:
            self.target_tid = None
        self.total_hits = 0
        self.bad_trick = False
        self.trace_snap1 = None
        self.empty_trace_bits = None
        self.restart = 0
        if self.cpu.architecture == 'arm':
            lenreg = 'r0'
        elif self.cpu.architecture == 'arm64':
            lenreg = 'x0'
        else:
            lenreg = 'eax'
        self.len_reg_num = self.cpu.iface.int_register.get_number(lenreg)
        self.pc_reg = self.cpu.iface.int_register.get_number('pc')
        self.addr = None
        self.orig_buffer = None
        self.hang_cycles = 90000000
        hang = os.getenv('HANG_CYCLES')
        if hang is not None:
            self.hang_cycles = int(hang)
        self.lgr.debug('AFL init from snap %s' % snap_name)
        self.addr_of_count = None

        self.snap_name = snap_name
        self.loadPickle(snap_name)

        self.resim_ctl = None
        #if resimUtils.isParallel():
        if test_file is None:
            if stat.S_ISFIFO(os.stat('resim_ctl.fifo').st_mode):
                self.lgr.debug('afl found resim_ctl.fifo, open it for read %s' % os.path.abspath('resim_ctl.fifo'))
                self.resim_ctl = os.open('resim_ctl.fifo', os.O_RDONLY | os.O_NONBLOCK)
                self.lgr.debug('afl back from open')
            else: 
                self.lgr.debug('AFL did NOT find resim_ctl.fifo')
         
        self.starting_cycle = self.target_cpu.cycles 
        self.total_cycles = 0
        self.tmp_time = time.time()
        self.fname = fname
        self.tid_list = []
        self.commence_coverage = None
        self.commence_after_exits = None
        self.counter_bp = None
        self.counter_hap = None
        self.exit_counter = 0
        self.exit_eip = None
        self.commence_params = commence_params
        self.stop_hap_cycle = None

        self.exit_syscall = None

        self.did_page_faults = False
        self.test_file = test_file
        self.function_backstop_hap = None
        self.functionBackstop()
        if target_proc is None:
            self.top.debugTidGroup(self.tid, to_user=False, track_threads=False)
            self.finishInit()
            self.disableReverse()

        else:
            if self.count > 1 or self.commence_params is not None: 
                if self.commence_params is not None and os.path.isfile(self.commence_params):
                    self.loadCommenceParams()
                else:
                    # need good data to determine where we should commence coverage
                    if self.test_file is None:
                        self.lgr.error('afl can only generate commence_params with a test file')
                        self.top.quit()
                        return
                    else:
                        with open(self.test_file, 'rb') as fh:
                            self.in_data = fh.read()
                    self.afl_packet_count = self.packet_count
                    self.doWriteData()
            ''' need a bookmark to get back to here after setting up debug process '''
            self.top.resetOrigin()
            self.top.setTarget(self.target_cell) 
            self.lgr.debug('afl use target proc %s on cell %s, call debug' % (target_proc, target_cell))
            self.top.debugProc(target_proc, self.aflInitCallback, track_threads=False)
        #self.coverage.watchExits()
        self.context_manager.setExitCallback(self.didExit)

    def didExit(self, dumb=None):
        self.lgr.debug('afl didExit, break simulation')
        SIM_break_simulation('didExit')
    
    def ranToIO(self, dumb):
        ''' callback after completing runToIO '''
        #SIM_break_simulation('remove this')
        self.commence_coverage = self.target_cpu.cycles - self.starting_cycle
        self.lgr.debug('afl ran to IO cycles for commence coverage after: 0x%x cycles' % self.commence_coverage)
        self.top.rmSyscall('runToIO', cell_name=self.cell_name)

        # return to origin and run forward again, this time counting syscall exits
        eip = self.top.getEIP(cpu=self.target_cpu)
        self.exit_eip = self.mem_utils.v2p(self.target_cpu, eip)
        self.tid = self.top.getTID(target=self.target_cell)

        #cmd = 'skip-to bookmark = bookmark0'
        #cli.quiet_run_command(cmd)
        self.top.skipToCycle(self.starting_cycle, cpu=self.target_cpu)
        SIM_run_alone(self.setHapsAndRun, None)

    def setHapsAndRun(self, dumb):
        self.top.stopTracking()
        self.context_manager.stopWatchTasksAlone()
        self.setCycleHap(None)
        self.setCounterHap(None)
        self.lgr.debug(' <><><><><><><><><><><><><>ranToIO set counter hap and cycle hap now continue from cycle 0x%x <><><><><><><><><><><><><>' % self.target_cpu.cycles)
        #print('remove this target cpu context %s' % self.target_cpu.current_context)
        SIM_run_alone(SIM_run_command, 'continue')

    def setCounterHap(self, dumb=None):
        self.exit_counter = 0
        self.lgr.debug('afl setCounterHap')
        self.counter_bp = SIM_breakpoint(self.target_cpu.physical_memory, Sim_Break_Physical, Sim_Access_Execute, self.exit_eip, 1, 0)
        #self.counter_bp = SIM_breakpoint(self.target_cpu.current_context, Sim_Break_Linear, Sim_Access_Execute, self.exit_eip, 1, 0)
        self.counter_hap = SIM_hap_add_callback_index("Core_Breakpoint_Memop", self.counterHap, None, self.counter_bp)

    def counterHap(self, dumb, third, break_num, memory):
        if self.counter_hap is None:
            return
        tid = self.top.getTID(target=self.target_cell)
        if tid != self.target_tid:
            #self.lgr.debug('afl counterHap wrong tid:%s, wanted %s' % (tid, self.target_tid))
            return
        self.exit_counter = self.exit_counter+1
        #self.lgr.debug('afl counterHap, count now %d' % self.exit_counter)
        if self.commence_after_exits is not None and self.exit_counter == self.commence_after_exits:
            eip = self.top.getEIP(cpu=self.target_cpu)
            #self.lgr.debug('<><><><><><><><><><>afl counterHap reached desired count, enable coverage breaks eip 0x%x <><><><><><><><><><>' % eip)
            self.coverage.enableAll()
            SIM_run_alone(self.setHangCallback, None)
            hap = self.counter_hap
            SIM_run_alone(self.rmCounterHap, hap)
            self.counter_hap = None

    def setHangCallback(self, dumb):
        self.backstop.setHangCallback(self.coverage.recordHang, self.hang_cycles)

    def aflInitCallback(self):
        self.lgr.debug('afl aflInitCallback')
        ''' Now in target process'''

        self.target_tid = self.top.getTID()
        ''' We are in the target process and completed debug setup including getting coverage module.  Go back to origin '''
        self.tid_list = self.context_manager.getWatchTids()
        self.lgr.debug('afl aflInitCallback. target tid: %s finish init to set coverage and such tid_list len %d' % (self.target_tid, len(self.tid_list)))
        if self.targetFD is not None and self.count > 1 and self.commence_after_exits is None:
            ''' run to IO before finishing init '''
            self.lgr.debug('afl aflInitCallback targetFD 0x%x' % self.targetFD)
            self.top.jumperDisable(target=self.cell_name)
            self.top.setCommandCallback(self.ranToIO)
            self.top.runToIO(self.targetFD, count=self.count, break_simulation=True, target=self.target_cell)
        else:
            self.lgr.debug('afl aflInitCallback not targetFD, just call finishCallback')
            self.finishCallback()

    def finishCallback(self, dumb=None):
        ''' Setup complete, ready to restore origin and go '''
        #self.lgr.debug('afl finishCallback call finishInit')
        self.finishInit()
        #cmd = 'skip-to bookmark = bookmark0'
        #cli.quiet_run_command(cmd)
        self.top.skipToCycle(self.starting_cycle, cpu=self.target_cpu)
        self.disableReverse()
        self.top.setTarget(self.cell_name)
        self.context_manager.stopWatchTasks()
        tid = self.top.getTID()
        #self.lgr.debug('afl finishCallback, restored to original bookmark and reset target to %s tid: %s' % (self.cell_name, tid))
        self.goN(0)

    def disableReverse(self):
        if not self.top.nativeReverse():
            self.top.disableReverse()
            self.top.takeSnapshot('origin')
        else:
            cli.quiet_run_command('disable-reverse-execution')
            #VT_take_snapshot('origin')
            cli.quiet_run_command('enable-unsupported-feature internals')
            cli.quiet_run_command('save-snapshot name = origin')

    def finishInit(self, dumb=None):
            if len(self.tid_list) == 0:
                # If we did a pre-run ?
                self.tid_list = self.context_manager.getWatchTids()
            self.lgr.debug('afl finishInit %d tids in list' % len(self.tid_list))
            self.top.removeDebugBreaks(keep_watching=False, keep_coverage=False, immediate=True)
            #if self.orig_buffer is not None:
            #    self.lgr.debug('restored %d bytes 0x%x context %s' % (len(self.orig_buffer), self.addr, self.cpu.current_context))
            #    self.mem_utils.writeBytes(self.cpu, self.addr, self.orig_buffer) 
            if self.fname is None:
                analysis_path = self.top.getAnalysisPath(self.target_proc)
                prog_path = self.top.getProgPath(self.target_proc, target=self.target_cell)
            else:
                analysis_path = self.top.getAnalysisPath(self.fname)
                if '/' not in self.fname:
                    prog_path = self.top.getProgPath(self.fname)
                    print('Relative path given, guessing you mean %s' % prog_path)
                    self.lgr.debug('afl Relative path given, guessing you mean %s' % prog_path)
                else:
                    prog_path = self.fname

            self.coverage = self.top.getCoverage()
            if self.coverage is None:
                self.lgr.error('Failed to get coverage.')
                self.top.quit()
                return
            self.coverage.enableCoverage(self.target_tid, backstop=self.backstop, backstop_cycles=self.backstop_cycles, 
                afl=True, fname=prog_path, linear=self.linear, create_dead_zone=self.create_dead_zone, record_hits=False)

            if not self.linear:
                self.context_manager.restoreDefaultContext()
                self.lgr.debug('afl, set default context. %s' % str(self.target_cpu.current_context))

            self.coverage.doCoverage()
            if self.test_file is None:
                self.synchAFL()
            if self.commence_after_exits is not None:
                self.coverage.disableAll()
            else:
                self.setHangCallback(None)
            self.lgr.debug('afl finishInit, num packets is %d stop_on_read is %r' % (self.packet_count, self.stop_on_read))
            self.fault_hap = None
            self.lgr.debug('afl finishInit, call debugExitHap to catch exits')
            self.exit_syscall = self.top.debugExitHap(context=self.target_cpu.current_context)

            self.lgr.debug('afl finishInit, clear context manager debugging tid')
            self.context_manager.clearDebuggingTid()
            #tracemalloc.start()
            # hack around Simics model bug
            #self.fixFaults()

    def rmStopHap(self):
        if self.stop_hap is not None:
            SIM_hap_delete_callback_id("Core_Simulation_Stopped", self.stop_hap)
            self.stop_hap = None
            #self.lgr.debug('afl removed stop hap')

    def traceChecksum(self, trace_bits):
        cksum = 0
        for byte in trace_bits:
            cksum += byte
        return cksum & 0xff
    def finishUp(self): 
            if self.bad_trick and self.empty_trace_bits is not None:
                trace_bits = self.empty_trace_bits
            else:
                trace_bits = self.coverage.getTraceBits()
                #cksum = self.traceChecksum(trace_bits)
                #self.lgr.debug('afl finishup cksum is 0x%x' % cksum)
                if self.empty_trace_bits is None:
                    self.empty_trace_bits = trace_bits
            self.coverage.rmModeHap()
            new_hits = self.coverage.getHitCount() 
            self.total_hits += new_hits
            delta_cycles = self.target_cpu.cycles-self.starting_cycle
            self.total_cycles = self.total_cycles+(self.target_cpu.cycles-self.starting_cycle)
            if self.iteration % 100 == 0:
                avg = self.total_hits/100
                avg_cycles = self.total_cycles/100
                now = time.time()
                delta = 100/(now - self.tmp_time)
                self.lgr.debug('afl finishUp average hits in last 100 iterations is %d avg cycles: 0x%x execs/sec: %.2f' % (avg, int(avg_cycles), delta))
                self.total_hits = 0
                self.total_cycles = 0
                self.tmp_time = time.time()
                struct._clearcache()
                #dog = SIM_run_command('list-breakpoints')
                #self.lgr.debug(dog)
                #print(dog)
                #self.top.showHaps()
            #self.lgr.debug('afl finishUp bitfile iteration %d cycle: 0x%x new_hits: %d delta cycles 0x%x' % (self.iteration, self.target_cpu.cycles, new_hits, delta_cycles))
            if self.create_dead_zone:
                self.lgr.debug('afl finishUp, create dead zone so ignore status to avoid hangs.')
                status = AFL_OK
            else:
                status = self.coverage.getStatus()
            if status == AFL_OK:
                #tid_list = self.context_manager.getWatchTids()
                if len(self.tid_list) == 0:
                    self.lgr.error('afl finishUp no tids from getThreadTids')
                for tid in self.tid_list:
                    if self.page_faults.hasPendingPageFault(tid):
                        self.lgr.debug('afl finishUp found pending page fault for tid:%s' % tid)
                        status = AFL_CRASH
                        break
            # why again and again?
            #self.page_faults.stopWatchPageFaults()
            self.page_faults.clearPendingFaults()
            self.top.clearExitTid()
            if status == AFL_CRASH:
                self.lgr.debug('afl finishUp status reflects crash %d iteration %d, data written to ./icrashed' %(status, self.iteration)) 
                with open('./icrashed', 'wb') as fh:
                    fh.write(self.orig_in_data)
            elif status == AFL_HANG:
                self.lgr.debug('afl finishUp status reflects hang %d iteration %d, data written to ./ihung' %(status, self.iteration)) 
                with open('./ihung', 'wb') as fh:
                    fh.write(self.orig_in_data)
                #self.top.quit()
                #return
            if self.test_file is not None:
                if status == AFL_CRASH:
                    self.lgr.debug('afl test file, found %d unique hits, CRASHED.  Done.' % self.total_hits)
                    print('afl test file %s, found %d unique hits crashed !! ' % (self.test_file, self.total_hits))
                elif status == AFL_HANG:
                    self.lgr.debug('afl test file, found %d unique hits, HUNG. Done' % self.total_hits)
                    print('afl test file %s, found %d unique hits hung ' % (self.test_file, self.total_hits))
                else:
                    now = time.time()
                    delta = (now - self.tmp_time)
                    self.lgr.debug('afl test file, found %d unique hits. 0x%x cycles in %.2f seconds Done' % (self.total_hits, delta_cycles, delta))
                    print('afl test file %s, found %d unique hits, 0x%x cycles %.2f seconds' % (self.test_file, self.total_hits, delta_cycles, delta))
                return

            if self.one_done:
                self.sock.close()
                self.coverage.stopCover()
                self.lgr.debug('afl one and done, removed coverage breaks')
                return

            fifo_read = None
            if self.resim_ctl is not None:
                try:
                    fifo_read = os.read(self.resim_ctl, 10)
                except OSError as err:
                    pass
            do_quit = False
            if fifo_read is not None:
                if fifo_read.startswith(b'restart'):
                    self.lgr.debug('afl fifo_read got %s, do restart' % fifo_read)
                    self.restart = True
                elif fifo_read.startswith(b'quit'):
                    do_quit = True

            closed_fd = self.write_data.closedFD() 
            if closed_fd and status == AFL_OK:
                #self.lgr.debug('afl status closed')
                status = AFL_CLOSED 

            ''' Send the status message '''
            if self.restart:
                self.lgr.debug('afl telling AFL we will restart')
            #self.lgr.debug('resim_done iteration: %d status: %d size: %d restart: %d' % (self.iteration, status, self.orig_data_length, self.restart))
            self.sendMsg('resim_done iteration: %d status: %d size: %d restart: %d' % (self.iteration, status, self.orig_data_length, self.restart))
            try: 
                self.sock.sendall(trace_bits)
                pass
            except:
                self.lgr.debug('AFL went away while we were sending trace_bits')
                self.rmStopHap()
                return
            if status != AFL_OK:
                #self.lgr.debug('afl stopHap status back from sendall trace_bits')
                pass
            '''
            if self.iteration == 1:
                self.trace_snap1 = tracemalloc.take_snapshot()
            elif self.iteration == 1000:
                trace_snap2 = tracemalloc.take_snapshot()
                top_stats = trace_snap2.compare_to(self.trace_snap1, 'lineno')
                self.lgr.debug('found %d topstats' % len(top_stats))
                for stat in top_stats[:10]:
                    self.lgr.debug(stat)
                SIM_run_command('q')
            '''
            if self.restart == 0:
                if do_quit:
                    self.lgr.debug('afl was told to quit, bye')
                    self.saveThisData()
                    self.top.quit()
                self.iteration += 1 
                self.in_data = self.getMsg()
                if self.in_data is None:
                    self.lgr.error('Got None from afl')
                    self.rmStopHap()
                    if self.resim_ctl is not None:
                        self.top.quit()
                    return
                SIM_run_alone(self.goN, status)
            else:
                self.lgr.debug('afl was told to restart, bye')
                self.top.quit()

    def saveThisData(self):
        with open('./final_data.io', 'wb') as fh:
            fh.write(self.orig_in_data)

    def stopHap(self, dumb, one, exception, error_string):
        ''' Entered when the backstop is hit'''
        ''' Also if coverage record exit is hit '''
        #self.lgr.debug('afl stopHap cycle 0x%x' % self.target_cpu.cycles)
        if self.stop_hap is None:
            return
        if self.target_cpu.cycles == self.starting_cycle:
            self.lgr.debug('afl stopHap but got nowhere.  continue.')
            SIM_run_alone(SIM_continue, 0)
            return
        self.finishUp()

    def goN(self, status):
        if status == AFL_CRASH or status == AFL_HANG:
            self.lgr.debug('afl goN after crash or hang')
        ''' Only applies to multi-packet UDP fu '''
        self.current_packet = 0
        self.bad_trick = False
        #self.lgr.debug('afl goN context is %s' % str(self.target_cpu.current_context))
        ''' If just starting, get data from afl, otherwise, was read from stopHap. '''
        if self.stop_hap is None:
            self.tmp_time = time.time()
            self.lgr.debug('afl goN first, context is %s' % str(self.target_cpu.current_context))
            if self.test_file is None:
                self.in_data = self.getMsg()
            else:
                with open(self.test_file, 'rb') as fh:
                    self.in_data = fh.read()
            if self.in_data is None:
                self.lgr.error('Got None from afl')
                return
        self.orig_data_length = len(self.in_data)
        self.orig_in_data = self.in_data
        
        if self.commence_after_exits is not None:
            self.coverage.disableAll()
            #self.lgr.debug('afl goN disabled coverage breakpoints')
        #self.lgr.debug('afl goN restore snapshot')
        if not self.top.nativeReverse():
            self.top.restoreSnapshot('origin')
        else:
            cli.quiet_run_command('restore-snapshot name=origin')
            #VT_restore_snapshot('origin')
        if not self.linear and self.context_manager.isDebugContext():
            SIM_run_alone(self.context_manager.restoreDefaultContext, None)
        #self.top.restoreRESimContext()
        if self.commence_after_exits is not None:
            self.setCounterHap()

        #self.lgr.debug('got %d of data from afl iteration %d' % (len(self.in_data), self.iteration))
        if status == AFL_CRASH or status == AFL_HANG:
            self.lgr.debug('afl goN after crash or hang. restored snapshot after getting %d bytes from afl' % len(self.in_data))
       
        current_length = len(self.in_data)
        self.afl_packet_count = self.packet_count
        if self.udp_header is None and self.packet_count > 1 and current_length < (self.pad_to_size*(self.packet_count-1)):
            self.lgr.debug('afl packet count of %d and size of %d, but only %d bytes from AFL.  Cannot do it.' % (self.packet_count, self.pad_to_size, current_length))
            self.afl_packet_count = (current_length / self.pad_to_size) + 1
            self.lgr.debug('afl packet count now %d' % self.afl_packet_count)
       

        if self.create_dead_zone:
            self.lgr.debug('afl goN dead zone iteration %d' % self.iteration)
        ''' clear the bit_trace '''
        #self.lgr.debug('afl goN call doCoverage')
        if self.linear:
            self.lgr.debug('afl, linear use context manager to watch tasks restore RESim context')
            self.context_manager.restoreDebugContext()
            self.context_manager.watchTasks()
        self.coverage.doCoverage()

        #self.lgr.debug('afl, did coverage, cycle: 0x%x' % self.target_cpu.cycles)
        if self.stop_hap is None:
            #self.lgr.debug('afl added stop hap')
            self.stop_hap = SIM_hap_add_callback("Core_Simulation_Stopped", self.stopHap,  None)
        if status == AFL_CRASH or status == AFL_HANG:
            self.lgr.debug('afl goN after crash or hang, watch exits, cpu cycle was 0x%x context %s' % (self.target_cpu.cycles, self.target_cpu.current_context))
            self.coverage.watchExits(tid=self.target_tid)
            self.exit_syscall = self.top.debugExitHap(context=self.target_cpu.current_context)

        self.doWriteData()

        if not self.did_page_faults: 
            # TBD why again and again?
            self.page_faults.watchPageFaults(afl=True)
            self.did_page_faults = True
        if self.exit_syscall is not None:
            # syscall tracks cycle of recent entry to avoid hitting same hap for a single syscall.  clear that.
            self.exit_syscall.resetHackCycle()
        #self.lgr.debug('afl goN now continue current context %s' % str(self.cpu.current_context))
        #cli.quiet_run_command('c') 
        SIM_continue(0)

    def doWriteData(self):
        shared_syscall = self.top.getSharedSyscall()
        if self.write_data is None:
            self.write_data = writeData.WriteData(self.top, self.cpu, self.in_data, self.afl_packet_count, 
                 self.mem_utils, self.context_manager, self.backstop, self.snap_name, self.lgr, udp_header=self.udp_header, 
                 pad_to_size=self.pad_to_size, filter=self.filter_module, backstop_cycles=self.backstop_cycles, force_default_context=True,
                 stop_on_read=self.stop_on_read, ioctl_count_max=self.ioctl_count_max, select_count_max=self.select_count_max,backstop_delay=self.backstop_delay,
                 shared_syscall=shared_syscall)
        else:
           self.write_data.reset(self.in_data, self.afl_packet_count, self.addr)

        count = self.write_data.write()
        if self.mem_utils.isKernel(self.addr):
            if self.addr_of_count is not None and not self.top.isWindows():
                #self.lgr.debug('afl set ioctl wrote len in_data %d to 0x%x' % (count, self.addr_of_count))
                self.mem_utils.writeWord32(self.cpu, self.addr_of_count, count)
                self.write_data.watchIOCtl()

        
    def whenDone(self):
        #self.lgr.debug('afl whenDone callback')
        pass

    def synchAFL(self):
        
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_address = ('localhost', self.port)
        self.lgr.debug('afl connect to port %d' % self.port)
        connected = False
        self.sock.settimeout(30)
        count = 0
        while not connected and count < 200:
            try:
                self.sock.connect(server_address)
                connected = True
            except socket.error:
                print('Connect timeout, try again')
                time.sleep(0.1)
            count = count + 1
        if connected:    
            self.lgr.debug('afl back from connect')
            self.sock.settimeout(None)
            print('RESim connected to AFL port %d' % self.port)
            self.sendMsg('hi from resim')
            reply = self.getMsg()
            self.iteration = int(reply.split()[-1].strip())+1
            self.lgr.debug('afl synchAFL reply from afl: %s start with given iteration plus 1 %d' % (reply, self.iteration))
        else:
            self.lgr.error('afl synchAFL failed to connect')

    def sendMsg(self, msg):
        msg_size = len(msg)
        ms = struct.pack("i", msg_size) 
        #self.sock.sendall(ms+bytes(msg, 'utf8'))
        if sys.version_info[0] == 3:
            try:
                #self.sock.sendall(combine)
                self.sock.sendall(ms+bytes(msg, 'utf8'))
            except:
                self.rmStopHap()
                print('AFL went away');
                self.lgr.debug('AFL went away while in sendMsg');
        else:
            try:
                #self.sock.sendall(combine)
                self.sock.sendall(ms+msg)
            except:
                self.rmStopHap()
                print('AFL went away');
                self.lgr.debug('AFL went away while in sendMsg');
        #self.lgr.debug('sent to AFL len %d: %s' % (msg_size, msg))

    def getMsg(self):
        data = None
        try:
            data = self.sock.recv(4)
        except socket.error as e:
            self.lgr.error('afl recv error %s' % e)
            self.top.quit()
        #self.lgr.debug('got data len %d %s' % (len(data), data))
        if data is None or len(data) == 0:
            self.sock.close()
            return None
        msg_len = struct.unpack("i", data)[0]
        #self.lgr.debug('getMsg got msg_len of %d' % msg_len)
        msg = bytearray()
        expected = msg_len
        amount_received = 0
        while amount_received < msg_len:
            data = self.sock.recv(expected)
            if data is None or len(data) == 0:
                self.sock.close()
                self.rmStopHap()
                self.lgr.debug("got nothing from afl")
                return None
            #self.lgr.debug('got from afl: %s' % data)
            amount_received += len(data)
            expected = expected - len(data)
            msg = msg+data
        return msg
 

    def loadPickle(self, name):
        afl_file = os.path.join('./', name, self.cell_name, 'afl.pickle')
        if os.path.isfile(afl_file):
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

    def fixFaults(self):
        if self.target_cpu.architecture.startswith('arm'):
            self.fault_hap = SIM_hap_add_callback_obj_index("Core_Exception", self.target_cpu, 0,
                 self.faultCallback, self.target_cpu, 1)

    def faultCallback(self, cpu, one, exception_number):
        if self.fault_hap is not None:
            reg_num = cpu.iface.int_register.get_number("combined_data_fsr")
            fsr = cpu.iface.int_register.read(reg_num)
            if fsr == 2:
               cpu.iface.int_register.write(reg_num,1)
               self.lgr.warning('hacked ARM fsr register from 2 to 1')

    def setCycleHap(self, dumb=None):
        if self.cycle_event is None:
            self.cycle_event = SIM_register_event("afl commence", SIM_get_class("sim"), Sim_EC_Notsaved, self.cycle_handler, None, None, None, None)
            self.lgr.debug('afl setCycleHap set afl commence')
        else:
            SIM_event_cancel_time(self.target_cpu, self.cycle_event, self.target_cpu, None, None)
            self.lgr.debug('afl setCycleHap did registercancel')
        commence_cycle = self.target_cpu.cycles + self.commence_coverage
        self.lgr.debug('afl setCycleHap posted cycle of 0x%x cpu: %s look for cycle 0x%x (%d) current cycle:0x%x' % (self.commence_coverage, self.target_cpu.name, commence_cycle, commence_cycle, self.target_cpu.cycles))
        SIM_event_post_cycle(self.target_cpu, self.cycle_event, self.target_cpu, self.commence_coverage, self.commence_coverage)

    def cycle_handler(self, obj, cycles):
        if self.cycle_event is None:
            return
        self.lgr.debug('afl cycle_handler exit counter is %d' % self.exit_counter)
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
        self.lgr.debug('afl cycle_handler now set stopHapCycle and stop')
        SIM_run_alone(self.doCycleStop, None)
        #self.lgr.debug('afl cycle_handler call enable coverage breakpoints cycle now: 0x%x' % self.target_cpu.cycles)
        #self.coverage.enableAll()
        # TBD jumpers should match playAFL?  Two kinds: one for diagnostics and one for real control flow around crc's
        #self.top.jumperEnable(target=self.cell_name)

    def doCycleStop(self, dumb):
        SIM_event_cancel_time(self.target_cpu, self.cycle_event, self.target_cpu, None, None)
        self.cycle_event = None
        self.stop_hap_cycle = SIM_hap_add_callback("Core_Simulation_Stopped", self.stopHapCycle,  None)
        SIM_break_simulation('afl cycle_handler')

    def rmCounterHap(self, hap):
        #self.lgr.debug('afl rmCounterHap')
        SIM_hap_delete_callback_id('Core_Breakpoint_Memop', hap)
        SIM_delete_breakpoint(self.counter_bp)
        self.counter_bp = None

    def stopHapCycle(self, dumb, one, exception, error_string):
        #self.lgr.debug('afl stopHapCycle cycle 0x%x' % self.target_cpu.cycles)
        if self.stop_hap_cycle is not None:
            SIM_run_alone(self.rmStopHapCycle, None)
            SIM_run_alone(self.finishCallback, None)

    def rmStopHapCycle(self, dumb):
        if self.stop_hap_cycle is not None:
            SIM_hap_delete_callback_id("Core_Simulation_Stopped", self.stop_hap_cycle)
            self.stop_hap_cycle = None

    def functionBackstop(self):
        function_bs = os.getenv('FUNCTION_BACKSTOP')
        self.lgr.debug('afl functionBackstop function_bs %s' % function_bs)
        if function_bs is not None:
            if os.path.isfile(function_bs):
                with open(function_bs) as fh:
                    for line in fh:
                        line = line.strip()
                        if line.startswith('#'):
                            continue
                        addr = int(line, 16)
                        function_break = SIM_breakpoint(self.target_cpu.current_context, Sim_Break_Linear, Sim_Access_Execute, addr, 1, 0)
                        self.function_backstop_hap = SIM_hap_add_callback_index("Core_Breakpoint_Memop", self.functionBackstopHap, None, function_break)
                        self.lgr.debug('afl functionBackstop set break at 0x%x' % addr)
                        
    def functionBackstopHap(self, dumb, third, break_num, memory):
        if self.function_backstop_hap is None:
            return
        #self.lgr.debug('afl functionBackstopHap stop it')
        SIM_break_simulation('afl function backstop')
               
    def loadCommenceParams(self): 
        with open(self.commence_params) as fh:
            self.commence_after_exits = int(fh.readline(), 16) 
            self.exit_eip = int(fh.readline(), 16) 
            self.target_tid = fh.readline()
            self.lgr.debug('afl loadCommenceParams loaded from %s' % self.commence_params)
