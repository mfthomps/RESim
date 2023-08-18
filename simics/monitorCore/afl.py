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
#import tracemalloc
from simics import *
RESIM_MSG_SIZE=80
AFL_OK=0
AFL_CRASH=1
AFL_HANG=2
AFL_CLOSED=3
class AFL():
    def __init__(self, top, cpu, cell_name, coverage, backstop, mem_utils, dataWatch, snap_name, context_manager, page_faults, lgr,
                 packet_count=1, stop_on_read=False, fname=None, linear=False, target=None, create_dead_zone=False, port=8765, 
                 one_done=False):
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
        self.dataWatch = dataWatch
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
        self.target = target
        self.create_dead_zone = create_dead_zone
        self.backstop.setCallback(self.whenDone)
        self.port = port
        self.one_done = one_done
        self.page_faults = page_faults
        sor = os.getenv('AFL_STOP_ON_READ')
        if sor is not None and sor.lower() == 'true':
            self.stop_on_read = True
        # TBD why are sor and backstop mutually exclusive?
        if stop_on_read:
            self.backstop_cycles = 0
        else:
            if os.getenv('AFL_BACK_STOP_CYCLES') is not None:
                self.backstop_cycles =   int(os.getenv('AFL_BACK_STOP_CYCLES'))
                self.lgr.debug('afl AFL_BACK_STOP_CYCLES is %d' % self.backstop_cycles)
            else:
                self.lgr.warning('no AFL_BACK_STOP_CYCLES defined, using default of 100000')
                self.backstop_cycles =   1000000
                
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.settimeout(2)
        self.server_address = ('localhost', self.port)
        self.iteration = 1
        self.pid = self.top.getPID()
        self.total_hits = 0
        self.bad_trick = False
        self.trace_snap1 = None
        self.empty_trace_bits = None
        self.restart = 0
        if self.cpu.architecture == 'arm':
            lenreg = 'r0'
        else:
            lenreg = 'eax'
        self.len_reg_num = self.cpu.iface.int_register.get_number(lenreg)
        self.pc_reg = self.cpu.iface.int_register.get_number('pc')
        self.addr = None
        self.orig_buffer = None
        hang_cycles = 90000000
        hang = os.getenv('HANG_CYCLES')
        if hang is not None:
            hang_cycles = int(hang)
        self.backstop.setHangCallback(self.coverage.recordHang, hang_cycles)
        self.lgr.debug('AFL init from snap %s' % snap_name)

        self.snap_name = snap_name
        self.loadPickle(snap_name)

        self.resim_ctl = None
        #if resimUtils.isParallel():
        if stat.S_ISFIFO(os.stat('resim_ctl.fifo').st_mode):
            self.lgr.debug('afl found resim_ctl.fifo, open it for read %s' % os.path.abspath('resim_ctl.fifo'))
            self.resim_ctl = os.open('resim_ctl.fifo', os.O_RDONLY | os.O_NONBLOCK)
            self.lgr.debug('afl back from open')
        else: 
            self.lgr.debug('AFL did NOT find resim_ctl.fifo')
         
        self.starting_cycle = cpu.cycles 
        self.total_cycles = 0
        self.tmp_time = time.time()
        self.fname = fname
        self.pid_list = []
        if target is None:
            self.pid_list = self.context_manager.getWatchPids()
            self.lgr.debug('afl %d pids in list' % len(self.pid_list))
            self.top.removeDebugBreaks(keep_watching=False, keep_coverage=False, immediate=True)
            #if self.orig_buffer is not None:
            #    self.lgr.debug('restored %d bytes 0x%x context %s' % (len(self.orig_buffer), self.addr, self.cpu.current_context))
            #    self.mem_utils.writeBytes(self.cpu, self.addr, self.orig_buffer) 
            analysis_path = self.top.getAnalysisPath(self.fname)
            self.coverage.enableCoverage(self.pid, backstop=self.backstop, backstop_cycles=self.backstop_cycles, 
                afl=True, fname=analysis_path, linear=linear, create_dead_zone=self.create_dead_zone, record_hits=False)

            if not self.linear:
                self.context_manager.restoreDefaultContext()
                self.lgr.debug('afl, set default context. %s' % str(self.cpu.current_context))

            cli.quiet_run_command('disable-reverse-execution')
            cli.quiet_run_command('enable-unsupported-feature internals')
            cli.quiet_run_command('save-snapshot name = origin')
            self.coverage.doCoverage()
            self.synchAFL()
            self.lgr.debug('afl done init, num packets is %d stop_on_read is %r' % (self.packet_count, self.stop_on_read))
            self.fault_hap = None
            #tracemalloc.start()
            # hack around Simics model bug
            #self.fixFaults()
        else:
            self.lgr.debug('afl use target %s, call debug' % target)
            ''' need a bookmark to get back to here after setting up debug process '''
            self.top.resetOrigin()
   
            self.top.debugProc(target, self.aflInitCallback)
        #self.coverage.watchExits()
    

    def aflInitCallback(self):
        self.lgr.debug('afl aflInitCallback')
        ''' Now in target process'''
        self.coverage = self.top.getCoverage()
        self.pid = self.top.getPID()
        
        self.pid_list = self.context_manager.getWatchPids()
        self.lgr.debug('afl aflInitCallback %d pids in list' % len(self.pid_list))

        self.top.removeDebugBreaks(keep_watching=False, keep_coverage=False, immediate=True)
        analysis_path = self.top.getAnalysisPath(self.fname)
        self.coverage.enableCoverage(self.pid, backstop=self.backstop, backstop_cycles=self.backstop_cycles, 
            afl=True, fname=analysis_path)
        self.coverage.doCoverage()
        cmd = 'skip-to bookmark = bookmark0'
        cli.quiet_run_command(cmd)
        cli.quiet_run_command('disable-reverse-execution')
        cli.quiet_run_command('enable-unsupported-feature internals')
        cli.quiet_run_command('save-snapshot name = origin')
        self.synchAFL()
        self.lgr.debug('afl done init, num packets is %d stop_on_read is %r' % (self.packet_count, self.stop_on_read))
        self.fault_hap = None
        self.top.noWatchSysEnter()
        self.tmp_time = time.time()
        self.goN(0) 


    def rmStopHap(self):
        if self.stop_hap is not None:
            SIM_hap_delete_callback_id("Core_Simulation_Stopped", self.stop_hap)
            self.stop_hap = None
            #self.lgr.debug('afl removed stop hap')

    def finishUp(self): 
            if self.bad_trick and self.empty_trace_bits is not None:
                trace_bits = self.empty_trace_bits
            else:
                trace_bits = self.coverage.getTraceBits()
                if self.empty_trace_bits is None:
                    self.empty_trace_bits = trace_bits
            new_hits = self.coverage.getHitCount() 
            self.total_hits += new_hits
            self.total_cycles = self.total_cycles+(self.cpu.cycles-self.starting_cycle)
            if self.iteration % 100 == 0:
                avg = self.total_hits/100
                avg_cycles = self.total_cycles/100
                now = time.time()
                delta = 100/(now - self.tmp_time)
                self.lgr.debug('afl average hits in last 100 iterations is %d avg cycles: 0x%x execs/sec: %.2f' % (avg, int(avg_cycles), delta))
                self.total_hits = 0
                self.total_cycles = 0
                self.tmp_time = time.time()
                struct._clearcache()
                #dog = SIM_run_command('list-breakpoints')
                #self.lgr.debug(dog)
                #print(dog)
                #self.top.showHaps()
            #self.lgr.debug('afl stopHap bitfile iteration %d cycle: 0x%x new_hits: %d' % (self.iteration, self.cpu.cycles, new_hits))
            if self.create_dead_zone:
                self.lgr.debug('afl finishUp, create dead zone so ignore status to avoid hangs.')
                status = AFL_OK
            else:
                status = self.coverage.getStatus()
            if status == AFL_OK:
                #pid_list = self.context_manager.getWatchPids()
                if len(self.pid_list) == 0:
                    self.lgr.error('afl no pids from getThreadPids')
                for pid in self.pid_list:
                    if self.page_faults.hasPendingPageFault(pid):
                        self.lgr.debug('afl finishUp found pending page fault for pid %d' % pid)
                        status = AFL_CRASH
                        break
            self.page_faults.stopWatchPageFaults()
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
                    with open('./final_data.io', 'wb') as fh:
                        fh.write(self.orig_in_data)
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

    def stopHap(self, dumb, one, exception, error_string):
        ''' Entered when the backstop is hit'''
        ''' Also if coverage record exit is hit '''
        #self.lgr.debug('afl stopHap %s %s %s %s' % (str(dumb), str(one), str(exception), str(error_string)))
        if self.stop_hap is None:
            return
        if self.cpu.cycles == self.starting_cycle:
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
        ''' If just starting, get data from afl, otherwise, was read from stopHap. '''
        if self.stop_hap is None:
            self.lgr.debug('afl goN first, context is %s' % str(self.cpu.current_context))
            self.in_data = self.getMsg()
            if self.in_data is None:
                self.lgr.error('Got None from afl')
                return
        self.orig_data_length = len(self.in_data)
        self.orig_in_data = self.in_data
        
        cli.quiet_run_command('restore-snapshot name=origin')
        if not self.linear and self.context_manager.isDebugContext():
            SIM_run_alone(self.context_manager.restoreDefaultContext, None)
        #self.top.restoreRESimContext()

        #self.lgr.debug('got %d of data from afl iteration %d' % (len(self.in_data), self.iteration))
        if status == AFL_CRASH or status == AFL_HANG:
            self.lgr.debug('afl goN after crash or hang. restored snapshot after getting %d bytes from afl' % len(self.in_data))
       
        current_length = len(self.in_data)
        self.afl_packet_count = self.packet_count
        if self.udp_header is None and self.packet_count > 1 and current_length < (self.pad_to_size*(self.packet_count-1)):
            self.lgr.debug('afl packet count of %d and size of %d, but only %d bytes from AFL.  Cannot do it.' % (self.packet_count, self.pad_to_size, current_length))
            self.afl_packet_count = (current_length / self.pad_to_size) + 1
            self.lgr.debug('afl packet count now %d' % self.afl_packet_count)
       

        ''' TBD remove this?  addr always from pickle?'''
        #if self.addr is None:
        #   self.addr, max_len = self.dataWatch.firstBufferAddress()
        #   if self.addr is None:
        #       self.lgr.error('AFL, no firstBufferAddress found')
        #       return

        if self.create_dead_zone:
            self.lgr.debug('afl goN dead zone iteration %d' % self.iteration)
        ''' clear the bit_trace '''
        #self.lgr.debug('afl goN call doCoverage')
        if self.linear:
            #self.lgr.debug('afl, linear use context manager to watch tasks')
            self.context_manager.restoreDebugContext()
            self.context_manager.watchTasks()
        self.coverage.doCoverage()

        #self.lgr.debug('afl, did coverage, cycle: 0x%x' % self.cpu.cycles)
        if self.stop_hap is None:
            #self.lgr.debug('afl added stop hap')
            self.stop_hap = SIM_hap_add_callback("Core_Simulation_Stopped", self.stopHap,  None)
        if status == AFL_CRASH or status == AFL_HANG:
            self.lgr.debug('afl goN after crash or hang, watch exits, cpu cycle was 0x%x context %s' % (self.cpu.cycles, self.cpu.current_context))
            self.coverage.watchExits(pid=self.pid)

        if self.write_data is None:
            self.write_data = writeData.WriteData(self.top, self.cpu, self.in_data, self.afl_packet_count, 
                 self.mem_utils, self.context_manager, self.backstop, self.snap_name, self.lgr, udp_header=self.udp_header, 
                 pad_to_size=self.pad_to_size, filter=self.filter_module, backstop_cycles=self.backstop_cycles, force_default_context=True,
                 stop_on_read=self.stop_on_read)
        else:
           self.write_data.reset(self.in_data, self.afl_packet_count, self.addr)

        self.write_data.write()
        self.page_faults.watchPageFaults()
        #cli.quiet_run_command('c') 
        SIM_continue(0)
        
    def whenDone(self):
        #self.lgr.debug('afl whenDone callback')
        pass

    def synchAFL(self):
        
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_address = ('localhost', self.port)
        self.lgr.debug('afl connect to port %d' % self.port)
        connected = False
        self.sock.settimeout(30)
        while not connected:
            try:
                self.sock.connect(server_address)
                connected = True
            except socket.error:
                print('Connect timeout, try again')
        self.lgr.debug('afl back from connect')
        self.sock.settimeout(None)
        print('RESim connected to AFL port %d' % self.port)
        self.sendMsg('hi from resim')
        reply = self.getMsg()
        self.iteration = int(reply.split()[-1].strip())+1
        self.lgr.debug('afl synchAFL reply from afl: %s start with given iteration plus 1 %d' % (reply, self.iteration))

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

    def fixFaults(self):
        if self.cpu.architecture == 'arm':
            self.fault_hap = SIM_hap_add_callback_obj_index("Core_Exception", self.cpu, 0,
                 self.faultCallback, self.cpu, 1)

    def faultCallback(self, cpu, one, exception_number):
        if self.fault_hap is not None:
            reg_num = cpu.iface.int_register.get_number("combined_data_fsr")
            fsr = cpu.iface.int_register.read(reg_num)
            if fsr == 2:
               cpu.iface.int_register.write(reg_num,1)
               self.lgr.warning('hacked ARM fsr register from 2 to 1')

