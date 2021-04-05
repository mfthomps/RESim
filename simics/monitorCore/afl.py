import backStop
import os
import shutil
import time
import socket
import sys
import pickle
import struct
import cli
import stopFunction
import imp 
from simics import *
RESIM_MSG_SIZE=80
class AFL():
    def __init__(self, top, cpu, cell_name, coverage, backstop, mem_utils, dataWatch, snap_name, lgr, fd=None, packet_count=1, stop_on_read=False):
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
        if packet_count > 0 and not (self.udp_header is not None or self.pad_to_size > 0):
            self.lgr.error('Multi-packet requested but no pad or UDP header has been given in env variables')
            return
        self.filter_module = None
        self.packet_filter = os.getenv('AFL_PACKET_FILTER')
        if self.packet_filter is not None:
            file_path = './%s.py' % self.packet_filter
            abs_path = os.path.abspath(file_path)
            self.filter_module = imp.load_source(self.packet_filter, abs_path)
            '''
            module_name = self.packet_filter
            spec = importlib.util.spec_from_file_location(module_name, file_path)
            filter_module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(flter_module)
            '''

        self.pad_char = chr(0)
        self.cpu = cpu
        self.cell_name = cell_name
        self.top = top
        self.mem_utils = mem_utils
        self.fd = fd
        self.stop_on_read = stop_on_read
        self.dataWatch = dataWatch
        self.coverage = coverage
        # For multi-packet UDP.  afl_packet_count may be adjusted less than given packet count.
        self.packet_count = packet_count
        self.afl_packet_count = None
        self.current_packet = 0
        self.backstop = backstop
        self.stop_hap = None
        self.return_ip = None
        self.call_ip = None
        self.call_break = None
        self.call_hap = None
        self.in_data = None
        self.orig_in_data = None
        self.orig_data_length = 0
        self.backstop.setCallback(self.whenDone)
        ''' careful changing this, may hit backstop before crashed process killed '''
        #self.backstop_cycles =  500000
        if stop_on_read:
            self.backstop_cycles = 0
        else:
            self.backstop_cycles =   100000
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.settimeout(2)
        self.server_address = ('localhost', 8765)
        self.iteration = 1
        self.pid = self.top.getPID()
        self.total_hits = 0
        self.bad_trick = False
        self.empty_trace_bits = None
        if self.cpu.architecture == 'arm':
            lenreg = 'r0'
        else:
            lenreg = 'eax'
        self.len_reg_num = self.cpu.iface.int_register.get_number(lenreg)
        self.pc_reg = self.cpu.iface.int_register.get_number('pc')
        self.addr = None
        self.max_len = None
        if fd is not None:
            self.prepInject(snap_name)
        else:
            self.lgr.debug('AFL init from snap %s' % snap_name)
            self.loadPickle(snap_name)
            self.finishInit()
        self.lgr.debug('afl done init, num packets is %d stop_on_read is %r' % (self.packet_count, self.stop_on_read))
     
    def finishInit(self): 
        self.top.removeDebugBreaks(keep_watching=False, keep_coverage=False)
        self.coverage.enableCoverage(self.pid, backstop=self.backstop, backstop_cycles=self.backstop_cycles, afl=True)
        cli.quiet_run_command('disable-reverse-execution')
        cli.quiet_run_command('enable-unsupported-feature internals')
        cli.quiet_run_command('save-snapshot name = origin')
        self.synchAFL()

    def rmStopHap(self):
        if self.stop_hap is not None:
            SIM_hap_delete_callback_id("Core_Simulation_Stopped", self.stop_hap)
            self.stop_hap = None

    def goAlone(self, dumb):
        SIM_run_command('c') 
   
    def finishUp(self): 
            if self.bad_trick and self.empty_trace_bits is not None:
                trace_bits = self.empty_trace_bits
            else:
                trace_bits = self.coverage.getTraceBits()
                if self.empty_trace_bits is None:
                    self.empty_trace_bits = trace_bits
            self.total_hits += self.coverage.getHitCount() 
            if self.iteration % 100 == 0:
                avg = self.total_hits/100
                self.lgr.debug('afl average hits in last 100 iterations is %d' % avg)
                self.total_hits = 0
            #self.lgr.debug('afl stopHap bitfile iteration %d cycle: 0x%x' % (self.iteration, self.cpu.cycles))
            status = self.coverage.getStatus()
            if status != 0:
                self.lgr.debug('afl stopHap status not zero %d iteration %d, data written to /tmp/icrashed' %(status, self.iteration)) 
                with open('/tmp/icrashed', 'w') as fh:
                    fh.write(self.orig_in_data)
                self.lgr.debug('afl stopHap cpu context is %s' % self.cpu.current_context)

            ''' Send the status message '''
            self.sendMsg('resim_done iteration: %d status: %d size: %d' % (self.iteration, status, self.orig_data_length))
            try: 
                self.sock.sendall(trace_bits)
            except:
                self.lgr.debug('AFL went away while we were sending trace_bits')
                self.rmStopHap()
                return
            if status != 0:
                self.lgr.debug('afl stopHap status back from sendall trace_bits')
            self.iteration += 1 
            self.in_data = self.getMsg()
            if self.in_data is None:
                self.lgr.error('Got None from afl')
                self.rmStopHap()
                return
            SIM_run_alone(self.goN, status)

    def stopHap(self, dumb, one, exception, error_string):
        ''' Entered when the backstop is hit, or the recv call is hit if stop_on_read '''
        ''' Also if coverage record exit is hit '''
        #self.lgr.debug('afl stopHap')
        if self.stop_hap is None:
            return
        if self.current_packet < self.afl_packet_count:
            eip = self.top.getEIP()  
            if eip != self.call_ip:
                self.lgr.debug('afl stopHap thought we would be at recv call, not?  Perhaps program exited.  Do finishUp')
                self.finishUp()
                return
            self.cpu.iface.int_register.write(self.pc_reg, self.return_ip)
            self.writeData()
            if self.bad_trick:
                #self.lgr.debug('afl stopHap saw filter fail, bail')
                self.finishUp()
            else:
                #self.lgr.debug('afl stopHap set PC to 0x%x and wrote data, now continue' % self.return_ip)
                SIM_run_alone(self.goAlone, None)
        else:
            #self.stop_hap = None
            #self.lgr.debug('afl stopHapx')
            self.finishUp()

    def goN(self, status):
        if status != 0:
            self.lgr.debug('afl goN after crash. Call getMsg')
        ''' Only applies to multi-packet UDP fu '''
        self.current_packet = 0
        self.bad_trick = False
        ''' If just starting, get data from afl, otherwise, was read from stopHap. '''
        if self.stop_hap is None:
            self.in_data = self.getMsg()
            if self.in_data is None:
                self.lgr.error('Got None from afl')
                return
        self.orig_data_length = len(self.in_data)
        self.orig_in_data = self.in_data
        
        cli.quiet_run_command('restore-snapshot name=origin')

        #self.lgr.debug('got %d of data from afl iteration %d' % (len(self.in_data), self.iteration))
        if status != 0:
            self.lgr.debug('afl goN after crash. restored snapshot after getting %d bytes from afl' % len(self.in_data))
       
        current_length = len(self.in_data)
        self.afl_packet_count = self.packet_count
        if self.udp_header is None and self.packet_count > 1 and current_length < (self.pad_to_size*(self.packet_count-1)):
            self.lgr.debug('afl packet count of %d and size of %d, but only %d bytes from AFL.  Cannot do it.' % (self.packet_count, self.pad_to_size, current_length))
            self.afl_packet_count = (current_length / self.pad_to_size) + 1
            self.lgr.debug('afl packet count now %d' % self.afl_packet_count)
       

        if self.addr is None:
           self.addr, max_len = self.dataWatch.firstBufferAddress()
           if self.addr is None:
               self.lgr.error('AFL, no firstBufferAddress found')
               return


        ''' clear the bit_trace '''
        self.coverage.doCoverage()

        #self.lgr.debug('afl, did coverage, cycle: 0x%x' % self.cpu.cycles)
        if self.stop_hap is None:
            self.stop_hap = SIM_hap_add_callback("Core_Simulation_Stopped", self.stopHap,  None)
        if status != 0:
            self.lgr.debug('afl goN call continue, cpu cycle was 0x%x context %s' % (self.cpu.cycles, self.cpu.current_context))
            self.coverage.watchExits()

        self.writeData()
           
        cli.quiet_run_command('c') 

    def writeData(self):
        ''' Write next chunk of data received from AFL into the receive buffer '''
        ''' NOTE this adjusts self.in_data after the write to prep for next packet '''
        current_length = len(self.in_data)
        tot_length = current_length
        pad_count = 0
        self.current_packet = self.current_packet+1
        if self.packet_filter is not None and not self.filter_module.filter(self.in_data):
            #self.lgr.debug('afl packet number %d filter blocks it, write nulls' % self.current_packet)
            #self.lgr.debug(self.in_data[:500])
            b = bytearray(100)
            self.mem_utils.writeString(self.cpu, self.addr, b) 
            self.afl_packet_count = 1
            tot_length = 100
            self.bad_trick = True
        elif self.afl_packet_count == 1 or self.current_packet >= self.afl_packet_count:  
            ''' Data from AFL is trimmed.  Pad it to satisfy the application if needed '''
            pad_count = self.pad_to_size - current_length
            self.mem_utils.writeString(self.cpu, self.addr, self.in_data) 
            #self.lgr.debug('afl wrote last packet %d %d bytes  %s' % (self.current_packet, len(self.in_data), self.in_data[:50]))
            if pad_count > 0:
                b = bytearray(pad_count)
                self.mem_utils.writeString(self.cpu, self.addr+current_length, b) 
                tot_length += pad_count
            if self.backstop_cycles > 0:
                self.backstop.setFutureCycleAlone(self.backstop_cycles)
        elif self.pad_to_size > 0 and self.udp_header is None:
            first_data = self.in_data[0:self.pad_to_size]
            self.mem_utils.writeString(self.cpu, self.addr, first_data) 
            self.in_data = self.in_data[self.pad_to_size:]
            tot_length = self.pad_to_size
        else:
            index = self.in_data[5:].find(self.udp_header)
            if index > 0:
                first_data = self.in_data[:(index+5)]
                self.mem_utils.writeString(self.cpu, self.addr, first_data) 
                self.in_data = self.in_data[len(first_data):]
                # TBD add handling of padding with udp header                
                tot_length = len(first_data)
                #self.lgr.debug('afl wrote packet %d %d bytes  %s' % (self.current_packet, len(first_data), first_data[:50]))
                #self.lgr.debug('afl next packet would start with %s' % self.in_data[:50])
            else:
                #self.lgr.debug('afl 2nd UDP header %s not found, write nulls and cut packet count' % self.udp_header)
                #self.lgr.debug(self.in_data[:500])
                b = bytearray(100)
                self.mem_utils.writeString(self.cpu, self.addr, b) 
                self.afl_packet_count = 1
                tot_length = 100

        if self.call_hap is None and (self.afl_packet_count > self.current_packet or self.stop_on_read):
            ''' Break on the next recv call, either to multi-UDP fu, or to declare we are done (stop_on_read) '''
            cell = self.top.getCell()
            self.call_break = SIM_breakpoint(cell, Sim_Break_Linear, Sim_Access_Execute, self.call_ip, 1, 0)
            self.call_hap = SIM_hap_add_callback_index("Core_Breakpoint_Memop", self.callHap, None, self.call_break)
            #self.lgr.debug('afl writeData set call break at 0x%x and hap, cycle is 0x%x' % (self.call_ip, self.cpu.cycles))

        ''' Tell the application how much data it read ''' 
        self.cpu.iface.int_register.write(self.len_reg_num, tot_length)

    def callHap(self, dumb, third, break_num, memory):
        ''' Hit a call to recv '''
        if self.call_hap is None:
            return
        if self.current_packet > self.afl_packet_count:
            #self.lgr.debug('afl callHap current packet %d above count %d' % (self.current_packet, self.afl_packet_count))
            return
        '''
        this_pid = self.top.getPID()
        if this_pid != self.pid:
            self.lgr.debug('afl callHap wrong pid got %d wanted %d' % (this_pid, self.pid))
            return
        '''
        #self.lgr.debug('afl callHap packet %d cycles 0x%x' % (self.current_packet, self.cpu.cycles))
        if self.stop_on_read:
            #self.lgr.debug('afl callHap stop on read')
            SIM_break_simulation('stop on read')
            return
        if len(self.in_data) == 0:
            self.lgr.error('afl callHap current packet %d no data left' % (self.current_packet))
            SIM_break_simulation('broken offset')
            SIM_run_alone(self.delCallHap, None)
            return

        self.writeData()
        if self.current_packet >= self.afl_packet_count:
            # set backstop if needed, we are on the last (or only) packet.
            #SIM_run_alone(self.delCallHap, None)
            if self.backstop_cycles > 0:
                self.backstop.setFutureCycleAlone(self.backstop_cycles)

    def delCallHap(self, dumb):
        #self.lgr.debug('afl delCallHap')
        SIM_delete_breakpoint(self.call_break)
        SIM_hap_delete_callback_id('Core_Breakpoint_Memop', self.call_hap)
        self.call_hap = None

    def whenDone(self):
        #self.lgr.debug('afl whenDone callback')
        pass

    def synchAFL(self):
        
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_address = ('localhost', 8765)
        self.sock.connect(server_address)
        self.coverage.doCoverage()
        num_blocks = self.coverage.getNumBlocks()
        self.sendMsg('hi from resim')
        reply = self.getMsg()
        self.lgr.debug('afl synchAFL reply from afl: %s' % reply)

    def sendMsg(self, msg):
        msg_size = len(msg)
        ms = struct.pack("i", msg_size) 
        combine=''.join((ms,msg))
        try:
            self.sock.sendall(combine)
        except:
            self.rmStopHap()
            print('AFL went away');
            self.lgr.debug('AFL went away while in sendMsg');
        #self.lgr.debug('sent to AFL len %d: %s' % (msg_size, msg))

    def getMsg(self):
        data = self.sock.recv(4)
        #self.lgr.debug('got data len %d %s' % (len(data), data))
        if data is None or len(data) == 0:
            self.sock.close()
            return None
        msg_len = struct.unpack("i", data)[0]
        #self.lgr.debug('getMsg got msg_len of %d' % msg_len)
        msg = "" 
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
 
    def instrumentAlone(self, snap_name): 
        self.top.removeDebugBreaks(keep_watching=False, keep_coverage=True)
        ''' go forward one to user space and record the return IP '''
        SIM_run_command('pselect %s' % self.cpu.name)
        SIM_run_command('si')
        self.return_ip = self.top.getEIP(self.cpu)
        ret_cycle = self.cpu.cycles
        pid = self.top.getPID()
        self.lgr.debug('instrument snap_name %s stepped to return IP: 0x%x pid:%d cycle is 0x%x' % (snap_name, self.return_ip, pid, self.cpu.cycles))
        ''' return to the call to record that IP '''
        frame, cycle = self.top.getRecentEnterCycle()
        exit_info = self.top.getMatchingExitInfo()
        previous = cycle - 1
        SIM_run_command('skip-to cycle=%d' % previous)
        self.call_ip = self.top.getEIP(self.cpu)
        pid = self.top.getPID()
        self.lgr.debug('instrument  skipped to call IP: 0x%x pid:%d callnum: %d cycle is 0x%x' % (self.call_ip, pid, frame['syscall_num'], self.cpu.cycles))
        ''' skip back to return so the snapshot is ready to inject input '''
        SIM_run_command('skip-to cycle=%d' % ret_cycle)
        self.pickleit(snap_name, exit_info)
        #self.finishInit()

    def instrumentIO(self, snap_name):
        self.lgr.debug("in instrument IO");
        SIM_run_alone(self.instrumentAlone, snap_name)

    def prepInject(self, snap_name):
        ''' Use runToInput to find location of desired input call.  Set callback to instrument the call and return '''
        self.lgr.debug('afl prepInject snap %s' % snap_name)
        f1 = stopFunction.StopFunction(self.instrumentIO, [snap_name], nest=False)
        flist = [f1]
        self.top.runToInput(self.fd, flist_in=flist)

    def pickleit(self, name, exit_info):
        self.top.writeConfig(name)
        pickDict = {}
        pickDict['call_ip'] = self.call_ip
        pickDict['return_ip'] = self.return_ip
        pickDict['addr'] = exit_info.retval_addr
        if exit_info.sock_struct is not None:
            pickDict['size'] = exit_info.sock_struct.length
        else:
            pickDict['size'] = exit_info.count
        self.lgr.debug('afl pickleit save addr 0x%x size %d' % (pickDict['addr'], pickDict['size']))
        afl_file = os.path.join('./', name, self.cell_name, 'afl.pickle')
        pickle.dump( pickDict, open( afl_file, "wb") ) 

    def loadPickle(self, name):
        afl_file = os.path.join('./', name, self.cell_name, 'afl.pickle')
        if os.path.isfile(afl_file):
            self.lgr.debug('afl pickle from %s' % afl_file)
            so_pickle = pickle.load( open(afl_file, 'rb') ) 
            #print('start %s' % str(so_pickle['text_start']))
            self.call_ip = so_pickle['call_ip']
            self.return_ip = so_pickle['return_ip']
            if 'addr' in so_pickle:
                self.addr = so_pickle['addr']
                self.max_len = so_pickle['size']
