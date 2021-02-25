import backStop
import os
import shutil
import time
import socket
import sys
import struct
import cli
from simics import *
RESIM_MSG_SIZE=80
class AFL():
    def __init__(self, top, cpu, coverage, backstop, mem_utils, dataWatch, lgr):
        ''' *** FIX THIS ***'''
        self.pad_to_size = 1448
        self.pad_char = chr(0)
        self.cpu = cpu
        self.lgr = lgr
        self.top = top
        self.mem_utils = mem_utils
        self.dataWatch = dataWatch
        self.coverage = coverage
        self.path = '/home/mike/SEED/afl/target_input.io'
        self.backstop = backstop
        self.stop_hap = None
        self.backstop.setCallback(self.whenDone)
        ''' careful changing this, may hit backstop before crashed process killed '''
        self.backstop_cycles =  500000
        #self.backstop_cycles = 100000
        self.coverage.enableCoverage(backstop=self.backstop, backstop_cycles=self.backstop_cycles, afl=True)
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.settimeout(2)
        self.server_address = ('localhost', 8765)
        self.iteration = 0
        cli.quiet_run_command('disable-reverse-execution')
        cli.quiet_run_command('enable-unsupported-feature internals')
        cli.quiet_run_command('save-snapshot name = origin')
        self.synchAFL()

    def stopHap(self, stop_action, one, exception, error_string):
        if self.stop_hap is not None:
            self.stop_hap = None
            #self.lgr.debug('afl stopHap')
            trace_bits = self.coverage.getTraceBits()
           

            bit_file = open('/home/mike/SEED/afl/bitfile', 'w')
            bit_file.write(trace_bits)
            bit_file.close()

           

            #self.lgr.debug('afl stopHap bitfile')
            status = self.coverage.getStatus()
            self.sendMsg('resim_done iteration: %d status: %d' % (self.iteration, status))

            #self.sock.sendall(trace_bits)

            self.iteration += 1 
            count = 0
            b=0
            for b in trace_bits:
                if b > 0:
                    break
                count += 1
            #self.lgr.debug('afl stopHap counted %d different trace hits' % count)
            self.lgr.debug('afl iteration %d stopHap first hit at %d value %d' % (self.iteration, count, b))
            SIM_run_alone(self.goN, None)

    def go(self, dumb=None):
        ''' wait for AFL to indicate it is ready, then process the file '''
        #self.lgr.debug('afl go iteration %d' % self.iteration)
        msg = self.getMsg()
        #self.lgr.debug('afl from afl: %s' % msg)
        if msg is not None and msg.startswith('afl_ready'):
            if self.stop_hap is None:
                self.stop_hap = SIM_hap_add_callback("Core_Simulation_Stopped", self.stopHap,  None)
            self.run()
        else:
            self.lgr.error('Unexpected message from afl: %s' % msg)
            return
        parts = msg.split()
        timeout = int(parts[2])
        new_cycles = timeout * 1000
        #if new_cycles != self.backstop_cycles:
        #    self.lgr.debug('afl go backstop_cycles changed from %d to %d' % (self.backstop_cycles, new_cycles))
        #    self.backstop_cycles = new_cycles

    def goN(self, dumb=None):
        in_data = self.getMsg()
        if in_data is None:
            self.lgr.error('Got None from afl')
            return
        if self.stop_hap is None:
            self.stop_hap = SIM_hap_add_callback("Core_Simulation_Stopped", self.stopHap,  None)
          
        current_length = len(in_data)
        pad_count = self.pad_to_size - current_length
        #self.lgr.debug('AFL goN data size %d  pad %d' % (current_length, pad_count))

        cli.quiet_run_command('restore-snapshot name=origin')

        lenreg = None
        if self.cpu.architecture == 'arm':
            lenreg = 'r0'
        else:
            lenreg = 'eax'
        addr, max_len = self.dataWatch.firstBufferAddress()
        if addr is None:
            self.lgr.error('AFL, no firstBufferAddress found')
            return
        self.dataWatch.clearWatchMarks()
        self.dataWatch.clearWatches()
        #self.lgr.debug('injectIO clear watch marks this len is %d, max_len is %s' % (len(byte_string), max_len))
        #self.lgr.debug('injectIO Addr: 0x%x byte_string is %s' % (addr, str(byte_string)))
        
        self.mem_utils.writeString(self.cpu, addr, in_data) 
        tot_length = current_length
        if pad_count > 0:
            b = bytearray(pad_count)
            self.mem_utils.writeString(self.cpu, addr+current_length, b) 
            tot_length += pad_count
         
        #self.writeRegValue(lenreg, len(byte_string))
        reg_num = self.cpu.iface.int_register.get_number(lenreg)
        self.cpu.iface.int_register.write(reg_num, tot_length)
        self.backstop.setFutureCycleAlone(self.backstop_cycles)
        self.coverage.doCoverage()
        #self.lgr.debug('afl, did coverage, now run context: %s' % self.cpu.current_context)
        SIM_run_command('c') 

    def run(self):
        self.coverage.doCoverage()
        current_size = os.path.getsize(self.path)
        pad_count = self.pad_to_size - current_size
        if pad_count > 0: 
            fh = open(self.path, 'rb+')
            pad_string = self.pad_char*pad_count
            fh.seek(0, 2)
            fh.write(pad_string)  
            fh.close()
        cli.quiet_run_command('restore-snapshot name=origin')
        self.top.injectIO(self.path, stay=True, afl=True)
        self.backstop.setFutureCycleAlone(self.backstop_cycles)
        #self.lgr.debug('afl, did coverage, now run context: %s' % self.cpu.current_context)
        SIM_run_command('c') 

    def whenDone(self):
        #self.lgr.debug('afl whenDone callback')
        pass

    def synchAFL(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_address = ('localhost', 8765)
        self.sock.connect(server_address)
        self.sendMsg('hi from resim')
        reply = self.getMsg()
        self.lgr.debug('afl synchAFL reply from afl: %s' % reply)

    def sendMsgx(self, msg):
        if len(msg) > RESIM_MSG_SIZE:
            self.lgr.error("afl sendMsg message too long %s" % msg)
            return
        pad = RESIM_MSG_SIZE - len(msg)
        msg = msg + pad*chr(0)
        self.sock.sendall(msg)

    def getMsgx(self):
        amount_received = 0
        amount_expected = RESIM_MSG_SIZE
        msg = "" 
        while amount_received < amount_expected:
            data = self.sock.recv(RESIM_MSG_SIZE)
            if data is None or len(data) == 0:
                self.sock.close()
                return None
            amount_received += len(data)
            msg = msg+data
        return msg
   
    def sendMsg(self, msg):
        msg_size = len(msg)
        ms = struct.pack("i", msg_size) 
        combine=''.join((ms,msg))
        try:
            self.sock.sendall(combine)
        except:
            print('AFL went away');
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
                return None
            #self.lgr.debug('got from afl: %s' % data)
            amount_received += len(data)
            expected = expected - len(data)
            msg = msg+data
        return msg
    
