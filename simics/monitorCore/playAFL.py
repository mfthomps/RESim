from simics import *
import writeData
import cli
import sys
import os
import pickle

class PlayAFL():
    def __init__(self, top, cpu, cell_name, backstop, coverage, mem_utils, dataWatch, target, snap_name, lgr, packet_count=1, stop_on_read=False, findbb=None):
        self.top = top
        self.backstop = backstop
        self.coverage = coverage
        self.mem_utils = mem_utils
        self.dataWatch = dataWatch
        self.snap_name = snap_name
        self.cpu = cpu
        self.cell_name = cell_name
        self.lgr = lgr
        self.findbb = findbb
        self.write_data = None
        afl_output = os.getenv('AFL_OUTPUT')
        if afl_output is None:
            afl_output = os.path.join(os.getenv('HOME'), 'SEED','afl','afl-output')
        pad_env = os.getenv('AFL_PAD') 
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
            return None
        self.target = target
        self.afl_dir = os.path.join(afl_output, target,'queue')
        self.afl_list = [f for f in os.listdir(self.afl_dir) if os.path.isfile(os.path.join(self.afl_dir, f))]
        self.index = 0 
        self.stop_hap = None
        self.call_hap = None
        self.call_break = None
        self.bb_break = None
        self.bb_hap = None
        self.addr = None
        self.in_data = None
        #self.backstop_cycles =   100000
        self.backstop_cycles =   900000
        self.stop_on_read =   stop_on_read
        self.packet_count = packet_count
        self.afl_packet_count = None
        self.current_packet = 0
        self.call_ip = None
        self.hit_total = 0
        ''' replay file names that hit the given bb '''
        self.bnt_list = []
        self.pid = self.top.getPID()
        self.stop_on_break = False
        if self.cpu.architecture == 'arm':
            lenreg = 'r0'
        else:
            lenreg = 'eax'
        self.len_reg_num = self.cpu.iface.int_register.get_number(lenreg)
        self.loadPickle(snap_name)
        cli.quiet_run_command('disable-reverse-execution')
        cli.quiet_run_command('enable-unsupported-feature internals')
        cli.quiet_run_command('save-snapshot name = origin')
        self.top.removeDebugBreaks(keep_watching=False, keep_coverage=False)
        if self.coverage is not None:
            self.coverage.enableCoverage(self.pid, backstop=self.backstop, backstop_cycles=self.backstop_cycles, afl=False)
            self.coverage.doCoverage(force_default_context=False, no_merge=True, physical=True)

    def go(self):
        if self.stop_hap is None:
            self.stop_hap = SIM_hap_add_callback("Core_Simulation_Stopped", self.stopHap,  None)
        SIM_run_alone(self.goAlone, None)

    def goAlone(self, dumb):
        self.current_packet=1
        if self.index < len(self.afl_list):
            cli.quiet_run_command('restore-snapshot name = origin')
            full = os.path.join(self.afl_dir, self.afl_list[self.index])
            with open(full) as fh:
                self.in_data = bytearray(fh.read())
            self.lgr.debug('playAFL goAlone loaded %d bytes from file session %d of %d' % (len(self.in_data), self.index, len(self.afl_list)))
            self.afl_packet_count = self.packet_count
            if self.addr is None:
                self.addr, max_len = self.dataWatch.firstBufferAddress()
        
            #self.top.restoreRESimContext()
            self.write_data = writeData.WriteData(self.top, self.cpu, self.in_data, self.afl_packet_count, self.addr,  
                 self.max_len, self.call_ip, self.return_ip, self.mem_utils, self.backstop, self.lgr, udp_header=self.udp_header, 
                 pad_to_size=self.pad_to_size, backstop_cycles=self.backstop_cycles)
            self.write_data.write()
            self.lgr.debug('playAFL goAlone file %s continue from cycle 0x%x %d cpu context: %s' % (self.afl_list[self.index], self.cpu.cycles, self.cpu.cycles, str(self.cpu.current_context)))
            self.backstop.setFutureCycleAlone(self.backstop_cycles)
            self.index += 1
            SIM_run_command('c')
        else:
            if self.coverage is not None:
                hits = self.coverage.getHitCount()
                self.lgr.debug('Found %d total hits, save as %s' % (hits, self.target))
                self.coverage.saveCoverage(fname=self.target)
            self.delCallHap(None)               
            self.delStopHap(None)               
            if self.findbb is not None:
                for f in self.bnt_list:
                    print(f)
            print('Played %d sessions' % len(self.afl_list))

    def playBreak(self, bnt_index):
        self.current_packet = 1
        self.index = 0
        self.afl_list = [self.bnt_list[bnt_index]]
        cli.quiet_run_command('enable-reverse-execution')
        self.stop_on_break = True
        self.lgr.debug('playAFL playBreak')
        self.goAlone(None)

    def stopHap(self, dumb, one, exception, error_string):
        self.lgr.debug('in stopHap')
        if self.stop_hap is not None:
            if self.coverage is not None:
                self.lgr.debug('playAFL stopHap, got %d hits' % self.coverage.getHitCount())
                hits = self.coverage.getHitCount()
                if hits > self.hit_total:
                    delta = hits - self.hit_total
                    self.hit_total = hits 
                    self.lgr.debug('Found %d new hits' % delta)
            else:
                self.lgr.debug('playAFL stopHap')
            SIM_run_alone(self.goAlone, None)


    def bbHap(self, dumb, third, break_num, memory):
        ''' Hit basic block we were looking for'''
        if self.bb_hap is None:
            return
        self.lgr.debug('bbHap hit')
        self.bnt_list.append(self.afl_list[self.index])
        if self.stop_on_break:
            SIM_break_simulation('done bbHap')

    def callHap(self, dumb, third, break_num, memory):
        ''' Hit a call to recv '''
        if self.call_hap is None:
            return
        if self.current_packet > self.afl_packet_count:
            self.lgr.debug('afl callHap current packet %d above count %d' % (self.current_packet, self.afl_packet_count))
            return
        this_pid = self.top.getPID()
        if this_pid != self.pid:
            self.lgr.debug('afl callHap wrong pid got %d wanted %d' % (this_pid, self.pid))
            return
        self.lgr.debug('afl callHap packet %d cycles 0x%x' % (self.current_packet, self.cpu.cycles))
        if self.stop_on_read:
            self.lgr.debug('afl callHap stop on read')
            SIM_break_simulation('stop on read')
            return
        if len(self.in_data) == 0:
            self.lgr.error('afl callHap current packet %d no data left' % (self.current_packet))
            SIM_break_simulation('broken offset')
            SIM_run_alone(self.delCallHap, None)
            return

        self.write_data.write()
        if self.current_packet >= self.afl_packet_count:
            # set backstop if needed, we are on the last (or only) packet.
            #SIM_run_alone(self.delCallHap, None)
            if self.backstop_cycles > 0:
                self.backstop.setFutureCycleAlone(self.backstop_cycles)

    def delCallHap(self, dumb):
        #self.lgr.debug('afl delCallHap')
        if self.call_hap is not None:
            SIM_delete_breakpoint(self.call_break)
            SIM_hap_delete_callback_id('Core_Breakpoint_Memop', self.call_hap)
            self.call_hap = None
        if self.bb_break is not None:
            SIM_delete_breakpoint(self.bb_break)
            SIM_hap_delete_callback_id('Core_Breakpoint_Memop', self.bb_hap)
            self.bb_break = None
            self.bb_hap = None
        

    def delStopHap(self, dumb):
        #self.lgr.debug('afl delCallHap')
        SIM_hap_delete_callback_id('Core_Simulation_Stopped', self.stop_hap)

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
