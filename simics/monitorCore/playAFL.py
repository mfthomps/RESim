from simics import *
import writeData
import cli
import sys
import os
import pickle

class PlayAFL():
    def __init__(self, top, cpu, cell_name, backstop, coverage, mem_utils, dataWatch, target, 
             snap_name, context_manager, lgr, packet_count=1, stop_on_read=False, linear=False):
        self.top = top
        self.backstop = backstop
        self.coverage = coverage
        self.mem_utils = mem_utils
        self.dataWatch = dataWatch
        self.snap_name = snap_name
        self.cpu = cpu
        self.context_manager = context_manager
        self.cell_name = cell_name
        self.lgr = lgr
        self.findbb = None
        self.write_data = None
        self.orig_buffer = None
        self.max_len = None
        self.return_ip = None
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
        self.lgr.debug('playAFL afl list has %d items' % len(self.afl_list))
        self.index = -1
        self.stop_hap = None
        self.call_hap = None
        self.call_break = None
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
        if not self.loadPickle(snap_name):
            print('No AFL data stored for checkpoint %s, cannot play AFL.' % snap_name)
            return None
        cli.quiet_run_command('disable-reverse-execution')
        cli.quiet_run_command('enable-unsupported-feature internals')
        cli.quiet_run_command('save-snapshot name = origin')
        self.top.removeDebugBreaks(keep_watching=False, keep_coverage=False)
        if self.coverage is not None:
            self.coverage.enableCoverage(self.pid, backstop=self.backstop, backstop_cycles=self.backstop_cycles, afl=False, linear=linear)
            physical = True
            if linear:
                physical = False
                self.lgr.debug('afl, linear use context manager to watch tasks')
                self.context_manager.restoreDebugContext()
                self.context_manager.watchTasks()
            self.coverage.doCoverage(force_default_context=False, no_merge=True, physical=physical)

    def go(self, findbb=None):
        if self.call_ip is None:
            self.lgr.debug('No call IP, refuse to go.')
            print('No call IP, refuse to go.')
            return
        self.bnt_list = []
        self.index = -1
        self.hit_total = 0
        self.findbb = findbb
        if self.stop_hap is None:
            self.stop_hap = SIM_hap_add_callback("Core_Simulation_Stopped", self.stopHap,  None)
        SIM_run_alone(self.goAlone, None)

    def goAlone(self, dumb):
        self.current_packet=1
        self.index += 1
        if self.index < len(self.afl_list):
            cli.quiet_run_command('restore-snapshot name = origin')
            if self.coverage is not None:
                if self.findbb is not None:
                    self.coverage.clearHits() 
            if self.orig_buffer is not None:
                self.lgr.debug('restore bytes to %s cpu %s' % (str(self.addr), str(self.cpu)))
                self.mem_utils.writeString(self.cpu, self.addr, self.orig_buffer)
            full = os.path.join(self.afl_dir, self.afl_list[self.index])
            with open(full, 'rb') as fh:
                if sys.version_info[0] == 2:
                    self.in_data = bytearray(fh.read())
                else:
                    self.in_data = fh.read()
            self.lgr.debug('playAFL goAlone loaded %d bytes from file session %d of %d' % (len(self.in_data), self.index, len(self.afl_list)))
            self.afl_packet_count = self.packet_count
            if self.addr is None:
                self.addr, self.max_len = self.dataWatch.firstBufferAddress()
        
            #self.top.restoreRESimContext()
            self.write_data = writeData.WriteData(self.top, self.cpu, self.in_data, self.afl_packet_count, self.addr,  
                 self.max_len, self.call_ip, self.return_ip, self.mem_utils, self.backstop, self.lgr, udp_header=self.udp_header, 
                 pad_to_size=self.pad_to_size, backstop_cycles=self.backstop_cycles)
            self.write_data.write()
            self.lgr.debug('playAFL goAlone file %s continue from cycle 0x%x %d cpu context: %s' % (self.afl_list[self.index], self.cpu.cycles, self.cpu.cycles, str(self.cpu.current_context)))
            self.backstop.setFutureCycleAlone(self.backstop_cycles)
            SIM_run_command('c')
        else:
            ''' did all sessions '''
            if self.coverage is not None and self.findbb is None:
                hits = self.coverage.getHitCount()
                self.lgr.debug('Found %d total hits, save as %s' % (hits, self.target))
                self.coverage.saveCoverage(fname=self.target)
            self.delStopHap(None)               
            if self.findbb is not None:
                for f, n in sorted(self.bnt_list):
                    print('%-30s  packet %d' % (f, n))
                print('Found %d sessions that hit address 0x%x' % (len(self.bnt_list), self.findbb))
            print('Played %d sessions' % len(self.afl_list))
            cli.quiet_run_command('restore-snapshot name = origin')

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
                self.lgr.debug('playAFL stopHap index %d, got %d hits' % (self.index, self.coverage.getHitCount()))
                hits = self.coverage.getHitCount()
                if hits > self.hit_total:
                    delta = hits - self.hit_total
                    self.hit_total = hits 
                    self.lgr.debug('Found %d new hits' % delta)
                if self.findbb is not None and self.index < len(self.afl_list):
                    hit_bbs = self.coverage.getBlocksHit()
                    if self.findbb in hit_bbs:
                        packet_num = self.write_data.getCurrentPacket()
                        self.bnt_list.append((self.afl_list[self.index], packet_num))
            else:
                self.lgr.debug('playAFL stopHap')
            SIM_run_alone(self.goAlone, None)


    def delStopHap(self, dumb):
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
            self.call_ip = so_pickle['call_ip']
            self.return_ip = so_pickle['return_ip']
            if 'addr' in so_pickle:
                self.addr = so_pickle['addr']
                self.max_len = so_pickle['size']
            if 'orig_buffer' in so_pickle:
                self.orig_buffer = so_pickle['orig_buffer']
        return retval
