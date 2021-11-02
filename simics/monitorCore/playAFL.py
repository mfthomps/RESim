from simics import *
import writeData
import aflPath
import cli
import sys
import os
import glob
import pickle
import json

class PlayAFL():
    def __init__(self, top, cpu, cell_name, backstop, coverage, mem_utils, dataWatch, target, 
             snap_name, context_manager, cfg_file, lgr, packet_count=1, stop_on_read=False, linear=False, create_dead_zone=False, afl_mode=False):
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
        self.afl_mode = afl_mode
        self.findbb = None
        self.write_data = None
        self.orig_buffer = None
        self.max_len = None
        self.return_ip = None
        self.cfg_file = cfg_file
        afl_output = aflPath.getAFLOutput()
        self.all_hits = []
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
        if os.path.isfile(target):
            self.target = 'oneplay'
            self.afl_dir = os.path.dirname(target)
            base = os.path.basename(target)
            self.afl_list = [base]
        else:
            self.target = target
            self.afl_dir = os.path.join(afl_output, target,'queue')
            gpath = os.path.join(afl_output, target, 'resim_*', 'queue', 'id:*')
            print('gpath is %s' % gpath)
            glist = glob.glob(gpath)
            if len(glist) == 0 and os.path.isdir(self.afl_dir):
                self.afl_list = [f for f in os.listdir(self.afl_dir) if os.path.isfile(os.path.join(self.afl_dir, f))]
            else:
                ''' Assume Parallel fuzzing '''
                self.afl_list = []
                for path in glist:
                    if 'sync:' not in path:
                        self.afl_list.append(path)
        self.lgr.debug('playAFL afl list has %d items' % len(self.afl_list))
        self.index = -1
        self.stop_hap = None
        self.call_hap = None
        self.call_break = None
        self.addr = None
        self.in_data = None
        #self.backstop_cycles =   100000
        self.backstop_cycles =   900000
        bsc = os.getenv('BACK_STOP_CYCLES')
        if bsc is not None:
            self.backstop_cycles = int(bsc)
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
        env_max_len = os.getenv('AFL_MAX_LEN')
        if env_max_len is not None:
            self.max_len = int(env_max_len)
        cli.quiet_run_command('disable-reverse-execution')
        cli.quiet_run_command('enable-unsupported-feature internals')
        cli.quiet_run_command('save-snapshot name = origin')
        self.top.removeDebugBreaks(keep_watching=False, keep_coverage=False)
        if self.coverage is not None:
            self.coverage.enableCoverage(self.pid, backstop=self.backstop, backstop_cycles=self.backstop_cycles, 
               afl=afl_mode, linear=linear, create_dead_zone=create_dead_zone)
            physical = True
            if linear:
                physical = False
                self.lgr.debug('afl, linear use context manager to watch tasks')
                self.context_manager.restoreDebugContext()
                self.context_manager.watchTasks()
            self.coverage.doCoverage(no_merge=True, physical=physical)

            full_path = self.coverage.getFullPath()
            full_path = os.path.abspath(full_path)
    
            hits_path = self.coverage.getHitsPath()+'.prog'
            parent = os.path.dirname(os.path.abspath(hits_path))
            print('parent is %s' % parent)
            try:
                os.makedirs(parent)
            except:
                pass
            with open(hits_path, 'w') as fh:
                fh.write(full_path+'\n')
                fh.write(self.cfg_file+'\n')
            #print('full_path is %s,  wrote that to %s' % (full_path, hits_path))
            #self.backstop.setCallback(self.whenDone)



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
        done = False
        if self.target != 'oneplay':
            ''' skip files if already have coverage '''
            while not done and self.index < len(self.afl_list):
                fname = self.getHitsPath(self.index)
                if not os.path.isfile(fname):
                    done = True
                else:
                    hits_json = json.load(open(fname))
                    for hit in hits_json:
                        hit = int(hit)
                        if hit not in self.all_hits:
                            self.all_hits.append(hit)
                    self.index += 1
        if self.index < len(self.afl_list):
            cli.quiet_run_command('restore-snapshot name = origin')
            if self.coverage is not None:
                self.coverage.clearHits() 
                #self.coverage.doCoverage() 
            if self.orig_buffer is not None:
                #self.lgr.debug('playAFL restored %d bytes to original buffer at 0x%x' % (len(self.orig_buffer), self.addr))
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
        
            if self.orig_buffer is not None:
                ''' restore receive buffer to original condition in case injected data is smaller than original and poor code
                    references data past the end of what is received. '''
                self.mem_utils.writeString(self.cpu, self.addr, self.orig_buffer) 
                self.lgr.debug('playAFL restored %d bytes to original buffer at 0x%x' % (len(self.orig_buffer), self.addr))
            #self.top.restoreRESimContext()
            #self.context_manager.restoreDebugContext()
            self.write_data = writeData.WriteData(self.top, self.cpu, self.in_data, self.afl_packet_count, self.addr,  
                 self.max_len, self.call_ip, self.return_ip, self.mem_utils, self.backstop, self.lgr, udp_header=self.udp_header, 
                 pad_to_size=self.pad_to_size, backstop_cycles=self.backstop_cycles, force_default_context=True)
            eip = self.top.getEIP(self.cpu)
            count = self.write_data.write()
            self.lgr.debug('playAFL goAlone ip: 0x%x wrote %d bytes from file %s continue from cycle 0x%x %d cpu context: %s' % (eip, count, self.afl_list[self.index], self.cpu.cycles, self.cpu.cycles, str(self.cpu.current_context)))
            self.backstop.setFutureCycleAlone(self.backstop_cycles)

            if self.afl_mode: 
                self.coverage.watchExits()
            elif self.coverage is not None:
                self.coverage.watchExits(callback=self.reportExit)
            else:
                self.context_manager.watchGroupExits()
                self.context_manager.setExitCallback(self.reportExit)
            SIM_run_command('c')
        else:
            ''' did all sessions '''
            if self.coverage is not None and self.findbb is None:
                hits = self.coverage.getHitCount()
                self.lgr.debug('All sessions done, save as %s' % (self.target))
                hits_path = self.coverage.getHitsPath()
  
                s = json.dumps(self.all_hits)
                save_name = '%s.%s.hits' % (hits_path, self.target)
                try:
                    os.makedirs(os.path.dirname(hits_path))
                except:
                    pass
                with open(save_name, 'w') as fh:
                    fh.write(s)
                    fh.flush()
                print('Hits file written to %s' % save_name)
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

    def getHitsPath(self, index):
        queue_dir = os.path.dirname(self.afl_list[index])
        queue_parent = os.path.dirname(queue_dir)
        coverage_dir = os.path.join(queue_parent, 'coverage')
        try:
            os.makedirs(coverage_dir)
        except:
            pass
        fname = os.path.join(coverage_dir, os.path.basename(self.afl_list[self.index])) 
        return fname

    def recordHits(self, hit_bbs):
        ''' hits will go in a "coverage" directory along side queue, etc. '''
        #hit_list = list(hit_bbs.keys())
        fname = self.getHitsPath(self.index)
        with open(fname, 'w') as fh:
            #json.dump(hit_list, fh) 
            json.dump(hit_bbs, fh) 
        #for hit in hit_list:
        for hit in hit_bbs:
            hit = int(hit)
            if hit not in self.all_hits:
                self.all_hits.append(hit)

    def stopHap(self, dumb, one, exception, error_string):
        self.lgr.debug('in stopHap')
        if self.stop_hap is not None:
            if self.coverage is not None:
                num_packets = self.write_data.getCurrentPacket()
                self.lgr.debug('playAFL stopHap index %d, got %d hits, %d packets' % (self.index, self.coverage.getHitCount(), num_packets))
                self.backstop.clearCycle()
                hits = self.coverage.getHitCount()
                if hits > self.hit_total:
                    delta = hits - self.hit_total
                    self.hit_total = hits 
                    self.lgr.debug('Found %d new hits' % delta)
                hit_bbs = self.coverage.getBlocksHit()
                if self.findbb is not None and self.index < len(self.afl_list):
                    self.lgr.debug('looking for bb 0x%x' % self.findbb)
                    if self.findbb in hit_bbs:
                        packet_num = self.write_data.getCurrentPacket()
                        self.bnt_list.append((self.afl_list[self.index], packet_num))
                else:
                    self.recordHits(hit_bbs)
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

    def reportExit(self):
        print('Process exit  cycles 0x%x' % self.cpu.cycles)
        SIM_break_simulation('process exit')
 
