from simics import *
import writeData
import aflPath
import resimUtils
import cli
import sys
import os
import glob
import pickle
import json

class PlayAFL():
    def __init__(self, top, cpu, cell_name, backstop, coverage, mem_utils, dataWatch, target, 
             snap_name, context_manager, cfg_file, lgr, packet_count=1, stop_on_read=False, linear=False, 
             create_dead_zone=False, afl_mode=False, crashes=False, parallel=False, only_thread=False, fname=None):
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
        self.return_ip = None
        self.cfg_file = cfg_file
        self.target = target
        self.afl_dir = aflPath.getAFLOutput()
        self.all_hits = []
        self.afl_list = []
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
            sor = os.getenv('STOP_ON_READ')
            if sor is not None and sor.lower() == 'true':
                self.stop_on_read = True
        self.udp_header = os.getenv('AFL_UDP_HEADER')
        if packet_count > 1 and not (self.udp_header is not None or self.pad_to_size > 0):
            self.lgr.error('Multi-packet requested but no pad or UDP header has been given in env variables')
            return None
        if os.path.isfile(target):
            ''' single file to play '''
            self.target = 'oneplay'
            relative = target[(len(self.afl_dir)+1):]
            if target.startswith(aflPath.getAFLOutput()) and len(relative.strip()) > 0:
                self.afl_list = [relative]
                self.lgr.debug('playAFL, single file, path relative to afl_dir is %s' % relative)
            else:
                self.afl_list = [target]
                self.lgr.debug('playAFL, single file, abs path is %s' % target)
        else:
            if not crashes:
                print('get target queue')
                self.lgr.debug('playAFL get queue for target %s' % target)
                self.afl_list = aflPath.getTargetQueue(target, get_all=True)
                if len(self.afl_list) == 0:
                    print('No queue files found for %s' % target)
                    self.lgr.debug('playAFL No queue files found for %s' % target)
                    return
            else:
                self.afl_list = aflPath.getTargetCrashes(target)
                if len(self.afl_list) == 0:
                    print('No crashes found for %s' % target)
                    return
            print('Playing %d sessions.  Please wait until that is reported.' % len(self.afl_list))
        self.lgr.debug('playAFL afl list has %d items' % len(self.afl_list))
        self.index = -1
        self.stop_hap = None
        self.call_hap = None
        self.call_break = None
        self.addr = None
        self.in_data = None
        #self.backstop_cycles =   100000
        if afl_mode:
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
        self.call_ip = None
        self.hit_total = 0

        self.filter_module = None
        packet_filter = os.getenv('AFL_PACKET_FILTER')
        if packet_filter is not None:
            self.filter_module = resimUtils.getPacketFilter(packet_filter, lgr)

        ''' replay file names that hit the given bb '''
        self.bnt_list = []
        self.pid = self.top.getPID()
        self.stop_on_break = False
        self.exit_list = []
        if self.cpu.architecture == 'arm':
            lenreg = 'r0'
        else:
            lenreg = 'eax'
        self.len_reg_num = self.cpu.iface.int_register.get_number(lenreg)
        
        self.snap_name = snap_name
        if not self.loadPickle(snap_name):
            print('No AFL data stored for checkpoint %s, cannot play AFL.' % snap_name)
            return None
        cli.quiet_run_command('disable-reverse-execution')
        cli.quiet_run_command('enable-unsupported-feature internals')
        cli.quiet_run_command('save-snapshot name = origin')
        self.top.removeDebugBreaks(keep_watching=False, keep_coverage=False)
        self.physical=False
        if self.coverage is not None:
            full_path = None
            if fname is not None:
                full_path = self.top.getFullPath(fname)
            self.coverage.enableCoverage(self.pid, backstop=self.backstop, backstop_cycles=self.backstop_cycles, 
               afl=afl_mode, linear=linear, create_dead_zone=create_dead_zone, only_thread=only_thread, fname=full_path)
            self.physical = True
            if linear:
                self.physical = False
                self.lgr.debug('afl, linear use context manager to watch tasks')
                self.context_manager.restoreDebugContext()
                self.context_manager.watchTasks()
            self.coverage.doCoverage(no_merge=True, physical=self.physical)

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
        hang_cycles = 90000000
        hang = os.getenv('HANG_CYCLES')
        if hang is not None:
            hang_cycles = int(hang)
        self.backstop.setHangCallback(self.hangCallback, hang_cycles)
        self.initial_cycle = cpu.cycles

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

    def hangCallback(self, cycles):
        self.lgr.debug('playAFL hang detected')
        SIM_break_simulation('hang')

    def goAlone(self, clear_hits):
        self.current_packet=1
        self.index += 1
        self.lgr.debug('playAFL goAlone, len of afl list is %d, index now %d' % (len(self.afl_list), self.index))
        done = False
        if self.target != 'oneplay':
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
        if self.index < len(self.afl_list):
            self.lgr.debug('playAFL goAlone index %d' % self.index)
            cli.quiet_run_command('restore-snapshot name = origin')
            if self.coverage is not None:
                if clear_hits:
                    self.coverage.stopCover() 
                    self.coverage.doCoverage(no_merge=True, physical=self.physical) 
            #if self.orig_buffer is not None:
            #    #self.lgr.debug('playAFL restored %d bytes to original buffer at 0x%x' % (len(self.orig_buffer), self.addr))
            #    self.mem_utils.writeBytes(self.cpu, self.addr, self.orig_buffer) 
            self.lgr.debug('playAFL try afl_list entry %s' % self.afl_list[self.index])
            full = os.path.join(self.afl_dir, self.afl_list[self.index])
            if not os.path.isfile(full):
                self.lgr.debug('No file at %s, non-parallel file' % full)
                full = os.path.join(self.afl_dir, self.target, 'queue', self.afl_list[self.index])
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
            if self.write_data is None:
                self.write_data = writeData.WriteData(self.top, self.cpu, self.in_data, self.afl_packet_count, 
                         self.mem_utils, self.backstop, self.snap_name, self.lgr, udp_header=self.udp_header, 
                         pad_to_size=self.pad_to_size, backstop_cycles=self.backstop_cycles, force_default_context=True, 
                         filter=self.filter_module, stop_on_read=self.stop_on_read, shared_syscall=self.top.getSharedSyscall())
            else:
                self.write_data.reset(self.in_data, self.afl_packet_count, self.addr)
            eip = self.top.getEIP(self.cpu)
            count = self.write_data.write()
            self.lgr.debug('playAFL goAlone ip: 0x%x wrote %d bytes from file %s continue from cycle 0x%x %d cpu context: %s' % (eip, count, self.afl_list[self.index], self.cpu.cycles, self.cpu.cycles, str(self.cpu.current_context)))
            self.backstop.setFutureCycle(self.backstop_cycles, now=True)

            if self.afl_mode: 
                self.coverage.watchExits()
            elif self.coverage is not None:
                self.coverage.watchExits(callback=self.reportExit)
            else:
                self.context_manager.watchGroupExits()
                self.context_manager.setExitCallback(self.reportExit)
            if self.stop_hap is None:
                self.stop_hap = SIM_hap_add_callback("Core_Simulation_Stopped", self.stopHap,  None)
            self.lgr.debug('playAFL goAlone now continue')
            SIM_run_command('c')
        else:
            self.lgr.debug('playAFL did all sessions.')
            ''' did all sessions '''
            if self.coverage is not None and self.findbb is None and not self.afl_mode and not self.parallel:
                hits = self.coverage.getHitCount()
                self.lgr.debug('All sessions done, save %d all_hits as %s' % (len(self.all_hits), self.target))
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
                print('%d Hits file written to %s' % (len(self.all_hits), save_name))
            elif self.parallel:
                self.top.quit()
            self.delStopHap(None)               
            if self.findbb is not None:
                for f, n in sorted(self.bnt_list):
                    print('%-30s  packet %d' % (f, n))
                print('Found %d sessions that hit address 0x%x' % (len(self.bnt_list), self.findbb))
            print('Played %d sessions' % len(self.afl_list))
            cli.quiet_run_command('restore-snapshot name = origin')
            if len(self.exit_list)>0:
                print('%d Sessions that called exit:' % len(self.exit_list))
                for exit in sorted(self.exit_list):
                    print(exit)
                print('\n\n  Sessions that did not exit:')
        
                for item in sorted(self.afl_list):
                    if item not in self.exit_list:
                        print(item)
                

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
        if self.cpu.cycles == self.initial_cycle:
            self.lgr.debug('playAFL stopHap, but did not get anywhere, continue?')
            SIM_run_alone(SIM_continue, 0)
            return
        if self.stop_hap is not None:
            if self.coverage is not None:
                num_packets = self.write_data.getCurrentPacket()
                self.lgr.debug('playAFL stopHap index %d, got %d hits, %d packets cycles: 0x%x' % (self.index, self.coverage.getHitCount(), 
                     num_packets, self.cpu.cycles))
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
                else:
                    self.recordHits(hit_bbs)
                if self.coverage.didExit():
                    self.exit_list.append(self.afl_list[self.index])
            else:
                self.lgr.debug('playAFL stopHap')
            SIM_run_alone(self.goAlone, True)


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
            if 'orig_buffer' in so_pickle:
                self.orig_buffer = so_pickle['orig_buffer']
        return retval

    def reportExit(self):
        print('Process exit  cycles 0x%x' % self.cpu.cycles)
        SIM_break_simulation('process exit')
 
