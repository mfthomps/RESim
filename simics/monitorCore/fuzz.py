import os
import pickle
import shutil
import writeData
from simics import *
class Fuzz():
    def __init__(self, top, cpu, cell_name, path, coverage, backstop, mem_utils, snap_name, lgr, packet_count, fname):
        self.cpu = cpu
        self.cell_name = cell_name
        self.lgr = lgr
        self.top = top
        self.coverage = coverage
        self.path = None
        self.orig_path = path
        self.packet_count = packet_count
        self.backstop = backstop
        self.mem_utils = mem_utils
        self.stop_hap = None
        #self.backstop.setCallback(self.whenDone)
        pid = top.getPID()
        if os.getenv('BACK_STOP_CYCLES') is not None:
            self.backstop_cycles =   int(os.getenv('BACK_STOP_CYCLES'))
            self.lgr.debug('fuzz BACK_STOP_CYCLES is %d' % self.backstop_cycles)
        else:
            self.lgr.warning('no BACK_STOP_CYCLES defined, using default of 100000')
            self.backstop_cycles =   100000
        self.coverage.enableCoverage(pid, backstop=self.backstop, backstop_cycles=self.backstop_cycles, fname=fname)
        self.shrinking = True
        self.orig_hits = None
        ''' number of bytes to subtract from file if number of hits is not changed '''
        self.delta = None
        self.current_size = None
        self.previous_size = None
        self.orig_size = None
        self.pad_to_size = None
        self.pad_char = None
        self.count = 0
        self.addr = None
        self.max_len = None
        self.call_ip = None
        self.return_ip = None
        self.loadPickle(snap_name)
        ''' iterate until delta below this '''
        self.threshold = None
        if self.cpu.architecture == 'arm':
            lenreg = 'r0'
        else:
            lenreg = 'eax'
        self.len_reg_num = self.cpu.iface.int_register.get_number(lenreg)
        self.lgr.debug('Fuzz init')

        self.write_data = None

    def stopHap(self, stop_action, one, exception, error_string):
        self.lgr.debug('fuzz stopHap')
        SIM_run_alone(self.trimBack, None)

    def trim(self):
        ''' keep cutting in half until hits drops. then back off and trim half that...'''
        self.lgr.debug('fuzz trim')
        self.path = os.path.join('/tmp', 'trimmer') 
        shutil.copyfile(self.orig_path, self.path)

        self.orig_size = os.path.getsize(self.path)
        self.delta = self.orig_size / 2
        self.threshold = (self.orig_size / 20)
        self.pad_char = chr(0)
        self.pad_to_size = self.orig_size
        self.lgr.debug('fuzz trim orig_size %d delta %d threshold is %d' % (self.orig_size, self.delta, self.threshold))
        if self.stop_hap is None:
            self.stop_hap = SIM_hap_add_callback("Core_Simulation_Stopped", self.stopHap,  None)
        self.run()

    def rmHap(self):
        SIM_hap_delete_callback_id("Core_Simulation_Stopped", self.stop_hap)
        self.stop_hap = None
      
    def grow(self):
        shutil.copyfile(self.orig_path, self.path)
        ''' back to original size '''
        self.lgr.debug('fuzz trim grow enter with current size %d delta %d' % (self.current_size, self.delta))
        self.current_size = self.previous_size
        self.lgr.debug('fuzz trim grow restore back to %d byte' % (self.current_size))
        self.delta = self.delta / 2
        self.current_size = self.current_size - self.delta
        self.delta = self.delta / 2
        self.fileTrim()
        self.lgr.debug('fuzz trim grow back to %d byte' % (self.current_size))
        self.run()

    def fileTrim(self, nopad=False):
        fh = open(self.path, 'rb+')
        fh.truncate(self.current_size)
        #self.lgr.debug('truncated to %d' % self.current_size)
        if self.pad_char is not None and not nopad:
            pad_count = self.pad_to_size - self.current_size
            pad_string = self.pad_char*pad_count
            fh.seek(0, 2)
            fh.write(pad_string)  
        fh.close()
        size = os.path.getsize(self.path)
        if self.pad_char is not None:
            self.lgr.debug('fuzz fileTrimmed and padded to %d' % size)
        
    def checkPad(self):
        ''' try padding if not already done '''
        if self.pad_char is None:
            self.lgr.debug('fuzz, try again with padding')
            self.pad_char = chr(0)
            self.pad_to_size = self.current_size
            self.trim()
        else:
            self.rmHap()

    def trimTest(self, dumb):
        hit = len(self.coverage.getBlocksHit())
        print('fuzz says no more blocks being hit after %d hits' % hit)
        if self.count < 3:
            self.count += 1
            self.run()

    def trimBack(self, dumb):
        ''' called when a trim finishes, or initial run finished ''' 
        hits = len(self.coverage.getBlocksHit())
        if self.orig_hits is None:
            if hits == 0:
                self.lgr.error('No basic blocks hit with original data')
                return
            self.orig_hits = hits
            self.current_size = os.path.getsize(self.path)
            self.previous_size = self.current_size
            self.lgr.debug('fuzz trimBack first run, orig hits %d, size %d' % (self.orig_hits, self.current_size))
        else:
            self.lgr.debug('fuzz trimBack found %d hits' % hits)
           
        if hits == self.orig_hits:
            ''' keep shrinking '''
            self.previous_size = self.current_size
            if self.current_size > self.delta:
                self.current_size = self.current_size - self.delta
                if self.delta > self.threshold:
                    ''' go smaller next time if still unchanged '''
                    self.delta = self.delta/2
            else:
                self.lgr.error('fuzz trimBack current size would go negative %d' % self.current_size)
                return
            self.fileTrim()
            self.lgr.debug('fuzz trim shrink to %d delta %d' % (self.current_size, self.delta)) 
            self.run()
            #else:
            #    self.lgr.debug('fuzz threshold hit trim done, delta %d, threshold %d size %s' % (self.delta, self.threshold, self.current_size))
            #    self.checkPad()
        else:
            ''' fewer hits.  if delta has not reached threshold, grow it and start reducing again '''
            if self.delta > self.threshold:
                self.lgr.debug('fuzz trim did shrink, changed hits to %d, so grow' % (hits))
                self.grow()
            else:
                ''' must be done, restore to previous, and do not pad, will feed to AFL '''
                self.current_size = self.previous_size
                shutil.copyfile(self.orig_path, self.path)
                self.fileTrim(nopad=True)
                self.lgr.debug('fuzz threshold hit with reduced hits.  Restore size to %d' % self.current_size)
                self.checkPad()
        
    def writeData(self):    
        with open(self.path) as fh:
            in_data = fh.read()
        self.write_data = writeData.WriteData(self.top, self.cpu, in_data, self.packet_count, self.addr,  
                 self.max_len, self.call_ip, self.return_ip, self.mem_utils, self.backstop, self.lgr, udp_header=None, 
                 pad_to_size=None, filter=None, backstop_cycles=self.backstop_cycles)
        num_bytes = self.write_data.write()
        #self.mem_utils.writeString(self.cpu, self.addr, in_data) 
        #self.cpu.iface.int_register.write(self.len_reg_num, len(in_data))
        self.lgr.debug('fuzz writeData wrote %d bytes to 0x%x' % (num_bytes, self.addr))


    def run(self):
        self.coverage.doCoverage(no_merge=True)
        #self.top.injectIO(self.path, stay=True)
        self.top.goToOrigin()
        self.writeData()
        if self.backstop_cycles > 0:
            self.lgr.debug('fuzz setting backstop')
            self.backstop.setFutureCycleAlone(self.backstop_cycles)
        self.lgr.debug('fuzz, did coverage, now run')
        SIM_run_command('c') 

    def whenDone(self):
        hit = len(self.coverage.getBlocksHit())
        print('fuzz says no more blocks being hit after %d hits' % hit)

    def loadPickle(self, name):
        afl_file = os.path.join('./', name, self.cell_name, 'afl.pickle')
        if os.path.isfile(afl_file):
            so_pickle = pickle.load( open(afl_file, 'rb') ) 
            #print('start %s' % str(so_pickle['text_start']))
            self.call_ip = so_pickle['call_ip']
            self.return_ip = so_pickle['return_ip']
            if 'addr' in so_pickle:
                self.addr = so_pickle['addr']
                self.max_len = so_pickle['size']
            self.lgr.debug('afl pickle from %s addr: 0x%x max_len: %d' % (afl_file, self.addr, self.max_len))
