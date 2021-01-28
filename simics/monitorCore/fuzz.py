import backStop
import os
import shutil
from simics import *
class Fuzz():
    def __init__(self, top, cpu, path, coverage, lgr):
        self.cpu = cpu
        self.lgr = lgr
        self.top = top
        self.coverage = coverage
        self.path = None
        self.orig_path = path
        self.backstop = backStop.BackStop(self.cpu, self.lgr)
        self.stop_hap = None
        #self.backstop.setCallback(self.whenDone)
        self.coverage.enableCoverage(backstop=self.backstop, backstop_cycles=500000)
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
        ''' iterate until delta below this '''
        self.threshold = None
        

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
        self.lgr.debug('fuzz trim threshold is %d' % (self.threshold))
        if self.stop_hap is None:
            self.stop_hap = SIM_hap_add_callback("Core_Simulation_Stopped", self.stopHap,  None)
        self.run()
      
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
            self.orig_hits = hits
            self.current_size = os.path.getsize(self.path)
            self.previous_size = self.current_size
            self.lgr.debug('fuzz trimBack orig hits %d, size %d' % (self.orig_hits, self.current_size))
        else:
            self.lgr.debug('fuzz trimBack found %d hits' % hits)
           
        if hits == self.orig_hits:
            ''' keep shrinking '''
            self.previous_size = self.current_size
            self.current_size = self.current_size - self.delta
            if self.delta > self.threshold:
                ''' go smaller next time if still unchanged '''
                self.delta = self.delta/2
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
                ''' must be done, restore to previous '''
                self.current_size = self.previous_size
                shutil.copyfile(self.orig_path, self.path)
                self.fileTrim(nopad=True)
                self.lgr.debug('fuzz threshold hit with reduced hits.  Restore size to %d' % self.current_size)
                self.checkPad()
            

    def run(self):
        self.coverage.doCoverage()
        self.top.injectIO(self.path, stay=True)
        self.lgr.debug('fuzz, did coverage, now run')
        SIM_run_command('c') 

    def whenDone(self):
        hit = len(self.coverage.getBlocksHit())
        print('fuzz says no more blocks being hit after %d hits' % hit)
