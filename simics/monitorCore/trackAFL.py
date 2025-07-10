import os
import json
import glob
from simics import *
class TrackAFL():
    def __init__(self, top, target, lgr):
        self.top = top
        self.lgr = lgr
        afl_output = top.getAFLOutput()
        self.target = target
        self.afl_dir = os.path.join(afl_output, target,'queue')
        self.stop_hap = None
        self.afl_list = []
        self.lgr.debug('trackAFL afl list has %d items' % len(self.afl_list))
        self.index = 0
        self.inject_instance = None
        self.did_exit = []

        afl_output = top.getAFLOutput()
        self.target = target
        self.afl_dir = os.path.join(afl_output, target)
        unique_path = os.path.join(self.afl_dir, target+'.unique')
        print('TrackAFL, NOTE will only play the first packet.  Paths from %s' % unique_path)
        if os.path.isfile(unique_path):
            cover_list = json.load(open(unique_path))
            for path in cover_list:
                base = os.path.basename(path)
                grand = os.path.dirname(os.path.dirname(path))
                new = os.path.join(grand, 'queue', base)
                self.afl_list.append(new)
            self.lgr.debug('trackAFL found unique file at %s, %d entries' % (unique_path, len(self.afl_list)))
        else:
            gpath = os.path.join(self.afl_dir, 'resim_*', 'queue', 'id:*')
            glist = glob.glob(gpath)
            if len(glist) > 0:
                for path in glist:
                    if 'sync:' not in path:
                        self.afl_list.append(path)
            else:
                if os.path.isdir(self.afl_dir):
                    self.afl_list = [f for f in os.listdir(self.afl_dir) if os.path.isfile(os.path.join(self.afl_dir, f))]

    def getTrackPath(self, index):
        queue_dir = os.path.dirname(self.afl_list[index])
        queue_parent = os.path.dirname(queue_dir)
        trackio_dir = os.path.join(queue_parent, 'trackio')
        try:
            os.makedirs(trackio_dir)
        except:
            pass
        fname = os.path.join(trackio_dir, os.path.basename(self.afl_list[self.index])) 
        return fname

    def doNext(self):
        self.lgr.debug('trackAFL doNext, save previous')
        self.inject_instance.saveJson()
        SIM_run_alone(self.setStopAlone, None)

    def stopHap(self, dumb, one, exception, error_string):
        self.lgr.debug('in stopHap')
        if self.stop_hap is not None:
            self.index = self.index+1
            if self.index < len(self.afl_list):
                SIM_run_alone(self.go, None)
            else:
                print('All files have been processed (have trackio output files)')
                self.checkCrashes()

    def checkCrashes(self):
        for crashed in self.did_exit:
            self.lgr.debug('File resulted in exit: %s' % crashed)
            print('File resulted in exit: %s' % crashed)
        return

    def go(self, dumb=None):
        cpu = self.top.getCPU()
        if self.stop_hap is not None:
            self.top.RES_add_stop_callback(self.stop_hap)
            self.stop_hap = None
            eip = self.top.getEIP(cpu)
            self.lgr.debug('trackAFL go, bout to go to origin.  eip 0x%x cycles 0x%x' % (eip, cpu.cycles))
            self.top.goToOrigin()
            eip = self.top.getEIP(cpu)
            self.lgr.debug('trackAFL go, DID to go to origin.  eip 0x%x cycles 0x%x' % (eip, cpu.cycles))
        eip = self.top.getEIP(cpu)
        got_one=False
        while not got_one and self.index < len(self.afl_list):
            if not os.path.isfile(self.getTrackPath(self.index)):
                got_one = True
            else:
                self.index = self.index+1
        if not got_one:
            print('All files have been processed (have trackio output files)')
            self.checkCrashes()
        else:
            self.lgr.debug('trackAFL eip: 0x%x, cycles 0x%x go file: %s' % (eip, cpu.cycles, self.afl_list[self.index]))
            
            path = self.getTrackPath(self.index)
            if self.inject_instance is None:
                ''' More than one packet will corrupt the origin, so you must set limit_one. '''
                self.inject_instance = self.top.injectIO(self.afl_list[self.index], callback=self.doNext, limit_one=True, no_rop=False, go=False)
                self.inject_instance.setExitCallback(self.reportExit)
                self.inject_instance.setSaveJson(path)
                self.inject_instance.go()
            else:
                self.inject_instance.setDfile(self.afl_list[self.index])
                ''' do not skip to the receive buffer, its cycle had been incremented for obscure reasons '''
                self.inject_instance.setSaveJson(path)
                self.inject_instance.go(no_go_receive=True)

    def setStopAlone(self, dumb):
        if self.stop_hap is None:
            self.lgr.debug('trackAFL setStopAlone')
            self.stop_hap = self.top.RES_delete_stop_hap(self.stopHap,  None)
            SIM_break_simulation('trackafl')

    def reportExit(self):
        print('Process exited -- crash?')
        self.lgr.debug('Process exited -- crash?')
        self.did_exit.append(self.afl_list[self.index])
        self.setStopAlone(None)
