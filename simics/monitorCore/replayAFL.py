import glob
import os
import time
import shutil
#import threading
from simics import *

class ReplayAFL():
    def __init__(self, top, target, index, targetFD, lgr):
        self.lgr = lgr
        self.top = top
        self.afl_dir = os.getenv('AFL_OUTPUT')
        self.ip = os.getenv('TARGET_IP')
        self.port = os.getenv('TARGET_PORT')
        self.header = os.getenv('AFL_UDP_HEADER')
        self.resim_dir = os.getenv('RESIM')
        self.target = target
        self.index = index
        self.targetFD = targetFD
        here= os.path.dirname(os.path.realpath(__file__))
        self.client_path = os.path.join(here, 'clientudpMult')
        self.top.debugSnap(final_fun = self.go)

    def startAlone(self, driver):
        driver.start()

    def go(self):
        retval = False
        glob_mask = '%s/%s/queue/id:*%s,src*' % (self.afl_dir, self.target, self.index)
        glist = glob.glob(glob_mask)
        if len(glist) == 0:
            glob_mask = '%s/%s/queue/id:*%s,orig*' % (self.afl_dir, self.target, self.index)
            glist = glob.glob(glob_mask)

        if len(glist) == 0:
            self.lgr.error('No files found looking for %s %s %s' % (self.target, self.index, glob_mask))
        elif len(glist) == 1:
            retval = True
            print('tracking %s' % glist[0])
        else:
            self.lgr.error('Too many matches, try adding leading zeros?')
        if retval:
            #driver = threading.Thread(target=feedDriver, args=(self.ip, self.port, self.header, self.lgr, ))
            #self.lgr.debug('start thread')
            #SIM_run_alone(self.startAlone, driver)
            shutil.copyfile(glist[0], '/tmp/sendudp')
            script_file = os.path.join(self.resim_dir, 'simics', 'monitorCore', 'sendDriver.sh')
            cmd = '%s %s %s %s %s &' % (script_file, self.client_path, self.ip, self.port, self.header)
            result=os.system(cmd)
            self.lgr.debug('ReplayAFL tmpdriver cmd: %s result %s' % (cmd, result))
            self.lgr.debug('call track for fd %d' % self.targetFD)
            self.top.trackIO(self.targetFD, reset=True)

        return retval

        

