import glob
import os
import time
import shutil
#import threading
from simics import *
here= os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
client_path = os.path.join(here, 'workspace','clientudpMult')
def feedDriver(ip, port, header, lgr):
    lgr.debug('feedDriver, enter loop')
    result = 1
    cmd = 'scp -P 4022 /tmp/sendudp localhost:/tmp/sendudp'
    while result != 0:
        lgr.debug('do cmd: %s' % cmd)
        result = os.system(cmd)
        lgr.debug('back from command')
        if result != 0:
            lgr.debug('driver not responding')
            time.sleep(1)
    lgr.debug('out of feedDriver loop') 
    cmd = 'scp -P 4022 %s localhost:/tmp/' % client_path
    result = os.system(cmd)
    cmd = 'ssh -p 4022 mike@localhost chmod a+x /tmp/clientudpMult'
    result = os.system(cmd)
    cmd = 'ssh -p 4022 mike@localhost /tmp/clientudpMult %s %d' % (ip, port)
    result = os.system(cmd)

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
            cmd = '%s %s %s %s &' % (script_file, self.ip, self.port, self.header)
            result=os.system(cmd)
            self.lgr.debug('ReplayAFL tmpdriver cmd: %s result %s' % (cmd, result))
            self.lgr.debug('call track for fd %d' % self.targetFD)
            self.top.trackIO(self.targetFD, reset=True)

        return retval

        

