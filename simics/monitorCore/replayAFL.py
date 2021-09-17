import glob
import os
import time
import shutil
#import threading
from simics import *
import stopFunction

class ReplayAFL():
    def __init__(self, top, target, index, targetFD, lgr, instance = None, tcp=False, cover=False):
        self.lgr = lgr
        self.top = top
        self.afl_dir = os.getenv('AFL_OUTPUT')
        if self.afl_dir is None:
            self.afl_dir = os.path.join(os.getenv('AFL_DATA'), 'output')
        self.ip = os.getenv('TARGET_IP')
        self.port = os.getenv('TARGET_PORT')
        if self.ip is None or self.port is None: 
            print('Missing TARGET_IP or TARGET_PORT in the ini file.')
            return
        self.header = os.getenv('AFL_UDP_HEADER')
        self.resim_dir = os.getenv('RESIM')
        self.target = target
        self.index = index
        self.instance = instance
        self.tcp = tcp
        self.targetFD = targetFD
        self.cover = cover
        here= os.path.dirname(os.path.realpath(__file__))
        if not tcp:
            self.client_path = os.path.join(here, 'clientudpMult')
        else:
            self.client_path = os.path.join(here, 'clientTCP')
        self.top.debugSnap(final_fun = self.go)

    def startAlone(self, driver):
        driver.start()

    def trackAlone(self, fd):
        if self.cover:
            self.top.enableCoverage()
        self.top.trackIO(fd, reset=True)

    def doTrack(self):
        ''' Invoked as a callback when the accept call returns '''
        ida_msg = self.top.getIdaMessage()
        ''' get new FD form ida message '''
        fd=ida_msg.split('new_fd:')[1].split()[0].strip()
        fd = int(fd)
        self.top.allowReverse()
        SIM_run_alone(self.trackAlone, fd)

    def go(self):
        self.lgr.debug('replayAFL go')
        retval = False
        if self.instance is None:
            glob_mask = '%s/%s/queue/id:*0%s,src*' % (self.afl_dir, self.target, self.index)
            glist = glob.glob(glob_mask)
            if len(glist) == 0:
                glob_mask = '%s/%s/queue/id:*%s,orig*' % (self.afl_dir, self.target, self.index)
                glist = glob.glob(glob_mask)
        else:
            resim_instance = 'resim_%d' % self.instance
            glob_mask = '%s/%s/%s/queue/id:*0%s,src*' % (self.afl_dir, self.target, resim_instance, self.index)
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
            dumb, forwarding = cli.quiet_run_command('list-port-forwarding-setup')
            ssh_port = None
            for line in forwarding.splitlines():
                if line.strip().endswith(':22'):
                    ssh_port = line.split()[3] 
                    break
            if ssh_port is None:
                self.lgr.error('No forwarding port found for ssh port 21')
                return
            script_file = os.path.join(self.resim_dir, 'simics', 'monitorCore', 'sendDriver.sh')
            cmd = '%s %s %s %s %s %s &' % (script_file, ssh_port, self.client_path, self.ip, self.port, self.header)
            result=os.system(cmd)
            self.lgr.debug('ReplayAFL tmpdriver cmd: %s result %s' % (cmd, result))
            self.lgr.debug('call track for fd %d' % self.targetFD)
            if not self.tcp: 
                if self.cover:
                    self.top.enableCoverage()
                self.top.trackIO(self.targetFD, reset=True)
            else:
                ''' Run to accept to get the new FD and then do trackIO from the doTrack callback'''
                self.top.noReverse()
                self.lgr.debug('replayAFL run to accept')
                f1 = stopFunction.StopFunction(self.doTrack, [], nest=False)
                flist = [f1]
                self.top.runToAccept(self.targetFD, flist=flist)

        return retval


