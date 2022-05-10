import os
import time
import shutil
import subprocess
import shlex
#import threading
from simics import *
import cli
import stopFunction
import aflPath

class ReplayAFL():
    def __init__(self, top, target, index, targetFD, lgr, instance = None, tcp=False, cover=False, trace=False):
        self.lgr = lgr
        self.top = top
        self.afl_dir = aflPath.getAFLOutput()
        self.ip = os.getenv('TARGET_IP')
        self.port = os.getenv('TARGET_PORT')
        if self.ip is None or self.port is None: 
            print('Missing TARGET_IP or TARGET_PORT in the ini file.')
            self.lgr.warning('Missing TARGET_IP or TARGET_PORT in the ini file.')
            return
        self.header = os.getenv('AFL_UDP_HEADER')
        self.resim_dir = os.getenv('RESIM')
        self.target = target
        self.index = index
        self.instance = instance
        self.tcp = tcp
        self.targetFD = targetFD
        self.cover = cover
        self.trace = trace
        ''' child process that manages driver '''
        self.send_driver = None
        here= os.path.dirname(os.path.realpath(__file__))
        if not tcp:
            self.client_path = os.path.join(here, 'clientudpMult')
        else:
            self.client_path = os.path.join(here, 'clientTCP')
        self.lgr.debug('replayAFL call debugSnap')
        self.top.debugSnap(final_fun = self.go)

    def startAlone(self, driver):
        driver.start()

    def trackAlone(self, fd):
        if self.cover:
            self.top.enableCoverage()
        self.top.trackIO(fd, reset=True, callback=self.killDriver)

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
        afl_file = aflPath.getAFLPath(self.target, self.index, self.instance)
        if afl_file is not None: 
            retval = True
            print('Replaying %s' % afl_file)
            
        if retval:
            #driver = threading.Thread(target=feedDriver, args=(self.ip, self.port, self.header, self.lgr, ))
            #self.lgr.debug('start thread')
            #SIM_run_alone(self.startAlone, driver)
            shutil.copyfile(afl_file, '/tmp/sendudp')
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
            #result=os.system(cmd)
            self.send_driver = subprocess.Popen(shlex.split(cmd), stdin=subprocess.PIPE, stdout=subprocess.PIPE,stderr=subprocess.PIPE)
            self.lgr.debug('ReplayAFL tmpdriver cmd: %s ' % (cmd))
            self.lgr.debug('replay for fd %d' % self.targetFD)
            if self.trace:
                self.top.noReverse()
                self.top.traceAll()
                SIM_run_command('c') 
            else:
                if not self.tcp: 
                    if self.cover:
                        self.top.enableCoverage()
                    self.top.trackIO(self.targetFD, reset=True, callback=self.killDriver)
                else:
                    ''' Run to accept to get the new FD and then do trackIO from the doTrack callback'''
                    self.top.noReverse()
                    self.lgr.debug('replayAFL run to accept')
                    f1 = stopFunction.StopFunction(self.doTrack, [], nest=False)
                    flist = [f1]
                    self.top.runToAccept(self.targetFD, flist=flist)

        return retval

    def killDriver(self):
        if self.send_driver is not None:
            self.send_driver.kill()
            self.lgr.debug('replayAFL killed driver')
            self.send_driver = None
        if self.cover:
            self.top.saveCoverage()
