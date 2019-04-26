#!/usr/bin/python
'''
 * This software was created by United States Government employees
 * and may not be copyrighted.
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
 * ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
'''
import time
import os
import sys
import kazoo
import fnmatch
import socket
import logging
import subprocess
import time
from monitorLibs import szk
from monitorLibs import configMgr
from monitorLibs import utils
'''
Walk a CB hierarchy and use Ida to create its databases
'''
class idaAnalysis():
    def __init__(self, zk, logdir, cb_dir):
        self.zk = zk
        self.logdir = logdir
        self.setLogger()

        if not os.path.exists(cb_dir):
            print 'missing directory: %s' % cb_dir
            self.lgr.error('missing directory: %s' % cb_dir)
            exit(1)
        cbs = os.listdir(cb_dir)
        for cb in cbs:
            print 'look at executables for %s' % cb
            self.lgr.debug('look at executables for %s' % cb)
            a_path = '%s/%s/%s/%s' % (cb_dir, cb, szk.AUTHOR, cb)
            self.doBins(a_path, a_path, cb)
            a_mg_path = '%s/%s/%s/%s' % (cb_dir, cb, szk.AUTHOR, cb+'_MG')
            self.doBins(a_mg_path, a_mg_path, cb)

    def doBins(self, path, dest, cb):
        bins = os.listdir(path)
        for b in bins:
            if b.startswith(cb):
                a_exec = os.path.join(path, b)
                if os.path.isfile(a_exec):
                    #b_path = os.path.join(dest, b)
                    #try:
                    #    os.mkdir(b_path)
                    #except:
                    #    pass 
                    if not os.path.isfile(a_exec+'.idb'):
                        print('would do cb exec %s results to %s' % (a_exec, path))
                        self.lgr.debug('doBins would do cb exec %s results to %s' % (a_exec, path))
                        cmd = '/home/mike/ida-6.8/idaq -T"CGC" -B %s' % a_exec
                        print('os command: %s' % cmd)
                        os.system(cmd)
                        #subprocess.call(['./idaAnalysis.sh', a_exec, path])
                    else:
                        self.lgr.debug('idb already exists')

    def setLogger(self):
        self.lgr = logging.getLogger(__name__)
        self.lgr.setLevel(logging.DEBUG)
        fh = logging.FileHandler(self.logdir+'/ida_analysis.log')
        fh.setLevel(logging.DEBUG)
        frmt = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
        fh.setFormatter(frmt)
        self.lgr.addHandler(fh)
        self.lgr.info('Start of log from idaAnalysis.py')

hostname = socket.gethostname()
cfg = configMgr.configMgr()
zk = szk.szk(hostname+"_idaAnalysis", cfg)
ia = idaAnalysis(zk, cfg.logdir, cfg.cb_dir)
