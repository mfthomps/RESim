from simics import *
import cli
import sys
import os
import glob
import re
import decode
import decodeArm
import decodePPC32
import pageUtils
import aflPath

class ReportExit():
    def __init__(self, top, cpu, pid, mem_utils, fname, max_reports, one_done, report_index, lgr, report_dir=None):
        self.top = top
        self.cpu = cpu
        self.pid = pid
        self.lgr = lgr
        self.report_index = report_index
        self.one_done = one_done
        self.mem_utils = mem_utils
        self.flist = []
        self.fname = fname
        self.index = 0
        if os.path.isfile(fname):
            self.flist.append(fname)
        else:
            self.flist = aflPath.getTargetExits(fname)
        if report_dir is None:
            self.report_dir = '/tmp/exit_report'
        else:
            self.report_dir = report_dir
        try:
            os.makedirs(self.report_dir)
        except:
            pass
        self.exit_report = None
        self.report_path = None
        if self.cpu.architecture.startswith('arm'):
            self.decode = decodeArm
        elif self.cpu.architecture == 'ppc32':
            self.decode = decodePPC32
        else:
            self.decode = decode

    def go(self):
         if self.index < len(self.flist):
            if self.report_index is None:
                report_file = 'exit_report_%05d' % self.index
            else:
                report_file = 'exit_report_%05d' % self.report_index
            self.report_path = os.path.join(self.report_dir, report_file)
            print('Creating exit report at %s' % self.report_path)
            self.lgr.debug('Creating exit report at %s' % self.report_path)
            self.exit_report = open(self.report_path, 'w')
      
            SIM_run_alone(self.goAlone, None)
         else:
            self.lgr.debug('index %d exceeds number of exits in flist %d' % (self.index, len(self.flist)))
            if self.one_done:
                self.top.quit()

    def goAlone(self, dumb):
        self.top.setCommandCallback(self.doneForward)

        self.exit_report.write("Exit report for %s\n" % self.flist[self.index])
        self.top.playAFL(self.fname, trace_all=True)

    def doneForward(self):
        self.lgr.debug('reportExit doneForward')
