from simics import *
import cli
import sys
import os

class PlayAFL():
    def __init__(self, top, cpu, backstop, coverage, mem_utils, dataWatch, target, lgr):
        self.top = top
        self.backstop = backstop
        self.coverage = coverage
        self.mem_utils = mem_utils
        self.dataWatch = dataWatch
        self.cpu = cpu
        self.lgr = lgr
        afl_output = os.getenv('AFL_OUTPUT')
        if afl_output is None:
            afl_output = os.path.join(os.getenv('HOME'), 'SEED','afl','afl-output')
        self.afl_dir = os.path.join(afl_output, target,'queue')
        self.afl_list = [f for f in os.listdir(self.afl_dir) if os.path.isfile(os.path.join(self.afl_dir, f))]
        self.index = 0 
        self.stop_hap = None
        self.addr = None
        self.backstop_cycles =   100000
        self.pid = self.top.getPID()
        cli.quiet_run_command('disable-reverse-execution')
        cli.quiet_run_command('enable-unsupported-feature internals')
        cli.quiet_run_command('save-snapshot name = origin')
        self.top.removeDebugBreaks(keep_watching=False, keep_coverage=False)
        self.coverage.enableCoverage(self.pid, backstop=self.backstop, backstop_cycles=self.backstop_cycles, afl=False)
        self.coverage.doCoverage(force_default_context=True)

    def go(self):
        if self.stop_hap is None:
            self.stop_hap = SIM_hap_add_callback("Core_Simulation_Stopped", self.stopHap,  None)
        SIM_run_alone(self.goAlone, None)

    def goAlone(self, dumb):
        if self.index < len(self.afl_list):
            cli.quiet_run_command('save-snapshot name = origin')
            full = os.path.join(self.afl_dir, self.afl_list[self.index])
            with open(full) as fh:
                data = bytearray(fh.read())
            self.addr, max_len = self.dataWatch.firstBufferAddress()
            self.mem_utils.writeString(self.cpu, self.addr, data) 
            self.lgr.debug('playAFL goAlone file %s continue' % self.afl_list[self.index])
            self.backstop.setFutureCycleAlone(self.backstop_cycles)
            self.index += 1
            SIM_run_command('c')
        else:
            self.coverage.saveCoverage()
            print('Played %d sessions' % len(self.afl_list))

    def stopHap(self, dumb, one, exception, error_string):
        if self.stop_hap is not None:
            self.lgr.debug('playAFL stopHap')
            SIM_run_alone(self.goAlone, None)
