from simics import *
import cli
import time
class TestSnap():
    def __init__(self, top, coverage, backstop, lgr):
        self.top=top
        self.lgr=lgr
        self.coverage = coverage
        self.backstop = backstop
        self.top.removeDebugBreaks(keep_watching=False, keep_coverage=False)
        #if self.orig_buffer is not None:
        #    self.lgr.debug('restored %d bytes 0x%x context %s' % (len(self.orig_buffer), self.addr, self.cpu.current_context))
        #    self.mem_utils.writeBytes(self.cpu, self.addr, self.orig_buffer) 
        #self.coverage.enableCoverage(self.pid, backstop=self.backstop, backstop_cycles=self.backstop_cycles, 
        #    afl=True, fname=fname, linear=linear, create_dead_zone=self.create_dead_zone, record_hits=False)
        pid = self.top.getPID()
        self.coverage.enableCoverage(pid, backstop=self.backstop, backstop_cycles=900000000, 
                afl=True, fname=None, linear=False, create_dead_zone=False, record_hits=False)
        cli.quiet_run_command('disable-reverse-execution')
        cli.quiet_run_command('enable-unsupported-feature internals')
        cli.quiet_run_command('save-snapshot name = origin')


    def go(self):
        then = time.time()
        iterations = 1000
        cycles = 0x26000
        for i in range(iterations):
            SIM_continue(cycles)
            cli.quiet_run_command('restore-snapshot name=origin')
        now = time.time()
        diff = now - then
        rate = float(iterations/diff)
        print('%d iterations is %d milli-seconds %f.2' % (iterations, diff, rate))
             
