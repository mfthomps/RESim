import cli
class TraceMgr():
    def __init__(self, lgr):
        self.trace_fh = None
        self.lgr = lgr
        self.cpu = None

    def write(self, msg):
        if self.trace_fh is not None:
            cycle = '%010x--' % self.cpu.cycles
            self.trace_fh.write(cycle+msg)

    def close(self):
        if self.trace_fh is not None:
            self.trace_fh.close()
            self.trace_fh = None

    def flush(self):
        if self.trace_fh is not None:
            self.trace_fh.flush()

    def open(self, fname, cpu):
        if self.trace_fh is not None:
            self.lgr.error('TraceMgr asked to open file %s while other still open' % fname)
            self.trace_fh.close()
            
        self.trace_fh = open(fname, 'w') 
        self.cpu = cpu
        time, ret = cli.quiet_run_command('ptime -t')
        msg = 'Trace start time: %s\n' % time
        self.write(msg)
        cmd = '%s.info' % cpu.name
        #print('cmd is %s' % cmd)
        info, ret = cli.quiet_run_command(cmd)
        for line in ret.splitlines():
            if 'frequency' in line:
                self.write(line.strip()+'\n') 
