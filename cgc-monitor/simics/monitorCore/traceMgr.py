class TraceMgr():
    def __init__(self, lgr):
        self.trace_fh = None
        self.lgr = lgr

    def write(self, msg):
        if self.trace_fh is not None:
            self.trace_fh.write(msg)

    def close(self):
        if self.trace_fh is not None:
            self.trace_fh.close()
            self.trace_fh = None

    def open(self, fname):
        if self.trace_fh is not None:
            self.lgr.error('TraceMgr asked to open file %s while other still open' % fname)
            self.trace_fh.close()
            
        self.trace_fh = open(fname, 'w') 
