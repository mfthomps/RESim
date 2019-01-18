class SharedSyscall():
    def __init__(self, lgr):
        self.exit_break1 = {}
        self.exit_break2 = {}
        self.pending_call = {}
        self.pending_execve = []
        self.lgr = lgr

    def hasBreak(self, pid):
        if pid in self.exit_break1:
            return True
        else:
            return False
    def rmBreaks(self, pid):
        if pid in self.exit_break1:
            del self.exit_break1[pid]
        if pid in self.exit_break2:
            del self.exit_break2[pid]
        if pid in self.pending_call:
            del self.pending_call[pid]
   
    def getPendingCall(self, pid):
        if pid in self.pending_call:
            return self.pending_call[pid]
        else:
            return None
 
    def addBothBreaks(self, pid, breakpt1, breakpt2, callnum):
        self.addBreak1(pid, breakpt1, callnum)
        self.addBreak2(pid, breakpt2, callnum)

    def addBreak1(self, pid, breakpt, callnum):
        if not pid in self.exit_break1:
            self.exit_break1[pid] = breakpt
            self.pending_call[pid] = callnum
        else:
            self.lgr.error('SharedSyscall exit_break1 already defined for pid %d' % pid)

    def addBreak2(self, pid, breakpt, callnum):
        if not pid in self.exit_break2:
            self.exit_break2[pid] = breakpt
        else:
            self.lgr.error('SharedSyscall exit_break2 already defined for pid %d' % pid)
 
    def getBreak1(self, pid):
        if pid in self.exit_break1:
            return self.exit_break1[pid]
        else:
            self.lgr.error('SharedSyscall exit_break1 has no pid %d' % pid)

    def getBreak2(self, pid):
        if pid in self.exit_break2:
            return self.exit_break2[pid]
        else:
            self.lgr.error('SharedSyscall exit_break2 has no pid %d' % pid)

    def addPendingExecve(self, pid):
        self.pending_execve.append(pid)

    def rmPendingExecve(self, pid):
        self.pending_execve.remove(pid)

    def isPendingExecve(self, pid):
        if pid in self.pending_execve:
            return True
        else:
            return False
