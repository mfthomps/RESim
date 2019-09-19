'''
Structures for cleaning up stop haps used in reverse execution
'''
class HapCleaner():
    hlist = None 
    def __init__(self, cpu):
        self.hlist = []
        self.cpu = cpu

    class HapType():
        def __init__(self, htype, hap):
            self.htype = htype
            self.hap = hap

    def add(self, htype, hap):
        ht = self.HapType(htype, hap)
        self.hlist.append(ht)

class StopAction():
    ''' hap_clearer is a list of haps to delete
        breakpoints is a list to be deleted
        flist is list of functions to be executed of type stopFunction'''
    def __init__(self, hap_cleaner, breakpoints, flist=None, break_addrs = [], pid=None, prelude=None, wrong_pid_action=None):
        self.hap_clean = hap_cleaner
        self.break_addrs = break_addrs
        self.exit_addr = None
        self.pid = pid
        self.prelude = prelude
        self.wrong_pid_action = wrong_pid_action
        if breakpoints is not None:
            self.breakpoints = breakpoints
        else:
            self.breakpoints = []
        if flist is not None:
            self.flist = flist
        else:
            self.flist = []

    def run(self, wrong_pid=False):
        ''' Process the functions in the flist '''
        if len(self.flist) > 0:
            fun = self.flist.pop(0)
            print('stop action %s wrong pid %r  match %r' % (str(fun.fun), wrong_pid, fun.match_pid))
            if not (wrong_pid and fun.match_pid):
                fun.run(self.flist, wrong_pid=wrong_pid)

    def getBreaks(self):
        return self.break_addrs

    def setExitAddr(self, exit_addr):
        self.exit_addr = exit_addr

    def getExitAddr(self):
        return self.exit_addr

    def addFun(self, fun):
        self.flist.append(fun)

    def listFuns(self):
        retval = ''
        for f in self.flist:
            retval = retval + str(f.getFun()) + ' '
        return retval
