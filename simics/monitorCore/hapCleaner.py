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
    def __init__(self, hap_cleaner, breakpoints=[], flist=None, break_addrs = [], tid=None, prelude=None, wrong_tid_action=None):
        self.hap_clean = hap_cleaner
        self.break_addrs = break_addrs
        self.exit_addr = None
        self.tid = tid
        self.prelude = prelude
        self.wrong_tid_action = wrong_tid_action
        if breakpoints is not None:
            self.breakpoints = breakpoints
        else:
            self.breakpoints = []
        if flist is not None:
            self.flist = flist
        else:
            self.flist = []

    def run(self, wrong_tid=False, cb_param=None):
        ''' Process the functions in the flist, these are the stopFunction class'''
        retval = True
        if len(self.flist) > 0:
            fun = self.flist.pop(0)
            #print('stop action %s wrong tid %r  match %r' % (str(fun.fun), wrong_tid, fun.match_tid))
            if fun.getFun() is None:
                print('StopAction has function is None')
                retval = False
            else:
                if not (wrong_tid and fun.match_tid):
                    fun.run(self.flist, wrong_tid=wrong_tid, cb_param=cb_param)
        return retval

    def getBreaks(self):
        return self.break_addrs

    def setExitAddr(self, exit_addr):
        self.exit_addr = exit_addr

    def getExitAddr(self):
        return self.exit_addr

    def getFlist(self):
        return self.flist

    def addFun(self, fun):
        self.flist.append(fun)

    def rmFun(self, in_fun):
        got_one = None
        for fun in self.flist:
            if fun.getFun() == in_fun:
               got_one = fun
               break
        if got_one is not None:
            self.flist.remove(fun) 

    def listFuns(self):
        retval = ''
        for f in self.flist:
            retval = retval + str(f.getFun()) + ' '
        return retval
