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
        breakpoints to be deleted
        list of functions to be executed '''
    def __init__(self, hap_cleaner, breakpoints, flist=None, break_addrs = []):
        self.hap_clean = hap_cleaner
        self.break_addrs = break_addrs
        if breakpoints is not None:
            self.breakpoints = breakpoints
        else:
            self.breakpoints = []
        if flist is not None:
            self.flist = flist
        else:
            self.flist = []
    def run(self):
        ''' Process the functions in the flist '''
        if len(self.flist) > 0:
            fun = self.flist.pop(0)
            fun.run(self.flist)

    def getBreaks(self):
        return self.break_addrs
