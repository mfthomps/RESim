
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
    def __init__(self, hap_cleaner, breakpoints, flist=None):
        self.hap_clean = hap_cleaner
        if breakpoints is not None:
            self.breakpoints = breakpoints
        else:
            self.breakpoints = []
        if flist is not None:
            self.flist = flist
        else:
            self.flist = []

