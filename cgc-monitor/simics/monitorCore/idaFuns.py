import os
import json
class IDAFuns():
    class FunInfo():
        def __init__(self, fun):
            self.fun = fun
            self.end = None

    def __init__(self, path, lgr):
        self.funs = {}
        self.lgr = lgr
        self.lgr.debug('IDAFuns for path %s' % path)
        if os.path.isfile(path):
            with open(path) as fh:
                self.funs = json.load(fh)
 
    def isFun(self, fun_in):
        fun = str(fun_in) 
        if fun in self.funs:
            return True
        else:
            return False

    def inFun(self, ip, fun_in):
        #self.lgr.debug('is 0x%x in %x ' % (ip, fun))
        fun = str(fun_in) 
        if fun in self.funs:
            if ip >= self.funs[fun]['start'] and ip <= self.funs[fun]['end']:
                return True
        else:
            return False 
