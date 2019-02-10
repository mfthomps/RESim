import os
class IDAFuns():
    class FunInfo():
        def __init__(self, fun):
            self.fun = fun
            self.end = None

    def __init__(self, path, lgr):
        self.funs = {}
        self.lgr = lgr
        flist = []
        self.lgr.debug('IDAFuns for path %s' % path)
        if os.path.isfile(path):
            with open(path) as fh:
                for line in fh:
                    fun_s = line.split()[0].rstrip('L')
                    try: 
                        fun_addr = int(fun_s, 16)
                        flist.append(fun_addr)
                    except:
                        self.lgr.error('could not parse int from %s' % fun_s)
        else:
            self.lgr.debug('IDAFuns no file at %s' % path)
            return
        sflist = sorted(flist)
        prev_f = None
        for f in sflist:
            finfo = self.FunInfo(f)
            if prev_f is not None:
                prev_f.end = f-1
                #self.lgr.debug('add function 0x%x' % prev_f.fun)
                self.funs[prev_f.fun] = prev_f
                
            prev_f = finfo 
 
    def isFun(self, fun):
        if fun in self.funs:
            return True
        else:
            return False

    def inFun(self, ip, fun):
        #self.lgr.debug('is 0x%x in %x ' % (ip, fun))
        if fun in self.funs:
            if ip >= fun and ip <= self.funs[fun].end:
                return True
        else:
            return False 
