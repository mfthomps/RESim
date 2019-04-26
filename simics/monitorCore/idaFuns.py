import os
import json
class IDAFuns():

    def __init__(self, path, lgr):
        self.funs = {}
        self.lgr = lgr
        #self.lgr.debug('IDAFuns for path %s' % path)
        if os.path.isfile(path):
            with open(path) as fh:
                jfuns = json.load(fh)
                for sfun in jfuns:
                    fun = int(sfun)
                    self.funs[fun] = jfuns[sfun]

    def getFunPath(self, path):
        fun_path = path+'.funs'
        if not os.path.isfile(fun_path):
            ''' No functions file, check for symbolic links '''
            #self.lgr.debug('is link? %s' % path)
            if os.path.islink(path):
                actual = os.path.join(os.path.dirname(path), os.readlink(path))
                #self.lgr.debug('actual  %s' % actual)
                fun_path = actual+'.funs'
        return fun_path
            
    def add(self, path, offset):

        funfile = self.getFunPath(path)
        if os.path.isfile(funfile):
            with open(funfile) as fh:
                #self.lgr.debug('IDAFuns add for path %s' % path)
                newfuns = json.load(fh) 
                for f in newfuns:
                    fun = int(f)+offset
                    self.funs[fun] = {}
                    self.funs[fun]['start'] = fun
                    self.funs[fun]['end'] = newfuns[f]['end']+offset
                    self.funs[fun]['name'] = newfuns[f]['name']
                    #self.lgr.debug('idaFun add was %s %x %x   now %x %x %x' % (f, newfuns[f]['start'], newfuns[f]['end'], fun, self.funs[fun]['start'], self.funs[fun]['end']))
        else:
            #self.lgr.debug('IDAFuns NOTHING at %s' % funfile)
            pass

 
    def isFun(self, fun):
        if fun in self.funs:
            return True
        else:
            return False

    def inFun(self, ip, fun):
        #self.lgr.debug('is 0x%x in %x ' % (ip, fun))
        if fun in self.funs:
            if ip >= self.funs[fun]['start'] and ip <= self.funs[fun]['end']:
                return True
        else:
            return False 

    def getFun(self, ip):
        for fun in self.funs:
            if ip >= self.funs[fun]['start'] and ip <= self.funs[fun]['end']:
                return fun
            #print('ip 0x%x start 0x%x - 0x%x' % (ip, self.funs[fun]['start'], self.funs[fun]['end']))
        return None
