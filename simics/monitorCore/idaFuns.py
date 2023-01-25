import os
import json
class IDAFuns():

    def __init__(self, path, lgr):
        self.funs = {}
        self.lgr = lgr
        self.did_paths = []
        self.lgr.debug('IDAFuns for path %s' % path)
        self.mangle = {}
        if path.endswith('funs'):
            mpath = path[:-4]+'mangle' 
            if os.path.isfile(mpath):
               with open(mpath) as fh:
                   self.mangle = json.load(fh)
                   lgr.debug('Loaded mangle from %s' % mpath)
            else:
                lgr.debug('no mangle file at %s' % mpath)
        if os.path.isfile(path):
            with open(path) as fh:
                jfuns = json.load(fh)
                for sfun in jfuns:
                    fun = int(sfun)
                    fun_rec = jfuns[sfun]
                    fun_name = fun_rec['name']
                    if fun_name.startswith('__imp__'):
                        fun_name = fun_name[7:]
                    if fun_name in self.mangle:
                        #lgr.debug('****************** %s in mangle as %s' % (fun_name, self.mangle[fun_name]))
                        fun_rec['name'] = self.mangle[fun_name]
                        #lgr.debug('function name for 0x%x (%s) changed to %s' % (fun, fun_name, fun_rec['name']))
                    self.funs[fun] = fun_rec
                self.did_paths.append(path[:-5])

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
        if path in self.did_paths:
            return
        else:
            self.did_paths.append(path)
        funfile = self.getFunPath(path)
        if os.path.isfile(funfile):
            with open(funfile) as fh:
                self.lgr.debug('IDAFuns add for path %s offset 0x%x' % (path, offset))
                newfuns = json.load(fh) 
                for f in newfuns:
                    fun = int(f)+offset
                    self.funs[fun] = {}
                    self.funs[fun]['start'] = fun
                    self.funs[fun]['end'] = newfuns[f]['end']+offset
                    self.funs[fun]['name'] = newfuns[f]['name']
                    #self.lgr.debug('idaFun add %s was %s %x %x   now %x %x %x' % (newfuns[f]['name'], f, newfuns[f]['start'], newfuns[f]['end'], fun, self.funs[fun]['start'], self.funs[fun]['end']))
        else:
            self.lgr.debug('IDAFuns NOTHING at %s' % funfile)
            pass

 
    def isFun(self, fun):
        if fun in self.funs:
            return True
        else:
            return False

    def getAddr(self, name):
        for fun in self.funs:
            if self.funs[fun]['name'] == name:
                return self.funs[fun]['start'], self.funs[fun]['end']
        return None, None
 
    def getName(self, fun):
        if fun in self.funs:
            return self.funs[fun]['name']
        else:
            return None

    def inFun(self, ip, fun):
        #self.lgr.debug('is 0x%x in %x ' % (ip, fun))
        if fun in self.funs:
            #print('start 0x%x end 0x%x' % (self.funs[fun]['start'], self.funs[fun]['end']))
            if ip >= self.funs[fun]['start'] and ip <= self.funs[fun]['end']:
                return True
        return False 

    def getFun(self, ip):
        for fun in self.funs:
            #print('ip 0x%x start 0x%x - 0x%x' % (ip, self.funs[fun]['start'], self.funs[fun]['end']))
            if ip >= self.funs[fun]['start'] and ip <= self.funs[fun]['end']:
                return fun
        return None

    def getFunName(self, ip):
        retval = None
        if ip in self.funs:
            retval = self.getName(ip)
        else:
            fun = self.getFun(ip)
            if fun is not None:
                retval = self.getName(fun)
        return retval

    def showFuns(self, search=None):
        for fun in sorted(self.funs):
            if search is not None:
                if search in self.funs[fun]['name']:
                    print('\t%20s \t0x%x\t%x' % (self.funs[fun]['name'], self.funs[fun]['start'], self.funs[fun]['end']))
            else:
                print('\t%20s \t0x%x\t%x' % (self.funs[fun]['name'], self.funs[fun]['start'], self.funs[fun]['end']))
        

    def demangle(self, fun):
        if fun in self.mangle:
            return self.mangle[fun]
        else:
            return fun
