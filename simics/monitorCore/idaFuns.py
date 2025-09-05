import os
import json
import clibFuns
def rmPrefix(fun):
    if fun.startswith('.'):
        fun = fun[1:]
    for pre in clibFuns.mem_prefixes:
        if fun.startswith(pre):
            fun = fun[len(pre):]
    #if fun.startswith('_'):
    #    fun = fun[1:]
    return fun

class IDAFuns():

    def __init__(self, path, lgr, offset=0):
        ''' self.funs primary dict key is the address of the function per initial IDA/ghidra analysis adjusted by the load address & offset '''
        self.funs = {}
        self.lgr = lgr
        self.offset = offset
        self.did_paths = []
        self.have_funs_for = []
        self.lgr.debug('IDAFuns for path %s offset 0x%x' % (path, offset))
        self.mangle = {}
        self.unwind = {}
        if path.endswith('funs'):
            mpath = path[:-4]+'mangle' 
            if os.path.isfile(mpath):
               with open(mpath) as fh:
                   mangle_file = json.load(fh)
                   lgr.debug('Loaded mangle from %s' % mpath)
                   for m in mangle_file:
                       fun = rmPrefix(m)
                       self.mangle[fun] = mangle_file[m]
            else:
                lgr.debug('idaFuns init no mangle file at %s' % mpath)
            upath = path[:-4]+'unwind' 
            if os.path.isfile(upath):
               with open(upath) as fh:
                   self.unwind = json.load(fh)
                   lgr.debug('Loaded unwind from %s' % upath)
            else:
                #lgr.debug('no unwind file at %s' % upath)
                pass
        if os.path.isfile(path):
            with open(path) as fh:
                jfuns = json.load(fh)
                self.lgr.debug('idaFuns read funs from %s' % path)
                for sfun in jfuns:
                    fun_rec = jfuns[sfun]
                    fun_name = fun_rec['name']
                    if fun_name.startswith('__imp__'):
                        fun_name = fun_name[7:]
                    fun_name = rmPrefix(fun_name)
                    adjusted = fun_rec['start'] + offset
                    fun = adjusted
                    if fun_name in self.mangle:
                        #lgr.debug('****************** %s in mangle as %s' % (fun_name, self.mangle[fun_name]))
                        demangled = self.mangle[fun_name]
                        fun_name = rmPrefix(demangled)
                        fun_rec['name'] = fun_name
                        #lgr.debug('demangled function name for 0x%x changed to %s' % (fun, fun_name))
                    fun_rec['start'] = adjusted
                    fun_rec['end'] = fun_rec['end'] + offset
                    ''' index by load address to avoid collisions '''
                    self.funs[fun] = fun_rec
                self.did_paths.append(path[:-5])
        self.lgr.debug('idaFuns loaded %d funs' % len(self.funs))

    def getFunPath(self, path):
        if path is None:
            return None
        if path.endswith('.funs'):
            fun_path = path
        else:
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
        if path is None or path in self.did_paths:
            return
        else:
            self.did_paths.append(path)
        funfile = self.getFunPath(path)
        self.lgr.debug('idaFuns add path %s funfile %s' % (path, funfile))

        add_mangle = []
        mpath = funfile[:-4]+'mangle' 
        if os.path.isfile(mpath):
           with open(mpath) as fh:
               add_mangle = json.load(fh)
               for m in add_mangle:
                   fun = rmPrefix(m)
                   if fun not in self.mangle:
                       self.mangle[fun] = add_mangle[m]
               self.lgr.debug('Loaded additional mangle from %s' % mpath)
        else:
            self.lgr.debug('idaFuns add no mangle file at %s' % mpath)

        if os.path.isfile(funfile):
            with open(funfile) as fh:
                fname = os.path.basename(funfile)[:-5]
                self.have_funs_for.append(fname)
                self.lgr.debug('IDAFuns add for path %s offset 0x%x fname %s' % (path, offset, fname))
                newfuns = json.load(fh) 
                for f in newfuns:
                    fun_int = int(f)
                    fun = fun_int + offset
                    if fun in self.funs:
                        self.lgr.error('idaFuns collision on function 0x%x fun_int 0x%x offset 0x%x file: %s' % (fun, fun_int, offset, funfile))
                    self.funs[fun] = {}
                    self.funs[fun]['start'] = fun
                    self.funs[fun]['end'] = newfuns[f]['end']+offset
                    fun_name = newfuns[f]['name']
                    fun_name = rmPrefix(fun_name)
                    self.funs[fun]['name'] = fun_name
                    if 'adjust_sp' in newfuns[f]:
                        self.funs[fun]['adjust_sp'] = newfuns[f]['adjust_sp']
                    #if fun_name == 'memcpy':
                    #    self.lgr.debug('idaFuns memcpy fun 0x%x fun_int 0x%x offset 0x%x' % (fun, fun_int, offset))
                    fun_name = rmPrefix(fun_name)
                    if fun_name in add_mangle:
                        #self.lgr.debug('****************** %s in add mangle as %s' % (fun_name, add_mangle[fun_name]))
                        demangled = add_mangle[fun_name]
                        fun_name = rmPrefix(demangled)
                        self.funs[fun]['name'] = fun_name
                    elif fun_name.startswith('_ZNK'):
                        self.lgr.debug('#################### %s not in mangle? ' % fun_name)
                   
                    #self.lgr.debug('idaFun add %s was %s %x %x   now %x %x %x' % (newfuns[f]['name'], f, newfuns[f]['start'], newfuns[f]['end'], fun, self.funs[fun]['start'], self.funs[fun]['end']))

        else:
            self.lgr.debug('IDAFuns NOTHING at %s' % funfile)
            pass

 
    def isFun(self, fun):
        ''' The given fun is the rebased value '''
        retval = False
        if fun is not None:
            if fun in self.funs:
                retval = True
        else:
            self.lgr.debug('idaFuns isFun called with fun of None')
        return retval

    def getAddr(self, name):
        ''' return the start and end of a function (loaded) given its name '''
        for fun in self.funs:
            if self.funs[fun]['name'] == name:
                return self.funs[fun]['start'], self.funs[fun]['end']
        return None, None
 
    def getName(self, fun):
        ''' Given a function address (loaded), return the name '''
        retval = None
        if fun is not None:
            if fun in self.funs:
                retval = self.funs[fun]['name']
        return retval

    def inFun(self, ip, fun):
        ''' Is the given IP within the given function? '''
        if fun is not None:
            #self.lgr.debug('is 0x%x in %x ' % (ip, fun))
            if fun in self.funs:
                #print('start 0x%x end 0x%x' % (self.funs[fun]['start'], self.funs[fun]['end']))
                if ip >= self.funs[fun]['start'] and ip <= self.funs[fun]['end']:
                    return True
            else:
                self.lgr.debug('idaFuns inFun given fun 0x%x is not a function' % fun)
        return False 

    def getFun(self, ip):
        ''' Returns the loaded function address of the fuction containing a given ip '''
        if ip is not None:
            for fun in self.funs:
                #print('ip 0x%x start 0x%x - 0x%x' % (ip, self.funs[fun]['start'], self.funs[fun]['end']))
                if ip >= self.funs[fun]['start'] and ip <= self.funs[fun]['end']:
                    return fun
        else:
            self.lgr.error('idaFuns getFun called with ip of None')
        return None

    def getFunName(self, ip):
        ''' Return the function name of the function containing a given IP (loaded) '''
        retval = None
        if ip is not None:
            if ip in self.funs:
                retval = self.funs[ip]['name']
            else:
                fun = self.getFun(ip)
                if fun is not None:
                    retval = self.funs[fun]['name']
        return retval

    def showFuns(self, search=None):
        for fun in sorted(self.funs):
            if search is not None:
                if search in self.funs[fun]['name']:
                    print('\t%20s \t0x%x\t%x' % (self.funs[fun]['name'], self.funs[fun]['start'], self.funs[fun]['end']))
            else:
                print('\t%20s \t0x%x\t%x' % (self.funs[fun]['name'], self.funs[fun]['start'], self.funs[fun]['end']))


    def demangle(self, fun):
        ''' Return the demangled function name based on IDA analysis. '''
        retval = fun
        if fun is not None:
            if fun in self.mangle:
                retval = self.mangle[fun]
                
            elif len(fun) > 4:
                #if '_traits' in fun:
                #    ''' TBD what level of matching matters?'''
                #    fun = fun.split('_traits')[0]
                #    fun = rmPrefix(fun)
                #    #self.lgr.debug('demangle look for fun %s' % fun)
                for mf in self.mangle:
                    if mf.startswith(fun) or fun.startswith(mf):
                        retval = self.mangle[mf]
                        #self.lgr.debug('demangle got match %s' % retval)
                        break
                
        return retval

    def showMangle(self, search=None):
        with open('/tmp/mangle.txt', 'w') as fh:
            for fun in self.mangle:
                print('mangle %s to %s' % (fun, self.mangle[fun]))
                fh.write('mangle %s to %s\n' % (fun, self.mangle[fun]))

    def isUnwind(self, ip):
        retval = False
        if ip in self.funs:
            fun = ip
        else:
            fun = self.getFun(ip)
        if fun in self.unwind:
            retval = True
        return retval

    def showFunEntries(self, fun_name):
        for fun in self.funs:
            if self.funs[fun]['name'] == fun_name:
                size = self.funs[fun]['end'] - self.funs[fun]['start'] 
                print('fun entry 0x%x size %d' % (fun, size))

    def getFunEntry(self, fun_name):
        ''' get the loaded address of the entry of a given function name, with preference to the largest function '''
        big = 0
        retval = None
        for fun in self.funs:
            if self.funs[fun]['name'] == fun_name:
                size = self.funs[fun]['end'] - self.funs[fun]['start'] 
                if size > big:
                    big = size
                    retval = self.funs[fun]['start']
        return retval
 
    def getFunLoaded(self, fun_addr):
        ''' get the loaded function entry for a given analysis function address '''
        retval = None
        if fun_addr in self.funs:
            retval = self.funs[fun_addr]['start']
        return retval

    def getFunWithin(self, fun_name, start, end):
        big = 0
        retval = None
        self.lgr.debug('idaFuns getFunWithin look for %s within start 0x%x end 0x%x' % (fun_name, start, end))
        for fun in self.funs:
            if self.funs[fun]['name'] == fun_name:
                self.lgr.debug('idaFuns getFunWithin found match for %s, fun start 0x%x  end 0x%x' % (fun_name, self.funs[fun]['start'], self.funs[fun]['end']))
                if self.funs[fun]['start'] >= start and self.funs[fun]['end'] <= end:
                    size = self.funs[fun]['end'] - self.funs[fun]['start'] 
                    self.lgr.debug('idaFuns getFunWithin %s matches, and within, size 0x%x' % (fun_name, size))
                    if size > big:
                        big = size
                        retval = self.funs[fun]['start']
        return retval
           
    def getFuns(self):
        return self.funs 

    def stackAdjust(self, fun_name):
        retval = 0
        for fun in self.funs:
            if self.funs[fun]['name'] == fun_name:
                #self.lgr.debug('idaFuns stackAdjust fun 0x%x matched %s' % (fun, fun_name))
                if 'adjust_sp' in self.funs[fun]:
                    retval = self.funs[fun]['adjust_sp']
                    if retval > 0:
                        break
        return retval

    def haveFuns(self, fname):
        if fname in self.have_funs_for:
            return True
        else:
            return False
