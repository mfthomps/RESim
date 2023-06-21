import os
import glob
class TargetFS():
    def __init__(self, top, root_prefix, root_subdirs):
        self.top = top
        self.root_prefix = root_prefix
        self.root_subdirs = root_subdirs
        self.lgr = None

    def find(self, name):
        retval = None
        if len(self.root_subdirs) == 0:
            retval = self.findFrom(name, self.root_prefix)
        else:
            for subdir in self.root_subdirs:
                from_dir = os.path.join(self.root_prefix, subdir)
                retval = self.findFrom(name, from_dir)
                if retval is not None:
                    self.lgr.debug('TargetFS find found %s' % retval)
                    break
        return retval

    def findFrom(self, name, from_dir):
        #if self.top.isWindows():
        #    ''' TBD avoid searching forever'''
        #    return None
        self.lgr.debug('TargetFS find from %s look for [%s]' % (from_dir, name))
        for root, dirs, files in os.walk(from_dir):
   
            #self.lgr.debug('TargetFS find files is %s' % str(files))
            if name in files:
                retval = os.path.join(from_dir, root, name)
                abspath = os.path.abspath(retval)
                return abspath
        return None

    def getRootPrefix(self):
        return self.root_prefix
 
    def getFull(self, path, lgr=None):
        retval = None
        self.lgr = lgr
        if self.top.isWindows():
            path = path.replace('\\', '/')
            #if lgr is not None:
            #     lgr.debug('getFull windows, new path is %s' % path)
            
        if path.startswith('./'):
             base = os.path.basename(path)
             fun_file = base+'.funs'
             lgr.debug('is relative, fun_file %s' % fun_file)
             full_fun = self.find(fun_file)
             if full_fun is not None:              
                 retval = os.path.join(os.path.dirname(full_fun), base)
                 #lgr.debug('getFull found file %s' % retval)
             else:
                 retval = self.find(base)
        else:     
            if lgr is not None:
                lgr.debug('getFull look at %s' % path) 
            if path.startswith('/??/C:/'):
                path = path[7:]
                if lgr is not None:
                    lgr.debug('getFull changed to %s' % path) 
            elif path.startswith('/'):
                path = path[1:]
            full = os.path.join(self.root_prefix, path)
            if os.path.islink(full):
                real = os.readlink(full)
                if lgr is not None:
                    lgr.debug('TargetFS link real %s' % real)
                if real.startswith('/'):
                    real = real[1:]
                    retval = os.path.join(self.root_prefix, real)
                else:
                    retval = os.path.join(os.path.dirname(full), real)
            elif not os.path.isfile(full):
                if lgr is not None:
                    lgr.debug('TargetFS getFull no file at %s -- use glob' % full)
                flist = glob.glob(full+'*')
                if len(flist) > 0:
                    retval = flist[0]
                else:
                    if lgr is not None:
                        lgr.debug('TargetFS getFull, no glob at %s' % (full+'*'))
                    ''' try basename '''
                    base = os.path.basename(path)
                    fun_file = base+'.funs'
                    if lgr is not None:
                        lgr.debug('is relative, fun_file %s' % fun_file)
                    full_fun = self.find(fun_file)
                    if full_fun is not None:              
                        retval = os.path.join(os.path.dirname(full_fun), base)
                        #if lgr is not None:
                        #    lgr.debug('getFull found file %s' % retval)
                    else:
                        retval = self.find(base)
                        if lgr is not None:
                            lgr.debug('getFull used find found file %s' % retval)

            else:
                retval = full
        if retval is not None:
            retval = os.path.abspath(retval)
        return retval
