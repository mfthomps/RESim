import os
import glob
class TargetFS():
    def __init__(self, top, root_prefix, root_subdirs, lgr=None):
        self.top = top
        self.root_prefix = root_prefix
        if root_subdirs is None:
            self.root_subdirs = []
        else:
            self.root_subdirs = root_subdirs
       
        self.lgr = lgr
        self.file_cache = {}

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
        # use file searching via os.walk to find an executable with the given name.
        # avoid files in etc.  TBD warn if multiple finds?
        self.lgr.debug('TargetFS find from %s look for [%s]' % (from_dir, name))
        for root, dirs, files in os.walk(from_dir):
   
            #self.lgr.debug('TargetFS find files is %s' % str(files))
            #TBD poor coverage of what might actually occur.  Need to weed out scripts some other way
            if '/etc/' in root or '/lib/' in root or '/sh/' in root or root.endswith('/sh'):
                continue 
            if name in files:
                self.lgr.debug('TargetFS findFrom found %s root %s name %s' % (name, root, name))
                retval = os.path.join(from_dir, root, name)
                abspath = os.path.abspath(retval)
                return abspath
        return None

    def getRootPrefix(self):
        return self.root_prefix
 
    def getFull(self, path, lgr=None):
        retval = None
        self.lgr = lgr
        if path is None:
            return None
        if self.top is not None and self.top.isWindows():
            path = path.replace('\\', '/')
            #if lgr is not None:
            #     lgr.debug('getFull windows, new path is %s' % path)
            
        if path.startswith('./'):
             base = os.path.basename(path)
             #fun_file = base+'.funs'
             #lgr.debug('TargetFS getFull is relative, fun_file %s' % fun_file)
             #full_fun = self.find(fun_file)
             #if full_fun is not None:              
             #    retval = os.path.join(os.path.dirname(full_fun), base)
             #    #lgr.debug('getFull found file %s' % retval)
             #else:
             #    retval = self.find(base)
             retval = self.find(base)
        else:     
            if lgr is not None:
                lgr.debug('getFull look at %s' % path) 
            if path.startswith('/??/C:/'):
                path = path[7:]
                if lgr is not None:
                    lgr.debug('TargetFS getFull not relative changed to %s' % path) 
            elif path.startswith('/'):
                path = path[1:]
            elif '/' not in path and path in self.file_cache:
                return self.file_cache[path] 

            if self.root_prefix is None or self.root_prefix.lower() == 'none':
                lgr.debug('TargetFS getFull no root prefix, maybe just the driver')
                return None
            full = os.path.join(self.root_prefix, path)
            if lgr is not None:
                lgr.debug('TargetFS full is %s' % full)
            if os.path.islink(full):
                real = os.readlink(full)
                if lgr is not None:
                    lgr.debug('TargetFS not relative link real %s' % real)
                if real.startswith('/'):
                    real = real[1:]
                    retval = os.path.join(self.root_prefix, real)
                elif real.startswith('../'):
                    while real.startswith('../'):
                        real = real[3:]
                    retval = os.path.join(self.root_prefix, real)
                else:
                    retval = os.path.join(os.path.dirname(full), real)
            elif not os.path.isfile(full):
                if lgr is not None:
                    lgr.debug('TargetFS getFull not relative no file at %s -- use glob.  path is %s' % (full, path))
                flist = glob.glob(full+'*')
                if len(flist) > 0:
                    retval = flist[0]
                elif not '/' in path:
                    # TBD, avoid finding a program that would fail execve
                    if lgr is not None:
                        lgr.debug('TargetFS getFull, not relative no glob at %s' % (full+'*'))
                    ''' try basename '''
                    retval = self.find(path)
                    base = os.path.basename(retval)
                    if path == base and retval is not None and path not in self.file_cache:
                        self.file_cache[path] = retval
                    if lgr is not None:
                         lgr.debug('getFull used find found file %s' % retval)
                else:
                    self.lgr.debug('TargetFS, did not find program %s' % full)

            else:
                retval = full
        if retval is not None:
            retval = os.path.abspath(retval)
        return retval
