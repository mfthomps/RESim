import os
import glob
import re
import fnmatch
'''
work around case insensitive file system.
Assumes root_prefix and root_subdirs have proper case.
All else is unknown.
'''
def findPattern(path: str, glob_pat: str, ignore_case: bool = False):
    rule = re.compile(fnmatch.translate(glob_pat), re.IGNORECASE) if ignore_case \
            else re.compile(fnmatch.translate(glob_pat))
    return [n for n in os.listdir(path) if rule.match(n)]

def getfileInsensitive(path, root_prefix, lgr):
    got_it = False
    retval = root_prefix
    cur_dir = root_prefix
    if '/' in path:
        parts = path.split('/')
        for p in parts[:-1]:
            lgr.debug('getfileInsensitve part %s cur_dir %s' % (p, cur_dir))
            dlist = [ name for name in os.listdir(cur_dir) if os.path.isdir(os.path.join(cur_dir, name)) ]

            for d in dlist:
                if d.upper() == p.upper():
                    retval = os.path.join(retval, d)
                    cur_dir = os.path.join(cur_dir, d)
                    break
        p = parts[-1]
        lgr.debug('getfileInsensitve cur_dir %s last part %s' % (cur_dir, p))
        flist = os.listdir(cur_dir)
        for f in flist:
            if f.upper() == p.upper():
                retval = os.path.join(retval, f) 
                got_it = True
                break
    else:
        pass
    if not got_it:
        retval = None
    return retval
    

class TargetFS():
    def __init__(self, top, root_prefix, root_subdirs):
        self.top = top
        self.root_prefix = root_prefix
        self.root_subdirs = root_subdirs
        self.lgr = None


    def getRootPrefix(self):
        return self.root_prefix

 
    def getFull(self, path, lgr=None):
        retval = None
        self.lgr = lgr
        if self.top.isWindows():
            path = path.replace('\\', '/')
            if lgr is not None:
                 lgr.debug('getFull windows, new path is %s' % path)
            
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
            full = os.path.join(self.root_prefix, path)
            self.lgr.debug('winTargetFS root_prefix %s path %s full %s' % (self.root_prefix, path, full))
            full_insensitive = getfileInsensitive(path, self.root_prefix, lgr)
            self.lgr.debug('full_insenstive is %s' % full_insensitive)
            if full_insensitive is None or not os.path.isfile(full_insensitive):
                if lgr is not None:
                    lgr.debug('TargetFS getFull not relative no file at %s -- use glob' % full)
                pattern = path
                if self.root_subdirs is None or len(self.root_subdirs) == 0:
                    flist = findPattern(self.root_prefix, pattern, ignore_case=True)
                    if len(flist) > 0:
                        retval = os.path.join(self.root_prefix, flist[0])
                else:
                    for subdir in self.root_subdirs:
                        subpath = os.path.join(self.root_prefix, subdir)
                        self.lgr.debug('TargetFS getFull subpath %s  pattern %s' % (subpath, pattern))
                        flist = findPattern(subpath, pattern)
                        if len(flist) > 0:
                            retval = os.path.join(subpath, flist[0])
                            break 
                for f in flist:
                    self.lgr.debug('targetFS getFull got %s' % f)
            else:
                retval = full
        if retval is not None:
            retval = os.path.abspath(retval)
        return retval
