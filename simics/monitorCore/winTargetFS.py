import os
import glob
import re
import fnmatch
import resimUtils
'''
work around case insensitive file system.
Assumes root_prefix and root_subdirs have proper case.
All else is unknown.
'''
def findPattern(path: str, glob_pat: str, ignore_case: bool = False, lgr=None):
    #lgr.debug('findPatter glob_pat is %s' % glob_pat) 
    rule = re.compile(fnmatch.translate(glob_pat), re.IGNORECASE) if ignore_case \
            else re.compile(fnmatch.translate(glob_pat))
    #for n in os.listdir(path):
    #    lgr.debug('n is %s' % n)
    #    if rule.match(n):
    #        lgr.debug('matched')
    #    else:
    #        lgr.debug('failed matched')
          
    return [n for n in os.listdir(path) if rule.match(n)]


class TargetFS():
    def __init__(self, top, root_prefix, root_subdirs):
        self.top = top
        self.root_prefix = root_prefix
        self.root_subdirs = root_subdirs
        self.cache = {}
        self.lgr = None


    def getRootPrefix(self):
        return self.root_prefix

 
    def getFull(self, path, lgr=None):
        retval = None
        self.lgr = lgr
        path = path.replace('\\', '/')
        if lgr is not None:
             lgr.debug('getFull windows, new path is %s' % path)
        if path in self.cache:
            return self.cache[path]   
        elif path.startswith('./'):
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
            full_insensitive = resimUtils.getfileInsensitive(path, self.root_prefix, lgr)
            self.lgr.debug('full_insenstive is %s' % full_insensitive)
            if full_insensitive is None or not os.path.isfile(full_insensitive):
                if lgr is not None:
                    lgr.debug('TargetFS getFull not relative no file at %s -- use glob' % full)
                pattern = path
                if self.root_subdirs is None or len(self.root_subdirs) == 0:
                    #self.lgr.debug('pattern %s' % pattern)
                    flist = findPattern(self.root_prefix, pattern, ignore_case=True, lgr=self.lgr)
                    if len(flist) == 0:
                        pattern = '%s*' % path
                        flist = findPattern(self.root_prefix, pattern, ignore_case=True, lgr=self.lgr)
                    if len(flist) > 0:
                        retval = os.path.join(self.root_prefix, flist[0])
                else:
                    for subdir in self.root_subdirs:
                        subpath = os.path.join(self.root_prefix, subdir)
                        #self.lgr.debug('TargetFS getFull subpath %s  pattern %s' % (subpath, pattern))
                        flist = findPattern(subpath, pattern, lgr=self.lgr)
                        if len(flist) == 0:
                            pattern = '%s*' % path
                            flist = findPattern(subpath, pattern, ignore_case=True, lgr=self.lgr)
                        if len(flist) > 0:
                            retval = os.path.join(subpath, flist[0])
                            break 
                for f in flist:
                    self.lgr.debug('targetFS getFull got %s' % f)
            else:
                retval = full_insensitive
        if retval is not None:
            retval = os.path.abspath(retval)
            ret_base = os.path.basename(retval)
            if ret_base not in self.cache:
                self.cache[ret_base] = retval
            elif self.cache[ret_base] != retval:
                self.lgr.error('winTargetFS bad assumption about program base names?, %s already in cache as %s' % (ret_base, self.cache[ret_base]))
        return retval
