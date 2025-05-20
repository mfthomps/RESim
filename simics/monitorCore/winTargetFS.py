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
    def __init__(self, top, root_prefix, root_subdirs, lgr):
        self.top = top
        self.root_prefix = root_prefix
        self.root_subdirs = root_subdirs
        self.cache = {}
        self.lgr = lgr
        self.comm_len = 14
        self.exec_dict = resimUtils.getExecDict(root_prefix, lgr=lgr)

    def getRootPrefix(self):
        return self.root_prefix

 
    def getFull(self, path, lgr=None):
        retval = None
        if self.lgr is None:
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
            path = resimUtils.getWinPath(path, self.root_prefix, lgr=lgr)
            if lgr is not None:
                self.lgr.debug('winTargetFS getFull root_prefix %s path %s len root_subdirs %d' % (self.root_prefix, path, len(self.root_subdirs)))
            if '/' in path:
                maybe = os.path.join(self.root_prefix, path)
                if os.path.isfile(maybe): 
                    self.lgr.debug('winTargetFS getFull got slash set retval to %s' % maybe)
                    retval = maybe
            if retval is None:
                retval = self.checkExecDict(path, lgr=lgr)
                if retval == 'multiple_results':
                    retval = None
                
            if retval is None:
                full_insensitive = resimUtils.getfileInsensitive(path, self.root_prefix, self.root_subdirs, lgr)
                if lgr is not None:
                    self.lgr.debug('winTargetFS getFull full_insenstive is %s' % full_insensitive)
                if full_insensitive is None or not os.path.isfile(full_insensitive):
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
                    #for f in flist:
                    #    self.lgr.debug('targetFS getFull got %s' % f)
                else:
                    retval = full_insensitive
        if retval is not None:
            self.lgr.debug('winTargetFS getFull retval %s, now get abs path?' % path)
            retval = os.path.abspath(retval)
            self.lgr.debug('winTargetFS getFull abs %s' % retval)
            ret_base = os.path.basename(retval)
            if ret_base not in self.cache:
                self.cache[ret_base] = retval
            elif self.cache[ret_base] != retval:
                if lgr is not None:
                    lgr.error('winTargetFS bad assumption about program base names?, %s already in cache as %s' % (ret_base, self.cache[ret_base]))
                else:
                    print('winTargetFS bad assumption about program base names?, %s already in cache as %s' % (ret_base, self.cache[ret_base]))
        return retval

    def checkExecDict(self, path, lgr=None):
        retval = None   
        if self.exec_dict is not None:
            path_base = os.path.basename(path)
            if lgr is not None:
                lgr.debug('winTargetFS checkExecDict path_base %s' % path_base)
            if path_base in self.exec_dict:
                if len(self.exec_dict[path_base]) == 1: 
                    retval = os.path.join(self.root_prefix, self.exec_dict[path_base][0]['path'])
                elif len(self.exec_dict[path_base]) > 1: 
                    if lgr is not None:
                        lgr.debug('multiple paths for %s??' % path)
                        return 'multiple_results'
                        
                if lgr is not None:
                    lgr.debug('winTargetFS checkExecDict found path for %s, %s' % (path_base, retval))
            #elif path_base == path and len(path) == self.comm_len:
            elif path_base == path:
                result_list = []
                for exec_base in self.exec_dict:
                    if exec_base.lower().startswith(path.lower()):
                        result = os.path.join(self.root_prefix, self.exec_dict[exec_base][0]['path'])
                        result_list.append(result)
                        if lgr is not None:
                            lgr.debug('winTargetFS checkExecDict found truncated base, and path for %s, %s' % (path_base, retval))
                if len(result_list) == 1:
                    retval = result_list[0] 
                elif len(result_list) > 1:
                    print('Multiple results found for %s:  %s' % (path, str(result_list)))
                    retval = 'multiple_results'
        else:
            if lgr is not None:
                lgr.debug('winTargetFS checkExecDict no exec_dict')
        return retval
