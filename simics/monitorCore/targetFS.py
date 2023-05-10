import os
import glob
class TargetFS():
    def __init__(self, root_prefix):
        self.root_prefix = root_prefix

    def find(self, name):
        for root, dirs, files in os.walk(self.root_prefix):
            if name in files:
                retval = os.path.join(root, name)
                return os.path.abspath(retval)
        return None

    def getRootPrefix(self):
        return self.root_prefix
 
    def getFull(self, path, lgr=None):
        retval = None
        if path.startswith('./'):
             base = os.path.basename(path)
             fun_file = base+'.funs'
             lgr.debug('is relative, fun_file %s' % fun_file)
             full_fun = self.find(fun_file)
             if full_fun is not None:              
                 retval = os.path.join(os.path.dirname(full_fun), base)
                 lgr.debug('getFull found file %s' % retval)
             else:
                 retval = self.find(base)
        else:     
            if path.startswith('/'):
                path = path[1:]
            full = os.path.join(self.root_prefix, path)
            if os.path.islink(full):
                real = os.readlink(full)
                #if lgr is not None:
                #    lgr.debug('TargetFS link real %s' % real)
                if real.startswith('/'):
                    real = real[1:]
                    retval = os.path.join(self.root_prefix, real)
                else:
                    retval = os.path.join(os.path.dirname(full), real)
            elif not os.path.isfile(full):
                #if lgr is not None:
                #    #lgr.debug('TargetFS getFull no file at %s -- use glob' % full)
                flist = glob.glob(full+'*')
                if len(flist) > 0:
                    retval = flist[0]
                else:
                    #if lgr is not None:
                    #    lgr.debug('TargetFS getFull, no glob at %s' % (full+'*'))
                    ''' try basename '''
                    base = os.path.basename(path)
                    fun_file = base+'.funs'
                    #if lgr is not None:
                    #    lgr.debug('is relative, fun_file %s' % fun_file)
                    full_fun = self.find(fun_file)
                    if full_fun is not None:              
                        retval = os.path.join(os.path.dirname(full_fun), base)
                        #if lgr is not None:
                        #    lgr.debug('getFull found file %s' % retval)
                    else:
                        retval = self.find(base)
                        #if lgr is not None:
                        #    lgr.debug('getFull used find found file %s' % retval)

            else:
                retval = full
        if retval is not None:
            retval = os.path.abspath(retval)
        return retval
