import os
class TargetFS():
    def __init__(self, root_prefix):
        self.root_prefix = root_prefix

    def getFull(self, path, lgr=None):
        if path.startswith('/'):
            path = path[1:]
        full = os.path.join(self.root_prefix, path)
        #if lgr is not None:
        #    lgr.debug('TargetFS full %s' % full)
        if os.path.islink(full):
            real = os.readlink(full)
            #if lgr is not None:
            #    lgr.debug('TargetFS link real %s' % real)
            if real.startswith('/'):
                real = real[1:]
                retval = os.path.join(self.root_prefix, real)
            else:
                retval = os.path.join(os.path.dirname(full), real)
        else:
            retval = full
        return retval
