import os
class TargetFS():
    def __init__(self, root_prefix):
        self.root_prefix = root_prefix

    def getFull(self, path):
        if path.startswith('/'):
            path = path[1:]
        full = os.path.join(self.root_prefix, path)
        if os.path.islink(full):
            real = os.readlink(full)
            if real.startswith('/'):
                real = real[1:]
            retval = os.path.join(self.root_prefix, real)
        else:
            retval = full
        return retval
