import os
class UserIterators():
    def __init__(self, path):
        self.path = path
        self.iterators = []
        if os.path.isfile(path):
            with open(path) as fh:
                for line in fh:
                    try:
                       fun = int(line.strip(), 16)
                    except ValueError:
                       print('Failed to read function addresses from %s' % path)
                       return
                    self.iterators.append(fun)

    def add(self, fun):
        if fun not in self.iterators and fun is not None:
            self.iterators.append(fun) 
            with open(self.path, 'w') as fh:
                for fun in self.iterators:
                    fh.write('0x%x\n' % fun)

    def isIterator(self, fun, lgr):
        #lgr.debug('isIterator 0x%x in %s' % (fun, str(self.iterators)))
        if fun in self.iterators:
            return True
        return False
