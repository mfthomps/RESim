import os
class UserIterators():
    def __init__(self, path, lgr, root_dir):
        self.path = path
        self.lgr = lgr
        self.iterators = []
        self.load(path)
        self.lgr.debug('userIterators count now %d from %s' % (len(self.iterators), self.path))
        ida_data = os.getenv('RESIM_IDA_DATA')
        if ida_data is None:
            self.lgr.error('RESIM_IDA_DATA not defined')
            return
        base = os.path.basename(self.path).rsplit('.', )[0]
        self.new_path = os.path.join(ida_data, root_dir, base, base+'.iterators')
        if os.path.isfile(self.new_path):
            self.load(self.new_path)
            self.lgr.debug('userIterators count now %d from %s' % (len(self.iterators), self.new_path))

    def load(self, path):
        if os.path.isfile(path):
            with open(path) as fh:
                for line in fh:
                    try:
                       fun = int(line.strip(), 16)
                    except ValueError:
                       print('Failed to read function addresses from %s' % path)
                       return
                    self.iterators.append(fun)
                    self.lgr.debug('userIterators added fun 0x%x' % fun)

    def add(self, fun):
        if fun not in self.iterators and fun is not None:
            self.iterators.append(fun) 
            try:
                with open(self.path, 'w') as fh:
                    for f in self.iterators:
                        fh.write('0x%x\n' % f)
                    self.lgr.debug('userIterators wrote to %s' % self.path)
            except IOError:
                self.path = self.new_path
                with open(self.path, 'w') as fh:
                    self.lgr.debug('userIterators failed first write, then wrote to %s' % self.path)
                    for f in self.iterators:
                        fh.write('0x%x\n' % f)
        else:
            self.lgr.debug('uesrIterator did not add, fun may be None')

    def isIterator(self, fun):
        #self.lgr.debug('isIterator 0x%x in %s' % (fun, str(self.iterators)))
        if fun in self.iterators:
            #self.lgr.debug('isIterator YES')
            return True
        return False
