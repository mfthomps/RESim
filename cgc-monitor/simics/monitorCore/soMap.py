import os
class SOMap():
    def __init__(self, lgr):
        self.so_addr_map = {}
        self.so_file_map = {}
        self.lgr = lgr
    def addSO(self, pid, fpath, addr):
        if pid not in self.so_addr_map:
            self.so_addr_map[pid] = {}
            self.so_file_map[pid] = {}
        self.so_addr_map[pid][fpath] = addr
        self.so_file_map[pid][addr] = fpath
    def showSO(self, pid):
        if pid in self.so_file_map:
            for addr in sorted(self.so_file_map[pid]):
                print('0x%x  %s' % (addr, self.so_file_map[pid][addr])) 
        else:
            print('no so map for %d' % pid)

    def getSOFile(self, pid, addr_in):
        retval = None
        prev = None
        if pid in self.so_file_map:
            for addr in sorted(self.so_file_map[pid]):
                if addr > addr_in:
                    if prev is None:
                        retval = ('first so for %d is at 0x%x, you asked for 0x%x' % (pid, addr, addr_in))
                        return None
                    retval = 'so_file:%s' % self.so_file_map[pid][prev]
                    break
                else:
                    prev = addr 
            if retval is None:
                retval = 'so_file:%s' % self.so_file_map[pid][prev]
            
        else:
            retval = ('no so map for %d' % pid)
        return retval

    def getSOAddr(self, pid, fname):
        retval = 'so file %s not found' % fname
        if pid in self.so_file_map:
            for fpath in self.so_file_map[pid]:
                base = os.path.base(fpath)
                if base == fname:
                    if retval is not None:
                        retval = 'multiple so files with fname %s' % fname
                        break
                    else:
                        retval = 'so_addr:0x%x' % self.so_addr_map[pid][base]
        else:
            retval = ('no so map for %d' % pid)
        return retval
    

        
