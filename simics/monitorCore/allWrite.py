import os
class WriteStuff():
    def __init__(self, comm, fd, fname, fh):
        self.comm = comm
        self.fd = fd
        self.fh = fh
        self.fname = fname
all_write_dir = '/tmp/allwrite'

class AllWrite():
    def __init__(self):
        self.pids = {}
        try:
            os.mkdir(all_write_dir)
        except:
            pass
        self.junk = {}

    def write(self, comm, pid, fd, stuff):
        if pid in self.pids:
            if self.pids[pid].comm != comm:        
                self.pids[pid].fh.close()
                del self.pids[pid]
                if comm not in self.junk:
                    self.junk[comm] = 0
                self.junk[comm] += 1
                if self.junk[comm] > 4:
                    return
                fname = '%s_%s.out' % (comm, pid)
                full = os.path.join(all_write_dir, fname)
                fh = open(full, 'w')
                aw = WriteStuff(comm, fd, fname, fh)
                self.pids[pid] = aw
        else:
            fname = '%s_%s.out' % (comm, pid)
            full = os.path.join(all_write_dir, fname)
            fh = open(full, 'w')
            aw = WriteStuff(comm, fd, fname, fh)
            self.pids[pid] = aw
        self.pids[pid].fh.write(stuff)
        self.pids[pid].fh.flush()
    
