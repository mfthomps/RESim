import json
class Binder():
    def __init__(self, lgr):
        self.binders = []
        self.lgr = lgr

    class BindRec():
        def __init__(self, tid, fd, prog, address, port):
            self.tid = tid
            self.fd = fd
            self.prog = prog
            self.address = address
            self.port = port
            self.new_fd = []
        def getJson(self):
            retval = {}
            retval['tid'] = self.tid
            retval['fd'] = self.fd
            retval['new_fd'] = self.new_fd
            retval['prog'] = self.prog
            retval['address'] = self.address
            retval['port'] = self.port
            return retval

    def add(self, tid, fd, prog, address, port):
        bind_rec = self.BindRec(tid, fd, prog, address, port)
        self.binders.append(bind_rec) 
        self.lgr.debug(('binder add %s' % self.toString(bind_rec)))
        return bind_rec

    def accept(self, tid, fd, new_fd):
        for bind_rec in self.binders:
            if bind_rec.fd == fd:
                bind_rec.new_fd.append(new_fd)
                break
        

    def dumpJson(self, fname):
        jdump = []
        for bind_rec in self.binders:
            jdump.append(bind_rec.getJson()) 
        with open(fname, 'w') as fh:
            s = json.dumps(jdump)
            fh.write(s)
            self.lgr.debug('binder dumpJson wrote %d from %s' % (len(jdump), fname))

    def loadJson(self, fname):
        with open(fname) as fh:
            s = fh.read()
            jload = json.loads(s)
            for jrec in jload:
                bind_rec = self.add(jrec['tid'], jrec['fd'], jrec['prog'], jrec['address'], jrec['port'])
                if 'new_fd' in jrec:
                    bind_rec.new_fd = jrec['new_fd'] 
            self.lgr.debug('binder loadJson loaded %d from %s' % (len(jload), fname))

    def toString(self, bind_rec):
        if bind_rec.new_fd is None:
            accept = ''
        else:
            accept = ','.join(str(a) for a in bind_rec.new_fd)
        if bind_rec.port is not None:
            line = '%-60s \t%d\t%s:%s\t%s' % (bind_rec.prog, bind_rec.fd, bind_rec.address, str(bind_rec.port), accept)
        else:
            line = '%-60s \t%d\t%s\t%s' % (bind_rec.prog, bind_rec.fd, bind_rec.address, accept)
        return line

    def showAll(self, fname):
        did = []
        with open(fname, 'w') as fh:
            for bind_rec in self.binders:
                line = self.toString(bind_rec)
                if line not in did:
                    print(line)
                    did.append(line)
                    fh.write(line+'\n')
 
