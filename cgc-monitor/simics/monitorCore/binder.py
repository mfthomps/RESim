import json
class Binder():
    def __init__(self):
        self.binders = []

    class BindRec():
        def __init__(self, pid, prog, address, port):
            self.pid = pid
            self.prog = prog
            self.address = address
            self.port = port
        def getJson(self):
            retval = {}
            retval['pid'] = self.pid
            retval['prog'] = self.prog
            retval['address'] = self.address
            retval['port'] = self.port
            return retval

    def add(self, pid, prog, address, port):
        bind_rec = self.BindRec(pid, prog, address, port)
        self.binders.append(bind_rec) 

    def dumpJson(self, fname):
        jdump = []
        for bind_rec in self.binders:
            jdump.append(bind_rec.getJson()) 
        with open(fname, 'w') as fh:
            s = json.dumps(jdump)
            fh.write(s)

    def showAll(self, fname):
        with open(fname, 'w') as fh:
            for bind_rec in self.binders:
                line = '%-60s \t%s:%d' % (bind_rec.prog, bind_rec.address, bind_rec.port)
                print(line)
                fh.write(line+'\n')
 
