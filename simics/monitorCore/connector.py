import json
class Connector():
    '''
    Track which processes attempt connections 
    NOTE: Only the first attempt is recorded here.
    '''
    def __init__(self, lgr):
        self.connectors = []
        self.lgr = lgr

    class ConnectRec():
        def __init__(self, pid, fd, prog, address, port):
            self.pid = pid
            self.fd = fd
            self.prog = prog
            self.address = address
            self.port = port

        def getJson(self):
            retval = {}
            retval['pid'] = self.pid
            retval['fd'] = self.fd
            retval['prog'] = self.prog
            retval['address'] = self.address
            retval['port'] = self.port
            return retval

    def getConnectors(self):
        return self.connectors

    def add(self, pid, fd, prog, address, port):
        for connect_rec in self.connectors:
            if connect_rec.prog == prog and connect_rec.address == address and connect_rec.port == port:
                return
        connect_rec = self.ConnectRec(pid, fd, prog, address, port)
        self.connectors.append(connect_rec) 
        self.lgr.debug('connector add %s' % self.toString(connect_rec))

    def dumpJson(self, fname):
        jdump = []
        for connect_rec in self.connectors:
            jdump.append(connect_rec.getJson()) 
        with open(fname, 'w') as fh:
            s = json.dumps(jdump)
            fh.write(s)
            self.lgr.debug('connectors wrote %d records to %s' % (len(jdump), fname))

    def loadJson(self, fname):
        with open(fname) as fh:
            s = fh.read()
            jload = json.loads(s)
            for jrec in jload:
                self.add(jrec['pid'], jrec['fd'], jrec['prog'], jrec['address'], jrec['port'])
            self.lgr.debug('connectors read %d records from %s' % (len(jload), fname))

    def toString(self, connect_rec):        
        if connect_rec.port is not None:
            line = '%-60s %d \t%d \t%s:%s' % (connect_rec.prog, connect_rec.pid, connect_rec.fd, connect_rec.address, str(connect_rec.port))
        else:
            line = '%-60s %d \t%d \t%s' % (connect_rec.prog,  connect_rec.pid, connect_rec.fd, connect_rec.address)
        return line

    def showAll(self, fname):
        with open(fname, 'w') as fh:
            for connect_rec in self.connectors:
                line = self.toString(connect_rec)
                print(line)
                fh.write(line+'\n')
 
