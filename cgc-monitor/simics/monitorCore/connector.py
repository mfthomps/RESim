import json
class Connector():
    '''
    Track which processes attempt connections to routable addresses.
    NOTE: Only the first attempt is recorded here.
    '''
    def __init__(self):
        self.connectors = []

    class ConnectRec():
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
        for connect_rec in self.connectors:
            if connect_rec.pid == pid and connect_rec.address == address and connect_rec.port == port:
                return
        connect_rec = self.ConnectRec(pid, prog, address, port)
        self.connectors.append(connect_rec) 

    def dumpJson(self, fname):
        jdump = []
        for connect_rec in self.connectors:
            jdump.append(connect_rec.getJson()) 
        with open(fname, 'w') as fh:
            s = json.dumps(jdump)
            fh.write(s)

    def showAll(self, fname):
        with open(fname, 'w') as fh:
            for connect_rec in self.connectors:
                line = '%-60s \t%s:%d' % (connect_rec.prog, connect_rec.address, connect_rec.port)
                print(line)
                fh.write(line+'\n')
 
