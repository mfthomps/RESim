import net
class SockStruct():
    def __init__(self, cpu, params, mem_utils, fd=None, length=0, sock_type=None, lgr=None):
        self.length = length
        self.flags = 0
        if fd is None:
            ''' must be 32-bit socketcall, find addr.  fd, length and flags are speculative '''
            self.fd = mem_utils.readWord32(cpu, params)
            self.length = mem_utils.readWord32(cpu, params+8)
            self.flags = mem_utils.readWord32(cpu, params+12)
            self.addr = mem_utils.readWord32(cpu, params+4)
        else:
            self.fd = fd
            #self.addr = mem_utils.readWord32(cpu, params)
            self.addr = params
            self.length = length
        self.port = None
        self.sin_addr = None
        self.sa_data = None
        self.sa_family = None
        self.sock_type = sock_type
        self.domain = None
        self.protocol = None
        self.lgr = lgr
        try:
            self.sa_family = mem_utils.readWord16le(cpu, self.addr)
        except:
            print('net sockStruct failed reading sa family from 0x%x' % self.addr)
            if lgr is not None:
                lgr.error('net sockStruct failed reading sa family from 0x%x' % self.addr)
            return
        if lgr is not None:
            lgr.debug('net sockStruct sa_family read as 0x%x' % self.sa_family)
        if self.sa_family == 1:
            self.sa_data = mem_utils.readString(cpu, self.addr+2, 256)
        elif self.sa_family == 2:
            self.port = mem_utils.readWord16le(cpu, self.addr+2)
            self.sin_addr = mem_utils.readWord32(cpu, self.addr+4)

    def famName(self):
        if self.sa_family is not None and self.sa_family < len(net.domaintype):
            return net.domaintype[self.sa_family]
        else:
            return None

    def dottedIP(self):
      if self.sin_addr is None:
          return self.famName()
      "Convert 32-bit integer to dotted IPv4 address."
      return ".".join(map(lambda n: str(self.sin_addr>>n & 0xFF), [0,8,16,24]))

    def dottedPort(self):
        return '%s:%s' % (self.dottedIP(), self.port)

    def getName(self):
        if self.sa_family == 1:
            return self.sa_data
        elif self.sa_family == 2:
            name = '%s:%s' % (self.dottedIP(), self.port)
            return name
        else:
            return None

    def isExternal(self):
        if self.sa_family == 2:
            ip = self.dottedIP()
            if not ip.startswith('0.0.') and not ip.startswith('127.'):
                return True
        return False

    def addressInfo(self):
        ''' for use in printing traces '''
        flag = ''
        if self.isExternal():
            flag = 'EXTERNAL IP'
        return flag

    def addParams(self, params):
        self.domain = params.domain
        self.sock_type = params.sock_type
        self.protocol = params.protocol

    def getString(self):
        fd = ''
        addr = ''
        sock_type = ''
        if self.fd is not None and self.fd >= 0:
            fd = 'FD: %d (0x%x)' % (self.fd, self.fd)
        if self.addr is not None:
            addr = 'addr: 0x%x' % self.addr
        if self.sock_type is not None:
            if self.sock_type < len(net.socktype):
                sock_type = 'type: %s' % net.socktype[self.sock_type]
            else:
                sock_type = 'type: %s' % self.sock_type
        if self.sa_family is None:
            retval = ('%s sa_family unknown' % (fd))
        elif self.sa_family == 1:
            retval = ('%s sa_family%d: %s %s %s sa_data: %s' % (fd, self.sa_family, self.famName(), sock_type, addr, self.sa_data))
        elif (self.sa_family == 2 or self.sa_family == 0) and self.port is not None:
            retval = ('%s sa_family%d: %s %s %s IP address: %s:%d' % (fd, self.sa_family, self.famName(), sock_type, addr, self.dottedIP(), self.port))
        else:
            retval = ('%s sa_family%d: %s %s TBD' % (fd, self.sa_family, self.famName(), addr))
        return retval
