import pickle
import os
SOCKET      =1 
BIND        =2
CONNECT     =3
LISTEN      =4
ACCEPT      =5
GETSOCKNAME =6
GETPEERNAME =7
SOCKETPAIR  =8
SEND        =9
RECV        =10
SENDTO      =11
RECVFROM    =12
SHUTDOWN    =13
SETSOCKOPT  =14
GETSOCKOPT  =15
SENDMSG     =16
RECVMSG     =17
ACCEPT4     =18

callname = ['dumb', 'SOCKET', 'BIND', 'CONNECT', 'LISTEN', 'ACCEPT', 'GETSOCKNAME', 'GETPEERNAME', 'SOCKETPAIR', 'SEND', 'RECV', 'SENDTO' , 'RECVFROM',   
    'SHUTDOWN' , 'SETSOCKOPT', 'GETSOCKOPT', 'SENDMSG', 'RECVMSG', 'ACCEPT4']

SOCK_STREAM     = 1
SOCK_DGRAM      = 2
SOCK_RAW        = 3
SOCK_RDM        = 4
SOCK_SEQPACKET  = 5
SOCK_DCCP       = 6
SOCK_PACKET     = 10

socktype = ['dumb', 'SOCK_STREAM', 'SOCK_DGRAM', 'SOCK_RAW', 'SOCK_RDM', 'SOCK_SEQPACKET', 'SOCK_DCCP', 'SOCK_PACKET']

SOCK_TYPE_MASK = 0xf
AF_LOCAL = 1
AF_INET = 2
domaintype = [ 'AF_UNSPEC', 'AF_LOCAL', 'AF_INET', 'AF_AX25', 'AF_IPX', 'AF_APPLETALK', 'AF_NETROM', 'AF_BRIDGE',
'AF_ATMPVC', 'AF_X25', 'AF_INET6', 'AF_ROSE', 'AF_DECnet', 'AF_NETBEUI', 'AF_SECURITY', 'AF_KEY', 'AF_NETLINK']

FIONBIO = 0x5421
FIONREAD = 0x541B

class NetInfo():
    def __init__(self, ip, mask, broadcast, dev, label):
        self.ip = ip
        self.mask = mask
        self.broadcast = broadcast
        self.dev = dev
        self.label = label 
 
class NetAddresses():
    def __init__(self, lgr):
        self.ipv4_addrs = []
        self.net_commands = []
        self.lgr = lgr 
    def add(self, ip, mask, broadcast, dev, label):
        info = NetInfo(ip, mask, broadcast, dev, label)
        self.ipv4_addrs.append(info)
    def checkNet(self, prog, args):
        if '/bin/ip addr add' in args:
            self.lgr.debug('NetAddresses checkNet found net info %s' % args) 
            self.net_commands.append(args)
        elif 'ifconfig' in args:
            self.lgr.debug('NetAddresses checkNet found net info %s' % args) 
            self.net_commands.append(args)

    def getCommands(self):
        return self.net_commands

    def pickleit(self, net_file):
        pickle.dump( self.net_commands, open( net_file, "wb" ) )

    def loadfile(self, net_file):
        if os.path.isfile(net_file):
            self.net_commands = pickle.load( open(net_file, 'rb') ) 
        else:
            self.lgr.debug('no net file %s for checkpoint load' % net_file)

class SockStruct():
    def __init__(self, cpu, params, mem_utils):
        self.fd = mem_utils.readWord32(cpu, params)
        self.port = None
        self.sin_addr = None
        self.sa_data = None
        addr = mem_utils.readWord32(cpu, params+4)
        self.addr = addr
        self.length = mem_utils.readWord32(cpu, params+8)
        self.flags = mem_utils.readWord32(cpu, params+12)
        self.sa_family = mem_utils.readWord16(cpu, addr) 
        if self.sa_family == 1:
            self.sa_data = mem_utils.readString(cpu, addr+2, 256)
        elif self.sa_family == 2:
            self.port = mem_utils.readWord16le(cpu, addr+2)
            self.sin_addr = mem_utils.readWord32(cpu, addr+4)

    def famName(self):
        if self.sa_family is not None and self.sa_family < len(domaintype):
            return domaintype[self.sa_family]
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

    def isRoutable(self):
        if self.sa_family == 2:
            ip = self.dottedIP()
            if not ip.startswith('0.0.') and not ip.startswith('127.'):
                return True
        return False

    def addressInfo(self):
        ''' for use in printing traces '''
        flag = ''
        if self.isRoutable():
            flag = 'ROUTABLE IP'
        return flag

    def getString(self):
        if self.sa_family == 1:
            retval = ('FD: %d sa_family: %s  sa_data: %s' % (self.fd, self.famName(), self.sa_data))
        elif self.sa_family == 2:
            retval = ('FD: %d sa_family: %s  address: %s:%d' % (self.fd, self.famName(), self.dottedIP(), self.port))
        else:
            retval = ('FD: %d sa_family: %s  TBD' % (self.fd, self.famName()))
        return retval

