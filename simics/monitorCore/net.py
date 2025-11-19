import pickle
import os
import resimUtils
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
readcalls = ['RECV', 'RECVFROM', 'RECVMSG']

SOCK_STREAM     = 1
SOCK_DGRAM      = 2
SOCK_RAW        = 3
SOCK_RDM        = 4
SOCK_SEQPACKET  = 5
SOCK_DCCP       = 6
SOCK_PACKET     = 10

socktype = ['dumb', 'SOCK_STREAM', 'SOCK_DGRAM', 'SOCK_RAW', 'SOCK_RDM', 'SOCK_SEQPACKET', 'SOCK_DCCP', 'UNUNSED1', 'UNUSED2', 'UNUSED3', 'SOCK_PACKET']

SOCK_TYPE_MASK = 0xf
AF_LOCAL = 1
AF_INET = 2
AF_NETLINK = 16
domaintype = [ 'AF_UNSPEC', 'AF_LOCAL', 'AF_INET', 'AF_AX25', 'AF_IPX', 'AF_APPLETALK', 'AF_NETROM', 'AF_BRIDGE',
'AF_ATMPVC', 'AF_X25', 'AF_INET6', 'AF_ROSE', 'AF_DECnet', 'AF_NETBEUI', 'AF_SECURITY', 'AF_KEY', 'AF_NETLINK',
'AF_PACKET', 'AF_ASH', 'AF_ECONET', 'AF_ATMSVC', 'AF_RDS', 'AF_SNA', 'AF_IRDA', 'AF_PPPOX', 'AF_WANPIPE', 'AF_LLC',	
'UNUSED27', 'UNUSED28', 'AF_CAN', 'AF_TIPC', 'AF_BLUETOOTH', 'AF_IUCV', 'AF_RXRPC', 'AF_ISDN', 'AF_PHONET', 'AF_IEEE802154', 'AF_CAIF',	
'AF_ALG', 'AF_NFC', 'AF_MAX']

FIONBIO = 0x5421
FIONREAD = 0x541B

''' fcntl commands '''
F_CNTL_CMDS = [ 'F_DUPFD', 'F_GETFD', 'F_SETFD', 'F_GETFL', 'F_SETFL', 'F_GETLK', 'F_SETLK', 'F_SETLKW', 'F_SETOWN', 'F_GETOWN', 'F_SETSIG', 'F_GETSIG' ]


O_NONBLOCK  =   0x00004000
O_CLOEXEC   =   0x02000000        
O_ACCMODE   =   0O00000003
O_RDONLY    =   0O00000000
O_WRONLY    =   0O00000001
O_RDWR      =   0O00000002
O_CREAT     =   0O00000100        
O_EXCL      =   0O00000200       
O_NOCTTY    =   0O00000400      
O_TRUNC     =   0O00001000     
O_APPEND    =   0O00002000
O_NONBLOCK  =   0O00004000
O_SYNC      =   0O00010000
FASYNC      =   0O00020000    
O_DIRECT    =   0O00040000   
O_LARGEFILE =   0O00100000
O_DIRECTORY =   0O00200000  
O_NOFOLLOW  =   0O00400000 

def fcntlCmdIs(cmd, s):
    retval = False
    if cmd in range(len(F_CNTL_CMDS)):
        if F_CNTL_CMDS[cmd] == s:
            retval = True
    elif cmd == 0x406 and s == 'F_DUPFD':
            retval = True
    return retval

def fcntlCmd(cmd):
    retval =  str(cmd)
    if cmd in range(len(F_CNTL_CMDS)):
        retval = F_CNTL_CMDS[cmd] 
    return retval

def fcntlGetCmd(cmd):
    if cmd in range(len(F_CNTL_CMDS)):
        retval = F_CNTL_CMDS[cmd]
    elif cmd == 0x406:
        retval = 'F_DUPFD_CLO_EXEC'
    else:  
        retval = '0x%x' % cmd
    return retval

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

class SockAddrNL():
    def __init__(self, nl_pid, nl_groups):
        self.nl_pid = nl_pid
        self.nl_groups = nl_groups

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
        self.sock_addr_nl = None
        try:
            self.sa_family = mem_utils.readWord16(cpu, self.addr) 
        except:
            #print('net sockStruct failed reading sa family from 0x%x' % self.addr)
            if lgr is not None:
                lgr.debug('net sockStruct failed reading sa family from 0x%x' % self.addr)
            return
        if lgr is not None and self.sa_family is not None:
            lgr.debug('net sockStruct sa_family read as 0x%x' % self.sa_family)
        if self.sa_family == AF_LOCAL:
            self.sa_data = mem_utils.readString(cpu, self.addr+2, 256)
        elif self.sa_family == AF_INET:
            self.port = mem_utils.readWord16le(cpu, self.addr+2)
            self.sin_addr = mem_utils.readWord32(cpu, self.addr+4)
        elif self.sa_family == AF_NETLINK:
            pid = mem_utils.readWord16le(cpu, self.addr+4)
            groups = mem_utils.readWord32(cpu, self.addr+8)
            self.sock_addr_nl = SockAddrNL(pid, groups)

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
            if self.sock_type < len(socktype):
                sock_type = 'type: %s' % socktype[self.sock_type]
            else:
                sock_type = 'type: %s' % self.sock_type
        if self.sa_family is None:
            retval = ('%s sa_family unknown' % (fd))
        elif self.sa_family == AF_LOCAL:
            retval = ('%s sa_family%d: %s %s %s sa_data: %s' % (fd, self.sa_family, self.famName(), sock_type, addr, self.sa_data))
        elif (self.sa_family == AF_INET or self.sa_family == 0) and self.port is not None:
            retval = ('%s sa_family%d: %s %s %s IP address: %s:%d' % (fd, self.sa_family, self.famName(), sock_type, addr, self.dottedIP(), self.port))
        elif self.sa_family == AF_NETLINK:
            if self.sock_addr_nl is not None:
                retval = ('%s sa_family%d: %s %s %s sock_addr_nl.pid %d sock_addr_nl.groups: 0x%x ' % (fd, self.sa_family, self.famName(), sock_type, addr, self.sock_addr_nl.nl_pid, self.sock_addr_nl.nl_groups))
            else:
                retval = ('%s sa_family%d: %s %s %s sock_addr_nl IS NONE ' % (fd, self.sa_family, self.famName(), sock_type, addr))
        else:
            retval = ('%s sa_family%d: %s %s TBD' % (fd, self.sa_family, self.famName(), addr))
        return retval

class Iovec():
    def __init__(self, base, length):
        self.base = base
        self.length = length
class Msghdr():
    '''
           struct iovec {                    /* Scatter/gather array items */
               void  *iov_base;              /* Starting address */
               size_t iov_len;               /* Number of bytes to transfer */
           };

           struct msghdr {
               void         *msg_name;       /* optional address */
               socklen_t     msg_namelen;    /* size of address */
               struct iovec *msg_iov;        /* scatter/gather array */
               size_t        msg_iovlen;     /* # elements in msg_iov */
               void         *msg_control;    /* ancillary data, see below */
               size_t        msg_controllen; /* ancillary data buffer len */
               int           msg_flags;      /* flags on received message */
           };
    '''

    def __init__(self, cpu, mem_utils, msghdr_address, lgr):
        self.msg_name = mem_utils.readAppPtr(cpu, msghdr_address) 
        self.msg_namelen = mem_utils.readAppPtr(cpu, msghdr_address+mem_utils.wordSize(cpu)) 
        self.msg_iov = mem_utils.readAppPtr(cpu, msghdr_address+2*mem_utils.wordSize(cpu)) 
        self.msg_iovlen = mem_utils.readAppPtr(cpu, msghdr_address+3*mem_utils.wordSize(cpu)) 
        #print('msghdr_address is 0x%x' % msghdr_address)
        self.msg_control = mem_utils.readAppPtr(cpu, msghdr_address+4*mem_utils.wordSize(cpu)) 
        self.msg_controllen = mem_utils.readAppPtr(cpu, msghdr_address+5*mem_utils.wordSize(cpu)) 
        self.flags = mem_utils.readAppPtr(cpu, msghdr_address+6*mem_utils.wordSize(cpu)) 
        self.cpu = cpu
        self.mem_utils = mem_utils
        self.lgr = lgr

    def getIovec(self):
        retval = []
        iov_size = 2*self.mem_utils.wordSize(self.cpu)
        if self.msg_iov is not None:
            iov_addr = self.msg_iov
            limit = max(10, self.msg_iovlen)
            for i in range(limit):
                base = self.mem_utils.readAppPtr(self.cpu, iov_addr)
                length = self.mem_utils.readAppPtr(self.cpu, iov_addr+self.mem_utils.wordSize(self.cpu))
                retval.append(Iovec(base, length)) 
                iov_addr = iov_addr+iov_size
        return retval

    def getString(self):
        if self.msg_name is None:
            retval = 'msg_name not initialized'
        else:
            retval = 'msg_name 0x%x  msg_namelen: %d  msg_iov: 0x%x  msg_iovlen: %d  msg_control: 0x%x msg_controllen %d flags 0x%x' % (self.msg_name,
                 self.msg_namelen, self.msg_iov, self.msg_iovlen, self.msg_control, self.msg_controllen, self.flags)
            iov_size = 2*self.mem_utils.wordSize(self.cpu)
            iov_addr = self.msg_iov
            iov_string = ''
            #print('msg_iovlen is %d iov_addr 0x%x  iov_size %d' % (self.msg_iovlen, iov_addr, iov_size))
            limit = min(10, self.msg_iovlen)
            for i in range(limit):
                base = self.mem_utils.readAppPtr(self.cpu, iov_addr)
                if base is None:
                    iov_string = ' failed to get base from 0x%x' % iov_addr
                    break
                length = self.mem_utils.readAppPtr(self.cpu, iov_addr+self.mem_utils.wordSize(self.cpu))
                iov_string = iov_string+'\n\tbase: 0x%x  length: %d' % (base, length) 
                iov_addr = iov_addr+iov_size
            retval = retval + iov_string    
        return retval

    def getDumpString(self):
        if self.msg_name is None:
            retval = 'msg_name not initialized'
        else:
            retval = ''
            iov_size = 2*self.mem_utils.wordSize(self.cpu)
            iov_addr = self.msg_iov
            iov_string = ''
            #print('msg_iovlen is %d iov_addr 0x%x  iov_size %d' % (self.msg_iovlen, iov_addr, iov_size))
            limit = min(10, self.msg_iovlen)
            for i in range(limit):
                base = self.mem_utils.readAppPtr(self.cpu, iov_addr)
                length = self.mem_utils.readAppPtr(self.cpu, iov_addr+self.mem_utils.wordSize(self.cpu))
                limit = min(length, 1024)
                #byte_string, dumb = self.mem_utils.getBytes(cpu, limit, exit_info.retval_addr)
                byte_tuple = self.mem_utils.getBytes(self.cpu, limit, base)
                s = resimUtils.getHexDump(byte_tuple[:1024])
                self.lgr.debug('base 0x%x length %d str: %s' % (base, length, s))
                retval = retval + s
                iov_addr = iov_addr+iov_size
        return retval

    def getByteArray(self):
        if self.msg_name is None:
            retval = 'msg_name not initialized'
        else:
            retval = bytearray()
            iov_size = 2*self.mem_utils.wordSize(self.cpu)
            iov_addr = self.msg_iov
            iov_string = ''
            limit = min(10, self.msg_iovlen)
            self.lgr.debug('msg_iovlen is %d iov_addr 0x%x  iov_size %d limit %d' % (self.msg_iovlen, iov_addr, iov_size, limit))
            for i in range(limit):
                base = self.mem_utils.readAppPtr(self.cpu, iov_addr)
                length = self.mem_utils.readAppPtr(self.cpu, iov_addr+self.mem_utils.wordSize(self.cpu))
                limit = min(length, 1024)
                #byte_string, dumb = self.mem_utils.getBytes(cpu, limit, exit_info.retval_addr)
                byte_tuple = self.mem_utils.getBytes(self.cpu, limit, base)
                retval = retval + bytearray(byte_tuple)
                iov_addr = iov_addr+iov_size
                self.lgr.debug('len of byte tuple %d, current len of retval %d' % (len(byte_tuple), len(retval)))
        return retval
