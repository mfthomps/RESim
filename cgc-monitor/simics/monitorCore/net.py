import pickle
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
        self.net_commands = pickle.load( open(net_file, 'rb') ) 
