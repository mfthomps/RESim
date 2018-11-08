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

#define AF_UNSPEC       0
#define AF_UNIX         1       /* Unix domain sockets          */
#define AF_LOCAL        1       /* POSIX name for AF_UNIX       */
#define AF_INET         2       /* Internet IP Protocol         */
#define AF_AX25         3       /* Amateur Radio AX.25          */
#define AF_IPX          4       /* Novell IPX                   */
#define AF_APPLETALK    5       /* AppleTalk DDP                */
#define AF_NETROM       6       /* Amateur Radio NET/ROM        */
#define AF_BRIDGE       7       /* Multiprotocol bridge         */
#define AF_ATMPVC       8       /* ATM PVCs                     */
#define AF_X25          9       /* Reserved for X.25 project    */
#define AF_INET6        10      /* IP version 6                 */
#define AF_ROSE         11      /* Amateur Radio X.25 PLP       */
#define AF_DECnet       12      /* Reserved for DECnet project  */
#define AF_NETBEUI      13      /* Reserved for 802.2LLC project*/
#define AF_SECURITY     14      /* Security callback pseudo AF */
#define AF_KEY          15      /* PF_KEY key management API */
#define AF_NETLINK      16
#define AF_ROUTE        AF_NETLINK /* Alias to emulate 4.4BSD */


