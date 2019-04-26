#!/usr/bin/env python
import array
''' number of bytes '''
unsigned_long = 4 
NFDBITS  = 8 * unsigned_long
FD_SET_SIZE = 1024
FDSET_LONGS = FD_SET_SIZE/NFDBITS
_1UL = 32

'''
#undef __FD_SET
static inline void __FD_SET(unsigned long __fd, __kernel_fd_set *__fdsetp)
{
        unsigned long __tmp = __fd / __NFDBITS;
        unsigned long __rem = __fd % __NFDBITS;
        __fdsetp->fds_bits[__tmp] |= (1UL<<__rem);
}

#undef __FD_CLR
static inline void __FD_CLR(unsigned long __fd, __kernel_fd_set *__fdsetp)
{
        unsigned long __tmp = __fd / __NFDBITS;
        unsigned long __rem = __fd % __NFDBITS;
        __fdsetp->fds_bits[__tmp] &= ~(1UL<<__rem);
}

#undef __FD_ISSET
static inline int __FD_ISSET(unsigned long __fd, const __kernel_fd_set *__p)
{
        unsigned long __tmp = __fd / __NFDBITS;
        unsigned long __rem = __fd % __NFDBITS;
        return (__p->fds_bits[__tmp] & (1UL<<__rem)) != 0;
}

'''

class KernelFDSet():
    def __init__(self):
        self.set = array.array('L', range(FDSET_LONGS))
    def isSet(self,fd):
        tmp = fd / NFDBITS
        rem = fd % NFDBITS;
        
        val = (self.set[tmp] & (_1UL<<rem)) != 0
        return val

print('FDSET_LONGS is %d' % FDSET_LONGS)
x = KernelFDSet()
x.set[0] = 0x000040
print str(x)
   
for i in range(1,40):
    print(x.isSet(i))
