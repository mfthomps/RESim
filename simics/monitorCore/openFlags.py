O_ACCMODE = 0o00000003
O_RDONLY = 0o00000000
O_WRONLY = 0o00000001
O_RDWR = 0o00000002
O_CREAT = 0o00000100  
O_TRUNC = 0o00001000
O_DIRECTORY = 0o200000
O_NONBLOCK =  0o4000


def getFlags(flags):
    retval = ''
    if flags == 0:
        retval = 'RDONLY'
    else:
        if flags & O_WRONLY > 0:
            retval = 'WRONLY'
        if flags & O_RDWR > 0:
            retval = 'RDWR'
        if flags & O_CREAT > 0:
            retval = retval + ' CREAT'
        if flags & O_TRUNC > 0:
            retval = retval + ' TRUNC'
        if flags & O_DIRECTORY > 0:
            retval = retval + ' DIRECTORY'
        if flags & O_NONBLOCK > 0:
            retval = retval + ' NONBLOCK'
    if len(retval) == 0:
        retval = '0o%o' % flags
    return retval
