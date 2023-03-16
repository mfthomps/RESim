EPOLLIN = 0x001
EPOLLPRI = 0x002
EPOLLOUT = 0x004
EPOLLRDNORM = 0x040
EPOLLRDBAND = 0x080
EPOLLWRNORM = 0x100
EPOLLWRBAND = 0x200
EPOLLMSG = 0x400
EPOLLERR = 0x008
EPOLLHUP = 0x010
EPOLLRDHUP = 0x2000
EPOLLONESHOT = (1 << 30)
EPOLLET = (1 << 31)
def getEvent(cpu, mem_utils, events_ptr, lgr):
    retval = ''
    events = mem_utils.readWord32(cpu, events_ptr)
    if events is None:
        lgr.debug('epoll getEvent, events is None, reading from 0x%x' % ((events_ptr)))
        return retval
    data_ptr = mem_utils.readPtr(cpu, events_ptr+4)
    if data_ptr is None:
        lgr.debug('epoll getEvent, data_ptr is None, reading from 0x%x' % ((events_ptr+4)))
        return retval
    data_ptr2 = mem_utils.readPtr(cpu, events_ptr+8)
    if data_ptr2 is None:
        lgr.debug('epoll getEvent, data_ptr2 is None, reading from 0x%x' % ((events_ptr+8)))
        return retval
    value = mem_utils.readWord32(cpu, data_ptr)
    value2 = mem_utils.readWord32(cpu, data_ptr2)
    if data_ptr is not None:
        if value is None:
            lgr.debug('\t\tevents: 0x%x ptr 0x%x ' % (events, data_ptr)) 
            retval = retval+('\t\tevents: 0x%x ptr 0x%x \n' % (events, data_ptr)) 
        else:
            lgr.debug('\t\tevents: 0x%x ptr 0x%x value: 0x%x' % (events, data_ptr, value)) 
            retval = retval+('\t\tevents: 0x%x ptr 0x%x value: 0x%x\n' % (events, data_ptr, value)) 
        if value2 is None:
            lgr.debug('\t\tptr2 0x%x ' % (data_ptr2)) 
            retval = retval+('\t\tptr2 0x%x \n' % (data_ptr2)) 
        else:
            lgr.debug('\t\tptr2 0x%x value: 0x%x' % (data_ptr2, value2)) 
            retval = retval+('\t\tptr2 0x%x value2: 0x%x\n' % (data_ptr2, value2)) 
    else:
        retval = retval+('\t\tCould not read data_ptr from 0x%x\n' % events_ptr) 
    return retval
