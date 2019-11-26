class WriteMarks():
    def __init__(self, mem_utils, cpu, lgr):
        self.mark_list = []
        self.mem_utils = mem_utils
        self.cpu = cpu
        self.lgr = lgr
        self.prev_ip = []

    def showMarks(self):
        i = 0
        for mark in self.mark_list:
            print('%d %s  ip:0x%x' % (i, mark.mark.getMsg(), mark.ip))
            i += 1
        
    class WatchMark():
        ''' Objects that are listed as watch marks -- highest level stored in mark_list'''
        def __init__(self, cycle, ip, mark):
            self.cycle = cycle
            self.ip = ip
            self.mark = mark
        def getJson(self):
            retval = {}
            retval['cycle'] = self.cycle
            retval['ip'] = self.ip
            retval['msg'] = self.mark.getMsg()
            retval['start'] = self.mark.addr
            retval['end'] = self.mark.end_addr
            retval['size'] = self.mark.size
            return retval

    class DataMark():
        def __init__(self, addr, size):
            self.addr = addr
            ''' bytes written per instruction '''
            self.size = size
            ''' track ranges '''
            self.end_addr = None

        def getMsg(self):
            if self.end_addr is None:
                mark_msg = 'Wrote %d bytes to 0x%08x' % (self.size, self.addr)
            else:
                length = self.end_addr - self.addr + 1
                mark_msg = 'Iterate writes of %d bytes over 0x%08x-0x%08x (%d bytes)' % (self.size, self.addr, 
                     self.end_addr, length)
            return mark_msg

        def addrRange(self, addr, size):
            retval = False
            if self.end_addr is None:
                if addr == (self.addr+self.size):
                    self.end_addr = addr+size-1
                    retval = True
            else:
                if addr == self.end_addr+1:
                    self.end_addr = addr+size-1
                    retval = True
            return retval 

    def recordIP(self, ip):
        self.prev_ip.append(ip)
        if len(self.prev_ip) > 1:
            self.prev_ip.pop(0)

    def dataWrite(self, addr, size): 
        ip = self.mem_utils.getRegValue(self.cpu, 'pc')
        ''' TBD generalize for loops that make multiple refs? '''
        if ip not in self.prev_ip:
            dm = self.DataMark(addr, size)
            self.mark_list.append(self.WatchMark(self.cpu.cycles, ip, dm))
            self.lgr.debug('WriteMarks dataWrite ip:0x%x %s' % (ip, dm.getMsg()))
            self.prev_ip = []
        else:
            if len(self.prev_ip) > 0:
                prev_mark = self.mark_list[-1]
                self.lgr.debug('prev_mark class is %s' % prev_mark.mark.__class__.__name__)
                if isinstance(prev_mark.mark, self.DataMark):
                    if prev_mark.mark.addrRange(addr, size):
                        self.lgr.debug('writeMarks dataWrite ip:0x%x size: %d is range addr 0x%x' % (ip, size, addr))
                    else:
                        dm = self.DataMark(addr, size)
                        self.mark_list.append(self.WatchMark(self.cpu.cycles, ip, dm))
                        self.lgr.debug('writeMarks dataWrite same IP as previous DataMark, not contiguous ip:0x%x %s' % (ip, dm.getMsg()))
                else:
                    dm = self.DataMark(addr, size)
                    self.mark_list.append(self.WatchMark(self.cpu.cycles, ip, dm))
                    self.lgr.debug('writeMarks dataWrite followed something other than DataMark ip:0x%x %s' % (ip, dm.getMsg()))
            else:
                self.lgr.error('writeMarks dataWrite, len of prev_ip is zero?')
        self.recordIP(ip)

    def getWatchMarks(self):
        retval = []
        for mark in self.mark_list:
            retval.append(mark.getJson())
        self.lgr.debug('writeMarks getWatchMarks return %d items' % len(retval))
        return retval        

    def getCycle(self, index):
        self.lgr.debug('writeMarks getCycle index %d len %s' % (index, len(self.mark_list)))
        if index < len(self.mark_list):
            return self.mark_list[index].cycle
        else:
            return None

