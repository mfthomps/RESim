class WatchMarks():
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
        
    class CallMark():
        def __init__(self, msg, max_len, recv_addr):
            self.msg = msg
            self.max_len = max_len
            self.recv_addr = recv_addr
        def getMsg(self):
            return self.msg

    class CopyMark():
        def __init__(self, src, dest, length, buf_start):
            self.src = src
            self.dest = dest
            self.length = length
            self.buf_start = buf_start
            if buf_start is not None:
                offset = src - buf_start
                self.msg = 'Copy %d bytes from 0x%x to 0x%x. (from offset %d into buffer at 0x%x)' % (length, src, dest, offset, buf_start)
            else:
                self.msg = 'Copy %d bytes from 0x%x to 0x%x. (Source buffer starts before known buffers!)' % (length, src, dest)
        def getMsg(self):
            return self.msg

    class SetMark():
        def __init__(self, dest, length, buf_start):
            self.dest = dest
            self.length = length
            self.buf_start = buf_start
            offset = dest - buf_start
            self.msg = 'memset %d bytes starting 0x%x (offset %d into buffer at 0x%x)' % (length, dest, offset, buf_start)
        def getMsg(self):
            return self.msg

    class DataMark():
        def __init__(self, addr, start, length, cmp_ins):
            self.addr = addr
            if addr is not None:
                self.offset = addr - start
            else:
                self.offset = None
            self.start = start
            self.length = length
            self.cmp_ins = cmp_ins
            self.end_addr = None
            self.loop_count = 0

        def getMsg(self):
            if self.addr is None:
                mark_msg = 'Memory mod, original buffer %d bytes starting at 0x%x' % (self.length, self.start)
            elif self.end_addr is None:
                mark_msg = 'Read from 0x%08x offset %4d into 0x%8x (buf size %4d) %s' % (self.addr, self.offset, self.start, self.length, self.cmp_ins)
            else:
                length = self.end_addr- self.addr + 1
                mark_msg = 'Iterate %d times over 0x%08x-0x%08x (%d bytes) starting offset %4d into 0x%8x (buf size %4d) %s' % (self.loop_count, self.addr, 
                     self.end_addr, length, self.offset, self.start, self.length, self.cmp_ins)
            return mark_msg

        def addrRange(self, addr):
            self.end_addr = addr
            self.loop_count += 1

    class KernelMark():
        def __init__(self, addr, count, callnum, fd):
            self.addr = addr
            self.count = count
            self.callnum = callnum
            self.fd = fd
            self.msg = 'Kernel read %d bytes from 0x%x call_num: %d FD: %d' % (count, addr, callnum, fd)
        def getMsg(self):
            return self.msg

    class CompareMark():
        def __init__(self, ours, theirs, count, the_str, buf_start):
            self.the_str = the_str
            self.ours = ours    
            self.theirs = theirs    
            self.count = count    
            if buf_start is not None:
                offset = ours - buf_start
                self.msg = 'memcmp 0x%x (%d bytes into buffer at 0x%x) to %s (at 0x%x, %d bytes)' % (ours, offset, buf_start, self.the_str, theirs, count)
            else:
                self.msg = 'memcmp 0x%x (unknown buffer) to %s (at 0x%x, %d bytes)' % (ours, self.the_str, theirs, count)
        def getMsg(self):
            return self.msg

    class StrChrMark():
        def __init__(self, ours, the_chr, count):
            self.the_chr = the_chr
            self.ours = ours    
            self.count = count    
            if self.the_chr > 20:
                self.msg = 'strchr in string at 0x%x find 0x%x(%s) ' % (ours, self.the_chr, chr(self.the_chr))
            else:
                self.msg = 'strchr in string at 0x%x find 0x%x' % (ours, self.the_chr)
        def getMsg(self):
            return self.msg

    class IteratorMark():
        def __init__(self, fun, addr, buf_start): 
            self.fun = fun
            self.addr = addr
            offset = addr - buf_start
            self.msg = 'iterator %s %x (%d bytes into buffer at 0x%x)' % (fun, addr, offset, buf_start)
        def getMsg(self):
            return self.msg

    class WatchMark():
        ''' Objects that are listed as watch marks -- highest level stored in mark_list'''
        def __init__(self, cycle, ip, msg):
            self.cycle = cycle
            self.ip = ip
            self.mark = msg
        def getJson(self):
            retval = {}
            retval['cycle'] = self.cycle
            retval['ip'] = self.ip
            retval['msg'] = self.mark.getMsg()
            return retval

    def recordIP(self, ip):
        self.prev_ip.append(ip)
        if len(self.prev_ip) > 4:
            self.prev_ip.pop(0)

    def markCall(self, msg, max_len, recv_addr=None):
        ip = self.mem_utils.getRegValue(self.cpu, 'pc')
        cm = self.CallMark(msg, max_len, recv_addr)
        ''' HACK to account for recv recorded while  about to leave kernel '''
        cycles = self.cpu.cycles
        if recv_addr is not None:
            cycles=cycles+1
        self.mark_list.append(self.WatchMark(cycles, ip, cm))
        if recv_addr is None:
            self.lgr.debug('watchMarks markCall 0x%x %s' % (ip, msg))
        else:
            self.lgr.debug('watchMarks markCall 0x%x %s recv_addr: 0x%x' % (ip, msg, recv_addr))
        self.recordIP(ip)
  
    def memoryMod(self, start, length):
        ip = self.mem_utils.getRegValue(self.cpu, 'pc')
        dm = self.DataMark(None, start, length, None)
        self.mark_list.append(self.WatchMark(self.cpu.cycles, ip, dm))
        self.lgr.debug('watchMarks memoryMod 0x%x %s appended, len of mark_list now %d' % (ip, dm.getMsg(), len(self.mark_list)))
 
    def dataRead(self, addr, start, length, cmp_ins): 
        ip = self.mem_utils.getRegValue(self.cpu, 'pc')
        ''' TBD generalize for loops that make multiple refs? '''
        if ip not in self.prev_ip:
            dm = self.DataMark(addr, start, length, cmp_ins)
            self.mark_list.append(self.WatchMark(self.cpu.cycles, ip, dm))
            self.lgr.debug('watchMarks dataRead 0x%x %s appended, len of mark_list now %d' % (ip, dm.getMsg(), len(self.mark_list)))
            self.prev_ip = []
        else:
            if len(self.prev_ip) > 0:
                pm = self.mark_list[-1]
                self.lgr.debug('pm class is %s' % pm.mark.__class__.__name__)
                if isinstance(pm.mark, self.DataMark):
                    pm.mark.addrRange(addr)
                    self.lgr.debug('watchMarks dataRead 0x%x range 0x%x' % (ip, addr))
                else:
                    dm = self.DataMark(addr, start, length, cmp_ins)
                    self.mark_list.append(self.WatchMark(self.cpu.cycles, ip, dm))
                    self.lgr.debug('watchMarks dataRead followed something other than DataMark 0x%x %s' % (ip, dm.getMsg()))
        self.recordIP(ip)

    def getMarkFromIndex(self, index):
        if index < len(self.mark_list):
            return self.mark_list[index]
        else:
            return None

    def getWatchMarks(self):
        retval = []
        for mark in self.mark_list:
            retval.append(mark.getJson())
        return retval        

    def getCycle(self, index):
        self.lgr.debug('watchMarks getCycle index %d len %s' % (index, len(self.mark_list)))
        if index < len(self.mark_list):
            return self.mark_list[index].cycle
        else:
            return None

    def removeRedundantDataMark(self, dest):
        if len(self.prev_ip) > 0:
            pm = self.mark_list[-1]
            if isinstance(pm.mark, self.DataMark):
                if pm.mark.addr == dest:
                    ''' a copy record for the same data read previously recorded, remove the redundant data read '''
                    del self.mark_list[-1]

    def copy(self, src, dest, length, buf_start):
        ip = self.mem_utils.getRegValue(self.cpu, 'pc')
        cm = self.CopyMark(src, dest, length, buf_start)
        self.lgr.debug('watchMarks copy 0x%x %s' % (ip, cm.getMsg()))
        self.removeRedundantDataMark(dest)
        self.mark_list.append(self.WatchMark(self.cpu.cycles, ip, cm))
        

    def memset(self, dest, length, buf_start):
        ip = self.mem_utils.getRegValue(self.cpu, 'pc')
        sm = self.SetMark(dest, length, buf_start)
        self.mark_list.append(self.WatchMark(self.cpu.cycles, ip, sm))
        self.lgr.debug('watchMarks memset 0x%x %s' % (ip, sm.getMsg()))

    def kernel(self, addr, count, frame):
        ip = self.mem_utils.getRegValue(self.cpu, 'pc')
        callnum = self.mem_utils.getCallNum(self.cpu)
        fd = frame['param1']
        km = self.KernelMark(addr, count, callnum, fd)
        self.mark_list.append(self.WatchMark(self.cpu.cycles, ip, km))
        self.lgr.debug('watchMarks kernel 0x%x %s' % (ip, km.getMsg()))

    def compare(self, ours, theirs, count, buf_start):
        ip = self.mem_utils.getRegValue(self.cpu, 'pc')
        if count > 0:
            the_str = self.mem_utils.readString(self.cpu, theirs, count)
       
            if the_str is not None:
                the_str = the_str.decode('ascii', 'replace')
        else:
            the_str = ''
        cm = self.CompareMark(ours, theirs, count, the_str, buf_start) 
        self.removeRedundantDataMark(ours)
        self.mark_list.append(self.WatchMark(self.cpu.cycles, ip, cm))
        self.lgr.debug('watchMarks compare 0x%x %s' % (ip, cm.getMsg()))

    def strchr(self, ours, the_chr, count):
        ip = self.mem_utils.getRegValue(self.cpu, 'pc')
        cm = self.StrChrMark(ours, the_chr, count)
        self.removeRedundantDataMark(ours)
        self.mark_list.append(self.WatchMark(self.cpu.cycles, ip, cm))
        self.lgr.debug('watchMarks strchr 0x%x %s' % (ip, cm.getMsg()))

    def iterator(self, fun, src, buf_start):
        ip = self.mem_utils.getRegValue(self.cpu, 'pc')
        im = self.IteratorMark(fun, src, buf_start)
        self.mark_list.append(self.WatchMark(self.cpu.cycles, ip, im))        
        self.lgr.debug('watchMarks iterator 0x%x %s' % (ip, im.getMsg()))

    def clearWatchMarks(self): 
        del self.mark_list[:] 
        self.prev_ip = []

    def firstBufferAddress(self):
        retval = None
        for mark in self.mark_list:
           self.lgr.debug('check mark type %s' % type(mark.mark))
           if isinstance(mark.mark, self.CallMark) and mark.mark.recv_addr is not None:
               self.lgr.debug('watchMarks firstBufferAddress is CallMark addr 0x%x' % mark.mark.recv_addr)
               retval = mark.mark.recv_addr
               break
           elif isinstance(mark.mark, self.DataMark):
               self.lgr.debug('watchMarks firstBufferAddress is DataMark addr 0x%x' % mark.mark.start)
               retval = mark.mark.start
               break 

        return retval

    def firstBufferIndex(self):
        retval = None
        index = 0
        for mark in self.mark_list:
           if isinstance(mark.mark, self.CallMark) and mark.mark.recv_addr is not None:
               self.lgr.debug('watchMarks firstBufferIndex is CallMark addr 0x%x' % mark.mark.recv_addr)
               retval = index
               break
           elif isinstance(mark.mark, self.DataMark):
               self.lgr.debug('watchMarks firstBufferIndex is DataMark addr 0x%x' % mark.mark.start)
               retval = index
               break 
           index += 1
        return retval
