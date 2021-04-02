from simics import Sim_Trans_Load
import pickle
import os
class WatchMarks():
    def __init__(self, mem_utils, cpu, cell_name, run_from_snap, lgr):
        self.mark_list = []
        self.mem_utils = mem_utils
        self.cpu = cpu
        self.cell_name = cell_name
        self.lgr = lgr
        self.call_cycle = None
        self.prev_ip = []
        self.recent_buf_address = None
        self.recent_buf_max_len = None
        if run_from_snap is not None:
            self.loadPickle(run_from_snap)

    def saveMarks(self, fpath):
        with open(fpath, 'w') as fh:
            i = 0
            for mark in self.mark_list:
                the_str = mark.mark.getMsg().encode('utf-8', 'ignore')
                fh.write('%d %s  ip:0x%x\n' % (i, the_str, mark.ip))
                i += 1

    def showMarks(self):
        i = 0
        for mark in self.mark_list:
            print('%d %s  ip:0x%x' % (i, mark.mark.getMsg(), mark.ip))
            i += 1
        
    class CallMark():
        def __init__(self, msg, max_len, recv_addr, length):
            self.msg = msg
            self.max_len = max_len
            self.recv_addr = recv_addr
            self.len = length
        def getMsg(self):
            return self.msg

    class CopyMark():
        def __init__(self, src, dest, length, buf_start, op_type, strcpy=False):
            self.src = src
            self.dest = dest
            self.length = length
            self.buf_start = buf_start
            self.op_type = op_type
            self.strcpy = strcpy
            if op_type == Sim_Trans_Load:
                if buf_start is not None:
                    offset = src - buf_start
                    self.msg = 'Copy %d bytes from 0x%x to 0x%x. (from offset %d into buffer at 0x%x)' % (length, src, dest, offset, buf_start)
                else:
                    self.msg = 'Copy %d bytes from 0x%x to 0x%x. (Source buffer starts before known buffers!)' % (length, src, dest)
            else:
                if buf_start is not None:
                    offset = src - buf_start
                    self.msg = 'Modify Copy %d bytes from 0x%x to 0x%x. (from offset %d into buffer at 0x%x)' % (length, src, dest, offset, buf_start)
                else:
                    self.msg = 'Modify Copy %d bytes from 0x%x to 0x%x. Buffer unknown!)' % (length, src, dest, )
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
        def __init__(self, addr, start, length, cmp_ins, modify=False):
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
            self.modify = modify

        def getMsg(self):
            if self.addr is None or self.start is None:
                mark_msg = 'Error getting mark message'
            elif self.modify:
                mark_msg = 'Memory mod, addr: 0x%x original buffer %d bytes starting at 0x%x' % (self.addr, self.length, self.start)
            elif self.addr is None:
                mark_msg = 'Memory mod reset, original buffer %d bytes starting at 0x%x' % (self.length, self.start)
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
        def __init__(self, fun, ours, theirs, count, src_str, dest_str, buf_start):
            self.src_str = src_str
            self.dst_str = dest_str
            self.fun = fun
            self.ours = ours    
            self.theirs = theirs    
            self.count = count    
            if buf_start is not None:
                offset = ours - buf_start
                self.msg = '%s 0x%x %s (%d bytes into buffer at 0x%x) to %s (at 0x%x, %d bytes)' % (fun, ours, src_str, offset, buf_start, dest_str, theirs, count)
            else:
                self.msg = '%s 0x%x %s (unknown buffer) to %s (at 0x%x, %d bytes)' % (fun, ours, src_str, dest_str, theirs, count)
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

    class ScanMark():
        def __init__(self, src, dest, count):
            self.src = src    
            self.dest = dest    
            self.count = count    
            if dest is None:
                self.msg = 'sscanf failed to parse from 0x%x' % src
            else:
                self.msg = 'sscanf src 0x%x to 0x%x' % (src, dest)

        def getMsg(self):
            return self.msg

    class XMLPropMark():
        def __init__(self, src, count, the_str, result):
            self.src = src    
            self.count = count    
            self.msg = 'xmlProp %s src 0x%x len %d. Prop: %s' % (the_str, src, count, result)

        def getMsg(self):
            return self.msg

    class InetAddrMark():
        def __init__(self, src, count, the_str):
            self.src = src    
            self.count = count    
            self.msg = 'InetAddr %s src 0x%x len %d' % (the_str, src, count)

        def getMsg(self):
            return self.msg

    class LenMark():
        def __init__(self, src, count):
            self.src = src    
            self.count = count    
            self.msg = 'strlen src 0x%x len %d' % (src, count)

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

    class MallocMark():
        def __init__(self, addr, size):
            self.addr = addr
            self.size = size
            self.msg = 'malloc addr: 0x%x size: %d' % (addr, size)
        def getMsg(self):
            return self.msg

    class FreeMark():
        def __init__(self, addr):
            self.addr = addr
            self.msg = 'free addr: 0x%x' % (addr)
        def getMsg(self):
            return self.msg

    class FreeXMLMark():
        def __init__(self):
            self.msg = 'FreeXMLDoc'
        def getMsg(self):
            return self.msg

    class XMLParseFileMark():
        def __init__(self, addr, size):
            self.addr = addr
            self.size = size
            self.msg = 'xmlParseFile addr: 0x%x size: %d' % (addr, size)
        def getMsg(self):
            return self.msg

    class GetTokenMark():
        def __init__(self, src, dest, the_string):
            self.addr = src
            self.msg = 'GetToken addr: 0x%x token: %s' % (src, the_string)
        def getMsg(self):
            return self.msg

    class StrPtr():
        def __init__(self, fun, the_string):
            self.msg = '%s string: %s' % (fun, the_string)
        def getMsg(self):
            return self.msg

    class ReturnInt():
        def __init__(self, fun, value):
            self.msg = '%s value: %s' % (fun, value)
        def getMsg(self):
            return self.msg

    class WatchMark():
        ''' Objects that are listed as watch marks -- highest level stored in mark_list'''
        def __init__(self, return_cycle, call_cycle, ip, msg):
            self.cycle = return_cycle
            self.call_cycle = call_cycle
            self.ip = ip
            self.mark = msg
        def getJson(self, origin):
            retval = {}
            retval['cycle'] = self.cycle - origin
            retval['ip'] = self.ip
            retval['msg'] = self.mark.getMsg()
            return retval

    def recordIP(self, ip):
        self.prev_ip.append(ip)
        if len(self.prev_ip) > 4:
            self.prev_ip.pop(0)

    def markCall(self, msg, max_len, recv_addr=None, length=None):
        ip = self.mem_utils.getRegValue(self.cpu, 'pc')
        cm = self.CallMark(msg, max_len, recv_addr, length)
        ''' HACK to account for recv recorded while  about to leave kernel '''
        cycles = self.cpu.cycles
        if recv_addr is not None:
            cycles=cycles+1
        self.addWatchMark(ip, cm, cycles=cycles)
        if recv_addr is None:
            self.lgr.debug('watchMarks markCall 0x%x %s' % (ip, msg))
        else:
            self.lgr.debug('watchMarks markCall 0x%x %s recv_addr: 0x%x' % (ip, msg, recv_addr))
            if self.recent_buf_address is None:
                self.recent_buf_address = recv_addr
                self.recent_buf_max_len = max_len
        self.recordIP(ip)
  
    def memoryMod(self, start, length, addr=None):
        ip = self.mem_utils.getRegValue(self.cpu, 'pc')
        dm = self.DataMark(addr, start, length, None, modify=True)
        self.addWatchMark(ip, dm)
        self.lgr.debug('watchMarks memoryMod 0x%x %s appended, len of mark_list now %d' % (ip, dm.getMsg(), len(self.mark_list)))
 
    def dataRead(self, addr, start, length, cmp_ins): 
        ip = self.mem_utils.getRegValue(self.cpu, 'pc')
        ''' TBD generalize for loops that make multiple refs? '''
        if ip not in self.prev_ip:
            dm = self.DataMark(addr, start, length, cmp_ins)
            self.addWatchMark(ip, dm)
            self.lgr.debug('watchMarks dataRead 0x%x %s appended, cycle: 0x%x len of mark_list now %d' % (ip, dm.getMsg(), self.cpu.cycles, len(self.mark_list)))
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
                    self.addWatchMark(ip, dm)
                    self.lgr.debug('watchMarks dataRead followed something other than DataMark 0x%x %s' % (ip, dm.getMsg()))
        self.recordIP(ip)

    def getMarkFromIndex(self, index):
        if index < len(self.mark_list):
            return self.mark_list[index]
        else:
            return None

    def getWatchMarks(self, origin=0):
        retval = []
        for mark in self.mark_list:
            retval.append(mark.getJson(origin))
        return retval        

    def getCycle(self, index):
        if index < len(self.mark_list):
            #self.lgr.debug('watchMarks getCycle index %d len %s cycle: 0x%x' % (index, len(self.mark_list), self.mark_list[index].cycle))
            return self.mark_list[index].cycle
        else:
            return None

    def removeRedundantDataMark(self, dest):
        if len(self.prev_ip) > 0:
            pm = self.mark_list[-1]
            if isinstance(pm.mark, self.DataMark):
                if pm.mark.addr == dest:
                    ''' a copy record for the same data read previously recorded, remove the redundant data read '''
                    self.lgr.debug('watchMarks removeRedundantDataMark ')
                    del self.mark_list[-1]

    def getMarkCopyOffset(self, address):
        ''' Intended for reverse data tracking. If a CopyMark is found encompassing the given cycle, return the 
            source address that corresponds to the given destination address. '''
        retval = None
        ret_mark = None
        cycle = self.cpu.cycles
        for mark in self.mark_list:
            if cycle >= mark.call_cycle and cycle <= mark.cycle:
                if mark.mark.__class__.__name__ == 'CopyMark':
                    offset = address - mark.mark.dest
                    retval = mark.mark.src+offset
                    ret_mark = mark
                else:
                    self.lgr.debug('watchMarks getMarkCopyOffset found cycle, but not a copy, is type %s. %s' % (mark.mark.__class__.__name__, mark.mark.getMsg()))
                break
        return retval, ret_mark

    def getCopyMark(self):
        ''' If currently in a copy function, return the associated mark '''
        retval = None
        cycle = self.cpu.cycles
        for mark in self.mark_list:
            if cycle >= mark.call_cycle and cycle <= mark.cycle:
                if mark.mark.__class__.__name__ == 'CopyMark':
                    retval = mark
                    break
        return retval
        
                
    def addWatchMark(self, ip, msg, cycles=None):
        if cycles is None:
            cycles = self.cpu.cycles
        wm = self.WatchMark(cycles, self.call_cycle, ip, msg)
        self.mark_list.append(wm)
        self.lgr.debug('addWatchMark len now %d' % len(self.mark_list))
        return wm

    def copy(self, src, dest, length, buf_start, op_type, strcpy=False):
        ip = self.mem_utils.getRegValue(self.cpu, 'pc')
        cm = self.CopyMark(src, dest, length, buf_start, op_type, strcpy)
        self.lgr.debug('watchMarks copy 0x%x %s' % (ip, cm.getMsg()))
        #self.removeRedundantDataMark(dest)
        wm = self.addWatchMark(ip, cm)
        return wm
        

    def memset(self, dest, length, buf_start):
        ip = self.mem_utils.getRegValue(self.cpu, 'pc')
        sm = self.SetMark(dest, length, buf_start)
        self.addWatchMark(ip, sm)
        self.lgr.debug('watchMarks memset 0x%x %s' % (ip, sm.getMsg()))

    def kernel(self, addr, count, frame):
        ip = self.mem_utils.getRegValue(self.cpu, 'pc')
        callnum = self.mem_utils.getCallNum(self.cpu)
        fd = frame['param1']
        km = self.KernelMark(addr, count, callnum, fd)
        self.addWatchMark(ip, km)
        self.lgr.debug('watchMarks kernel 0x%x %s' % (ip, km.getMsg()))

    def compare(self, fun, dest, src, count, buf_start):
        ip = self.mem_utils.getRegValue(self.cpu, 'pc')
        if count > 0:
            dst_str = self.mem_utils.readString(self.cpu, dest, count)
            if dst_str is not None:
                dst_str = dst_str.decode('ascii', 'replace')
            src_str = self.mem_utils.readString(self.cpu, src, count)
            if src_str is not None:
                src_str = src_str.decode('ascii', 'replace')
        else:
            dst_str = ''
            src_str = ''
        cm = self.CompareMark(fun, dest, src, count, src_str, dst_str, buf_start) 
        self.addWatchMark(ip, cm)
        self.lgr.debug('watchMarks compare (%s) 0x%x %s' % (fun, ip, cm.getMsg()))

    def strchr(self, ours, the_chr, count):
        ip = self.mem_utils.getRegValue(self.cpu, 'pc')
        cm = self.StrChrMark(ours, the_chr, count)
        self.removeRedundantDataMark(ours)
        self.addWatchMark(ip, cm)
        self.lgr.debug('watchMarks strchr 0x%x %s' % (ip, cm.getMsg()))

    def sscanf(self, src, dest, count):
        ip = self.mem_utils.getRegValue(self.cpu, 'pc')
        sm = self.ScanMark(src, dest, count)        
        self.addWatchMark(ip, sm)
        self.lgr.debug('watchMarks sscanf 0x%x %s' % (ip, sm.getMsg()))


    def strlen(self, src, count):
        ip = self.mem_utils.getRegValue(self.cpu, 'pc')
        lm = self.LenMark(src, count)        
        self.addWatchMark(ip, lm)
        self.lgr.debug('watchMarks strlen 0x%x %s' % (ip, lm.getMsg()))

    def xmlGetProp(self, src, count, the_string, dest):
        ip = self.mem_utils.getRegValue(self.cpu, 'pc')
        result = 'Not found'
        if dest != 0:
            result = self.mem_utils.readString(self.cpu, dest, 20)
        xm = self.XMLPropMark(src, count, the_string, result)        
        self.addWatchMark(ip, xm)
        self.lgr.debug('watchMarks xmlGetProp 0x%x %s' % (ip, xm.getMsg()))

    def inet_addr(self, src, count, the_string):
        ip = self.mem_utils.getRegValue(self.cpu, 'pc')
        xm = self.InetAddrMark(src, count, the_string)        
        self.addWatchMark(ip, xm)
        self.lgr.debug('watchMarks inet_addr 0x%x %s' % (ip, xm.getMsg()))

    def iterator(self, fun, src, buf_start):
        ip = self.mem_utils.getRegValue(self.cpu, 'pc')
        im = self.IteratorMark(fun, src, buf_start)
        self.addWatchMark(ip, im)
        self.lgr.debug('watchMarks iterator 0x%x %s' % (ip, im.getMsg()))

    def malloc(self, addr, size):
        ip = self.mem_utils.getRegValue(self.cpu, 'pc')
        mm = self.MallocMark(addr, size)
        self.addWatchMark(ip, mm)
        self.lgr.debug('watchMarks malloc 0x%x %s' % (ip, mm.getMsg()))
    def free(self, addr):
        ip = self.mem_utils.getRegValue(self.cpu, 'pc')
        fm = self.FreeMark(addr)
        self.addWatchMark(ip, fm)
        self.lgr.debug('watchMarks free 0x%x %s' % (ip, fm.getMsg()))

    def freeXMLDoc(self):
        ip = self.mem_utils.getRegValue(self.cpu, 'pc')
        fm = self.FreeXMLMark()
        self.addWatchMark(ip, fm)

    def xmlParseFile(self, dest, count):
        ip = self.mem_utils.getRegValue(self.cpu, 'pc')
        fm = self.XMLParseFileMark(dest, count)
        self.addWatchMark(ip, fm)
      
    def getToken(self, src, dest, the_string):
        ip = self.mem_utils.getRegValue(self.cpu, 'pc')
        fm = self.GetTokenMark(src, dest, the_string)
        self.addWatchMark(ip, fm)

    def strPtr(self, dest, fun):
        ip = self.mem_utils.getRegValue(self.cpu, 'pc')
        the_string = self.mem_utils.readString(self.cpu, dest, 40)
        fm = self.StrPtr(fun, the_string)
        self.addWatchMark(ip, fm)

    def returnInt(self, count, fun):
        ip = self.mem_utils.getRegValue(self.cpu, 'pc')
        fm = self.ReturnInt(fun, count)
        self.addWatchMark(ip, fm)

    def clearWatchMarks(self): 
        self.lgr.debug('watchMarks clearWatchMarks')
        del self.mark_list[:] 
        self.prev_ip = []

    def firstBufferAddress(self):
        ''' address of first buffer '''
        retval = None
        ''' maximum length per initial read '''
        max_len = None
        for mark in self.mark_list:
           self.lgr.debug('check mark type %s' % type(mark.mark))
           if isinstance(mark.mark, self.CallMark) and mark.mark.recv_addr is not None:
               self.lgr.debug('watchMarks firstBufferAddress is CallMark addr 0x%x' % mark.mark.recv_addr)
               retval = mark.mark.recv_addr
               max_len = mark.mark.max_len
               break
           elif isinstance(mark.mark, self.DataMark):
               self.lgr.debug('watchMarks firstBufferAddress is DataMark addr 0x%x' % mark.mark.start)
               retval = mark.mark.start
               max_len = self.recent_buf_max_len
               break 
        if retval is not None:
            self.recent_buf_address = retval
            self.recent_buf_max_len = max_len
            self.lgr.debug('watchMarks firstBuffer address 0x%x' % retval)
        elif self.recent_buf_address is not None:
            #self.lgr.debug('watchMarks firstBufferAddress, no marks, using recent 0x%x' % self.recent_buf_address)
            retval = self.recent_buf_address
            max_len = self.recent_buf_max_len
        else:
            self.lgr.error('watchMarks, no recent_buf_address was recorded')
        return retval, max_len

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

    def nextWatchMark(self):
        retval = None
        cur_cycle = self.cpu.cycles
        index = 0
        for mark in self.mark_list:
            if mark.cycle > cur_cycle:
                retval = index
                break
            index += 1
        return retval

    def undoMark(self):
        self.mark_list.pop()

    def latestCycle(self):
        latest_mark = self.mark_list[-1]
        return latest_mark.cycle

    def registerCallCycle(self):
        self.call_cycle = self.cpu.cycles
      
    def getCallCycle(self):
        return self.call_cycle

    def loadPickle(self, name):
        mark_file = os.path.join('./', name, self.cell_name, 'watchMarks.pickle')
        if os.path.isfile(mark_file):
            pickDict = pickle.load( open(mark_file, 'rb') ) 
            self.recent_buf_address = pickDict['recent_buf_address'] 
            self.recent_buf_max_len = pickDict['recent_buf_max_len'] 

    def pickleit(self, name):
        mark_file = os.path.join('./', name, self.cell_name, 'watchMarks.pickle')
        pickDict = {}
        pickDict['recent_buf_address'] = self.recent_buf_address
        pickDict['recent_buf_max_len'] = self.recent_buf_max_len
        self.lgr.debug('watchMarks pickleit to %s recent_buf_addres: %s' % (mark_file, str(self.recent_buf_address)))
        pickle.dump( pickDict, open( mark_file, "wb") ) 
