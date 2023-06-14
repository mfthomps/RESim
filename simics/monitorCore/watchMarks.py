from simics import Sim_Trans_Load
import pickle
import json
import os
import sys
class CallMark():
    def __init__(self, msg, max_len, recv_addr, length, fd, is_lib=False):
        if recv_addr is not None:
            if max_len is not None:
                self.msg = '%s addr: 0x%x  length: %d max_len: %d' % (msg, recv_addr, length, max_len)
            else:
                self.msg = '%s addr: 0x%x  length: %d' % (msg, recv_addr, length)
             
        else:
            self.msg = msg
        self.max_len = max_len
        self.recv_addr = recv_addr
        self.len = length
        self.fd = fd
        self.is_lib = is_lib
    def getMsg(self):
        return self.msg

class CopyMark():
    def __init__(self, src, dest, length, buf_start, op_type, strcpy=False, sp=None, truncated=None):
        self.src = src
        self.dest = dest
        self.length = length
        self.buf_start = buf_start
        self.op_type = op_type
        self.strcpy = strcpy
        self.sp = sp
        if op_type == Sim_Trans_Load:
            if buf_start is not None:
                offset = src - buf_start
                trunc_string = ''
                if truncated is not None:
                    trunc_string = ' (trucated from %d)' % truncated        
                self.msg = 'Copy %d bytes%s from 0x%08x to 0x%08x . (from offset %d into buffer at 0x%x)' % (length, trunc_string, src, dest, offset, buf_start)
            else:
                self.msg = 'Copy %d bytes from 0x%x to 0x%08x . (Source buffer starts before known buffers!)' % (length, src, dest)
        else:
            if buf_start is not None:
                if dest == buf_start:
                    self.msg = 'Modify Copy %d bytes from 0x%08x to 0x%08x . (to start of buffer at 0x%x)' % (length, src, dest, buf_start)
                else:
                    offset = dest - buf_start
                    self.msg = 'Modify Copy %d bytes from 0x%08x to 0x%08x . (to offset %d into buffer at 0x%x)' % (length, src, dest, offset, buf_start)
            elif length is not None:
                self.msg = 'Modify Copy %d bytes from 0x%08x to 0x%08x . Buffer unknown!)' % (length, src, dest, )
            else:
                self.msg = 'Modify Copy length is none, not where wth'
    def getMsg(self):
        return self.msg

class SetMark():
    def __init__(self, dest, length, buf_start, lgr):
        self.dest = dest
        self.length = length
        self.buf_start = buf_start
        if buf_start is not None:
            offset = dest - buf_start
            self.msg = 'memset %d bytes starting 0x%x (offset %d into buffer at 0x%x)' % (length, dest, offset, buf_start)
        else:
            offset = 0
            self.msg = 'memset %d bytes starting 0x%x **Not a known buffer' % (length, dest)
            lgr.debug(self.msg)
    def getMsg(self):
        return self.msg

class DataMark():
    def __init__(self, addr, start, length, cmp_ins, trans_size, lgr, modify=False, ad_hoc=False, dest=None, sp=None, note=None, value=None):
        self.lgr = lgr
        self.addr = addr
        ''' offset into the buffer starting at start '''
        if addr is not None:
            self.offset = addr - start
        else:
            self.offset = None
        ''' start is the start of the accessed buffer '''
        self.start = start
        ''' length of the accessed buffer '''
        self.length = length
        self.cmp_ins = cmp_ins
        ''' only used if multiple iterations, or ad-hoc data copy.  reflects the last address read from.'''
        if ad_hoc:
            self.end_addr = addr+trans_size-1
            #self.lgr.debug('DataMark ad_hoc end_addr is now 0x%x' % self.end_addr)
        else:
            self.end_addr = None
        self.loop_count = 0
        self.modify = modify
        self.ad_hoc = ad_hoc
        self.trans_size = trans_size
        self.dest = dest
        self.sp = sp
        self.note = note
        self.value = value
        ''' keep value after a reset '''
        self.was_ad_hoc = False
        #self.lgr.debug('DataMark addr 0x%x start 0x%x length %d, offset %d' % (addr, start, length, self.offset))

    def getMsg(self):
        if self.start is None:
            mark_msg = 'Error getting mark message'
        elif self.modify and self.addr is not None:
            mark_msg = 'Write %d to  0x%08x offset %4d into 0x%08x (buf size %4d)' % (self.trans_size, self.addr, self.offset, self.start, self.length)
        elif self.addr is None:
            mark_msg = 'Memory mod reset, original buffer %d bytes starting at 0x%x' % (self.length, self.start)
        elif self.end_addr is None:
            offset_string = ''
            if self.offset != 0 or self.trans_size != self.length:
                offset_string = 'offset %4d into 0x%08x (buf size %4d)' % (self.offset, self.start, self.length)
            if self.note is None:
                mark_msg = 'Read %d from 0x%08x %s %s' % (self.trans_size, self.addr, offset_string, self.cmp_ins)
            else:
                mark_msg = '%s %d bytes into dest 0x%08x from 0x%08x %s %s' % (self.note, self.trans_size, self.dest, self.addr, offset_string, self.cmp_ins)
        elif self.ad_hoc or self.was_ad_hoc:
            copy_length = (self.end_addr - self.addr) + 1
            #self.lgr.debug('DataMark getMsg ad-hoc length is %d' % copy_length)
            if self.start is not None:
                if copy_length == self.length and self.start == self.addr:
                    mark_msg = 'Copy %d bytes from 0x%08x to 0x%08x . Ad-hoc' % (copy_length, self.addr, self.dest)
                else: 
                    offset = self.addr - self.start
                    mark_msg = 'Copy %d bytes from 0x%08x to 0x%08x . Ad-hoc (from offset %d into buffer at 0x%x)' % (copy_length, self.addr, self.dest, offset, self.start)
            else:
                mark_msg = 'Copy %d bytes from 0x%08x to 0x%08x . Ad-hoc (Source buffer starts before known buffers!)' % (copy_length, self.addr, self.dest)
        else:
            copy_length = self.end_addr- self.addr + 1
            mark_msg = 'Iterate %d times over 0x%08x-0x%08x (%d bytes) starting offset %4d into 0x%8x (buf size %4d) %s' % (self.loop_count, self.addr, 
                 self.end_addr, copy_length, self.offset, self.start, self.length, self.cmp_ins)
        return mark_msg

    def addrRange(self, addr):
        self.end_addr = addr
        self.loop_count += 1
        #self.lgr.debug('DataMark addrRange end_addr now 0x%x loop_count %d' % (self.end_addr, self.loop_count))

    def noAdHoc(self):
        if self.ad_hoc:
            self.was_ad_hoc = True
            self.ad_hoc = False

class KernelMark():
    def __init__(self, addr, count, callnum, fd):
        self.addr = addr
        self.count = count
        self.callnum = callnum
        self.fd = fd
        self.msg = 'Kernel read %d bytes from 0x%x call_num: %d FD: %d' % (count, addr, callnum, fd)
    def getMsg(self):
        return self.msg

class KernelModMark():
    def __init__(self, addr, count, callnum, fd):
        self.addr = addr
        self.count = count
        self.callnum = callnum
        self.fd = fd
        self.msg = 'Kernel overwrote %d bytes from 0x%x call_num: %d FD: %d' % (count, addr, callnum, fd)
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
    def __init__(self, start, the_chr, count):
        self.the_chr = the_chr
        self.start = start    
        self.count = count    
        if self.the_chr > 20 and self.the_chr < 256:
            self.msg = 'strchr in string at 0x%x find 0x%x(%s) ' % (start, self.the_chr, chr(self.the_chr))
        else:
            self.msg = 'strchr in string at 0x%x find 0x%x' % (start, self.the_chr)
    def getMsg(self):
        return self.msg

class StrtousMark():
    def __init__(self, fun, src):
        self.src = src
        self.msg = '%s at 0x%x' % (fun, self.src)
    def getMsg(self):
        return self.msg

class ScanMark():
    def __init__(self, src, dest, count, buf_start, sp):
        self.src = src    
        self.dest = dest    
        self.count = count    
        self.buf_start = buf_start    
        self.sp = sp    
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

class InetNtopMark():
    def __init__(self, dest, count, the_str):
        self.dest = dest    
        self.count = count    
        self.msg = 'InetAddr %s dest 0x%x len %d' % (the_str, dest, count)

    def getMsg(self):
        return self.msg

class LenMark():
    def __init__(self, src, count):
        self.src = src    
        self.count = count    
        self.msg = 'strlen src 0x%x len %d' % (src, count)

    def getMsg(self):
        return self.msg

class SprintfMark():
    def __init__(self, fun, src, dest, count, buf_start, sp):
        self.fun = fun    
        self.src = src    
        self.dest = dest    
        self.count = count    
        self.buf_start = buf_start    
        self.sp = sp    
        self.msg = '%s src: 0x%x dest 0x%x len %d' % (fun, src, dest, count)

    def getMsg(self):
        return self.msg

class FprintfMark():
    def __init__(self, fun, src):
        self.fun = fun    
        self.src = src    
        self.msg = '%s src 0x%x' % (fun, src)

    def getMsg(self):
        return self.msg

class FwriteMark():
    def __init__(self, fun, src, count):
        self.fun = fun    
        self.src = src    
        self.count = count    
        self.msg = '%s src 0x%x count %d' % (fun, src, count)

    def getMsg(self):
        return self.msg

class GlobMark():
    def __init__(self, fun, src, count):
        self.fun = fun    
        self.src = src    
        self.count = count    
        self.msg = '%s src 0x%x count %d' % (fun, src, count)

    def getMsg(self):
        return self.msg

class IteratorMark():
    def __init__(self, fun, addr, buf_start): 
        self.fun = fun
        self.addr = addr
        if buf_start is None:        
            self.msg = 'iterator %s %x No buffer start found?)' % (fun, addr)
        else:
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
    def __init__(self, addr, fun):
        self.addr = addr
        self.msg = '%s addr: 0x%x' % (fun, addr)
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

class ResetOrigin():
    def __init__(self, origin_watches, new_msg):
        if new_msg is None:
            self.msg = 'Reset origin with %d data watches' % len(origin_watches)
        else:
            self.msg = new_msg
        self.origin_watches = origin_watches
    def getMsg(self):
        return self.msg

class LogMark():
    def __init__(self, s, prefix):
        self.msg = '%s : %s' % (prefix, s)
    def getMsg(self):
        return self.msg

class PushMark():
    def __init__(self, addr, dest, buf_start, length, ip, push_size):
        self.addr = addr
        self.dest = dest
        self.length = length
        self.start = buf_start
        self.ip = ip
        if addr == buf_start and length == push_size:
            self.msg = 'push from 0x%x to 0x%x' % (addr, dest)
        else:
            offset = addr - buf_start
            self.msg = 'push from 0x%08x (offset %d within buffer starting at 0x%08x) to 0x%08x' % (addr, offset, buf_start, dest)
    def getMsg(self):
        return self.msg
 
class FGetsMark():
    def __init__(self, fun, addr, dest, count, start):
        self.addr = addr
        self.dest = dest
        self.length = count
        self.start = start
        if start is not None:
            offset = addr - start
            self.msg = 'fgets from 0x%08x (offset %d within buffer starting at 0x%08x) to 0x%08x' % (addr, offset, start, dest)
        else:
            self.msg = 'fgets from 0x%08x (unknown buffer?) to 0x%08x' % (addr, dest)
    def getMsg(self):
        return self.msg

class StringMark():
    def __init__(self, fun, src, dest, count, start):
        self.src = src
        self.dest = dest
        self.length = count
        self.start = start
        if start is not None:
            offset = src - start
            self.msg = '%s from 0x%08x (offset %d within buffer starting at 0x%08x) to 0x%08x %d bytes' % (fun, src, offset, start, dest, count)
        else:
            self.msg = '%s from 0x%08x (unknown buffer?) to 0x%08x %d bytes' % (fun, src, dest, count)
    def getMsg(self):
        return self.msg

class ReplaceMark():
    def __init__(self, fun, src, dest, pos, length, start):
        self.src = src
        self.dest = dest
        self.pos = pos
        self.length = length
        self.start = start
        if start is not None:
            offset = src - start
            self.msg = '%s from 0x%08x (offset %d within buffer starting at 0x%08x) to 0x%08x pos: %d, %d bytes' % (fun, src, offset, start, dest, pos, length)
        else:
            self.msg = '%s from 0x%08x (unknown buffer?) to 0x%08x pos %d, %d bytes' % (fun, src, dest, pos, length)
    def getMsg(self):
        return self.msg
class AppendMark():
    def __init__(self, fun, src, dest, length, start):
        self.src = src
        self.dest = dest
        self.length = length
        self.start = start
        if start is not None:
            offset = src - start
            self.msg = '%s from 0x%08x (offset %d within buffer starting at 0x%08x) to 0x%08x %d bytes' % (fun, src, offset, start, dest, length)
        else:
            self.msg = '%s from 0x%08x (unknown buffer?) to 0x%08x %d bytes' % (fun, src, dest, length)
    def getMsg(self):
        return self.msg
class AssignMark():
    def __init__(self, fun, src, dest, length, start):
        self.src = src
        self.dest = dest
        self.length = length
        self.start = start
        if start is not None:
            offset = src - start
            self.msg = '%s from 0x%08x (offset %d within buffer starting at 0x%08x) to 0x%08x %d bytes' % (fun, src, offset, start, dest, length)
        else:
            self.msg = '%s from 0x%08x (unknown buffer?) to 0x%08x %d bytes' % (fun, src, dest, length)
    def getMsg(self):
        return self.msg
class CharLookupMark():
    def __init__(self, addr, stuff, length):
        self.addr = addr
        self.end_addr = addr
        self.length = length
        self.stuff = stuff
    def extend(self):
        self.end_addr = self.end_addr+1
    def getMsg(self):
        if self.length is not None:
            length = self.length
        else:
            length = self.end_addr - self.addr
        msg = 'Char Lookup buffer at 0x%x len %d, %s' % (self.addr, length, self.stuff)
        return msg
class CharPtrMark():
    def __init__(self, addr, ptr, value):
        self.addr = addr
        self.ptr = ptr
        self.value = value
    def getMsg(self):
        msg = 'Char Ptr reference at 0x%x, pointer to 0x%x value: 0x%x' % (self.addr, self.ptr, self.value)
        return msg
class MscMark():
    def __init__(self, fun, addr):
        self.addr = addr
        if addr is not None:
            self.msg = '%s read 0x%x' % (fun, addr)
        else:
            self.msg = '%s read None' % (fun)
    def getMsg(self):
        return self.msg

class WatchMarks():
    def __init__(self, top, mem_utils, cpu, cell_name, run_from_snap, lgr):
        self.mark_list = []
        ''' Previous marks that are no longer reachable due to origin resets '''
        self.stale_marks = []
        self.mem_utils = mem_utils
        self.cpu = cpu
        self.top = top
        self.cell_name = cell_name
        self.lgr = lgr
        self.call_cycle = None
        self.prev_ip = []
        self.recent_buf_address = None
        self.recent_buf_max_len = None
        if run_from_snap is not None:
            self.loadPickle(run_from_snap)
        ''' will store so map with saved json files ''' 
        self.so_map = None

    def saveMarks(self, fpath):
        with open(fpath, 'w') as fh:
            i = 1
            for mark in self.stale_marks:
                the_str = mark.mark.getMsg().encode('utf-8', 'ignore')
                fh.write('%d %s  ip:0x%x cycle: 0x%x\n' % (i, the_str, mark.ip, mark.cycle))
                i += 1
            fh.write('\n\nBegin active watch marks.\n\n')
            i = 1
            for mark in self.mark_list:
                the_str = mark.mark.getMsg().encode('utf-8', 'ignore')
                fh.write('%d %s  ip:0x%x cycle: 0x%x\n' % (i, the_str, mark.ip, mark.cycle))
                i += 1

    def showMarks(self, old=False, verbose=False):
        i = 1
        if old:
            for mark in self.stale_marks:
                cycle = ' '
                if verbose:
                    cycle = ' 0x%x ' % mark.cycle
                print('%d%s%s  ip:0x%x pid:%d' % (i, cycle, mark.mark.getMsg(), mark.ip, mark.pid))
                i += 1
            print('Begin active watch marks.')
        elif len(self.stale_marks)>0:
            print('%d stale marks not displayed.  use old=True to see them.' % len(self.stale_marks))
        i = 1
        for mark in self.mark_list:
            cycle = ' '
            if verbose:
                cycle = ' 0x%x ' % mark.cycle
            print('%d%s%s  ip:0x%x pid:%d' % (i, cycle, mark.mark.getMsg(), mark.ip, mark.pid))
            i += 1
        self.lgr.debug('watchMarks, showed %d marks' % len(self.mark_list))
        

    class WatchMark():
        ''' Objects that are listed as watch marks -- highest level stored in mark_list'''
        def __init__(self, return_cycle, call_cycle, ip, pid, mark):
            self.cycle = return_cycle
            self.call_cycle = call_cycle
            self.ip = ip
            self.pid = pid
            self.mark = mark
        def getJson(self, origin):
            retval = {}
            retval['cycle'] = self.cycle - origin
            retval['ip'] = self.ip
            retval['pid'] = self.pid
            retval['msg'] = self.mark.getMsg()
            return retval

    def recordIP(self, ip):
        self.prev_ip.append(ip)
        if len(self.prev_ip) > 4:
            self.prev_ip.pop(0)

    def markCall(self, msg, max_len, recv_addr=None, length=None, fd=None, is_lib=False):
        ip = self.mem_utils.getRegValue(self.cpu, 'pc')
        cm = CallMark(msg, max_len, recv_addr, length, fd, is_lib=is_lib)
        cycles = self.cpu.cycles
        self.addWatchMark(cm, cycles=cycles)
        if recv_addr is None:
            self.lgr.debug('watchMarks markCall ip: 0x%x cycles: 0x%x %s' % (ip, cycles, msg))
        else:
            self.lgr.debug('watchMarks markCall ip: 0x%x cycles: 0x%x %s wrote to: 0x%x' % (ip, cycles, msg, recv_addr))
            if self.recent_buf_address is None:
                self.recent_buf_address = recv_addr
                self.recent_buf_max_len = max_len
        self.recordIP(ip)
 
    def resetOrigin(self, origin_watches, reuse_msg=False, record_old=False): 
        old_msg = None
        if reuse_msg:
           old_origin = self.getMarkFromIndex(1)
           if old_origin is not None:
               old_msg = old_origin.mark.getMsg() 
        self.clearWatchMarks(record_old=record_old)
        ro = ResetOrigin(origin_watches, new_msg=old_msg)
        self.addWatchMark(ro)
        self.lgr.debug('watchMarks resetOrigin')

    def memoryMod(self, start, length, trans_size, addr=None):
        ip = self.mem_utils.getRegValue(self.cpu, 'pc')
        dm = DataMark(addr, start, length, None, trans_size, self.lgr, modify=True)
        self.addWatchMark(dm)
        ''' DO NOT DELETE THIS LOG ENTRY, used in testing '''
        self.lgr.debug('watchMarks memoryMod 0x%x msg:<%s> -- Appended, len of mark_list now %d' % (ip, dm.getMsg(), len(self.mark_list)))
 
    def dataRead(self, addr, start, length, cmp_ins, trans_size, ad_hoc=False, dest=None, note=None, ip=None, cycles=None): 
        if ip is None:
            ip = self.mem_utils.getRegValue(self.cpu, 'pc')
        wm = None
        ''' TBD generalize for loops that make multiple refs? '''
        if ip not in self.prev_ip and not ad_hoc and not note:
            value = self.mem_utils.readBytes(self.cpu, addr, trans_size)
            dm = DataMark(addr, start, length, cmp_ins, trans_size, self.lgr, value=int.from_bytes(value, byteorder='little', signed=False))
            wm = self.addWatchMark(dm, ip=ip, cycles=cycles)
            ''' DO NOT DELETE THIS LOG ENTRY, used in testing '''
            self.lgr.debug('watchMarks dataRead ip: 0x%x %s appended, cycle: 0x%x len of mark_list now %d' % (ip, dm.getMsg(), self.cpu.cycles, len(self.mark_list)))
            self.prev_ip = []
        elif ad_hoc:
            if len(self.mark_list) > 0:
                pm = self.mark_list[-1]
                if isinstance(pm.mark, DataMark) and pm.mark.ad_hoc and pm.mark.end_addr is not None and addr == (pm.mark.end_addr+1):
                    end_addr = addr + trans_size - 1
                    #self.lgr.debug('watchMarks dataRead extend range for add 0x%x to 0x%x' % (addr, end_addr))
                    pm.mark.addrRange(end_addr)
                else:
                    #self.lgr.debug('watchMarks create new ad hoc data mark for read from 0x%x, ref buffer start 0x%x, len %d dest 0x%x, trans size %d cycle 0x%x' % (addr, start, length, dest, trans_size, self.cpu.cycles))
                    #sp, base = self.getStackBase(dest)
                    sp = self.isStackBuf(dest)
                    #self.lgr.debug('sp is %s' % str(sp))
                    dm = DataMark(addr, start, length, cmp_ins, trans_size, self.lgr, ad_hoc=True, dest=dest, sp=sp)
                    wm = self.addWatchMark(dm)
            else:
                self.lgr.warning('watchMarks dataRead, ad_hoc but empty mark list')
        elif note is not None:
            dm = DataMark(addr, start, length, cmp_ins, trans_size, self.lgr, note=note, dest=dest)
            wm = self.addWatchMark(dm)
            #self.lgr.debug('watchMarks dataRead with note ip: 0x%x %s' % (ip, dm.getMsg()))
        else:
            if len(self.prev_ip) > 0:
                pm = self.mark_list[-1]
                #self.lgr.debug('pm class is %s' % pm.mark.__class__.__name__)
                if isinstance(pm.mark, DataMark):
                    pm.mark.addrRange(addr)
                    if pm.mark.ad_hoc:
                        #self.lgr.debug('watchMarks was add-hoc, but this is not, so reset it')
                        pm.mark.noAdHoc()
                    #self.lgr.debug('watchMarks dataRead 0x%x range 0x%x' % (ip, addr))
                else:
                    dm = DataMark(addr, start, length, cmp_ins, trans_size, self.lgr)
                    wm = self.addWatchMark(dm, cycles=cycles)
                    #self.lgr.debug('watchMarks dataRead followed something other than DataMark 0x%x %s' % (ip, dm.getMsg()))
        self.recordIP(ip)
        return wm

    def getMarkFromIndex(self, index):
        index = index -1
        if index < len(self.mark_list):
            return self.mark_list[index]
        else:
            return None

    def getWatchMarks(self, origin=0):
        retval = []
        self.lgr.debug('watchMarks getWatchMarks len is %d' % len(self.mark_list))
        for mark in self.mark_list:
            retval.append(mark.getJson(origin))
        return retval        

    def isCall(self, index):
        index = index -1
        self.lgr.debug('watchMarks isCall type of index %d is %s' % (index, type(self.mark_list[index].mark)))
        if isinstance(self.mark_list[index].mark, CallMark):
            if self.mark_list[index].mark.is_lib:
                return False
            else:
                return True
        else:
            return False

    def getIP(self, index):
        index = index-1
        if index < len(self.mark_list):
            #self.lgr.debug('watchMarks getCycle index %d len %s cycle: 0x%x' % (index, len(self.mark_list), self.mark_list[index].cycle))
            return self.mark_list[index].ip
        else:
            return None

    def getCycle(self, index):
        index = index-1
        if index < len(self.mark_list):
            #self.lgr.debug('watchMarks getCycle index %d len %s cycle: 0x%x' % (index, len(self.mark_list), self.mark_list[index].cycle))
            return self.mark_list[index].cycle
        else:
            return None

    def removeRedundantDataMark(self, dest):
        if len(self.prev_ip) > 0:
            pm = self.mark_list[-1]
            if isinstance(pm.mark, DataMark):
                if pm.mark.addr == dest:
                    ''' a copy record for the same data read previously recorded, remove the redundant data read '''
                    self.lgr.debug('watchMarks removeRedundantDataMark ')
                    del self.mark_list[-1]

    def isCopyMark(self, mark):
        if mark.mark.__class__.__name__ in ['CopyMark', 'StringMark', 'ReplaceMark', 'AppendMark', 'AssignMark']:
            return True
        else:
            return False

    def getMarkCopyOffset(self, address):
        ''' Intended for reverse data tracking. If a CopyMark is found encompassing the given address, return the 
            source address that corresponds to the given destination address. '''
        retval = None
        offset = None
        ret_mark = None
        cycle = self.cpu.cycles
        for mark in self.mark_list:
            if mark.call_cycle is not None and mark.cycle is not None and cycle >= mark.call_cycle and cycle <= mark.cycle:
                if self.isCopyMark(mark):
                    if address >= mark.mark.dest and address <= (mark.mark.dest+mark.mark.length):
                        #math = mark.mark.dest+mark.mark.length
                        #self.lgr.debug('getMarkCopyOffset found that address 0x%x is between 0x%x len %d (0x%x)' % (address, mark.mark.dest, mark.mark.length, math))
                        offset = address - mark.mark.dest
                        retval = mark.mark.src+offset
                        #self.lgr.debug('and... the offset from dest is %d.  The src was 0x%x, plus the offset gives 0x%x' % (offset, mark.mark.src, retval))
                        ret_mark = mark
                else:
                    self.lgr.debug('watchMarks getMarkCopyOffset found cycle, but not a copy, is type %s. %s' % (mark.mark.__class__.__name__, mark.mark.getMsg()))
                break
        return retval, offset, ret_mark

    def getCopyMark(self):
        ''' If currently in a copy function, return the associated mark '''
        retval = None
        cycle = self.cpu.cycles
        for mark in self.mark_list:
            if mark.cycle is None or mark.call_cycle is None:
                self.lgr.debug('getCopyMark no call_cycle for mark %s' % mark)
                continue
            if cycle >= mark.call_cycle and cycle <= mark.cycle:
                if self.isCopyMark(mark):
                    retval = mark
                    break
        return retval
        
                
    def addWatchMark(self, mark, cycles=None, ip=None):
        if self.so_map is None:
            self.so_map = json.loads(self.top.getSOMap(quiet=True))
            if self.so_map is None:
                self.lgr.error('watchMarks addWatchMark, so_map is None')
            else:
                self.lgr.debug('dataWatch addWatchMark got so_map')
        if ip is None:
            ip = self.mem_utils.getRegValue(self.cpu, 'pc')
        pid = self.top.getPID()
        if cycles is None:
            cycles = self.cpu.cycles
        wm = self.WatchMark(cycles, self.call_cycle, ip, pid, mark)
        self.mark_list.append(wm)
        #self.lgr.debug('addWatchMark len now %d' % len(self.mark_list))
        return wm

    def isStackBuf(self, dest):
        sp = self.mem_utils.getRegValue(self.cpu, 'sp')
        if dest >= sp:
            return True
        else:
            return False

    def getStackBase(self, dest):
        base = None
        sp = None
        if self.cpu.architecture != 'arm':
            sp = self.mem_utils.getRegValue(self.cpu, 'sp')
            base = self.mem_utils.getRegValue(self.cpu, 'ebp')
            if dest is not None and dest > sp and dest <= base:
                  ''' copy is to a stack buffer.  Record so it can be deleted when opportuntity arises '''
                  pass
            else:
                sp = None
                base = None
        else:
            st = self.top.getStackTraceQuiet(max_frames=2, max_bytes=1000)
            if st is None:
                self.lgr.debug('getStackBase stack trace is None, wrong pid?')
                return
            frames = st.getFrames(2)
            for f in frames:
                self.lgr.debug(f.dumpString())
            if len(frames) > 1:
                next_frame = frames[1]
                if next_frame.instruct.startswith('bl'):
                    sp = self.mem_utils.getRegValue(self.cpu, 'sp')
                    base = next_frame.sp
                else:
                    self.lgr.debug('watchMarks getStackBase, next frame does not look like an lr return, unable to delete temporary stack frame?')
        return sp, base


    def copy(self, src, dest, length, buf_start, op_type, strcpy=False, truncated=None):
        #sp, base = self.getStackBase(dest)
        sp = self.isStackBuf(dest)
        cm = CopyMark(src, dest, length, buf_start, op_type, strcpy, sp=sp, truncated=truncated)
        self.lgr.debug('watchMarks copy %s' % (cm.getMsg()))
        #self.removeRedundantDataMark(dest)
        wm = self.addWatchMark(cm)
        return wm
        

    def memset(self, dest, length, buf_start):
        sm = SetMark(dest, length, buf_start, self.lgr)
        self.addWatchMark(sm)
        self.lgr.debug('watchMarks memset %s' % (sm.getMsg()))

    def kernel(self, addr, count, fd, callnum):
        km = KernelMark(addr, count, callnum, fd)
        self.addWatchMark(km)
        self.lgr.debug('watchMarks kernel %s' % (km.getMsg()))

    def kernelMod(self, addr, count, frame):
        callnum = self.mem_utils.getCallNum(self.cpu)
        fd = frame['param1']
        km = KernelModMark(addr, count, callnum, fd)
        self.addWatchMark(km)
        self.lgr.debug('watchMarks kernelMod %s' % (km.getMsg()))

    def compare(self, fun, dest, src, count, buf_start):
        if count > 0:
            dst_str = self.mem_utils.readString(self.cpu, dest, count)
            if dst_str is not None:
                if (sys.version_info < (3,0)):
                    self.lgr.debug('watchMarks compare, do decode')
                    dst_str = dst_str.decode('ascii', 'replace')
            src_str = self.mem_utils.readString(self.cpu, src, count)
            if src_str is not None:
                if (sys.version_info < (3,0)):
                    self.lgr.debug('watchMarks compare, do decode')
                    src_str = src_str.decode('ascii', 'replace')
            src_str = src_str.replace('\n\r','<newline>')
            src_str = src_str.replace('\n','<newline>')
            src_str = src_str.replace('\t','<tab>')
            #hexstring = ":".join("{:02x}".format(ord(c)) for c in src_str)
            #self.lgr.debug('srcdst_string hex is %s' % hexstring)
        else:
            dst_str = ''
            src_str = ''
        cm = CompareMark(fun, dest, src, count, dst_str, src_str, buf_start) 
        self.addWatchMark(cm)
        self.lgr.debug('watchMarks compare (%s) %s' % (fun, cm.getMsg()))

    def strchr(self, start, the_chr, count):
        cm = StrChrMark(start, the_chr, count)
        self.removeRedundantDataMark(start)
        self.addWatchMark(cm)
        self.lgr.debug('watchMarks strchr %s' % (cm.getMsg()))

    def strtoul(self, fun, src):
        cm = StrtousMark(fun, src)
        self.addWatchMark(cm)
        self.lgr.debug('watchMarks strtous %s' % (cm.getMsg()))

    def sscanf(self, src, dest, count, buf_start):
        #sp, base = self.getStackBase(dest)
        if dest is not None:
            sp = self.isStackBuf(dest)
        else:
            sp = None
        sm = ScanMark(src, dest, count, buf_start, sp)        
        wm = self.addWatchMark(sm)
        self.lgr.debug('watchMarks sscanf %s' % (sm.getMsg()))
        return wm

    def strlen(self, src, count):
        lm = LenMark(src, count)        
        self.addWatchMark(lm)
        self.lgr.debug('watchMarks strlen %s' % (lm.getMsg()))

    def sprintf(self, fun, src, dest, count, buf_start):
        #sp, base = self.getStackBase(dest)
        sp = self.isStackBuf(dest)
        lm = SprintfMark(fun, src, dest, count, buf_start, sp)        
        wm = self.addWatchMark(lm)
        self.lgr.debug('watchMarks %s %s' % (fun, lm.getMsg()))
        return wm

    def fprintf(self, fun, src):
        lm = FprintfMark(fun, src)
        wm = self.addWatchMark(lm)
        self.lgr.debug('watchMarks %s %s' % (fun, lm.getMsg()))
        return wm

    def fwrite(self, fun, src, count):
        wm = FwriteMark(fun, src, count)
        self.addWatchMark(wm)
        self.lgr.debug('watchMarks %s %s' % (fun, wm.getMsg()))

    def glob(self, fun, src, count):
        wm = GlobMark(fun, src, count)
        self.addWatchMark(wm)
        self.lgr.debug('watchMarks %s %s' % (fun, wm.getMsg()))

    def inet_addr(self, src, count, the_string):
        xm = InetAddrMark(src, count, the_string)        
        self.addWatchMark(xm)
        self.lgr.debug('watchMarks inet_addr %s' % (xm.getMsg()))

    def inet_ntop(self, dest, count, the_string):
        xm = InetNtopMark(dest, count, the_string)        
        self.lgr.debug('watchMarks inet_ntop %s' % (xm.getMsg()))
        wm = self.addWatchMark(xm)
        return wm

    def xmlGetProp(self, src, count, the_string, dest):
        result = 'Not found'
        if dest != 0:
            result = self.mem_utils.readString(self.cpu, dest, 20)
        xm = XMLPropMark(src, count, the_string, result)        
        self.addWatchMark(xm)
        self.lgr.debug('watchMarks xmlGetProp %s' % (xm.getMsg()))

    def iterator(self, fun, src, buf_start):
        im = IteratorMark(fun, src, buf_start)
        self.addWatchMark(im)
        self.lgr.debug('watchMarks iterator %s' % (im.getMsg()))

    def malloc(self, addr, size):
        mm = MallocMark(addr, size)
        self.addWatchMark(mm)
        self.lgr.debug('watchMarks malloc %s' % (mm.getMsg()))

    def free(self, addr, fun):
        if addr is not None:
            fm = FreeMark(addr, fun)
            self.addWatchMark(fm)
            self.lgr.debug('watchMarks free %s' % (fm.getMsg()))
        else:
            self.lgr.debug('watchMarks free %s but addr is none' % fun)

    def freeXMLDoc(self):
        fm = FreeXMLMark()
        self.addWatchMark(fm)

    def xmlParseFile(self, dest, count):
        fm = XMLParseFileMark(dest, count)
        self.addWatchMark(fm)
      
    def getToken(self, src, dest, the_string):
        fm = GetTokenMark(src, dest, the_string)
        self.addWatchMark(fm)

    def strPtr(self, dest, fun):
        the_string = self.mem_utils.readString(self.cpu, dest, 40)
        fm = StrPtr(fun, the_string)
        self.addWatchMark(fm)

    def returnInt(self, count, fun):
        fm = ReturnInt(fun, count)
        self.addWatchMark(fm)

    def logMark(self, s, prefix):
        lm = LogMark(s, prefix)
        self.addWatchMark(lm)

    def pushMark(self, src, dest, buf_start, length, ip):
        pm = PushMark(src, dest, buf_start, length, ip, self.mem_utils.WORD_SIZE)
        wm = self.addWatchMark(pm)
        return wm

    def fgetsMark(self, fun, src, dest, count, start):
        fm = FGetsMark(fun, src, dest, count, start)
        self.addWatchMark(fm)

    def stringMark(self, fun, src, dest, count, start):
        fm = StringMark(fun, src, dest, count, start)
        self.addWatchMark(fm)

    def replaceMark(self, fun, src, dest, pos, length, start):
        fm = ReplaceMark(fun, src, dest, pos, length, start)
        self.addWatchMark(fm)

    def appendMark(self, fun, src, dest, length, start):
        fm = AppendMark(fun, src, dest, length, start)
        self.addWatchMark(fm)

    def assignMark(self, fun, src, dest, length, start):
        fm = AssignMark(fun, src, dest, length, start)
        self.addWatchMark(fm)

    def charLookupMark(self, addr, msg, length=None):
        add_mark = True
        if length is None:        
            if len(self.mark_list) > 0:
                pm = self.mark_list[-1]
                if isinstance(pm.mark, CharLookupMark) and addr == (pm.mark.end_addr+1):
                    pm.mark.extend()
                    add_mark = False
        if add_mark:
            cm = CharLookupMark(addr, msg, length)
            self.addWatchMark(cm)

    def charPtrMark(self, addr, ptr, value):
        cm = CharPtrMark(addr, ptr, value)
        self.addWatchMark(cm)
        
    def mscMark(self, fun, src):
        fm = MscMark(fun, src)
        self.addWatchMark(fm)
        self.lgr.debug(fm.getMsg())

    def clearWatchMarks(self, record_old=False): 
        self.lgr.debug('watchMarks clearWatchMarks, entered with %d marks and %d stale marks' % (len(self.mark_list), len(self.stale_marks)))
        if record_old:
            self.stale_marks.extend(self.mark_list)
        del self.mark_list[:] 
        self.mark_list = []
        self.prev_ip = []
        self.lgr.debug('watchMarks clearWatchMarks, leave with %d marks and %d stale marks' % (len(self.mark_list), len(self.stale_marks)))

    def firstBufferAddress(self):
        ''' address of first buffer '''
        retval = None
        ''' maximum length per initial read '''
        max_len = None
        for mark in self.mark_list:
           self.lgr.debug('check mark type %s' % type(mark.mark))
           if isinstance(mark.mark, CallMark) and mark.mark.recv_addr is not None:
               self.lgr.debug('watchMarks firstBufferAddress is CallMark addr 0x%x' % mark.mark.recv_addr)
               retval = mark.mark.recv_addr
               max_len = mark.mark.max_len
               break
           elif isinstance(mark.mark, DataMark):
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
        index = 1
        for mark in self.mark_list:
           if isinstance(mark.mark, CallMark) and mark.mark.recv_addr is not None:
               self.lgr.debug('watchMarks firstBufferIndex is CallMark addr 0x%x' % mark.mark.recv_addr)
               retval = index
               break
           elif isinstance(mark.mark, DataMark):
               self.lgr.debug('watchMarks firstBufferIndex is DataMark addr 0x%x' % mark.mark.start)
               retval = index
               break 
           index += 1
        return retval

    def nextWatchMark(self):
        retval = None
        cur_cycle = self.cpu.cycles
        index = 1
        for mark in self.mark_list:
            if mark.cycle > cur_cycle:
                retval = index
                break
            index += 1
        return retval

    def undoMark(self):
        self.mark_list.pop()

    def latestCycle(self):
        if len(self.mark_list) > 0:
            latest_mark = self.mark_list[-1]
            return latest_mark.cycle
        else:
            return None

    def registerCallCycle(self):
        self.call_cycle = self.cpu.cycles
      
    def getCallCycle(self):
        return self.call_cycle

    def readCount(self):
        ''' get count of read/recv, i.e., CallMarks having recv_addr values '''
        retval = 0
        prev_cycle = 0
        for mark in self.mark_list:
           if isinstance(mark.mark, CallMark):
               if mark.mark.recv_addr is not None and mark.call_cycle != prev_cycle:
                   retval += 1
                   prev_cycle = mark.call_cycle
        return retval

    def whichRead(self):
        ''' Return the number of reads that have occured prior to this cycle.
            Intended to decorate automated backtrace bookmarks with context.'''
        found = None
        num_reads = 0
        self.lgr.debug('watchMarks whichRead')
        for mark in reversed(self.mark_list):
           if mark.call_cycle is not None and mark.call_cycle > self.cpu.cycles:
               continue
           self.lgr.debug('watchMarks whichRead mark.mark %s' % str(mark.mark))
           if isinstance(mark.mark, CallMark):
               if mark.mark.recv_addr is not None:
                   num_reads += 1
                   self.lgr.debug('num_reads now %d' % num_reads)
                   if mark.call_cycle is not None and mark.call_cycle >= self.cpu.cycles:
                       self.lgr.debug('num_reads found num_reads %d' % num_reads)
                       found = num_reads
        if found is None:
            retval = None
        else:
            retval = num_reads - (found - 1)
                 
        return retval
       
    def markCount(self):
        return (len(self.mark_list) + len(self.stale_marks))

    def getMarks(self):
        return self.mark.list

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

    def saveJson(self, fname, packet=1):
        my_marks = []
        start_index = 1
        self.lgr.debug('watchMarks saveJson %d marks to file %s packet %d' % (len(self.mark_list), fname, packet))
        if os.path.isfile(fname):
            try:
                combined = json.load(open(fname))
                my_marks = combined['marks']
                start_index = len(my_marks)
                self.lgr.debug('watchMarks loaded my_marks with %d marks' % len(my_marks))
            except:
                my_marks = []
        new_marks = self.getJson(self.mark_list, packet=packet, start_index=start_index)
        my_marks.extend(new_marks)
        with open(fname, 'w') as fh:
            combined = {}
            combined['somap'] = self.so_map
            combined['marks'] = my_marks
            json.dump(combined, fh) 

    def getDataWatchList(self):
        ''' get list intended for use in recontructing data watches '''
        my_marks = []
        for mark in self.mark_list:
            if isinstance(mark.mark, ResetOrigin):
                for origin_watch in mark.mark.origin_watches:
                    entry = {}
                    entry['cycle'] = mark.cycle
                    entry['start'] = origin_watch['start']
                    entry['length'] = origin_watch['length']
                my_marks.append(entry)
            else:
                entry = {}
                entry['cycle'] = mark.cycle
                if isinstance(mark.mark, CopyMark):
                    entry['start'] = mark.mark.dest 
                    entry['length'] = mark.mark.length 
                elif isinstance(mark.mark, ScanMark):
                    entry['start'] = mark.mark.dest 
                    entry['length'] = mark.mark.count 
                elif isinstance(mark.mark, SprintfMark):
                    entry['start'] = mark.mark.dest
                    entry['length'] = mark.mark.count
                elif isinstance(mark.mark, CallMark):
                    entry['start'] = mark.mark.recv_addr
                    entry['length'] = mark.mark.len
                elif isinstance(mark.mark, DataMark) and not mark.mark.modify:
                    entry['start'] = mark.mark.addr
                    entry['length'] = mark.mark.trans_size
                elif isinstance(mark.mark, DataMark) and mark.mark.modify:
                    entry['start'] = mark.mark.addr
                    entry['length'] = mark.mark.trans_size
                if 'start' in entry:
                    my_marks.append(entry)
        return my_marks

    def getAllJson(self):
        self.lgr.debug('getAllJson %d stale and %d new marks' % (len(self.stale_marks), len(self.mark_list)))
        all_marks = self.getJson(self.stale_marks)
        new_marks = self.getJson(self.mark_list, start_index=len(self.stale_marks))
        all_marks.extend(new_marks)
        self.lgr.debug('getAllJson returning %d marks' % len(all_marks))
        return all_marks

    def getJson(self, mark_list, packet=1, start_index=1):
        my_marks = []
        index = start_index
        for mark in mark_list:
            entry = {}
            entry['ip'] = mark.ip
            entry['cycle'] = mark.cycle
            entry['packet'] = packet
            entry['index'] = index
            index = index + 1
            #self.lgr.debug('saveJson mark %s' % str(mark.mark)) 
            if isinstance(mark.mark, CopyMark):
                entry['mark_type'] = 'copy' 
                entry['src'] = mark.mark.src 
                entry['dest'] = mark.mark.dest 
                entry['length'] = mark.mark.length 
                entry['reference_buffer'] = mark.mark.buf_start 

            elif isinstance(mark.mark, DataMark) and mark.mark.ad_hoc and mark.mark.start is not None:
                entry['mark_type'] = 'copy' 
                entry['src'] = mark.mark.addr
                entry['dest'] = mark.mark.dest 
                entry['length'] = (mark.mark.end_addr - mark.mark.addr)+1
                entry['reference_buffer'] = mark.mark.start 

            elif isinstance(mark.mark, ScanMark):
                entry['mark_type'] = 'scan' 
                entry['src'] = mark.mark.src 
                entry['dest'] = mark.mark.dest 
                entry['length'] = mark.mark.count 
                entry['reference_buffer'] = mark.mark.buf_start 
            elif isinstance(mark.mark, SprintfMark):
                entry['mark_type'] = 'sprint' 
                entry['src'] = mark.mark.src
                entry['dest'] = mark.mark.dest
                entry['count'] = mark.mark.count
                entry['reference_buffer'] = mark.mark.buf_start 
            elif isinstance(mark.mark, CallMark):
                entry['mark_type'] = 'call' 
                entry['recv_addr'] = mark.mark.recv_addr
                entry['length'] = mark.mark.len
                entry['fd'] = mark.mark.fd
            elif isinstance(mark.mark, DataMark) and not mark.mark.modify and not mark.mark.ad_hoc:
                entry['mark_type'] = 'read' 
                entry['addr'] = mark.mark.addr
                entry['reference_buffer'] = mark.mark.start
                entry['trans_size'] = mark.mark.trans_size
                entry['value'] = mark.mark.value
            elif isinstance(mark.mark, DataMark) and mark.mark.modify:
                entry['mark_type'] = 'write' 
                entry['addr'] = mark.mark.addr
                entry['reference_buffer'] = mark.mark.start
                entry['trans_size'] = mark.mark.trans_size
            elif isinstance(mark.mark, KernelMark):
                entry['mark_type'] = 'kernel' 
                entry['addr'] = mark.mark.addr
                entry['count'] = mark.mark.count
                entry['callnum'] = mark.mark.callnum
                entry['fd'] = mark.mark.fd
            elif isinstance(mark.mark, StrChrMark):
                entry['mark_type'] = 'strchr' 
                entry['the_char'] = mark.mark.the_chr
                entry['start'] = mark.mark.start
                entry['count'] = mark.mark.count
            elif isinstance(mark.mark, CompareMark):
                entry['mark_type'] = 'compare' 
                entry['src_str'] = mark.mark.src_str
                entry['dst_str'] = mark.mark.dst_str
                entry['ours'] = mark.mark.ours
                entry['theirs'] = mark.mark.theirs
                entry['count'] = mark.mark.count
            elif isinstance(mark.mark, StrtousMark):
                entry['mark_type'] = 'strt' 
                entry['src'] = mark.mark.src
            elif isinstance(mark.mark, StringMark):
                entry['mark_type'] = 'string' 
                entry['src'] = mark.mark.src
                entry['dest'] = mark.mark.dest
                entry['length'] = mark.mark.length
            elif isinstance(mark.mark, ReplaceMark):
                entry['mark_type'] = 'replace' 
                entry['src'] = mark.mark.src
                entry['dest'] = mark.mark.dest
                entry['pos'] = mark.mark.pos
                entry['length'] = mark.mark.length
            elif isinstance(mark.mark, AppendMark):
                entry['mark_type'] = 'append' 
                entry['src'] = mark.mark.src
                entry['dest'] = mark.mark.dest
                entry['length'] = mark.mark.length
            elif isinstance(mark.mark, AssignMark):
                entry['mark_type'] = 'assign' 
                entry['src'] = mark.mark.src
                entry['dest'] = mark.mark.dest
                entry['length'] = mark.mark.length
            elif isinstance(mark.mark, MscMark):
                entry['mark_type'] = 'msc' 
                entry['src'] = mark.mark.addr
            elif isinstance(mark.mark, LenMark):
                entry['mark_type'] = 'len' 
                entry['src'] = mark.mark.src
                entry['count'] = mark.mark.count
            elif isinstance(mark.mark, CharLookupMark):
                entry['mark_type'] = 'char_lookup' 
                entry['addr'] = mark.mark.addr
                entry['length'] = mark.mark.length
                entry['stuff'] = mark.mark.stuff
            elif isinstance(mark.mark, CharPtrMark):
                entry['mark_type'] = 'char_ptr' 
                entry['addr'] = mark.mark.addr
                entry['ptr'] = mark.mark.ptr
                entry['value'] = mark.mark.value


            elif isinstance(mark.mark, IteratorMark) or isinstance(mark.mark, KernelModMark) or isinstance(mark.mark, SetMark):
                continue
            else:
                self.lgr.debug('unknown mark type? %s' % str(mark.mark))
                continue
            my_marks.append(entry)
        return my_marks
