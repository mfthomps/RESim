'''
 * This software was created by United States Government employees
 * and may not be copyrighted.
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
 * ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
'''
'''
TraceMarks class:  Use watchMarks from the DataWatch to backtrace sources
of data.  This is entirely static based on the dynamically created
watchMarks.  This class reads the watchMarks and creates 4 sets of objects
representing:
    original reads, i.e., injest of data
    memory copies caused by memcpy, scan, or ad-hoc copying
    writes to pipes
    reads from pipes
These are then used to locate the original buffers and offsets of 
addresses.
'''
def isMod(mark, offset, mods):
    retval = False
    if mark['reference_buffer'] in mods:
        if offset in mods[mark['reference_buffer']]:
            retval = True
    return retval

class ReadMark():
    def __init__(self, offset, size, ip, cycle, packet):
        self.offset = offset
        self.size = size
        self.ip = ip
        self.cycle = cycle
        self.packet = packet

class OrigRead():
    def __init__(self, mark, read_count, prior_bytes_read, lgr):
        self.addr = mark['recv_addr']
        self.length = mark['length']
        self.cycle = mark['cycle']
        self.read_count = read_count
        self.prior_bytes_read = prior_bytes_read
        self.lgr = lgr
    def within(self, addr, cycle):
        end = self.addr + self.length - 1
        #if self.lgr is not None:
        #    self.lgr.debug('traceMarks OrigRead is 0x%x within 0x%x -> 0x%x and cycle 0x%x >= 0x%x' (addr, self.addr, end, cycle, self.cycle))
        if addr >= self.addr and addr <= (self.addr + self.length) and cycle >= self.cycle:
            return True
        else:
            return False
    def offset(self, addr):
        offset = addr - self.addr
        return offset
    def toString(self):
        if self.addr is not None:
            return ('Read/recv # %d orig addr: %x  orig len: %d  cycle: %x' % (self.read_count, self.addr, self.length, self.cycle))
        else:
            return ('Error, addr in OrigRead is None')

class DataRef():
    ''' Map copied buffers to their original data injest.  Any given copy may result
        in multiple DataRefs.
    '''
    def __init__(self, addr, length, orig_read, offset, cycle, mark_type):
        self.addr = addr
        self.length = length
        self.orig_read = orig_read
        ''' offset into original read buffer '''
        self.offset = offset
        self.cycle = cycle
        self.mark_type = mark_type
    def within(self, addr, cycle):
        #print('type: %s is 0x%x between 0x%x and 0x%x,  and cycle 0x%x >= 0x%x' % (self.mark_type, addr, self.addr, (self.addr+self.length), cycle, self.cycle))
        if addr >= self.addr and addr <= (self.addr + self.length) and cycle >= self.cycle:
            return True
        else:
            return False

    def getOffset(self, addr):
        offset_into_ref = addr - self.addr
        tot_offset = self.offset + offset_into_ref
        return tot_offset

    def toString(self):
        return ('addr: 0x%x  len: %d  cycle: 0x%x offset %d into orig: %s' % (self.addr, self.length, self.cycle, self.offset, self.orig_read.toString()))

class PipeRef():
    def __init__(self, write_fd, read_fd, length, orig_read, offset, cycle):
        self.write_fd = write_fd
        self.read_fd = read_fd
        self.length = length
        self.remaining = length
        self.orig_read = orig_read
        ''' offset into original read buffer '''
        self.offset = offset
        self.cycle = cycle

    def getOffset(self, addr):
        tot_offset = self.offset + addr
        return tot_offset

    def toString(self):
        return ('PipeRef write_fd: %d  read_fd: %d len: %d  offset %d into orig: %s' % (self.write_fd, self.read_fd, self.length, self.offset, self.orig_read.toString()))

class TraceMarks():
    def __init__(self, dataWatch, lgr):
        self.dataWatch = dataWatch
        self.lgr = lgr
        self.watch_marks = dataWatch.getAllJson()
        self.lgr.debug('traceMarks got %d marks' % len(self.watch_marks))
        ''' Map references to offsets within original reads '''
        self.refs = []
        self.pipes = []
        self.mods = {}
        ''' buffers read from original read/recv, does not include 2ndary reads, e.g., via pipes
            Ordered, use cycle to find the correct one
        '''
        self.orig_reads = []
        ''' Load up the orig_reads and the refs '''
        self.traceRefs()

    def getOrigRead(self, addr, cycle):
        ''' Return the oldest OrigRead (if any) containing the given address and with a cyle less than the given'''
        self.lgr.debug('traceMarks getOrigRead addr 0x%x cycle 0x%x there are %d orig_reads' % (addr, cycle, len(self.orig_reads)))

        if len(self.orig_reads) > 0:
            for orig in self.orig_reads[::-1]:
                self.lgr.debug('traceMarks check %s' % orig)
                if orig.within(addr, cycle):
                    offset = orig.offset(addr)
                    return orig, offset
        return None, None
          
    def findRef(self, ref_addr, cycle): 
        ''' Find the most recent ref containing the given address '''
        retval = None
        for ref in self.refs[::-1]:
            if ref.within(ref_addr, cycle):
                ''' found ref containing ref_addr '''
                retval = ref
                break
        return retval

    def findOrig(self, ref_addr, cycle):
        ''' Look through the refs to find the original buffer address and offset for the given reference address '''
        return_orig = None
        return_offset = None
        ref = self.findRef(ref_addr, cycle)
        if ref is not None:
            return_offset = ref.getOffset(ref_addr)
            return_orig = ref.orig_read
        return return_orig, return_offset

    def getPipeRefs(self, fd):
        retval = []
        for pipe in self.pipes:
            if fd == pipe.read_fd:
                retval.append(pipe)
        return retval

    def handlePipeRead(self, mark):
        ''' Generate refs based on reading from buffers into which data from a pipe has flowed.
        '''
        self.lgr.debug('call on different fd: %d  try a pipe?' % mark['fd'])
        ''' find all pipe ref that wrote to that fd '''
        pipe_refs = self.getPipeRefs(mark['fd'])
        dest = mark['recv_addr']
        if len(pipe_refs) == 0:
            self.lgr.debug('traceRefs did not find any pipeRef for fd %s' % mark['fd'])
            return
        else:
            remaining_bytes = mark['length']
            pipe_index = 0
            while remaining_bytes > 0 and pipe_index < len(pipe_refs):
                while pipe_index < len(pipe_refs) and pipe_refs[pipe_index].remaining == 0:
                    pipe_index += 1
                if pipe_index >= len(pipe_refs):
                    break
                pipe_ref = pipe_refs[pipe_index]
                if remaining_bytes > pipe_ref.remaining:
                    ref_len = pipe_ref.remaining
                else:
                    ref_len = remaining_bytes

                self.lgr.debug('traceRefs found pipe ref for fd %d, it is %s' % (mark['fd'], pipe_ref.toString()))
                new_ref = DataRef(dest, ref_len, pipe_ref.orig_read, pipe_ref.offset, mark['cycle'], 'pipe_ref')
                self.refs.append(new_ref)
                self.lgr.debug('traceRefs pipe new ref: %s' % new_ref.toString())
                dest = dest + ref_len
                remaining_bytes = remaining_bytes - ref_len
                pipe_ref.remaining = pipe_ref.remaining - ref_len

    def handlePipeWrite(self, mark, read_fd):
        ''' Create pipeRefs for the given write to a pipe, i.e., the kernel reads from a watched buffer and writes to the pipe'''
        src = mark['addr']
        remaining_bytes = mark['count']
        while remaining_bytes > 0:
            orig_read, offset = self.getOrigRead(src, mark['cycle'])
            if orig_read is None:
                '''  Source of kernel write is not an original buffer.  Find a ref containing the source '''
                ref = self.findRef(src, mark['cycle'])
                if ref is None:
                    self.lgr.debug('kernel write, COULD NOT FIND original buffer for 0x%x' % src)
                    break
                else:
                    if remaining_bytes > ref.length:
                        ref_len = ref.length
                    else:
                        ref_len = remaining_bytes
                    offset = ref.getOffset(src)
                    self.lgr.debug('kernel found ref for addr 0x%x.  Ref is %s Offset into orig is %d' % (src, ref.toString(), offset))
                    new_pipe = PipeRef(mark['fd'], read_fd, ref_len, ref.orig_read, offset, mark['cycle'])
                    self.pipes.append(new_pipe)
                    self.lgr.debug('traceRefs PipeRef: %s' % new_pipe.toString())
                    remaining_bytes = remaining_bytes - ref_len
                    src = src + ref_len
            else:
                ''' read from original buffer '''
                if remaining_bytes > orig_read.length:
                    ref_len = orig_read.length
                else:
                    ref_len = remaining_bytes
                offset = orig_read.offset(src)
                self.lgr.debug('create new pipe ref for kernel orig buf write to fd %d with mark: len %s  offset %s' % (mark['fd'], ref_len, offset))
                new_pipe = PipeRef(mark['fd'], read_fd, ref_len, orig, offset, mark['cycle'])
                self.lgr.debug('traceRefs kernel read from orig buffer PipeRef: %s' % new_pipe.toString())
                remaining_bytes = remaining_bytes - ref_len
                src = src + ref_len

    def handleCopy(self, mark):
        ''' create data refs for the given copy operation '''
        src = mark['src']
        dest = mark['dest']
        remaining_bytes = mark['length']
        while remaining_bytes > 0:
            orig_read, offset = self.getOrigRead(src, mark['cycle'])
            if orig_read is None:
                '''  Source of copy is not an original buffer.  Find a ref containing the source '''
                ref = self.findRef(src, mark['cycle'])
                if ref is None:
                    self.lgr.debug('copy, COULD NOT FIND original buffer for 0x%x' % src)
                    break
                else:
                    if remaining_bytes > ref.length:
                        ref_len = ref.length
                    else:
                        ref_len = remaining_bytes
                    offset = ref.getOffset(src)
                    self.lgr.debug('copy found ref for src 0x%x.  Ref is %s. offset %d into orig' % (src, ref.toString(), offset))
                    self.lgr.debug('create new data ref from copy to dest 0x%x with mark: len %s  offset %s' % (dest, ref_len, offset))
                    new_ref = DataRef(dest, ref_len, ref.orig_read, offset, mark['cycle'], mark['mark_type'])
                    self.refs.append(new_ref)
                    self.lgr.debug('traceRefs copy new ref: %s' % new_ref.toString())
                    remaining_bytes = remaining_bytes - ref_len
                    src = src + ref_len
                    dest = dest + ref_len
         
            else:
                if remaining_bytes > orig_read.length:
                    ref_len = orig_read.length
                else:
                    ref_len = remaining_bytes
                offset = orig_read.offset(src)
                self.lgr.debug('create new DataRef from orig ref with mark: len %s  offset %s' % (ref_len, offset))
                new_ref = DataRef(dest, ref_len, orig_read, offset, mark['cycle'], mark['mark_type'])
                self.refs.append(new_ref)
                self.lgr.debug('copy created new DataRef from orig directly, new ref: %s' % new_ref.toString())
                remaining_bytes = remaining_bytes - ref_len
                src = src + ref_len

    def traceRefs(self):
        
        ''' Support tracking data references back to their original buffer location '''
        ''' Identify which data offsets have been modified (written to) '''
        ''' TODO.  Change pipe reads to distinct watch mark.  Turn orig_addr into dict or class with item per
            read/inject to handle multi packet marks'''
        orig_addr = None 
        retval = None
        did_one = False
        injest_fd = None
        read_count = 0
        prior_bytes_read = 0
        for mark in self.watch_marks:
            self.lgr.debug('mark is %s' % mark['mark_type'])
            ''' TBD expand to handle calls and source addresses '''
            if mark['mark_type'] == 'call' and mark['data_stream'] and mark['length'] is not None:
                if not did_one:
                    did_one = True
                    injest_fd = mark['fd']
                    self.lgr.debug('traceRefs set injest_fd to %s' % (injest_fd))
                self.lgr.debug('call fd is %s' % str(mark['fd']))
                if mark['fd'] != injest_fd and mark['fd'] is not None:
                    self.handlePipeRead(mark)        
                else:
                    read_count += 1
                    orig_read = OrigRead(mark, read_count, prior_bytes_read, self.lgr)
                    self.lgr.debug('original addr %s' % orig_read.toString())
                    self.orig_reads.append(orig_read)
                    self.lgr.debug('len of orig_reads now %d' % len(self.orig_reads))
                    prior_bytes_read = prior_bytes_read + mark['length']
        
            elif mark['mark_type'] == 'kernel':
                read_fd = self.dataWatch.getPipeReader(str(mark['fd']))
                if read_fd is None:
                    self.lgr.debug('traceRefs kernel found no read fd from datawatch for write fd %s' % (mark['fd']))
                    continue
                self.handlePipeWrite(mark, read_fd)

            elif mark['mark_type'] in ['copy', 'scan'] and mark['length'] is not None:

                self.handleCopy(mark) 
            elif mark['mark_type'] in ['sprint'] and mark['count'] is not None:
                ''' TBD ugly '''
                mark['length'] = mark['count']
                self.handleCopy(mark) 
        return retval 
