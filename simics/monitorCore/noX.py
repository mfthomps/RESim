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

import simics
import pageUtils
import logging
'''
    Keep track of a process's "non executable" allocated memory.
    All input addresses and lengths are adjusted to cover entire pages.
    The primary purpose of all this is to support the "isIn" function
    to determine if some arbitrary address is part of non-executable
    memory.
'''
class noX():
    pid_ranges = {}
    #ranges = []
    page_size = None
    class arange():
        def __init__(self, start, length, page_size):
            start, end = pageUtils.adjust(start, length, page_size)
            self.start = start
            self.end = end
            #print 'set nox range from %x to %x' % (self.start, self.end)

    def __init__(self, page_size, cell_info, lgr):
        self.page_size = page_size
        self.lgr = lgr
        for cell_name in cell_info:
            self.pid_ranges[cell_name] = {}

    def isIn(self, cell_name, pid, address):
        #self.lgr.debug('in noX isIn')
        if pid in self.pid_ranges[cell_name]:
            ranges = self.pid_ranges[cell_name][pid]
            for r in ranges:
                #self.lgr.debug('check %x against %x & %x' % (address, r.start, r.end))
                if address >= r.start and address <= r.end:
                    return True
        else:
            #self.lgr.log('noX in isIn, pid %d not in ranges for cell %s for address %x.  ' % \
            #         (pid, cell_name, address))
            pass

        return False

    def clear(self, cell_name, pid):
        self.lgr.debug('noX clearing for %s:%d' % (cell_name, pid))
        if pid in self.pid_ranges[cell_name]:
            del self.pid_ranges[cell_name][pid][:]
            del self.pid_ranges[cell_name][pid]

    def getPrevious(self, cell_name, pid, start):
        end = start + 1
        if pid in self.pid_ranges[cell_name]:
            ranges = self.pid_ranges[cell_name][pid]
            for r in ranges:
                if r.end == end:
                    return r
        return None

    def getNext(self, cell_name, pid, end):
        start = end - 1
        if pid in self.pid_ranges[cell_name]:
            ranges = self.pid_ranges[cell_name][pid]
            for r in ranges:
                if r.start == start:
                    return r
        return None

    def add(self, cell_name, pid, start, length):
        end = start + length
        #print 'nox add %x %x %x' % (start, length, end)
        if pid not in self.pid_ranges[cell_name]:
            self.pid_ranges[cell_name][pid] = []
        r = self.getPrevious(cell_name, pid, start)
        done = False
        if r is not None:
            r.end = end
            done = True
        r = self.getNext(cell_name, pid, end)
        if r is not None:
            r.start = start
            done = True
        if not done:
            self.pid_ranges[cell_name][pid].append(self.arange(start, length, self.page_size))
               

    def remove(self, cell_name, pid, start, length): 
        end = start + length
        done = False
        if pid in self.pid_ranges[cell_name]:
            ranges = self.pid_ranges[cell_name][pid]
        #print 'try to remove nox %x : %x' % (start, end)
            for r in ranges:
                #print 'look for %x in %x - %x' % (start, r.start, r.end)
                if start == r.start: 
                    #print 'it matches start'
                    if end == r.end:
                        ranges.remove(r)
                        done = True
                        break
                    else:
                        #print 'it does not matches end'
                        r.start = end+1
                        done = True
                        break
                elif end == r.end:
                    r.end = start - 1
                    done = True
                    break
                elif start > r.start and end < r.end:
                    ''' a hole '''
                    newr = self.arange(end+1, r.end, self.page_size)
                    r.end = start - 1
                    ranges.append(newr)
                    done = True
                    break
        if not done:
            #print 'what to do with remove range %x, %x ????' % (start, length)
            self.lgr.debug( 'what to do with remove range %x, %x ????' % (start, length))
        return done    

