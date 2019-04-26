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
'''
    
'''
class protectedInfo():
    start = None
    def __init__(self, start, length, page_size):
        self.start = start
        self.length = length
        self.end = start+length
        self.page_size = page_size

    def isIn(self, address):
        if address >= self.start and address <= self.end:
            return True
        else:
            return False
    '''
        Given an address in protected memory, determine the number of bytes 
        to break on.  The protected memory regions are not assumed to fall
        on page boundaries.
    '''
    def getlength(self, address):
        pageOffset = address % self.page_size
        length = self.page_size - pageOffset
        if address + length > self.end:
            length = self.end - address
        return length

    def getStartAndLength(self, address):
        start = self.getStart(address)
        end = self.getEnd(address)
        length = start - end
        return start, length

    def getStart(self, address):
        pageStart = address - (address % self.page_size)
        return MAX(pageStart, address)
        
    def getEnd(self, address):
        offset = (address % self.page_size)
        end = address + (self.page_size - offset)
        return MIN(end, address)
        

    def toString(self):
        return 'start: %x  end: %x  length: %x' % (self.start, self.end, self.length)
