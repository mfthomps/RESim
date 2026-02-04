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
import json
from simics import *
import resimUtils
class WatchMalloc():
    def __init__(self, top, path, context_manager, lgr):
        self.top = top
        self.context_manager = context_manager
        self.lgr = lgr
        self.malloc_json = None
        self.hap_list = []
        self.bit_arrays = {}
        self.malloc_map = {}
        
        with open(path, 'r') as fh:
            self.malloc_json = json.load(fh)
            self.lgr.debug('watchMalloc loaded %d records' % len(self.malloc_json))

    def watch(self):
        self.lgr.debug('watchMalloc watch')
        for rec in self.malloc_json:
            addr = rec['addr']
            size = rec['size']
            self.setOneBreak(addr, size)
            self.malloc_map[addr] = size
            self.bit_arrays[addr] = resimUtils.makeBitArray(size, fill=1)

    def setOneBreak(self, addr, size):
        break_num = self.context_manager.genBreakpoint(None, Sim_Break_Linear, Sim_Access_Read | Sim_Access_Write, addr, (size-1), 0)
        hap = self.context_manager.genHapIndex("Core_Breakpoint_Memop", self.readHap, addr, break_num, 'watchMalloc')
        self.hap_list.append(hap)

    def readHap(self, addr, an_object, the_break, memory):
        op_type = SIM_get_mem_op_type(memory)
        offset = memory.logical_address - addr
        trans_size = memory.size
        eip = self.top.getEIP()
        fun_name = self.top.getSO(eip, with_fun=True)
        #self.lgr.debug('readHap hit addr: 0x%x within malloc start of 0x%x op_type %d offset: %d size: %d fun: %s' % (memory.logical_address, addr, op_type, offset, trans_size, fun_name))
        if op_type == 2:
            # a write, clear the bit
            for i in range(trans_size):
                clearit = offset+i
                resimUtils.clearBit(self.bit_arrays[addr], clearit)
        else:
            is_set = resimUtils.testBit(self.bit_arrays[addr], offset)
            if is_set != 0:
                self.lgr.debug('readHap hit addr: 0x%x within malloc start 0x%x size 0x%x op_type %d offset: %d trans_size: %d fun: %s' % (memory.logical_address, addr, self.malloc_map[addr], op_type, offset, trans_size, fun_name))
                if trans_size == 8:
                   read_addr = self.top.readPtr(memory.logical_address)
                   if read_addr is not None and self.top.isCode(read_addr):
                        self.lgr.debug('readHap hit addr: 0x%x is code HOHO?????????????????' % read_addr)
                        fun_name = self.top.getSO(read_addr, with_fun=True)
                        print('Ref to code ptr 0x%x, fun %s, offset 0x%x into malloc addr 0x%x size 0x%x' % (read_addr, fun_name, offset, addr, 
                             self.malloc_map[addr]))
                

    def allocCallback(self, function, addr, size=None):
        self.lgr.debug('watchMalloc allocCallback fun %s addr 0x%x' % (function, addr))
        if addr in self.malloc_map:
            self.lgr.debug('watchMalloc allocCallback HIT ONE OF OURS!  fun %s addr 0x%x' % (function, addr))
