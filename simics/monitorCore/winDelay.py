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
Handle read/recv system calls with asynchronous results.  Sets a hap on the
address that is to contain the byte count and generates a trace message
when the kernel writes to the address.
'''
from simics import *
class WinDelay():
    def __init__(self, cpu, count_addr, buffer_addr, mem_utils, context_manager, trace_mgr, call_name, kbuffer, fd, lgr):
        self.cpu = cpu
        self.count_addr = count_addr
        self.buffer_addr = buffer_addr
        self.mem_utils = mem_utils
        self.context_manager = context_manager
        self.trace_mgr = trace_mgr
        self.call_name = call_name
        ''' used for prep inject watch to locate kernel buffers for data injection. '''
        self.kbuffer = kbuffer

        self.lgr = lgr
        self.fd = fd
        self.count_write_hap = None
        ''' used for data tracking, e.g., trackIO '''
        self.data_watch = None
        self.linger = None

        self.cycles = self.cpu.cycles
        ''' Set the hap'''    
        self.setCountWriteHap()

    def setDataWatch(self, data_watch, linger):
        self.data_watch = data_watch
        self.linger = linger

    def doDataWatch(self, return_count, trace_msg):
        if self.data_watch is not None:
            self.data_watch.setRange(self.buffer_addr, return_count, msg=trace_msg, 
                       max_len=return_count, recv_addr=self.buffer_addr, fd=self.fd)
            if self.linger: 
                self.data_watch.stopWatch() 
                self.data_watch.watch(break_simulation=False, i_am_alone=True)

    def setCountWriteHap(self):
        ''' Set a break/hap on the address at which we think the kernel will write the byte count from an asynch read/recv '''
        proc_break = self.context_manager.genBreakpoint(None, Sim_Break_Linear, Sim_Access_Write, self.count_addr, 1, 0)
        self.count_write_hap = self.context_manager.genHapIndex("Core_Breakpoint_Memop", self.writeCountHap, None, proc_break, 'winDelayCountHap')

    def writeCountHap(self, dumb, third, forth, memory):
        ''' Invoked when the count address is written to '''
        if self.count_write_hap is None:
            return
        return_count = SIM_get_mem_op_value_le(memory)

        #return_count = self.mem_utils.readWord32(self.cpu, self.count_addr)
        self.lgr.debug('winDelay writeCountHap read count from 0x%x got 0x%x' % (self.count_addr, return_count))
        if return_count == 0:
            self.lgr.debug('WinDelay return count of zero.  now what?')
        else:
            max_read = min(return_count, 100)
            read_data = self.mem_utils.readString(self.cpu, self.buffer_addr, max_read)
            trace_msg = self.call_name+' completed from cycle 0x%x count 0x%x data %s\n' % (self.cycles, return_count, read_data)
            self.trace_mgr.write(trace_msg)
            self.lgr.debug('winDelay writeCountHap %s' % trace_msg)
            #SIM_break_simulation('WinDelay')
            self.doDataWatch(return_count, trace_msg)
        ''' Remove the break/hap '''
        hap = self.count_write_hap
        SIM_run_alone(self.rmHap, hap) 
        self.count_write_hap = None
        
    def rmHap(self, hap): 
        self.context_manager.genDeleteHap(self.count_write_hap)
