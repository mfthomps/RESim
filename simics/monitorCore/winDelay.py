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
from resimHaps import *
import memUtils
class WinDelay():
    def __init__(self, top, cpu, count_addr, buffer_addr, mem_utils, context_manager, trace_mgr, call_name, kbuffer, fd, lgr, count=None):
        self.top = top
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
        self.mode_hap = None

        self.cycles = self.cpu.cycles
        self.return_count = None
        self.trace_msg = None
        self.count = count

        ''' Control when to generate watch marks and trace messages'''
        self.did_exit = False

        ''' wth?'''
        self.hack_count = 0

        ''' Count provided by writeData, e.g., for injectIO.  WinDelay created just for purpose of returning to user space and setting data watch'''
        if count is None:
            ''' Set the hap'''    
            self.setCountWriteHap()
        else:
            self.return_count = count

    def setDataWatch(self, data_watch, linger):
        self.lgr.debug('winDelay setDataWatch')
        if self.top.tracking():
            self.lgr.debug('winDelay setDataWatch setting data_watch')
            self.data_watch = data_watch
            self.linger = linger
            self.data_watch.registerHapForRemoval(self)

    def doDataWatch(self, dumb=None):
        if self.data_watch is not None:
            self.lgr.debug('winDelay doDataWatch call setRange for 0x%x count 0x%x' % (self.buffer_addr, self.return_count))
            if self.kbuffer is not None:
                self.kbuffer.readReturn(self.return_count)
            self.data_watch.setRange(self.buffer_addr, self.return_count, msg=self.trace_msg, 
                       max_len=self.return_count, recv_addr=self.buffer_addr, fd=self.fd)
            if self.linger: 
                self.data_watch.stopWatch() 
                self.data_watch.watch(break_simulation=False, i_am_alone=True)
            RES_hap_delete_callback_id("Core_Mode_Change", self.mode_hap)
            self.mode_hap = None
            #if not self.top.isRunning():
            #    SIM_continue(0)

    def setCountWriteHap(self):
        ''' Set a break/hap on the address at which we think the kernel will write the byte count from an asynch read/recv '''
        proc_break = self.context_manager.genBreakpoint(None, Sim_Break_Linear, Sim_Access_Write, self.count_addr, 1, 0)
        self.count_write_hap = self.context_manager.genHapIndex("Core_Breakpoint_Memop", self.writeCountHap, None, proc_break, 'winDelayCountHap')
        self.lgr.debug('winDelay setCountWriteHap to 0x%x' % self.count_addr)

    def writeCountHap(self, dumb, third, forth, memory):
        ''' Invoked when the count address is written to '''
        if self.count_write_hap is None or self.context_manager.isReverseContext():
            return
        if not self.did_exit and self.hack_count < 1:
            self.lgr.debug('winDelay writeCountHap skipping first kernel write to count address.  TBD if always needed.')
            self.hack_count = self.hack_count + 1
            return
        return_count = SIM_get_mem_op_value_le(memory)

        #return_count = self.mem_utils.readWord32(self.cpu, self.count_addr)
        self.lgr.debug('winDelay writeCountHap read count from 0x%x got 0x%x did exit? %r' % (self.count_addr, return_count, self.did_exit))
        if return_count == 0:
            self.lgr.debug('winDelay return count of zero.  now what?')
        else:
            max_read = min(return_count, 100)
            read_data = self.mem_utils.readString(self.cpu, self.buffer_addr, max_read)
            if self.did_exit:
                trace_msg = self.call_name+' completed from cycle: 0x%x count: 0x%x data: %s\n' % (self.cycles, return_count, repr(read_data))
                self.trace_mgr.write(trace_msg)
                self.lgr.debug('winDelay writeCountHap already did exit so log the trace message %s' % trace_msg)
            else:
                trace_msg = self.call_name+' return  count: 0x%x data: %s\n' % (return_count, repr(read_data))
                self.lgr.debug('winDelay writeCountHap have not yet done exit so log SAVE the trace message %s' % trace_msg)
            #SIM_break_simulation('WinDelay')
            # we are in the kernel at some arbitrary place.  run to user space
            self.return_count = return_count
            self.trace_msg = trace_msg
            self.lgr.debug('winDelay writeCountHap trace_msg: %s' % trace_msg)
            if self.data_watch is not None and self.did_exit:
                SIM_run_alone(self.toUserAlone, None)
        ''' Remove the break/hap '''
        hap = self.count_write_hap
        SIM_run_alone(self.rmHap, hap) 
        self.count_write_hap = None

    def toUserAlone(self, dumb):
        pid = self.top.getPID()
        self.mode_hap = RES_hap_add_callback_obj("Core_Mode_Change", self.cpu, 0, self.modeChanged, pid)
        self.lgr.debug('windDelay toUserAlone, set mode hap for pid %d' % pid)

    def modeChanged(self, want_pid, one, old, new):
        if self.mode_hap is None:
            return
        this_pid = self.top.getPID()
        if want_pid != this_pid:
            self.lgr.debug('windDelay mode changed wrong pid, wanted %d got %d' % (want_pid, this_pid))
            return
        cpl = memUtils.getCPL(self.cpu)
        if new == Sim_CPU_Mode_Supervisor:
            self.lgr.warning('windDelay mode changed wrong mode, new is supervisor?')
        else:
            self.lgr.debug('windDelay mode changed in user, call doDataWatch')
            SIM_run_alone(self.doDataWatch, None)
        
    def rmHap(self, hap, immediate=False): 
        self.context_manager.genDeleteHap(hap, immediate=immediate)
        self.lgr.debug('winDelay rmHap removed hap %d' % hap)

    def rmAllHaps(self, immediate=False):
        self.lgr.debug('winDelay rmAllHaps')
        if self.count_write_hap is not None:
            hap = self.count_write_hap
            if immediate:
                self.rmHap(hap, immediate=True)
            else:
                SIM_run_alone(self.rmHap, hap) 
            self.count_write_hap = None

    def exitingKernel(self, trace_msg, not_ready):
        retval = False
        if self.trace_msg is not None:
            '''Data and count already written, log it '''
            retval = True
            if not_ready:
                self.trace_msg = self.trace_msg+ ' Though kernel reported not ready.\n'
            self.trace_mgr.write(self.trace_msg)
            self.lgr.debug('winDelay exitingKernel already got data so log the trace message %s' % self.trace_msg)
            if self.data_watch is not None:
                self.lgr.debug('winDelay exitingKernel do data watch')
                SIM_run_alone(self.toUserAlone, None)
        else:
            self.lgr.debug('winDelay exitingKernel did not yet see data')
            self.did_exit = True
        return retval



