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
import resimUtils
import net
class WinDelay():
    def __init__(self, top, cpu, count_addr, buffer_addr, sock_addr, mem_utils, context_manager, trace_mgr, 
                  call_name, kbuffer, fd, count, lgr, watch_count_addr=True):
        self.top = top
        self.cpu = cpu
        self.count_addr = count_addr
        self.buffer_addr = buffer_addr
        self.sock_addr = sock_addr
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
        if watch_count_addr:
            ''' Set the hap'''    
            self.setCountWriteHap()
        else:
            self.return_count = count

        ''' assess call params.  Note exit_info.call_params is the data structure generated as part of the syscall.  Changes made here
            affect that structure.
        '''
        self.exit_info = None

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
            self.data_watch.setRange(self.count_addr, 4, msg='read count')
            if self.sock_addr is not None:
                self.data_watch.setRange(self.sock_addr, 8, msg='source address')
                self.exit_info.sock_addr = self.sock_addr
                self.lgr.debug('winDelay doDataWatch sock_struct addr 0x%x' % self.sock_addr)
            if self.linger: 
                self.data_watch.stopWatch() 
                self.data_watch.watch(break_simulation=False, i_am_alone=True)
            #if not self.top.isRunning():
            #    SIM_continue(0)
        else:
            ''' assume we got here due to call parameters '''
            my_syscall = self.exit_info.syscall_instance
            #if not my_syscall.linger: 
            #    self.stopTrace()
            if my_syscall is None:
                self.lgr.error('winCallExit could not get syscall for %s' % self.call_name)
            else:
                #if eax != 0:
                #    new_msg = exit_info.trace_msg + ' ' + trace_msg
                #    self.context_manager.setIdaMessage(new_msg)
                self.context_manager.setIdaMessage('%s %s' % (self.call_name, self.trace_msg))
                self.lgr.debug('winCallExit call stopAlone of syscall')
                SIM_run_alone(my_syscall.stopAlone, self.call_name)
                self.top.idaMessage() 
        RES_hap_delete_callback_id("Core_Mode_Change", self.mode_hap)
        self.mode_hap = None

    def setCountWriteHap(self):
        ''' Set a break/hap on the address at which we think the kernel will write the byte count from an asynch read/recv '''
        proc_break = self.context_manager.genBreakpoint(None, Sim_Break_Linear, Sim_Access_Write, self.count_addr, 1, 0)
        self.count_write_hap = self.context_manager.genHapIndex("Core_Breakpoint_Memop", self.writeCountHap, None, proc_break, 'winDelayCountHap')
        self.lgr.debug('winDelay setCountWriteHap to 0x%x' % self.count_addr)
        #proc_break = self.context_manager.genBreakpoint(None, Sim_Break_Linear, Sim_Access_Write, self.buffer_addr, self.count, 0)
        #self.count_write_hap = self.context_manager.genHapIndex("Core_Breakpoint_Memop", self.writeBufferHap, None, proc_break, 'winDelayBufferHap')

    #def writeBufferHap(self, dumb, third, forth, memory):
    #    SIM_break_simulation('wrote to buffer 0x%x' % self.buffer_addr)

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
            #read_data = self.mem_utils.readString(self.cpu, self.buffer_addr, max_read)

            byte_array = self.mem_utils.getBytes(self.cpu, return_count, self.buffer_addr)
            if byte_array is not None:
                read_data = resimUtils.getHexDump(byte_array[:max_read])
                # TBD add traceFiles to windows
                #if self.traceFiles is not None:
                #    self.traceFiles.read(pid, exit_info.old_fd, byte_array)
            else:
                read_data = '<< NOT MAPPED >>'

            if self.did_exit:
                trace_msg = self.call_name+' completed from cycle: 0x%x count: 0x%x requested: 0x%x data: %s\n' % (self.cycles, return_count, 
                   self.exit_info.count, repr(read_data))
                self.trace_mgr.write(trace_msg)
                self.lgr.debug('winDelay writeCountHap already did exit so log the trace message %s' % trace_msg)
            else:
                trace_msg = self.call_name+' return count: 0x%x request: 0x%x data: %s\n' % (return_count, self.exit_info.count, repr(read_data))
                self.lgr.debug('winDelay writeCountHap have not yet done exit so log SAVE the trace message %s' % trace_msg)
            if self.call_name == 'RECV_DATAGRAM':
                self.lgr.debug('winDelay get sock struct from addr 0x%x' % self.sock_addr)
                self.exit_info.sock_addr = self.sock_addr
                sock_struct = net.SockStruct(self.cpu, self.sock_addr, self.mem_utils, -1)
                sock_string = sock_struct.getString()
                trace_msg = trace_msg + ' '+sock_string+'\n'
                self.lgr.debug('winDelay RECV_DATAGRAM socket addr %s' % sock_string)
                #SIM_break_simulation(trace_msg)
                if self.exit_info is not None and self.exit_info.call_params is not None and self.exit_info.call_params.sub_match is not None:
                    self.lgr.debug('winDelay sees a submatch, test it')
                    byte_index = 0
                    match = True
                    for c in self.exit_info.call_params.sub_match:
                        v = byte_array[byte_index]
                        if c != chr(v):
                            match = False
                            self.lgr.debug('winDelay failed sub_match. %x does not match %x' % (ord(c), v))
                            break
                    if match:
                        self.lgr.debug('winDelay got sub_match.')  
                        self.exit_info.call_params.sub_match = None
                    else:
                        self.exit_info.call_params = None

            #SIM_break_simulation('WinDelay')
            # we are in the kernel at some arbitrary place.  run to user space
            self.return_count = return_count
            self.trace_msg = trace_msg
            self.lgr.debug('winDelay writeCountHap trace_msg: %s' % trace_msg)
            if (self.data_watch is not None or (self.exit_info.call_params is not None and self.exit_info.call_params.break_simulation)) and self.did_exit:
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
            # hack to avoid repeating call name
            self.trace_msg = self.trace_msg.split(' ', 1)[1]
            combined_msg = trace_msg + ' '+self.trace_msg
            self.trace_mgr.write(combined_msg)
            self.lgr.debug('winDelay exitingKernel already got data so log the trace message %s' % combined_msg)
            if self.data_watch is not None or (self.exit_info is not None and self.exit_info.call_params is not None and self.exit_info.call_params.break_simulation):
                self.lgr.debug('winDelay exitingKernel do data watch or break simulation due to call params')
                SIM_run_alone(self.toUserAlone, None)
        else:
            self.lgr.debug('winDelay exitingKernel did not yet see data')
            self.did_exit = True
        return retval

    def setExitInfo(self, exit_info):
        self.exit_info = exit_info

