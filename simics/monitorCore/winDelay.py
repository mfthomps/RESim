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
    def __init__(self, top, cpu, tid, comm, exit_info, sock_addr, mem_utils, context_manager, trace_mgr, 
                  call_name, kbuffer, fd, count, stop_action, lgr, watch_count_addr=True):
        self.top = top
        self.cpu = cpu
        self.tid = tid
        self.comm = comm
        ''' Note exit_info and its structs, e.g., exit_info.call_params are data structures generated as part of the syscall.  Changes made here
            affect those structures.
        '''
        self.exit_info = exit_info
        self.sock_addr = sock_addr
        self.mem_utils = mem_utils
        self.context_manager = context_manager
        self.trace_mgr = trace_mgr
        self.call_name = call_name
        ''' used for prepInjectWatch to locate kernel buffers for data injection. '''
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
        # used for prepInject
        self.stop_action = stop_action

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
        ''' delete mode hap after this number of mode changes that are not the tid we are looking for '''
        self.to_user_limit = 5000
        self.to_user_count = 0

        self.do_not_stop = False
        self.device_not_ready = False

        self.read_fixup_callback = None

        self.traceFiles = self.top.getTraceFiles()

    def setDataWatch(self, data_watch, linger):
        #self.lgr.debug('winDelay setDataWatch')
        if self.top.tracking():
            self.lgr.debug('winDelay setDataWatch setting data_watch')
            self.data_watch = data_watch
            self.linger = linger
            self.data_watch.registerHapForRemoval(self)

    def doDataWatch(self, did_delay):
        if self.exit_info is None:
            self.lgr.debug('winDelay doDataWatch BUT NO EXIT INFO')
            return
        self.lgr.debug('winDelay doDataWatch')
        if self.data_watch is not None:
            self.lgr.debug('winDelay doDataWatch call setRange for 0x%x count 0x%x' % (self.exit_info.retval_addr, self.return_count))
            if self.kbuffer is not None:
                self.kbuffer.readReturn(self.return_count)
            if self.trace_msg is None:
                self.trace_msg = 'Injected data copied to 0x%x %d bytes' % (self.exit_info.retval_addr, self.return_count)
            self.data_watch.setRange(self.exit_info.retval_addr, self.return_count, msg=self.trace_msg, 
                       max_len=self.return_count, recv_addr=self.exit_info.retval_addr, fd=self.fd)

            if did_delay:
                #count_addr = self.exit_info.delay_count_addr
                self.exit_info.did_delay = True
            else:
                #count_addr = self.exit_info.count_addr
                pass
            #self.data_watch.setRange(count_addr, 4, msg='read count')
            self.data_watch.setRange(self.exit_info.delay_count_addr, 4, msg='read count')
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
            ''' assume we got here due to call parameters or stop_action'''
            self.lgr.debug('winDelay doDataWatch no dataWatch stop_action is %s' % str(self.stop_action))
            my_syscall = self.exit_info.syscall_instance
            #if not my_syscall.linger: 
            #    self.stopTrace()
            if my_syscall is None:
                self.lgr.error('winDelay doDataWatch could not get syscall for %s' % self.call_name)
            elif not my_syscall.linger and not self.do_not_stop:
                # TBD should not be soley based on linger.  break_simulation parameter?
                #if eax != 0:
                #    new_msg = exit_info.trace_msg + ' ' + trace_msg
                #    self.context_manager.setIdaMessage(new_msg)
                self.context_manager.setIdaMessage('%s %s' % (self.call_name, self.trace_msg))
                self.lgr.debug('winDelay doDataWatch call stopAlone of syscall')
                SIM_run_alone(my_syscall.stopAlone, self.call_name)
                self.top.idaMessage() 
        if self.mode_hap is not None:
            RES_hap_delete_callback_id("Core_Mode_Change", self.mode_hap)
            self.mode_hap = None
        self.remove()

    def setCountWriteHap(self):
        if self.count_write_hap is None:
            if self.exit_info.delay_count_addr is None:
                self.lgr.debug('winDelay setCountWriteHap but delay_count_addr is None')
            else:
                ''' Set a break/hap on the address at which we think the kernel will write the byte count from an asynch read/recv '''
                proc_break = self.context_manager.genBreakpoint(None, Sim_Break_Linear, Sim_Access_Write, self.exit_info.delay_count_addr, 1, 0)
                name = 'windDelayCountHap-%s' % self.tid
                self.count_write_hap = self.context_manager.genHapIndex("Core_Breakpoint_Memop", self.writeCountHap, None, proc_break, name)
                self.lgr.debug('winDelay setCountWriteHap to 0x%x hap %d module %s delay_count_addr 0x%x' % (self.exit_info.delay_count_addr, self.count_write_hap, str(self), self.exit_info.delay_count_addr))
            #proc_break = self.context_manager.genBreakpoint(None, Sim_Break_Linear, Sim_Access_Write, self.exit_info.retval_addr, self.count, 0)
            #self.count_write_hap = self.context_manager.genHapIndex("Core_Breakpoint_Memop", self.writeBufferHap, None, proc_break, 'winDelayBufferHap')
        else:
            self.lgr.warning('winDelay setCountWriteHap already set!!!')

    #def writeBufferHap(self, dumb, third, forth, memory):
    #    SIM_break_simulation('wrote to buffer 0x%x' % self.exit_info.retval_addr)

    def getIOData(self, return_count, count_addr):
        #return_count = self.mem_utils.readWord32(self.cpu, self.exit_info.count_addr)
        self.lgr.debug('winDelay getIOData tid:%s read count from 0x%x got 0x%x did exit? %r' % (self.tid, count_addr, return_count, self.did_exit))
        if return_count == 0:
            self.lgr.debug('winDelay return count of zero.  now what?')
        else:
            max_read = min(return_count, 500)
            max_bytes = min(return_count, 2000)
            #read_data = self.mem_utils.readString(self.cpu, self.exit_info.retval_addr, max_read)

            byte_array = self.mem_utils.getBytes(self.cpu, max_bytes, self.exit_info.retval_addr)
            if byte_array is not None:
                read_data = resimUtils.getHexDump(byte_array[:max_read])
                if self.traceFiles is not None:
                    tid = self.top.getTID()
                    self.traceFiles.read(tid, self.exit_info.old_fd, byte_array)
            else:
                read_data = '<< NOT MAPPED >>'

            if self.did_exit:
                trace_msg = self.call_name+' completed from cycle: 0x%x tid:%s (%s) handle: 0x%x count: 0x%x into buffer: 0x%x requested: 0x%x data: %s\n' % (self.cycles, self.tid, self.comm, self.fd, return_count, 
                   self.exit_info.retval_addr, self.exit_info.count, repr(read_data))
                self.trace_mgr.write(trace_msg)
                self.lgr.debug('winDelay getIOData already did exit so log the trace message %s' % trace_msg)
            else:
                trace_msg = self.call_name+' handle: 0x%x return count: 0x%x request: 0x%x address: 0x%x data: %s\n' % (self.fd, return_count, self.exit_info.count, self.exit_info.retval_addr, repr(read_data))
                self.lgr.debug('winDelay getIOData tid:%s getIOData have not yet done exit so log SAVE the trace message %s' % (self.tid, trace_msg))
            if self.call_name == 'RECV_DATAGRAM':
                self.lgr.debug('winDelay getIOData tid:%s get sock struct from addr 0x%x' % (self.tid, self.sock_addr))
                self.exit_info.sock_addr = self.sock_addr
                sock_struct = net.SockStruct(self.cpu, self.sock_addr, self.mem_utils, -1)
                sock_string = sock_struct.getString()
                trace_msg = trace_msg + ' '+sock_string+'\n'
                self.lgr.debug('winDelay getIOData RECV_DATAGRAM socket addr %s' % sock_string)
                #SIM_break_simulation(trace_msg)
            if self.call_name in ['RECV_DATAGRAM', 'RECV', 'SEND', 'SEND_DATAGRAM']:
                for call_param in self.exit_info.call_params:
                    self.lgr.debug('winDelay getIOData param name %s check for call %s sub_match is %s' % (call_param.name, self.call_name, call_param.sub_match))
                    if call_param.match_param is not None and call_param.name in ['runToReceive', 'runToSend']:
                        if call_param.match_param in read_data:
                            self.lgr.debug('winDelay getIOData got match of matched_param.')  
                            call_param.match_param = None
                            self.exit_info.matched_param = call_param
                        else:
                            self.exit_info.matched_param = None
                            self.do_not_stop = True
                            pass
                    elif call_param.sub_match is not None and call_param.name in ['runToIO']:
                        if call_param.sub_match in read_data:
                            self.lgr.debug('winDelay getIOData got match of sub_match.')  
                            call_param.match_param = None
                            self.exit_info.matched_param = call_param
                        else:
                            self.exit_info.matched_param = None
                            self.do_not_stop = True
                            pass

            self.trace_msg = trace_msg
            self.lgr.debug('winDelay getIOData trace_msg: %s' % trace_msg)
                
        self.return_count = return_count

    def writeCountHap(self, dumb, third, forth, memory):
        ''' Invoked when the count address is written to '''
        if self.count_write_hap is None or self.context_manager.isReverseContext():
            return
        if not self.did_exit and self.hack_count < 1:
            return_count = memUtils.memoryValue(self.cpu, memory)
            self.lgr.debug('winDelay writeCountHap tid:%s skipping first kernel write to count address, value is 0x%x.  TBD if always needed.' % (self.tid, return_count))
            self.hack_count = self.hack_count + 1
            return
        if memory.size > 8:
            self.lgr.error('winDelay writeCountHap memory size > 8: %d  ???? module %s' % (memory.size, str(self)))
            return
        else:
            return_count = memUtils.memoryValue(self.cpu, memory)
        if return_count > 0: 
            tid = self.top.getTID()
            if tid != self.tid:
                self.lgr.debug('winDelay writeCountHap for self.tid %s, but current tid is %s' % (self.tid, tid))
            else:
                self.lgr.debug('winDelay writeCountHap tid:%s module %s' % (self.tid, str(self)))
            if self.read_fixup_callback is not None:
                # adjust return count and track data read from kernel buffer if applicable
                self.lgr.debug('winDelay writeCountHap call read fixup callback')
                fixed_count = self.read_fixup_callback(self.exit_info.old_fd, self.exit_info.delay_count_addr)
                self.read_fixup_callback = None 
            # TBD ?
            #self.getIOData(return_count, memory.logical_address)
            self.getIOData(return_count, self.exit_info.delay_count_addr)
            #SIM_break_simulation('WinDelay')
            # we are in the kernel at some arbitrary place.  run to user space
            if (self.data_watch is not None or self.stop_action is not None or (self.exit_info.matched_param is not None and self.exit_info.matched_param.break_simulation)) and self.did_exit:
                SIM_run_alone(self.toUserAlone, None)
            ''' Remove the break/hap '''
            hap = self.count_write_hap
            self.lgr.debug('winDelay writeCountHap tid:%s return_count was %d from address 0x%x, removing count_write_hap %d' % (self.tid, return_count, memory.logical_address, hap))
            SIM_run_alone(self.rmHap, hap) 
            self.count_write_hap = None
            #if self.did_exit and self.exit_info.syscall_instance is not None:
            #    self.lgr.debug('winDelay writeCountHap remove win delay for tid:%s fd 0x%x' % (self.tid, self.exit_info.old_fd))
            #    self.exit_info.syscall_instance.rmWinDelay(self.tid, self.exit_info.old_fd)
        else:
            self.lgr.debug('winDelay writeCountHap got count of zero, assume kernel init')

    def toUserAlone(self, dumb):
        self.to_user_count = 0
        self.mode_hap = RES_hap_add_callback_obj("Core_Mode_Change", self.cpu, 0, self.modeChanged, self.tid)
        self.lgr.debug('winDelay toUserAlone, set mode hap for tid:%s' % self.tid)

    def modeChanged(self, want_tid, one, old, new):
        if self.mode_hap is None:
            return
        this_tid = self.top.getTID()
        if want_tid != this_tid:
            self.to_user_count = self.to_user_count+1
            if self.to_user_count > self.to_user_limit:
                self.lgr.warning('winDelay mode changed wrong tid, wanted %s got %s HIT LIMIT, remove mode hap' % (want_tid, this_tid))
                self.to_user_count = 0
                SIM_run_alone(self.doDataWatch, True)
            else:    
                #self.lgr.debug('winDelay mode changed wrong tid, wanted %s got %s' % (want_tid, this_tid))
                return
        cpl = memUtils.getCPL(self.cpu)
        if new == Sim_CPU_Mode_Supervisor:
            self.lgr.warning('winDelay mode changed wrong mode, new is supervisor?')
        else:
            self.lgr.debug('winDelay mode changed in user, call doDataWatch')
            SIM_run_alone(self.doDataWatch, True)
        
    def rmHap(self, hap, immediate=False): 
        self.context_manager.genDeleteHap(hap, immediate=immediate)
        self.lgr.debug('winDelay tid:%s rmHap removed hap %d' % (self.tid, hap))

    def rmAllHaps(self, immediate=False):
        #self.lgr.debug('winDelay rmAllHaps immediate: %r' % immediate)
        if self.count_write_hap is not None:
            hap = self.count_write_hap
            if immediate:
                self.rmHap(hap, immediate=True)
            else:
                SIM_run_alone(self.rmHap, hap) 
            self.count_write_hap = None
            #self.lgr.debug('winDelay rmAllHaps removed count_write_hap')

    def exitingKernel(self, trace_msg, not_ready, read_fixup_callback):
        retval = False
        if self.call_name in ['RECV_DATAGRAM', 'RECV', 'ReadFile']:
            self.lgr.debug('winDelay exitingKernel set read_fixup_callback to %s' % read_fixup_callback)
            self.read_fixup_callback = read_fixup_callback
        if self.trace_msg is not None or not not_ready:
            if self.trace_msg is None and not not_ready:
                #if self.exit_info.count_addr is None:
                if self.exit_info.delay_count_addr is None:
                    self.lgr.debug('winDelay exitingKernel tid:%s with no delay but exit_info.delay_count_addr is None' % self.tid)
                    return 
                return_count = self.mem_utils.readWord32(self.cpu, self.exit_info.delay_count_addr)
                if return_count is None:
                    self.lgr.debug('winDelay exitingKernel tid:%s with no delay return_count none reading from count addr 0x%x' % (self.tid, self.exit_info.delay_count_addr))
                    return 
                self.lgr.debug('winDelay exitingKernel tid:%s with no delay assume data it is there, return count 0x%x' % (self.tid, return_count))
                if return_count > 0:
                    if self.read_fixup_callback is not None:
                        # adjust return count and track data read from kernel buffer if applicable
                        self.lgr.debug('winDelay exitingKernel call read fixup callback')
                        fixed_count = self.read_fixup_callback(self.exit_info.old_fd, self.exit_info.delay_count_addr)
                        self.read_fixup_callback = None 

                    self.getIOData(return_count, self.exit_info.delay_count_addr)
                    if self.data_watch is not None or (self.exit_info is not None and self.exit_info.matched_param is not None and self.exit_info.matched_param.break_simulation):
                        self.doDataWatch(False)
                    combined_msg = trace_msg + ' '+self.trace_msg
                    self.trace_mgr.write(combined_msg)
                self.remove()
                retval = True
                #self.lgr.debug('winDelay exitingKernel with no delay and no sign of data.  no idea what to think')
                #self.did_exit=True
            else:
                '''Data and count already written, log it '''
                retval = True
                if not_ready:
                    self.trace_msg = self.trace_msg+ ' Though kernel reported not ready.\n'
                # hack to avoid repeating call name
                #self.trace_msg = self.trace_msg.split(' ', 1)[1]
                combined_msg = trace_msg + ' '+self.trace_msg
                self.trace_mgr.write(combined_msg)
                self.lgr.debug('winDelay exitingKernel tid:%s already got data so log the trace message %s' % (self.tid, combined_msg))
                if self.data_watch is not None or (self.exit_info is not None and self.exit_info.matched_param is not None and self.exit_info.matched_param.break_simulation):
                    self.lgr.debug('winDelay exitingKernel do data watch or break simulation due to call params')
                    SIM_run_alone(self.toUserAlone, None)
                #if self.exit_info.syscall_instance is not None:
                #    self.lgr.debug('winDelay exitingKernel remove win delay for tid:%s fd 0x%x' % (self.tid, self.exit_info.old_fd))
                #    self.exit_info.syscall_instance.rmWinDelay(self.tid, self.exit_info.old_fd)
                if self.read_fixup_callback is not None:
                    # adjust return count and track data read from kernel buffer if applicable
                    self.lgr.debug('winDelay exitingKernel after data and count already written, call read fixup callback')
                    fixed_count = self.read_fixup_callback(self.exit_info.old_fd, self.exit_info.delay_count_addr)
                    self.read_fixup_callback = None 
        else:
            self.lgr.debug('winDelay exitingKernel tid:%s did not yet see data' % self.tid)
            self.did_exit = True
        return retval
    def remove(self):
        self.lgr.debug('winDelay remove tid:%s' % self.tid)
        self.rmAllHaps()
        self.exit_info = None
        self.device_not_ready = False

    def deviceNotReady(self):
        self.device_not_ready = True
