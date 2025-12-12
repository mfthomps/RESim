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
from simics import *
import sys
import os
import pickle
import taskUtils
import winDelay
import winSocket
import net
import syscall
from resimSimicsUtils import rprint
from resimHaps import *
import syscall
'''
Inject data into memory buffers
'''
class WriteData():
    def __init__(self, top, cpu, in_data, expected_packet_count, 
                 mem_utils, context_manager, backstop, snapshot_name, lgr, udp_header=None, pad_to_size=None, filter=None, 
                 force_default_context=False, backstop_cycles=None, stop_on_read=False, ioctl_count_max=None, select_count_max=None, write_callback=None, limit_one=False, 
                  dataWatch=None, shared_syscall=None, no_reset=None, set_ret_hap=True, backstop_delay=None, stop_callback=None):
        ''' expected_packet_count == -1 for TCP '''
        # genMonitor
        self.top = top
        self.cpu = cpu
        if force_default_context:
            self.cell = self.top.getCell()
        else:
            self.cell = self.top.getRESimContext()
        # The data to write, e.g., from a file or from AFL
        self.in_data = in_data
        self.orig_in_data = in_data
        # How many packets we expect to write overall.  
        #   -1 -- write max_length bytes until all data is gone
        #   Otherwise, if udp_header, use that as delimiter to
        #                 write multiple packets.  Truncate if needed.
        #                 And pad to pad_to_size if defined.
        #              else
        #                 Use pad_to_size to split data into packets,
        #                 and pad the last (or only) packet.
        self.expected_packet_count = expected_packet_count
        # Memory location in which to wrte
        self.addr = None
        self.max_len = 9999

        # Use to skip over kernel recv processing
        self.call_ip = None
        self.return_ip = None
        self.select_call_ip = None
        self.select_return_ip = None
        self.k_start_ptr = None
        self.k_end_ptr = None

        self.fd = None

        #  NOTE all these haps get deleted on startup, so don't 
        #  create them until they are needed.
        self.call_hap = None
        self.call_break = None
        self.select_hap = None
        self.select_break = None
        self.poll_hap = None
        self.poll_break = None
        self.ret_hap = None
        self.ret_break = None
        self.close_hap = None
        self.close_break = None
        # see in_data
        if sys.version_info[0] > 2 and type(udp_header) == str:
            self.udp_header = bytes(udp_header, encoding='utf8')
        else:
            self.udp_header = udp_header
        self.pad_to_size = pad_to_size
        self.mem_utils = mem_utils
        self.context_manager = context_manager
        self.backstop = backstop
        self.backstop_cycles = backstop_cycles
        self.backstop_delay = backstop_delay
        if backstop_delay is not None:
            self.backstop.setDelay(backstop_delay)
        self.write_callback = write_callback
        self.lgr = lgr
        self.limit_one = limit_one
        self.set_ret_hap = set_ret_hap
        self.max_packets = os.getenv('AFL_MAX_PACKETS')
        if self.max_packets is not None:
            self.max_packets = int(self.max_packets)

        if self.cpu.architecture == 'arm':
            lenreg = 'r0'
            pcreg = 'pc'
        elif self.cpu.architecture == 'arm64':
            lenreg = 'x0'
            pcreg = 'pc'
        elif self.cpu.architecture == 'ppc32':
            lenreg = 'r3'
            pcreg = 'pc'
        else:
            lenreg = 'eax'
            pcreg = 'eip'
        self.len_reg_num = self.cpu.iface.int_register.get_number(lenreg)
        self.pc_reg = self.cpu.iface.int_register.get_number(pcreg)

        # most recent packet we've written
        self.current_packet = 0

        self.stop_on_read = stop_on_read
        self.ioctl_count_max = ioctl_count_max
        self.ioctl_count = 0
        self.select_count_max = select_count_max
        self.select_count = 0
        self.k_bufs = None
        self.k_buf_len = None
        self.orig_buffer = None
        # for restoring user space to what it was, less what we read from the kernel
        self.user_space_addr = None
        self.user_space_count = None

        # for windows
        self.addr_of_count = None

        self.stop_callback = stop_callback

        self.loadPickle(snapshot_name)

        if self.call_ip is not None:
            self.lgr.debug('writeData packet count %d add: 0x%x max_len (before adjust) %d in_data len: %d call_ip: 0x%x return_ip: 0x%x context: %s stop_on_read: %r udp: %s' % (self.expected_packet_count, 
                 self.addr, self.max_len, len(in_data), self.call_ip, self.return_ip, str(self.cell), self.stop_on_read, self.udp_header))
        else:
            self.lgr.debug('writeData packet count %d add: 0x%x max_len %d in_data len: %d context: %s stop_on_read: %r udp: %s' % (self.expected_packet_count, 
                 self.addr, self.max_len, len(in_data), str(self.cell), self.stop_on_read, self.udp_header))

        self.tid = self.top.getTID()
        self.filter = filter
        self.dataWatch = dataWatch
        env_max_len = os.getenv('AFL_MAX_LEN')
        if env_max_len is not None:
            #if self.max_len is None or self.max_len > int(env_max_len):
            self.lgr.debug('writeData Overrode max_len value from pickle with value from environment')
            self.max_len = int(env_max_len)

        stop_on_close_env = os.getenv('AFL_STOP_ON_CLOSE')
        self.stop_on_close = False
        if stop_on_close_env is not None and stop_on_close_env.lower()=='true':
            self.stop_on_close = True
            self.lgr.debug('writeData, stop on close is true')

        self.total_read = 0
        self.read_limit = None
        ''' only restore call hap if there was one '''
        self.was_a_call_hap = False

        ''' support fixup of read counts '''
        self.shared_syscall = shared_syscall

        self.kernel_buf_consumed = False
        self.closed_fd = False
        self.no_reset = no_reset

        self.skip_read_n = os.getenv('AFL_SKIP_READ_N')
        if self.skip_read_n is not None:
            self.skip_read_n = int(self.skip_read_n)
            self.lgr.debug('writeData AFL_SKIP_READ_N is %d' % self.skip_read_n)
        if self.k_bufs is not None:
            ''' TBD clarify fix logic here '''
            self.read_count = 2
        else:
            self.read_count = 0
        ''' keep afl from running amuck'''
        self.udp_header_limit = 10
        self.no_call_hap = os.getenv('AFL_NO_CALL_HAP')
        if self.no_call_hap:
            self.lgr.debug('Preventing set of callHap')

        if self.top.isWindows():
            self.ioctl_op_map = winSocket.getOpMap()
        else:
            self.ioctl_op_map = None

        # TBD assumes single thread doing IO, change to dict?
        # start true to catch ret from kernel?
        self.pending_call = True
        self.pending_callname = None
        self.pending_select = None
        # know when to return 0 from ioctl
        self.ioctl_flag = None
        self.watch_ioctl = False
        self.tracing_io = False
        self.syscallManager = None

    def reset(self, in_data, expected_packet_count, addr):
        self.lgr.debug('writeData reset')
        self.in_data = in_data
        self.addr = addr
        self.expected_packet_count = expected_packet_count
        self.current_packet = 0
        self.total_read = 0
        if self.k_bufs is not None:
            ''' TBD clarify fix logic here '''
            self.read_count = 2
        else:
            self.read_count = 0
        self.kernel_buf_consumed = False
        self.closed_fd = False
        self.ioctl_count = 0
        self.select_count = 0
        self.pending_callname = None
        self.pending_select = None
        if self.backstop_delay is not None:
            self.backstop.setDelay(self.backstop_delay)

    def writeKdata(self, data):
        ''' write data to kernel buffers '''
        if self.k_bufs is None:
            ''' TBD remove this, all kernel buffers should now use k_bufs'''
            self.lgr.error('writeKdata, missing k_bufs')
            return
        else:
            remain = len(data)
            offset = 0
            index = 0
            ''' So we can restore use space content to what it was, less what we read from kernel 
                We are in a read system call, but not at the kernel entry.'''
            if self.user_space_count is None: 
                self.user_space_addr, self.user_space_count = self.top.getReadAddr()
            #self.lgr.debug('writeData writeKdata, user_space_buffer 0x%x count %d' % (self.user_space_addr, self.user_space_count))
            self.orig_buffer = self.mem_utils.readBytes(self.cpu, self.user_space_addr, self.user_space_count)
            #self.lgr.debug('writeData writeKdata, orig buf len %d' % len(self.orig_buffer))
            if not self.no_call_hap and not self.tracing_io:
                #self.lgr.debug('writeData writeKdata, call setCallHap and set total_read to %d' % self.user_space_count)
                self.setCallHap()
                # Account for initial bytes read since we will only catch incoming syscalls
                self.total_read = self.user_space_count
            while remain > 0:
                 if index >= len(self.k_bufs):
                     self.lgr.error('writeKdata index %d out of range with %d bytes remaining. len self.k_bufs is %d' % (index, remain, len(self.k_bufs)))
                     break
                 count = min(self.k_buf_len[index], remain)
                 end = offset + count
                 #self.lgr.debug('writeData writeKdata write %d bytes to 0x%x.  k_buf_len is %d remain: %d count: %d' % (len(data[offset:end]), self.k_bufs[index], self.k_buf_len[index], remain, count))
                 self.mem_utils.writeString(self.cpu, self.k_bufs[index], data[offset:end])
                 index = index + 1
                 offset = offset + count 
                 remain = remain - count
                 #self.lgr.debug('writeKdata offset %d remain %d' % (offset, remain))

            if self.top.isWindows() and self.dataWatch is not None:
                #self.lgr.debug('writeData writeKdata, use winDelay to set data watch ''')
                dum, comm, tid = self.top.getCurrentProc(target_cpu=self.cpu)
                exit_info = syscall.ExitInfo(None, self.cpu, tid, None, None, None, None)
                exit_info.retval_addr = self.user_space_addr
                exit_info.count_addr = self.addr_of_count
                exit_info.delay_count_addr = self.addr_of_count
                asynch_handler = winDelay.WinDelay(self.top, self.cpu, tid, comm, exit_info, self.user_space_addr, 
                        self.mem_utils, self.context_manager, None, None, None, self.fd, len(data), None, self.lgr, watch_count_addr=False)

                asynch_handler.setDataWatch(self.dataWatch, True)
                asynch_handler.toUserAlone(None)

          
    
    def write(self, record=False):
        ''' Write data into an application buffer or the kernel buffer, depending on information 
            recorded during the prepInject '''
        #self.lgr.debug('writeData write, addr is 0x%x filter: %s' % (self.addr, str(self.filter)))
        if self.k_start_ptr is not None:
            ''' we have buffer start/end info from tracing ioctl '''
            ''' TBD remove this, all kernel bufs now use kbuf?'''
            self.lgr.error('found k_start_ptr, deprecated?')
            return
            '''
            this_len = len(self.in_data)
            orig_len = self.getOrigLen()
            if this_len > orig_len:
                #self.lgr.warning('writeData kernel buffer writing %d bytes' % (this_len))
                pass 
            if self.filter is not None: 
                result = self.filter.filter(self.in_data, self.current_packet)
                self.mem_utils.writeString(self.cpu, self.addr, result) 
            else:
                self.mem_utils.writeString(self.cpu, self.addr, self.in_data) 
            retval = this_len
            self.modKernBufSize(this_len)
            #self.setCallHap()
            '''
        elif self.mem_utils.isKernel(self.addr):
            self.total_read = 0
            # not done, no control over size. prep must use maximum buffer
            if len(self.in_data) > self.max_len:
                self.in_data = self.in_data[:self.max_len]
                self.lgr.debug('writeData  write truncated in data to %d bytes' % self.max_len)
            if self.filter is not None: 
                result = self.filter.filter(self.in_data, self.current_packet)
                if len(result) > self.max_len:
                    self.lgr.warning('writeData filter generated %d bytes, will be trimmed to %d.  May cause breakage, e.g., CRCs' % (len(result), self.max_len))
                    result = result[:self.max_len]
                self.writeKdata(result)
                self.lgr.debug('writeData filter wrote %d bytes' % len(result))
                retval = len(result)
            else:
                self.writeKdata(self.in_data)
                retval = len(self.in_data)


            #self.lgr.debug('writeData write is to kernel buffer %d bytes to 0x%x' % (retval, self.addr))
            #if self.dataWatch is not None:
            #    ''' Limit reads to buffer size '''
            #    self.dataWatch.setReadLimit(retval, self.readLimitCallback)
            #else:
            ''' Limit reads to buffer size using a hap on the read return '''
            ''' TBD can we stop tracking total read now that sharedSyscall is used to adjust values?'''
            if self.set_ret_hap:
                #self.lgr.debug('writeData call setRetHap')
                self.setRetHap()
            self.read_limit = retval
            self.in_data = ''
            self.pending_call = True
            if self.addr_of_count is not None:
                self.ioctl_flag = 1
                self.ioctl_count = 1
                self.pending_call = False
                #self.lgr.debug('writeData setCountValue.  Assume ioctl describes how much read. wrote count 0x%x to addr 0x%x' % (retval, self.addr_of_count))
           
        else:
            #self.lgr.debug('writeData write is to user buffer')
            retval = self.userBufWrite(record)
        if self.stop_on_close and self.close_hap is None:
            self.setCloseHap()
        return retval

    def readLimitCallback(self):
        ''' Called by dataWatch when kernel buffer size is consumed TBD NO IT IS NOT.  remove this?'''
        if self.call_hap is None and self.call_ip is not None:
            self.lgr.debug('writeData readLimitCallback, add callHap at 0x%x context is %s' % (self.call_ip, self.cpu.current_context))
            #self.call_break = SIM_breakpoint(self.cell, Sim_Break_Linear, Sim_Access_Execute, self.call_ip, 1, 0)
            self.call_break = SIM_breakpoint(self.cpu.current_context, Sim_Break_Linear, Sim_Access_Execute, self.call_ip, 1, 0)
            self.call_hap = RES_hap_add_callback_index("Core_Breakpoint_Memop", self.callHap, None, self.call_break)

    def setCountValue(self, count):
        ''' Modify the count value seen by the application on its return from a read/recv '''
        if self.top.isWindows():
            word_size = self.top.getWordSize()
            if word_size == 4:
                #self.mem_utils.writeWord32(self.cpu, self.addr_of_count, count)
                self.top.writeWord(self.addr_of_count, count, target_cpu=self.cpu, word_size=4)
            else: 
                #self.mem_utils.writeWord(self.cpu, self.addr_of_count, count)
                self.top.writeWord(self.addr_of_count, count, target_cpu=self.cpu, word_size=8)
            #self.lgr.debug('writeData wrote count value %d to addr 0x%x' % (count, self.addr_of_count))
        else:
            self.cpu.iface.int_register.write(self.len_reg_num, count)
            #self.lgr.debug('writeData wrote count value %d to reg num  %d' % (count, self.len_reg_num))

    def userBufWrite(self, record=False):
        ''' inject data into the application buffer and set the return count value seen by the application '''
        retval = None
        #self.lgr.debug('userBufWrite self.max_len is %d in data is %d bytes' % (self.max_len, len(self.in_data)))
        if self.current_packet > 1 and self.no_reset is not None:
             self.lgr.debug('writeData userBufWrite, current packet %d, no reset so stop' % self.current_packet)
             SIM_break_simulation('writeData userBufWrite, no reset')
             if self.stop_callback is not None:
                 self.stop_callback()
             return
        if self.expected_packet_count <= 1 and self.udp_header is None:
            if self.expected_packet_count != 1 and len(self.in_data) > self.max_len:
                #self.lgr.debug('writeData userBufWrite in data %d bytes longer than max_len %d' % (len(self.in_data), self.max_len))
                next_data = self.in_data[:self.max_len]
                self.in_data = self.in_data[self.max_len:]
                if self.filter is not None:
                    result = self.filter.filter(next_data, self.current_packet)
                    # this truncating is crude.  TBD handle truncating with filters.  Go back and further shorten the in_data?
                    if len(result) > self.max_len:
                        result = result[:self.max_len]
                        #self.lgr.debug('writeData userBufWrite used filter, truncated result len %d' % (len(result)))
                    self.mem_utils.writeString(self.cpu, self.addr, result) 
                    self.setCountValue(len(result))
                    retval = len(result)
                else: 
                    self.mem_utils.writeString(self.cpu, self.addr, next_data) 
                    self.setCountValue(len(next_data))
                    retval = len(next_data)
                #self.lgr.debug('writeData userBufWrite TCP not last packet, wrote %d bytes to 0x%x packet_num %d remaining bytes %d' % (len(next_data), self.addr, self.current_packet, len(self.in_data)))
                #self.lgr.debug('%s' % next_data)
                if self.max_len == 1:
                    ''' Assume reading byte at a time into buffer '''
                    ''' TBD REMOVE THIS.  At least for TCP?  Character at a time input requires injection into kernel buffer '''
                    self.addr = self.addr+1
            else:
                if len(self.in_data) > self.max_len:
                    self.in_data = self.in_data[:self.max_len]
                tot_len = len(self.in_data)
                if self.filter is not None:
                    result = self.filter.filter(self.in_data, self.current_packet)
                    if result is None:
                        self.lgr.error('writeData userBufWrite filter returned none')
                        return
                    if len(result) > self.max_len:
                        result = result[:self.max_len]
                        #self.lgr.debug('writeData userBufWrite used TCP last or udp, filter, truncated result len %d' % (len(result)))
                    self.mem_utils.writeString(self.cpu, self.addr, result) 
                    tot_len = len(result)
                else:
                    self.mem_utils.writeString(self.cpu, self.addr, self.in_data) 
                eip = self.top.getEIP(self.cpu)
                #self.lgr.debug('writeData userBufWrite TCP last packet (or headerless UDP), wrote %d bytes to 0x%x packet_num %d eip 0x%x' % (tot_len, self.addr, self.current_packet, eip))
                if self.pad_to_size is not None and tot_len < self.pad_to_size:
                    pad_count = self.pad_to_size - len(self.in_data)
                    b = bytearray(pad_count)
                    next_addr = self.addr + len(self.in_data)
                    self.mem_utils.writeString(self.cpu, next_addr, b) 
                    #self.lgr.debug('writeData userBufWrite TCP last packet, padded %d bytes' % pad_count)
                    tot_len = tot_len + pad_count
                self.setCountValue(tot_len)
                self.in_data = ''
                retval = tot_len
        elif self.udp_header is not None:
            ''' see if there will be yet another udp header '''
            index = self.in_data[5:].find(self.udp_header)
            #self.lgr.debug('userBufWrite got %d when look for %s in %s' % (index, self.udp_header, self.in_data[5:]))
            if index > 0 and self.current_packet > self.udp_header_limit:
                self.lgr.debug('writeData,userBufWrite  too many udp headers')
                index = -1
            if index > 0:
                first_data = self.in_data[:(index+5)]
                self.in_data = self.in_data[len(first_data):]
                if len(first_data) > self.max_len:
                    #self.lgr.debug('writeData, userBufWrite udp, trimmed first data to max_len')
                    first_data = first_data[:self.max_len]
                if self.filter is not None: 
                    result = self.filter.filter(first_data, self.current_packet)
                    self.mem_utils.writeString(self.cpu, self.addr, result) 
                    retval = len(result)
                else: 
                    self.mem_utils.writeString(self.cpu, self.addr, first_data) 
                    retval = len(first_data)
                # TBD add handling of padding with udp header                
                eip = self.top.getEIP(self.cpu)
                #self.lgr.debug('writeData userBufWrite wrote packet %d %d bytes addr 0x%x ip: 0x%x  %s' % (self.current_packet, len(first_data), self.addr, eip, first_data[:50]))
                #self.lgr.debug('writeData userBufWrite next packet would start with %s' % self.in_data[:50])
            else:
                ''' no next udp header found'''
                eip = self.top.getEIP(self.cpu)
                data = self.in_data[:self.max_len]
                #self.lgr.debug('writeData userBufWrite wrote packect %d %d bytes addr 0x%x ip: 0x%x ' % (self.current_packet, len(data), self.addr, eip))
                #self.lgr.debug('writeData userBufWrite next UDP header %s not found wrote remaining packet' % (self.udp_header))
                result = data
                if self.filter is not None:
                    result = self.filter.filter(data, self.current_packet)
                self.mem_utils.writeString(self.cpu, self.addr, result)
                retval = len(result)
                self.in_data = ''
                #retval = 100
            self.setCountValue(tot_len)
            ''' reflect current packet in artifacts, starting with one'''
            self.top.setPacketNumber((self.current_packet+1))
                
        else:
            self.lgr.error('writeData userBufWrite could not handle data parameters.')
        #self.lgr.debug('writeData userBufWrite tracing_io ? %r' % self.tracing_io)
        if not self.tracing_io and (self.stop_on_read or self.udp_header is not None or (self.pad_to_size is not None and self.pad_to_size > 0)):
            self.lgr.debug('writeData userBufWrite call setCallHap')
            self.setCallHap()

        if self.top.isWindows() and self.stop_on_read:
            self.lgr.debug('writeData userBufWrite call shared syscall to set read fixup to didRead')
            self.shared_syscall.setReadFixup(self.didUserRead)

        #if len(self.in_data) > 0:
        #    self.setCallHap()
        #else:
        #    SIM_run_alone(self.delCallHap, None)
        self.current_packet += 1
        return retval

    def setCallHap(self):
        if self.call_hap is None:
            self.syscallManager = self.top.getSyscallManager()
            self.lgr.debug('writeData setCallHap call to watch all syscalls callback') 
            #self.call_hap = self.syscallManager.watchAllSyscalls(None, 'writeData', callback=self.callCallback)
            self.call_hap = self.syscallManager.watchAllSyscalls(self.cpu.current_context, 'writeData', callback=self.callCallback)
        
    def setSelectStopHap(self):
        if self.select_hap is None:
            word_size = self.top.getWordSize()
            # TBD what about select for older linux.
            if word_size == 8:
                entry = self.top.getSyscallEntry('pselect6')
            else:
                entry = self.top.getSyscallEntry('_newselect')
            self.lgr.debug('writeData setSelectStopHap on 0x%x' % entry)
            if entry is not None:
                self.select_break = SIM_breakpoint(self.cell, Sim_Break_Linear, Sim_Access_Execute, entry, 1, 0)
                if word_size == 8:
                    entry = self.top.getSyscallEntry('ppoll')
                else:
                    entry = self.top.getSyscallEntry('poll')
                self.poll_break = SIM_breakpoint(self.cell, Sim_Break_Linear, Sim_Access_Execute, entry, 1, 0)
                self.select_hap = RES_hap_add_callback_index("Core_Breakpoint_Memop", self.selectStopHap, None, self.select_break)
                self.poll_hap = RES_hap_add_callback_index("Core_Breakpoint_Memop", self.selectStopHap, None, self.poll_break)
            else:
                self.lgr.debug('writeData setSelectStopHap failed to get entry for _newselect')

    def setRetHap(self):
        #self.lgr.debug('writeData setRetHap') 
        #if self.shared_syscall is None:
        if not self.tracing_io:
            #self.lgr.debug('writeData not tracing IO, we must do it')
            if self.ret_hap is None: 
                phys_block = self.cpu.iface.processor_info.logical_to_physical(self.return_ip, Sim_Access_Execute)
                self.ret_break = SIM_breakpoint(self.cpu.physical_memory, Sim_Break_Physical, Sim_Access_Execute, phys_block.address, 1, 0)
                self.ret_hap = RES_hap_add_callback_index("Core_Breakpoint_Memop", self.retHap, None, self.ret_break)
                self.lgr.debug('writeData setRetHap on return_ip 0x%x (phys 0x%x) cell is %s' % (self.return_ip, phys_block.address, str(self.cell)))
        elif self.shared_syscall is not None:
            self.lgr.debug('writeData setRetHap call sharedSyscall setReadFixup')
            if self.top.isWindows():
                self.shared_syscall.setReadFixup(self.windowsReadFixup)
            else:
                if self.addr_of_count is not None:
                    self.shared_syscall.setReadFixup(self.doRetIOCtl)
                else:
                    self.shared_syscall.setReadFixup(self.doRetFixup)
                self.shared_syscall.setSelectFixup(self.doRetSelect)
                self.shared_syscall.setPollFixup(self.doRetPoll)
        else:
            self.lgr.error('writeData setRetHap, shared_syscall is None and not tracing io')

    def selectHap(self, dumb, third, break_num, memory):
        ''' Hit a call to select or poll'''
        if self.select_hap is None:
            return
        self.lgr.debug('writeData selectHap ')
        if self.stop_on_read and self.mem_utils.isKernel(self.addr):

            #self.lgr.debug('writeData selectHap stop on read')
            if self.write_callback is not None:
                SIM_run_alone(self.write_callback, 0)
            elif self.top.getCommandCallback() is not None:
                cb = self.top.getCommandCallback()
                self.lgr.debug('writeData selectHap is command callback, call to %s' % cb)
                cb()
            else:
                #self.lgr.debug('writeData selectHap break simulation')
                SIM_break_simulation('writeData selectHap stop on read callback is None')
                if self.stop_callback is not None:
                    self.stop_callback()
            return
        tid = self.top.getTID()
        if self.stop_on_read and len(self.in_data) == 0:
            if self.write_callback is not None:
                SIM_run_alone(self.write_callback, 0)
            elif self.top.getCommandCallback() is not None:
                cb = self.top.getCommandCallback()
                self.lgr.debug('writeData selectHap no more data, three is a command callback, call to %s' % cb)
                cb()
            else:
                self.lgr.debug('writeData selectHap stop on read and no more data write callback is None')
                SIM_break_simulation('writeData selectHap stop on read and no more data')
                if self.stop_callback is not None:
                    self.stop_callback()
            return
        if tid != self.tid:
            #self.lgr.debug('writeData callHap wrong tid, got %d wanted %d' % (tid, self.tid)) 
            return
        if len(self.in_data) == 0 or (self.max_packets is not None and self.current_packet >= self.max_packets):
            #self.lgr.debug('writeData selectHap current packet %d no data left, let backstop timeout? return value of zero to application since we cant block.' % (self.current_packet))
            pass
        else:
            if self.limit_one:
                self.lgr.warning('writeData selectHap, would write more data, but limit_one')
                #self.lgr.debug(frame_s)
            
            else:
                ''' Skip over kernel to the return ip '''
                self.cpu.iface.int_register.write(self.pc_reg, self.select_return_ip)
                self.lgr.debug('writeData selectHap, skipped over kernel')

    #def callHap(self, dumb, third, break_num, memory):
    def callCallback(self):
        ''' Hit a call to recv or ioctl or... This callback is made from syscall on entry, vice sharedSyscall on exit'''
        if self.call_hap is None:
            return
        tid = self.top.getTID()
        if tid != self.tid:
            #self.lgr.debug('writeData callHap wrong tid, got %s wanted %s' % (tid, self.tid)) 
            return
        skip_it = False
        if self.top.isWindows():
            # TBD check FD
            eip = self.top.getEIP(self.cpu)
            callnum = self.mem_utils.getCallNum(self.cpu)
            callname = self.top.syscallName(callnum)
            self.lgr.debug('writeData callHap call %s' % callname)
            if callname == 'DeviceIoControlFile':
                frame = self.top.frameFromRegs()
                operation = frame['param6'] & 0xffffffff
                if operation in self.ioctl_op_map:
                    op_cmd = self.ioctl_op_map[operation]
                    frame_s = taskUtils.stringFromFrame(frame)
                    self.lgr.debug('writeData callHap,  is Windows is io_ctl tid:%s eip: 0x%x cycles: 0x%x callname %s op: %s frame: %s' % (tid, eip, 
                         self.cpu.cycles, callname, op_cmd, frame_s))
                    if op_cmd not in ['RECV', 'RECV_DATAGRAM', 'ReadFile']:
                        skip_it = True
                    fd = frame['param1']
                    if fd != self.fd:
                        skip_it = True
                    callname = op_cmd
                    self.lgr.debug('writeData callHap skip it %r' % skip_it)
            else:
                self.lgr.debug('writeData callHap, windows expected DeviceIoControFile got %s' % callname)
                skip_it = True
        else:
            eip = self.top.getEIP(self.cpu)
            callnum = self.mem_utils.getCallNum(self.cpu)
            callname = self.top.syscallName(callnum)
            frame = self.top.frameFromRegs()
            peek = False
            if callname == 'socketcall':        
                ''' must be 32-bit get params from struct '''
                socket_callnum = frame['param1']
                callname = net.callname[socket_callnum].lower()
                ss = net.SockStruct(self.cpu, frame['param2'], self.mem_utils, lgr=self.lgr)
                fd = ss.fd
                count = ss.count
                peek = ss.flags & net.MSG_PEEK
            else:
                fd = frame['param1']
                count = frame['param3']
                if callname.startswith('recv'):
                    flags = frame['param4']
                    peek = flags & net.MSG_PEEK
            # Adjust count of bytes read if a kernel buffer so we know when we hit the limit.
            if self.mem_utils.isKernel(self.addr) and callname in ['recv', 'recvfrom', 'read']:
                if (self.total_read + count) > self.read_limit:
                    self.kernel_buf_consumed = True
                elif peek == 0:
                    self.total_read = self.total_read + count
                self.lgr.debug('writeData callHap count %d total read now %d read limit is %d' % (count, self.total_read, self.read_limit))
            #self.lgr.debug('writeData callHap, callname  %s fd %s' % (callname, fd))
            if callname not in ['recv', 'read', 'recvfrom', 'ioctl', 'close', 'select', '_newselect', 'pselect6']:
                skip_it = True
            elif fd != self.fd and callname not in ['select', '_newselect', 'pselect6']:
                #self.lgr.debug('writeData callHap wrong fd, skip it')
                skip_it = True
            elif self.mem_utils.isKernel(self.addr) and callname in ['select', '_newselect', 'pselect6']:
                select_info = syscall.SelectInfo(frame['param1'], frame['param2'], frame['param3'], frame['param4'], frame['param5'], 
                     self.cpu, self.mem_utils, self.lgr)
                #self.lgr.debug('writeData callHap is select %s' % select_info.getString())
                if select_info.hasFD(self.fd):
                    #self.lgr.debug('writeData callHap is select on our fd %d' % self.fd)
                    self.pending_select = select_info
                else:
                    skip_it = True
            elif callname not in ['recv', 'recvfrom', 'read'] and not (self.watch_ioctl and callname == 'ioctl'):
                #self.lgr.debug('writeData callHap wrong call %s' % callname)
                skip_it = True
            if self.read_count == 0 and self.addr_of_count is not None:
                # was an ioctl and we've not yet hit the read, so just let it go
                #self.lgr.debug('writeData callHap was ioctl not yet hit, skip it')
                skip_it = True
            #self.lgr.debug('writeData callHap eip: 0x%x callnum %d  call: %s fd: %d cycle: 0x%x context: %s skip_it %r' % (eip, callnum, 
            #     callname, fd, self.cpu.cycles, str(self.cpu.current_context), skip_it))

        if not skip_it:
            self.read_count = self.read_count + 1
            #self.lgr.debug('writeData callHap, read_count is %d tid:%s callname %s' % (self.read_count, tid, callname))
            self.pending_call = True
            self.handleCall(callname)

    def doBreakSimulation(self, msg):
        if self.write_callback is not None:
            SIM_break_simulation(msg)
            #self.lgr.debug(msg)
            SIM_run_alone(self.write_callback, 0)
        else:
            # TBD leave it up to playAFL, inject and others?
            #SIM_run_alone(self.delCallHap, None)
            SIM_break_simulation(msg+' no write_callback')
            if self.stop_callback is not None:
                 self.stop_callback()
            #self.lgr.debug(msg+' no write_callback')

    def handleCall(self, callname):
        # TBD reworked, must be updated for Windows
        self.pending_callname = callname
        tid = self.top.getTID()
        if tid != self.tid:
            self.lgr.debug('writeData handleCall wrong tid, got %d wanted %d' % (tid, self.tid)) 
            return
        if callname in ['recv', 'recvfrom', 'read', 'RECV', 'RECV_DATAGRAM', 'ReadFile']:
            #self.lgr.debug('writeData handleCall is recv')
            if self.max_packets is not None and self.current_packet >= self.max_packets:
                self.doBreakSimulation('writeData handleCall max_packets')
            elif not self.mem_utils.isKernel(self.addr):
                if len(self.in_data) == 0:
                    if self.stop_on_read: 
                        self.doBreakSimulation('writeData handleCall stop_on_read')
                    #else:
                    #    self.lgr.debug('writeData handleCall out of data, let backstop handle it')
                else:
                    # User buffer, e.g., UDP skip over kernel read unless told not to limit to one read
                    frame = self.top.frameFromRegs()
                    frame_s = taskUtils.stringFromFrame(frame)
                    #self.lgr.debug('handleCall writeData handleCall user buffer frame: %s' % frame_s)
        
                    if self.limit_one:
                        self.lgr.warning('writeData handleCall, would write more data, but limit_one')
                        #self.lgr.debug(frame_s)
                    
                    else:
                        ''' Skip over kernel to the return ip '''
                        self.cpu.iface.int_register.write(self.pc_reg, self.return_ip)
                        count = self.write()
                        self.lgr.debug('writeData handleCall, skip over kernel receive processing and wrote %d more bytes context %s' % (count, self.cpu.current_context))
                        #print('did write')
                        if self.current_packet >= self.expected_packet_count:
                            # set backstop if needed, we are on the last (or only) packet.
                            #SIM_run_alone(self.delCallHap, None)
                            if self.backstop_cycles > 0:
                                #self.lgr.debug('writeData setting backstop')
                                self.backstop.setFutureCycle(self.backstop_cycles)
                        if self.write_callback is not None:
                            SIM_run_alone(self.write_callback, count)
            else:
                # Kernel buffer
                if self.kernel_buf_consumed:
                    self.doBreakSimulation('writeData handleCall kernel buffer consumed')
        elif self.select_count_max is not None and callname in['select', '_newselect', 'pselect6']:
            self.checkSelect()
        elif self.pending_select is not None:
            if callname not in['select', '_newselect', 'pselect6']:
                self.lgr.error('writeData handleCall pending_select but not a select call, bail. cannot get here')
                return
            self.lgr.debug('writeData handleCall is select')
            if self.mem_utils.isKernel(self.addr):
                if self.kernel_buf_consumed:
                    #self.lgr.debug('writeData handleCall pending_select, kernel buffer consumed')
                    pass
                else:
                    #self.lgr.debug('writeData handleCall pending_select, kernel buffer not consumed, clear pending_select')
                    self.pending_select = None
        elif callname == 'ioctl' and self.watch_ioctl:
            #self.lgr.debug('writeData handleCall is ioctl and watching ioctl')
            if self.mem_utils.isKernel(self.addr):
                self.checkIOCtl()
            else: 
                #self.lgr.error('writeData handleCall watch_ioctl but not a kernel buffer.  Not yet handled, bail.')
                return
        elif callname == 'close' and self.stop_on_close:
            self.doBreakSimulation('writeData handleCall close and stop_on_close')
        else:
            self.lgr.debug('writeData handleCall did not handle call %s' % callname)
            pass
           
    def checkIOCtl(self):
        if self.watch_ioctl:
            #self.lgr.debug('writeData checkIOCtl, ioctl_count coming in is %d max is %d' % (self.ioctl_count, self.ioctl_count_max))
            self.ioctl_count = self.ioctl_count+1
            if self.ioctl_count_max is not None and self.ioctl_count  >= self.ioctl_count_max:
                self.doBreakSimulation('writeData checkIOCtl ioctl_count_max')
            elif self.ret_hap is None:
                self.lgr.debug('writeData checkIOCtl ioctl call to setRetHap')
                self.setRetHap()

    def checkSelect(self):
        # return False if simulation being halted due to select count or poll count or no_reset
        # Also used for poll
        retval = True
        if self.no_reset is not None:
            #self.lgr.debug('writeData checkSelect no reset')
            self.doBreakSimulation('writeData checkSelect no reset')
            retval = False
        elif self.select_count_max is not None:
            #self.lgr.debug('writeData checkSelect, select_count coming in is %d max is %d' % (self.select_count, self.select_count_max))
            self.select_count = self.select_count+1
            if self.select_count_max is not None and self.select_count  >= self.select_count_max:
                #self.lgr.debug('writeData checkSelect will break simulation cycles: 0x%x' % self.cpu.cycles)
                self.doBreakSimulation('writeData checkSelect select count')
                retval = False
            elif self.ret_hap is None:
                #self.lgr.debug('writeData checkSelect call to setRetHap')
                self.setRetHap()
        return retval


    def doRetIOCtl(self, fd, callname=None, addr_of_count=None, peek=False):
        retval = None
        tid = self.top.getTID()
        if tid != self.tid:
            return
        #self.lgr.debug('writeData doRetIOCtl fd %d callname %s tid %s' % (fd, callname, tid))
        self.pending_call = False
        if callname is not None and callname != 'ioctl':
            return self.doRetFixup(fd)
        if fd == self.fd:
            if self.ioctl_flag is not None:
                if self.no_reset is None:
                    # must be second call, return zero
                    if addr_of_count is None:
                        addr_of_count = self.addr_of_count
                    self.lgr.debug('writeData doRetIOCtl set return value to zero to addr 0x%x' % addr_of_count)
                    #self.mem_utils.writeWord32(self.cpu, addr_of_count, 0)
                    self.top.writeWord(addr_of_count, 0, target_cpu=self.cpu, word_size=4)
                else:
                    self.lgr.debug('writeData doRetIOCtl would adjust count to zero, but no reset write_callback %s' % self.write_callback)
                    if self.write_callback is not None:
                        SIM_break_simulation('writeData doRetIOCtl would adjust count to zero, but no reset')
                        self.write_callback(0)
                    elif self.top.getCommandCallback() is not None:
                        cb = self.top.getCommandCallback()
                        self.lgr.debug('writeData doRetIOCtl is command callback, call to %s' % cb)
                        cb()
                    else:
                        SIM_break_simulation('writeData doRetIOCtl would adjust count to zero, but no reset')
                        if self.stop_callback is not None:
                            self.stop_callback()
        return retval

    def doRetSelect(self, select_info):
        self.lgr.debug('writeData doRetSelect kernel_buf_consumed: %r select_count_max %s self.fd %d' % (self.kernel_buf_consumed, self.select_count_max, self.fd))
        # return False if simulation is being halted
        retval = True
        tid = self.top.getTID()
        if tid == self.tid: 
            if self.kernel_buf_consumed or self.select_count_max is not None:
                if select_info.setHasFD(self.fd, select_info.readfds): 
                    if not self.checkSelect():
                        retval = False
                    self.lgr.debug('writeData doRetSelect kbuf consumed and has our FD as a read retval:%r (false means we are halting simulation)' % retval)
                    #self.doBreakSimulation('writeData doRetSelect select on our fd')
        return retval

    def doRetPoll(self, poll_info):
        # return False if simulation is being halted
        self.lgr.debug('writeData doRetPoll')
        retval = True
        if self.kernel_buf_consumed:
            if poll_info.hasFD(self.fd):
                if not self.checkSelect():
                    retval = False
                self.lgr.debug('writeData doRetPoll kbuf consumed and has our FD as a read retval %r' % retval)
                #self.doBreakSimulation('writeData doRetSelect select on our fd')
        return retval
                
    def doRetFixup(self, fd, callname=None, addr_of_count=None, peek=0):
        ''' We've returned from a read/recv.  Fix up eax if needed and track kernel buffer consumption.'''
        self.lgr.debug('writeData doRetFixup begin fd %d looking for %d total_read: %d  read_limit %d peek: %s' % (fd, self.fd, self.total_read, self.read_limit, peek))
        eax = self.mem_utils.getRegValue(self.cpu, 'syscall_ret')
        tid = self.top.getTID()
        # hack
        self.top.flushTrace()
        if tid != self.tid or fd != self.fd:
            return eax
        self.pending_call = False
        eax = self.mem_utils.getSigned(eax)
        if eax <= 0: 
            #self.lgr.error('writeData retHap got count of %d' % eax)
            return eax
        remain = self.read_limit - self.total_read

        if self.total_read >= self.read_limit and self.stop_on_read:
            self.lgr.debug('writeData doRetFixup even before this read, total_read was %d and read_limit 0x%x, so we will break.  btw, read count was %d' % (self.total_read, self.read_limit, eax))
            SIM_break_simulation('writeData doRetFixup even before this read, total_read was %d and read_limit 0x%x, so we will break.  btw, read count was %d' % (self.total_read, self.read_limit, eax))
            if self.stop_callback is not None:
                self.stop_callback()
            return None
        if self.mem_utils.isKernel(self.addr):
            if (self.total_read + eax) > self.read_limit:
                self.kernel_buf_consumed = True
                self.lgr.debug('writeData doRetFixup read %d, limit %d total_read %d and break simulation' % (eax, self.read_limit, self.total_read))
                SIM_break_simulation('writeData doRetFixup total_read 0x%x over read_limit 0x%x and stop_on_read, break simulation stop_callback %s' % (self.total_read, self.read_limit, self.stop_callback))
                if self.stop_callback is not None:
                    self.stop_callback()
                return None

        if peek == 0:
            self.total_read = self.total_read + eax
            self.lgr.debug('writeData doRetFixup read %d, limit %d total_read %d remain: %d no_reset: %s' % (eax, self.read_limit, self.total_read, remain, self.no_reset))
        else:
            self.lgr.debug('writeData doRetFixup WAS PEEK read %d, limit %d total_read %d remain: %d no_reset: %s' % (eax, self.read_limit, self.total_read, remain, self.no_reset))

        #if self.stop_on_read and self.total_read >= self.read_limit:
        if self.total_read >= self.read_limit:
            if self.mem_utils.isKernel(self.addr):
                self.lgr.debug('writeData retHap read limit, set kernel_buf_consumed')
                self.kernel_buf_consumed = True
                if self.shared_syscall is not None and self.no_reset is None:
                    self.shared_syscall.foolSelect(self.fd)
        if self.total_read > self.read_limit:
            self.lgr.debug('writeData retHap read over limit of %d' % self.read_limit)
            if self.mem_utils.isKernel(self.addr):
                 ''' adjust the return value and continue '''
                 if eax > remain and self.no_reset is None:
                     #if self.no_reset:
                     #    self.lgr.debug('writeData doRetFixup, would alter return value, but no_reset is set.  Stop simulation.')
                     #    SIM_break_simulation('writeData doRetFixup no reset')
                     #    return None
                     if self.user_space_addr is not None:
                         start = self.user_space_addr + remain
                         #self.lgr.debug('writeData doRetFixup restored original buffer, %d bytes starting at 0x%x' % (len(self.orig_buffer[remain:eax]), start))
                         self.mem_utils.writeString(self.cpu, start, self.orig_buffer[remain:eax])

                     self.top.writeRegValue('syscall_ret', remain, alone=True, reuse_msg=True)
                     self.lgr.debug('writeData adjusted return eax from %d to remain value of %d kernel buf consumed' % (eax, remain))
                     #rprint('**** Adjusted return value, RESET Origin ***') 
                     eax = remain
                     self.kernel_buf_consumed = True
                     if self.shared_syscall is not None:
                         self.shared_syscall.foolSelect(self.fd)
                 if not self.no_call_hap and not self.tracing_io:
                     self.setCallHap()
                 if self.top.isWindows():
                     ''' TBD '''
                     pass
                 else:
                     self.setSelectStopHap()
                 # TBD why was this being deleted?
                 #SIM_run_alone(self.delRetHap, None)
                 self.lgr.debug('writeData doRetFixup read over limit of %d, setCallHap and let it go' % self.read_limit)
            else:
                 ''' User space injections begin after the return.  TBD should not get here because should be caught by a read call? ''' 
                 self.lgr.debug('writeData retHap read over limit of %d' % self.read_limit)
                 SIM_break_simulation('Over read limit')
                 if self.stop_callback is not None:
                     self.stop_callback()
                 return None
        return eax

    def windowsReadFixup(self, fd, count_addr):
        count = self.mem_utils.readWord32(self.cpu, count_addr)
        self.lgr.debug('writeData winReadFixup FD: 0x%x  count_addr 0x%x read count of %d total_read now: %d  read limit %d' % (fd, count_addr, count, self.total_read, self.read_limit))
        remain = self.read_limit - self.total_read

        if self.total_read >= self.read_limit and self.stop_on_read:
            self.lgr.debug('writeData windowsReadFixup read %d, limit %d total_read %d remain: %d past limit and stop_on_read, stop' % (count, self.read_limit, self.total_read, remain))
            SIM_break_simulation('writeData windowsReadFixup total_read 0x%x over read_limit 0x%x and stop_on_read, break simulation' % (self.total_read, self.read_limit))
            if self.stop_callback is not None:
                self.stop_callback()
            return None
        self.total_read = self.total_read + count
        self.lgr.debug('writeData windowsReadFixup read %d, limit %d total_read %d remain: %d no_reset: %s' % (count, self.read_limit, self.total_read, remain, self.no_reset))

        #if self.stop_on_read and self.total_read >= self.read_limit:
        if self.total_read >= self.read_limit:
            if self.mem_utils.isKernel(self.addr):
                self.lgr.debug('writeData windowsReadFixup read limit, set kernel_buf_consumed')
                self.kernel_buf_consumed = True
        if self.total_read > self.read_limit:
            self.lgr.debug('writeData windowsReadFixup read over limit of %d' % self.read_limit)
            if self.mem_utils.isKernel(self.addr):
                 ''' adjust the return value and continue '''
                 if count > remain and self.no_reset is None:
                     if self.user_space_addr is not None:
                         start = self.user_space_addr + remain
                         self.lgr.debug('writeData windowsReadFixup restored original buffer, %d bytes starting at 0x%x' % (len(self.orig_buffer[remain:count]), start))
                         self.mem_utils.writeString(self.cpu, start, self.orig_buffer[remain:count])

                     self.top.writeWord(count_addr, remain, target_cpu=self.cpu, word_size=4)
                     self.lgr.debug('writeData adjusted count from from %d to remain value of %d kernel buf consumed' % (count, remain))
                     #rprint('**** Adjusted return value, RESET Origin ***') 
                     self.kernel_buf_consumed = True
                 if not self.no_call_hap and not self.tracing_io:
                     self.setCallHap()
                 # TBD why was this being deleted?
                 #SIM_run_alone(self.delRetHap, None)
                 self.lgr.debug('writeData windowsReadFixup read over limit of %d, setCallHap and let it go' % self.read_limit)
            else:
                 ''' User space injections begin after the return.  TBD should not get here because should be caught by a read call? ''' 
                 self.lgr.debug('writeData windowsReadFixup read over limit of %d' % self.read_limit)
                 SIM_break_simulation('Over read limit')
                 if self.stop_callback is not None:
                     self.stop_callback()
                 return None

    def retHap(self, dumb, third, break_num, memory):
        # TBD reworked, must be updated for Windows
        ''' Hit a return from read or ioctl'''
        if self.ret_hap is None:
            #self.lgr.debug('writeData retHap no ret_hap bail')
            return
        if not self.pending_call:
            #self.lgr.debug('writeData retHap no pending call bail')
            return
        tid = self.top.getTID()
        if tid != self.tid:
            #self.lgr.debug('writeData retHap wrong tid, got %d wanted %d' % (tid, self.tid)) 
            return
        self.lgr.debug('writeData retHap pending_callname %s cycle 0x%x' % (self.pending_callname, self.cpu.cycles))
        if self.pending_callname is None and self.pending_select is None:
            return
        elif self.pending_callname not in ['recv', 'read', 'recvfrom', 'ioctl', 'close', 'select', '_newselect', 'pselect6']:
            return
        if self.pending_select is not None:
            if self.pending_select.setHasFD(self.fd, self.pending_select.readfds): 
                if self.mem_utils.isKernel(self.addr):
                    self.checkSelect()
                self.lgr.debug('writeData retHap was pending select now %s' % self.pending_select.getString())
                self.pending_select.resetFD(self.fd, self.pending_select.readfds)
                eax = self.mem_utils.getRegValue(self.cpu, 'syscall_ret')
                eax = eax -1
                self.top.writeRegValue('syscall_ret', eax, alone=True)
                #self.lgr.debug('writeData retHap modified select result, cleared fd and set eax to %d' % eax)
            else:
                self.lgr.debug('writeData retHap had pending_select, but not our fd, which is %d' % self.fd)
                pass
            self.pending_select = None
        elif self.pending_callname == 'ioctl' and self.watch_ioctl:
            self.doRetIOCtl(self.fd)
        elif self.pending_callname in ['recv', 'recvfrom', 'read']:
            self.lgr.debug('writeData retHap call doRetFixup')
            self.doRetFixup(self.fd)
        self.pending_callname = None
        
    def restoreCallHap(self):
        if self.was_a_call_hap:
            self.lgr.debug('writeData restoreCalHap')
            self.setCallHap()

    def delCallHap(self, dumb):
        self.lgr.debug('writeData delCallHap')
        '''
        if self.call_hap is not None:
            self.was_a_call_hap = True
            #self.lgr.debug('writeData delCallHap callbreak %d' % self.call_break)
            RES_delete_breakpoint(self.call_break)
            RES_hap_delete_callback_id('Core_Breakpoint_Memop', self.call_hap)
            self.call_hap = None
            self.call_break = None
        if self.select_hap is not None:
            #self.lgr.debug('writeData delCallHap select_break %d' % self.select_break)
            RES_delete_breakpoint(self.select_break)
            RES_hap_delete_callback_id('Core_Breakpoint_Memop', self.select_hap)
            self.select_hap = None
            self.select_break = None
        if self.poll_hap is not None:
            #self.lgr.debug('writeData delCallHap poll_break %d' % self.poll_break)
            RES_delete_breakpoint(self.poll_break)
            RES_hap_delete_callback_id('Core_Breakpoint_Memop', self.poll_hap)
            self.poll_hap = None
            self.poll_break = None
        if self.close_hap is not None:
            #self.lgr.debug('writeData delCallHap delete close_break %d' % self.close_break)
            RES_delete_breakpoint(self.close_break)
            RES_hap_delete_callback_id('Core_Breakpoint_Memop', self.close_hap)
            self.close_hap = None
            self.close_break = None
        '''
        if self.syscallManager is not None:
            self.syscallManager.rmSyscall('writeData')
        self.delRetHap(dumb)

    def delRetHap(self, dumb):
        if self.ret_hap is not None:
            #self.lgr.debug('writeData delRetHap')
            #self.lgr.debug('writeData delCallHap re_break %d' % self.ret_break)
            RES_delete_breakpoint(self.ret_break)
            RES_hap_delete_callback_id('Core_Breakpoint_Memop', self.ret_hap)
            self.ret_hap = None
            self.ret_break = None

    def getCurrentPacket(self):
        return self.current_packet

    def getOrigLen(self):
        val1 = self.mem_utils.readWord(self.cpu, self.k_start_ptr)
        val2 = self.mem_utils.readWord(self.cpu, self.k_end_ptr)
        retval = abs(val1-val2)
        return retval

    def modKernBufSize(self, bytes_wrote):
        if self.k_start_ptr is not None:
            val1 = self.mem_utils.readWord(self.cpu, self.k_start_ptr)
            val2 = self.mem_utils.readWord(self.cpu, self.k_end_ptr)
            #self.lgr.debug('injectIO modKernBufSize bytes_wrote %d  start_ptr 0x%x val1: 0x%x  end_ptr 0x%x val2: 0x%x' % (bytes_wrote, self.k_start_ptr, val1, self.k_end_ptr, val2))
            if val1 > val2:
                start_val = val2
                end_val = val1
                start_ptr = self.k_end_ptr 
                end_ptr = self.k_start_ptr 
            else:
                start_val = val1
                end_val = val2
                start_ptr = self.k_start_ptr 
                end_ptr = self.k_end_ptr 

            orig_len = end_val - start_val
            new_end = start_val + bytes_wrote
            self.lgr.debug('injectIO modKernBufSize orig_len is %d write new_end of 0x%x to 0x%x' % (orig_len, new_end, end_ptr))
            self.mem_utils.writeWord(self.cpu, end_ptr, new_end)

    def setCloseHap(self):
        if self.close_hap is None:
            entry = self.top.getSyscallEntry('close')
            self.close_break = SIM_breakpoint(self.cell, Sim_Break_Linear, Sim_Access_Execute, entry, 1, 0)
            self.close_hap = RES_hap_add_callback_index("Core_Breakpoint_Memop", self.closeHap, None, self.close_break)
            #self.lgr.debug('writeData setCloseHap on entry 0x%x context %s current %s' % (entry, str(self.cell), str(self.cpu.current_context)))

    def closeHap(self, dumb, third, break_num, memory):
        frame = self.top.frameFromRegs()
        fd = frame['param1']
        if fd == self.fd:
            if self.close_hap is not None:
                #self.lgr.debug('writeData closeHap')
                self.closed_fd = True
                self.handleCall('close')

    def selectStopHap(self, dumb, third, break_num, memory):
        if self.select_hap is not None:
            #self.lgr.debug('writeData selectStopHap')
            self.handleCall('select')
            '''
            if self.write_callback is not None:
                SIM_run_alone(self.write_callback, 0)
            else:
                self.lgr.debug('writeData closeHap break simulation')
                SIM_break_simulation('writeData closeHap')
            '''
    def closedFD(self):
        return self.closed_fd

    def watchIOCtl(self):
         self.watch_ioctl = True

    def tracingIO(self):
        # syscalls of IO are being traced, thus we need not catch syscalls or returns
        self.tracing_io = True

    def didUserRead(self, fd, addr):
        if self.stop_on_read and fd == self.fd: 
            self.lgr.debug('writeData didUserRead stop_on_read fd 0x%x' % fd)
            self.doBreakSimulation('writeData didUserRead stop_on_read')

    def loadPickle(self, name):
        cell_name = self.top.getTopComponentName(self.cpu)
        afl_file = os.path.join('./', name, cell_name, 'afl.pickle')
        if os.path.isfile(afl_file):
            self.lgr.debug('writeData pickle from %s' % afl_file)
            so_pickle = pickle.load( open(afl_file, 'rb') ) 
            #print('start %s' % str(so_pickle['text_start']))
            if 'call_ip' in so_pickle:
                self.call_ip = so_pickle['call_ip']
                self.return_ip = so_pickle['return_ip']
            if self.call_ip is None and self.return_ip is not None:
                if self.cpu.architecture.startswith('arm'):
                    self.call_ip = self.return_ip - 4
                    self.lgr.debug('writeData pickle, no call_ip, hack to 4 before ret, 0x%x' % self.call_ip)
                else:
                    self.lgr.warning("writeData pickle, no call_ip, FIX for non-arm")
            if 'select_call_ip' in so_pickle:
                self.select_call_ip = so_pickle['select_call_ip']
                self.select_return_ip = so_pickle['select_return_ip']
                #self.lgr.debug('writeData pickle got select call_ip 0x%x' % self.select_call_ip)
            if self.select_call_ip is None and self.select_return_ip is not None:
                if self.cpu.architecture.startswith('arm'):
                    self.select_call_ip = self.select_return_ip - 4
                    self.lgr.debug('writeData pickle, no select_call_ip, hack to 4 before ret, 0x%x' % self.select_call_ip)
                else:
                    self.lgr.warning("writeData pickle, no select_call_ip, FIX for non-arm")
            if 'addr' in so_pickle:
                self.addr = so_pickle['addr']
                if self.addr is None:
                    self.lgr.error('loadPickle got addr of None')
            if 'size' in so_pickle and so_pickle['size'] is not None:
                self.max_len = so_pickle['size']
                self.lgr.debug('writeData pickle got %d as max_len' % self.max_len)
            if 'fd' in so_pickle:
                self.fd = so_pickle['fd']
            if 'addr_addr' in so_pickle:
                self.addr_addr = so_pickle['addr_addr']
                self.addr_size = so_pickle['addr_size']
            if 'k_start_ptr' in so_pickle:
                self.k_start_ptr = so_pickle['k_start_ptr']
                self.k_end_ptr = so_pickle['k_end_ptr']

            if 'k_bufs' in so_pickle:
                self.k_bufs = so_pickle['k_bufs']
                buf_len = so_pickle['k_buf_len']
                if type(buf_len) is int:
                    self.k_buf_len = []
                    for i in range(len(self.k_bufs)):
                        self.k_buf_len.append(buf_len)
                else:
                    self.k_buf_len = buf_len
                self.lgr.debug('writeData pickle got %d k_bufs' % len(self.k_bufs))

            if 'orig_buffer' in so_pickle:
                self.orig_buffer = so_pickle['orig_buffer']
                self.lgr.debug('writeData load orig_buffer from pickle')

            if 'user_count' in so_pickle:
                self.user_space_count = so_pickle['user_count']
                self.user_space_addr = so_pickle['user_addr']
                self.lgr.debug('writeData load user_addr 0x%x count %d' % (self.user_space_addr, self.user_space_count))
               
            if 'addr_of_count' in so_pickle: 
                self.addr_of_count = so_pickle['addr_of_count']
                self.lgr.debug('writeData load add_of_count 0x%x' % (self.addr_of_count))
        else:
            self.lgr.debug('injectIO load, no pickle file at %s' % afl_file)
