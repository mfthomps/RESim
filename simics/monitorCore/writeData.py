from simics import *
import sys
import os
import pickle
import taskUtils
import winDelay
import winSocket
from resimUtils import rprint
from resimHaps import *
class WriteData():
    def __init__(self, top, cpu, in_data, expected_packet_count, 
                 mem_utils, context_manager, backstop, snapshot_name, lgr, udp_header=None, pad_to_size=None, filter=None, 
                 force_default_context=False, backstop_cycles=None, stop_on_read=False, write_callback=None, limit_one=False, 
                  dataWatch=None, shared_syscall=None, no_reset=False):
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
        self.write_callback = write_callback
        self.lgr = lgr
        self.limit_one = limit_one
        self.max_packets = os.getenv('AFL_MAX_PACKETS')
        if self.max_packets is not None:
            self.max_packets = int(self.max_packets)

        if self.cpu.architecture == 'arm':
            lenreg = 'r0'
            pcreg = 'pc'
        else:
            lenreg = 'eax'
            pcreg = 'eip'
        self.len_reg_num = self.cpu.iface.int_register.get_number(lenreg)
        self.pc_reg = self.cpu.iface.int_register.get_number(pcreg)

        # most recent packet we've written
        self.current_packet = 0

        self.stop_on_read = stop_on_read
        self.k_bufs = None
        self.orig_buffer = None
        # for restoring user space to what it was, less what we read from the kernel
        self.user_space_addr = None
        self.user_space_count = None

        # for windows
        self.addr_of_count = None

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

        self.pending_call = True

    def reset(self, in_data, expected_packet_count, addr):
        self.in_data = in_data
        self.addr = addr
        self.expected_packet_count = expected_packet_count
        self.current_packet = 0
        self.total_read = 0
        self.read_count = 0
        self.kernel_buf_consumed = False
        self.closed_fd = False

    def writeKdata(self, data):
        ''' write data to kernel buffers '''
        if self.k_bufs is None:
            ''' TBD remove this, all kernel buffers should now use k_bufs'''
            self.lgr.error('writeKdata, missing k_bufs')
            #self.mem_utils.writeString(self.cpu, self.addr, data) 
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
            #self.lgr.debug('writeData writeKdata, call setCallHap')
            if not self.no_call_hap:
                self.setCallHap()
            while remain > 0:
                 count = min(self.k_buf_len, remain)
                 end = offset + count
                 if index >= len(self.k_bufs):
                     self.lgr.error('writeKdata index %d out of range with %d bytes remaining, count was %d.' % (index, remain, count))
                     self.lgr.debug('writeKdata to buf[%d] data[%d:%d] remain %d' % (index,  offset, end, remain))
                     break
                 #self.lgr.debug('writeKdata write %d bytes to 0x%x.  k_buf_len is %d' % (len(data[offset:end]), self.k_bufs[index], self.k_buf_len))
                 self.mem_utils.writeString(self.cpu, self.k_bufs[index], data[offset:end])
                 index = index + 1
                 offset = offset + count 
                 remain = remain - count

            if self.top.isWindows() and self.dataWatch is not None:
                self.lgr.debug('writeData writeKdata, use winDelay to set data watch ''')
                asynch_handler = winDelay.WinDelay(self.top, self.cpu, self.addr_of_count, self.user_space_addr, None,
                        self.mem_utils, self.context_manager, None, None, None, self.fd, self.user_space_count, self.lgr, watch_count_addr=False)

                asynch_handler.setDataWatch(self.dataWatch, True)
                asynch_handler.toUserAlone(None)

          
    
    def write(self, record=False):
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
            ''' not done, no control over size. prep must use maximum buffer'''
            if len(self.in_data) > self.max_len:
                self.in_data = self.in_data[:self.max_len]
                self.lgr.debug('writeData  write truncated in data to %d bytes' % self.max_len)
            if self.filter is not None: 
                result = self.filter.filter(self.in_data, self.current_packet)
                if len(result) > self.max_len:
                    self.lgr.warning('dataWrite filter generated %d bytes, will be trimmed to %d.  May cause breakage, e.g., CRCs' % (len(result), self.max_len))
                    result = result[:self.max_len]
                self.writeKdata(result)
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
            #self.lgr.debug('writeData call setRetHap')
            self.setRetHap()
            self.read_limit = retval
            self.total_read = 0
            self.in_data = ''
            self.pending_call = True
           
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
        if self.top.isWindows():
            word_size = self.top.getWordSize()
            if word_size == 4:
                self.mem_utils.writeWord32(self.cpu, self.addr_of_count, count)
            else: 
                self.mem_utils.writeWord(self.cpu, self.addr_of_count, count)
            #self.lgr.debug('writeData wrote count value %d to addr 0x%x' % (count, self.addr_of_count))
        else:
            self.cpu.iface.int_register.write(self.len_reg_num, count)

    def userBufWrite(self, record=False):
        retval = None
        if self.current_packet > 1 and self.no_reset:
             self.lgr.debug('writeData userBufWrite, current packet %d, no reset so stop' % self.current_packet)
             SIM_break_simulation('writeData userBufWrite, no reset')
             return
        if self.expected_packet_count <= 1 and self.udp_header is None:
            if self.expected_packet_count != 1 and len(self.in_data) > self.max_len:
                next_data = self.in_data[:self.max_len]
                self.in_data = self.in_data[self.max_len:]
                if self.filter is not None:
                    result = self.filter.filter(next_data, self.current_packet)
                    self.mem_utils.writeString(self.cpu, self.addr, result) 
                    #self.lgr.debug('writeData first_data failed filter, wrote nulls')
                else: 
                    self.mem_utils.writeString(self.cpu, self.addr, next_data) 
                #self.lgr.debug('writeData TCP not last packet, wrote %d bytes to 0x%x packet_num %d remaining bytes %d' % (len(next_data), self.addr, self.current_packet, len(self.in_data)))
                #self.lgr.debug('%s' % next_data)
                self.setCountValue(len(next_data))
                retval = len(next_data)
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
                    self.mem_utils.writeString(self.cpu, self.addr, result) 
                    tot_len = len(result)
                else:
                    self.mem_utils.writeString(self.cpu, self.addr, self.in_data) 
                eip = self.top.getEIP(self.cpu)
                #self.lgr.debug('writeData TCP last packet (or headerless UDP), wrote %d bytes to 0x%x packet_num %d eip 0x%x' % (tot_len, self.addr, self.current_packet, eip))
                if self.pad_to_size is not None and tot_len < self.pad_to_size:
                    pad_count = self.pad_to_size - len(self.in_data)
                    b = bytearray(pad_count)
                    next_addr = self.addr + len(self.in_data)
                    self.mem_utils.writeString(self.cpu, next_addr, b) 
                    #self.lgr.debug('writeData TCP last packet, padded %d bytes' % pad_count)
                    tot_len = tot_len + pad_count
                self.setCountValue(tot_len)
                self.in_data = ''
                retval = tot_len
        elif self.udp_header is not None:
            ''' see if there will be yet another udp header '''
            index = self.in_data[5:].find(self.udp_header)
            #self.lgr.debug('got %d when look for %s in %s' % (index, self.udp_header, self.in_data[5:]))
            if index > 0 and self.current_packet > self.udp_header_limit:
                self.lgr.debug('writeData, too many udp headers')
                index = -1
            if index > 0:
                first_data = self.in_data[:(index+5)]
                self.in_data = self.in_data[len(first_data):]
                if len(first_data) > self.max_len:
                    #self.lgr.debug('writeData, udp, trimmed first data to max_len')
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
                #self.lgr.debug('writeData wrote packet %d %d bytes addr 0x%x ip: 0x%x  %s' % (self.current_packet, len(first_data), self.addr, eip, first_data[:50]))
                #self.lgr.debug('writeData next packet would start with %s' % self.in_data[:50])
            else:
                ''' no next udp header found'''
                eip = self.top.getEIP(self.cpu)
                data = self.in_data[:self.max_len]
                #self.lgr.debug('writeData wrote packect %d %d bytes addr 0x%x ip: 0x%x ' % (self.current_packet, len(data), self.addr, eip))
                #self.lgr.debug('writeData next UDP header %s not found wrote remaining packet' % (self.udp_header))
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
            self.lgr.error('writeData could not handle data parameters.')

        self.setCallHap()
        #if len(self.in_data) > 0:
        #    self.setCallHap()
        #else:
        #    SIM_run_alone(self.delCallHap, None)
        self.current_packet += 1
        return retval

    def setCallHap(self):
        #if self.call_hap is None and (self.stop_on_read or len(self.in_data)>0):
        # TBD fix for windows?  asynch hell?
        if self.call_hap is None:
            #if self.k_start_ptr is None and not self.mem_utils.isKernel(self.addr) and self.call_ip is not None:
            if self.k_start_ptr is None and self.call_ip is not None:
                ''' NOTE stop on read will miss processing performed by other threads. '''
                #self.lgr.debug('writeData set callHap on call_ip 0x%x, cell is %s' % (self.call_ip, str(self.cell)))
                phys_block = self.cpu.iface.processor_info.logical_to_physical(self.call_ip, Sim_Access_Execute)
                self.call_break = SIM_breakpoint(self.cpu.physical_memory, Sim_Break_Physical, Sim_Access_Execute, phys_block.address, 1, 0)
                #self.call_break = SIM_breakpoint(self.cell, Sim_Break_Linear, Sim_Access_Execute, self.call_ip, 1, 0)
                self.call_hap = RES_hap_add_callback_index("Core_Breakpoint_Memop", self.callHap, None, self.call_break)
                if self.select_call_ip is not None:
                    self.select_break = SIM_breakpoint(self.cell, Sim_Break_Linear, Sim_Access_Execute, self.select_call_ip, 1, 0)
                    self.select_hap = RES_hap_add_callback_index("Core_Breakpoint_Memop", self.selectHap, None, self.select_break)
                    self.lgr.debug('writeData set selectHap on select_call_ip 0x%x, cell is %s' % (self.select_call_ip, str(self.cell)))

    def setSelectStopHap(self):
        if self.select_hap is None:
            if self.mem_utils.WORD_SIZE == 8:
                entry = self.top.getSyscallEntry('select')
            else:
                entry = self.top.getSyscallEntry('_newselect')
            #self.lgr.debug('writeData setSelectStopHap on 0x%x' % entry)
            if entry is not None:
                self.select_break = SIM_breakpoint(self.cell, Sim_Break_Linear, Sim_Access_Execute, entry, 1, 0)
                entry = self.top.getSyscallEntry('poll')
                self.poll_break = SIM_breakpoint(self.cell, Sim_Break_Linear, Sim_Access_Execute, entry, 1, 0)
                self.select_hap = RES_hap_add_callback_index("Core_Breakpoint_Memop", self.selectStopHap, None, self.select_break)
                self.poll_hap = RES_hap_add_callback_index("Core_Breakpoint_Memop", self.selectStopHap, None, self.poll_break)
            else:
                self.lgr.debug('writeData setSelectStopHap failed to get entry for _newselect')

    def setRetHap(self):
        if self.shared_syscall is None:
            if self.ret_hap is None: 
                #self.lgr.debug('writeData set retHap on return_ip 0x%x, cell is %s' % (self.return_ip, str(self.cell)))
                #self.ret_break = SIM_breakpoint(self.cell, Sim_Break_Linear, Sim_Access_Execute, self.return_ip, 1, 0)
                phys_block = self.cpu.iface.processor_info.logical_to_physical(self.return_ip, Sim_Access_Execute)
                self.ret_break = SIM_breakpoint(self.cpu.physical_memory, Sim_Break_Physical, Sim_Access_Execute, phys_block.address, 1, 0)
                self.ret_hap = RES_hap_add_callback_index("Core_Breakpoint_Memop", self.retHap, None, self.ret_break)
        else:
            #self.lgr.debug('writeData set retHap call sharedSyscall setReadFixup')
            self.shared_syscall.setReadFixup(self.doRetFixup)

    def selectHap(self, dumb, third, break_num, memory):
        ''' Hit a call to select or poll'''
        if self.select_hap is None:
            return
        #self.lgr.debug('writeData selectHap ')
        if self.stop_on_read and self.mem_utils.isKernel(self.addr):

            #self.lgr.debug('writeData selectHap stop on read')
            if self.write_callback is not None:
                SIM_run_alone(self.write_callback, 0)
            else:
                #self.lgr.debug('writeData selectHap break simulation')
                SIM_break_simulation('writeData selectHap stop on read callback is None')
            return
        tid = self.top.getTID()
        if self.stop_on_read and len(self.in_data) == 0:
            if self.write_callback is not None:
                SIM_run_alone(self.write_callback, 0)
            else:
                #self.lgr.debug('writeData selectHap stop on read and no more data write callback is None')
                SIM_break_simulation('writeData selectHap stop on read and no more data')
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

    def callHap(self, dumb, third, break_num, memory):
        ''' Hit a call to recv '''
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
            if callname == 'DeviceIoControlFile':
                frame = self.top.frameFromRegs()
                operation = frame['param6'] & 0xffffffff
                if operation in self.ioctl_op_map:
                    op_cmd = self.ioctl_op_map[operation]
                    #self.lgr.debug('writeData callHap,  is Windows TBD bail if RECV tid:%s eip: 0x%x cycles: 0x%x callname %s op: %s' % (tid, eip, 
                    #     self.cpu.cycles, callname, op_cmd))
                    if op_cmd != 'RECV':
                        skip_it = True
            else:
                #self.lgr.debug('writeData callHap, windows expected DeviceIoControFile got %s' % callname)
                skip_it = True

            #    return
        else:
            eip = self.top.getEIP(self.cpu)
            callnum = self.mem_utils.getCallNum(self.cpu)
            callname = self.top.syscallName(callnum)
            frame = self.top.frameFromRegs()
            fd = frame['param1']
            if fd != self.fd:
                #self.lgr.debug('writeData callHap wrong fd, skip it')
                skip_it = True
            if callname == 'socketcall':
                self.lgr.warning('writeData fix this so we know if we are calling a read')
            elif callname not in ['recv', 'recvfrom', 'read']:
                #self.lgr.debug('writeData callHap wrong call %s' % callname)
                skip_it = True
            #self.lgr.debug('writeData callHap eip: 0x%x callnum %d  call: %s fd: %d cycle: 0x%x context: %s' % (eip, callnum, 
            #     callname, fd, self.cpu.cycles, str(self.cpu.current_context)))

        if not skip_it:
            self.read_count = self.read_count + 1
            #self.lgr.debug('writeData callHap, read_count is %d tid:%s' % (self.read_count, tid))
            self.pending_call = True
            self.handleCall()

    def handleCall(self):
        tid = self.top.getTID()
        if tid != self.tid:
            #self.lgr.debug('writeData handleCall wrong tid, got %d wanted %d' % (tid, self.tid)) 
            return
        eip = self.top.getEIP(self.cpu)
        self.lgr.debug('writeData handleCall, tid:%s write_callback %s closed_fd: %r eip: 0x%x cycle: 0x%x' % (tid, self.write_callback, self.closed_fd, eip, self.cpu.cycles))
        if self.closed_fd or len(self.in_data) == 0 or (self.max_packets is not None and self.current_packet >= self.max_packets):
            if self.closed_fd:
                #self.lgr.debug('writeData handleCall current packet %d. closed FD write_callback: %s' % (self.current_packet, self.write_callback))
                pass
            else:
                #self.lgr.debug('writeData handleCall current packet %d. Len in_data: %d write_callback: %s' % (self.current_packet, len(self.in_data), self.write_callback))
                pass
            '''
            self.cpu.iface.int_register.write(self.pc_reg, self.return_ip)
            self.cpu.iface.int_register.write(self.len_reg_num, 0)
            '''
            if self.write_callback is not None:
                self.lgr.debug('writeData handleCall write_callback not None')
                if self.mem_utils.isKernel(self.addr):
                    if self.closed_fd:
                        rprint('fd closed')
                        #self.lgr.debug('writeData handleCall fd closed, stop and call write_callback')
                        SIM_break_simulation('fd closed.')
                        SIM_run_alone(self.write_callback, 0)

                    elif not self.kernel_buf_consumed:
                        #self.lgr.debug('writeData handleCall kernel buffer not consumed.')
                        if self.skip_read_n is not None and self.skip_read_n == self.read_count:
                            # REMOVE/fix TBD
                            self.cpu.iface.int_register.write(self.pc_reg, self.return_ip)
                            self.top.writeRegValue('syscall_ret', 0x12, alone=True, reuse_msg=True)
                            self.lgr.debug('writeData handleCall hacked it')
                            self.read_count = 0
                        else:
                            self.user_space_addr, length = self.top.getReadAddr()
                            if self.user_space_addr is not None:
                                #self.lgr.debug('writeData handleCall user space addr is 0x%x' % self.user_space_addr)
                                self.orig_buffer = self.mem_utils.readBytes(self.cpu, self.user_space_addr, length)
                        
                    else:
                        rprint('kernel buffer data consumed')
                        self.lgr.debug('writeData handleCall kernel buffer data consumed, stop')
                        SIM_break_simulation('kernel buffer data consumed.')
                        self.lgr.debug('writeData handleCall current packet %d kernel buffer' % self.current_packet)
                        SIM_run_alone(self.write_callback, 0)
                elif len(self.in_data) == 0:
                    #self.lgr.debug('writeData handleCall current packet %d no data left, break simulation' % self.current_packet)
                    SIM_run_alone(self.write_callback, 0)
                    #if not self.top.isWindows():
                    #    SIM_run_alone(self.write_callback, 0)
                    #else:
                    #    self.lgr.debug('writeData handleCall current packet %d no data left, has a callback, but this is windows so break simulation' % self.current_packet)
                    #    SIM_break_simulation('buffer data consumed.')
            else:
                # no callback
                if self.mem_utils.isKernel(self.addr):
                    if self.closed_fd:
                        SIM_run_alone(self.delCallHap, None)
                        SIM_break_simulation('writeData fd closed')
                        #self.lgr.debug('writeData handleCall current packet %d fd closed stop simulation' % self.current_packet)
                    elif not self.kernel_buf_consumed:
                        self.user_space_addr, length = self.top.getReadAddr()
                        if self.user_space_addr is not None:
                            self.orig_buffer = self.mem_utils.readBytes(self.cpu, self.user_space_addr, length)
                        #self.lgr.debug('writeData handleCall kernel buf not consumed')
                    else:
                        self.top.haltCoverage()
                        SIM_run_alone(self.delCallHap, None)
                        SIM_break_simulation('writeData out of data')
                        #self.lgr.debug('writeData handleCall current packet %d no data left, stop simulation' % self.current_packet)
                else:
                    if self.stop_on_read:
                        SIM_run_alone(self.delCallHap, None)
                        #self.lgr.debug('writeData handleCall current packet %d no data left, stop_on_read set so stop' % self.current_packet)
                        SIM_break_simulation('writeData out of data')
                    elif self.top.isWindows():
                        SIM_run_alone(self.delCallHap, None)
                        #self.lgr.debug('writeData handleCall current packet %d no data left, is windows, stop for lack of a plan' % self.current_packet)
                        SIM_break_simulation('writeData out of data windows')
                    else:
                        #self.lgr.debug('writeData handleCall current packet %d no data left, continue and trust in backstop' % self.current_packet)
                        pass
            #SIM_run_alone(self.delCallHap, None)
        else:
            
            frame = self.top.frameFromRegs()
            frame_s = taskUtils.stringFromFrame(frame)
            #self.lgr.debug('handleCall writeData frame: %s' % frame_s)

            if self.limit_one:
                self.lgr.warning('writeData handleCall, would write more data, but limit_one')
                #self.lgr.debug(frame_s)
            
            else:
                ''' Skip over kernel to the return ip '''
                self.cpu.iface.int_register.write(self.pc_reg, self.return_ip)
                count = self.write()
                #self.lgr.debug('writeData handleCall, skip over kernel receive processing and wrote %d more bytes context %s' % (count, self.cpu.current_context))
                #print('did write')
                if self.current_packet >= self.expected_packet_count:
                    # set backstop if needed, we are on the last (or only) packet.
                    #SIM_run_alone(self.delCallHap, None)
                    if self.backstop_cycles > 0:
                        #self.lgr.debug('writeData setting backstop')
                        self.backstop.setFutureCycle(self.backstop_cycles)
                if self.write_callback is not None:
                    SIM_run_alone(self.write_callback, count)
                
    def doRetFixup(self, fd):
        ''' We've returned from a read/recv.  Fix up eax if needed and track kernel buffer consumption.'''
        eax = self.mem_utils.getRegValue(self.cpu, 'syscall_ret')
        tid = self.top.getTID()
        if tid != self.tid or fd != self.fd:
            return eax
        eax = self.mem_utils.getSigned(eax)
        if eax <= 0: 
            #self.lgr.error('writeData retHap got count of %d' % eax)
            return eax
        self.pending_call = False
        remain = self.read_limit - self.total_read

        if self.total_read >= self.read_limit and self.stop_on_read:
            #self.lgr.debug('writeData doRetFixup read %d, limit %d total_read %d remain: %d past limit and stop_on_read, stop' % (eax, self.read_limit, self.total_read, remain))
            SIM_break_simulation('writeData doRetFixup no reset')
            return None
        self.total_read = self.total_read + eax
        #self.lgr.debug('writeData doRetFixup read %d, limit %d total_read %d remain: %d' % (eax, self.read_limit, self.total_read, remain))

        if self.stop_on_read and self.total_read >= self.read_limit:
            if self.mem_utils.isKernel(self.addr):
                self.kernel_buf_consumed = True
        if self.total_read > self.read_limit:
            #self.lgr.debug('writeData retHap read over limit of %d' % self.read_limit)
            if self.mem_utils.isKernel(self.addr):
                 ''' adjust the return value and continue '''
                 if eax > remain:
                     if self.no_reset:
                         #self.lgr.debug('writeData doRetFixup, would alter return value, but no_reset is set.  Stop simulation.')
                         SIM_break_simulation('writeData doRetFixup no reset')
                     if self.user_space_addr is not None:
                         start = self.user_space_addr + remain
                         #self.lgr.debug('writeData doRetFixup restored original buffer, %d bytes starting at 0x%x' % (len(self.orig_buffer[remain:eax]), start))
                         self.mem_utils.writeString(self.cpu, start, self.orig_buffer[remain:eax])

                     self.top.writeRegValue('syscall_ret', remain, alone=True, reuse_msg=True)
                     #self.lgr.debug('writeData adjusted return eax from %d to remain value of %d' % (eax, remain))
                     #rprint('**** Adjusted return value, RESET Origin ***') 
                     eax = remain
                     self.kernel_buf_consumed = True
                 if not self.no_call_hap:
                     self.setCallHap()
                 if self.top.isWindows():
                     ''' TBD '''
                     pass
                 else:
                     self.setSelectStopHap()
                 # TBD why was this being deleted?
                 #SIM_run_alone(self.delRetHap, None)
                 #self.lgr.debug('writeData doRetFixup read over limit of %d, setCallHap and let it go' % self.read_limit)
            else:
                 ''' User space injections begin after the return.  TBD should not get here because should be caught by a read call? ''' 
                 SIM_break_simulation('Over read limit')
                 #self.lgr.debug('writeData retHap read over limit of %d' % self.read_limit)
        return eax

    def retHap(self, dumb, third, break_num, memory):
        ''' Hit a return from read'''
        if self.ret_hap is None:
            return
        if not self.pending_call:
            return
        #self.lgr.debug('retHap call doRetFixup')
        self.doRetFixup(self.fd)
        
    def restoreCallHap(self):
        if self.was_a_call_hap:
            #self.lgr.debug('writeData restoreCalHap')
            self.setCallHap()

    def delCallHap(self, dumb):
        #self.lgr.debug('writeData delCallHap')
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
            #self.lgr.debug('injectIO modKernBufSize orig_len is %d write new_end of 0x%x to 0x%x' % (orig_len, new_end, end_ptr))
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
                self.handleCall()

    def selectStopHap(self, dumb, third, break_num, memory):
        if self.select_hap is not None:
            #self.lgr.debug('writeData selectStopHap')
            self.handleCall()
            '''
            if self.write_callback is not None:
                SIM_run_alone(self.write_callback, 0)
            else:
                self.lgr.debug('writeData closeHap break simulation')
                SIM_break_simulation('writeData closeHap')
            '''
    def closedFD(self):
        return self.closed_fd

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
                if self.cpu.architecture == 'arm':
                    self.call_ip = self.return_ip - 4
                    self.lgr.debug('writeData pickle, no call_ip, hack to 4 before ret, 0x%x' % self.call_ip)
                else:
                    self.lgr.warning("writeData pickle, no call_ip, FIX for non-arm")
            if 'select_call_ip' in so_pickle:
                self.select_call_ip = so_pickle['select_call_ip']
                self.select_return_ip = so_pickle['select_return_ip']
                #self.lgr.debug('writeData pickle got select call_ip 0x%x' % self.select_call_ip)
            if self.select_call_ip is None and self.select_return_ip is not None:
                if self.cpu.architecture == 'arm':
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
            if 'fd' in so_pickle:
                self.fd = so_pickle['fd']
            if 'addr_addr' in so_pickle:
                self.addr_addr = so_pickle['addr_addr']
                self.addr_size = so_pickle['addr_size']
            if 'k_start_ptr' in so_pickle:
                self.k_start_ptr = so_pickle['k_start_ptr']
                self.k_end_ptr = so_pickle['k_end_ptr']

            if 'k_bufs' in so_pickle:
                self.lgr.debug('writeData pickle got k_bufs')
                self.k_bufs = so_pickle['k_bufs']
                self.k_buf_len = so_pickle['k_buf_len']

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
