from simics import *
import sys
import taskUtils
class WriteData():
    def __init__(self, top, cpu, in_data, expected_packet_count, addr,  
                 max_length, call_ip, return_ip, mem_utils, backstop, lgr, udp_header=None, pad_to_size=None, filter=None, 
                 force_default_context=False, backstop_cycles=None, stop_on_read=False, write_callback=None, limit_one=False):
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
        self.addr = addr
        self.max_len = max_length
        # Use to skip over kernel recv processing
        self.call_ip = call_ip
        self.return_ip = return_ip
        
        self.call_hap = None
        self.call_break = None
        # see in_data
        if sys.version_info[0] > 2 and type(udp_header) == str:
            self.udp_header = bytes(udp_header, encoding='utf8')
        else:
            self.udp_header = udp_header
        self.pad_to_size = pad_to_size
        self.mem_utils = mem_utils
        self.backstop = backstop
        self.backstop_cycles = backstop_cycles
        self.write_callback = write_callback
        self.lgr = lgr
        self.limit_one = limit_one

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
        #self.lgr.debug('writeData packet count %d add: 0x%x max_len %d in_data len: %d call_ip: 0x%x return_ip: 0x%x context: %s stop_on_read: %r udp: %s' % (self.expected_packet_count, 
        #     self.addr, self.max_len, len(in_data), self.call_ip, self.return_ip, str(self.cell), self.stop_on_read, self.udp_header))

        self.pid = self.top.getPID()
        self.filter = filter

    def reset(self, in_data, expected_packet_count, addr):
        self.in_data = in_data
        self.addr = addr
        self.expected_packet_count = expected_packet_count
        self.current_packet = 0

    def write(self, record=False):
        retval = None
        if self.expected_packet_count <= 1 and self.udp_header is None:
            if self.expected_packet_count != 1 and len(self.in_data) > self.max_len:
                next_data = self.in_data[:self.max_len]
                self.in_data = self.in_data[self.max_len:]
                self.mem_utils.writeString(self.cpu, self.addr, next_data) 
                #self.lgr.debug('writeData TCP not last packet, wrote %d bytes to 0x%x packet_num %d remaining bytes %d' % (len(next_data), self.addr, self.current_packet, len(self.in_data)))
                self.cpu.iface.int_register.write(self.len_reg_num, len(next_data))
                retval = len(next_data)
            else:
                if len(self.in_data) > self.max_len:
                    self.in_data = self.in_data[:self.max_len]
                self.mem_utils.writeString(self.cpu, self.addr, self.in_data) 
                tot_len = len(self.in_data)
                #self.lgr.debug('writeData TCP last packet, wrote %d bytes to 0x%x packet_num %d' % (tot_len, self.addr, self.current_packet))
                if self.pad_to_size is not None and tot_len < self.pad_to_size:
                    pad_count = self.pad_to_size - len(self.in_data)
                    b = bytearray(pad_count)
                    next_addr = self.addr + len(self.in_data)
                    self.mem_utils.writeString(self.cpu, next_addr, b) 
                    #self.lgr.debug('writeData TCP last packet, padded %d bytes' % pad_count)
                    tot_len = tot_len + pad_count
                self.cpu.iface.int_register.write(self.len_reg_num, tot_len)
                self.in_data = ''
                retval = tot_len
        elif self.udp_header is not None:
            ''' see if there will be yet another udp header '''
            index = self.in_data[5:].find(self.udp_header)
            if index > 0:
                first_data = self.in_data[:(index+5)]
                self.in_data = self.in_data[len(first_data):]
                if len(first_data) > self.max_len:
                    #self.lgr.debug('writeData, udp, trimmed first data to max_len')
                    first_data = first_data[:self.max_len]
                if self.filter is not None and not self.filter.filter(first_data, self.current_packet):
                    self.mem_utils.writeString(self.cpu, self.addr, bytearray(len(first_data))) 
                    #self.lgr.debug('writeData first_data failed filter, wrote nulls')
                else: 
                    self.mem_utils.writeString(self.cpu, self.addr, first_data) 
                # TBD add handling of padding with udp header                
                retval = len(first_data)
                #self.lgr.debug('writeData wrote packet %d %d bytes  %s' % (self.current_packet, len(first_data), first_data[:50]))
                #self.lgr.debug('writeData next packet would start with %s' % self.in_data[:50])
            else:
                ''' no next udp header found'''
                data = self.in_data[:self.max_len]
                #self.lgr.debug('writeData next UDP header %s not found packet %d  write remaining packet len %d max_len %d in_data len %d' % (self.udp_header, self.current_packet, len(data), self.max_len, len(self.in_data)))
                if self.filter is not None and not self.filter.filter(data, self.current_packet):
                    self.mem_utils.writeString(self.cpu, self.addr, bytearray(len(data))) 
                    #self.lgr.debug('writeData failed filter, wrote nulls')
                else:
                    self.mem_utils.writeString(self.cpu, self.addr, data) 
                retval = len(data)
                self.in_data = ''
                #retval = 100
            self.cpu.iface.int_register.write(self.len_reg_num, retval)
                
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
        if self.call_hap is None:
            ''' NOTE stop on read will miss processing performed by other threads. '''
            #self.lgr.debug('writeData set callHap on call_ip 0x%x, cell is %s' % (self.call_ip, str(self.cell)))
            self.call_break = SIM_breakpoint(self.cell, Sim_Break_Linear, Sim_Access_Execute, self.call_ip, 1, 0)
            self.call_hap = SIM_hap_add_callback_index("Core_Breakpoint_Memop", self.callHap, None, self.call_break)

    def callHap(self, dumb, third, break_num, memory):
        ''' Hit a call to recv '''
        if self.call_hap is None:
            return
        pid = self.top.getPID()
        if pid != self.pid:
            #self.lgr.debug('writeData callHap wrong pid, got %d wanted %d' % (pid, self.pid)) 
            return
        if len(self.in_data) == 0:
            #self.lgr.debug('writeData callHap current packet %d no data left, stopping' % (self.current_packet))
            SIM_break_simulation('broken offset')
            SIM_run_alone(self.delCallHap, None)
        else:
            frame = self.top.frameFromRegs(self.cpu)
            frame_s = taskUtils.stringFromFrame(frame)
            #self.lgr.debug('callHap writeData frame: %s' % frame_s)
            if self.limit_one:
                self.lgr.warning('writeData callHap, would write more data, but limit_one')
                #self.lgr.debug(frame_s)
            
            else:
                self.cpu.iface.int_register.write(self.pc_reg, self.return_ip)
                count = self.write()
                #print('did write')
                #self.lgr.debug('writeData callHap, skip over kernel receive processing and wrote %d more bytes context %s' % (count, self.cpu.current_context))
                if self.current_packet >= self.expected_packet_count:
                    # set backstop if needed, we are on the last (or only) packet.
                    #SIM_run_alone(self.delCallHap, None)
                    if self.backstop_cycles > 0:
                        #self.lgr.debug('writeData setting backstop')
                        self.backstop.setFutureCycle(self.backstop_cycles)
                if self.write_callback is not None:
                    SIM_run_alone(self.write_callback, count)

    def delCallHap(self, dumb):
        #self.lgr.debug('writeData delCallHap')
        if self.call_hap is not None:
            SIM_delete_breakpoint(self.call_break)
            SIM_hap_delete_callback_id('Core_Breakpoint_Memop', self.call_hap)
            self.call_hap = None
            self.call_break = None

    def getCurrentPacket(self):
        return self.current_packet
