from simics import *
import sys
import os
import pickle
import taskUtils
from resimUtils import rprint
from resimHaps import *
class WriteData():
    def __init__(self, top, cpu, in_data, expected_packet_count, 
                 mem_utils, backstop, snapshot_name, lgr, udp_header=None, pad_to_size=None, filter=None, 
                 force_default_context=False, backstop_cycles=None, stop_on_read=False, write_callback=None, limit_one=False, 
                  dataWatch=None):
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
        self.callnum = None
        self.socket_callname = None

        self.call_hap = None
        self.call_break = None
        self.select_hap = None
        self.select_break = None
        self.ret_hap = None
        self.ret_break = None
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

        self.loadPickle(snapshot_name)

        if self.call_ip is not None:
            self.lgr.debug('writeData packet count %d add: 0x%x max_len %d in_data len: %d call_ip: 0x%x return_ip: 0x%x context: %s stop_on_read: %r udp: %s' % (self.expected_packet_count, 
                 self.addr, self.max_len, len(in_data), self.call_ip, self.return_ip, str(self.cell), self.stop_on_read, self.udp_header))
        else:
            self.lgr.debug('writeData packet count %d add: 0x%x max_len %d in_data len: %d context: %s stop_on_read: %r udp: %s' % (self.expected_packet_count, 
                 self.addr, self.max_len, len(in_data), str(self.cell), self.stop_on_read, self.udp_header))

        self.pid = self.top.getPID()
        self.filter = filter
        self.orig_len = len(in_data)
        self.dataWatch = dataWatch
        env_max_len = os.getenv('AFL_MAX_LEN')
        if env_max_len is not None:
            self.lgr.debug('writeData Overrode max_len value from pickle with value from environment')
            self.max_len = int(env_max_len)

        self.total_read = 0
        self.read_limit = None

    def reset(self, in_data, expected_packet_count, addr):
        self.in_data = in_data
        self.addr = addr
        self.expected_packet_count = expected_packet_count
        self.current_packet = 0

    
    def write(self, record=False):
        #self.lgr.debug('writeData write, addr is 0x%x' % self.addr)
        if self.k_start_ptr is not None:
            ''' we have buffer start/end info from tracing ioctl '''
            this_len = len(self.in_data)
            orig_len = self.getOrigLen()
            if this_len > orig_len:
                self.lgr.warning('writeData kernel buffer writing %d bytes' % (this_len))
            self.mem_utils.writeString(self.cpu, self.addr, self.in_data) 
            retval = this_len
            self.modKernBufSize(this_len)
            #self.setCallHap()
        elif self.mem_utils.isKernel(self.addr):
            ''' not done, no control over size. prep must use maximum buffer'''
            self.mem_utils.writeString(self.cpu, self.addr, self.in_data) 
            retval = len(self.in_data)
            #self.lgr.debug('writeData write is to kernel buffer %d bytes to 0x%x' % (retval, self.addr))
            if self.dataWatch is not None:
                ''' Limit reads to buffer size '''
                self.dataWatch.setReadLimit(retval, self.readLimitCallback)
            else:
                ''' Limit reads to buffer size using a hap on the read return '''
                self.setRetHap()
                self.read_limit = retval
                self.total_read = 0
            self.in_data = ''
           
        else:
            #self.lgr.debug('writeData write is to user buffer')
            retval = self.userBufWrite(record)
        return retval

    def readLimitCallback(self):
        ''' Called by dataWatch when kernel buffer size is consumed '''
        if self.call_hap is None and self.call_ip is not None:
            self.lgr.debug('writeData readLimitCallback, add callHap')
            self.call_break = SIM_breakpoint(self.cell, Sim_Break_Linear, Sim_Access_Execute, self.call_ip, 1, 0)
            self.call_hap = RES_hap_add_callback_index("Core_Breakpoint_Memop", self.callHap, None, self.call_break)

    def userBufWrite(self, record=False):
        retval = None
        if self.expected_packet_count <= 1 and self.udp_header is None:
            if self.expected_packet_count != 1 and len(self.in_data) > self.max_len:
                next_data = self.in_data[:self.max_len]
                self.in_data = self.in_data[self.max_len:]
                self.mem_utils.writeString(self.cpu, self.addr, next_data) 
                #self.lgr.debug('writeData TCP not last packet, wrote %d bytes to 0x%x packet_num %d remaining bytes %d' % (len(next_data), self.addr, self.current_packet, len(self.in_data)))
                #self.lgr.debug('%s' % next_data)
                self.cpu.iface.int_register.write(self.len_reg_num, len(next_data))
                retval = len(next_data)
                if self.max_len == 1:
                    ''' Assume reading byte at a time into buffer '''
                    ''' TBD REMOVE THIS.  At least for TCP?  Character at a time input requires injection into kernel buffer '''
                    self.addr = self.addr+1
            else:
                if len(self.in_data) > self.max_len:
                    self.in_data = self.in_data[:self.max_len]
                self.mem_utils.writeString(self.cpu, self.addr, self.in_data) 
                tot_len = len(self.in_data)
                eip = self.top.getEIP(self.cpu)
                #self.lgr.debug('writeData TCP last packet, wrote %d bytes to 0x%x packet_num %d eip 0x%x' % (tot_len, self.addr, self.current_packet, eip))
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
                eip = self.top.getEIP(self.cpu)
                #self.lgr.debug('writeData wrote packet %d %d bytes addr 0x%x ip: 0x%x  %s' % (self.current_packet, len(first_data), self.addr, eip, first_data[:50]))
                #self.lgr.debug('writeData next packet would start with %s' % self.in_data[:50])
            else:
                ''' no next udp header found'''
                eip = self.top.getEIP(self.cpu)
                data = self.in_data[:self.max_len]
                #self.lgr.debug('writeData wrote packect %d %d bytes addr 0x%x ip: 0x%x ' % (self.current_packet, len(data), self.addr, eip))
                #self.lgr.debug('writeData next UDP header %s not found wrote remaining packet' % (self.udp_header))
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
            if self.k_start_ptr is None and not self.mem_utils.isKernel(self.addr) and self.call_ip is not None:
                ''' NOTE stop on read will miss processing performed by other threads. '''
                self.lgr.debug('writeData set callHap on call_ip 0x%x, cell is %s' % (self.call_ip, str(self.cell)))
                self.call_break = SIM_breakpoint(self.cell, Sim_Break_Linear, Sim_Access_Execute, self.call_ip, 1, 0)
                self.call_hap = RES_hap_add_callback_index("Core_Breakpoint_Memop", self.callHap, None, self.call_break)
                if self.select_call_ip is not None:
                    self.select_break = SIM_breakpoint(self.cell, Sim_Break_Linear, Sim_Access_Execute, self.select_call_ip, 1, 0)
                    self.select_hap = RES_hap_add_callback_index("Core_Breakpoint_Memop", self.selectHap, None, self.select_break)
                    self.lgr.debug('writeData set selectHap on select_call_ip 0x%x, cell is %s' % (self.select_call_ip, str(self.cell)))

    def setRetHap(self):
        if self.ret_hap is None: 
            self.lgr.debug('writeData set retHap on return_ip 0x%x, cell is %s' % (self.return_ip, str(self.cell)))
            self.ret_break = SIM_breakpoint(self.cell, Sim_Break_Linear, Sim_Access_Execute, self.return_ip, 1, 0)
            self.ret_hap = RES_hap_add_callback_index("Core_Breakpoint_Memop", self.retHap, None, self.ret_break)

    def selectHap(self, dumb, third, break_num, memory):
        ''' Hit a call to select'''
        if self.select_hap is None:
            return
        #self.lgr.debug('writeData selectHap ')
        if self.stop_on_read:
            self.lgr.debug('writeData selectHap stop on read')
            SIM_break_simulation('writeData selectHap stop on read')
            return
        pid = self.top.getPID()
        if self.stop_on_read and len(self.in_data) == 0:
            self.lgr.debug('writeData selectHap stop on read')
            SIM_break_simulation('writeData selectHap stop on read')
            return
        if pid != self.pid:
            #self.lgr.debug('writeData callHap wrong pid, got %d wanted %d' % (pid, self.pid)) 
            return
        if len(self.in_data) == 0 or (self.max_packets is not None and self.current_packet >= self.max_packets):
            self.lgr.debug('writeData selectHap current packet %d no data left, let backstop timeout? return value of zero to application since we cant block.' % (self.current_packet))
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
        self.handleCall()

    def handleCall(self):
        pid = self.top.getPID()
        if self.stop_on_read and len(self.in_data) == 0:
            self.lgr.debug('writeData stop on read')
            SIM_break_simulation('writeData stop on read')
            return
        if pid != self.pid:
            #self.lgr.debug('writeData callHap wrong pid, got %d wanted %d' % (pid, self.pid)) 
            return
        if len(self.in_data) == 0 or (self.max_packets is not None and self.current_packet >= self.max_packets):
            #self.lgr.debug('writeData callHap current packet %d no data left, let backstop timeout? return value of zero to application since we cant block.' % (self.current_packet))
            '''
            self.cpu.iface.int_register.write(self.pc_reg, self.return_ip)
            self.cpu.iface.int_register.write(self.len_reg_num, 0)
            '''
            if self.write_callback is not None:
                if self.mem_utils.isKernel(self.addr):
                    #rprint('kernel buffer data consumed')
                    SIM_break_simulation('kernel buffer data consumed.')
                    #self.lgr.debug('writeData callHap current packet %d no data left, kernel buffer, stop simulation' % self.current_packet)
                else:
                    SIM_run_alone(self.write_callback, 0)
            else:
                if self.mem_utils.isKernel(self.addr):
                    SIM_break_simulation('writeData out of data')
                    #self.lgr.debug('writeData callHap current packet %d no data left, stop simulation' % self.current_packet)
                else:
                    #self.lgr.debug('writeData callHap current packet %d no data left, continue and trust in backstop' % self.current_packet)
                    pass
            #SIM_run_alone(self.delCallHap, None)
        else:
            
            frame = self.top.frameFromRegs(self.cpu)
            frame_s = taskUtils.stringFromFrame(frame)
            #self.lgr.debug('callHap writeData frame: %s' % frame_s)

            if self.limit_one:
                self.lgr.warning('writeData callHap, would write more data, but limit_one')
                #self.lgr.debug(frame_s)
            
            else:
                ''' Skip over kernel to the return ip '''
                self.cpu.iface.int_register.write(self.pc_reg, self.return_ip)
                count = self.write()
                #self.lgr.debug('writeData callHap, skip over kernel receive processing and wrote %d more bytes context %s' % (count, self.cpu.current_context))
                #print('did write')
                if self.current_packet >= self.expected_packet_count:
                    # set backstop if needed, we are on the last (or only) packet.
                    #SIM_run_alone(self.delCallHap, None)
                    if self.backstop_cycles > 0:
                        #self.lgr.debug('writeData setting backstop')
                        self.backstop.setFutureCycle(self.backstop_cycles)
                if self.write_callback is not None:
                    SIM_run_alone(self.write_callback, count)
                

    def retHap(self, dumb, third, break_num, memory):
        ''' Hit a return from read'''
        if self.callHap is None:
            return
        eax = self.mem_utils.getRegValue(self.cpu, 'syscall_ret')
        eax = self.mem_utils.getSigned(eax)
        if eax <= 0: 
            self.lgr.error('writeData retHap got count of %d' % eax)
            return
        self.total_read = self.total_read + eax
        if self.total_read > self.read_limit:
            self.lgr.debug('writeData retHap read over limit of %d' % self.read_limit)
            if self.write_callback is not None:
                 SIM_run_alone(self.write_callback, count)
            else:
                 SIM_break_simulation('Over read limit')
        

    def delCallHap(self, dumb):
        #self.lgr.debug('writeData delCallHap')
        if self.call_hap is not None:
            SIM_delete_breakpoint(self.call_break)
            RES_hap_delete_callback_id('Core_Breakpoint_Memop', self.call_hap)
            self.call_hap = None
            self.call_break = None
        if self.select_hap is not None:
            SIM_delete_breakpoint(self.select_break)
            RES_hap_delete_callback_id('Core_Breakpoint_Memop', self.select_hap)
            self.select_hap = None
            self.select_break = None
        if self.ret_hap is not None:
            SIM_delete_breakpoint(self.ret_break)
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

            if 'orig_buffer' in so_pickle:
                self.orig_buffer = so_pickle['orig_buffer']
                self.lgr.debug('injectiO load orig_buffer from pickle')
            if 'callnum' in so_pickle:
                self.callnum = so_pickle['callnum']
                self.socket_callname = so_pickle['socket_callname']
                self.lgr.debug('loadPickle callnum %d socket_callname %s' % (self.callnum, self.socket_callname))
                
