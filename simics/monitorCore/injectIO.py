from simics import *
import cli
import os
import pickle
class InjectIO():
    def __init__(self, top, cpu, cell_name, pid, backstop, dfile, dataWatch, bookmarks, mem_utils, context_manager,
           lgr, snap_name, stay=False, keep_size=False, callback=None, packet_count=1, stop_on_read=False, bytes_was=None):
        self.dfile = dfile
        self.stay = stay
        self.cpu = cpu
        self.cell_name = cell_name
        self.pid = pid
        self.backstop = backstop
        self.dataWatch = dataWatch
        self.bookmarks = bookmarks
        self.keep_size = keep_size
        self.callback = callback
        self.mem_utils = mem_utils
        self.context_manager = context_manager
        self.top = top
        self.lgr = lgr
        self.in_data = None
        self.backstop_cycles =   9000000
        self.stop_on_read =   stop_on_read
        self.packet_count = packet_count
        if self.packet_count > 0: 
            self.stop_on_read = True
        self.afl_packet_count = None
        self.current_packet = 0
        self.call_ip = None
        self.call_hap = None
        self.call_break = None
        self.addr = None
        self.max_len = None
        self.loadPickle(snap_name)
        if self.addr is None: 
            self.addr, self.max_len = self.dataWatch.firstBufferAddress()
            if self.addr is None:
                self.lgr.error('injectIO, no firstBufferAddress found')
                return

        if self.cpu.architecture == 'arm':
            lenreg = 'r0'
        else:
            lenreg = 'eax'
        self.len_reg_num = self.cpu.iface.int_register.get_number(lenreg)
        self.pc_reg = self.cpu.iface.int_register.get_number('pc')
        self.pad_to_size = 0
        self.udp_header = os.getenv('AFL_UDP_HEADER')
        self.bytes_was = bytes_was

    def go(self):
        ''' Go to the first data receive watch mark (or the origin if the watch mark does not exist),
            which we assume follows a read, recv, etc.  Then write the dfile content into
            memory, e.g., starting at R1 of a ARM recv.  Adjust the returned length, e.g., R0
            to match the length of the  dfile.  Finally, run trackIO on the given file descriptor.
            Assumes we are stopped.  
            If "stay", then just inject and don't run.
        '''
        if self.addr is None:
            return
        if self.callback is None:
            self.callback = self.top.stopTrackIO
        if not os.path.isfile(self.dfile):
            print('File not found at %s\n\n' % self.dfile)
            return
        ''' Add memUtil function to put byte array into memory '''
        byte_string = None
        
        self.afl_packet_count = self.packet_count
        with open(self.dfile) as fh:
            self.in_data = fh.read()

        ''' Got to origin/recv location unless not yet debugging '''
        ''' Note obscure use of bookmarks to determine if we've are just starting. '''
        
        if self.bookmarks is not None:
            self.dataWatch.goToRecvMark()
        else:
            self.lgr.debug('injectIO debug_pid is None, first run?')

        lenreg = None
        lenreg2 = None
        if self.cpu.architecture == 'arm':
            ''' **SEEMS WRONG, what was observed? **length register, seems to acutally be R7, at least that is what libc uses and reports (as R0 by the time
                the invoker sees it.  So, we'll set both for alternate libc implementations? '''
            lenreg = 'r0'
            #lenreg2 = 'r7'
        else:
            lenreg = 'eax'
        if self.bytes_was is not None:
            self.mem_utils.writeString(self.cpu, self.addr, self.bytes_was) 

        ''' Set Debug before write to use RESim context on the callHap '''
        self.top.stopDebug()
        self.top.debugPidGroup(self.pid) 
        self.bookmarks = self.top.getBookmarksInstance()

        bytes_wrote = self.writeData()
        self.dataWatch.clearWatchMarks()
        self.dataWatch.clearWatches()
        self.lgr.debug('injectIO did write %d bytes to addr 0x%x max_len %d cycle: 0x%x  Now clear watches' % (bytes_wrote, self.addr, self.max_len, self.cpu.cycles))
        if not self.stay:
            self.bookmarks.setOrigin(self.cpu)
            cli.quiet_run_command('disable-reverse-execution')
            cli.quiet_run_command('enable-reverse-execution')
            self.dataWatch.setRange(self.addr, bytes_wrote, 'injectIO', back_stop=False, recv_addr=self.addr, max_len = self.max_len)
            self.top.watchROP()
            print('retracking IO') 
            self.lgr.debug('retracking IO') 
            self.top.retrack(clear=False, callback=self.callback)    

    def writeData(self):
        ''' Write next chunk of data into the receive buffer '''
        ''' NOTE this adjusts self.in_data after the write to prep for next packet '''
        current_length = len(self.in_data)
        tot_length = current_length
        pad_count = 0
        self.current_packet = self.current_packet + 1
        self.lgr.debug('writeData packet %d afl_packet_count is %s' % (self.current_packet, str(self.afl_packet_count)))
        if self.afl_packet_count == 1 or self.current_packet >= self.afl_packet_count:  
            ''' Data from AFL is trimmed.  Pad it to satisfy the application if needed '''
            pad_count = self.pad_to_size - current_length
            self.mem_utils.writeString(self.cpu, self.addr, self.in_data) 
            self.lgr.debug('injectIO writeData wrote last packet %d %d bytes  %s' % (self.current_packet, len(self.in_data), self.in_data[:50]))
            if pad_count > 0:
                b = bytearray(pad_count)
                self.mem_utils.writeString(self.cpu, self.addr+current_length, b) 
                tot_length += pad_count
            if self.backstop_cycles > 0:
                self.lgr.debug('injection setting backstop cycles')
                self.backstop.setFutureCycleAlone(self.backstop_cycles)
            self.in_data = ''
        elif self.pad_to_size > 0 and self.udp_header is None:
            first_data = self.in_data[0:self.pad_to_size]
            self.mem_utils.writeString(self.cpu, self.addr, first_data) 
            self.lgr.debug('injectIO writeData wrote truncated data')
            self.in_data = self.in_data[self.pad_to_size:]
            tot_length = self.pad_to_size
        else:
            index = self.in_data[5:].find(self.udp_header)
            if index > 0:
                first_data = self.in_data[:(index+5)]
                self.mem_utils.writeString(self.cpu, self.addr, first_data) 
                self.in_data = self.in_data[len(first_data):]
                # TBD add handling of padding with udp header                
                tot_length = len(first_data)
                self.lgr.debug('injectIO writeData wrote packet %d %d bytes  %s' % (self.current_packet, len(first_data), first_data[:50]))
                #self.lgr.debug('afl next packet would start with %s' % self.in_data[:50])
            else:
                self.lgr.debug('afl next UDP header %s not found packet %d  afl_packet_count is %d, write nulls and cut packet count' % (self.udp_header, self.current_packet, 
                    self.afl_packet_count))
                #self.lgr.debug(self.in_data[:500])
                b = bytearray(100)
                self.mem_utils.writeString(self.cpu, self.addr, b) 
                self.afl_packet_count = 1
                tot_length = 100

        if self.call_hap is None and (self.afl_packet_count > self.current_packet or self.stop_on_read):
            ''' Break on the next recv call, either to multi-UDP fu, or to declare we are done (stop_on_read) '''
            cell = self.top.getCell()
            #self.call_break = SIM_breakpoint(cell, Sim_Break_Linear, Sim_Access_Execute, self.call_ip, 1, 0)
            self.call_break = self.context_manager.genBreakpoint(cell, Sim_Break_Linear, Sim_Access_Execute, self.call_ip, 1, 0)
            #self.call_hap = SIM_hap_add_callback_index("Core_Breakpoint_Memop", self.callHap, None, self.call_break)
            self.call_hap = self.context_manager.genHapIndex("Core_Breakpoint_Memop", self.callHap, None, self.call_break , 'inject_read')
            self.lgr.debug('injectIO writeData writeData set call break at 0x%x and hap, cycle is 0x%x' % (self.call_ip, self.cpu.cycles))


        ''' Tell the application how much data it read ''' 
        if not self.keep_size:
            self.cpu.iface.int_register.write(self.len_reg_num, tot_length)
            self.lgr.debug('injectIO from file %s. Length set to 0x%x' % (self.dfile, tot_length))
            print('injectIO from file %s. Length set to 0x%x' % (self.dfile, tot_length))
        else:
            tot_length = self.cpu.iface.int_register.read(self.len_reg_num)
            self.lgr.debug('injectIO from file %s, retaining original length of %d' % (self.dfile, tot_length))
            print('injectIO from file %s, retaining original length of %d' % (self.dfile, tot_length))
        return tot_length

    def delCallHap(self, dumb):
        self.lgr.debug('injectIO delCallHap')
        self.context_manager.genDeleteHap(self.call_hap)
        #SIM_delete_breakpoint(self.call_break)
        #SIM_hap_delete_callback_id('Core_Breakpoint_Memop', self.call_hap)
        self.call_hap = None

    def resetOrigin(self, dumb):
            self.bookmarks.setOrigin(self.cpu)
            SIM_run_command('disable-reverse-execution') 
            SIM_run_command('enable-reverse-execution') 

    def callHap(self, dumb, third, break_num, memory):
        ''' Hit a call to recv '''
        if self.call_hap is None:
            return
        if self.current_packet > self.afl_packet_count:
            self.lgr.debug('injectIO callHap current packet %d above count %d' % (self.current_packet, self.afl_packet_count))
            pass
        elif self.current_packet < self.afl_packet_count:
            self.lgr.debug('injectIO callHap more packets, do a write')
            self.cpu.iface.int_register.write(self.pc_reg, self.return_ip)
            self.writeData()
            SIM_run_alone(self.resetOrigin, None)
        else:
            SIM_run_alone(self.delCallHap, None)

    def loadPickle(self, name):
        afl_file = os.path.join('./', name, self.cell_name, 'afl.pickle')
        if os.path.isfile(afl_file):
            self.lgr.debug('afl pickle from %s' % afl_file)
            so_pickle = pickle.load( open(afl_file, 'rb') ) 
            #print('start %s' % str(so_pickle['text_start']))
            self.call_ip = so_pickle['call_ip']
            self.return_ip = so_pickle['return_ip']
            if 'addr' in so_pickle:
                self.addr = so_pickle['addr']
                self.max_len = so_pickle['size']

