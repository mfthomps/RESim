from simics import *
import writeData
import cli
import os
import sys
import pickle
class InjectIO():
    def __init__(self, top, cpu, cell_name, pid, backstop, dfile, dataWatch, bookmarks, mem_utils, context_manager,
           lgr, snap_name, stay=False, keep_size=False, callback=None, packet_count=1, stop_on_read=False, 
           coverage=False, packet_size=None, target=None, targetFD=None, trace_all=False):
        self.dfile = dfile
        self.stay = stay
        self.cpu = cpu
        self.cell_name = cell_name
        self.pid = pid
        self.backstop = backstop
        self.dataWatch = dataWatch
        self.bookmarks = bookmarks
        self.keep_size = keep_size
        ''' What to do when tracking completes.  Default will be to call stopTrack. '''
        self.callback = callback
        self.mem_utils = mem_utils
        self.context_manager = context_manager
        self.top = top
        self.lgr = lgr
        self.in_data = None
        self.backstop_cycles =   9000000
        self.stop_on_read =   stop_on_read
        self.packet_count = packet_count
        if self.packet_count > 1: 
            self.stop_on_read = True
        self.current_packet = 0
        self.call_ip = None
        self.call_hap = None
        self.call_break = None
        self.addr = None
        self.max_len = None
        self.orig_buffer = None
        self.loadPickle(snap_name)
        if self.addr is None: 
            self.addr, self.max_len = self.dataWatch.firstBufferAddress()
            if self.addr is None:
                self.lgr.error('injectIO, no firstBufferAddress found')
                return
        else:
            self.lgr.debug('injectIO loaded from pickle, addr: 0x%x max_len %d' % (self.addr, self.max_len))
        if packet_size is not None:
            self.max_len = packet_size

        self.coverage = coverage
        if self.cpu.architecture == 'arm':
            lenreg = 'r0'
        else:
            lenreg = 'eax'
        self.len_reg_num = self.cpu.iface.int_register.get_number(lenreg)
        self.pc_reg = self.cpu.iface.int_register.get_number('pc')
        self.pad_to_size = 0
        pad_env = os.getenv('AFL_PAD')
        if pad_env is not None:
            self.pad_to_size = int(pad_env)
            self.lgr.debug('injectIO got pad of %d' % self.pad_to_size)
        self.udp_header = os.getenv('AFL_UDP_HEADER')
        self.write_data = None
        ''' process name and FD to track, i.e., if process differs from the one consuming injected data. '''
        self.target = target
        self.targetFD = targetFD

        # No data tracking, just trace all system calls
        self.trace_all = trace_all

        self.stop_hap = None

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

        #with open(self.dfile) as fh:
        #    self.in_data = fh.read()
        with open(self.dfile, 'rb') as fh:
            if sys.version_info[0] == 2:
                self.in_data = bytearray(fh.read())
            else:
                self.in_data = fh.read()

        ''' Got to origin/recv location unless not yet debugging '''
        if self.target is None:
            self.dataWatch.goToRecvMark()

        lenreg = None
        lenreg2 = None
        if self.cpu.architecture == 'arm':
            ''' **SEEMS WRONG, what was observed? **length register, seems to acutally be R7, at least that is what libc uses and reports (as R0 by the time
                the invoker sees it.  So, we'll set both for alternate libc implementations? '''
            lenreg = 'r0'
            #lenreg2 = 'r7'
        else:
            lenreg = 'eax'
        if self.orig_buffer is not None:
            ''' restore receive buffer to original condition in case injected data is smaller than original and poor code
                references data past the end of what is received. '''
            self.mem_utils.writeString(self.cpu, self.addr, self.orig_buffer) 
            self.lgr.debug('injectIO restored %d bytes to original buffer' % len(self.orig_buffer))

        if self.target is None and not self.trace_all:
            ''' Set Debug before write to use RESim context on the callHap '''
            self.top.stopDebug()
            self.top.debugPidGroup(self.pid) 

        self.write_data = writeData.WriteData(self.top, self.cpu, self.in_data, self.packet_count, self.addr,  
                 self.max_len, self.call_ip, self.return_ip, self.mem_utils, self.backstop, self.lgr, udp_header=self.udp_header, 
                 pad_to_size=self.pad_to_size, backstop_cycles=self.backstop_cycles, stop_on_read=self.stop_on_read, write_callback=self.writeCallback)
        self.bookmarks = self.top.getBookmarksInstance()

        #bytes_wrote = self.writeData()
        bytes_wrote = self.write_data.write()
        if self.target is None:
            self.dataWatch.clearWatchMarks()
            self.dataWatch.clearWatches()
            if self.coverage:
                self.top.enableCoverage()
            self.lgr.debug('injectIO did write %d bytes to addr 0x%x max_len %d cycle: 0x%x  Now clear watches' % (bytes_wrote, self.addr, self.max_len, self.cpu.cycles))
            if not self.stay:
                if not self.trace_all:
                    self.bookmarks.setOrigin(self.cpu)
                    cli.quiet_run_command('disable-reverse-execution')
                    cli.quiet_run_command('enable-reverse-execution')
                    #self.dataWatch.setRange(self.addr, bytes_wrote, 'injectIO', back_stop=False, recv_addr=self.addr, max_len = self.max_len)
                    ''' per trackIO, look at entire buffer for ref to old data '''
                    self.dataWatch.setRange(self.addr, bytes_wrote, 'injectIO', back_stop=False, recv_addr=self.addr, max_len = self.max_len)
                    if self.addr_addr is not None:
                        self.dataWatch.setRange(self.addr_addr, self.addr_size, 'injectIO-addr')
                    self.top.watchROP()
                self.top.traceAll()
                use_backstop=True
                if self.stop_on_read:
                    use_backstop = False
                if self.trace_all:
                    cli.quiet_run_command('c')
                else:
                    print('retracking IO') 
                    self.lgr.debug('retracking IO') 
                    self.top.retrack(clear=False, callback=self.callback, use_backstop=use_backstop)    
        else:
            ''' target is not current process.  go to target then callback to injectCalback'''
            self.lgr.debug('injectIO debug to %s' % self.target)
            self.top.resetOrigin()
            ''' watch for death of this process as well '''
            self.context_manager.stopWatchTasks()
            self.context_manager.watchGroupExits()
            self.top.watchPageFaults()
            #self.context_manager.setExitCallback(self.recordExit)
            self.top.debugProc(self.target, final_fun=self.injectCallback)
            #self.top.debugProc(self.target, final_fun=self.injectCallback, pre_fun=self.context_manager.resetWatchTasks)

    def injectCallback(self):
        ''' called at the end of the debug hap chain, meaning we are in the target process. '''
        self.lgr.debug('injectIO injectCallback')
        self.context_manager.watchGroupExits()
        self.bookmarks = self.top.getBookmarksInstance()
        self.top.trackIO(self.targetFD)

    def delCallHap(self):
        if self.write_data is not None:
            self.write_data.delCallHap(None)

    def setCallHap(self):
        if self.write_data is not None:
            self.write_data.setCallHap()
    

    def resetOrigin(self, dumb):
            self.bookmarks.setOrigin(self.cpu)
            SIM_run_command('disable-reverse-execution') 
            SIM_run_command('enable-reverse-execution') 

    def resetReverseAlone(self, count):
        self.lgr.debug('injectIO, handling subsequent packet, must reset watch marks and bookmarks')
        self.resetOrigin(None)
        self.dataWatch.clearWatchMarks()
        self.dataWatch.setRange(self.addr, count, 'injectIO', back_stop=False, recv_addr=self.addr, max_len = self.max_len)
        if self.addr_addr is not None:
            self.dataWatch.setRange(self.addr_addr, self.addr_size, 'injectIO-addr')

        SIM_hap_delete_callback_id("Core_Simulation_Stopped", self.stop_hap)
        self.stop_hap = None
        SIM_run_command('c')
        

    def stopHap(self, count, one, exception, error_string):
        if self.stop_hap is None:
            return
        self.lgr.debug('injectIO stopHap from writeCalback')
        SIM_run_alone(self.resetReverseAlone, count)
        
    def writeCallback(self, count):
        self.stop_hap = SIM_hap_add_callback("Core_Simulation_Stopped", 
        	     self.stopHap, count)
        SIM_break_simulation('writeCallback')

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
            if 'addr_addr' in so_pickle:
                self.addr_addr = so_pickle['addr_addr']
                self.addr_size = so_pickle['addr_size']
            if 'orig_buffer' in so_pickle:
                self.orig_buffer = so_pickle['orig_buffer']
                self.lgr.debug('injectiO load orig_buffer from pickle')
