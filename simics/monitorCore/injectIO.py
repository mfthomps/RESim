from simics import *
import writeData
import cli
import os
import pickle
class InjectIO():
    def __init__(self, top, cpu, cell_name, pid, backstop, dfile, dataWatch, bookmarks, mem_utils, context_manager,
           lgr, snap_name, stay=False, keep_size=False, callback=None, packet_count=1, stop_on_read=False, bytes_was=None, 
           coverage=False, packet_size=None, target=None, targetFD=None):
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
        self.udp_header = os.getenv('AFL_UDP_HEADER')
        self.bytes_was = bytes_was
        self.write_data = None
        ''' process name and FD to track, i.e., if process differs from the one consuming injected data. '''
        self.target = target
        self.targetFD = targetFD

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

        with open(self.dfile) as fh:
            self.in_data = fh.read()

        ''' Got to origin/recv location unless not yet debugging '''
        ''' Note obscure use of bookmarks to determine if we've are just starting. '''
        
        if self.bookmarks is not None:
            if self.target is not None:
                ''' Do not have an origin bookmark because replay starts at different process.  Manually skip '''
                SIM_run_command('pselect %s' % self.cpu.name)
                SIM_run_command('skip-to bookmark = bookmark0')
            else:
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
            ''' not used? attempt to restore receive buffer to original condition in case injected data is smaller than original and poor code
                references data past the end of what is received. '''
            self.mem_utils.writeString(self.cpu, self.addr, self.bytes_was) 

        if self.target is None:
            ''' Set Debug before write to use RESim context on the callHap '''
            self.top.stopDebug()
            self.top.debugPidGroup(self.pid) 

        self.write_data = writeData.WriteData(self.top, self.cpu, self.in_data, self.packet_count, self.addr,  
                 self.max_len, self.call_ip, self.return_ip, self.mem_utils, self.backstop, self.lgr, udp_header=self.udp_header, 
                 pad_to_size=self.pad_to_size, backstop_cycles=self.backstop_cycles, stop_on_read=self.stop_on_read)
        self.bookmarks = self.top.getBookmarksInstance()

        #bytes_wrote = self.writeData()
        bytes_wrote = self.write_data.write()
        if self.target is None:
            self.dataWatch.clearWatchMarks()
            self.dataWatch.clearWatches()
            if self.coverage:
                self.top.enableCoverage()
            self.lgr.debug('injectIO did write %d bytes to addr 0x%x max_len %d cycle: 0x%x  Now clear watches' % (bytes_wrote, self.addr, self.max_len, self.cpu.cycles))
            if not self.stay and self.target is None:
                self.bookmarks.setOrigin(self.cpu)
                cli.quiet_run_command('disable-reverse-execution')
                cli.quiet_run_command('enable-reverse-execution')
                self.dataWatch.setRange(self.addr, bytes_wrote, 'injectIO', back_stop=False, recv_addr=self.addr, max_len = self.max_len)
                self.top.watchROP()
                print('retracking IO') 
                self.lgr.debug('retracking IO') 
                self.top.traceAll()
                use_backstop=True
                if self.stop_on_read:
                    use_backstop = False
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

