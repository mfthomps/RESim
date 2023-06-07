from simics import *
import writeData
import memUtils
import cli
import os
import sys
import pickle
from resimHaps import *
import resimUtils
class InjectIO():
    def __init__(self, top, cpu, cell_name, pid, backstop, dfile, dataWatch, bookmarks, mem_utils, context_manager,
           lgr, snap_name, stay=False, keep_size=False, callback=None, packet_count=1, stop_on_read=False, 
           coverage=False, fname=None, target=None, targetFD=None, trace_all=False, save_json=None, no_track=False, no_reset=False,
           limit_one=False, no_rop=False, instruct_trace=False, break_on=None, mark_logs=False, no_iterators=False, only_thread=False):
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
        self.lgr.debug('break_on given as %s fname as %s' % (str(break_on), fname))
        self.break_on = break_on
        if break_on is not None and fname is not None:
            self.lgr.debug('break_on given as 0x%x' % break_on)
            so_entry = self.top.getSOAddr(fname, pid=self.pid)
            if so_entry is None:
                self.lgr.error('injectIO no SO entry for %s' % prog)
            if so_entry.address is not None:
                if so_entry.locate is not None:
                    self.break_on = self.break_on + so_entry.locate + so_entry.offset
                    self.lgr.debug('injectIO adjusted break_on to be 0x%x' % self.break_on)
            else:
                self.lgr.error('injectIO SO entry address is None for %s' % fname)
        self.in_data = None
        self.backstop_cycles =   9000000
        bsc = os.getenv('BACK_STOP_CYCLES')
        if bsc is not None:
            self.backstop_cycles = int(bsc)
        hang_cycles = 90000000
        hang = os.getenv('HANG_CYCLES')
        if hang is not None:
            hang_cycles = int(hang)
        if callback is not None:
            hang_callback = callback
        else:
            hang_callback = self.recordHang
        self.backstop.setHangCallback(hang_callback, hang_cycles)
        self.stop_on_read =   stop_on_read
        self.packet_count = packet_count
        #if self.packet_count > 1: 
        #    self.stop_on_read = True
        self.current_packet = 0
        self.addr = None
        self.addr_addr = None

        self.max_len = None
        self.orig_buffer = None
        self.limit_one = limit_one
        self.clear_retrack = False
        self.fd = None

        self.snap_name = snap_name
        self.loadPickle(snap_name)
        if self.addr is None: 
            self.addr, self.max_len = self.dataWatch.firstBufferAddress()
            if self.addr is None:
                self.lgr.error('injectIO, no firstBufferAddress found')
                return

        self.coverage = coverage
        self.fname = fname
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

        self.save_json = save_json

        self.stop_hap = None
        self.no_rop = no_rop
        self.instruct_trace = instruct_trace
        sor = os.getenv('AFL_STOP_ON_READ')
        self.lgr.debug('sor is %s' % sor)
        if sor is not None and sor.lower() == 'true':
            self.stop_on_read = True
            self.lgr.debug('injectIO stop_on_read is true')
        self.break_on_hap = None
        if not self.coverage:
            self.dataWatch.enable()
        self.dataWatch.clearWatchMarks(record_old=True)
        self.mark_logs = mark_logs
        self.filter_module = None
        packet_filter = os.getenv('AFL_PACKET_FILTER')
        if packet_filter is not None:
            self.filter_module = resimUtils.getPacketFilter(packet_filter, lgr)
        self.no_iterators = no_iterators
        self.only_thread = only_thread
        self.no_track = no_track
        self.hit_break_on = False
        self.no_reset = no_reset

    def breakCleanup(self, dumb):
        if self.break_on_hap is not None:
            self.context_manager.genDeleteHap(self.break_on_hap)
        self.lgr.debug('breakCleanup do stopandgo')
        if self.callback is not None:
            ''' NOTE obscure way of telling injectToBB that we stopped due to a hit, vice a backstop'''
            self.top.setCommandCallbackParam(True)
            self.top.stopAndGo(self.callback)
        else:
            self.top.stopAndGo(self.top.skipAndMail)

    def breakOnHap(self, prec, third, forth, memory):
        self.lgr.debug('injectIO breakOnHap')
        if self.break_on_hap is None:
            return
        self.hit_break_on = True
        SIM_run_alone(self.breakCleanup, None)

    def go(self, no_go_receive=False):
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
            if self.save_json is not None:
                self.callback = self.saveJson
                self.lgr.debug('injectIO set callback to %s' % str(self.callback))
            elif self.mem_utils.isKernel(self.addr):
                self.lgr.debug('injectIO set callback to stopTrackIO, no better plan when modifying kernel buffer')
                self.callback = self.top.stopTrackIO
            elif self.stop_on_read:
                self.lgr.debug('injectIO set callback to stopTrackIO, based on ENV variable')
                self.callback = self.top.stopTrackIO
            else:
                self.lgr.debug('injectIO no callback set for when we are out of data.  Assume program knows best, e.g., will block on read')
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
        self.lgr.info('injectIO go, write data total size %d file %s' % (len(self.in_data), self.dfile))

        ''' Got to origin/recv location unless not yet debugging, or unless modifying kernel buffer '''
        if self.target is None and not no_go_receive and not self.mem_utils.isKernel(self.addr):
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
        if self.orig_buffer is not None and not self.mem_utils.isKernel(self.addr):
            ''' restore receive buffer to original condition in case injected data is smaller than original and poor code
                references data past the end of what is received. '''
            #self.mem_utils.writeString(self.cpu, self.addr, self.orig_buffer) 
            self.mem_utils.writeBytes(self.cpu, self.addr, self.orig_buffer) 
            self.lgr.debug('injectIO restored %d bytes to original buffer at 0x%x' % (len(self.orig_buffer), self.addr))

        if self.target is None and not self.trace_all and not self.instruct_trace and not self.no_track:
            ''' Set Debug before write to use RESim context on the callHap '''
            ''' We assume we are in user space in the target process and thus will not move.'''
            cpl = memUtils.getCPL(self.cpu)
            if cpl == 0:
                self.lgr.warning('The snapshot from prepInject left us in the kernel, try forward 1')
                SIM_run_command('pselect %s' % self.cpu.name)
                SIM_run_command('si')
                cpl = memUtils.getCPL(self.cpu)
                if cpl == 0:
                    self.lgr.error('Still in kernel, cannot work from here.  Check your prepInject snapshot. Exit.')
                    return 

            self.top.stopDebug()
            self.top.debugPidGroup(self.pid) 
            if self.only_thread:
                self.context_manager.watchOnlyThis()
            self.top.watchPageFaults()
            if self.no_rop:
                self.lgr.debug('injectIO stop ROP')
                self.top.watchROP(watching=False)
        elif self.instruct_trace:
            base = os.path.basename(self.dfile)
            print('base is %s' % base)
            trace_file = base+'.trace'
            self.top.instructTrace(trace_file, watch_threads=True)

        self.bookmarks = self.top.getBookmarksInstance()
        force_default_context = False
        if self.bookmarks is None:
            force_default_context = True
        if self.no_iterators:
            self.lgr.debug('injectIO dissable user iterators')
            self.dataWatch.setUserIterators(None)

        if self.trace_all: 
            use_data_watch = None
        else:
            use_data_watch = self.dataWatch
        self.write_data = writeData.WriteData(self.top, self.cpu, self.in_data, self.packet_count, 
                 self.mem_utils, self.backstop, self.snap_name, self.lgr, udp_header=self.udp_header, 
                 pad_to_size=self.pad_to_size, backstop_cycles=self.backstop_cycles, stop_on_read=self.stop_on_read, force_default_context=force_default_context,
                 write_callback=self.writeCallback, limit_one=self.limit_one, dataWatch=use_data_watch, filter=self.filter_module, 
                 shared_syscall=self.top.getSharedSyscall(), no_reset=self.no_reset)

        #bytes_wrote = self.writeData()
        bytes_wrote = self.write_data.write()
        if bytes_wrote is None:
            self.lgr.error('got None for bytes_wrote in injectIO')
            return
        eip = self.top.getEIP(self.cpu)
        if self.target is None:
            self.dataWatch.clearWatchMarks(record_old=True)
            self.dataWatch.clearWatches()
            if self.coverage:
                self.lgr.debug('injectIO enabled coverage')
                self.top.enableCoverage(backstop_cycles=self.backstop_cycles, fname=self.fname)
            self.lgr.debug('injectIO ip: 0x%x did write %d bytes to addr 0x%x cycle: 0x%x  Now clear watches' % (eip, bytes_wrote, self.addr, self.cpu.cycles))
            if self.max_len is not None and self.max_len < bytes_wrote:
                self.lgr.error('Max len is %d but %d bytes written.  May cause corruption' % (self.max_len, bytes_wrote))
            if not self.stay:
                if self.break_on is not None:
                    self.lgr.debug('injectIO set breakon at 0x%x' % self.break_on)
                    proc_break = self.context_manager.genBreakpoint(None, Sim_Break_Linear, Sim_Access_Execute, self.break_on, 1, 0)
                    self.break_on_hap = self.context_manager.genHapIndex("Core_Breakpoint_Memop", self.breakOnHap, None, proc_break, 'break_on')
                if not self.trace_all and not self.instruct_trace and not self.no_track:
                    self.lgr.debug('injectIO not traceall, about to set origin, eip: 0x%x  cycles: 0x%x' % (eip, self.cpu.cycles))
                    self.bookmarks.setOrigin(self.cpu)
                    cli.quiet_run_command('disable-reverse-execution')
                    cli.quiet_run_command('enable-reverse-execution')
                    eip = self.top.getEIP(self.cpu)
                    self.lgr.debug('injectIO back from cmds eip: 0x%x  cycles: 0x%x' % (eip, self.cpu.cycles))
                    #self.dataWatch.setRange(self.addr, bytes_wrote, 'injectIO', back_stop=False, recv_addr=self.addr, max_len = self.max_len)
                    ''' per trackIO, look at entire buffer for ref to old data '''
                    if not self.mem_utils.isKernel(self.addr):
                        self.dataWatch.setRange(self.addr, bytes_wrote, 'injectIO', back_stop=False, recv_addr=self.addr, max_len = self.max_len)
                        ''' special case'''
                        if self.max_len == 1:
                            self.addr += 1
                        if self.addr_addr is not None:
                            self.dataWatch.setRange(self.addr_addr, self.addr_size, 'injectIO-addr')
                    if not self.no_rop:
                        self.top.watchROP()
                else:
                    self.top.traceAll()
                use_backstop=True
                if self.stop_on_read:
                    use_backstop = False
                if self.trace_all or self.instruct_trace or self.no_track:
                    self.lgr.debug('injectIO trace_all or instruct_trace requested.  Context is %s' % self.cpu.current_context)
                    cli.quiet_run_command('c')
                elif not self.mem_utils.isKernel(self.addr):
                    print('retracking IO') 
                    if self.mark_logs:
                        self.lgr.debug('injectIO call traceAll for mark_logs')
                        self.top.traceAll()
                    self.lgr.debug('retracking IO callback: %s' % str(self.callback)) 
                    self.top.retrack(clear=self.clear_retrack, callback=self.callback, use_backstop=use_backstop)    
                    # TBD why?
                    #self.callback = None
                else:
                    ''' Injected into kernel buffer '''
                    self.top.stopTrackIO()
                    self.dataWatch.clearWatches()
                    self.dataWatch.setCallback(self.callback)
                    self.context_manager.watchTasks()
                    if self.mark_logs:
                        self.lgr.debug('injectIO call traceAll for mark_logs')
                        self.top.traceAll()
                    self.top.runToIO(self.fd, linger=True, break_simulation=False)
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
        ''' called at the end of the debug hap chain, meaning we are in the target process. 
            Intended for watching process other than the one reading the data. '''
        self.lgr.debug('injectIO injectCallback')
        self.context_manager.watchGroupExits()
        self.bookmarks = self.top.getBookmarksInstance()
        if self.save_json is not None:
            self.top.trackIO(self.targetFD, callback=self.saveJson, quiet=True)
        else:
            self.top.trackIO(self.targetFD, quiet=True)

    def delCallHap(self, dumb=None):
        if self.write_data is not None:
            self.write_data.delCallHap(None)

    def restoreCallHap(self):
        if self.write_data is not None:
            self.write_data.restoreCallHap()
    

    def resetOrigin(self, dumb):
        if self.bookmarks is not None:
            self.bookmarks.setOrigin(self.cpu)
        SIM_run_command('disable-reverse-execution') 
        SIM_run_command('enable-reverse-execution') 

    def resetReverseAlone(self, count):
        ''' called when the writeData callHap is hit.  packet number already incremented, so reduce by 1 '''
        if self.no_reset:
            self.lgr.debug('resetReverseAlone no reset, so stop.')
        else:
            if count != 0:
                packet_num = self.write_data.getCurrentPacket() - 1
                self.saveJson(packet=packet_num)
                self.lgr.debug('injectIO, handling subsequent packet number %d, must reset watch marks and bookmarks, and save trackio json ' % packet_num)
                self.resetOrigin(None)
                self.dataWatch.clearWatchMarks(record_old=True)
            if count != 0:
                self.dataWatch.setRange(self.addr, count, 'injectIO', back_stop=False, recv_addr=self.addr, max_len = self.max_len)
                ''' special case'''
                if self.max_len == 1:
                    self.addr += 1
                if self.addr_addr is not None:
                    self.dataWatch.setRange(self.addr_addr, self.addr_size, 'injectIO-addr')
    
            if self.stop_hap is not None:
                self.lgr.debug('injectIO resetReverseAlone delete stop hap')
                RES_hap_delete_callback_id("Core_Simulation_Stopped", self.stop_hap)
                self.stop_hap = None
            if count > 0:
                SIM_run_command('c')
            else:
                cmd_callback = self.top.getCommandCallback()
                if self.callback is not None:
                    if cmd_callback is None:
                        self.lgr.debug('resetReverseAlone no more data, remove writeData callback and invoke the given callback (%s)' % str(self.callback))
                        self.write_data.delCallHap(None)
                        self.callback()
                    else:
                        self.lgr.debug('resetReverseAlone no more data, remove writeData callback found command callback, override given callback (%s)' % str(cmd_callback))
                        cmd_callback()
                else:
                    self.lgr.debug('resetReverseAlone no callback, go for it and continue.')
                    SIM_run_command('c')
        

    def stopHap(self, count, one, exception, error_string):
        if self.stop_hap is None:
            return
        self.lgr.debug('injectIO stopHap from writeCallback count %s' % str(count))
        if count is not None:
            SIM_run_alone(self.resetReverseAlone, count)
        else:
            self.lgr.debug('injectIO stopHap, count None, just stop?')
        
    def writeCallback(self, count):
        self.lgr.debug('injectIO writeCallback')
        self.stop_hap = RES_hap_add_callback("Core_Simulation_Stopped", 
        	     self.stopHap, count)
        SIM_break_simulation('writeCallback')

    def loadPickle(self, name):
        afl_file = os.path.join('./', name, self.cell_name, 'afl.pickle')
        if os.path.isfile(afl_file):
            self.lgr.debug('afl pickle from %s' % afl_file)
            so_pickle = pickle.load( open(afl_file, 'rb') ) 
            #print('start %s' % str(so_pickle['text_start']))
            if 'addr' in so_pickle:
                self.addr = so_pickle['addr']
            else:
                self.lgr.debug('injectIO no addr in pickle?')

            if 'orig_buffer' in so_pickle:
                self.orig_buffer = so_pickle['orig_buffer']
                if self.orig_buffer is not None:
                    self.lgr.debug('injectiO load orig_buffer from pickle %d bytes' % len(self.orig_buffer))
            if 'size' in so_pickle and so_pickle['size'] is not None:
                self.max_len = so_pickle['size']
                self.lgr.debug('injectiO load max_len read %d' % self.max_len)
            if 'addr_addr' in so_pickle:
                self.addr_addr = so_pickle['addr_addr']
                self.addr_size = so_pickle['addr_size']
            if 'fd' in so_pickle:
                self.fd = so_pickle['fd']
        else:
            self.lgr.error('injectIO expected to find a pickle at %s, cannot continue' % afl_file) 

    def saveJson(self, save_file=None, packet=None):
        if packet is None:
            packet = self.write_data.getCurrentPacket()
        self.lgr.debug('injectIO saveJson packet %d' % packet)
        if save_file is None and self.save_json is not None:
            self.dataWatch.saveJson(self.save_json, packet=packet)
        elif save_file is not None:
            self.dataWatch.saveJson(save_file, packet=packet)
        self.top.stopTrackIO()

    def setDfile(self, dfile):
        self.dfile = dfile
        self.clear_retrack = True

    def setExitCallback(self, exit_callback):
        self.context_manager.setExitCallback(exit_callback)

    def setSaveJson(self, save_file):
        self.save_json = save_file

    def recordHang(self, cycles):
        self.lgr.debug('Hang')
        print('Hang')
        if self.coverage:
            self.top.saveCoverage()
        SIM_break_simulation('hang')

           
    def getFilter(self):
        return self.filter_module 
