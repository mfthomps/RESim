from simics import *
import pageUtils
import taskUtils
import stopFunction
import hapCleaner
import decode
import decodeArm
import elfText
import memUtils
import watchMarks
import backStop
import net
import os
import sys
mem_funs = ['memcpy','memmove','memcmp','strcpy','strcmp','strncmp', 'strcasecmp', 'strncpy', 'strtoul', 'mempcpy', 
            'j_memcpy', 'strchr', 'strrchr', 'strdup', 'memset', 'sscanf', 'strlen', 'LOWEST', 'glob', 'fwrite', 'IO_do_write', 'xmlStrcmp',
            'xmlGetProp', 'inet_addr', 'FreeXMLDoc', 'GetToken', 'xml_element_free', 'xml_element_name', 'xml_element_children_size', 'xmlParseFile', 'xml_parse',
            'printf', 'fprintf', 'sprintf', 'vsnprintf']
#no_stop_funs = ['xml_element_free', 'xml_element_name']
no_stop_funs = ['xml_element_free']
class DataWatch():
    ''' Watch a range of memory and stop when it is read.  Intended for use in tracking
        reads to buffers into which data has been read, e.g., via RECV. '''
    def __init__(self, top, cpu, cell_name, page_size, context_manager, mem_utils, task_utils, rev_to_call, param, run_from_snap, back_stop, lgr):
        ''' data watch structures reflecting what we are watching '''
        self.start = []
        self.length = []
        self.hack_reuse = []
        self.cycle = []
        self.mark = []
        self.read_hap = []
        self.top = top
        self.cpu = cpu
        self.cell_name = cell_name
        self.context_manager = context_manager
        self.mem_utils = mem_utils
        self.task_utils = task_utils
        self.lgr = lgr
        self.page_size = page_size
        self.show_cmp = False
        self.break_simulation = True
        self.rev_to_call = rev_to_call
        self.param = param
        self.return_break = None
        self.return_hap = None
        self.prev_cycle = None
        ''' for guessing if stack buffer is being re-used '''
        self.prev_read_cycle = 0
        self.ida_funs = None
        self.relocatables = None
        self.user_iterators = None
        self.other_starts = [] # buffer starts that were skipped because they were subranges.
        self.other_lengths = [] 
        self.retrack = False
        self.back_stop = back_stop
        self.watchMarks = watchMarks.WatchMarks(mem_utils, cpu, cell_name, run_from_snap, lgr)
        self.call_break = None
        self.call_hap = None
        self.call_stop_hap = None
        self.mem_something = None
        ''' used to guess if we encountered a ghost frame '''
        self.cycles_was = 0
        self.undo_hap = None
        back_stop_string = os.getenv('BACK_STOP_CYCLES')
        if back_stop_string is None:
            self.back_stop_cycles = 5000000
        else:
            self.back_stop_cycles = int(back_stop_string)
        ''' Do not set backstop until first read, otherwise accept followed by writes will trigger it. '''
        self.use_back_stop = False
        
        lgr.debug('DataWatch init with back_stop_cycles %d' % self.back_stop_cycles)
        if cpu.architecture == 'arm':
            self.decode = decodeArm
        else:
            self.decode = decode
        self.malloc_dict = {}
        self.pending_call = False
        self.ghost_stop_hap = None
        ''' don't set backstop on reads of these addresses, e.g., for ioctl '''
        self.no_backstop = []
        ''' support deletion of stack buffers after return from function '''
        self.stack_buffers = {}
        self.stack_buf_hap = {}
        ''' optimize parameter gathering without having to reverse '''
        self.mem_fun_entries = {}
        ''' limit number of marks gathered '''
        self.max_marks = None
        ''' used by writeData when simulating responses from ioctl '''
        self.total_read = 0

    def setRange(self, start, length, msg=None, max_len=None, back_stop=True, recv_addr=None, no_backstop=False, watch_mark=None, fd=None):
        ''' set a data watch range.  fd only set for readish syscalls as a way to track bytes read when simulating internal kernel buffer '''
        ''' TBD try forcing watch to maxlen '''
        if max_len is None:
            my_len = length
        else:
            my_len = max_len
        #self.lgr.debug('DataWatch set range start 0x%x watch length 0x%x actual count %d back_stop: %r' % (start, my_len, length, back_stop))
        if fd is not None:
            self.total_read = self.total_read + length
        if not self.use_back_stop and back_stop:
            self.use_back_stop = True
            self.lgr.debug('DataWatch, backstop set, start data session')

        end = start+my_len
        overlap = False
        for index in range(len(self.start)):
            if self.start[index] != 0:
                this_end = self.start[index] + self.length[index]
                if self.start[index] <= start and this_end >= end:
                    overlap = True
                    #self.lgr.debug('DataWatch setRange found overlap, skip it')
                    if start not in self.other_starts:
                        self.other_starts.append(start)
                        self.other_lengths.append(my_len)
                    break
                elif self.start[index] >= start and this_end <= end:
                    #self.lgr.debug('DataWatch setRange found subrange, replace it')
                    self.start[index] = start
                    self.length[index] = my_len
                    overlap = True
                    break
                elif start == (this_end+1):
                    self.length[index] = self.length[index]+my_len
                    #self.lgr.debug('DataWatch extending subrange')
                    overlap = True
                    break
        if not overlap:
            self.start.append(start)
            self.length.append(my_len)
            self.hack_reuse.append(0)
            self.cycle.append(self.cpu.cycles)
            self.mark.append(watch_mark)
            if watch_mark is not None and watch_mark.mark.sp is not None:
                ret_to = self.getReturnAddr()
                if ret_to is not None:
                    self.lgr.debug('DataWatch setRange stack buffer, set a break at 0x%x to delete this range on return' % ret_to)
                    if ret_to not in self.stack_buffers:
                        self.stack_buffers[ret_to] = []
                        proc_break = self.context_manager.genBreakpoint(None, Sim_Break_Linear, Sim_Access_Execute, ret_to, 1, 0)
                        self.stack_buf_hap[ret_to] = self.context_manager.genHapIndex("Core_Breakpoint_Memop", self.stackBufHap, None, proc_break, 'stack_buf_hap')
                    index = len(self.start)-1
                    self.stack_buffers[ret_to].append(index)
                else:
                    self.lgr.debug('DataWatch setRange stack buffer, but return address was NONE, so buffer reuse will cause hits')

            #self.lgr.debug('DataWatch adding start 0x%x cycle 0x%x' % (start, self.cpu.cycles))
        if msg is not None:
            if sys.version_info[0] >= 3:
                fixed = msg
            else:
                fixed = unicode(msg, errors='replace')
            # TBD why max_len and not count???
            if recv_addr is None:
                recv_addr = start
            self.watchMarks.markCall(fixed, max_len, recv_addr, length, fd=fd)
            if self.prev_cycle is None:
                ''' first data read, start data session if doing coverage '''
                self.top.startDataSessions()
                self.prev_cycle = self.cpu.cycles
        if no_backstop:
            self.no_backstop.append(start)

    def stackBufHap(self, dumb, third, forth, memory):
        eip = memory.logical_address
        if eip in self.stack_buf_hap:
            self.context_manager.genDeleteHap(self.stack_buf_hap[eip])
            for range_index in self.stack_buffers[eip]:
                if range_index in self.read_hap:
                    #self.lgr.debug('dataWatch stackBufHap remove watch for index %d starting 0x%x' % (range_index, self.start[range_index]))
                    self.context_manager.genDeleteHap(self.read_hap[range_index], immediate=False)
                    self.read_hap[range_index] = None
                    self.start[range_index] = 0
            del self.stack_buf_hap[eip] 

    def getReturnAddr(self):
        retval = None
        if self.cpu.architecture != 'arm': 
            bp = self.mem_utils.getRegValue(self.cpu, 'ebp')
            if bp != 0:
                ret_to_addr = bp + self.mem_utils.WORD_SIZE
                retval = self.mem_utils.readPtr(self.cpu, ret_to_addr)
        return retval

    def close(self, fd):
        ''' called when FD is closed and we might be doing a trackIO '''
        eip = self.top.getEIP(self.cpu)
        msg = 'closed FD: %d' % fd
        self.watchMarks.markCall(msg, None, None, fd=fd)
       
    def watchFunEntries(self): 
        #self.lgr.debug('watchFunEntries')
        for fun in self.mem_fun_entries:
            if self.mem_fun_entries[fun].hap is None:
                proc_break = self.context_manager.genBreakpoint(None, Sim_Break_Linear, Sim_Access_Execute, self.mem_fun_entries[fun].eip, 1, 0)
                hap = self.context_manager.genHapIndex("Core_Breakpoint_Memop", self.memSomethingEntry, fun, proc_break, 'mem_fun_entry') 
                self.mem_fun_entries[fun].hap = hap

    def watch(self, show_cmp=False, break_simulation=None, i_am_alone=False, no_backstop=False):
        #self.lgr.debug('DataWatch watch show_cmp: %r cpu: %s length of watched buffers is %d length of read_hap %d' % (show_cmp, self.cpu.name, 
        #   len(self.start), len(self.read_hap)))
        self.show_cmp = show_cmp         
        if break_simulation is not None:
            self.break_simulation = break_simulation         
        #self.lgr.debug('watch break_sim %s  use_back %s  no_back %s' % (str(break_simulation), str(self.use_back_stop), str(no_backstop)))
        if self.back_stop is not None and not self.break_simulation and self.use_back_stop and not no_backstop:
            self.back_stop.setFutureCycle(self.back_stop_cycles)
        self.watchFunEntries()
        if len(self.start) > 0:
            self.setBreakRange(i_am_alone)
            return True
        return False

    def showCmp(self, addr): 
        eip = self.top.getEIP(self.cpu)
        instruct = SIM_disassemble_address(self.cpu, eip, 1, 0)
        self.lgr.debug('showCmp eip 0x%x %s' % (eip, instruct[1]))
        mval = self.mem_utils.readWord32(self.cpu, addr)
        if instruct[1].startswith('cmp'):
            op2, op1 = self.decode.getOperands(instruct[1])
            val = None
            if self.decode.isReg(op2):
                val = self.mem_utils.getRegValue(self.cpu, op2)
            elif self.decode.isReg(op1):
                val = self.mem_utils.getRegValue(self.cpu, op1)
            if val is not None:
                print('%s  reg: 0x%x  addr:0x%x mval: 0x%08x' % (instruct[1], val, addr, mval))
          
    def getCmp(self):
        retval = '' 
        eip = self.top.getEIP(self.cpu)
        for i in range(10):
            instruct = SIM_disassemble_address(self.cpu, eip, 1, 0)
            if instruct[1].startswith('cmp'):
                retval = instruct[1]
                break
            elif instruct[1].startswith('pop') and 'pc' in instruct[1]:
                break
            else:
                eip = eip + instruct[0]
        return retval
           
    def deleteReturnHap(self, dumb): 
        if self.return_hap is not None:
            self.context_manager.genDeleteHap(self.return_hap)
            self.return_hap = None
               
    def stopWatch(self, break_simulation=None, immediate=False, leave_fun_entries=False): 
        #self.lgr.debug('dataWatch stopWatch')
        for index in range(len(self.start)):
            if self.start[index] == 0:
                continue
            if index < len(self.read_hap):
                if self.read_hap[index] is not None:
                    #self.lgr.debug('dataWatch stopWatch delete hap %d' % self.read_hap[index])
                    self.context_manager.genDeleteHap(self.read_hap[index], immediate=immediate)
            else:
                self.lgr.debug('dataWatch stopWatch index %d not in read_hap len is %d ' % (index, len(self.read_hap)))
        #self.lgr.debug('DataWatch stopWatch removed read haps')
        del self.read_hap[:]
        if break_simulation is not None: 
            self.break_simulation = break_simulation
            self.lgr.debug('DataWatch stopWatch break_simulation %r' % break_simulation)
        self.deleteReturnHap(None)

        if not leave_fun_entries:
            for fun in self.mem_fun_entries:
                self.context_manager.genDeleteHap(self.mem_fun_entries[fun].hap, immediate=immediate)
                self.mem_fun_entries[fun].hap = None
      
        if self.back_stop is not None:
            self.back_stop.clearCycle()
        self.pending_call = False
    
    def kernelReturnHap(self, kernel_return_info, third, forth, memory):
        eax = self.mem_utils.getRegValue(self.cpu, 'syscall_ret')
        self.lgr.debug('kernelReturnHap, retval 0x%x  addr: 0x%x context: %s' % (eax, 
            kernel_return_info.addr, str(self.cpu.current_context)))
        #self.top.showHaps()
        dum_cpu, cur_addr, comm, pid = self.task_utils.currentProcessInfo(self.cpu)
        frame, cycles = self.rev_to_call.getRecentCycleFrame(pid)
        if kernel_return_info.op_type == Sim_Trans_Load:
            self.watchMarks.kernel(kernel_return_info.addr, eax, frame)
        else:
            self.watchMarks.kernelMod(kernel_return_info.addr, eax, frame)
 
        if self.back_stop is not None and not self.break_simulation and self.use_back_stop:
            self.back_stop.setFutureCycle(self.back_stop_cycles)
        SIM_run_alone(self.deleteReturnHap, None)
        self.watch()

    def kernelReturn(self, kernel_return_info):
        #cell = self.top.getCell()
        #proc_break = self.context_manager.genBreakpoint(cell, Sim_Break_Linear, Sim_Access_Execute, self.param.arm_ret, 1, 0)
        #self.return_hap = self.context_manager.genHapIndex("Core_Breakpoint_Memop", self.kernelReturnHap, addr, proc_break, 'memcpy_return_hap')
        self.lgr.debug('kernelReturn for addr 0x%x optype %s' % (kernel_return_info.addr, str(kernel_return_info.op_type))) 
        if not self.break_simulation:
            self.stopWatch()
        if self.cpu.architecture == 'arm':
            cell = self.top.getCell()
            proc_break = self.context_manager.genBreakpoint(None, Sim_Break_Linear, Sim_Access_Execute, self.param.arm_ret, 1, 0)
            self.return_hap = self.context_manager.genHapIndex("Core_Breakpoint_Memop", self.kernelReturnHap, 
                 kernel_return_info, proc_break, 'memcpy_return_hap')
        else:
            #self.lgr.debug('Only ARM kernel return handled for now') 
            #self.watch()
            cell = self.top.getCell()
            proc_break = self.context_manager.genBreakpoint(None, Sim_Break_Linear, Sim_Access_Execute, self.param.sysexit, 1, 0)
            self.return_hap = self.context_manager.genHapIndex("Core_Breakpoint_Memop", self.kernelReturnHap, 
                 kernel_return_info, proc_break, 'memcpy_return_hap')
       
       
    class MemSomething():
        def __init__(self, fun, addr, ret_ip, src, dest, count, called_from_ip, op_type, length, start, ret_addr_addr=None, run=False, trans_size=None):
            self.fun = fun
            self.addr = addr
            self.ret_ip = ret_ip
            self.src = src
            self.dest = dest
            self.the_string = None
            self.count = count
            self.called_from_ip = called_from_ip
            self.trans_size = trans_size
            self.ret_addr_addr = ret_addr_addr
            ''' used for finishReadHap '''
            self.op_type = op_type
            self.length = length
            self.start = start
            self.dest_list = []
            ''' used for file tracking, e.g., if xmlParse '''
            self.run = run
     
    def startUndoAlone(self, dumb):
        self.undo_hap = SIM_hap_add_callback("Core_Simulation_Stopped", self.undoHap, self.mem_something)
        self.watchMarks.undoMark()
        SIM_break_simulation('undo it')
 
    def returnHap(self, dumb, third, forth, memory):
        ''' should be at return from a memsomething.  see  getMemParams for gathering of parameters'''
        if self.return_hap is None:
            return
        SIM_run_alone(self.deleteReturnHap, None)
        eip = self.top.getEIP(self.cpu)
        if self.cpu.cycles < self.cycles_was:
            if self.mem_something.addr is None:
                '''  Not due to a readHap, just restore breaks and continue '''
                pass
            else:
                self.lgr.debug('dataWatch returnHap suspect a ghost frame, returned from assumed memsomething to ip: 0x%x, but cycles less than when we read the data' % eip)
                SIM_run_alone(self.startUndoAlone, None)
                return
        self.lgr.debug('dataWatch returnHap should be at return from memsomething, eip 0x%x cycles: 0x%x' % (eip, self.cpu.cycles))
        self.context_manager.genDeleteHap(self.return_hap)
        self.return_hap = None
        self.pending_call = False
        self.top.restoreDebugBreaks(was_watching=True)
        if self.mem_something.fun == 'memcpy' or self.mem_something.fun == 'mempcpy' or \
           self.mem_something.fun == 'j_memcpy' or self.mem_something.fun == 'memmove':
            self.lgr.debug('dataWatch returnHap, return from %s src: 0x%x dest: 0x%x count %d ' % (self.mem_something.fun, self.mem_something.src, 
                   self.mem_something.dest, self.mem_something.count))
            
            if self.mem_something.op_type == Sim_Trans_Load:
                buf_start = self.findRange(self.mem_something.src)
                if buf_start is None:
                    self.lgr.error('dataWatch buf_start for 0x%x is none in memcpyish?' % (self.mem_something.src))
                    buf_start = 0
                    #SIM_break_simulation('mempcpy')
                    #return
            else:
                self.lgr.debug('returnHap copy not a Load, first see if src is a buf')
                buf_start = self.findRange(self.mem_something.src)
                if buf_start is None:
                    buf_start = self.findRange(self.mem_something.dest)

            mark = self.watchMarks.copy(self.mem_something.src, self.mem_something.dest, self.mem_something.count, buf_start, self.mem_something.op_type)
            if self.mem_something.op_type == Sim_Trans_Load:
                self.lgr.debug('returnHap set range for copy')
                self.setRange(self.mem_something.dest, self.mem_something.count, None, watch_mark=mark) 
        elif self.mem_something.fun == 'memcmp':
            buf_start = self.findRange(self.mem_something.dest)
            self.watchMarks.compare(self.mem_something.fun, self.mem_something.dest, self.mem_something.src, self.mem_something.count, buf_start)
            self.lgr.debug('dataWatch returnHap, return from %s compare: 0x%x  to: 0x%x count %d ' % (self.mem_something.fun, self.mem_something.src, 
                   self.mem_something.dest, self.mem_something.count))
        elif self.mem_something.fun in ['strcmp', 'strncmp', 'strcasecmp', 'xmlStrcmp']: 
            buf_start = self.findRange(self.mem_something.dest)
            self.watchMarks.compare(self.mem_something.fun, self.mem_something.dest, self.mem_something.src, self.mem_something.count, buf_start)
            self.lgr.debug('dataWatch returnHap, return from %s  0x%x  to: 0x%x count %d ' % (self.mem_something.fun, 
                   self.mem_something.src, self.mem_something.dest, self.mem_something.count))
        elif self.mem_something.fun in ['strchr', 'strrchr']:
            buf_start = self.findRange(self.mem_something.src)
            if self.cpu.architecture != 'arm':
                self.lgr.debug('datawatch strchr confusion, mem_something.the_chr is 0x%x' % self.mem_something.the_chr)
                #the_chr = self.mem_utils.readByte(self.cpu, self.mem_something.the_chr)
                the_chr = self.mem_something.the_chr
            else:
                the_chr = self.mem_something.the_chr
            self.watchMarks.strchr(self.mem_something.src, the_chr, self.mem_something.count)
            self.lgr.debug('dataWatch returnHap, return from %s strchr 0x%x count %d ' % (self.mem_something.fun, 
                   self.mem_something.the_chr, self.mem_something.count))
        elif self.mem_something.fun in ['strtoul', 'strtoull']:
            self.watchMarks.strtoul(self.mem_something.src)
        elif self.mem_something.fun == 'strcpy' or self.mem_something.fun == 'strncpy':
            self.lgr.debug('dataWatch returnHap, strcpy return from %s src: 0x%x dest: 0x%x count %d ' % (self.mem_something.fun, self.mem_something.src, 
                   self.mem_something.dest, self.mem_something.count))
            buf_start = self.findRange(self.mem_something.src)
            if buf_start is None:
                self.lgr.error('dataWatch buf_start for 0x%x is none in strcpy?' % (self.mem_something.src))
            mark = self.watchMarks.copy(self.mem_something.src, self.mem_something.dest, self.mem_something.count, buf_start, self.mem_something.op_type, 
                       strcpy=True)
            self.setRange(self.mem_something.dest, self.mem_something.count, None, watch_mark = mark) 
        elif self.mem_something.fun == 'memset':
            self.setRange(0, 0, None) 
            self.lgr.debug('dataWatch returnHap, return from memset dest: 0x%x count %d ' % (self.mem_something.dest, self.mem_something.count))
            buf_start = self.findRange(self.mem_something.dest)
            self.watchMarks.memset(self.mem_something.dest, self.mem_something.count, buf_start)
        elif self.mem_something.fun == 'strdup':
            if self.cpu.architecture == 'arm':
                self.mem_something.dest = self.mem_utils.getRegValue(self.cpu, 'r0')
            else: 
                self.mem_something.dest = self.mem_utils.getRegValue(self.cpu, 'eax')
            self.lgr.debug('dataWatch returnHap, strdup return from %s src: 0x%x dest: 0x%x count %d ' % (self.mem_something.fun, self.mem_something.src, 
                   self.mem_something.dest, self.mem_something.count))
            if self.mem_something.op_type == Sim_Trans_Load:
                buf_start = self.findRange(self.mem_something.src)
                if buf_start is None:
                    self.lgr.error('dataWatch buf_start for 0x%x is none in strdup?' % (self.mem_something.src))
            else:
                buf_start = self.findRange(self.mem_something.dest)
            mark=self.watchMarks.copy(self.mem_something.src, self.mem_something.dest, self.mem_something.count, buf_start, self.mem_something.op_type)
            if self.mem_something.op_type == Sim_Trans_Load:
                self.setRange(self.mem_something.dest, self.mem_something.count, None, watch_mark=mark) 
        elif self.mem_something.fun == 'sscanf':
            eax = self.mem_utils.getRegValue(self.cpu, 'syscall_ret')
            param_count = self.mem_utils.getSigned(eax)
            self.lgr.debug('dataWatch returnHap, sscanf return from sscanf src 0x%x param_count %d' % (self.mem_something.src, param_count))
            buf_start = self.findRange(self.mem_something.src)
            if param_count > 0:
                for i in range(param_count):
                    mark = self.watchMarks.sscanf(self.mem_something.src, self.mem_something.dest_list[i], self.mem_something.count, buf_start)
                    self.setRange(self.mem_something.dest_list[i], self.mem_something.count, None, watch_mark=mark) 
            else:
                self.lgr.debug('dataWatch returnHap sscanf returned error')
                self.watchMarks.sscanf(self.mem_something.src, None, None, buf_start)
        elif self.mem_something.fun == 'strlen':
            self.lgr.debug('dataWatch returnHap, return from %s src: 0x%x count %d ' % (self.mem_something.fun, self.mem_something.src, 
                   self.mem_something.count))
            self.watchMarks.strlen(self.mem_something.src, self.mem_something.count)
        elif self.mem_something.fun == 'vsnprintf' or self.mem_something.fun == 'sprintf':
            if self.mem_something.dest is None:
                self.lgr.debug('dataWatch vsnprintf dest is None')
            buf_start = self.findRange(self.mem_something.src)
            self.mem_something.src = self.mem_something.addr
            self.mem_something.count = self.getStrLen(self.mem_something.dest)        
            mark = self.watchMarks.sprintf(self.mem_something.fun, self.mem_something.addr, self.mem_something.dest, self.mem_something.count, buf_start)
            self.lgr.debug('dataWatch returnHap, return from %s src: 0x%x dst: 0x%x count %d ' % (self.mem_something.fun, self.mem_something.src, 
                   self.mem_something.dest, self.mem_something.count))
            self.setRange(self.mem_something.dest, self.mem_something.count, None, watch_mark=mark) 
        elif self.mem_something.fun == 'fprintf' or self.mem_something.fun == 'printf':
            self.lgr.debug('dataWatch returnHap, return from %s src: 0x%x ' % (self.mem_something.fun, self.mem_something.src))
            self.watchMarks.fprintf(self.mem_something.fun, self.mem_something.src)
        elif self.mem_something.fun == 'fwrite' or self.mem_something.fun == 'IO_do_write':
            self.lgr.debug('dataWatch returnHap, return from %s src: 0x%x ' % (self.mem_something.fun, self.mem_something.src))
            self.watchMarks.fwrite(self.mem_something.fun, self.mem_something.src, self.mem_something.count)
        elif self.mem_something.fun == 'glob':
            self.lgr.debug('dataWatch returnHap, return from %s src: 0x%x ' % (self.mem_something.fun, self.mem_something.src))
            self.mem_something.count = self.getStrLen(self.mem_something.src)
            self.watchMarks.glob(self.mem_something.fun, self.mem_something.src, self.mem_something.count)

        # Begin XML
        elif self.mem_something.fun == 'xmlGetProp':
            self.lgr.debug('dataWatch returnHap, return from %s string: %s count %d ' % (self.mem_something.fun, self.mem_something.the_string, 
                   self.mem_something.count))
            if self.cpu.architecture == 'arm':
                self.mem_something.dest = self.mem_utils.getRegValue(self.cpu, 'r0')
            else:
                self.mem_something.dest = self.mem_utils.readPtr(self.cpu, sp)
            
            self.watchMarks.xmlGetProp(self.mem_something.src, self.mem_something.count, self.mem_something.the_string, self.mem_something.dest)
        elif self.mem_something.fun == 'inet_addr':
            self.lgr.debug('dataWatch returnHap, return from %s IP: %s count %d ' % (self.mem_something.fun, self.mem_something.the_string, 
                   self.mem_something.count))
            self.watchMarks.inet_addr(self.mem_something.src, self.mem_something.count, self.mem_something.the_string)
        elif self.mem_something.fun == 'FreeXMLDoc':
            self.lgr.debug('dataWatch returnHap, return from %s' % (self.mem_something.fun))
            self.watchMarks.freeXMLDoc()
        elif self.mem_something.fun == 'xmlParseFile' or self.mem_something.fun == 'xml_parse':
            self.lgr.debug('dataWatch returnHap, return from %s' % (self.mem_something.fun))
            if self.cpu.architecture == 'arm':
                xml_doc = self.mem_utils.getRegValue(self.cpu, 'r0')
            else:
                sp = self.mem_utils.getRegValue(self.cpu, 'sp')
                xml_doc = self.mem_utils.readPtr(self.cpu, sp)

            self.top.stopTraceMalloc()
            self.me_trace_malloc = False
            malloc_ranges = self.mergeMalloc()
            tot_size = 0
            self.lgr.debug('xmlParse Malloc:')
            for addr in sorted(malloc_ranges):
                self.lgr.debug('0x%x   0x%x' % (addr, malloc_ranges[addr]))
                tot_size = tot_size + malloc_ranges[addr]
                self.setRange(addr, malloc_ranges[addr], None) 
            self.watchMarks.xmlParseFile(xml_doc, tot_size)
        elif self.mem_something.fun == 'GetToken':
            if self.cpu.architecture == 'arm':
                self.lgr.error('dataWatch GetToken not yet for arm')
            else:
                self.mem_something.dest = self.mem_utils.getRegValue(self.cpu, 'eax')
                self.mem_something.the_string = self.mem_utils.readString(self.cpu, self.mem_something.dest, 40)
            self.lgr.debug('dataWatch returnHap, return from %s token: %s' % (self.mem_something.fun, self.mem_something.the_string))
            self.watchMarks.getToken(self.mem_something.src, self.mem_something.dest, self.mem_something.the_string)
        elif self.mem_something.fun == 'xml_element_name':
            self.lgr.debug('dataWatch returnHap, return from %s' % (self.mem_something.fun))
            if self.cpu.architecture == 'arm':
                self.mem_something.dest = self.mem_utils.getRegValue(self.cpu, 'r0')
            else: 
                self.mem_something.dest = self.mem_utils.getRegValue(self.cpu, 'eax')
            self.watchMarks.strPtr(self.mem_something.dest, self.mem_something.fun)
        elif self.mem_something.fun == 'xml_element_children_size':
            self.lgr.debug('dataWatch returnHap, return from %s' % (self.mem_something.fun))
            if self.cpu.architecture == 'arm':
                self.mem_something.count = self.mem_utils.getRegValue(self.cpu, 'r0')
            else: 
                self.mem_something.count = self.mem_utils.getRegValue(self.cpu, 'eax')
            self.watchMarks.returnInt(self.mem_something.count, self.mem_something.fun)
        elif self.mem_something.fun not in mem_funs:
            ''' assume iterator '''
            self.lgr.debug('dataWatch returnHap, return from iterator %s src: 0x%x ' % (self.mem_something.fun, self.mem_something.src))
            buf_start = self.findRange(self.mem_something.src)
            self.watchMarks.iterator(self.mem_something.fun, self.mem_something.src, buf_start)
        elif self.mem_something.fun not in no_stop_funs and mem_something.addr is not None:
            self.lgr.error('dataWatch returnHap no handler for %s' % self.mem_something.fun)
        #SIM_break_simulation('return hap')
        #return
        self.watch()

    class MemCallRec():
        def __init__(self, hap, ret_addr_offset, eip):
            self.hap = hap
            self.ret_addr_offset = ret_addr_offset
            self.eip = eip

    def memSomethingEntry(self, fun, third, forth, memory):
        self.lgr.debug('memSomethingEntry, fun %s' % fun)
        if fun not in self.mem_fun_entries or self.mem_fun_entries[fun].hap is None:
            self.lgr.debug('memSomethingEntry, fun %s not in mem_fun_entries haps' % fun)
            return
        sp = self.mem_utils.getRegValue(self.cpu, 'sp')
        if not self.cpu.architecture == 'arm':
            ret_addr = self.mem_utils.readPtr(self.cpu, sp)
            self.lgr.debug('memSomethingEntry, ret_addr 0x%x' % (ret_addr))
        elif self.mem_fun_entries[fun].ret_addr_offset is not None:
                addr_of_ret_addr = sp - self.mem_fun_entries[fun].ret_addr_offset
                ret_addr = self.mem_utils.readPtr(self.cpu, addr_of_ret_addr)
                self.lgr.debug('memSomethingEntry, addr_of_ret_addr 0x%x, ret_addr 0x%x' % (addr_of_ret_addr, ret_addr))
        else: 
            ret_addr = self.mem_utils.getRegValue(self.cpu, 'lr')
            self.lgr.debug('memSomthingEntry ARM ret_addr_offset is None, use lr value of 0x%x' % ret_addr)
        self.mem_something = self.MemSomething(fun, None, ret_addr, None, None, None, None, None, None, None)
        #                                     (fun, addr, ret_ip, src, dest, count, called_from_ip, op_type, length, start, ret_addr_addr=None, run=False, trans_size=None): 
        SIM_run_alone(self.getMemParams, False)


    def getCallParams(self, sp):
        retval1 = None
        retval2 = None
        retval3 = None
        if self.cpu.architecture == 'arm':
            retval1 = self.mem_utils.getRegValue(self.cpu, 'r0')
            retval2 = self.mem_utils.getRegValue(self.cpu, 'r1')
            retval3 = self.mem_utils.getRegValue(self.cpu, 'r2')
        else:
            retval1 = self.mem_utils.readPtr(self.cpu, sp)
            retval2 = self.mem_utils.readPtr(self.cpu, sp+self.mem_utils.WORD_SIZE)
            retval3 = self.mem_utils.readWord32(self.cpu, sp+2*self.mem_utils.WORD_SIZE)
        return retval1, retval2, retval3

    def getMemParams(self, data_hit):
            self.watchMarks.registerCallCycle();
            ''' assuming we are a the call to a memsomething, get its parameters '''
            sp = self.mem_utils.getRegValue(self.cpu, 'sp')
            if data_hit:
                next_instruct = self.cpu.cycles+1
                if not self.skipToTest(next_instruct):
                    self.lgr.error('getMemParams, tried going forward, failed')
                    return
                if self.mem_something.fun not in self.mem_fun_entries:
                    eip = self.top.getEIP(self.cpu)
                    ret_addr_offset = None
                    if self.mem_something.ret_addr_addr is not None:
                        ret = self.mem_utils.readPtr(self.cpu, self.mem_something.ret_addr_addr)
                        ret_addr_offset = sp - self.mem_something.ret_addr_addr 
                        self.lgr.debug('getmemParam did step forward would record fun %s at 0x%x ret_addr ofset is %d ret_addr_addr 0x%x ret 0x%x' % (self.mem_something.fun, eip, ret_addr_offset,
                           self.mem_something.ret_addr_addr, ret))
                    else:
                        self.lgr.debug('getmemParam did step forward would record fun %s at 0x%x ret_addr ofset is None, assume lr retrun' % (self.mem_something.fun, eip))
                    self.mem_fun_entries[self.mem_something.fun] = self.MemCallRec(None, ret_addr_offset, eip)
            else:
                ''' adjust  to account for simics not adjusting sp on break on function entry '''
                sp = sp + self.mem_utils.WORD_SIZE

            self.pending_call = True
            self.lgr.debug('dataWatch getMemParams, pending_call set True,  fun is %s' % self.mem_something.fun)
            if self.mem_something.fun == 'memcpy' or self.mem_something.fun == 'memmove' or self.mem_something.fun == 'mempcpy' or self.mem_something.fun == 'j_memcpy': 
                
                self.mem_something.dest, self.mem_something.src, dumb = self.getCallParams(sp)
                if self.cpu.architecture == 'arm':
                    self.mem_something.count = self.mem_utils.getRegValue(self.cpu, 'r2')
                else:
                    if self.mem_something.fun == 'mempcpy':
                        eip = self.top.getEIP(self.cpu)
                        so_file = self.top.getSOFile(eip)
                        if so_file is not None and 'libc' in so_file.lower():
                            count_addr = self.mem_utils.readPtr(self.cpu, sp+2*self.mem_utils.WORD_SIZE)
                            self.mem_something.count = self.mem_utils.readWord32(self.cpu, count_addr)
                            self.lgr.debug('mempcy but is libc count_addr 0x%x, count %d' % (count_addr, self.mem_something.count))
                        else:
                            self.mem_something.count = self.mem_utils.readWord32(self.cpu, sp+2*self.mem_utils.WORD_SIZE)
                            self.lgr.debug('mempcy but not libc, so file %s  count %d' % (so_file, self.mem_something.count))
                    else:
                        self.mem_something.count = self.mem_utils.readWord32(self.cpu, sp+2*self.mem_utils.WORD_SIZE)
                self.lgr.debug('getMemParams memcpy-ish dest 0x%x  src 0x%x count 0x%x' % (self.mem_something.dest, self.mem_something.src, 
                    self.mem_something.count))
            elif self.mem_something.fun == 'memset':
                self.mem_something.dest, dumb, self.mem_something.count = self.getCallParams(sp)
                self.mem_something.src = self.mem_something.dest
            elif self.mem_something.fun == 'memcmp':
                self.mem_something.dest, self.mem_something.src, self.mem_something.count = self.getCallParams(sp)
                self.mem_something.src = self.mem_something.dest
            elif self.mem_something.fun == 'strdup':
                self.mem_something.src, dumb1, dubm2, self.getCallParams(sp)
                self.mem_something.count = self.getStrLen(self.mem_something.src)        
            elif self.mem_something.fun == 'strcpy' or self.mem_something.fun == 'strncpy':
                if self.cpu.architecture == 'arm':
                    if self.mem_something.src is None:
                        self.mem_something.src = self.mem_utils.getRegValue(self.cpu, 'r1')
                    self.mem_something.count = self.getStrLen(self.mem_something.src)        
                    if self.mem_something.fun == 'strncpy':
                        n = self.mem_utils.getRegValue(self.cpu, 'r3')
                        if self.mem_something.count > n:
                            self.mem_something.count = n
                    self.mem_something.dest = self.mem_utils.getRegValue(self.cpu, 'r0')
                    ''' TBD this fails on buffer overlap, but that leads to crash anyway? '''
                    self.lgr.debug('getMemParams strcpy, src: 0x%x dest: 0x%x count(maybe): %d' % (self.mem_something.src, self.mem_something.dest, self.mem_something.count))
                else:
                    if self.mem_something.src is None:
                        self.mem_something.src = self.mem_utils.readPtr(self.cpu, sp+self.mem_utils.WORD_SIZE)
                    self.mem_something.count = self.getStrLen(self.mem_something.src)        
                    if self.mem_something.fun == 'strncpy':
                        n_addr = sp+2*self.mem_utils.WORD_SIZE
                        n = self.mem_utils.readWord(self.cpu, n_addr)
                        self.lgr.debug('getMemParams strncpy count was %d, n was %d  n_addr was 0x%x' % (self.mem_something.count, n, n_addr))
                        if self.mem_something.count > n:
                            self.mem_something.count = n
                    self.mem_something.dest = self.mem_utils.readPtr(self.cpu, sp)
            elif self.mem_something.fun in ['strcmp', 'strncmp', 'strcasecmp', 'xmlStrcmp']: 
                self.mem_something.dest, self.mem_something.src, dumb = self.getCallParams(sp)
                if self.cpu.architecture == 'arm':
                    if self.mem_something.fun == 'strncmp':
                        limit = self.mem_utils.getRegValue(self.cpu, 'r2')
                        self.mem_something.count = min(limit, self.getStrLen(self.mem_something.src))
                    else:
                        self.mem_something.count = self.getStrLen(self.mem_something.src)        

                    self.lgr.debug('getMemParams %s, src: 0x%x dest: 0x%x count: %d' % (self.mem_something.fun, self.mem_something.src, 
                         self.mem_something.dest, self.mem_something.count))
                else:
                    if self.mem_something.fun == 'strncmp':
                        limit = self.mem_utils.readPtr(self.cpu, sp+2*self.mem_utils.WORD_SIZE)
                        self.mem_something.count = min(limit, self.getStrLen(self.mem_something.src))
                    else:
                        self.mem_something.count = self.getStrLen(self.mem_something.src)        
            elif self.mem_something.fun in ['strchr', 'strrchr']:
                self.mem_something.src, self.mem_something.the_chr, dumb = self.getCallParams(sp)
                ''' TBD fix to reflect strnchr? '''
                self.mem_something.count=1
            elif self.mem_something.fun in ['strtoul', 'strtoull']:
                self.mem_something.src, dumb2, dumb = self.getCallParams(sp)

            elif self.mem_something.fun == 'sscanf':
                if self.cpu.architecture == 'arm':
                    format_addr = self.mem_utils.getRegValue(self.cpu, 'r1')
                else:
                    format_addr= self.mem_utils.readPtr(self.cpu, sp+self.mem_utils.WORD_SIZE)
                format_str = self.mem_utils.readString(self.cpu, format_addr, 40)
                nparams = format_str.count('%')
                if self.cpu.architecture == 'arm':
                    param_addr = self.mem_utils.getRegValue(self.cpu, 'r2')
                    for i in range(nparams):
                        offset = (i)*self.mem_utils.WORD_SIZE
                        param = self.mem_utils.readPtr(self.cpu, param_addr+offset)
                        self.mem_something.dest_list.append(param) 
                    self.mem_something.src = self.mem_utils.getRegValue(self.cpu, 'r0')
                else:
                    for i in range(nparams):
                        offset = (i+2)*self.mem_utils.WORD_SIZE
                        param = self.mem_utils.readPtr(self.cpu, sp+offset)
                        self.mem_something.dest_list.append(param) 
                    self.mem_something.src = self.mem_utils.readPtr(self.cpu, sp)
                ''' TBD fix this '''
                self.mem_something.count = 1
            elif self.mem_something.fun == 'strlen':
                if self.cpu.architecture == 'arm':
                    self.mem_something.src = self.mem_utils.getRegValue(self.cpu, 'r0')
                else:
                    self.mem_something.src = self.mem_utils.readPtr(self.cpu, sp)
                self.lgr.debug('dataWatch is strlen, cal getStrLen for 0x%x' % self.mem_something.src)
                self.mem_something.count = self.getStrLen(self.mem_something.src)        
                self.lgr.debug('dataWatch back from getStrLen')
            elif self.mem_something.fun in ['vsnprintf', 'sprintf']:
                # TBD generalized this
                self.mem_something.dest, self.mem_something.src, dumb = self.getCallParams(sp)
            elif self.mem_something.fun == 'fprintf' or self.mem_something.fun == 'printf':
                dumb2, self.mem_something.src, dumb = self.getCallParams(sp)

            elif self.mem_something.fun == 'fwrite' or self.mem_something.fun == 'IO_do_write':
                self.mem_something.src, self.mem_something.count, dumb = self.getCallParams(sp)

            elif self.mem_something.fun == 'glob' or self.mem_something.fun == 'IO_do_write':
                self.mem_something.src, dumb1, dumb = self.getCallParams(sp)

            # Begin XML
            elif self.mem_something.fun == 'xmlGetProp':
                if self.cpu.architecture == 'arm':
                    self.mem_something.src = self.mem_utils.getRegValue(self.cpu, 'r1')
                else:
                    self.mem_something.src = self.mem_utils.readPtr(self.cpu, sp+self.mem_utils.WORD_SIZE)
                self.mem_something.count = self.getStrLen(self.mem_something.src)        
                self.mem_something.the_string = self.mem_utils.readString(self.cpu, self.mem_something.src, self.mem_something.count)
            elif self.mem_something.fun == 'inet_addr':
                if self.cpu.architecture == 'arm':
                    self.mem_something.src = self.mem_utils.getRegValue(self.cpu, 'r0')
                else:
                    self.mem_something.src = self.mem_utils.readPtr(self.cpu, sp)
                self.mem_something.count = self.getStrLen(self.mem_something.src)        
                self.mem_something.the_string = self.mem_utils.readString(self.cpu, self.mem_something.src, self.mem_something.count)
            elif self.mem_something.fun == 'GetToken':
                if self.cpu.architecture == 'arm':
                    self.mem_something.src = self.mem_utils.getRegValue(self.cpu, 'r0')
                else:
                    self.mem_something.src = self.mem_utils.readPtr(self.cpu, sp)

            elif self.mem_something.fun == 'FreeXMLDoc':
                self.mem_something.count = 0

            elif self.mem_something.fun == 'xmlParseFile' or self.mem_something.fun == 'xml_parse':
                self.me_trace_malloc = True
                self.top.traceMalloc()
                self.lgr.debug('getMemParams xml parse')
                 
            cell = self.top.getCell()
            ''' Assume we have disabled debugging in context manager while fussing with parameters. '''
            self.top.restoreDebugBreaks(was_watching=True)

            #self.context_manager.restoreDefaultContext()
            skip_fun = False
            if not data_hit:
                self.lgr.debug('dataWatch not data_hit, find range for buf_start using src 0x%x' % self.mem_something.src)
                ''' see if src is one of our buffers '''
                buf_start = self.findRange(self.mem_something.src)
                if buf_start is None:
                    ''' handle ambigous calls such as strcmp '''
                    if self.mem_something.dest is not None:
                        buf_start = self.findRange(self.mem_something.dest)
                    if buf_start is None:
                        skip_fun = True
                        if self.mem_something.src is not None and self.mem_something.dest is not None:
                            self.lgr.debug('dataWatch getMemParams, src 0x%x and dst 0x%x not buffers we care about, skip it' % (self.mem_something.src,
                                 self.mem_something.dest))
                        else:
                            self.lgr.debug('dataWatch getMemParams, src 0x%x  not buffer we care about, skip it' % (self.mem_something.src))
                else:
                    self.mem_something.op_type = Sim_Trans_Load
                    self.lgr.debug('datgaWatch getMemParams got buf_start of 0x%x' % buf_start)
            if not skip_fun:
                #self.stopWatch(leave_fun_entries = True)
                self.stopWatch()
                resim_context = self.context_manager.getRESimContext()
                proc_break = self.context_manager.genBreakpoint(resim_context, Sim_Break_Linear, Sim_Access_Execute, self.mem_something.ret_ip, 1, 0)
                self.return_hap = self.context_manager.genHapIndex("Core_Breakpoint_Memop", self.returnHap, None, proc_break, 'memcpy_return_hap')
                if self.back_stop is not None and not self.break_simulation and self.use_back_stop:
                    self.back_stop.setFutureCycle(self.back_stop_cycles)
                self.lgr.debug('getMemParams set hap on ret_ip at 0x%x context %s Now run!' % (self.mem_something.ret_ip, 
                     str(self.cpu.current_context)))
                if data_hit:
                    SIM_run_command('c')

    def runToReturnAlone(self, dumb):
        cell = self.top.getCell()
        resim_context = self.context_manager.getRESimContext()
        #self.context_manager.restoreDefaultContext()
        #proc_break = self.context_manager.genBreakpoint(cell, Sim_Break_Linear, Sim_Access_Execute, self.mem_something.ret_ip, 1, 0)
        proc_break = self.context_manager.genBreakpoint(resim_context, Sim_Break_Linear, Sim_Access_Execute, self.mem_something.ret_ip, 1, 0)
        self.return_hap = self.context_manager.genHapIndex("Core_Breakpoint_Memop", self.returnHap, self.mem_something, proc_break, 'memsomething_return_hap')
        self.lgr.debug('runToReturnAlone set returnHap with breakpoint %d break at ret_ip 0x%x' % (proc_break, self.mem_something.ret_ip))
        if self.mem_something.run:
            SIM_run_command('c')

    def undoHap(self, dumb, one, exception, error_string):
        
        if self.undo_hap is not None:
            SIM_hap_delete_callback_id("Core_Simulation_Stopped", self.undo_hap)
            self.undo_hap = None
            SIM_run_alone(self.undoAlone, None)

    def undoAlone(self, dumb):
            self.lgr.debug('undoAlone skip back to 0x%x' % self.save_cycle)
            if not self.skipToTest(self.save_cycle):
                self.lgr.error('undoAlone unable to skip to save cycle 0x%x, got 0x%x' % (self.save_cycle, self.cpu.cycles))
                return
            else:
                self.lgr.debug('skip done')
            eip = self.top.getEIP(self.cpu)
            dum_cpu, cur_addr, comm, pid = self.task_utils.currentProcessInfo(self.cpu)
            self.watch(i_am_alone=True)
            addr = self.mem_something.src
            if self.mem_something.op_type != Sim_Trans_Load or addr is None:
                addr = self.mem_something.dest
            self.lgr.debug('dataWatch undoAlone would run forward, first restore debug context')
            self.finishReadHap(self.mem_something.op_type, self.mem_something.trans_size, eip, addr, self.mem_something.length, self.mem_something.start, pid)
            self.context_manager.restoreDebugContext()
            self.top.restoreDebugBreaks()
            SIM_run_command('c')

    def hitCallStopHap(self, dumb, one, exception, error_string):
        ''' we are at the call to a memsomething, get the parameters '''
        self.lgr.debug('DataWatch hitCallStopHap')
        if self.call_stop_hap is not None:
            cycle_dif = self.cycles_was - self.cpu.cycles
            #self.lgr.debug('hitCallStopHap will delete hap %d break %d cycle_dif 0x%x' % (self.call_hap, self.call_break, cycle_dif))
            SIM_hap_delete_callback_id("Core_Simulation_Stopped", self.call_stop_hap)
            SIM_delete_breakpoint(self.call_break)
            SIM_hap_delete_callback_id("Core_Breakpoint_Memop", self.call_hap)
            self.call_stop_hap = None
            self.call_hap = None
        else:
            return
        eip = self.top.getEIP(self.cpu)
        ''' TBD dynamically adjust cycle_dif limit?  make exceptions for some calls, e.g., xmlparse? '''
        if eip != self.mem_something.called_from_ip or cycle_dif > 300000:
            if eip != self.mem_something.called_from_ip:
                self.lgr.debug('hitCallStopHap not stopped on expected call. Wanted 0x%x got 0x%x' % (self.mem_something.called_from_ip, eip))
            else:
                self.lgr.debug('hitCallStopHap stopped too far back cycle_dif 0x%x, assume a ghost frame' % cycle_dif)
            SIM_run_alone(self.undoAlone, self.mem_something)
        else:
            latest_cycle = self.watchMarks.latestCycle()
            if latest_cycle > self.cpu.cycles:
                self.lgr.debug('hitCallStopHap stopped at 0x%x, prior to most recent watch mark having cycle: 0x%x, assume a ghost frame' % (self.cpu.cycles, latest_cycle))
                SIM_run_alone(self.undoAlone, self.mem_something)
            else:
                self.lgr.debug('dataWatch hitCallStopHap function %s call getMemParams at eip 0x%x' % (self.mem_something.fun, eip))
                SIM_run_alone(self.getMemParams, True)
       
    def vt_handler(self, memory):
        location = memory.physical_address
        self.lgr.debug('vt_handler at 0x%x set call_stop_hap cycle: 0x%x' % (location, self.cpu.cycles))
        SIM_run_alone(self.deleteGhostStopHap, None)
        SIM_run_alone(self.setCallStopAlone, None)
        SIM_break_simulation('vt_handler')

    def hitCallCallback(self, cpu, third, forth, memory):
        if self.call_hap is not None:
            dum_cpu, cur_addr, comm, pid = self.task_utils.currentProcessInfo(self.cpu)
            if self.cpu.cycles > self.cycles_was:
                #self.lgr.debug('hitCallCallback pid:%d memory 0x%x  BAD cycle: 0x%x' % (pid, memory.physical_address, self.cpu.cycles))
                pass
            else:
                self.lgr.debug('hitCallCallback pid:%d memory 0x%x  cycle: 0x%x' % (pid, memory.physical_address, self.cpu.cycles))
            VT_in_time_order(self.vt_handler, memory)

    def setCallStopAlone(self, dumb):
        self.lgr.debug('dataWatch setCalStopAlone')
        self.call_stop_hap = SIM_hap_add_callback("Core_Simulation_Stopped", self.hitCallStopHap, None)

    def revAlone(self, dumb):
        self.top.removeDebugBreaks(immediate=True)
        self.stopWatch(immediate=True)
        phys_block = self.cpu.iface.processor_info.logical_to_physical(self.mem_something.called_from_ip, Sim_Access_Read)
        #if self.mem_something.called_from_ip == 0xb6e41430:
        #if self.mem_something.called_from_ip == 0xb6e736fc:
        #    print('getting sick, would break at 0x%x phys 0x%x' %  (self.mem_something.called_from_ip, phys_block.address))
        #    return
        pcell = self.cpu.physical_memory
        self.call_break = SIM_breakpoint(pcell, Sim_Break_Physical, Sim_Access_Execute, phys_block.address, 1, 0)
        #cell = self.top.getCell()
        #self.call_break = SIM_breakpoint(cell, Sim_Break_Linear, Sim_Access_Execute, self.mem_something.called_from_ip, 1, 0)
        self.call_hap = SIM_hap_add_callback_index("Core_Breakpoint_Memop", self.hitCallCallback, self.cpu, self.call_break)
        ''' in case we chase ghost frames mimicking memsomething calls  and need to return '''
        self.save_cycle = self.cpu.cycles - 1
        self.lgr.debug('dataWatch revAlone break %d set on IP of call 0x%x (phys 0x%x) and call hap %d set save_cycle 0x%x, now reverse' % (self.call_break, 
           self.mem_something.called_from_ip, phys_block.address, self.call_hap, self.save_cycle))
        self.cycles_was = self.save_cycle+1
        #SIM_run_command('list-breakpoints')
        self.lgr.debug('revAlone now rev cycles_was: 0x%x' % self.cycles_was)
        self.ghost_stop_hap = SIM_hap_add_callback("Core_Simulation_Stopped", self.ghostStopHap, None)
        SIM_run_command('reverse')

    def ghostStopHap(self, dumb, one, exception, error_string):
        self.lgr.debug('ghost stop hap')
        if self.ghost_stop_hap is not None:
            self.deleteGhostStopHap(None)
            SIM_run_alone(self.undoAlone, None)
       
    def deleteGhostStopHap(self, dumb): 
        if self.ghost_stop_hap is not None:
            SIM_hap_delete_callback_id("Core_Simulation_Stopped", self.ghost_stop_hap)
            self.ghost_stop_hap = None

    def memstuffStopHap(self, dumb, one, exception, error_string):
        ''' We may had been in a memsomething and have stopped.  Set a break on the address 
            of the call to the function and reverse. '''
        if self.stop_hap is not None:
            #self.lgr.debug('memstuffStopHap stopHap will delete hap %s' % str(self.stop_hap))
            SIM_hap_delete_callback_id("Core_Simulation_Stopped", self.stop_hap)
            self.stop_hap = None
        else:
            return
        #self.lgr.debug('memstuffStopHap, reverse to call at ip 0x%x' % self.mem_something.called_from_ip)
        SIM_run_alone(self.revAlone, None)

    def getStrLen(self, src):
        addr = src
        done = False
        #self.lgr.debug('getStrLen from 0x%x' % src)
        while not done:
            v = self.mem_utils.readByte(self.cpu, addr)
            #self.lgr.debug('getStrLen got 0x%x from 0x%x' % (v, addr))
            if v is None:
                self.lgr.debug('getStrLen got NONE for 0x%x' % (addr))
                done = True
            if v == 0:
                done = True
            else:
                addr += 1
        return addr - src

    def handleMemStuff(self, dumb):
        '''
        We are within a memcpy type functionfor which we believe we know the calling conventions (or a user-defined iterator).  However those values have been
        lost to the vagaries of the implementation by the time we hit the breakpoint.  We need to stop; Reverse to the call; record the parameters;
        set a break on the return; and continue.  We'll assume not too many instructions between us and the call, so manually walk er back.
        '''
        #self.lgr.debug('handleMemStuff ret_addr 0x%x fun %s called_from_ip 0x%x' % (self.mem_something.ret_ip, self.mem_something.fun, self.mem_something.called_from_ip))
        if self.mem_something.fun not in mem_funs or self.mem_something.fun in no_stop_funs: 
            ''' assume it is a user iterator '''
            if self.mem_something.src is not None:
                self.lgr.debug('handleMemStuff assume iterator or function that need not reverse to call, src: 0x%x  %s clear backstop' % (self.mem_something.src, self.cpu.current_context))
            else:
                self.lgr.debug('handleMemStuff assume iterator or function that need not reverse to call, IS a modify,  Just return and come back on read')
                return
            self.pending_call = True
            ''' iterator may take  while to return? '''
            self.watchMarks.iterator(self.mem_something.fun, self.mem_something.src, self.mem_something.src)
            self.back_stop.clearCycle()
            #SIM_break_simulation('handle memstuff')
            SIM_run_alone(self.runToReturnAlone, None)
        else: 
            ''' walk backwards to the call, and get the parameters.  TBD, why not do same for strcpy and strcmp? '''
            self.stop_hap = SIM_hap_add_callback("Core_Simulation_Stopped", 
        	     self.memstuffStopHap, None)
            SIM_break_simulation('handle memstuff')
            
    def getStartLength(self, index, addr):
        hap_start = self.start[index]
        i = 0
        ret_start = hap_start
        ret_length = self.length[index]
        for start in self.other_starts:
            if start > hap_start and start <= addr:
                ret_start = start
                ret_length = self.other_lengths[i]
                self.lgr.debug('getStartLength replaced buffer start %x with %x' % (hap_start, ret_start))
                break
        return ret_start, ret_length
   
    class KernelReturnInfo():
        def __init__(self, addr, op_type):
            self.addr = addr 
            self.op_type = op_type 
    
    def finishReadHap(self, op_type, trans_size, eip, addr, length, start, pid, index=None):
        instruct = SIM_disassemble_address(self.cpu, eip, 1, 0)
        offset = addr - start
        cpl = memUtils.getCPL(self.cpu)
        #self.lgr.debug('finishReadHap eip: 0x%x addr 0x%x' % (eip, addr))
        if op_type == Sim_Trans_Load:
            if cpl == 0:
                #if not self.break_simulation:
                #    self.stopWatch()
                self.lgr.debug('dataWatch finishReadHap, read in kernel, set kernelReturn hap')
                #self.return_hap = 'eh'
                SIM_run_alone(self.kernelReturn, self.KernelReturnInfo(addr, op_type))
            else:
                #self.lgr.debug('finishReadHap Data read from 0x%x within input buffer (offset of %d into buffer of %d bytes starting at 0x%x) pid:%d eip: 0x%x <%s> cycle:0x%x' % (addr, 
                #        offset, length, start, pid, eip, instruct[1], self.cpu.cycles))
                self.prev_read_cycle = self.cpu.cycles
                msg = ('Data read from 0x%x within input buffer (offset of %d into %d bytes starting at 0x%x) eip: 0x%x' % (addr, 
                            offset, length, start, eip))
                #self.lgr.debug(msg)
                self.context_manager.setIdaMessage(msg)
                if instruct[1].startswith('repe cmpsb'):
                    esi = self.mem_utils.getRegValue(self.cpu, 'esi')
                    edi = self.mem_utils.getRegValue(self.cpu, 'edi')
                    count = self.mem_utils.getRegValue(self.cpu, 'ecx')
                    buf_start = self.findRange(edi)
                    self.watchMarks.compare('rep cmpsb', edi, esi, count, buf_start)
                else: 
                    self.watchMarks.dataRead(addr, start, length, self.getCmp(), trans_size)
                if self.break_simulation:
                    SIM_break_simulation('DataWatch read data')


        elif cpl > 0:
            ''' is a write to a data watch buffer '''
           # self.lgr.debug('finishReadHap Data written to 0x%x within input buffer (offset of %d into buffer of %d bytes starting at 0x%x) pid:%d eip: 0x%x' % (addr, offset, length, start, pid, eip))
            self.context_manager.setIdaMessage('Data written to 0x%x within input buffer (offset of %d into %d bytes starting at 0x%x) eip: 0x%x' % (addr, offset, length, start, eip))
            
            sp = self.mem_utils.getRegValue(self.cpu, 'sp')
            ''' TBD git rid of this and depend on catching returns from function '''
            if False and addr > sp and index is not None and (self.cpu.cycles - self.prev_read_cycle)<100:
                self.hack_reuse[index] = self.hack_reuse[index]+1
                if self.hack_reuse[index] > self.length[index]/3:
                    ''' Assume reused stack buffer, remove it from watch '''
                    self.lgr.debug('dataWatch finishReadHap remove watch for index %d' % index)
                    self.context_manager.genDeleteHap(self.read_hap[index], immediate=False)
                    self.read_hap[index] = None
                    self.start[index] = 0
                else:
                    self.watchMarks.memoryMod(start, length, trans_size, addr=addr)
            else:
                self.watchMarks.memoryMod(start, length, trans_size, addr=addr)
            if self.break_simulation:
                ''' TBD when to treat buffer as unused?  does it matter?'''
                self.start[index] = 0
                SIM_break_simulation('DataWatch written data')
        elif self.retrack:
            self.lgr.debug('dataWatch finishReadHap, modification by kernel, set kernelReturn hap')
            self.return_hap = 'eh'
            SIM_run_alone(self.kernelReturn, self.KernelReturnInfo(addr, op_type))
            self.lgr.debug('Data written by kernel to 0x%x within input buffer (offset of %d into buffer of %d bytes starting at 0x%x) pid:%d eip: 0x%x. In retrack, stop here TBD FIX THIS.' % (addr, offset, length, start, pid, eip))
            #self.stopWatch()
        else:
            self.lgr.debug('dataWatch finishReadHap, modification by kernel, set kernelReturn hap')
            SIM_run_alone(self.kernelReturn, self.KernelReturnInfo(addr, op_type))

    def readHap(self, index, an_object, breakpoint, memory):
        if self.return_hap is not None:
            return
        if self.max_marks is not None and self.watchMarks.markCount() > self.max_marks:
            SIM_break_simulation('max marks exceeded')
            return
        addr = memory.logical_address
        op_type = SIM_get_mem_op_type(memory)
        eip = self.top.getEIP(self.cpu)
        #break_handle = self.context_manager.getBreakHandle(breakpoint)
        #self.lgr.debug('readHap eip: 0x%x addr: 0x%x index: %d breakpoint: %d op_tpye: %s bytes: %d cycle: 0x%x' % (eip, addr, index, breakpoint, str(op_type), 
        #    memory.size, self.cpu.cycles))
        #if addr == 0xb5f70686:
        #    SIM_break_simulation('wet')
        #return
        ''' watched data has been read (or written) '''
        if self.prev_cycle is None:
            ''' first data read, start data session if doing coverage '''
            self.top.startDataSessions()
        if self.cpu.cycles == self.prev_cycle:
            self.lgr.debug('readHap hit twice')
            return
        if len(self.read_hap) == 0:
            return
        self.prev_cycle = self.cpu.cycles
        if op_type != Sim_Trans_Load and addr in self.no_backstop:
            self.start[index] = 0
            self.lgr.debug('watchData readHap modified no_backstop memory, remove from watch list')
            if index < len(self.read_hap):
                if self.read_hap[index] is not None:
                    self.lgr.debug('dataWatch readHap  delete hap %d' % self.read_hap[index])
                    self.context_manager.genDeleteHap(self.read_hap[index], immediate=False)
                    self.read_hap[index] = None

        dum_cpu, cur_addr, comm, pid = self.task_utils.currentProcessInfo(self.cpu)

        if self.back_stop is not None and not self.break_simulation and self.use_back_stop and addr not in self.no_backstop:
            self.back_stop.setFutureCycle(self.back_stop_cycles)
        else:
            self.lgr.debug('dataWatch readHap NO backstop set.  break sim %r  use back %r' % (self.break_simulation, self.use_back_stop))
        if index >= len(self.read_hap):
            self.lgr.error('dataWatch readHap pid:%d invalid index %d, only %d read haps' % (pid, index, len(self.read_hap)))
            return
        if self.read_hap[index] is None or self.read_hap[index] == 0:
            self.lgr.debug('readHap index %d none or zero' % index)
            return
        self.lgr.debug('dataWatch readHap pid:%d index %d addr 0x%x eip 0x%x cycles: 0x%x' % (pid, index, addr, eip, self.cpu.cycles))
        if self.show_cmp:
            self.showCmp(addr)

        if self.break_simulation:
            self.lgr.debug('readHap will break_simulation, set the stop hap')
            self.stopWatch()
            SIM_run_alone(self.setStopHap, None)

        start, length = self.getStartLength(index, addr) 
        self.lgr.debug('readHap index %d addr 0x%x got start of 0x%x' % (index, addr, start))
        cpl = memUtils.getCPL(self.cpu)
        ''' If execution outside of text segment, check for mem-something library call '''
        #start, end = self.context_manager.getText()
        call_sp = None
        #self.lgr.debug('readHap eip 0x%x start 0x%x  end 0x%x' % (eip, start, end))
        if cpl != 0:
            #if not self.break_simulation:
            #    ''' prevent stack trace from triggering haps '''
            #    self.stopWatch()
            mem_stuff = None
       
            #self.lgr.debug('dataWatch get stack trace to look for memsomething')
            st = self.top.getStackTraceQuiet(max_frames=20, max_bytes=1000)
            if st is None:
                self.lgr.debug('stack trace is None, wrong pid?')
                return
            #self.lgr.debug('%s' % st.getJson()) 
            # look for memcpy'ish... TBD generalize 
            frames = st.getFrames(20)
            mem_stuff = self.memsomething(frames, mem_funs, st)

            skip_this = False
            if mem_stuff is not None and mem_stuff.fun.startswith('mempcpy'):
                if mem_stuff.ret_addr is not None:
                    so_file = self.top.getSOFile(mem_stuff.ret_addr)
                    if so_file is not None and 'libc' in so_file.lower():
                        skip_this = True
                        self.lgr.debug('DataWatch skip mempcpy called from libc')
                    else:
                        self.lgr.debug('DataWatch is mempcpy but not libc')
                else:
                    self.lgr.debug('DataWatch is mempcpy but no ret addr')
                    
        
            if mem_stuff is not None and not skip_this:
                if mem_stuff.ret_addr is not None and mem_stuff.called_from_ip is not None:
                    self.lgr.debug('DataWatch readHap ret_ip 0x%x called_from_ip is 0x%x' % (mem_stuff.ret_addr, mem_stuff.called_from_ip))
                else:
                    self.lgr.debug('DataWatch readHap ret_ip  or called_from_ip no ret_addr found')
                ''' referenced memory address is src/dest depending on op_type''' 
                dest = None
                src = addr
                if op_type != Sim_Trans_Load:
                    src = None
                    dest = addr
                self.mem_something = self.MemSomething(mem_stuff.fun, addr, mem_stuff.ret_addr, src, dest, None, 
                      mem_stuff.called_from_ip, op_type, length, start, ret_addr_addr = mem_stuff.ret_addr_addr, trans_size=memory.size)
                SIM_run_alone(self.handleMemStuff, None)
                return
            else:
                #self.lgr.debug('DataWatch readHap not memsomething, reset the watch ')
                #self.watch()
                pass
        self.finishReadHap(op_type, memory.size, eip, addr, length, start, pid, index=index)
 
       
    def showWatch(self):
        for index in range(len(self.start)):
            if self.start[index] != 0:
                print('%d start: 0x%x  length: 0x%x' % (index, self.start[index], self.length[index]))
 
    def setBreakRange(self, i_am_alone=False):
        ''' Set breakpoints for each range defined in self.start and self.length '''
        context = self.context_manager.getRESimContext()
        num_existing_haps = len(self.read_hap)
        for index in range(num_existing_haps, len(self.start)):
            if self.start[index] == 0:
                #self.lgr.debug('DataWatch setBreakRange index %d is 0' % index)
                self.read_hap.append(None)
                continue
            ''' TBD should this be a physical bp?  Why explicit RESim context -- perhaps debugging_pid is not set while
                fussing with memsomething parameters? '''
           
            break_num = self.context_manager.genBreakpoint(context, Sim_Break_Linear, Sim_Access_Read | Sim_Access_Write, self.start[index], self.length[index], 0)
            end = self.start[index] + self.length[index] 
            eip = self.top.getEIP(self.cpu)
            #self.lgr.debug('DataWatch setBreakRange eip: 0x%x Adding breakpoint %d for %x-%x length %x index now %d number of read_haps was %d' % (eip, break_num, self.start[index], end, 
            #    self.length[index], index, len(self.read_hap)))
            self.read_hap.append(self.context_manager.genHapIndex("Core_Breakpoint_Memop", self.readHap, index, break_num, 'dataWatch'))
            

        #if self.back_stop is not None and not self.break_simulation and self.use_back_stop:
        #    #self.lgr.debug('dataWatch, setBreakRange call to setFutureCycle')
        #    self.back_stop.setFutureCycle(self.back_stop_cycles, now=i_am_alone)

    def stopHap(self, stop_action, one, exception, error_string):
        if stop_action is None or stop_action.hap_clean is None:
            self.lgr.error('dataWatch stopHap error, stop_action None?')
            return
        eip = self.top.getEIP(self.cpu)
        self.lgr.debug('dataWatch stopHap eip 0x%x cycle: 0x%x' % (eip, stop_action.hap_clean.cpu.cycles))

        if self.stop_hap is not None:
            #self.lgr.debug('dataWatch stopHap will delete hap %s' % str(self.stop_hap))
            SIM_hap_delete_callback_id("Core_Simulation_Stopped", self.stop_hap)
            self.stop_hap = None
            ''' check functions in list '''
            #self.lgr.debug('stopHap now run actions %s' % str(stop_action.flist))
            stop_action.run()
         
    def setStopHap(self, dumb):
        f1 = stopFunction.StopFunction(self.top.skipAndMail, [], nest=False)
        flist = [f1]
        hap_clean = hapCleaner.HapCleaner(self.cpu)
        stop_action = hapCleaner.StopAction(hap_clean, None, flist)
        self.stop_hap = SIM_hap_add_callback("Core_Simulation_Stopped", 
        	     self.stopHap, stop_action)
        #self.lgr.debug('setStopHap set actions %s' % str(stop_action.flist))

    def setShow(self):
        self.show_cmp = ~ self.show_cmp
        return self.show_cmp

    def findRange(self, addr):
        retval = None
        if addr is None:
            self.lgr.error('dataWatch findRange called with addr of None')
        else:
            for index in range(len(self.start)):
                if self.start[index] != 0:
                    end = self.start[index] + self.length[index]
                    self.lgr.debug('findRange is 0x%x between 0x%x and 0x%x?' % (addr, self.start[index], end))
                    if addr >= self.start[index] and addr <= end:
                        retval = self.start[index]
                        break
        return retval

    def findRangeIndex(self, addr):
        for index in range(len(self.start)):
            if self.start[index] != 0:
                end = self.start[index] + self.length[index]
                #self.lgr.debug('findRange is 0x%x between 0x%x and 0x%x?' % (addr, self.start[index], end))
                if addr >= self.start[index] and addr <= end:
                    return index
        return None

    def getWatchMarks(self):
        origin = self.top.getFirstCycle()
        return self.watchMarks.getWatchMarks(origin=origin)

    def goToMark(self, index):
        retval = None
        cycle = self.watchMarks.getCycle(index)
        if cycle is not None:
            SIM_run_command('pselect %s' % self.cpu.name)
            SIM_run_command('skip-to cycle=%d' % cycle)
            retval = cycle
            if cycle != self.cpu.cycles:
                self.lgr.error('dataWatch goToMark got wrong cycle, asked for 0x%x got 0x%x' % (cycle, self.cpu.cycles))
                retval = None
            else:
                self.lgr.debug('dataWatch goToMark cycle now 0x%x' % cycle)
            self.context_manager.restoreWatchTasks()
        else:
           self.lgr.error('No data mark with index %d' % index)
        return retval

    def clearWatchMarks(self): 
        self.watchMarks.clearWatchMarks()

    def clearWatches(self, cycle=None):
        if cycle is None:
            #self.lgr.debug('DataWatch clear Watches, no cycle given')
            self.prev_cycle = None
        else:
            self.lgr.debug('DataWatch clear Watches cycle 0x%x' % cycle)
        self.stopWatch()
        self.break_simulation = True
        self.stack_buffers = {}
        for eip in self.stack_buf_hap:
            self.context_manager.genDeleteHap(self.stack_buf_hap[eip])
        self.stack_buf_hap = {}
        if cycle is None:
            del self.start[:]
            del self.length[:]
            del self.hack_reuse[:]
            del self.cycle[:]
            self.other_starts = []
            self.other_lengths = []
        elif cycle == -1:
            ''' at origin, assume not first retrack, keep first entry '''
            del self.start[1:]
            del self.length[1:]
            del self.hack_reuse[1:]
            del self.cycle[1:]
            self.lgr.debug('clearWatches, left only first entry, start is 0x%x' % (self.start[0]))
            self.watchMarks.memoryMod(self.start[0], self.length[0], 0)
        else:
            found = None
            ''' self.cycle is a list of cycles corresponding to each watch mark entry
                find the first recorded cycle that is later than the current cycle.
            '''
            for index in range(len(self.cycle)):
                self.lgr.debug('clearWAtches cycle 0x%x list 0x%x' % (cycle, self.cycle[index]))
                ''' hack off by one to hande syscall returns about to return from kernel '''
                if self.cycle[index] > cycle-1:
                    self.lgr.debug('clearWatches found cycle index %s' % index)
                    found = index
                    break
            if found is not None and len(self.start)>index:
                self.lgr.debug('clearWatches, before list reset start[%d] is 0x%x' % (index, self.start[index]))
                del self.start[index+1:]
                del self.length[index+1:]
                del self.hack_reuse[index+1:]
                del self.cycle[index+1:]
                self.lgr.debug('clearWatches, reset list, index %d start[%d] is 0x%x' % (index, index, self.start[index]))
                self.watchMarks.memoryMod(self.start[index], self.length[index], 0)
                

    def setIdaFuns(self, ida_funs):
        self.lgr.debug('DataWatch setIdaFuns')
        self.ida_funs = ida_funs

    def setRelocatables(self, relocatables):
        self.lgr.debug('DataWatch setRelocatables')
        self.relocatables = relocatables

    def setCallback(self, callback):
        ''' what should backStop call when no activity for N cycles? '''
        self.lgr.debug('dataWatch setCallback, call to backstop to set callback')
        self.back_stop.setCallback(callback)

    def showWatchMarks(self):
        self.watchMarks.showMarks()

    def saveWatchMarks(self, fpath):
        self.watchMarks.saveMarks(fpath)

    def tagIterator(self, index):
        ''' Call from IDA Client to collapse a range of data references into the given watch mark index ''' 
        self.lgr.debug('DataWatch tagIterator index %d' % index)
        if self.ida_funs is not None:
            watch_mark = self.watchMarks.getMarkFromIndex(index)
            if watch_mark is not None:
                fun = self.ida_funs.getFun(watch_mark.ip)
                if fun is None:
                    self.lgr.error('DataWatch tagIterator failed to get function for 0x%x' % ip)
                else:
                    self.lgr.debug('DataWatch add iterator for function 0x%x from watch_mark IP of 0x%x' % (fun, watch_mark.ip))
                    self.user_iterators.add(fun)
            else:
                self.lgr.error('failed to get watch mark for index %d' % index)

    def setUserIterators(self, user_iterators):
        self.user_iterators = user_iterators

    def wouldBreakSimulation(self):
        if self.break_simulation:
            return True
        return False

    def rmBackStop(self):
        self.use_back_stop = False

    def setRetrack(self, value, use_backstop=True):
        self.lgr.debug('DataWatch setRetrack %r' % value)
        self.retrack = value
        if value and use_backstop:
            self.use_back_stop = True

    def fileStopHap(self):
        self.lgr.debug('fileStopHap')
        #if not self.skipToTest(self.cpu.cycles+1):
        #        self.lgr.error('fileStopHap unable to skip to next cycle got 0x%x' % (self.cpu.cycles))
        #        return
        st = self.top.getStackTraceQuiet(max_frames=16, max_bytes=100)
        my_mem_funs = ['xmlParseFile']
        if st is None:
            self.lgr.debug('stack trace is None, wrong pid?')
            return
        ''' look for memcpy'ish... TBD generalize '''
        frames = st.getFrames(20)
        mem_stuff = self.memsomething(frames, my_mem_funs, st)
        if mem_stuff is not None:
            self.lgr.debug('mem_stuff function %s, ret_ip is 0x%x' % (mem_stuff.fun, mem_stuff.ret_addr))
            self.mem_something = self.MemSomething(mem_stuff.fun, None, mem_stuff.ret_addr, None, None, None, 
                mem_stuff.called_from_ip, None, None, None, run=True)
            self.break_simulation=False
            self.me_trace_malloc = True
            self.top.traceMalloc()
            SIM_run_alone(self.runToReturnAlone, dumb)
        else:
            self.lgr.debug('Failed to get memsomething from stack frames')

    def setFileStopHap(self, dumb):
        f1 = stopFunction.StopFunction(self.fileStopHap, [], nest=False)
        flist = [f1]
        hap_clean = hapCleaner.HapCleaner(self.cpu)
        stop_action = hapCleaner.StopAction(hap_clean, None, flist)
        self.stop_hap = SIM_hap_add_callback("Core_Simulation_Stopped", 
        	     self.stopHap, stop_action)
        self.lgr.debug('setFileStopHap set actions %s' % str(stop_action.flist))

    def trackFile(self, callback, compat32):
        self.lgr.debug('DataWatch trackFile call watch')
        self.setFileStopHap(None)
        ''' what to do when backstop is reached (N cycles with no activity '''
        self.setCallback(callback)


    def trackIO(self, fd, callback, compat32, max_marks):
        self.lgr.debug('DataWatch trackIO for fd %d' % fd)
        ''' first make sure we are not in the kernel on this FD '''
        # NO, would reverse to state that may not be properly initialized.
        # Do not assume that call to receive implies the system is ready
        # to receive.
        #self.rev_to_call.preCallFD(fd) 
        self.max_marks = max_marks
        self.lgr.debug('DataWatch trackIO call watch')
        self.watch(break_simulation=False)
        ''' what to do when backstop is reached (N cycles with no activity '''
        self.setCallback(callback)

    def firstBufferAddress(self):
        return self.watchMarks.firstBufferAddress()

    def goToRecvMark(self):
        index = self.watchMarks.firstBufferIndex()
        if index is not None:
            self.goToMark(index)
            self.lgr.debug('dataWatch goToRecvMark, index %d cycles: 0x%x' % (index, self.cpu.cycles))
        else:
            self.lgr.debug('dataWatch goToRecvMark No first buffer index, go to origin')
            self.top.goToOrigin()

    def nextWatchMark(self):
        return self.watchMarks.nextWatchMark()

    def recordMalloc(self, addr, size):
        if self.me_trace_malloc:
            self.malloc_dict[addr] = size
        else:
            self.watchMarks.malloc(addr, size)

    def recordFree(self, addr):
        if self.me_trace_malloc:
            if addr not in self.malloc_dict:
                self.lgr.debug('Freed value not in malloc db: 0x%x' % addr)
            else:
                del self.malloc_dict[addr]
        else:
            self.watchMarks.free(addr)

    def skipToTest(self, cycle):
        while SIM_simics_is_running():
            self.lgr.error('skipToTest but simics running')
            time.sleep(1)
        retval = True
        SIM_run_command('pselect %s' % self.cpu.name)
        cmd = 'skip-to cycle = %d ' % cycle
        SIM_run_command(cmd)
        now = self.cpu.cycles
        if now != cycle:
            self.lgr.error('skipToTest failed wanted 0x%x got 0x%x' % (cycle, now))
            time.sleep(1)
            SIM_run_command(cmd)
            now = self.cpu.cycles
            if now != cycle:
                self.lgr.error('skipToTest failed again wanted 0x%x got 0x%x' % (cycle, now))
                retval = False
            else:
                # do you really want debug context at this point?
                #self.context_manager.restoreDebugContext() 
                pass
        else:
            # do you really want debug context at this point?
            #self.context_manager.restoreDebugContext() 
            pass
        return retval

    def mergeMallocXX(self):
        did_something = True
        remove_items = {}
        key_list = list(sorted(self.malloc_dict))
        while did_something:
            did_something = False
            ''' each mallo'd address, sorted '''
            for addr in sorted(self.malloc_dict):
                ''' get next address to see if it should be merged with htis one '''
                try:
                    next_key = key_list[key_list.index(addr)+1]
                except (ValueError, IndexError):
                    continue
                ''' end is last address in current addr, plus malloc structure fu '''
                end = addr + self.malloc_dict[addr] + 24
                if next_key < end:
                    self.lgr.debug('mergeMalloc addr 0x%x end 0x%x  next_addr 0x%x' % (addr, end, next_key))
                    if addr in remove_items: 
                        ''' this address already merged, extend size of parent by this size '''
                        parent_addr = remove_items[addr]
                        self.malloc_dict[parent_addr] = self.malloc_dict[parent_addr]+self.malloc_dict[next_key] 
                        remove_items[next_key] = remove_items[addr]
                    else:
                        self.malloc_dict[addr] = self.malloc_dict[addr]+self.malloc_dict[next_key] 
                        remove_items[next_key] = addr
                else:
                    self.lgr.debug('Next addr 0x%x not less than end of current 0x%x' % (next_key, end))
        for remove in remove_items:
            del self.malloc_dict[remove]



    def mergeMalloc(self):
        retval = {}
        did_something = True
        key_list = list(sorted(self.malloc_dict))
        last_addr = None
        ''' each malloc'd address, sorted '''
        for addr in sorted(self.malloc_dict):
            end = last_addr
            if last_addr is not None: 
                end = last_addr+retval[last_addr]+32
                if addr < end:
                    ''' adjacent to previous malloc ''' 
                    size = (addr - last_addr) + self.malloc_dict[addr]
                    retval[last_addr] = size
                    new_end = last_addr + size
                    self.lgr.debug('mergeMalloc, adjacent, extend range now 0x%x to 0x%x' % (last_addr, new_end))
                else:
                    if last_addr is not None:
                        new_end = addr + self.malloc_dict[addr]
                        self.lgr.debug('mergeMalloc new addr 0x%x not less than 0x%x.  Add range 0x%x to 0x%x' % (addr, end, addr, new_end))
                    ''' either first, or not adjacent '''
                    retval[addr] = self.malloc_dict[addr]
                    last_addr = addr
            else:
                retval[addr] = self.malloc_dict[addr]
                last_addr = addr
                
        return retval 

    class MemStuff():
        def __init__(self, ret_addr, fun, called_from_ip, ret_addr_addr):
            self.ret_addr = ret_addr
            self.fun = fun
            ''' sp of location of return address '''
            self.ret_addr_addr = ret_addr_addr
            self.called_from_ip = called_from_ip

    def funPrecidence(self, fun):
        fun_precidence = mem_funs.index(fun)
        if fun_precidence < mem_funs.index('LOWEST'):
            fun_precidence = 0 
        return fun_precidence
    
    def memsomething(self, frames, local_mem_funs, st):
        ''' Is there a call to a memcpy'ish function, or a user iterator, in the last few frames? If so, return the return address '''
        ''' Will iterate through the frames backwards, looking for the highest level function'''
        mem_prefixes = ['isoc99_', '.__', '___', '__', '._', '_', '.', 'j_']
        retval = None
        max_precidence = -1
        max_index = len(frames)-1
        #self.lgr.debug('memsomething begin, max_index %d' % (max_index))
        outer_index = None
        prev_fun = None
        for i in range(max_index, -1, -1):
            frame = frames[i]
            if frame.fun_addr is None:
                #self.lgr.debug('dataWatch memsomething frame %d fun_addr is None' % i)
                frame.fun_addr = self.ida_funs.getFun(frame.ip)
            if frame.fun_addr is None:
                #self.lgr.debug('dataWatch memsomething frame %d ip: 0x%x fun_addr NONE instruct is %s' % (i, frame.ip, frame.instruct))
                pass
            else:
                #self.lgr.debug('dataWatch memsomething frame %d ip: 0x%x fun_addr 0x%x instruct is %s' % (i, frame.ip, frame.fun_addr, frame.instruct))
                pass
            if frame.instruct is not None:
                fun = None
                if frame.fun_name is not None:
                    fun = frame.fun_name
                    if '@' in frame.fun_name:
                        fun = frame.fun_name.split('@')[0]
                        try:
                            fun_hex = int(fun, 16) 
                            if self.ida_funs is not None:
                                fun_name = self.ida_funs.getName(fun_hex)
                                #self.lgr.debug('looked for fun for 0x%x got %s' % (fun_hex, fun_name))
                                if fun_name is not None:
                                    fun = fun_name
                            else:
                                self.lgr.debug('No ida_funs')
                        except ValueError:
                            pass
                    for pre in mem_prefixes:
                        if fun.startswith(pre):
                            fun = fun[len(pre):]
                            #self.lgr.debug('found memsomething prefix %s, fun now %s' % (pre, fun))
                    if fun not in local_mem_funs and fun.startswith('v'):
                        fun = fun[1:]
                #self.lgr.debug('dataWatch memsomething fun is %s' % fun)
                if fun is not None and fun == prev_fun:
                    self.lgr.debug('dataWatch memsomething repeated fun is %s  -- skip it' % fun)
                    continue
                else:
                    prev_fun = fun
                
                if fun in local_mem_funs or self.user_iterators.isIterator(frame.fun_addr):
                    if fun in local_mem_funs:
                        #self.lgr.debug('fun in local_mem_funs %s' % fun)
                        fun_precidence = self.funPrecidence(fun)
                        if fun_precidence == 0 and i > 3:
                            #self.lgr.debug('dataWatch memsomething i is %d and precidence %d, bailing' % (i, fun_precidence))
                            continue
                    if self.user_iterators.isIterator(frame.fun_addr):
                        #self.lgr.debug('fun is iterator 0x%x' % frame.fun_addr) 
                        fun_precidence = 999
                    #self.lgr.debug('dataWatch memsomething, is %s, frame: %s' % (fun, frame.dumpString()))
                    if fun_precidence < max_precidence:
                        self.lgr.debug('dataWatch memsomething precidence %d less than current max %d, skip it' % (fun_precidence, max_precidence))
                        continue
                    max_precidence = fun_precidence
                    if frame.ret_addr is not None:
                        ret_addr = frame.ret_addr
                    elif frame.sp > 0 and i != 0:
                        ''' TBD poor assumption about sp pointing to the return address?  have we made this so, arm exceptions? '''
                        ret_addr = self.mem_utils.readPtr(self.cpu, frame.sp)
                        #self.lgr.debug('dataWatch memsomething assumption about sp being ret addr? set to 0x%x' % ret_addr)
                    else:
                        #self.lgr.error('memsomething sp is zero and no ret_addr?')
                        ret_addr = None
                    if ret_addr is not None:
                        #self.lgr.debug('dataWatch memsomething ret_addr 0x%x frame.ip is 0x%x' % (ret_addr, frame.ip))
                        if frame.lr_return:
                            addr_of_ret_addr = None
                        elif frame.ret_to_addr is not None:
                            addr_of_ret_addr = frame.ret_to_addr
                            #self.lgr.debug('datawatch memsomething using ret_to_addr from frame of 0x%x' % frame.ret_to_addr)
                        else:
                            addr_of_ret_addr = frame.sp
                            #self.lgr.debug('datawatch memsomething using ret_to_addr from SP of 0x%x' % frame.sp)
                        retval = self.MemStuff(ret_addr, fun, frame.ip, addr_of_ret_addr)
                        break 
                else:
                    #if frame.fun_addr is None:
                    #    self.lgr.debug('no soap, fun fun_addr is NONE') 
                    #else:
                    #    self.lgr.debug('no soap, fun is <%s> fun_addr 0x%x' % (fun, frame.fun_addr))
                    pass
        return retval

    def getMarkCopyOffset(self, address):
         return self.watchMarks.getMarkCopyOffset(address)

    def getCopyMark(self):
        retval =  self.watchMarks.getCopyMark()
        latest_cycle = self.watchMarks.latestCycle()
        call_cycle = self.watchMarks.getCallCycle()
        if retval is None and latest_cycle is not None and call_cycle is not None:
            if self.pending_call and self.cpu.cycles > latest_cycle and self.cpu.cycles > call_cycle:
                self.lgr.debug('dataWatch getCopyMark pending was %s ' % self.mem_something.fun)
                ''' We may be in a copy and died therein '''
                strcpy = False
                if self.mem_something.fun == 'strcpy':
                    strcpy = True
                retval = self.watchMarks.copy(self.mem_something.src, self.mem_something.dest, self.mem_something.count, None, None, strcpy=strcpy)
        return retval
        
    def readCount(self):
        return self.watchMarks.readCount()   
    def whichRead(self):
        return self.watchMarks.whichRead()   

    def pickleit(self, name):
        self.watchMarks.pickleit(name)

    def saveJson(self, fname, packet=1):
        self.watchMarks.saveJson(fname, packet=packet)

    def getMarkFromIndex(self, index):
        return self.watchMarks.getMarkFromIndex(index)

    def getTotalRead(self):
        return self.total_read

    def setMaxMarks(self, marks):
        self.max_marks = marks
