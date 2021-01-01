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
mem_funs = ['memcpy','memmove','memcmp','strcpy','strcmp','strncmp', 'xmlStrcmp', 'strncpy', 'mempcpy', 
            'j_memcpy', 'strchr', 'strdup', 'memset', 'sscanf', 'strlen', 
            'xmlParseFile', 'xml_parse', 'xmlGetProp', 'inet_addr', 'FreeXMLDoc', 'GetToken']
class DataWatch():
    ''' Watch a range of memory and stop when it is read.  Intended for use in tracking
        reads to buffers into which data has been read, e.g., via RECV. '''
    def __init__(self, top, cpu, page_size, context_manager, mem_utils, task_utils, rev_to_call, param, lgr):
        ''' data watch structures reflecting what we are watching '''
        self.start = []
        self.length = []
        self.cycle = []
        self.read_hap = []
        self.top = top
        self.cpu = cpu
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
        self.ida_funs = None
        self.relocatables = None
        self.user_iterators = None
        self.other_starts = [] # buffer starts that were skipped because they were subranges.
        self.other_lengths = [] 
        self.retrack = False
        self.back_stop = backStop.BackStop(self.cpu, self.lgr)
        self.watchMarks = watchMarks.WatchMarks(mem_utils, cpu, lgr)
        back_stop_string = os.getenv('BACK_STOP_CYCLES')
        self.call_break = None
        self.call_hap = None
        ''' used to guess if we encountered a ghost frame '''
        self.cycles_was = 0
        self.undo_hap = None
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

    def setRange(self, start, length, msg=None, max_len=None, back_stop=True, recv_addr=None):
        self.lgr.debug('DataWatch set range start 0x%x length 0x%x back_stop: %r' % (start, length, back_stop))
        if not self.use_back_stop and back_stop:
            self.use_back_stop = True
            self.lgr.debug('DataWatch, backstop set, start data session')

        end = start+length
        overlap = False
        for index in range(len(self.start)):
            if self.start[index] != 0:
                this_end = self.start[index] + self.length[index]
                if self.start[index] <= start and this_end >= end:
                    overlap = True
                    self.lgr.debug('DataWatch setRange found overlap, skip it')
                    if start not in self.other_starts:
                        self.other_starts.append(start)
                        self.other_lengths.append(length)
                    break
                elif self.start[index] >= start and this_end <= end:
                    self.lgr.debug('DataWatch setRange found subrange, replace it')
                    self.start[index] = start
                    self.length[index] = length
                    overlap = True
                    break
                elif start == (this_end+1):
                    self.length[index] = self.length[index]+length
                    overlap = True
                    break
        if not overlap:
            self.start.append(start)
            self.length.append(length)
            self.cycle.append(self.cpu.cycles)
            self.lgr.debug('DataWatch adding start 0x%x cycle 0x%x' % (start, self.cpu.cycles))
        if msg is not None:
            fixed = unicode(msg, errors='replace')
            # TBD why max_len and not count???
            self.watchMarks.markCall(fixed, max_len, recv_addr, length)

    def close(self, fd):
        ''' called when FD is closed and we might be doing a trackIO '''
        eip = self.top.getEIP(self.cpu)
        msg = 'closed FD: %d' % fd
        self.watchMarks.markCall(msg, None, None)
        

    def watch(self, show_cmp=False, break_simulation=None, i_am_alone=False):
        self.lgr.debug('DataWatch watch show_cmp: %r cpu: %s' % (show_cmp, self.cpu.name))
        self.show_cmp = show_cmp         
        if break_simulation is not None:
            self.break_simulation = break_simulation         
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
            
               
    def stopWatch(self, break_simulation=None): 
        self.lgr.debug('dataWatch stopWatch')
        for index in range(len(self.start)):
            if self.start[index] == 0:
                continue
            if index < len(self.read_hap):
                if self.read_hap[index] is not None:
                    self.context_manager.genDeleteHap(self.read_hap[index])
            else:
                self.lgr.debug('dataWatch stopWatch index %d not in read_hap len is %d ' % (index, len(self.read_hap)))
        del self.read_hap[:]
        if break_simulation is not None: 
            self.break_simulation = break_simulation
            self.lgr.debug('DataWatch stopWatch break_simulation %r' % break_simulation)
        if self.return_hap is not None:
            self.context_manager.genDeleteHap(self.return_hap)
            self.return_hap = None
      
        if self.back_stop is not None:
            self.back_stop.clearCycle()
    
    def kernelReturnHap(self, addr, third, forth, memory):
        self.context_manager.genDeleteHap(self.return_hap)
        eax = self.mem_utils.getRegValue(self.cpu, 'syscall_ret')
        self.lgr.debug('kernelReturnHap, retval 0x%x  addr: 0x%x' % (eax, addr))
        dum_cpu, cur_addr, comm, pid = self.task_utils.currentProcessInfo(self.cpu)
        frame, cycles = self.rev_to_call.getRecentCycleFrame(pid)
        self.watchMarks.kernel(addr, eax, frame)
        self.watch()

    def kernelReturn(self, addr):
        cell = self.top.getCell()
        proc_break = self.context_manager.genBreakpoint(cell, Sim_Break_Linear, Sim_Access_Execute, self.param.arm_ret, 1, 0)
        self.return_hap = self.context_manager.genHapIndex("Core_Breakpoint_Memop", self.kernelReturnHap, addr, proc_break, 'memcpy_return_hap')
        '''
        if self.cpu.architecture == 'arm':
            cell = self.top.getCell()
            proc_break = self.context_manager.genBreakpoint(cell, Sim_Break_Linear, Sim_Access_Execute, self.param.arm_ret, 1, 0)
            self.return_hap = self.context_manager.genHapIndex("Core_Breakpoint_Memop", self.kernelReturnHap, addr, proc_break, 'memcpy_return_hap')
        else:
            self.lgr.debug('Only ARM kernel return handled for now') 
            self.watch()
        '''
       
    class MemSomething():
        def __init__(self, fun, ret_ip, src, dest, count, called_from_ip, op_type, length, start, run=False): 
            self.fun = fun
            self.ret_ip = ret_ip
            self.src = src
            self.dest = dest
            self.the_string = None
            self.count = count
            self.called_from_ip = called_from_ip
            ''' used for finishReadHap '''
            self.op_type = op_type
            self.length = length
            self.start = start
            self.dest_list = []
            ''' used for file tracking, e.g., if xmlParse '''
            self.run = run
     
    def startUndoAlone(self, mem_something):
        self.undo_hap = SIM_hap_add_callback("Core_Simulation_Stopped", self.undoHap, mem_something)
        self.watchMarks.undoMark()
        SIM_break_simulation('undo it')
 
    def returnHap(self, mem_something, third, forth, memory):
        ''' should be at return from a memsomething.  see  getMemParams for gathering of parameters'''
        if self.return_hap is None:
            return
        if self.cpu.cycles < self.cycles_was:
            self.lgr.debug('dataWatch returnHap suspect a ghost frame, returned from assumed memsomething, but cycles less than when we read the data')
            SIM_run_alone(self.startUndoAlone, mem_something)
            return
        eip = self.top.getEIP(self.cpu)
        self.lgr.debug('returnHap should be at return from memsomething, eip 0x%x cycles: 0x%x' % (eip, self.cpu.cycles))
        self.context_manager.genDeleteHap(self.return_hap)
        self.return_hap = None
        self.top.restoreDebugBreaks(was_watching=True)
        if mem_something.fun == 'memcpy' or mem_something.fun == 'mempcpy' or \
           mem_something.fun == 'j_memcpy' or mem_something.fun == 'memmove':
            self.lgr.debug('dataWatch returnHap, return from %s src: 0x%x dest: 0x%x count %d ' % (mem_something.fun, mem_something.src, 
                   mem_something.dest, mem_something.count))
            self.setRange(mem_something.dest, mem_something.count, None) 
            buf_start = self.findRange(mem_something.src)
            if buf_start is None:
                self.lgr.error('dataWatch buf_start for 0x%x is none?' % (mem_something.src))
            self.watchMarks.copy(mem_something.src, mem_something.dest, mem_something.count, buf_start)
        elif mem_something.fun == 'memcmp':
            buf_start = self.findRange(mem_something.dest)
            self.watchMarks.compare(mem_something.fun, mem_something.dest, mem_something.src, mem_something.count, buf_start)
            self.lgr.debug('dataWatch returnHap, return from %s compare: 0x%x  to: 0x%x count %d ' % (mem_something.fun, mem_something.src, 
                   mem_something.dest, mem_something.count))
        elif mem_something.fun in ['strcmp', 'strncmp', 'xmlStrcmp']: 
            buf_start = self.findRange(mem_something.dest)
            self.watchMarks.compare(mem_something.fun, mem_something.dest, mem_something.src, mem_something.count, buf_start)
            self.lgr.debug('dataWatch returnHap, return from %s  0x%x  to: 0x%x count %d ' % (mem_something.fun, 
                   mem_something.src, mem_something.dest, mem_something.count))
        elif mem_something.fun == 'strchr':
            buf_start = self.findRange(mem_something.dest)
            self.watchMarks.strchr(mem_something.dest, mem_something.the_chr, mem_something.count)
            self.lgr.debug('dataWatch returnHap, return from %s strchr 0x%x  to: 0x%x count %d ' % (mem_something.fun, 
                   mem_something.src, mem_something.the_chr, mem_something.count))
        elif mem_something.fun == 'strcpy':
            self.lgr.debug('dataWatch returnHap, strcpy return from %s src: 0x%x dest: 0x%x count %d ' % (mem_something.fun, mem_something.src, 
                   mem_something.dest, mem_something.count))
            self.setRange(mem_something.dest, mem_something.count, None) 
            buf_start = self.findRange(mem_something.src)
            if buf_start is None:
                self.lgr.error('dataWatch buf_start for 0x%x is none?' % (mem_something.src))
            self.watchMarks.copy(mem_something.src, mem_something.dest, mem_something.count, buf_start)
        elif mem_something.fun == 'memset':
            self.setRange(0, 0, None) 
            self.lgr.debug('dataWatch returnHap, return from memset dest: 0x%x count %d ' % (mem_something.dest, mem_something.count))
            buf_start = self.findRange(mem_something.dest)
            self.watchMarks.memset(mem_something.dest, mem_something.count, buf_start)
        elif mem_something.fun == 'strdup':
            if self.cpu.architecture == 'arm':
                self.lgr.error('datawatch strdup not yet for arm')
                return
            
            mem_something.dest = self.mem_utils.getRegValue(self.cpu, 'eax')
            self.lgr.debug('dataWatch returnHap, strdup return from %s src: 0x%x dest: 0x%x count %d ' % (mem_something.fun, mem_something.src, 
                   mem_something.dest, mem_something.count))
            self.setRange(mem_something.dest, mem_something.count, None) 
            buf_start = self.findRange(mem_something.src)
            if buf_start is None:
                self.lgr.error('dataWatch buf_start for 0x%x is none?' % (mem_something.src))
            self.watchMarks.copy(mem_something.src, mem_something.dest, mem_something.count, buf_start)
        elif mem_something.fun == 'sscanf':
            eax = self.mem_utils.getRegValue(self.cpu, 'syscall_ret')
            param_count = self.mem_utils.getSigned(eax)
            self.lgr.debug('dataWatch returnHap, sscanf return from sscanf src 0x%x param_count %d' % (mem_something.src, param_count))
            if param_count > 0:
                for i in range(param_count):
                    self.setRange(mem_something.dest_list[i], mem_something.count, None) 
                    self.watchMarks.sscanf(mem_something.src, mem_something.dest_list[i], mem_something.count)
            else:
                self.lgr.debug('dataWatch returnHap sscanf returned error')
                self.watchMarks.sscanf(mem_something.src, None, None)
        elif mem_something.fun == 'strlen':
            self.lgr.debug('dataWatch returnHap, return from %s src: 0x%x count %d ' % (mem_something.fun, mem_something.src, 
                   mem_something.count))
            self.watchMarks.strlen(mem_something.src, mem_something.count)
        elif mem_something.fun == 'xmlGetProp':
            self.lgr.debug('dataWatch returnHap, return from %s string: %s count %d ' % (mem_something.fun, mem_something.the_string, 
                   mem_something.count))
            if self.cpu.architecture == 'arm':
                mem_something.dest = self.mem_utils.getRegValue(self.cpu, 'r0')
            else:
                mem_something.dest = self.mem_utils.readPtr(self.cpu, sp)
            
            self.watchMarks.xmlGetProp(mem_something.src, mem_something.count, mem_something.the_string, mem_something.dest)
        elif mem_something.fun == 'inet_addr':
            self.lgr.debug('dataWatch returnHap, return from %s IP: %s count %d ' % (mem_something.fun, mem_something.the_string, 
                   mem_something.count))
            self.watchMarks.inet_addr(mem_something.src, mem_something.count, mem_something.the_string)
        elif mem_something.fun == 'FreeXMLDoc':
            self.lgr.debug('dataWatch returnHap, return from %s' % (mem_something.fun))
            self.watchMarks.freeXMLDoc()
        elif mem_something.fun == 'xmlParseFile' or mem_something.fun == 'xml_parse':
            self.lgr.debug('dataWatch returnHap, return from %s' % (mem_something.fun))
            if self.cpu.architecture == 'arm':
                xml_doc = self.mem_utils.getRegValue(self.cpu, 'r0')
            else:
                sp = self.mem_utils.getRegValue(self.cpu, 'sp')
                xml_doc = self.mem_utils.readPtr(self.cpu, sp)

            self.top.stopTraceMalloc()
            self.me_trace_malloc = False
            self.mergeMalloc()
            tot_size = 0
            self.lgr.debug('xmlParse Malloc:')
            for addr in sorted(self.malloc_dict):
                self.lgr.debug('0x%x   0x%x' % (addr, self.malloc_dict[addr]))
                tot_size = tot_size + self.malloc_dict[addr]
                self.setRange(addr, self.malloc_dict[addr], None) 
            self.watchMarks.xmlParseFile(xml_doc, tot_size)
        elif mem_something.fun == 'GetToken':
            if self.cpu.architecture == 'arm':
                self.lgr.error('dataWatch GetToken not yet for arm')
            else:
                mem_something.dest = self.mem_utils.getRegValue(self.cpu, 'eax')
                mem_something.the_string = self.mem_utils.readString(self.cpu, mem_something.dest, 40)
            self.lgr.debug('dataWatch returnHap, return from %s token: %s' % (mem_something.fun, mem_something.the_string))
            self.watchMarks.getToken(mem_something.src, mem_something.dest, mem_something.the_string)
           

        elif mem_something.fun not in mem_funs:
            ''' assume iterator '''
            self.lgr.debug('dataWatch returnHap, return from iterator %s src: 0x%x ' % (mem_something.fun, mem_something.src))
            buf_start = self.findRange(mem_something.src)
            self.watchMarks.iterator(mem_something.fun, mem_something.src, buf_start)
        else:
            self.lgr.error('dataWatch returnHap no handler for %s' % mem_something.fun)
        #SIM_break_simulation('return hap')
        #return
        self.watch()


    def getMemParams(self, mem_something):
            ''' assuming we are a the call to a memsomething, get its parameters '''
            sp = self.mem_utils.getRegValue(self.cpu, 'sp')
            if mem_something.fun == 'memcpy' or mem_something.fun == 'memmove' or mem_something.fun == 'mempcpy' or mem_something.fun == 'j_memcpy': 
                if self.cpu.architecture == 'arm':
                    mem_something.dest = self.mem_utils.getRegValue(self.cpu, 'r0')
                    mem_something.src = self.mem_utils.getRegValue(self.cpu, 'r1')
                    mem_something.count = self.mem_utils.getRegValue(self.cpu, 'r2')
                else:
                    mem_something.dest = self.mem_utils.readPtr(self.cpu, sp)
                    mem_something.src = self.mem_utils.readPtr(self.cpu, sp+self.mem_utils.WORD_SIZE)
                    mem_something.count = self.mem_utils.readWord32(self.cpu, sp+2*self.mem_utils.WORD_SIZE)
                self.lgr.debug('getMemParams dest 0x%x  src 0x%x count 0x%x' % (mem_something.dest, mem_something.src, 
                    mem_something.count))
            elif mem_something.fun == 'memset':
                mem_something.src = None
                if self.cpu.architecture == 'arm':
                    mem_something.dest = self.mem_utils.getRegValue(self.cpu, 'r0')
                    mem_something.count = self.mem_utils.getRegValue(self.cpu, 'r2')
                else:
                    mem_something.dest = self.mem_utils.readPtr(self.cpu, sp)
                    mem_something.count = self.mem_utils.readWord32(self.cpu, sp+2*self.mem_utils.WORD_SIZE)
            elif mem_something.fun == 'memcmp':
                if self.cpu.architecture == 'arm':
                    mem_something.count = self.mem_utils.getRegValue(self.cpu, 'r2')
                    mem_something.src = self.mem_utils.getRegValue(self.cpu, 'r0')
                    mem_something.dest = self.mem_utils.getRegValue(self.cpu, 'r1')
                else:
                    mem_something.src = self.mem_utils.readPtr(self.cpu, sp)
                    mem_something.dest = self.mem_utils.readPtr(self.cpu, sp+self.mem_utils.WORD_SIZE)
                    mem_something.count = self.mem_utils.readWord32(self.cpu, sp+2*self.mem_utils.WORD_SIZE)
            elif mem_something.fun == 'strdup':
                mem_something.count = self.getStrLen(mem_something.src)        
            elif mem_something.fun == 'strcpy':
                mem_something.count = self.getStrLen(mem_something.src)        
                if self.cpu.architecture == 'arm':
                    mem_something.dest = self.mem_utils.getRegValue(self.cpu, 'r0')
                    ''' TBD this fails on buffer overlap, but that leads to crash anyway? '''
                    self.lgr.debug('getMemParams strcpy, src: 0x%x dest: 0x%x count(maybe): %d' % (mem_something.src, mem_something.dest, mem_something.count))
                else:
                    mem_something.dest = self.mem_utils.readPtr(self.cpu, sp)
            elif mem_something.fun in ['strcmp', 'strncmp', 'xmlStrcmp']: 
                if self.cpu.architecture == 'arm':
                    mem_something.dest = self.mem_utils.getRegValue(self.cpu, 'r0')
                    mem_something.src = self.mem_utils.getRegValue(self.cpu, 'r1')
                    if mem_something.fun == 'strncmp':
                        limit = self.mem_utils.getRegValue(self.cpu, 'r2')
                        mem_something.count = min(limit, self.getStrLen(mem_something.src))
                    else:
                        mem_something.count = self.getStrLen(mem_something.src)        

                    self.lgr.debug('getMemParams %s, src: 0x%x dest: 0x%x count: %d' % (mem_something.fun, mem_something.src, 
                         mem_something.dest, mem_something.count))
                else:
                    mem_something.src = self.mem_utils.readPtr(self.cpu, sp)
                    mem_something.dest = self.mem_utils.readPtr(self.cpu, sp+self.mem_utils.WORD_SIZE)
                    if mem_something.fun == 'strncmp':
                        limit = self.mem_utils.readPtr(self.cpu, sp+2*self.mem_utils.WORD_SIZE)
                        mem_something.count = min(limit, self.getStrLen(mem_something.src))
                    else:
                        mem_something.count = self.getStrLen(mem_something.src)        
            elif mem_something.fun == 'strchr':
                if self.cpu.architecture == 'arm':
                    mem_something.dest = self.mem_utils.getRegValue(self.cpu, 'r0')
                    mem_something.the_chr = self.mem_utils.getRegValue(self.cpu, 'r1')
                    self.lgr.debug('getMemParams strchr, src: 0x%x chr: %s count(maybe): %d' % (mem_something.src, mem_something.the_chr, mem_something.count))
                else:
                    mem_something.dest = self.mem_utils.readPtr(self.cpu, sp)
                    mem_something.the_chr = self.mem_utils.readPtr(self.cpu, sp+self.mem_utils.WORD_SIZE)
                ''' TBD fix to reflect strnchr? '''
                mem_something.count=1
            elif mem_something.fun == 'sscanf':
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
                        mem_something.dest_list.append(param) 
                    mem_something.src = self.mem_utils.getRegValue(self.cpu, 'r0')
                else:
                    for i in range(nparams):
                        offset = (i+2)*self.mem_utils.WORD_SIZE
                        param = self.mem_utils.readPtr(self.cpu, sp+offset)
                        mem_something.dest_list.append(param) 
                    mem_something.src = self.mem_utils.readPtr(self.cpu, sp)
                ''' TBD fix this '''
                mem_something.count = 1
            elif mem_something.fun == 'strlen':
                if self.cpu.architecture == 'arm':
                    mem_something.src = self.mem_utils.getRegValue(self.cpu, 'r0')
                else:
                    mem_something.src = self.mem_utils.readPtr(self.cpu, sp)
                mem_something.count = self.getStrLen(mem_something.src)        
            elif mem_something.fun == 'xmlGetProp':
                if self.cpu.architecture == 'arm':
                    mem_something.src = self.mem_utils.getRegValue(self.cpu, 'r1')
                else:
                    mem_something.src = self.mem_utils.readPtr(self.cpu, sp+self.mem_utils.WORD_SIZE)
                mem_something.count = self.getStrLen(mem_something.src)        
                mem_something.the_string = self.mem_utils.readString(self.cpu, mem_something.src, mem_something.count)
            elif mem_something.fun == 'inet_addr':
                if self.cpu.architecture == 'arm':
                    mem_something.src = self.mem_utils.getRegValue(self.cpu, 'r0')
                else:
                    mem_something.src = self.mem_utils.readPtr(self.cpu, sp)
                mem_something.count = self.getStrLen(mem_something.src)        
                mem_something.the_string = self.mem_utils.readString(self.cpu, mem_something.src, mem_something.count)
            elif mem_something.fun == 'GetToken':
                if self.cpu.architecture == 'arm':
                    mem_something.src = self.mem_utils.getRegValue(self.cpu, 'r0')
                else:
                    mem_something.src = self.mem_utils.readPtr(self.cpu, sp)

            elif mem_something.fun == 'FreeXMLDoc':
                mem_something.count = 0

            elif mem_something.fun == 'xmlParseFile' or mem_something.fun == 'xml_parse':
                self.me_trace_malloc = True
                self.top.traceMalloc()
                self.lgr.debug('getMemParams xml parse')
                 
            cell = self.top.getCell()
            ''' Assume we have disabled debugging in context manager while fussing with parameters. Thus breakpoints
                are set on the default context.  Make sure we are in the default context. '''
            self.context_manager.restoreDefaultContext()
            proc_break = self.context_manager.genBreakpoint(cell, Sim_Break_Linear, Sim_Access_Execute, mem_something.ret_ip, 1, 0)
            self.return_hap = self.context_manager.genHapIndex("Core_Breakpoint_Memop", self.returnHap, mem_something, proc_break, 'memcpy_return_hap')
            self.lgr.debug('getMemParams set hap on ret_ip at 0x%x context %s Now run!' % (mem_something.ret_ip, 
                 str(self.cpu.current_context)))
            SIM_run_command('c')

    def runToReturnAlone(self, mem_something):
        cell = self.top.getCell()
        proc_break = self.context_manager.genBreakpoint(cell, Sim_Break_Linear, Sim_Access_Execute, mem_something.ret_ip, 1, 0)
        self.return_hap = self.context_manager.genHapIndex("Core_Breakpoint_Memop", self.returnHap, mem_something, proc_break, 'memsomething_return_hap')
        if mem_something.run:
            SIM_run_command('c')

    def undoHap(self, mem_something, one, exception, error_string):
        
        if self.undo_hap is not None:
            SIM_hap_delete_callback_id("Core_Simulation_Stopped", self.undo_hap)
            self.undo_hap = None
            SIM_run_alone(self.undoAlone, mem_something)

    def undoAlone(self, mem_something):
            self.lgr.debug('undoAlone skip back to 0x%x' % self.save_cycle)
            if not self.skipToTest(self.save_cycle):
                self.lgr.error('undoAlone unable to skip to save cycle 0x%x, got 0x%x' % (self.save_cycle, self.cpu.cycles))
                return
            else:
                self.lgr.debug('skip done')
            eip = self.top.getEIP(self.cpu)
            dum_cpu, cur_addr, comm, pid = self.task_utils.currentProcessInfo(self.cpu)
            self.watch(i_am_alone=True)
            self.finishReadHap(mem_something.op_type, eip, mem_something.src, mem_something.length, mem_something.start, pid)
            self.lgr.debug('undoAlone would run forward, first restore debug context')
            self.context_manager.restoreDebugContext()
            SIM_run_command('c')

    def hitCallStopHap(self, mem_something, one, exception, error_string):
        ''' we are at the call to a memsomething, get the parameters '''
        if self.call_hap is not None:
            cycle_dif = self.cycles_was - self.cpu.cycles
            #self.lgr.debug('hitCallStopHap will delete hap %s cycle_dif 0x%x' % (str(self.call_hap), cycle_dif))
            SIM_hap_delete_callback_id("Core_Simulation_Stopped", self.call_hap)
            SIM_delete_breakpoint(self.call_break)
            self.stop_hap = None
        else:
            return
        eip = self.top.getEIP(self.cpu)
        ''' TBD dynamically adjust cycle_dif limit?  make exceptions for some calls, e.g., xmlparse? '''
        if eip != mem_something.called_from_ip or cycle_dif > 300000:
            if eip != mem_something.called_from_ip:
                self.lgr.debug('hitCallStopHap not stopped on expected call. Wanted 0x%x got 0x%x' % (mem_something.called_from_ip, eip))
            else:
                self.lgr.debug('hitCallStopHap stopped too far back cycle_dif 0x%x, assume a ghost frame' % cycle_dif)
            SIM_run_alone(self.undoAlone, mem_something)
        else:
            self.lgr.debug('dataWatch hitCallStopHap function %s call getMemParams at eip 0x%x' % (mem_something.fun, eip))
            SIM_run_alone(self.getMemParams, mem_something)
       
    def revAlone(self, dumb):
        ''' TBD why need to stop coverage?  should not hit any of those bp going backwards? '''
        #self.top.removeDebugBreaks(keep_coverage=False)
        self.top.removeDebugBreaks()
        self.cycles_was = self.cpu.cycles
        self.lgr.debug('revAlone now rev cycles_was: 0x%x' % self.cycles_was)
        SIM_run_command('rev')  

    def memstuffStopHap(self, mem_something, one, exception, error_string):
        ''' We had been in a memsomething and have stopped.  Set a break on the address 
            of the call to the function and another stop hap and reverse. '''
        if self.stop_hap is not None:
            self.lgr.debug('memstuffStopHap stopHap will delete hap %s' % str(self.stop_hap))
            SIM_hap_delete_callback_id("Core_Simulation_Stopped", self.stop_hap)
            self.stop_hap = None
        else:
            return
        self.lgr.debug('memstuffStopHap, reverse to call at ip 0x%x' % mem_something.called_from_ip)
        #SIM_run_alone(self.walkAlone, mem_something)
        phys_block = self.cpu.iface.processor_info.logical_to_physical(mem_something.called_from_ip, Sim_Access_Read)
        pcell = self.cpu.physical_memory
        self.call_break = SIM_breakpoint(pcell, Sim_Break_Physical, Sim_Access_Execute, phys_block.address, 1, 0)
        self.call_hap = SIM_hap_add_callback("Core_Simulation_Stopped", 
        	     self.hitCallStopHap, mem_something)
        ''' in case we chase ghost frames mimicking memsomething calls  and need to return '''
        self.save_cycle = self.cpu.cycles - 1
        self.lgr.debug('memStuffStopHap break %d set on IP of call 0x%x (phys 0x%x) and stop hap %d set save_cycle 0x%x, now reverse' % (self.call_break, 
           mem_something.called_from_ip, phys_block.address, self.call_hap, self.save_cycle))
        SIM_run_alone(self.revAlone, None)

    def getStrLen(self, src):
        addr = src
        done = False
        #self.lgr.debug('getStrLen from 0x%x' % src)
        while not done:
            v = self.mem_utils.readByte(self.cpu, addr)
            #self.lgr.debug('getStrLen got 0x%x from 0x%x' % (v, addr))
            if v == 0:
                done = True
            else:
                addr += 1
        return addr - src

    def handleMemStuff(self, mem_something):
        '''
        We are within a memcpy type function for which we believe we know the calling conventions.  However those values have been
        lost to the vagaries of the implementation by the time we hit the breakpoint.  We need to stop; Reverse to the call; record the parameters;
        set a break on the return; and continue.  We'll assume not too many instructions between us and the call, so manually walk er back.
        '''
        self.lgr.debug('handleMemStuff ret_addr 0x%x fun %s called_from_ip 0x%x' % (mem_something.ret_ip, mem_something.fun, mem_something.called_from_ip))
        if mem_something.fun not in mem_funs: 
            ''' assume it is a user iterator '''
            self.lgr.debug('handleMemStuff assume iterator, src: 0x%x ' % (mem_something.src))
            SIM_run_alone(self.runToReturnAlone, mem_something)
        else: 
            ''' walk backwards to the call, and get the parameters.  TBD, why not do same for strcpy and strcmp? '''
            self.stop_hap = SIM_hap_add_callback("Core_Simulation_Stopped", 
        	     self.memstuffStopHap, mem_something)
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
    
    
    def finishReadHap(self, op_type, eip, addr, length, start, pid, index=None):
        instruct = SIM_disassemble_address(self.cpu, eip, 1, 0)
        offset = addr - start
        cpl = memUtils.getCPL(self.cpu)
        if op_type == Sim_Trans_Load:
            self.lgr.debug('finishReadHap Data read from 0x%x within input buffer (offset of %d into buffer of %d bytes starting at 0x%x) pid:%d eip: 0x%x <%s> cycle:0x%x' % (addr, 
                    offset, length, start, pid, eip, instruct[1], self.cpu.cycles))
            msg = ('Data read from 0x%x within input buffer (offset of %d into %d bytes starting at 0x%x) eip: 0x%x' % (addr, 
                        offset, length, start, eip))
            self.context_manager.setIdaMessage(msg)
            self.watchMarks.dataRead(addr, start, length, self.getCmp())
            if self.break_simulation:
                SIM_break_simulation('DataWatch read data')

            if cpl == 0:
                if not self.break_simulation:
                    self.stopWatch()
                SIM_run_alone(self.kernelReturn, addr)
        elif cpl > 0:
            ''' is a write to a data watch buffer '''
            self.lgr.debug('finishReadHap Data written to 0x%x within input buffer (offset of %d into buffer of %d bytes starting at 0x%x) pid:%d eip: 0x%x' % (addr, offset, length, start, pid, eip))
            self.context_manager.setIdaMessage('Data written to 0x%x within input buffer (offset of %d into %d bytes starting at 0x%x) eip: 0x%x' % (addr, offset, length, start, eip))
            
            sp = self.mem_utils.getRegValue(self.cpu, 'sp')
            if addr > sp and index is not None:
                self.lgr.debug('finishReadHap remove watch for index %d' % index)
                ''' Assume reused stack buffer, remove it from watch '''
                self.start[index] = 0
            else:
                self.watchMarks.memoryMod(start, length, addr=addr)
            if self.break_simulation:
                ''' TBD when to treat buffer as unused?  does it matter?'''
                self.start[index] = 0
                SIM_break_simulation('DataWatch written data')
        elif self.retrack:
            self.lgr.debug('Data written by kernel to 0x%x within input buffer (offset of %d into buffer of %d bytes starting at 0x%x) pid:%d eip: 0x%x. In retrack, stop here.' % (addr, offset, length, start, pid, eip))
            #self.stopWatch()

    def readHap(self, index, third, forth, memory):
        ''' watched data has been read (or written) '''
        if self.prev_cycle is None:
            ''' first data read, start data session if doing coverage '''
            self.top.startDataSessions()
        if self.cpu.cycles == self.prev_cycle:
            return
        if len(self.read_hap) == 0:
            return
        self.prev_cycle = self.cpu.cycles

        dum_cpu, cur_addr, comm, pid = self.task_utils.currentProcessInfo(self.cpu)

        if self.back_stop is not None and not self.break_simulation and self.use_back_stop:
            self.back_stop.setFutureCycle(self.back_stop_cycles)
        else:
            self.lgr.debug('dataWatch readHap NO backstop set.  break sim %r  use back %r' % (self.break_simulation, self.use_back_stop))
        if index >= len(self.read_hap):
            self.lgr.error('dataWatch readHap pid:%d invalid index %d, only %d read haps' % (pid, index, len(self.read_hap)))
            return
        if self.read_hap[index] is None or self.read_hap[index] == 0:
            return
        op_type = SIM_get_mem_op_type(memory)
        addr = memory.logical_address
        eip = self.top.getEIP(self.cpu)
        self.lgr.debug('dataWatch readHap pid:%d index %d addr 0x%x eip 0x%x cycles: 0x%x' % (pid, index, addr, eip, self.cpu.cycles))
        if self.show_cmp:
            self.showCmp(addr)

        if self.break_simulation:
            self.lgr.debug('readHap will break_simulation, set the stop hap')
            self.stopWatch()
            SIM_run_alone(self.setStopHap, None)

        start, length = self.getStartLength(index, addr) 
        cpl = memUtils.getCPL(self.cpu)
        ''' If execution outside of text segment, check for mem-something library call '''
        #start, end = self.context_manager.getText()
        call_sp = None
        #self.lgr.debug('readHap eip 0x%x start 0x%x  end 0x%x' % (eip, start, end))
        if cpl != 0:
            if not self.break_simulation:
                ''' prevent stack trace from triggering haps '''
                self.stopWatch()
            self.lgr.debug('dataWatch get stack trace to look for memsomething')
            #st = self.top.getStackTraceQuiet(max_frames=3, max_bytes=100)
            st = self.top.getStackTraceQuiet(max_frames=6, max_bytes=100, mem_funs=mem_funs)
            if st is None:
                self.lgr.debug('stack trace is None, wrong pid?')
                return
            #self.lgr.debug('%s' % st.getJson()) 
            ''' look for memcpy'ish... TBD generalize '''
            mem_stuff = st.memsomething()
            if mem_stuff is not None:
                self.lgr.debug('DataWatch readHap ret_ip 0x%x called_from_ip is 0x%x' % (mem_stuff.ret_addr, mem_stuff.called_from_ip))
                ''' src is the referenced memory address by default ''' 
                mem_something = self.MemSomething(mem_stuff.fun, mem_stuff.ret_addr, addr, None, None, mem_stuff.called_from_ip, op_type, length, start)
                SIM_run_alone(self.handleMemStuff, mem_something)
                return
            else:
                self.lgr.debug('DataWatch readHap not memsomething, reset the watch')
                self.watch()
        self.finishReadHap(op_type, eip, addr, length, start, pid, index=index)
 
       
    def showWatch(self):
        for index in range(len(self.start)):
            if self.start[index] != 0:
                print('%d start: 0x%x  length: 0x%x' % (index, self.start[index], self.length[index]))
 
    def setBreakRange(self, i_am_alone=False):
        context = self.context_manager.getRESimContext()
        for index in range(len(self.start)):
            if self.start[index] == 0:
                #self.lgr.debug('DataWatch setBreakRange index %d is 0' % index)
                self.read_hap.append(None)
                continue
            ''' TBD should this be a physical bp?  Why explicit RESim context -- perhaps debugging_pid is not set while
                fussing with memsomething parameters? '''
            break_num = self.context_manager.genBreakpoint(context, Sim_Break_Linear, Sim_Access_Read | Sim_Access_Write, self.start[index], self.length[index], 0)
            end = self.start[index] + self.length[index] 
            eip = self.top.getEIP(self.cpu)
            #self.lgr.debug('DataWatch setBreakRange eip: 0x%x Adding breakpoint %d for %x-%x length %x index now %d' % (eip, break_num, self.start[index], end, self.length[index], index))
            self.read_hap.append(self.context_manager.genHapIndex("Core_Breakpoint_Memop", self.readHap, index, break_num, 'dataWatch'))
        if self.back_stop is not None and not self.break_simulation and self.use_back_stop:
            self.lgr.debug('dataWatch, setBreakRange call to setFutureCycle')
            self.back_stop.setFutureCycle(self.back_stop_cycles, now=i_am_alone)

    def stopHap(self, stop_action, one, exception, error_string):
        if stop_action is None or stop_action.hap_clean is None:
            self.lgr.error('dataWatch stopHap error, stop_action None?')
            return
        eip = self.top.getEIP(self.cpu)
        self.lgr.debug('dataWatch stopHap eip 0x%x cycle: 0x%x' % (eip, stop_action.hap_clean.cpu.cycles))

        if self.stop_hap is not None:
            self.lgr.debug('dataWatch stopHap will delete hap %s' % str(self.stop_hap))
            SIM_hap_delete_callback_id("Core_Simulation_Stopped", self.stop_hap)
            self.stop_hap = None
            ''' check functions in list '''
            self.lgr.debug('stopHap now run actions %s' % str(stop_action.flist))
            stop_action.run()
         
    def setStopHap(self, dumb):
        f1 = stopFunction.StopFunction(self.top.skipAndMail, [], nest=False)
        flist = [f1]
        hap_clean = hapCleaner.HapCleaner(self.cpu)
        stop_action = hapCleaner.StopAction(hap_clean, None, flist)
        self.stop_hap = SIM_hap_add_callback("Core_Simulation_Stopped", 
        	     self.stopHap, stop_action)
        self.lgr.debug('setStopHap set actions %s' % str(stop_action.flist))

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
                    #self.lgr.debug('findRange is 0x%x between 0x%x and 0x%x?' % (addr, self.start[index], end))
                    if addr >= self.start[index] and addr <= end:
                        retval = self.start[index]
                        break
        return retval

    def findRangeIndex(self, addr):
        for index in range(len(self.start)):
            if self.start[index] != 0:
                end = self.start[index] + self.length[index]
                self.lgr.debug('findRange is 0x%x between 0x%x and 0x%x?' % (addr, self.start[index], end))
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
            self.lgr.debug('DataWatch clear Watches, no cycle given')
            self.prev_cycle = None
        else:
            self.lgr.debug('DataWatch clear Watches cycle 0x%x' % cycle)
        self.stopWatch()
        self.break_simulation = True
        if cycle is None:
            del self.start[:]
            del self.length[:]
            del self.cycle[:]
            self.other_starts = []
            self.other_lengths = []
        elif cycle == -1:
            ''' at origin, assume not first retrack, keep first entry '''
            del self.start[1:]
            del self.length[1:]
            del self.cycle[1:]
            self.lgr.debug('clearWatches, left only first entry, start is 0x%x' % (self.start[0]))
            self.watchMarks.memoryMod(self.start[0], self.length[0])
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
                del self.cycle[index+1:]
                self.lgr.debug('clearWatches, reset list, index %d start[%d] is 0x%x' % (index, index, self.start[index]))
                self.watchMarks.memoryMod(self.start[index], self.length[index])
                

    def setIdaFuns(self, ida_funs):
        self.lgr.debug('DataWatch setIdaFuns')
        self.ida_funs = ida_funs

    def setRelocatables(self, relocatables):
        self.lgr.debug('DataWatch setRelocatables')
        self.relocatables = relocatables

    def setCallback(self, callback):
        ''' what should backStop call when no activity for N cycles? '''
        self.back_stop.setCallback(callback)

    def showWatchMarks(self):
        self.watchMarks.showMarks()

    def saveWatchMarks(self, fpath):
        self.watchMarks.saveMarks(fpath)

    def tagIterator(self, index):
        ''' Call from IDA Client to collapse a range of data references into the given watch mark index ''' 
        self.lgr.debug('DataWatch tagIterator')
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

    def setRetrack(self, value):
        self.lgr.debug('DataWatch setRetrack %r' % value)
        self.retrack = value
        if value:
            self.use_back_stop = True

    def fileStopHap(self):
        self.lgr.debug('fileStopHap')
        #if not self.skipToTest(self.cpu.cycles+1):
        #        self.lgr.error('fileStopHap unable to skip to next cycle got 0x%x' % (self.cpu.cycles))
        #        return
        st = self.top.getStackTraceQuiet(max_frames=16, max_bytes=100, mem_funs=['xmlParseFile'])
        if st is None:
            self.lgr.debug('stack trace is None, wrong pid?')
            return
        ''' look for memcpy'ish... TBD generalize '''
        mem_stuff = st.memsomething()
        if mem_stuff is not None:
            self.lgr.debug('mem_stuff function %s, ret_ip is 0x%x' % (mem_stuff.fun, mem_stuff.ret_addr))
            mem_something = self.MemSomething(mem_stuff.fun, mem_stuff.ret_addr, None, None, None, 
                mem_stuff.called_from_ip, None, None, None, run=True)
            self.break_simulation=False
            self.me_trace_malloc = True
            self.top.traceMalloc()
            SIM_run_alone(self.runToReturnAlone, mem_something)
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

    def trackIO(self, fd, callback, compat32):
        self.lgr.debug('DataWatch trackIO for fd %d' % fd)
        ''' first make sure we are not in the kernel on this FD '''
        read_calls = ['read', 'recv', 'recvfrom']
        plist = {}
        pid_list = self.context_manager.getThreadPids()
        tasks = self.task_utils.getTaskStructs()
        plist = {}
        for t in tasks:
            if tasks[t].pid in pid_list:
                plist[tasks[t].pid] = t 
        in_kernel = False
        frame = None
        cycles = None
        for pid in plist:
            t = plist[pid]
            if tasks[t].state > 0:
                frame, cycles = self.rev_to_call.getRecentCycleFrame(pid)
                if frame is not None:
                    call = self.task_utils.syscallName(frame['syscall_num'], compat32)
                    if call in read_calls and frame['param1'] == fd:
                        print('pid %d in kernel on %s of fd %d' % (pid, call, fd))
                        in_kernel = True
                        break
                    elif call == 'select' or call == '_newselect':
                        select_info = frame['select']
                        self.lgr.debug('DataWatch trackIO check select for %d' % fd)
                        if select_info.hasFD(fd):
                            print('pid %d in kernel on select including %d' % (pid, fd))
                            in_kernel = True
                            break
                    elif call == 'socketcall' and 'ss' in frame:
                        socket_callnum = frame['param1']
                        socket_callname = net.callname[socket_callnum].lower()
                        ss = frame['ss']
                        if ss.fd == fd:
                            print('pid %d in kernel on %s of fd %d' % (pid, socket_callname, fd)) 
                            in_kernel = True
                            break
       
        if in_kernel:
            self.lgr.debug('DataWatch trackIO in kernel, do skip')
            self.top.removeDebugBreaks()
            cmd = 'skip-to cycle = %d ' % (cycles)
            SIM_run_command(cmd)
            print('skipped back to 0x%x' % cycles)
            self.lgr.debug('DataWatch trackIO skipped to 0x%x' % self.cpu.cycles)
            self.top.restoreDebugBreaks(was_watching=True)
        

        self.lgr.debug('DataWatch trackIO call watch')
        self.watch(break_simulation=False)
        ''' what to do when backstop is reached (N cycles with no activity '''
        self.setCallback(callback)

    def firstBufferAddress(self):
        return self.watchMarks.firstBufferAddress()

    def goToRecvMark(self):
        index = self.watchMarks.firstBufferIndex()
        if index is not None:
            self.lgr.debug('dataWatch goToRecvMark, index %d' % index)
            self.goToMark(index)
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

    def mergeMalloc(self):
        did_something = True
        remove_items = {}
        key_list = list(sorted(self.malloc_dict))
        while did_something:
            did_something = False
            for addr in sorted(self.malloc_dict):
                try:
                    next_key = key_list[key_list.index(addr)+1]
                except (ValueError, IndexError):
                    continue
                end = addr + self.malloc_dict[addr] + 24
                if next_key < end:
                    #self.lgr.debug('mergeMalloc addr 0x%x end 0x%x  next_addr 0x%x' % (addr, end, next_key))
                    if addr in remove_items: 
                        parent_addr = remove_items[addr]
                        self.malloc_dict[parent_addr] = self.malloc_dict[parent_addr]+self.malloc_dict[next_key] 
                        remove_items[next_key] = remove_items[addr]
                    else:
                        self.malloc_dict[addr] = self.malloc_dict[addr]+self.malloc_dict[next_key] 
                        remove_items[next_key] = addr
        for remove in remove_items:
            del self.malloc_dict[remove]
