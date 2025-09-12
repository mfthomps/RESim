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
import cli
import pageUtils
import taskUtils
import stopFunction
import hapCleaner
import decode
import decodeArm
import decodePPC32
import elfText
import memUtils
import watchMarks
import backStop
import resimUtils
import resimSimicsUtils
import readLibTrack
import net
import os
import sys
import pickle
import traceback
import reWatch
import clibFuns
import appendCharReturns
from resimHaps import *
import disableAndRun
import functionNoWatch
import dataWatchManager
import nullTestLoop
import defaultConfig
MAX_WATCH_MARKS = 1000
mem_funs = ['memcpy','memmove','memcmp','memchr', 'strcpy','strcmp','strncmp', 'strnicmp', 'strncasecmp', 'fnmatch', 'buffer_caseless_compare', 'strtok', 'strpbrk', 'strspn', 'strcspn', 
            'strcasecmp', 'strncpy', 'strlcpy', 'strtoul', 'String5toInt', 'string_strncmp', 'string_strnicmp', 'string_strlen',
            'strtol', 'strtoll', 'strtoq', 'atoi', 'mempcpy', 'wcscmp', 'mbscmp', 'mbscmp_l', 'trim', 'getopt',
            'j_memcpy', 'strchr', 'strrchr', 'strstr', 'strdup', 'memset', 'sscanf', 'strlen', 'LOWEST', 'glob', 'fwrite', 'IO_do_write', 'xmlStrcmp',
            'xmlGetProp', 'inet_addr', 'inet_ntop', 'FreeXMLDoc', 'GetToken', 'xml_element_free', 'xml_element_name', 'xml_element_children_size', 'xmlParseFile', 'xml_parse',
            'xmlParseChunk', 'xmlrpc_base64_decode', 'printf', 'fprintf', 'sprintf', 'vsnprintf', 'vfprintf', 'snprintf', 'asprintf', 'vasprintf', 'fputs', 'syslog', 'getenv', 'regexec', 
            'string_chr', 'string_std', 'string_basic_char', 'string_basic_std', 'string_win_basic_char', 'basic_istringstream', 'string', 'str', 'ostream_insert', 'regcomp', 
            'replace_chr', 'replace_std', 'replace', 'replace_safe', 'append_chr_n', 'assign_chr', 'compare_chr', 'charLookup', 'charLookupX', 'charLookupY', 'output_processor',
            'UuidToStringA', 'fgets', 'WSAAddressToStringA', 'win_streambuf_getc', 'realloc', 'String16fromAscii_helper', 'QStringHash', 'String5split', 
            'String14compare_helper', 'String14compare_helper_latin',
            'String6toUtf8', 'String3mid', 'String3arg', 'String4left', 'Stringa', 'StringS1_eq','Stringeq', 'ByteArray5toInt', 'xxJsonObject5value', 'xxJsonObjectix', 'xxJsonValueRefa']
''' Functions whose data must be hit, i.e., hitting function entry point will not work '''
funs_need_addr = ['ostream_insert', 'charLookup', 'charLookupX', 'charLookupY']
#no_stop_funs = ['xml_element_free', 'xml_element_name']
no_stop_funs = ['xml_element_free', 'JsonObject5value', 'JsonObjectix', 'JsonValueRefa']
''' made up functions that could not have ghost frames?'''
no_ghosts = ['charLookup', 'charLookupX', 'charLookupY']
''' TBD confirm end_cleanup is a good choice for free'''
free_funs = ['free_ptr', 'free', 'regcomp', 'destroy', 'delete', 'end_cleanup', 'erase', 'new', 'DTDynamicString_', 'malloc', 'memset', 'ArrayData10deallocate']
# remove allocators, should not get that as windows function
allocators = ['string_basic_windows', 'malloc', 'ostream_insert', 'create']
char_ring_functions = ['ringqPutc']
mem_copyish_functions = ['memcpy', 'mempcpy', 'j_memcpy', 'memmove', 'memcpy_xmm']
reg_return_funs = ['win_streambuf_getc']
#missed_deallocate = ['String6toUtf8', 'String16fromAscii_helper']
missed_deallocate = []
for fun in mem_funs:
    if fun not in mem_copyish_functions:
        missed_deallocate.append(fun)
class MemSomething():
    def __init__(self, fun, fun_addr, addr, ret_ip, src, dest, called_from_ip, op_type, length, start, ret_addr_addr=None, run=False, trans_size=None, frames=[]):
            self.fun = fun
            self.fun_addr = fun_addr
            self.addr = addr
            self.ret_ip = ret_ip
            self.src = src
            self.dest = dest
            self.the_string = None
            self.the_chr = None
            self.called_from_ip = called_from_ip
            self.trans_size = trans_size
            # meaning varies. poor name'''
            self.ret_addr_addr = ret_addr_addr
            # used for finishReadHap '''
            self.op_type = op_type
            self.length = length
            # may be used to identify the start of a memcpy buffer, which may be less than src '''
            self.start = start
            self.frames = frames
            self.dest_list = []
            # used for file tracking, e.g., if xmlParse '''
            self.run = run
            # was memcpy length beyond our buffer?'''
            self.truncated = None
            self.pos = None
            self.re_watch = None
            # special case of multiple watch buffers in one memcpy
            self.multi_index_list = []
 

class MemStuff():
    def __init__(self, ret_addr, fun, fun_addr, called_from_ip, ret_addr_addr, frames=[]):
        self.ret_addr = ret_addr
        self.fun = fun
        self.fun_addr = fun_addr
        ''' sp of location of return address '''
        self.ret_addr_addr = ret_addr_addr
        self.called_from_ip = called_from_ip
        self.frames=frames

class DataWatch():
    ''' Watch a range of memory and stop when it is read.  Intended for use in tracking
        reads to buffers into which data has been read, e.g., via RECV. '''
    def __init__(self, top, cpu, cell_name, page_size, context_manager, mem_utils, task_utils, rev_to_call, param, run_from_snap, 
                 backstop, compat32, comp_dict, so_map, reverse_mgr, lgr, backstop_cycles=None):
        ''' data watch structures reflecting what we are watching '''
        self.rev_to_call = rev_to_call
        self.top = top
        self.cpu = cpu
        self.cell_name = cell_name
        self.param = param
        self.context_manager = context_manager
        self.mem_utils = mem_utils
        self.task_utils = task_utils
        self.lgr = lgr
        self.compat32 = compat32
        self.page_size = page_size
        self.backstop = backstop
        self.comp_dict = comp_dict
        self.so_map = so_map
        self.reverse_mgr = reverse_mgr
        self.run_from_snap = run_from_snap
        self.buffer_offset = None
        self.buffer_length = None
        self.finish_check_move_hap = None
        self.watchMarks = watchMarks.WatchMarks(top, mem_utils, cpu, cell_name, run_from_snap, lgr)
        self.backstop_cycles = defaultConfig.backstopCycles()
        self.lgr.debug('dataWatch backstop_cycles %s' % self.backstop_cycles)
        read_loop_string = os.getenv('READ_LOOP_MAX')
        if read_loop_string is None:
            self.read_loop_max = 10000
        else:
            self.read_loop_max = int(read_loop_string)
        #lgr.debug('DataWatch init with backstop_cycles %d compat32: %r' % (self.backstop_cycles, compat32))
        if cpu.architecture.startswith('arm'):
            self.decode = decodeArm
        elif cpu.architecture == 'ppc32':
            self.decode = decodePPC32
            self.lgr.debug('dataWatch using decodePPC32')
        else:
            self.decode = decode
        self.readLib = readLibTrack.ReadLibTrack(cpu, self.mem_utils, 
                  self.context_manager, self, self.top, self.lgr)
        ''' ignore modify of ad-hoc buffer for same cycle '''
        self.move_cycle = 0
        self.move_cycle_max = 0
        self.fun_mgr = None
        ''' optimize parameter gathering without having to reverse. Keyed by function and eip to handle multiple instances of sameish functions '''
        self.mem_fun_entries = {}
        self.added_mem_fun_entry = False

        ''' limit number of marks gathered '''
        self.max_marks = 2000
        self.resetState()

        ''' hack to ignore reuse of fgets buffers if reading stuff we don't care about '''
        self.recent_fgets = None
        self.recent_reused_index=None
        ''' control trace of malloc calls, e.g., within xml parsing '''
        self.me_trace_malloc = False

        self.save_cycle = None
        #self.loadFunEntryPickle(run_from_snap)

        ''' ring buffers for characters copied via char_ring_functions '''
        self.ring_char_entry = {}
        self.ring_char_hap = {}
        self.append_char_returns = None
        if 'APPEND_CHAR_RETURNS' in comp_dict:
            def_file = comp_dict['APPEND_CHAR_RETURNS']
            self.append_char_returns = appendCharReturns.AppendCharReturns(top, self, cpu, def_file, cell_name, mem_utils, context_manager, lgr)
        self.ignore_addr_list = []
        # TBD change these to physical addresses?
        if 'IGNORE_ADDR_FILE' in comp_dict:
            ignore_file = comp_dict['IGNORE_ADDR_FILE']
            self.ignoreAddrList(ignore_file)

        self.function_no_watch = None
        self.callback = None
        self.last_byteswap = 0
        self.stopped = False
        # TBD multithread?
        self.strtok_ptr = None
        self.ignore_entry_cycle = None

    def resetState(self):
        self.lgr.debug('resetState')
        self.start = []
        self.length = []
        self.hack_reuse = []
        self.cycle = []
        self.mark = []
        self.read_hap = []
        self.range_cr3 = []
        self.phys_start = []
        self.linear_breaks = []
        self.show_cmp = False
        self.break_simulation = True
        self.return_break = None
        self.return_hap = None
        self.kernel_return_hap = []
        # for debugging multiple breaks on same address'''
        self.prev_cycle = None
        self.prev_index = None
        # for guessing if stack buffer is being re-used '''
        self.prev_read_cycle = 0
        self.other_starts = [] # buffer starts that were skipped because they were subranges.
        self.other_lengths = [] 
        self.retrack = False
        self.call_break = None
        self.call_hap = None
        self.call_stop_hap = None
        self.mem_something = None
        # used to guess if we encountered a ghost frame '''
        self.cycles_was = 0
        self.undo_hap = None
        # Do not set backstop until first read, otherwise accept followed by writes will trigger it. '''
        self.use_backstop = False
        
        self.malloc_dict = {}
        self.pending_call = False
        self.ghost_stop_hap = None
        # don't set backstop on reads of these addresses, e.g., for ioctl '''
        self.no_backstop = []
        # support deletion of stack buffers after return from function '''
        self.stack_buffers = {}
        self.stack_buf_hap = {}
        self.stack_this = {}
        self.stack_this_hap = {}
        # watch for string destroy?'''
        self.destroy_entry = None
        self.destroy_hap = None
        # used by writeData when simulating responses from ioctl '''
        self.total_read = 0
        self.read_limit_trigger = None
        self.read_limit_callback = None
        # skip hit on ad_hoc buffer that was just added, and likely not yet executed.'''
        self.last_ad_hoc = []
        # sanitiy check for programs run amuck '''
        self.index_hits = {}

        self.disabled = True
        # expect readHap to be hit twice'''
        self.undo_pending = False

        self.transform_push_hap = None
        self.recent_fgets = None
        self.recent_reused_index=None

        # catch c++ string reuse/free '''
        self.string_this = {}

        # optimization to avoid hunt for memsomething on iterations '''
        self.not_mem_something = []

        self.re_watch_list = []

        self.stop_hap = None

        self.skip_entries = []

        # ad-hock clearing of smallish buffers through multiple writes'''
        self.hack_reuse_index = None
        self.hack_reuse = []

        # Modules whose haps need to be removed when tracking is stopped.  These will not be recreated '''
        self.remove_external_haps = []

        # optimization to avoid rechecking for ad-hoc copies on same addresses '''
        self.not_ad_hoc_copy = []
        # and to avoid stack trace '''
        self.is_ad_hoc_move = []

        # most recent frames from check for memsomething '''
        self.frames = []

        # recent record during check move for use in creating a watch mark if a potential obscure memcpy does not pan out '''
        self.move_stuff = None

        # Do not start tracking until this string is read '''
        self.commence_with = None
        self.commence_offset = 0

        # Optimization for loopy calls to memcpy from within clibish functions. '''
        self.recent_entry_bp = None

        # Distinguish multiple instances of dataWatch module, per page mapping '''
        self.comm = None
        self.data_watch_manager = None

        # Hack for funs like strnlen that might ref data beyond string end.
        # strlen 0x48e on string len 2 (3 including null) causes read of 8 bytes starting at 490
        # our watch buffer is at 494 and thus we think the strlen does not pertain to our buffer, but the breakpoint will be hit
        self.last_buffer_not_found = None

        self.call_trace = False
        # hack for function results being referenced in things like string16fromAscii
        self.last_fun_result = None

        # for handling broken stack parsing that leads to ghost frames
        self.recent_ghost_call_addr = None

        self.no_reset = False
        self.failed_comm_list = []

    def addFreadAlone(self, dumb):
        self.lgr.debug('dataWatch addFreadAlone')
        self.stop_hap = self.top.RES_add_stop_callback(self.memstuffStopHap, self.freadCallback)
        SIM_break_simulation('addFreadAlone')

    def checkFread(self, start, length):
        retval = False
        self.lgr.debug('dataWatch checkFread')
        st = self.top.getStackTraceQuiet(max_frames=20, max_bytes=1000)
        if st is None:
            self.lgr.debug('stack trace is None, wrong tid?')
            return False
        #self.lgr.debug('%s' % st.getJson()) 
        # look for memcpy'ish... TBD generalize 
        frames = st.getFrames(20)
        for f in frames:
            if f.fun_name == 'fread':
                ret_addr = f.ret_addr
                called_from = f.ip
                self.mem_something = MemSomething(f.fun_name, f.fun_addr, start, f.ret_addr, start, None, 
                      f.ip, None, length, start)
                self.lgr.debug('checkFread got fread')
                SIM_run_alone(self.addFreadAlone, None)
                retval = True
                break
        return retval

    def freadCallback(self, dumb, one, exception, error_string):
        self.lgr.debug('dataWatch freadCallback')
        #SIM_run_alone(self.context_manager.enableAll, None)
        SIM_run_command('enable-vmp') 
        if self.call_stop_hap is not None:
            cycle_dif = self.cycles_was - self.cpu.cycles
            #self.lgr.debug('hit CallStopHap will delete hap %d break %d cycle_dif 0x%x' % (self.call_hap, self.call_break, cycle_dif))
            self.top.RES_delete_stop_hap(self.call_stop_hap)
            #self.rmCallHap()
            if self.call_break is not None:
                self.reverse_mgr.SIM_delete_breakpoint(self.call_break)
                self.call_break = None
            self.call_stop_hap = None
        else:
            return
        sp = self.mem_utils.getRegValue(self.cpu, 'sp')
        start, dumb2, dumb = self.getCallParams(sp)
        self.lgr.debug('freadCallback call setRange with start 0x%x len %d' % (start, self.mem_something.length))
        msg = 'fread to 0x%x %d bytes' % (start, self.mem_something.length)
        self.setRange(start, self.mem_something.length, msg=msg)
        self.enableBreaks()
        self.backstop.setFutureCycle(self.backstop_cycles)
        #SIM_run_alone(SIM_run_command, 'c')
        SIM_run_alone(SIM_continue, 0)

    def enableBreaks(self, dumb=None):
        self.context_manager.enableAll()
        self.top.enableOtherBreaks()

    def disableBreaks(self, filter=None, direction=None):
        self.context_manager.disableAll(filter=filter, direction=direction)
        self.top.disableOtherBreaks()

    def isCopyMark(self, watch_mark):
        retval = False
        if watch_mark is not None:
            #self.lgr.debug('dataWatch isCopymark mark is %s' % str(watch_mark.mark))
            if isinstance(watch_mark.mark, watchMarks.CopyMark):
                if watch_mark.mark.sp is not None:
                    retval = True
            elif isinstance(watch_mark.mark, watchMarks.DataMark):
                #self.lgr.debug('dataWatch is data, ad hoc?, ')
                if watch_mark.mark.ad_hoc:
                    #self.lgr.debug('dataWatch ad hoc')
                    #if watch_mark.mark.sp is not None:
                    retval = True
        return retval

    def setStackBufHaps(self):
        for ret_to in self.stack_buffers:
            if ret_to not in self.stack_buf_hap and ret_to != -1:
                #self.lgr.debug('dataWatch setStackBufHaps add hap for eip 0x%x' % ret_to)
                proc_break = self.context_manager.genBreakpoint(None, Sim_Break_Linear, Sim_Access_Execute, ret_to, 1, 0)
                self.stack_buf_hap[ret_to] = self.context_manager.genHapIndex("Core_Breakpoint_Memop", self.stackBufHap, None, proc_break, 'stack_buf_hap')

    def setStackThisHaps(self):
        for ret_to in self.stack_this:
            if ret_to not in self.stack_this_hap:
                #self.lgr.debug('dataWatch setStackThisHaps add hap for eip 0x%x' % ret_to)
                proc_break = self.context_manager.genBreakpoint(None, Sim_Break_Linear, Sim_Access_Execute, ret_to, 1, 0)
                self.stack_this_hap[ret_to] = self.context_manager.genHapIndex("Core_Breakpoint_Memop", self.stackThisHap, None, proc_break, 'stack_this_hap')

    def stopStackThisHaps(self, immediate=False):
        for eip in self.stack_this_hap:
            #self.lgr.debug('dataWatch stopStackThisHaps delete hap for eip 0x%x' % eip)
            hap = self.stack_this_hap[eip]
            self.context_manager.genDeleteHap(hap, immediate=immediate)
        self.stack_this_hap = {}

    def manageStackThis(self, index_list, ret_to):
        if ret_to is not None:
            eip = self.top.getEIP(self.cpu)
            #self.lgr.debug('manageStackBuf ret_to 0x%x, eip 0x%x' % (ret_to, eip))
            if eip == ret_to:
                #self.lgr.error('manageStackBuf, eh????')
                return
            if ret_to not in self.stack_this:
                self.stack_this[ret_to] = []
                #self.lgr.debug('DataWatch manageStackThis stack buffer, set a break at 0x%x to delete this range on return' % ret_to)
                if ret_to not in self.stack_this_hap:
                    proc_break = self.context_manager.genBreakpoint(None, Sim_Break_Linear, Sim_Access_Execute, ret_to, 1, 0)
                    self.stack_this_hap[ret_to] = self.context_manager.genHapIndex("Core_Breakpoint_Memop", self.stackThisHap, None, proc_break, 'stack_this_hap')
                #else:
                #    self.lgr.debug('dataWatch manageStackThis 0x%x was already in the stack_this_hap, but was not in stack_this???' % ret_to)
            else:
                #self.lgr.debug('dataWatch manageStackBuf eip 0x%x already in stack_this, no hap set' % ret_to)
                pass
            for index in index_list:
                self.stack_this[ret_to].append(index)
            #self.lgr.debug('added index %d to stack_this[0x%x]' % (index, ret_to))
        else:
            pass

    def manageStackBuf(self, index_list, ret_to):
        if ret_to is not None:
            eip = self.top.getEIP(self.cpu)
            self.lgr.debug('manageStackBuf ret_to 0x%x, eip 0x%x' % (ret_to, eip))
            if eip == ret_to:
                self.lgr.error('manageStackBuf, eh????')
                return
            self.lgr.debug('DataWatch manageStackBuf stack buffer, set a break at 0x%x to delete this range on return' % ret_to)
            if ret_to not in self.stack_buffers:
                self.stack_buffers[ret_to] = []
                proc_break = self.context_manager.genBreakpoint(None, Sim_Break_Linear, Sim_Access_Execute, ret_to, 1, 0)
                self.stack_buf_hap[ret_to] = self.context_manager.genHapIndex("Core_Breakpoint_Memop", self.stackBufHap, None, proc_break, 'stack_buf_hap')
                self.lgr.debug('dataWatch manageStackBuf added stack_buf_hap[0x%x] %d' % (ret_to, self.stack_buf_hap[ret_to]))
            else:
                self.lgr.debug('dataWatch manageStackBuf eip 0x%x already in stack_buffers, no hap set' % ret_to)
                pass
            for index in index_list:
                self.stack_buffers[ret_to].append(index)
                self.lgr.debug('dataWatch manageStackBuf added index %d to stack_buffers[0x%x]' % (index, ret_to))
        else:
            pass
            self.lgr.debug('DataWatch manageStackBuf stack buffer, but return address was NONE, so buffer reuse will cause hits')

    def setRange(self, start, length, msg=None, max_len=None, backstop=True, recv_addr=None, no_backstop=False, 
                 watch_mark=None, fd=None, is_lib=False, no_extend=False, ignore_commence=False, data_stream=False, kbuffer=None):
        ''' set a data watch range.  fd only set for readish syscalls as a way to track bytes read when simulating internal kernel buffer '''
        ''' TBD try forcing watch to maxlen '''
        if self.disabled:
            self.lgr.debug('dataWatch setRange disabled')
            return
        if fd is not None and self.readLib is not None and self.readLib.inFun():
            ''' Within a read lib, ignore '''
            return
        if length == 0:
            self.lgr.error('dataWatch setRange called with length of zero')
            return
        self.lgr.debug('dataWatch setRange start 0x%x length 0x%x commence with %s ignore: %r' % (start, length, self.commence_with, ignore_commence))
        if self.commence_with is not None and not ignore_commence:
            match = True
            addr = start + self.commence_offset
            for c in self.commence_with:
                v = self.mem_utils.readByte(self.cpu, addr)
                if v is None or c != chr(v):
                    match = False
                    self.lgr.debug('dataWatch setRange failed commence. %x does not match %x' % (ord(c), v))
                    break
                else:
                    addr = addr + 1
            if match:
                self.commence_with = None
                if kbuffer is not None:
                    self.lgr.debug('dataWatch setRange commence matched, call kbuf and return.  kbuffer will skip back before call and do again.')
                    kbuffer.gotCommence()
                    return
                else:
                    self.lgr.debug('dataWatch setRange commence matched but no kbuffer')
            else:
                return

        self.lgr.debug('dataWatch setRange start 0x%x length 0x%x  len of self.start is %d' % (start, length, len(self.start)))
        # See returns above
        if len(self.start) == 0 and not self.top.isVxDKM(target=self.cell_name):
            # first range, set mmap syscall
            if not self.top.isWindows():
                # TBD what about windows?
                self.watchMmap()
            #self.watchExecve()
            self.top.trackThreads()
            dum_cpu, self.comm, tid = self.task_utils.curThread()
            self.lgr.debug('dataWatch FIRST range, set comm to %s' % self.comm)

        if fd is not None:
            self.total_read = self.total_read + length
            if self.read_limit_trigger is not None and self.total_read >= self.read_limit_trigger and self.read_limit_callback is not None:
                self.read_limit_callback()
                if len(self.start) == 0:
                    ''' TBD seems to only make sense on first read '''
                    #self.lgr.debug('dataWatch setRange over read limit, set retval to %d' % self.read_limit_trigger)
                    self.mem_utils.setRegValue(self.cpu, 'syscall_ret', self.read_limit_trigger)
                    length = self.read_limit_trigger    
                    if msg is not None:
                        msg = msg+' Count truncated to given %d bytes' % length
            # TBD note on why file read is treated differently?
            #if self.checkFread(start, length):
            #    self.lgr.debug('dataWatch setRange was fread, return for now')
            #    return
            if self.buffer_offset is not None:
                start = start + self.buffer_offset 
                length = self.buffer_length
                self.buffer_offset = None
                self.buffer_length = None
                self.lgr.debug('dataWatch setRange adjusted start/length per buffer_offset to 0x%x %d' % (start, length))
        if not self.use_backstop and backstop:
            self.use_backstop = True
            #self.lgr.debug('DataWatch, backstop set, start data session')

        if max_len is None or max_len == 0:
            my_len = length
        else:
            # TBD intent to handle applications that reference old buffer data, i.e., past the end of the read count, but what if 
            # read length is huge?
            if max_len > 1500:
                self.lgr.warning('dataWatch setRange large length given %d, setting len of buffer to what we got %s' % (max_len, length)) 
                my_len = length
            else:
                self.lgr.warning('dataWatch setRange NOT large length given %d, setting len of read buffer to that.' % (max_len)) 
                my_len = max_len

        self.lgr.debug('DataWatch set range start 0x%x watch length 0x%x actual count %d back_stop: %r total_read %d fd: %s callback: %s' % (start, 
               my_len, length, backstop, self.total_read, str(fd), str(self.read_limit_callback)))
        end = start+(my_len-1)
        overlap = False
        if not no_extend:
            did_replace = []
            for index in range(len(self.start)):
                if self.start[index] is not None:
                    this_end = self.start[index] + (self.length[index]-1)
                    #self.lgr.debug('dataWatch setRange look for related start 0x%x end 0x%x this start 0x%x this end 0x%x' % (start, end, self.start[index], this_end))
                    if self.start[index] <= start and this_end >= end:
                        overlap = True
                        self.lgr.debug('DataWatch setRange found overlap, skip it')
                        if start not in self.other_starts:
                            self.other_starts.append(start)
                            self.other_lengths.append(my_len)
                        break
                    elif self.start[index] >= start and this_end <= end:
                        for already_replaced in did_replace:
                            already_end = self.start[already_replaced] + (self.length[already_replaced]-1)
                            if self.start[already_replaced] >= start and already_end <= end:
                                self.lgr.debug('DataWatch setRange found subrange that was already replaced.  Remove this one')
                                self.start[index] = None
                                hap = self.read_hap[index]
                                self.context_manager.genDeleteHap(hap, immediate=False)
                                self.read_hap[index] = None
                            elif start >= self.start[already_replaced] and  end <= already_end:
                                self.lgr.debug('DataWatch setRange found subrange that was already replaced. This one is bigger.  Remove other one')
                                self.start[already_replaced] = None
                                hap = self.read_hap[already_replaced]
                                self.context_manager.genDeleteHap(hap, immediate=False)
                                self.read_hap[already_replaced] = None
                        if self.start[index] is not None: 
                            self.lgr.debug('DataWatch setRange found subrange, replace old start 0x%x old len %d with new start 0x%x len %d' % (self.start[index], 
                                   self.length[index], start, my_len))
                            self.start[index] = start
                            self.length[index] = my_len
                            did_replace.append(index)
                        overlap = True

                    elif start == (this_end+1):
                        self.length[index] = self.length[index]+my_len
                        self.lgr.debug('DataWatch extending after end of range of index %d, len now %d' % (index, self.length[index]))
                        overlap = True
                        self.resetIndexHap(index)
                        break
                    elif (end+1) == self.start[index]:
                        self.length[index] = self.length[index]+my_len
                        self.start[index] = start
                        self.lgr.debug('DataWatch extending backwards prior to start of range of index %d, len now %d' % (index, self.length[index]))
                        overlap = True
                        self.resetIndexHap(index)
                        break
                    elif(start >= self.start[index] and start <= this_end) and end > this_end:
                        ''' TBD combine with above?'''
                        self.length[index] = end - self.start[index]
                        self.lgr.debug('DataWatch extending range of index %d, len now %d' % (index, self.length[index]))
                        overlap = True
                        self.resetIndexHap(index)
                        break
        else:
            self.lgr.debug('dataWatch setRange was no_extend')
        self.lgr.debug('dataWatch overlap %r test if copymark %s' % (overlap, str(watch_mark)))
        #if not overlap or self.isCopyMark(watch_mark):
        # TBD why care if a copy mark?
        if not overlap:
            # The indices are not reused.  Parallel arrays
            self.start.append(start)
            self.length.append(my_len)
            self.hack_reuse.append(0)
            self.cycle.append(self.cpu.cycles)
            self.mark.append(watch_mark)

            phys = self.mem_utils.v2p(self.cpu, start)
            self.phys_start.append(phys)
            self.range_cr3.append(memUtils.getCR3(self.cpu))
            
            sp = self.mem_utils.getRegValue(self.cpu, 'sp')
            self.lgr.debug('dataWatch setRange msg %s stack 0x%x  start 0x%x range_cr3 0x%x' % (msg, sp, start, self.range_cr3[-1]))
            #if (self.isCopyMark(watch_mark) and watch_mark.mark.sp) or \
            #         ((msg == 'fun result' or (msg is not None and msg.startswith('injectIO'))) and self.watchMarks.isStackBuf(start)):
            if self.watchMarks.isStackBuf(start):
                ''' TBD awkward method for deciding to watch function results going to memory'''
                index = len(self.start)-1
                self.lgr.debug('dataWatch setRange is it a stack buffer? start 0x%x check ret addr' % (start))
                ret_to = None
                cpl = memUtils.getCPL(self.cpu)
                if cpl > 0:
                    ret_to = self.getReturnAddr()
                if ret_to is None:
                    if not self.cpu.architecture.startswith('arm'):
                        bp = self.mem_utils.getRegValue(self.cpu, 'ebp')
                        if bp != 0:
                            dum_cpu, comm, tid = self.task_utils.curThread()
                            word_size = self.top.wordSize(tid, target=self.cell_name)
                            ret_to_addr = bp + word_size
                            self.lgr.debug('dataWatch setRange bp 0x%x ret_to_addr 0x%x wordsize %d' % (bp, ret_to_addr,word_size))
                            maybe = self.mem_utils.readAppPtr(self.cpu, ret_to_addr, size=word_size)
                            if maybe is not None:
                                self.lgr.debug('dataWatch setRange got mabe of 0x%x' % maybe)
                                if self.top.isCode(maybe):
                                    ret_to = maybe
                                    self.lgr.debug('dataWatch stack buffer but no good return address, using bp to get 0x%x' % ret_to)
                            else:
                                self.lgr.debug('dataWatch stack buffer got none reading ret_to_addr 0x%x' % ret_to_addr)
                if ret_to is not None:
                    self.lgr.debug('dataWatch setRange is stack buffer start 0x%x, ret_to 0x%x index %d' % (start, ret_to, index))
                    self.manageStackBuf([index], ret_to)
                else:
                    if -1 not in self.stack_buffers:
                        self.stack_buffers[-1] = []
                    self.lgr.debug('dataWatch setRange is stack buffer no return address, add index %d to failed stack buffers' % index)
                    self.stack_buffers[-1].append(index)

            self.lgr.debug('DataWatch adding start 0x%x, len %d cycle 0x%x len of start now %d' % (start, length, self.cpu.cycles, len(self.start)))
        if msg is not None:
            if sys.version_info[0] >= 3:
                fixed = msg
            else:
                fixed = unicode(msg, errors='replace')
            # TBD why max_len and not count???  Attempt to watch reuse of input buffer, e.g., reading past end recent receive?
            if recv_addr is None:
                recv_addr = start
            self.lgr.debug('dataWatch call markCall, msg %s length %d data_stream %r' % (fixed, length, data_stream))
            ''' TBD what if fun result? e.g., checkNumericStore'''
            self.watchMarks.markCall(fixed, max_len=max_len, recv_addr=recv_addr, length=length, fd=fd, is_lib=is_lib, data_stream=data_stream)
            if self.prev_cycle is None:
                ''' first data read, start data session if doing coverage '''
                self.top.startDataSessions()
                self.prev_cycle = self.cpu.cycles
        if no_backstop:
            self.no_backstop.append(start)
        self.setBreakRange()
        self.lgr.debug('dataWatch setRange called setBreakRange, leaving setRange len of self.start is %d' % len(self.start))

    def stackThisHap(self, dumb, an_object, the_breakpoint, memory):
        ''' Returned from function on call chain that created a c++ object whose this is in the stack.  See
            if the object should be deleted.  Otherwise, set a hap on the
            next stack frame 
        '''
        eip = memory.logical_address
        #self.lgr.debug('stackThisHap eip 0x%x' % eip)
        if eip in self.stack_this_hap:
            self.context_manager.genDeleteHap(self.stack_this_hap[eip])
            #self.lgr.debug('stackThisHap eip in stack_buf_hap')
            sp = self.mem_utils.getRegValue(self.cpu, 'sp')

            instruct = self.top.disassembleAddress(self.cpu, eip)
            op2, op1 = self.decode.getOperands(instruct[1])
            new_sp = self.adjustSP(sp, instruct, op1, op2)
            if new_sp is not None:
                #self.lgr.debug('dataWatch stackThisHap adjusted sp to 0x%x' % new_sp)
                sp = new_sp

            ret_to = self.getReturnAddr()
            replace_index = []
            ''' stack_this dict of lists of all string_this object addresses for a return address '''
            for this in self.stack_this[eip]:
                if this in self.string_this: 
                   ''' is a c++ string '''
                   did_remove = False
                   if this < sp:
                        str_addr = self.string_this[this]
                        if str_addr < sp:
                            #self.lgr.debug('dataWatch stackThisHap sp: 0x%x remove watch for string this 0x%x buffer at 0x%x' % (sp, this, str_addr))
                            self.rmRange(str_addr)
                            del self.string_this[this]
                            did_remove = True
                   if not did_remove:
                        if ret_to is not None:
                            ''' avoid trying to return from text to some library '''
                            if self.top.isMainText(eip) and not self.top.isMainText(ret_to):
                                #self.lgr.debug('dataWatch stackThisHap, start 0x%x not less than sp 0x%x, but would be return to lib from main, skip it).' % (self.start[range_index], sp))
                                pass
                            else:
                                #self.lgr.debug('dataWatch stackThisHap, string this 0x%x (or its content string) not less than sp 0x%x, set break on next frame.' % (this, sp))
                                replace_index.append(this)
            else:
               self.lgr.debug('dataWatch stackThisHap this 0x%x not in stack_this for eip 0x%x' % (this, eip))
            self.lgr.debug('stackThisHap remove entry for 0x%x' % eip)
            del self.stack_this_hap[eip] 
            del self.stack_this[eip] 
            if len(replace_index) > 0:
                self.lgr.debug('dataWatch stackThisHap will replace %d indices' % (len(replace_index)))
                self.manageStackThis(replace_index, ret_to)
            
        else:
            #self.lgr.debug('stackThisHap eip NOT in stack_this')
            pass

    def checkFailedStackBufs(self, check_index):
        retval = False
        if -1 in self.stack_buffers:
            sp = self.mem_utils.getRegValue(self.cpu, 'sp')
            rm_list = []
            self.lgr.debug('dataWatch checkFailedStackBufs sp: 0x%x' % (sp))
            for failed_index in self.stack_buffers[-1]:
                if failed_index >= len(self.start) or self.start[failed_index] is None:
                    #self.lgr.debug('dataWatch checkFailedStackBufs failed index %d not in self.start (or is None), sp: 0x%x' % (failed_index, sp))
                    continue
                #self.lgr.debug('dataWatch checkFailedStackBufs failed index %d start 0x%x sp 0x%x' % (failed_index, self.start[failed_index], sp))
                if self.start[failed_index] <= sp and failed_index < len(self.read_hap):
                    rm_list.append(failed_index)
                    #self.lgr.debug('dataWatch checkFailedStackbufs remove start 0x%x failed index %d' % (self.start[failed_index], failed_index))
                    hap = self.read_hap[failed_index]
                    self.context_manager.genDeleteHap(hap, immediate=False)
                    self.read_hap[failed_index] = None
                    self.start[failed_index] = None
                    if failed_index == check_index:
                        retval = True
            for failed_index in rm_list:
                self.stack_buffers[-1].remove(failed_index)
        return retval

    def stackBufHap(self, dumb, an_object, the_breakpoint, memory):
        ''' Returned from function on call chain that created a stack buffer.  See
            if the stack buffer should be deleted.  Otherwise, set a hap on the
            next stack frame 
            NOTE: also force-called on return from memsomething.
        '''
        eip = memory.logical_address
        self.lgr.debug('stackBufHap eip 0x%x cycle: 0x%x' % (eip, self.cpu.cycles))
        if eip in self.stack_buf_hap:
            self.context_manager.genDeleteHap(self.stack_buf_hap[eip])
            self.lgr.debug('stackBufHap deleted stack_buf_hap[0x%x] %d' % (eip, self.stack_buf_hap[eip]))
            sp = self.mem_utils.getRegValue(self.cpu, 'sp')

            instruct = self.top.disassembleAddress(self.cpu, eip)
            op2, op1 = self.decode.getOperands(instruct[1])
            new_sp = self.adjustSP(sp, instruct, op1, op2)
            if new_sp is not None:
                self.lgr.debug('dataWatch stackBufHap adjusted sp to 0x%x' % new_sp)
                sp = new_sp

            ret_to = self.getReturnAddr()
            replace_index = []
            # TBD remove. now doing check of failed indices on each write to a buffer
            #if -1 in self.stack_buffers:
            #    ''' tack these failed ones to this eip as an expediant'''
            #    for failed_index in self.stack_buffers[-1]:
            #        self.stack_buffers[eip].append(failed_index)
            #    del self.stack_buffers[-1] 
            for range_index in self.stack_buffers[eip]:
               if range_index < len(self.read_hap):
                   if range_index >= len(self.start):
                       self.lgr.debug('dataWatch stackBufHap range_index %d beyond len of self.start???' % range_index)
                       continue
                   if self.start[range_index] is None:
                        self.lgr.debug('dataWatch stackBufHap  index start[%d] is None' % (range_index))
                        continue
  
                   if self.start[range_index] <= sp:
                        self.lgr.debug('dataWatch stackBufHap remove watch for index %d starting 0x%x' % (range_index, self.start[range_index]))
                        hap = self.read_hap[range_index]
                        self.context_manager.genDeleteHap(hap, immediate=False)
                        self.read_hap[range_index] = None
                        self.start[range_index] = None
                   else:
                        if ret_to is not None:
                            ''' avoid trying to return from text to some library '''
                            if self.top.isMainText(eip) and not self.top.isMainText(ret_to):
                                self.lgr.debug('dataWatch stackBufHap, start 0x%x not less than sp 0x%x, but would be return to lib from main, skip it).' % (self.start[range_index], sp))
                                pass
                            else:
                                self.lgr.debug('dataWatch stackBufHap, start 0x%x not less than sp 0x%x, set break on next frame.' % (self.start[range_index], sp))
                                replace_index.append(range_index)
               else:
                   self.lgr.debug('dataWatch stackBufHap range_index %d out of range of read_hap whose len is %d?' % (range_index, len(self.read_hap)))
                   self.lgr.debug('read_hap has %s' % str(self.read_hap))
            self.lgr.debug('stackBufHap remove stack buf hap entry for 0x%x len of buffers for that will now be %d' % (eip, len(replace_index)))
            del self.stack_buf_hap[eip] 
            del self.stack_buffers[eip] 
            if len(replace_index) > 0:
                self.lgr.debug('dataWatch stackBuffHap will replace %d indices' % (len(replace_index)))
                self.manageStackBuf(replace_index, ret_to)
            
        else:
            #self.lgr.debug('stackBufHap eip 0x%x NOT in stack_buf_hap' % eip)
            pass 

    def getReturnAddr(self):
        #self.lgr.debug('dataWatch getReturnAddr')
        retval = None
        #if self.cpu.architecture == 'arm':
        #     ret_addr = self.mem_utils.getRegValue(self.cpu, 'lr')
        #     eip = self.top.getEIP(self.cpu)
        #     if ret_addr != eip and self.top.isCode(ret_addr):
        #         retval = ret_addr
        eip = self.top.getEIP(self.cpu)
        if retval is None:
            st = self.top.getStackTraceQuiet(max_frames=4, max_bytes=1000, skip_recurse=True)
            if st is None:
                self.lgr.debug('dataWatch getReturnAddr stack trace is None, wrong tid?')
                return None
            frames = st.getFrames(4)
            #self.lgr.debug('dataWatch getReturnAddr %d frames' % len(frames))
            for frame in frames:
                if resimUtils.isClib(frame.fname):
                    #self.lgr.debug('dataWatch getReturnAddr stack frame is clib, skip')
                    continue
                if frame.ret_addr is not None and frame.ret_addr != eip:
                    #self.lgr.debug('dataWatch getReturnAddr got 0x%x' % frame.ret_addr)
                    retval = frame.ret_addr
                    break
        if retval is None:
            self.lgr.debug('dataWatch getReturnAddr got zilch')
        return retval

    def close(self, fd):
        ''' called when FD is closed and we might be doing a trackIO '''
        eip = self.top.getEIP(self.cpu)
        msg = 'closed FD: %d (0x%x)' % (fd, fd)
        self.watchMarks.markCall(msg, fd=fd)
       
    def watchFunEntries(self): 
        self.lgr.debug('watchFunEntries, %d entries' % len(self.mem_fun_entries))
        for fun in self.mem_fun_entries:
            self.lgr.debug('watchFunEntries, fun %s %d entries' % (fun, len(self.mem_fun_entries)))
            for eip in self.mem_fun_entries[fun]:
                if self.mem_fun_entries[fun][eip].hap is None and not self.mem_fun_entries[fun][eip].disabled:
                    phys_block = self.cpu.iface.processor_info.logical_to_physical(eip, Sim_Access_Execute)
                    if phys_block is None:
                        self.lgr.warning('dataWatch watchFunEntries, code at 0x%x not mapped, will not catch entry' % eip)
                    proc_break = self.context_manager.genBreakpoint(None, Sim_Break_Linear, Sim_Access_Execute, eip, 1, 0)
                    name = 'mem_fun_entry_%s' % fun
                    hap = self.context_manager.genHapIndex("Core_Breakpoint_Memop", self.memSomethingEntry, fun, proc_break, name)
                    self.mem_fun_entries[fun][eip].hap = hap
                    #self.lgr.debug('dataWatch watchFunEntries set fun entry break on 0x%x for fun %s context %s' % (eip, fun, self.cpu.current_context))
        if self.destroy_entry is not None and self.destroy_hap is None:
            #self.lgr.debug('dataWatch watchFunEntries add destroy entry hap')
            proc_break = self.context_manager.genBreakpoint(None, Sim_Break_Linear, Sim_Access_Execute, self.destroy_entry, 1, 0)
            self.destroy_hap = self.context_manager.genHapIndex("Core_Breakpoint_Memop", self.destroyEntry, None, proc_break, 'destroy_entry') 

    def watch(self, show_cmp=False, break_simulation=None, i_am_alone=False, no_backstop=False):
        if self.disabled:
            return
        self.stopped = False
        ''' set the data watches, e.g., after a reverse execution is complete.'''
        self.lgr.debug('DataWatch watch show_cmp: %r cpu: %s length of watched buffers is %d length of read_hap %d cycles: 0x%x' % (show_cmp, self.cpu.name, 
           len(self.start), len(self.read_hap), self.cpu.cycles))
        retval = False
        self.show_cmp = show_cmp         
        if break_simulation is not None:
            self.break_simulation = break_simulation         
        self.lgr.debug('watch alone %r break_sim %s  use_back %s  no_back %s' % (i_am_alone, str(break_simulation), str(self.use_backstop), str(no_backstop)))
        if self.backstop is not None and not self.break_simulation and self.use_backstop and not no_backstop:
            self.backstop.setFutureCycle(self.backstop_cycles)
        self.watchFunEntries()
        if len(self.start) > 0:
            if i_am_alone:
                self.setBreakRange(i_am_alone)
            else:
                SIM_run_alone(self.setBreakRange, i_am_alone)
            retval = True

        for re_watch in self.re_watch_list:
            re_watch.setMapBreakRange()

        self.setStackBufHaps()
        self.setStackThisHaps()
        self.setRingCharBreaks()
        if self.append_char_returns is not None:
            self.append_char_returns.setBreaks()
        if self.function_no_watch is not None:
            self.function_no_watch.restoreBreaks()

        return retval

    def showCmp(self, addr): 
        eip = self.top.getEIP(self.cpu)
        instruct = self.top.disassembleAddress(self.cpu, eip)
        #self.lgr.debug('showCmp eip 0x%x %s' % (eip, instruct[1]))
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
          
    def deleteReturnHap(self, hap): 
        if hap is not None:
            self.context_manager.genDeleteHap(hap, immediate=True)
            self.lgr.debug('dataWatch deleteReturnHap')

    def resetIndexHap(self, index):
        if self.start[index] is not None:
            self.lgr.debug('dataWatch resetIndexHap for %d len of start: %d  len of read_hap %d' % (index, len(self.start), len(self.read_hap)))
            if index < len(self.read_hap):
                hap = self.read_hap[index]
                self.context_manager.genDeleteHap(hap)
                self.read_hap[index] = None
                self.lgr.debug('dataWatch resetIndexHap setOneBreak')
                self.setOneBreak(index, replace=True)
            else:
                self.lgr.debug('remove this?')
                SIM_break_simulation('remove this')
               
    def stopWatch(self, break_simulation=None, immediate=False, leave_fun_entries=False, leave_backstop=False): 
        ''' stop data watches, e.g., in prep for reverse execution or to run free from a memsomething call to its return'''
        if self.disabled:
            return
        self.stopped = True
        self.lgr.debug('dataWatch stopWatch immediate: %r len of start is %d len of read_hap: %d cycle: 0x%x' % (immediate, len(self.start), len(self.read_hap), self.cpu.cycles))
        for index in range(len(self.start)):
            if self.start[index] is None:
                continue
            if index < len(self.read_hap):
                if self.read_hap[index] is not None:
                    #self.lgr.debug('dataWatch stopWatch delete read_hap %d' % self.read_hap[index])
                    self.context_manager.genDeleteHap(self.read_hap[index], immediate=immediate)
                    self.read_hap[index] = None
            else:
                #self.lgr.debug('dataWatch stopWatch index %d not in read_hap len is %d ' % (index, len(self.read_hap)))
                pass
        #self.lgr.debug('DataWatch stopWatch removed read haps')
        if break_simulation is not None: 
            self.break_simulation = break_simulation
            self.lgr.debug('DataWatch stopWatch break_simulation %r' % break_simulation)
        hap = self.return_hap
        SIM_run_alone(self.deleteReturnHap, hap)
        self.return_hap = None
        #self.lgr.debug('DataWatch stopWatch return_hap is now None leave_fun_entries: %r' % leave_fun_entries)
        if not leave_fun_entries:
            for fun in self.mem_fun_entries:
                for eip in self.mem_fun_entries[fun]:
                    if self.mem_fun_entries[fun][eip].hap is not None:
                        hap = self.mem_fun_entries[fun][eip].hap
                        self.context_manager.genDeleteHap(hap, immediate=immediate)
                        self.mem_fun_entries[fun][eip].hap = None
            if self.destroy_hap is not None:
                self.context_manager.genDeleteHap(self.destroy_hap, immediate=immediate)
                self.destroy_hap = None
      
        if self.backstop is not None and not leave_backstop:
            self.backstop.clearCycle()
        self.pending_call = False
        for re_watch in self.re_watch_list:
            re_watch.stopMapWatch(immediate=immediate)

        for eip in self.stack_buf_hap:
            #self.lgr.debug('DataWatch stopWatch remove stack_buf_hap[0x%x] %d' % (eip, self.stack_buf_hap[eip]))
            hap = self.stack_buf_hap[eip]
            self.context_manager.genDeleteHap(hap, immediate=immediate)
        self.stack_buf_hap = {}

        self.rmRingCharBreaks()

        self.stopStackThisHaps(immediate=immediate)
        #if self.finish_check_move_hap is not None:
        #    self.lgr.debug('DataWatch stopWatch delete finish_check_move_hap')
        #    self.context_manager.genDeleteHap(self.finish_check_move_hap, immediate=True)
        #    self.finish_check_move_hap = None
        if self.call_stop_hap is not None:
            hap = self.call_stop_hap
            self.top.RES_delete_stop_hap(hap)
            self.call_stop_hap = None

        if self.append_char_returns is not None:
            self.append_char_returns.rmHaps()

        if self.function_no_watch is not None:
            self.function_no_watch.rmBreaks(immediate=immediate)

    def resetWatch(self):
        self.lgr.debug('dataWatch resetWatch')
        self.stopWatch(immediate=True)
        self.resetState()

    def getPipeReader(self, write_fd):
        retval = None
        full_path = self.top.getFullPath()
        base = os.path.basename(full_path)
        if os.path.isfile('pipes.txt'):
            self.lgr.debug('dataWatch gt pipeReader file')
            with open('pipes.txt') as fh:
                for line in fh:
                    parts = line.split()
                    path  = parts[0]
                    name  = parts[1]
                    self.lgr.debug('parts2 is %s' % parts[2])
                    if parts[2].startswith('W'):
                        writes = parts[2][3:-2]
                        reads = parts[3][3:-2]
                    else:
                        self.lgr.debug('parts3 is %s' % parts[3])
                        writes = parts[3][3:-2]
                        self.lgr.debug('writes is %s' % writes)
                        reads = parts[2][3:-2]
                    if writes == write_fd:
                        retval = int(reads)
                        break
        return retval

    def runToIOAlone(self, fd):
        self.top.runToIO(fd, linger=True, break_simulation=False, run=False)

    def kernelReturnHap(self, kernel_return_info, an_object, the_breakpoint, memory):
        ''' Data buffer had been read/written while in the kernel.  We ran forward to the return
            and now determine what the kernel call was about. '''
        # TBD not yet right for windows
        # in case we got here via sharedSyscall
        if len(self.kernel_return_hap) == 0:
            return
        self.top.getSharedSyscall().setcallback(None, None)
        eax = self.mem_utils.getRegValue(self.cpu, 'syscall_ret')
        eax = self.mem_utils.getSigned(eax)
        #self.top.showHaps()
        dum_cpu, comm, tid = self.task_utils.curThread()
        frame, cycles = self.top.getPreviousEnterCycle(tid=tid)
        if frame is None:
            self.lgr.debug('dataWatch kernelReturnHap failed to get previous frame, bail')
            return
        eip = self.top.getEIP(self.cpu)
        self.lgr.debug('kernelReturnHap, tid:%s (%s) eip: 0x%x retval 0x%x  addr: 0x%x context: %s compat32: %r cur_cycles: 0x%x, recent cycle: 0x%x' % (tid, 
                        comm, eip, eax, kernel_return_info.addr, str(self.cpu.current_context), self.compat32, self.cpu.cycles, cycles))
        #self.lgr.debug(taskUtils.stringFromFrame(frame))
        if kernel_return_info.op_type == Sim_Trans_Load:
            fname = None
            write_fd = None
            if 'ss' in frame:
                #self.lgr.debug('frame has ss: %s' % frame['ss'].getString())
                # TBD assuming linux alwasy?
                if self.top.isWindows():
                    self.lgr.error('dataWatch kernelReturnHap did not expect ss in frame')
                
                callnum = 102
                call = net.callname[frame['param1']].lower()
                write_fd = frame['ss'].fd
                buf_start = self.findRange(kernel_return_info.addr)
                self.watchMarks.kernel(kernel_return_info.addr, eax, write_fd, fname, callnum, call, buf_start)
            else:
                #callnum = self.mem_utils.getCallNum(self.cpu)
                callnum = frame['syscall_num']
                call = self.task_utils.syscallName(callnum, self.compat32)
                self.lgr.debug('dataWatch kernelReturnHap got callnum %d call %s' % (callnum, call))
                if call == 'open' or call.startswith('fstat') or call.startswith('stat') or call in ['creat', 'mkdir', 'rename']:
                    fname_addr = frame['param1']
                    fname = self.mem_utils.readString(self.cpu, fname_addr, 100)
                    count = len(fname)
                    self.lgr.debug('dataWatch kernelReturnHap got fname %s count %d' % (fname, count))
                    src = fname_addr
                elif call == 'writev':
                    # TBD only record the first buffer of an iov
                    write_fd = frame['param1']
                    iov_addr = frame['param2']
                    src = self.mem_utils.readPtr(self.cpu, iov_addr)
                    count = self.mem_utils.readPtr(self.cpu, iov_addr+self.mem_utils.wordSize(self.cpu))
                elif call.startswith('write') or call.startswith('send'):
                    write_fd = frame['param1']
                    count = eax
                    self.lgr.debug('dataWatch kernelReturnHap unknown count %d' % (count))
                    src = frame['param2']
                elif call == 'execve':
                    self.lgr.debug('dataWatch kernelReturnHap TBD handle execve set src to addr 0x%x and count to 8' % kernel_return_info.addr)
                    src = kernel_return_info.addr
                    count = 8
                else:
                    self.lgr.debug('dataWatch kernelReturnHap TBD handle this, just set src to addr 0x%x' % kernel_return_info.addr)
                    src = kernel_return_info.addr
                    count = 0
                buf_start, buf_length, dumb = self.findBufForRange(src, count)
                #buf_start = self.findRange(src)
                wm = self.watchMarks.kernel(src, count, write_fd, fname, callnum, call, buf_start)
                self.lgr.debug('kernelReturnHap not socket, call %s, frame: %s count was %d' % (call, taskUtils.stringFromFrame(frame), count))
            if write_fd is not None:
                read_fd = self.getPipeReader(str(write_fd))
                if read_fd is not None:
                    self.lgr.debug('dataWatch got pipe reader %d from write_fd %d, set read hap.' % (read_fd, write_fd))
                    SIM_run_alone(self.runToIOAlone, read_fd)
                else:
                    self.lgr.debug('dataWatch no pipe reader found for fd %d' % write_fd)
        else:
            callnum = frame['syscall_num']
            call = self.task_utils.syscallName(callnum, self.compat32)
            self.lgr.debug('dataWatch kernelReturnHap is modification, got callnum %d call %s' % (callnum, call))
            buf_start = self.findRange(kernel_return_info.addr)
            self.watchMarks.kernelMod(kernel_return_info.addr, eax, frame, callnum, call, buf_start)
 
        if self.backstop is not None and not self.break_simulation and self.use_backstop:
            self.backstop.setFutureCycle(self.backstop_cycles)
        for hap in self.kernel_return_hap:
            SIM_run_alone(self.deleteReturnHap, hap)
        self.kernel_return_hap = []
        self.lgr.debug('dataWatch kernelReturn reset watch')
        ''' TBD was true'''
        self.watch(i_am_alone=False)

    def kernelReturn(self, kernel_return_info):
        ''' The readHap found that the kernel read or wrote one of our buffers.  Run to the kernel return. '''
        if self.top.getSharedSyscall().callbackPending():
            return
        self.lgr.debug('kernelReturn for addr 0x%x optype %s cycle 0x%x' % (kernel_return_info.addr, str(kernel_return_info.op_type), self.cpu.cycles))
        ''' hack TBD '''
        self.top.getSharedSyscall().setcallback(self.kernelReturnHap, kernel_return_info)

        #return

        # TBD now done by checking callbackPending from readHap?
        #if not self.break_simulation:
        #    self.stopWatch(leave_fun_entries = True)
        if self.cpu.architecture.startswith('arm'):
            cell = self.top.getCell()
            proc_break = self.context_manager.genBreakpoint(None, Sim_Break_Linear, Sim_Access_Execute, self.param.arm_ret, 1, 0)
            return_hap = self.context_manager.genHapIndex("Core_Breakpoint_Memop", self.kernelReturnHap, 
                 kernel_return_info, proc_break, 'kernel_return_hap')
            self.kernel_return_hap.append(return_hap)
        else:
            #self.lgr.debug('Only ARM kernel return handled for now') 
            #self.watch()
            cell = self.top.getCell()
            if self.param.sysexit is not None:
                self.lgr.debug('dataWatch kernelReturn set break on exit_addr 0x%x' % self.param.sysexit)
                proc_break = self.context_manager.genBreakpoint(None, Sim_Break_Linear, Sim_Access_Execute, self.param.sysexit, 1, 0)
                return_hap = self.context_manager.genHapIndex("Core_Breakpoint_Memop", self.kernelReturnHap, kernel_return_info, proc_break, 'kernel_return_hap')
                self.kernel_return_hap.append(return_hap)
            if self.param.iretd is not None:
                self.lgr.debug('dataWatch kernelReturn set break on iretd 0x%x' % self.param.iretd)
                proc_break = self.context_manager.genBreakpoint(None, Sim_Break_Linear, Sim_Access_Execute, self.param.iretd, 1, 0)
                return_hap = self.context_manager.genHapIndex("Core_Breakpoint_Memop", self.kernelReturnHap, kernel_return_info, proc_break, 'kernel_return_hap')
                self.kernel_return_hap.append(return_hap)
            if self.param.sysret64 is not None:
                self.lgr.debug('dataWatch kernelReturn set break on sysret64 0x%x' % self.param.sysret64)
                proc_break = self.context_manager.genBreakpoint(None, Sim_Break_Linear, Sim_Access_Execute, self.param.sysret64, 1, 0)
                return_hap = self.context_manager.genHapIndex("Core_Breakpoint_Memop", self.kernelReturnHap, kernel_return_info, proc_break, 'kernel_return_hap')
       
      
    def checkNumericStore(self): 
        if self.mem_something.ret_ip is not None:
            next_ip = self.mem_something.ret_ip
            next_instruct = self.top.disassembleAddress(self.cpu, next_ip)
            self.lgr.debug('dataWatch checkNumericStore next instruct 0x%x  %s' % (next_ip, next_instruct[1]))
            if self.cpu.architecture.startswith('arm'):
                if next_instruct[1].startswith('str'):
                    op2, op1 = self.decode.getOperands(next_instruct[1])
                    ret_reg =  self.mem_utils.getCallRetReg(self.cpu)
                    if self.decode.regIsPart(op1, ret_reg):
                        self.lgr.debug('dataWatch checkNumericStore found %s' % next_instruct[1])
                        addr = self.decode.getAddressFromOperand(self.cpu, op2, self.lgr)
                        if addr is not None:
                            count = self.mem_utils.wordSize(self.cpu)
                            if next_instruct[1].startswith('strh'):
                                count = int(self.mem_utils.wordSize(self.cpu)/2)
                            self.setRange(addr, count, 'fun result')
                            self.last_fun_result = addr
                            self.move_cycle = self.cpu.cycles
                            self.move_cycle_max = self.cpu.cycles+1
                            self.lgr.debug('move_cycle_max now 0x%x' % self.move_cycle_max)
            elif self.cpu.architecture == 'ppc32':
                if next_instruct[1].startswith('st'):
                    op2, op1 = self.decode.getOperands(next_instruct[1])
                    ret_reg =  self.mem_utils.getCallRetReg(self.cpu)
                    if self.decode.regIsPart(op1, ret_reg):
                        self.lgr.debug('dataWatch checkNumericStore found %s' % next_instruct[1])
                        addr = self.decode.getAddressFromOperand(self.cpu, op2, self.lgr)
                        if addr is not None:
                            self.lgr.debug('dataWatch checkNumericStore got addr 0x%x' % addr)
                            count = self.mem_utils.wordSize(self.cpu)
                            if next_instruct[1].startswith('strh'):
                                count = int(self.mem_utils.wordSize(self.cpu)/2)
                            self.setRange(addr, count, 'fun result')
                            self.last_fun_result = addr
                            self.move_cycle = self.cpu.cycles
                            self.move_cycle_max = self.cpu.cycles+1
                            self.lgr.debug('move_cycle_max now 0x%x' % self.move_cycle_max)
            else:
                count = 0
                while(count < 4):
                     if next_instruct[1].startswith('mov'):
                         op2, op1 = self.decode.getOperands(next_instruct[1])
                         #self.lgr.debug('dataWatch checkNumericStore is mov op1 %s op2 %s' % (op1, op2))
                         ret_reg =  self.mem_utils.getCallRetReg(self.cpu)
                         if self.decode.regIsPart(op2, ret_reg):
                             addr = self.decode.getAddressFromOperand(self.cpu, op1, self.lgr)
                             if addr is not None:
                                 count = self.mem_utils.wordSize(self.cpu)
                                 self.setRange(addr, count, 'fun result')
                                 self.last_fun_result = addr
                                 self.move_cycle = self.cpu.cycles
                                 self.move_cycle_max = self.cpu.cycles+count+1
                                 self.lgr.debug('dataWatch checkNumericStore set range on 0x%x move_cycle_max now 0x%x' % (addr, self.move_cycle_max))
                         break
                     else:
                         count = count + 1
                         next_ip = next_ip + next_instruct[0]
                         next_instruct = self.top.disassembleAddress(self.cpu, next_ip)
                         #self.lgr.debug('dataWatch checkNumericStore count %d next instruct 0x%x  %s' % (count, next_ip, next_instruct[1]))
                         
        else:
            self.lgr.debug('dataWatch checkNumericStore, ret_ip is None')
          
     
    def startUndoAlone(self, dumb):
        self.undo_hap = self.top.RES_add_stop_callback(self.undoHap, self.mem_something)
        # TBD ever case of mark created before we decide it is a ghost?
        #self.watchMarks.undoMark()
        self.lgr.debug('dataWatch startUndoAlone')
        SIM_break_simulation('undo it')

    def watchStackObject(self, obj_ptr):
        if self.watchMarks.isStackBuf(obj_ptr):
            if obj_ptr in self.string_this:
                ''' TBD any good criteria for removing the range? '''
                self.lgr.debug('datawatch watchStackObject, string this 0x%x already recorded, WOULD HAVE removed its buffer (0x%x) and then update it.' % (obj_ptr, self.string_this[obj_ptr]))
                #self.rmRange(self.string_this[obj_ptr])
            else:
                self.lgr.debug('datawatch watchStackObject, new string this 0x%x will point to 0x%x' % (obj_ptr, self.mem_something.dest)) 
                ret_to = self.getReturnAddr()
                self.manageStackThis([obj_ptr], ret_to)
            self.string_this[obj_ptr] = self.mem_something.dest
        else:
            self.lgr.debug('dataWatch watchStackObject obj_ptr (this) in heap 0x%x' % obj_ptr)

    def handleMemCpyReturn(self):
        '''
        At a return from a memcpy function
        '''
        self.lgr.debug('dataWatch handleMemCpyReturn, return from %s src: 0x%x dest: 0x%x count %d ' % (self.mem_something.fun, self.mem_something.src, 
               self.mem_something.dest, self.mem_something.length))
        if self.mem_something.length == 0:
            self.lgr.debug('dataWatch got zero count for memcpy, just bail')
            #SIM_break_simulation('mempcpy')
            return
        skip_it = False          
        if len(self.mem_something.multi_index_list) == 0:
            buf_start = self.findRange(self.mem_something.src)
            if self.mem_something.op_type != Sim_Trans_Load:
                self.lgr.debug('handleMemCpyReturn copy not a Load, first see if src is a buf')
                buf_start = self.findRange(self.mem_something.src)
                if buf_start is None:
                    self.lgr.debug('dataWatch handleMemCpyReturn, overwrite buffer with unwatched content.')
                    buf_index = self.findRangeIndex(self.mem_something.dest)
                    if buf_index is not None:
                        if self.start[buf_index] == self.mem_something.dest and self.length[buf_index] <= self.mem_something.length:
                            self.lgr.debug('dataWatch handleMemCpyReturn, overwrite buffer start exact match.  Length of buffer %d, len of copy %d., remove the buffer' % (self.length[buf_index], self.mem_something.length))
                            if buf_index in self.read_hap:
                                hap = self.read_hap[buf_index]
                                self.context_manager.genDeleteHap(hap, immediate=False)
                                self.read_hap[buf_index] = None
                            self.start[buf_index] = None
                        else:
                            self.lgr.warning('dataWatch handleMemCpyReturn, TBD, overwrite buffer but not a match with start.  The buffer: 0x%x len %d.  Copy dest: 0x%x len %d.  Remove subrange' % (self.start[buf_index], self.length[buf_index], self.mem_something.dest, self.mem_something.length))
    
                            self.rmSubRange(self.mem_something.dest, self.mem_something.length)
                    else:
                        self.lgr.debug('dataWatch handleMemCpyReturn memcpy, but nothing we care about')
                        skip_it = True
            if not skip_it:
                mark = self.watchMarks.copy(self.mem_something.src, self.mem_something.dest, self.mem_something.length, buf_start, 
                    self.mem_something.op_type, truncated=self.mem_something.truncated, copy_start = self.mem_something.start)
                if self.mem_something.op_type == Sim_Trans_Load and self.mem_something.length > 0:
                    #self.lgr.debug('returnHap set range for copy')
                    self.setRange(self.mem_something.dest, self.mem_something.length, None, watch_mark=mark) 
                    self.setBreakRange()
        else:
            # multiple watch buffers in the copy
            self.lgr.debug('dataWatch handleMemcpyReturn %d multi buffers' % len(self.mem_something.multi_index_list))
            #for index in self.mem_something.multi_index_list:
            for src, length in self.mem_something.multi_index_list:
                #src = self.start[index]
                #length = self.length[index]
                offset = src - self.mem_something.src
                dest = self.mem_something.dest + offset
                mark = self.watchMarks.copy(src, dest, length, src, Sim_Trans_Load)
                self.setRange(dest, length, None, watch_mark=mark) 
            self.setBreakRange()
 
    def returnHap(self, skip_this, an_object, the_breakpt, memory):
        ''' should be at return from a memsomething.  see  getMemParams for gathering of parameters'''
        if self.return_hap is None:
            return
        hap = self.return_hap
        SIM_run_alone(self.deleteReturnHap, hap)
        self.return_hap = None
        eip = self.top.getEIP(self.cpu)
        self.enableBreaks()
        self.backstop.setFutureCycle(self.backstop_cycles)
        if self.cpu.cycles < self.cycles_was:
            if self.mem_something.addr is None:
                '''  Not due to a readHap, just restore breaks and continue '''
                pass
            else:
                self.lgr.debug('dataWatch returnHap suspect a ghost frame, returned from assumed memsomething to ip: 0x%x, but cycles 0x%x less than when we read the data 0x%x' % (eip, self.cpu.cycles, self.cycles_was))
                SIM_run_alone(self.startUndoAlone, None)
                return
        self.lgr.debug('dataWatch returnHap should be at return from memsomething fun %s, eip 0x%x cycles: 0x%x skip_this %r' % (self.mem_something.fun, eip, self.cpu.cycles, skip_this))
        hap = self.return_hap
        self.pending_call = False

        if skip_this:
            self.lgr.debug('dataWatch returnHap skip_this, bail')
            return
        dum_cpu, comm, tid = self.task_utils.curThread()
        word_size = self.top.wordSize(tid, target=self.cell_name)
        if self.mem_something.fun in mem_copyish_functions:
            self.handleMemCpyReturn()
        elif self.mem_something.fun in 'memcmp':
            str1 = self.mem_something.dest
            str2 = self.mem_something.src
            buf_start = self.findRange(str1)
            if buf_start is None:
                tmp = str1
                str1 = str2
                str2 = tmp
                buf_start = self.findRange(str1)
            self.watchMarks.compare(self.mem_something.fun, str1, str2, self.mem_something.length, buf_start)
            #self.lgr.debug('dataWatch returnHap, return from %s compare: 0x%x  to: 0x%x count %d ' % (self.mem_something.fun, self.mem_something.src, 
            #       self.mem_something.dest, self.mem_something.length))
        elif self.mem_something.fun in ['strcmp', 'strncmp', 'strnicmp', 'strcasecmp', 'strncasecmp', 'xmlStrcmp', 'strpbrk', 'strspn', 'strcspn','wcscmp', 
                                        'mbscmp','mbscmp_l', 'strtok', 'buffer_caseless_compare', 'strstr', 'string_strncmp', 'fnmatch']: 
            buf_start = self.findRange(self.mem_something.dest)
            if buf_start is None:
                buf_start = self.findRange(self.mem_something.src)
                if buf_start is None:
                    self.lgr.error('dataWatch returnHap failed to find a buf_start for 0x%x' % self.mem_something.src)
                    return
            if self.mem_something.fun == 'strtok':
                self.lgr.debug('dataWatch returnHap, return from %s  0x%x  to: 0x%x count %d ' % (self.mem_something.fun, 
                       self.mem_something.src, self.mem_something.dest, self.mem_something.length))
                the_delim = self.mem_utils.readString(self.cpu, self.mem_something.src, 40)
                retaddr = self.mem_utils.getRegValue(self.cpu, 'syscall_ret')
                cur_ptr = self.strtok_ptr
                if retaddr != 0:
                    self.mem_something.the_string = self.mem_utils.readString(self.cpu, retaddr, 4000)
                    self.lgr.debug('dataWatch returnHap strtok returned token string %s' % self.mem_something.the_string)
                    self.lgr.debug('dataWatch returnHap strtok the delimiter was %s' % the_delim)
                    self.strtok_ptr = self.strtok_ptr + len(self.mem_something.the_string)+len(the_delim)
                    self.lgr.debug('dataWatch returnHap strtok adjusted the strtok_ptr to now be 0x%x' % self.strtok_ptr)
                mark = self.watchMarks.strtok(self.mem_something.fun, cur_ptr, the_delim, self.mem_something.the_string, retaddr, buf_start)
                if retaddr != 0:
                    self.setRange(retaddr, len(self.mem_something.the_string), None, watch_mark = mark) 
            else:
                self.lgr.debug('dataWatch returnHap, return from %s  0x%x  to: 0x%x count %d ' % (self.mem_something.fun, 
                       self.mem_something.src, self.mem_something.dest, self.mem_something.length))
                self.watchMarks.compare(self.mem_something.fun, self.mem_something.dest, self.mem_something.src, self.mem_something.length, buf_start)
        elif self.mem_something.fun in ['strchr', 'strrchr', 'memchr']:
            buf_start = self.findRange(self.mem_something.src)
            if self.mem_something.the_chr is None:
                self.lgr.debug('dataWatch returnHap, return from %s but the_chr is None? ' % (self.mem_something.fun))
            else:
                self.watchMarks.strchr(self.mem_something.fun, self.mem_something.src, self.mem_something.the_chr, self.mem_something.length)
            self.lgr.debug('dataWatch returnHap, return from %s strchr 0x%x count %d ' % (self.mem_something.fun, 
                   self.mem_something.the_chr, self.mem_something.length))
        elif self.mem_something.fun in ['strtoul', 'strtoull', 'strtol', 'strtoll', 'strtoq', 'atoi', 'String5toInt', 'ByteArray5toInt']:
            self.watchMarks.strtoul(self.mem_something.fun, self.mem_something.src)
            ''' see if result is stored in memory '''
            self.lgr.debug('dataWatch %s check numeric store' % self.mem_something.fun)
            self.checkNumericStore()
            

        elif self.mem_something.fun in ['strcpy', 'strncpy', 'strlcpy']: 
            # TBD change to only set range on portion of function range that intersects data watch
            #self.lgr.debug('dataWatch returnHap, strcpy return from %s src: 0x%x dest: 0x%x count %d ' % (self.mem_something.fun, self.mem_something.src, 
            #       self.mem_something.dest, self.mem_something.length))
            buf_start = self.findRange(self.mem_something.src)
            if buf_start is None:
                ''' strcpy into the buffer? TBD, reused buffer?'''
                self.lgr.debug('dataWatch buf_start for 0x%x is none in strcpy?' % (self.mem_something.src))
                pass
            mark = self.watchMarks.copy(self.mem_something.src, self.mem_something.dest, self.mem_something.length, buf_start, self.mem_something.op_type, 
                       strcpy=True)
            if buf_start is not None and self.mem_something.length > 0:
                self.setRange(self.mem_something.dest, self.mem_something.length, None, watch_mark = mark) 
                self.setBreakRange()
        elif self.mem_something.fun == 'memset':
            #self.lgr.debug('dataWatch returnHap, return from memset dest: 0x%x count %d ' % (self.mem_something.dest, self.mem_something.length))
            buf_index = self.findRangeIndex(self.mem_something.dest)
            if buf_index is not None:
                #self.lgr.debug('dataWatch returnHap memset on one of our buffers')
                if self.start[buf_index] == self.mem_something.dest and self.length[buf_index] <= self.mem_something.length:
                    self.lgr.debug('dataWatch returnHap memset is exact match, remove buffer index %d addr 0x%x' % (buf_index, self.mem_something.dest))
                    if buf_index in self.read_hap:
                        hap = self.read_hap[buf_index] 
                        self.lgr.debug('dataWatch returnHap memset delete the hap %d' % hap)
                        self.context_manager.genDeleteHap(hap, immediate=False)
                        self.read_hap[buf_index] = None
                    self.start[buf_index] = None
                else:
                    self.lgr.warning('dataWatch returnHap memset but not match, TBD fix this buf start 0x%x  len %d' % (self.start[buf_index], self.length[buf_index]))
                self.watchMarks.memset(self.mem_something.dest, self.mem_something.length, self.start[buf_index])
        elif self.mem_something.fun == 'strdup':
            self.mem_something.dest = self.mem_utils.getRegValue(self.cpu, 'syscall_ret')
            self.lgr.debug('dataWatch returnHap, strdup return from %s src: 0x%x dest: 0x%x count %d ' % (self.mem_something.fun, self.mem_something.src, 
                   self.mem_something.dest, self.mem_something.length))
            if self.mem_something.op_type == Sim_Trans_Load:
                buf_start = self.findRange(self.mem_something.src)
                if buf_start is None:
                    self.lgr.error('dataWatch buf_start for 0x%x is none in strdup?' % (self.mem_something.src))
            else:
                buf_start = self.findRange(self.mem_something.dest)
            mark = self.watchMarks.copy(self.mem_something.src, self.mem_something.dest, self.mem_something.length, buf_start, self.mem_something.op_type)
            if self.mem_something.op_type == Sim_Trans_Load and self.mem_something.length > 0:
                self.setRange(self.mem_something.dest, self.mem_something.length, None, watch_mark=mark) 
                self.setBreakRange()
        elif self.mem_something.fun == 'sscanf':
            eax = self.mem_utils.getRegValue(self.cpu, 'syscall_ret')
            param_count = self.mem_utils.getSigned(eax)
            self.lgr.debug('dataWatch returnHap, sscanf return from sscanf src 0x%x param_count %d' % (self.mem_something.src, param_count))
            buf_start = self.findRange(self.mem_something.src)
            if param_count > 0:
                for i in range(param_count):
                    mark = self.watchMarks.sscanf(self.mem_something.src, self.mem_something.dest_list[i], self.mem_something.length, buf_start)
                    self.setRange(self.mem_something.dest_list[i], self.mem_something.length, None, watch_mark=mark) 
                self.setBreakRange()
            else:
                self.lgr.debug('dataWatch returnHap sscanf returned error')
                self.watchMarks.sscanf(self.mem_something.src, None, None, buf_start)
        elif self.mem_something.fun == 'strlen':
            self.lgr.debug('dataWatch returnHap, return from %s src: 0x%x count %d ' % (self.mem_something.fun, self.mem_something.src, 
                   self.mem_something.length))
            self.watchMarks.strlen(self.mem_something.src, self.mem_something.length)
            self.checkNumericStore()
        elif self.mem_something.fun in ['vsnprintf', 'sprintf', 'snprintf', 'vasprintf', 'asprintf']:
            if self.mem_something.dest is None:
                self.lgr.debug('dataWatch %s dest is None' % self.mem_something.fun)
            if self.mem_something.addr is None:
                self.lgr.error('dataWatch returnHap mem_something.addr is None')
                return
            self.mem_something.src = self.mem_something.addr
            self.lgr.debug('dataWatch returnHap printfish mem_something.src is 0x%x' % self.mem_something.src)
            buf_start = self.findRange(self.mem_something.src)
            self.mem_something.length = self.getStrLen(self.mem_something.dest)        
            mark = self.watchMarks.sprintf(self.mem_something.fun, self.mem_something.addr, self.mem_something.dest, self.mem_something.length, buf_start)
            if buf_start is not None:
                self.lgr.debug('dataWatch returnHap, return from %s src: 0x%x dst: 0x%x count %d buf_start: 0x%x' % (self.mem_something.fun, self.mem_something.src, 
                       self.mem_something.dest, self.mem_something.length, buf_start))
            else:
                self.lgr.debug('dataWatch returnHap, return from %s src: 0x%x dst: 0x%x count %d NO BUFFER FOUND' % (self.mem_something.fun, self.mem_something.src, 
                       self.mem_something.dest, self.mem_something.length))
            self.setRange(self.mem_something.dest, self.mem_something.length, None, watch_mark=mark) 
            self.setBreakRange()
        elif self.mem_something.fun in ['fprintf', 'printf', 'vfprintf', 'syslog', 'output_processor','fputs']:
            if self.mem_something.src is None:
                self.mem_something.src = self.mem_something.addr
            self.lgr.debug('dataWatch returnHap, return from %s src: 0x%x ' % (self.mem_something.fun, self.mem_something.src))
            self.watchMarks.fprintf(self.mem_something.fun, self.mem_something.src)
        elif self.mem_something.fun == 'fwrite' or self.mem_something.fun == 'IO_do_write':
            self.lgr.debug('dataWatch returnHap, return from %s src: 0x%x ' % (self.mem_something.fun, self.mem_something.src))
            self.watchMarks.fwrite(self.mem_something.fun, self.mem_something.src, self.mem_something.length)
        elif self.mem_something.fun == 'glob':
            self.lgr.debug('dataWatch returnHap, return from %s src: 0x%x ' % (self.mem_something.fun, self.mem_something.src))
            self.mem_something.length = self.getStrLen(self.mem_something.src)
            self.watchMarks.glob(self.mem_something.fun, self.mem_something.src, self.mem_something.length)
        elif self.mem_something.fun == 'inet_addr':
            self.lgr.debug('dataWatch returnHap, return from %s IP: %s count %d ' % (self.mem_something.fun, self.mem_something.the_string, 
                   self.mem_something.length))
            self.watchMarks.inet_addr(self.mem_something.src, self.mem_something.length, self.mem_something.the_string)
        elif self.mem_something.fun == 'inet_ntop':
            self.mem_something.length = self.getStrLen(self.mem_something.dest)        
            self.mem_something.the_string = self.mem_utils.readString(self.cpu, self.mem_something.dest, self.mem_something.length)
            self.lgr.debug('dataWatch returnHap, return from %s IP: %s count %d ' % (self.mem_something.fun, self.mem_something.the_string, 
                   self.mem_something.length))
            mark = self.watchMarks.inet_ntop(self.mem_something.dest, self.mem_something.length, self.mem_something.the_string)
            self.setRange(self.mem_something.dest, self.mem_something.length, None, watch_mark=mark) 
            self.setBreakRange()
        elif self.mem_something.fun == 'fgets':
            buf_start = self.findRange(self.mem_something.dest)
            returned_dest = self.mem_utils.getRegValue(self.cpu, 'syscall_ret')
            mark = self.watchMarks.fgetsMark(self.mem_something.fun, self.mem_something.dest, self.mem_something.length, buf_start)
            self.lgr.debug('dataWatch returnHap, return from %s dst: 0x%x count %d ' % (self.mem_something.fun, self.mem_something.dest, self.mem_something.length))
            #if self.mem_something.length > 0:
            #    self.setRange(self.mem_something.dest, self.mem_something.length, None, watch_mark=mark) 
            #    self.setBreakRange()
            self.recent_fgets = self.mem_something.dest
        elif self.mem_something.fun in ['getenv', 'regexec', 'ostream_insert', 'trim', 'QStringHash', 'JsonObject5value', 'JsonObjectix', 'JsonValueRef']:
            mark = self.watchMarks.mscMark(self.mem_something.fun, self.mem_something.addr)
            if self.mem_something.fun == 'ostream_insert':
                # TBD assuming this is always a temporary string
                self.rmRange(self.mem_something.addr) 
                self.lgr.debug('dataWatch returnHap assuming ostream_insert is temp string.')
        elif self.mem_something.fun.startswith('string_basic'):
            if self.mem_something.ret_addr_addr is not None:
                self.mem_something.dest = self.mem_utils.readAppPtr(self.cpu, self.mem_something.ret_addr_addr, size=word_size)
                #self.mem_something.length = self.getStrLen(self.mem_something.src)        
                self.lgr.debug('dataWatch returnHap, return from %s src: 0x%x dst: 0x%x count: %d ' % (self.mem_something.fun, self.mem_something.src, self.mem_something.dest,
                   self.mem_something.length))
                buf_start = self.findRange(self.mem_something.src)
                mark = self.watchMarks.stringMark(self.mem_something.fun, self.mem_something.src, self.mem_something.dest, self.mem_something.length, buf_start)
                self.lgr.debug('dataWatch returnHap, call setRange dest 0x%x  count %d' % (self.mem_something.dest, self.mem_something.length))
                if self.mem_something.length > 0:
                    self.setRange(self.mem_something.dest, self.mem_something.length, None, watch_mark=mark) 
                    self.setBreakRange()
                    self.watchStackObject(self.mem_something.ret_addr_addr)
        elif self.mem_something.fun.startswith('string_win_basic'):
            # tbd generalize for x64, arm?
            self.mem_something.dest = self.mem_utils.getRegValue(self.cpu, 'this')
            self.lgr.debug('dataWatch returnHap, return from %s src: 0x%x dst: 0x%x count: %d  addr 0x%x (may not match buffer)' % (self.mem_something.fun, 
                            self.mem_something.src, self.mem_something.dest, self.mem_something.length, self.mem_something.addr))
            buf_start = self.findRange(self.mem_something.addr)
            if buf_start is None:
                adjusted = self.mem_something.addr+self.mem_something.trans_size
                self.lgr.debug('dataWatch returnHap adjusted addr to get buf start 0x%x' % adjusted)
                buf_start = self.findRange(adjusted)
            if buf_start > self.mem_something.src:
                delta = buf_start - self.mem_something.src
                self.mem_something.src = buf_start
                self.mem_something.length = self.mem_something.length - delta
            mark = self.watchMarks.stringMark(self.mem_something.fun, self.mem_something.src, self.mem_something.dest, self.mem_something.length, buf_start)
            self.lgr.debug('dataWatch returnHap, call setRange dest 0x%x  count %d' % (self.mem_something.dest, self.mem_something.length))
            if self.mem_something.length > 0:
                self.setRange(self.mem_something.dest, self.mem_something.length, None, watch_mark=mark) 
                self.setBreakRange()

        elif self.mem_something.fun == 'basic_istringstream':
            # eax + 0x10 is where return string starts
            returned = self.mem_utils.getRegValue(self.cpu, 'syscall_ret')
            addr_addr = returned + 0x10
            self.mem_something.dest = self.mem_utils.readAppPtr(self.cpu, addr_addr, size=word_size)
            self.lgr.debug('dataWatch returnHap, return from %s src: 0x%x dst: 0x%x count: %d ' % (self.mem_something.fun, self.mem_something.src, self.mem_something.dest,
               self.mem_something.length))
            buf_start = self.findRange(self.mem_something.src)
            mark = self.watchMarks.stringMark(self.mem_something.fun, self.mem_something.src, self.mem_something.dest, self.mem_something.length, buf_start)
            self.lgr.debug('dataWatch returnHap, call setRange dest 0x%x  count %d' % (self.mem_something.dest, self.mem_something.length))
            if self.mem_something.length > 0:
                self.setRange(self.mem_something.dest, self.mem_something.length, None, watch_mark=mark) 
                self.setBreakRange()
                #self.watchStackObject(obj_ptr)

        elif self.mem_something.fun in ['String4left', 'String3mid', 'Stringa', 'String3arg']:
            ''' QTCore '''
            # eax + 0x10 is where return string starts
            returned = self.mem_utils.getRegValue(self.cpu, 'syscall_ret')
            addr_addr = self.mem_utils.readAppPtr(self.cpu, returned, size=word_size)
            ''' Offset within source structure at which our watch buffer starts '''
            if self.mem_something.src > self.mem_something.ret_addr_addr:
                offset = self.mem_something.src - self.mem_something.ret_addr_addr
            else:
                self.lgr.debug('dataWatch return %s our data watch src was 0x%x but the buffer start was 0x%x, set offset to 0x10?' % (self.mem_something.fun, self.mem_something.src, self.mem_something.ret_addr_addr))
                offset = 0x10
            ''' include the string header to catch deallocates '''
            self.mem_something.dest = addr_addr + offset
            self.lgr.debug('dataWatch returnHap, return from %s src: 0x%x dst: 0x%x count: %d addr_addr: 0x%x offset %d' % (self.mem_something.fun, self.mem_something.src, self.mem_something.dest,
               self.mem_something.length, addr_addr, offset))
            ''' informational for the watch mark'''
            buf_start = self.findRange(self.mem_something.src)
            mark = self.watchMarks.stringMark(self.mem_something.fun, self.mem_something.src, self.mem_something.dest, self.mem_something.length, buf_start)
            self.lgr.debug('dataWatch returnHap, call setRange dest 0x%x  count %d' % (self.mem_something.dest, self.mem_something.length))
            if self.mem_something.length > 0:
                self.setRange(self.mem_something.dest, self.mem_something.length, None, watch_mark=mark) 
                self.setBreakRange()
                ''' catch deallocate '''
                self.watchStackObject(addr_addr)
        elif self.mem_something.fun in ['StringS1_eq', 'Stringeq']:
            ''' some kind of compare '''
            buf_start, buf_length, dumb = self.findBufForRange(self.mem_something.src, self.mem_something.length)
            if buf_start is None:
                buf_start, buf_length, dumb = self.findBufForRange(self.mem_something.dest, self.mem_something.length)
            if buf_start is None:
                self.lgr.debug('dataWatch %s failed to find buf_start. src 0x%x dest 0x%x' % (self.mem_something.fun, self.mem_something.src, self.mem_something.dest))
            else:
                self.watchMarks.compare(self.mem_something.fun, self.mem_something.src, self.mem_something.dest, self.mem_something.length, buf_start, two_bytes=True)
        elif self.mem_something.fun.startswith('string') or self.mem_something.fun == 'str':
            skip_it = False
            obj_ptr = self.mem_utils.getRegValue(self.cpu, 'syscall_ret')
            self.mem_something.dest = self.mem_utils.readAppPtr(self.cpu, obj_ptr, size=word_size)
            if self.mem_something.dest == self.mem_something.src:
                self.lgr.debug('dataWatch returnHap string src same as dest, bail')
            else:
                if self.cpu.architecture.startswith('arm'):
                    if self.cpu.architecture == 'arm':
                        r1val = self.mem_utils.getRegValue(self.cpu, 'r1')
                    else:
                        r1val = self.mem_utils.getRegValue(self.cpu, 'x1')
                    if r1val == self.mem_something.src:
                        self.mem_something.length = self.getStrLen(self.mem_something.src)        
                        self.lgr.debug('dataWatch string, r1 unchanged, use src length of %d' % self.mem_something.length)
                    elif r1val < 5000:
                        self.mem_something.length = r1val
                    else:
                        self.lgr.warning('dataWatch string return size %d, confused? skipping' % r1val)
                        skip_it = True
                else:
                    ''' TBD is this right for x86? '''
                    self.mem_something.length = self.getStrLen(self.mem_something.src)        
                    self.lgr.debug('dataWatch string return size x86 got %d' % self.mem_something.length)
                if not skip_it:
                    if self.mem_something.src is None:
                        self.lgr.error('dataWatch returnHap src is None')
                    elif self.mem_something.dest is None:
                        self.lgr.error('dataWatch returnHap dest is None')
                    else:
                        self.lgr.debug('dataWatch returnHap, return from %s src: 0x%x dst: 0x%x count: %d ' % (self.mem_something.fun, self.mem_something.src, self.mem_something.dest,
                           self.mem_something.length))
                        buf_start = self.findRange(self.mem_something.src)
                        mark = self.watchMarks.stringMark(self.mem_something.fun, self.mem_something.src, self.mem_something.dest, self.mem_something.length, buf_start)
                        self.lgr.debug('dataWatch returnHap, call setRange dest 0x%x  count %d' % (self.mem_something.dest, self.mem_something.length))
                        if self.mem_something.length > 0:
                            self.setRange(self.mem_something.dest, self.mem_something.length, None, watch_mark=mark) 
                            self.setBreakRange()
                            self.watchStackObject(obj_ptr)
        elif self.mem_something.fun == 'replace_safe':
            ''' TBD different than replace? '''
            skip_it = False
            obj_ptr = self.mem_utils.getRegValue(self.cpu, 'syscall_ret')
            self.mem_something.dest = self.mem_utils.readAppPtr(self.cpu, obj_ptr, size=word_size)
            self.lgr.debug('dataWatch returnHap, return from %s src: 0x%x dst: 0x%x pos: %d length: %d ' % (self.mem_something.fun, self.mem_something.src, self.mem_something.dest,
               self.mem_something.pos, self.mem_something.length))
            buf_start = self.findRange(self.mem_something.src)
            self.watchStackObject(obj_ptr)

            mark = self.watchMarks.replaceMark(self.mem_something.fun, self.mem_something.src, self.mem_something.dest, self.mem_something.pos, self.mem_something.length, buf_start)
            if self.mem_something.length > 0:
                self.setRange(self.mem_something.dest, self.mem_something.length, None, watch_mark=mark) 
                self.setBreakRange()
        elif self.mem_something.fun.startswith('replace'):
            skip_it = False
            #obj_ptr = self.mem_utils.getRegValue(self.cpu, 'syscall_ret')
            obj_ptr = self.mem_something.ret_addr_addr
            self.mem_something.dest = self.mem_utils.readAppPtr(self.cpu, obj_ptr, size=word_size)
            self.lgr.debug('dataWatch returnHap, return from %s src: 0x%x dst: 0x%x pos: %d length: %d ' % (self.mem_something.fun, self.mem_something.src, self.mem_something.dest,
               self.mem_something.pos, self.mem_something.length))
            buf_start = self.findRange(self.mem_something.src)
            self.watchStackObject(obj_ptr)

            mark = self.watchMarks.replaceMark(self.mem_something.fun, self.mem_something.src, self.mem_something.dest, self.mem_something.pos, self.mem_something.length, buf_start)
            if self.mem_something.length > 0:
                self.setRange(self.mem_something.dest, self.mem_something.length, None, watch_mark=mark) 
                self.setBreakRange()
        elif self.mem_something.fun.startswith('append'):
            obj_ptr = self.mem_utils.getRegValue(self.cpu, 'syscall_ret')
            self.mem_something.dest = self.mem_utils.readAppPtr(self.cpu, obj_ptr, size=word_size)
            self.lgr.debug('dataWatch returnHap, return from %s src: 0x%x dst: 0x%x length: %d ' % (self.mem_something.fun, self.mem_something.src, self.mem_something.dest,
               self.mem_something.length))
            buf_start = self.findRange(self.mem_something.src)
            mark = self.watchMarks.appendMark(self.mem_something.fun, self.mem_something.src, self.mem_something.dest, self.mem_something.length, buf_start)
            if self.mem_something.length > 0:
                self.setRange(self.mem_something.dest, self.mem_something.length, None, watch_mark=mark) 
                self.setBreakRange()
        elif self.mem_something.fun.startswith('assign'):
            obj_ptr = self.mem_utils.getRegValue(self.cpu, 'syscall_ret')
            dest = self.mem_utils.readAppPtr(self.cpu, obj_ptr, size=word_size)
            dest_start = self.findRange(dest)
            src_start = self.findRange(self.mem_something.src)
            if src_start is None and dest_start is not None:
                self.lgr.debug('dataWatch returnHap assigning unknown buffer to known buffer, remove the destination')
                self.rmRange(dest)
            elif src_start is not None and dest_start is None:
                self.mem_something.dest = dest
                if self.mem_something.length is None:
                    self.lgr.warning('dataWatch returnHap assign length is none, setting to 0')
                    self.mem_something.length = 0
                self.lgr.debug('dataWatch returnHap, return from %s src: 0x%x dst: 0x%x length: %d ' % (self.mem_something.fun, self.mem_something.src, self.mem_something.dest,
                   self.mem_something.length))
                buf_start = self.findRange(self.mem_something.src)
                mark = self.watchMarks.assignMark(self.mem_something.fun, self.mem_something.src, self.mem_something.dest, self.mem_something.length, buf_start)
                if self.mem_something.length > 0:
                    self.setRange(self.mem_something.dest, self.mem_something.length, None, watch_mark=mark) 
                    self.setBreakRange()

        elif self.mem_something.fun.startswith('compare'):
            self.lgr.debug('dataWatch returnHap, return from %s src: 0x%x dst: 0x%x length: %d ' % (self.mem_something.fun, self.mem_something.src, self.mem_something.dest,
               self.mem_something.length))
            str1 = self.mem_something.dest
            str2 = self.mem_something.src
            buf_start = self.findRange(str1)
            if buf_start is None:
                tmp = str1
                str1 = str2
                str2 = tmp
                buf_start = self.findRange(str1)
            buf_start = self.findRange(self.mem_something.dest)
            self.watchMarks.compare(self.mem_something.fun, str1, str2, self.mem_something.length, buf_start)
        elif self.mem_something.fun in ['charLookupX', 'charLookupY']:
            if self.mem_something.ret_addr_addr is None:
                self.lgr.debug('dataWatch returnHap %s cur_ptr (ret_addr_addr) is None' % self.mem_something.fun)
                return
            elif self.mem_something.addr is None:
                self.lgr.debug('dataWatch returnHap %s addr is None' % self.mem_something.fun)
                return
            else:
                self.lgr.debug('dataWatch returnHap %s cur_ptr(ret_addr_addr) is 0x%x' % (self.mem_something.fun, self.mem_something.ret_addr_addr))
            retval = self.mem_utils.getRegValue(self.cpu, 'syscall_ret')
            cur_addr = self.mem_utils.readAppPtr(self.cpu, self.mem_something.ret_addr_addr, size=word_size)
            self.lgr.debug('dataWatch returnHap %s cur_addr is 0x%x retval 0x%x' % (self.mem_something.fun, cur_addr, retval))
            if retval == 0 and cur_addr is not None:
                self.lgr.debug('dataWatch returnHap %s nothing found cur_addr is 0x%x' % (self.mem_something.fun, cur_addr))
                msg = 'Not found %s. Search chars: %s ' % (self.mem_something.fun, self.mem_something.re_watch.getSearchChars())
                self.lgr.debug('dataWatch returnHap %s addr: 0x%x nothing found return_ptr is 0x%x ' % (self.mem_something.fun, self.mem_something.addr,
                   cur_addr))
                self.lgr.debug(msg)
            elif cur_addr is None:
                msg = '%s error could not read cur_addr from 0x%x UNDO' % (self.mem_something.fun, self.mem_something.ret_addr_addr)
                self.lgr.debug(msg)
                SIM_run_alone(self.startUndoAlone, None)
                return
            else:
                #self.mem_something.re_watch.watchCharReference(self.mem_something.ret_addr_addr)
                offset = cur_addr - self.mem_something.addr
                found_chr = self.mem_utils.readByte(self.cpu, cur_addr)
                msg = 'Match found %s. Search chars: %s  found: 0x%x offset 0x%x from 0x%x' % (self.mem_something.fun, 
                    self.mem_something.re_watch.getSearchChars(), found_chr, offset, self.mem_something.addr) 
                self.lgr.debug('dataWatch returnHap %s addr: 0x%x match found chr 0x%x cur_addr is 0x%x offset %d' % (self.mem_something.fun,
                       self.mem_something.addr, found_chr, cur_addr, offset))
                self.lgr.debug(msg)
            self.watchMarks.charLookupMark(self.mem_something.addr, msg, self.mem_something.length)
            self.mem_something.re_watch.stopMapWatch()

        elif self.mem_something.fun in ['charLookup']:
            if self.mem_something.ret_addr_addr is None:
                self.lgr.debug('dataWatch returnHap %s ret_addr_addr is None' % self.mem_something.fun)
                return
            elif self.mem_something.addr is None:
                self.lgr.debug('dataWatch returnHap %s addr is None' % self.mem_something.fun)
                return
            else:
                self.lgr.debug('dataWatch returnHap %s ret_addr_addr is 0x%x' % (self.mem_something.fun, self.mem_something.ret_addr_addr))
            retval = self.mem_utils.getRegValue(self.cpu, 'syscall_ret')
            return_ptr = self.mem_utils.readAppPtr(self.cpu, self.mem_something.ret_addr_addr, size=word_size)
            length = 0
            if retval == 0 and return_ptr is not None:
                self.lgr.debug('dataWatch returnHap charLookup nothing found return_ptr is 0x%x' % return_ptr)
                end_ptr = self.mem_utils.readAppPtr(self.cpu, return_ptr, size=word_size)
                length = end_ptr - self.mem_something.addr
                msg = 'Not found %s. Search chars: %s  found: %s' % (self.mem_something.fun, self.mem_something.re_watch.getSearchChars(), ' '.join(self.mem_something.re_watch.getFoundChars()))
                self.lgr.debug('dataWatch returnHap charLookup addr: 0x%x nothing found return_ptr is 0x%x end_ptr 0x%x length %d' % (self.mem_something.addr,
                   return_ptr, end_ptr, length))
                self.lgr.debug(msg)
            elif return_ptr is None:
                msg = 'charLookup error could not read return_ptr from 0x%x UNDO' % self.mem_something.ret_addr_addr
                self.lgr.debug(msg)
                SIM_run_alone(self.startUndoAlone, None)
                return
            else:
                self.mem_something.re_watch.watchCharReference(self.mem_something.ret_addr_addr)
                found_ptr = self.mem_utils.readAppPtr(self.cpu, return_ptr, size=word_size)
                if found_ptr is None:
                    msg = 'charLookuperror could not read found_ptr from 0x%x' % return_ptr
                else:
                    length = found_ptr - self.mem_something.addr
                    range_len = len(self.start)
                    msg = 'Match found %s. Search chars: %s  found: %s' % (self.mem_something.fun, self.mem_something.re_watch.getSearchChars(), ' '.join(self.mem_something.re_watch.getFoundChars()))
                    self.lgr.debug('dataWatch returnHap charLookup addr: 0x%x match found return_ptr is 0x%x found_ptr 0x%x length %d' % (self.mem_something.addr,
                       return_ptr, found_ptr, length))
                self.lgr.debug(msg)
            self.watchMarks.charLookupMark(self.mem_something.addr, msg, length)
            self.mem_something.re_watch.stopMapWatch()
        elif self.mem_something.fun.startswith('UuidToStringA'):
            self.mem_something.dest = self.mem_utils.readAppPtr(self.cpu, self.mem_something.ret_addr_addr, size=word_size)
            self.mem_something.the_string = self.mem_utils.readString(self.cpu, self.mem_something.dest, self.mem_something.length)
            buf_start, buf_length, dumb = self.findBufForRange(self.mem_something.src, self.mem_something.length)
            wm = self.watchMarks.dataToString(self.mem_something.fun, self.mem_something.src, self.mem_something.dest, self.mem_something.length, buf_start)
            self.setRange(self.mem_something.dest, 16, watch_mark=wm)
        elif self.mem_something.fun.startswith('WSAAddressToString'):
            buf_start, buf_length, dumb = self.findBufForRange(self.mem_something.src, self.mem_something.length)
            wm = self.watchMarks.dataToString(self.mem_something.fun, self.mem_something.src, self.mem_something.dest, self.mem_something.length, buf_start)
            self.setRange(self.mem_something.dest, self.mem_something.length, watch_mark=wm)

        elif self.mem_something.fun == 'realloc':
            new_addr = self.mem_utils.getRegValue(self.cpu, 'syscall_ret')
            if not memUtils.isNull(new_addr):
                # assume full source buffer moved
                buf_index = self.findRangeIndex(self.mem_something.src)
                if buf_index is not None:
                    count = self.length[buf_index] 
                    buf_start = self.start[buf_index] 
                    self.lgr.debug('%s src 0x%x count 0x%x retval addr 0x%x' % (self.mem_something.fun, self.mem_something.src, count, new_addr))
                    wm = self.watchMarks.copy(self.mem_something.src, new_addr, count, buf_start, Sim_Trans_Load, fun_name=self.mem_something.fun)
                    self.setRange(new_addr, count, watch_mark=wm)
                else:
                    self.lgr.debug('%s no buffer index found for src 0x%x' % (self.mem_something.fun, self.mem_something.src))
            else:
                self.lgr.debug('%s returned error 0x%x' % (self.mem_something.fun, new_addr))
            
        elif self.mem_something.fun == 'getopt':
            ret_addr = self.mem_utils.getRegValue(self.cpu, 'syscall_ret')
            if not memUtils.isNull(ret_addr):
                token = self.mem_utils.readString(self.cpu, ret_addr, 40)
                self.lgr.debug('%s returned addr 0x%x token is %s' % (self.mem_something.fun, ret_addr, token))
                wm = self.watchMarks.getopt(self.mem_something.fun, ret_addr, token, self.mem_something.length, self.mem_something.src, self.mem_something.the_string)
                self.setRange(ret_addr, len(token), watch_mark=wm)
            else:
                self.lgr.debug('%s returned error 0x%x' % (self.mem_something.fun, ret_addr))
                wm = self.watchMarks.getopt(self.mem_something.fun, None, None, self.mem_something.length, self.mem_something.src, self.mem_something.the_string)
        elif self.mem_something.fun == 'String16fromAscii_helper':
            this_addr = self.mem_utils.getRegValue(self.cpu, 'syscall_ret')
            self.mem_something.dest = this_addr + 0x10 + self.mem_something.pos
            range_count = self.mem_something.length * 2
            watch_buf_start = self.findRange(self.mem_something.src)
            self.lgr.debug('%s returned src 0x%x dest addr 0x%x string length count %d range count %d this_addr: 0x%x' % (self.mem_something.fun, self.mem_something.src, 
                   self.mem_something.dest, self.mem_something.length, range_count, this_addr)) 
            wm = self.watchMarks.copy(self.mem_something.src, self.mem_something.dest, self.mem_something.length, watch_buf_start, Sim_Trans_Load, fun_name=self.mem_something.fun, 
                                      truncated=self.mem_something.truncated, copy_start=self.mem_something.start)
            self.setRange(self.mem_something.dest, range_count, watch_mark=wm)
            self.watchStackObject(this_addr)


        elif self.mem_something.fun == 'String5split':
            ret_struct_addr_addr = self.mem_utils.getRegValue(self.cpu, 'syscall_ret')
            ret_struct_addr = self.mem_utils.readAppPtr(self.cpu, ret_struct_addr_addr, size=word_size)
            ret_count_addr = ret_struct_addr + 3 * word_size
            ret_count = self.mem_utils.readWord32(self.cpu, ret_count_addr)
            ret_count_max = min(20, ret_count)
            ret_item_addr_addr = ret_struct_addr + 0x10
            self.lgr.debug('%s ret_strut_addr 0x%x ret_count %d ret_count_max %d' % (self.mem_something.fun, ret_struct_addr, ret_count, ret_count_max))
            item_list = []
            for index in range(ret_count_max):
                ret_item_addr = self.mem_utils.readAppPtr(self.cpu, ret_item_addr_addr, size=word_size)
                ret_item_len_addr = ret_item_addr + word_size
                ret_item_len = self.mem_utils.readWord32(self.cpu, ret_item_len_addr)
                if ret_item_len == 0 or ret_item_len is None:
                    break
                ret_item_string_addr = ret_item_addr + 0x10
                self.lgr.debug('\t %s len 0x%x  ret_item_string_addr 0x%x ret_item_addr 0x%x' % (self.mem_something.fun, ret_item_len, ret_item_string_addr, ret_item_addr))
                item_list.append((ret_item_len, ret_item_string_addr))
                ret_item_addr_addr = ret_item_addr_addr + word_size
            wm = self.watchMarks.split(self.mem_something.src, self.mem_something.the_string, item_list, self.mem_something.fun)
            for item_len, item_addr in item_list:
                self.setRange(item_addr, item_len, watch_mark=wm)
        elif self.mem_something.fun.startswith('String14compare_helper'):
            buf_start, buf_length, dumb = self.findBufForRange(self.mem_something.src, self.mem_something.length)
            if buf_start is None:
                self.lgr.debug('%s failed to get buf_start for src 0x%x' % (self.mem_something.fun, self.mem_something.src))
            else:
                self.lgr.debug('%s buf_start is 0x%x for mem_something.src 0x%x dest: 0x%x length %d compare string %s' % (self.mem_something.fun, buf_start, self.mem_something.src,
                    self.mem_something.dest, self.mem_something.length, self.mem_something.the_string))
                self.watchMarks.compare(self.mem_something.fun, self.mem_something.src, self.mem_something.dest, self.mem_something.length, buf_start, two_bytes=True)
        elif self.mem_something.fun == 'String6toUtf8':
            ret_struct_addr_addr = self.mem_utils.getRegValue(self.cpu, 'syscall_ret')
            ret_struct_addr = self.mem_utils.readAppPtr(self.cpu, ret_struct_addr_addr, size=word_size)
            self.mem_something.dest = ret_struct_addr
            src_count = self.mem_something.length
            self.mem_something.length = self.mem_utils.readWord32(self.cpu, ret_struct_addr + word_size)
            buf_start, buf_length, dumb = self.findBufForRange(self.mem_something.src, src_count)
            if buf_start is None:
                self.lgr.debug('%s failed to get buf_start for src 0x%x' % (self.mem_something.fun, self.mem_something.src))
            else:
                self.lgr.debug('%s src 0x%x count 0x%x retval addr 0x%x' % (self.mem_something.fun, self.mem_something.src, self.mem_something.length, self.mem_something.dest))
                wm = self.watchMarks.copy(self.mem_something.src, self.mem_something.dest, self.mem_something.length, buf_start, Sim_Trans_Load, fun_name=self.mem_something.fun)
                self.setRange(self.mem_something.dest, self.mem_something.length, watch_mark=wm)
            
        # Begin XML
        elif self.mem_something.fun == 'xmlGetProp':
            self.lgr.debug('dataWatch returnHap, return from %s string: %s count %d ' % (self.mem_something.fun, self.mem_something.the_string, 
                   self.mem_something.length))
            self.mem_something.dest = getXmlReturn(self)
            self.watchMarks.xmlGetProp(self.mem_something.src, self.mem_something.length, self.mem_something.the_string, self.mem_something.dest)
        elif self.mem_something.fun == 'FreeXMLDoc':
            self.lgr.debug('dataWatch returnHap, return from %s' % (self.mem_something.fun))
            self.watchMarks.freeXMLDoc()
        elif self.mem_something.fun in ['xmlParseFile', 'xml_parse', 'xmlParseChunk']:
            self.lgr.debug('dataWatch returnHap, return from %s' % (self.mem_something.fun))
            if self.mem_something.fun == 'xmlParseChunk':
                xml_doc = self.mem_something.src
            else:
                # TBD why not gotten on the way in?
                xml_doc = getXmlReturn(self)

            self.top.stopTraceMalloc()
            self.me_trace_malloc = False
            malloc_ranges = self.mergeMalloc()
            tot_size = 0
            self.lgr.debug('xmlParse Malloc:')
            for addr in sorted(malloc_ranges):
                self.lgr.debug('0x%x   0x%x' % (addr, malloc_ranges[addr]))
                tot_size = tot_size + malloc_ranges[addr]
                self.setRange(addr, malloc_ranges[addr], None) 
            self.setBreakRange()
            self.watchMarks.xmlParseFile(xml_doc, tot_size)
        elif self.mem_something.fun == 'GetToken':
            if self.cpu.architecture.startswith('arm'):
                self.lgr.error('dataWatch GetToken not yet for arm')
            else:
                self.mem_something.dest = self.mem_utils.getRegValue(self.cpu, 'eax')
                self.mem_something.the_string = self.mem_utils.readString(self.cpu, self.mem_something.dest, 40)
            self.lgr.debug('dataWatch returnHap, return from %s token: %s' % (self.mem_something.fun, self.mem_something.the_string))
            self.watchMarks.getToken(self.mem_something.src, self.mem_something.dest, self.mem_something.the_string)
        elif self.mem_something.fun == 'xml_element_name':
            self.lgr.debug('dataWatch returnHap, return from %s' % (self.mem_something.fun))
            self.mem_something.dest = self.mem_utils.getRegValue(self.cpu, 'syscall-ret')
            self.watchMarks.strPtr(self.mem_something.dest, self.mem_something.fun)
        elif self.mem_something.fun == 'xml_element_children_size':
            self.lgr.debug('dataWatch returnHap, return from %s' % (self.mem_something.fun))
            self.mem_something.length = self.mem_utils.getRegValue(self.cpu, 'syscall_ret')
            self.watchMarks.returnInt(self.mem_something.length, self.mem_something.fun)
        elif self.mem_something.fun == 'xmlrpc_base64_decode':
            retaddr = self.mem_utils.getRegValue(self.cpu, 'syscall_ret')
            self.mem_something.length = self.mem_utils.readWord(self.cpu, retaddr)
            self.mem_something.dest = self.mem_utils.readWord(self.cpu, retaddr+2*word_size)
            self.lgr.debug('dataWatch returnHap %s count %d from 0x%x dest 0x%x' % (self.mem_something.fun, self.mem_something.length, self.mem_something.src, self.mem_something.dest))
            buf_start = self.findRange(self.mem_something.src)
            wm = self.watchMarks.base64Decode(self.mem_something.fun, self.mem_something.src, self.mem_something.dest, self.mem_something.length, buf_start)
            self.setRange(self.mem_something.dest, self.mem_something.length, watch_mark=wm)
            

        elif self.mem_something.fun in reg_return_funs:
            #adhoc = self.lookPushedReg()
            self.lgr.debug('return from %s' % self.mem_something.fun)
        elif self.mem_something.fun not in mem_funs:
            ''' assume iterator '''
            self.lgr.debug('dataWatch returnHap eip: 0x%x, return from iterator %s src: 0x%x ' % (eip, self.mem_something.fun, self.mem_something.src))
            buf_start = self.findRange(self.mem_something.src)
            self.watchMarks.iterator(self.mem_something.fun, self.mem_something.src, buf_start)
        elif self.mem_something.fun not in no_stop_funs and self.mem_something.addr is not None:
            self.lgr.error('dataWatch returnHap no handler for %s' % self.mem_something.fun)
        #SIM_break_simulation('return hap')
        #return
        self.lgr.debug('dataWatch returnHap call watch')

        if self.max_marks is not None and self.watchMarks.markCount() >= self.max_marks:
            self.maxMarksExceeded()
        else:
            #self.watch(i_am_alone=True)
            self.lgr.debug('dataWatch returnHap back from call watch')
            
            ''' See if this return should result in deletion of temp stack buffers '''
            self.stackBufHap(None, None, None, memory)
            #self.lgr.debug('dataWatch returnHap done')
        
    def getXmlReturn(self): 
        retval = None
        if self.cpu.architecture == 'arm':
            retval = self.mem_utils.getRegValue(self.cpu, 'r0')
        elif self.cpu.architecture == 'arm64':
            retval = self.mem_utils.getRegValue(self.cpu, 'x0')
        else:
            retval = self.mem_utils.readAppPtr(self.cpu, sp, size=word_size)
        return retval

    class MemCallRec():
        def __init__(self, hap, ret_addr_offset, eip):
            self.hap = hap
            self.ret_addr_offset = ret_addr_offset
            self.eip = eip
            self.skip_count = 0
            self.disabled = False

    def destroyEntry(self, dumb, an_object, the_breakpoint, memory):
        if self.destroy_hap is None:
            return
        r0 = self.mem_utils.getRegValue(self.cpu, 'syscall_ret')
        self.lgr.debug('dataWatch destroyEntry r0 0x%x' % r0)
        if r0 in self.string_this:
            self.rmRange(self.string_this[r0])
            #self.lgr.debug('dataWatch destroyEntry removed buffer 0x%x' % self.string_this[r0])
            del self.string_this[r0] 
        else:
            ''' TBD assumption? '''
            char_start = r0+0xc 
            buf_index = self.findRangeIndex(char_start)
            if buf_index is not None:
                #self.lgr.debug('dataWatch destroyEntry this looks like a string buffer at 0x%x, remove it.' % char_start)
                self.rmRange(char_start)

    def memSomethingEntry(self, fun, an_object, the_breakpoint, memory):
        ''' HAP hit when a memsomething entry is hit (assumes break has been set based on previous data hit or 
            pickled fun_entries '''
        if self.cpu.cycles == self.ignore_entry_cycle:
            return
        eip = memory.logical_address
        if eip in self.skip_entries:
            return
        if self.pending_call:
            self.lgr.debug('dataWatch memSomethingEntry but pending call, bail')
            return
        dum_cpu, comm, tid = self.task_utils.curThread()
        if not self.task_utils.commMatch(comm, self.comm):
            self.lgr.debug('memSomethingEntry tid:%s (%s) fun %s but wanted comm %s, bail' % (tid, comm, fun, self.comm))
            return
        word_size = self.top.wordSize(tid, target=self.cell_name)
        self.lgr.debug('********* memSomethingEntry, tid:%s fun %s eip 0x%x cycle: 0x%x context: %s word_size %d break num %d' % (tid, fun, eip, self.cpu.cycles, self.cpu.current_context, word_size, the_breakpoint))
        if fun not in self.mem_fun_entries or eip not in self.mem_fun_entries[fun] or self.mem_fun_entries[fun][eip].hap is None:
            self.lgr.debug('memSomethingEntry, fun %s eip 0x%x not in mem_fun_entries haps' % (fun, eip))
            return

        sp = self.mem_utils.getRegValue(self.cpu, 'sp') 
        if self.top.isWindows():
            # stack cookies?  TBD fix this
            param_sp = sp + word_size
        else:
            param_sp = sp
        self.mem_something.fun = fun
        # special case check for memcpy of 1 byte
        if self.mem_something.fun in mem_copyish_functions:

            self.mem_something.dest, self.mem_something.src, self.mem_something.length = self.getCallParams(param_sp, word_size)

            if self.mem_something.length == 1:
                self.lgr.debug('dataWatch memSomethingEntry size one, src 0x%x dest 0x%x let it go.  Will catch special case in readHap' % (self.mem_something.src, self.mem_something.dest))
                return
            else:
                buf_start, buf_length, dumb = self.findBufForRange(self.mem_something.src, self.mem_something.length)
                if buf_start is None:
                    if self.mem_something.dest is not None:
                        buf_start = self.findRange(self.mem_something.dest)
                    if buf_start is None:
                        self.lgr.debug('dataWatch memSomethingEntry, src 0x%x not something we care about and dest does not fall in a buffer, skip it' % self.mem_something.src)
                        return
                
        # TBD what is this about?
        #if self.cpu.architecture != 'arm':
        #    bp = self.mem_utils.getRegValue(self.cpu, 'ebp')
        #    if bp == self.recent_entry_bp:
        #        self.lgr.debug('dataWatch memSomethingEntry, bp 0x%x is same as recent, bail' % bp)
        #        return
        #    else:
        #       self.recent_entry_bp = bp
         
    
        # special case for memsomething functions calling memcpy.  
        if fun in ['memcpy', 'strlen']:
            st = self.top.getStackTraceQuiet(max_frames=20, max_bytes=1000)
            if st is None:
                self.lgr.error('DataWatch memSomethingEntry failed to get stack trace')
                return 
            else:
                self.frames = st.getFrames(20)
                got_memsomething = self.memsomething(self.frames[1:], mem_funs)
                if got_memsomething is not None:
                    self.lgr.debug('DataWatch memSomethingEntry %s called from other memsomething. bail' % fun)
                    return 
        if self.max_marks is not None and self.watchMarks.markCount() >= self.max_marks:
            self.maxMarksExceeded()
            return

        # TBD what is the point of this ret_to logic?
        #ret_to = self.getReturnAddr()
        #''' TBD expand to catch all free-type functions?  Also, cases where we would still want to see this?'''
        #if not fun == 'memset' and ret_to is not None and not self.top.isMainText(ret_to) and self.fun_mgr.getFun(ret_to) is None:
        #    self.lgr.debug('memSomethingEntry, fun %s called from 0x%x, not main text' % (fun, ret_to))
        #    return
        self.lgr.debug('memSomethingEntry, sp 0x%x' % (sp))
        if self.cpu.architecture not in ['arm', 'arm64', 'ppc32']:
            ret_addr = self.mem_utils.readAppPtr(self.cpu, sp, size=word_size)
            self.lgr.debug('memSomethingEntry, ret_addr 0x%x' % (ret_addr))
        elif self.mem_fun_entries[fun][eip].ret_addr_offset is not None:
                addr_of_ret_addr = sp - self.mem_fun_entries[fun][eip].ret_addr_offset
                ret_addr = self.mem_utils.readAppPtr(self.cpu, addr_of_ret_addr, size=word_size)
                if ret_addr == 0:
                    ret_addr = self.mem_utils.getRegValue(self.cpu, 'lr')
                    self.lgr.warning('dataWatch memSomethingEntry got zero for ret_addr.  addr_of_addr: 0x%x.  Assume arm and use lr of 0x%x instead' % (addr_of_ret_addr, ret_addr))
                else:
                    lr = self.mem_utils.getRegValue(self.cpu, 'lr')
                    self.lgr.debug('memSomethingEntry, addr_of_ret_addr 0x%x, ret_addr 0x%x, but lr is 0x%x' % (addr_of_ret_addr, ret_addr, lr))
        else: 
            ret_addr = self.mem_utils.getRegValue(self.cpu, 'lr')
            self.lgr.debug('memSomthingEntry ARM or ppc32 ret_addr_offset is None, use lr value of 0x%x' % ret_addr)
        self.mem_something = MemSomething(fun, eip, None, ret_addr, None, None, None, None, None, None)
        #                                     (fun, addr, ret_ip, src, dest, count, called_from_ip, op_type, length, start, ret_addr_addr=None, run=False, trans_size=None): 

        SIM_run_alone(self.getMemParams, False)


    def get4CallParams(self, sp):
        retval1 = None
        retval2 = None
        retval3 = None
        retval4 = None
        if self.cpu.architecture.startswith('arm'):
            if self.cpu.architecture == 'arm64' and self.mem_utils.arm64App(self.cpu):
                retval1 = self.mem_utils.getRegValue(self.cpu, 'x0')
                retval2 = self.mem_utils.getRegValue(self.cpu, 'x1')
                retval3 = self.mem_utils.getRegValue(self.cpu, 'x2')
                retval4 = self.mem_utils.getRegValue(self.cpu, 'x3')
            else:
                retval1 = self.mem_utils.getRegValue(self.cpu, 'r0')
                retval2 = self.mem_utils.getRegValue(self.cpu, 'r1')
                retval3 = self.mem_utils.getRegValue(self.cpu, 'r2')
                retval4 = self.mem_utils.getRegValue(self.cpu, 'r3')
        else:
            retval1 = self.mem_utils.readAppPtr(self.cpu, sp)
            retval2 = self.mem_utils.readAppPtr(self.cpu, sp+self.mem_utils.wordSize(self.cpu))
            retval3 = self.mem_utils.readWord32(self.cpu, sp+2*self.mem_utils.wordSize(self.cpu))
            retval4 = self.mem_utils.readWord32(self.cpu, sp+3*self.mem_utils.wordSize(self.cpu))
        return retval1, retval2, retval3, retval4

    def getCallParams(self, sp, word_size=None):
        if word_size is None:
            word_size = self.mem_utils.wordSize(self.cpu)
        retval1 = None
        retval2 = None
        retval3 = None
        if self.cpu.architecture.startswith('arm'):
            if self.cpu.architecture == 'arm64' and self.mem_utils.arm64App(self.cpu):
                retval1 = self.mem_utils.getRegValue(self.cpu, 'x0')
                retval2 = self.mem_utils.getRegValue(self.cpu, 'x1')
                retval3 = self.mem_utils.getRegValue(self.cpu, 'x2')
            else:
                retval1 = self.mem_utils.getRegValue(self.cpu, 'r0')
                retval2 = self.mem_utils.getRegValue(self.cpu, 'r1')
                retval3 = self.mem_utils.getRegValue(self.cpu, 'r2')
        elif self.cpu.architecture == 'ppc32':
                retval1 = self.mem_utils.getRegValue(self.cpu, 'r3')
                retval2 = self.mem_utils.getRegValue(self.cpu, 'r4')
                retval3 = self.mem_utils.getRegValue(self.cpu, 'r5')
        elif self.top.isWindows(target=self.cell_name) and word_size == 8:
            retval1 = self.mem_utils.getRegValue(self.cpu, 'rcx')
            retval2 = self.mem_utils.getRegValue(self.cpu, 'rdx')
            retval3 = self.mem_utils.getRegValue(self.cpu, 'r8')
        #elif self.top.isWindows(target=self.cell_name) and not force_sp:
        #    retval1 = self.mem_utils.getRegValue(self.cpu, 'eax')
        #    retval2 = self.mem_utils.getRegValue(self.cpu, 'ebx')
        #    retval3 = self.mem_utils.getRegValue(self.cpu, 'ecx')
        elif word_size == 8:
            retval1 = self.mem_utils.getRegValue(self.cpu, 'rsi')
            retval2 = self.mem_utils.getRegValue(self.cpu, 'rdi')
            retval3 = self.mem_utils.getRegValue(self.cpu, 'rdx')
        else:
            retval1 = self.mem_utils.readAppPtr(self.cpu, sp, size=word_size)
            retval2 = self.mem_utils.readAppPtr(self.cpu, sp+word_size, size=word_size)
            retval3 = self.mem_utils.readAppPtr(self.cpu, sp+2*word_size, size=word_size)
        return retval1, retval2, retval3

    def skipIntoFun(self):
        ''' skip forward at least 1 cycle to get to either the function entry point, or the link table call
            If ppc32, many need to go forward after r3 adjust...'''
        retval = True
        next_cycle = self.cpu.cycles+1
        if self.top.skipToCycle(next_cycle, cpu=self.cpu, disable=True):
            if self.cpu.architecture == 'ppc32':
                pc = self.top.getEIP(self.cpu)
                instruct = self.top.disassembleAddress(self.cpu, pc)
                if instruct[1].strip().startswith('addi'):
                    next_cycle = self.cpu.cycles+1
                    if not self.top.skipToCycle(next_cycle, cpu=self.cpu, disable=True):
                        retval = False
        else:
            retval = False
        return retval
            
    def getMemParams(self, data_hit):
            ''' data_hit is true if a read hap led to this call.  otherwise we simply broke on entry to 
                the memcpy-ish routine and came here via the memSomethingEntry hap, and we are running alone.
                Will call gatherCallParams after some housekeeping'''
            self.lgr.debug('dataWatch getMemParams, data_hit: %r context: %s' % (data_hit, self.cpu.current_context))
            skip_fun = False
            no_buffer_found = False
            self.watchMarks.registerCallCycle();
            ''' assuming we are a the call to a memsomething, get its parameters '''
            sp = self.mem_utils.getRegValue(self.cpu, 'sp')
            eip = self.top.getEIP(self.cpu)
            dum_cpu, comm, tid = self.task_utils.curThread()
            word_size = self.top.wordSize(tid, target=self.cell_name)
            if data_hit:
                if not self.skipIntoFun(): 
                    self.lgr.error('getMemParams, tried going forward into function, failed')
                    return
                #status = SIM_simics_is_running() 
                #self.lgr.debug('dataWatch getMemParams, try skipToTest to get to 0x%x simics running? %r' % (next_instruct, status)) 
                #if not self.top.skipToCycle(next_instruct, cpu=self.cpu, disable=True):
                #    self.lgr.error('getMemParams, tried going forward, failed')
                #    return
                self.recent_ghost_call_addr = None
                eip = self.top.getEIP(self.cpu)
                ''' TBD parse the va_list and look for sources so we can handle sprintf'''
                fun = self.mem_something.fun
                if fun in self.mem_fun_entries and eip in self.mem_fun_entries[fun] and not self.mem_fun_entries[fun][eip].disabled:
                    self.lgr.debug('dataWatch getMemParams data hit but 0x%x already in mem_fun_entries for %s' % (eip, fun))
                    skip_fun = True

                if (fun not in self.mem_fun_entries or eip not in self.mem_fun_entries[fun] or self.mem_fun_entries[fun][eip].disabled) and 'printf' not in fun and \
                                     'syslog' not in fun and 'memset' not  in fun and 'fgets' not in fun:
                    ret_addr_offset = None
                    if self.mem_something.ret_addr_addr is not None:
                        ret = self.mem_utils.readAppPtr(self.cpu, self.mem_something.ret_addr_addr, size=word_size)
                        if self.mem_something.ret_ip is not None and ret != self.mem_something.ret_ip:
                            self.lgr.debug('dataWatch getMemParams, do not believe we have an address of ret_addr.  ret: 0x%x  mem_something.ret_ip: 0x%x' % (ret, 
                               self.mem_something.ret_ip)) 
                            ''' do not believe we have an address of ret_addr '''
                            pass
                        else:
                            ret_addr_offset = sp - self.mem_something.ret_addr_addr 
                            self.lgr.debug('dataWatch getMemParam did step forward would record fun %s at 0x%x ret_addr ofset is %d ret_addr_addr 0x%x read ret_addr 0x%x, memsomething ret_ip 0x%x' % (fun, eip, ret_addr_offset, self.mem_something.ret_addr_addr, ret, self.mem_something.ret_ip))
                    else:
                        self.lgr.debug('dataWatch getMemParam ret_addr_addr is None, did step forward would record fun %s at 0x%x ret_addr ofset is None, assume lr retrun' % (fun, eip))
                    #if fun not in funs_need_addr:
                    self.lgr.debug('dataWatch getMemParams add mem_something_entry addr %s eip 0x%x' % (fun, eip))
                    if fun not in self.mem_fun_entries:
                        self.mem_fun_entries[fun] = {}
                    if eip not in self.mem_fun_entries[fun]:
                        self.mem_fun_entries[fun][eip] = self.MemCallRec(None, ret_addr_offset, eip)
                        self.added_mem_fun_entry = True
                    else:
                        self.lgr.debug('dataWatch getMemParms eip 0x%x already in mem_fun_entries, enable it' % eip)
                        self.mem_fun_entries[fun][eip].disabled = False 
                    self.watchFunEntries()
                #else:
                #    self.lgr.debug('dataWatch getMemParams, fun %s in mem_fun_entries? will return' % fun)
                #    return
            else:
                ''' adjust  to account for simics not adjusting sp on break on function entry '''
                sp = sp + self.mem_utils.wordSize(self.cpu)

            self.pending_call = True
            self.lgr.debug('dataWatch getMemParams, pending_call set True,  fun is %s' % self.mem_something.fun)
            cell = self.top.getCell()
            ''' use massive if block to get parameters. ''' 
            skip_fun = self.gatherCallParams(sp, eip, word_size, data_hit)
            self.lgr.debug('dataWatch getMemParams, back from gather')

            if data_hit: 
                ''' Assume we have disabled debugging in context manager while fussing with parameters. '''
                #self.top.restoreDebugBreaks(was_watching=True)
                #self.lgr.debug('dataWatch getMemParams, back from restore debug')
                pass
            elif self.mem_something.src is None:
                self.lgr.debug('dataWatch getMemParams src is None and data not hit, bail')
                self.pending_call = False
                return

            ''' NOTE returns above '''
            if len(self.mem_something.multi_index_list) == 0 and not data_hit and not skip_fun and self.mem_something.fun not in ['getenv', 'getopt']:
                self.lgr.debug('dataWatch not data_hit, find range for buf_start using src 0x%x' % self.mem_something.src)
                ''' see if src is one of our buffers '''
                buf_start = None
                buf_length = None    
                if self.mem_something.length is not None:
                    self.lgr.debug('dataWatch getMemParams count is not none %d' % self.mem_something.length)
                    buf_start, buf_length, dumb = self.findBufForRange(self.mem_something.src, self.mem_something.length)
                    if buf_start is None:
                        self.lgr.debug('dataWatch getMemParams count is not None but buf_start is None')
                else:
                    self.lgr.debug('dataWatch getMemParams count is None')
                    buf_index = self.findRangeIndex(self.mem_something.src)
                    if buf_index is not None:
                        buf_start = self.start[buf_index]
                        self.lgr.debug('dataWatch getMemParams count is None, buf_index not none')
                    else:
                        self.lgr.debug('dataWatch getMemParams count is None, and so is buf index for src 0x%x' % self.mem_something.src)
                if buf_start is None:
                    ''' handle ambigous calls such as strcmp '''
                    if self.mem_something.dest is not None:
                        buf_start, buf_length, dumb = self.findBufForRange(self.mem_something.dest, self.mem_something.length)
                    if buf_start is None:
                        self.lgr.debug('dataWatch getMemParams buf_start none, ambigous call like strcmp')
                        skip_fun = True
                        if self.mem_something.src is not None and self.mem_something.dest is not None:
                            self.lgr.debug('dataWatch getMemParams, src 0x%x and dst 0x%x not buffers we care about, skip it' % (self.mem_something.src,
                                 self.mem_something.dest))
                        elif self.mem_something.src is not None:
                            self.lgr.debug('dataWatch getMemParams, src 0x%x  not buffer we care about, skip it' % (self.mem_something.src))
                        no_buffer_found = True
                        # way to determine if breakpoint hap may follow this should be ignored.
                        self.last_buffer_not_found = self.mem_something.src
                        #self.mem_fun_entries[self.mem_something.fun][eip] = self.MemCallRec(None, ret_addr_offset, eip)
                        self.mem_fun_entries[self.mem_something.fun][eip].skip_count += 1
                        if self.mem_fun_entries[self.mem_something.fun][eip].skip_count > 10:
                            self.mem_fun_entries[self.mem_something.fun][eip].disabled = True
                            self.lgr.debug('dataWatch getMemparams disabled mem fun entry for %s' % self.mem_something.fun)
                            self.mem_fun_entries[self.mem_something.fun][eip].skip_count = 0
                            hap = self.mem_fun_entries[self.mem_something.fun][eip].hap
                            self.context_manager.genDeleteHap(hap)
                            self.mem_fun_entries[self.mem_something.fun][eip].hap = None
                            
                    else:
                        if self.mem_something.fun not in mem_copyish_functions:
                            self.lgr.debug('dataWatch getMemParams not via hit, not src, but found dest 0x%x in buf_start of 0x%x, swap src/dest' % (self.mem_something.dest, buf_start))
                            tmp = self.mem_something.src
                            self.mem_something.src = self.mem_something.dest
                            self.mem_something.dest = tmp
                        else:
                            self.lgr.debug('dataWatch getMemParams not via hit, not src, but found dest 0x%x in buf_start of 0x%x.  is cpyish, do not swap' % (self.mem_something.dest, buf_start))
                else:
                    if 'cmp' in self.mem_something.fun:
                        self.lgr.debug('dataWatch getMemParams not via hit, is cmp, do not mess with src')
                    else:
                        if self.mem_something.start is None:
                            self.mem_something.start = buf_start 
                        if self.mem_something.length is None:
                            self.mem_something.length = buf_length 
                        self.mem_something.op_type = Sim_Trans_Load
                    self.lgr.debug('dataWatch getMemParams fun %s not via hit, found src 0x%x in buf_start of 0x%x' % (self.mem_something.fun, self.mem_something.src, buf_start))
            if not skip_fun:
                if self.mem_something.fun in self.mem_fun_entries:
                    self.mem_fun_entries[self.mem_something.fun][eip].disabled = False
                if self.mem_something.ret_ip == 0:
                    self.lgr.error('dataWatch getMemParams ret_ip is zero, bail')
                    self.pending_call = False
                    return
                self.disableBreaks(filter='dataWatch')
                self.lgr.debug('call runToReturn')
                self.runToReturn()
                dum_cpu, comm, tid = self.task_utils.curThread()
                self.lgr.debug('getMemParams tid:%s (%s) eip: 0x%x fun %s set hap on ret_ip at 0x%x context %s hit: %r cycle: 0x%x Now run!' % (tid, comm, eip, 
                     self.mem_something.fun, self.mem_something.ret_ip, str(self.cpu.current_context), data_hit, self.cpu.cycles))
                if data_hit:
                    self.ignore_entry_cycle = self.cpu.cycles
                    SIM_continue(0)
                    #SIM_run_command('c')
            else:
                self.lgr.debug('dataWatch getMemParams skip fun.')
                self.pending_call = False
                # run to return, but do not gather anything
                if no_buffer_found:
                    self.lgr.debug('dataWatch getMemParams skip fun no buffer found.')
                    pass
                    #is_running = self.top.isRunning()
                    #if not is_running:
                    #    self.lgr.debug('getMemParams, not running, kick it.')
                    #    SIM_continue(0)
                else:
                    self.runToReturn(True)
                    if data_hit:
                        dum_cpu, comm, tid = self.task_utils.curThread()
                        self.lgr.debug('getMemParams tid:%s (%s) eip: 0x%x cycle: 0x%x skip fun from stop to gather, now run' % (tid, comm, eip, self.cpu.cycles))
                        SIM_continue(0)
                        #SIM_run_command('c')

    def multiBuffer(self, src, length, dest):
        '''
        Are there multiple watch buffers within the range?
        '''
        retval = False
        # use getIntersect to handle intersections of buffers
        multi_list = []
        end = src + length - 1
        self.lgr.debug('dataWatch multiBuffer look for multiple buffers between 0x%x and 0x%x' % (src, end))
        for index in range(len(self.start)):
            if self.start[index] is not None:
                inter_start, inter_length = self.getIntersect(self.start[index], self.length[index], src, length)
                #if self.start[index] >= src: 
                #    this_end = self.start[index] + self.length[index]
                #    #if this_end <= end:
                #    if self.start[index] <= end:
                #        index_list.append(index)
                if inter_start is not None:
                    multi_list.append((inter_start, inter_length))
                    self.lgr.debug('dataWatch multiBuffer added from index %d start 0x%x len %d' % (index, inter_start, inter_length))
        if len(multi_list) > 1:
            retval = True
            self.mem_something.multi_index_list = list(multi_list)
            self.mem_something.start = src
            self.mem_something.dest = dest
            # set these just to keep sanity check from failing in getMemParams
            self.mem_something.src = src
            self.mem_something.length = length
        return retval
 
    def gatherMemCpyCallParams(self, sp, eip, word_size, data_hit):
        '''
        at a memcpy type call.  Some special handling.  First, will check if multiple buffers are copied, e.g.,
        fields within a json. 
        '''
        skip_fun = False
        #self.mem_something.dest, self.mem_something.src, self.mem_something.length = self.getCallParams(sp, word_size)
        param_dest, param_src, param_length = self.getCallParams(sp, word_size)
        if param_src is None:
            self.lgr.error('dataWatch gatherMemCpyParams failed to get param_src for sp 0x%x' % sp)
            SIM_break_simulation('remove this')
            return True
        orig_param_length = param_length
        # Are there multiple buffers within this copy?
        if self.multiBuffer(param_src, param_length, param_dest):
            return False
        buf_start, buf_length, dumb = self.findBufForRange(param_src, param_length)
        if data_hit:
            ''' sanity check '''
            if buf_start is None:
                skip_fun = True
                if self.mem_something.addr is None:
                    self.lgr.debug('dataWatch gatherCallParams %s BAD FIND on fun entry (no data hit), src 0x%x count %d findBufForRange failed to find buf' % (self.mem_something.fun,
                        param_src, param_length))
                else:
                    self.lgr.debug('dataWatch gatherCallParams %s BAD FIND src 0x%x count %d but addr 0x%x  findBufForRange failed to find buf' % (self.mem_something.fun,
                        param_src, param_length, self.mem_something.addr))
            else:
                buf_end = buf_start + buf_length-1
                if self.mem_something.addr < buf_start or self.mem_something.addr > buf_end:
                    skip_fun = True
                    self.lgr.debug('dataWatch gatherCallParams %s BAD FIND got src 0x%x count %d but addr 0x%x' % (self.mem_something.fun, param_src, param_length,
                        self.mem_something.addr))
                else:
                    self.lgr.debug('dataWatch gatherCallParams %s got count %d src 0x%x dest 0x%x' % (self.mem_something.fun, param_length,
                        param_src, param_dest))
        if not skip_fun:
            ''' Special cases to change length and other esoterica '''
            if self.cpu.architecture.startswith('arm'):
                if self.cpu.architecture == 'arm64' and self.mem_utils.arm64App(self.cpu):
                    param_length = self.mem_utils.getRegValue(self.cpu, 'x2')
                else:
                    param_length = self.mem_utils.getRegValue(self.cpu, 'r2')
            elif self.cpu.architecture != 'ppc32': 
                if self.mem_something.fun == 'mempcpy':
                    so_file = self.top.getSOFile(eip)
                    if so_file is not None and 'libc' in so_file.lower():
                        count_addr = self.mem_utils.readAppPtr(self.cpu, sp+2*word_size, size=word_size)
                        param_length = self.mem_utils.readWord32(self.cpu, count_addr)
                        self.lgr.debug('mempcy but is libc count_addr 0x%x, count %d' % (count_addr, param_length))
                    else:
                        param_length = self.mem_utils.readWord32(self.cpu, sp+2*word_size)
                        self.lgr.debug('mempcy but not libc, so file %s  count %d' % (so_file, param_length))
                elif self.mem_something.fun != 'memcpy_xmm' and word_size == 4:
                    param_length = self.mem_utils.readWord32(self.cpu, sp+2*word_size)
            if param_length == 0:
                self.lgr.debug('dataWatch gatherCallParams sees 0 count for copy, skip this function.')
                self.pending_call = False
                skip_fun = True
            else:
                for oframe in self.mem_something.frames:
                    #self.lgr.debug('dataWatch gatherCallParams memsomething fun %s' % oframe.fun_name)
                    if oframe.fun_name is not None and oframe.fun_name == 'fgets':
                        #self.lgr.debug('dataWatch gatherCallParams memsomething is fgets.')
                        if oframe.ret_addr is not None:
                            #self.lgr.debug('dataWatch gatherCallParams fgets ret ip is 0x%x' % oframe.ret_addr)
                            self.mem_something.ret_ip = oframe.ret_addr
                            self.mem_something.fun = 'fgets'
                   
                pass
                #self.lgr.debug('gatherCallParams memcpy-ish dest 0x%x  src 0x%x count 0x%x' % (param_dest, param_src, 
                #    param_length))

            ''' recalculate buf_start and buf_length per new param_length '''
            skip_fun = self.bufferWithinBuffer(param_src, param_length, param_dest, orig_param_length)
        return skip_fun

    def bufferWithinBuffer(self, param_src, param_length, param_dest, orig_param_length):
        retval = False
        buf_start, buf_length, dumb = self.findBufForRange(param_src, param_length)
        if buf_start is not None:
            self.lgr.debug('dataWatch bufferWithinBuffer found buffer intersect start 0x%x length %d param_src was 0x%x len 0x%x' % (buf_start, buf_length, param_src, param_length))
            self.mem_something.src = buf_start
            self.mem_something.length = buf_length
            if buf_length < orig_param_length:
                self.mem_something.truncated = orig_param_length
                self.mem_something.start = param_src
                self.lgr.debug('dataWatch bufferWithinBuffer mem_somthing.start set to 0x%x' % param_src)
            if buf_start >= param_src:
                offset = buf_start - param_src
            else:
                offset = 0
            eip = self.top.getEIP(self.cpu)
            if param_dest is not None:
                self.mem_something.dest = param_dest + offset
                self.lgr.debug('dataWatch bufferWithinBuffer  eip: 0x%x %s src is 0x%x, count: %d dest 0x%x' % (eip, self.mem_something.fun, self.mem_something.src, 
                     self.mem_something.length, self.mem_something.dest))
                self.checkBufClobber(param_dest, param_length)
            else:
                self.mem_something.pos = offset
                self.lgr.debug('dataWatch bufferWithinBuffer  eip: 0x%x %s src is 0x%x, count: %d dest not yet known, offset will be 0x%x' % (eip, self.mem_something.fun, self.mem_something.src, 
                     self.mem_something.length, self.mem_something.pos))
        else:
            self.lgr.debug('dataWatch bufferWithinBuffer %s  buf_start None for param_src 0x%x' % (self.mem_something.fun, param_src))
            retval = True
        return retval

    def checkBufClobber(self, dest, length):
        buf_start, buf_length, index = self.findBufForRange(dest, length)
        if buf_start is not None:
            self.lgr.debug('dataWatch checkBufClobber dest 0x%x length 0x%x remove subrange 0x%x len 0x%x' % (dest, length, buf_start, buf_length))
            self.rmSubRange(buf_start, buf_length)

    def gatherCallParams(self, sp, eip, word_size, data_hit):
        skip_fun = False
        if self.mem_something.fun in mem_copyish_functions:
            self.lgr.debug('dataWatch gatherCallParams sp 0x%x ip 0x%x call gatherMemCpyCallParams' % (sp, eip))
            skip_fun = self.gatherMemCpyCallParams(sp, eip, word_size, data_hit)

        elif self.mem_something.fun == 'memset':
            self.mem_something.dest, dumb, self.mem_something.length = self.getCallParams(sp, word_size)
            self.mem_something.src = self.mem_something.dest
        elif self.mem_something.fun == 'memcmp':
            self.mem_something.dest, self.mem_something.src, self.mem_something.length = self.getCallParams(sp, word_size)
            self.lgr.debug('getmemParams memcmp dest 0x%x src 0x%x' % (self.mem_something.dest, self.mem_something.src))
        elif self.mem_something.fun == 'memchr':
            self.mem_something.src, self.mem_something.the_chr, self.mem_something.length = self.getCallParams(sp, word_size)
            self.lgr.debug('getmemParams memchr src 0x%x chr 0x%x' % (self.mem_something.src, self.mem_something.the_chr))
        elif self.mem_something.fun == 'strdup':
            self.mem_something.src, dumb1, dubm2 = self.getCallParams(sp, word_size)
            self.mem_something.length = self.getStrLen(self.mem_something.src)        
            self.lgr.debug('getmemParams strdup src 0x%x count %d (0x%x)' % (self.mem_something.src, self.mem_something.length, self.mem_something.length))
        elif self.mem_something.fun in ['strcpy', 'strncpy', 'strlcpy']:
            self.mem_something.dest, self.mem_something.src, maybe_count = self.getCallParams(sp, word_size)
            if self.mem_something.fun in ['strncpy', 'strlcpy']:
                self.mem_something.length = maybe_count
            else:
                self.mem_something.length = self.getStrLen(self.mem_something.src)        
            
            self.lgr.debug('gatherCallParams dest 0x%x src 0x%x count 0x%x' % (self.mem_something.dest, self.mem_something.src, self.mem_something.length))
        elif self.mem_something.fun in ['strcmp', 'strncmp', 'strnicmp', 'strcasecmp', 'strncasecmp', 'xmlStrcmp', 'strpbrk', 'strspn', 'strcspn','wcscmp', 'mbscmp', 
                                       'mbscmp_l', 'strtok', 'strstr', 'fnmatch']: 
            self.mem_something.dest, self.mem_something.src, count_maybe = self.getCallParams(sp, word_size)
            if self.mem_something.fun == 'strncmp':
                #limit = self.mem_utils.getRegValue(self.cpu, 'r2')
                limit = count_maybe
                self.mem_something.length = min(limit, self.getStrLen(self.mem_something.src))
            elif self.mem_something.fun == 'strtok':
                if self.mem_something.dest != 0:
                    self.strtok_ptr = self.mem_something.dest
                    the_str = self.mem_utils.readString(self.cpu, self.mem_something.dest, 40)
                    self.lgr.debug('dataWatch gatherParams %s new string at 0x%x: %s' % (self.mem_something.fun, self.mem_something.dest, the_str))
                else:
                    the_str = self.mem_utils.readString(self.cpu, self.strtok_ptr, 40)
                    self.lgr.debug('dataWatch gatherParams %s continue with prev string at 0x%x: %s' % (self.mem_something.fun, self.strtok_ptr, the_str))
                    self.mem_something.dest = self.strtok_ptr 
                self.mem_something.length = self.getStrLen(self.mem_something.src)        
            else:
                self.mem_something.length = self.getStrLen(self.mem_something.src)        

            self.lgr.debug('gatherCallParams %s, src: 0x%x dest: 0x%x count: %d' % (self.mem_something.fun, self.mem_something.src, 
                     self.mem_something.dest, self.mem_something.length))
        elif self.mem_something.fun in ['string_strncmp']:
            # src may be a chr string, or a string type like dest
            #obj, self.mem_something.src, count_maybe = self.getCallParams(sp, word_size)
            dest, src, count_maybe = self.getCallParams(sp, word_size)
            limit = count_maybe
            src_char = self.mem_utils.readByte(self.cpu, src)
            if src_char == 0:
                self.lgr.debug('gatherCallParams src is a string object addr 0x%x' % src)
                self.mem_something.src = self.mem_utils.readPtr(self.cpu, src+8)
            else:
                self.mem_something.src = src
            dest_char = self.mem_utils.readByte(self.cpu, dest)
            if dest_char == 0:
                self.lgr.debug('gatherCallParams dest is a string object addr 0x%x' % dest)
                self.mem_something.dest = self.mem_utils.readPtr(self.cpu, dest+8)
            else:
                self.mem_something.dest = dest
            self.mem_something.length = min(limit, self.getStrLen(self.mem_something.src))
            self.lgr.debug('gatherCallParams %s, src: 0x%x dest: 0x%x count: %d' % (self.mem_something.fun, self.mem_something.src, 
                     self.mem_something.dest, self.mem_something.length))

        elif self.mem_something.fun in ['buffer_caseless_compare']:
            self.mem_something.dest, self.mem_something.length, self.mem_something.src = self.getCallParams(sp, word_size)

        elif self.mem_something.fun in ['strchr', 'strrchr']:
            self.mem_something.src, self.mem_something.the_chr, dumb = self.getCallParams(sp, word_size)
            self.lgr.debug('gatherCallParams fun %s src 0x%x' % (self.mem_something.fun, self.mem_something.src))
            if self.mem_something.src is None:
                self.lgr.error('got none for src cycle: 0x%x' % (self.mem_something.fun, self.cpu.cycles))
            # TBD had this for 8 byte words  A windows thing?
            #   self.mem_something.the_chr, self.mem_something.src, dumb = self.getCallParams(sp, word_size)
            ''' TBD fix to reflect strnchr? '''
            self.mem_something.length=1
        elif self.mem_something.fun in ['strtoul', 'strtoull', 'strtol', 'strtoll', 'strtoq', 'atoi']:
            self.mem_something.src, dumb2, dumb = self.getCallParams(sp, word_size)
        elif self.mem_something.fun in ['ByteArray5toInt']:
            dumb1, dumb2, self.mem_something.count = self.getCallParams(sp, word_size)
            this = self.mem_utils.getRegValue(self.cpu, 'this')
            struct_addr = self.mem_utils.readAppPtr(self.cpu, this, size=word_size)
            self.mem_something.src = struct_addr+0x10
        elif self.mem_something.fun in ['String5toInt']:
            this = self.mem_utils.getRegValue(self.cpu, 'this')
            struct_addr = self.mem_utils.readAppPtr(self.cpu, this, size=word_size)
            self.mem_something.src = struct_addr+0x10
            self.lgr.debug('dataWatch gatherParams %s this 0x%x struct_addr 0x%x src 0x%x' % (self.mem_something.fun, this, struct_addr, self.mem_something.src))
        elif self.mem_something.fun == 'sscanf':
            self.mem_something.src, format_addr, dumb2 = self.getCallParams(sp, word_size)
            format_str = self.mem_utils.readString(self.cpu, format_addr, 40)
            nparams = format_str.count('%')
            for i in range(nparams):
                offset = (i)*word_size
                param = self.mem_utils.readAppPtr(self.cpu, format_addr+offset, size=word_size)
                self.mem_something.dest_list.append(param) 
            ''' TBD fix this '''
            self.mem_something.length = 1
        elif self.mem_something.fun == 'string_strlen':
            obj, dumb, dumb2 = self.getCallParams(sp, word_size)
            self.mem_something.src = self.mem_utils.readWord(self.cpu, (obj+8))
            self.lgr.debug('dataWatch gatherCallParams is %s, call getStrLen for src 0x%x' % (self.mem_something.fun, self.mem_something.src))
            self.mem_something.length = self.getStrLen(self.mem_something.src)        
        elif self.mem_something.fun == 'strlen':
            self.mem_something.src, dumb, dumb2 = self.getCallParams(sp, word_size)
            self.lgr.debug('dataWatch gatherCallParams is strlen, call getStrLen for 0x%x' % self.mem_something.src)
            self.mem_something.length = self.getStrLen(self.mem_something.src)        
            self.lgr.debug('dataWatch gatherCallParams back from getStrLen')
        elif self.mem_something.fun in ['vsnprintf', 'sprintf', 'snprintf', 'vasprintf', 'asprintf']:
            # TBD generalized this
            if word_size == 8:
                dumb2, self.mem_something.dest, dumb = self.getCallParams(sp, word_size)
            else:
                self.mem_something.dest, dumb2 , dumb = self.getCallParams(sp, word_size)
        elif self.mem_something.fun in ['fprintf', 'printf', 'vfprintf', 'syslog']:
            #dumb2, self.mem_something.src, dumb = self.getCallParams(sp, word_size)
            # TBD parse args
            pass

        elif self.mem_something.fun in ['output_processor']:
            dumb2, self.mem_something.src, dumb = self.getCallParams(sp, word_size)
            self.lgr.debug('dataWatch gatherCallParams output_processor src is 0x%x' % self.mem_something.src)

        elif self.mem_something.fun == 'fwrite' or self.mem_something.fun == 'IO_do_write':
            self.mem_something.src, self.mem_something.length, dumb = self.getCallParams(sp, word_size)

        elif self.mem_something.fun == 'glob' or self.mem_something.fun == 'IO_do_write':
            self.mem_something.src, dumb1, dumb = self.getCallParams(sp, word_size)

        elif self.mem_something.fun == 'inet_addr':
            self.mem_something.src, dumb2 , dumb = self.getCallParams(sp, word_size)
            self.mem_something.length = self.getStrLen(self.mem_something.src)        
            self.mem_something.the_string = self.mem_utils.readString(self.cpu, self.mem_something.src, self.mem_something.length)

        elif self.mem_something.fun == 'inet_ntop':
            dumb1, dumb2, self.mem_something.dest = self.getCallParams(sp, word_size)
        elif self.mem_something.fun in ['getenv', 'regexec', 'ostream_insert', 'trim', 'QStringHash', 'JsonObject5value', 'JsonObjectix', 'JsonValueRef']:
            self.lgr.debug('dataWatch getMemParms %s' % self.mem_something.fun)
            self.mem_something.src, dumb1, dumb = self.getCallParams(sp, word_size)

        elif self.mem_something.fun == 'string_std':
            this, src_addr, dumb2 = self.getCallParams(sp, word_size)
            self.mem_something.src = self.mem_utils.readAppPtr(self.cpu, src_addr, size=word_size)
            self.lgr.debug('dataWatch getMemParms eip: 0x%x %s src([r1]) is 0x%x, this: 0x%x' % (eip, self.mem_something.fun, self.mem_something.src, this))
            
        elif self.mem_something.fun == 'string_chr':
            this, self.mem_something.src, dumb2 = self.getCallParams(sp, word_size)
            self.lgr.debug('dataWatch getMemParms  eip: 0x%x %s src(r1) is 0x%x, this: 0x%x' % (eip, self.mem_something.fun, self.mem_something.src, this))

        elif self.mem_something.fun == 'str':
            this, src_addr, dumb2 = self.getCallParams(sp, word_size)
            self.mem_something.src = self.mem_utils.readAppPtr(self.cpu, src_addr, size=word_size)
            self.lgr.debug('dataWatch getMemParms eip: 0x%x %s src([r1]) is 0x%x, this: 0x%x' % (eip, self.mem_something.fun, self.mem_something.src, this))

        elif self.mem_something.fun == 'string_basic_char':
            self.mem_something.ret_addr_addr, self.mem_something.src, self.mem_something.length = self.getCallParams(sp, word_size)
            #self.mem_something.ret_addr_addr, self.mem_something.src, dumb = self.getCallParams(sp)
            self.lgr.debug('dataWatch getMemParms  eip: 0x%x %s src is 0x%x, ret_addr_addr(this): 0x%x count: %d' % (eip, self.mem_something.fun, self.mem_something.src, 
                 self.mem_something.ret_addr_addr, self.mem_something.length))

        elif self.mem_something.fun == 'string_basic_std':
            src_addr, self.mem_something.length, dumb = self.getCallParams(sp, word_size)
            self.mem_something.src = self.mem_utils.readAppPtr(self.cpu, src_addr, size=word_size)
            self.lgr.debug('dataWatch getMemParms eip: 0x%x %s src([r1]) is 0x%x, count %d' % (eip, self.mem_something.fun, self.mem_something.src, self.mem_something.length))

        elif self.mem_something.fun == 'string_win_basic_char':
            self.mem_something.src, self.mem_something.length, dumb = self.getCallParams(sp, word_size)
            the_string = self.mem_utils.readString(self.cpu, self.mem_something.src, 1000)
            # TBD some instances do not have a count.  See clibFuns signature, if char is first in parens, then there is a count?
            self.mem_something.length = min(len(the_string), self.mem_something.length)
            self.lgr.debug('dataWatch getMemParms  eip: 0x%x %s src is 0x%x, count: %d' % (eip, self.mem_something.fun, self.mem_something.src, 
                 self.mem_something.length))

        elif self.mem_something.fun == 'basic_istringstream':
            src_struct, dumb, dumb2 = self.getCallParams(sp, word_size)
            self.mem_something.src = self.mem_utils.readAppPtr(self.cpu,  src_struct+4)
            the_string = self.mem_utils.readString(self.cpu, self.mem_something.src, 1000)
            self.mem_something.length = len(the_string)
            self.lgr.debug('dataWatch getMemParms  eip: 0x%x %s src is 0x%x, count: %d' % (eip, self.mem_something.fun, self.mem_something.src, 
                 self.mem_something.length))

        elif self.mem_something.fun in ['String4left', 'String3mid', 'Stringa', 'String3arg']:
            src_addr_addr, count, dumb2 = self.getCallParams(sp, word_size)
            src_addr = self.mem_utils.readAppPtr(self.cpu,  src_addr_addr)
            count = self.mem_utils.readWord32(self.cpu, src_addr+word_size)
            start, length, dumb = self.findBufForRange(src_addr, count)
            if start is None:
                self.lgr.debug('dataWatch getMemParams %s failed to find buf for addr 0x%x count %d' % (self.mem_something.fun, src_addr, count))
                skip_fun = True
            else:
                self.mem_something.src = start
                self.mem_something.length = length
                # misuse of field to store start address of src struct to determine offset within dest String
                self.mem_something.ret_addr_addr = src_addr
                self.lgr.debug('dataWatch getMemParms  eip: 0x%x %s src is 0x%x, count: %d' % (eip, self.mem_something.fun, self.mem_something.src, 
                     self.mem_something.length))

        elif self.mem_something.fun == 'StringS1_eq':
            src_addr_addr, dst_addr_addr, dump = self.getCallParams(sp, word_size)
            src_addr = self.mem_utils.readAppPtr(self.cpu, src_addr_addr, size=word_size)
            self.mem_something.src = src_addr + 0x10
            dest_addr = self.mem_utils.readAppPtr(self.cpu, dst_addr_addr, size=word_size)
            self.mem_something.dest = dest_addr + 0x10
            self.mem_something.length = self.mem_utils.readWord32(self.cpu, src_addr+word_size)
            self.lgr.debug('dataWatch getMemParms  eip: 0x%x %s src is 0x%x, dest: 0x%x count: %d' % (eip, self.mem_something.fun, self.mem_something.src, 
                 self.mem_something.dest, self.mem_something.length))

        elif self.mem_something.fun == 'Stringeq':
            this = self.mem_utils.getRegValue(self.cpu, 'this')
            self.mem_something.src = self.mem_utils.readAppPtr(self.cpu, this, size=word_size)
            dst_addr_addr, dumb, dumb2 = self.getCallParams(sp, word_size)
            dst_addr = self.mem_utils.readAppPtr(self.cpu, dst_addr_addr, size=word_size) 
            self.mem_something.dest = dst_addr + 0x10
            self.mem_something.length = self.mem_utils.readWord32(self.cpu, dst_addr+word_size)
            self.lgr.debug('dataWatch getMemParams %s this 0x%x src 0x%x dest 0x%x length %d' % (self.mem_something.fun, this, self.mem_something.src, self.mem_something.dest, self.mem_something.length))

        elif self.mem_something.fun == 'replace_std':
            self.mem_something.ret_addr_addr, self.mem_something.pos, self.mem_something.length, src_addr = self.get4CallParams(sp)
            self.mem_something.src = self.mem_utils.readAppPtr(self.cpu, src_addr, size=word_size)
            self.lgr.debug('dataWatch getMemParms 0x%x %s src([r3]) is 0x%x, this: 0x%x' % (eip, self.mem_something.fun, self.mem_something.src, self.mem_something.ret_addr_addr))
            
        elif self.mem_something.fun == 'replace_chr':
            self.mem_something.ret_addr_addr, self.mem_something.pos, self.mem_something.length, self.mem_something.src = self.get4CallParams(sp)
            if self.mem_something.length == 0:
                self.mem_something.length = self.getStrLen(self.mem_something.src)        
            self.lgr.debug('dataWatch getMemParms 0x%x %s src(r3) is 0x%x len %d, this: 0x%x' % (eip, self.mem_something.fun, self.mem_something.src, self.mem_something.length, self.mem_something.ret_addr_addr))
        elif self.mem_something.fun == 'replace_safe':
            self.mem_something.ret_addr_addr, self.mem_something.pos, self.mem_something.length, self.mem_something.src = self.get4CallParams(sp)
            index = self.findRangeIndex(self.mem_something.src)
            if index is not None:
                maybe_this = self.start[index] - 0xc
                maybe_len = self.mem_utils.readWord32(self.cpu, maybe_this)
                if maybe_len == self.length[index]:
                    self.lgr.debug('dataWatch gatherCallParams smells like an object pointer, adjust start to include it.  start[%d] now 0x%x' % (index, maybe_this))
                    self.start[index] = maybe_this

            if self.mem_something.length == 0:
                self.mem_something.length = self.getStrLen(self.mem_something.src)        
            self.lgr.debug('dataWatch getMemParms 0x%x %s src(r3) is 0x%x len %d' % (eip, self.mem_something.fun, self.mem_something.src, self.mem_something.length))

        elif self.mem_something.fun == 'append_chr_n':
            this, self.mem_something.src, self.mem_something.length = self.getCallParams(sp, word_size)
            self.lgr.debug('dataWatch getMemParms %s src(r1) is 0x%x len %d' % (self.mem_something.fun, self.mem_something.src, self.mem_something.length))
        elif self.mem_something.fun == 'append_chr':
            this, self.mem_something.src, dumb = self.getCallParams(sp, word_size)
            self.mem_something.length = self.getStrLen(self.mem_something.src)        
            self.lgr.debug('dataWatch getMemParms %s src(r1) is 0x%x len %d' % (self.mem_something.fun, self.mem_something.src, self.mem_something.length))
        elif self.mem_something.fun == 'append_std':
            this, src_addr, dumb = self.getCallParams(sp, word_size)
            self.mem_something.src = self.mem_utils.readAppPtr(self.cpu, src_addr, size=word_size)
            self.mem_something.length = 1
            self.lgr.warning('dataWatch gatherCallParams append_std length?')
        elif self.mem_something.fun == 'assign_chr':
            ''' TBD extend for (char *, len)'''
            this, self.mem_something.src, dumb = self.getCallParams(sp, word_size)
            self.mem_something.length = self.getStrLen(self.mem_something.src)        
            self.lgr.debug('dataWatch getMemParms %s src(r1) is 0x%x len %d' % (self.mem_something.fun, self.mem_something.src, self.mem_something.length))
        elif self.mem_something.fun == 'compare_chr':
            ''' TBD extend for (char *, len)'''
            obj_ptr, self.mem_something.src, dumb = self.getCallParams(sp, word_size)
            self.mem_something.length = self.getStrLen(self.mem_something.src)        
            self.mem_something.dest = self.mem_utils.readAppPtr(self.cpu, obj_ptr, size=word_size)
            self.lgr.debug('dataWatch getMemParms %s 0x%x to 0x%x len %d' % (self.mem_something.fun, self.mem_something.src, self.mem_something.dest, self.mem_something.length))
        elif self.mem_something.fun in ['charLookup']:
            r0 = self.mem_utils.getRegValue(self.cpu, 'syscall_ret')
            self.mem_something.ret_addr_addr = self.mem_utils.readAppPtr(self.cpu, r0, size=word_size)
            if self.mem_something.ret_addr_addr is not None and (self.mem_something.addr is not None or not data_hit):
                if self.mem_something.addr is not None:
                    self.lgr.debug('dataWatch getMemParms %s addr 0x%x r0 0x%x ret_addr_addr 0x%x data_hit %r' % (self.mem_something.fun, self.mem_something.addr, 
                        r0, self.mem_something.ret_addr_addr, data_hit))
                else:
                    self.lgr.debug('dataWatch getMemParms %s (not a data hit) r0 0x%x ret_addr_addr 0x%x data_hit %r' % (self.mem_something.fun, r0, self.mem_something.ret_addr_addr, data_hit))
            elif self.mem_something.ret_addr_addr is None:
                self.skip_entries.append(self.mem_something.fun_addr)
                self.added_mem_fun_entry = True
                self.lgr.debug('dataWatch getMemParms %s addr %s ret_addr_addr is None? data_hit %r, add to skip_entries' % (self.mem_something.fun, str(self.mem_something.addr), data_hit))
                skip_fun = True
            else:
                self.skip_entries.append(self.mem_something.fun_addr)
                self.added_mem_fun_entry = True
                self.lgr.debug('dataWatch getMemParms %s addr %s ret_addr_addr is unknown? add to skip_entries' % (self.mem_something.fun, str(self.mem_something.addr)))
                skip_fun = True
        elif self.mem_something.fun in ['charLookupX', 'charLookupY']:
            r0 = self.mem_utils.getRegValue(self.cpu, 'syscall_ret')
            end_ptr = r0 + 0x10
            end_addr = self.mem_utils.readAppPtr(self.cpu, end_ptr, size=word_size)
           
            cur_ptr = r0 + 0x14
            cur_addr = self.mem_utils.readAppPtr(self.cpu, cur_ptr, size=word_size)
            if end_addr is not None and cur_addr is not None:
                length = end_addr - cur_addr + 1
                self.lgr.debug('dataWatch getMemParams %s cur_addr 0x%x end 0x%x length 0x%x' % (self.mem_something.fun, cur_addr, end_addr, length))
                self.mem_something.length = length
                self.mem_something.ret_addr_addr = cur_ptr
            if self.mem_something.ret_addr_addr is not None and (self.mem_something.addr is not None or not data_hit):
                if self.mem_something.addr is not None:
                    self.lgr.debug('dataWatch getMemParms %s addr 0x%x r0 0x%x cur_ptr 0x%x data_hit %r' % (self.mem_something.fun, self.mem_something.addr, 
                        r0, self.mem_something.ret_addr_addr, data_hit))
                else:
                    self.lgr.debug('dataWatch getMemParms %s (not a data hit) r0 0x%x cur_ptr 0x%x data_hit %r' % (self.mem_something.fun, r0, self.mem_something.ret_addr_addr, data_hit))
            else:
                self.skip_entries.append(self.mem_something.fun_addr)
                self.added_mem_fun_entry = True
                self.lgr.debug('dataWatch getMemParms %s addr %s cur_ptr is unknown? add to skip_entries' % (self.mem_something.fun, str(self.mem_something.addr)))
                skip_fun = True
        elif self.mem_something.fun == 'UuidToStringA':
            src_addr, this, dumb = self.getCallParams(sp, word_size)
            self.mem_something.src_addr = src_addr
            self.mem_something.ret_addr_addr = this
            self.mem_something.length = 16
            self.lgr.debug('dataWatch getMemParams %s this addr 0x%x src_addr 0x%x' % (self.mem_something.fun, this, src_addr))
                 
        elif self.mem_something.fun == 'fgets':
            # TBD was commented out. 
            self.mem_something.dest, self.mem_something.length, dumb = self.getCallParams(sp, word_size)

        elif self.mem_something.fun == 'fputs':
            # TBD was commented out. 
            self.mem_something.src, dumb2, dumb = self.getCallParams(sp, word_size)

        elif self.mem_something.fun.startswith('WSAAddressToString'):
            self.mem_something.src, self.mem_something.length, dumb = self.getCallParams(sp, word_size)
            self.mem_something.dest = self.mem_utils.readAppPtr(self.cpu, sp+3*word_size, size=word_size)
            self.lgr.debug('dataWatch getMemParams %s src 0x%x dest 0x%x count %d' % (self.mem_something.fun, self.mem_something.src, self.mem_something.dest, self.mem_something.length))

        elif self.mem_something.fun == 'realloc':
            self.mem_something.dumb2, self.mem_something.src, dumb = self.getCallParams(sp, word_size)
            self.lgr.debug('dataWatch getMemParams %s src 0x%x' % (self.mem_something.fun, self.mem_something.src))
        elif self.mem_something.fun == 'getopt':
            self.mem_something.length, self.mem_something.src, optstring_addr = self.getCallParams(sp, word_size)
            if optstring_addr is not None:
                self.mem_something.the_string = self.mem_utils.readString(self.cpu, optstring_addr, 100)
                self.lgr.debug('dataWatch getMemParams %s argc %d, argv 0x%x optstring: 0x%x %s' % (self.mem_something.fun, self.mem_something.length, self.mem_something.src, 
                     optstring_addr, self.mem_something.the_string))
            else:
                self.lgr.debug('dataWatch getMemParams %s argc %d, argv 0x%x no optstring' % (self.mem_something.length, self.mem_something.src))

        elif self.mem_something.fun == 'String16fromAscii_helper':
            param_src, dumb2, dumb = self.getCallParams(sp, word_size)
            self.mem_something.the_string = self.mem_utils.readString(self.cpu, param_src, 100)
            param_length = self.getStrLen(param_src, only_ascii=True)        
            if self.mem_something.the_string is None or len(self.mem_something.the_string) == 0:
                self.lgr.debug('dataWatch getMemParams %s src: 0x%x string is NULL, bail' % (self.mem_something.fun, param_src))
                skip_fun = True
            else:
                self.lgr.debug('dataWatch getMemParams %s src: 0x%x string %s' % (self.mem_something.fun, param_src, self.mem_something.the_string))
                skip_fun = self.bufferWithinBuffer(param_src, param_length, None, param_length)

        elif self.mem_something.fun == 'String5split':
            struct_addr_addr, dumb2, dumb = self.getCallParams(sp, word_size)
            delim_addr_addr = struct_addr_addr + word_size
            struct_addr = self.mem_utils.readAppPtr(self.cpu, struct_addr_addr, size=word_size)
            src_len_addr = struct_addr + word_size
            src_len = self.mem_utils.readWord32(self.cpu, src_len_addr)
            self.mem_something.src = struct_addr + 0x10
            delim_addr = self.mem_utils.readAppPtr(self.cpu, delim_addr_addr, size=word_size) 
            delim_len_addr = delim_addr + word_size
            delim_len = self.mem_utils.readWord32(self.cpu, delim_len_addr)
            delim_chr_addr = delim_addr+0x10
            delim = self.mem_utils.readString(self.cpu, delim_chr_addr, delim_len) 
            self.mem_something.the_string = delim
            self.lgr.debug('%s struct_addr 0x%x src_len 0x%x src 0x%x delim_addr 0x%x delim %s' % (self.mem_something.fun, struct_addr, src_len, self.mem_something.src, delim_addr, delim))
        elif self.mem_something.fun == 'String14compare_helper':
            self.mem_something.src, self.mem_something.length, self.mem_something.dest = self.getCallParams(sp, word_size)
            self.mem_something.the_string = self.mem_utils.readString(self.cpu, self.mem_something.dest, self.mem_something.length)
        elif self.mem_something.fun == 'String14compare_helper_latin':
            self.mem_something.src, self.mem_something.length, dumb = self.getCallParams(sp, word_size)
            self.mem_something.dest = self.mem_utils.readAppPtr(self.cpu, sp+3*word_size, size=word_size)
            self.mem_something.the_string = self.mem_utils.readString(self.cpu, self.mem_something.dest, self.mem_something.length)
        elif self.mem_something.fun == 'String6toUtf8':
            struct_addr_addr, dumb2, dumb = self.getCallParams(sp, word_size)
            struct_addr = self.mem_utils.readAppPtr(self.cpu, struct_addr_addr, size=word_size)
            self.mem_something.src = struct_addr + 0x10
            src_len_addr = struct_addr + word_size
            src_len = self.mem_utils.readWord32(self.cpu, src_len_addr)
            # stash len in count, will replace with count of moved data (ascii string)
            self.mem_something.length = src_len

        # Begin XML
        elif self.mem_something.fun == 'xmlGetProp':
            self.mem_something.src, dumb2, dumb = self.getCallParams(sp, word_size)
            self.mem_something.length = self.getStrLen(self.mem_something.src)        
            self.mem_something.the_string = self.mem_utils.readString(self.cpu, self.mem_something.src, self.mem_something.length)
        elif self.mem_something.fun == 'GetToken':
            self.mem_something.src, dumb2, dumb = self.getCallParams(sp, word_size)
        elif self.mem_something.fun == 'xmlrpc_base64_decode':
            self.mem_something.src, dumb2, dumb = self.getCallParams(sp, word_size)

        elif self.mem_something.fun == 'FreeXMLDoc':
            self.mem_something.length = 0

        elif self.mem_something.fun in ['xmlParseFile', 'xml_parse', 'xmlParseChunk']:
            self.me_trace_malloc = True
            self.top.traceMalloc()
            self.lgr.debug('gatherCallParams xml parse')
            if self.mem_something.fun == 'xmlParseChunk':
                  dumb2, self.mem_something.src, dumb = self.getCallParams(sp, word_size)
      
        return skip_fun             


    def runToReturnXXXX(self, skip_this=False):
        # TBD why 2 functions?
        self.lgr.debug('dataWatch runToReturn current context is %s' % str(self.cpu.current_context))
        resim_context = self.context_manager.getRESimContext()
        proc_break = self.context_manager.genBreakpoint(resim_context, Sim_Break_Linear, Sim_Access_Execute, self.mem_something.ret_ip, 1, 0)
        self.return_hap = self.context_manager.genHapIndex("Core_Breakpoint_Memop", self.returnHap, skip_this, proc_break, 'memcpy_return_hap')
        self.context_manager.restoreDebugContext()
        if self.backstop is not None and not self.break_simulation and self.use_backstop:
            self.lgr.debug('dataWatch runToReturn clear backstop')
            self.backstop.clearCycle()

    def runToReturnAndGo(self, skip_this=False):
        self.runToReturn(skip_this=skip_this)
        if self.mem_something.run:
            SIM_continue(0)
    
    def runToReturn(self, skip_this=False):
        cell = self.top.getCell()
        resim_context = self.context_manager.getRESimContext()
        #proc_break = self.context_manager.genBreakpoint(cell, Sim_Break_Linear, Sim_Access_Execute, self.mem_something.ret_ip, 1, 0)
        proc_break = self.context_manager.genBreakpoint(resim_context, Sim_Break_Linear, Sim_Access_Execute, self.mem_something.ret_ip, 1, 0)
        self.return_hap = self.context_manager.genHapIndex("Core_Breakpoint_Memop", self.returnHap, skip_this, proc_break, 'memsomething_return_hap')
        self.lgr.debug('runToReturn set returnHap with breakpoint %d break at ret_ip 0x%x' % (proc_break, self.mem_something.ret_ip))
        self.context_manager.restoreDebugContext()
        if self.backstop is not None and not self.break_simulation and self.use_backstop:
            self.lgr.debug('dataWatch runToReturnAlone clear backstop')
            self.backstop.clearCycle()

    def undoHap(self, dumb, one, exception, error_string):
        
        if self.undo_hap is not None:
            self.lgr.debug('dataWatch undoHap')
            self.top.RES_delete_stop_hap(self.undo_hap)
            self.undo_hap = None
            SIM_run_alone(self.undoAlone, None)

    def undoAlone(self, dumb):
            #oneless = self.save_cycle -1
            oneless = self.save_cycle 
            self.lgr.debug('dataWatch undoAlone skip back to 0x%x' % oneless)
            if not self.top.skipToCycle(oneless, cpu=self.cpu, disable=True):
                self.lgr.error('dataWatch undoAlone unable to skip to save cycle 0x%x, got 0x%x' % (oneless, self.cpu.cycles))
                return
    
            eip = self.top.getEIP(self.cpu)
            dum_cpu, comm, tid = self.task_utils.curThread()
            self.lgr.debug('dataWatch skip done eip 0x%x tid %s cycle 0x%x' % (eip, tid, self.cpu.cycles))
            self.watch(i_am_alone=True)
            '''
            addr = self.mem_something.src
            if self.mem_something.op_type != Sim_Trans_Load or addr is None:
                addr = self.mem_something.dest

            '''
            self.watchMarks.dataRead(self.mem_something.addr, self.mem_something.start, self.mem_something.length, self.mem_something.trans_size, ip=eip, cycles=self.cpu.cycles)
            self.lgr.debug('dataWatch undoAlone eip: 0x%x would run forward, first restore debug context' % eip)
            self.context_manager.restoreDebugContext()
            self.enableBreaks()
            self.backstop.setFutureCycle(self.backstop_cycles)
            self.lgr.debug('dataWatch undoAlone now run forward')

            #SIM_run_command('c')
            SIM_continue(0)

    def rmCallHap(self):
        if self.call_hap is not None:
            self.reverse_mgr.SIM_delete_breakpoint(self.call_break)
            SIM_hap_delete_callback_id("Core_Breakpoint_Memop", self.call_hap)
            self.call_hap = None
            self.call_break = None

    def hitCallStopHap(self, called_from_reverse_mgr, one, exception, error_string):
        #self.lgr.debug('dataWatch hitCallStopHap execption %s  error_string %s cycle: 0x%x' % (exception, error_string, self.cpu.cycles))
        if self.call_stop_hap is not None or called_from_reverse_mgr is not None:
            self.enableBreaks()
            SIM_run_alone(self.hitCallStopHapAlone, called_from_reverse_mgr)
 
    def hitCallStopHapAlone(self, called_from_reverse_mgr):
        self.context_manager.clearReverseContext()
        SIM_run_command('enable-vmp') 
        
        ''' we are at the call to a memsomething, get the parameters '''
        eip = self.top.getEIP(self.cpu)
        first_cycle = self.top.getFirstCycle()
        self.lgr.debug('DataWatch hitCallStopHap eip 0x%x cycles: 0x%x first_cycle: 0x%x' % (eip, self.cpu.cycles, first_cycle))
        cycle_dif = self.cycles_was - self.cpu.cycles
        #self.lgr.debug('hitCallStopHap will delete call_stop_hap %d cycle_dif 0x%x' % (self.call_stop_hap, cycle_dif))
        if called_from_reverse_mgr is None:
            self.top.RES_delete_stop_hap(self.call_stop_hap)
        self.call_stop_hap = None
        #self.rmCallHap()
        self.lgr.debug('hitCallStopHap remove call_break %d' % self.call_break)
        self.reverse_mgr.SIM_delete_breakpoint(self.call_break)
        self.call_break = None
        ''' TBD dynamically adjust cycle_dif limit?  make exceptions for some calls, e.g., xmlparse? '''
        #if eip != self.mem_something.called_from_ip or cycle_dif > 300000:
        if self.cpu.cycles == first_cycle:
            self.lgr.debug('hitCallStopHap stopped at original bookmark, assume a ghost frame')
            self.undo_pending = True
            SIM_run_alone(self.undoAlone, self.mem_something)
        if self.cpu.cycles == self.prev_mark_cycle:
            sp = self.mem_utils.getRegValue(self.cpu, 'sp')
            if self.top.isVxDKM(cpu=self.cpu) and sp < self.mem_something.ret_addr_addr:
                self.lgr.debug('dataWatch hitCallStopHap stopped at previous watchmark, but is vxworks and stack frame still good, assume all is well and delete prev watch mark')
                self.watchMarks.rmLast(1)
                SIM_run_alone(self.getMemParams, True)
            else:
                self.lgr.debug('dataWatch hitCallStopHap stopped at previous watchmark, assume a ghost frame sp is 0x%x' % sp)
                self.undo_pending = True
                self.recent_ghost_call_addr = self.mem_something.called_from_ip
                SIM_run_alone(self.undoAlone, self.mem_something)

        elif eip != self.mem_something.called_from_ip or cycle_dif > 0xF000000:
            if eip != self.mem_something.called_from_ip:
                self.lgr.debug('dataWatch hitCallStopHap not stopped on expected call. Wanted 0x%x got 0x%x assume a ghost frame' % (self.mem_something.called_from_ip, eip))
            else:
                self.lgr.debug('dataWatch hitCallStopHap stopped too far back cycle_dif 0x%x, assume a ghost frame' % cycle_dif)
            self.undo_pending = True
            SIM_run_alone(self.undoAlone, self.mem_something)
        else:
            latest_cycle = self.watchMarks.latestCycle()
            if latest_cycle is not None:
                if self.mem_something.fun not in no_ghosts and latest_cycle > self.cpu.cycles:
                    # TBD better way to know this is our stack frame 
                    sp = self.mem_utils.getRegValue(self.cpu, 'sp') - 0x10
                    if self.mem_something.ret_addr_addr is not None:
                        self.lgr.debug('dataWatch dataWatch hitCallStopHap cycle past latest.  sp is 0x%x ret_addr_addr 0x%x' % (sp, self.mem_something.ret_addr_addr))
                    if self.mem_something.ret_addr_addr is None or (self.top.isVxDKM(cpu=self.cpu) and sp < self.mem_something.ret_addr_addr):
                        self.lgr.debug('dataWatch hitCallStopHap stopped at 0x%x, prior to most recent watch mark having cycle: 0x%x, no ret_addr_addr or sp retval still good, so assume recent watch mark is a subfunction of the memsomething.  Remove the subfunction' % (self.cpu.cycles, latest_cycle))
                        self.watchMarks.rmLast(1)
                        SIM_run_alone(self.getMemParams, True)
                    else:
                        self.lgr.debug('dataWatch hitCallStopHap stopped at 0x%x, prior to most recent watch mark having cycle: 0x%x, assume a ghost frame' % (self.cpu.cycles, latest_cycle))
                        self.undo_pending = True
                        SIM_run_alone(self.undoAlone, self.mem_something)
                else:
                    self.lgr.debug('dataWatch hitCallStopHap function %s call getMemParams at eip 0x%x' % (self.mem_something.fun, eip))
                    SIM_run_alone(self.getMemParams, True)
            else:
                self.lgr.error('dataWatch hitCallStopHap, latest_cycle is None')

    def revAlone(self, alternate_callback=None):
        is_running = self.top.isRunning()
        status = SIM_simics_is_running()
        self.lgr.debug('dataWatch revAlone, resim running? %r  simics status %r' % (is_running, status))

        if self.mem_something is None:
            self.lgr.error('dataWatch revAlone with mem_something of None')
            return
        if self.mem_something.fun in self.mem_fun_entries and self.mem_something.fun_addr in self.mem_fun_entries[self.mem_something.fun] \
               and self.mem_something.fun not in funs_need_addr and self.mem_fun_entries[self.mem_something.fun][self.mem_something.fun_addr].disabled != True:
            
            instruct = self.top.disassembleAddress(self.cpu, self.mem_something.fun_addr)
            if self.mem_something.op_type != Sim_Trans_Load:
                self.lgr.debug('dataWatch revAlone, entry 0x%x already in mem_fun_entires, but is a store, so ignore after removing the range', self.mem_something.fun_addr)
                self.rmRange(self.mem_something.addr) 
                SIM_continue(0)
                return
            #elif self.mem_something.fun in ['strlen','strchr'] and self.last_buffer_not_found is not None and abs(self.mem_something.addr - self.last_buffer_not_found) < 20:
            elif self.mem_something.fun.startswith('str') and self.last_buffer_not_found is not None and abs(self.mem_something.addr - self.last_buffer_not_found) < 20:
                # very obscure, see declaration of last_buffer_not_found
                SIM_continue(0)
                return
            elif self.mem_something.fun.startswith('String16') and self.mem_something.addr == self.last_fun_result:
                # see declaration of last_fun_result
                self.lgr.debug('dataWatch revAlone, is String16 referencing previous function result at 0x%x, tbd make watch mark' % self.last_fun_result)
                SIM_continue(0)
                return

            elif not instruct[1].startswith('jmp'):
                self.lgr.error('dataWatch revAlone but entry 0x%x already in mem_fun_entires', self.mem_something.fun_addr)
                return
            else:
                self.lgr.debug('dataWatch revAlone, entry 0x%x already in mem_fun_entires, but is a jump.  TBD sort out multiple entry points', self.mem_something.fun_addr)

        self.disableBreaks(direction='reverse')

        self.cycles_was = self.cpu.cycles
        self.save_cycle = self.cycles_was - 1
        ''' Simics broken TBD '''
        #if True:
        #    resimUtils.skipToTest(self.cpu, self.save_cycle, self.lgr)
        #    resimUtils.skipToTest(self.cpu, self.cycles_was, self.lgr)
        #    self.lgr.debug('dataWatch revAlone, did Simics 2 step')
          
        
        phys_block = self.cpu.iface.processor_info.logical_to_physical(self.mem_something.called_from_ip, Sim_Access_Read)
        #cell = self.top.getCell()
        #self.call_break = SIM_breakpoint(cell, Sim_Break_Linear, Sim_Access_Execute, self.mem_something.called_from_ip, 1, 0)

        self.call_break = self.reverse_mgr.SIM_breakpoint(self.cpu.physical_memory, Sim_Break_Physical, Sim_Access_Execute, phys_block.address, 1, 0)

        ''' in case we chase ghost frames mimicking memsomething calls  and need to return '''
        #self.lgr.debug('dataWatch revAlone break %d set on IP of call 0x%x (phys 0x%x) d set save_cycle 0x%x, now reverse' % (self.call_break, 
        #   self.mem_something.called_from_ip, phys_block.address, self.save_cycle))
        self.prev_mark_cycle = self.watchMarks.latestCycle()
        delta = None
        reverse_to = False
        if self.prev_mark_cycle is not None and self.mem_something.ret_addr_addr is not None and not self.top.isVxDKM(cpu=self.cpu):
            delta = self.cpu.cycles - self.prev_mark_cycle
            reverse_to = True
            #rev_cmd = 'reverse-to cycle = %d' % self.prev_mark_cycle 
            self.lgr.debug('dataWatch revAlone break %d set on IP of call 0x%x (phys 0x%x) and save_cycle 0x%x (%d). Delta cycles is %d ret_addr_addr 0x%x, now reverse' % (self.call_break, 
               self.mem_something.called_from_ip, phys_block.address, self.save_cycle, self.save_cycle, delta, self.mem_something.ret_addr_addr))
        else:
            #rev_cmd = 'reverse' 
            self.lgr.debug('dataWatch revAlone break %d set on IP of call 0x%x (phys 0x%x) and save_cycle 0x%x (%d). No previous cycle, so just now reverse' % (self.call_break, 
                self.mem_something.called_from_ip, phys_block.address, self.save_cycle, self.save_cycle))
        #self.lgr.debug('cell is %s  cpu context %s' % (cell, self.cpu.current_context))
        #SIM_run_command('list-breakpoints')
        if alternate_callback is None:
            if not self.reverse_mgr.nativeReverse():
                self.reverse_mgr.setCallback(self.hitCallStopHap)
            else:
                self.call_stop_hap = self.top.RES_add_stop_callback(self.hitCallStopHap, None)
        else:
            if not self.reverse_mgr.nativeReverse():
                self.reverse_mgr.setCallback(alternate_callback)
            else:
                self.call_stop_hap = self.top.RES_add_stop_callback(alternate_callback, None)
        SIM_run_command('disable-vmp') 
        self.context_manager.setReverseContext()
        #if delta > 1000:
        #    print('would run this: %s' % rev_cmd)
        #else:
        #    SIM_run_command(rev_cmd)


        if reverse_to:
            self.lgr.debug('dataWatch revAlone is reverse_to, reverse to previous cycle 0x%x expecting to hit breakpoint 0x%x before we reach that cycle.' % (self.prev_mark_cycle, self.mem_something.called_from_ip))

            self.reverse_mgr.reverseTo(self.prev_mark_cycle)
        else:
            self.lgr.debug('dataWatch revAlone just reverse')
            self.reverse_mgr.reverse()


    def ghostStopHap(self, dumb, one, exception, error_string):
        self.lgr.debug('ghost stop hap cycle is 0x%x' % self.cpu.cycles)
        if self.ghost_stop_hap is not None:
            if self.cpu.cycles == self.cycles_was:
                self.lgr.debug('dataWatch ghostStopHap for no damn reason?')
                return
            self.deleteGhostStopHap(None)
            SIM_run_alone(self.undoAlone, None)
       
    def deleteGhostStopHap(self, dumb): 
        if self.ghost_stop_hap is not None:
            self.top.RES_delete_stop_hap(self.ghost_stop_hap)
            self.ghost_stop_hap = None

    def rmStopHap(self, hap):
        self.top.RES_delete_stop_hap(hap)

    def memstuffStopHap(self, alternate_callback, one, exception, error_string):
        ''' We may have been in a memsomething and have stopped.  Set a break on the address 
            of the call to the function and reverse. '''
        #self.lgr.debug('memstuffStopHap stopHap ')
        if self.stop_hap is not None:
            #self.lgr.debug('memstuffStopHap stopHap will delete hap %s' % str(self.stop_hap))
            hap = self.stop_hap
            self.top.RES_delete_stop_hap_run_alone(hap)
            self.stop_hap = None
        else:
            return
        if self.stopped:
            self.lgr.debug('dataWatch memstuffStopHap, dataWatch is stopped, return')
            return
        self.lgr.debug('memstuffStopHap, reverse to call fun %s at ip 0x%x' % (self.mem_something.fun, self.mem_something.called_from_ip))
        SIM_run_alone(self.revAlone, alternate_callback)

    def getStrLen(self, src, only_ascii=False):
        addr = src
        done = False
        #self.lgr.debug('getStrLen from 0x%x' % src)
        while not done:
            v = self.mem_utils.readByte(self.cpu, addr)
            #if v is not None:
            #    self.lgr.debug('getStrLen got 0x%x from 0x%x' % (v, addr))
            if v is None:
                self.lgr.debug('getStrLen got NONE for 0x%x' % (addr))
                done = True
            elif v == 0:
                done = True
            elif only_ascii and v > 127:
                done = True
            addr += 1
        return addr - src

    def handleMemStuff(self, op_type):
        '''
        We are within a memcpy type function for which we believe we know the calling conventions (or a user-defined iterator).  However those values have been
        lost to the vagaries of the implementation by the time we hit the breakpoint.  We need to stop; Reverse to the call; record the parameters;
        set a break on the return; and continue.  We'll assume not too many instructions between us and the call, so manually walk er back.
        '''
        if self.mem_something.ret_ip is not None and self.mem_something.called_from_ip is not None:
            self.lgr.debug('handleMemStuff ret_addr 0x%x fun %s called_from_ip 0x%x' % (self.mem_something.ret_ip, self.mem_something.fun, self.mem_something.called_from_ip))
        else:
            self.lgr.debug('handleMemStuff got none for either ret_addr or called_from_ip')
        if self.stopped:
            self.lgr.debug('dataWatch handleMemStuff, dataWatch is stopped, return')
            return
        
        if self.mem_something.fun in self.mem_fun_entries and self.mem_something.fun_addr in self.mem_fun_entries[self.mem_something.fun] \
               and self.mem_something.fun not in funs_need_addr and self.mem_fun_entries[self.mem_something.fun][self.mem_something.fun_addr].disabled != True:
 
            if op_type is not None and op_type != Sim_Trans_Load and self.mem_something.fun in missed_deallocate:
                self.rmRange(self.mem_something.addr) 
                self.lgr.debug('dataWatch handleMemStuff fun %s already in mem_fun_entries, but is not a load and in missed_deallocate, remove range and bail' % (self.mem_something.fun))
            else:

                self.lgr.warning('dataWatch handleMemStuff but entry for fun %s already in mem_fun_entires addr 0x%x' % (self.mem_something.fun, self.mem_something.fun_addr))

                # Do reverse to call anyway.  TBD why was entry not caught.  alternate entry?  Usually due to bad stack frame generation.
                self.stop_hap = self.top.RES_add_stop_callback(self.memstuffStopHap, None)
                self.lgr.debug('handleMemStuff fun in mem_fun_entries now stop')
                SIM_break_simulation('handle memstuff')

        elif self.mem_something.fun not in mem_funs or self.mem_something.fun in no_stop_funs: 
            ''' assume it is a user iterator '''
            if self.mem_something.src is not None:
                self.lgr.debug('handleMemStuff assume iterator or function that need not reverse to call, src: 0x%x  %s clear backstop' % (self.mem_something.src, self.cpu.current_context))
                self.pending_call = True
                ''' iterator may take  while to return? '''
                ''' iterator mark will be recorded on return '''
                #self.watchMarks.iterator(self.mem_something.fun, self.mem_something.src, self.mem_something.src)
                #SIM_break_simulation('handle memstuff')
                self.runToReturnAndGo(skip_this=False)
            else:
                self.lgr.debug('handleMemStuff assume iterator or function that need not reverse to call, IS a modify,  Just return and come back on read')
                return
        else: 
            ''' run back to the call '''
            self.stop_hap = self.top.RES_add_stop_callback(self.memstuffStopHap, None)
            self.lgr.debug('handleMemStuff now stop to run back to call')
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

    def adHocCopy(self, addr, trans_size, dest_addr, start, length, byte_swap=False):
        retval = False
        if dest_addr != addr or byte_swap:
            #self.lgr.debug('dataWatch adHocCopy might add address 0x%x' % dest_addr)
            existing_index = self.findRangeIndex(dest_addr)
            if existing_index is None:
                ''' TBD may miss some add hocs? not likely '''
                #if addr is not None:
                #    self.lgr.debug('dataWatch adHocCopy will add dest address 0x%x, src 0x%x' % (dest_addr, addr))
                #else:
                #    self.lgr.debug('dataWatch adHocCopy will add dest address 0x%x' % (dest_addr))
                self.last_ad_hoc.append(dest_addr)
                retval = True
            elif byte_swap:
                self.lgr.debug('dataWatch adHocCopy byte swap of address 0x%x' % (addr))
                self.last_ad_hoc.append(dest_addr)
                retval = True
            elif start is not None:
                ''' Re-use of ad-hoc buffer '''
                self.lgr.debug('dataWatch adHocCopy, reuse of ad-hoc buffer index %d? addr 0x%x start 0x%x' % (existing_index, addr, start))
                self.recent_reused_index = existing_index
                self.last_ad_hoc.append(dest_addr)
                retval = True
        else:
            self.lgr.debug('dataWatch adHocCopy dest is same as addr')
        return retval

    def finishCheckMoveHap(self, our_reg, an_object, breakpoint, memory):
        ''' Hap invoked when we reach the end of a candidate ad hoc move '''
        if self.finish_check_move_hap is None:
            return
        if self.call_hap is not None:
            eip = self.top.getEIP(self.cpu)
            self.lgr.warning('finishCheckMove found call_hap ? eip is 0x%x, delete the check_move hap' % eip)
            self.context_manager.genDeleteHap(self.finish_check_move_hap, immediate=True)
            self.finish_check_move_hap = None
            return
        self.lgr.debug('dataWatch finishCheckMoveHap dest_op %s' % self.move_stuff.dest_op)
        dest_addr = self.decode.getAddressFromOperand(self.cpu, self.move_stuff.dest_op, self.lgr)
        adhoc = False
        if self.move_stuff.function is None and our_reg is not None:
            if our_reg.startswith('xmm'):
                '''  TBD bad assumption?  think it is always like a memcpy '''
                adhoc = True
            else:
                adhoc = self.adHocCopy(self.move_stuff.addr, self.move_stuff.trans_size, dest_addr, self.move_stuff.start, self.move_stuff.length)
                self.lgr.debug('dataWatch finishCheckMoveHap back from adHocCopy adhoc %r' % adhoc)
            
            '''
            if dest_addr != move_stuff.addr:
                self.lgr.debug('dataWatch finishCheckMoveHap might add address 0x%x' % dest_addr)
                existing_index = self.findRangeIndex(dest_addr)
                if existing_index is None:
                    self.lgr.debug('dataWatch finishCheckMoveHap will add address 0x%x' % dest_addr)
                    self.last_ad_hoc=dest_addr
                    adhoc = True
                else:
                    self.lgr.debug('dataWatch finishCheckMoveHap, reuse of ad-hoc buffer? addr 0x%x start 0x%x' % (move_stuff.addr, move_stuff.start))
                    self.recent_reused_index = existing_index
                    pass
            else:
                self.lgr.debug('dataWatch finishCheckMoveHap dest is same as addr')
            '''
        else: 
            self.lgr.debug('dataWatch finishCheckMove Hap move_stuff function is None')

        if adhoc:
            self.lgr.debug('dataWatch finishCheckMoveHap is ad hoc')
            if self.move_stuff.trans_size >= 16:
                f = self.frames[1]
                self.mem_something = MemSomething(f.fun_name, f.fun_addr, self.move_stuff.start, f.ret_addr, self.move_stuff.start, dest_addr, 
                      f.ip, None, self.move_stuff.length, self.move_stuff.start, ret_addr_addr=f.ret_to_addr)
                self.lgr.debug('dataWatch finishCheckMoveHap may be a memcpy with no fun name trans_size 0x%x' % self.move_stuff.trans_size)
                SIM_run_alone(self.stopForMemcpyCheck, None)
                return 
 
            #self.recordAdHocCopy(self.move_stuff.addr, self.move_stuff.start, self.move_stuff.length, self.move_stuff.trans_size, dest=self.last_ad_hoc[-1])
            self.recordAdHocCopy(self.move_stuff.addr, self.move_stuff.start, self.move_stuff.length, self.move_stuff.trans_size, dest_addr)

        elif self.move_stuff.function is not None:
            if dest_addr != self.move_stuff.addr:
                #self.lgr.debug('dataWatch finishCheckMove, function return value wrote to addr 0x%x  function %s' % (self.move_stuff.addr, self.move_stuff.function))
                wm = self.watchMarks.dataRead(self.move_stuff.addr, self.move_stuff.start, self.move_stuff.length, 
                         self.move_stuff.trans_size, note=self.move_stuff.function, dest=dest_addr)
                self.setRange(dest_addr, self.move_stuff.trans_size, watch_mark=wm)
                self.lgr.debug('dataWatch finishCheckMoveHap is ad hoc addr 0x%x  ad_hoc %r, dest 0x%x' % (self.move_stuff.addr, ad_hoc, dest_addr))
                self.setBreakRange()
                self.move_cycle = self.cpu.cycles
                self.move_cycle_max = self.cpu.cycles+1
                self.lgr.debug('move_cycle_max now 0x%x' % self.move_cycle_max)
            else:
                self.lgr.debug('dataWatch finishCheckMove rewrote 0x%x using %s' % (dest_addr, self.move_stuff.function))
                mark = self.watchMarks.mscMark(self.move_stuff.function, dest_addr)
                self.move_cycle = self.cpu.cycles
                self.move_cycle_max = self.cpu.cycles+1
        else:
            #self.lgr.debug('dataWatch finishCheckMove, not ad_hoc addr 0x%x  start 0x%x ad_hoc %r ip: 0x%x' % (self.move_stuff.addr, self.move_stuff.start, ad_hoc, 
            #     self.move_stuff.ip))
            if self.cpu.cycles != self.prev_cycle:
                #self.lgr.debug('dataWatch checkMove found nothing, use prev cycle 0x%x for recording' % self.prev_cycle)
                self.watchMarks.dataRead(self.move_stuff.addr, self.move_stuff.start, self.move_stuff.length,
                         self.move_stuff.trans_size, ip=self.move_stuff.ip, cycles=self.move_stuff.cycle)
                #         self.move_stuff.trans_size, ip=self.move_stuff.ip, cycles=self.prev_cycle)
            else:
                self.watchMarks.dataRead(self.move_stuff.addr, self.move_stuff.start, self.move_stuff.length, 
                         self.move_stuff.trans_size, ip=self.move_stuff.ip, cycle=self.move_stuff.cycle)
        #self.lgr.debug('dataWatch finishCheckMove now delete hap')
        if self.finish_check_move_hap is None:
            self.lgr.error('it is none')
        self.context_manager.genDeleteHap(self.finish_check_move_hap, immediate=True)
        self.finish_check_move_hap = None

    def recordAdHocCopy(self, src, buf_start, buf_length, copy_size, dest, byte_swap=False):
        if src is not None:
            self.lgr.debug('dataWatch recordAdHocCopy src 0x%x dest 0x%x size 0x%x' % (src, dest, copy_size))
            wm = self.watchMarks.dataRead(src, buf_start, buf_length, copy_size, ad_hoc=True, dest=dest, byte_swap=byte_swap)
            if not byte_swap: 
                self.setRange(dest, copy_size, watch_mark=wm)
                self.lgr.debug('dataWatch recordAdHocCopy not byte_swap src 0x%x dest 0x%x size 0x%x' % (src, dest, copy_size))
                self.setBreakRange()
        else:
            self.lgr.debug('dataWatch recordAdHocCopy charDevCopy dest 0x%x' % (dest))
            wm = self.watchMarks.charCopy('read', dest)
            self.setRange(dest, 1, watch_mark=wm)
       
        #''' TBD breaks something?'''
        #self.move_cycle = self.cpu.cycles
        #self.move_cycle_max = self.cpu.cycles+1

    class CheckMoveStuff():
        def __init__(self, addr, trans_size, start, length, dest_op, function=None, ip=None, cycle=None):
            self.addr = addr
            self.trans_size = trans_size
            self.start = start
            self.length = length
            self.dest_op = dest_op
            self.function = function
            self.ip = ip
            self.cycle = cycle
        def getString(self):
            if self.ip is not None:
                return 'addr: 0x%x trans_size: %d start: 0x%x len: %d ip: 0x%x' % (self.addr, self.trans_size, self.start, self.length, self.ip)
            else:
                return 'addr: 0x%x trans_size: %d start: 0x%x len: %d' % (self.addr, self.trans_size, self.start, self.length)

    def isDataTransformCall(self, instruct, call_instr, recent_instructs=[]):
        fun_list = ['ntohl', 'ntohs', 'htonl', 'htons', 'tolower', 'toupper', 'ordinal_']
        retval = None
        if self.fun_mgr is not None and self.fun_mgr.isCall(instruct[1]):
            fun_hex, fun = self.fun_mgr.getFunNameFromInstruction(instruct, call_instr, recent_instructs=recent_instructs, check_reg=True)
            if fun_hex is not None:
                self.lgr.debug('isDataTransformCall fun is %s  (0x%x)' % (fun, fun_hex))
            else:
                self.lgr.debug('isDataTransformCall fun is %s  failed to get fun_hex from %s' % (fun, instruct[1]))

            if fun is not None:
                for tform in fun_list:
                    if tform in fun.lower():
                        retval = fun
                        break
        return retval

    def isTestByValue(self, instruct, call_instr, recent_instructs=[]):
        fun_list = ['isspace', 'iswspace', 'isspace_l', 'iswspace_l', 'isprint', 'iswprint', 'isprint_l', 'iswprint_l']
        retval = None
        if self.fun_mgr is not None and self.fun_mgr.isCall(instruct[1]):
            fun_hex, fun = self.fun_mgr.getFunNameFromInstruction(instruct, call_instr, recent_instructs=recent_instructs, check_reg=True)
            if fun_hex is not None:
                self.lgr.debug('isTestByValue fun is %s  (0x%x)' % (fun, fun_hex))
            else:
                self.lgr.debug('isTestByValue fun is %s  failed to get fun_hex from %s' % (fun, instruct[1]))

            if fun is not None:
                for tform in fun_list:
                    if tform in fun.lower():
                        retval = fun
                        break
        self.lgr.debug('isTestByValue retval %s' % retval)
        return retval

    def isDataRef(self, instruct, call_instr, recent_instructs=[]):
        retval = None
        if self.fun_mgr is not None and self.fun_mgr.isCall(instruct[1]):
            fun_hex, fun = self.fun_mgr.getFunNameFromInstruction(instruct, call_instr, recent_instructs=recent_instructs, check_reg=True)
            if fun_hex is not None:
                self.lgr.debug('isDataRef fun is %s  (0x%x)' % (fun, fun_hex))
            else:
                self.lgr.debug('isDataRef fun is %s  failed to get fun_hex from %s' % (fun, instruct[1]))
            if fun is not None and 'isalpha' in fun:
                retval = fun
        return retval

    def checkNTOHL(self, next_ip, addr, trans_size, start, length, recent_instructs=[]):
        ''' if the given ip is a call to a data transform, e.g., ntohl, see if the result is
            written to memory, and if so, track that buffer.'''
        retval = False
        if self.fun_mgr is None:
            self.lgr.debug('dataWatch checkNTOHL with no fun_mgr')
            return False
        self.lgr.debug('dataWatch checkNTOHL addr 0x%x' % addr)
        orig_ip = self.top.getEIP(self.cpu)
        orig_cycle = self.cpu.cycles
        instruct = self.top.disassembleAddress(self.cpu, next_ip)
        fun = self.isDataTransformCall(instruct, next_ip, recent_instructs=recent_instructs)
        reg_values = {}
        if fun is not None:
                self.lgr.debug('dataWatch checkNTOHL is %s' % fun)
                our_reg = self.mem_utils.getCallRetReg(self.cpu)
                next_instruct = instruct
                for i in range(5):
                    next_ip = next_ip + next_instruct[0]
                    next_instruct = self.top.disassembleAddress(self.cpu, next_ip)
                    if next_instruct[1].startswith('jmp'):
                        dumb, op1 = self.decode.getOperands(next_instruct[1])
                        next_ip = self.decode.getAddressFromOperand(self.cpu, op1, self.lgr)
                        next_instruct = self.top.disassembleAddress(self.cpu, next_ip)
                        self.lgr.debug('datawatch checkNTOHL, was jump changed next inst is now  0x%x is %s' % (next_ip, next_instruct[1]))
                        
                    elif decode.isBranch(self.cpu, next_instruct[1]):
                        break
                    op2, op1 = self.decode.getOperands(next_instruct[1])
                    self.lgr.debug('datawatch checkNTOHL, next inst at 0x%x is %s' % (next_ip, next_instruct[1]))
                    if next_instruct[1].startswith('mov') and self.decode.isReg(op2) and self.decode.regIsPart(op2, our_reg):
                        if self.decode.isReg(op1):
                            self.lgr.debug('dataWatch checkNTOHL, our reg now is %s' % op1)
                            our_reg = op1
                        else:
                            self.lgr.debug('dataWatch checkNTOHL, maybe op1 is %s' % op1)
                            dest_addr = self.decode.getAddressFromOperand(self.cpu, op1, self.lgr, reg_values=reg_values)
                            if dest_addr is not None:
                                self.lgr.debug('checkNTOHL addr found to be 0x%x' % dest_addr)
                                break_num = self.context_manager.genBreakpoint(None, Sim_Break_Linear, Sim_Access_Execute, next_ip, 1, 0)
                                self.move_stuff = self.CheckMoveStuff(addr, trans_size, start, length, op1, function = fun, ip=orig_ip, cycle=orig_cycle)
                                self.lgr.debug('dataWatch checkNTOHL set finishCheckMoveHap')
                                self.finish_check_move_hap = self.context_manager.genHapIndex("Core_Breakpoint_Memop", 
                                         self.finishCheckMoveHap, None, break_num, 'checkMove')
                                retval = True
                            break
                    elif next_instruct[1].startswith('mov') and self.decode.isReg(op1):
                        value = self.decode.getAddressFromOperand(self.cpu, op2, self.lgr)
                        if value is not None:
                            reg_values[op1] = value
                     
        else:
            fun = self.isDataRef(instruct, next_ip, recent_instructs=recent_instructs)
            if fun is not None:
                self.lgr.debug('dataWatch checkNOTHL is data ref %s' % fun)
                retval = True
                mark = self.watchMarks.mscMark(fun, addr)
        return retval

    def checkPushedTest(self, next_ip, addr, trans_size, start, length, recent_instructs=[]):
        ''' if the given ip is a call to a function that tests the value of a parameter that is passed-by-value, e.g., isspace '''
        retval = False
        if self.fun_mgr is None:
            self.lgr.debug('dataWatch checkNTOHL with no fun_mgr')
            return False
        orig_ip = self.top.getEIP(self.cpu)
        orig_cycle = self.cpu.cycles
        cur_ip = next_ip
        max_try = 5
        for i in range(max_try):
            instruct = self.top.disassembleAddress(self.cpu, cur_ip)
            self.lgr.debug('dataWatch checkPushedTest instruct %s' % instruct[1])
            fun = self.isTestByValue(instruct, cur_ip, recent_instructs=recent_instructs)
            if fun is not None:
                wm = self.watchMarks.pushTestMark(fun, addr, cur_ip)
                self.lgr.debug('dataWatch checkPushedTest found fun %s for addr 0x%x did watchMark %s' % (fun, addr, wm.mark.getMsg()))
                retval = True
                break
            cur_ip = cur_ip + instruct[0]
            recent_instructs.append(instruct[1])
        return retval

    def adjustSP(self, sp, instruct, op1, op2):
        sign = None
        retval = None
        if instruct[1].startswith('sub') and 'sp' in op1:
            sign = -1
        elif instruct[1].startswith('add') and 'sp' in op1:
            sign = 1
        if sign is not None:
            if ',' in op2:
                op2 = op2.split(',')[1]
            val = self.decode.getValue(op2, self.cpu)
            if val is None:
                self.lgr.error('dataWatch adjustSP could not get value from op2 %s' % op2)
            else:
                retval = sp + (val * sign)
        return retval

    def getMoveDestAddr(self, next_instruct, op1, op2, our_reg_list):
        dest_addr = None
        if self.cpu.architecture.startswith('arm'):
            #self.lgr.debug('dataWatch getMoveDestAddr instruct: %s' % next_instruct[1]) 
            if next_instruct[1].startswith('str') and self.decode.isReg(op1): 
                #self.lgr.debug('dataWatch getMoveDestAddr is str op1 is <%s>  reglist is %s' % (op1, str(our_reg_list)))
                if self.decode.regIsPartList(op1, our_reg_list):
                    #self.lgr.debug('dataWatch getMoveDestAddr is in reg list')
                    dest_addr = self.decode.getAddressFromOperand(self.cpu, op2, self.lgr)
        elif self.cpu.architecture == 'ppc32':
            if next_instruct[1].startswith('st') and self.decode.isReg(op1) and op1 in our_reg_list: 
                self.lgr.debug('dataWatch getMoveDestAddr %s' % next_instruct[1])
                dest_addr = self.decode.getAddressFromOperand(self.cpu, op2, self.lgr)
                if dest_addr is not None:
                    self.lgr.debug('dataWatch getMoveDestAddr dest_addr 0x%x' % dest_addr)
        else:
            if next_instruct[1].startswith('mov') and self.decode.isReg(op2) and self.decode.regIsPartList(op2, our_reg_list):
                self.lgr.debug('dataWatch getMoveDestAddr, maybe op1 is %s' % op1)
                dest_addr = self.decode.getAddressFromOperand(self.cpu, op1, self.lgr)
        return dest_addr

    def loopAdHocMult(self, addr, trans_size, start, length, instruct, reg_set, eip, orig_ip, orig_cycle):
            ''' For arm '''
            # TBD NOT yet adjusting move_cycle_max
            adhoc = False
            next_ip = eip
            next_instruct = instruct
            op2, op1 = self.decode.getOperands(next_instruct[1])
            track_sp = self.mem_utils.getRegValue(self.cpu, 'sp')
            new_sp = self.adjustSP(track_sp, next_instruct, op1, op2)
            if new_sp is not None:
                track_sp = new_sp
            #self.lgr.debug('dataWatch loopAdHocMult, reg_set %s, eip 0x%x starting sp 0x%x trns_size %d' % (reg_set, eip, track_sp, trans_size))
            max_num = 7
            for i in range(max_num):
                next_ip = next_ip + next_instruct[0]
                next_instruct = self.top.disassembleAddress(self.cpu, next_ip)
                if decode.isBranch(self.cpu, next_instruct[1]) or decode.isCall(self.cpu, next_instruct[1], ignore_flags=True):
                    #self.lgr.debug('datawatch loopAdHocMult, next inst at 0x%x is %s  is branch' % (next_ip, next_instruct[1]))
                    break
                op2, op1 = self.decode.getOperands(next_instruct[1])
                #self.lgr.debug('datawatch loopAdHocMult, next inst at 0x%x is %s  --- op1: %s  op2: %s' % (next_ip, next_instruct[1], op1, op2))
                new_sp = self.adjustSP(track_sp, next_instruct, op1, op2)
                if next_instruct[1].startswith('stm') and op2 == reg_set:
                    #self.lgr.debug('loopAdHocMult, got stm reg set match, op1 is %s' % op1)
                    reg_count = self.decode.regCount(reg_set)
                    if reg_count is None:
                        #self.lgr.error('did not get reg count from %s' % reg_set)
                        break
                    trans_size = trans_size * reg_count
                    adhoc = True
                    break_num = self.context_manager.genBreakpoint(None, Sim_Break_Linear, Sim_Access_Execute, next_ip, 1, 0)
                    dest_op = op1
                    self.move_stuff = self.CheckMoveStuff(addr, trans_size, start, length, dest_op, ip=orig_ip, cycle=orig_cycle)
                    #self.lgr.debug('dataWatch loopAdHocMult addr 0x%x  start 0x%x set finishCheckMoveHap' % (addr, start))
                    self.finish_check_move_hap = self.context_manager.genHapIndex("Core_Breakpoint_Memop", 
                             self.finishCheckMoveHap, None, break_num, 'loopAdHoc')
                    break
            return adhoc                

    def loopAdHoc(self, addr, trans_size, start, length, instruct, our_reg, eip, orig_ip, orig_cycle, tid, only_push=False):
        #self.lgr.debug('dataWatch loopAdHoc')
        ''' Loop through the next several instructions to see if our reg is stored to memory,
            or pushed onto the stack for a call

            Function deliberately does not evaluate the first instruction because it may be an mov from a buffer
            that triggered this call.  Use of this function following returns should force eip to be the call.
           
        '''
        #TBD this will miss copies and such that occur in branches.  It assumes no branching between the start and the next
        adhoc = False
        next_ip = eip
        next_instruct = instruct
        op2, op1 = self.decode.getOperands(next_instruct[1])
        mn = self.decode.getMn(next_instruct[1])
        track_sp = self.mem_utils.getRegValue(self.cpu, 'sp')
        #self.lgr.debug('dataWatch loopAdHoc, sp from reg 0x%x' % track_sp)
        new_sp = self.adjustSP(track_sp, next_instruct, op1, op2)
        if new_sp is not None:
            #self.lgr.debug('dataWatch loopAdHoc, sp from adjustSP 0x%x' % new_sp)
            track_sp = new_sp
        #self.lgr.debug('dataWatch loopAdHoc, our_reg %s, eip 0x%x instruct %s starting sp 0x%x' % (our_reg, eip, instruct[1], track_sp))
        our_reg_list = [our_reg]
        max_num = 10
        if our_reg.startswith('xmm'):
            max_num = 100

        word_size = self.top.wordSize(tid, target=self.cell_name)
        recent_instructs = []
        flags = None
        byte_swap = False
        for move_cycles in range(max_num):
             
            next_ip, next_instruct, mn, jump_cycles = self.getNextInstruct(next_instruct, next_ip, flags, our_reg)
            if next_ip is None:
                break
            if mn.startswith('j') or mn.startswith('b') or mn.startswith('call'):
                break
            op2, op1 = self.decode.getOperands(next_instruct[1])
            mn = self.decode.getMn(next_instruct[1])
            #self.lgr.debug('datawatch loopAdHoc, next inst at 0x%x is %s  --- op1: %s  op2: %s' % (next_ip, next_instruct[1], op1, op2))
            new_sp = self.adjustSP(track_sp, next_instruct, op1, op2)
            dest_addr = None
            if not only_push:
                dest_addr = self.getMoveDestAddr(next_instruct, op1, op2, our_reg_list)
            #if dest_addr is not None:
            #    self.lgr.debug('dataWatch loopAdHoc dest_addr 0x%x' % dest_addr)
            #else:
            #    self.lgr.debug('dataWatch loopAdHoc dest_addr is None')
 
            if dest_addr is not None:
                adhoc = False
                if next_instruct[1].startswith('mov') and self.decode.regIsPartList(op2, our_reg_list) and 'sp' in op1:
                    this_sp = self.decode.getAddressFromOperand(self.cpu, op1, self.lgr)
                    #self.lgr.debug('dataWatch loopAdHoc push via mov.  Moved to SP value 0x%x,  hack sp because checkPushedData will subtract word size from it' % this_sp)
                    this_sp = this_sp + word_size
                    adhoc = self.checkPushedData(this_sp, our_reg_list, next_instruct, next_ip, addr, trans_size, start, length, recent_instructs, word_size)
                if not adhoc:
                    adhoc = self.gotAdHocDest(next_ip, next_instruct, op1, op2, addr, trans_size, dest_addr, start, length, byte_swap, our_reg, our_reg_list, recent_instructs, orig_ip, orig_cycle, (move_cycles+jump_cycles), word_size)
                    break
            elif (next_instruct[1].startswith('mov') or next_instruct[1].startswith('or')) and self.decode.isReg(op2) and self.decode.regIsPartList(op2, our_reg_list) and self.decode.isReg(op1):
                    self.lgr.debug('dataWatch loopAdHoc, adding our_reg to %s' % op1)
                    our_reg_list.append(op1)
            elif self.cpu.architecture not in ['arm', 'arm64'] and (next_instruct[1].startswith('mov') or next_instruct[1].startswith('lea')) and self.decode.isReg(op1) and op1 in our_reg_list:
                # TBD fix for arm
                #self.lgr.debug('dataWatch loopAdHoc, removing %s from our_reg_list' % op1)
                our_reg_list.remove(op1)
            elif self.cpu.architecture in ['arm', 'arm64'] and self.decode.isReg(op1) and op1 in our_reg_list and \
                                                    (next_instruct[1].startswith('mov') or next_instruct[1].startswith('sub') or next_instruct[1].startswith('add')):
                    our_reg_list.remove(op1)
            elif new_sp is not None:
                #self.lgr.debug('dataWatch loopAdHoc is stack adjust, now 0x%x' % new_sp)
                track_sp = new_sp
            elif  next_instruct[1].startswith('push') and self.top.isCode(next_ip): 
                self.lgr.debug('dataWatch loopAdHoc is push op1: <%s>  our_reg_list: %s' % (op1, str(our_reg_list)))
                ''' TBD extend for arm stm,  use for windows?'''
                if self.decode.isReg(op1) and self.decode.regIsPartList(op1, our_reg_list):
                    ''' Pushed our register '''
                    adhoc = self.checkPushedData(track_sp, our_reg_list, next_instruct, next_ip, addr, trans_size, start, length, recent_instructs, word_size)
                    break
                else:
                    track_sp = track_sp - word_size
            elif  next_instruct[1].startswith('bswap') and op1 in our_reg_list:
                byte_swap = True
                # TBD hacky hueristic to know if we should break up a buffer just because some part is written to.
                self.last_byteswap = self.cpu.cycles
                self.lgr.debug('dataWatch oopAdHoc byteswap')
            elif  mn in ['test', 'cmp']:
                flags = self.testCompare(mn, op1, op2, recent_instructs, next_ip)

            recent_instructs.append(next_instruct[1])
        #self.lgr.debug('dataWatch loopAdHoc exit move_cycles is %d' % move_cycles)
        return adhoc

    def gotAdHocDest(self, next_ip, next_instruct, op1, op2, addr, trans_size, dest_addr, start, length, byte_swap, our_reg, our_reg_list, recent_instructs, orig_ip, orig_cycle, move_cycles, word_size):
        adhoc = False
        ''' If dest is relative to sp, assume its value is good and avoid use of finishCheckMove, which is skipped if we encounter another read hap'''
        if 'sp' in op1:
            if next_instruct[1].startswith('mov') and '[' in op1 and 'sp' in op1 and self.decode.isReg(op2) and self.decode.regIsPartList(op2, our_reg_list):
                # is this a size to malloc?
                next_next_ip = next_ip + next_instruct[0]
                next_next_instruct = self.top.disassembleAddress(self.cpu, next_next_ip)
                fun_hex, fun = self.fun_mgr.getFunNameFromInstruction(next_next_instruct, next_next_ip)
                self.lgr.debug('dataWatch gotAdHocDest reg %s moved to SP and call to %s' % (op2, fun))
                if fun is not None and 'malloc' in fun:
                    adhoc = True
                    if word_size == 4:
                        val = self.mem_utils.readWord32(self.cpu, addr)
                    else:
                        val = self.mem_utils.readWord(self.cpu, addr)
                    self.lgr.debug('dataWatch gotAdHocDest is malloc reg %s value 0x%x' % (op2, val))
                    self.watchMarks.mallocSize(addr, val)
            if not adhoc:
                adhoc = self.adHocCopy(addr, trans_size, dest_addr, start, length)
                self.lgr.debug('dataWatch gotAdHocDest back from adHocCopy adhoc %r' % adhoc)
                if adhoc:
                    self.move_cycle = self.cpu.cycles
                    self.move_cycle_max = self.cpu.cycles+move_cycles+1
                    self.lgr.debug('move_cycle_max now 0x%x' % self.move_cycle_max)
                    self.recordAdHocCopy(addr, start, length, trans_size, dest_addr)
        else:
            offset = self.checkNoTaint(op1, recent_instructs)
            if offset is not None:
                self.lgr.debug('dataWatch gotAdHocDest dest addr base reg seems unchanged, or scalar. %s offset 0x%x op2 is %s' % (op1, offset, op2))
                if self.decode.isReg(op2):
                    trans_size = min(decode.regLen(op2), trans_size)
                    self.lgr.debug('dataWatch gotAdHocDest set trans_size to %d' % trans_size)
                dest_addr = dest_addr + offset
                adhoc = self.adHocCopy(addr, trans_size, dest_addr, start, length, byte_swap=byte_swap)
                self.lgr.debug('dataWatch gotAdHocDestx back from adHocCopy adhoc %r length %d trans_size %d' % (adhoc, length, trans_size))
                if adhoc:
                    self.recordAdHocCopy(addr, start, length, trans_size, dest_addr, byte_swap=byte_swap)
                    self.move_cycle_max = self.cpu.cycles+move_cycles+1
                    self.move_cycle = self.cpu.cycles
                    self.lgr.debug('move_cycle_max now 0x%x' % self.move_cycle_max)
            else:                   
                #self.lgr.debug('dataWatch gotAdHocDest dest addr found to be 0x%x, not relative to SP' % dest_addr)
                adhoc = True
                break_num = self.context_manager.genBreakpoint(None, Sim_Break_Linear, Sim_Access_Execute, next_ip, 1, 0)
                dest_op = op1
                if self.cpu.architecture in ['arm', 'arm64']:
                    dest_op = op2
                ''' We have a candidate check move destination.  Run there to check if it really moves our register into memory '''
                self.move_stuff = self.CheckMoveStuff(addr, trans_size, start, length, dest_op, ip=orig_ip, cycle=orig_cycle)
                # set these here since we know the max.  note though, we may decide this was not a move.  safe?
                self.move_cycle = self.cpu.cycles
                self.move_cycle_max = self.cpu.cycles+move_cycles+1
                self.lgr.debug('move_cycle_max now 0x%x' % self.move_cycle_max)
                self.lgr.debug('dataWatch gotAdHocDest addr 0x%x  start 0x%x set finishCheckMoveHap on eip 0x%x current_context %s' % (addr, 
                      start, next_ip, self.cpu.current_context))
                self.finish_check_move_hap = self.context_manager.genHapIndex("Core_Breakpoint_Memop", 
                         self.finishCheckMoveHap, our_reg, break_num, 'loopAdHoc')
        return adhoc
    def testCompare(self, mn, op1, op2, recent, ip):
        # look at test/cmp instructions and return flgs.  TBD needs to be built out.
        retval = None
        self.lgr.debug('dataWatch testCompare ip: 0x%x mn %s, op1 %s op2 %s' % (ip, mn, op1, op2))
        if mn == 'test' and op1 == op2:
            self.lgr.debug('dataWatch testCompare is test self')
            offset = self.checkNoTaint(op1, recent)
            if offset is not None:
                self.lgr.debug('dataWatch testCompare not tainted')
                val = self.mem_utils.getRegValue(self.cpu, op1)
                if val == 0:
                    retval = ['ZF']
                else:
                    self.lgr.debug('dataWatch testCompare clear zero flag')
                    retval = []
                reg_size = self.decode.regLen(op1)
                self.lgr.debug('dataWatch testCompare reg_size %d val 0x%x' % (reg_size, val))
                if reg_size == 1:
                    mask = 0x80 
                elif reg_size == 2:
                    mask = 0x8000 
                elif reg_size == 4:
                    mask = 0x80000000 
                else:
                    mask = 0x8000000000000000
                if val & mask:
                    self.lgr.debug('dataWatch testCompare signed')
                    retval.append('SF')
        return retval
                
    def checkNoTaint(self, op, recent):
        # return offset if the recent instructions do not seem to affect the register found in op. otherwise return None
        retval = 0
        if '[' in op: 
            content = op.split('[', 1)[1].split(']')[0]
            if '+' in content:
                reg = content[:content.index('+')]
            elif '-' in content:
                reg = content[:content.index('-')]
            else:
                reg = content
            self.lgr.debug('dataWatch recentNoTaint reg is %s' % reg)
            for instruct in recent:
                op2, op1 = self.decode.getOperands(instruct)
                if op1 == reg:
                    self.lgr.debug('dataWatch recentNoTaint found mod in %s' % instruct)
                    retval = self.decode.isScalarAdd(op1, instruct) 
                    if retval is not None:
                        self.lgr.debug('dataWatch recentNoTaint found offset 0x%x' % retval)
        return retval
        
    def getNextInstruct(self, instruct, ip, flags, our_reg):        
        # look for branches we can satisfy and adjust instruction and ip accordingly
        # TBD needs build out for arm
        next_ip = ip + instruct[0]
        next_instruct = self.top.disassembleAddress(self.cpu, next_ip)
        mn = self.decode.getMn(next_instruct[1])
        #self.lgr.debug('dataWatch getNextInstruct next_ip 0x%x next_instruc %s' % (next_ip, next_instruct[1]))
        jump_cycles = 1
        while next_instruct[1].startswith('j') or mn == 'b':
            jump_cycles =  jump_cycles+1
            # TBD move branch tests into single routine that returns next_ip and next_instruct
            #self.lgr.debug('dataWatch getNextInstruct ip 0x%x instruc %s jump_cycles %d' % (next_ip, next_instruct[1], jump_cycles))
            if next_instruct[1].startswith('jmp') or mn == 'b':
                parts = next_instruct[1].split()
                if len(parts) == 2:
                    try:
                        next_ip = int(parts[1], 16)
                        next_instruct = self.top.disassembleAddress(self.cpu, next_ip)
                        mn = self.decode.getMn(next_instruct[1])
                        continue
                    except:
                        self.lgr.debug('dataWatch getNextInstruct is jmp failed to get jump dest from %s' % (next_instruct[1]))
                        next_ip = None
                        break
                 
            elif (decode.isBranch(self.cpu, next_instruct[1]) and not our_reg.startswith('xmm')) or next_instruct[1].startswith('ret'):
                ''' Normally bail on branch, but catch xmm mem copies that have a lot of processing. TBD this is broken since we can't follow branches properly'''
                #self.lgr.debug('dataWatch getNextInstruct is branch %s flags %s' % (next_instruct[1], str(flags)))
                if flags is not None:
                    if mn in ['jnz', 'jne']:
                        self.lgr.debug('dataWatch getNextInstruct is jnz flags %s' % str(flags))
                        if 'ZF' in flags:
                            next_ip = next_ip + next_instruct[0]
                            next_instruct = self.top.disassembleAddress(self.cpu, next_ip)
                            mn = self.decode.getMn(next_instruct[1])
                        else: 
                            parts = next_instruct[1].split()
                            if len(parts) == 2:
                                try:
                                    next_ip = int(parts[1], 16)
                                    next_instruct = self.top.disassembleAddress(self.cpu, next_ip)
                                    mn = self.decode.getMn(next_instruct[1])
                                except:
                                    self.lgr.debug('dataWatch getNextInstruct is jnz failed to get jump dest from %s' % (next_instruct[1]))
                                    next_ip = None
                                    break
                    elif mn in ['jz', 'je']:
                        self.lgr.debug('dataWatch getNextInstruct is jz flags %s' % str(flags))
                        if 'ZF' not in flags:
                            next_ip = next_ip + next_instruct[0]
                            next_instruct = self.top.disassembleAddress(self.cpu, next_ip)
                            mn = self.decode.getMn(next_instruct[1])
                        else: 
                            parts = next_instruct[1].split()
                            if len(parts) == 2:
                                try:
                                    next_ip = int(parts[1], 16)
                                    next_instruct = self.top.disassembleAddress(self.cpu, next_ip)
                                    mn = self.decode.getMn(next_instruct[1])
                                except:
                                    self.lgr.debug('dataWatch getNextInstruct is jz failed to get jump dest from %s' % (next_instruct[1]))
                                    next_ip = None
                                    break
                    elif mn in ['js']:
                        self.lgr.debug('dataWatch getNextInstruct is js flags %s' % str(flags))
                        if 'SF' not in flags:
                            next_ip = next_ip + next_instruct[0]
                            next_instruct = self.top.disassembleAddress(self.cpu, next_ip)
                            mn = self.decode.getMn(next_instruct[1])
                        else: 
                            parts = next_instruct[1].split()
                            if len(parts) == 2:
                                try:
                                    next_ip = int(parts[1], 16)
                                    next_instruct = self.top.disassembleAddress(self.cpu, next_ip)
                                    mn = self.decode.getMn(next_instruct[1])
                                except:
                                    self.lgr.debug('dataWatch getNextInstruct is js failed to get jump dest from %s' % (next_instruct[1]))
                                    next_ip = None
                                    break
                    else:
                        next_ip = None
                        break
                else:
                    next_ip = None
                    break
            else:
                break
        #if next_ip is not None:
        #    self.lgr.debug('dataWatch getNextInstruct return next_ip 0x%x next_instruct %s ' % (next_ip, next_instruct[1]))
        #else:
        #    self.lgr.debug('dataWatch getNextInstruct return None')
        return next_ip, next_instruct, mn, jump_cycles

    def checkPushedData(self, track_sp, our_reg_list, next_instruct, orig_ip, addr, trans_size, start, length, recent_instructs, word_size):
        adhoc = False
        next_next_ip = orig_ip + next_instruct[0]
        #self.lgr.debug('dataWatch loopAdHoc pushed our reg, next_next_ip is 0x%s' % next_next_ip)
        ''' Assumes calls we care about to ntohl-type calls immediatly follow push of our register 
            See if result of function is stored to memory. 
        '''
        #self.lgr.debug('dataWatch checkPushedData is push (or similar), see if the call is to a data transform.  next_next_ip is 0x%x' % (next_next_ip))
        adhoc = self.checkNTOHL(next_next_ip, addr, trans_size, start, length, recent_instructs=recent_instructs)
        if not adhoc:
            adhoc = self.checkPushedTest(next_next_ip, addr, trans_size, start, length, recent_instructs=recent_instructs)
        if not adhoc:
            self.lgr.debug('dataWatch checkPushedData, not a NTOHL into memory')
            ''' TBD tweak this for ARM fu '''
            ''' If call to ntohl-like function (but result not stored to memory per above, don't record push '''
            instruct = self.top.disassembleAddress(self.cpu, next_next_ip)
        
            self.lgr.debug('dataWatch checkPushedData see if next is a data xform')
            fun = self.isDataTransformCall(instruct, next_next_ip, recent_instructs=recent_instructs)
            if fun is None:
                ''' Will track the push.  Manage so the stack buffer (the push), is removed on return.'''
                track_sp = track_sp - word_size
                loop_instructions = len(recent_instructs)
                self.lgr.debug('dataWatch checkPushedData next was not data xform, track the push to track_sp 0x%x, consumed %d loop instructions' % (track_sp, loop_instructions))
                adhoc = self.trackPush(track_sp, instruct, addr, start, length, next_next_ip, loop_instructions=loop_instructions)
            else:
                ''' set a break/hap on return from transform to see if its eax gets pushed onto the stack for a call.'''
                orig_cycle = self.cpu.cycles
                self.move_stuff = self.CheckMoveStuff(addr, trans_size, start, length, fun, ip=orig_ip, cycle=orig_cycle)
                after_call = next_next_ip + instruct[0]
                self.lgr.debug('dataWatch checkPushedData, was push, saw it is a data transform function, look for push of result, thinking after_call is 0x%x.' % after_call)
                break_num = self.context_manager.genBreakpoint(None, Sim_Break_Linear, Sim_Access_Execute, after_call, 1, 0)
                track_sp = track_sp - word_size
                ntoh_rec = self.NTOHType(track_sp, next_next_ip, fun)
                self.transform_push_hap = self.context_manager.genHapIndex("Core_Breakpoint_Memop", 
                     self.transformPushHap, ntoh_rec, break_num, 'transformPush')
                adhoc = True
        else:
            self.lgr.debug('dataWatch checkPushedData checkNTOHL found write to memory or a test of a pass by value')
            pass
        return adhoc

    class NTOHType():
        def __init__(self, sp, ip, fun):
            self.sp = sp   
            self.ip = ip   
            self.fun = fun   
            self.reg = None

    def trackPush(self, sp, instruct, addr, start, length, ip, loop_instructions=0):
        retval = True
        ret_to = self.findCallReturn(ip, instruct)
        if ret_to is None:
            self.lgr.debug('dataWatch trackPush, findCallReturn failed for 0x%x, %s' % (ip, instruct[1]))
            retval = False
        else:
            # A buffer value was pushed on the stack and we don't know the called function,
            # so just track it as a new buffer.
            self.setRange(sp, self.mem_utils.wordSize(self.cpu), no_extend=True)
            self.watchMarks.pushMark(addr, sp, start, length, ip)                            
            self.lgr.debug('dataWatch trackPush, did push ip 0x%x cycle 0x%x' % (ip, self.cpu.cycles))
            self.setBreakRange()
            self.move_cycle = self.cpu.cycles
            self.move_cycle_max = self.cpu.cycles + 1 + loop_instructions
            self.lgr.debug('dataWatch trackPush move_cycle_max now 0x%x' % self.move_cycle_max)
            if ret_to not in self.stack_buffers:
                self.stack_buffers[ret_to] = []
                proc_break = self.context_manager.genBreakpoint(None, Sim_Break_Linear, Sim_Access_Execute, ret_to, 1, 0)
                self.stack_buf_hap[ret_to] = self.context_manager.genHapIndex("Core_Breakpoint_Memop", self.stackBufHap, None, proc_break, 'stack_buf_hap')
                self.lgr.debug('dataWatch trackPush stack_buf_hap[0x%x] %d x added to stack_buffers' % (ret_to, self.stack_buf_hap[ret_to]))
            else:
                #self.lgr.debug('dataWatch trackPush eip 0x%x already in stack_buffers, no hap set' % ret_to)
                pass
            index = len(self.start)-1
            self.stack_buffers[ret_to].append(index)
            #self.lgr.debug('dataWatch trackPush appended index %d to stack_buffers.  start of that is 0x%x' % (index, self.start[index]))

    def bailAlone(self, dumb):
            SIM_break_simulation('trackPush failure')
            self.top.stopTracking()      

    def findCallReturn(self, ip, instruct):
        next_instruct = instruct
        next_ip = ip
        limit = 20
        count = 0
        retval = None
        if self.fun_mgr is not None:
            while not self.fun_mgr.isCall(next_instruct[1]):
                next_ip = next_ip + next_instruct[0]
                next_instruct = self.top.disassembleAddress(self.cpu, next_ip)
                if count > limit:
                    self.lgr.debug('dataWatch findCall failed to find call after ip 0x%x.' % ip)
                    next_ip = None
                    break
                count += 1
            if next_ip is not None:
                retval = next_ip + next_instruct[0]
        return retval

    def lookPushedReg(self):
        '''
        At return from a function that returns a value in a register, e.g, eax.
        See if this value is passed to some function of interest.
        '''
        eip = self.top.getEIP(self.cpu)
        our_reg = self.mem_utils.getCallRetReg(self.cpu)
        dum_cpu, comm, tid = self.task_utils.curThread()
        self.lgr.debug('dataWatch lookPushedReg cycle 0x%x' % self.cpu.cycles)
        instruct = self.top.disassembleAddress(self.cpu, self.mem_something.called_from_ip)
        # pass called-from address because loopAdHoc does not assess the first instruction.
        # set only_push so we are not distracted by move of value into a temp variable
        adhoc = self.loopAdHoc(self.mem_something.addr, self.mem_something.trans_size, self.mem_something.start, self.mem_something.length, 
                     instruct, our_reg, self.mem_something.called_from_ip, eip, self.cpu.cycles, tid, only_push=True)


        return adhoc

    def transformPushHap(self, xform_rec, an_object, breakpoint, memory):
        ''' Returned from a data transform call that operated on tracked data.  See if return value is put somewhere or passed to another function.'''
        if self.transform_push_hap is not None:
            self.lgr.debug('dataWatch transformPushHap %s' % self.move_stuff.getString())
            self.context_manager.genDeleteHap(self.transform_push_hap)
            self.transform_push_hap = None
            eip = self.top.getEIP(self.cpu)
            instruct = SIM_disassemble_address(self.cpu, eip, 1, 0)
            our_reg = self.mem_utils.getCallRetReg(self.cpu)
            dum_cpu, comm, tid = self.task_utils.curThread()
            self.lgr.debug('dataWatch transformPushHap call loopAdHoc?? recurs?')
            adhoc = self.loopAdHoc(self.move_stuff.addr, self.move_stuff.trans_size, self.move_stuff.start, self.move_stuff.length, 
                           instruct, our_reg, eip, self.move_stuff.ip, self.move_stuff.cycle, tid)
            if adhoc:
                self.lgr.debug('dataWatch transformPushHap was adHoc')
            else:
                self.lgr.debug('dataWatch transformPushHap was NOT adHoc,  record the xform function')
                append = ' to reg %s' % our_reg
                mark = self.watchMarks.mscMark(xform_rec.fun, self.move_stuff.addr, msg_append=append)

    def checkXmmMove(self, addr, our_reg, src_maybe, eip, instruct, tid):
        retval = False
        if instruct[1].startswith('movdqa') and our_reg.startswith('xmm'):
            qcount = 1
            done_movdqa = False
            next_eip = eip
            next_instruct = instruct
            src = self.decode.getAddressFromOperand(self.cpu, src_maybe, self.lgr)
            if src is not None:
                while not done_movdqa:
                    next_eip = next_eip + next_instruct[0]
                    next_instruct = self.top.disassembleAddress(self.cpu, next_eip)
                    if next_instruct[1].startswith('movdqa'):
                        qcount = qcount + 1
                    elif next_instruct[1].startswith('movups'):
                        op2, op1 = self.decode.getOperands(next_instruct[1])
                        dest = self.decode.getAddressFromOperand(self.cpu, op1, self.lgr)
                        if dest is None:
                            self.lgr.error('dataWatch checkXmmMove failed to get dest from %s' % (next_instruct[1]))
                        else:
                            self.lgr.debug('dataWatch checkXmmMove got dest 0x%x' % dest)
                            retval = True 
                        done_movdqa = True
                    else:
                        self.lgr.error('dataWatch checkXmmMove confused by %s' % (next_instruct[1]))
                        break
        if retval:
            # last instruct was a movups.  See if next is a move of remainder
            next_eip = next_eip + next_instruct[0]
            next_instruct = self.top.disassembleAddress(self.cpu, next_eip)
            remain_src = None
            bytes_moved = 16 * qcount
            if next_instruct[1].startswith('mov '):
                op2, op1 = self.decode.getOperands(next_instruct[1])
                remain_src = self.decode.getAddressFromOperand(self.cpu, op2, self.lgr)
                self.lgr.debug('dataWatch checkXmmMove src 0x%x bytes_moved 0x%x, remain_src 0x%x' % (src, bytes_moved, remain_src))
                if remain_src == (src+bytes_moved):
                    bytes_moved = bytes_moved + 8
                    self.lgr.debug('dataWatch checkXmmMove is remain, bytes_moved now 0x%x' % bytes_moved)
                else:
                    self.lgr.error('dataWatch checkXmmMove confused')
                    return False
                next_eip = next_eip + next_instruct[0]
                next_instruct = self.top.disassembleAddress(self.cpu, next_eip)
            done_moveups = False
            while not done_moveups:
                if next_instruct[1].startswith('movups'):
                    next_eip = next_eip + next_instruct[0]
                    next_instruct = self.top.disassembleAddress(self.cpu, next_eip)
                else:
                    done_moveups = True
            if remain_src is not None:
                next_eip = next_eip + next_instruct[0]
                next_instruct = self.top.disassembleAddress(self.cpu, next_eip)
            self.lgr.debug('dataWatch checkXmmMove will run forward to next_eip 0x%x' % next_eip)
            index = self.findRangeIndex(addr)
            wm = self.watchMarks.copy(src, dest, bytes_moved, self.start[index], Sim_Trans_Load)
            self.setRange(dest, bytes_moved)
            msg = wm.mark.getMsg()
            #self.lgr.debug('dataWatch checkXmmMove add wm %s' % msg)
            disableAndRun.DisableAndRun(self.cpu, next_eip, self.context_manager, self.lgr)
        return retval

    def checkMove(self, addr, trans_size, start, length, eip, instruct, tid):
        ''' Does this look like a move from memA=>reg=>memB ? '''
        ''' If so, return dest.  Also checks for regex references using reWatch module '''
        ''' The given eip is where the read happened.'''
        self.lgr.debug('dataWatch checkMove %s addr 0x%x' % (instruct[1], addr))
        adhoc = False
        was_checked = False
        self.recent_reused_index = None
        orig_ip = self.top.getEIP(self.cpu)
        orig_cycle = self.cpu.cycles
        if instruct[1].startswith('mov') or instruct[1].startswith('ldr') or (self.cpu.architecture == 'ppc32' and instruct[1].startswith('l')):
            op2, op1 = self.decode.getOperands(instruct[1])
            self.lgr.debug('dataWatch checkMove op1 %s op2 %s' % (op1, op2))
            if self.decode.isReg(op1):
                self.lgr.debug('dataWatch checkMove is mov to reg %s eip:0x%x' % (op1, eip))
                our_reg = op1
                adhoc = self.checkXmmMove(addr, our_reg, op2, eip, instruct, tid)
                if not adhoc:
                    adhoc = self.loopAdHoc(addr, trans_size, start, length, instruct, our_reg, eip, orig_ip, orig_cycle, tid)
                    self.lgr.debug('dataWatch checkMove loopAdHoc returned %r' % adhoc)
                was_checked = True
        elif instruct[1].startswith('ldm'):
            op2, op1 = self.decode.getOperands(instruct[1])
            reg_set = op2
            adhoc = self.loopAdHocMult(addr, trans_size, start, length, instruct, reg_set, eip, orig_ip, orig_cycle)
            was_checked = True
        if not adhoc:
            if was_checked:
                if eip not in self.not_ad_hoc_copy and not self.watchMarks.ipIsAdHoc(eip):
                    self.lgr.debug('dataWatch checkMove addr 0x%x add 0x%x to not_ad_hoc_copy' % (addr, eip))
                    self.not_ad_hoc_copy.append(eip)

            if not self.checkReWatch(tid, eip, instruct, addr, start, length, trans_size):
                self.lgr.debug('dataWatch checkMove not a reWatch')
                is_test_loop = False
                if instruct[1].startswith('mov'):
                    null_test_loop = nullTestLoop.NullTestLoop(self.top, self.cpu, self, self.context_manager, self.watchMarks, self.mem_utils, self.decode, eip, addr, instruct, self.lgr)
                    if null_test_loop.checkForLoop():
                        is_test_loop = True
                if not is_test_loop:
                    self.watchMarks.dataRead(addr, start, length, trans_size)
                    if self.finish_check_move_hap is not None:
                        self.lgr.debug('DataWatch checkMove delete finish_check_move_hap')
                        hap = self.finish_check_move_hap
                        self.context_manager.genDeleteHap(hap, immediate=False)
                        self.finish_check_move_hap = None
        else:
            ''' was ad hoc, do not bother to stack trace on next hit '''
            if eip not in self.is_ad_hoc_move:
                self.is_ad_hoc_move.append(eip)

    def checkReWatch(self, tid, eip, instruct, addr, start, length, trans_size):
        retval = False
        ''' make sure we are not back here due to an UNDO '''
        seen_movie = False
        if self.save_cycle is not None:
            delta = self.cpu.cycles - self.save_cycle
            if delta < 4:
                seen_movie = True 
        re_watch = None
        if not seen_movie:
            self.save_cycle = self.cpu.cycles - 1
            re_watch = reWatch.REWatch.isCharLookup(addr, eip, instruct, self.decode, self.cpu, tid, self.mem_utils, 
                  self.context_manager, self.watchMarks, self.top, self.lgr)
        else:
            self.lgr.debug('dataWatch checkReWatch think this is an undo, do not look for reWatch')
        if re_watch is not None:
            retval = True
            self.re_watch_list.append(re_watch)
            new_mem_something = re_watch.getMemSomething(addr) 
            if new_mem_something is None:
                  self.lgr.error('dataWatch checkReWatch getMemSomething returned none')
                  SIM_break_simulation('error in checkRewatch')
                  return
            if new_mem_something.fun_addr is None:
                  # TBD maybe keep list of data hit EIPs to know this is the one that came in via the fun entry?
                  self.lgr.debug('dataWatch checkReWatch new_mem_something.fun_addr is None. Must be unanalyzed function.  TBD find way to add based on guesswork')
            else: 
                self.lgr.debug('dataWatch checkReWatch tid:%s is re watch, new_mem_something.fun_addr 0x%x' % (tid, new_mem_something.fun_addr))
            if new_mem_something.fun_addr in self.skip_entries:
                self.lgr.debug('dataWatch checkReWatch tid:%s is re watch, 0x%x in skip_entries, bail' % (tid, new_mem_something.fun_addr))
                return
            ''' crude test to see if function call is to GOT, which makes actual function call'''
            hack_match = None
            if self.mem_something is not None and self.mem_something.fun_addr is not None and self.mem_something.fun_addr != new_mem_something.fun_addr:
                fun_instruct = self.top.disassembleAddress(self.cpu, self.mem_something.fun_addr)[1]
                self.lgr.debug('dataWatch checkReWatch re_watch look for got in instruct %s' % fun_instruct)
                ''' TBD generalize this'''
                if self.cpu.architecture in ['arm', 'arm64'] and fun_instruct.startswith('b'):
                    parts = fun_instruct.split()
                    try:
                        hack_match = int(parts[1].strip(), 16)
                        self.lgr.debug('dataWatch checkReWatch re_watch GOT call, generalize this 0x%x' % hack_match)
                    except:
                        self.lgr.debug('dataWatch checkReWatch re_watch GOT crapped out, instruct %s' % fun_instruct)
                        pass
                    
            if self.mem_something is not None and self.mem_something.fun_addr is not None and (self.mem_something.fun_addr == new_mem_something.fun_addr or \
                      (hack_match is not None and hack_match == new_mem_something.fun_addr)):
                ''' We already gathered ret_addr_addr on our way in.  Do not need to reverse '''
                ret_addr_addr = self.mem_something.ret_addr_addr
                src = self.mem_something.src
                self.mem_something = new_mem_something
                self.mem_something.ret_addr_addr = ret_addr_addr
                ''' TBD fix.  generalize? '''
                if self.mem_something.fun == 'ostream_insert':
                    self.mem_something.src = src
                self.lgr.debug('dataWatch checkReWatch tid:%s is re watch, we already gathered ret_addr_addr on our way in at fun entry 0x%x.  Do not need to reverse. cycles: 0x%x ' %(tid, self.mem_something.fun_addr, self.cpu.cycles))
                self.runToReturnAndGo()
            else:
                if self.mem_something.fun_addr is None:
                    self.lgr.debug('dataWatch checkReWatch tid:%s is re watch, funs do not match, fun addr NONE' % (tid)) 
                elif new_mem_something.fun_addr is None:
                    self.lgr.debug('dataWatch checkReWatch tid:%s is re watch, funs do not match, new_mem_something.fun_addr is none' % (tid))
                else:
                    self.lgr.debug('dataWatch checkReWatch tid:%s is re watch, funs do not match, fun addr 0x%x  new fun addr 0x%x  cycles: 0x%x ' %(tid, self.mem_something.fun_addr,
                        new_mem_something.fun_addr, self.cpu.cycles))
                self.mem_something = new_mem_something
    
                if self.mem_something is not None:
                    SIM_run_alone(self.handleMemStuff, None)
                else:
                    self.lgr.error('dataWatch checkReWatch failed to get mem_something from re_watch')
                    self.watchMarks.dataRead(addr, start, length, trans_size)
        return retval

    def isReuse(self, eip):
        ''' guess is a data buffer is being recycled, e.g., loaded with zeros'''
        retval = False
        instruct = self.top.disassembleAddress(self.cpu, eip)
        ''' TBD why care about direct move vs some other reuse of buffer???'''
        if self.decode.isDirectMove(instruct[1]):
            retval = True
        elif instruct[1].startswith('str'):
            op2, op1 = self.decode.getOperands(instruct[1])
            if self.decode.isReg(op1) and self.decode.getValue(op1, self.cpu, lgr=self.lgr)==0:
                retval = True
        return retval

    def checkRep(self, instruct, addr, buf_start):
        # look for rep or repe type instruction
        retval = None
        if instruct[1].startswith('repe cmpsb') or instruct[1].startswith('repe cmpsd'):
            esi = self.mem_utils.getRegValue(self.cpu, 'esi')
            edi = self.mem_utils.getRegValue(self.cpu, 'edi')
            count = self.mem_utils.getRegValue(self.cpu, 'ecx')
            if instruct[1].startswith('repe cmpsd'):
                count = count*4
            buf_start = self.findRange(edi)
            if buf_start is None:
                buf_start = self.findRange(esi)
                wm = self.watchMarks.compare(instruct[1], esi, edi, count, buf_start)
            else:
                wm = self.watchMarks.compare(instruct[1], edi, esi, count, buf_start)
            retval = wm.mark.getMsg()
        elif instruct[1].startswith('rep movsb') or instruct[1].startswith('rep movsd'):
            esi = self.mem_utils.getRegValue(self.cpu, 'esi')
            edi = self.mem_utils.getRegValue(self.cpu, 'edi')
            count = self.mem_utils.getRegValue(self.cpu, 'ecx')
            if instruct[1].startswith('rep movsd'):
                count = count*4
            self.lgr.debug('dataWatch checkRep esi 0x%x edi 0x%x count %d buf_start 0x%x addr 0x%x' % (esi, edi, count, buf_start, addr))
            start = esi
            if buf_start > start:
                start = buf_start
                count = count - (buf_start - esi)
                self.lgr.debug('dataWatch checkRep esi was before start of buffer, set start to start of buffer, count changed to %d' % count)
            wm = self.watchMarks.copy(start, edi, count, buf_start, Sim_Trans_Load)
            self.setRange(edi, count)
            retval = wm.mark.getMsg()
            self.move_cycle = self.cpu.cycles
            #self.move_cycle_max = self.cpu.cycles + int(count/4)
            self.move_cycle_max = self.cpu.cycles + 1
            self.lgr.debug('dataWatch checkRep move cycle 0x%x max 0x%x' % (self.move_cycle, self.move_cycle_max))
        return retval
              
    def finishReadHap(self, op_type, trans_size, eip, addr, length, start, tid, index=None):
        instruct = self.top.disassembleAddress(self.cpu, eip)
        offset = addr - start
        cpl = memUtils.getCPL(self.cpu)
        self.lgr.debug('dataWatch finishReadHap eip: 0x%x addr 0x%x' % (eip, addr))
        if op_type == Sim_Trans_Load:
            if cpl == 0:
                #if not self.break_simulation:
                #    self.stopWatch()
                self.lgr.debug('dataWatch finishReadHap, read in kernel, set kernelReturn hap')
                #self.return_hap = 'eh'
                SIM_run_alone(self.kernelReturn, self.KernelReturnInfo(addr, op_type))
                return
            else:
                #self.lgr.debug('finishReadHap Data read from 0x%x within buffer (offset of %d into buffer of %d bytes starting at 0x%x) tid:%s eip: 0x%x <%s> cycle:0x%x' % (addr, 
                #        offset, length, start, tid, eip, instruct[1], self.cpu.cycles))
                self.prev_read_cycle = self.cpu.cycles
                msg = ('Data read from 0x%x within buffer (offset of %d into %d bytes starting at 0x%x) eip: 0x%x' % (addr, 
                            offset, length, start, eip))
                self.lgr.debug(msg)
                self.context_manager.setIdaMessage(msg)
                # see if it is a a rep/repe type instruction
                rep_msg = self.checkRep(instruct, addr, start)
                if rep_msg is not None:
                    msg = rep_msg
                    self.lgr.debug(msg)
                    self.context_manager.setIdaMessage(msg)
                    self.lgr.debug('dataWatch finishReadHap, found a rep move, call set break range')
                    self.setBreakRange()
                else: 
                    loop_msg = self.checkLoopCmp(eip, instruct, addr)
                    if loop_msg is not None:
                        msg = loop_msg
                        self.lgr.debug(msg)
                    else:         
                        adhoc = False
                        ''' see if an ad-hoc move. checkMove will update watch marks '''
                        if eip not in self.not_ad_hoc_copy:
                            self.checkMove(addr, trans_size, start, length, eip, instruct, tid)
                            self.lgr.debug('dataWatch back from checkMove')
                        else:
                            self.lgr.debug('dataWatch eip 0x%x is in not_ad_hoc_copy list' % eip)
                            if not self.checkReWatch(tid, eip, instruct, addr, start, length, trans_size):
                                self.lgr.debug('dataWatch checkMove xx not a reWatch')
                                is_test_loop = False
                                if instruct[1].startswith('mov'):
                                    null_test_loop = nullTestLoop.NullTestLoop(self.top, self.cpu, self, self.context_manager, self.watchMarks, self.mem_utils, self.decode, eip, addr, instruct, self.lgr)
                                    if null_test_loop.checkForLoop():
                                        is_test_loop = True
                                if not is_test_loop:
                                    self.lgr.debug('dataWatch checkMove xx not a null test loop %s' % instruct[1])
                                    self.watchMarks.dataRead(addr, start, length, trans_size)

                if self.break_simulation:
                    self.lgr.debug('dataWatch told to break simulation')
                    SIM_break_simulation('DataWatch read data')


        elif cpl > 0:
            ''' is a write to a data watch buffer '''
            #self.lgr.debug('finishReadHap Data written to 0x%x within buffer (offset of %d into buffer of %d bytes starting at 0x%x) tid:%s eip: 0x%x' % (addr, offset, length, start, tid, eip))
            if addr == self.recent_fgets:
                self.lgr.debug('dataWatch reuse of fgets buffer at 0x%x, remove it' % addr)
                self.rmRange(addr)
            else:   
                self.context_manager.setIdaMessage('Data written to 0x%x within buffer (offset of %d into %d bytes starting at 0x%x) eip: 0x%x' % (addr, offset, length, start, eip))
                #self.lgr.debug('Data written to 0x%x within buffer (offset of %d into %d bytes starting at 0x%x) eip: 0x%x' % (addr, offset, length, start, eip))
                ''' TBD move to separate function.  ad-hoc check for xmm based buffer clear.  prehaps too crude.'''
                if instruct[1].startswith('movdqa xmmword'):
                    self.lgr.debug('dataWatch finishReadHap is xmm instruct %s' % instruct[1])
                    xmm0 = self.mem_utils.getRegValue(self.cpu, 'xmm0L') 
                    if xmm0 is not None:
                        self.lgr.debug('dataWatch finishReadHap xmm0L value 0x%x' % xmm0)
                    if xmm0 == 0 and index is not None:
                        ''' assume the whole fbuffer will go '''
                        length = self.length[index]
                        trans_size = self.length[index] 
                        addr = start
            
                recent = self.watchMarks.getRecentMark()
                self.watchMarks.memoryMod(start, length, trans_size, addr=addr)

                if (self.cpu.cycles - self.last_byteswap) > 0x100:
                    if self.break_simulation:
                        ''' TBD when to treat buffer as unused?  does it matter?'''
                        self.start[index] = None
                        self.lgr.debug('dataWatch toldx to break simulation')
                        SIM_break_simulation('DataWatch written data')
                    else:
                        ''' TBD deleting buffer, sometimes, in finishReadHap, here too?'''
                        if isinstance(recent.mark, watchMarks.DataMark) and recent.mark.addr == addr and recent.mark.trans_size == trans_size: 
                           self.lgr.debug('dataWatch did mem mod, did recent read of same data, assume manipulation')
                           pass
                        else: 
                            self.lgr.debug('dataWatch did mem mod, call rmSubRange for 0x%x len 0x%x' % (addr, trans_size))
                            if trans_size > 1:
                                self.rmSubRange(addr, trans_size)
                            else:
                                self.lgr.debug('********remove this*********************REMOVE THIS**********************')
                            pass
                else:
                    self.lgr.debug('dataWatch did mem mod, but recent byteswap, assume messing with read values.')
        elif self.retrack:
            self.lgr.debug('dataWatch finishReadHap, modification by kernel, set kernelReturn hap cycle 0x%x' % self.cpu.cycles)
            ''' return_hap may already be pending '''
            #self.return_hap = 'eh'
            SIM_run_alone(self.kernelReturn, self.KernelReturnInfo(addr, op_type))
            self.lgr.debug('Data written by kernel to 0x%x within buffer (offset of %d into buffer of %d bytes starting at 0x%x) tid:%s eip: 0x%x. In retrack, stop here TBD FIX THIS.' % (addr, offset, length, start, tid, eip))
            #self.stopWatch()
            self.rmSubRange(addr, trans_size)
        else:
            self.lgr.debug('dataWatch finishReadHap, modification by kernel, set kernelReturn hap')
            SIM_run_alone(self.kernelReturn, self.KernelReturnInfo(addr, op_type))

    def readHap(self, index, an_object, breakpoint, memory):
        '''
        Front-line HAP hit called back to when a watched data buffer is read or written.  
        Will use memsomething function to determine if the reference is part of a clibish function such as
        memcpy, memcmp, etc.  Uses checkFree to determine if the reference is part of a "free" operation that
        should result in our no longer watching the buffer.  If neither of those seem to be the case, it will
        call finishReadHap, which will look for ad-hoc moves.

        When memsomethings are found, we set a break on their entry so that future hits on that memsomething can be caught
        without triggering the readHap.  TBD trade off between setting breaks beforehand?  Save for rerun of runTrack operations?
        '''
        if self.return_hap is not None: 
            self.lgr.debug('readHap return_hap not none, bail')
            return
        if self.context_manager.isReverseContext():
            self.lgr.debug('readHap is reverse context, bail')
            return
        if index >= len(self.start):
            self.lgr.debug('dataWatch readHap index %d but len of start is %d addr 0x%x' % (index, len(self.start), memory.logical_address))
            return
        addr = memory.logical_address
        if addr in self.ignore_addr_list:
            return

        if self.read_hap[index] is None:
            self.lgr.debug('dataWatch readHap for index %d is None bail' % index)
            return

        op_type = SIM_get_mem_op_type(memory)
        eip = self.top.getEIP(self.cpu)
        #if self.cpu.cycles == 0x3de4883da:
        #    SIM_break_simulation('remove this')
        #    return
        #if self.top.isVxDKM(target=self.cell_name) and self.so_map.inVxWorks(eip): 
        #    start, length = self.findBufForRange(memory.logical_address, memory.size)
        #    self.lgr.debug('dataWatch readHap in VxWorks addr 0x%x op_type %d cycles: 0x%x.' % (memory.logical_address, op_type, self.cpu.cycles))
        #    if not self.lookForMemStuff(addr, start, length, memory, op_type, eip, None):
        #        self.lgr.debug('dataWatch readHap in VxWorks but not memstuff.  TBD')
        #    return

        dum_cpu, comm, tid = self.task_utils.curThread()
        if not self.task_utils.commMatch(comm, self.comm):
            if comm in self.failed_comm_list:
                self.lgr.debug('readHap tid:%s comm %s in failed comm list' % (tid, comm))
                return
            index_of_phys = self.findRangeIndexPhys(memory.physical_address)
            self.lgr.debug('readHap tid:%s comm %s, but we are %s physical 0x%x index_of_phys %s start %s op_type: %d cycle: 0x%x' % (tid, comm, self.comm, memory.physical_address, index_of_phys, self.start[index_of_phys], op_type, self.cpu.cycles))
        
            if self.cpu.cycles == self.prev_cycle:
                self.lgr.debug('readHap same cycle as previous, bail')
                return
          
            if self.start[index] is None:
                latest_index = self.findRangeIndexPhys(memory.physical_address)
                if latest_index is None:
                    self.lgr.debug('readHap comm %s, but we are %s, index %d is None bail phys was 0x%x, ' % (comm, self.comm, index, memory.physical_address))
                    return
                else:
                    self.lgr.debug('readHap not our comm, switched index %d with latest %d' % (index, latest_index))
                    index = latest_index
                    if start[index] is None:
                        self.lgr.debug('readHap %s is not our comm, start[%d] still none, bail' % (comm, index))
            if op_type == Sim_Trans_Load:
                if index not in self.linear_breaks:
                    self.lgr.debug('readHap index %d not in self.linear_breaks comm is %s  self.comm %s phys mem hit 0x%x' % (index, comm, self.comm, memory.physical_address))
                    if self.data_watch_manager is None:
                        self.data_watch_manager = dataWatchManager.DataWatchManager(self.top, self, self.cpu, self.cell_name, self.page_size, 
                                    self.context_manager, self.mem_utils, self.task_utils, self.rev_to_call, self.param, self.run_from_snap, self.backstop, 
                                    self.compat32, self.comp_dict, self.so_map, self.reverse_mgr, self.lgr)
                    if self.data_watch_manager.failedCreate():
                        self.data_watch_manager = None
                        self.lgr.debug('readHap comm %s, but we are %s and create new data watch failed,, bail' % (comm, self.comm))
                        self.failed_comm_list.append(comm)
                        if index_of_phys < len(self.start):
                            if self.start[index_of_phys] is not None:
                                self.lgr.debug('readHap record wrong comm')
                                msg = 'Read from buffer 0x%x %d bytes' % (self.start[index_of_phys], memory.size)
                                self.watchMarks.mscMark('Other process', memory.physical_address, msg)
                            else:
                                self.lgr.debug('readHap start[%d] is none' % index_of_phys)
                        else:    
                            self.lgr.debug('readHap index %d not in start' % index_of_phys)
                    else:     
                        self.recordOtherProcRead(memory.physical_address, memory.size, addr, index, comm, tid, op_type)
                        self.lgr.debug('readHap comm %s, but we are %s, bail' % (comm, self.comm))
                        self.prev_cycle = self.cpu.cycles
                    return
                else:
                    self.lgr.debug('readHap comm %s, but we are %s, TBD is a linear break????' % (comm, self.comm))
            else:
                self.lgr.debug('readHap comm %s, but we are %s, TBD is a modify, remove range start[%d]=0x%x and bail' % (comm, self.comm, index, self.start[index]))
                self.rmRange(self.start[index])
                return

        # may be multiple overlapping buffer ranges, index is simply first reported by Simics.  Find
        # the most recently defined range
        latest_index = self.findRangeIndex(addr)
        self.lgr.debug('readHap tid:%s latest index for addr 0x%x is %s' % (tid, addr, latest_index))
        if latest_index is not None and latest_index != index:
            self.lgr.debug('readHap altering index from %d to more recently defined buffer at index %d' % (index, latest_index))
            index = latest_index

        cpl = memUtils.getCPL(self.cpu)

        if cpl > 0:
            if addr == 0:
                self.lgr.error('readHap memory logical address zero???, index %d' % index)
                SIM_break_simulation('remove this')
        else:
            if addr is None:
                self.lgr.debug('dataWatch readHap in kernel, addr None, compute offset. index %d size %d' % (index, size))
                start = self.start[index]
                if start is not None:
                    phys_of_start = self.mem_utils.v2p(self.cpu, start)
                    if phys_of_start is not None:
                        self.lgr.debug('dataWatch readHap reference from kernel.  Index %d. Reference memory.logical_address 0x%x memory.physical_addr 0x%x, start[%d] is 0x%x phys of start 0x%x' % (index, memory.logical_address, memory.physical_address, index, start, phys_of_start))
                        delta = phys_of_start - memory.physical_address
                        if delta >= 0:
                            addr = start + delta 
                            self.lgr.debug('dataWatch readHap in kernel delta 0x%x, set addr to 0x%x' % (delta, addr))
                        else:
                            self.lgr.debug('dataWatch readHap in kernel delta negative?  0x%x, ' % (delta))
                             
                    else:
                        self.lgr.error('dataWatch readHap no physical address for start address 0x%x' % start)
                else:
                    self.lgr.error('dataWatch readHap no start address for index %s' % index)
            else:
                #self.lgr.debug('dataWatch readHap reference from kernel.  Index %d. Reference memory.logical_address 0x%x phys 0x%x size %d' % (index, 
                #     memory.logical_address, memory.physical_address, memory.size))
                start, length, dumb = self.findBufForRange(memory.logical_address, memory.size)
                if start is None:
                     #self.lgr.warning('dataWatch readHap reference from kernel for index %d that does not cover this address 0x%x WILL BAIL' % (index, memory.logical_address))
                     return
                else:
                     self.lgr.debug('dataWatch readHap reference from kernel for index %d buffer start 0x%x' % (index, start))
    
        if op_type != Sim_Trans_Load:
            self.lgr.debug('dataWatch readHap not a load, cycles: 0x%x move_cycle: 0x%x  move_cycle_max: 0x%x' % (self.cpu.cycles, self.move_cycle, self.move_cycle_max))
            
            if self.top.isVxDKM(cpu=self.cpu):
                task = self.mem_utils.getCurrentTask()
            else:
                task = None
            if self.top.isVxDKM(cpu=self.cpu) and self.top.getSharedSyscall().getPendingCall(task) in ['fgets']:
                self.lgr.debug('dataWatch readHap is fgets, bail')
                return
            if not (self.move_cycle <= self.cpu.cycles and self.move_cycle_max >= self.cpu.cycles):
                #self.lgr.debug('****************dataWatch readHap tid:%s write addr: 0x%x index: %d marks: %s max: %s cycle: 0x%x eip: 0x%x' % (tid, addr, index, str(self.watchMarks.markCount()), str(self.max_marks), 
                #     self.cpu.cycles, eip))
                if self.mem_utils.isKernel(eip) and  self.top.getSharedSyscall().callbackPending():
                    self.lgr.debug('dataWatch readHap still kernel, just a read, ignore')
                    return
                if self.checkFailedStackBufs(index):
                    self.lgr.debug('dataWatch readHap is a write to dead stack buf %d, skip it' % index)
                    return
                if memory.size <= 8:
                    new_value = memUtils.memoryValue(self.cpu, memory)
                    if self.cheapReuse(eip, addr, memory.size, new_value):
                        return
                else:
                    buf = memUtils.memoryValue(self.cpu, memory)
                    if all(v == 0 for v in buf):
                        self.lgr.debug('dataWatch readHap wrote %d bytes value %s, remove buffer' % (memory.size, str(buf)))
                        self.rmRange(addr) 
            else:
                self.lgr.debug('dataWatch just a write to 0x%x that is part of a copy.  Ignore' % addr)
        else:
            break_handle = self.context_manager.getBreakHandle(breakpoint)
            if break_handle is None:
                self.lgr.error('dataWatch failed to get break_handle for breakpoint 0x%x (%d) addr: 0x%x index %d cycle 0x%x' % (breakpoint, breakpoint, addr, index, self.cpu.cycles))
                return
            self.lgr.debug('****************dataWatch readHap tid:%s read addr: 0x%x index: %d breakpoint: %d handle: %d marks: %s max: %s cycle: 0x%x eip: 0x%x phys_addr 0x%x' % (tid, addr, index, breakpoint, break_handle, str(self.watchMarks.markCount()), str(self.max_marks), 
                 self.cpu.cycles, eip, memory.physical_address))

            if self.mem_utils.isKernel(eip) and  self.top.getSharedSyscall().callbackPending():
                self.lgr.debug('dataWatch readHap still kernel, is a write remove subrange and return')
                self.rmSubRange(addr, memory.size)
                return
   
        if self.max_marks is not None and self.watchMarks.markCount() >= self.max_marks:
            self.lgr.debug('dataWatch readHap max marks exceeded read haps: %d' % len(self.read_hap))
            ''' hap echos? '''
            if len(self.read_hap) == 0:
                return
            self.maxMarksExceeded()
            return

        ''' ad hoc sanitity check for wayward programs, fuzzed, etc.'''
        #if index not in self.length or (index in self.length and self.length[index]<10):
        if index >= len(self.length) or (index < len(self.length) and self.length[index]<10):
            if index not in self.index_hits:
                self.index_hits[index] = 0
            self.index_hits[index] = self.index_hits[index]+1
            #self.lgr.error('dataWatch readHap %d hits on  index %d, ' % (self.index_hits[index], index))
            if self.index_hits[index] > self.read_loop_max:
                self.lgr.error('dataWatch readHap over %d hits on index %d eip 0x%x, stopping watch cycle: 0x%x' % (self.read_loop_max, index, eip, self.cpu.cycles))
                read_loop = os.getenv('READ_LOOP')
                if read_loop is not None and read_loop.lower() == 'quit':
                    self.top.quit()
                else:
                    self.top.pendingFault(target=self.cell_name)
                self.stopWatch(leave_backstop=True)
                return
        ''' watched data has been read (or written) '''
        if self.prev_cycle is None:
            ''' first data read, start data session if doing coverage '''
            self.top.startDataSessions()
        if self.cpu.cycles == self.prev_cycle and not self.undo_pending:
            if index != self.prev_index:
                self.lgr.debug('readHap hit twice this index %d  previous index %d' % (index, self.prev_index))
                if self.start[self.prev_index] is not None and self.start[index] is not None: 
                    self.lgr.debug('readHap prev start[%d] is 0x%x start for this is 0x%x' % (self.prev_index, self.start[self.prev_index], self.start[index]))
             
            return
        if len(self.read_hap) == 0:
            return
        if op_type != Sim_Trans_Load:
            if addr in self.last_ad_hoc:
                self.last_ad_hoc.remove(addr)
                ''' we just added this add hoc data move, but had not yet executed the instruction '''
                return
        if op_type != Sim_Trans_Load:
            self.lgr.debug('dataWatch readHap check move cycle current 0x%x move_cycle 0x%x max 0x%x' % (self.cpu.cycles, self.move_cycle, self.move_cycle_max))
            if self.move_cycle <= self.cpu.cycles and self.move_cycle_max >= self.cpu.cycles:
                ''' just writing to memory as part of previously recorded ad-hoc copy '''
                self.lgr.debug('dataWatch readHap just writing to memory as part of previously recorded ad-hoc copy')
                return
            remove_watch = False
            if addr in self.no_backstop:
                remove_watch = True
            elif len(self.length) > index and memory.size == self.length[index]:
                if self.isReuse(eip):
                    #self.lgr.debug('dataWatch readHap direct move or such into watch, remove it')
                    remove_watch = True
     
            if remove_watch:
                self.start[index] = None
                self.lgr.debug('watchData readHap modified no_backstop memory, remove index %d from watch list' % index)
                if index < len(self.read_hap):
                    if self.read_hap[index] is not None:
                        #self.lgr.debug('dataWatch readHap  delete hap %d' % self.read_hap[index])
                        hap = self.read_hap[index]
                        self.context_manager.genDeleteHap(hap, immediate=False)
                        self.read_hap[index] = None
                return
        else:
            self.recent_reused_index=None
            self.hack_reuse_index = None
            if self.mem_something is not None and self.mem_something.dest is not None:
                if self.oneByteCopy(addr, memory.size):
                    self.lgr.debug('dataWatch readHap, one byte copy')
                    self.prev_cycle = self.cpu.cycles
                    self.prev_index = index
                    return

        ''' NOTE RETURNS above '''
        if self.finish_check_move_hap is not None:
            self.lgr.debug('DataWatch readHap delete finish_check_move_hap')
            hap = self.finish_check_move_hap
            self.context_manager.genDeleteHap(hap, immediate=False)
            self.finish_check_move_hap = None

        if self.backstop is not None and not self.break_simulation and self.use_backstop and addr not in self.no_backstop:
            self.backstop.setFutureCycle(self.backstop_cycles)
        else:
            self.lgr.debug('dataWatch readHap NO backstop set.  break sim %r  use back %r' % (self.break_simulation, self.use_backstop))
        if index >= len(self.read_hap):
            self.lgr.error('dataWatch readHap tid:%s invalid index %d, only %d read haps' % (tid, index, len(self.read_hap)))
            return
        if self.read_hap[index] is None or self.read_hap[index] == 0:
            self.lgr.debug('readHap index %d none or zero' % index)
            return

        self.prev_cycle = self.cpu.cycles
        self.prev_index = index

        phys_addr = memory.physical_address
        if addr is None:
            addr_s = 'None'
        else:
            addr_s = '0x%x' % addr
        self.lgr.debug('****X dataWatch readHap tid:%s index %d addr 0x%x (phys: 0x%x) eip 0x%x cycles: 0x%x op_type: %s current_context %s cpl: %d memory.size(trans_size)=%d' % (tid, index, addr, phys_addr, eip, self.cpu.cycles, op_type, self.cpu.current_context, cpl, memory.size))
        #if self.cpu.cycles == 0x3ddf59392:
        #    SIM_break_simulation('remove this')
        #    return
        if self.show_cmp:
            self.showCmp(addr)

        if self.break_simulation:
            self.lgr.debug('readHap will break_simulation, set the stop hap')
            self.stopWatch()
            SIM_run_alone(self.setStopHap, None)

        if index >= len(self.start):
            self.lgr.debug('dataWatch readHap index %d is beyond range of start?.' % index)
            return 
 
        elif self.start[index] is None:
            self.lgr.debug('dataWatch readHap index %d has no start value, likely deleted but not immediate.' % index)
            return 

        start, length = self.getStartLength(index, addr) 
        #self.lgr.debug('readHap index %d addr 0x%x got start of 0x%x, len %d' % (index, addr, start, length))
        cpl = memUtils.getCPL(self.cpu)
        ''' If execution outside of text segment, check for mem-something library call '''
        if cpl != 0:
            #if not self.break_simulation:
            #    ''' prevent stack trace from triggering haps '''
            #    self.stopWatch()
            self.userSpaceRef(eip, tid, addr, start, length, memory.size, op_type, index=index)

        else:
            self.lgr.debug('dataWatch readHap cpl 0, memory.size %d' % memory.size)
            self.finishReadHap(op_type, memory.size, eip, addr, length, start, tid, index=index)

    def userSpaceRef(self, eip, tid, addr, start, length, trans_size, op_type, index=None):
        self.lgr.debug('dataWatch userSpaceRef eip 0x%x tid: %s addr 0x%x op_type: %d cycle: 0x%x' % (eip, tid, addr, op_type, self.cpu.cycles))
        if True:
            instruct = self.top.disassembleAddress(self.cpu, eip)
            if self.fun_mgr is not None:
                fun = self.fun_mgr.getFun(eip)
            else:
                fun = None 
            if fun is None:
                ''' This value is only used to check if we've looked to see if the current funtion is a memsomething.'''
                fun = eip

            ''' TBD seems impossible for a push to trigger a load.  huh?'''
            if not self.top.isWindows(target=self.cell_name) and instruct[1].startswith('push') and self.top.isCode(eip) and op_type == Sim_Trans_Load:
                self.lgr.debug('********* is a push, provide an explaination please!')
                sp = self.mem_utils.getRegValue(self.cpu, 'sp') - self.mem_utils.wordSize(self.cpu)
                self.trackPush(sp, instruct, addr, start, length, eip)
            elif fun in self.not_mem_something:
                self.lgr.debug('DataWatch userSpaceRef fun 0x%x in not_mem_something call finishReadHap memory.size %d' % (fun, trans_size))
                self.finishReadHap(op_type, trans_size, eip, addr, length, start, tid, index=index)
            elif eip in self.is_ad_hoc_move:
                self.lgr.debug('DataWatch userSpaceRef eip 0x%x in is_ad_hoc_move call finishReadHap memory.size %d' % (eip, trans_size))
                self.finishReadHap(op_type, trans_size, eip, addr, length, start, tid, index=index)
            else:
                ''' Get the stack frame so we can look for memsomething or frees '''
                self.lgr.debug('DataWatch call getStackTrace from readHap fun 0x%x not in not_mem_something' % fun)
                st = self.top.getStackTraceQuiet(max_frames=20, max_bytes=1000)
                if st is None:
                    self.lgr.debug('DataWatch userSpaceRef stack trace is None, wrong tid?')
                else:
                    self.frames = st.getFrames(20)
                    if index is not None and not self.checkFree(index, op_type):
                        if not self.lookForMemStuff(addr, start, length, trans_size, op_type, eip, fun):
                            self.lgr.debug('dataWatch, not memstuff, do finishRead trans_size %d' % trans_size)
                            self.finishReadHap(op_type, trans_size, eip, addr, length, start, tid, index=index)
                            # TBD already done in lookForMemStuff?
                            #if fun is not None and fun not in self.not_mem_something:
                            #    self.lgr.debug('DataWatch readHap not memsomething add fun 0x%x to not_mem_something' % fun)
                            #    self.not_mem_something.append(fun)
                        else:
                            self.lgr.debug('dataWatch not checkFree and lookForMemStuf')
                    else:
                        #self.lgr.debug('dataWatch was checkFree')
                        pass

    def cheapReuse(self, eip, addr, size, new_value):
        ''' look for quick and dirty signs of buffer reuse '''
        retval = False
        if self.fun_mgr is None:
            self.lgr.error('dataWatch cheapReuse no funMgr')
            return retval
        fun_name = self.fun_mgr.funFromAddr(eip)
        self.lgr.debug('dataWatch cheapReuse is write addr 0x%x eip: 0x%x fun_name %s cycles: 0x%x size %d' % (addr, eip, fun_name, self.cpu.cycles, size))
        index = self.findRangeIndex(addr)
        if index is not None and self.length[index] <= size and new_value == 0:
            self.lgr.debug('dataWatch cheapReuse is write zero of same size as buffer, remove the buffer at index %d' % index)
            self.rmRange(addr) 
            retval = True
        elif index is not None and self.length[index] < size:
            self.lgr.debug('dataWatch cheapReuse is write %d bytes greater than size %d, remove the buffer at index %d' % (size, self.length[index], index))
            self.rmRange(addr) 
        if not retval and self.top.isVxDKM(cpu=self.cpu) and self.so_map.inVxWorks(eip): 
            instruct = self.top.disassembleAddress(self.cpu, eip)
            if instruct[1].startswith('stm'):
                self.lgr.debug('dataWatch cheapReuse is write addr 0x%x in vxWorks with stm... instruct.  Assume we missed a stack buffer' % addr)
                self.rmRange(addr)
                retval = True 
        if not retval and fun_name is not None:
            if self.top.isWindows(target=self.cell_name):
                if fun_name in mem_funs:
                    if self.mem_something is None or self.mem_something.length != 1 or size != 1 or addr != self.mem_something.src:
                        self.lgr.debug('dataWatch cheapReuse mod within memsomething. Remove buffer 0x%x TBD too crude.' % addr)
                        if index is None:
                            addr = addr + size - 1
                            self.lgr.debug('dataWatch cheapReuse index was none, so hack addr to 0x%x assuming write is a few bytes before the buffer.' % addr)
                        self.rmRange(addr)
                        retval = True
                elif 'destructor' in fun_name:
                    self.lgr.debug('dataWatch cheapReuse mod looks like destructor addr 0x%x, TBD roll into other free functions?' % addr)
                    self.rmRange(addr)
                    retval = True
                elif fun_name.startswith('basic_string') and 'Eos' in fun_name:
                    self.lgr.debug('dataWatch cheapReuse mod basic_string Eos, assume done with buffer? %s' % fun_name)
                    self.rmRange(addr)
            else:
                #if fun_name.startswith('std::vector') or fun_name.startswith('allocate_') or fun_name == 'memcpy':
                if fun_name.startswith('std::vector') or fun_name.startswith('allocate_'):
                    self.lgr.debug('dataWatch cheapReuse mod is function %s and we think we missed a free.  Assume reuse' % (fun_name))
                    self.rmRange(addr)
                    retval = True
        if not retval:
            sp = self.mem_utils.getRegValue(self.cpu, 'sp')
            if sp >= addr and sp <= (addr+4):
                instruct = self.top.disassembleAddress(self.cpu, eip)
                if self.fun_mgr is not None and self.fun_mgr.isCall(instruct[1]):
                    self.lgr.debug('cheapReuse, looks like stack push into buffer, assume we missed free.')
                    self.rmRange(addr)
                    retval = True
        if not retval:
            instruct = self.top.disassembleAddress(self.cpu, eip)
            self.lgr.debug('dataWatch cheapReuse, eip 0x%x check arm buf set to zero instruct %s' % (eip, instruct[1]))
            if self.cpu.architecture in ['arm', 'arm64'] and instruct[1].startswith('str'):
                self.lgr.debug('cheapReuse, check arm buf set to zero is str')
                op2, op1 = self.decode.getOperands(instruct[1])
                prev_eip = eip - instruct[0]
                prev_instruct = self.top.disassembleAddress(self.cpu, prev_eip)
                prev_op2, prev_op1 = self.decode.getOperands(prev_instruct[1])
                self.lgr.debug('cheapReuse, check arm buf set to zero prev_op1 %s op1 %s prev_op2 %s' % (prev_op1, op1, prev_op2)) 
                if prev_op1 == op1 and prev_op2 == '#0':
                    self.lgr.debug('cheapReuse, looks like setting buffer values to zero in arm 0x%x %s' % (eip, instruct[1]))
                    self.rmRange(addr)
                    retval = True
         
        if not retval:
            # these cases do not remove a buffer, while those above do.
            if size == 1:
                recent = self.watchMarks.getRecentMark()
                if isinstance(recent.mark, watchMarks.CopyMark) and recent.mark.length == 1:
                    self.lgr.debug('cheapReuse, looks like memcpy of 1 was handled and this is just the write')
                    retval = True
                elif isinstance(recent.mark, watchMarks.DataMark) and recent.mark.ad_hoc:
                    last_copy = recent.mark.dest + recent.mark.loop_count
                    #last_copy = recent.mark.dest + recent.mark.loop_count - 1 
                    self.lgr.debug('cheapReuse, looks maybe like ad hoc copy last_copy src: 0x%x dest: 0x%x len %d last_copy was 0x%x addr: 0x%x cycle: 0x%x' % (recent.mark.addr,
                       recent.mark.dest, recent.mark.length, last_copy, addr, self.cpu.cycles))
                    if addr == last_copy:
                        retval = True
                        self.lgr.debug('cheapReuse, is an ad hoc copy this is just the write')
        self.lgr.debug('cheapReuse returning retval of %r' % retval)
        return retval

    def rmFree(self, fun, index):
        self.lgr.debug('dataWatch rmFree delete hap index %d for %s start[index] 0x%x' % (index, fun, self.start[index]))
        hap = self.read_hap[index]
        self.context_manager.genDeleteHap(hap, immediate=False)
        self.read_hap[index] = None
        self.start[index] = None

    def checkFree(self, index, op_type):
        ''' Look at stack frame to determine if this is a call to a free-type of function '''
        retval = False
        if self.start[index] is None:
            self.debug('dataWatch checkFree called with index %d, but that start is None')
        else:
            max_index = len(self.frames)-1
            for i in range(max_index, -1, -1):
                frame = self.frames[i]
                fun = clibFuns.adjustFunName(frame.fun_name, self.fun_mgr, self.lgr)
                self.lgr.debug('dataWatch checkFree fun is %s op_type %d' % (fun, op_type))
                if fun in free_funs:
                    # avoid killing data buffer containing size to malloc some other buffer
                    # also avoid killing new that reads our data
                    if not (fun == 'new' and op_type == Sim_Trans_Load) and ((fun != 'malloc' and fun != 'new') or op_type != Sim_Trans_Store):
                        self.lgr.debug('dataWatch checkFree fun %s' % fun)
                        self.recordFree(self.start[index], fun)
                        self.rmFree(fun, index)
                        ''' Very ad-hoc an incomplete.  Catch all future destroys and see if they name string object. Cannot reliably rely on data breakpoints?'''
                        if fun == 'destroy':
                            self.lgr.debug('dataWatch checkFree is destroy fun_addr is 0x%x' % frame.fun_addr)
                            if self.destroy_entry is None:
                                self.lgr.debug('first destroy, destroy it.') 
                                self.destroy_entry = frame.fun_addr
                                self.lgr.debug('dataWatch checkFree add destroy entry hap')
                                proc_break = self.context_manager.genBreakpoint(None, Sim_Break_Linear, Sim_Access_Execute, self.destroy_entry, 1, 0)
                                self.destroy_hap = self.context_manager.genHapIndex("Core_Breakpoint_Memop", self.destroyEntry, None, proc_break, 'destroy_entry') 
                                self.destroyEntry(None, None, None, None)
                        retval = True
                        break
        return retval
  

    def lookForMemStuff(self, addr, start, length, trans_size, op_type, eip, fun):
        ''' See if reference is within a memcpy type of function '''
        retval = False
        mem_stuff = None
        # check if we already failed on this memsomething
        if not self.undo_pending:
            # look for memcpy'ish... TBD generalize 
            #if self.top.isVxDKM(target=self.cell_name) and self.so_map.inVxWorks(eip): 
            #    self.lgr.debug('dataWatch lookForMemStuff is in vxworks')
            #    mem_stuff = vxUtils.memsomething(self.top, self.cpu, self.mem_utils, self.task_utils, self.so_map, self.lgr)
            #else:
            #    mem_stuff = self.memsomething(self.frames, mem_funs, op_type=op_type)
            mem_stuff = self.memsomething(self.frames, mem_funs, op_type=op_type)
        else:
            self.lgr.debug('DataWatch lookForMemStuff, skip memsomething, already failed on it')
            self.undo_pending = False
 
        skip_this = False
        if mem_stuff is not None and mem_stuff.fun is not None and mem_stuff.fun.startswith('mempcpy'):
            if mem_stuff.ret_addr is not None:
                so_file = self.top.getSOFile(mem_stuff.ret_addr)
                if so_file is not None and 'libc' in so_file.lower():
                    skip_this = True
                    self.lgr.debug('DataWatch lookForMemstuff skip mempcpy called from libc')
                else:
                    self.lgr.debug('DataWatch lookForMemstuff is mempcpy but not libc')
            else:
                self.lgr.debug('DataWatch lookForMemstuff is mempcpy but no ret addr')
                
        if mem_stuff is not None and mem_stuff.fun is None:
            ''' cause this hit to be skipped while we look for memcpy '''
            retval = True 
        elif mem_stuff is not None and not skip_this:
            if mem_stuff.called_from_ip == self.recent_ghost_call_addr:
                self.lgr.debug('DataWatch lookForMemstuff called_from_ip 0x%x same as previous failed ghost frame, do not try to find stack frame' % (mem_stuff.called_from_ip))
                
            elif (mem_stuff.fun in allocators or mem_stuff.fun in missed_deallocate) and op_type == Sim_Trans_Store:
                self.rmRange(addr)
                self.lgr.debug('DataWatch lookForMemstuff buffer mod in allocator or missed deallocate, assume we missed a free and remove it 0x%x' % addr)
                retval = True
            else:
                if mem_stuff.ret_addr is not None and mem_stuff.called_from_ip is not None:
                    self.lgr.debug('DataWatch lookForMemstuff ret_ip 0x%x called_from_ip is 0x%x' % (mem_stuff.ret_addr, mem_stuff.called_from_ip))
                else:
                    self.lgr.debug('DataWatch lookForMemstuff ret_ip  or called_from_ip no ret_addr found')
                ''' referenced memory address is src/dest depending on op_type''' 
                dest = None
                src = addr
                if op_type != Sim_Trans_Load:
                    src = None
                    dest = addr
                self.mem_something = MemSomething(mem_stuff.fun, mem_stuff.fun_addr, addr, mem_stuff.ret_addr, src, dest, 
                      mem_stuff.called_from_ip, op_type, length, start, ret_addr_addr = mem_stuff.ret_addr_addr, trans_size=trans_size,
                      frames=mem_stuff.frames)
                if mem_stuff.fun in reg_return_funs:
                    self.lgr.debug('DataWatch lookForMemstuff is reg_return_fun %s addr 0x%x' % (mem_stuff.fun, addr))
                else:
                    SIM_run_alone(self.handleMemStuff, op_type)
                retval = True
        else:
            #self.lgr.debug('DataWatch lookForMemstuff not memsomething, reset the watch ')
            #self.watch()
            if fun is not None and fun not in self.not_mem_something:
                fun_name = self.fun_mgr.funFromAddr(fun)
                if not self.so_map.isLibc(eip):
                    if fun_name not in mem_funs: 
                        self.lgr.debug('DataWatch lookForMemstuff not memsomething add fun 0x%x to not_mem_something fun_name %s' % (fun, fun_name))
                        self.not_mem_something.append(fun)
                    else:
                        self.lgr.debug('DataWatch lookForMemstuff fun 0x%x is in local funs %s' % (fun, fun_name))
                else:
                    self.lgr.debug('DataWatch lookForMemstuff not memsomething fun 0x%x eip 0x%x is clib %s' % (fun, eip, fun_name))
            pass
        return retval
       
    def showWatch(self):
        for index in range(len(self.start)):
            if self.start[index] is not None:
                print('%d start: 0x%x  length: 0x%x' % (index, self.start[index], self.length[index]))

    def setOneBreak(self, index, replace=False):
        # Use physical address for break.  TBD exceptions to this?
        #if index == 52:
        #    self.lgr.debug('setOneBreak NOW CALL v2p')
        #self.lgr.debug('setOneBreak index %d' % index)
        if self.length[index] == 0:
            self.lgr.error('dataWatch setOneBreak length for index %d is zero?  bail start of that index is 0x%x' % (index, self.start[index]))
            return
        self.lgr.debug('dataWatch setOneBreak index %d  force_cr3 to 0x%x' % (index, self.range_cr3[index]))
        phys = self.mem_utils.v2p(self.cpu, self.start[index], force_cr3=self.range_cr3[index], do_log=False)
        #phys_block = self.cpu.iface.processor_info.logical_to_physical(self.start[index], Sim_Access_Read)
        #if index == 52:
        #    self.lgr.debug('setOneBreak index self.start[%d] = 0x%x phys: 0x%x cr3 0x%x' % (index, self.start[index], phys, self.range_cr3[index]))
        if phys is not None and phys != 0:
            # TBD presupposes buffers are in contiguous pages
            break_num = self.context_manager.genBreakpoint(self.cpu.physical_memory, Sim_Break_Physical, Sim_Access_Read | Sim_Access_Write, phys, self.length[index], 0)
            if index in self.linear_breaks:
                self.lgr.debug('dataWatch setOneBreak remove linear break index %d' % index)
                self.linear_breaks.remove(index)
            # update this, it may be shuffled
            self.phys_start[index] = phys
        else:
            self.lgr.debug('dataWatch setOneBreak no phys addr for 0x%x, use linear index is %d' % (self.start[index], index))
            break_num = self.context_manager.genBreakpoint(None, Sim_Break_Linear, Sim_Access_Read | Sim_Access_Write, self.start[index], self.length[index], 0)
            if index not in self.linear_breaks:
                self.linear_breaks.append(index)
        end = self.start[index] + (self.length[index] - 1)
        eip = self.top.getEIP(self.cpu)
        hap = self.context_manager.genHapIndex("Core_Breakpoint_Memop", self.readHap, index, break_num, 'dataWatch')
        if phys is not None and phys != 0:
            self.lgr.debug('DataWatch setOneBreak eip: 0x%x Adding breakpoint %d for 0x%x-%x length 0x%x (physical 0x%x, cr3: 0x%x) hap: %d index now %d number of read_haps was %d  cpu context:%s cycles: 0x%x' % (eip, 
                break_num, self.start[index], end, self.length[index], phys, self.range_cr3[index], hap, index, len(self.read_hap), self.cpu.current_context, self.cpu.cycles))
        else:
            self.lgr.debug('DataWatch setOneBreak eip: 0x%x Adding breakpoint %d for 0x%x-%x length 0x%x NO PHYS hap: %d index now %d number of read_haps was %d   cpu context:%s' % (eip, 
                break_num, self.start[index], end, self.length[index], hap, index, len(self.read_hap), self.cpu.current_context))
        if not replace:
            self.read_hap.append(hap)
        else:
            self.read_hap[index] = hap
 
    def setBreakRange(self, i_am_alone=False):
        # TBD i_am_alone only for diagnostics
        #self.lgr.debug('dataWatch setBreakRange len of start is %d' % len(self.start))
        ''' Set breakpoints for each range defined in self.start and self.length 
            These are lists, as is self.read_hap.  Elements are never removed from
            the list, they are set to None when the range is removed.
        '''
        '''
        context = self.context_manager.getRESimContext()
        num_existing_haps = len(self.read_hap)
        self.lgr.debug('DataWatch setBreakRange num_existing_haps %d, len of self.start %d' % (num_existing_haps, len(self.start)))
        for index in range(num_existing_haps, len(self.start)):
            if self.start[index] is None:
                #self.lgr.debug('DataWatch setBreakRange index %d is 0' % index)
                self.read_hap.append(None)
                continue
                #TBD should this be a physical bp?  Why explicit RESim context -- perhaps debugging_tid is not set while
                #fussing with memsomething parameters? 
            self.setOneBreak(index)
        '''
        for index in range(len(self.start)):
            if self.start[index] is not None:
                if index < len(self.read_hap):
                    if self.read_hap[index] is None:
                        #self.lgr.debug('remove this index %d of do replace and setOneBreak' % index)
                        self.setOneBreak(index, replace=True)
                    #else:
                    #    self.lgr.debug('remove this index %d of readhap is none' % index)
                elif index == len(self.read_hap):
                    #self.lgr.debug('remove this index %d of do append and setOneBreak' % index)
                    self.setOneBreak(index, replace=False)
                else:
                    self.lgr.error('dataWatch setBreakRange start index, hap index mismatch')
            elif index >= len(self.read_hap):
                self.read_hap.append(None)
                self.lgr.debug('dataWatch setBreakRange this start[%d] is none, but len of readhap is %d, add a none to read_hap' % (index, len(self.read_hap)))
            
        if len(self.start) != len(self.read_hap):
            self.lgr.error('dataWatch setBreakRange start len is %d while read_hap is %d' % (len(self.start), len(self.read_hap)))

        #if self.backstop is not None and not self.break_simulation and self.use_backstop:
        #    #self.lgr.debug('dataWatch, setBreakRange call to setFutureCycle')
        #    self.backstop.setFutureCycle(self.backstop_cycles, now=i_am_alone)

    def stopHap(self, stop_action, one, exception, error_string):
        if stop_action is None or stop_action.hap_clean is None:
            self.lgr.error('dataWatch stopHap error, stop_action None?')
            return
        eip = self.top.getEIP(self.cpu)
        self.lgr.debug('dataWatch stopHap eip 0x%x cycle: 0x%x' % (eip, stop_action.hap_clean.cpu.cycles))

        if self.stop_hap is not None:
            self.lgr.debug('dataWatch stopHap will delete hap %s' % str(self.stop_hap))
            hap = self.stop_hap
            self.top.RES_delete_stop_hap_run_alone(hap)
            self.stop_hap = None
            ''' check functions in list '''
            self.lgr.debug('stopHap now run actions %s' % str(stop_action.flist))
            stop_action.run()

    def delStopHap(self, hap):
        self.lgr.debug('dataWatch delStopHap delete hap %d' % hap)
        self.top.RES_delete_stop_hap(hap)
         
    def setStopHap(self, dumb):
        f1 = stopFunction.StopFunction(self.top.skipAndMail, [], nest=False)
        flist = [f1]
        hap_clean = hapCleaner.HapCleaner(self.cpu)
        stop_action = hapCleaner.StopAction(hap_clean, flist=flist)
        self.stop_hap = self.top.RES_add_stop_callback(self.stopHap, stop_action)
        self.lgr.debug('dataWatch setStopHap set actions %s' % str(stop_action.flist))

    def setShow(self):
        self.show_cmp = ~ self.show_cmp
        return self.show_cmp

    def rmSubRange(self, addr, trans_size):
        ''' remove a subrange within a buffer '''
        buf_start, buf_length, index = self.findBufForRange(addr, trans_size)
        if index is not None:
            if index != self.recent_reused_index:
                start = self.start[index]
                length = self.length[index]
                end = start + length - 1
                ''' try to catch ad-hoc buffer deletion based on multiple writes in a row '''
                force_reuse = False
                if start == addr and end == addr+trans_size-1:
                    force_reuse = True 
                elif start == addr:
                    self.hack_reuse_index = index
                    self.hack_reuse = []
                    self.hack_reuse.append(addr)
                    self.lgr.debug('dataWatch rmSubRange start == addr, use hack_reuse')
                elif index == self.hack_reuse_index:
                    if addr not in self.hack_reuse:
                        self.hack_reuse.append(addr)
                        if (len(self.hack_reuse) * self.mem_utils.wordSize(self.cpu)) >= length:
                            force_reuse = True
                            self.lgr.debug('dataWatch rmSubRange force reuse')
              
                #if force_reuse or (start >= addr and end <= (addr+trans_size)):
                if force_reuse or (start <= addr and end >= (addr+trans_size)) or (start > addr and (addr+trans_size) >= end):
                    self.lgr.debug('dataWatch rmSubRange, IS overlap (or force_reuse) start 0x%x end 0x%x  addr 0x%x trans_size 0x%x' % (start, end, addr, trans_size))
                    new_start = None
                    self.lgr.debug('dataWatch rmSubRange, addr: 0x%x start 0x%x length: %d end 0x%x' % (addr, start, length, end))
                    self.lgr.debug('dataWatch rmSubRange start[%d] (0x%x length %x) set to None' % (index, self.start[index], self.length[index]))
                    self.start[index] = None
                    if index < len(self.read_hap) and self.read_hap[index] is not None:
                        self.lgr.debug('dataWatch rmSubRange removing read_hap[%d] %d' % (index, self.read_hap[index]))
                        hap = self.read_hap[index]
                        self.context_manager.genDeleteHap(hap, immediate=False)
                        self.read_hap[index] = None
                    if start < addr:
                        newlen = addr - start 
                        if newlen > 0:
                            self.lgr.debug('dataWatch rmSubRange adding new range start 0x%x len %x' % (start, newlen))
                            self.setRange(start, newlen, no_extend=True)
                        new_start = addr + trans_size
                    elif start == addr and trans_size < length:
                        new_start = addr+trans_size
                    if new_start is not None:
                        self.lgr.debug('dataWatch rmSubrange new_start 0x%x end 0x%x' % (new_start, end)) 
                    if new_start is not None and new_start < end:
                        newlen = end - new_start + 1
                        if newlen > 0:
                            self.lgr.debug('dataWatch rmSubRange adding range for new start 0x%x new len %x' % (new_start, newlen))
                            self.setRange(new_start, newlen, no_extend=True)
                    # redo data watch breaks
                    self.stopWatch()
                    self.watch()
                else:
                    self.lgr.debug('dataWatch subRange, do not remove, no overlap, start 0x%x end 0x%x  addr 0x%x trans_size 0x%x' % (start, end, addr, trans_size))
                    pass
            else:
                self.lgr.debug('dataWatch rmSubRange found index %d was recent reused index, do not delete subrange.' % index)
        else:
            self.lgr.debug('dataWatch rmSubRange no index for addr 0x%x' % addr)

    def rmRange(self, addr):
        index = self.findRangeIndex(addr)
        if index is not None:
            self.lgr.debug('dataWatch rmRange addr 0x%x index %d ' % (addr, index))
            self.start[index] = None
            if index < len(self.read_hap) and self.read_hap[index] is not None:
                self.lgr.debug('dataWatch rmRange addr 0x%x index %d len of read_hap %d call genDeleteHap' % (addr, index, len(self.read_hap)))
                hap = self.read_hap[index]
                self.context_manager.genDeleteHap(hap, immediate=False)
                self.read_hap[index] = None
            else:
                if index >= len(self.read_hap):
                    self.lgr.debug('dataWatch rmRange addr 0x%x index %d NOT IN RANGE of read_hap (has %d haps)' % (addr, index, len(self.read_hap)))
                else:
                    self.lgr.debug('dataWatch rmRange addr 0x%x read_hap[%d] is None?  (has %d haps)' % (addr, index, len(self.read_hap)))
                    

    def findRange(self, addr):
        retval = None
        self.lgr.debug('findRange addr 0x%x' % addr)
        if addr is None:
            self.lgr.error('dataWatch findRange called with addr of None')
            raise Exception('addr is none')
        else:
            # first see if it is an original buffer
            recv_addr, length, read_count = self.watchMarks.origBuffer(addr)
            if recv_addr is not None:
                retval = recv_addr
                self.lgr.debug('findRange addr 0x%x found in call buffer # %d, addr 0x%x' % (addr, read_count, recv_addr))
            else:
                for index in reversed(range(len(self.start))):
                    if self.start[index] is not None:
                        end = self.start[index] + self.length[index] - 1
                        #self.lgr.debug('findRange is 0x%x between 0x%x and 0x%x?' % (addr, self.start[index], end))
                        if addr >= self.start[index] and addr <= end:
                            retval = self.start[index]
                            break
        return retval

    def findRangeIndex(self, addr):
        for index in reversed(range(len(self.start))):
            if self.start[index] is not None:
                end = self.start[index] + (self.length[index]-1)
                #self.lgr.debug('findRange is 0x%x between 0x%x and 0x%x?' % (addr, self.start[index], end))
                if addr is not None and addr >= self.start[index] and addr <= end:
                    return index
        return None

    def findRangeIndexPhys(self, addr):
        for index in reversed(range(len(self.start))):
            if self.start[index] is not None:
                end = self.phys_start[index] + (self.length[index]-1)
                #self.lgr.debug('findRange is 0x%x between 0x%x and 0x%x?' % (addr, self.start[index], end))
                if addr is not None and addr >= self.phys_start[index] and addr <= end:
                    return index
        return None

    def inRange(self, addr, start, end):
        if addr >= start and addr <= end:
            return True
        else:
            return False

    def getIntersect(self, start1, length1, start2, length2):
        ''' get the intersection (overlap) of two ranges '''
        ret_start = None
        ret_length = None
        end1 = start1 + length1 - 1
        end2 = start2 + length2 - 1
        if self.inRange(start1, start2, end2):
            ret_start = start1
            ret_end = min(end1, end2)
            ret_length = ret_end - ret_start + 1
        elif self.inRange(start2, start1, end1):
            ret_start = start2
            ret_end = min(end1, end2)
            ret_length = ret_end - ret_start + 1
        else:
            self.lgr.debug('dataWatch getIntersect no overlap in start1 0x%x length1 %d start2 0x%x length2 %d' % (start1, length1, start2, length2))
            pass
 
        return ret_start, ret_length
            
    def findBufForRange(self, addr, length):
        '''
        Given a buffer address and length (e.g., the address and count from a memcpy call), find a data watch and return the lowest address
        of the watch buffer that is within the input buffer, and the number of bytes within
        the watch buffer that are within the input buffer.
        '''
        ret_start = None
        ret_length = None
        ret_index = None
        if addr is not None:
            range_end = addr + length - 1

            recv_addr, recv_length, read_count = self.watchMarks.origBuffer(addr)
            if recv_addr is not None:
                #TBD what if given length outside of call buffer?
                ret_start = recv_addr
                ret_length = recv_length
                ret_start, ret_length = self.getIntersect(addr, length, recv_addr, recv_length)
                ret_index = self.findRangeIndex(addr)
                self.lgr.debug('dataWatch findBufForRange found 0x%x in orig 0x%x' % (addr, ret_start))
                if ret_length is None:
                    self.lgr.debug('dataWatch findbufForRange ret_length None for addr 0x%x' % addr)
            else:
                self.lgr.debug('findBuffForRange 0x%x not in orig' % addr)
                for index in reversed(range(len(self.start))):
                    if self.start[index] is not None:
                        ret_start, ret_length = self.getIntersect(addr, length, self.start[index], self.length[index])
                        if ret_start is not None:
                            #self.lgr.debug('dataWatch findBufForRange found 0x%x len 0x%x in intersect 0x%x len 0x%x' % (addr, length, self.start[index], self.length[index]))
                            ret_index = index
                            break            
        return ret_start, ret_length, ret_index

    def showRange(self, addr):
        index = self.findRangeIndex(addr)
        if index is not None:
            print('Address 0x%x in buffer starting at 0x%x, length %d' % (addr, self.start[index], self.length[index]))
        else:
            print('Address 0x%x not in any buffer.' % addr)

    def getWatchMarks(self):
        origin = self.top.getFirstCycle()
        return self.watchMarks.getWatchMarks(origin=origin)

    def goToMark(self, index):
        self.lgr.debug('dataWatch goToMark index %d' % index)
        retval = None
        cycle = self.watchMarks.getCycle(index)

        #self.lgr.debug('dataWatch goToMark cycle would be 0x%x' % cycle)
        #return
        if cycle is not None:
            self.top.skipToCycle(cycle, cpu=self.cpu, disable=True)
            retval = cycle
            if cycle != self.cpu.cycles:
                self.lgr.error('dataWatch goToMark got wrong cycle, asked for 0x%x got 0x%x' % (cycle, self.cpu.cycles))
                retval = None
            else:
                self.lgr.debug('dataWatch goToMark cycle now 0x%x' % cycle)
            eip = self.top.getEIP(self.cpu)
            mark_ip = self.watchMarks.getIP(index)
            if eip != mark_ip:
                self.lgr.warning('dataWatch goToMark index %d eip 0x%x does not match mark ip 0x%x mark cycle: 0x%x' % (index, eip, mark_ip, cycle))
                self.reverse_mgr.revOne()
                eip = self.top.getEIP(self.cpu)
                if eip != mark_ip:
                    self.top.skipToCycle(cycle, cpu=self.cpu, disable=True)
                    eip = self.top.getEIP(self.cpu)
                if eip != mark_ip:
                    self.lgr.error('dataWatch goToMark index %d eip 0x%x does not match mark ip 0x%x mark cycle: 0x%x Second attempt' % (index, eip, mark_ip, cycle))
                    retval = None
            else:
                if self.watchMarks.isCall(index):
                    cycle = self.cpu.cycles+1
                    if not self.top.skipToCycle(cycle, cpu=self.cpu, disable=True):
                        self.lgr.error('dataWatch goToMark got wrong cycle after adjust for call, asked for 0x%x got 0x%x' % (cycle, self.cpu.cycles))
                        retval = None
                    else:
                        self.lgr.debug('dataWatch goToMark adjusted for call cycle now 0x%x' % cycle)
                        if index == 1:
                            # TBD obscure special case needs explaination
                            call_ret_val = self.mem_utils.getRegValue(self.cpu, 'syscall_ret')
                            mark = self.watchMarks.getMarkFromIndex(index)
                            if mark.mark.len is not None and call_ret_val != mark.mark.len:
                                self.lgr.debug('dataWatch goToMark length %d does not match syscall_ret of %d' % (mark.mark.len, call_ret_val))
                                self.mem_utils.setRegValue(self.cpu, 'syscall_ret', call_ret_val)
                else:
                    self.lgr.debug('dataWatch goToMark index %d NOT a call' % index)
            self.context_manager.restoreWatchTasks()
        else:
           self.lgr.error('No data mark with index %d' % index)
        return retval

    def clearWatchMarks(self, record_old=False): 
        self.watchMarks.clearWatchMarks(record_old=record_old)


    def clearWatches(self, cycle=None, immediate=False, leave_backstop=False):
        self.lgr.debug('dataWatch clearWatches')
        if cycle is None:
            self.lgr.debug('DataWatch clearWatches, no cycle given')
            self.prev_cycle = None
            self.prev_index = None
        else:
            self.lgr.debug('DataWatch clearWatches cycle 0x%x' % cycle)
        self.stopWatch(immediate=immediate, leave_backstop=leave_backstop)
        self.lgr.debug('DataWatch clearWatches set break_simulation False')
        # TBD ??
        self.break_simulation = False
        #self.break_simulation = True
        self.stack_buffers = {}
        self.total_read = 0
        self.last_ad_hoc = []
        for eip in self.stack_buf_hap:
            self.lgr.debug('DataWatch clearWatches remove stack_buf_hap[0x%x] %d' % (eip, self.stack_buf_hap[eip]))
            self.context_manager.genDeleteHap(self.stack_buf_hap[eip], immediate=immediate)
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
                if self.start[index] is not None:
                    self.lgr.debug('clearWatches, before list reset start[%d] is 0x%x, len %d' % (index, self.start[index], self.length[index]))
                del self.start[index+1:]
                del self.length[index+1:]
                del self.hack_reuse[index+1:]
                del self.cycle[index+1:]
                if self.start[index] is not None:
                    self.lgr.debug('clearWatches, reset list, index %d start[%d] is 0x%x, len %d' % (index, index, self.start[index], self.length[index]))
                else:
                    self.lgr.debug('clearWatches, reset list, index %d start[%d] is NONE' % (index, index))


    def resetOrigin(self, cycle, reuse_msg=False, record_old=False):
        ''' remove all data watches and rebuild based on watchmarks earlier than given cycle '''
        if len(self.start) == 0:
            return
        # Returns false if directed to not reset the origin
        if self.no_reset:
            self.lgr.debug('dataWatch resetOrigin, but no_reset set.  Stop simulation')
            SIM_break_simulation('no reset')
            return False
        data_watch_list = self.watchMarks.getDataWatchList()
        origin_watches = []
        if len(self.cycle) > 0 and cycle <= self.cycle[-1]:
            del self.start[:]
            del self.length[:]
            del self.hack_reuse[:]
            del self.cycle[:]
            self.other_starts = []
            self.other_lengths = []
            for data_watch in data_watch_list:
                if data_watch['cycle'] <= cycle:
                    if data_watch['start'] is not None:
                        self.setRange(data_watch['start'], data_watch['length']) 
                        origin_watches.append(data_watch)
                    else:
                        self.lgr.debug('dataWatch resetOrigin  watch has no start %s' % str(data_watch))
                else:
                    self.lgr.debug('dataWatch resetOrigin clearWatches found cycle 0x%x > given 0x%x, stop rebuild' % (data_watch['cycle'], cycle))
                    break
            self.lgr.debug('dataWatch resetOrigin cleared and rebuilt data watches now call watchmarks')
        else:
            self.lgr.debug('dataWatch resetOrigin current cycle greater than last recorded, do not reset data watches')
            for data_watch in data_watch_list:
                if data_watch['start'] is not None:
                    origin_watches.append(data_watch)
        self.watchMarks.resetOrigin(origin_watches, reuse_msg=reuse_msg, record_old=record_old)
        return True

    def setFunMgr(self, fun_mgr):
        self.lgr.debug('DataWatch setFunMgr')
        self.fun_mgr = fun_mgr
        self.initRingChar()
        if 'FUNCTION_NO_WATCH' in self.comp_dict:
            def_file = self.comp_dict['FUNCTION_NO_WATCH']
            self.function_no_watch = functionNoWatch.FunctionNoWatch(self.top, self, self.cpu, def_file, self.cell_name, self.mem_utils, self.context_manager, self.so_map, self.lgr)
            self.lgr.debug('dataWatch setFunMgr set functin_no_watch for %s' % def_file)

    def setCallback(self, callback):
        ''' what should backStop call when no activity for N cycles?  Or if max marks exceeded'''
        self.lgr.debug('dataWatch setCallback, call to backstop to set callback %s' % str(callback))
        self.backstop.setCallback(callback)
        # use if max marks exceeded
        if self.callback is None:
            self.callback = callback

    def setMaxMarksCallback(self, callback):
        self.lgr.debug('dataWatch setMaxMarksCallback to %s' % str(callback))
        self.callback = callback

    def showWatchMarks(self, old=False, verbose=False):
        self.watchMarks.showMarks(old=old, verbose=verbose)

    def saveWatchMarks(self, fpath):
        self.watchMarks.saveMarks(fpath)

    def tagIterator(self, index):
        ''' Call from IDA Client to collapse a range of data references into the given watch mark index ''' 
        self.lgr.debug('DataWatch tagIterator index %d' % index)
        if self.fun_mgr is not None:
            watch_mark = self.watchMarks.getMarkFromIndex(index)
            if watch_mark is not None:
                fun = self.fun_mgr.getFun(watch_mark.ip)
                if fun is None:
                    self.lgr.error('DataWatch tagIterator failed to get function for 0x%x' % ip)
                else:
                    self.lgr.debug('DataWatch add iterator for function 0x%x from watch_mark IP of 0x%x' % (fun, watch_mark.ip))
                    self.fun_mgr.addIterator(fun)
            else:
                self.lgr.error('failed to get watch mark for index %d' % index)
        else:
            self.lgr.error('dataWatch tagIterator called but no IDA functions defined yet.  Debugging?')


    def wouldBreakSimulation(self):
        if self.break_simulation:
            return True
        return False

    def rmBackStop(self):
        self.use_backstop = False

    def setRetrack(self, value, use_backstop=True):
        self.lgr.debug('DataWatch setRetrack %r' % value)
        self.retrack = value
        if value and use_backstop:
            self.use_backstop = True

    def fileStopHap(self):
        self.lgr.debug('fileStopHap')
        #if not self.skipToTest(self.cpu.cycles+1):
        #        self.lgr.error('fileStopHap unable to skip to next cycle got 0x%x' % (self.cpu.cycles))
        #        return
        st = self.top.getStackTraceQuiet(max_frames=16, max_bytes=100)
        my_mem_funs = ['xmlParseFile']
        if st is None:
            self.lgr.debug('stack trace is None, wrong tid?')
            return
        ''' look for memcpy'ish... TBD generalize '''
        frames = st.getFrames(20)
        mem_stuff = self.memsomething(frames, my_mem_funs)
        if mem_stuff is not None:
            self.lgr.debug('mem_stuff function %s, ret_ip is 0x%x' % (mem_stuff.fun, mem_stuff.ret_addr))
            self.mem_something = MemSomething(mem_stuff.fun, mem_stuff.fun_addr, None, mem_stuff.ret_addr, None, None, 
                mem_stuff.called_from_ip, None, None, None, run=True)
            self.break_simulation=False
            self.me_trace_malloc = True
            self.top.traceMalloc()
            SIM_run_alone(self.runToReturnAndGo, False)
        else:
            self.lgr.debug('Failed to get memsomething from stack frames')

    def setFileStopHap(self, dumb):
        f1 = stopFunction.StopFunction(self.fileStopHap, [], nest=False)
        flist = [f1]
        hap_clean = hapCleaner.HapCleaner(self.cpu)
        stop_action = hapCleaner.StopAction(hap_clean, flist=flist)
        self.stop_hap = self.top.RES_add_stop_callback(self.stopHap, stop_action)
        self.lgr.debug('setFileStopHap set actions %s' % str(stop_action.flist))

    def trackFile(self, callback, compat32):
        self.lgr.debug('DataWatch trackFile call watch')
        self.setFileStopHap(None)
        ''' what to do when backstop is reached (N cycles with no activity '''
        self.setCallback(callback)


    def trackIO(self, fd, callback, compat32, max_marks, quiet=False, offset = None, length = None, backstop_cycles=None):
        self.lgr.debug('DataWatch trackIO for fd %d' % fd)
        self.buffer_offset = offset
        self.buffer_length = length
        ''' first make sure we are not in the kernel on this FD '''
        # NO, would reverse to state that may not be properly initialized.
        # Do not assume that call to receive implies the system is ready
        # to receive.
        #self.rev_to_call.preCallFD(fd) 
        if max_marks is not None:
            self.max_marks = max_marks
            self.lgr.debug('DataWatch trackIO watch max_marks set to %s' % self.max_marks)
        elif self.max_marks is None:
            self.max_marks = 2000
            self.lgr.debug('DataWatch trackIO NO watch max_marks given.  Use default set to %s' % max_marks)
        if backstop_cycles is not None and backstop_cycles != 0:
            self.backstop_cycles = backstop_cycles
            self.lgr.debug('DataWatch trackIO backstop_cycles set to %d' % self.backstop_cycles)
            self.backstop.setFutureCycle(self.backstop_cycles)
        self.watch(break_simulation=False)
        ''' what to do when backstop is reached (N cycles with no activity '''
        self.setCallback(callback)
        self.enable()
        report_backstop = not quiet
        self.backstop.reportBackstop(report_backstop)
        fun_mgr = self.top.getFunMgr()
        self.readLib.trackReadLib(fun_mgr)

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

    def recordFree(self, addr, fun=None):
        if self.me_trace_malloc:
            if addr not in self.malloc_dict:
                self.lgr.debug('Freed value not in malloc db: 0x%x' % addr)
            else:
                del self.malloc_dict[addr]
        else:
            if fun is None:
                fun = 'free'
            self.watchMarks.free(addr, fun)
            for this in self.string_this:
                if self.string_this[this] == addr:
                    r0 = self.mem_utils.getRegValue(self.cpu, 'syscall_ret')
                    self.lgr.debug('dataWatch recordFree 0x%x in string this as 0x%x, r0 is 0x%x' % (addr, this, r0)) 

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
                    new_end = last_addr + size - 1
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

    def funPrecidence(self, fun):
        fun_precidence = mem_funs.index(fun)
        if fun_precidence < mem_funs.index('LOWEST'):
            fun_precidence = 0 
        return fun_precidence

    def findMemcpy(self, frames, index):
        retval = False
        if index == 1:
            return retval
        max_index = index - 1
        for i in range(max_index, -1, -1):
            frame = frames[i]
            self.lgr.debug('dataWatch findMemcpy fun is %s' % frame.fun_name)
            if 'memcpy' in frame.fun_name:
                retval = True
                break
        return retval

    def checkFramesAbove(self, frames, index):
        ''' Do the frames above the index make sense if the index is a memsomething? 
            If not, return the index of what fails to make sense.
        '''
        retval = None
        if index == 1:
            return retval
        max_index = index - 1
        index_so = self.top.getSOFile(frames[index].ip)
        if os.path.basename(index_so) == os.path.basename(self.top.getFullPath()):
            is_static = True
        else:
            is_static = False
        for i in range(max_index, -1, -1):
            frame = frames[i]
            if self.fun_mgr is not None:
                fun_addr = self.fun_mgr.getFun(frame.ip)
                if fun_addr is not None:
                    fun_of_ip = self.fun_mgr.getName(fun_addr)
                    so_file = self.top.getSOFile(fun_addr)
                    if fun_of_ip == 'main':
                        self.lgr.debug('dataWatch checkFrames above, found main fun_of_ip: %s  so_file: %s' % (fun_of_ip, so_file))
                        retval = i
                        break
                    elif not is_static and so_file is not None:
                        if os.path.basename(so_file) == os.path.basename(self.top.getFullPath()):
                            self.lgr.debug('dataWatch checkFrames above, found so file %s is our program, return false' % so_file)
                            retval = i
                            break
                       
        return retval
                  
    def memsomething(self, frames, local_mem_funs, op_type=None):
        ''' Is there a call to a memcpy'ish function, or a user iterator, in the last few frames? If so, return the return address '''
        ''' Will iterate through the frames backwards, looking for the highest level function.
            Returns data of class MemStuff'''
        retval = None
        max_precidence = -1
        max_index = len(frames)-1
        self.lgr.debug('memsomething begin, max_index %d op_type %s' % (max_index, str(op_type)))
        outer_index = None
        prev_fun = None
        #for i in range(max_index, -1, -1):
        # do not want to be in the memsomething function
        for i in range(max_index, 0, -1):
            frame = frames[i]
            if frame.fun_addr is None and self.fun_mgr is not None:
                self.lgr.debug('dataWatch memsomething frame %d fun_addr is None' % i)
                frame.fun_addr = self.fun_mgr.getFun(frame.ip)
            #if frame.fun_addr is None:
            #    self.lgr.debug('dataWatch memsomething frame %d ip: 0x%x fun_addr NONE instruct is %s' % (i, frame.ip, frame.instruct))
            #    pass
            #else:
            #    self.lgr.debug('dataWatch memsomething frame %d ip: 0x%x fun_addr 0x%x instruct is %s' % (i, frame.ip, frame.fun_addr, frame.instruct))
            #    pass
            #self.lgr.debug('dataWatch memsomething frame fname: %s' % frame.fname)
            if frame.instruct is not None:
                #self.lgr.debug('dataWatch memsomething before adjust, fun is %s' % frame.fun_name)
                #if self.top.isWindows():
                #    fun = None
                #else:
                fun = clibFuns.adjustFunName(frame.fun_name, self.fun_mgr, self.lgr)
                if fun is not None:
                    if fun not in local_mem_funs and fun.startswith('v'):
                        fun = fun[1:]
                    #if frame.fun_addr is not None:
                    #    self.lgr.debug('dataWatch memsomething frame %d fun is %s fun_addr: 0x%x ip: 0x%x sp: 0x%x' % (i, fun, frame.fun_addr, frame.ip, frame.sp))
                    #else:
                    #    self.lgr.debug('dataWatch memsomething frame %d fun is %s fun_addr None(maybe got jmp) ip: 0x%x sp: 0x%x' % (i, fun, frame.ip, frame.sp))
                elif frame.fun_addr is not None:
                    if frame.ip is not None and frame.sp is not None:
                        self.lgr.debug('dataWatch memsomething frame %d fun is None fun_addr: 0x%x ip: 0x%x sp: 0x%x' % (i, frame.fun_addr, frame.ip, frame.sp))
                    else:
                        self.lgr.debug('dataWatch memsomething frame %d fun is None ip or sp is none' % i)
                        continue
                else:
                    self.lgr.debug('dataWatch memsomething frame %d fun is None fun_addr is none' % i)
                    continue
                if fun is not None and fun == prev_fun and fun != 'None':
                    #self.lgr.debug('dataWatch memsomething repeated fun is %s  -- skip it' % fun)
                    continue
                else:
                    #self.lgr.debug('dataWatch memsomething set prev_fun to %s' % fun)
                    prev_fun = fun
                if op_type == Sim_Trans_Store and fun in allocators:
                    # TBD generalize this mess
                    self.lgr.debug('dataWatch memsomething is allocator %s' % fun)
                    retval = MemStuff(0, fun, 0, 0, 0)

                elif fun in local_mem_funs or self.fun_mgr.isIterator(frame.fun_addr):
                    if fun in local_mem_funs:
                        fun_precidence = self.funPrecidence(fun)
                        self.lgr.debug('dataWatch memsomething fun in local_mem_funs %s, set fun_precidence to %d' % (fun, fun_precidence))
                        # TBD tune this, maybe by clib?  sscanf is at level 4 sometimes.
                        if fun_precidence == 0 and i > 4:
                            ''' Is it some clib calling some other clib?  ghosts?'''
                            start = i - 1
                            if clibFuns.allClib(frames, start):
                                self.lgr.debug('dataWatch memsomething i is %d and precidence %d, bailing' % (i, fun_precidence))
                                continue
                    if self.fun_mgr.isIterator(frame.fun_addr):
                        #self.lgr.debug('fun is iterator 0x%x' % frame.fun_addr) 
                        fun_precidence = 999
                    #self.lgr.debug('dataWatch memsomething frame index %d, is %s, frame: %s' % (i, fun, frame.dumpString()))
                    if fun_precidence < max_precidence:
                        self.lgr.debug('dataWatch memsomething precidence %d less than current max %d, skip it' % (fun_precidence, max_precidence))
                        continue
                    max_precidence = fun_precidence
                    if frame.ret_addr is not None:
                        ret_addr = frame.ret_addr
                    elif frame.sp > 0 and i != 0:
                        ''' TBD poor assumption about sp pointing to the return address?  have we made this so, arm exceptions? '''
                        dum_cpu, comm, tid = self.task_utils.curThread()
                        word_size = self.top.wordSize(tid, target=self.cell_name)
                        ret_addr = self.mem_utils.readAppPtr(self.cpu, frame.sp, size=word_size)
                        self.lgr.debug('dataWatch memsomething assumption about sp being ret addr? set to 0x%x' % ret_addr)
                    else:
                        self.lgr.error('memsomething sp is zero and no ret_addr?')
                        ret_addr = None
                    if ret_addr is not None:
                        self.lgr.debug('dataWatch memsomething ret_addr 0x%x frame.ip is 0x%x' % (ret_addr, frame.ip))
                        ''' Make sure there is not a main or similar above this frame.  TBD make standard in stack module? '''
                        bad_index = self.checkFramesAbove(frames, i)
                        if bad_index is None:

                            if frame.lr_return:
                                addr_of_ret_addr = None
                            elif frame.ret_to_addr is not None:
                                addr_of_ret_addr = frame.ret_to_addr
                                self.lgr.debug('datawatch memsomething using ret_to_addr from frame of 0x%x' % frame.ret_to_addr)
                            else:
                                addr_of_ret_addr = frame.sp
                                self.lgr.debug('datawatch memsomething using ret_to_addr from SP of 0x%x' % frame.sp)
                            retval = MemStuff(ret_addr, fun, frame.fun_addr, frame.ip, addr_of_ret_addr, frames=frames)
                            break 
                        else:
                            ''' NOTE: modifying loop index! '''
                            i = bad_index - 1
                            self.lgr.debug('datawatch memsomething found frame that may be floor, change loop index to %d' % i)
                            
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
        self.lgr.debug('dataWatch getCopyMark')
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
                retval = self.watchMarks.copy(self.mem_something.src, self.mem_something.dest, self.mem_something.length, None, None, strcpy=strcpy)
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
        self.lgr.debug('dataWatch max marks set to %d' % marks)
        self.max_marks = marks

    def enable(self):
        if self.disabled:
            self.lgr.debug('dataWatch enable')
            self.disabled = False

    def disable(self):
        self.lgr.debug('dataWatch disable')
        self.disabled=True
        self.top.rmSyscall('dataWatchMmap')
        

    def setReadLimit(self, limit, callback):
        self.read_limit_trigger = limit
        self.read_limit_callback = callback
        self.lgr.debug('dataWatch setReadLimit to %d callback %s' % (limit, self.read_limit_callback))

    def getAllJson(self):
        return self.watchMarks.getAllJson()

    def markTrace(self, s):
        if self.call_trace:
            self.markLog(s, 'syscall')

    def markLog(self, s, prefix):
        self.lgr.debug('dataWatch markLog')
        self.watchMarks.logMark(s, prefix)

    def watchArgs(self):
        self.enable()
        self.break_simulation = False
        sp = self.mem_utils.getRegValue(self.cpu, 'sp')
        argc = self.mem_utils.readAppPtr(self.cpu, sp)
        self.lgr.debug('dataWatch watchArgs sp 0x%x, argc is %d break_simulation now false' % (sp, argc))
        argptr = sp + self.mem_utils.wordSize(self.cpu)
        for index in range(argc):
            ''' TBD good size limit? '''
            valptr = self.mem_utils.readAppPtr(self.cpu, argptr)
            argval = self.mem_utils.readString(self.cpu, valptr, 100)
            self.lgr.debug('dataWatch watchArgs arg %d is %s' % (index, argval))
            argptr = argptr + self.mem_utils.wordSize(self.cpu)
            msg = 'prog arg %s' % argval
            self.setRange(argptr, len(argval), msg=msg)
        self.setBreakRange()
        
    def watchCGIArgs(self):
        self.enable()
        self.break_simulation = False
        sp = self.mem_utils.getRegValue(self.cpu, 'sp')
        argc = self.mem_utils.readAppPtr(self.cpu, sp)
        self.lgr.debug('dataWatch watchCGIArgs sp 0x%x, argc is %d' % (sp, argc))
        argptr = sp + self.mem_utils.wordSize(self.cpu)
        valptr = self.mem_utils.readAppPtr(self.cpu, argptr)
        if argc != 1:
            self.lgr.error('dataWatch watchCGIArgs expected only one argv, got %d' % argc)
        else:
            index = 0
            while True:
                ''' TBD good size limit? '''
                argval = self.mem_utils.readString(self.cpu, valptr, 1200)
                if argval is None or len(argval) == 0:
                    self.lgr.debug('dataWatch watchCGIArgs Got null argval')
                    break
                self.lgr.debug('dataWatch watchCGIArgs arg %d is %s' % (index, argval))
                msg = 'cgi-bin arg %s' % argval
                self.setRange(valptr, len(argval), msg=msg)
                valptr = valptr + len(argval)+1
                index = index + 1
            self.setBreakRange()

    def showFunEntries(self):
        for fun in self.mem_fun_entries:
            for eip in self.mem_fun_entries[fun]:
                print('%s  0x%x' % (fun, eip))
                self.lgr.debug('%s  0x%x' % (fun, eip))

    def loadFunEntryPickle(self, name):
        if name is not None:
            entries_file = os.path.join('./', name, self.cell_name, 'funEntry.pickle')
            if os.path.isfile(entries_file):
                entries = pickle.load( open(entries_file, 'rb') ) 
                if 'fun_entries' in entries:
                    self.mem_fun_entries = entries['fun_entries']
                    self.skip_entries = entries['skip_entries']
                    self.lgr.debug('dataWatch loadFunEntryPickle loaded for %d functions' % len(self.mem_fun_entries))
                else:
                    self.lgr.debug('dataWatch loadFunEntryPickle, no fun_entries, nothing loaded.')
        #self.showFunEntries()

    def pickleFunEntries(self, name):
        if self.added_mem_fun_entry:
            entries_dir = os.path.join('./', name, self.cell_name)
            try:
                os.mkdir(entries_dir)
            except:
                pass
            entries_file = os.path.join(entries_dir, 'funEntry.pickle')
            entries = {}
            entries['fun_entries'] = self.mem_fun_entries
            self.lgr.debug('dataWatch pickleFunEntries saved %d fun entries' % len(self.mem_fun_entries))
            entries['skip_entries'] = self.skip_entries
            pickle.dump(entries, open( entries_file, "wb") ) 

    def registerHapForRemoval(self, module):
        self.lgr.debug('dataWatch registerHapForRemoval %s' % str(module))
        self.remove_external_haps.append(module)

    def removeExternalHaps(self, immediate=False):
        self.lgr.debug('dataWatch removeExternalHaps')
        for module in self.remove_external_haps:
            self.lgr.debug('dataWatch removeExternalHaps call rmAllHaps for %s' % (str(module)))
            module.rmAllHaps(immediate=immediate)
        self.remove_external_haps = []

    def recordObscureMemcpyEntry(self, rcx):
            ''' we are at the call.  we need to record the function entry, so step 1 '''
            next_cycle = self.cpu.cycles+1
            if not self.top.skipToCycle(next_cycle, cpu=self.cpu, disable=True):
                self.lgr.error('recordObscureEntry, tried going forward, failed')
                return
            rax = self.mem_utils.getRegValue(self.cpu, 'rax')
            r8 = self.mem_utils.getRegValue(self.cpu, 'r8')
            self.lgr.debug('dataWatch recordObscureMemcpyEntry dest is in range, looks like a memcpy rax is %d r8 %d' % (rax, r8))
            self.mem_something.dest = rcx
            self.mem_something.length = r8
            self.mem_something.fun = 'memcpy_xmm'
            self.mem_something.run = True
            self.mem_something.op_type = Sim_Trans_Load

            eip = self.top.getEIP(self.cpu)
            rsp = self.mem_utils.getRegValue(self.cpu, 'rsp')
            ret_addr_offset = rsp - self.mem_something.ret_addr_addr 
            self.lgr.debug('dataWatch recordObscureMemcpyEntry add mem_something_entry addr %s eip 0x%x ret_addr_addr 0x%x ret_addr_offset 0x%x' % (self.mem_something.fun, 
                            eip, self.mem_something.ret_addr_addr, ret_addr_offset))
            if self.mem_something.fun not in self.mem_fun_entries:
                self.mem_fun_entries[self.mem_something.fun] = {}
            if eip not in self.mem_fun_entries[self.mem_something.fun]:
                self.mem_fun_entries[self.mem_something.fun][eip] = self.MemCallRec(None, ret_addr_offset, eip)
                self.added_mem_fun_entry = True
            else:
                self.lgr.debug('dataWatch recordObscureMemcpyEntry eip 0x%x already in mem_fun_entries' % eip)
            self.runToReturnAndGo(skip_this=False)

    def recordObscureMemcpyEntry2(self, src_dest_count):
            src_ptr, dest_ptr, count = src_dest_count
            ''' we are at the call to a memcpyis whose parameters are on the stack.  we need to record the function entry '''
            next_cycle = self.cpu.cycles+1
            if not self.top.skipToCycle(next_cycle, cpu=self.cpu, disable=True):
                self.lgr.error('recordObscureEntry, tried going forward, failed')
                return
            self.lgr.debug('dataWatch recordObscureMemcpyEntry2')
            self.mem_something.dest = dest_ptr
            self.mem_something.length = count
            self.mem_something.fun = 'memcpy_xmm'
            self.mem_something.run = True
            self.mem_something.op_type = Sim_Trans_Load

            eip = self.top.getEIP(self.cpu)
            rsp = self.mem_utils.getRegValue(self.cpu, 'rsp')
            ret_addr_offset = rsp - self.mem_something.ret_addr_addr 
            self.lgr.debug('dataWatch recordObscureMemcpyEntry2 add mem_something_entry addr %s eip 0x%x ret_addr_addr 0x%x ret_addr_offset 0x%x' % (self.mem_something.fun, 
                            eip, self.mem_something.ret_addr_addr, ret_addr_offset))
            if self.mem_something.fun not in self.mem_fun_entries:
                self.mem_fun_entries[self.mem_something.fun] = {}
            if eip not in self.mem_fun_entries[self.mem_something.fun]:
                self.mem_fun_entries[self.mem_something.fun][eip] = self.MemCallRec(None, ret_addr_offset, eip)
                self.added_mem_fun_entry = True
            else:
                self.lgr.debug('dataWatch recordObscureMemcpyEntry2 eip 0x%x already in mem_fun_entries' % eip)
            self.runToReturnAndGo(False)

    def memcpyCheck(self, called_from_reverse_mgr, one, exception, error_string):
        if self.call_stop_hap is not None or called_from_reverse_mgr is not None:
            self.memcpyCheckBody(called_from_reverse_mgr)

    def memcpyCheckBody(self, called_from_reverse_mgr):
        ''' We are at the call to what looks like an obscure memcpy.  We are stopped, but in a hap.
            Determine if this is in fact an obscure memcpy (one with no analysis signature).
        '''
        self.lgr.debug('dataWatch memcpyCheck cycle: 0x%x' % self.cpu.cycles)
        SIM_run_alone(self.enableBreaks, None)
        SIM_run_command('enable-vmp') 
        cycle_dif = self.cycles_was - self.cpu.cycles
        #self.lgr.debug('hit CallStopHap will delete hap %d break %d cycle_dif 0x%x' % (self.call_hap, self.call_break, cycle_dif))
        if called_from_reverse_mgr is None:
            self.top.RES_delete_stop_hap(self.call_stop_hap)
        #self.rmCallHap()
        if self.call_break is not None:
            self.reverse_mgr.SIM_delete_breakpoint(self.call_break)
            self.call_break = None
        self.call_stop_hap = None
        self.lgr.debug('dataWatch memcpyCheck.  now what?')
        buf_index = self.findRangeIndex(self.mem_something.src)
        got_it = False
        if buf_index is not None:
            dum_cpu, comm, tid = self.task_utils.curThread()
            rdx = self.mem_utils.getRegValue(self.cpu, 'rdx')
            if rdx == self.mem_something.src:
                self.lgr.debug('dataWatch memcpyCheck src is rdx 0x%x' % rdx)
                ''' see if destination (not nessesarily beginning of dest buffer, depends on memcy sequency), is within range of rcx to buffer size '''
                rcx = self.mem_utils.getRegValue(self.cpu, 'rcx')
                end = rcx + self.length[buf_index] - 1
                if self.mem_something.dest >= rcx and self.mem_something.dest <= end: 
                    got_it = True
                    ''' Record the function entry and run to the return '''
                    SIM_run_alone(self.recordObscureMemcpyEntry, rcx)
                else:
                    self.lgr.debug('dataWatch memcpyCheck src rcx 0x%x and end 0x%x does not include dest 0x%x' % (rcx, end, self.mem_something.dest))
            else:
                # see if stack parameters
                word_size = self.top.wordSize(tid, target=self.cell_name)
                rsp = self.mem_utils.getRegValue(self.cpu, 'sp')
                src_ptr = self.mem_utils.readAppPtr(self.cpu, rsp+word_size, word_size)
                self.lgr.debug('dataWatch memcpyCheck tid:%s src_ptr from stack is 0x%x word_size %d' % (tid, src_ptr, word_size))
                # hack to handle memcpy first byte  TBD ranges are not right per what is actually copied.
                if (src_ptr+1) >= self.start[buf_index] and src_ptr < (self.start[buf_index]+self.length[buf_index]):
                    dest_ptr = self.mem_utils.readAppPtr(self.cpu, rsp, word_size)
                    count = self.mem_utils.readAppPtr(self.cpu, rsp+2*word_size, word_size)
                    end = dest_ptr + self.length[buf_index] - 1
                    if self.mem_something.dest >= dest_ptr and self.mem_something.dest <= end: 
                        self.lgr.debug('dataWatch memcpyCheck looks like stack params, dest_ptr 0x%x count 0x%x' % (dest_ptr, count))
                        src_dest_count = (src_ptr, dest_ptr, count)
                        got_it = True
                        SIM_run_alone(self.recordObscureMemcpyEntry2, src_dest_count)
                else:
                    self.lgr.debug('dataWatch memcpyCheck src 0x%x does not match rdx 0x%x or src_ptr from stack 0x%x' % (self.mem_something.src, rdx, src_ptr))
        else:
            self.lgr.debug('dataWatch memcpyCheck src not in ranges 0x%x' % self.mem_something.scr)
        if not got_it:
            pass
            self.lgr.debug('dataWatch memcpyCheck not a memcpy signature, complete the ad-hoc copy ''')
            wm = self.watchMarks.dataRead(self.move_stuff.addr, self.move_stuff.start, self.move_stuff.length, 
                     self.move_stuff.trans_size, ad_hoc=True, dest=self.last_ad_hoc[-1])
            ''' recorded in mem_something as part of obscure memcpy check '''
            dest_addr = self.mem_something.dest
            self.setRange(dest_addr, self.move_stuff.trans_size, watch_mark=wm)
            #self.lgr.debug('dataWatch memcpyCheck is ad hoc addr 0x%x  adhoc %r, dest 0x%x' % (self.move_stuff.addr, adhoc, dest_addr))
            self.setBreakRange()
            self.move_cycle = self.cpu.cycles
            self.move_cycle_max = self.cpu.cycles+1
            self.lgr.debug('move_cycle_max now 0x%x' % self.move_cycle_max)

    def stopForMemcpyCheck(self, dumb):
        if self.finish_check_move_hap is None:
            self.lgr.error('DataWatch stopForMemcpyCheck finish_check_move_hap is none')
            return
        self.context_manager.genDeleteHap(self.finish_check_move_hap, immediate=True)
        self.finish_check_move_hap = None
        self.stop_hap = self.top.RES_add_stop_callback(self.memstuffStopHap, self.memcpyCheck)
        self.lgr.debug('stopForMemcpyCheck, is big move, look for memcpy')
        SIM_break_simulation('stopForMemcpyCheck')

    def setUserIterators(self, iterators):
        self.fun_mgr.setUserIterators(iterators)

    def commenceWith(self, commence_with, offset=0):
        self.commence_with = commence_with
        self.commence_offset = offset
 
    def hasCommenceWith(self):
        if self.commence_with is not None:
            return True
        else:
            return False

    def loadRingChars(self):
        self.lgr.debug('dataWatch loadRingChars')
        for fun in char_ring_functions:
            entry = self.top.getFunEntry(fun)
            if entry is not None:
                self.ring_char_entry[entry] = fun
                self.lgr.debug('dataWatch loadRingChars set entry 0x%x for fun %s' % (entry, fun))
            else:
                self.lgr.debug('dataWatch loadRingChars no entry for fun %s' % fun)

    def setRingCharBreaks(self):
        if len(self.ring_char_hap) == 0:
            #self.lgr.debug('dataWatch setRingCharBreaks')
            for entry in self.ring_char_entry:
                #self.lgr.debug('dataWatch setRingCharBreaks set on 0x%x' % entry)
                proc_break = self.context_manager.genBreakpoint(None, Sim_Break_Linear, Sim_Access_Execute, entry, 1, 0)
                self.ring_char_hap[entry] = self.context_manager.genHapIndex("Core_Breakpoint_Memop", self.ringCharHap, None, proc_break, 
                       self.ring_char_entry[entry])

    def initRingChar(self):
        self.lgr.debug('dataWatch initRingChar')
        self.loadRingChars()
        self.setRingCharBreaks()

    def rmRingCharBreaks(self): 
        #self.lgr.debug('dataWatch rmRingCharBreaks')
        for entry in self.ring_char_hap: 
            self.context_manager.genDeleteHap(self.ring_char_hap[entry], immediate=True)
        self.ring_char_hap = {} 

    def ringCharHap(self, dumb, the_object, break_num, memory):
        eip = memory.logical_address
        if eip not in self.ring_char_hap:
            self.lgr.debug('dataWatch ringCharHap hap is gone for eip 0x%x' % eip)
            return

        #self.lgr.debug('dataWatch ringCharHap eip 0x%x cycle: 0x%x' % (eip, self.cpu.cycles))
 
        mark = self.watchMarks.getRecentMark()
        if mark is not None and isinstance(mark.mark, watchMarks.DataMark) and mark.mark.length == 1:
            self.lgr.debug('dataWatch ringCharHap recent mark was 1 byte data.') 
            ''' do not use cycle delta, might be scheduling.  TBD how to tie read mark to this call.  EIP delta? No, wrappers break that.'''
            if True:
                addr = mark.mark.addr
                prev_mark = self.watchMarks.getRecentMark(prev=1)
                self.lgr.debug('dataWatch ringCharHap recent addr 0x%x  prev_mark %s' % (addr, prev_mark.mark.getMsg()))
                if isinstance(prev_mark.mark, watchMarks.CopyMark) and mark.mark.length == 1:
                    self.lgr.debug('dataWatch ringCharHap prev was copy mark src: 0x%x dest: 0x%x' % (prev_mark.mark.src, prev_mark.mark.dest))
                    if addr == prev_mark.mark.dest:
                        source = prev_mark.mark.src
                        # remove previous 2 marks and update the ad-hoc copy
                        if self.cpu.architecture == 'arm':
                            ptr1 = self.mem_utils.getRegValue(self.cpu, 'r0') + 8
                            dest = self.mem_utils.readPtr(self.cpu, ptr1) + 1
                            self.lgr.debug('dataWatch ringCharHap src %x dest 0x%x remove previous 2 marks and update the ad-hoc copy' % (source, dest))
                            self.watchMarks.rmLast(2)
                            mark = self.watchMarks.dataRead(source, source, 1, 1, ad_hoc=True, dest=dest, note='ringChar')
                            self.setRange(dest, 1, None, watch_mark=mark) 
                            self.move_cycle = self.cpu.cycles
                            self.move_cycle_max = self.cpu.cycles+1
                            self.lgr.debug('move_cycle_max now 0x%x' % self.move_cycle_max)
                            #self.setBreakRange()
                        else:
                            self.lgr.warning('dataWatch ringCharHap only arm is handled for now')
 
              
    def oneByteCopy(self, addr, size):
        ''' We hit a function entry that was a 1 byte copy, then we hit a readHap and called this to confirm that was the 1 byte copy.
            Since only one byte, record it and go on.'''
        retval = False
        if self.mem_something is not None:
            if self.mem_something.dest is None:
                self.lgr.debug('dataWatch oneByteCopy called with dest of None addr 0x%x' % addr)
            elif self.mem_something.length == 1 and size == 1 and addr == self.mem_something.src:
                self.lgr.debug('dataWatch oneByteCopy, maybe got one, addr 0x%x' % addr)
                index = self.findRangeIndex(addr)
                if index is not None and index < len(self.start):
                    retval = True
                    mark = self.watchMarks.copy(self.mem_something.src, self.mem_something.dest, self.mem_something.length, self.start[index], Sim_Trans_Load)
                    if self.findRange(self.mem_something.dest) is None:
                        self.setRange(self.mem_something.dest, self.mem_something.length, None, watch_mark=mark) 
                        self.setBreakRange()
                        self.move_cycle = self.cpu.cycles
                        self.move_cycle_max = self.cpu.cycles+1
                        self.lgr.debug('dataWatch oneByteCopy, set the range move_cycle_max 0x%x' % self.move_cycle_max)
                else:
                    self.lgr.debug('dataWatch oneByteCopy address 0x%x is not a known buffer, why are we here?  index %s' % (addr, index))
        else:
            self.lgr.debug('dataWatch oneByteCopy memsomething is none') 
        return retval

    def findMarkIp(self, ip):
        return self.watchMarks.findMarkIp(ip)

    def findStaleMarkIp(self, ip):
        return self.watchMarks.findStaleMarkIp(ip)

    def doAppend(self, this, addr):
        wm = self.watchMarks.findCharAppend(this)
        if wm is None:
            wm = self.watchMarks.charAppendMark('charAppend', this, addr)
        else:
            if addr == wm.mark.addr:
                # still appending to old buffer
                wm.mark.extend()
            else:
                # switched buffers
                wm.mark.switchTo(addr)

        self.lgr.debug('dataWatch doAppend wm now %s' % wm.mark.getMsg())



    def maxMarksExceeded(self):
            self.lgr.debug('dataWatch maxMarksExceeded check callback')
            use_callback = None
            if self.callback is not None: 
                use_callback = self.callback
                self.lgr.debug('dataWatch maxMarksExceeded using self.callback')
            elif self.top.getCommandCallback() is not None:
                self.lgr.debug('dataWatch maxMarksExceeded using command callback')
                use_callback = self.top.getCommandCallback()

            if use_callback is None:
                self.lgr.debug('dataWatch maxMarksExceeded no callback')
                self.clearWatches()
                SIM_break_simulation('max marks exceeded')
                print('Data Watches removed')
             
            else:
                #SIM_break_simulation('max marks exceeded')
                self.lgr.debug('dataWatch max marks exceeded, use stopAndGo to call  callback %s' % str(use_callback))
                self.clearWatches(leave_backstop=True)
                self.top.stopAndGo(use_callback)
                #self.callback()
                self.callback = None

    def mmap(self, addr):
        if self.disabled:
            self.lgr.debug('dataWatch mmap disabled')
            return
        phys_of_addr = self.mem_utils.v2p(self.cpu, addr)
        if phys_of_addr is None:
            self.lgr.debug('dataWatch mmap called with addr 0x%x, but not mapped' % addr)
            #return 
        else:
            self.lgr.debug('dataWatch mmap addr 0x%x phys is 0x%x cycles: 0x%x' % (addr, phys_of_addr, self.cpu.cycles))
        index = self.findRangeIndex(addr)
        if index is not None:
            self.lgr.debug('dataWatch mmap redo range')
            length = self.length[index]
            self.rmRange(addr)
            self.setRange(addr, length)        
            self.setBreakRange()
            #SIM_break_simulation('remove this')
        else:
            self.lgr.debug('dataWatch mmap range not found')
            pass

    def watchMmap(self):
        dum_cpu, comm, tid = self.task_utils.curThread()
        word_size = self.top.wordSize(tid, target=self.cell_name)
        if word_size == 8:
            call_list = ['mmap']
        else:
            call_list = ['mmap', 'mmap2']
        self.top.runTo(call_list, None, linger_in=True, name='dataWatchMmap', run=False, ignore_running=True)
        self.lgr.debug('dataWatch did watchMmap')

    def watchExecve(self):
        self.top.runTo(['execve'], None, linger_in=True, name='dataWatchMmap', run=False, ignore_running=True)
        self.lgr.debug('dataWatch did watchExecve')

    def checkLoopCmp(self, eip, instruct, addr):
        retval = None
        # Does the read reference look like a loop counter comparison?
        op2, op1 = self.decode.getOperands(instruct[1])
        if instruct[1].startswith('cmp') and (self.decode.isReg(op1) or self.decode.isReg(op2)):
            prev_read = self.watchMarks.findReadIpAddr(eip, addr)
            if prev_read is not None and not prev_read.mark.ad_hoc:
                loop_count = prev_read.mark.loopCompare(instruct[1])
                retval = 'loop counter compare at 0x%x, count %d' % (addr, loop_count)
            
        return retval
       
    def nextCallMark(self):
        return self.watchMarks.nextCallMark() 

    def markCall(self, msg, fd):
        self.watchMarks.markCall(msg, fd=fd)

    def setBackstop(self):
        if self.backstop is not None and not self.break_simulation and self.use_backstop:
            self.lgr.debug('dataWatch setBackstop')
            self.backstop.setFutureCycle(self.backstop_cycles)

    def clearBackstop(self):
        if self.backstop is not None:
            self.lgr.debug('dataWatch clearBackstop')
            self.backstop.clearCycle()

    def ignoreAddrList(self, ignore_addr_file):
        if ignore_addr_file is not None:
            if os.path.isfile(ignore_addr_file):
                with open(ignore_addr_file) as fh:
                    for line in fh:
                        line = line.strip() 
                        if not line.startswith('#'):
                            value = int(line, 16)
                            self.ignore_addr_list.append(value) 
            else:
                self.lgr.error('dataWatch ignoreList file %s not found' % ignore_addr_file)

    def fgetc(self, fd, char):
        msg = 'fgetc char: 0x%x' % char
        self.lgr.debug('call watchMarks for %s' % msg)
        self.watchMarks.markCall(msg, fd=fd)
        eip = self.top.getEIP(self.cpu)
        orig_ip = eip
        orig_cycle = self.cpu.cycles
        dum_cpu, comm, tid = self.task_utils.curThread()
        instruct = self.top.disassembleAddress(self.cpu, eip)
        if self.cpu.architecture.startswith('arm'):
            if self.cpu.architecture == 'arm64' and self.mem_utils.arm64App(self.cpu):
                our_reg = 'x0'
            else:
                our_reg = 'r0'
        else:
            our_reg = 'eax'
        self.loopAdHoc(None, 1, None, None, instruct, our_reg, eip, orig_ip, orig_cycle, tid, only_push=False)

    def fscanf(self, fd, format_str, ret_count, retval_addr_list):
        msg = 'fscanf format %s reval_count %d ret_addr 0x%x 0x%x 0x%x' % (format_str, ret_count, retval_addr_list[0], retval_addr_list[1], retval_addr_list[2]) 
        self.watchMarks.markCall(msg, fd=fd)
        format_index = 0
        for i in range(ret_count):
            token_index = format_str[format_index:].index('%')
            self.lgr.debug('dataWatch fscanf look for percent in %s found at %d' % (format_str[format_index:], token_index))
            if token_index >= 0:
                type_index = token_index + 1 
                token_type = format_str[format_index:][type_index]
                if token_type == 's':
                    the_string = self.mem_utils.readString(self.cpu, retval_addr_list[i], 100)
                    msg = 'fscan string param %d string is %s' % (i, the_string) 
                    self.lgr.debug('dataWatch '+msg)
                    self.setRange(retval_addr_list[i], len(the_string), msg)
                elif token_type == 'c':
                    the_char = self.mem_utils.readByte(self.cpu, retval_addr_list[i])
                    msg = 'fscan char param %d the char: %s' % (i, the_char) 
                    self.lgr.debug('dataWatch '+msg)
                    self.setRange(retval_addr_list[i], 1, msg)
                else:
                    self.lgr.debug('dataWatch fscanf format %s not yet handled' % token_type)
                format_index = type_index+1
            else:
                self.lgr.debug('dataWatch fscanf no percent found in %s' % format_str[format_index:])    
        # reset data watches
        self.stopWatch() 
        self.watch(break_simulation=False, i_am_alone=True)
                     
    def recordOtherProcRead(self, phys_addr, trans_size, addr, index, cur_comm, cur_tid, op_type):
        self.lgr.debug('dataWatch recordOtherProcRead BEGIN')
        #index_phys = self.mem_utils.v2p(self.cpu, self.start[index], force_cr3=self.range_cr3[index], do_log=True)
        index_phys = self.phys_start[index]
        delta = phys_addr - index_phys
        linear_addr = self.start[index]+delta
        dum_cpu, comm, tid = self.task_utils.curThread()
        cpl = memUtils.getCPL(self.cpu)
        self.lgr.debug('dataWatch recordOtherProcRead self.comm: %s index: %d index_phys: 0x%x phys_addr: 0x%x linear: 0x%x delta: 0x%x trans_size %d tid:%s (%s) cpl: %d opt_type: %d' % (self.comm, index, index_phys, phys_addr, linear_addr, delta, trans_size, tid, comm, cpl, op_type))
        self.data_watch_manager.recordRead(self.comm, index, phys_addr, linear_addr, self.start[index], self.length[index], trans_size, cur_comm, cur_tid, op_type)
                     
    def markCallTrace(self):                            
        self.call_trace = True
                    
    def didSomething(self):
        ''' Did dataWatch start tracking anything?  Helps calls know if things like readReplace haps should be disabled.'''
        if len(self.start) > 0:
            return True
        else:
            return False                    
                
    def noReset(self):
        self.no_reset = True


