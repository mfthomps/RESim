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
import elfText
import memUtils
import watchMarks
import backStop
import resimUtils
import readLibTrack
import net
import os
import sys
import pickle
import traceback
import reWatch
import clibFuns
from resimHaps import *
MAX_WATCH_MARKS = 1000
mem_funs = ['memcpy','memmove','memcmp','strcpy','strcmp','strncmp','strncasecmp', 'strpbrk', 'strspn', 'strcspn', 'strcasecmp', 'strncpy', 'strtoul', 
            'strtol', 'strtoll', 'strtoq', 'atoi', 'mempcpy', 
            'j_memcpy', 'strchr', 'strrchr', 'strdup', 'memset', 'sscanf', 'strlen', 'LOWEST', 'glob', 'fwrite', 'IO_do_write', 'xmlStrcmp',
            'xmlGetProp', 'inet_addr', 'inet_ntop', 'FreeXMLDoc', 'GetToken', 'xml_element_free', 'xml_element_name', 'xml_element_children_size', 'xmlParseFile', 'xml_parse',
            'printf', 'fprintf', 'sprintf', 'vsnprintf', 'snprintf', 'syslog', 'getenv', 'regexec', 
            'string_chr', 'string_std', 'string_basic_char', 'string_basic_std', 'string', 'str', 'ostream_insert', 'regcomp', 
            'replace_chr', 'replace_std', 'replace', 'replace_safe', 'append_chr_n', 'assign_chr', 'compare_chr', 'charLookup']
#win_mem_funs = []
''' Functions whose data must be hit, i.e., hitting function entry point will not work '''
funs_need_addr = ['ostream_insert', 'charLookup']
#no_stop_funs = ['xml_element_free', 'xml_element_name']
no_stop_funs = ['xml_element_free']
''' made up functions that could not have ghost frames?'''
no_ghosts = ['charLookup']
''' TBD confirm end_cleanup is a good choice for free'''
free_funs = ['free_ptr', 'free', 'regcomp', 'destroy', 'delete', 'end_cleanup', 'erase', 'new']
class MemSomething():
    def __init__(self, fun, fun_addr, addr, ret_ip, src, dest, count, called_from_ip, op_type, length, start, ret_addr_addr=None, run=False, trans_size=None, frames=[]):
            self.fun = fun
            self.fun_addr = fun_addr
            self.addr = addr
            self.ret_ip = ret_ip
            self.src = src
            self.dest = dest
            self.the_string = None
            self.the_chr = None
            self.count = count
            self.called_from_ip = called_from_ip
            self.trans_size = trans_size
            self.ret_addr_addr = ret_addr_addr
            ''' used for finishReadHap '''
            self.op_type = op_type
            self.length = length
            self.start = start
            self.frames = frames
            self.dest_list = []
            ''' used for file tracking, e.g., if xmlParse '''
            self.run = run
            ''' was memcpy length beyond our buffer?'''
            self.truncated = None
            self.pos = None
            self.re_watch = None

class DataWatch():
    ''' Watch a range of memory and stop when it is read.  Intended for use in tracking
        reads to buffers into which data has been read, e.g., via RECV. '''
    def __init__(self, top, cpu, cell_name, page_size, context_manager, mem_utils, task_utils, rev_to_call, param, run_from_snap, back_stop, compat32, lgr):
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
        self.back_stop = back_stop
        self.finish_check_move_hap = None
        self.watchMarks = watchMarks.WatchMarks(top, mem_utils, cpu, cell_name, run_from_snap, lgr)
        back_stop_string = os.getenv('BACK_STOP_CYCLES')
        if back_stop_string is None:
            self.back_stop_cycles = 5000000
        else:
            self.back_stop_cycles = int(back_stop_string)
        read_loop_string = os.getenv('READ_LOOP_MAX')
        if read_loop_string is None:
            self.read_loop_max = 10000
        else:
            self.read_loop_max = int(read_loop_string)
        #lgr.debug('DataWatch init with back_stop_cycles %d compat32: %r' % (self.back_stop_cycles, compat32))
        if cpu.architecture == 'arm':
            self.decode = decodeArm
        else:
            self.decode = decode
        self.readLib = readLibTrack.ReadLibTrack(cpu, self.mem_utils, 
                  self.context_manager, self, self.top, self.lgr)
        self.user_iterators = None
        ''' ignore modify of ad-hoc buffer for same cycle '''
        self.move_cycle = 0
        self.ida_funs = None
        self.fun_mgr = None
        ''' optimize parameter gathering without having to reverse. Keyed by function and eip to handle multiple instances of sameish functions '''
        self.mem_fun_entries = {}
        self.added_mem_fun_entry = False

        self.resetState()

        ''' hack to ignore reuse of fgets buffers if reading stuff we don't care about '''
        self.recent_fgets = None
        self.recent_reused_index=None
        ''' control trace of malloc calls, e.g., within xml parsing '''
        self.me_trace_malloc = False

        self.save_cycle = None
        #self.loadFunEntryPickle(run_from_snap)

    def resetState(self):
        self.lgr.debug('resetState')
        self.start = []
        self.length = []
        self.hack_reuse = []
        self.cycle = []
        self.mark = []
        self.read_hap = []
        self.show_cmp = False
        self.break_simulation = True
        self.return_break = None
        self.return_hap = None
        self.prev_cycle = None
        ''' for guessing if stack buffer is being re-used '''
        self.prev_read_cycle = 0
        self.other_starts = [] # buffer starts that were skipped because they were subranges.
        self.other_lengths = [] 
        self.retrack = False
        self.call_break = None
        self.call_hap = None
        self.call_stop_hap = None
        self.mem_something = None
        ''' used to guess if we encountered a ghost frame '''
        self.cycles_was = 0
        self.undo_hap = None
        ''' Do not set backstop until first read, otherwise accept followed by writes will trigger it. '''
        self.use_back_stop = False
        
        self.malloc_dict = {}
        self.pending_call = False
        self.ghost_stop_hap = None
        ''' don't set backstop on reads of these addresses, e.g., for ioctl '''
        self.no_backstop = []
        ''' support deletion of stack buffers after return from function '''
        self.stack_buffers = {}
        self.stack_buf_hap = {}
        self.stack_this = {}
        self.stack_this_hap = {}
        ''' watch for string destroy?'''
        self.destroy_entry = None
        self.destroy_hap = None
        ''' limit number of marks gathered '''
        self.max_marks = None
        ''' used by writeData when simulating responses from ioctl '''
        self.total_read = 0
        self.read_limit_trigger = None
        self.read_limit_callback = None
        ''' skip hit on ad_hoc buffer that was just added, and likely not yet executed.'''
        self.last_ad_hoc = 0
        ''' sanitiy check for programs run amuck '''
        self.index_hits = {}

        self.disabled = True
        ''' expect readHap to be hit twice'''
        self.undo_pending = False

        self.transform_push_hap = None
        self.recent_fgets = None
        self.recent_reused_index=None

        ''' catch c++ string reuse/free '''
        self.string_this = {}

        ''' optimization to avoid hunt for memsomething on iterations '''
        self.not_mem_something = []

        self.re_watch_list = []

        #self.char_ptrs = []
        self.stop_hap = None

        self.skip_entries = []

        ''' ad-hock clearing of smallish buffers through multiple writes'''
        self.hack_reuse_index = None
        self.hack_reuse = []

        ''' Modules whose haps need to be removed when tracking is stopped.  These will not be recreated '''
        self.remove_external_haps = []

        ''' optimization to avoid rechecking for ad-hoc copies on same addresses '''
        self.not_ad_hoc_copy = []

        ''' most recent frames from check for memsomething '''
        self.frames = []

        ''' recent record during check move for use in creating a watch mark if a potential obscure memcpy does not pan out '''
        self.move_stuff = None

    def addFreadAlone(self, dumb):
        self.lgr.debug('dataWatch addFreadAlone')
        self.stop_hap = SIM_hap_add_callback("Core_Simulation_Stopped", self.memstuffStopHap, self.freadCallback)
        SIM_break_simulation('handle memstuff')

    def checkFread(self, start, length):
        retval = False
        self.lgr.debug('dataWatch checkFread')
        st = self.top.getStackTraceQuiet(max_frames=20, max_bytes=1000)
        if st is None:
            self.lgr.debug('stack trace is None, wrong pid?')
            return False
        #self.lgr.debug('%s' % st.getJson()) 
        # look for memcpy'ish... TBD generalize 
        frames = st.getFrames(20)
        for f in frames:
            if f.fun_name == 'fread':
                ret_addr = f.ret_addr
                called_from = f.ip
                self.mem_something = MemSomething(f.fun_name, f.fun_addr, start, f.ret_addr, start, None, None, 
                      f.ip, None, length, start)
                #self.lgr.debug('checkFread got fread')
                SIM_run_alone(self.addFreadAlone, None)
                retval = True
                break
        return retval

    def freadCallback(self, dumb, one, exception, error_string):
        self.lgr.debug('dataWatch freadCallback')
        SIM_run_command('enable-vmp') 
        if self.call_stop_hap is not None:
            cycle_dif = self.cycles_was - self.cpu.cycles
            #self.lgr.debug('hit CallStopHap will delete hap %d break %d cycle_dif 0x%x' % (self.call_hap, self.call_break, cycle_dif))
            SIM_hap_delete_callback_id("Core_Simulation_Stopped", self.call_stop_hap)
            #self.rmCallHap()
            if self.call_break is not None:
                RES_delete_breakpoint(self.call_break)
            self.call_stop_hap = None
        else:
            return
        sp = self.mem_utils.getRegValue(self.cpu, 'sp')
        start, dumb2, dumb = self.getCallParams(sp)
        #self.lgr.debug('freadCallback call setRange with start 0x%x len %d' % (start, self.mem_something.length))
        msg = 'fread to 0x%x %d bytes' % (start, self.mem_something.length)
        self.setRange(start, self.mem_something.length, msg=msg)
        self.top.restoreDebugBreaks(was_watching=True)
        self.watch()
        SIM_run_alone(SIM_run_command, 'c')

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

    def setStackThisHaps(self):
        for ret_to in self.stack_this:
            if ret_to not in self.stack_this_hap:
                #self.lgr.debug('dataWatch setStackThisHaps add hap for eip 0x%x' % ret_to)
                proc_break = self.context_manager.genBreakpoint(None, Sim_Break_Linear, Sim_Access_Execute, ret_to, 1, 0)
                self.stack_this_hap[ret_to] = self.context_manager.genHapIndex("Core_Breakpoint_Memop", self.stackThisHap, None, proc_break, 'stack_this_hap')

    def stopStackThisHaps(self, immediate=False):
        for eip in self.stack_this_hap:
            #self.lgr.debug('dataWatch stopStackThisHaps delete hap for eip 0x%x' % eip)
            self.context_manager.genDeleteHap(self.stack_this_hap[eip], immediate=immediate)
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
                #self.lgr.debug('DataWatch manageStackBuf stack buffer, set a break at 0x%x to delete this range on return' % ret_to)
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
            #self.lgr.debug('manageStackBuf ret_to 0x%x, eip 0x%x' % (ret_to, eip))
            if eip == ret_to:
                #self.lgr.error('manageStackBuf, eh????')
                return
            #self.lgr.debug('DataWatch manageStackBuf stack buffer, set a break at 0x%x to delete this range on return' % ret_to)
            if ret_to not in self.stack_buffers:
                self.stack_buffers[ret_to] = []
                proc_break = self.context_manager.genBreakpoint(None, Sim_Break_Linear, Sim_Access_Execute, ret_to, 1, 0)
                self.stack_buf_hap[ret_to] = self.context_manager.genHapIndex("Core_Breakpoint_Memop", self.stackBufHap, None, proc_break, 'stack_buf_hap')
                self.lgr.debug('dataWatch manageStackBuf added stack_buf_hap[0x%x] %d' % (ret_to, self.stack_buf_hap[ret_to]))
            else:
                #self.lgr.debug('dataWatch manageStackBuf eip 0x%x already in stack_buffers, no hap set' % ret_to)
                pass
            for index in index_list:
                self.stack_buffers[ret_to].append(index)
            #self.lgr.debug('added index %d to stack_buffers[0x%x]' % (index, ret_to))
        else:
            pass
            #self.lgr.debug('DataWatch manageStackBuf stack buffer, but return address was NONE, so buffer reuse will cause hits')

    def setRange(self, start, length, msg=None, max_len=None, back_stop=True, recv_addr=None, no_backstop=False, 
                 watch_mark=None, fd=None, is_lib=False, no_extend=False):
        ''' set a data watch range.  fd only set for readish syscalls as a way to track bytes read when simulating internal kernel buffer '''
        ''' TBD try forcing watch to maxlen '''
        if self.disabled:
            return
        if fd is not None and self.readLib is not None and self.readLib.inFun():
            ''' Within a read lib, ignore '''
            return
        if length == 0:
            self.lgr.error('dataWatch setRange called with length of zero')
            return

        if fd is not None:
            self.total_read = self.total_read + length
            if self.read_limit_trigger is not None and self.total_read >= self.read_limit_trigger and self.read_limit_callback is not None:
                self.read_limit_callback()
                if len(self.start) == 0:
                    ''' TBD seems to only make sense on first read '''
                    self.lgr.debug('dataWatch setRange over read limit, set retval to %d' % self.read_limit_trigger)
                    self.mem_utils.setRegValue(self.cpu, 'syscall_ret', self.read_limit_trigger)
                    length = self.read_limit_trigger    
                    if msg is not None:
                        msg = msg+' Count truncated to given %d bytes' % length
            if self.checkFread(start, length):
                self.lgr.debug('dataWatch setRange was fread, return for now')
                return
        if not self.use_back_stop and back_stop:
            self.use_back_stop = True
            #self.lgr.debug('DataWatch, backstop set, start data session')

        if max_len is None:
            my_len = length
        else:
            # TBD intent to handle applications that reference old buffer data, i.e., past the end of the read count, but what if 
            # read length is huge?
            if max_len > 1500:
                #self.lgr.warning('dataWatch setRange large length given %d, setting len of buffer to what we got %s' % (max_len, length)) 
                my_len = length
            else:
                #self.lgr.warning('dataWatch setRange NOT large length given %d, setting len of read buffer to that.' % (max_len)) 
                my_len = max_len

        self.lgr.debug('DataWatch set range start 0x%x watch length 0x%x actual count %d back_stop: %r total_read %d fd: %s callback: %s' % (start, 
               my_len, length, back_stop, self.total_read, str(fd), str(self.read_limit_callback)))
        end = start+(my_len-1)
        overlap = False
        if not no_extend:
            for index in range(len(self.start)):
                if self.start[index] is not None:
                    this_end = self.start[index] + (self.length[index]-1)
                    #self.lgr.debug('dataWatch setRange look for related start 0x%x end 0x%x this start 0x%x this end 0x%x' % (start, end, self.start[index], this_end))
                    if self.start[index] <= start and this_end >= end:
                        overlap = True
                        #self.lgr.debug('DataWatch setRange found overlap, skip it')
                        if start not in self.other_starts:
                            self.other_starts.append(start)
                            self.other_lengths.append(my_len)
                        break
                    elif self.start[index] >= start and this_end <= end:
                        #self.lgr.debug('DataWatch setRange found subrange, replace it with start 0x%x len %d' % (start, my_len))
                        self.start[index] = start
                        self.length[index] = my_len
                        overlap = True
                        break
                    elif start == (this_end+1):
                        self.length[index] = self.length[index]+my_len
                        #self.lgr.debug('DataWatch extending after end of range of index %d, len now %d' % (index, self.length[index]))
                        overlap = True
                        self.stopWatch()
                        self.watch(i_am_alone=True)
                        break
                    elif(start >= self.start[index] and start <= this_end) and end > this_end:
                        ''' TBD combine with above?'''
                        self.length[index] = end - self.start[index]
                        #self.lgr.debug('DataWatch extending range of index %d, len now %d' % (index, self.length[index]))
                        overlap = True
                        self.stopWatch()
                        self.watch(i_am_alone=True)
                        break
        self.lgr.debug('dataWatch overlap %r test if copymark %s' % (overlap, str(watch_mark)))
        if not overlap or self.isCopyMark(watch_mark):
            self.start.append(start)
            self.length.append(my_len)
            self.hack_reuse.append(0)
            self.cycle.append(self.cpu.cycles)
            self.mark.append(watch_mark)
            if (self.isCopyMark(watch_mark) and watch_mark.mark.sp) or (msg == 'fun result' and self.watchMarks.isStackBuf(start)):
                ''' TBD awkward method for deciding to watch function results going to memory'''
                #self.lgr.debug('dataWatch setRange is stack buffer start 0x%x' % start)
                #ret_to = self.getReturnAddr(watch_mark.mark)
                index = len(self.start)-1
                ret_to = self.getReturnAddr()
                self.manageStackBuf([index], ret_to)

            #self.lgr.debug('DataWatch adding start 0x%x, len %d cycle 0x%x' % (start, length, self.cpu.cycles))
        if msg is not None:
            if sys.version_info[0] >= 3:
                fixed = msg
            else:
                fixed = unicode(msg, errors='replace')
            # TBD why max_len and not count???  Attempt to watch reuse of input buffer, e.g., reading past end recent receive?
            if recv_addr is None:
                recv_addr = start
            self.lgr.debug('dataWatch call markCall, length %d' % length)
            ''' TBD what if fun result? e.g., checkNumericStore'''
            self.watchMarks.markCall(fixed, max_len, recv_addr=recv_addr, length=length, fd=fd, is_lib=is_lib)
            if self.prev_cycle is None:
                ''' first data read, start data session if doing coverage '''
                self.top.startDataSessions()
                self.prev_cycle = self.cpu.cycles
        if no_backstop:
            self.no_backstop.append(start)

    def stackThisHap(self, dumb, third, forth, memory):
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

            instruct = SIM_disassemble_address(self.cpu, eip, 1, 0)
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
                #self.lgr.debug('dataWatch stackBuffHap will replace %d indices' % (len(replace_index)))
                self.manageStackThis(replace_index, ret_to)
            
        else:
            #self.lgr.debug('stackThisHap eip NOT in stack_this')
            pass



    def stackBufHap(self, dumb, third, forth, memory):
        ''' Returned from function on call chain that created a stack buffer.  See
            if the stack buffer should be deleted.  Otherwise, set a hap on the
            next stack frame 
        '''
        eip = memory.logical_address
        #self.lgr.debug('stackBufHap eip 0x%x' % eip)
        if eip in self.stack_buf_hap:
            self.context_manager.genDeleteHap(self.stack_buf_hap[eip])
            self.lgr.debug('stackBufHap deleted stack_buf_hap[0x%x] %d' % (eip, self.stack_buf_hap[eip]))
            sp = self.mem_utils.getRegValue(self.cpu, 'sp')

            instruct = SIM_disassemble_address(self.cpu, eip, 1, 0)
            op2, op1 = self.decode.getOperands(instruct[1])
            new_sp = self.adjustSP(sp, instruct, op1, op2)
            if new_sp is not None:
                #self.lgr.debug('dataWatch stackBufHap adjusted sp to 0x%x' % new_sp)
                sp = new_sp

            ret_to = self.getReturnAddr()
            replace_index = []
            for range_index in self.stack_buffers[eip]:
               if range_index < len(self.read_hap):
                   if self.start[range_index] is None:
                        #self.lgr.debug('dataWatch stackBufHap  index start[%d] is None' % (range_index))
                        continue
  
                   if self.start[range_index] < sp:
                        #self.lgr.debug('dataWatch stackBufHap remove watch for index %d starting 0x%x' % (range_index, self.start[range_index]))
                        self.context_manager.genDeleteHap(self.read_hap[range_index], immediate=False)
                        self.read_hap[range_index] = None
                        self.start[range_index] = None
                   else:
                        if ret_to is not None:
                            ''' avoid trying to return from text to some library '''
                            if self.top.isMainText(eip) and not self.top.isMainText(ret_to):
                                #self.lgr.debug('dataWatch stackBufHap, start 0x%x not less than sp 0x%x, but would be return to lib from main, skip it).' % (self.start[range_index], sp))
                                pass
                            else:
                                #self.lgr.debug('dataWatch stackBufHap, start 0x%x not less than sp 0x%x, set break on next frame.' % (self.start[range_index], sp))
                                replace_index.append(range_index)
               else:
                   self.lgr.debug('dataWatch stackBufHap range_index %d out of range of read_hap whose len is %d?' % (range_index, len(self.read_hap)))
                   self.lgr.debug('read_hap has %s' % str(self.read_hap))
            self.lgr.debug('stackBufHap remove stack buf hap entry for 0x%x' % eip)
            del self.stack_buf_hap[eip] 
            del self.stack_buffers[eip] 
            if len(replace_index) > 0:
                #self.lgr.debug('dataWatch stackBuffHap will replace %d indices' % (len(replace_index)))
                self.manageStackBuf(replace_index, ret_to)
            
        else:
            self.lgr.debug('stackBufHap eip 0x%x NOT in stack_buf_hap' % eip)
            pass 

    def getReturnAddr(self):
        retval = None
        self.lgr.debug('dataWatch getReturnAddr')
        st = self.top.getStackTraceQuiet(max_frames=2, max_bytes=1000)
        if st is None:
            self.lgr.debug('getStackBase stack trace is None, wrong pid?')
            return None
        frames = st.getFrames(2)
        for frame in frames:
            if frame.ret_addr is not None:
                #self.lgr.debug('dataWatch getReturnAddr got 0x%x' % frame.ret_addr)
                retval = frame.ret_addr
                break
        if retval is None:
            self.lgr.debug('dataWatch getReturnAddr go zilch')
        return retval

    def getReturnAddrXX(self, mark):
        retval = None
        if self.cpu.architecture != 'arm': 
            bp = self.mem_utils.getRegValue(self.cpu, 'ebp')
            if bp != 0:
                ret_to_addr = bp + self.mem_utils.WORD_SIZE
                retval = self.mem_utils.readPtr(self.cpu, ret_to_addr)
        else:
            retval = self.mem_utils.readPtr(self.cpu, mark.base)
        return retval

    def close(self, fd):
        ''' called when FD is closed and we might be doing a trackIO '''
        eip = self.top.getEIP(self.cpu)
        msg = 'closed FD: %d' % fd
        self.watchMarks.markCall(msg, None, None, fd=fd)
       
    def watchFunEntries(self): 
        #self.lgr.debug('watchFunEntries, %d entries' % len(self.mem_fun_entries))
        for fun in self.mem_fun_entries:
            #self.lgr.debug('watchFunEntries, fun %s %d entries' % (fun, len(self.mem_fun_entries)))
            for eip in self.mem_fun_entries[fun]:
                if self.mem_fun_entries[fun][eip].hap is None:
                    phys_block = self.cpu.iface.processor_info.logical_to_physical(eip, Sim_Access_Execute)
                    if phys_block is None:
                        self.lgr.warning('dataWatch watchFunEntries, code at 0x%x not mapped, will not catch entry' % eip)
                    proc_break = self.context_manager.genBreakpoint(None, Sim_Break_Linear, Sim_Access_Execute, eip, 1, 0)
                    hap = self.context_manager.genHapIndex("Core_Breakpoint_Memop", self.memSomethingEntry, fun, proc_break, 'mem_fun_entry') 
                    self.mem_fun_entries[fun][eip].hap = hap
                    #self.lgr.debug('dataWatch watchFunEntries set fun entry break on 0x%x for fun %s' % (eip, fun))
        if self.destroy_entry is not None and self.destroy_hap is None:
            #self.lgr.debug('dataWatch watchFunEntries add destroy entry hap')
            proc_break = self.context_manager.genBreakpoint(None, Sim_Break_Linear, Sim_Access_Execute, self.destroy_entry, 1, 0)
            self.destroy_hap = self.context_manager.genHapIndex("Core_Breakpoint_Memop", self.destroyEntry, None, proc_break, 'destroy_entry') 

    def watch(self, show_cmp=False, break_simulation=None, i_am_alone=False, no_backstop=False):
        ''' set the data watches, e.g., after a reverse execution is complete.'''
        #self.lgr.debug('DataWatch watch show_cmp: %r cpu: %s length of watched buffers is %d length of read_hap %d' % (show_cmp, self.cpu.name, 
        #   len(self.start), len(self.read_hap)))
        retval = False
        self.show_cmp = show_cmp         
        if break_simulation is not None:
            self.break_simulation = break_simulation         
        #self.lgr.debug('watch alone %r break_sim %s  use_back %s  no_back %s' % (i_am_alone, str(break_simulation), str(self.use_back_stop), str(no_backstop)))
        if self.back_stop is not None and not self.break_simulation and self.use_back_stop and not no_backstop:
            self.back_stop.setFutureCycle(self.back_stop_cycles)
        self.watchFunEntries()
        if len(self.start) > 0:
            if i_am_alone:
                SIM_run_alone(self.setBreakRange, i_am_alone)
            else:
                self.setBreakRange(i_am_alone)
            retval = True

        for re_watch in self.re_watch_list:
            re_watch.setMapBreakRange()

        self.setStackThisHaps()

        return retval

    def showCmp(self, addr): 
        eip = self.top.getEIP(self.cpu)
        instruct = SIM_disassemble_address(self.cpu, eip, 1, 0)
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
        ''' stop data watches, e.g., in prep for reverse execution '''
        #self.lgr.debug('dataWatch stopWatch immediate: %r len of start is %d len of read_hap: %d' % (immediate, len(self.start), len(self.read_hap)))
        for index in range(len(self.start)):
            if self.start[index] is None:
                continue
            if index < len(self.read_hap):
                if self.read_hap[index] is not None:
                    #self.lgr.debug('dataWatch stopWatch delete read_hap %d' % self.read_hap[index])
                    self.context_manager.genDeleteHap(self.read_hap[index], immediate=immediate)
            else:
                self.lgr.debug('dataWatch stopWatch index %d not in read_hap len is %d ' % (index, len(self.read_hap)))
                pass
        #self.lgr.debug('DataWatch stopWatch removed read haps')
        del self.read_hap[:]
        if break_simulation is not None: 
            self.break_simulation = break_simulation
            self.lgr.debug('DataWatch stopWatch break_simulation %r' % break_simulation)
        self.deleteReturnHap(None)

        if not leave_fun_entries:
            for fun in self.mem_fun_entries:
                for eip in self.mem_fun_entries[fun]:
                    if self.mem_fun_entries[fun][eip].hap is not None:
                        self.context_manager.genDeleteHap(self.mem_fun_entries[fun][eip].hap, immediate=immediate)
                        self.mem_fun_entries[fun][eip].hap = None
            if self.destroy_hap is not None:
                self.context_manager.genDeleteHap(self.destroy_hap, immediate=immediate)
                self.destroy_hap = None
      
        if self.back_stop is not None:
            self.back_stop.clearCycle()
        self.pending_call = False
        for re_watch in self.re_watch_list:
            re_watch.stopMapWatch(immediate=immediate)

        for eip in self.stack_buf_hap:
            self.lgr.debug('DataWatch stopWatch remove stack_buf_hap[0x%x] %d' % (eip, self.stack_buf_hap[eip]))
            self.context_manager.genDeleteHap(self.stack_buf_hap[eip])

        self.stopStackThisHaps(immediate=immediate)
        #if self.finish_check_move_hap is not None:
        #    self.lgr.debug('DataWatch stopWatch delete finish_check_move_hap')
        #    self.context_manager.genDeleteHap(self.finish_check_move_hap, immediate=True)
        #    self.finish_check_move_hap = None
        if self.call_stop_hap is not None:
            SIM_run_alone(self.delStopHap, self.call_stop_hap)
            self.call_stop_hap = None

    def resetWatch(self):
        #self.lgr.debug('dataWatch resetWatch')
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

    def kernelReturnHap(self, kernel_return_info, third, forth, memory):
        eax = self.mem_utils.getRegValue(self.cpu, 'syscall_ret')
        eax = self.mem_utils.getSigned(eax)
        #self.top.showHaps()
        dum_cpu, cur_addr, comm, pid = self.task_utils.currentProcessInfo(self.cpu)
        #frame, cycles = self.rev_to_call.getRecentCycleFrame(pid)
        frame, cycles = self.rev_to_call.getPreviousCycleFrame(pid)
        eip = self.top.getEIP(self.cpu)
        #self.lgr.debug('kernelReturnHap, pid:%d (%s) eip: 0x%x retval 0x%x  addr: 0x%x context: %s compat32: %r cur_cycles: 0x%x, recent cycle: 0x%x' % (pid, comm, eip, eax, 
        #    kernel_return_info.addr, str(self.cpu.current_context), self.compat32, self.cpu.cycles, cycles))
        #self.lgr.debug(taskUtils.stringFromFrame(frame))
        if kernel_return_info.op_type == Sim_Trans_Load:
            if 'ss' in frame:
                #self.lgr.debug('frame has ss: %s' % frame['ss'].getString())
                callnum = 102
                call = net.callname[frame['param1']].lower()
                write_fd = frame['ss'].fd
                self.watchMarks.kernel(kernel_return_info.addr, eax, write_fd, callnum)
            else:
                callnum = self.mem_utils.getCallNum(self.cpu)
                call = self.task_utils.syscallName(callnum, self.compat32)
                write_fd = frame['param1']
                self.watchMarks.kernel(kernel_return_info.addr, eax, write_fd, callnum)

            read_fd = self.getPipeReader(str(write_fd))
            if read_fd is not None:
                self.lgr.debug('dataWatch got pipe reader %d from write_fd %d, set read hap.' % (read_fd, write_fd))
                SIM_run_alone(self.runToIOAlone, read_fd)
            else:
                self.lgr.debug('dataWatch no pipe reader found for fd %d' % write_fd)
        else:
            self.watchMarks.kernelMod(kernel_return_info.addr, eax, frame)
 
        if self.back_stop is not None and not self.break_simulation and self.use_back_stop:
            self.back_stop.setFutureCycle(self.back_stop_cycles)
        SIM_run_alone(self.deleteReturnHap, None)
        self.lgr.debug('dataWatch kernelReturn reset watch')
        ''' TBD was true'''
        self.watch(i_am_alone=False)

    def kernelReturn(self, kernel_return_info):
        if self.top.getSharedSyscall().callbackPending():
            return
        #self.lgr.debug('kernelReturn for addr 0x%x optype %s' % (kernel_return_info.addr, str(kernel_return_info.op_type))) 
        ''' hack TBD '''
        self.top.getSharedSyscall().setcallback(self.kernelReturnHap, kernel_return_info)

        #return

        if not self.break_simulation:
            #self.stopWatch()
            self.stopWatch(leave_fun_entries = True)
        if self.cpu.architecture == 'arm':
            cell = self.top.getCell()
            proc_break = self.context_manager.genBreakpoint(None, Sim_Break_Linear, Sim_Access_Execute, self.param.arm_ret, 1, 0)
            self.return_hap = self.context_manager.genHapIndex("Core_Breakpoint_Memop", self.kernelReturnHap, 
                 kernel_return_info, proc_break, 'kernel_return_hap')
        else:
            #self.lgr.debug('Only ARM kernel return handled for now') 
            #self.watch()
            cell = self.top.getCell()
            if self.param.sysexit is not None:
                exit_addr = self.param.sysexit
            elif self.param.iretd is not None:
                exit_addr = self.param.iretd
            else:
                self.lgr.error('dataWatch kernelReturn could not find kernel exit address')
                return
            proc_break = self.context_manager.genBreakpoint(None, Sim_Break_Linear, Sim_Access_Execute, exit_addr, 1, 0)
            self.return_hap = self.context_manager.genHapIndex("Core_Breakpoint_Memop", self.kernelReturnHap, 
                 kernel_return_info, proc_break, 'kernel_return_hap')
       
      
    def checkNumericStore(self): 
        if self.mem_something.called_from_ip is not None:
            ip = self.mem_something.called_from_ip
            instruct = SIM_disassemble_address(self.cpu, ip, 1, 0)
            next_ip = ip + instruct[0]
            next_instruct = SIM_disassemble_address(self.cpu, next_ip, 1, 0)
            if next_instruct[1].startswith('str'):
                op2, op1 = self.decode.getOperands(next_instruct[1])
                if op1 == self.mem_utils.regs['syscall_ret']:
                    #self.lgr.debug('dataWatch checkNumericStore found %s' % next_instruct[1])
                    addr = self.decode.getAddressFromOperand(self.cpu, op2, self.lgr)
                    if addr is not None:
                        count = self.mem_utils.WORD_SIZE
                        if next_instruct[1].startswith('strh'):
                            count = int(self.mem_utils.WORD_SIZE/2)
                        self.setRange(addr, count, 'fun result')
                        self.move_cycle = self.cpu.cycles
          
     
    def startUndoAlone(self, dumb):
        self.undo_hap = SIM_hap_add_callback("Core_Simulation_Stopped", self.undoHap, self.mem_something)
        self.watchMarks.undoMark()
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
        SIM_run_alone(self.top.restoreDebugBreaks, True)
        #self.top.restoreDebugBreaks(was_watching=True)
        if self.mem_something.fun == 'memcpy' or self.mem_something.fun == 'mempcpy' or \
           self.mem_something.fun == 'j_memcpy' or self.mem_something.fun == 'memmove':
            self.lgr.debug('dataWatch returnHap, return from %s src: 0x%x dest: 0x%x count %d ' % (self.mem_something.fun, self.mem_something.src, 
                   self.mem_something.dest, self.mem_something.count))
            if self.mem_something.count == 0:
                self.lgr.error('got zero count for memcpy')
                SIM_break_simulation('mempcpy')
                return
            skip_it = False          
            if self.mem_something.op_type == Sim_Trans_Load:
                #buf_start = self.findRange(self.mem_something.src)
                buf_index = self.findRangeIndex(self.mem_something.src)
                if buf_index is None:
                    self.lgr.debug('dataWatch buf_start for 0x%x is none in memcpyish?' % (self.mem_something.src))
                    buf_start = 0
                    #SIM_break_simulation('mempcpy')
                    #return
                else:
                    buf_start = self.start[buf_index]
                    if self.length[buf_index] < self.mem_something.count:
                        self.lgr.debug('dataWatch returnHap copy more than our buffer, truncate to %d' % self.length[buf_index])
                        self.mem_something.truncated = self.mem_something.count 
                        self.mem_something.count = self.length[buf_index]
            else:
                self.lgr.debug('returnHap copy not a Load, first see if src is a buf')
                buf_start = self.findRange(self.mem_something.src)
                if buf_start is None:
                    self.lgr.debug('dataWatch returnHap, overwrite buffer with unwatched content.')
                    buf_index = self.findRangeIndex(self.mem_something.dest)
                    if buf_index is not None:
                        if self.start[buf_index] == self.mem_something.dest and self.length[buf_index] <= self.mem_something.count:
                            self.lgr.debug('dataWatch returnHap, overwrite buffer exact match, remove the buffer')
                            if buf_index in self.read_hap:
                                self.context_manager.genDeleteHap(self.read_hap[buf_index], immediate=False)
                                self.read_hap[buf_index] = None
                            self.start[buf_index] = None
                        else:
                            self.lgr.warning('dataWatch returnHap, TBD, overwrite buffer exact match, but not a match.  start 0x%x len %d' % (self.start[buf_index], 
                                   self.length[buf_index]))
                    else:
                        self.lgr.debug('dataWatch returnHap memcpy, but nothing we care about')
                        skip_it = True
            if not skip_it:
                mark = self.watchMarks.copy(self.mem_something.src, self.mem_something.dest, self.mem_something.count, buf_start, 
                    self.mem_something.op_type, truncated=self.mem_something.truncated)
                if self.mem_something.op_type == Sim_Trans_Load and self.mem_something.count > 0:
                    #self.lgr.debug('returnHap set range for copy')
                    self.setRange(self.mem_something.dest, self.mem_something.count, None, watch_mark=mark) 
                    self.setBreakRange()
        elif self.mem_something.fun == 'memcmp':
            str1 = self.mem_something.dest
            str2 = self.mem_something.src
            buf_start = self.findRange(str1)
            if buf_start is None:
                tmp = str1
                str1 = str2
                str2 = tmp
                buf_start = self.findRange(str1)
            self.watchMarks.compare(self.mem_something.fun, str1, str2, self.mem_something.count, buf_start)
            #self.lgr.debug('dataWatch returnHap, return from %s compare: 0x%x  to: 0x%x count %d ' % (self.mem_something.fun, self.mem_something.src, 
            #       self.mem_something.dest, self.mem_something.count))
        elif self.mem_something.fun in ['strcmp', 'strncmp', 'strcasecmp', 'strncasecmp', 'xmlStrcmp', 'strpbrk', 'strspn', 'strcspn']: 
            buf_start = self.findRange(self.mem_something.dest)
            self.watchMarks.compare(self.mem_something.fun, self.mem_something.dest, self.mem_something.src, self.mem_something.count, buf_start)
            #self.lgr.debug('dataWatch returnHap, return from %s  0x%x  to: 0x%x count %d ' % (self.mem_something.fun, 
            #       self.mem_something.src, self.mem_something.dest, self.mem_something.count))
        elif self.mem_something.fun in ['strchr', 'strrchr']:
            buf_start = self.findRange(self.mem_something.src)
            if self.cpu.architecture != 'arm':
                self.lgr.debug('datawatch strchr confusion, mem_something.the_chr is 0x%x' % self.mem_something.the_chr)
                #the_chr = self.mem_utils.readByte(self.cpu, self.mem_something.the_chr)
                the_chr = self.mem_something.the_chr
            else:
                the_chr = self.mem_something.the_chr
            self.watchMarks.strchr(self.mem_something.src, the_chr, self.mem_something.count)
            #self.lgr.debug('dataWatch returnHap, return from %s strchr 0x%x count %d ' % (self.mem_something.fun, 
            #       self.mem_something.the_chr, self.mem_something.count))
        elif self.mem_something.fun in ['strtoul', 'strtoull', 'strtol', 'strtoll', 'strtoq', 'atoi']:
            self.watchMarks.strtoul(self.mem_something.fun, self.mem_something.src)
            ''' see if result is stored in memory '''
            self.checkNumericStore()
            

        elif self.mem_something.fun == 'strcpy' or self.mem_something.fun == 'strncpy':
            #self.lgr.debug('dataWatch returnHap, strcpy return from %s src: 0x%x dest: 0x%x count %d ' % (self.mem_something.fun, self.mem_something.src, 
            #       self.mem_something.dest, self.mem_something.count))
            buf_start = self.findRange(self.mem_something.src)
            if buf_start is None:
                ''' strcpy into the buffer? TBD, reused buffer?'''
                self.lgr.debug('dataWatch buf_start for 0x%x is none in strcpy?' % (self.mem_something.src))
                pass
            mark = self.watchMarks.copy(self.mem_something.src, self.mem_something.dest, self.mem_something.count, buf_start, self.mem_something.op_type, 
                       strcpy=True)
            if buf_start is not None and self.mem_something.count > 0:
                self.setRange(self.mem_something.dest, self.mem_something.count, None, watch_mark = mark) 
                self.setBreakRange()
        elif self.mem_something.fun == 'memset':
            #self.lgr.debug('dataWatch returnHap, return from memset dest: 0x%x count %d ' % (self.mem_something.dest, self.mem_something.count))
            buf_index = self.findRangeIndex(self.mem_something.dest)
            if buf_index is not None:
                #self.lgr.debug('dataWatch returnHap memset on one of our buffers')
                if self.start[buf_index] == self.mem_something.dest and self.length[buf_index] <= self.mem_something.count:
                    self.lgr.debug('dataWatch returnHap memset is exact match, remove buffer')
                    if buf_index in self.read_hap:
                        self.context_manager.genDeleteHap(self.read_hap[buf_index], immediate=False)
                        self.read_hap[buf_index] = None
                    self.start[buf_index] = None
                else:
                    self.lgr.warning('dataWatch returnHap memset but not match, TBD fix this buf start 0x%x  len %d' % (self.start[buf_index], self.length[buf_index]))
                self.watchMarks.memset(self.mem_something.dest, self.mem_something.count, self.start[buf_index])
        elif self.mem_something.fun == 'strdup':
            if self.cpu.architecture == 'arm':
                self.mem_something.dest = self.mem_utils.getRegValue(self.cpu, 'r0')
            else: 
                self.mem_something.dest = self.mem_utils.getRegValue(self.cpu, 'eax')
            #self.lgr.debug('dataWatch returnHap, strdup return from %s src: 0x%x dest: 0x%x count %d ' % (self.mem_something.fun, self.mem_something.src, 
            #       self.mem_something.dest, self.mem_something.count))
            if self.mem_something.op_type == Sim_Trans_Load:
                buf_start = self.findRange(self.mem_something.src)
                if buf_start is None:
                    self.lgr.error('dataWatch buf_start for 0x%x is none in strdup?' % (self.mem_something.src))
            else:
                buf_start = self.findRange(self.mem_something.dest)
            mark = self.watchMarks.copy(self.mem_something.src, self.mem_something.dest, self.mem_something.count, buf_start, self.mem_something.op_type)
            if self.mem_something.op_type == Sim_Trans_Load and self.mem_something.count > 0:
                self.setRange(self.mem_something.dest, self.mem_something.count, None, watch_mark=mark) 
                self.setBreakRange()
        elif self.mem_something.fun == 'sscanf':
            eax = self.mem_utils.getRegValue(self.cpu, 'syscall_ret')
            param_count = self.mem_utils.getSigned(eax)
            self.lgr.debug('dataWatch returnHap, sscanf return from sscanf src 0x%x param_count %d' % (self.mem_something.src, param_count))
            buf_start = self.findRange(self.mem_something.src)
            if param_count > 0:
                for i in range(param_count):
                    mark = self.watchMarks.sscanf(self.mem_something.src, self.mem_something.dest_list[i], self.mem_something.count, buf_start)
                    self.setRange(self.mem_something.dest_list[i], self.mem_something.count, None, watch_mark=mark) 
                self.setBreakRange()
            else:
                self.lgr.debug('dataWatch returnHap sscanf returned error')
                self.watchMarks.sscanf(self.mem_something.src, None, None, buf_start)
        elif self.mem_something.fun == 'strlen':
            self.lgr.debug('dataWatch returnHap, return from %s src: 0x%x count %d ' % (self.mem_something.fun, self.mem_something.src, 
                   self.mem_something.count))
            self.watchMarks.strlen(self.mem_something.src, self.mem_something.count)
        elif self.mem_something.fun in ['vsnprintf', 'sprintf', 'snprintf']:
            if self.mem_something.dest is None:
                self.lgr.debug('dataWatch %s dest is None' % self.mem_something.fun)
            self.mem_something.src = self.mem_something.addr
            buf_start = self.findRange(self.mem_something.src)
            self.mem_something.count = self.getStrLen(self.mem_something.dest)        
            mark = self.watchMarks.sprintf(self.mem_something.fun, self.mem_something.addr, self.mem_something.dest, self.mem_something.count, buf_start)
            self.lgr.debug('dataWatch returnHap, return from %s src: 0x%x dst: 0x%x count %d ' % (self.mem_something.fun, self.mem_something.src, 
                   self.mem_something.dest, self.mem_something.count))
            self.setRange(self.mem_something.dest, self.mem_something.count, None, watch_mark=mark) 
            self.setBreakRange()
        elif self.mem_something.fun in ['fprintf', 'printf', 'syslog']:
            self.lgr.debug('dataWatch returnHap, return from %s src: 0x%x ' % (self.mem_something.fun, self.mem_something.src))
            self.watchMarks.fprintf(self.mem_something.fun, self.mem_something.src)
        elif self.mem_something.fun == 'fwrite' or self.mem_something.fun == 'IO_do_write':
            self.lgr.debug('dataWatch returnHap, return from %s src: 0x%x ' % (self.mem_something.fun, self.mem_something.src))
            self.watchMarks.fwrite(self.mem_something.fun, self.mem_something.src, self.mem_something.count)
        elif self.mem_something.fun == 'glob':
            self.lgr.debug('dataWatch returnHap, return from %s src: 0x%x ' % (self.mem_something.fun, self.mem_something.src))
            self.mem_something.count = self.getStrLen(self.mem_something.src)
            self.watchMarks.glob(self.mem_something.fun, self.mem_something.src, self.mem_something.count)
        elif self.mem_something.fun == 'inet_addr':
            self.lgr.debug('dataWatch returnHap, return from %s IP: %s count %d ' % (self.mem_something.fun, self.mem_something.the_string, 
                   self.mem_something.count))
            self.watchMarks.inet_addr(self.mem_something.src, self.mem_something.count, self.mem_something.the_string)
        elif self.mem_something.fun == 'inet_ntop':
            self.mem_something.count = self.getStrLen(self.mem_something.dest)        
            self.mem_something.the_string = self.mem_utils.readString(self.cpu, self.mem_something.dest, self.mem_something.count)
            self.lgr.debug('dataWatch returnHap, return from %s IP: %s count %d ' % (self.mem_something.fun, self.mem_something.the_string, 
                   self.mem_something.count))
            mark = self.watchMarks.inet_ntop(self.mem_something.dest, self.mem_something.count, self.mem_something.the_string)
            self.setRange(self.mem_something.dest, self.mem_something.count, None, watch_mark=mark) 
            self.setBreakRange()
        elif self.mem_something.fun == 'fgets':
            buf_start = self.findRange(self.mem_something.src)
            self.mem_something.dest = self.mem_utils.getRegValue(self.cpu, 'syscall_ret')
            mark = self.watchMarks.fgetsMark(self.mem_something.fun, self.mem_something.src, self.mem_something.dest, self.mem_something.count, buf_start)
            self.lgr.debug('dataWatch returnHap, return from %s src: 0x%x dst: 0x%x count %d ' % (self.mem_something.fun, self.mem_something.src, 
                   self.mem_something.dest, self.mem_something.count))
            if self.mem_something.count > 0:
                self.setRange(self.mem_something.dest, self.mem_something.count, None, watch_mark=mark) 
                self.setBreakRange()
            self.recent_fgets = self.mem_something.dest
        elif self.mem_something.fun in ['getenv', 'regexec', 'ostream_insert']:
            mark = self.watchMarks.mscMark(self.mem_something.fun, self.mem_something.addr)
        elif self.mem_something.fun.startswith('string_basic'):
            if self.mem_something.ret_addr_addr is not None:
                self.mem_something.dest = self.mem_utils.readPtr(self.cpu, self.mem_something.ret_addr_addr)
                #self.mem_something.count = self.getStrLen(self.mem_something.src)        
                self.lgr.debug('dataWatch returnHap, return from %s src: 0x%x dst: 0x%x count: %d ' % (self.mem_something.fun, self.mem_something.src, self.mem_something.dest,
                   self.mem_something.count))
                buf_start = self.findRange(self.mem_something.src)
                mark = self.watchMarks.stringMark(self.mem_something.fun, self.mem_something.src, self.mem_something.dest, self.mem_something.count, buf_start)
                self.lgr.debug('dataWatch returnHap, call setRange dest 0x%x  count %d' % (self.mem_something.dest, self.mem_something.count))
                if self.mem_something.count > 0:
                    self.setRange(self.mem_something.dest, self.mem_something.count, None, watch_mark=mark) 
                    self.setBreakRange()
                    self.watchStackObject(self.mem_something.ret_addr_addr)

        elif self.mem_something.fun.startswith('string'):
            skip_it = False
            obj_ptr = self.mem_utils.getRegValue(self.cpu, 'syscall_ret')
            self.mem_something.dest = self.mem_utils.readPtr(self.cpu, obj_ptr)
            if self.mem_something.dest == self.mem_something.src:
                self.lgr.debug('dataWatch returnHap string src same as dest, bail')
            else:
                if self.cpu.architecture == 'arm':
                    r1val = self.mem_utils.getRegValue(self.cpu, 'r1')
                    if r1val == self.mem_something.src:
                        self.mem_something.count = self.getStrLen(self.mem_something.src)        
                        self.lgr.debug('dataWatch string, r1 unchanged, use src length of %d' % self.mem_something.count)
                    elif r1val < 5000:
                        self.mem_something.count = r1val
                    else:
                        self.lgr.warning('dataWatch string return size %d, confused? skipping' % r1val)
                        skip_it = True
                        #SIM_break_simulation('remove this')
                        #return
                else:
                    ''' TBD is this right for x86? '''
                    self.mem_something.count = self.getStrLen(self.mem_something.src)        
                    self.lgr.debug('dataWatch string return size x86 got %d' % self.mem_something.count)
                if not skip_it:
                    self.lgr.debug('dataWatch returnHap, return from %s src: 0x%x dst: 0x%x count: %d ' % (self.mem_something.fun, self.mem_something.src, self.mem_something.dest,
                       self.mem_something.count))
                    buf_start = self.findRange(self.mem_something.src)
                    mark = self.watchMarks.stringMark(self.mem_something.fun, self.mem_something.src, self.mem_something.dest, self.mem_something.count, buf_start)
                    self.lgr.debug('dataWatch returnHap, call setRange dest 0x%x  count %d' % (self.mem_something.dest, self.mem_something.count))
                    if self.mem_something.count > 0:
                        self.setRange(self.mem_something.dest, self.mem_something.count, None, watch_mark=mark) 
                        self.setBreakRange()
                        self.watchStackObject(obj_ptr)
        elif self.mem_something.fun == 'str':
            ''' TBD crude copy, clean up'''
            skip_it = False
            obj_ptr = self.mem_utils.getRegValue(self.cpu, 'syscall_ret')
            self.mem_something.dest = self.mem_utils.readPtr(self.cpu, obj_ptr)
            if self.cpu.architecture == 'arm':
                r1val = self.mem_utils.getRegValue(self.cpu, 'r1')
                if r1val == self.mem_something.src:
                    self.mem_something.count = self.getStrLen(self.mem_something.src)        
                    self.lgr.debug('dataWatch string, r1 unchanged, use src length of %d' % self.mem_something.count)
                elif r1val < 5000:
                    self.mem_something.count = r1val
                else:
                    self.lgr.warning('dataWatch string return size %d, confused? skipping' % r1val)
                    skip_it = True
            else:
                ''' TBD is this right for x86? '''
                self.lgr.warning('dataWatch str return size not yet tested on x86')
                self.mem_something.count = 1
            if not skip_it:
                self.lgr.debug('dataWatch returnHap, return from %s src: 0x%x dst: 0x%x count: %d ' % (self.mem_something.fun, self.mem_something.src, self.mem_something.dest,
                   self.mem_something.count))
                buf_start = self.findRange(self.mem_something.src)
                mark = self.watchMarks.stringMark(self.mem_something.fun, self.mem_something.src, self.mem_something.dest, self.mem_something.count, buf_start)
                if self.mem_something.count > 0:
                    self.setRange(self.mem_something.dest, self.mem_something.count, None, watch_mark=mark) 
                    self.setBreakRange()
                    self.watchStackObject(obj_ptr)
        elif self.mem_something.fun == 'replace_safe':
            ''' TBD different than replace? '''
            skip_it = False
            obj_ptr = self.mem_utils.getRegValue(self.cpu, 'syscall_ret')
            self.mem_something.dest = self.mem_utils.readPtr(self.cpu, obj_ptr)
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
            self.mem_something.dest = self.mem_utils.readPtr(self.cpu, obj_ptr)
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
            self.mem_something.dest = self.mem_utils.readPtr(self.cpu, obj_ptr)
            self.lgr.debug('dataWatch returnHap, return from %s src: 0x%x dst: 0x%x length: %d ' % (self.mem_something.fun, self.mem_something.src, self.mem_something.dest,
               self.mem_something.length))
            buf_start = self.findRange(self.mem_something.src)
            mark = self.watchMarks.appendMark(self.mem_something.fun, self.mem_something.src, self.mem_something.dest, self.mem_something.length, buf_start)
            if self.mem_something.length > 0:
                self.setRange(self.mem_something.dest, self.mem_something.length, None, watch_mark=mark) 
                self.setBreakRange()
        elif self.mem_something.fun.startswith('assign'):
            obj_ptr = self.mem_utils.getRegValue(self.cpu, 'syscall_ret')
            dest = self.mem_utils.readPtr(self.cpu, obj_ptr)
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
        elif self.mem_something.fun == 'charLookup':
            if self.mem_something.ret_addr_addr is None:
                self.lgr.debug('dataWatch returnHap charLookup ret_addr_addr is None')
                return
            elif self.mem_something.addr is None:
                self.lgr.debug('dataWatch returnHap charLookup addr is None')
                return
            else:
                self.lgr.debug('dataWatch returnHap charLookup ret_addr_addr is 0x%x' % self.mem_something.ret_addr_addr)
            retval = self.mem_utils.getRegValue(self.cpu, 'syscall_ret')
            return_ptr = self.mem_utils.readPtr(self.cpu, self.mem_something.ret_addr_addr)
            length = 0
            if retval == 0 and return_ptr is not None:
                self.lgr.debug('dataWatch returnHap charLookup nothing found return_ptr is 0x%x' % return_ptr)
                end_ptr = self.mem_utils.readPtr(self.cpu, return_ptr)
                length = end_ptr - self.mem_something.addr
                msg = 'Not found. Search chars: %s  found: %s' % (self.mem_something.re_watch.getSearchChars(), ' '.join(self.mem_something.re_watch.getFoundChars()))
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
                found_ptr = self.mem_utils.readPtr(self.cpu, return_ptr)
                if found_ptr is None:
                    msg = 'charLookuperror could not read found_ptr from 0x%x' % return_ptr
                else:
                    length = found_ptr - self.mem_something.addr
                    range_len = len(self.start)
                    ''' TBD wag '''
                    #block_start = return_ptr + 0x20
                    #self.setRange(block_start, 0x20)
                    #if range_len < len(self.start):
                    #    ''' added the range, note it is a char pointer '''
                    #    self.char_ptrs.append(range_len)
                    msg = 'Match found. Search chars: %s  found: %s' % (self.mem_something.re_watch.getSearchChars(), ' '.join(self.mem_something.re_watch.getFoundChars()))
                    self.lgr.debug('dataWatch returnHap charLookup addr: 0x%x match found return_ptr is 0x%x found_ptr 0x%x length %d' % (self.mem_something.addr,
                       return_ptr, found_ptr, length))
                self.lgr.debug(msg)
            self.watchMarks.charLookupMark(self.mem_something.addr, msg, length)
            self.mem_something.re_watch.stopMapWatch()
            
        # Begin XML
        elif self.mem_something.fun == 'xmlGetProp':
            self.lgr.debug('dataWatch returnHap, return from %s string: %s count %d ' % (self.mem_something.fun, self.mem_something.the_string, 
                   self.mem_something.count))
            if self.cpu.architecture == 'arm':
                self.mem_something.dest = self.mem_utils.getRegValue(self.cpu, 'r0')
            else:
                self.mem_something.dest = self.mem_utils.readPtr(self.cpu, sp)
            
            self.watchMarks.xmlGetProp(self.mem_something.src, self.mem_something.count, self.mem_something.the_string, self.mem_something.dest)
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
            self.setBreakRange()
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
            self.lgr.debug('dataWatch returnHap eip: 0x%x, return from iterator %s src: 0x%x ' % (eip, self.mem_something.fun, self.mem_something.src))
            buf_start = self.findRange(self.mem_something.src)
            self.watchMarks.iterator(self.mem_something.fun, self.mem_something.src, buf_start)
        elif self.mem_something.fun not in no_stop_funs and self.mem_something.addr is not None:
            self.lgr.error('dataWatch returnHap no handler for %s' % self.mem_something.fun)
        #SIM_break_simulation('return hap')
        #return
        self.lgr.debug('dataWatch returnHap call watch')
        self.watch(i_am_alone=True)
        
        ''' See if this return should result in deletion of temp stack buffers '''
        self.stackBufHap(None, None, None, memory)
        self.lgr.debug('dataWatch returnHap done')
         

    class MemCallRec():
        def __init__(self, hap, ret_addr_offset, eip):
            self.hap = hap
            self.ret_addr_offset = ret_addr_offset
            self.eip = eip

    def destroyEntry(self, dumb, third, forth, memory):
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

    def memSomethingEntry(self, fun, third, forth, memory):
        eip = memory.logical_address
        if eip in self.skip_entries:
            return
        if self.pending_call:
            self.lgr.debug('dataWatch memSomethingEntry but pending call, bail')
            return
        cpu, cur_addr, comm, pid = self.task_utils.currentProcessInfo(self.cpu)
        self.lgr.debug('memSomethingEntry, pid:%d fun %s eip 0x%x cycle: 0x%x' % (pid, fun, eip, self.cpu.cycles))
        if fun not in self.mem_fun_entries or eip not in self.mem_fun_entries[fun] or self.mem_fun_entries[fun][eip].hap is None:
            self.lgr.debug('memSomethingEntry, fun %s eip 0x%x not in mem_fun_entries haps' % (fun, eip))
            return
        ret_to = self.getReturnAddr()
        if ret_to is not None and not self.top.isMainText(ret_to):
            self.lgr.debug('memSomethingEntry, fun %s called from 0x%x, not main text' % (fun, ret_to))
            return
        sp = self.mem_utils.getRegValue(self.cpu, 'sp')
        if self.cpu.architecture != 'arm':
            ret_addr = self.mem_utils.readPtr(self.cpu, sp)
            #self.lgr.debug('memSomethingEntry, ret_addr 0x%x' % (ret_addr))
        elif self.mem_fun_entries[fun][eip].ret_addr_offset is not None:
                addr_of_ret_addr = sp - self.mem_fun_entries[fun][eip].ret_addr_offset
                ret_addr = self.mem_utils.readPtr(self.cpu, addr_of_ret_addr)
                if ret_addr == 0:
                    ret_addr = self.mem_utils.getRegValue(self.cpu, 'lr')
                    self.lgr.warning('dataWatch memSomethingEntry got zero for ret_addr.  addr_of_addr: 0x%x.  Assume arm and use lr of 0x%x instead' % (addr_of_ret_addr, ret_addr))
                else:
                    lr = self.mem_utils.getRegValue(self.cpu, 'lr')
                    self.lgr.debug('memSomethingEntry, addr_of_ret_addr 0x%x, ret_addr 0x%x, but lr is 0x%x' % (addr_of_ret_addr, ret_addr, lr))
        else: 
            ret_addr = self.mem_utils.getRegValue(self.cpu, 'lr')
            self.lgr.debug('memSomthingEntry ARM ret_addr_offset is None, use lr value of 0x%x' % ret_addr)
        self.mem_something = MemSomething(fun, eip, None, ret_addr, None, None, None, None, None, None, None)
        #                                     (fun, addr, ret_ip, src, dest, count, called_from_ip, op_type, length, start, ret_addr_addr=None, run=False, trans_size=None): 
        SIM_run_alone(self.getMemParams, False)


    def get4CallParams(self, sp):
        retval1 = None
        retval2 = None
        retval3 = None
        retval4 = None
        if self.cpu.architecture == 'arm':
            retval1 = self.mem_utils.getRegValue(self.cpu, 'r0')
            retval2 = self.mem_utils.getRegValue(self.cpu, 'r1')
            retval3 = self.mem_utils.getRegValue(self.cpu, 'r2')
            retval4 = self.mem_utils.getRegValue(self.cpu, 'r3')
        else:
            retval1 = self.mem_utils.readPtr(self.cpu, sp)
            retval2 = self.mem_utils.readPtr(self.cpu, sp+self.mem_utils.WORD_SIZE)
            retval3 = self.mem_utils.readWord32(self.cpu, sp+2*self.mem_utils.WORD_SIZE)
            retval4 = self.mem_utils.readWord32(self.cpu, sp+3*self.mem_utils.WORD_SIZE)
        return retval1, retval2, retval3, retval4

    def getCallParams(self, sp):
        retval1 = None
        retval2 = None
        retval3 = None
        if self.cpu.architecture == 'arm':
            retval1 = self.mem_utils.getRegValue(self.cpu, 'r0')
            retval2 = self.mem_utils.getRegValue(self.cpu, 'r1')
            retval3 = self.mem_utils.getRegValue(self.cpu, 'r2')
        elif self.top.isWindows():
            retval1 = self.mem_utils.getRegValue(self.cpu, 'rcx')
            retval2 = self.mem_utils.getRegValue(self.cpu, 'rdx')
            retval3 = self.mem_utils.getRegValue(self.cpu, 'r8')
        else:
            retval1 = self.mem_utils.readPtr(self.cpu, sp)
            retval2 = self.mem_utils.readPtr(self.cpu, sp+self.mem_utils.WORD_SIZE)
            retval3 = self.mem_utils.readWord32(self.cpu, sp+2*self.mem_utils.WORD_SIZE)
        return retval1, retval2, retval3

    def getMemParams(self, data_hit):
            ''' data_hit is true if a read hap led to this call.  otherwise we simply broke on entry to 
                the memcpy-ish routine '''
            self.lgr.debug('dataWatch getMemParams, data_hit: %r' % data_hit)
            skip_fun = False
            self.watchMarks.registerCallCycle();
            ''' assuming we are a the call to a memsomething, get its parameters '''
            sp = self.mem_utils.getRegValue(self.cpu, 'sp')
            eip = self.top.getEIP(self.cpu)
            if data_hit:
                next_instruct = self.cpu.cycles+1
                status = SIM_simics_is_running() 
                self.lgr.debug('dataWatch getMemParams, try skipToTest to get to 0x%x simics running? %r' % (next_instruct, status)) 
                if not resimUtils.skipToTest(self.cpu, next_instruct, self.lgr):
                    self.lgr.error('getMemParams, tried going forward, failed')
                    return
                eip = self.top.getEIP(self.cpu)
                ''' TBD parse the va_list and look for sources so we can handle sprintf'''
                fun = self.mem_something.fun
                if fun in self.mem_fun_entries and eip in self.mem_fun_entries[fun]:
                    self.lgr.debug('dataWatch getMemParams data hit but 0x%x already in mem_fun_entries for %s' % (eip, fun))
                    skip_fun = True

                if (self.mem_something.fun not in self.mem_fun_entries or eip not in self.mem_fun_entries[self.mem_something.fun]) and 'printf' not in self.mem_something.fun and \
                                     'syslog' not in self.mem_something.fun and 'fgets' not in self.mem_something.fun:
                    ret_addr_offset = None
                    if self.mem_something.ret_addr_addr is not None:
                        ret = self.mem_utils.readPtr(self.cpu, self.mem_something.ret_addr_addr)
                        if self.mem_something.ret_ip is not None and ret != self.mem_something.ret_ip:
                            self.lgr.debug('dataWatch getMemParams, do not believe we have an address of ret_addr.  ret: 0x%x  mem_something.ret_ip: 0x%x' % (ret, 
                               self.mem_something.ret_ip)) 
                            ''' do not believe we have an address of ret_addr '''
                            pass
                        else:
                            ret_addr_offset = sp - self.mem_something.ret_addr_addr 
                            self.lgr.debug('dataWatch getMemParam did step forward would record fun %s at 0x%x ret_addr ofset is %d ret_addr_addr 0x%x read ret_addr 0x%x, memsomthing ret_ip 0x%x' % (self.mem_something.fun, eip, ret_addr_offset, self.mem_something.ret_addr_addr, ret, self.mem_something.ret_ip))
                    else:
                        self.lgr.debug('dataWatch getMemParam ret_addr_addr is None, did step forward would record fun %s at 0x%x ret_addr ofset is None, assume lr retrun' % (self.mem_something.fun, eip))
                    #if self.mem_something.fun not in funs_need_addr:
                    self.lgr.debug('dataWatch getMemParams add mem_something_entry addr %s eip 0x%x' % (self.mem_something.fun, eip))
                    if self.mem_something.fun not in self.mem_fun_entries:
                        self.mem_fun_entries[self.mem_something.fun] = {}
                    if eip not in self.mem_fun_entries[self.mem_something.fun]:
                        self.mem_fun_entries[self.mem_something.fun][eip] = self.MemCallRec(None, ret_addr_offset, eip)
                        self.added_mem_fun_entry = True
                    else:
                        self.lgr.debug('dataWatch getMemParms eip 0x%x already in mem_fun_entries' % eip)
                #else:
                #    self.lgr.debug('dataWatch getMemParams, fun %s in mem_fun_entries? will return' % self.mem_something.fun)
                #    return
            else:
                ''' adjust  to account for simics not adjusting sp on break on function entry '''
                sp = sp + self.mem_utils.WORD_SIZE

            ''' NOTE returns above '''
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
                            #self.lgr.debug('mempcy but is libc count_addr 0x%x, count %d' % (count_addr, self.mem_something.count))
                        else:
                            self.mem_something.count = self.mem_utils.readWord32(self.cpu, sp+2*self.mem_utils.WORD_SIZE)
                            #self.lgr.debug('mempcy but not libc, so file %s  count %d' % (so_file, self.mem_something.count))
                    else:
                        self.mem_something.count = self.mem_utils.readWord32(self.cpu, sp+2*self.mem_utils.WORD_SIZE)
                if self.mem_something.count == 0:
                    self.lgr.debug('dataWatch getMemParams sees 0 count for copy, skip this function.')
                    self.pending_call = False
                    skip_fun = True
                else:
                    for oframe in self.mem_something.frames:
                        #self.lgr.debug('dataWatch getMemParams memsomething fun %s' % oframe.fun_name)
                        if oframe.fun_name is not None and oframe.fun_name == 'fgets':
                            #self.lgr.debug('dataWatch getMemParams memsomething is fgets.')
                            if oframe.ret_addr is not None:
                                #self.lgr.debug('dataWatch getMemParams fgets ret ip is 0x%x' % oframe.ret_addr)
                                self.mem_something.ret_ip = oframe.ret_addr
                                self.mem_something.fun = 'fgets'
                       
                    pass
                    #self.lgr.debug('getMemParams memcpy-ish dest 0x%x  src 0x%x count 0x%x' % (self.mem_something.dest, self.mem_something.src, 
                    #    self.mem_something.count))
            elif self.mem_something.fun == 'memset':
                self.mem_something.dest, dumb, self.mem_something.count = self.getCallParams(sp)
                self.mem_something.src = self.mem_something.dest
            elif self.mem_something.fun == 'memcmp':
                self.mem_something.dest, self.mem_something.src, self.mem_something.count = self.getCallParams(sp)
                self.lgr.debug('getmemParams memcmp dest 0x%x src 0x%x' % (self.mem_something.dest, self.mem_something.src))
            elif self.mem_something.fun == 'strdup':
                self.mem_something.src, dumb1, dubm2 = self.getCallParams(sp)
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
            elif self.mem_something.fun in ['strcmp', 'strncmp', 'strcasecmp', 'strncasecmp', 'xmlStrcmp', 'strpbrk', 'strspn', 'strcspn']: 
                self.mem_something.dest, self.mem_something.src, count_maybe = self.getCallParams(sp)
                if self.cpu.architecture == 'arm':
                    if self.mem_something.fun == 'strncmp':
                        #limit = self.mem_utils.getRegValue(self.cpu, 'r2')
                        limit = count_maybe
                        self.mem_something.count = min(limit, self.getStrLen(self.mem_something.src))
                    else:
                        self.mem_something.count = self.getStrLen(self.mem_something.src)        

                    self.lgr.debug('getMemParams %s, src: 0x%x dest: 0x%x count: %d' % (self.mem_something.fun, self.mem_something.src, 
                         self.mem_something.dest, self.mem_something.count))
                else:
                    if self.mem_something.fun == 'strncmp':
                        #limit = self.mem_utils.readPtr(self.cpu, sp+2*self.mem_utils.WORD_SIZE)
                        limit = count_maybe
                        self.mem_something.count = min(limit, self.getStrLen(self.mem_something.src))
                    else:
                        self.mem_something.count = self.getStrLen(self.mem_something.src)        
            elif self.mem_something.fun in ['strchr', 'strrchr']:
                self.mem_something.src, self.mem_something.the_chr, dumb = self.getCallParams(sp)
                ''' TBD fix to reflect strnchr? '''
                self.mem_something.count=1
            elif self.mem_something.fun in ['strtoul', 'strtoull', 'strtol', 'strtoll', 'strtoq', 'atoi']:
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
                self.lgr.debug('dataWatch getMemParams is strlen, cal getStrLen for 0x%x' % self.mem_something.src)
                self.mem_something.count = self.getStrLen(self.mem_something.src)        
                self.lgr.debug('dataWatch getMemParams back from getStrLen')
            elif self.mem_something.fun in ['vsnprintf', 'sprintf', 'snprintf']:
                # TBD generalized this
                self.mem_something.dest, dumb2 , dumb = self.getCallParams(sp)
            elif self.mem_something.fun in ['fprintf', 'printf', 'syslog']:
                dumb2, self.mem_something.src, dumb = self.getCallParams(sp)

            elif self.mem_something.fun == 'fwrite' or self.mem_something.fun == 'IO_do_write':
                self.mem_something.src, self.mem_something.count, dumb = self.getCallParams(sp)

            elif self.mem_something.fun == 'glob' or self.mem_something.fun == 'IO_do_write':
                self.mem_something.src, dumb1, dumb = self.getCallParams(sp)

            elif self.mem_something.fun == 'inet_addr':
                if self.cpu.architecture == 'arm':
                    self.mem_something.src = self.mem_utils.getRegValue(self.cpu, 'r0')
                else:
                    self.mem_something.src = self.mem_utils.readPtr(self.cpu, sp)
                self.mem_something.count = self.getStrLen(self.mem_something.src)        
                self.mem_something.the_string = self.mem_utils.readString(self.cpu, self.mem_something.src, self.mem_something.count)

            elif self.mem_something.fun == 'inet_ntop':
                dumb1, dumb2, self.mem_something.dest = self.getCallParams(sp)
            elif self.mem_something.fun in ['getenv', 'regexec', 'ostream_insert']:
                self.lgr.debug('dataWatch getMemParms %s' % self.mem_something.fun)
                self.mem_something.src, dumb1, dumb = self.getCallParams(sp)

            elif self.mem_something.fun == 'string_std':
                this, src_addr, dumb2 = self.getCallParams(sp)
                self.mem_something.src = self.mem_utils.readPtr(self.cpu, src_addr)
                self.lgr.debug('dataWatch getMemParms eip: 0x%x %s src([r1]) is 0x%x, this: 0x%x' % (eip, self.mem_something.fun, self.mem_something.src, this))
                
            elif self.mem_something.fun == 'string_chr':
                this, self.mem_something.src, dumb2 = self.getCallParams(sp)
                self.lgr.debug('dataWatch getMemParms  eip: 0x%x %s src(r1) is 0x%x, this: 0x%x' % (eip, self.mem_something.fun, self.mem_something.src, this))

            elif self.mem_something.fun == 'str':
                this, src_addr, dumb2 = self.getCallParams(sp)
                self.mem_something.src = self.mem_utils.readPtr(self.cpu, src_addr)
                self.lgr.debug('dataWatch getMemParms eip: 0x%x %s src([r1]) is 0x%x, this: 0x%x' % (eip, self.mem_something.fun, self.mem_something.src, this))

            elif self.mem_something.fun == 'string_basic_char':
                self.mem_something.ret_addr_addr, self.mem_something.src, self.mem_something.count = self.getCallParams(sp)
                #self.mem_something.ret_addr_addr, self.mem_something.src, dumb = self.getCallParams(sp)
                self.lgr.debug('dataWatch getMemParms  eip: 0x%x %s src is 0x%x, ret_addr_addr(this): 0x%x count: %d' % (eip, self.mem_something.fun, self.mem_something.src, 
                     self.mem_something.ret_addr_addr, self.mem_something.count))

            elif self.mem_something.fun == 'string_basic_std':
                src_addr, self.mem_something.count, dumb = self.getCallParams(sp)
                self.mem_something.src = self.mem_utils.readPtr(self.cpu, src_addr)
                self.lgr.debug('dataWatch getMemParms eip: 0x%x %s src([r1]) is 0x%x, count %d' % (eip, self.mem_something.fun, self.mem_something.src, self.mem_something.count))


            elif self.mem_something.fun == 'replace_std':
                self.mem_something.ret_addr_addr, self.mem_something.pos, self.mem_something.length, src_addr = self.get4CallParams(sp)
                self.mem_something.src = self.mem_utils.readPtr(self.cpu, src_addr)
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
                        self.lgr.debug('dataWatch getMemParams smells like an object pointer, adjust start to include it.  start[%d] now 0x%x' % (index, maybe_this))
                        self.start[index] = maybe_this

                if self.mem_something.length == 0:
                    self.mem_something.length = self.getStrLen(self.mem_something.src)        
                self.lgr.debug('dataWatch getMemParms 0x%x %s src(r3) is 0x%x len %d, this: 0x%x' % (eip, self.mem_something.fun, self.mem_something.src, self.mem_something.length, this))

            elif self.mem_something.fun == 'append_chr_n':
                this, self.mem_something.src, self.mem_something.length = self.getCallParams(sp)
                self.lgr.debug('dataWatch getMemParms %s src(r1) is 0x%x len %d' % (self.mem_something.fun, self.mem_something.src, self.mem_something.length))
            elif self.mem_something.fun == 'append_chr':
                this, self.mem_something.src, dumb = self.getCallParams(sp)
                self.mem_something.length = self.getStrLen(self.mem_something.src)        
                self.lgr.debug('dataWatch getMemParms %s src(r1) is 0x%x len %d' % (self.mem_something.fun, self.mem_something.src, self.mem_something.length))
            elif self.mem_something.fun == 'append_std':
                this, src_addr, dumb = self.getCallParams(sp)
                self.mem_something.src = self.mem_utils.readPtr(self.cpu, src_addr)
                self.mem_something.length = 1
                self.lgr.warning('dataWatch getMemParams append_std length?')
            elif self.mem_something.fun == 'assign_chr':
                ''' TBD extend for (char *, len)'''
                this, self.mem_something.src, dumb = self.getCallParams(sp)
                self.mem_something.length = self.getStrLen(self.mem_something.src)        
                self.lgr.debug('dataWatch getMemParms %s src(r1) is 0x%x len %d' % (self.mem_something.fun, self.mem_something.src, self.mem_something.length))
            elif self.mem_something.fun == 'compare_chr':
                ''' TBD extend for (char *, len)'''
                obj_ptr, self.mem_something.src, dumb = self.getCallParams(sp)
                self.mem_something.length = self.getStrLen(self.mem_something.src)        
                self.mem_something.dest = self.mem_utils.readPtr(self.cpu, obj_ptr)
                self.lgr.debug('dataWatch getMemParms %s 0x%x to 0x%x len %d' % (self.mem_something.fun, self.mem_something.src, self.mem_something.dest, self.mem_something.length))
            elif self.mem_something.fun == 'charLookup':
                r0 = self.mem_utils.getRegValue(self.cpu, 'syscall_ret')
                self.mem_something.ret_addr_addr = self.mem_utils.readPtr(self.cpu, r0)
                if self.mem_something.ret_addr_addr is not None and (self.mem_something.addr is not None or not data_hit):
                    if self.mem_something.addr is not None:
                        self.lgr.debug('dataWatch getMemParms %s addr 0x%x r0 0x%x ret_addr_addr 0x%x' % (self.mem_something.fun, self.mem_something.addr, 
                            r0, self.mem_something.ret_addr_addr))
                    else:
                        self.lgr.debug('dataWatch getMemParms %s (not a data hit) r0 0x%x ret_addr_addr 0x%x' % (self.mem_something.fun, r0, self.mem_something.ret_addr_addr))
                elif self.mem_something.ret_addr_addr is None:
                    self.skip_entries.append(self.mem_something.fun_addr)
                    self.added_mem_fun_entry = True
                    self.lgr.debug('dataWatch getMemParms %s addr %s ret_addr_addr is None? add to skip_entries' % (self.mem_something.fun, str(self.mem_something.addr)))
                    skip_it = True
                else:
                    self.skip_entries.append(self.mem_something.fun_addr)
                    self.added_mem_fun_entry = True
                    self.lgr.debug('dataWatch getMemParms %s addr %s ret_addr_addr is unknown? add to skip_entries' % (self.mem_something.fun, str(self.mem_something.addr)))
                    skip_it = True
            #elif self.mem_something.fun == 'fgets':
            #    self.mem_something.dest, self.mem_something.count, dumb = self.getCallParams(sp)

            # Begin XML
            elif self.mem_something.fun == 'xmlGetProp':
                if self.cpu.architecture == 'arm':
                    self.mem_something.src = self.mem_utils.getRegValue(self.cpu, 'r1')
                else:
                    self.mem_something.src = self.mem_utils.readPtr(self.cpu, sp+self.mem_utils.WORD_SIZE)
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
            if not data_hit and not skip_fun and self.mem_something not in ['getenv']:
                #self.lgr.debug('dataWatch not data_hit, find range for buf_start using src 0x%x' % self.mem_something.src)
                ''' see if src is one of our buffers '''
                #buf_start = self.findRange(self.mem_something.src)
                buf_index = self.findRangeIndex(self.mem_something.src)
                if buf_index is None:
                    ''' handle ambigous calls such as strcmp '''
                    buf_start = None
                    if self.mem_something.dest is not None:
                        buf_start = self.findRange(self.mem_something.dest)
                    if buf_start is None:
                        skip_fun = True
                        if self.mem_something.src is not None and self.mem_something.dest is not None:
                            self.lgr.debug('dataWatch getMemParams, src 0x%x and dst 0x%x not buffers we care about, skip it' % (self.mem_something.src,
                                 self.mem_something.dest))
                        elif self.mem_something.src is not None:
                            self.lgr.debug('dataWatch getMemParams, src 0x%x  not buffer we care about, skip it' % (self.mem_something.src))
                    else:
                        self.lgr.debug('dataWatch getMemParams not via hit, not src, but found dest 0x%x in buf_start of 0x%x' % (self.mem_something.dest, buf_start))
                else:
                    if self.mem_something.count is not None and self.length[buf_index] < self.mem_something.count:
                        self.lgr.debug('dataWatch getMemParams no data hit, copy larger than buffer, truncate to %d' % self.length[buf_index])
                        self.mem_something.count = self.length[buf_index]
                    self.mem_something.op_type = Sim_Trans_Load
                    self.lgr.debug('dataWatch getMemParams not via hit, found src 0x%x in buf_start of 0x%x' % (self.mem_something.src, self.start[buf_index]))
            if not skip_fun:
                if self.mem_something.ret_ip == 0:
                    self.lgr.error('dataWatch getMemParams ret_ip is zero, bail')
                    self.pending_call = False
                    return
                #self.stopWatch(leave_fun_entries = True)
                self.stopWatch(immediate=True)
                self.runToReturn()
                dum_cpu, cur_addr, comm, pid = self.task_utils.currentProcessInfo(self.cpu)
                self.lgr.debug('getMemParams pid:%d (%s) eip: 0x%x fun %s set hap on ret_ip at 0x%x context %s hit: %r Now run!' % (pid, comm, eip, self.mem_something.fun,
                     self.mem_something.ret_ip, str(self.cpu.current_context), data_hit))
                if data_hit:
                    SIM_run_command('c')
            else:
                self.lgr.debug('dataWatch getMemParams skip fun.')
                self.pending_call = False
                is_running = self.top.isRunning()
                if not is_running:
                    self.lgr.debug('getMemParams, not running, kick it.')
                    SIM_continue(0)

    def runToReturn(self):
        resim_context = self.context_manager.getRESimContext()
        proc_break = self.context_manager.genBreakpoint(resim_context, Sim_Break_Linear, Sim_Access_Execute, self.mem_something.ret_ip, 1, 0)
        self.return_hap = self.context_manager.genHapIndex("Core_Breakpoint_Memop", self.returnHap, None, proc_break, 'memcpy_return_hap')
        if self.back_stop is not None and not self.break_simulation and self.use_back_stop:
            self.back_stop.setFutureCycle(self.back_stop_cycles)

    def runToReturnAlone(self, dumb):
        cell = self.top.getCell()
        resim_context = self.context_manager.getRESimContext()
        #self.context_manager.restoreDefaultContext()
        #proc_break = self.context_manager.genBreakpoint(cell, Sim_Break_Linear, Sim_Access_Execute, self.mem_something.ret_ip, 1, 0)
        proc_break = self.context_manager.genBreakpoint(resim_context, Sim_Break_Linear, Sim_Access_Execute, self.mem_something.ret_ip, 1, 0)
        self.return_hap = self.context_manager.genHapIndex("Core_Breakpoint_Memop", self.returnHap, self.mem_something, proc_break, 'memsomething_return_hap')
        self.lgr.debug('runToReturnAlone set returnHap with breakpoint %d break at ret_ip 0x%x' % (proc_break, self.mem_something.ret_ip))
        self.context_manager.restoreDebugContext()
        if self.mem_something.run:
            SIM_continue(0)

    def undoHap(self, dumb, one, exception, error_string):
        
        if self.undo_hap is not None:
            self.lgr.debug('dataWatch undoHap')
            SIM_hap_delete_callback_id("Core_Simulation_Stopped", self.undo_hap)
            self.undo_hap = None
            SIM_run_alone(self.undoAlone, None)

    def undoAlone(self, dumb):
            #oneless = self.save_cycle -1
            oneless = self.save_cycle 
            self.lgr.debug('undoAlone skip back to 0x%x' % oneless)
            if not resimUtils.skipToTest(self.cpu, oneless, self.lgr):
                self.lgr.error('undoAlone unable to skip to save cycle 0x%x, got 0x%x' % (oneless, self.cpu.cycles))
                return
            else:
                self.lgr.debug('skip done')
            eip = self.top.getEIP(self.cpu)
            dum_cpu, cur_addr, comm, pid = self.task_utils.currentProcessInfo(self.cpu)
            self.watch(i_am_alone=True)
            '''
            addr = self.mem_something.src
            if self.mem_something.op_type != Sim_Trans_Load or addr is None:
                addr = self.mem_something.dest

            '''
            self.lgr.debug('dataWatch undoAlone eip: 0x%x would run forward, first restore debug context' % eip)
            self.context_manager.restoreDebugContext()
            self.top.restoreDebugBreaks()
            #self.finishReadHap(self.mem_something.op_type, self.mem_something.trans_size, eip, addr, self.mem_something.length, self.mem_something.start, pid)
            SIM_run_command('c')

    def rmCallHap(self):
        if self.call_hap is not None:
            RES_delete_breakpoint(self.call_break)
            SIM_hap_delete_callback_id("Core_Breakpoint_Memop", self.call_hap)
            self.call_hap = None
            self.call_break = None

    def hitCallStopHap(self, vt_stuff, one, exception, error_string):
        SIM_run_alone(self.hitCallStopHapAlone, vt_stuff)
 
    def hitCallStopHapAlone(self, vt_stuff):
        SIM_run_command('enable-vmp') 
        if vt_stuff is not None and vt_stuff.simics_fail:
            resimUtils.skipToTest(self.cpu, vt_stuff.cycle, self.lgr)
            self.lgr.debug('dataWatch hitStopHap alone, simics rev failure, skipped to cycle 0x%x' % vt_stuff.cycle)
        
        ''' we are at the call to a memsomething, get the parameters '''
        eip = self.top.getEIP(self.cpu)
        self.lgr.debug('DataWatch hitCallStopHap eip 0x%x' % eip)
        if self.call_stop_hap is not None:
            cycle_dif = self.cycles_was - self.cpu.cycles
            self.lgr.debug('hitCallStopHap will delete call_stop_hap %d cycle_dif 0x%x' % (self.call_stop_hap, cycle_dif))
            SIM_hap_delete_callback_id("Core_Simulation_Stopped", self.call_stop_hap)
            self.call_stop_hap = None
            #self.rmCallHap()
            RES_delete_breakpoint(self.call_break)
            self.call_break = None
        else:
            return
        ''' TBD dynamically adjust cycle_dif limit?  make exceptions for some calls, e.g., xmlparse? '''
        if eip != self.mem_something.called_from_ip or cycle_dif > 300000:
            if eip != self.mem_something.called_from_ip:
                self.lgr.debug('hitCallStopHap not stopped on expected call. Wanted 0x%x got 0x%x' % (self.mem_something.called_from_ip, eip))
            else:
                self.lgr.debug('hitCallStopHap stopped too far back cycle_dif 0x%x, assume a ghost frame' % cycle_dif)
            self.undo_pending = True
            SIM_run_alone(self.undoAlone, self.mem_something)
        else:
            latest_cycle = self.watchMarks.latestCycle()
            if latest_cycle is not None:
                if self.mem_something.fun not in no_ghosts and latest_cycle > self.cpu.cycles:
                    self.lgr.debug('hitCallStopHap stopped at 0x%x, prior to most recent watch mark having cycle: 0x%x, assume a ghost frame' % (self.cpu.cycles, latest_cycle))
                    self.undo_pending = True
                    SIM_run_alone(self.undoAlone, self.mem_something)
                else:
                    self.lgr.debug('dataWatch hitCallStopHap function %s call getMemParams at eip 0x%x' % (self.mem_something.fun, eip))
                    SIM_run_alone(self.getMemParams, True)
            else:
                self.lgr.error('hitCallStopHap, latest_cycle is None')

    def revAlone(self, alternate_callback=None):
        is_running = self.top.isRunning()
        status = SIM_simics_is_running()
        self.lgr.debug('dataWatch revAlone, resim running? %r  simics status %r' % (is_running, status))
        self.top.removeDebugBreaks(immediate=True)
        self.stopWatch(immediate=True)
        if self.mem_something is None:
            self.lgr.error('dataWatch revAlone with mem_something of None')
            return
        if self.mem_something.fun in self.mem_fun_entries and self.mem_something.fun_addr in self.mem_fun_entries[self.mem_something.fun] \
               and self.mem_something.fun not in funs_need_addr:
            self.lgr.error('dataWatch revAlone but entry 0x%x already in mem_fun_entires', self.mem_something.fun_addr)
            return

        self.cycles_was = self.cpu.cycles
        self.save_cycle = self.cycles_was - 1
        ''' Simics broken TBD '''
        if True:
            resimUtils.skipToTest(self.cpu, self.save_cycle, self.lgr)
            resimUtils.skipToTest(self.cpu, self.cycles_was, self.lgr)
            self.lgr.debug('dataWatch revAlone, did Simics 2 step')
          
        
        phys_block = self.cpu.iface.processor_info.logical_to_physical(self.mem_something.called_from_ip, Sim_Access_Read)
        #cell = self.top.getCell()
        #self.call_break = SIM_breakpoint(cell, Sim_Break_Linear, Sim_Access_Execute, self.mem_something.called_from_ip, 1, 0)

        self.call_break = SIM_breakpoint(self.cpu.physical_memory, Sim_Break_Physical, Sim_Access_Execute, phys_block.address, 1, 0)

        ''' in case we chase ghost frames mimicking memsomething calls  and need to return '''
        #self.lgr.debug('dataWatch revAlone break %d set on IP of call 0x%x (phys 0x%x) and call_hap %d set save_cycle 0x%x, now reverse' % (self.call_break, 
        #   self.mem_something.called_from_ip, phys_block.address, self.call_hap, self.save_cycle))
        self.lgr.debug('dataWatch revAlone break %d set on IP of call 0x%x (phys 0x%x) and save_cycle 0x%x (%d), now reverse' % (self.call_break, 
           self.mem_something.called_from_ip, phys_block.address, self.save_cycle, self.save_cycle))
        #self.lgr.debug('cell is %s  cpu context %s' % (cell, self.cpu.current_context))
        #SIM_run_command('list-breakpoints')
        if alternate_callback is None:
            callback = self.hitCallStopHap
        else:
            callback = alternate_callback
        SIM_run_command('disable-vmp') 
        self.call_stop_hap = SIM_hap_add_callback("Core_Simulation_Stopped", callback, None)
        SIM_run_command('reverse')


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
            SIM_hap_delete_callback_id("Core_Simulation_Stopped", self.ghost_stop_hap)
            self.ghost_stop_hap = None

    def memstuffStopHap(self, alternate_callback, one, exception, error_string):
        ''' We may had been in a memsomething and have stopped.  Set a break on the address 
            of the call to the function and reverse. '''
        #self.lgr.debug('memstuffStopHap stopHap ')
        if self.stop_hap is not None:
            #self.lgr.debug('memstuffStopHap stopHap will delete hap %s' % str(self.stop_hap))
            SIM_hap_delete_callback_id("Core_Simulation_Stopped", self.stop_hap)
            self.stop_hap = None
        else:
            return
        self.lgr.debug('memstuffStopHap, reverse to call at ip 0x%x' % self.mem_something.called_from_ip)
        SIM_run_alone(self.revAlone, alternate_callback)

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
        We are within a memcpy type function for which we believe we know the calling conventions (or a user-defined iterator).  However those values have been
        lost to the vagaries of the implementation by the time we hit the breakpoint.  We need to stop; Reverse to the call; record the parameters;
        set a break on the return; and continue.  We'll assume not too many instructions between us and the call, so manually walk er back.
        '''
        #if self.mem_something.ret_ip is not None and self.mem_something.called_from_ip is not None:
        #    self.lgr.debug('handleMemStuff ret_addr 0x%x fun %s called_from_ip 0x%x' % (self.mem_something.ret_ip, self.mem_something.fun, self.mem_something.called_from_ip))
        #else:
        #    self.lgr.debug('handleMemStuff got none for either ret_addr or called_from_ip')
        
        if self.mem_something.fun in self.mem_fun_entries and self.mem_something.fun_addr in self.mem_fun_entries[self.mem_something.fun] \
               and self.mem_something.fun not in funs_need_addr:
            self.lgr.warning('dataWatch handleMemStuff but entry for fun %s already in mem_fun_entires addr 0x%x' % (self.mem_something.fun, self.mem_something.fun_addr))

        elif self.mem_something.fun not in mem_funs or self.mem_something.fun in no_stop_funs: 
            ''' assume it is a user iterator '''
            if self.mem_something.src is not None:
                self.lgr.debug('handleMemStuff assume iterator or function that need not reverse to call, src: 0x%x  %s clear backstop' % (self.mem_something.src, self.cpu.current_context))
                self.pending_call = True
                ''' iterator may take  while to return? '''
                ''' iterator mark will be recorded on return '''
                #self.watchMarks.iterator(self.mem_something.fun, self.mem_something.src, self.mem_something.src)
                self.back_stop.clearCycle()
                #SIM_break_simulation('handle memstuff')
                SIM_run_alone(self.runToReturnAlone, None)
            else:
                self.lgr.debug('handleMemStuff assume iterator or function that need not reverse to call, IS a modify,  Just return and come back on read')
                return
        else: 
            ''' run back to the call '''
            self.stop_hap = SIM_hap_add_callback("Core_Simulation_Stopped", 
        	     self.memstuffStopHap, None)
            self.lgr.debug('handleMemStuff now stop')
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

    def adHocCopy(self, addr, trans_size, dest_addr, start, length):
        retval = False
        if dest_addr != addr:
            #self.lgr.debug('dataWatch adHocCopy might add address 0x%x' % dest_addr)
            existing_index = self.findRangeIndex(dest_addr)
            if existing_index is None:
                ''' TBD may miss some add hocs? not likely '''
                #self.lgr.debug('dataWatch adHocCopy will add address 0x%x' % dest_addr)
                self.last_ad_hoc=dest_addr
                retval = True
            else:
                ''' Re-use of ad-hoc buffer '''
                #self.lgr.debug('dataWatch adHocCopy, reuse of ad-hoc buffer? addr 0x%x start 0x%x' % (addr, start))
                self.recent_reused_index = existing_index
                pass
        else:
            self.lgr.debug('dataWatch adHocCopy dest is same as addr')
        return retval

    def finishCheckMoveHap(self, dumb, an_object, breakpoint, memory):
        ''' Hap invoked when we reach the end of a canidate ad hoc move '''
        if self.finish_check_move_hap is None:
            return
        if self.call_hap is not None:
            eip = self.top.getEIP(self.cpu)
            self.lgr.warning('finishCheckMove found call_hap ? eip is 0x%x, delete the check_move hap' % eip)
            self.context_manager.genDeleteHap(self.finish_check_move_hap, immediate=True)
            self.finish_check_move_hap = None
            return
        self.lgr.debug('dataWatch finishCheckMoveHap')
        dest_addr = self.decode.getAddressFromOperand(self.cpu, self.move_stuff.dest_op, self.lgr)
        ad_hoc = False
        if self.move_stuff.function is None:
            ad_hoc = self.adHocCopy(self.move_stuff.addr, self.move_stuff.trans_size, dest_addr, self.move_stuff.start, self.move_stuff.length)
            
            '''
            if dest_addr != move_stuff.addr:
                self.lgr.debug('dataWatch finishCheckMoveHap might add address 0x%x' % dest_addr)
                existing_index = self.findRangeIndex(dest_addr)
                if existing_index is None:
                    self.lgr.debug('dataWatch finishCheckMoveHap will add address 0x%x' % dest_addr)
                    self.last_ad_hoc=dest_addr
                    ad_hoc = True
                else:
                    self.lgr.debug('dataWatch finishCheckMoveHap, reuse of ad-hoc buffer? addr 0x%x start 0x%x' % (move_stuff.addr, move_stuff.start))
                    self.recent_reused_index = existing_index
                    pass
            else:
                self.lgr.debug('dataWatch finishCheckMoveHap dest is same as addr')
            '''

        if ad_hoc:
            if self.move_stuff.trans_size >= 16:
                f = self.frames[1]
                self.mem_something = MemSomething(f.fun_name, f.fun_addr, self.move_stuff.start, f.ret_addr, self.move_stuff.start, dest_addr, None, 
                      f.ip, None, self.move_stuff.length, self.move_stuff.start)
                self.lgr.debug('dataWatch finishCheckMoveHap may be a memcpy with no fun name')
                SIM_run_alone(self.stopForMemcpyCheck, None)
                return 
            wm = self.watchMarks.dataRead(self.move_stuff.addr, self.move_stuff.start, self.move_stuff.length, 
                     self.getCmp(), self.move_stuff.trans_size, ad_hoc=True, dest=self.last_ad_hoc)
            self.setRange(dest_addr, self.move_stuff.trans_size, watch_mark=wm)
            #self.lgr.debug('dataWatch finishCheckMoveHap is ad hoc addr 0x%x  ad_hoc %r, dest 0x%x' % (self.move_stuff.addr, ad_hoc, dest_addr))
            self.setBreakRange()
            ''' TBD breaks something?'''
            self.move_cycle = self.cpu.cycles
        elif self.move_stuff.function is not None:
            if dest_addr != self.move_stuff.addr:
                #self.lgr.debug('dataWatch finishCheckMove, function return value wrote to addr 0x%x  function %s' % (self.move_stuff.addr, self.move_stuff.function))
                wm = self.watchMarks.dataRead(self.move_stuff.addr, self.move_stuff.start, self.move_stuff.length, 
                         self.getCmp(), self.move_stuff.trans_size, note=self.move_stuff.function, dest=dest_addr)
                self.setRange(dest_addr, self.move_stuff.trans_size, watch_mark=wm)
                #self.lgr.debug('dataWatch finishCheckMoveHap is ad hoc addr 0x%x  ad_hoc %r, dest 0x%x' % (self.move_stuff.addr, ad_hoc, dest_addr))
                self.setBreakRange()
                self.move_cycle = self.cpu.cycles
            else:
                self.lgr.debug('dataWatch finishCheckMove rewrote 0x%x using %s' % (dest_addr, self.move_stuff.function))
        else:
            #self.lgr.debug('dataWatch finishCheckMove, not ad_hoc addr 0x%x  start 0x%x ad_hoc %r ip: 0x%x' % (self.move_stuff.addr, self.move_stuff.start, ad_hoc, 
            #     self.move_stuff.ip))
            if self.cpu.cycles != self.prev_cycle:
                #self.lgr.debug('dataWatch checkMove found nothing, use prev cycle 0x%x for recording' % self.prev_cycle)
                self.watchMarks.dataRead(self.move_stuff.addr, self.move_stuff.start, self.move_stuff.length, self.getCmp(), self.move_stuff.trans_size, ip=self.move_stuff.ip,
                         cycles=self.prev_cycle)
            else:
                self.watchMarks.dataRead(self.move_stuff.addr, self.move_stuff.start, self.move_stuff.length, self.getCmp(), self.move_stuff.trans_size, ip=self.move_stuff.ip)
        #self.lgr.debug('dataWatch finishCheckMove now delete hap')
        if self.finish_check_move_hap is None:
            self.lgr.error('it is none')
        self.context_manager.genDeleteHap(self.finish_check_move_hap, immediate=True)
        self.finish_check_move_hap = None


    class CheckMoveStuff():
        def __init__(self, addr, trans_size, start, length, dest_op, function=None, ip=None):
            self.addr = addr
            self.trans_size = trans_size
            self.start = start
            self.length = length
            self.dest_op = dest_op
            self.function = function
            self.ip = ip
        def getString(self):
            if self.ip is not None:
                return 'addr: 0x%x trans_size: %d start: 0x%x len: %d ip: 0x%x' % (self.addr, self.trans_size, self.start, self.length, self.ip)
            else:
                return 'addr: 0x%x trans_size: %d start: 0x%x len: %d' % (self.addr, self.trans_size, self.start, self.length)

    def isDataTransformCall(self, instruct):
        fun_list = ['ntohl', 'htonl', 'tolower', 'toupper']
        retval = None
        if self.fun_mgr is not None and self.fun_mgr.isCall(instruct[1]):
            fun_hex, fun = self.fun_mgr.getFunName(instruct[1])
            if fun_hex is not None:
                self.lgr.debug('isDataTransformCall fun is %s  (0x%x)' % (fun, fun_hex))
            else:
                self.lgr.debug('isDataTransformCall fun is %s  failed to get fun_hex from %s' % (fun, instruct[1]))

            if fun is not None:
                for tform in fun_list:
                    if tform in fun:
                        retval = fun
                        break
        return retval

    def isDataRef(self, instruct):
        retval = None
        if self.fun_mgr is not None and self.fun_mgr.isCall(instruct[1]):
            fun_hex, fun = self.fun_mgr.getFunName(instruct[1])
            if fun_hex is not None:
                self.lgr.debug('isDataRef fun is %s  (0x%x)' % (fun, fun_hex))
            else:
                self.lgr.debug('isDataRef fun is %s  failed to get fun_hex from %s' % (fun, instruct[1]))
            if fun is not None and 'isalpha' in fun:
                retval = fun
        return retval

    def checkNTOHL(self, next_ip, addr, trans_size, start, length):
        ''' if the given ip is a call to a data transform, e.g., ntohl, see if the result is
            written to memory, and if so, track that buffer.'''
        retval = False
        if self.fun_mgr is None:
            self.lgr.debug('dataWatch checkNTOHL with no fun_mgr')
            return False
        orig_ip = self.top.getEIP(self.cpu)
        instruct = SIM_disassemble_address(self.cpu, next_ip, 1, 0)
        fun = self.isDataTransformCall(instruct)
        if fun is not None:
                self.lgr.debug('dataWatch checkNTOHL is %s' % fun)
                our_reg = self.mem_utils.regs['syscall_ret']
                next_instruct = instruct
                for i in range(5):
                    next_ip = next_ip + next_instruct[0]
                    next_instruct = SIM_disassemble_address(self.cpu, next_ip, 1, 0)
                    if decode.isBranch(self.cpu, next_instruct[1]):
                        break
                    op2, op1 = self.decode.getOperands(next_instruct[1])
                    #self.lgr.debug('datawatch checkNTOHL, next inst at 0x%x is %s' % (next_ip, next_instruct[1]))
                    if next_instruct[1].startswith('mov') and self.decode.isReg(op2) and self.decode.regIsPart(op2, our_reg):
                        if self.decode.isReg(op1):
                            #self.lgr.debug('dataWatch checkNTOHL, our reg now is %s' % op1)
                            our_reg = op1
                        else:
                            #self.lgr.debug('dataWatch checkNTOHL, maybe op1 is %s' % op1)
                            dest_addr = self.decode.getAddressFromOperand(self.cpu, op1, self.lgr)
                            if dest_addr is not None:
                                #self.lgr.debug('checkNTOHL addr found to be 0x%x' % dest_addr)
                                break_num = self.context_manager.genBreakpoint(None, Sim_Break_Linear, Sim_Access_Execute, next_ip, 1, 0)
                                self.move_stuff = self.CheckMoveStuff(addr, trans_size, start, length, op1, function = fun, ip=orig_ip)
                                self.lgr.debug('dataWatch checkNTOHL set finishCheckMoveHap')
                                self.finish_check_move_hap = self.context_manager.genHapIndex("Core_Breakpoint_Memop", 
                                         self.finishCheckMoveHap, None, break_num, 'checkMove')
                                retval = True
                            break
        else:
            fun = self.isDataRef(instruct)
            if fun is not None:
                self.lgr.debug('dataWatch checkNOTHL is data ref %s' % fun)
                retval = True
                mark = self.watchMarks.mscMark(fun, addr)
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
        if self.cpu.architecture == 'arm':
            #self.lgr.debug('dataWatch getMoveDestAddr instruct: %s' % next_instruct[1]) 
            if next_instruct[1].startswith('str') and self.decode.isReg(op1): 
                #self.lgr.debug('dataWatch getMoveDestAddr is str op1 is <%s>  reglist is %s' % (op1, str(our_reg_list)))
                if self.decode.regIsPartList(op1, our_reg_list):
                    #self.lgr.debug('dataWatch getMoveDestAddr is in reg list')
                    dest_addr = self.decode.getAddressFromOperand(self.cpu, op2, self.lgr)
        else:
            if next_instruct[1].startswith('mov') and self.decode.isReg(op2) and self.decode.regIsPartList(op2, our_reg_list):
                #self.lgr.debug('dataWatch loopAdHoc, maybe op1 is %s' % op1)
                dest_addr = self.decode.getAddressFromOperand(self.cpu, op1, self.lgr)
        return dest_addr

    def loopAdHocMult(self, addr, trans_size, start, length, instruct, reg_set, eip, orig_ip):
            ''' For arm '''
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
                next_instruct = SIM_disassemble_address(self.cpu, next_ip, 1, 0)
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
                    self.move_stuff = self.CheckMoveStuff(addr, trans_size, start, length, dest_op, ip=orig_ip)
                    #self.lgr.debug('dataWatch loopAdHoc addr 0x%x  start 0x%x set finishCheckMoveHap' % (addr, start))
                    self.finish_check_move_hap = self.context_manager.genHapIndex("Core_Breakpoint_Memop", 
                             self.finishCheckMoveHap, None, break_num, 'loopAdHoc')
                    break
            return adhoc                

    def loopAdHoc(self, addr, trans_size, start, length, instruct, our_reg, eip, orig_ip):
            ''' Loop through the next several instructions to see if our reg is stored to memory,
                or pushed onto the stack for a call'''
            ''' TBD this will miss copies and such that occur in branches.  It assumes no branching between the start and the next'''
            adhoc = False
            next_ip = eip
            next_instruct = instruct
            op2, op1 = self.decode.getOperands(next_instruct[1])
            track_sp = self.mem_utils.getRegValue(self.cpu, 'sp')
            new_sp = self.adjustSP(track_sp, next_instruct, op1, op2)
            if new_sp is not None:
                track_sp = new_sp
            #self.lgr.debug('dataWatch loopAdHoc, our_reg %s, eip 0x%x starting sp 0x%x' % (our_reg, eip, track_sp))
            our_reg_list = [our_reg]
            max_num = 10
            if our_reg.startswith('xmm'):
                max_num = 100
            for i in range(max_num):
                next_ip = next_ip + next_instruct[0]
                next_instruct = SIM_disassemble_address(self.cpu, next_ip, 1, 0)
                ''' Normally bail on branch, but catch xmm mem copies that have a lot of processing.'''
                if decode.isBranch(self.cpu, next_instruct[1]) and not our_reg.startswith('xmm'):
                    #self.lgr.debug('dataWatch loopAdHoc is branch %s' % next_instruct[1])
                    break
                op2, op1 = self.decode.getOperands(next_instruct[1])
                #self.lgr.debug('datawatch loopAdHoc, next inst at 0x%x is %s  --- op1: %s  op2: %s' % (next_ip, next_instruct[1], op1, op2))
                new_sp = self.adjustSP(track_sp, next_instruct, op1, op2)
                dest_addr = self.getMoveDestAddr(next_instruct, op1, op2, our_reg_list)
                if dest_addr is not None:
                    ''' If dest is relative to sp, assume its value is good and avoid use of finishCheckMove, which is skipped if we encounter another read hap'''
                    if 'sp' in op2:
                        adhoc = self.adHocCopy(addr, trans_size, dest_addr, start, length)
                        break
                    else:                   
                        #self.lgr.debug('dataWatch loopAdHoc dest addr found to be 0x%x, not relative to SP' % dest_addr)
                        adhoc = True
                        break_num = self.context_manager.genBreakpoint(None, Sim_Break_Linear, Sim_Access_Execute, next_ip, 1, 0)
                        dest_op = op1
                        if self.cpu.architecture == 'arm':
                            dest_op = op2
                        ''' We have a candidate check move destination.  Run there to check if it really moves our register into memory '''
                        self.move_stuff = self.CheckMoveStuff(addr, trans_size, start, length, dest_op, ip=orig_ip)
                        #self.lgr.debug('dataWatch loopAdHoc addr 0x%x  start 0x%x set finishCheckMoveHap on eip 0x%x' % (addr, start, next_ip))
                        self.finish_check_move_hap = self.context_manager.genHapIndex("Core_Breakpoint_Memop", 
                                 self.finishCheckMoveHap, None, break_num, 'loopAdHoc')
                        break
                elif next_instruct[1].startswith('mov') and self.decode.isReg(op2) and self.decode.regIsPartList(op2, our_reg_list) and self.decode.isReg(op1):
                        #self.lgr.debug('dataWatch loopAdHoc, adding our_reg to %s' % op1)
                        our_reg_list.append(op1)
                elif self.cpu.architecture != 'arm' and next_instruct[1].startswith('mov') and self.decode.isReg(op1) and op1 in our_reg_list:
                    # TBD fix for arm
                    #self.lgr.debug('dataWatch loopAdHoc, removing %s from our_reg_list' % op1)
                    our_reg_list.remove(op1)
                elif self.cpu.architecture == 'arm' and self.decode.isReg(op1) and op1 in our_reg_list and \
                     (next_instruct[1].startswith('mov') or next_instruct[1].startswith('sub') or next_instruct[1].startswith('add')):
                        our_reg_list.remove(op1)

                elif new_sp is not None:
                    #self.lgr.debug('dataWatch loopAdHoc is stack adjust, now 0x%x' % new_sp)
                    track_sp = new_sp
                elif next_instruct[1].startswith('push') and self.top.isCode(next_ip): 
                    ''' TBD extend for arm stm'''
                    if self.decode.isReg(op1) and self.decode.regIsPartList(op1, our_reg_list):
                        ''' Pushed our register '''
                        next_next_ip = next_ip + next_instruct[0]
                        ''' Assumes calls we care about to ntohl-type calls immediatly follow push of our register 
                            See if result of function is stored to memory. 
                        '''
                        #self.lgr.debug('dataWatch loopAdHoc is push, see if the call is to a data transform.  next_next_ip is 0x%x' % (next_next_ip))
                        adhoc = self.checkNTOHL(next_next_ip, addr, trans_size, start, length)
                        if not adhoc:
                            #self.lgr.debug('dataWatch loopAdHoc, not a NTOHL into memory')
                            ''' TBD tweak this for ARM fu '''
                            ''' If call to ntohl-like function (but result not stored to memory per above, don't record push '''
                            instruct = SIM_disassemble_address(self.cpu, next_next_ip, 1, 0)
                            fun = self.isDataTransformCall(instruct)
                            if fun is None:
                                ''' Will track the push.  Manage so the stack buffer (the push), is removed on return.'''
                                track_sp = track_sp - self.mem_utils.WORD_SIZE
                                self.trackPush(track_sp, instruct, addr, start, length, next_next_ip)
                                adhoc = True
                            else:
                                ''' set a break/hap on return from transform to see if its eax gets pushed onto the stack for a call.'''
                                self.move_stuff = self.CheckMoveStuff(addr, trans_size, start, length, fun, ip=orig_ip)
                                after_call = next_next_ip + instruct[0]
                                #self.lgr.debug('dataWatch loopAdHoc, was push, saw it is a data transform function, look for push of result, thinking after_call is 0x%x.' % after_call)
                                break_num = self.context_manager.genBreakpoint(None, Sim_Break_Linear, Sim_Access_Execute, after_call, 1, 0)
                                self.transform_push_hap = self.context_manager.genHapIndex("Core_Breakpoint_Memop", 
                                     self.transformPushHap, None, break_num, 'transformPush')
                                adhoc = True
                        else:
                            #self.lgr.debug('dataWatch loopAdHoc checkNTOHL found write to memory')
                            pass
                        break
                    else:
                        track_sp = track_sp - self.mem_utils.WORD_SIZE
                        #self.lgr.debug('dataWatch loopAdHoc track_sp now 0x%x' % track_sp) 
            #self.lgr.debug('dataWatch loopAdHoc exit i is %d' % i)
            return adhoc

    def trackPush(self, sp, instruct, addr, start, length, ip):
        self.setRange(sp, self.mem_utils.WORD_SIZE, no_extend=True)
        self.watchMarks.pushMark(addr, sp, start, length, ip)                            
        self.lgr.debug('dataWatch trackPush, did push')
        self.setBreakRange()
        ret_to = self.findCallReturn(ip, instruct)
        if ret_to is None:
            self.lgr.error('dataWatch trackPush, findCallReturn failed for 0x%x, %s' % (ip, instruct[1]))
            SIM_break_simulation('trackPush failure')
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

    def findCallReturn(self, ip, instruct):
        next_instruct = instruct
        next_ip = ip
        limit = 10
        count = 0
        retval = None
        if self.fun_mgr is not None:
            while not self.fun_mgr.isCall(next_instruct[1]):
                next_ip = next_ip + next_instruct[0]
                next_instruct = SIM_disassemble_address(self.cpu, next_ip, 1, 0)
                if count > limit:
                    self.lgr.error('dataWatch findCall failed to find call.')
                    next_ip = None
                    break
                count += 1
            if next_ip is not None:
                retval = next_ip + next_instruct[0]
        return retval


    def transformPushHap(self, dubm, an_object, breakpoint, memory):
        ''' Returned from a data transform call that operated on tracked data.  See if return value is put somewhere or passed to another function.'''
        if self.transform_push_hap is not None:
            self.lgr.debug('dataWatch transformPushHap %s' % self.move_stuff.getString())
            self.context_manager.genDeleteHap(self.transform_push_hap)
            self.transform_push_hap = None
            eip = self.top.getEIP(self.cpu)
            instruct = SIM_disassemble_address(self.cpu, eip, 1, 0)
            our_reg = self.mem_utils.regs['syscall_ret']
            adhoc = self.loopAdHoc(self.move_stuff.addr, self.move_stuff.trans_size, self.move_stuff.start, self.move_stuff.length, instruct, our_reg, eip, self.move_stuff.ip)

    def checkMove(self, addr, trans_size, start, length, eip, instruct, pid):
        ''' Does this look like a move from memA=>reg=>memB ? '''
        ''' If so, return dest.  Also checks for regex references using reWatch module '''
        ''' The given eip is where the read happened.'''
        self.lgr.debug('dataWatch checkMove %s' % instruct[1])
        adhoc = False
        was_checked = False
        orig_ip = self.top.getEIP(self.cpu)
        if instruct[1].startswith('mov') or instruct[1].startswith('ldr'):
            op2, op1 = self.decode.getOperands(instruct[1])
            if self.decode.isReg(op1):
                self.lgr.debug('dataWatch checkMove is mov to reg %s eip:0x%x' % (op1, eip))
                our_reg = op1
                adhoc = self.loopAdHoc(addr, trans_size, start, length, instruct, our_reg, eip, orig_ip)
                was_checked = True
        elif instruct[1].startswith('ldm'):
            op2, op1 = self.decode.getOperands(instruct[1])
            reg_set = op2
            adhoc = self.loopAdHocMult(addr, trans_size, start, length, instruct, reg_set, eip, orig_ip)
            was_checked = True
        if not adhoc:
            if was_checked:
                if eip not in self.not_ad_hoc_copy:
                    self.not_ad_hoc_copy.append(eip)
            ''' make sure we are not back here due to an UNDO '''
            seen_movie = False
            if self.save_cycle is not None:
                delta = self.cpu.cycles - self.save_cycle
                if delta < 4:
                    seen_movie = True 
            re_watch = None
            if not seen_movie:
                self.save_cycle = self.cpu.cycles - 1
                re_watch = reWatch.REWatch.isCharLookup(addr, eip, instruct, self.decode, self.cpu, pid, self.mem_utils, 
                      self.context_manager, self.watchMarks, self.top, self.lgr)
            if re_watch is not None:
                self.re_watch_list.append(re_watch)

                new_mem_something = re_watch.getMemSomething(addr) 
                if new_mem_something is None:
                    if self.mem_something.fun_addr is not None:
                        self.lgr.debug('re_watch got no fun addr, mem_something fun addr 0x%x' % self.mem_something.fun_addr)
                        
                    else:
                        self.lgr.debug('re_watch got no fun addr, mem_something fun addr none also')
                       
                
                if new_mem_something.fun_addr in self.skip_entries:
                    self.lgr.debug('dataWatch checkMove pid:%d is re watch, 0x%x in skip_entries, bail' % (pid, new_mem_something.fun_addr))
                    return
                ''' crude test to see if function call is to GOT, which makes actual function call'''
                hack_match = None
                if self.mem_something is not None and self.mem_something.fun_addr is not None and self.mem_something.fun_addr != new_mem_something.fun_addr:
                    fun_instruct = SIM_disassemble_address(self.cpu, self.mem_something.fun_addr, 1, 0)[1]
                    self.lgr.debug('dataWatch checkMove re_watch look for got in instruct %s' % fun_instruct)
                    ''' TBD generalize this'''
                    if self.cpu.architecture == 'arm' and fun_instruct.startswith('b'):
                        parts = fun_instruct.split()
                        try:
                            hack_match = int(parts[1].strip(), 16)
                            self.lgr.debug('dataWatch checkMove re_watch GOT call, generalize this 0x%x' % hack_match)
                        except:
                            self.lgr.debug('dataWatch checkMove re_watch GOT crapped out, instruct %s' % fun_instruct)
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
                    self.lgr.debug('dataWatch checkMove pid:%d is re watch, we already gathered ret_addr_addr on our way in at fun entry 0x%x.  Do not need to reverse. cycles: 0x%x ' %(pid, self.mem_something.fun_addr, self.cpu.cycles))
                    self.runToReturn()
                else:
                    if self.mem_something.fun_addr is None:
                        self.lgr.debug('dataWatch checkMove pid:%d is re watch, funs do not match, fun addr NONE' % (pid)) 
                    elif new_mem_something.fun_addr is None:
                        self.lgr.debug('dataWatch checkMove pid:%d is re watch, funs do not match, new_mem_something.fun_addr is none' % (pid))
                    else:
                        self.lgr.debug('dataWatch checkMove pid:%d is re watch, funs do not match, fun addr 0x%x  new fun addr 0x%x  cycles: 0x%x ' %(pid, self.mem_something.fun_addr,
                            new_mem_something.fun_addr, self.cpu.cycles))
                    self.mem_something = new_mem_something

                    if self.mem_something is not None:
                        SIM_run_alone(self.handleMemStuff, None)
                    else:
                        self.lgr.error('dataWatch checkMove failed to get mem_something from re_watch')
                        self.watchMarks.dataRead(addr, start, length, self.getCmp(), trans_size)
            else: 
                #self.lgr.debug('dataWatch checkMove not a reWatch')
                self.watchMarks.dataRead(addr, start, length, self.getCmp(), trans_size)

    def isReuse(self, eip):
        ''' guess is a data buffer is being recycled, e.g., loaded with zeros'''
        retval = False
        instruct = SIM_disassemble_address(self.cpu, eip, 1, 0)
        ''' TBD why care about direct move vs some other reuse of buffer???'''
        if self.decode.isDirectMove(instruct[1]):
            retval = True
        elif instruct[1].startswith('str'):
            op2, op1 = self.decode.getOperands(instruct[1])
            if self.decode.isReg(op1) and self.decode.getValue(op1, self.cpu)==0:
                retval = True
        return retval
              
    def finishReadHap(self, op_type, trans_size, eip, addr, length, start, pid, index=None):
        instruct = SIM_disassemble_address(self.cpu, eip, 1, 0)
        offset = addr - start
        cpl = memUtils.getCPL(self.cpu)
        self.lgr.debug('dataWatch finishReadHap eip: 0x%x addr 0x%x' % (eip, addr))
        if op_type == Sim_Trans_Load:
            if cpl == 0:
                #if not self.break_simulation:
                #    self.stopWatch()
                #self.lgr.debug('dataWatch finishReadHap, read in kernel, set kernelReturn hap')
                #self.return_hap = 'eh'
                SIM_run_alone(self.kernelReturn, self.KernelReturnInfo(addr, op_type))
                return
            else:
                #self.lgr.debug('finishReadHap Data read from 0x%x within buffer (offset of %d into buffer of %d bytes starting at 0x%x) pid:%d eip: 0x%x <%s> cycle:0x%x' % (addr, 
                #        offset, length, start, pid, eip, instruct[1], self.cpu.cycles))
                self.prev_read_cycle = self.cpu.cycles
                msg = ('Data read from 0x%x within buffer (offset of %d into %d bytes starting at 0x%x) eip: 0x%x' % (addr, 
                            offset, length, start, eip))
                self.lgr.debug(msg)
                self.context_manager.setIdaMessage(msg)
                if instruct[1].startswith('repe cmpsb'):
                    esi = self.mem_utils.getRegValue(self.cpu, 'esi')
                    edi = self.mem_utils.getRegValue(self.cpu, 'edi')
                    count = self.mem_utils.getRegValue(self.cpu, 'ecx')
                    buf_start = self.findRange(edi)
                    self.watchMarks.compare('rep cmpsb', edi, esi, count, buf_start)
                #elif index in self.char_ptrs:
                #    self.lgr.debug('dataWatch finishReadHap hit a char pointer')
                #    self.watchMarks.charPtrMark(addr)
                else: 
                    ad_hoc = False
                    ''' see if an ad-hoc move. checkMove will update watch marks '''
                    if eip not in self.not_ad_hoc_copy:
                        self.checkMove(addr, trans_size, start, length, eip, instruct, pid)
                if self.break_simulation:
                    self.lgr.debug('dataWatch told to break simulation')
                    SIM_break_simulation('DataWatch read data')


        elif cpl > 0:
            ''' is a write to a data watch buffer '''
            #self.lgr.debug('finishReadHap Data written to 0x%x within buffer (offset of %d into buffer of %d bytes starting at 0x%x) pid:%d eip: 0x%x' % (addr, offset, length, start, pid, eip))
            if addr == self.recent_fgets:
                self.lgr.debug('dataWatch reuse of fgets buffer at 0x%x, remove it' % addr)
                self.rmRange(addr)
            else:   
                self.context_manager.setIdaMessage('Data written to 0x%x within buffer (offset of %d into %d bytes starting at 0x%x) eip: 0x%x' % (addr, offset, length, start, eip))
                #self.lgr.debug('Data written to 0x%x within buffer (offset of %d into %d bytes starting at 0x%x) eip: 0x%x' % (addr, offset, length, start, eip))
                ''' TBD move to separate function.  ad-hoc check for mmx based buffer clear.  prehaps too crude.'''
                if instruct[1].startswith('movdqa xmmword'):
                    xmm0 = self.mem_utils.getRegValue(self.cpu, 'xmm0') 
                    if xmm0 == 0 and index is not None:
                        ''' assume the whole fbuffer will go '''
                        start = self.start[index]
                        length = self.length[index]
                        trans_size = self.length[index] 
                        addr = start
            
                self.watchMarks.memoryMod(start, length, trans_size, addr=addr)
                if self.break_simulation:
                    ''' TBD when to treat buffer as unused?  does it matter?'''
                    self.start[index] = None
                    self.lgr.debug('dataWatch toldx to break simulation')
                    SIM_break_simulation('DataWatch written data')
                else:
                    ''' TBD deleting buffer, sometimes, in finishReadHap, here too?'''
                    self.lgr.debug('dataWatch did mem mod, call rmSubRange for 0x%x len 0x%x' % (addr, trans_size))
                    self.rmSubRange(addr, trans_size)
                    pass
        elif self.retrack:
            self.lgr.debug('dataWatch finishReadHap, modification by kernel, set kernelReturn hap')
            self.return_hap = 'eh'
            SIM_run_alone(self.kernelReturn, self.KernelReturnInfo(addr, op_type))
            self.lgr.debug('Data written by kernel to 0x%x within buffer (offset of %d into buffer of %d bytes starting at 0x%x) pid:%d eip: 0x%x. In retrack, stop here TBD FIX THIS.' % (addr, offset, length, start, pid, eip))
            #self.stopWatch()
        else:
            #self.lgr.debug('dataWatch finishReadHap, modification by kernel, set kernelReturn hap')
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
            return
        op_type = SIM_get_mem_op_type(memory)
        eip = self.top.getEIP(self.cpu)
        dum_cpu, cur_addr, comm, pid = self.task_utils.currentProcessInfo(self.cpu)
    
        if op_type != Sim_Trans_Load:
            self.lgr.debug('dataWatch readHap pid:%d write addr: 0x%x index: %d marks: %s max: %s cycle: 0x%x eip: 0x%x' % (pid, memory.logical_address, index, str(self.watchMarks.markCount()), str(self.max_marks), 
                 self.cpu.cycles, eip))
        else:
            self.lgr.debug('dataWatch readHap pid:%d read addr: 0x%x index: %d marks: %s max: %s cycle: 0x%x eip: 0x%x' % (pid, memory.logical_address, index, str(self.watchMarks.markCount()), str(self.max_marks), 
                 self.cpu.cycles, eip))
   
   
        #if self.watchMarks.markCount() == 186:
        #    print('is 186')
        #    SIM_break_simulation("FIX THIS")
        #    return
        if self.max_marks is not None and self.watchMarks.markCount() > self.max_marks:
            self.lgr.debug('dataWatch max marks exceeded')
            self.stopWatch()
            self.clearWatches()
            SIM_break_simulation('max marks exceeded')
            print('Data Watches removed')
            return

        addr = memory.logical_address
        ''' ad hoc sanitity check for wayward programs, fuzzed, etc.'''
        #if index not in self.length or (index in self.length and self.length[index]<10):
        if index >= len(self.length) or (index < len(self.length) and self.length[index]<10):
            if index not in self.index_hits:
                self.index_hits[index] = 0
            self.index_hits[index] = self.index_hits[index]+1
            #self.lgr.error('dataWatch readHap %d hits on  index %d, ' % (self.index_hits[index], index))
            if self.index_hits[index] > self.read_loop_max:
                self.lgr.error('dataWatch readHap over %d hits on index %d eip 0x%x, stopping watch' % (self.read_loop_max, index, eip))
                read_loop = os.getenv('READ_LOOP')
                if read_loop is not None and read_loop.lower() == 'quit':
                    self.top.quit()
                self.stopWatch()
                return
        ''' watched data has been read (or written) '''
        if self.prev_cycle is None:
            ''' first data read, start data session if doing coverage '''
            self.top.startDataSessions()
        if self.cpu.cycles == self.prev_cycle and not self.undo_pending:
            #self.lgr.debug('readHap hit twice')
            return
        if len(self.read_hap) == 0:
            return
        if op_type != Sim_Trans_Load:
            if addr == self.last_ad_hoc:
                ''' we just added this add hoc data move, but had not yet executed the instruction '''
                return
        if op_type != Sim_Trans_Load:
            if self.move_cycle == self.cpu.cycles:
                ''' just writing to memory as part of previously recorded ad-hoc copy '''
                #self.lgr.debug('dataWatch readHap just writing to memory as part of previously recorded ad-hoc copy')
                return
            #if index in self.char_ptrs:
            #    ''' ignore write to character pointer blocks '''
            #    return
            remove_watch = False
            if addr in self.no_backstop:
                remove_watch = True
            elif len(self.length) > index and memory.size == self.length[index]:
                if self.isReuse(eip):
                    #self.lgr.debug('dataWatch readHap direct move or such into watch, remove it')
                    remove_watch = True
     
            if remove_watch:
                self.start[index] = None
                #self.lgr.debug('watchData readHap modified no_backstop memory, remove from watch list')
                if index < len(self.read_hap):
                    if self.read_hap[index] is not None:
                        #self.lgr.debug('dataWatch readHap  delete hap %d' % self.read_hap[index])
                        self.context_manager.genDeleteHap(self.read_hap[index], immediate=False)
                        self.read_hap[index] = None
                return
        else:
            self.recent_reused_index=None
            self.hack_reuse_index = None

        ''' NOTE RETURNS above '''
        if self.finish_check_move_hap is not None:
            #self.lgr.debug('DataWatch readHap delete finish_check_move_hap')
            self.context_manager.genDeleteHap(self.finish_check_move_hap, immediate=False)
            self.finish_check_move_hap = None
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

        self.prev_cycle = self.cpu.cycles

        self.lgr.debug('dataWatch readHap pid:%d index %d addr 0x%x eip 0x%x cycles: 0x%x' % (pid, index, addr, eip, self.cpu.cycles))
        if self.show_cmp:
            self.showCmp(addr)

        if self.break_simulation:
            self.lgr.debug('readHap will break_simulation, set the stop hap')
            self.stopWatch()
            SIM_run_alone(self.setStopHap, None)

        if self.start[index] is None:
            self.lgr.debug('dataWatch readHap index %d has no start value, likely deleted but not immediate.' % index)
            return 

        start, length = self.getStartLength(index, addr) 
        self.lgr.debug('readHap index %d addr 0x%x got start of 0x%x, len %d' % (index, addr, start, length))
        cpl = memUtils.getCPL(self.cpu)
        ''' If execution outside of text segment, check for mem-something library call '''
        if cpl != 0:
            #if not self.break_simulation:
            #    ''' prevent stack trace from triggering haps '''
            #    self.stopWatch()


            instruct = SIM_disassemble_address(self.cpu, eip, 1, 0)
            fun = self.ida_funs.getFun(eip)
            ''' TBD seems impossible for a push to trigger a load.  huh?'''
            if instruct[1].startswith('push') and self.top.isCode(eip) and op_type == Sim_Trans_Load:
                self.lgr.debug('********* is a push, provide an explaination please!')
                sp = self.mem_utils.getRegValue(self.cpu, 'sp') - self.mem_utils.WORD_SIZE
                self.trackPush(sp, instruct, addr, start, length, eip)
            elif fun in self.not_mem_something:
                self.finishReadHap(op_type, memory.size, eip, addr, length, start, pid, index=index)
            else:
                ''' Get the stack frame so we can look for memsomething or frees '''
                st = self.top.getStackTraceQuiet(max_frames=20, max_bytes=1000)
                if st is None:
                    self.lgr.debug('DataWatch readHap stack trace is None, wrong pid?')
                else:
                    self.frames = st.getFrames(20)
                    if not self.checkFree(self.frames, index):
                        if not self.lookForMemStuff(addr, start, length, memory, op_type, eip, fun):
                            self.lgr.debug('dataWatch, not memstuff, do finishRead')
                            self.finishReadHap(op_type, memory.size, eip, addr, length, start, pid, index=index)
                        else:
                            self.lgr.debug('dataWatch not checkFree maybe memstuff?')
                    else:
                        #self.lgr.debug('dataWatch was checkFree')
                        pass
        else:
            self.finishReadHap(op_type, memory.size, eip, addr, length, start, pid, index=index)

    def rmFree(self, fun, index):
        self.lgr.debug('dataWatch rmFree delete hap for %s' % fun)
        self.context_manager.genDeleteHap(self.read_hap[index], immediate=False)
        self.read_hap[index] = None
        self.start[index] = None

    def checkFree(self, frames, index):
        ''' Look at stack frame to determine if this is a call to a free-type of function '''
        retval = False
        if self.start[index] is None:
            self.debug('dataWatch checkFree called with index %d, but that start is None')
        else:
            max_index = len(frames)-1
            for i in range(max_index, -1, -1):
                frame = frames[i]
                fun = clibFuns.adjustFunName(frame, self.ida_funs, self.lgr)
                #self.lgr.debug('dataWatch checkFree fun is %s' % fun)
                if fun in free_funs:
                    self.recordFree(self.start[index], fun)
                    self.rmFree(fun, index)
                    ''' Very ad-hoc an incomplete.  Catch all future destroys and see if they name string object. Cannot reliably rely on data breakpoints?'''
                    if fun == 'destroy':
                        self.lgr.debug('is destroy fun_addr is 0x%x' % frame.fun_addr)
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
  

    def lookForMemStuff(self, addr, start, length, memory, op_type, eip, fun):
        ''' See if reference is within a memcpy type of function '''
        retval = False
        mem_stuff = None
        # check if we already failed on this memsomething
        if not self.undo_pending:
            #self.lgr.debug('%s' % st.getJson()) 
            # look for memcpy'ish... TBD generalize 
            #if self.top.isWindows():
            #    mem_stuff = self.memsomething(frames, win_mem_funs)
            #else:
            #    mem_stuff = self.memsomething(frames, mem_funs)
            mem_stuff = self.memsomething(self.frames, mem_funs)
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
            #if mem_stuff.ret_addr is not None and mem_stuff.called_from_ip is not None:
            #    self.lgr.debug('DataWatch lookForMemstuff ret_ip 0x%x called_from_ip is 0x%x' % (mem_stuff.ret_addr, mem_stuff.called_from_ip))
            #else:
            #    self.lgr.debug('DataWatch lookForMemstuff ret_ip  or called_from_ip no ret_addr found')
            ''' referenced memory address is src/dest depending on op_type''' 
            dest = None
            src = addr
            if op_type != Sim_Trans_Load:
                src = None
                dest = addr
            self.mem_something = MemSomething(mem_stuff.fun, mem_stuff.fun_addr, addr, mem_stuff.ret_addr, src, dest, None, 
                  mem_stuff.called_from_ip, op_type, length, start, ret_addr_addr = mem_stuff.ret_addr_addr, trans_size=memory.size,
                  frames=mem_stuff.frames)
            SIM_run_alone(self.handleMemStuff, None)
            retval = True
        else:
            #self.lgr.debug('DataWatch lookForMemstuff not memsomething, reset the watch ')
            #self.watch()
            if fun not in self.not_mem_something:
                self.lgr.debug('DataWatch lookForMemstuff not memsomething add fun 0x%x to not_mem_something' % fun)
                self.not_mem_something.append(fun)
            pass
        return retval
       
    def showWatch(self):
        for index in range(len(self.start)):
            if self.start[index] is not None:
                print('%d start: 0x%x  length: 0x%x' % (index, self.start[index], self.length[index]))
 
    def setBreakRange(self, i_am_alone=False):
        self.lgr.debug('dataWatch setBreakRange')
        ''' Set breakpoints for each range defined in self.start and self.length '''
        context = self.context_manager.getRESimContext()
        num_existing_haps = len(self.read_hap)
        for index in range(num_existing_haps, len(self.start)):
            if self.start[index] is None:
                #self.lgr.debug('DataWatch setBreakRange index %d is 0' % index)
                self.read_hap.append(None)
                continue
            ''' TBD should this be a physical bp?  Why explicit RESim context -- perhaps debugging_pid is not set while
                fussing with memsomething parameters? '''
           
            break_num = self.context_manager.genBreakpoint(context, Sim_Break_Linear, Sim_Access_Read | Sim_Access_Write, self.start[index], self.length[index], 0)
            end = self.start[index] + self.length[index] 
            eip = self.top.getEIP(self.cpu)
            hap = self.context_manager.genHapIndex("Core_Breakpoint_Memop", self.readHap, index, break_num, 'dataWatch')
            self.lgr.debug('DataWatch setBreakRange eip: 0x%x Adding breakpoint %d for %x-%x length %x hap: %d index now %d number of read_haps was %d  alone? %r cpu context:%s' % (eip, 
                break_num, self.start[index], end, self.length[index], hap, index, len(self.read_hap), i_am_alone, self.cpu.current_context))
            self.read_hap.append(hap)
            #self.lgr.debug('DataWatch back from set break range')
            
        if len(self.start) != len(self.read_hap):
            self.lgr.error('dataWatch setBreakRange start len is %d while read_hap is %d' % (len(self.start), len(self.read_hap)))

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
            self.lgr.debug('dataWatch stopHap will delete hap %s' % str(self.stop_hap))
            SIM_run_alone(self.delStopHap, self.stop_hap)
            self.stop_hap = None
            ''' check functions in list '''
            #self.lgr.debug('stopHap now run actions %s' % str(stop_action.flist))
            stop_action.run()

    def delStopHap(self, hap):
        self.lgr.debug('dataWatch delStopHap delete hap %d' % hap)
        SIM_hap_delete_callback_id("Core_Simulation_Stopped", hap)
         
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

    def rmSubRange(self, addr, trans_size):
        index = self.findRangeIndex(addr)
        if index is not None:
            if index != self.recent_reused_index:
                start = self.start[index]
                length = self.length[index]
                end = start + length - 1
                ''' try to catch ad-hoc buffer deletion based on multiple writes in a row '''
                force_reuse = False
                if start == addr:
                    self.hack_reuse_index = index
                    self.hack_reuse = []
                    self.hack_reuse.append(addr)
                elif index == self.hack_reuse_index:
                    if addr not in self.hack_reuse:
                        self.hack_reuse.append(addr)
                        if (len(self.hack_reuse) * self.mem_utils.wordSize(self.cpu)) >= length:
                            force_reuse = True
                            self.lgr.debug('dataWatch rmSubRange force reuse')
              
                if force_reuse or (start >= addr and end <= (addr+trans_size)):
                    self.lgr.debug('dataWatch rmSubRange, IS overlap start 0x%x end 0x%x  addr 0x%x trans_size 0x%x' % (start, end, addr, trans_size))
                    new_start = None
                    self.lgr.debug('dataWatch rmSubRange, addr: 0x%x start 0x%x length: %d end 0x%x' % (addr, start, length, end))
                    self.start[index] = None
                    self.lgr.debug('dataWatch rmSubRange index[%d] set to None' % index)
                    if index < len(self.read_hap) and self.read_hap[index] is not None:
                        self.lgr.debug('dataWatch rmSubRange read_hap[%d] %d' % (index, self.read_hap[index]))
                        self.context_manager.genDeleteHap(self.read_hap[index], immediate=False)
                        self.read_hap[index] = None
                    if start < addr:
                        newlen = addr - start + 1
                        if newlen > 0:
                            self.setRange(start, newlen, no_extend=True)
                        new_start = addr + trans_size
                    elif start == addr and trans_size < length:
                        new_start = addr+trans_size
                    if new_start is not None and new_start < end:
                        newlen = end - new_start + 1
                        if newlen > 0:
                            self.setRange(new_start, newlen, no_extend=True)
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
            self.start[index] = None
            if index < len(self.read_hap) and self.read_hap[index] is not None:
                #self.lgr.debug('dataWatch rmRange addr 0x%x index %d len of read_hap %d call genDeleteHap' % (addr, index, len(self.read_hap)))
                self.context_manager.genDeleteHap(self.read_hap[index], immediate=False)
                self.read_hap[index] = None
            else:
                if index >= len(self.read_hap):
                    self.lgr.debug('dataWatch rmRange addr 0x%x index %d NOT IN RANGE of read_hap (has %d haps)' % (addr, index, len(self.read_hap)))
                else:
                    self.lgr.debug('dataWatch rmRange addr 0x%x read_hap[%d] is None?  (has %d haps)' % (addr, index, len(self.read_hap)))
                    

    def findRange(self, addr):
        retval = None
        if addr is None:
            self.lgr.error('dataWatch findRange called with addr of None')
            raise Exception('addr is none')
        else:
            for index in range(len(self.start)):
                if self.start[index] is not None:
                    end = self.start[index] + self.length[index]
                    #self.lgr.debug('findRange is 0x%x between 0x%x and 0x%x?' % (addr, self.start[index], end))
                    if addr >= self.start[index] and addr <= end:
                        retval = self.start[index]
                        break
        return retval

    def findRangeIndex(self, addr):
        for index in range(len(self.start)):
            if self.start[index] is not None:
                end = self.start[index] + (self.length[index]-1)
                #self.lgr.debug('findRange is 0x%x between 0x%x and 0x%x?' % (addr, self.start[index], end))
                if addr is not None and addr >= self.start[index] and addr <= end:
                    return index
        return None

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
        if cycle is not None:
            resimUtils.skipToTest(self.cpu, cycle, self.lgr)
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
                cli.quiet_run_command('rev 1')
                resimUtils.skipToTest(self.cpu, cycle, self.lgr)
                eip = self.top.getEIP(self.cpu)
                if eip != mark_ip:
                    self.lgr.error('dataWatch goToMark index %d eip 0x%x does not match mark ip 0x%x mark cycle: 0x%x Second attempt' % (index, eip, mark_ip, cycle))
                    retval = None
            else:
                if self.watchMarks.isCall(index):
                    cycle = self.cpu.cycles+1
                    if not resimUtils.skipToTest(self.cpu, cycle, self.lgr):
                        self.lgr.error('dataWatch goToMark got wrong cycle after adjust for call, asked for 0x%x got 0x%x' % (cycle, self.cpu.cycles))
                        retval = None
                    else:
                        self.lgr.debug('dataWatch goToMark adjusted for call cycle now 0x%x' % cycle)
                        if index == 1:
                            call_ret_val = self.mem_utils.getRegValue(self.cpu, 'syscall_ret')
                            mark = self.watchMarks.getMarkFromIndex(index)
                            if call_ret_val != mark.mark.len:
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


    def clearWatches(self, cycle=None):
        self.lgr.debug('dataWatch clearWatches')
        if cycle is None:
            self.lgr.debug('DataWatch clear Watches, no cycle given')
            self.prev_cycle = None
        else:
            self.lgr.debug('DataWatch clear Watches cycle 0x%x' % cycle)
        self.stopWatch()
        self.break_simulation = True
        self.stack_buffers = {}
        self.total_read = 0
        self.last_ad_hoc = 0
        for eip in self.stack_buf_hap:
            self.lgr.debug('DataWatch remove stack_buf_hap[0x%x] %d' % (eip, self.stack_buf_hap[eip]))
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
                self.lgr.debug('clearWatches, reset list, index %d start[%d] is 0x%x, len %d' % (index, index, self.start[index], self.length[index]))


    def resetOrigin(self, cycle, reuse_msg=False, record_old=False):
        ''' remove all data watches and rebuild based on watchmarks earlier than given cycle '''
        if len(self.start) == 0:
            return
        del self.start[:]
        del self.length[:]
        del self.hack_reuse[:]
        del self.cycle[:]
        self.other_starts = []
        self.other_lengths = []
        data_watch_list = self.watchMarks.getDataWatchList()
        self.lgr.debug('clearWatches rebuild data watches')
        origin_watches = []
        for data_watch in data_watch_list:
            if data_watch['cycle'] <= cycle:
                self.setRange(data_watch['start'], data_watch['length']) 
                origin_watches.append(data_watch)
            else:
                self.lgr.debug('clearWatches found cycle 0x%x > given 0x%x, stop rebuild' % (data_watch['cycle'], cycle))
                break
        self.lgr.debug('dataWatch resetOrigin now call watchmarks')
        self.watchMarks.resetOrigin(origin_watches, reuse_msg=reuse_msg, record_old=record_old)

    def setIdaFuns(self, ida_funs):
        self.lgr.debug('DataWatch setIdaFuns')
        self.ida_funs = ida_funs

    def setFunMgr(self, fun_mgr):
        self.lgr.debug('DataWatch setFunMgr')
        self.fun_mgr = fun_mgr

    def setCallback(self, callback):
        ''' what should backStop call when no activity for N cycles? '''
        self.lgr.debug('dataWatch setCallback, call to backstop to set callback')
        self.back_stop.setCallback(callback)

    def showWatchMarks(self, old=False, verbose=False):
        self.watchMarks.showMarks(old=old, verbose=verbose)

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
        else:
            self.lgr.error('dataWatch tagIterator called but no IDA functions defined yet.  Debugging?')

    def setUserIterators(self, user_iterators):
        self.user_iterators = user_iterators
        self.lgr.debug('dataWatch setUserIterators %s' % str(user_iterators))

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
        mem_stuff = self.memsomething(frames, my_mem_funs)
        if mem_stuff is not None:
            self.lgr.debug('mem_stuff function %s, ret_ip is 0x%x' % (mem_stuff.fun, mem_stuff.ret_addr))
            self.mem_something = MemSomething(mem_stuff.fun, mem_stuff.fun_addr, None, mem_stuff.ret_addr, None, None, None, 
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


    def trackIO(self, fd, callback, compat32, max_marks, quiet=False):
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
        self.disabled = False
        report_backstop = not quiet
        self.back_stop.reportBackstop(report_backstop)
        ida_funs = self.top.getIdaFuns()
        self.readLib.trackReadLib(ida_funs)

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
        def __init__(self, ret_addr, fun, fun_addr, called_from_ip, ret_addr_addr, frames=[]):
            self.ret_addr = ret_addr
            self.fun = fun
            self.fun_addr = fun_addr
            ''' sp of location of return address '''
            self.ret_addr_addr = ret_addr_addr
            self.called_from_ip = called_from_ip
            self.frames=frames

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
        for i in range(max_index, -1, -1):
            frame = frames[i]
            if self.ida_funs is not None:
                fun_addr = self.ida_funs.getFun(frame.ip)
                fun_of_ip = self.ida_funs.getName(fun_addr)
                so_file = self.top.getSOFile(fun_addr)
                if fun_addr is not None:
                    if fun_of_ip == 'main':
                        #self.lgr.debug('dataWatch checkFrames above, found main fun_of_ip: %s  so_file: %s' % (fun_of_ip, so_file))
                        retval = i
                        break
                    elif so_file is not None:
                        if os.path.basename(so_file) == os.path.basename(self.top.getFullPath()):
                            #self.lgr.debug('dataWatch checkFrames above, found so file is our program, return false')
                            retval = i
                            break
                       
        return retval
                  
    def memsomething(self, frames, local_mem_funs):
        ''' Is there a call to a memcpy'ish function, or a user iterator, in the last few frames? If so, return the return address '''
        ''' Will iterate through the frames backwards, looking for the highest level function'''
        retval = None
        max_precidence = -1
        max_index = len(frames)-1
        self.lgr.debug('memsomething begin, max_index %d' % (max_index))
        outer_index = None
        prev_fun = None
        for i in range(max_index, -1, -1):
            frame = frames[i]
            if frame.fun_addr is None and self.ida_funs is not None:
                self.lgr.debug('dataWatch memsomething frame %d fun_addr is None' % i)
                frame.fun_addr = self.ida_funs.getFun(frame.ip)
            if frame.fun_addr is None:
                self.lgr.debug('dataWatch memsomething frame %d ip: 0x%x fun_addr NONE instruct is %s' % (i, frame.ip, frame.instruct))
                pass
            else:
                self.lgr.debug('dataWatch memsomething frame %d ip: 0x%x fun_addr 0x%x instruct is %s' % (i, frame.ip, frame.fun_addr, frame.instruct))
                pass
            self.lgr.debug('dataWatch memsomething frame fname: %s' % frame.fname)
            if frame.instruct is not None:
                #self.lgr.debug('dataWatch memsomething before adjust, fun is %s' % frame.fun_name)
                #if self.top.isWindows():
                #    fun = None
                #else:
                fun = clibFuns.adjustFunName(frame, self.ida_funs, self.lgr)
                if fun is not None:
                    if fun not in local_mem_funs and fun.startswith('v'):
                        fun = fun[1:]
                #self.lgr.debug('dataWatch memsomething frame %d fun is %s fun_addr: 0x%x ip: 0x%x sp: 0x%x' % (i, fun, frame.fun_addr, frame.ip, frame.sp))
                if fun is not None and fun == prev_fun and fun != 'None':
                    #self.lgr.debug('dataWatch memsomething repeated fun is %s  -- skip it' % fun)
                    continue
                else:
                    #self.lgr.debug('dataWatch memsomething set prev_fun to %s' % fun)
                    prev_fun = fun
                if self.user_iterators is None:
                    #self.lgr.debug('NO user iterators')
                    pass
                if fun in local_mem_funs or (self.user_iterators is not None and self.user_iterators.isIterator(frame.fun_addr)):
                    if fun in local_mem_funs:
                        fun_precidence = self.funPrecidence(fun)
                        #self.lgr.debug('fun in local_mem_funs %s, set fun_precidence to %d' % (fun, fun_precidence))
                        if fun_precidence == 0 and i > 3:
                            ''' Is it some clib calling some other clib?  ghosts?'''
                            start = i - 1
                            if clibFuns.allClib(frames, start):
                                #self.lgr.debug('dataWatch memsomething i is %d and precidence %d, bailing' % (i, fun_precidence))
                                continue
                    if self.user_iterators is not None and self.user_iterators.isIterator(frame.fun_addr):
                        #self.lgr.debug('fun is iterator 0x%x' % frame.fun_addr) 
                        fun_precidence = 999
                    self.lgr.debug('dataWatch memsomething frame index %d, is %s, frame: %s' % (i, fun, frame.dumpString()))
                    if fun_precidence < max_precidence:
                        #self.lgr.debug('dataWatch memsomething precidence %d less than current max %d, skip it' % (fun_precidence, max_precidence))
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
                        ''' Make sure there is not a main or similar above this frame.  TBD make standard in stack module? '''
                        bad_index = self.checkFramesAbove(frames, i)
                        if bad_index is None:

                            if frame.lr_return:
                                addr_of_ret_addr = None
                            elif frame.ret_to_addr is not None:
                                addr_of_ret_addr = frame.ret_to_addr
                                #self.lgr.debug('datawatch memsomething using ret_to_addr from frame of 0x%x' % frame.ret_to_addr)
                            else:
                                addr_of_ret_addr = frame.sp
                                #self.lgr.debug('datawatch memsomething using ret_to_addr from SP of 0x%x' % frame.sp)
                            retval = self.MemStuff(ret_addr, fun, frame.fun_addr, frame.ip, addr_of_ret_addr, frames=frames)
                            break 
                        else:
                            ''' NOTE: modifying loop index! '''
                            i = bad_index - 1
                            #self.lgr.debug('datawatch memsomething found frame that may be floor, change loop index to %d' % i)
                            
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
        self.lgr.debug('dataWatch max marks set to %d' % marks)
        self.max_marks = marks

    def enable(self):
        self.disabled = False

    def setReadLimit(self, limit, callback):
        self.read_limit_trigger = limit
        self.read_limit_callback = callback
        self.lgr.debug('dataWatch setReadLimit to %d callback %s' % (limit, self.read_limit_callback))

    def getAllJson(self):
        return self.watchMarks.getAllJson()

    def markLog(self, s, prefix):
        self.lgr.debug('dataWatch markLog')
        self.watchMarks.logMark(s, prefix)

    def watchArgs(self):
        self.enable()
        self.break_simulation = False
        sp = self.mem_utils.getRegValue(self.cpu, 'sp')
        argc = self.mem_utils.readPtr(self.cpu, sp)
        self.lgr.debug('dataWatch watchArgs sp 0x%x, argc is %d' % (sp, argc))
        argptr = sp + self.mem_utils.WORD_SIZE
        for index in range(argc):
            ''' TBD good size limit? '''
            valptr = self.mem_utils.readPtr(self.cpu, argptr)
            argval = self.mem_utils.readString(self.cpu, valptr, 100)
            self.lgr.debug('dataWatch watchArgs arg %d is %s' % (index, argval))
            argptr = argptr + self.mem_utils.WORD_SIZE
            msg = 'prog arg %s' % argval
            self.setRange(argptr, len(argval), msg=msg)
        self.setBreakRange()
        
    def watchCGIArgs(self):
        self.enable()
        self.break_simulation = False
        sp = self.mem_utils.getRegValue(self.cpu, 'sp')
        argc = self.mem_utils.readPtr(self.cpu, sp)
        self.lgr.debug('dataWatch watchCGIArgs sp 0x%x, argc is %d' % (sp, argc))
        argptr = sp + self.mem_utils.WORD_SIZE
        valptr = self.mem_utils.readPtr(self.cpu, argptr)
        if argc != 1:
            self.ldr.error('dataWatch watchCGIArgs expected only one argv, got %d' % argc)
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
            entries_file = os.path.join('./', name, self.cell_name, 'funEntry.pickle')
            entries = {}
            entries['fun_entries'] = self.mem_fun_entries
            self.lgr.debug('dataWatch pickleFunEntries saved %d fun entries' % len(self.mem_fun_entries))
            entries['skip_entries'] = self.skip_entries
            pickle.dump(entries, open( entries_file, "wb") ) 

    def registerHapForRemoval(self, module):
        self.lgr.debug('winDelay registerHapForRemoval')
        self.remove_external_haps.append(module)

    def removeExternalHaps(self, immediate=False):
        self.lgr.debug('winDelay removeExternalHaps')
        for module in self.remove_external_haps:
            module.rmAllHaps(immediate=immediate)
        self.remove_external_haps = []

    def memcpyCheck(self, vt_stuff, one, exception, error_string):
        self.lgr.debug('dataWatch memcpyCheck')
        SIM_run_command('enable-vmp') 
        if self.call_stop_hap is not None:
            cycle_dif = self.cycles_was - self.cpu.cycles
            #self.lgr.debug('hit CallStopHap will delete hap %d break %d cycle_dif 0x%x' % (self.call_hap, self.call_break, cycle_dif))
            SIM_hap_delete_callback_id("Core_Simulation_Stopped", self.call_stop_hap)
            #self.rmCallHap()
            if self.call_break is not None:
                RES_delete_breakpoint(self.call_break)
            self.call_stop_hap = None
        else:
            return
        self.lgr.debug('dataWatch memcpyCheck.  now what?')
        buf_index = self.findRangeIndex(self.mem_something.src)
        got_it = False
        if buf_index is not None:
            rdx = self.mem_utils.getRegValue(self.cpu, 'rdx')
            if rdx == self.mem_something.src:
                self.lgr.debug('dataWatch memcpyCheck src is rdx 0x%x' % rdx)
                ''' see if destination (not nessesarily beginning of dest buffer, depends on memcy sequency), is within range of rcx to buffer size '''
                rcx = self.mem_utils.getRegValue(self.cpu, 'rcx')
                end = rcx + self.length[buf_index]
                if self.mem_something.dest >= rcx and self.mem_something.dest <= end: 
                    rax = self.mem_utils.getRegValue(self.cpu, 'rax')
                    self.lgr.debug('dataWatch memcpyCheck dest is in range, looks like a memcpy rax is %d' % rax)
                    got_it = True
                    self.mem_something.dest = rcx
                    self.mem_something.count = rax
                    self.mem_something.fun = 'memcpy'
                    self.mem_something.run = True
                    self.mem_something.op_type = Sim_Trans_Load
                    SIM_run_alone(self.runToReturnAlone, None)
        if not got_it:
            pass
            self.lgr.debug('dataWatch memcpyCheck not a memcpy signature, complete the ad-hoc copy ''')
            wm = self.watchMarks.dataRead(self.move_stuff.addr, self.move_stuff.start, self.move_stuff.length, 
                     self.getCmp(), self.move_stuff.trans_size, ad_hoc=True, dest=self.last_ad_hoc)
            ''' recorded in mem_something as part of obscure memcpy check '''
            dest_addr = self.mem_something.dest_addr
            self.setRange(dest_addr, self.move_stuff.trans_size, watch_mark=wm)
            #self.lgr.debug('dataWatch finishCheckMoveHap is ad hoc addr 0x%x  ad_hoc %r, dest 0x%x' % (self.move_stuff.addr, ad_hoc, dest_addr))
            self.setBreakRange()

    def stopForMemcpyCheck(self, dumb):
        if self.finish_check_move_hap is None:
            self.lgr.error('DataWatch stopForMemcpyCheck finish_check_move_hap is none')
            return
        self.context_manager.genDeleteHap(self.finish_check_move_hap, immediate=True)
        self.finish_check_move_hap = None
        self.stop_hap = SIM_hap_add_callback("Core_Simulation_Stopped", self.memstuffStopHap, self.memcpyCheck)
        self.lgr.debug('stopForMemcpyCheck, is big move, look for memcpy')
        SIM_break_simulation('handle memstuff')
